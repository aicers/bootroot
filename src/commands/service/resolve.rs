use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::input_validation::{
    ValidationError, validate_cidr_list, validate_dns_label, validate_domain_name,
    validate_numeric_instance_id,
};

use crate::cli::args::{HookFailurePolicyArg, ReloadStyle, ServiceAddArgs};
use crate::cli::prompt::Prompt;
use crate::commands::constants::DEFAULT_SECRET_ID_WRAP_TTL;
use crate::commands::openbao_auth::{
    RuntimeAuthResolved, resolve_runtime_auth, resolve_runtime_auth_optional,
};
use crate::i18n::Messages;
use crate::state::{
    DEFAULT_HOOK_TIMEOUT_SECS, DeliveryMode, HookFailurePolicyEntry, PostRenewHookEntry,
};

#[derive(Debug)]
pub(crate) struct ResolvedServiceAdd {
    pub(crate) service_name: String,
    pub(crate) delivery_mode: DeliveryMode,
    pub(crate) hostname: String,
    pub(crate) domain: String,
    pub(crate) agent_config: PathBuf,
    pub(crate) cert_path: PathBuf,
    pub(crate) key_path: PathBuf,
    pub(crate) instance_id: Option<String>,
    pub(crate) runtime_auth: Option<RuntimeAuthResolved>,
    pub(crate) notes: Option<String>,
    pub(crate) post_renew_hooks: Vec<PostRenewHookEntry>,
    pub(crate) secret_id_ttl: Option<String>,
    pub(crate) secret_id_wrap_ttl: Option<String>,
    pub(crate) token_bound_cidrs: Option<Vec<String>>,
    /// Operator-supplied ACME account email.  `None` means
    /// `--agent-email` was not provided on `service add`; renderers
    /// fall back to [`DEFAULT_AGENT_EMAIL`].  Preserved as `Option`
    /// so that idempotent remote reruns can distinguish an explicit
    /// operator value from the compose-topology default.
    pub(crate) agent_email: Option<String>,
    /// Operator-supplied ACME directory URL.  `None` means
    /// `--agent-server` was not provided; renderers fall back to
    /// [`DEFAULT_AGENT_SERVER`].
    pub(crate) agent_server: Option<String>,
    /// Operator-supplied HTTP-01 responder admin URL.  `None` means
    /// `--agent-responder-url` was not provided; renderers fall back
    /// to [`DEFAULT_AGENT_RESPONDER_URL`].
    pub(crate) agent_responder_url: Option<String>,
    /// Resolved numeric gid for `--cert-group`. `None` means the
    /// operator did not opt into the group-readable cert policy and
    /// the agent preserves the host-local default. See issue #593.
    pub(crate) cert_group_gid: Option<u32>,
    /// Operator-supplied absolute `--secret-id-path` override
    /// (local-file delivery only). `None` keeps the default location
    /// under `<secrets_dir>/services/<svc>/`. When `Some`, `secret_id`,
    /// its sibling `role_id`, and `eab.json` are relocated there, owned
    /// by the agent account. See issue #722.
    pub(crate) secret_id_path_override: Option<PathBuf>,
}

#[allow(clippy::too_many_lines)]
pub(super) fn resolve_service_add_args(
    args: &ServiceAddArgs,
    messages: &Messages,
    preview: bool,
) -> Result<ResolvedServiceAdd> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let mut prompt = Prompt::new(&mut input, &mut output, messages);

    let service_name = match &args.service_name {
        Some(value) => validate_service_name(value, messages)?,
        None => prompt.prompt_with_validation(messages.prompt_service_name(), None, |value| {
            validate_service_name(value, messages)
        })?,
    };

    let delivery_mode = args.delivery_mode.unwrap_or_default();

    let hostname = match &args.hostname {
        Some(value) => validate_hostname(value, messages)?,
        None => prompt.prompt_with_validation(messages.prompt_hostname(), None, |value| {
            validate_hostname(value, messages)
        })?,
    };

    let domain = match &args.domain {
        Some(value) => validate_domain(value, messages)?,
        None => prompt.prompt_with_validation(messages.prompt_domain(), None, |value| {
            validate_domain(value, messages)
        })?,
    };

    let agent_config = resolve_path(
        args.agent_config.clone(),
        messages.prompt_agent_config(),
        &mut prompt,
        false,
        messages,
    )?;
    // Remote-bootstrap agent-config paths name a file on the *remote*
    // host, so only local-file paths are normalized against this
    // host's filesystem.
    let agent_config = if matches!(delivery_mode, DeliveryMode::LocalFile) {
        normalize_local_agent_config_path(&agent_config)?
    } else {
        agent_config
    };

    let cert_path = resolve_path(
        args.cert_path.clone(),
        messages.prompt_cert_path(),
        &mut prompt,
        false,
        messages,
    )?;

    let key_path = resolve_path(
        args.key_path.clone(),
        messages.prompt_key_path(),
        &mut prompt,
        false,
        messages,
    )?;

    let instance_id = match &args.instance_id {
        Some(value) => validate_instance_id(value, messages)?,
        None => prompt.prompt_with_validation(messages.prompt_instance_id(), None, |value| {
            validate_instance_id(value, messages)
        })?,
    };
    let runtime_auth = if preview {
        resolve_runtime_auth_optional(&args.runtime_auth)?
    } else {
        Some(resolve_runtime_auth(&args.runtime_auth, true, messages)?)
    };

    let post_renew_hooks = resolve_post_renew_hooks(args)?;

    let secret_id_wrap_ttl = if args.no_wrap {
        Some("0".to_string())
    } else {
        args.secret_id_wrap_ttl.clone()
    };

    validate_rn_cidrs(&args.rn_cidrs, messages)?;
    if args.rn_cidrs.len() == 1 && args.rn_cidrs.first().map(String::as_str) == Some("clear") {
        anyhow::bail!(messages.error_rn_cidrs_clear_on_add());
    }
    let token_bound_cidrs = if args.rn_cidrs.is_empty() {
        None
    } else {
        Some(args.rn_cidrs.clone())
    };

    let agent_email = args.agent_email.clone();
    let agent_server = args.agent_server.clone();
    let agent_responder_url = args.agent_responder_url.clone();

    let cert_group_gid = resolve_cert_group_for_add(args, delivery_mode, messages)?;

    let secret_id_path_override =
        resolve_secret_id_path_override(args.secret_id_path.as_deref(), delivery_mode, messages)?;

    Ok(ResolvedServiceAdd {
        service_name,
        delivery_mode,
        hostname,
        domain,
        agent_config,
        cert_path,
        key_path,
        instance_id: Some(instance_id),
        runtime_auth,
        notes: args.notes.clone(),
        post_renew_hooks,
        secret_id_ttl: args.secret_id_ttl.clone(),
        secret_id_wrap_ttl,
        token_bound_cidrs,
        agent_email,
        agent_server,
        agent_responder_url,
        cert_group_gid,
        secret_id_path_override,
    })
}

/// Filename of a service's `role_id`, always derived as the `secret_id`
/// sibling. Kept here so the override collision guard rejects a
/// `--secret-id-path` whose final component matches it.
const SERVICE_ROLE_ID_FILENAME: &str = "role_id";

/// Resolves the `--secret-id-path` override, applying the checks that do
/// not require `state`: it is honoured for local-file delivery only, must
/// be absolute, and must not end in `role_id` (which would collide with
/// the derived sibling `role_id` file). The secrets-tree containment and
/// parent-existence checks need `state.secrets_dir()` and run later in
/// [`validate_secret_id_path_override`].
fn resolve_secret_id_path_override(
    value: Option<&Path>,
    delivery_mode: DeliveryMode,
    messages: &Messages,
) -> Result<Option<PathBuf>> {
    let Some(path) = value else {
        return Ok(None);
    };
    if !matches!(delivery_mode, DeliveryMode::LocalFile) {
        anyhow::bail!(messages.error_service_secret_id_path_requires_local_file());
    }
    if !path.is_absolute() {
        anyhow::bail!(
            messages.error_service_secret_id_path_not_absolute(&path.display().to_string())
        );
    }
    if path.file_name().and_then(|name| name.to_str()) == Some(SERVICE_ROLE_ID_FILENAME) {
        anyhow::bail!(
            messages.error_service_secret_id_path_role_id_collision(&path.display().to_string())
        );
    }
    Ok(Some(path.to_path_buf()))
}

/// Applies the `--secret-id-path` override checks that need
/// `state.secrets_dir()`: the resolved path must lie **outside** the
/// root-owned secrets tree (the non-root agent cannot traverse into it),
/// and its parent directory (operator-provisioned, agent-owned) must
/// already exist. Containment is checked both lexically and — because the
/// writers follow symlinks in the parent — against the canonicalized
/// parent, so a parent spelled outside the tree but symlinked into it is
/// rejected. A no-op when no override was supplied.
pub(crate) fn validate_secret_id_path_override(
    override_path: Option<&Path>,
    secrets_dir: &Path,
    messages: &Messages,
) -> Result<()> {
    let Some(path) = override_path else {
        return Ok(());
    };
    let within = bootroot::fs_util::path_is_within(path, secrets_dir).with_context(|| {
        format!(
            "failed to compare {} against secrets dir {}",
            path.display(),
            secrets_dir.display()
        )
    })?;
    if within {
        anyhow::bail!(messages.error_service_secret_id_path_inside_secrets_dir(
            &path.display().to_string(),
            &secrets_dir.display().to_string(),
        ));
    }
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        anyhow::bail!(
            messages.error_service_secret_id_path_parent_missing(&path.display().to_string())
        );
    };
    if !parent.is_dir() {
        anyhow::bail!(
            messages.error_service_secret_id_path_parent_missing(&parent.display().to_string())
        );
    }
    // The lexical `path_is_within` check above only inspects the spelling,
    // but the override writers create `secret_id`/`role_id` inside `parent`
    // after following any symlinks in it. A parent spelled outside the tree
    // but symlinked into it (e.g. `/tmp/link -> <secrets_dir>/services/foo`)
    // would land the credentials in the root-owned tree the non-root agent
    // cannot traverse, chowned to that tree's owner — the exact non-functional
    // layout the override exists to reject. Canonicalize the (already-existing)
    // parent and the secrets tree so a symlinked parent that resolves into the
    // tree is rejected regardless of how it is spelled.
    let canonical_parent = parent.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize override parent {}",
            parent.display()
        )
    })?;
    let canonical_secrets = match secrets_dir.canonicalize() {
        Ok(dir) => dir,
        Err(_) => bootroot::fs_util::absolute_lexical(secrets_dir).with_context(|| {
            format!("failed to normalize secrets dir {}", secrets_dir.display())
        })?,
    };
    if canonical_parent.starts_with(&canonical_secrets) {
        anyhow::bail!(messages.error_service_secret_id_path_inside_secrets_dir(
            &path.display().to_string(),
            &secrets_dir.display().to_string(),
        ));
    }
    Ok(())
}

/// Resolves `--cert-group` for `service add` based on the deployment
/// mode. `local-file` accepts a numeric gid or a name and validates
/// the caller can actually `chown` to it (so the failure surface lands
/// at `service add` time rather than at the next rotation). `remote-
/// bootstrap` accepts numeric form only and validates only that the
/// number is non-zero — name resolution and membership are checked on
/// the remote agent host because the control host's NSS may differ.
pub(super) fn resolve_cert_group_for_add(
    args: &ServiceAddArgs,
    delivery_mode: DeliveryMode,
    _messages: &Messages,
) -> Result<Option<u32>> {
    let Some(raw) = args.cert_group.as_deref() else {
        return Ok(None);
    };
    let gid = match delivery_mode {
        DeliveryMode::LocalFile => bootroot::cert_group::parse_cert_group_local(raw)
            .map_err(|err| anyhow::anyhow!("{err}"))?,
        DeliveryMode::RemoteBootstrap => bootroot::cert_group::parse_cert_group_remote(raw)
            .map_err(|err| anyhow::anyhow!("{err}"))?,
    };
    if matches!(delivery_mode, DeliveryMode::LocalFile) {
        bootroot::cert_group::validate_local_gid_membership(gid)
            .map_err(|err| anyhow::anyhow!("{err}"))?;
    }
    Ok(Some(gid))
}

pub(super) fn validate_service_add(args: &ResolvedServiceAdd, messages: &Messages) -> Result<()> {
    validate_service_name(&args.service_name, messages)?;
    validate_hostname(&args.hostname, messages)?;
    validate_domain(&args.domain, messages)?;
    validate_instance_id(args.instance_id.as_deref().unwrap_or_default(), messages)?;
    Ok(())
}

/// Resolves the effective wrap TTL from the stored `Option`.
///
/// - `None` → default (`"30m"`)
/// - `Some("0")` → wrapping disabled → returns `None`
/// - `Some(ttl)` → explicit override
pub(crate) fn effective_wrap_ttl(stored: Option<&str>) -> Option<&str> {
    match stored {
        None => Some(DEFAULT_SECRET_ID_WRAP_TTL),
        Some("0") => None,
        Some(ttl) => Some(ttl),
    }
}

fn validate_service_name(value: &str, messages: &Messages) -> Result<String> {
    validate_dns_label(value).map_err(|err| service_name_error(err, messages))?;
    Ok(value.to_string())
}

fn validate_hostname(value: &str, messages: &Messages) -> Result<String> {
    validate_dns_label(value).map_err(|err| hostname_error(err, messages))?;
    Ok(value.to_string())
}

fn validate_domain(value: &str, messages: &Messages) -> Result<String> {
    validate_domain_name(value).map_err(|err| domain_error(err, messages))?;
    Ok(value.to_string())
}

fn validate_instance_id(value: &str, messages: &Messages) -> Result<String> {
    validate_numeric_instance_id(value).map_err(|err| instance_id_error(err, messages))?;
    Ok(value.to_string())
}

fn service_name_error(err: ValidationError, messages: &Messages) -> anyhow::Error {
    match err {
        ValidationError::Empty => anyhow::anyhow!(messages.error_value_required()),
        ValidationError::InvalidDnsLabel
        | ValidationError::InvalidDomainName
        | ValidationError::InvalidCidr
        | ValidationError::CidrClearConflict
        | ValidationError::NonNumeric => anyhow::anyhow!(messages.error_service_name_invalid()),
    }
}

fn hostname_error(err: ValidationError, messages: &Messages) -> anyhow::Error {
    match err {
        ValidationError::Empty => anyhow::anyhow!(messages.error_value_required()),
        ValidationError::InvalidDnsLabel
        | ValidationError::InvalidDomainName
        | ValidationError::InvalidCidr
        | ValidationError::CidrClearConflict
        | ValidationError::NonNumeric => anyhow::anyhow!(messages.error_hostname_invalid()),
    }
}

fn domain_error(err: ValidationError, messages: &Messages) -> anyhow::Error {
    match err {
        ValidationError::Empty => anyhow::anyhow!(messages.error_value_required()),
        ValidationError::InvalidDnsLabel
        | ValidationError::InvalidDomainName
        | ValidationError::InvalidCidr
        | ValidationError::CidrClearConflict
        | ValidationError::NonNumeric => anyhow::anyhow!(messages.error_domain_invalid()),
    }
}

fn instance_id_error(err: ValidationError, messages: &Messages) -> anyhow::Error {
    match err {
        ValidationError::Empty => anyhow::anyhow!(messages.error_service_instance_id_required()),
        ValidationError::InvalidDnsLabel
        | ValidationError::InvalidDomainName
        | ValidationError::InvalidCidr
        | ValidationError::CidrClearConflict
        | ValidationError::NonNumeric => anyhow::anyhow!(messages.error_instance_id_invalid()),
    }
}

pub(super) fn validate_rn_cidrs(values: &[String], messages: &Messages) -> Result<()> {
    validate_cidr_list(values).map_err(|err| match err {
        ValidationError::CidrClearConflict => {
            anyhow::anyhow!(messages.error_rn_cidrs_clear_conflict())
        }
        ValidationError::InvalidCidr => {
            let bad = values
                .iter()
                .find(|v| *v != "clear" && bootroot::input_validation::validate_cidr(v).is_err())
                .map_or("", String::as_str);
            anyhow::anyhow!(messages.error_rn_cidrs_invalid(bad))
        }
        _ => anyhow::anyhow!(messages.error_rn_cidrs_invalid("")),
    })?;
    Ok(())
}

fn resolve_post_renew_hooks(args: &ServiceAddArgs) -> Result<Vec<PostRenewHookEntry>> {
    resolve_post_renew_hooks_from_parts(&PostRenewHookInputs {
        reload_style: args.reload_style,
        reload_target: args.reload_target.as_deref(),
        post_renew_command: args.post_renew_command.as_deref(),
        post_renew_arg: &args.post_renew_arg,
        post_renew_timeout_secs: args.post_renew_timeout_secs,
        post_renew_on_failure: args.post_renew_on_failure,
    })
}

/// Snapshot of the post-renew hook flags supplied by an operator on
/// either `service add` or `service update`. The fields are borrowed so
/// callers do not have to clone vectors and strings just to drive the
/// shared resolution logic.
pub(super) struct PostRenewHookInputs<'a> {
    pub(super) reload_style: Option<ReloadStyle>,
    pub(super) reload_target: Option<&'a str>,
    pub(super) post_renew_command: Option<&'a str>,
    pub(super) post_renew_arg: &'a [String],
    pub(super) post_renew_timeout_secs: Option<u64>,
    pub(super) post_renew_on_failure: Option<HookFailurePolicyArg>,
}

impl PostRenewHookInputs<'_> {
    /// Reports whether the operator passed any hook-related flag. Used
    /// by `service update` to distinguish "leave hooks as-is" from
    /// "rewrite hooks".
    pub(super) fn any_flag_set(&self) -> bool {
        self.reload_style.is_some()
            || self.reload_target.is_some()
            || self.post_renew_command.is_some()
            || !self.post_renew_arg.is_empty()
            || self.post_renew_timeout_secs.is_some()
            || self.post_renew_on_failure.is_some()
    }
}

/// Resolves the post-renew hook flags into the ordered list persisted to
/// state and rendered into `agent.toml`.
///
/// A `--reload-style` preset and a `--post-renew-command` custom hook may
/// be supplied together in one invocation (issue #702). Because clap
/// collapses each flag into its own field, the relative CLI position
/// between the two forms is unrecoverable, so the emission order is fixed
/// by rule rather than by input order: the **preset entry is pushed
/// first, then the custom-command entry**. Single-form invocations and the
/// existing per-flag validation are unchanged.
pub(super) fn resolve_post_renew_hooks_from_parts(
    inputs: &PostRenewHookInputs<'_>,
) -> Result<Vec<PostRenewHookEntry>> {
    let mut hooks = Vec::new();

    // Preset entry first (deterministic order: preset before custom).
    if let Some(style) = inputs.reload_style {
        hooks.extend(resolve_reload_preset(style, inputs.reload_target)?);
    } else if inputs.reload_target.is_some() {
        anyhow::bail!("--reload-target requires --reload-style");
    }

    // Custom-command entry second.
    if let Some(command) = inputs.post_renew_command {
        if command.trim().is_empty() {
            anyhow::bail!("--post-renew-command must not be empty");
        }
        let timeout = inputs
            .post_renew_timeout_secs
            .unwrap_or(DEFAULT_HOOK_TIMEOUT_SECS);
        if timeout == 0 {
            anyhow::bail!("--post-renew-timeout-secs must be greater than 0");
        }
        let on_failure = inputs.post_renew_on_failure.map_or(
            HookFailurePolicyEntry::default(),
            HookFailurePolicyArg::into_entry,
        );
        hooks.push(PostRenewHookEntry {
            command: command.to_string(),
            args: inputs.post_renew_arg.to_vec(),
            timeout_secs: timeout,
            on_failure,
        });
    } else if !inputs.post_renew_arg.is_empty()
        || inputs.post_renew_timeout_secs.is_some()
        || inputs.post_renew_on_failure.is_some()
    {
        anyhow::bail!(
            "--post-renew-arg, --post-renew-timeout-secs, and --post-renew-on-failure require --post-renew-command"
        );
    }

    Ok(hooks)
}

fn resolve_reload_preset(
    style: ReloadStyle,
    target: Option<&str>,
) -> Result<Vec<PostRenewHookEntry>> {
    match style {
        ReloadStyle::None => Ok(Vec::new()),
        ReloadStyle::Systemd => {
            let unit = target.ok_or_else(|| {
                anyhow::anyhow!("--reload-style systemd requires --reload-target <unit-name>")
            })?;
            Ok(vec![PostRenewHookEntry {
                command: "systemctl".to_string(),
                args: vec!["reload".to_string(), unit.to_string()],
                timeout_secs: DEFAULT_HOOK_TIMEOUT_SECS,
                on_failure: HookFailurePolicyEntry::default(),
            }])
        }
        ReloadStyle::Sighup => {
            let name = target.ok_or_else(|| {
                anyhow::anyhow!("--reload-style sighup requires --reload-target <process-name>")
            })?;
            if name.contains('/') {
                anyhow::bail!(
                    "--reload-target for sighup preset must be a process name, not a path.\n\
                     Got: {name}\n\
                     For path-based matching, use the low-level flags:\n    \
                     --post-renew-command pkill \\\n    \
                     --post-renew-arg -HUP --post-renew-arg -f \\\n    \
                     --post-renew-arg <your-path>"
                );
            }
            Ok(vec![PostRenewHookEntry {
                command: "pkill".to_string(),
                args: vec!["-HUP".to_string(), name.to_string()],
                timeout_secs: DEFAULT_HOOK_TIMEOUT_SECS,
                on_failure: HookFailurePolicyEntry::default(),
            }])
        }
        ReloadStyle::DockerRestart => {
            let container = target.ok_or_else(|| {
                anyhow::anyhow!(
                    "--reload-style docker-restart requires --reload-target <container-name>"
                )
            })?;
            Ok(vec![PostRenewHookEntry {
                command: "docker".to_string(),
                args: vec!["restart".to_string(), container.to_string()],
                timeout_secs: DEFAULT_HOOK_TIMEOUT_SECS,
                on_failure: HookFailurePolicyEntry::default(),
            }])
        }
    }
}

/// Normalizes a local-file `--agent-config` path to an absolute,
/// lexically clean form (no `.`/`..` components) so equivalent
/// spellings of the same file (`agent.toml`, `./agent.toml`,
/// `sub/../agent.toml`) store and compare identically in the
/// one-config-per-service conflict guard. Symlinks are deliberately
/// left unresolved so state keeps the operator's chosen location; the
/// add-time conflict guard additionally canonicalizes existing files
/// when comparing, which covers symlinked spellings.
fn normalize_local_agent_config_path(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)
        .with_context(|| format!("failed to resolve absolute path for {}", path.display()))?;
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            // Lexical `..` handling: `a/b/..` is treated as `a`. A
            // symlinked intermediate directory can defeat this, which
            // the canonicalizing conflict comparison covers for files
            // that exist. Popping at the root is a no-op, matching
            // path resolution semantics for `/..`.
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

fn resolve_path(
    value: Option<PathBuf>,
    label: &str,
    prompt: &mut Prompt<'_>,
    must_exist: bool,
    messages: &Messages,
) -> Result<PathBuf> {
    let path = match value {
        Some(path) => path,
        None => prompt.prompt_with_validation(label, None, |input| {
            let candidate = PathBuf::from(input);
            validate_path(&candidate, must_exist, messages)?;
            Ok(candidate)
        })?,
    };
    validate_path(&path, must_exist, messages)?;
    Ok(path)
}

fn validate_path(path: &Path, must_exist: bool, messages: &Messages) -> Result<()> {
    if must_exist && !path.exists() {
        anyhow::bail!(messages.error_path_not_found(&path.display().to_string()));
    }
    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!(messages.error_parent_not_found(&path.display().to_string()))
    })?;
    // For input paths (`must_exist=true`) the parent must already exist —
    // a read on a missing dir would just produce a less helpful error
    // downstream.  For output paths (`must_exist=false`) `service add` is
    // the authoritative writer, so the parent is `create_dir_all`-ed at
    // the write boundary (`local_config.rs` for `agent_config`,
    // `fs_util::write_cert_and_key` for `cert_path` / `key_path`).
    // Resolution stays side-effect-free so `--dry-run` / `--print-only`
    // do not leak directories onto disk.
    if must_exist && !parent.as_os_str().is_empty() && !parent.exists() {
        anyhow::bail!(messages.error_parent_not_found(&parent.display().to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::cli::args::{AuthMode, RuntimeAuthArgs};

    fn empty_args() -> ServiceAddArgs {
        ServiceAddArgs {
            service_name: None,
            delivery_mode: None,
            dry_run: false,
            print_only: false,
            hostname: None,
            domain: None,
            agent_config: None,
            cert_path: None,
            key_path: None,
            secret_id_path: None,
            instance_id: None,
            agent_email: None,
            agent_server: None,
            agent_responder_url: None,
            runtime_auth: RuntimeAuthArgs {
                auth_mode: AuthMode::Auto,
                root_token: None,
                root_token_file: None,
                approle_role_id: None,
                approle_secret_id: None,
                approle_role_id_file: None,
                approle_secret_id_file: None,
            },
            notes: None,
            reload_style: None,
            reload_target: None,
            post_renew_command: None,
            post_renew_arg: Vec::new(),
            post_renew_timeout_secs: None,
            post_renew_on_failure: None,
            secret_id_ttl: None,
            secret_id_wrap_ttl: None,
            no_wrap: false,
            rn_cidrs: Vec::new(),
            cert_group: None,
        }
    }

    /// Equivalent relative spellings of the same file must normalize
    /// to one absolute path, or the add-time agent-config conflict
    /// guard can be bypassed by re-spelling the path (`./agent.toml`
    /// vs `agent.toml`), letting a second service overwrite the first
    /// service's single `[openbao]` identity.
    #[test]
    fn normalize_local_agent_config_path_unifies_equivalent_spellings() {
        let plain = normalize_local_agent_config_path(Path::new("agent.toml")).unwrap();
        let dotted = normalize_local_agent_config_path(Path::new("./agent.toml")).unwrap();
        let doubled = normalize_local_agent_config_path(Path::new("sub/.././agent.toml")).unwrap();

        assert!(plain.is_absolute(), "normalized path must be absolute");
        assert_eq!(plain, dotted);
        assert_eq!(plain, doubled);
    }

    /// Absolute inputs stay put apart from lexical cleanup, so the
    /// stored `agent_config_path` keeps the operator's chosen
    /// location instead of a symlink-resolved alias.
    #[test]
    fn normalize_local_agent_config_path_cleans_absolute_input() {
        let normalized =
            normalize_local_agent_config_path(Path::new("/etc/bootroot/./sub/../agent.toml"))
                .unwrap();
        assert_eq!(normalized, Path::new("/etc/bootroot/agent.toml"));
    }

    #[test]
    fn resolve_hooks_no_flags_returns_empty() {
        let args = empty_args();
        let hooks = resolve_post_renew_hooks(&args).unwrap();
        assert!(hooks.is_empty());
    }

    /// Issue #702: a `--reload-style` preset and a `--post-renew-command`
    /// custom hook may now be armed in one invocation. They are emitted in
    /// a deterministic order — the preset entry first, then the custom
    /// entry — because clap cannot recover the relative CLI position of the
    /// two flag groups.
    #[test]
    fn resolve_hooks_preset_and_custom_command_emit_both_in_order() {
        let mut args = empty_args();
        args.reload_style = Some(ReloadStyle::DockerRestart);
        args.reload_target = Some("aimer-web-next-app-1".to_string());
        args.post_renew_command = Some("docker".to_string());
        args.post_renew_arg = vec![
            "exec".to_string(),
            "aimer-web-nginx-prod-1".to_string(),
            "nginx".to_string(),
            "-s".to_string(),
            "reload".to_string(),
        ];

        let hooks = resolve_post_renew_hooks(&args).unwrap();
        assert_eq!(hooks.len(), 2, "both hooks must be emitted");

        // Preset entry first.
        assert_eq!(hooks[0].command, "docker");
        assert_eq!(hooks[0].args, vec!["restart", "aimer-web-next-app-1"]);

        // Custom-command entry second.
        assert_eq!(hooks[1].command, "docker");
        assert_eq!(
            hooks[1].args,
            vec!["exec", "aimer-web-nginx-prod-1", "nginx", "-s", "reload"]
        );
    }

    /// The custom hook's per-hook overrides (timeout, on-failure) apply to
    /// the custom entry only; the preset keeps its defaults even when both
    /// are armed together.
    #[test]
    fn resolve_hooks_preset_and_custom_command_apply_overrides_to_custom_only() {
        let mut args = empty_args();
        args.reload_style = Some(ReloadStyle::Systemd);
        args.reload_target = Some("nginx".to_string());
        args.post_renew_command = Some("systemctl".to_string());
        args.post_renew_arg = vec!["reload".to_string(), "next-app".to_string()];
        args.post_renew_timeout_secs = Some(60);
        args.post_renew_on_failure = Some(HookFailurePolicyArg::Stop);

        let hooks = resolve_post_renew_hooks(&args).unwrap();
        assert_eq!(hooks.len(), 2);

        assert_eq!(hooks[0].command, "systemctl");
        assert_eq!(hooks[0].args, vec!["reload", "nginx"]);
        assert_eq!(hooks[0].timeout_secs, DEFAULT_HOOK_TIMEOUT_SECS);
        assert_eq!(hooks[0].on_failure, HookFailurePolicyEntry::Continue);

        assert_eq!(hooks[1].command, "systemctl");
        assert_eq!(hooks[1].args, vec!["reload", "next-app"]);
        assert_eq!(hooks[1].timeout_secs, 60);
        assert_eq!(hooks[1].on_failure, HookFailurePolicyEntry::Stop);
    }

    /// A `--reload-style none` preset contributes no entry, so pairing it
    /// with orphaned low-level flags still surfaces the
    /// "require --post-renew-command" error rather than silently accepting
    /// them.
    #[test]
    fn resolve_hooks_none_preset_with_orphan_arg_errors() {
        let mut args = empty_args();
        args.reload_style = Some(ReloadStyle::None);
        args.post_renew_arg = vec!["reload".to_string()];

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("--post-renew-command"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_reload_target_without_style_errors() {
        let mut args = empty_args();
        args.reload_target = Some("nginx".to_string());

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("--reload-target requires"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_systemd_preset_expands_correctly() {
        let mut args = empty_args();
        args.reload_style = Some(ReloadStyle::Systemd);
        args.reload_target = Some("nginx".to_string());

        let hooks = resolve_post_renew_hooks(&args).unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].command, "systemctl");
        assert_eq!(hooks[0].args, vec!["reload", "nginx"]);
        assert_eq!(hooks[0].timeout_secs, DEFAULT_HOOK_TIMEOUT_SECS);
        assert_eq!(hooks[0].on_failure, HookFailurePolicyEntry::Continue);
    }

    #[test]
    fn resolve_hooks_sighup_preset_expands_correctly() {
        let mut args = empty_args();
        args.reload_style = Some(ReloadStyle::Sighup);
        args.reload_target = Some("myproc".to_string());

        let hooks = resolve_post_renew_hooks(&args).unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].command, "pkill");
        assert_eq!(hooks[0].args, vec!["-HUP", "myproc"]);
    }

    #[test]
    fn resolve_hooks_sighup_preset_rejects_path_like_target() {
        let mut args = empty_args();
        args.reload_style = Some(ReloadStyle::Sighup);
        args.reload_target = Some("review/target/release/review".to_string());

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("must be a process name, not a path"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("review/target/release/review"),
            "error should echo offending value: {msg}"
        );
        assert!(
            msg.contains("--post-renew-arg -f"),
            "error should point to low-level fallback: {msg}"
        );
    }

    #[test]
    fn resolve_hooks_sighup_preset_rejects_absolute_path_target() {
        let mut args = empty_args();
        args.reload_style = Some(ReloadStyle::Sighup);
        args.reload_target = Some("/usr/local/bin/myapp".to_string());

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string()
                .contains("must be a process name, not a path"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_docker_restart_preset_expands_correctly() {
        let mut args = empty_args();
        args.reload_style = Some(ReloadStyle::DockerRestart);
        args.reload_target = Some("my-ctr".to_string());

        let hooks = resolve_post_renew_hooks(&args).unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].command, "docker");
        assert_eq!(hooks[0].args, vec!["restart", "my-ctr"]);
    }

    #[test]
    fn resolve_hooks_none_preset_returns_empty() {
        let mut args = empty_args();
        args.reload_style = Some(ReloadStyle::None);

        let hooks = resolve_post_renew_hooks(&args).unwrap();
        assert!(hooks.is_empty());
    }

    #[test]
    fn resolve_hooks_systemd_without_target_errors() {
        let mut args = empty_args();
        args.reload_style = Some(ReloadStyle::Systemd);

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("--reload-target"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_low_level_with_defaults() {
        let mut args = empty_args();
        args.post_renew_command = Some("/usr/bin/reload.sh".to_string());

        let hooks = resolve_post_renew_hooks(&args).unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].command, "/usr/bin/reload.sh");
        assert!(hooks[0].args.is_empty());
        assert_eq!(hooks[0].timeout_secs, DEFAULT_HOOK_TIMEOUT_SECS);
        assert_eq!(hooks[0].on_failure, HookFailurePolicyEntry::Continue);
    }

    #[test]
    fn resolve_hooks_low_level_with_all_overrides() {
        let mut args = empty_args();
        args.post_renew_command = Some("systemctl".to_string());
        args.post_renew_arg = vec!["reload".to_string(), "nginx".to_string()];
        args.post_renew_timeout_secs = Some(60);
        args.post_renew_on_failure = Some(HookFailurePolicyArg::Stop);

        let hooks = resolve_post_renew_hooks(&args).unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].command, "systemctl");
        assert_eq!(hooks[0].args, vec!["reload", "nginx"]);
        assert_eq!(hooks[0].timeout_secs, 60);
        assert_eq!(hooks[0].on_failure, HookFailurePolicyEntry::Stop);
    }

    #[test]
    fn resolve_hooks_empty_command_is_rejected() {
        let mut args = empty_args();
        args.post_renew_command = Some(String::new());

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_whitespace_only_command_is_rejected() {
        let mut args = empty_args();
        args.post_renew_command = Some("   ".to_string());

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_zero_timeout_is_rejected() {
        let mut args = empty_args();
        args.post_renew_command = Some("reload.sh".to_string());
        args.post_renew_timeout_secs = Some(0);

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("greater than 0"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_post_renew_arg_without_command_errors() {
        let mut args = empty_args();
        args.post_renew_arg = vec!["reload".to_string()];

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("--post-renew-command"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_post_renew_timeout_without_command_errors() {
        let mut args = empty_args();
        args.post_renew_timeout_secs = Some(60);

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("--post-renew-command"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_post_renew_on_failure_without_command_errors() {
        let mut args = empty_args();
        args.post_renew_on_failure = Some(HookFailurePolicyArg::Stop);

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("--post-renew-command"),
            "unexpected error: {err}"
        );
    }

    /// Issue #607: `service add` output paths must accept a non-existent
    /// parent so the operator does not have to keep an out-of-band
    /// `mkdir -p` chain in sync with the flag values. The directory gets
    /// created at the write boundary (`local_config.rs` and
    /// `fs_util::write_cert_and_key`) rather than here, so resolution
    /// stays side-effect-free for `--dry-run` / `--print-only`.
    #[test]
    fn validate_path_allows_missing_parent_when_must_exist_is_false() {
        let messages = Messages::new("en").unwrap();
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("does/not/exist/agent.toml");
        assert!(!target.parent().unwrap().exists());

        validate_path(&target, false, &messages).expect("missing parent must be accepted");
        assert!(
            !target.parent().unwrap().exists(),
            "validate_path must not create directories on disk"
        );
    }

    #[test]
    fn validate_path_rejects_missing_parent_when_must_exist_is_true() {
        let messages = Messages::new("en").unwrap();
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("does/not/exist/input.pem");

        let err = validate_path(&target, true, &messages).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not found"),
            "expected a not-found error, got: {msg}"
        );
    }

    #[test]
    fn validate_path_accepts_existing_parent_when_must_exist_is_false() {
        let messages = Messages::new("en").unwrap();
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("agent.toml");

        validate_path(&target, false, &messages).expect("existing parent must be accepted");
    }

    #[test]
    fn resolve_secret_id_path_override_none_is_ok() {
        let messages = Messages::new("en").unwrap();
        assert!(
            resolve_secret_id_path_override(None, DeliveryMode::LocalFile, &messages)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn resolve_secret_id_path_override_rejects_remote_bootstrap() {
        let messages = Messages::new("en").unwrap();
        let err = resolve_secret_id_path_override(
            Some(Path::new("/etc/agent/svc/secret_id")),
            DeliveryMode::RemoteBootstrap,
            &messages,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("only honoured for local-file delivery")
        );
    }

    #[test]
    fn resolve_secret_id_path_override_rejects_relative() {
        let messages = Messages::new("en").unwrap();
        let err = resolve_secret_id_path_override(
            Some(Path::new("relative/secret_id")),
            DeliveryMode::LocalFile,
            &messages,
        )
        .unwrap_err();
        assert!(err.to_string().contains("must be an absolute path"));
    }

    #[test]
    fn resolve_secret_id_path_override_rejects_role_id_final_component() {
        let messages = Messages::new("en").unwrap();
        let err = resolve_secret_id_path_override(
            Some(Path::new("/etc/agent/svc/role_id")),
            DeliveryMode::LocalFile,
            &messages,
        )
        .unwrap_err();
        assert!(err.to_string().contains("must not end in `role_id`"));
    }

    #[test]
    fn resolve_secret_id_path_override_accepts_absolute_local_file() {
        let messages = Messages::new("en").unwrap();
        let resolved = resolve_secret_id_path_override(
            Some(Path::new("/etc/agent/svc/secret_id")),
            DeliveryMode::LocalFile,
            &messages,
        )
        .unwrap();
        assert_eq!(
            resolved.as_deref(),
            Some(Path::new("/etc/agent/svc/secret_id"))
        );
    }

    #[test]
    fn validate_secret_id_path_override_none_is_ok() {
        let messages = Messages::new("en").unwrap();
        validate_secret_id_path_override(None, Path::new("/var/lib/bootroot/secrets"), &messages)
            .unwrap();
    }

    #[test]
    fn validate_secret_id_path_override_rejects_inside_secrets_dir() {
        let messages = Messages::new("en").unwrap();
        let secrets_dir = Path::new("/var/lib/bootroot/secrets");
        let inside = secrets_dir.join("services/foo/secret_id");
        let err =
            validate_secret_id_path_override(Some(&inside), secrets_dir, &messages).unwrap_err();
        assert!(
            err.to_string()
                .contains("must resolve outside the root-owned secrets tree")
        );
    }

    #[test]
    fn validate_secret_id_path_override_rejects_missing_parent() {
        let messages = Messages::new("en").unwrap();
        let dir = tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        let missing = dir.path().join("no-such-dir").join("secret_id");
        let err =
            validate_secret_id_path_override(Some(&missing), &secrets_dir, &messages).unwrap_err();
        assert!(err.to_string().contains("parent directory does not exist"));
    }

    #[test]
    fn validate_secret_id_path_override_accepts_outside_with_existing_parent() {
        let messages = Messages::new("en").unwrap();
        let dir = tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        let agent_dir = dir.path().join("agent").join("svc");
        std::fs::create_dir_all(&agent_dir).unwrap();
        let target = agent_dir.join("secret_id");
        validate_secret_id_path_override(Some(&target), &secrets_dir, &messages).unwrap();
    }

    #[test]
    fn validate_secret_id_path_override_rejects_symlinked_parent_into_secrets_dir() {
        let messages = Messages::new("en").unwrap();
        let dir = tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        let inside = secrets_dir.join("services/foo");
        std::fs::create_dir_all(&inside).unwrap();
        // A parent spelled outside the tree but symlinked into it: the
        // lexical check passes, but canonicalization must still reject it.
        let link = dir.path().join("agent-link");
        std::os::unix::fs::symlink(&inside, &link).unwrap();
        let target = link.join("secret_id");
        let err =
            validate_secret_id_path_override(Some(&target), &secrets_dir, &messages).unwrap_err();
        assert!(
            err.to_string()
                .contains("must resolve outside the root-owned secrets tree")
        );
    }

    #[test]
    fn effective_wrap_ttl_none_returns_default() {
        assert_eq!(effective_wrap_ttl(None), Some("30m"));
    }

    #[test]
    fn effective_wrap_ttl_custom_returns_custom() {
        assert_eq!(effective_wrap_ttl(Some("10m")), Some("10m"));
    }

    #[test]
    fn effective_wrap_ttl_zero_disables_wrapping() {
        assert_eq!(effective_wrap_ttl(Some("0")), None);
    }
}
