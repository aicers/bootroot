//! The install side of the shared audit store: reading where it is,
//! creating it as root, and binding `OpenBao`'s file audit device into
//! it through a rendered Compose override.
//!
//! `[registrar] audit_store_dir` in the operator's `bootroot-agent`
//! configuration file is the **only** definition of where the store is.
//! Nothing here records a second copy of it — not `state.json`, not a
//! flag, not an environment variable — because both writers must
//! resolve into one directory, and two values that can drift are two
//! directories waiting to happen. That is why `bootroot init` takes
//! `--agent-config` and why `bootroot infra up` reads the bind source
//! back out of the rendered override rather than resolving it again.
//!
//! Only the `OpenBao` device actually starts writing here. The daemon's
//! verb records do not: nothing in this build constructs a record
//! store, and what this module delivers for that half is the empty
//! `records/` directory the store's trust checks accept.
//!
//! Nothing here enforces `audit_store_reserve_bytes`; the budget stays
//! a number in this build.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::registrar::audit_store::{
    AuditStoreLayoutError, PRODUCTION_UID, STORE_DIR_MODE, check_ancestors, check_store_directory,
    create_layout,
};
use serde::Deserialize;

use crate::commands::init::OPENBAO_AUDIT_COMPOSE_OVERRIDE_NAME;
use crate::i18n::Messages;
use crate::state::StateFile;

/// The container path `openbao/openbao.hcl` writes its file audit
/// device to. Unchanged by this override — only what backs it moves.
const OPENBAO_AUDIT_CONTAINER_PATH: &str = "/openbao/audit";

/// The `openbao` service's other two mounts, re-declared verbatim
/// because `!override` replaces the whole list and dropping one would
/// silently unmount `OpenBao`'s storage or its configuration.
const OPENBAO_DATA_MOUNT: &str = "openbao-data:/openbao/file";
const OPENBAO_CONFIG_MOUNT: &str = "./openbao:/openbao/config:ro";

/// Mode a freshly rendered override is created at.
const OVERRIDE_FILE_MODE: u32 = 0o644;

/// The `[registrar]` and `[registrar_endpoint]` halves of the
/// operator's configuration file, and nothing else.
///
/// Both tables are deserialized under exactly the daemon's structural
/// rules — same fields, same defaults, same `deny_unknown_fields` —
/// because both are the daemon's own types rather than copies. A file
/// the daemon would refuse to parse is refused here too.
///
/// Reusing [`bootroot::config::RegistrarEndpointSettings`] deliberately
/// does **not** import the daemon's platform rule for it: that rule
/// lives in a private, unexported `fn` of the library crate, so the
/// install side has no way to call it. The split is guaranteed by the
/// module boundary rather than by an instruction someone has to
/// remember — an installer is not a process about to listen.
///
/// Unknown *tables* are ignored rather than fought with: `[[profiles]]`,
/// `[acme]` and the rest belong to the daemon, and demanding a complete
/// daemon configuration to learn one path and one boolean is not an
/// installer's business.
#[derive(Debug, Deserialize)]
struct AgentConfigPartial {
    #[serde(default)]
    registrar: bootroot::config::RegistrarSettings,
    #[serde(default)]
    registrar_endpoint: bootroot::config::RegistrarEndpointSettings,
}

/// The two readings `--agent-config` carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentConfigView {
    /// `[registrar] audit_store_dir`, already validated.
    pub(crate) audit_store_dir: PathBuf,
    /// `[registrar_endpoint] enabled`, read as a plain field with no
    /// semantic rule applied.
    pub(crate) endpoint_enabled: bool,
}

/// Reads the two tables `init` needs out of the operator's
/// `bootroot-agent` configuration file.
///
/// Deliberately not [`bootroot::config::Settings::new`]: that requires
/// a non-empty `[[profiles]]` block, and not
/// `Settings::file_builder` either, which marks the file
/// `required(false)` so a nonexistent path would silently deserialize
/// into defaults instead of failing.
///
/// # Errors
///
/// Reading, parsing, deserializing and validating are four distinct
/// failures and each carries its own message naming the path and the
/// underlying error. A file with no `[registrar]` table is not one of
/// them: the documented defaults apply, because that is the daemon's
/// own configuration stating them.
pub(crate) fn load_agent_config(path: &Path, messages: &Messages) -> Result<AgentConfigView> {
    let display = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|err| {
        anyhow::anyhow!(
            messages.error_audit_store_agent_config_unreadable(&display, &err.to_string())
        )
    })?;
    let built = config::Config::builder()
        .add_source(config::File::from_str(&text, config::FileFormat::Toml))
        .build()
        .map_err(|err| {
            anyhow::anyhow!(
                messages.error_audit_store_agent_config_malformed(&display, &err.to_string())
            )
        })?;
    let partial: AgentConfigPartial = built.try_deserialize().map_err(|err| {
        anyhow::anyhow!(
            messages.error_audit_store_agent_config_undeserializable(&display, &err.to_string())
        )
    })?;
    bootroot::config::validate_registrar_settings(&partial.registrar).map_err(|err| {
        anyhow::anyhow!(
            messages.error_audit_store_agent_config_rejected(&display, &err.to_string())
        )
    })?;
    Ok(AgentConfigView {
        audit_store_dir: partial.registrar.audit_store_dir,
        endpoint_enabled: partial.registrar_endpoint.enabled,
    })
}

/// Returns the rendered audit override's path under `compose_dir`.
///
/// Its own name, alongside and independent of the exposed-port
/// override: that one rewrites `ports:` and this one rewrites
/// `volumes:`, so the two compose without interacting and both may be
/// passed with `-f` in one invocation.
#[must_use]
pub(crate) fn audit_override_path(compose_dir: &Path) -> PathBuf {
    compose_dir
        .join("secrets")
        .join("openbao")
        .join(OPENBAO_AUDIT_COMPOSE_OVERRIDE_NAME)
}

/// Renders the override that replaces the `openbao` service's
/// `volumes:` list so `/openbao/audit` is a bind mount of
/// `<audit_store_dir>/openbao`.
///
/// `!override` and not `!reset`: `!reset` discards the new value and
/// removes the attribute entirely, which would leave `OpenBao` with no
/// mounts at all.
///
/// The directory and the file both take the secrets tree's ownership
/// rather than the writing process's, because this is the one override
/// a **root-run** `bootroot init` renders and an unprivileged
/// `bootroot infra up` reads back. It also lands in
/// `<compose dir>/secrets/openbao` — the directory both `OpenBao` Agent
/// sidecars run out of, and which every other writer reaches through
/// [`fs_util::ensure_shared_secrets_dir`] for exactly this reason. A
/// `0700` level created under root's own uid is one neither the
/// sidecars nor the operator can traverse, and it is created here
/// first: this call runs before any other step of `init` touches the
/// tree, so whatever owner it establishes is the one every later level
/// inherits.
///
/// # Errors
///
/// Returns an error when the store directory cannot be spelled as a
/// Compose bind source, or when the directory or the file cannot be
/// written.
pub(crate) fn write_audit_override(
    compose_dir: &Path,
    store_dir: &Path,
    messages: &Messages,
) -> Result<PathBuf> {
    let bind_source = bootroot::registrar::audit_store::openbao_dir(store_dir);
    let content = render_audit_override(&bind_source, messages)?;
    let override_path = audit_override_path(compose_dir);
    let override_dir = override_path
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();
    fs_util::ensure_shared_secrets_dir_blocking(&override_dir)
        .with_context(|| messages.error_write_file_failed(&override_dir.display().to_string()))?;
    // `PreserveOrCreate`: a fresh file gets exactly this mode whatever
    // root's umask is, while an operator who narrowed the destination by
    // hand keeps that choice. The file carries one host path and nothing
    // secret.
    fs_util::atomic_replace_dir_owner_blocking(
        fs_util::Destination::operator_named(&override_path),
        content.as_bytes(),
        fs_util::StagedMode::PreserveOrCreate(OVERRIDE_FILE_MODE),
    )
    .with_context(|| messages.error_write_file_failed(&override_path.display().to_string()))?;
    Ok(override_path)
}

/// The rendered override's bytes for a given bind source.
///
/// Quoting settles what YAML reads back, but not what Compose then
/// makes of the scalar: it splits a bind mount's value on `:` into
/// source, target and mode, so a colon anywhere in the store's path
/// moves the boundary rather than travelling inside it. Both that and a
/// control character are refused here, before the override is rendered
/// and before any Docker call, rather than surfacing as a mount error
/// from a `docker compose` invocation two steps later.
fn render_audit_override(bind_source: &Path, messages: &Messages) -> Result<String> {
    let raw = bind_source.to_string_lossy();
    if raw.chars().any(|ch| ch.is_control() || ch == ':') {
        anyhow::bail!(messages.error_audit_store_dir_unrenderable(&raw));
    }
    let mount = compose_quote(&format!("{raw}:{OPENBAO_AUDIT_CONTAINER_PATH}"));
    Ok(format!(
        "\
services:
  openbao:
    volumes: !override
      - {OPENBAO_DATA_MOUNT}
      - {mount}
      - {OPENBAO_CONFIG_MOUNT}
"
    ))
}

/// Spells `value` as a YAML single-quoted scalar Compose reads back
/// verbatim.
///
/// A single quote is escaped by doubling it, which is YAML's own rule,
/// and a `$` is doubled because Compose interpolates `${...}` in every
/// value it reads.
fn compose_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''").replace('$', "$$"))
}

/// Reverses [`compose_quote`].
fn compose_unquote(value: &str) -> String {
    let inner = match value
        .strip_prefix('\'')
        .and_then(|rest| rest.strip_suffix('\''))
    {
        Some(quoted) => quoted.replace("''", "'"),
        None => value.trim_matches('"').to_string(),
    };
    inner.replace("$$", "$")
}

/// Reads the audit store directory back out of a rendered override.
///
/// The override file is the record of what `init` resolved, which is
/// what lets `bootroot infra up` bind the same store without reading
/// the daemon's configuration at all.
///
/// # Errors
///
/// Returns an error when the file cannot be read, or when it declares
/// no bind mount at the audit device's container path.
pub(crate) fn read_audit_override_store_dir(
    override_path: &Path,
    messages: &Messages,
) -> Result<PathBuf> {
    let display = override_path.display().to_string();
    let content = std::fs::read_to_string(override_path)
        .with_context(|| messages.error_read_file_failed(&display))?;
    let suffix = format!(":{OPENBAO_AUDIT_CONTAINER_PATH}");
    let bind_source = collect_openbao_volume_entries(&content)
        .into_iter()
        .find_map(|entry| {
            // Unquote first: the bind source is rendered as a
            // single-quoted scalar, so the container path is inside the
            // quotes rather than beside them.
            let unquoted = compose_unquote(entry.trim());
            unquoted.strip_suffix(suffix.as_str()).map(PathBuf::from)
        })
        .ok_or_else(|| anyhow::anyhow!(messages.error_audit_store_override_unreadable(&display)))?;
    // The bind source is `<audit_store_dir>/openbao` by construction,
    // so its parent is the store directory. `infra up` holds *that* to
    // the store directory contract: resolving the bind source itself
    // needs search permission on a root-owned `0700` directory, so an
    // unprivileged `lstat` of it returns `EACCES` on every correctly
    // provisioned host.
    bind_source
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!(messages.error_audit_store_override_unreadable(&display)))
}

/// Collects the `openbao` service's raw `volumes:` entries, with any
/// surrounding YAML quoting left on.
fn collect_openbao_volume_entries(compose: &str) -> Vec<String> {
    let mut entries = Vec::new();
    let mut in_service = false;
    let mut service_indent = 0usize;
    let mut in_volumes = false;
    let mut volumes_indent = 0usize;

    for line in compose.lines() {
        let indent = line.chars().take_while(|ch| ch.is_whitespace()).count();
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if in_service && indent <= service_indent && !trimmed.starts_with('-') {
            in_service = false;
            in_volumes = false;
        }

        if !in_service && trimmed == "openbao:" {
            in_service = true;
            service_indent = indent;
            in_volumes = false;
            continue;
        }

        if !in_service {
            continue;
        }

        if !in_volumes && (trimmed == "volumes:" || trimmed.starts_with("volumes:")) {
            in_volumes = true;
            volumes_indent = indent;
            continue;
        }

        if in_volumes && indent <= volumes_indent {
            in_volumes = false;
            continue;
        }

        if in_volumes && trimmed.starts_with('-') {
            let value = trimmed.trim_start_matches('-').trim();
            if !value.is_empty() {
                entries.push(value.to_string());
            }
        }
    }

    entries
}

/// Which command a store-directory refusal is being reported from.
///
/// The fault is the same either way; the remedy differs, because
/// `bootroot init` is the one command in this flow that runs as root.
#[derive(Clone, Copy)]
pub(crate) enum StoreCheckCaller {
    /// A root-run `bootroot init`, which provisions.
    Init,
    /// An unprivileged `bootroot infra up`, which only selects.
    InfraUp,
}

/// Renders a layout refusal through the translated catalog.
pub(crate) fn layout_error_message(
    error: &AuditStoreLayoutError,
    caller: StoreCheckCaller,
    expected_uid: u32,
    messages: &Messages,
) -> String {
    let path = error.path().display().to_string();
    match error {
        AuditStoreLayoutError::Ancestor { fault, .. } => {
            messages.error_audit_store_ancestor_invalid(&path, &messages.audit_store_fault(*fault))
        }
        AuditStoreLayoutError::OpenBaoDirectory { fault, .. } => {
            messages.error_audit_store_openbao_invalid(&path, &messages.audit_store_fault(*fault))
        }
        AuditStoreLayoutError::StoreDirectory { fault, .. } => {
            let found = messages.audit_store_fault(*fault);
            match caller {
                StoreCheckCaller::Init => messages.error_audit_store_dir_invalid(
                    &path,
                    &found,
                    expected_uid,
                    STORE_DIR_MODE,
                ),
                StoreCheckCaller::InfraUp => messages.error_audit_store_dir_unusable(
                    &path,
                    &found,
                    expected_uid,
                    STORE_DIR_MODE,
                ),
            }
        }
        AuditStoreLayoutError::Inspect { source, .. }
        | AuditStoreLayoutError::CreateDirectory { source, .. } => match caller {
            StoreCheckCaller::Init => {
                messages.error_audit_store_layout_failed(&path, &source.to_string())
            }
            // An unprivileged bring-up that cannot even `lstat` the
            // store is not "not provisioned": the ancestor rule
            // guarantees the store directory is reachable without
            // privilege, so an `EACCES` here is a host whose store is
            // not where `bootroot init` would have put it.
            StoreCheckCaller::InfraUp => messages.error_audit_store_dir_unusable(
                &path,
                &source.to_string(),
                expected_uid,
                STORE_DIR_MODE,
            ),
        },
    }
}

/// Everything `bootroot init` needs to decide what to do about the
/// audit store on this run.
pub(crate) struct AuditStoreInitInputs<'a> {
    /// The directory the compose file sits in, under which the
    /// override is rendered.
    pub(crate) compose_dir: &'a Path,
    /// The operator's `bootroot-agent` configuration file, when
    /// `--agent-config` was supplied.
    pub(crate) agent_config: Option<&'a Path>,
    /// `state.json`'s path, named in the disagreement error.
    pub(crate) state_path: &'a Path,
    /// The recorded predicate, read through the same
    /// `registrar_endpoint_intent` that forces TLS on `:8200` and
    /// publishes the internal credential.
    pub(crate) endpoint_recorded: bool,
    /// The uid the store directory and its record subdirectory must be
    /// owned by. Production passes 0; a test passes its own uid.
    pub(crate) expected_uid: u32,
}

/// What a run will do about the audit store, decided before anything is
/// created, rendered or deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuditStorePlan {
    /// Nothing to provision and nothing to unwind: the ordinary
    /// non-endpoint host.
    Idle,
    /// Both sources agree the endpoint is off and a rendered override is
    /// on disk, so that file goes. The store directories and everything
    /// in them are left exactly as they are: switching a host off
    /// changes what is mounted, never what is stored.
    Unwind(PathBuf),
    /// Provision the store at this directory and render the override.
    Provision(PathBuf),
}

/// Decides what this run does about the audit store, creating,
/// rendering and deleting nothing.
///
/// Every refusal `bootroot init` makes before it touches the filesystem
/// lives here — the required flag, the four load failures, the
/// enablement cross-check, the caller's own uid and the stale override
/// — so a caller with a destructive step of its own can raise them
/// ahead of that step rather than after it. [`apply_audit_store`] is
/// this plus the acting.
///
/// # Errors
///
/// Returns an error when `--agent-config` is required and absent, when
/// the file cannot be loaded, when the two recorded enablement values
/// disagree, when a run that would provision is not running as
/// `expected_uid`, or when a rendered override names a different store
/// than the configuration now resolves.
fn plan_audit_store(
    inputs: &AuditStoreInitInputs<'_>,
    messages: &Messages,
) -> Result<AuditStorePlan> {
    let override_path = audit_override_path(inputs.compose_dir);
    let rendered_present = override_path.exists();

    // A rendered override makes the flag mandatory even on a host whose
    // predicate is off, which keeps the deletion of an override from
    // being the one operation that never reads the daemon's
    // configuration.
    let Some(agent_config) = inputs.agent_config else {
        if inputs.endpoint_recorded || rendered_present {
            anyhow::bail!(messages.error_audit_store_agent_config_required());
        }
        return Ok(AuditStorePlan::Idle);
    };

    let view = load_agent_config(agent_config, messages)?;
    if view.endpoint_enabled != inputs.endpoint_recorded {
        anyhow::bail!(messages.error_audit_store_enablement_mismatch(
            &inputs.state_path.display().to_string(),
            inputs.endpoint_recorded,
            &agent_config.display().to_string(),
            view.endpoint_enabled,
        ));
    }

    if !inputs.endpoint_recorded {
        return Ok(if rendered_present {
            AuditStorePlan::Unwind(override_path)
        } else {
            AuditStorePlan::Idle
        });
    }

    // Refuse an unprivileged provisioning run *before* `create_layout`
    // has a chance to create anything. The layout is created owned by
    // whichever process creates it, so a non-root run would build
    // `audit_store_dir` and `records/` under the caller's own uid and
    // only then fail its own owner check — leaving behind a store that
    // the later, correct root run refuses as foreign-owned and
    // deliberately does not repair. Comparing against `expected_uid`
    // rather than against a literal 0 keeps the rule identical to the
    // one the layout checks apply, so a test running under its own uid
    // provisions exactly as production does under 0.
    let running_uid = fs_util::current_process_euid();
    if running_uid != inputs.expected_uid {
        anyhow::bail!(messages.error_audit_store_not_privileged(
            &view.audit_store_dir.display().to_string(),
            inputs.expected_uid,
            running_uid,
        ));
    }

    if rendered_present {
        let rendered_store = read_audit_override_store_dir(&override_path, messages)?;
        if rendered_store != view.audit_store_dir {
            anyhow::bail!(messages.error_audit_store_override_stale(
                &rendered_store.display().to_string(),
                &view.audit_store_dir.display().to_string(),
            ));
        }
    }

    Ok(AuditStorePlan::Provision(view.audit_store_dir))
}

/// Raises every refusal an `init` would raise about the audit store,
/// without creating, rendering or deleting anything.
///
/// `bootroot reinit` re-runs `init`, but only after it has removed the
/// `OpenBao` container and its volumes. A refusal raised for the first
/// time by that second pass would land after the wipe — the partial-init
/// trap reinit exists to recover from — so reinit raises them here
/// instead, beside its other pre-wipe preflights. Every check below is
/// a read, so running it twice costs nothing and decides nothing.
///
/// # Errors
///
/// Returns the same errors as [`apply_audit_store`], except those that
/// only a write can produce, plus the missing-override refusal the
/// bring-up between the wipe and the init pass would raise.
pub(crate) fn preflight_audit_store(
    inputs: &AuditStoreInitInputs<'_>,
    messages: &Messages,
) -> Result<()> {
    if let AuditStorePlan::Provision(store_dir) = plan_audit_store(inputs, messages)? {
        // The ancestor chain is the one remaining refusal `create_layout`
        // makes before it creates anything, and it is a pure read too.
        check_ancestors(&store_dir).map_err(|err| {
            anyhow::anyhow!(layout_error_message(
                &err,
                StoreCheckCaller::Init,
                inputs.expected_uid,
                messages
            ))
        })?;
        // Reinit brings the stack back up *before* it re-runs `init`,
        // and that bring-up gates on the recorded predicate alone: with
        // it enabled it requires the rendered override, which the init
        // pass has not written yet on a host that has never provisioned
        // one. Saying so here costs a read; leaving it to the bring-up
        // costs the wipe. Rendering it instead is not the answer — the
        // store it names has to be created by the root-run init pass,
        // and this preflight writes nothing.
        if !audit_override_path(inputs.compose_dir).exists() {
            anyhow::bail!(messages.error_audit_store_override_missing());
        }
    }
    Ok(())
}

/// Provisions the audit store, or unwinds it, and returns the override
/// to put on the Compose command line.
///
/// The order below is normative rather than incidental. Every preflight
/// refusal — the uid check and the stale-override check in
/// [`plan_audit_store`], then the ancestor-chain check inside
/// [`create_layout`] — runs before anything is created, rendered or
/// recreated, so a refused run leaves the store and the running mount
/// exactly as it found them.
///
/// # Errors
///
/// Returns an error when `--agent-config` is required and absent, when
/// the file cannot be loaded, when the two recorded enablement values
/// disagree, when the run is not privileged enough to create a store
/// owned by `expected_uid`, when a rendered override names a different
/// store than the configuration now resolves, or when the layout cannot
/// be created or fails its checks.
pub(crate) fn apply_audit_store(
    inputs: &AuditStoreInitInputs<'_>,
    messages: &Messages,
) -> Result<Option<PathBuf>> {
    match plan_audit_store(inputs, messages)? {
        AuditStorePlan::Idle => Ok(None),
        AuditStorePlan::Unwind(override_path) => {
            std::fs::remove_file(&override_path).with_context(|| {
                messages.error_write_file_failed(&override_path.display().to_string())
            })?;
            Ok(None)
        }
        AuditStorePlan::Provision(store_dir) => {
            create_layout(&store_dir, inputs.expected_uid).map_err(|err| {
                anyhow::anyhow!(layout_error_message(
                    &err,
                    StoreCheckCaller::Init,
                    inputs.expected_uid,
                    messages
                ))
            })?;
            let rendered = write_audit_override(inputs.compose_dir, &store_dir, messages)?;
            Ok(Some(rendered))
        }
    }
}

/// Resolves the audit override for a bring-up, checking only what an
/// unprivileged process can.
///
/// Gates on `state.json`'s recorded predicate and nothing else, and
/// reads no configuration: the rendered override names its own bind
/// source, so it is the record of what `init` resolved. Creates
/// nothing, writes no state, and never descends into the store —
/// establishing what is inside it is `bootroot init`'s job and
/// re-checking it at open time is the record store's.
///
/// # Errors
///
/// Returns an error naming `bootroot init` when the predicate is
/// recorded and the override is missing, unreadable, or names a store
/// directory that departs from the store directory contract.
pub(crate) fn resolve_audit_override(
    state_path: &Path,
    compose_dir: &Path,
    expected_uid: u32,
    messages: &Messages,
) -> Result<Option<PathBuf>> {
    if !state_path.exists() {
        return Ok(None);
    }
    let state = StateFile::load(state_path)?;
    if !state
        .registrar_endpoint
        .as_ref()
        .is_some_and(|recorded| recorded.enabled)
    {
        return Ok(None);
    }
    let override_path = audit_override_path(compose_dir);
    if !override_path.exists() {
        anyhow::bail!(messages.error_audit_store_override_missing());
    }
    let store_dir = read_audit_override_store_dir(&override_path, messages)?;
    check_store_directory(&store_dir, expected_uid).map_err(|err| {
        anyhow::anyhow!(layout_error_message(
            &err,
            StoreCheckCaller::InfraUp,
            expected_uid,
            messages
        ))
    })?;
    Ok(Some(override_path))
}

/// The uid a production run requires the store to be owned by.
#[must_use]
pub(crate) fn production_uid() -> u32 {
    PRODUCTION_UID
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    use bootroot::fs_util::current_process_euid;
    use bootroot::registrar::audit_store::{OPENBAO_SUBDIR, RECORDS_SUBDIR};
    use tempfile::TempDir;

    use super::*;
    use crate::i18n::test_messages;
    use crate::state::RegistrarEndpointState;

    const AGENT_CONFIG_NAME: &str = "agent.toml";

    /// A temporary directory every ancestor of which is world
    /// traversable; see the twin helper in the library layout module
    /// for why the platform default will not do.
    fn traversable_tempdir() -> TempDir {
        let base = Path::new("/tmp")
            .canonicalize()
            .expect("the physical /tmp resolves");
        let dir = tempfile::Builder::new()
            .prefix("bootroot-audit-store-cmd")
            .tempdir_in(base)
            .expect("temporary directory");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755))
            .expect("world-traversable base");
        dir
    }

    fn write_agent_config(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join(AGENT_CONFIG_NAME);
        fs::write(&path, body).expect("agent config");
        path
    }

    fn write_state(dir: &Path, endpoint: Option<bool>) -> PathBuf {
        let path = dir.join("state.json");
        let state = StateFile {
            registrar_endpoint: endpoint.map(|enabled| RegistrarEndpointState {
                enabled,
                domain: "example.com".to_string(),
                host: "host".to_string(),
            }),
            ..StateFile::default()
        };
        state.save(&path).expect("state.json");
        path
    }

    struct Fixture {
        base: TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let base = traversable_tempdir();
            fs::create_dir(base.path().join("compose")).expect("compose dir");
            Self { base }
        }

        fn compose_dir(&self) -> PathBuf {
            self.base.path().join("compose")
        }

        fn store_dir(&self) -> PathBuf {
            self.base.path().join("audit-store")
        }

        fn agent_config(&self, enabled: bool) -> PathBuf {
            self.agent_config_for(&self.store_dir(), enabled)
        }

        fn agent_config_for(&self, store_dir: &Path, enabled: bool) -> PathBuf {
            write_agent_config(
                self.base.path(),
                &format!(
                    "[registrar]\naudit_store_dir = \"{}\"\n\n[registrar_endpoint]\nenabled = {enabled}\n",
                    store_dir.display()
                ),
            )
        }

        fn state(&self, endpoint: Option<bool>) -> PathBuf {
            write_state(self.base.path(), endpoint)
        }

        fn inputs<'a>(
            agent_config: Option<&'a Path>,
            state_path: &'a Path,
            endpoint_recorded: bool,
            compose_dir: &'a Path,
        ) -> AuditStoreInitInputs<'a> {
            AuditStoreInitInputs {
                compose_dir,
                agent_config,
                state_path,
                endpoint_recorded,
                expected_uid: current_process_euid(),
            }
        }
    }

    // ---------------------------------------------------------------
    // Partial-file load
    // ---------------------------------------------------------------

    #[test]
    fn a_registrar_only_file_resolves_without_a_profiles_block() {
        let dir = traversable_tempdir();
        let path = write_agent_config(
            dir.path(),
            "[registrar]\naudit_store_dir = \"/srv/bootroot/audit-store\"\n",
        );
        let view = load_agent_config(&path, &test_messages()).expect("loads");
        assert_eq!(
            view.audit_store_dir,
            PathBuf::from("/srv/bootroot/audit-store")
        );
        assert!(!view.endpoint_enabled);
    }

    #[test]
    fn a_file_without_a_registrar_table_yields_the_documented_defaults() {
        let dir = traversable_tempdir();
        let path = write_agent_config(dir.path(), "[acme]\ndirectory_url = \"https://ca/acme\"\n");
        let view = load_agent_config(&path, &test_messages()).expect("loads");
        assert_eq!(
            view.audit_store_dir,
            bootroot::config::RegistrarSettings::default().audit_store_dir
        );
        assert!(!view.endpoint_enabled);
    }

    #[test]
    fn an_absent_or_empty_endpoint_table_reads_as_disabled() {
        let dir = traversable_tempdir();
        for body in ["[registrar]\n", "[registrar]\n\n[registrar_endpoint]\n"] {
            let path = write_agent_config(dir.path(), body);
            let view = load_agent_config(&path, &test_messages()).expect("loads");
            assert!(!view.endpoint_enabled, "unexpected reading of {body:?}");
        }
    }

    #[test]
    fn an_enabled_endpoint_loads_with_no_semantic_rule_applied() {
        // The daemon's own validation rejects an enabled endpoint off
        // Linux. Nothing in the install path can apply that rule:
        // `validate_registrar_endpoint_settings` is private to the
        // library crate and is not among the items re-exported from
        // `src/config.rs`, so this load succeeds on every target.
        let dir = traversable_tempdir();
        let path = write_agent_config(dir.path(), "[registrar_endpoint]\nenabled = true\n");
        let view = load_agent_config(&path, &test_messages()).expect("loads on any target");
        assert!(view.endpoint_enabled);
    }

    /// The install side neither calls the daemon's endpoint validator
    /// nor can: `validate_registrar_endpoint_settings` is a private
    /// `fn` of the library crate and is not among the items re-exported
    /// from `src/config.rs`.
    ///
    /// The load test above is the strong form of this on a non-Linux
    /// target, where the daemon's own rule would refuse an enabled
    /// endpoint. On Linux that rule accepts, so this scan asserts the
    /// weaker property directly — the split is guaranteed by the module
    /// boundary, and this catches an attempt to reopen it.
    #[test]
    fn nothing_in_the_install_path_names_the_endpoint_validator() {
        fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
            for entry in fs::read_dir(dir).expect("the commands tree must be readable") {
                let path = entry.expect("directory entry must be readable").path();
                if path.is_dir() {
                    rust_sources(&path, out);
                } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }

        let needle = "validate_registrar_endpoint_settings";
        let commands = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut files = Vec::new();
        rust_sources(&commands, &mut files);
        assert!(
            files.contains(&commands.join("audit_store.rs")),
            "the source walk must reach this module"
        );
        for file in files {
            let content = fs::read_to_string(&file).expect("source must be readable");
            // Only the production half: a `#[cfg(test)]` module naming
            // the validator — as this one does, to spell the needle —
            // calls nothing.
            let production = content.split("#[cfg(test)]").next().unwrap_or(&content);
            assert!(
                !production.contains(needle),
                "{} names the daemon's endpoint validator",
                file.display()
            );
        }
    }

    #[test]
    fn a_missing_or_unreadable_path_names_the_path() {
        let dir = traversable_tempdir();
        let missing = dir.path().join("nope.toml");
        let err = load_agent_config(&missing, &test_messages()).expect_err("refused");
        assert!(err.to_string().contains(&missing.display().to_string()));

        let a_directory = dir.path().join("adir");
        fs::create_dir(&a_directory).expect("dir");
        let err = load_agent_config(&a_directory, &test_messages()).expect_err("refused");
        assert!(err.to_string().contains(&a_directory.display().to_string()));
    }

    #[test]
    fn malformed_toml_names_the_path_and_the_parse_error() {
        let dir = traversable_tempdir();
        let path = write_agent_config(dir.path(), "[registrar\n");
        let err = load_agent_config(&path, &test_messages()).expect_err("refused");
        let rendered = err.to_string();
        assert!(rendered.contains(&path.display().to_string()));
        assert!(rendered.contains("not valid TOML"), "{rendered}");
    }

    #[test]
    fn an_unknown_key_in_either_table_is_a_deserialization_error() {
        let dir = traversable_tempdir();
        for body in [
            "[registrar]\naudit_store_dirr = \"/srv/store\"\n",
            "[registrar_endpoint]\nenable = true\n",
            "[registrar]\naudit_store_enforcement = \"whatever\"\n",
        ] {
            let path = write_agent_config(dir.path(), body);
            let err = load_agent_config(&path, &test_messages()).expect_err("refused");
            let rendered = err.to_string();
            assert!(rendered.contains(&path.display().to_string()), "{rendered}");
            assert!(
                rendered.contains("bootroot-agent itself would refuse"),
                "{body:?} did not fail deserialization: {rendered}"
            );
        }
    }

    #[test]
    fn a_registrar_table_failing_validation_names_the_path() {
        let dir = traversable_tempdir();
        let path = write_agent_config(dir.path(), "[registrar]\naudit_store_dir = \"relative\"\n");
        let err = load_agent_config(&path, &test_messages()).expect_err("refused");
        let rendered = err.to_string();
        assert!(rendered.contains(&path.display().to_string()), "{rendered}");
        assert!(rendered.contains("absolute path"), "{rendered}");
    }

    // ---------------------------------------------------------------
    // The required flag, and the enablement cross-check
    // ---------------------------------------------------------------

    #[test]
    fn an_enabled_predicate_without_the_flag_fails_naming_it() {
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let compose_dir = fixture.compose_dir();
        let err = apply_audit_store(
            &Fixture::inputs(None, &state, true, &compose_dir),
            &test_messages(),
        )
        .expect_err("refused");
        assert!(err.to_string().contains("--agent-config"), "{err}");
        assert!(!fixture.store_dir().exists());
        assert!(!audit_override_path(&compose_dir).exists());
    }

    #[test]
    fn a_rendered_override_without_the_flag_fails_naming_it_and_leaves_the_file() {
        let fixture = Fixture::new();
        let compose_dir = fixture.compose_dir();
        let rendered = write_audit_override(&compose_dir, &fixture.store_dir(), &test_messages())
            .expect("render");
        let before = fs::read(&rendered).expect("read");
        let state = fixture.state(Some(false));

        let err = apply_audit_store(
            &Fixture::inputs(None, &state, false, &compose_dir),
            &test_messages(),
        )
        .expect_err("refused");
        assert!(err.to_string().contains("--agent-config"), "{err}");
        assert_eq!(fs::read(&rendered).expect("read"), before);
    }

    #[test]
    fn no_predicate_and_no_rendered_override_makes_the_flag_optional() {
        let fixture = Fixture::new();
        let state = fixture.state(None);
        let compose_dir = fixture.compose_dir();
        let selected = apply_audit_store(
            &Fixture::inputs(None, &state, false, &compose_dir),
            &test_messages(),
        )
        .expect("no-op run");
        assert!(selected.is_none());
        assert!(!fixture.store_dir().exists());
        assert!(!audit_override_path(&compose_dir).exists());
    }

    #[test]
    fn a_supplied_file_is_cross_checked_even_where_the_flag_is_optional() {
        let fixture = Fixture::new();
        let state = fixture.state(None);
        let compose_dir = fixture.compose_dir();
        let agent_config = fixture.agent_config(true);
        let err = apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, false, &compose_dir),
            &test_messages(),
        )
        .expect_err("refused");
        let rendered = err.to_string();
        assert!(
            rendered.contains(&state.display().to_string()),
            "{rendered}"
        );
        assert!(
            rendered.contains(&agent_config.display().to_string()),
            "{rendered}"
        );
        assert!(!fixture.store_dir().exists());
    }

    #[test]
    fn a_recorded_true_over_a_disabling_configuration_is_refused_both_ways() {
        for (recorded, body_enabled) in [(true, false), (false, true)] {
            let fixture = Fixture::new();
            let state = fixture.state(Some(recorded));
            let compose_dir = fixture.compose_dir();
            let agent_config = fixture.agent_config(body_enabled);
            let err = apply_audit_store(
                &Fixture::inputs(Some(&agent_config), &state, recorded, &compose_dir),
                &test_messages(),
            )
            .expect_err("refused");
            let rendered = err.to_string();
            assert!(
                rendered.contains(&state.display().to_string()),
                "{rendered}"
            );
            assert!(
                rendered.contains(&agent_config.display().to_string()),
                "{rendered}"
            );
            assert!(
                rendered.contains("true") && rendered.contains("false"),
                "{rendered}"
            );
            assert!(!fixture.store_dir().exists());
            assert!(!audit_override_path(&compose_dir).exists());
            // Neither source is repaired from the other.
            assert_eq!(
                StateFile::load(&state)
                    .expect("state")
                    .registrar_endpoint
                    .map(|entry| entry.enabled),
                Some(recorded)
            );
        }
    }

    #[test]
    fn a_missing_endpoint_table_disagreeing_with_a_recorded_true_is_refused() {
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let compose_dir = fixture.compose_dir();
        let agent_config = write_agent_config(
            fixture.base.path(),
            &format!(
                "[registrar]\naudit_store_dir = \"{}\"\n",
                fixture.store_dir().display()
            ),
        );
        apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_dir),
            &test_messages(),
        )
        .expect_err("refused");
        assert!(!fixture.store_dir().exists());
    }

    /// Every combination of recorded value, flag presence and
    /// rendered-override presence.
    ///
    /// The flag is required exactly where the recorded predicate is
    /// enabled or a rendered override is on disk; everywhere else it is
    /// optional but never ignored.
    #[test]
    fn the_flag_is_required_exactly_where_provisioning_or_unwinding_happens() {
        for recorded in [true, false] {
            for supplied in [true, false] {
                for rendered_present in [true, false] {
                    let fixture = Fixture::new();
                    let compose_dir = fixture.compose_dir();
                    let state = fixture.state(Some(recorded));
                    if rendered_present {
                        write_audit_override(&compose_dir, &fixture.store_dir(), &test_messages())
                            .expect("render");
                    }
                    // The supplied file always agrees, so the only
                    // refusal this matrix can produce is the missing
                    // flag.
                    let agreeing = fixture.agent_config(recorded);
                    let outcome = apply_audit_store(
                        &Fixture::inputs(
                            supplied.then_some(agreeing.as_path()),
                            &state,
                            recorded,
                            &compose_dir,
                        ),
                        &test_messages(),
                    );
                    let case = format!(
                        "recorded={recorded} supplied={supplied} rendered={rendered_present}"
                    );
                    if supplied || !(recorded || rendered_present) {
                        let selected = outcome.unwrap_or_else(|err| panic!("{case}: {err}"));
                        assert_eq!(selected.is_some(), recorded, "{case}");
                    } else {
                        let err = outcome.err().unwrap_or_else(|| panic!("{case}: accepted"));
                        assert!(err.to_string().contains("--agent-config"), "{case}: {err}");
                    }
                }
            }
        }
    }

    /// Nothing records a second copy of the store's location.
    #[test]
    fn provisioning_writes_no_state_entry() {
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let before = fs::read(&state).expect("read");
        let compose_dir = fixture.compose_dir();
        let agent_config = fixture.agent_config(true);
        apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_dir),
            &test_messages(),
        )
        .expect("provisioned");

        assert_eq!(fs::read(&state).expect("read"), before);
        let raw = String::from_utf8(before).expect("utf-8");
        assert!(
            !raw.contains("audit_store"),
            "state.json gained an audit-store key"
        );
    }

    // ---------------------------------------------------------------
    // Provisioning
    // ---------------------------------------------------------------

    #[test]
    fn an_agreeing_run_creates_the_layout_and_renders_the_override() {
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let compose_dir = fixture.compose_dir();
        let agent_config = fixture.agent_config(true);
        let selected = apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_dir),
            &test_messages(),
        )
        .expect("provisioned");

        let store = fixture.store_dir();
        assert_eq!(
            selected.as_deref(),
            Some(audit_override_path(&compose_dir).as_path())
        );
        for dir in [&store, &store.join(RECORDS_SUBDIR)] {
            let meta = fs::symlink_metadata(dir).expect("metadata");
            assert_eq!(meta.permissions().mode() & 0o7777, 0o700);
            assert_eq!(
                std::os::unix::fs::MetadataExt::uid(&meta),
                current_process_euid()
            );
        }
        assert!(store.join(OPENBAO_SUBDIR).is_dir());

        let content = fs::read_to_string(audit_override_path(&compose_dir)).expect("override");
        assert!(content.contains("volumes: !override"), "{content}");
        assert!(content.contains("openbao-data:/openbao/file"), "{content}");
        assert!(
            content.contains("./openbao:/openbao/config:ro"),
            "{content}"
        );
        assert!(
            content.contains(&format!("{}/openbao:/openbao/audit", store.display())),
            "{content}"
        );
    }

    #[test]
    fn a_disabled_predicate_creates_nothing_and_renders_nothing() {
        for recorded in [None, Some(false)] {
            let fixture = Fixture::new();
            let state = fixture.state(recorded);
            let compose_dir = fixture.compose_dir();
            let agent_config = fixture.agent_config(false);
            let selected = apply_audit_store(
                &Fixture::inputs(Some(&agent_config), &state, false, &compose_dir),
                &test_messages(),
            )
            .expect("no-op");
            assert!(selected.is_none());
            assert!(!fixture.store_dir().exists());
            assert!(!audit_override_path(&compose_dir).exists());
        }
    }

    #[test]
    fn a_store_directory_at_a_wrong_mode_fails_naming_the_remedy() {
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let compose_dir = fixture.compose_dir();
        let agent_config = fixture.agent_config(true);
        let store = fixture.store_dir();
        fs::create_dir(&store).expect("store");
        fs::set_permissions(&store, fs::Permissions::from_mode(0o750)).expect("chmod");

        let err = apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_dir),
            &test_messages(),
        )
        .expect_err("refused");
        let rendered = err.to_string();
        assert!(
            rendered.contains(&store.display().to_string()),
            "{rendered}"
        );
        assert!(rendered.contains("0750"), "{rendered}");
        assert!(
            rendered.contains(&format!("chown 0:0 {}", store.display())),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!("chmod 0700 {}", store.display())),
            "{rendered}"
        );
        assert_eq!(
            fs::symlink_metadata(&store)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o750,
            "the mode was not repaired"
        );
    }

    #[test]
    fn an_ancestor_without_world_execute_fails_before_anything_is_created() {
        let fixture = Fixture::new();
        let tight = fixture.base.path().join("tight");
        fs::create_dir(&tight).expect("ancestor");
        fs::set_permissions(&tight, fs::Permissions::from_mode(0o700)).expect("chmod");
        let store = tight.join("audit-store");
        let state = fixture.state(Some(true));
        let compose_dir = fixture.compose_dir();
        let agent_config = fixture.agent_config_for(&store, true);

        let err = apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_dir),
            &test_messages(),
        )
        .expect_err("refused");
        assert!(
            err.to_string().contains(&tight.display().to_string()),
            "{err}"
        );
        assert!(!store.exists());
        assert!(!audit_override_path(&compose_dir).exists());
    }

    #[test]
    fn an_existing_openbao_directory_is_left_untouched_and_a_plant_is_refused() {
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let compose_dir = fixture.compose_dir();
        let agent_config = fixture.agent_config(true);
        apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_dir),
            &test_messages(),
        )
        .expect("first run");

        // A started deployment's `openbao/` belongs to the container's
        // user. A test cannot chown, but it can prove the mode is
        // neither asserted nor repaired, which is the same code path:
        // the check reads no owner and no mode for that path at all.
        let openbao = fixture.store_dir().join(OPENBAO_SUBDIR);
        fs::set_permissions(&openbao, fs::Permissions::from_mode(0o755)).expect("chmod");
        apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_dir),
            &test_messages(),
        )
        .expect("re-run over a started deployment");
        assert_eq!(
            fs::symlink_metadata(&openbao)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );

        fs::remove_dir(&openbao).expect("remove");
        fs::write(&openbao, b"planted").expect("plant");
        let err = apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_dir),
            &test_messages(),
        )
        .expect_err("refused");
        assert!(
            err.to_string().contains(&openbao.display().to_string()),
            "{err}"
        );
    }

    // ---------------------------------------------------------------
    // The pre-wipe preflight
    // ---------------------------------------------------------------

    /// `bootroot reinit` removes the `OpenBao` container and its volumes
    /// before it re-runs `init`, so every refusal the init pass would
    /// make has to be reachable ahead of that wipe. This asserts the
    /// preflight raises each of them and, for the runs it accepts,
    /// leaves the filesystem exactly as it found it.
    #[test]
    fn the_preflight_raises_every_init_refusal_without_touching_anything() {
        // The required flag, on the two runs that require it.
        let fixture = Fixture::new();
        let compose_dir = fixture.compose_dir();
        let state = fixture.state(Some(true));
        let err = preflight_audit_store(
            &Fixture::inputs(None, &state, true, &compose_dir),
            &test_messages(),
        )
        .expect_err("refused");
        assert!(err.to_string().contains("--agent-config"), "{err}");
        assert!(!fixture.store_dir().exists());

        // The enablement cross-check.
        let disagreeing = fixture.agent_config(false);
        preflight_audit_store(
            &Fixture::inputs(Some(&disagreeing), &state, true, &compose_dir),
            &test_messages(),
        )
        .expect_err("refused on disagreement");
        assert!(!fixture.store_dir().exists());

        // A `[registrar]` table the daemon itself would refuse.
        let bad = write_agent_config(
            fixture.base.path(),
            "[registrar]\naudit_store_dirr = \"/srv/store\"\n",
        );
        preflight_audit_store(
            &Fixture::inputs(Some(&bad), &state, true, &compose_dir),
            &test_messages(),
        )
        .expect_err("refused on deserialization");

        // The agreeing run over a host that has already provisioned once
        // is accepted, and creates, renders and deletes nothing:
        // provisioning is the init pass's, and after the wipe it is safe
        // to reach.
        let agreeing = fixture.agent_config(true);
        let rendered = write_audit_override(&compose_dir, &fixture.store_dir(), &test_messages())
            .expect("render");
        let before = fs::read(&rendered).expect("read");
        preflight_audit_store(
            &Fixture::inputs(Some(&agreeing), &state, true, &compose_dir),
            &test_messages(),
        )
        .expect("accepted");
        assert!(
            !fixture.store_dir().exists(),
            "the preflight created a store"
        );
        assert_eq!(fs::read(&rendered).expect("read"), before);
    }

    /// The bring-up reinit runs between the wipe and the init pass gates
    /// on the recorded predicate alone, so it demands the rendered
    /// override the init pass has not written yet. On a host whose
    /// predicate was recorded by hand and never provisioned, that
    /// refusal has to land here rather than after `OpenBao` has been
    /// removed.
    #[test]
    fn the_preflight_refuses_a_provisioning_run_with_no_override_yet() {
        let fixture = Fixture::new();
        let compose_dir = fixture.compose_dir();
        let state = fixture.state(Some(true));
        let agreeing = fixture.agent_config(true);

        let err = preflight_audit_store(
            &Fixture::inputs(Some(&agreeing), &state, true, &compose_dir),
            &test_messages(),
        )
        .expect_err("refused before the wipe");
        assert!(err.to_string().contains("bootroot init"), "{err}");
        assert!(!fixture.store_dir().exists());
        assert!(!audit_override_path(&compose_dir).exists());

        // The same refusal the bring-up would have raised afterwards,
        // which is what makes raising it here the whole point.
        let bring_up = resolve_audit_override(
            &state,
            &compose_dir,
            current_process_euid(),
            &test_messages(),
        )
        .expect_err("the bring-up refuses the same host");
        assert_eq!(bring_up.to_string(), err.to_string());
    }

    #[test]
    fn the_preflight_raises_the_stale_override_and_the_ancestor_refusals() {
        // A stale override, with the rendered file left byte-identical.
        let fixture = Fixture::new();
        let compose_dir = fixture.compose_dir();
        let state = fixture.state(Some(true));
        let rendered = write_audit_override(
            &compose_dir,
            &fixture.base.path().join("old-store"),
            &test_messages(),
        )
        .expect("render");
        let before = fs::read(&rendered).expect("read");
        let agreeing = fixture.agent_config(true);
        preflight_audit_store(
            &Fixture::inputs(Some(&agreeing), &state, true, &compose_dir),
            &test_messages(),
        )
        .expect_err("refused as stale");
        assert_eq!(fs::read(&rendered).expect("read"), before);

        // An ancestor without `o+x`, on a fixture with no rendered
        // override to get past first.
        let fixture = Fixture::new();
        let compose_dir = fixture.compose_dir();
        let state = fixture.state(Some(true));
        let tight = fixture.base.path().join("tight");
        fs::create_dir(&tight).expect("ancestor");
        fs::set_permissions(&tight, fs::Permissions::from_mode(0o700)).expect("chmod");
        let store = tight.join("audit-store");
        let agent_config = fixture.agent_config_for(&store, true);
        let err = preflight_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_dir),
            &test_messages(),
        )
        .expect_err("refused");
        assert!(
            err.to_string().contains(&tight.display().to_string()),
            "{err}"
        );
        assert!(!store.exists());
    }

    /// The unwinding run is a refusal source too, and the preflight must
    /// not perform the deletion it is only checking for.
    #[test]
    fn the_preflight_leaves_an_override_it_would_unwind_on_disk() {
        let fixture = Fixture::new();
        let compose_dir = fixture.compose_dir();
        let rendered = write_audit_override(&compose_dir, &fixture.store_dir(), &test_messages())
            .expect("render");
        let state = fixture.state(Some(false));

        preflight_audit_store(
            &Fixture::inputs(None, &state, false, &compose_dir),
            &test_messages(),
        )
        .expect_err("the rendered override keeps the flag mandatory");
        assert!(rendered.exists());

        let disabling = fixture.agent_config(false);
        preflight_audit_store(
            &Fixture::inputs(Some(&disabling), &state, false, &compose_dir),
            &test_messages(),
        )
        .expect("an agreeing false is accepted");
        assert!(
            rendered.exists(),
            "the preflight deleted the override the init pass unwinds"
        );
    }

    // ---------------------------------------------------------------
    // The caller's own uid
    // ---------------------------------------------------------------

    /// An `expected_uid` this process is not running as stands in for
    /// production's uid 0 under an unprivileged caller: the layout is
    /// created owned by whoever creates it, so without this refusal the
    /// run would build the store under its own uid and then fail its own
    /// owner check, leaving a directory the later root run refuses as
    /// foreign-owned and does not repair.
    #[test]
    fn an_unprivileged_provisioning_run_creates_nothing() {
        let fixture = Fixture::new();
        let compose_dir = fixture.compose_dir();
        let store_dir = fixture.store_dir();
        let agent_config = fixture.agent_config(true);
        let state = fixture.state(Some(true));

        let foreign_uid = current_process_euid().wrapping_add(1);
        let err = apply_audit_store(
            &AuditStoreInitInputs {
                compose_dir: &compose_dir,
                agent_config: Some(&agent_config),
                state_path: &state,
                endpoint_recorded: true,
                expected_uid: foreign_uid,
            },
            &test_messages(),
        )
        .expect_err("refused");
        let message = err.to_string();
        assert!(
            message.contains(&store_dir.display().to_string()),
            "{message}"
        );
        assert!(message.contains(&foreign_uid.to_string()), "{message}");
        assert!(
            message.contains(&current_process_euid().to_string()),
            "{message}"
        );

        assert!(
            !store_dir.exists(),
            "an unprivileged run left a store behind"
        );
        assert!(
            !audit_override_path(&compose_dir).exists(),
            "an unprivileged run rendered an override"
        );
    }

    /// The same refusal reaches `reinit` through the shared preflight,
    /// so an unprivileged reinit is refused while `OpenBao` is still
    /// intact rather than after the wipe.
    #[test]
    fn the_preflight_raises_the_unprivileged_refusal_before_the_wipe() {
        let fixture = Fixture::new();
        let compose_dir = fixture.compose_dir();
        let store_dir = fixture.store_dir();
        let agent_config = fixture.agent_config(true);
        let state = fixture.state(Some(true));
        // Rendered, so the missing-override refusal cannot be what
        // fires here.
        write_audit_override(&compose_dir, &store_dir, &test_messages()).expect("render");

        let foreign_uid = current_process_euid().wrapping_add(1);
        let err = preflight_audit_store(
            &AuditStoreInitInputs {
                compose_dir: &compose_dir,
                agent_config: Some(&agent_config),
                state_path: &state,
                endpoint_recorded: true,
                expected_uid: foreign_uid,
            },
            &test_messages(),
        )
        .expect_err("refused");
        assert!(err.to_string().contains(&foreign_uid.to_string()), "{err}");
        assert!(!store_dir.exists(), "the preflight created a store");
    }

    /// A run that provisions nothing asserts nothing about the caller's
    /// uid: an unwinding `init` on a host being switched off deletes a
    /// rendered override, and the store it no longer mounts is not
    /// touched either way.
    #[test]
    fn an_unwinding_run_is_not_held_to_the_provisioning_uid() {
        let fixture = Fixture::new();
        let compose_dir = fixture.compose_dir();
        let store_dir = fixture.store_dir();
        let rendered =
            write_audit_override(&compose_dir, &store_dir, &test_messages()).expect("render");
        let agent_config = fixture.agent_config(false);
        let state = fixture.state(Some(false));

        let selected = apply_audit_store(
            &AuditStoreInitInputs {
                compose_dir: &compose_dir,
                agent_config: Some(&agent_config),
                state_path: &state,
                endpoint_recorded: false,
                expected_uid: current_process_euid().wrapping_add(1),
            },
            &test_messages(),
        )
        .expect("an unwinding run is not a provisioning run");
        assert!(selected.is_none());
        assert!(!rendered.exists(), "the override was not deleted");
    }

    // ---------------------------------------------------------------
    // The stale override
    // ---------------------------------------------------------------

    #[test]
    fn a_stale_override_fails_before_anything_is_created_rendered_or_recreated() {
        let fixture = Fixture::new();
        let compose_dir = fixture.compose_dir();
        let recorded_store = fixture.base.path().join("old-store");
        let rendered =
            write_audit_override(&compose_dir, &recorded_store, &test_messages()).expect("render");
        let before = fs::read(&rendered).expect("read");

        let configured_store = fixture.base.path().join("new-store");
        let agent_config = fixture.agent_config_for(&configured_store, true);
        let state = fixture.state(Some(true));

        let err = apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_dir),
            &test_messages(),
        )
        .expect_err("refused");
        let message = err.to_string();
        assert!(
            message.contains(&recorded_store.display().to_string()),
            "{message}"
        );
        assert!(
            message.contains(&configured_store.display().to_string()),
            "{message}"
        );
        // Nothing created, and the rendered file is byte-identical. No
        // Compose invocation is reachable from here: the caller only
        // ever passes what this function returns, and it returned an
        // error.
        assert!(!configured_store.exists());
        assert!(!recorded_store.exists());
        assert_eq!(fs::read(&rendered).expect("read"), before);
    }

    // ---------------------------------------------------------------
    // Switching off
    // ---------------------------------------------------------------

    #[test]
    fn switching_off_stops_the_mount_before_it_deletes_the_rendered_file() {
        let fixture = Fixture::new();
        let compose_dir = fixture.compose_dir();
        let enabling = fixture.agent_config(true);
        let provisioned_state = fixture.state(Some(true));
        apply_audit_store(
            &Fixture::inputs(Some(&enabling), &provisioned_state, true, &compose_dir),
            &test_messages(),
        )
        .expect("provisioned");
        let rendered = audit_override_path(&compose_dir);
        let store = fixture.store_dir();
        fs::write(store.join(OPENBAO_SUBDIR).join("audit.log"), b"entry").expect("write");

        // Flip `state.json` alone: every selection path stops applying
        // the override immediately, and the rendered file stays.
        let state = fixture.state(Some(false));
        assert!(
            resolve_audit_override(
                &state,
                &compose_dir,
                current_process_euid(),
                &test_messages()
            )
            .expect("bring-up")
            .is_none()
        );
        assert!(rendered.exists());

        // An `init` still handed the enabling configuration is refused.
        apply_audit_store(
            &Fixture::inputs(Some(&enabling), &state, false, &compose_dir),
            &test_messages(),
        )
        .expect_err("refused on disagreement");
        assert!(rendered.exists());

        // An `init` given no configuration fails naming the flag.
        apply_audit_store(
            &Fixture::inputs(None, &state, false, &compose_dir),
            &test_messages(),
        )
        .expect_err("the rendered override keeps the flag mandatory");
        assert!(rendered.exists());

        // Only an agreeing `false` deletes it.
        let disabling = fixture.agent_config(false);
        let selected = apply_audit_store(
            &Fixture::inputs(Some(&disabling), &state, false, &compose_dir),
            &test_messages(),
        )
        .expect("unwound");
        assert!(selected.is_none());
        assert!(!rendered.exists());

        // The store and its contents are untouched throughout.
        assert!(store.join(RECORDS_SUBDIR).is_dir());
        assert_eq!(
            fs::read(store.join(OPENBAO_SUBDIR).join("audit.log")).expect("read"),
            b"entry"
        );
    }

    // ---------------------------------------------------------------
    // `infra up` resolution
    // ---------------------------------------------------------------

    fn provisioned_fixture() -> (Fixture, PathBuf, PathBuf) {
        let fixture = Fixture::new();
        let compose_dir = fixture.compose_dir();
        let agent_config = fixture.agent_config(true);
        let state = fixture.state(Some(true));
        apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_dir),
            &test_messages(),
        )
        .expect("provisioned");
        (fixture, state, compose_dir)
    }

    #[test]
    fn a_bring_up_selects_the_override_over_a_conforming_store() {
        let (fixture, state, compose_dir) = provisioned_fixture();
        // An unreadable `openbao/` under an otherwise valid store: the
        // check never descends, so it still succeeds.
        let openbao = fixture.store_dir().join(OPENBAO_SUBDIR);
        fs::set_permissions(&openbao, fs::Permissions::from_mode(0o000)).expect("chmod");

        let selected = resolve_audit_override(
            &state,
            &compose_dir,
            current_process_euid(),
            &test_messages(),
        )
        .expect("resolves");
        assert_eq!(
            selected.as_deref(),
            Some(audit_override_path(&compose_dir).as_path())
        );
        fs::set_permissions(&openbao, fs::Permissions::from_mode(0o700)).expect("restore");
    }

    #[test]
    fn a_bring_up_without_a_rendered_override_names_bootroot_init() {
        let (_fixture, state, compose_dir) = provisioned_fixture();
        fs::remove_file(audit_override_path(&compose_dir)).expect("remove");
        let err = resolve_audit_override(
            &state,
            &compose_dir,
            current_process_euid(),
            &test_messages(),
        )
        .expect_err("refused");
        assert!(err.to_string().contains("bootroot init"), "{err}");
    }

    #[test]
    fn a_bring_up_refuses_a_store_that_departs_from_the_contract() {
        type Plant = fn(&Path);
        let store_faults: [(&str, Plant); 3] = [
            ("mode 0750", |store| {
                fs::set_permissions(store, fs::Permissions::from_mode(0o750)).expect("chmod");
            }),
            ("mode 0755", |store| {
                fs::set_permissions(store, fs::Permissions::from_mode(0o755)).expect("chmod");
            }),
            ("a symlink", |store| {
                let elsewhere = store.with_extension("elsewhere");
                fs::create_dir(&elsewhere).expect("elsewhere");
                fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o700)).expect("chmod");
                fs::remove_dir_all(store).expect("remove");
                symlink(&elsewhere, store).expect("symlink");
            }),
        ];
        for (label, plant) in store_faults {
            let (fixture, state, compose_dir) = provisioned_fixture();
            plant(&fixture.store_dir());
            let err = resolve_audit_override(
                &state,
                &compose_dir,
                current_process_euid(),
                &test_messages(),
            )
            .expect_err("refused");
            let rendered = err.to_string();
            assert!(rendered.contains("bootroot init"), "{label}: {rendered}");
            assert!(
                rendered.contains(&fixture.store_dir().display().to_string()),
                "{label}: {rendered}"
            );
        }
    }

    #[test]
    fn a_bring_up_refuses_a_store_owned_by_another_uid_and_states_the_remedy() {
        let (fixture, state, compose_dir) = provisioned_fixture();
        let err = resolve_audit_override(
            &state,
            &compose_dir,
            current_process_euid() + 1,
            &test_messages(),
        )
        .expect_err("refused");
        let rendered = err.to_string();
        let store = fixture.store_dir().display().to_string();
        assert!(rendered.contains(&store), "{rendered}");
        assert!(
            rendered.contains(&format!("chown 0:0 {store}")),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!("chmod 0700 {store}")),
            "{rendered}"
        );
        assert!(rendered.contains("bootroot init"), "{rendered}");
    }

    #[test]
    fn a_disabled_predicate_selects_nothing_and_leaves_a_rendered_file_inert() {
        let (fixture, _state, compose_dir) = provisioned_fixture();
        for recorded in [None, Some(false)] {
            let state = write_state(fixture.base.path(), recorded);
            assert!(
                resolve_audit_override(
                    &state,
                    &compose_dir,
                    current_process_euid(),
                    &test_messages()
                )
                .expect("no selection")
                .is_none()
            );
        }
        assert!(audit_override_path(&compose_dir).exists());
    }

    #[test]
    fn an_absent_state_file_selects_nothing() {
        let fixture = Fixture::new();
        let state = fixture.base.path().join("absent.json");
        assert!(
            resolve_audit_override(
                &state,
                &fixture.compose_dir(),
                current_process_euid(),
                &test_messages()
            )
            .expect("no selection")
            .is_none()
        );
    }

    // ---------------------------------------------------------------
    // Rendering and reading back
    // ---------------------------------------------------------------

    #[test]
    fn a_rendered_override_round_trips_through_its_reader() {
        let dir = traversable_tempdir();
        for store in [
            dir.path().join("plain-store"),
            dir.path().join("with space"),
            dir.path().join("with'quote"),
            dir.path().join("with$dollar"),
        ] {
            let rendered =
                write_audit_override(dir.path(), &store, &test_messages()).expect("render");
            let read_back =
                read_audit_override_store_dir(&rendered, &test_messages()).expect("read back");
            assert_eq!(read_back, store);
        }
    }

    /// The one override rendered by root and read unprivileged, so its
    /// mode cannot be left to the umask `bootroot init` happens to run
    /// under.
    #[test]
    fn a_freshly_rendered_override_is_readable_by_the_operator() {
        let dir = traversable_tempdir();
        let compose_dir = dir.path().join("compose");
        fs::create_dir(&compose_dir).expect("compose dir");
        let rendered = write_audit_override(
            &compose_dir,
            &dir.path().join("audit-store"),
            &test_messages(),
        )
        .expect("render");
        assert_eq!(
            fs::symlink_metadata(&rendered)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o644
        );
        // `secrets/openbao` is the directory both OpenBao Agent sidecars
        // run out of, so it carries the secrets tree's own mode rather
        // than one this renderer picked — the same `0700` every other
        // level of that tree is created at, and the mode `init`'s later
        // recursive permission sweep would apply to it regardless.
        let override_dir = rendered.parent().expect("parent");
        assert_eq!(
            fs::symlink_metadata(override_dir)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );

        // A destination an operator narrowed by hand keeps that choice
        // across the next render.
        fs::set_permissions(&rendered, fs::Permissions::from_mode(0o600)).expect("chmod");
        write_audit_override(
            &compose_dir,
            &dir.path().join("audit-store"),
            &test_messages(),
        )
        .expect("re-render");
        assert_eq!(
            fs::symlink_metadata(&rendered)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );

        // The half that only a root-run `init` can get wrong, asserted
        // for the shape rather than the privilege: the file takes the
        // containing directory's owner, not the writing process's, so a
        // root render inside an operator-owned tree stays readable to
        // the unprivileged `infra up` that has to read it back.
        let dir_meta = fs::symlink_metadata(override_dir).expect("metadata");
        let file_meta = fs::symlink_metadata(&rendered).expect("metadata");
        assert_eq!(
            (file_meta.uid(), file_meta.gid()),
            (dir_meta.uid(), dir_meta.gid()),
            "the rendered override must belong to the secrets tree, not to the writer"
        );
    }

    /// Both characters a Compose bind mount cannot carry, refused
    /// before the override is rendered.
    ///
    /// The colon is the one an operator could plausibly reach: Compose
    /// splits a bind mount's value on it to find the source, the target
    /// and the mode, so `/srv/a:b` renders a mount naming `/srv/a` with
    /// the rest read as a target and a mode. Quoting does not help —
    /// the split happens after YAML has handed Compose the scalar — and
    /// nothing later would catch it, because the reader strips the same
    /// container-path suffix and hands back a store directory that
    /// matches the configuration exactly.
    #[test]
    fn a_store_directory_a_compose_mount_cannot_carry_is_refused() {
        let dir = traversable_tempdir();
        for name in ["bad\nstore", "bad:store"] {
            let store = dir.path().join(name);
            let err =
                write_audit_override(dir.path(), &store, &test_messages()).expect_err("refused");
            assert!(
                err.to_string().contains(&store.display().to_string()),
                "the refusal must name the path, got: {err}"
            );
            assert!(
                !audit_override_path(dir.path()).exists(),
                "{name} was refused after the override had already been rendered"
            );
        }
    }

    /// The repository's own compose files, read from the checkout the
    /// tests run in.
    fn repo_file(name: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(name);
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("reading {name}: {err}"))
    }

    #[test]
    fn the_audit_override_redeclares_the_services_other_mounts_verbatim() {
        let dir = traversable_tempdir();
        let store = dir.path().join("audit-store");
        let rendered = write_audit_override(dir.path(), &store, &test_messages()).expect("render");
        let entries = collect_openbao_volume_entries(&fs::read_to_string(&rendered).expect("read"));

        // `!override` replaces the whole list, so dropping one of these
        // would silently unmount OpenBao's storage or its configuration.
        for compose in ["docker-compose.yml", "docker-compose.deploy.yml"] {
            let base = collect_openbao_volume_entries(&repo_file(compose));
            assert!(
                base.contains(&OPENBAO_DATA_MOUNT.to_string()),
                "{compose} no longer declares {OPENBAO_DATA_MOUNT}"
            );
            assert!(
                base.contains(&OPENBAO_CONFIG_MOUNT.to_string()),
                "{compose} no longer declares {OPENBAO_CONFIG_MOUNT}"
            );
        }
        assert_eq!(
            entries,
            vec![
                OPENBAO_DATA_MOUNT.to_string(),
                compose_quote(&format!(
                    "{}/{OPENBAO_SUBDIR}:{OPENBAO_AUDIT_CONTAINER_PATH}",
                    store.display()
                )),
                OPENBAO_CONFIG_MOUNT.to_string(),
            ]
        );
    }

    #[test]
    fn the_named_volume_and_the_audit_device_stanza_are_left_alone() {
        for compose in ["docker-compose.yml", "docker-compose.deploy.yml"] {
            let content = repo_file(compose);
            // The override stops the volume being mounted where it
            // applies; it does not stop the volume existing, and an
            // existing deployment's audit history is in it.
            assert!(
                content.contains("\n  openbao-audit:\n"),
                "{compose} no longer declares the openbao-audit volume"
            );
            assert!(
                content.contains("openbao-audit:/openbao/audit"),
                "{compose} no longer mounts the openbao-audit volume by default"
            );
        }
        // The container path is unchanged, so the device's `file_path`
        // needs no edit and `verify_audit_file` keeps passing.
        let hcl = repo_file("openbao/openbao.hcl");
        assert!(
            hcl.contains("file_path = \"/openbao/audit/audit.log\""),
            "the audit device's file_path moved"
        );
    }

    #[test]
    fn the_two_overrides_rewrite_disjoint_attributes() {
        let dir = traversable_tempdir();
        let audit = write_audit_override(
            dir.path(),
            &dir.path().join("audit-store"),
            &test_messages(),
        )
        .expect("render audit");
        let exposed = crate::commands::guardrails::write_openbao_exposed_override(
            dir.path(),
            "10.0.0.5",
            &test_messages(),
        )
        .expect("render exposed");

        let audit_content = fs::read_to_string(&audit).expect("read audit");
        let exposed_content = fs::read_to_string(&exposed).expect("read exposed");
        // One rewrites `volumes:` and the other `ports:`, so the two
        // compose without interacting and the merged service keeps both
        // the publication and the bind mount.
        assert!(audit_content.contains("volumes: !override"));
        assert!(!audit_content.contains("ports:"));
        assert!(exposed_content.contains("ports: !override"));
        assert!(!exposed_content.contains("volumes:"));
        assert_ne!(audit, exposed, "the two overrides are separate files");
    }

    #[test]
    fn an_override_declaring_no_audit_mount_is_refused() {
        let dir = traversable_tempdir();
        let path = dir.path().join("docker-compose.audit.yml");
        fs::write(
            &path,
            "services:\n  openbao:\n    volumes: !override\n      - openbao-data:/openbao/file\n",
        )
        .expect("write");
        let err = read_audit_override_store_dir(&path, &test_messages()).expect_err("refused");
        assert!(
            err.to_string().contains(&path.display().to_string()),
            "{err}"
        );
    }
}
