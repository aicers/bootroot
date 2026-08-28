//! The install side of the shared audit store: reading where it is,
//! creating it as root, and binding `OpenBao`'s file audit device into
//! it through a rendered Compose override.
//!
//! `[registrar] audit_store_dir` in the operator's `bootroot-agent`
//! configuration file is the **only** definition of where the store is.
//! Nothing here records a second copy of it — not `state.json`, not a
//! flag, not an environment variable — because both writers must
//! resolve into one directory, and two values that can drift are two
//! directories waiting to happen. That is why both `bootroot init` and
//! an endpoint-enabled `bootroot infra up` take `--agent-config`; the
//! latter cross-checks it while preserving the bind source read from the
//! rendered override rather than silently resolving a new one.
//!
//! Only the `OpenBao` device actually starts writing here. The daemon's
//! verb records do not: nothing in this build constructs a record
//! store, and what this module delivers for that half is the empty
//! `records/` directory the store's trust checks accept.
//!
//! `audit_store_reserve_bytes` is enforced here in the shipped
//! `filesystem` mode, by [`reserve`]: a fully allocated loopback image
//! sized to the reserve, an `ext4` filesystem on it, and a generated
//! mount unit that puts it at `audit_store_dir` and restores it on
//! boot. The ceiling is then the image size, a quota by construction
//! the kernel enforces against both writers. An explicit
//! `audit_store_enforcement = "directory"` opts out of all of it and
//! leaves the budget a recorded number.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::config::AuditStoreEnforcement;
use bootroot::fs_util;
use bootroot::registrar::audit_store::{
    AuditStoreLayoutError, OPENBAO_CONTAINER_AUDIT_DIR, PRODUCTION_UID, STORE_DIR_MODE,
    check_store_directory, create_layout, create_mount_point,
};
use serde::Deserialize;

use crate::commands::compose_file::compose_file_dir;
use crate::commands::compose_project::ComposeIdentity;
use crate::commands::init::OPENBAO_AUDIT_COMPOSE_OVERRIDE_NAME;
use crate::i18n::Messages;
use crate::state::StateFile;

pub(crate) mod migration;
pub(crate) mod reserve;

/// The container path `openbao/openbao.hcl` writes its file audit
/// device to. Unchanged by this override — only what backs it moves.
const OPENBAO_AUDIT_CONTAINER_PATH: &str = OPENBAO_CONTAINER_AUDIT_DIR;

/// The `openbao` service's other two mounts, re-declared verbatim
/// because `!override` replaces the whole list and dropping one would
/// silently unmount `OpenBao`'s storage or its configuration.
const OPENBAO_DATA_MOUNT: &str = "openbao-data:/openbao/file";
const OPENBAO_CONFIG_MOUNT: &str = "./openbao:/openbao/config:ro";

/// Mode a freshly rendered override is created at.
const OVERRIDE_FILE_MODE: u32 = 0o644;

/// The command a rendered "run this again" step names on this surface.
///
/// A parameter rather than a literal inside the catalogue string, so
/// the installer fail-closed issue renders the same step for
/// `bootroot infra up` without a second copy of the sentence. Nothing
/// here supplies any other value: an already-initialised host cannot
/// re-run `bootroot init`, so activating enforcement on a live
/// deployment needs a surface this build does not have.
const RESERVE_RERUN_COMMAND: &str = "bootroot init";

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

/// The readings `--agent-config` carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentConfigView {
    /// `[registrar] audit_store_dir`, already validated.
    pub(crate) audit_store_dir: PathBuf,
    /// `[registrar_endpoint] enabled`, read as a plain field with no
    /// semantic rule applied.
    pub(crate) endpoint_enabled: bool,
    /// `[registrar] audit_store_enforcement` — the **only** input that
    /// selects a mode. Never inferred, never fallen back from, never
    /// written back.
    pub(crate) enforcement: AuditStoreEnforcement,
    /// `[registrar] audit_store_reserve_bytes`.
    pub(crate) reserve_bytes: u64,
    /// `[registrar] audit_max_file_bytes`, half of the reserve
    /// minimum's record worst case.
    pub(crate) max_file_bytes: u64,
    /// `[registrar] audit_max_retained_files`, the other half.
    pub(crate) max_retained_files: u32,
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
        enforcement: partial.registrar.audit_store_enforcement,
        reserve_bytes: partial.registrar.audit_store_reserve_bytes,
        max_file_bytes: partial.registrar.audit_max_file_bytes,
        max_retained_files: partial.registrar.audit_max_retained_files,
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
/// Quoting settles what YAML reads back, but a control character still
/// has no reliable Compose spelling. A colon is now a distinct `source:`
/// value in the long bind form, but remains refused because the reader,
/// systemd escaping and rendered shell commands all have to carry the
/// path too; widening that input contract is not this change's business.
fn render_audit_override(bind_source: &Path, messages: &Messages) -> Result<String> {
    let raw = bind_source.to_string_lossy();
    if raw.chars().any(|ch| ch.is_control() || ch == ':') {
        anyhow::bail!(messages.error_audit_store_dir_unrenderable(&raw));
    }
    let source = compose_quote(&raw);
    // Docker only refuses to create a missing source. An older underlying
    // `openbao/` directory still binds, so relocating that content is what
    // retires the residual boot-path exposure.
    Ok(format!(
        "\
services:
  openbao:
    volumes: !override
      - {OPENBAO_DATA_MOUNT}
      - type: bind
        source: {source}
        target: {OPENBAO_AUDIT_CONTAINER_PATH}
        bind:
          create_host_path: false
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
/// The override file is the record of the bind source `init` resolved.
/// `bootroot infra up` cross-checks the daemon configuration against it,
/// but keeps that source rather than silently moving the bind.
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
    let bind_source = read_audit_override_bind_source(&content)
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

/// Returns the bind source from either override syntax this repository
/// has rendered. Existing deployments carry the short form, while new
/// overrides use a long bind entry so Docker can refuse a missing source.
fn read_audit_override_bind_source(compose: &str) -> Option<PathBuf> {
    let entries = collect_openbao_volume_entries(compose);
    let suffix = format!(":{OPENBAO_AUDIT_CONTAINER_PATH}");
    for entry in entries {
        let trimmed = entry.trim();
        if let Some(source) = trimmed.strip_prefix("type: bind\n") {
            let mut source_value = None;
            let mut target = None;
            for line in source.lines() {
                let line = line.trim();
                if let Some(value) = line.strip_prefix("source:") {
                    source_value = Some(compose_unquote(value.trim()));
                } else if let Some(value) = line.strip_prefix("target:") {
                    target = Some(compose_unquote(value.trim()));
                }
            }
            if target.as_deref() == Some(OPENBAO_AUDIT_CONTAINER_PATH)
                && let Some(source) = source_value
            {
                return Some(PathBuf::from(source));
            }
        } else {
            // Unquote first: a prior renderer put the container path
            // inside the same scalar as the source.
            let unquoted = compose_unquote(trimmed);
            if let Some(source) = unquoted.strip_suffix(suffix.as_str()) {
                return Some(PathBuf::from(source));
            }
        }
    }
    None
}

/// Collects the `openbao` service's raw `volumes:` entries, with any
/// surrounding YAML quoting left on.
fn collect_openbao_volume_entries(compose: &str) -> Vec<String> {
    let mut entries = Vec::new();
    let mut in_service = false;
    let mut service_indent = 0usize;
    let mut in_volumes = false;
    let mut volumes_indent = 0usize;

    let mut current_mapping: Option<String> = None;
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
            if let Some(mapping) = current_mapping.take() {
                entries.push(mapping);
            }
            in_volumes = false;
            continue;
        }

        if in_volumes && trimmed.starts_with('-') {
            if let Some(mapping) = current_mapping.take() {
                entries.push(mapping);
            }
            let value = trimmed.trim_start_matches('-').trim();
            if !value.is_empty() {
                if value.starts_with("type:") {
                    current_mapping = Some(format!("{value}\n"));
                } else {
                    entries.push(value.to_string());
                }
            }
        } else if let Some(mapping) = current_mapping.as_mut() {
            mapping.push_str(trimmed);
            mapping.push('\n');
        }
    }
    if let Some(mapping) = current_mapping {
        entries.push(mapping);
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
    /// The compose file this run was pointed at. The override is
    /// rendered in its directory, and the migration's Compose stop
    /// names it with `-f`; deriving both from one value is what keeps
    /// the file the stop names and the directory the override lands in
    /// from ever being two different deployments.
    pub(crate) compose_file: &'a Path,
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
    /// Provision the store the configuration names and render the
    /// override.
    Provision(Box<AgentConfigView>),
}

/// Decides how endpoint and explicit-enforcement configuration gates
/// the audit store, creating, rendering and deleting nothing.
///
/// These gates do not inspect a prospective store layout. Reinit uses
/// them before its wipe, then separately evaluates the filesystem
/// reserve's phase-one facts. [`plan_audit_store`] adds the provisioning
/// checks that ordinary init needs before it acts.
///
/// # Errors
///
/// Returns an error when `--agent-config` is required and absent, when
/// the file cannot be loaded, or when the two recorded enablement values
/// disagree.
fn select_audit_store_plan(
    inputs: &AuditStoreInitInputs<'_>,
    messages: &Messages,
) -> Result<AuditStorePlan> {
    let override_path = audit_override_path(&compose_file_dir(inputs.compose_file));
    let rendered_present = override_path.exists();

    // A rendered override makes the flag mandatory even on a host whose
    // predicate is off, which keeps the deletion of an override from
    // being the one operation that never reads the daemon's
    // configuration.
    let Some(agent_config) = inputs.agent_config else {
        if inputs.endpoint_recorded || rendered_present {
            anyhow::bail!(messages.error_audit_store_agent_config_required("bootroot init"));
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

    Ok(AuditStorePlan::Provision(Box::new(view)))
}

/// Decides what ordinary init does about the audit store, creating,
/// rendering and deleting nothing.
///
/// This is [`select_audit_store_plan`] plus the validation that matters
/// only to a provisioning init pass. Reinit deliberately does not run
/// these checks before its wipe: a fresh host needs init to create and
/// render its first store, while reserve phase one remains the sole
/// filesystem preflight boundary.
fn plan_audit_store(
    inputs: &AuditStoreInitInputs<'_>,
    messages: &Messages,
) -> Result<AuditStorePlan> {
    let plan = select_audit_store_plan(inputs, messages)?;
    let AuditStorePlan::Provision(view) = plan else {
        return Ok(plan);
    };

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

    let override_path = audit_override_path(&compose_file_dir(inputs.compose_file));
    if override_path.exists() {
        let rendered_store = read_audit_override_store_dir(&override_path, messages)?;
        // `Path`'s own equality compares components, so the rendered
        // spelling and the configured one agree wherever they name
        // one directory — which is what keeps `filesystem` mode's
        // recording of the simplified form from reading back as a
        // store that moved.
        if rendered_store != view.audit_store_dir {
            anyhow::bail!(messages.error_audit_store_override_stale(
                &rendered_store.display().to_string(),
                &view.audit_store_dir.display().to_string(),
            ));
        }
    }

    Ok(AuditStorePlan::Provision(view))
}

/// Raises the audit-store refusals that must precede a reinit wipe,
/// without creating, rendering or deleting anything.
///
/// `bootroot reinit` re-runs `init`, but only after it has removed the
/// `OpenBao` container and its volumes. The endpoint/configuration gates
/// and filesystem reserve phase-one refusals therefore run here, before
/// that wipe. Phase-two work and normal init concerns remain on the init
/// path. Every check below is a read, so running it twice costs nothing
/// and decides nothing.
///
/// # Errors
///
/// Returns the endpoint/configuration gate errors and filesystem reserve
/// phase-one refusals that apply before reinit wipes `OpenBao`.
pub(crate) fn preflight_audit_store(
    inputs: &AuditStoreInitInputs<'_>,
    messages: &Messages,
) -> Result<()> {
    if let AuditStorePlan::Provision(view) = select_audit_store_plan(inputs, messages)? {
        // Phase-1 refusals only, and every one of them a pure read: a
        // sub-minimum reserve, a store path the artifacts cannot carry,
        // an image of the wrong type or the wrong size, a filesystem
        // with no room for the outstanding allocation, and an
        // underlying store larger than the reserve. Nothing is
        // created, nothing is rendered, nothing is installed, no mount
        // is verified and no outcome line is printed — a refusal
        // raised for the first time by the post-wipe `init` pass would
        // land after the OpenBao wipe.
        if view.enforcement == AuditStoreEnforcement::Filesystem {
            let compose_dir = compose_file_dir(inputs.compose_file);
            let identity = ComposeIdentity::resolve(inputs.compose_file, None, messages)?;
            let reserve_inputs = reserve_inputs(inputs, &view, &compose_dir, identity.project());
            let facts = reserve::evaluate(&reserve_inputs, &reserve::HostProbe, messages)?;
            // The one deliberate consequence, raised here rather than
            // by the post-wipe pass: a host whose store already holds
            // records cannot reinit until enforcement is activated or
            // `directory` mode is configured. The post-wipe pass would
            // reach the same verdict, after the records the verdict
            // exists to protect had already survived a wipe that had
            // no reason to spare them.
            // The holding-directory refusal comes first here too. A
            // reinit run while a migration is open would wipe OpenBao
            // and then meet the same verdict on the post-wipe pass,
            // with the records the verdict exists to protect having
            // already survived a wipe that had no reason to spare them.
            if facts.migration_open() {
                anyhow::bail!(messages.audit_reserve_finding_migration_holding(
                    &facts.migration.paths.holding.display().to_string(),
                    &facts.store_dir.display().to_string(),
                ));
            }
            if facts.underlying_not_empty() {
                anyhow::bail!(messages.audit_reserve_finding_store_not_empty(
                    &view.audit_store_dir.display().to_string(),
                    &facts.migration.paths.holding.display().to_string(),
                ));
            }
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
        AuditStorePlan::Provision(view) => match view.enforcement {
            AuditStoreEnforcement::Directory => {
                // The explicit opt-out, and its own complete path. The
                // store is created exactly as before this surface
                // existed, all three directories in one pass; no image
                // path or unit name is derived and no leftover of a
                // previous `filesystem`-mode run is looked for. The one
                // path this mode does read is the holding directory,
                // because an unfinished migration is detected in both
                // enforcement modes — here it is named rather than
                // raised as an outcome.
                let migration = reserve::detect_migration(
                    &view.audit_store_dir,
                    &reserve::HostProbe,
                    messages,
                )?;
                create_layout(&view.audit_store_dir, inputs.expected_uid).map_err(|err| {
                    anyhow::anyhow!(layout_error_message(
                        &err,
                        StoreCheckCaller::Init,
                        inputs.expected_uid,
                        messages
                    ))
                })?;
                let rendered = write_audit_override(
                    &compose_file_dir(inputs.compose_file),
                    &view.audit_store_dir,
                    messages,
                )?;
                println!(
                    "{}",
                    reserve::render_directory_outcome(
                        &view.audit_store_dir,
                        view.reserve_bytes,
                        &migration,
                        messages
                    )
                );
                Ok(Some(rendered))
            }
            AuditStoreEnforcement::Filesystem => {
                let compose_dir = compose_file_dir(inputs.compose_file);
                let identity = ComposeIdentity::resolve(inputs.compose_file, None, messages)?;
                let reserve_inputs =
                    reserve_inputs(inputs, &view, &compose_dir, identity.project());
                let probe = reserve::HostProbe;
                // Phase 1. Every refusal below is a read, and it runs
                // before the one filesystem object this path creates.
                let facts = reserve::evaluate(&reserve_inputs, &probe, messages)?;
                // A migration in progress overrides every other
                // verdict and creates nothing on the mounted store, so
                // it is reported before the one filesystem object this
                // path would otherwise create. The three artifacts are
                // still written: they are inert files the operator
                // needs, and the outcome's own rendering names them.
                if facts.migration_open() {
                    let artifacts = reserve::render_artifacts(&reserve_inputs, &facts);
                    reserve::write_artifacts(&artifacts, messages)?;
                    let report =
                        reserve::verify(&reserve_inputs, &facts, &artifacts, &probe, messages)?;
                    anyhow::bail!(reserve::render_filesystem_outcome(
                        &reserve_inputs,
                        &facts,
                        &artifacts,
                        &report,
                        messages
                    ));
                }
                // Everything below is the *simplified* store path
                // phase 1 established, never the configured spelling.
                // The mount point has to be the directory `Where=`
                // names, and the override's bind source has to be the
                // directory the mount covers; deriving the artifacts
                // from one path and creating the other is how a
                // configured `…/audit-store/.` provisions a store no
                // unit ever mounts.
                let store_dir = facts.store_dir.as_path();
                // The mount point, and nothing beneath it. Its
                // subdirectories come into being on the mounted
                // filesystem, which is step 4 of the rendered list and
                // the operator's to run.
                create_mount_point(store_dir, inputs.expected_uid, !facts.mount_present())
                    .map_err(|err| {
                        anyhow::anyhow!(layout_error_message(
                            &err,
                            StoreCheckCaller::Init,
                            inputs.expected_uid,
                            messages
                        ))
                    })?;
                let rendered = write_audit_override(
                    &compose_file_dir(inputs.compose_file),
                    store_dir,
                    messages,
                )?;
                let artifacts = reserve::render_artifacts(&reserve_inputs, &facts);
                reserve::write_artifacts(&artifacts, messages)?;
                // Phase 3.
                let report =
                    reserve::verify(&reserve_inputs, &facts, &artifacts, &probe, messages)?;
                let outcome = reserve::render_filesystem_outcome(
                    &reserve_inputs,
                    &facts,
                    &artifacts,
                    &report,
                    messages,
                );
                if !matches!(report, reserve::ReserveReport::Enforced { .. }) {
                    // The run fails under this outcome. It does not
                    // report success, rewrite `audit_store_enforcement`
                    // or continue as `directory`.
                    anyhow::bail!(outcome);
                }
                println!("{outcome}");
                Ok(Some(rendered))
            }
        },
    }
}

/// Assembles what the reserve derives everything from out of the two
/// halves the install side holds it in.
///
/// `compose_dir` and `compose_project` are passed in rather than read
/// off `inputs` because both are derived from the one compose file it
/// carries — the directory by [`compose_file_dir`] and the project by
/// [`ComposeIdentity`] — and the caller owns them for as long as the
/// borrowed inputs live.
fn reserve_inputs<'a>(
    inputs: &'a AuditStoreInitInputs<'a>,
    view: &'a AgentConfigView,
    compose_dir: &'a Path,
    compose_project: &'a str,
) -> reserve::ReserveInputs<'a> {
    reserve::ReserveInputs {
        store_dir: &view.audit_store_dir,
        compose_dir,
        compose_file: inputs.compose_file,
        compose_project,
        reserve_bytes: view.reserve_bytes,
        max_file_bytes: view.max_file_bytes,
        max_retained_files: view.max_retained_files,
        expected_uid: inputs.expected_uid,
        rerun_command: RESERVE_RERUN_COMMAND,
    }
}

/// Runs the audit-store portion of `bootroot infra up` before any Docker
/// invocation. It reads and renders the reserve phases, but performs none of
/// their phase-two host changes.
///
/// # Errors
///
/// Returns an error when the required configuration is absent or disagrees
/// with state, the rendered override is stale or unreadable, or filesystem
/// enforcement is anything short of enforced.
pub(crate) fn prepare_audit_store_for_infra_up(
    state_path: &Path,
    compose_file: &Path,
    agent_config: Option<&Path>,
    expected_uid: u32,
    messages: &Messages,
) -> Result<Option<PathBuf>> {
    // The compose file rather than its directory, so the Compose stop
    // the migration renders names the file this run was pointed at and
    // the override lands beside that same file.
    let compose_dir = compose_file_dir(compose_file);
    let compose_dir = compose_dir.as_path();
    let override_path = audit_override_path(compose_dir);
    let override_present = override_path.exists();
    let endpoint_recorded = if state_path.exists() {
        StateFile::load(state_path)?
            .registrar_endpoint
            .as_ref()
            .is_some_and(|recorded| recorded.enabled)
    } else {
        false
    };

    // This is intentionally before loading the configuration. A host that
    // never enabled the endpoint has no override, so `infra up` must keep its
    // pre-audit-store behavior without opening a configuration file.
    if !endpoint_recorded && !override_present {
        return Ok(None);
    }
    let agent_config = agent_config.ok_or_else(|| {
        anyhow::anyhow!(messages.error_audit_store_agent_config_required("bootroot infra up"))
    })?;
    let view = load_agent_config(agent_config, messages)?;
    if view.endpoint_enabled != endpoint_recorded {
        anyhow::bail!(messages.error_audit_store_enablement_mismatch(
            &state_path.display().to_string(),
            endpoint_recorded,
            &agent_config.display().to_string(),
            view.endpoint_enabled,
        ));
    }
    if !endpoint_recorded {
        return Ok(None);
    }
    if !override_present {
        anyhow::bail!(messages.error_audit_store_override_missing());
    }

    // The old short form remains a supported input. Compare before rewriting
    // it so the upgrade never silently points an existing deployment at the
    // store named by a different configuration file.
    let rendered_store = read_audit_override_store_dir(&override_path, messages)?;
    if rendered_store != view.audit_store_dir {
        anyhow::bail!(messages.error_audit_store_override_stale(
            &rendered_store.display().to_string(),
            &view.audit_store_dir.display().to_string(),
        ));
    }
    upgrade_audit_override(&override_path, messages)?;

    match view.enforcement {
        AuditStoreEnforcement::Directory => {
            // Before every other verdict, in both enforcement modes.
            let migration =
                reserve::detect_migration(&rendered_store, &reserve::HostProbe, messages)?;
            check_store_directory(&rendered_store, expected_uid).map_err(|err| {
                anyhow::anyhow!(layout_error_message(
                    &err,
                    StoreCheckCaller::InfraUp,
                    expected_uid,
                    messages
                ))
            })?;
            println!(
                "{}",
                reserve::render_directory_outcome(
                    &rendered_store,
                    view.reserve_bytes,
                    &migration,
                    messages
                )
            );
            Ok(Some(override_path))
        }
        AuditStoreEnforcement::Filesystem => {
            verify_filesystem_reserve_for_infra_up(
                &view,
                compose_dir,
                compose_file,
                agent_config,
                expected_uid,
                messages,
            )?;
            Ok(Some(override_path))
        }
    }
}

/// Runs the reserve's phases for a `filesystem`-mode `bootroot infra up`
/// and refuses every outcome short of **enforced**.
///
/// # Errors
///
/// Returns the phase-1 refusals, the store-directory contract error, and
/// the rendered **migration incomplete** or **provisioned, not
/// activated** outcome, each of which stops the bring-up before any
/// Docker call.
fn verify_filesystem_reserve_for_infra_up(
    view: &AgentConfigView,
    compose_dir: &Path,
    compose_file: &Path,
    agent_config: &Path,
    expected_uid: u32,
    messages: &Messages,
) -> Result<()> {
    let rerun_command = format!(
        "bootroot infra up --agent-config {}",
        reserve::sh_quote_path(agent_config)
    );
    let identity = ComposeIdentity::resolve(compose_file, None, messages)?;
    let inputs = reserve::ReserveInputs {
        store_dir: &view.audit_store_dir,
        compose_dir,
        compose_file,
        compose_project: identity.project(),
        reserve_bytes: view.reserve_bytes,
        max_file_bytes: view.max_file_bytes,
        max_retained_files: view.max_retained_files,
        expected_uid,
        rerun_command: &rerun_command,
    };
    let probe = reserve::HostProbe;
    let facts = reserve::evaluate(&inputs, &probe, messages)?;
    // The migration verdict comes ahead of the store-directory check as
    // well: while a migration is open the mount point carries whatever
    // mode the activation step has reached, and the migration outcome
    // is what tells the operator how to finish rather than a refusal
    // naming a mode.
    if !facts.migration_open() && facts.mount_present() {
        // Phase 3 deliberately does not assert the mounted filesystem
        // root's mode. Keep the existing bring-up contract where a mount
        // is present: the root itself is `audit_store_dir` and must be
        // the operator-owned `0700` store before Docker can bind into it.
        check_store_directory(&facts.store_dir, expected_uid).map_err(|err| {
            anyhow::anyhow!(layout_error_message(
                &err,
                StoreCheckCaller::InfraUp,
                expected_uid,
                messages
            ))
        })?;
    }
    let artifacts = reserve::render_artifacts(&inputs, &facts);
    reserve::write_artifacts(&artifacts, messages)?;
    let report = reserve::verify(&inputs, &facts, &artifacts, &probe, messages)?;
    let outcome =
        reserve::render_filesystem_outcome(&inputs, &facts, &artifacts, &report, messages);
    if !matches!(report, reserve::ReserveReport::Enforced { .. }) {
        anyhow::bail!(outcome);
    }
    println!("{outcome}");
    Ok(())
}

/// Rewrites the former scalar audit bind to the guarded long form.
///
/// The source is first recovered from the existing override and is never
/// derived from configuration: the rewrite changes Compose syntax, not where
/// an already-running deployment writes its audit device.
fn upgrade_audit_override(override_path: &Path, messages: &Messages) -> Result<()> {
    let display = override_path.display().to_string();
    let content = std::fs::read_to_string(override_path)
        .with_context(|| messages.error_read_file_failed(&display))?;
    if read_audit_override_bind_source(&content).is_none() {
        anyhow::bail!(messages.error_audit_store_override_unreadable(&display));
    }
    if collect_openbao_volume_entries(&content)
        .iter()
        .any(|entry| {
            entry.starts_with("type: bind\n")
                && entry.lines().any(|line| {
                    line.trim().strip_prefix("target:").map(str::trim)
                        == Some(OPENBAO_AUDIT_CONTAINER_PATH)
                })
        })
    {
        return Ok(());
    }

    let suffix = format!(":{OPENBAO_AUDIT_CONTAINER_PATH}");
    let mut rewritten = String::with_capacity(content.len() + 100);
    let mut replaced = false;
    for line in content.split_inclusive('\n') {
        let newline = line.strip_suffix('\n').unwrap_or(line);
        let indentation = newline.len() - newline.trim_start().len();
        let trimmed = newline.trim();
        if !replaced && trimmed.starts_with('-') {
            let value = trimmed.trim_start_matches('-').trim();
            let unquoted = compose_unquote(value);
            if let Some(source) = unquoted.strip_suffix(suffix.as_str()) {
                let indent = " ".repeat(indentation);
                let source = compose_quote(source);
                let _ = write!(
                    rewritten,
                    "{indent}- type: bind\n{indent}  source: {source}\n{indent}  target: {OPENBAO_AUDIT_CONTAINER_PATH}\n{indent}  bind:\n{indent}    create_host_path: false\n"
                );
                replaced = true;
                continue;
            }
        }
        rewritten.push_str(line);
    }
    if !replaced {
        anyhow::bail!(messages.error_audit_store_override_unreadable(&display));
    }
    fs_util::atomic_replace_dir_owner_blocking(
        fs_util::Destination::operator_named(override_path),
        rewritten.as_bytes(),
        fs_util::StagedMode::PreserveOrCreate(OVERRIDE_FILE_MODE),
    )
    .with_context(|| messages.error_write_file_failed(&display))
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
#[cfg(test)]
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

    /// 16 MiB — the `filesystem`-mode floor, and the smallest reserve
    /// a test can ask a host to have room for.
    const RESERVE_FLOOR_FOR_TESTS: u64 = 16 * 1024 * 1024;

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

        /// The `--compose-file` a run is pointed at. Its directory is
        /// [`Fixture::compose_dir`], which is what the override is
        /// rendered into and the artifacts are staged under.
        fn compose_file(&self) -> PathBuf {
            self.compose_dir().join("docker-compose.yml")
        }

        fn store_dir(&self) -> PathBuf {
            self.base.path().join("audit-store")
        }

        /// The layout and override assertions below are about the
        /// path `directory` mode keeps verbatim — all three
        /// directories created in one pass, the override rendered,
        /// the run continuing. `filesystem` mode's own path has its
        /// own tests in [`super::reserve::tests`], so these say which
        /// mode they mean rather than riding on the default.
        fn agent_config(&self, enabled: bool) -> PathBuf {
            self.agent_config_for(&self.store_dir(), enabled)
        }

        fn agent_config_for(&self, store_dir: &Path, enabled: bool) -> PathBuf {
            self.agent_config_in_mode(store_dir, enabled, "directory")
        }

        fn agent_config_in_mode(
            &self,
            store_dir: &Path,
            enabled: bool,
            enforcement: &str,
        ) -> PathBuf {
            write_agent_config(
                self.base.path(),
                &format!(
                    "[registrar]\naudit_store_dir = \"{}\"\naudit_store_enforcement = \"{enforcement}\"\n\n[registrar_endpoint]\nenabled = {enabled}\n",
                    store_dir.display()
                ),
            )
        }

        fn state(&self, endpoint: Option<bool>) -> PathBuf {
            write_state(self.base.path(), endpoint)
        }

        /// A `filesystem`-mode configuration whose reserve is the
        /// smallest one that clears the minimum, so the free-space
        /// preflight asks the host for 16 MiB rather than for the
        /// shipped 2 GiB default.
        fn filesystem_agent_config(&self, enabled: bool) -> PathBuf {
            self.filesystem_agent_config_with(enabled, RESERVE_FLOOR_FOR_TESTS)
        }

        fn filesystem_agent_config_with(&self, enabled: bool, reserve: u64) -> PathBuf {
            self.filesystem_agent_config_at(&self.store_dir(), enabled, reserve)
        }

        /// The same, over a store path the caller spells itself, so a
        /// test can configure one that is not simplified.
        fn filesystem_agent_config_at(
            &self,
            store_dir: &Path,
            enabled: bool,
            reserve: u64,
        ) -> PathBuf {
            write_agent_config(
                self.base.path(),
                &format!(
                    "[registrar]\naudit_store_dir = \"{}\"\naudit_store_enforcement = \"filesystem\"\naudit_store_reserve_bytes = {reserve}\naudit_store_low_water_bytes = 1024\naudit_max_file_bytes = 65536\naudit_max_retained_files = 1\n\n[registrar_endpoint]\nenabled = {enabled}\n",
                    store_dir.display()
                ),
            )
        }

        fn image_path(&self) -> PathBuf {
            self.base.path().join("audit-store.img")
        }

        fn artifact_dir(&self) -> PathBuf {
            self.compose_dir().join("audit-store")
        }

        fn inputs<'a>(
            agent_config: Option<&'a Path>,
            state_path: &'a Path,
            endpoint_recorded: bool,
            compose_file: &'a Path,
        ) -> AuditStoreInitInputs<'a> {
            AuditStoreInitInputs {
                compose_file,
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
        let compose_file = fixture.compose_file();
        let err = apply_audit_store(
            &Fixture::inputs(None, &state, true, &compose_file),
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
        let compose_file = fixture.compose_file();
        let rendered = write_audit_override(&compose_dir, &fixture.store_dir(), &test_messages())
            .expect("render");
        let before = fs::read(&rendered).expect("read");
        let state = fixture.state(Some(false));

        let err = apply_audit_store(
            &Fixture::inputs(None, &state, false, &compose_file),
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
        let compose_file = fixture.compose_file();
        let selected = apply_audit_store(
            &Fixture::inputs(None, &state, false, &compose_file),
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
        let compose_file = fixture.compose_file();
        let agent_config = fixture.agent_config(true);
        let err = apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, false, &compose_file),
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
            let compose_file = fixture.compose_file();
            let agent_config = fixture.agent_config(body_enabled);
            let err = apply_audit_store(
                &Fixture::inputs(Some(&agent_config), &state, recorded, &compose_file),
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
        let compose_file = fixture.compose_file();
        let agent_config = write_agent_config(
            fixture.base.path(),
            &format!(
                "[registrar]\naudit_store_dir = \"{}\"\n",
                fixture.store_dir().display()
            ),
        );
        apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
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
                    let compose_file = fixture.compose_file();
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
                            &compose_file,
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
        let compose_file = fixture.compose_file();
        let agent_config = fixture.agent_config(true);
        apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
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
        let compose_file = fixture.compose_file();
        let agent_config = fixture.agent_config(true);
        let selected = apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
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
        assert!(content.contains("- type: bind"), "{content}");
        assert!(
            content.contains(&format!("source: '{}/openbao'", store.display())),
            "{content}"
        );
        assert!(
            content.contains(
                "target: /openbao/audit\n        bind:\n          create_host_path: false"
            ),
            "{content}"
        );
    }

    #[test]
    fn a_disabled_predicate_creates_nothing_and_renders_nothing() {
        for recorded in [None, Some(false)] {
            let fixture = Fixture::new();
            let state = fixture.state(recorded);
            let compose_dir = fixture.compose_dir();
            let compose_file = fixture.compose_file();
            let agent_config = fixture.agent_config(false);
            let selected = apply_audit_store(
                &Fixture::inputs(Some(&agent_config), &state, false, &compose_file),
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
        let compose_file = fixture.compose_file();
        let agent_config = fixture.agent_config(true);
        let store = fixture.store_dir();
        fs::create_dir(&store).expect("store");
        fs::set_permissions(&store, fs::Permissions::from_mode(0o750)).expect("chmod");

        let err = apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
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
        let compose_file = fixture.compose_file();
        let agent_config = fixture.agent_config_for(&store, true);

        let err = apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
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
        let compose_file = fixture.compose_file();
        let agent_config = fixture.agent_config(true);
        apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
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
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
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
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
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
    /// before it re-runs `init`, so the endpoint/configuration gates and
    /// filesystem reserve phase-one refusals must be reachable ahead of
    /// that wipe. This asserts they are, and that accepted runs leave the
    /// filesystem exactly as they found it.
    #[test]
    fn the_preflight_raises_endpoint_configuration_gates_without_touching_anything() {
        // The required flag, on the two runs that require it.
        let fixture = Fixture::new();
        let compose_dir = fixture.compose_dir();
        let compose_file = fixture.compose_file();
        let state = fixture.state(Some(true));
        let err = preflight_audit_store(
            &Fixture::inputs(None, &state, true, &compose_file),
            &test_messages(),
        )
        .expect_err("refused");
        assert!(err.to_string().contains("--agent-config"), "{err}");
        assert!(!fixture.store_dir().exists());

        // The enablement cross-check.
        let disagreeing = fixture.agent_config(false);
        preflight_audit_store(
            &Fixture::inputs(Some(&disagreeing), &state, true, &compose_file),
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
            &Fixture::inputs(Some(&bad), &state, true, &compose_file),
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
            &Fixture::inputs(Some(&agreeing), &state, true, &compose_file),
            &test_messages(),
        )
        .expect("accepted");
        assert!(
            !fixture.store_dir().exists(),
            "the preflight created a store"
        );
        assert_eq!(fs::read(&rendered).expect("read"), before);
    }

    /// A fresh filesystem-mode host has no rendered override for the
    /// pre-wipe preflight to read. Once it clears phase one, it must
    /// proceed to the ordinary init path, which renders the override,
    /// reports the not-activated outcome, and gives the operator the
    /// phase-two commands exactly as a direct init would.
    #[test]
    fn the_preflight_leaves_fresh_filesystem_provisioning_to_init() {
        let fixture = Fixture::new();
        let compose_dir = fixture.compose_dir();
        let compose_file = fixture.compose_file();
        let state = fixture.state(Some(true));
        let agreeing = fixture.filesystem_agent_config(true);
        let inputs = Fixture::inputs(Some(&agreeing), &state, true, &compose_file);

        preflight_audit_store(&inputs, &test_messages()).expect("phase one clears");
        assert!(!fixture.store_dir().exists());
        assert!(!audit_override_path(&compose_dir).exists());
        assert!(!fixture.artifact_dir().exists());

        let outcome = apply_audit_store(&inputs, &test_messages())
            .expect_err("ordinary init reports the phase-two outcome");
        let text = outcome.to_string();
        assert!(text.contains("provisioned, not activated"), "{text}");
        let rerun = test_messages().audit_reserve_step_rerun(RESERVE_RERUN_COMMAND);
        for step in [
            test_messages().audit_reserve_step_image(),
            test_messages().audit_reserve_step_install(),
            test_messages().audit_reserve_step_subdirectories(),
            rerun.as_str(),
        ] {
            assert!(text.contains(step), "missing {step:?} from {text}");
        }
        assert!(audit_override_path(&compose_dir).exists());
        assert!(fixture.artifact_dir().is_dir());
    }

    #[test]
    fn the_preflight_defers_stale_override_and_ancestor_checks_to_init() {
        // A stale override is an ordinary init concern. The preflight
        // leaves it byte-identical and does not stop the wipe.
        let fixture = Fixture::new();
        let compose_dir = fixture.compose_dir();
        let compose_file = fixture.compose_file();
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
            &Fixture::inputs(Some(&agreeing), &state, true, &compose_file),
            &test_messages(),
        )
        .expect("the stale override is deferred to init");
        assert_eq!(fs::read(&rendered).expect("read"), before);

        // An ancestor without `o+x` is likewise a layout check for the
        // ordinary init pass, not a filesystem reserve phase-one fact.
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let tight = fixture.base.path().join("tight");
        fs::create_dir(&tight).expect("ancestor");
        fs::set_permissions(&tight, fs::Permissions::from_mode(0o700)).expect("chmod");
        let store = tight.join("audit-store");
        let agent_config =
            fixture.filesystem_agent_config_at(&store, true, RESERVE_FLOOR_FOR_TESTS);
        preflight_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
            &test_messages(),
        )
        .expect("the ancestor check is deferred to init");
        assert!(!store.exists());
    }

    /// The unwinding run is a refusal source too, and the preflight must
    /// not perform the deletion it is only checking for.
    #[test]
    fn the_preflight_leaves_an_override_it_would_unwind_on_disk() {
        let fixture = Fixture::new();
        let compose_dir = fixture.compose_dir();
        let compose_file = fixture.compose_file();
        let rendered = write_audit_override(&compose_dir, &fixture.store_dir(), &test_messages())
            .expect("render");
        let state = fixture.state(Some(false));

        preflight_audit_store(
            &Fixture::inputs(None, &state, false, &compose_file),
            &test_messages(),
        )
        .expect_err("the rendered override keeps the flag mandatory");
        assert!(rendered.exists());

        let disabling = fixture.agent_config(false);
        preflight_audit_store(
            &Fixture::inputs(Some(&disabling), &state, false, &compose_file),
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
        let compose_file = fixture.compose_file();
        let store_dir = fixture.store_dir();
        let agent_config = fixture.agent_config(true);
        let state = fixture.state(Some(true));

        let foreign_uid = current_process_euid().wrapping_add(1);
        let err = apply_audit_store(
            &AuditStoreInitInputs {
                compose_file: &compose_file,
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

    /// Reinit's preflight is deliberately phase-one-only. An ordinary
    /// init still rejects an unprivileged provisioning process, but
    /// reinit leaves that post-wipe/init concern to its init pass.
    #[test]
    fn the_preflight_defers_the_unprivileged_refusal_to_init() {
        let fixture = Fixture::new();
        let compose_dir = fixture.compose_dir();
        let compose_file = fixture.compose_file();
        let store_dir = fixture.store_dir();
        let agent_config = fixture.agent_config(true);
        let state = fixture.state(Some(true));
        write_audit_override(&compose_dir, &store_dir, &test_messages()).expect("render");

        let foreign_uid = current_process_euid().wrapping_add(1);
        preflight_audit_store(
            &AuditStoreInitInputs {
                compose_file: &compose_file,
                agent_config: Some(&agent_config),
                state_path: &state,
                endpoint_recorded: true,
                expected_uid: foreign_uid,
            },
            &test_messages(),
        )
        .expect("the uid check is deferred to init");
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
        let compose_file = fixture.compose_file();
        let store_dir = fixture.store_dir();
        let rendered =
            write_audit_override(&compose_dir, &store_dir, &test_messages()).expect("render");
        let agent_config = fixture.agent_config(false);
        let state = fixture.state(Some(false));

        let selected = apply_audit_store(
            &AuditStoreInitInputs {
                compose_file: &compose_file,
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
        let compose_file = fixture.compose_file();
        let recorded_store = fixture.base.path().join("old-store");
        let rendered =
            write_audit_override(&compose_dir, &recorded_store, &test_messages()).expect("render");
        let before = fs::read(&rendered).expect("read");

        let configured_store = fixture.base.path().join("new-store");
        let agent_config = fixture.agent_config_for(&configured_store, true);
        let state = fixture.state(Some(true));

        let err = apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
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
        let compose_file = fixture.compose_file();
        let enabling = fixture.agent_config(true);
        let provisioned_state = fixture.state(Some(true));
        apply_audit_store(
            &Fixture::inputs(Some(&enabling), &provisioned_state, true, &compose_file),
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
            &Fixture::inputs(Some(&enabling), &state, false, &compose_file),
            &test_messages(),
        )
        .expect_err("refused on disagreement");
        assert!(rendered.exists());

        // An `init` given no configuration fails naming the flag.
        apply_audit_store(
            &Fixture::inputs(None, &state, false, &compose_file),
            &test_messages(),
        )
        .expect_err("the rendered override keeps the flag mandatory");
        assert!(rendered.exists());

        // Only an agreeing `false` deletes it.
        let disabling = fixture.agent_config(false);
        let selected = apply_audit_store(
            &Fixture::inputs(Some(&disabling), &state, false, &compose_file),
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

    /// Returns the fixture, its `state.json`, the compose directory
    /// the override is rendered into and the compose file a run is
    /// pointed at.
    fn provisioned_fixture() -> (Fixture, PathBuf, PathBuf, PathBuf) {
        let fixture = Fixture::new();
        let compose_dir = fixture.compose_dir();
        let compose_file = fixture.compose_file();
        let agent_config = fixture.agent_config(true);
        let state = fixture.state(Some(true));
        apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
            &test_messages(),
        )
        .expect("provisioned");
        (fixture, state, compose_dir, compose_file)
    }

    #[test]
    fn infra_up_requires_its_agent_config_before_selecting_an_override() {
        let (_fixture, state, _compose_dir, compose_file) = provisioned_fixture();
        let err = prepare_audit_store_for_infra_up(
            &state,
            &compose_file,
            None,
            current_process_euid(),
            &test_messages(),
        )
        .expect_err("missing agent config");
        assert!(err.to_string().contains("bootroot infra up"), "{err}");
        assert!(err.to_string().contains("--agent-config"), "{err}");
    }

    #[test]
    fn infra_up_requires_its_agent_config_for_a_stale_override() {
        let (fixture, _state, _compose_dir, compose_file) = provisioned_fixture();
        let disabled_state = fixture.state(Some(false));
        let err = prepare_audit_store_for_infra_up(
            &disabled_state,
            &compose_file,
            None,
            current_process_euid(),
            &test_messages(),
        )
        .expect_err("an override still requires its configuration");
        assert!(err.to_string().contains("bootroot infra up"), "{err}");
        assert!(err.to_string().contains("--agent-config"), "{err}");
    }

    #[test]
    fn infra_up_rejects_an_agent_config_with_a_different_enablement() {
        let (fixture, state, _compose_dir, compose_file) = provisioned_fixture();
        let disabled_config = fixture.agent_config(false);
        let err = prepare_audit_store_for_infra_up(
            &state,
            &compose_file,
            Some(&disabled_config),
            current_process_euid(),
            &test_messages(),
        )
        .expect_err("different endpoint predicates are refused");
        assert!(err.to_string().contains("enablement disagrees"), "{err}");
        assert!(
            err.to_string().contains(&state.display().to_string()),
            "{err}"
        );
        assert!(
            err.to_string()
                .contains(&disabled_config.display().to_string()),
            "{err}"
        );
    }

    #[test]
    fn infra_up_leaves_a_never_enabled_host_without_configuration_reads() {
        let fixture = Fixture::new();
        let state = fixture.state(Some(false));
        let absent_config = fixture.base.path().join("does-not-exist.toml");
        assert!(
            prepare_audit_store_for_infra_up(
                &state,
                &fixture.compose_file(),
                Some(&absent_config),
                current_process_euid(),
                &test_messages(),
            )
            .expect("endpoint-disabled host is untouched")
            .is_none()
        );
    }

    #[test]
    fn infra_up_upgrades_a_legacy_override_without_repointing_it() {
        let (fixture, state, compose_dir, compose_file) = provisioned_fixture();
        let config = fixture.agent_config(true);
        let path = audit_override_path(&compose_dir);
        let store = fixture.store_dir();
        let source = format!("{}/{OPENBAO_SUBDIR}", store.display());
        fs::write(
            &path,
            format!(
                "services:\n  openbao:\n    volumes: !override\n      - {OPENBAO_DATA_MOUNT}\n      - {}\n      - {OPENBAO_CONFIG_MOUNT}\n",
                compose_quote(&format!("{source}:{OPENBAO_AUDIT_CONTAINER_PATH}"))
            ),
        )
        .expect("legacy override");

        prepare_audit_store_for_infra_up(
            &state,
            &compose_file,
            Some(&config),
            current_process_euid(),
            &test_messages(),
        )
        .expect("directory mode succeeds");
        let upgraded = fs::read_to_string(&path).expect("upgraded override");
        assert!(
            upgraded.contains(&format!("source: {}", compose_quote(&source))),
            "{upgraded}"
        );
        assert!(upgraded.contains("create_host_path: false"), "{upgraded}");

        prepare_audit_store_for_infra_up(
            &state,
            &compose_file,
            Some(&config),
            current_process_euid(),
            &test_messages(),
        )
        .expect("long form remains valid");
        assert_eq!(fs::read_to_string(&path).expect("second read"), upgraded);
    }

    #[test]
    fn infra_up_renders_and_refuses_an_unactivated_filesystem_reserve() {
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let compose_dir = fixture.compose_dir();
        let compose_file = fixture.compose_file();
        let config = fixture.filesystem_agent_config(true);
        let quoted_config = fixture
            .base
            .path()
            .join("agent config; $(touch ignored) '$HOME.toml");
        fs::rename(&config, &quoted_config).expect("rename config to a shell-sensitive path");
        write_audit_override(&compose_dir, &fixture.store_dir(), &test_messages())
            .expect("override");

        let err = prepare_audit_store_for_infra_up(
            &state,
            &compose_file,
            Some(&quoted_config),
            current_process_euid(),
            &test_messages(),
        )
        .expect_err("unactivated reserve refuses bring-up");
        let output = err.to_string();
        assert!(output.contains("provisioned, not activated"), "{output}");
        assert!(
            output.contains(&format!(
                "bootroot infra up --agent-config '{}'",
                quoted_config.display().to_string().replace('\'', "'\\''")
            )),
            "{output}"
        );
        assert!(fixture.artifact_dir().is_dir());
    }

    #[test]
    fn a_bring_up_selects_the_override_over_a_conforming_store() {
        let (fixture, state, compose_dir, _compose_file) = provisioned_fixture();
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
        let (_fixture, state, compose_dir, _compose_file) = provisioned_fixture();
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
            let (fixture, state, compose_dir, _compose_file) = provisioned_fixture();
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
        let (fixture, state, compose_dir, _compose_file) = provisioned_fixture();
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

    /// The mounted store root's own contract is enforced on the
    /// bring-up, which is the surface the issue assigns it to.
    ///
    /// Phase 3 verifies the image, the three artifacts, the mount
    /// identity and the two subdirectories — the four checks
    /// `enforced` is defined as. The root directory of the mounted
    /// filesystem is not among them: `mkfs.ext4` gives it `0755`, and
    /// bringing it to `0700` is phase-2 step 4's rendered `chmod`,
    /// there so that "the store directory contract — the one
    /// `bootroot infra up` applies to the path the rendered override
    /// names" holds. This asserts that the check is really there, so
    /// an operator who skipped that `chmod` is refused before any
    /// container binds into the store.
    #[test]
    fn a_bring_up_refuses_a_filesystem_mode_store_root_left_at_the_mkfs_mode() {
        let messages = test_messages();
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let compose_dir = fixture.compose_dir();
        let compose_file = fixture.compose_file();
        let agent_config = fixture.filesystem_agent_config(true);
        apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
            &messages,
        )
        .expect_err("provisioned, not activated");

        let store = fixture.store_dir();
        // What an `lstat` of the mount point sees once the operator
        // has mounted the reserve and not yet run step 4's `chmod`.
        fs::set_permissions(&store, fs::Permissions::from_mode(0o755)).expect("chmod");

        let err = resolve_audit_override(&state, &compose_dir, current_process_euid(), &messages)
            .expect_err("refused");
        let rendered = err.to_string();
        let store = store.display().to_string();
        assert!(rendered.contains(&store), "{rendered}");
        assert!(
            rendered.contains(&format!("chmod 0700 {store}")),
            "{rendered}"
        );
    }

    #[test]
    fn a_disabled_predicate_selects_nothing_and_leaves_a_rendered_file_inert() {
        let (fixture, _state, compose_dir, _compose_file) = provisioned_fixture();
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

    #[test]
    fn the_reader_accepts_the_previous_short_bind_form() {
        let dir = traversable_tempdir();
        let store = dir.path().join("legacy-store");
        let path = audit_override_path(dir.path());
        fs::create_dir_all(path.parent().expect("parent")).expect("override parent");
        fs::write(
            &path,
            format!(
                "services:\n  openbao:\n    volumes: !override\n      - {OPENBAO_DATA_MOUNT}\n      - {}\n      - {OPENBAO_CONFIG_MOUNT}\n",
                compose_quote(&format!(
                    "{}/{OPENBAO_SUBDIR}:{OPENBAO_AUDIT_CONTAINER_PATH}",
                    store.display()
                ))
            ),
        )
        .expect("legacy override");

        assert_eq!(
            read_audit_override_store_dir(&path, &test_messages()).expect("read legacy form"),
            store
        );
    }

    #[test]
    fn upgrading_a_legacy_bind_preserves_its_source_and_is_idempotent() {
        let dir = traversable_tempdir();
        let store = dir.path().join("legacy store$with'quote");
        let path = audit_override_path(dir.path());
        fs::create_dir_all(path.parent().expect("parent")).expect("override parent");
        let source = format!("{}/{OPENBAO_SUBDIR}", store.display());
        fs::write(
            &path,
            format!(
                "services:\n  openbao:\n    volumes: !override\n      - {OPENBAO_DATA_MOUNT}\n      - {}\n      - {OPENBAO_CONFIG_MOUNT}\n",
                compose_quote(&format!("{source}:{OPENBAO_AUDIT_CONTAINER_PATH}"))
            ),
        )
        .expect("legacy override");

        upgrade_audit_override(&path, &test_messages()).expect("upgrade");
        let upgraded = fs::read_to_string(&path).expect("upgraded override");
        assert!(
            upgraded.contains(&format!("source: {}", compose_quote(&source))),
            "{upgraded}"
        );
        assert!(upgraded.contains("create_host_path: false"), "{upgraded}");
        assert_eq!(
            read_audit_override_store_dir(&path, &test_messages()).expect("read upgraded form"),
            store
        );

        upgrade_audit_override(&path, &test_messages()).expect("second upgrade");
        assert_eq!(fs::read_to_string(&path).expect("second read"), upgraded);
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

    /// Both characters outside the store path contract are refused before
    /// the override is rendered.
    ///
    /// The long bind form renders a colon in its own `source:` field, but
    /// the legacy short-form reader, systemd escaping, and rendered shell
    /// commands still carry the path. Retaining the refusal prevents this
    /// change from widening their shared input contract.
    #[test]
    fn a_store_directory_outside_the_supported_path_contract_is_refused() {
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
        assert_eq!(entries.first(), Some(&OPENBAO_DATA_MOUNT.to_string()));
        assert_eq!(entries.last(), Some(&OPENBAO_CONFIG_MOUNT.to_string()));
        let audit = entries.get(1).expect("audit bind entry");
        assert!(audit.contains("type: bind"), "{audit}");
        assert!(
            audit.contains(&format!("source: '{}/{OPENBAO_SUBDIR}'", store.display())),
            "{audit}"
        );
        assert!(audit.contains("target: /openbao/audit"), "{audit}");
        assert!(audit.contains("create_host_path: false"), "{audit}");
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

    /// With the endpoint off, nothing this surface adds runs in
    /// either mode — no image path derived, no artifact rendered, no
    /// outcome line, no exit-status change.
    #[test]
    fn the_endpoint_gate_comes_first_in_both_modes() {
        for enforcement in ["filesystem", "directory"] {
            let fixture = Fixture::new();
            let state = fixture.state(Some(false));
            let compose_file = fixture.compose_file();
            let agent_config =
                fixture.agent_config_in_mode(&fixture.store_dir(), false, enforcement);
            let inputs = Fixture::inputs(Some(&agent_config), &state, false, &compose_file);
            assert_eq!(
                plan_audit_store(&inputs, &test_messages()).expect("planned"),
                AuditStorePlan::Idle,
                "{enforcement}"
            );
            assert_eq!(
                apply_audit_store(&inputs, &test_messages())
                    .expect("nothing to do")
                    .as_deref(),
                None,
                "{enforcement}"
            );
            assert!(!fixture.store_dir().exists(), "{enforcement}");
            assert!(!fixture.image_path().exists(), "{enforcement}");
            assert!(!fixture.artifact_dir().exists(), "{enforcement}");
        }
    }

    /// The install path creates the mount point and neither
    /// subdirectory: creating them first and mounting over them
    /// produces an empty store and a container that cannot write its
    /// mandatory audit device.
    #[test]
    fn a_filesystem_mode_run_creates_only_the_mount_point_and_stops() {
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let compose_dir = fixture.compose_dir();
        let compose_file = fixture.compose_file();
        let agent_config = fixture.filesystem_agent_config(true);
        let error = apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
            &test_messages(),
        )
        .expect_err("provisioned, not activated");
        let text = error.to_string();
        assert!(text.contains("provisioned, not activated"), "{text}");
        assert!(text.contains("ownership is not verified"), "{text}");

        let store = fixture.store_dir();
        assert!(store.is_dir());
        assert!(!store.join(RECORDS_SUBDIR).exists());
        assert!(!store.join(OPENBAO_SUBDIR).exists());
        // Not one phase-2 step is performed: no image, nothing under
        // `/etc/systemd/system`, no mount.
        assert!(!fixture.image_path().exists());

        // The three artifacts are written, and they are inert.
        assert!(fixture.artifact_dir().is_dir());
        assert!(
            fixture
                .artifact_dir()
                .join("docker.service.d")
                .join("10-bootroot-audit-store.conf")
                .is_file()
        );
        assert!(
            fixture
                .artifact_dir()
                .join("bootroot-registrar.service.d")
                .join("10-bootroot-audit-store.conf")
                .is_file()
        );
        let mount_units: Vec<PathBuf> = fs::read_dir(fixture.artifact_dir())
            .expect("artifact dir")
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().is_some_and(|ext| ext == "mount"))
            .collect();
        assert_eq!(mount_units.len(), 1, "{mount_units:?}");
        let unit = fs::read_to_string(mount_units.first().expect("the unit")).expect("unit");
        assert!(
            unit.contains(&format!("Where={}", store.display())),
            "{unit}"
        );
        assert!(
            unit.contains(&format!("What={}", fixture.image_path().display())),
            "{unit}"
        );

        // The rendered Compose override has the boot-path bind guard.
        let content = fs::read_to_string(audit_override_path(&compose_dir)).expect("override");
        assert!(content.contains("create_host_path: false"), "{content}");
        assert!(content.contains("bind:"), "{content}");
    }

    /// Phase 1 simplifies the store path, and the install path has to
    /// provision *that* path rather than the configured spelling: the
    /// mount point is the directory `Where=` names, and the Compose
    /// override's bind source is the directory the mount covers.
    #[test]
    fn a_store_path_that_is_not_simplified_is_provisioned_where_the_unit_names() {
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let compose_dir = fixture.compose_dir();
        let compose_file = fixture.compose_file();
        let store = fixture.store_dir();
        // The configured spelling: a trailing `.` component, which
        // `validate_registrar_settings` accepts and which no ancestor
        // walk over the raw path ever creates.
        let configured = store.join(".");
        let agent_config =
            fixture.filesystem_agent_config_at(&configured, true, RESERVE_FLOOR_FOR_TESTS);
        let inputs = Fixture::inputs(Some(&agent_config), &state, true, &compose_file);

        let error =
            apply_audit_store(&inputs, &test_messages()).expect_err("provisioned, not activated");
        assert!(
            error.to_string().contains("provisioned, not activated"),
            "{error}"
        );

        // The mount point exists, at the simplified path and at the
        // store directory contract's mode.
        let meta = fs::symlink_metadata(&store).expect("the mount point");
        assert!(meta.is_dir());
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        assert!(!store.join(RECORDS_SUBDIR).exists());
        assert!(!store.join(OPENBAO_SUBDIR).exists());

        // The unit and the override name one and the same directory.
        let mount_unit = fs::read_dir(fixture.artifact_dir())
            .expect("artifact dir")
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .find(|path| path.extension().is_some_and(|ext| ext == "mount"))
            .expect("the unit");
        let unit = fs::read_to_string(mount_unit).expect("unit");
        assert!(
            unit.contains(&format!("Where={}\n", store.display())),
            "{unit}"
        );
        assert_eq!(
            read_audit_override_store_dir(&audit_override_path(&compose_dir), &test_messages())
                .expect("the rendered override"),
            store
        );

        // And the re-run gets no further than the first one did: the
        // override it just wrote is not read back as naming another
        // store.
        let error =
            apply_audit_store(&inputs, &test_messages()).expect_err("provisioned, not activated");
        assert!(
            error.to_string().contains("provisioned, not activated"),
            "{error}"
        );
    }

    /// `directory` mode derives nothing and probes nothing, and its
    /// outcome is a success.
    #[test]
    fn a_directory_mode_run_creates_all_three_and_names_no_leftover() {
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let compose_file = fixture.compose_file();
        // A leftover image from a previous `filesystem`-mode run: a
        // `directory` run neither reads it nor names it.
        fs::write(fixture.image_path(), b"leftover").expect("leftover image");
        let agent_config = fixture.agent_config(true);
        let selected = apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
            &test_messages(),
        )
        .expect("unenforced (directory) is a success");
        assert!(selected.is_some());

        let store = fixture.store_dir();
        assert!(store.join(RECORDS_SUBDIR).is_dir());
        assert!(store.join(OPENBAO_SUBDIR).is_dir());
        assert!(!fixture.artifact_dir().exists());
        assert_eq!(
            fs::read(fixture.image_path()).expect("leftover image"),
            b"leftover"
        );
    }

    /// The derived holding directory beside a fixture's store.
    fn holding_dir(fixture: &Fixture) -> PathBuf {
        fixture.base.path().join("audit-store.pre-mount")
    }

    #[test]
    fn infra_up_refuses_the_bring_up_while_a_migration_is_open() {
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let compose_dir = fixture.compose_dir();
        let compose_file = fixture.compose_file();
        let config = fixture.filesystem_agent_config(true);
        write_audit_override(&compose_dir, &fixture.store_dir(), &test_messages())
            .expect("override");
        // Step 2 of the sequence, already run by the operator: the
        // store renamed aside and an empty mount point in its place.
        let holding = holding_dir(&fixture);
        fs::create_dir_all(holding.join(RECORDS_SUBDIR)).expect("holding");
        fs::write(holding.join(RECORDS_SUBDIR).join("audit.log"), b"a record").expect("a record");
        fs::create_dir_all(fixture.store_dir()).expect("mount point");

        let err = prepare_audit_store_for_infra_up(
            &state,
            &compose_file,
            Some(&config),
            current_process_euid(),
            &test_messages(),
        )
        .expect_err("an open migration refuses bring-up before any container starts");
        let output = err.to_string();
        assert!(output.contains("migration incomplete"), "{output}");
        assert!(output.contains(&holding.display().to_string()), "{output}");
        // Nothing was deleted, moved or created on the mounted store.
        assert_eq!(
            fs::read(holding.join(RECORDS_SUBDIR).join("audit.log")).expect("the record"),
            b"a record"
        );
        assert!(!fixture.store_dir().join(RECORDS_SUBDIR).exists());
        assert!(!fixture.store_dir().join(OPENBAO_SUBDIR).exists());
    }

    #[test]
    fn a_directory_mode_bring_up_names_the_holding_directory_and_continues() {
        let (fixture, state, compose_dir, compose_file) = provisioned_fixture();
        let config = fixture.agent_config(true);
        let holding = holding_dir(&fixture);
        fs::create_dir_all(holding.join(RECORDS_SUBDIR)).expect("holding");

        // `directory` mode raises no outcome of its own for this: the
        // run succeeds, and the holding directory is named rather than
        // left to be mistaken for debris.
        let selected = prepare_audit_store_for_infra_up(
            &state,
            &compose_file,
            Some(&config),
            current_process_euid(),
            &test_messages(),
        )
        .expect("directory mode continues");
        assert_eq!(
            selected.as_deref(),
            Some(audit_override_path(&compose_dir).as_path())
        );
        assert!(holding.join(RECORDS_SUBDIR).is_dir());
    }

    #[test]
    fn init_reports_the_migration_before_it_creates_the_mount_point() {
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let compose_file = fixture.compose_file();
        let agent_config = fixture.filesystem_agent_config(true);
        let holding = holding_dir(&fixture);
        fs::create_dir_all(holding.join(RECORDS_SUBDIR)).expect("holding");

        let error = apply_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
            &test_messages(),
        )
        .expect_err("an open migration fails the run");
        assert!(
            error.to_string().contains("migration incomplete"),
            "{error}"
        );
        // The one filesystem object this path would create is the
        // mount point, and it is not created while a migration is
        // open. The artifacts are still written: the outcome's own
        // activation rendering names them.
        assert!(!fixture.store_dir().exists());
        assert!(fixture.artifact_dir().is_dir());
        assert!(holding.join(RECORDS_SUBDIR).is_dir());
    }

    /// Every path under `root`, with its length, sorted.
    fn snapshot(root: &Path) -> Vec<(PathBuf, u64)> {
        let mut out = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(dir) = pending.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let meta = entry.metadata().expect("metadata");
                out.push((entry.path(), meta.len()));
                if meta.is_dir() {
                    pending.push(entry.path());
                }
            }
        }
        out.sort();
        out
    }

    /// bootroot performs no step of either procedure that changes the
    /// host: no rename, no copy, no verification, no `rmdir` and no
    /// unmount, whatever uid the run has. It renders or documents them,
    /// and reads metadata to decide what to render.
    #[test]
    fn no_bootroot_path_performs_host_surgery_on_a_migration() {
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let compose_dir = fixture.compose_dir();
        let compose_file = fixture.compose_file();
        let config = fixture.filesystem_agent_config(true);
        write_audit_override(&compose_dir, &fixture.store_dir(), &test_messages())
            .expect("override");
        let holding = holding_dir(&fixture);
        let migrated = fixture.base.path().join("audit-store.migrated");
        for tree in [&holding, &migrated] {
            fs::create_dir_all(tree.join(RECORDS_SUBDIR)).expect("a tree");
            fs::write(tree.join(RECORDS_SUBDIR).join("audit.log"), b"a record").expect("a record");
        }
        fs::create_dir_all(fixture.store_dir()).expect("mount point");

        let before = snapshot(&holding);
        let before_migrated = snapshot(&migrated);
        let before_store = snapshot(&fixture.store_dir());

        // Three surfaces, each run twice: a second pass re-reads rather
        // than acting on an earlier verdict.
        for _ in 0..2 {
            let inputs = Fixture::inputs(Some(&config), &state, true, &compose_file);
            preflight_audit_store(&inputs, &test_messages()).expect_err("refused");
            apply_audit_store(&inputs, &test_messages()).expect_err("refused");
            prepare_audit_store_for_infra_up(
                &state,
                &compose_file,
                Some(&config),
                current_process_euid(),
                &test_messages(),
            )
            .expect_err("refused");
        }

        assert_eq!(snapshot(&holding), before);
        assert_eq!(snapshot(&migrated), before_migrated);
        assert_eq!(snapshot(&fixture.store_dir()), before_store);
        assert!(holding.is_dir());
        assert!(migrated.is_dir());
        assert!(!fixture.image_path().exists());
    }

    #[test]
    fn the_reinit_preflight_refuses_an_open_migration_before_the_wipe() {
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let compose_file = fixture.compose_file();
        let agent_config = fixture.filesystem_agent_config(true);
        let holding = holding_dir(&fixture);
        fs::create_dir_all(holding.join(RECORDS_SUBDIR)).expect("holding");
        fs::write(holding.join(RECORDS_SUBDIR).join("audit.log"), b"a record").expect("a record");

        let error = preflight_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
            &test_messages(),
        )
        .expect_err("refused");
        assert!(error.to_string().contains("a migration of"), "{error}");
        assert!(!fixture.artifact_dir().exists());
        assert_eq!(
            fs::read(holding.join(RECORDS_SUBDIR).join("audit.log")).expect("the record"),
            b"a record"
        );
    }

    /// Every phase-1 refusal reaches `reinit` before the wipe, as a
    /// pure read.
    #[test]
    fn the_reinit_preflight_raises_the_reserve_refusals_before_the_wipe() {
        let messages = test_messages();

        // A sub-minimum reserve.
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let compose_file = fixture.compose_file();
        let agent_config = fixture.filesystem_agent_config_with(true, 1024 * 1024);
        let error = preflight_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
            &messages,
        )
        .expect_err("refused");
        assert!(error.to_string().contains("does not clear the"), "{error}");
        assert!(!fixture.store_dir().exists());
        assert!(!fixture.artifact_dir().exists());

        // A store path the artifacts cannot carry.
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        // A trailing space: systemd strips it off the value, leaving
        // `Where=` naming a path the unit name no longer matches.
        let hostile = fixture.base.path().join("audit-store ");
        let agent_config = fixture.agent_config_in_mode(&hostile, true, "filesystem");
        let error = preflight_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
            &messages,
        )
        .expect_err("refused");
        assert!(error.to_string().contains("systemd artifacts"), "{error}");
        assert!(!hostile.exists());

        // An image of the wrong size.
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let agent_config = fixture.filesystem_agent_config(true);
        fs::write(fixture.image_path(), b"wrong size").expect("image");
        let error = preflight_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
            &messages,
        )
        .expect_err("refused");
        assert!(error.to_string().contains("never resized"), "{error}");
        assert_eq!(
            fs::read(fixture.image_path()).expect("image"),
            b"wrong size"
        );

        // A store that already holds records.
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let agent_config = fixture.filesystem_agent_config(true);
        fs::create_dir_all(fixture.store_dir().join(RECORDS_SUBDIR)).expect("records");
        fs::write(
            fixture.store_dir().join(RECORDS_SUBDIR).join("audit.log"),
            b"a record",
        )
        .expect("a record");
        let error = preflight_audit_store(
            &Fixture::inputs(Some(&agent_config), &state, true, &compose_file),
            &messages,
        )
        .expect_err("refused");
        assert!(
            error.to_string().contains("two supported ways forward"),
            "{error}"
        );
        assert!(!fixture.artifact_dir().exists());
        assert_eq!(
            fs::read(fixture.store_dir().join(RECORDS_SUBDIR).join("audit.log"))
                .expect("the record"),
            b"a record"
        );
    }

    /// A store path that is not simplified survives the phase-one-only
    /// reinit preflight.
    ///
    /// `filesystem` mode derives its reserve facts from the simplified
    /// path. The ordinary init pass alone owns directory layout checks.
    #[test]
    fn the_reinit_preflight_clears_a_store_path_that_is_not_simplified() {
        let messages = test_messages();
        let fixture = Fixture::new();
        let state = fixture.state(Some(true));
        let compose_file = fixture.compose_file();
        let configured = fixture.store_dir().join(".");
        let agent_config =
            fixture.filesystem_agent_config_at(&configured, true, RESERVE_FLOOR_FOR_TESTS);
        let inputs = Fixture::inputs(Some(&agent_config), &state, true, &compose_file);

        // Provision: the mount point lands at the simplified path and
        // at the store directory contract's mode, and the override is
        // rendered. Phase 2 is the operator's, so the run stops at
        // `provisioned, not activated`.
        apply_audit_store(&inputs, &messages).expect_err("provisioned, not activated");
        let store = fixture.store_dir();
        let mode = fs::symlink_metadata(&store)
            .expect("the mount point")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
        // The mode an ancestor walk over the store directory itself
        // would refuse.
        assert_eq!(mode & 0o001, 0, "the store directory has no o+x");

        // The pre-wipe preflight only evaluates reserve phase one, so
        // this valid deployment spelling can reinit.
        preflight_audit_store(&inputs, &messages).expect("the pre-wipe preflight clears");

        // It still creates nothing beneath the store and installs
        // nothing: it is a pure read.
        assert!(!store.join(RECORDS_SUBDIR).exists());
        assert!(!store.join(OPENBAO_SUBDIR).exists());
        assert!(!fixture.image_path().exists());
    }

    /// The re-run step names the command the run continues under. The
    /// non-empty-store finding is the one deliberate exception: it
    /// names the live `infra up` refusal without making it a re-run
    /// instruction.
    #[test]
    fn the_rerun_step_is_parameterised_while_the_non_empty_finding_names_infra_up() {
        for locale in ["en", "ko"] {
            let messages = Messages::new(locale).expect("a locale");
            let rendered = messages.audit_reserve_step_rerun(RESERVE_RERUN_COMMAND);
            assert!(
                rendered.contains(RESERVE_RERUN_COMMAND),
                "{locale}: {rendered}"
            );
            assert!(!rendered.contains("infra up"), "{locale}: {rendered}");
            for text in [
                messages.audit_reserve_outcome_not_activated("/store"),
                messages.audit_reserve_outcome_directory("/store", 1),
                messages.audit_reserve_outcome_enforced("/img", 1, "u.mount", "/store"),
                messages.audit_reserve_steps_header().to_string(),
                messages.audit_reserve_openbao_owner_caveat().to_string(),
            ] {
                assert!(!text.contains("infra up"), "{locale}: {text}");
            }
            let finding =
                messages.audit_reserve_finding_store_not_empty("/store", "/store.pre-mount");
            assert!(
                finding.contains("`bootroot infra up`"),
                "{locale}: {finding}"
            );
        }
    }
}
