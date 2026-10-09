//! Provisioning the bootroot-internal privileged credential, inside
//! `init`'s existing rollback transaction.
//!
//! The order below is a correctness requirement, not a preference:
//!
//! 1. **Prerequisites.** `OpenBao` is bootstrapped, step-ca is
//!    initialized and the agent EAB (if the deployment has one) has been
//!    acquired. Nothing here runs before them: the leaf is signed with
//!    the intermediate key step-ca's initialization created, and the
//!    published config carries the EAB the endpoint's own certificates
//!    are ordered under.
//! 2. **Material.** The internal leaf is signed offline against the
//!    intermediate key, in the step-ca helper image, and the persistent
//!    ACME account key is carried over or created — all of it into a
//!    staging directory, so nothing is published yet. No ACME order is
//!    placed for the internal name.
//! 3. **Authority.** Under the init root token: enable `auth/cert` if it
//!    is absent, write the exact-allowlist policy, and write the one
//!    entry, whose `certificate` is the staged leaf and nothing else.
//!    The leaf has to exist first, which is why this follows stage 2.
//! 4. **Listener.** The existing `OpenBao` TLS transition runs, and the
//!    HTTPS URL is recorded.
//! 5. **Proof.** A real `auth/cert/login` over that HTTPS URL, with the
//!    staged material, must succeed. It is also the proof that the
//!    pinned entry and the staged leaf are a pair.
//! 6. **Publication.** Only then are the four credential files, the
//!    dedicated config and the private CA bundle moved into place. A
//!    run that replaced a credential the host already carried then
//!    reloads the endpoint daemon, whose loaded leaf the entry has
//!    refused since stage 3.
//!
//! Every step registers its undo with [`InitRollback`] *before* it acts,
//! so a failure at any point up to the publication restores the prior
//! listener, the prior state URL and the prior `OpenBao` artifacts —
//! removing what this run created and writing back verbatim what it
//! rewrote — and leaves no file behind. After the publication a host
//! that already carried a credential keeps the new entry and the new
//! files instead: they are a working pair, and the entry it had before
//! is pinned to a leaf that is no longer on disk. A host whose endpoint
//! predicate is false performs none of it.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;
use bootroot::registrar::internal::{
    ACME_ACCOUNT_FILE, AcmeAccountKey, CERT_AUTH_MOUNT, CERT_AUTH_ROLE, EndpointTables,
    InternalAgentConfigParams, InternalCredential, InternalMaterial, InternalPaths, MaterialStatus,
    PrivateKeyPem, SetSnapshot, build_registrar_internal_policy, capture_set,
    first_certificate_pem, material_status, publish_material, render_internal_agent_config,
};
use bootroot::registrar::registrar_internal_identity;
use bootroot::remote_bootstrap::client_url_from_bind_addr;
use bootroot::secret::HmacSecret;
use bootroot::{cert_group, config, fs_util};

use super::InitRollback;
use super::ca_certs::{compute_ca_bundle_pem, compute_ca_fingerprints};
use super::openbao_tls::{TLS_OUTPUT_MOUNT, chown_tls_output_dir, reject_symlinked_tls_output_dir};
use crate::commands::infra::run_docker_with_exec;
use crate::commands::init::constants::REGISTRAR_INTERNAL_NOT_AFTER;
use crate::commands::init::constants::openbao_constants::{
    POLICY_BOOTROOT_REGISTRAR_INTERNAL, TOKEN_TTL,
};
use crate::commands::init::{CA_CERTS_DIR, CA_INTERMEDIATE_CERT_FILENAME};
use crate::commands::rotate::STEP_CA_HELPER_IMAGE;
use crate::i18n::Messages;
use crate::state::StateFile;

/// The staging directory the leaf is signed into before it is proven and
/// published.
///
/// A sibling of the published names rather than a temporary elsewhere:
/// the publish is a rename, and a rename is only atomic within one
/// filesystem.
const STAGING_DIR: &str = ".staging";

/// The leaf and its key as the signing helper writes them into staging.
const STAGED_LEAF_FILE: &str = "leaf.pem";
const STAGED_KEY_FILE: &str = "key.pem";

/// The bootroot-internal identity's two parts, taken from the recorded
/// endpoint predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegistrarInternalIntent {
    /// The deployment domain the SAN is composed under.
    pub(crate) domain: String,
    /// The host label the SAN is composed with.
    pub(crate) host: String,
}

impl RegistrarInternalIntent {
    /// The one SAN this host's internal credential ever carries.
    pub(crate) fn san(&self) -> String {
        registrar_internal_identity(&self.host, &self.domain)
    }
}

/// Consumes the registrar endpoint-enablement predicate recorded in
/// `state.json`.
///
/// **`init` consumes the predicate; it never sets or changes it.**
/// `bootroot infra install` records it from `--registrar-endpoint-host`
/// and `--registrar-endpoint-domain`, and `init` carries the recorded
/// value through when it rewrites `state.json`. An absent or disabled
/// entry means the endpoint is off, and `init` then alters no listener
/// and creates no internal artifact.
///
/// # Errors
///
/// Returns an error when the state file exists but cannot be read or
/// parsed, or when an enabled entry names an empty host or domain — a
/// SAN cannot be composed from either, and guessing one would compose a
/// name the deployment's CA never issues.
pub(crate) fn registrar_endpoint_intent(
    state_path: &Path,
) -> Result<Option<RegistrarInternalIntent>> {
    if !state_path.exists() {
        return Ok(None);
    }
    let state = StateFile::load(state_path)?;
    let Some(recorded) = state.registrar_endpoint else {
        return Ok(None);
    };
    if !recorded.enabled {
        return Ok(None);
    }
    if recorded.host.trim().is_empty() || recorded.domain.trim().is_empty() {
        anyhow::bail!(
            "state.json enables the registrar endpoint but records an empty \
             `registrar_endpoint.host` or `registrar_endpoint.domain`; the \
             bootroot-internal SAN cannot be composed without both"
        );
    }
    Ok(Some(RegistrarInternalIntent {
        domain: recorded.domain,
        host: recorded.host,
    }))
}

/// An endpoint-enabled `init` run's two inputs: the recorded predicate
/// and the operator's `[registrar]` and `[registrar_endpoint]` tables.
#[derive(Debug)]
pub(crate) struct EnabledEndpoint {
    /// The identity's two parts, from `state.json`.
    pub(crate) intent: RegistrarInternalIntent,
    /// The two tables, as the `--agent-config` file spells them.
    pub(crate) tables: EndpointTables,
}

/// Holds the operator's `--agent-config` tables to every requirement an
/// enabled endpoint has, and returns them for rendering.
///
/// An endpoint-enabled host runs one `bootroot-agent` process on the
/// bootroot-internal config, and that process is the endpoint daemon:
/// `init` renders the operator's two tables into that config, so a
/// table the daemon would refuse is refused here instead, naming the
/// key. The checks are the daemon's own
/// ([`bootroot::config::validate_registrar_tables`]), less the platform
/// rule, which is the listening process's to apply.
///
/// This is a pure read, and `init` runs it before `apply_audit_store`
/// — before the audit store is created, its Compose override rendered or
/// deleted, or any Docker call made — so a refusal leaves the host
/// exactly as it found it. `reinit` runs it before its wipe for the same
/// reason. A disabled or absent predicate reads nothing and returns
/// `None`, whatever the operator's file holds. A file whose
/// `[registrar_endpoint] enabled` disagrees with the predicate passes
/// through untouched: the audit-store preflight refuses that
/// disagreement itself, with its own message.
///
/// # Errors
///
/// Returns an error when the predicate is enabled and `--agent-config`
/// is absent, unreadable, not TOML or not deserializable, or when its
/// tables break a rule an enabled endpoint holds them to.
pub(crate) fn preflight_endpoint_tables(
    intent: Option<RegistrarInternalIntent>,
    agent_config: Option<&Path>,
    messages: &Messages,
) -> Result<Option<EnabledEndpoint>> {
    let Some(intent) = intent else {
        return Ok(None);
    };
    let Some(path) = agent_config else {
        anyhow::bail!(messages.error_audit_store_agent_config_required("bootroot init"));
    };
    let display = path.display().to_string();
    let (text, partial) = crate::commands::audit_store::read_agent_config_text(path, messages)?;
    config::validate_registrar_tables(&partial.registrar, &partial.registrar_endpoint).map_err(
        |err| {
            anyhow::anyhow!(
                messages.error_registrar_endpoint_tables_rejected(&display, &err.to_string())
            )
        },
    )?;
    let tables = EndpointTables::extract(&text).map_err(|err| {
        anyhow::anyhow!(
            messages.error_audit_store_agent_config_malformed(&display, &format!("{err:#}"))
        )
    })?;
    Ok(Some(EnabledEndpoint { intent, tables }))
}

/// The internal config a rebuild outside `init` replaces, as read back
/// from disk.
#[derive(Debug)]
pub(crate) struct CurrentInternalConfig {
    /// The whole file, parsed as the daemon parses it: the record of the
    /// values `init` chose, which a repair keeps.
    pub(crate) settings: config::Settings,
    /// The operator's `[registrar]` and `[registrar_endpoint]` tables as
    /// written in the file; `None` on an endpoint-disabled host.
    pub(crate) endpoint_tables: Option<EndpointTables>,
}

/// Reads the internal config a rebuild outside `init` replaces, and the
/// `[registrar]` and `[registrar_endpoint]` tables it carries over.
///
/// Only `init` takes the two tables from the operator; every other
/// rebuild of `registrar-internal/agent.toml` keeps what is on disk,
/// with its values unchanged, and never asks for them again. A file
/// without them — an endpoint-disabled host — carries no tables. A
/// host whose file is gone returns `None`: there is nothing left to
/// carry, and the caller falls back to rebuilding what `init` chose. A
/// file that exists but cannot be read or parsed refuses the rebuild,
/// before anything is issued or published, because publishing over it
/// would silently drop the endpoint's configuration. "Parsed" means
/// what the daemon means by it: the whole file must deserialize as the
/// daemon's settings, so a syntactically valid file holding a value the
/// daemon would reject — in the two tables or anywhere else — is
/// refused rather than read around.
///
/// # Errors
///
/// Returns an error naming the file when it exists but cannot be read,
/// is not valid TOML, or does not deserialize as the daemon's settings.
pub(crate) async fn current_internal_config(
    paths: &InternalPaths,
    messages: &Messages,
) -> Result<Option<CurrentInternalConfig>> {
    let path = paths.agent_config();
    let refuse = |reason: String| {
        anyhow::anyhow!(
            messages
                .error_registrar_internal_tables_unreadable(&path.display().to_string(), &reason)
        )
    };
    let text = match tokio::fs::read_to_string(&path).await {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(refuse(err.to_string())),
    };
    let settings = config::Settings::from_toml_str(&text).map_err(|err| refuse(err.to_string()))?;
    let tables = EndpointTables::extract(&text).map_err(|err| refuse(format!("{err:#}")))?;
    Ok(Some(CurrentInternalConfig {
        settings,
        endpoint_tables: (!tables.is_empty()).then_some(tables),
    }))
}

/// The owned form of [`RegistrarInternalInputs`], built once by `init`
/// and borrowed at each of the two provisioning stages.
///
/// Owned because the two stages sit on either side of the `OpenBao` TLS
/// transition, and the values they share — the responder HMAC, the EAB
/// — are consumed by unrelated `init` steps in between.
pub(crate) struct RegistrarInternalContext {
    /// The identity's two parts.
    pub(crate) intent: RegistrarInternalIntent,
    /// The state-recorded secrets directory.
    pub(crate) secrets_dir: PathBuf,
    /// The `docker` executable the leaf is signed through.
    pub(crate) docker: PathBuf,
    /// The KV v2 mount the exact-allowlist policy is scoped to.
    pub(crate) kv_mount: String,
    /// The step-ca ACME directory URL.
    pub(crate) acme_server: String,
    /// The deployment contact email.
    pub(crate) email: String,
    /// The HTTP-01 responder admin URL.
    pub(crate) responder_url: String,
    /// The HTTP-01 responder shared HMAC.
    pub(crate) responder_hmac: HmacSecret,
    /// The EAB credentials, when the deployment registered any.
    pub(crate) eab: Option<crate::commands::init::types::EabCredentials>,
    /// The operator's `[registrar]` and `[registrar_endpoint]` tables
    /// the published config carries: `init`'s from `--agent-config`, a
    /// repair's from the config it replaces.
    pub(crate) endpoint_tables: Option<EndpointTables>,
}

impl RegistrarInternalContext {
    /// Borrows the context as the inputs both stages take.
    pub(crate) fn inputs(&self) -> RegistrarInternalInputs<'_> {
        RegistrarInternalInputs {
            intent: &self.intent,
            secrets_dir: &self.secrets_dir,
            docker: &self.docker,
            kv_mount: &self.kv_mount,
            acme_server: &self.acme_server,
            email: &self.email,
            responder_url: &self.responder_url,
            responder_hmac: &self.responder_hmac,
            eab: self.eab.as_ref(),
            endpoint_tables: self.endpoint_tables.as_ref(),
        }
    }
}

/// The staging directory the internal leaf is signed into.
///
/// A sibling of the published names rather than a temporary elsewhere:
/// the publish is a rename, and a rename is only atomic within one
/// filesystem.
pub(crate) fn staging_dir(paths: &InternalPaths) -> PathBuf {
    paths.dir().join(STAGING_DIR)
}

/// The step-ca ACME directory URL the internal config names.
///
/// The internal leaf itself is not ordered there, but the endpoint's two
/// surface certificates are, by the daemon that runs on this config. It
/// is an ordinary host daemon, not a container on the compose network,
/// so this is the *host-side* address step-ca is
/// published on — and a non-loopback `--stepca-bind` replaces the
/// loopback publication rather than adding to it. With a bind recorded
/// the URL therefore names that bind: a specific address as it is, a
/// wildcard as loopback, and the bind's own port either way. Every one
/// of those hosts is in the name set step-ca's serving certificate is
/// issued for (`build_stepca_ca_dns_names`), so TLS verification holds.
///
/// Without a recorded bind step-ca is on loopback, on this install's
/// `STEPCA_HOST_PORT` — the process environment, then this compose
/// directory's `.env`, then the compose default — rather than a
/// hard-coded `:9000`, which on a host co-located with a second
/// instance would reach *that* instance's step-ca.
///
/// Follows the configured provisioner name rather than hard-coding
/// `acme`: an install that renamed the ACME provisioner would otherwise
/// enrol against a directory step-ca does not serve.
pub(crate) fn internal_acme_server(
    provisioner: &str,
    stepca_bind_addr: Option<&str>,
    compose_dir: &Path,
) -> String {
    internal_acme_server_with_env(
        provisioner,
        stepca_bind_addr,
        compose_dir,
        std::env::var(bootroot::host_port::STEPCA_HOST_PORT_ENV)
            .ok()
            .as_deref(),
    )
}

/// [`internal_acme_server`] with the `STEPCA_HOST_PORT` value supplied
/// by the caller instead of read from the process environment, so the
/// precedence can be exercised without a process-global environment.
fn internal_acme_server_with_env(
    provisioner: &str,
    stepca_bind_addr: Option<&str>,
    compose_dir: &Path,
    env_value: Option<&str>,
) -> String {
    let base = stepca_bind_addr.map_or_else(
        || {
            let port =
                bootroot::host_port::resolve_stepca_host_port_with_env(env_value, compose_dir);
            format!("https://localhost:{port}")
        },
        client_url_from_bind_addr,
    );
    format!("{base}/acme/{provisioner}/directory")
}

/// The HTTP-01 responder admin URL the daemon on the internal config
/// drives its challenges through.
///
/// The host-side address for the same reason as
/// [`internal_acme_server`]. A recorded `--http01-admin-bind` both
/// replaces the loopback publication and puts the admin API behind TLS,
/// so the URL names the bind over `https://`; the admin certificate's
/// SANs (`build_http01_admin_tls_sans`) cover every host that yields,
/// and the internal profile's CA bundle anchors it. Without a recorded
/// bind the admin API is plaintext on loopback, on this install's
/// `HTTP01_ADMIN_HOST_PORT`.
pub(crate) fn internal_responder_url(
    http01_admin_bind_addr: Option<&str>,
    compose_dir: &Path,
) -> String {
    internal_responder_url_with_env(
        http01_admin_bind_addr,
        compose_dir,
        std::env::var(bootroot::host_port::HTTP01_ADMIN_HOST_PORT_ENV)
            .ok()
            .as_deref(),
    )
}

/// [`internal_responder_url`] with the `HTTP01_ADMIN_HOST_PORT` value
/// supplied by the caller.
fn internal_responder_url_with_env(
    http01_admin_bind_addr: Option<&str>,
    compose_dir: &Path,
    env_value: Option<&str>,
) -> String {
    http01_admin_bind_addr.map_or_else(
        || {
            let port = bootroot::host_port::resolve_http01_admin_host_port_with_env(
                env_value,
                compose_dir,
            );
            format!("http://127.0.0.1:{port}")
        },
        client_url_from_bind_addr,
    )
}

/// Everything provisioning needs, all of it already resolved by `init`.
pub(crate) struct RegistrarInternalInputs<'a> {
    /// The identity's two parts.
    pub(crate) intent: &'a RegistrarInternalIntent,
    /// The state-recorded secrets directory.
    pub(crate) secrets_dir: &'a Path,
    /// The `docker` executable the leaf is signed through.
    pub(crate) docker: &'a Path,
    /// The KV v2 mount the exact-allowlist policy is scoped to.
    pub(crate) kv_mount: &'a str,
    /// The step-ca ACME directory URL.
    pub(crate) acme_server: &'a str,
    /// The deployment contact email.
    pub(crate) email: &'a str,
    /// The HTTP-01 responder admin URL.
    pub(crate) responder_url: &'a str,
    /// The HTTP-01 responder shared HMAC.
    pub(crate) responder_hmac: &'a HmacSecret,
    /// The EAB credentials, when the deployment registered any.
    pub(crate) eab: Option<&'a crate::commands::init::types::EabCredentials>,
    /// The operator's two tables the published config carries.
    pub(crate) endpoint_tables: Option<&'a EndpointTables>,
}

/// Material signed into the staging directory, plus the trust state it
/// was signed against.
pub(crate) struct StagedInternal {
    paths: InternalPaths,
    staging: PathBuf,
    material: InternalMaterial,
    bundle_pem: String,
    fingerprints: Vec<String>,
}

impl StagedInternal {
    /// Replaces the trust set the publication writes into the private
    /// bundle and the config's pins.
    ///
    /// `init` publishes the active generation, which is what
    /// [`issue_internal_material`] staged. A rotation repair does not:
    /// the mandatory tail after Phase 4 replaces the credential while
    /// the fleet is still on the *additive* set, and publishing the
    /// narrowed set there would take this identity off a generation
    /// everything else still trusts. Applied before publication, so the
    /// bundle and the config are written once, together, on one set.
    #[must_use]
    pub(crate) fn with_trust(mut self, fingerprints: Vec<String>, bundle_pem: String) -> Self {
        self.fingerprints = fingerprints;
        self.bundle_pem = bundle_pem;
        self
    }

    /// The staged leaf's PEM block alone: the first certificate of the
    /// chain, without the intermediate that follows it.
    ///
    /// This is what the `auth/cert` entry is pinned to. The chain is
    /// what the client presents; the entry names the one certificate
    /// that may log in.
    ///
    /// # Errors
    ///
    /// Returns an error when the staged chain holds no certificate.
    pub(crate) fn leaf_pem(&self) -> Result<&str> {
        first_certificate_pem(&self.material.chain).ok_or_else(|| {
            anyhow::anyhow!("the staged bootroot-internal chain holds no certificate")
        })
    }
}

/// Whether an `init` run provisions this host's internal credential for
/// the first time or replaces one it found.
///
/// Read once, before the run registers or creates anything, because the
/// two differ in what a failure undoes and in whether a daemon can
/// already be running on the credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InternalProvisioning {
    /// Nothing was there: the layout directory is this run's to remove.
    First,
    /// A set — complete or partial — was already present.
    Replacement,
}

/// Registers this run's bootroot-internal teardown with the `init`
/// rollback envelope.
///
/// The layout directory is the rollback unit of a *first* provisioning:
/// this run then either publishes a complete credential or leaves
/// nothing behind. `init` is re-runnable, though, and a re-run that
/// fails must not have its rollback delete the working credential it
/// found — that would turn a retryable failure into an outage on the one
/// host the registrar depends on. So the directory is registered only
/// when nothing is there yet.
///
/// The staging directory is registered either way: it is this run's
/// alone and holds a private key that was never published.
///
/// Reports which of the two it found, for
/// [`settle_internal_publication`] to act on once the set is published.
pub(super) fn register_internal_rollback(
    rollback: &mut InitRollback,
    secrets_dir: &Path,
) -> InternalProvisioning {
    let paths = InternalPaths::new(secrets_dir);
    let provisioning = if matches!(material_status(&paths), MaterialStatus::Absent) {
        rollback.registrar_internal_dir = Some(paths.dir().to_path_buf());
        InternalProvisioning::First
    } else {
        InternalProvisioning::Replacement
    };
    rollback.registrar_internal_staging = Some(staging_dir(&paths));
    provisioning
}

/// Makes a published replacement the host's settled state, and reloads
/// the endpoint daemon onto it.
///
/// Called once [`verify_and_publish_internal`] has returned `Ok`. A
/// first provisioning has nothing to settle: its rollback still removes
/// the directory, the entry and the policy, and no daemon has loaded a
/// credential that did not exist.
///
/// A replacement differs on both counts, and both follow from the entry
/// being pinned to one leaf:
///
/// - The rollback's captured entry and policy name the *previous* leaf,
///   and the publication has just replaced that leaf on disk and
///   discarded its snapshot. Writing them back on a later failure would
///   leave `OpenBao` pinned to a certificate the host no longer has. So
///   every `OpenBao` undo this run registered for the credential is
///   dropped here: the new entry and the new files are the host's pair,
///   and a later failure keeps both.
/// - The running daemon loaded the previous leaf, which the entry has
///   refused since it was rewritten, and it loads its credential only at
///   start and on `SIGHUP`. So it is signalled, through `signal`, with
///   the rotations' own rule that no matching process is success.
///
/// # Errors
///
/// Returns the error `signal` returns. The rollback has been settled by
/// then, so the failure — an `init` failure like that of any later step
/// — leaves the new pair in place.
pub(super) fn settle_internal_publication(
    rollback: &mut InitRollback,
    provisioning: InternalProvisioning,
    secrets_dir: &Path,
    signal: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    if provisioning == InternalProvisioning::First {
        return Ok(());
    }
    rollback.registrar_internal_cert_auth_entry_backup = None;
    rollback.registrar_internal_policy_backup = None;
    // The same reasoning covers an artifact this run created beside
    // files it found: deleting it would leave the new files with nothing
    // to log in against.
    rollback.registrar_internal_cert_auth_entry = None;
    rollback.registrar_internal_cert_auth_mount_created = false;
    rollback
        .created_policies
        .retain(|name| name != POLICY_BOOTROOT_REGISTRAR_INTERNAL);
    signal(secrets_dir)
}

/// Creates the `auth/cert` mount, the exact-allowlist policy and the one
/// entry, pinned to the staged leaf, under the init root token.
///
/// Every artifact is registered for rollback before it is written, so a
/// later failure removes exactly what this run added, puts back exactly
/// what it rewrote, and leaves an `auth/cert` mount the deployment
/// already had alone.
///
/// # Errors
///
/// Returns an error if the staged chain holds no certificate or any
/// `OpenBao` read or write fails.
pub(super) async fn provision_internal_auth(
    client: &OpenBaoClient,
    inputs: &RegistrarInternalInputs<'_>,
    staged: &StagedInternal,
    rollback: &mut InitRollback,
) -> Result<()> {
    let leaf_pem = staged.leaf_pem()?;
    // Registered before the write, not after: a failure between the two
    // must still be undone. Which undo is registered depends on what
    // this run finds. An artifact this run creates is registered for
    // deletion; one it finds is captured verbatim and registered for
    // restoration, because `converge_internal_auth` below rewrites both
    // unconditionally. A re-run of `init` over an already-provisioned
    // host therefore neither has its rollback delete the working entry
    // and policy it found — the one way this teardown could take a
    // healthy deployment down — nor leaves them on this run's values
    // after a failure before the publication. The entry matters most:
    // the convergence pins it to a leaf that is still only in staging,
    // so a rollback that left it there would leave the host trusting a
    // certificate it does not have.
    //
    // Which is why neither lookup may be read as "absent" when it did
    // not answer. A transient read failure against a host that already
    // carries the entry would register a deletion for it, and a later
    // failure anywhere in the run would then take that host down.
    // Only a definitive not-found registers a destructive undo, so a
    // lookup that fails fails the run instead — before anything has
    // been created.
    let existing_entry = client
        .read_cert_auth_entry(CERT_AUTH_MOUNT, CERT_AUTH_ROLE)
        .await
        .context("reading the bootroot-registrar-internal cert auth entry")?;
    match existing_entry {
        Some(entry) => rollback.registrar_internal_cert_auth_entry_backup = Some(entry),
        None => rollback.registrar_internal_cert_auth_entry = Some(CERT_AUTH_ROLE.to_string()),
    }
    match client
        .read_policy(POLICY_BOOTROOT_REGISTRAR_INTERNAL)
        .await
        .context("reading the bootroot-registrar-internal policy")?
    {
        Some(policy) => rollback.registrar_internal_policy_backup = Some(policy),
        None => rollback
            .created_policies
            .push(POLICY_BOOTROOT_REGISTRAR_INTERNAL.to_string()),
    }
    // The mount registers itself the moment it exists, from inside
    // `converge_internal_auth`: the policy and the entry are written
    // after it, and a failure at either would otherwise leave a backend
    // this run enabled with nothing recorded to disable it.
    converge_internal_auth(
        client,
        inputs,
        leaf_pem,
        &mut rollback.registrar_internal_cert_auth_mount_created,
    )
    .await
}

/// Converges the `auth/cert` mount, the exact-allowlist policy and the
/// one entry, whose `certificate` is `leaf_pem`.
///
/// `leaf_pem` is the internal leaf alone — not its chain, and not the
/// deployment root. An entry that names a CA accepts every leaf of that
/// CA carrying the SAN, and any holder of the deployment's responder
/// HMAC can obtain one from step-ca; an entry that names the leaf
/// accepts that certificate and no other.
///
/// Shared by `init`'s provisioning and by the rotation and recovery
/// repairs, so the entry the three write cannot drift: one leaf, one
/// SAN, one policy.
///
/// `mounted_now` is set — never cleared — as soon as this call is what
/// enabled the backend, which is before the policy and the entry are
/// written. A caller inside a rollback envelope passes the flag it will
/// undo by, so a failure at either write still disables a backend this
/// run created; a caller outside one passes a local flag and reads it,
/// or ignores it, itself.
///
/// # Errors
///
/// Returns an error if any `OpenBao` write fails.
pub(crate) async fn converge_internal_auth(
    client: &OpenBaoClient,
    inputs: &RegistrarInternalInputs<'_>,
    leaf_pem: &str,
    mounted_now: &mut bool,
) -> Result<()> {
    if client
        .ensure_cert_auth(CERT_AUTH_MOUNT)
        .await
        .context("enabling the OpenBao cert auth backend")?
    {
        *mounted_now = true;
    }
    client
        .write_policy(
            POLICY_BOOTROOT_REGISTRAR_INTERNAL,
            &build_registrar_internal_policy(inputs.kv_mount),
        )
        .await
        .context("writing the bootroot-registrar-internal policy")?;

    client
        .write_cert_auth_entry(
            CERT_AUTH_MOUNT,
            CERT_AUTH_ROLE,
            leaf_pem,
            &inputs.intent.san(),
            &[POLICY_BOOTROOT_REGISTRAR_INTERNAL],
            TOKEN_TTL,
        )
        .await
        .context("creating the bootroot-registrar-internal cert auth entry")?;
    Ok(())
}

/// Signs the internal leaf offline and stages it, with the persistent
/// ACME account key, in the staging directory.
///
/// Nothing is published: the staged files sit under
/// [`STAGING_DIR`], registered for rollback, until a real certificate
/// login over the TLS listener has proved they work. Nothing in
/// `OpenBao` is touched and no ACME request is made, so a host missing
/// Docker, the intermediate key or `password.txt` fails here with
/// everything else as it was.
///
/// The signing runs before anything else is staged. The helper writes as
/// the owner of the secrets directory, so the staging directory is
/// handed to that owner first — and that hand-over re-owns whatever the
/// directory already holds. Run in this order, the only files that owner
/// ever owns in staging are the helper's own two outputs.
///
/// # Errors
///
/// Returns an error if the staging directory is a symlink or cannot be
/// created, the leaf cannot be signed, or the CA material cannot be
/// read.
pub(crate) async fn issue_internal_material(
    inputs: &RegistrarInternalInputs<'_>,
    messages: &Messages,
) -> Result<StagedInternal> {
    let paths = InternalPaths::new(inputs.secrets_dir);
    let staging = staging_dir(&paths);

    reject_symlinked_tls_output_dir(
        &staging,
        |path| messages.error_registrar_internal_staging_symlink(path),
        messages,
    )?;
    // Staging is one run's alone. What an interrupted run left behind is
    // an unpublished key nothing will ever use, and it must not be
    // re-owned along with the directory below.
    match tokio::fs::remove_dir_all(&staging).await {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err)
                .with_context(|| messages.error_write_file_failed(&staging.display().to_string()));
        }
    }
    fs_util::ensure_secrets_dir(&staging)
        .await
        .with_context(|| messages.error_write_file_failed(&staging.display().to_string()))?;

    // Read before the helper runs, and held in memory until it has: a
    // host with no CA certificates fails here, before a container is
    // started, and nothing but the helper's outputs is in staging while
    // the directory is being handed over.
    let fingerprints = compute_ca_fingerprints(inputs.secrets_dir, messages).await?;
    let bundle_pem = compute_ca_bundle_pem(inputs.secrets_dir, messages).await?;
    let intermediate_pem = read_ca_file(
        &inputs
            .secrets_dir
            .join(CA_CERTS_DIR)
            .join(CA_INTERMEDIATE_CERT_FILENAME),
        messages,
    )
    .await?;

    sign_internal_leaf(inputs, &staging, messages)?;

    let staged_cert = staging.join(STAGED_LEAF_FILE);
    let staged_key = staging.join(STAGED_KEY_FILE);
    let leaf_pem = tokio::fs::read_to_string(&staged_cert)
        .await
        .with_context(|| messages.error_read_file_failed(&staged_cert.display().to_string()))?;
    let key_pem = tokio::fs::read_to_string(&staged_key)
        .await
        .with_context(|| messages.error_read_file_failed(&staged_key.display().to_string()))?;

    let staged_bundle = staging.join("ca-bundle.pem");
    fs_util::write_ca_bundle(
        &staged_bundle,
        &bundle_pem,
        cert_group::CertGroupPolicy::none(),
    )
    .await
    .with_context(|| messages.error_write_file_failed(&staged_bundle.display().to_string()))?;

    let account = stage_account_key(&paths, &staging, messages).await?;
    let root_fingerprint = fingerprints
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("the deployment root fingerprint was not computed"))?;

    // `step` ends each file with a newline; a leaf that did not would
    // run its closing line into the intermediate's opening one.
    let separator = if leaf_pem.ends_with('\n') { "" } else { "\n" };
    Ok(StagedInternal {
        paths,
        staging,
        material: InternalMaterial {
            key: PrivateKeyPem::new(key_pem),
            chain: format!("{leaf_pem}{separator}{intermediate_pem}"),
            acme_account: AcmeAccountKey::new(account),
            root_fingerprint,
        },
        bundle_pem,
        fingerprints,
    })
}

/// Signs the internal leaf against the intermediate key, into `staging`.
///
/// `step certificate create` in the step-ca helper image, exactly as the
/// `OpenBao` and HTTP-01 admin TLS certificates are signed: the secrets
/// directory mounted at `/home/step`, the output directory mounted
/// beside it, and the helper running as the owner of the secrets
/// directory after a scoped root chown has handed that owner the output
/// directory. The SAN is both the subject and the only SAN.
///
/// `--no-password --insecure` writes the key unencrypted, as the daemon
/// needs it, and `step` creates both files at `0600`. Neither is
/// widened here: the key is read back and published at its final mode
/// by the material publisher, and the staging copy is removed.
fn sign_internal_leaf(
    inputs: &RegistrarInternalInputs<'_>,
    staging: &Path,
    messages: &Messages,
) -> Result<()> {
    let secrets_dir = inputs.secrets_dir;
    let mount_root = std::fs::canonicalize(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let secrets_mount = format!("{}:/home/step", mount_root.display());
    let staging_root = std::fs::canonicalize(staging)
        .with_context(|| messages.error_resolve_path_failed(&staging.display().to_string()))?;
    let staging_mount = format!("{}:{TLS_OUTPUT_MOUNT}", staging_root.display());

    let meta = std::fs::metadata(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let user_arg = format!("{}:{}", meta.uid(), meta.gid());

    chown_tls_output_dir(
        &staging_mount,
        &user_arg,
        inputs.docker,
        "docker registrar internal staging chown",
        messages.error_registrar_internal_provision_failed(),
        messages,
    )?;

    let san = inputs.intent.san();
    let intermediate_cert = format!("/home/step/{CA_CERTS_DIR}/{CA_INTERMEDIATE_CERT_FILENAME}");
    let output_cert = format!("{TLS_OUTPUT_MOUNT}/{STAGED_LEAF_FILE}");
    let output_key = format!("{TLS_OUTPUT_MOUNT}/{STAGED_KEY_FILE}");
    let args: [&str; 25] = [
        "run",
        "--user",
        &user_arg,
        "--rm",
        "-v",
        &secrets_mount,
        "-v",
        &staging_mount,
        STEP_CA_HELPER_IMAGE,
        "step",
        "certificate",
        "create",
        &san,
        &output_cert,
        &output_key,
        "--ca",
        &intermediate_cert,
        "--ca-key",
        "/home/step/secrets/intermediate_ca_key",
        "--ca-password-file",
        "/home/step/password.txt",
        "--no-password",
        "--insecure",
        "--san",
        &san,
    ];
    let mut args = args.to_vec();
    args.extend(["--not-after", REGISTRAR_INTERNAL_NOT_AFTER, "--force"]);

    run_docker_with_exec(
        &args,
        "docker step certificate create (registrar internal)",
        inputs.docker,
        messages,
    )
    .with_context(|| messages.error_registrar_internal_provision_failed())
}

/// Stages the persistent ACME account key and returns its contents.
///
/// The key is a member of the set for the daemon's sake:
/// `registrar-internal/agent.toml` names it in `[acme]
/// account_key_path`, and the endpoint's two surface certificates and
/// `bootroot registrar issue` are ordered under it. The internal leaf
/// no longer is, so the file is no longer a by-product of issuing it and
/// is staged in its own right: the published one is carried over
/// unchanged when there is one this crate's ACME client can read back,
/// and a fresh one is created otherwise.
///
/// Nothing is registered with step-ca here. The daemon registers the
/// account on its first order, as any agent with a new account key does.
async fn stage_account_key(
    paths: &InternalPaths,
    staging: &Path,
    messages: &Messages,
) -> Result<String> {
    let published = paths.acme_account();
    let contents = match tokio::fs::read_to_string(&published).await {
        Ok(existing) if bootroot::acme::is_account_key(&existing) => existing,
        Ok(_) => {
            eprintln!(
                "{}",
                messages.warning_registrar_internal_acme_file_replaced(
                    &published.display().to_string()
                )
            );
            new_account_key()?
        }
        Err(_) => new_account_key()?,
    };
    let staged = staging.join(ACME_ACCOUNT_FILE);
    fs_util::atomic_write(
        fs_util::Destination::bootroot_owned(&staged),
        contents.as_bytes(),
        fs_util::StagedMode::Policy(fs_util::KEY_FILE_MODE),
    )
    .await
    .with_context(|| messages.error_write_file_failed(&staged.display().to_string()))?;
    Ok(contents)
}

fn new_account_key() -> Result<String> {
    bootroot::acme::create_account_key().context("creating the bootroot-internal ACME account key")
}

/// Proves a certificate login works over the recorded HTTPS URL and then
/// publishes the material, the dedicated config and the private bundle.
///
/// The login happens **before** the first byte is published: a
/// credential that cannot authenticate must not be left on disk looking
/// as though it could.
///
/// # Errors
///
/// Returns an error when the recorded URL is plaintext, when the
/// certificate login fails, or when any file cannot be published.
pub(super) async fn verify_and_publish_internal(
    staged: &StagedInternal,
    inputs: &RegistrarInternalInputs<'_>,
    openbao_url: &str,
    messages: &Messages,
) -> Result<()> {
    verify_internal_login(staged, openbao_url).await?;
    publish_internal_set(staged, inputs, messages).await
}

/// Proves the staged credential can authenticate at `auth/cert` over
/// the recorded HTTPS URL.
///
/// # Errors
///
/// Returns an error when the URL is plaintext, when the transport
/// cannot be built, or when `OpenBao` rejects the certificate.
pub(crate) async fn verify_internal_login(
    staged: &StagedInternal,
    openbao_url: &str,
) -> Result<()> {
    // The layout's own parent, so the login proof re-reads the active
    // root from the very directory the published credential will sit
    // below. A staged leaf signed under a root that has since been
    // replaced is refused here rather than published.
    let secrets_dir =
        staged.paths.dir().parent().ok_or_else(|| {
            anyhow::anyhow!("the internal layout has no parent secrets directory")
        })?;
    let credential = InternalCredential::from_parts(
        secrets_dir,
        openbao_url,
        &staged.material,
        &staged.bundle_pem,
    )?;
    credential
        .authenticated()
        .await
        .context("proving the bootroot-internal certificate login over the TLS listener")?;
    Ok(())
}

/// Publishes the private bundle, the four credential files and the
/// dedicated config, then removes the staging copies.
///
/// The six files publish atomically one by one, but the set does not: a
/// failure part-way through would leave a re-run's new key beside the
/// previous chain, which still reads as a complete set and can no longer
/// log in. `init`'s rollback cannot repair that either — it deliberately
/// leaves an already-provisioned directory alone rather than deleting
/// the working credential it found. So the prior set is captured first
/// and put back on any failure, and the snapshot is discarded only once
/// the publication has completed.
///
/// # Errors
///
/// Returns an error when the prior set cannot be captured or when any
/// file cannot be published. In the latter case the prior set has been
/// restored, or the failure to restore it is reported beside the
/// failure that caused it.
pub(crate) async fn publish_internal_set(
    staged: &StagedInternal,
    inputs: &RegistrarInternalInputs<'_>,
    messages: &Messages,
) -> Result<()> {
    let snapshot = capture_set(&staged.paths)
        .await
        .context("capturing the bootroot-internal set the publication replaces")?;
    if let Err(err) = publish_internal_files(staged, inputs, messages).await {
        if let Err(restore_err) = snapshot.restore().await {
            eprintln!(
                "Warning: the bootroot-internal set could not be fully restored after a \
                 failed publication: {restore_err}; the previous files are kept at {}",
                snapshot.dir().display()
            );
            return Err(err);
        }
        discard_snapshot(snapshot).await;
        return Err(err);
    }
    discard_snapshot(snapshot).await;

    // The staging copies are the only thing left that holds the key at a
    // second path; remove them once the published set is complete.
    if let Err(err) = tokio::fs::remove_dir_all(&staged.staging).await {
        eprintln!(
            "Warning: failed to remove the staging directory {}: {err}",
            staged.staging.display()
        );
    }
    Ok(())
}

/// Drops a snapshot whose set is settled — published whole, or restored
/// whole.
///
/// Best effort: the bytes it holds are a copy of what is now on disk, so
/// a directory that survives costs an operator a stale copy rather than
/// the credential, and the error it would raise would displace the one
/// that matters.
pub(crate) async fn discard_snapshot(snapshot: SetSnapshot) {
    if let Err(err) = snapshot.discard().await {
        eprintln!("Warning: {err}");
    }
}

/// Writes the six files, in layout order, with no undo of its own.
///
/// Split out so that [`publish_internal_set`] can hold the prior set
/// around the whole sequence rather than around each file.
async fn publish_internal_files(
    staged: &StagedInternal,
    inputs: &RegistrarInternalInputs<'_>,
    messages: &Messages,
) -> Result<()> {
    fs_util::write_ca_bundle(
        &staged.paths.ca_bundle(),
        &staged.bundle_pem,
        cert_group::CertGroupPolicy::none(),
    )
    .await
    .with_context(|| {
        messages.error_write_file_failed(&staged.paths.ca_bundle().display().to_string())
    })?;

    publish_material(&staged.paths, &staged.material).await?;

    let config = internal_agent_config(staged, inputs);
    publish_internal_agent_config(&staged.paths, &config, messages).await
}

/// Renders the `agent.toml` the publication writes.
///
/// Split from the writer so the composition is assertable on its own:
/// publishing the file needs the root authority
/// [`publish_internal_agent_config`] requires, and the trust set the
/// pins are taken from is decided here rather than there.
fn internal_agent_config(staged: &StagedInternal, inputs: &RegistrarInternalInputs<'_>) -> String {
    render_internal_agent_config(
        &staged.paths,
        &InternalAgentConfigParams {
            email: inputs.email,
            server: inputs.acme_server,
            domain: &inputs.intent.domain,
            hostname: &inputs.intent.host,
            responder_url: inputs.responder_url,
            responder_hmac: inputs.responder_hmac,
            eab_kid: inputs.eab.map(|creds| creds.kid.as_str()),
            eab_hmac: inputs.eab.map(|creds| &creds.hmac),
            trusted_ca_sha256: &staged.fingerprints,
            endpoint_tables: inputs.endpoint_tables,
        },
    )
}

/// Publishes the generated `agent.toml`, `root:root` and `0600`.
///
/// Root-owned like the four credential files [`publish_material`] wrote
/// just above: this config carries the trust pins the endpoint daemon
/// orders its certificates against, and a host whose invoking user can
/// rewrite them is a host whose daemon can be pointed at a CA nobody
/// chose. The
/// ownership is selected here rather than inherited from the material
/// writer, so neither publication can lose it by way of the other.
async fn publish_internal_agent_config(
    paths: &InternalPaths,
    config: &str,
    messages: &Messages,
) -> Result<()> {
    fs_util::atomic_write_fixed_owner(
        fs_util::Destination::bootroot_owned(&paths.agent_config()),
        config.as_bytes(),
        fs_util::StagedMode::Policy(fs_util::KEY_FILE_MODE),
        fs_util::FixedOwner::root(),
    )
    .await
    .with_context(|| messages.error_write_file_failed(&paths.agent_config().display().to_string()))
}

async fn read_ca_file(path: &Path, messages: &Messages) -> Result<String> {
    tokio::fs::read_to_string(path)
        .await
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))
}

/// An operator `--agent-config` body for an enabled endpoint, carrying
/// the seven keys it requires and `extra_registrar` inside
/// `[registrar]`.
#[cfg(test)]
pub(crate) fn endpoint_agent_config(extra_registrar: &str) -> String {
    format!(
        "[registrar]\n\
         state_file = \"/var/lib/bootroot/state.json\"\n\
         agent_server = \"https://bootroot-ca.example.internal:9000/acme/acme/directory\"\n\
         agent_responder_url = \"http://bootroot-http01.example.internal:8080\"\n\
         {extra_registrar}\n\
         [registrar_endpoint]\n\
         enabled = true\n\
         server_cert_path = \"/etc/bootroot/registrar/server.crt\"\n\
         server_key_path = \"/etc/bootroot/registrar/server.key\"\n\
         client_cert_path = \"/etc/bootroot/registrar/client.crt\"\n\
         client_key_path = \"/etc/bootroot/registrar/client.key\"\n"
    )
}

/// Fixtures for tests that drive the offline signing: a deployment CA
/// to sign against, and a fake `docker` that stands in for the helper.
#[cfg(test)]
pub(crate) mod test_fixtures {
    use std::path::{Path, PathBuf};

    use crate::commands::init::{
        CA_CERTS_DIR, CA_INTERMEDIATE_CERT_FILENAME, CA_ROOT_CERT_FILENAME,
    };
    use crate::test_support::write_executable;

    /// The SAN of the host every fixture below describes.
    pub(crate) const INTERNAL_SAN: &str =
        "001.bootroot-registrar-internal.bootroot-01.example.internal";

    /// A root, an intermediate under it, and leaves under that.
    pub(crate) struct TestPki {
        pub(crate) root_pem: String,
        pub(crate) intermediate_pem: String,
        intermediate: rcgen::Issuer<'static, rcgen::KeyPair>,
    }

    /// A leaf and the key it was signed for, as `step` would write them.
    pub(crate) struct TestLeaf {
        pub(crate) cert_pem: String,
        pub(crate) key_pem: String,
    }

    impl TestPki {
        pub(crate) fn new() -> Self {
            let ca = |name: &str| {
                let mut params =
                    rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
                params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                params
                    .distinguished_name
                    .push(rcgen::DnType::CommonName, name);
                params
            };
            let root_key = rcgen::KeyPair::generate().expect("root key");
            let root_params = ca("test root");
            let root = root_params.self_signed(&root_key).expect("root");
            let root_issuer = rcgen::Issuer::new(root_params, root_key);
            let intermediate_key = rcgen::KeyPair::generate().expect("intermediate key");
            let intermediate_params = ca("test intermediate");
            let intermediate = intermediate_params
                .signed_by(&intermediate_key, &root_issuer)
                .expect("intermediate");
            Self {
                root_pem: root.pem(),
                intermediate_pem: intermediate.pem(),
                intermediate: rcgen::Issuer::new(intermediate_params, intermediate_key),
            }
        }

        /// Writes the two CA certificates where `init` leaves them.
        pub(crate) fn write_ca(&self, secrets_dir: &Path) {
            let certs = secrets_dir.join(CA_CERTS_DIR);
            std::fs::create_dir_all(&certs).expect("certs dir");
            std::fs::write(certs.join(CA_ROOT_CERT_FILENAME), &self.root_pem).expect("root");
            std::fs::write(
                certs.join(CA_INTERMEDIATE_CERT_FILENAME),
                &self.intermediate_pem,
            )
            .expect("intermediate");
        }

        /// A leaf for the internal SAN that expires at `not_after`.
        pub(crate) fn leaf(&self, not_after: time::OffsetDateTime) -> TestLeaf {
            let key = rcgen::KeyPair::generate().expect("leaf key");
            let mut params =
                rcgen::CertificateParams::new(vec![INTERNAL_SAN.to_string()]).expect("leaf params");
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, INTERNAL_SAN);
            params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
            params.not_after = not_after;
            let cert = params.signed_by(&key, &self.intermediate).expect("leaf");
            TestLeaf {
                cert_pem: cert.pem(),
                key_pem: key.serialize_pem(),
            }
        }

        /// A leaf with ten years ahead of it, as `init` signs one.
        pub(crate) fn fresh_leaf(&self) -> TestLeaf {
            self.leaf(time::OffsetDateTime::now_utc() + time::Duration::days(3650))
        }
    }

    /// Writes a fake `docker` that logs each invocation as one
    /// space-joined line in `args_log` and, for the `step certificate
    /// create` one, writes `leaf` into the directory mounted at
    /// `/output` — as `leaf.pem` and `key.pem`, both at `0600`, which is
    /// what the helper does.
    ///
    /// Self-contained in the sense the other fakes are: everything it
    /// needs is baked into the script, so nothing is read from the
    /// environment.
    pub(crate) fn write_signing_fake_docker(
        dir: &Path,
        args_log: &Path,
        leaf: &TestLeaf,
    ) -> PathBuf {
        let leaf_src = dir.join("fake-docker-leaf.pem");
        let key_src = dir.join("fake-docker-key.pem");
        std::fs::write(&leaf_src, &leaf.cert_pem).expect("leaf source");
        std::fs::write(&key_src, &leaf.key_pem).expect("key source");
        for path in [args_log, &leaf_src, &key_src] {
            assert!(
                !path.display().to_string().contains('\''),
                "the path is interpolated into a single-quoted shell word"
            );
        }
        let script = format!(
            "#!/bin/sh\nset -eu\n{{ printf '%s ' \"$@\"; printf '\\n'; }} >> '{log}'\n\
             out=''\ncreate=0\n\
             for arg in \"$@\"; do\n  case \"$arg\" in\n    \
             *:/output) out=\"${{arg%:/output}}\" ;;\n    create) create=1 ;;\n  esac\ndone\n\
             if [ \"$create\" = 1 ]; then\n  umask 077\n  \
             cat '{leaf}' > \"$out/leaf.pem\"\n  cat '{key}' > \"$out/key.pem\"\nfi\nexit 0\n",
            log = args_log.display(),
            leaf = leaf_src.display(),
            key = key_src.display(),
        );
        let path = dir.join("fake-docker");
        write_executable(&path, script.as_bytes());
        path
    }
}

#[cfg(test)]
mod endpoint_tables_tests {
    use bootroot::registrar::internal::{
        AGENT_CONFIG_FILE, EndpointTables, InternalAgentConfigParams, InternalPaths,
        render_internal_agent_config,
    };
    use tempfile::TempDir;

    use super::{
        RegistrarInternalIntent, current_internal_config, endpoint_agent_config,
        preflight_endpoint_tables,
    };
    use crate::i18n::test_messages;

    const ROOT_FP: &str = "aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900";

    fn intent() -> RegistrarInternalIntent {
        RegistrarInternalIntent {
            domain: "example.internal".to_string(),
            host: "bootroot-01".to_string(),
        }
    }

    fn write(dir: &TempDir, body: &str) -> std::path::PathBuf {
        let path = dir.path().join("agent.toml");
        std::fs::write(&path, body).expect("write the operator file");
        path
    }

    /// The two tables as the daemon deserializes them out of `contents`.
    fn parsed_tables(
        contents: &str,
    ) -> (
        bootroot::config::RegistrarSettings,
        bootroot::config::RegistrarEndpointSettings,
    ) {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join(AGENT_CONFIG_FILE);
        std::fs::write(&path, contents).expect("write");
        let settings =
            bootroot::config::Settings::from_file(Some(path)).expect("the config deserializes");
        (settings.registrar, settings.registrar_endpoint)
    }

    /// Renders an internal config carrying `tables`, as `init` or a
    /// rebuild would.
    /// The tables a rebuild carries over from `paths`, as the rebuild
    /// reads them.
    async fn carried_over_endpoint_tables(
        paths: &InternalPaths,
    ) -> anyhow::Result<Option<EndpointTables>> {
        Ok(current_internal_config(paths, &test_messages())
            .await?
            .and_then(|current| current.endpoint_tables))
    }

    fn internal_config(paths: &InternalPaths, tables: Option<&EndpointTables>) -> String {
        render_internal_agent_config(
            paths,
            &InternalAgentConfigParams {
                email: "ops@example.internal",
                server: "https://localhost:9000/acme/acme/directory",
                domain: "example.internal",
                hostname: "bootroot-01",
                responder_url: "http://127.0.0.1:8080",
                responder_hmac: &"hmac".into(),
                eab_kid: None,
                eab_hmac: None,
                trusted_ca_sha256: &[ROOT_FP.to_string()],
                endpoint_tables: tables,
            },
        )
    }

    /// A complete operator file passes and hands back its two tables.
    #[test]
    fn a_complete_operator_file_is_accepted() {
        let dir = TempDir::new().expect("tempdir");
        let body = endpoint_agent_config("rate_limit_admission_burst = 7\n");
        let path = write(&dir, &body);
        let enabled = preflight_endpoint_tables(Some(intent()), Some(&path), &test_messages())
            .expect("a complete file is accepted")
            .expect("an enabled predicate yields the tables");
        assert_eq!(enabled.intent, intent());
        let paths = InternalPaths::new(dir.path());
        assert_eq!(
            parsed_tables(&internal_config(&paths, Some(&enabled.tables))),
            parsed_tables(&body)
        );
    }

    /// Each required key, removed on its own, refuses the run and is
    /// named in the refusal.
    #[test]
    fn each_missing_required_key_is_refused_by_name() {
        let complete = endpoint_agent_config("");
        for key in [
            "state_file",
            "agent_server",
            "agent_responder_url",
            "server_cert_path",
            "server_key_path",
            "client_cert_path",
            "client_key_path",
        ] {
            let body: String = complete
                .lines()
                .filter(|line| !line.starts_with(&format!("{key} =")))
                .collect::<Vec<_>>()
                .join("\n");
            assert_ne!(body, complete, "{key} was in the complete file");
            let dir = TempDir::new().expect("tempdir");
            let path = write(&dir, &body);
            let err = preflight_endpoint_tables(Some(intent()), Some(&path), &test_messages())
                .err()
                .unwrap_or_else(|| panic!("a file without {key} was accepted"));
            let report = err.to_string();
            assert!(report.contains(key), "{key} is not named: {report}");
            assert!(
                report.contains(&path.display().to_string()),
                "the file is named: {report}"
            );
        }
    }

    /// A value that breaks its own rule is refused by key, not only an
    /// absent one.
    #[test]
    fn an_invalid_agent_server_is_refused_by_name() {
        let body = endpoint_agent_config("").replace(
            "https://bootroot-ca.example.internal:9000/acme/acme/directory",
            "not a url",
        );
        let dir = TempDir::new().expect("tempdir");
        let path = write(&dir, &body);
        let err = preflight_endpoint_tables(Some(intent()), Some(&path), &test_messages())
            .expect_err("an invalid agent_server is refused");
        assert!(err.to_string().contains("registrar.agent_server"), "{err}");

        let relative =
            endpoint_agent_config("").replace("\"/var/lib/bootroot/state.json\"", "\"state.json\"");
        let path = write(&dir, &relative);
        let err = preflight_endpoint_tables(Some(intent()), Some(&path), &test_messages())
            .expect_err("a relative state_file is refused");
        assert!(err.to_string().contains("registrar.state_file"), "{err}");
    }

    /// An enabled predicate with no `--agent-config` is refused with the
    /// existing mandatory-flag message.
    #[test]
    fn an_enabled_predicate_requires_the_flag() {
        let err = preflight_endpoint_tables(Some(intent()), None, &test_messages())
            .expect_err("the flag is mandatory");
        assert!(err.to_string().contains("--agent-config"), "{err}");
    }

    /// A disabled or absent predicate reads nothing, whatever the
    /// operator file holds — including no file at all.
    #[test]
    fn a_disabled_predicate_renders_nothing() {
        let dir = TempDir::new().expect("tempdir");
        let incomplete = write(&dir, "[registrar_endpoint]\nenabled = true\n");
        let complete = dir.path().join("complete.toml");
        std::fs::write(&complete, endpoint_agent_config("")).expect("write");
        let missing = dir.path().join("missing.toml");
        for agent_config in [None, Some(&incomplete), Some(&complete), Some(&missing)] {
            assert!(
                preflight_endpoint_tables(
                    None,
                    agent_config.map(std::path::PathBuf::as_path),
                    &test_messages()
                )
                .expect("a disabled predicate refuses nothing")
                .is_none()
            );
        }
    }

    /// A file that disables the endpoint under an enabled predicate is
    /// left to the audit store's disagreement refusal, unchanged.
    #[test]
    fn a_disagreeing_file_passes_through_to_the_disagreement_refusal() {
        let dir = TempDir::new().expect("tempdir");
        let path = write(&dir, "[registrar_endpoint]\nenabled = false\n");
        assert!(
            preflight_endpoint_tables(Some(intent()), Some(&path), &test_messages())
                .expect("not this check's refusal")
                .is_some()
        );
    }

    /// A rebuild outside `init` carries the tables over from the file on
    /// disk, parse-equal, and carries nothing from a file without them
    /// or from no file at all.
    #[tokio::test]
    async fn a_rebuild_carries_the_tables_over_from_disk() {
        let dir = TempDir::new().expect("tempdir");
        let paths = InternalPaths::new(dir.path());
        std::fs::create_dir_all(paths.dir()).expect("the internal directory");
        assert!(
            carried_over_endpoint_tables(&paths)
                .await
                .expect("an absent file carries nothing")
                .is_none()
        );

        let operator =
            EndpointTables::extract(&endpoint_agent_config("rate_limit_admission_burst = 7\n"))
                .expect("parses");
        let on_disk = internal_config(&paths, Some(&operator));
        std::fs::write(paths.agent_config(), &on_disk).expect("write the current config");
        let carried = carried_over_endpoint_tables(&paths)
            .await
            .expect("a readable file")
            .expect("the tables are carried");
        let rebuilt = internal_config(&paths, Some(&carried));
        assert_eq!(parsed_tables(&rebuilt), parsed_tables(&on_disk));
        assert_eq!(rebuilt, on_disk);

        std::fs::write(paths.agent_config(), internal_config(&paths, None))
            .expect("a disabled host's config");
        assert!(
            carried_over_endpoint_tables(&paths)
                .await
                .expect("a readable file")
                .is_none()
        );
    }

    /// A file that exists but does not parse refuses the rebuild,
    /// naming the file, rather than reading as "no tables".
    #[tokio::test]
    async fn an_unparseable_current_file_refuses_the_rebuild() {
        let dir = TempDir::new().expect("tempdir");
        let paths = InternalPaths::new(dir.path());
        std::fs::create_dir_all(paths.dir()).expect("the internal directory");
        std::fs::write(paths.agent_config(), "[registrar\n").expect("write");
        let err = carried_over_endpoint_tables(&paths)
            .await
            .expect_err("an unparseable file refuses");
        assert!(
            err.to_string()
                .contains(&paths.agent_config().display().to_string()),
            "{err}"
        );
    }

    /// A file that is valid TOML but whose tables the daemon cannot
    /// deserialize refuses the rebuild too: carrying such a table would
    /// publish a set the daemon cannot start on.
    #[tokio::test]
    async fn an_undeserializable_table_refuses_the_rebuild() {
        let dir = TempDir::new().expect("tempdir");
        let paths = InternalPaths::new(dir.path());
        std::fs::create_dir_all(paths.dir()).expect("the internal directory");
        let operator = EndpointTables::extract(&endpoint_agent_config(
            "rate_limit_admission_burst = \"bad\"\n",
        ))
        .expect("syntactically valid TOML");
        std::fs::write(
            paths.agent_config(),
            internal_config(&paths, Some(&operator)),
        )
        .expect("write the current config");
        let err = carried_over_endpoint_tables(&paths)
            .await
            .expect_err("an undeserializable table refuses");
        let message = err.to_string();
        assert!(
            message.contains(&paths.agent_config().display().to_string()),
            "{message}"
        );
        assert!(message.contains("rate_limit_admission_burst"), "{message}");
    }

    /// A file whose two tables deserialize but which holds a value the
    /// daemon rejects elsewhere refuses the rebuild as well: the whole
    /// file is the record a repair keeps, and one the daemon cannot
    /// parse is not read around.
    #[tokio::test]
    async fn an_undeserializable_value_outside_the_tables_refuses_the_rebuild() {
        let dir = TempDir::new().expect("tempdir");
        let paths = InternalPaths::new(dir.path());
        std::fs::create_dir_all(paths.dir()).expect("the internal directory");
        let operator =
            EndpointTables::extract(&endpoint_agent_config("")).expect("syntactically valid TOML");
        let rendered = internal_config(&paths, Some(&operator));
        let broken = rendered.replacen("poll_attempts = 15", "poll_attempts = \"bad\"", 1);
        assert_ne!(broken, rendered, "the fixture edits the rendered value");
        std::fs::write(paths.agent_config(), &broken).expect("write the current config");
        let err = current_internal_config(&paths, &test_messages())
            .await
            .expect_err("an undeserializable value refuses");
        let message = err.to_string();
        assert!(
            message.contains(&paths.agent_config().display().to_string()),
            "{message}"
        );
        assert!(message.contains("poll_attempts"), "{message}");
    }

    /// A parseable file hands back the whole settings a repair keeps,
    /// not only the two tables.
    #[tokio::test]
    async fn a_rebuild_reads_back_the_whole_config() {
        let dir = TempDir::new().expect("tempdir");
        let paths = InternalPaths::new(dir.path());
        std::fs::create_dir_all(paths.dir()).expect("the internal directory");
        std::fs::write(paths.agent_config(), internal_config(&paths, None))
            .expect("write the current config");
        let current = current_internal_config(&paths, &test_messages())
            .await
            .expect("a readable file")
            .expect("a present file");
        assert_eq!(current.settings.email, "ops@example.internal");
        assert_eq!(
            current.settings.acme.http_responder_url,
            "http://127.0.0.1:8080"
        );
    }
}

#[cfg(test)]
mod tests {
    use bootroot::registrar::internal::{InternalPaths, MaterialStatus, material_status};
    use tempfile::TempDir;

    use super::{
        RegistrarInternalIntent, register_internal_rollback, registrar_endpoint_intent, staging_dir,
    };
    use crate::commands::init::steps::InitRollback;
    use crate::state::{RegistrarEndpointState, StateFile};

    const DOMAIN: &str = "example.internal";
    const HOST: &str = "bootroot-01";

    fn state_with(endpoint: Option<RegistrarEndpointState>) -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            registrar_endpoint: endpoint,
            ..StateFile::default()
        };
        state.save(&path).expect("write state");
        (dir, path)
    }

    /// No state file at all — the very first `init` — reads as
    /// endpoint-disabled rather than as an error.
    #[test]
    fn a_missing_state_file_reads_as_disabled() {
        let dir = TempDir::new().expect("tempdir");
        assert_eq!(
            registrar_endpoint_intent(&dir.path().join("state.json")).expect("read"),
            None
        );
    }

    /// The two disabled shapes — no entry, and an entry that says
    /// `false` — both leave the host untouched.
    #[test]
    fn an_absent_or_disabled_entry_reads_as_disabled() {
        let (_dir, path) = state_with(None);
        assert_eq!(registrar_endpoint_intent(&path).expect("read"), None);

        let (_dir, path) = state_with(Some(RegistrarEndpointState {
            enabled: false,
            domain: DOMAIN.to_string(),
            host: HOST.to_string(),
        }));
        assert_eq!(registrar_endpoint_intent(&path).expect("read"), None);
    }

    #[test]
    fn an_enabled_entry_yields_the_fixed_san() {
        let (_dir, path) = state_with(Some(RegistrarEndpointState {
            enabled: true,
            domain: DOMAIN.to_string(),
            host: HOST.to_string(),
        }));
        let intent = registrar_endpoint_intent(&path)
            .expect("read")
            .expect("an enabled endpoint");
        assert_eq!(
            intent,
            RegistrarInternalIntent {
                domain: DOMAIN.to_string(),
                host: HOST.to_string(),
            }
        );
        assert_eq!(
            intent.san(),
            "001.bootroot-registrar-internal.bootroot-01.example.internal"
        );
    }

    /// An enabled endpoint with no host or no domain cannot compose a
    /// SAN. Guessing one would compose a name the deployment's CA never
    /// issues, so this fails the run instead.
    #[test]
    fn an_enabled_entry_missing_an_identity_part_is_an_error() {
        for (domain, host) in [("", HOST), (DOMAIN, ""), ("  ", "  ")] {
            let (_dir, path) = state_with(Some(RegistrarEndpointState {
                enabled: true,
                domain: domain.to_string(),
                host: host.to_string(),
            }));
            let err = registrar_endpoint_intent(&path)
                .expect_err("an incomplete identity must fail the run");
            assert!(
                err.to_string().contains("registrar_endpoint"),
                "{err} for ({domain:?}, {host:?})"
            );
        }
    }

    /// A first provisioning owns the layout directory, so a failure
    /// anywhere after this point removes it whole and leaves nothing
    /// half-provisioned behind.
    #[test]
    fn a_first_provisioning_registers_the_layout_directory() {
        let dir = TempDir::new().expect("tempdir");
        let paths = InternalPaths::new(dir.path());
        let mut rollback = InitRollback::default();
        register_internal_rollback(&mut rollback, dir.path());
        assert_eq!(
            rollback.registrar_internal_dir.as_deref(),
            Some(paths.dir())
        );
        assert_eq!(
            rollback.registrar_internal_staging,
            Some(staging_dir(&paths))
        );
    }

    /// `init` is re-runnable. A re-run over a host that already carries
    /// a credential must not register that credential for teardown: a
    /// failure later in the run would then delete a working credential
    /// and turn a retryable failure into an outage. Staging is still
    /// registered — it is this run's alone and holds an unpublished
    /// private key.
    #[test]
    fn a_re_run_leaves_an_existing_credential_out_of_the_teardown() {
        let dir = TempDir::new().expect("tempdir");
        let paths = InternalPaths::new(dir.path());
        std::fs::create_dir_all(paths.dir()).expect("layout dir");
        for path in paths.all() {
            std::fs::write(&path, "EXISTING").expect("existing artifact");
        }
        let mut rollback = InitRollback::default();
        register_internal_rollback(&mut rollback, dir.path());
        assert_eq!(rollback.registrar_internal_dir, None);
        assert_eq!(
            rollback.registrar_internal_staging,
            Some(staging_dir(&paths))
        );
    }

    /// A half-written set left by an earlier failed run is the prior
    /// state too, and rollback restores prior state rather than
    /// improving on it.
    #[test]
    fn a_partial_set_is_also_left_out_of_the_teardown() {
        let dir = TempDir::new().expect("tempdir");
        let paths = InternalPaths::new(dir.path());
        std::fs::create_dir_all(paths.dir()).expect("layout dir");
        std::fs::write(paths.key(), "EXISTING KEY").expect("key");
        assert!(matches!(
            material_status(&paths),
            MaterialStatus::Partial(_)
        ));
        let mut rollback = InitRollback::default();
        register_internal_rollback(&mut rollback, dir.path());
        assert_eq!(rollback.registrar_internal_dir, None);
    }

    /// A host that reads as disabled creates none of the internal
    /// artifacts, because nothing below the predicate ever runs. The
    /// layout check is what a later assertion in the E2E suite reduces
    /// to, stated here against the same predicate.
    #[test]
    fn a_disabled_host_has_no_internal_layout() {
        let dir = TempDir::new().expect("tempdir");
        assert_eq!(
            material_status(&InternalPaths::new(dir.path())),
            MaterialStatus::Absent
        );
    }
}

#[cfg(test)]
mod auth_provisioning_tests {
    use bootroot::openbao::OpenBaoClient;
    use bootroot::registrar::internal::{
        AcmeAccountKey, InternalMaterial, InternalPaths, PrivateKeyPem,
    };
    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{
        InternalProvisioning, RegistrarInternalContext, RegistrarInternalIntent, StagedInternal,
        provision_internal_auth, register_internal_rollback, settle_internal_publication,
        staging_dir,
    };
    use crate::commands::init::steps::InitRollback;
    use crate::i18n::test_messages;

    const ENTRY_PATH: &str = "/v1/auth/cert/certs/bootroot-registrar-internal";
    const POLICY_PATH: &str = "/v1/sys/policies/acl/bootroot-registrar-internal";
    /// A policy body deliberately unlike the one this crate writes, so a
    /// restore that reproduces it cannot be a convergence that happened
    /// to land on the same text.
    const PRIOR_POLICY: &str = "path \"secret/data/legacy\" {\n  capabilities = [\"read\"]\n}\n";

    /// The staged leaf, and the intermediate that follows it in the
    /// chain. Distinct bodies, so an entry that carried the chain — or
    /// the wrong half of it — is told apart from one that carries the
    /// leaf.
    const STAGED_LEAF: &str = "-----BEGIN CERTIFICATE-----\nTEVBRg\n-----END CERTIFICATE-----\n";
    const STAGED_INTERMEDIATE: &str =
        "-----BEGIN CERTIFICATE-----\nSU5U\n-----END CERTIFICATE-----\n";

    /// The convergence reads nothing from disk any more: the certificate
    /// it writes is the one it is handed.
    fn secrets_dir() -> TempDir {
        TempDir::new().expect("tempdir")
    }

    /// A leaf signed into staging, as `issue_internal_material` returns
    /// it: the chain is the leaf followed by the intermediate.
    fn staged(dir: &std::path::Path) -> StagedInternal {
        let paths = InternalPaths::new(dir);
        StagedInternal {
            staging: staging_dir(&paths),
            paths,
            material: InternalMaterial {
                key: PrivateKeyPem::new(
                    "-----BEGIN EC PRIVATE KEY-----\nQUJD\n-----END EC PRIVATE KEY-----\n"
                        .to_string(),
                ),
                chain: format!("{STAGED_LEAF}{STAGED_INTERMEDIATE}"),
                acme_account: AcmeAccountKey::new("{\"account_key_pkcs8\":\"QUJD\"}".to_string()),
                root_fingerprint:
                    "aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900".to_string(),
            },
            bundle_pem: STAGED_INTERMEDIATE.to_string(),
            fingerprints: Vec::new(),
        }
    }

    fn context(dir: &std::path::Path) -> RegistrarInternalContext {
        RegistrarInternalContext {
            intent: RegistrarInternalIntent {
                domain: "example.internal".to_string(),
                host: "bootroot-01".to_string(),
            },
            secrets_dir: dir.to_path_buf(),
            docker: std::path::PathBuf::from("/nonexistent/docker"),
            kv_mount: "secret".to_string(),
            acme_server: "https://localhost:9000/acme/acme/directory".to_string(),
            email: "ops@example.internal".to_string(),
            responder_url: "http://127.0.0.1:8080".to_string(),
            responder_hmac: "hmac".into(),
            eab: None,
            endpoint_tables: None,
        }
    }

    fn client(server: &MockServer) -> OpenBaoClient {
        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());
        client
    }

    /// The mount is registered the moment it exists, not once the whole
    /// convergence has returned. The policy write is the first thing
    /// after it, and a failure there used to leave an `auth/cert`
    /// backend this run enabled with nothing recorded to disable it —
    /// `OpenBao` altered after a failed `init`.
    #[tokio::test]
    async fn a_mount_this_run_enabled_is_registered_before_the_policy_write() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(ENTRY_PATH))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(POLICY_PATH))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/sys/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {}
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/sys/auth/cert"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(POLICY_PATH))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&server)
            .await;

        let dir = secrets_dir();
        let context = context(dir.path());
        let mut rollback = InitRollback::default();
        let err = provision_internal_auth(
            &client(&server),
            &context.inputs(),
            &staged(dir.path()),
            &mut rollback,
        )
        .await
        .expect_err("a failing policy write must fail the run");
        assert!(format!("{err:#}").contains("policy"), "{err:#}");

        assert!(
            rollback.registrar_internal_cert_auth_mount_created,
            "a backend this run enabled must be registered for teardown even when the \
             writes after it fail"
        );
        assert_eq!(
            rollback.registrar_internal_cert_auth_entry.as_deref(),
            Some("bootroot-registrar-internal")
        );
        assert!(
            rollback
                .created_policies
                .iter()
                .any(|name| name == "bootroot-registrar-internal")
        );
    }

    /// A lookup that did not answer is not an absent artifact. Reading
    /// it as one on a host that already carries the entry would register
    /// a deletion for it, and any later failure in the run would then
    /// take the credential down. The run fails instead — before
    /// anything has been created, and with nothing registered to
    /// destroy.
    #[tokio::test]
    async fn an_entry_lookup_failure_registers_no_destructive_undo() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(ENTRY_PATH))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(POLICY_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "name": "bootroot-registrar-internal", "policy": PRIOR_POLICY }
            })))
            .mount(&server)
            .await;
        // A run that cannot tell what is already there does not start
        // mounting either.
        Mock::given(method("POST"))
            .and(path("/v1/sys/auth/cert"))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&server)
            .await;

        let dir = secrets_dir();
        let context = context(dir.path());
        let mut rollback = InitRollback::default();
        let err = provision_internal_auth(
            &client(&server),
            &context.inputs(),
            &staged(dir.path()),
            &mut rollback,
        )
        .await
        .expect_err("a lookup failure must fail the run");
        assert!(
            format!("{err:#}").contains("cert auth entry"),
            "the refusal must name what could not be read: {err:#}"
        );
        assert_eq!(rollback.registrar_internal_cert_auth_entry, None);
        assert_eq!(rollback.created_policies, Vec::<String>::new());
        assert!(!rollback.registrar_internal_cert_auth_mount_created);
    }

    /// The same rule one lookup later: a policy read that did not answer
    /// registers no deletion for a policy the deployment may already
    /// carry. The entry lookup before it answered a definitive
    /// not-found, so its undo stands — deleting an entry that was never
    /// created is a no-op, and the entry is what a later stage would
    /// have created.
    #[tokio::test]
    async fn a_policy_lookup_failure_registers_no_policy_undo() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(ENTRY_PATH))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(POLICY_PATH))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/sys/auth/cert"))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&server)
            .await;

        let dir = secrets_dir();
        let context = context(dir.path());
        let mut rollback = InitRollback::default();
        let err = provision_internal_auth(
            &client(&server),
            &context.inputs(),
            &staged(dir.path()),
            &mut rollback,
        )
        .await
        .expect_err("a lookup failure must fail the run");
        assert!(
            format!("{err:#}").contains("policy"),
            "the refusal must name what could not be read: {err:#}"
        );
        assert_eq!(rollback.created_policies, Vec::<String>::new());
        assert!(!rollback.registrar_internal_cert_auth_mount_created);
    }

    /// A re-run over a host that already carries the entry, the policy
    /// and the mount registers no *destructive* undo for any of the
    /// three: rollback restores the prior state, and the prior state is
    /// a working credential.
    #[tokio::test]
    async fn a_re_run_registers_none_of_the_artifacts_it_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(ENTRY_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "display_name": "bootroot-registrar-internal" }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(POLICY_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "name": "bootroot-registrar-internal", "policy": PRIOR_POLICY }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/sys/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "cert/": { "type": "cert" } }
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/sys/auth/cert"))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(POLICY_PATH))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(ENTRY_PATH))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let dir = secrets_dir();
        let context = context(dir.path());
        let mut rollback = InitRollback::default();
        provision_internal_auth(
            &client(&server),
            &context.inputs(),
            &staged(dir.path()),
            &mut rollback,
        )
        .await
        .expect("converging what is already there must succeed");

        assert_eq!(rollback.registrar_internal_cert_auth_entry, None);
        assert_eq!(rollback.created_policies, Vec::<String>::new());
        assert!(!rollback.registrar_internal_cert_auth_mount_created);
        // What it registers instead: the bodies it is about to replace.
        assert!(rollback.registrar_internal_cert_auth_entry_backup.is_some());
        assert_eq!(
            rollback.registrar_internal_policy_backup.as_deref(),
            Some(PRIOR_POLICY)
        );
    }

    /// A mock `OpenBao` that already carries the mount, the entry and
    /// the policy, and accepts every write against them — the shape of
    /// a host `init` is re-run over. Every delete is refused, because a
    /// run that created none of the three may remove none of them.
    async fn established_host(prior_entry: &serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(ENTRY_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": prior_entry.clone()
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(POLICY_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "name": "bootroot-registrar-internal", "policy": PRIOR_POLICY }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/sys/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "cert/": { "type": "cert" } }
            })))
            .mount(&server)
            .await;
        for target in [ENTRY_PATH, POLICY_PATH] {
            Mock::given(method("POST"))
                .and(path(target))
                .respond_with(ResponseTemplate::new(204))
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .and(path(target))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
        }
        Mock::given(method("DELETE"))
            .and(path("/v1/sys/auth/cert"))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&server)
            .await;
        server
    }

    /// A host that already carries the whole set, under bytes no
    /// publication writes.
    fn provisioned_host(dir: &std::path::Path) -> InternalPaths {
        let paths = InternalPaths::new(dir);
        std::fs::create_dir_all(paths.dir()).expect("the internal directory");
        for path in paths.all() {
            std::fs::write(&path, "PRIOR").expect("a prior member");
        }
        paths
    }

    fn set_contents(paths: &InternalPaths) -> Vec<String> {
        paths
            .all()
            .iter()
            .map(|path| std::fs::read_to_string(path).expect("a member"))
            .collect()
    }

    /// Every body posted to `target`, in order.
    async fn posted(server: &MockServer, target: &str) -> Vec<serde_json::Value> {
        server
            .received_requests()
            .await
            .expect("the mock server records its requests")
            .iter()
            .filter(|req| req.method == wiremock::http::Method::POST && req.url.path() == target)
            .map(|req| serde_json::from_slice(&req.body).expect("a JSON request body"))
            .collect()
    }

    /// The entry's `certificate` is the staged leaf and only the leaf:
    /// not the chain the client presents, and not the deployment root.
    /// A CA there would accept every leaf of that CA carrying the SAN —
    /// one obtained from step-ca with the responder HMAC included.
    #[tokio::test]
    async fn the_entry_is_pinned_to_the_staged_leaf_alone() {
        let server = established_host(&serde_json::json!({})).await;
        let dir = secrets_dir();
        let context = context(dir.path());
        let mut rollback = InitRollback::default();
        provision_internal_auth(
            &client(&server),
            &context.inputs(),
            &staged(dir.path()),
            &mut rollback,
        )
        .await
        .expect("the convergence succeeds");

        let entries = posted(&server, ENTRY_PATH).await;
        let entry = entries.first().expect("the entry was written");
        assert_eq!(entry["certificate"], STAGED_LEAF);
        assert_eq!(
            entry["allowed_dns_sans"],
            "001.bootroot-registrar-internal.bootroot-01.example.internal"
        );
        assert_eq!(entry["allowed_common_names"], entry["allowed_dns_sans"]);
        assert_eq!(
            entry["token_policies"],
            serde_json::json!(["bootroot-registrar-internal"])
        );
        assert!(entry.get("token_bound_cidrs").is_none());
    }

    /// A chain that holds no certificate pins nothing, and nothing is
    /// read from or written to `OpenBao` for it.
    #[tokio::test]
    async fn a_staged_chain_without_a_certificate_reaches_no_openbao_request() {
        let server = MockServer::start().await;
        let dir = secrets_dir();
        let context = context(dir.path());
        let mut broken = staged(dir.path());
        broken.material.chain = "not a certificate\n".to_string();
        let mut rollback = InitRollback::default();
        provision_internal_auth(&client(&server), &context.inputs(), &broken, &mut rollback)
            .await
            .expect_err("there is no leaf to pin");
        assert!(
            server
                .received_requests()
                .await
                .expect("recording")
                .is_empty()
        );
    }

    /// The convergence rewrites the entry and the policy whether or not
    /// this run created them, so "delete only what this run created" is
    /// not the whole undo: a re-run that fails after the entry write and
    /// before the publication would otherwise leave the host's
    /// `auth/cert` entry pinned to this run's staged leaf while the
    /// on-disk leaf is still the previous one, which is precisely the
    /// state in which nothing can authenticate. Both bodies go back
    /// exactly as they were read, and the files were never touched.
    #[tokio::test]
    async fn a_failure_before_publication_restores_the_entry_and_policy_it_replaced() {
        let prior_entry = serde_json::json!({
            "certificate": "-----BEGIN CERTIFICATE-----\nT0xE\n-----END CERTIFICATE-----\n",
            "allowed_dns_sans": "001.bootroot-registrar-internal.old-host.old.internal",
            "token_policies": ["bootroot-registrar-internal"],
            "token_no_default_policy": true,
            "token_ttl": 3600,
            "display_name": "bootroot-registrar-internal",
        });
        let server = established_host(&prior_entry).await;

        let dir = secrets_dir();
        let context = context(dir.path());
        let mut rollback = InitRollback::default();
        let client = client(&server);
        // The run found a credential on disk, and staged its
        // replacement before it wrote the entry.
        let paths = provisioned_host(dir.path());
        let before = set_contents(&paths);
        assert_eq!(
            register_internal_rollback(&mut rollback, dir.path()),
            InternalProvisioning::Replacement
        );
        provision_internal_auth(
            &client,
            &context.inputs(),
            &staged(dir.path()),
            &mut rollback,
        )
        .await
        .expect("converging over an established credential must succeed");

        // The failure the transaction exists for: something between the
        // entry write and the publication gives up — the listener
        // transition, or the login proof — and the envelope unwinds.
        rollback.rollback(&client, "secret", &test_messages()).await;
        assert_eq!(
            set_contents(&paths),
            before,
            "the files the run found were never touched"
        );

        let entries = posted(&server, ENTRY_PATH).await;
        assert_eq!(
            entries.len(),
            2,
            "the entry is written once by the convergence and once by the restore"
        );
        assert_ne!(
            entries.first(),
            Some(&prior_entry),
            "the convergence must actually have replaced the entry, or the restore              below proves nothing"
        );
        assert_eq!(
            entries.get(1),
            Some(&prior_entry),
            "rollback must put the prior entry back byte for byte"
        );

        let policies = posted(&server, POLICY_PATH).await;
        assert_eq!(
            policies.len(),
            2,
            "the policy is written once by the convergence and once by the restore"
        );
        assert_ne!(
            policies
                .first()
                .and_then(|body| body.get("policy"))
                .and_then(serde_json::Value::as_str),
            Some(PRIOR_POLICY),
            "the convergence must actually have replaced the policy"
        );
        assert_eq!(
            policies
                .get(1)
                .and_then(|body| body.get("policy"))
                .and_then(serde_json::Value::as_str),
            Some(PRIOR_POLICY),
            "rollback must put the prior policy body back byte for byte"
        );
    }

    /// The prior entry a re-run finds: pinned to the leaf the host held
    /// before this run.
    fn prior_entry() -> serde_json::Value {
        serde_json::json!({
            "certificate": "-----BEGIN CERTIFICATE-----\nT0xE\n-----END CERTIFICATE-----\n",
            "allowed_dns_sans": "001.bootroot-registrar-internal.bootroot-01.example.internal",
            "token_policies": ["bootroot-registrar-internal"],
            "token_no_default_policy": true,
            "token_ttl": 3600,
            "display_name": "bootroot-registrar-internal",
        })
    }

    /// Once the replacement is published, the entry and policy the run
    /// captured name a leaf that is no longer on disk. A failure later
    /// in the run must therefore restore neither: the new entry stays in
    /// `OpenBao` and the new files stay on disk, a working pair. The
    /// daemon, still holding the leaf the pinned entry now refuses, is
    /// signalled — after the publication, and exactly once.
    #[tokio::test]
    async fn a_failure_after_publication_keeps_the_new_entry_and_files() {
        let server = established_host(&prior_entry()).await;
        let dir = secrets_dir();
        let context = context(dir.path());
        let mut rollback = InitRollback::default();
        let client = client(&server);

        let paths = provisioned_host(dir.path());
        let provisioning = register_internal_rollback(&mut rollback, dir.path());
        assert_eq!(provisioning, InternalProvisioning::Replacement);
        provision_internal_auth(
            &client,
            &context.inputs(),
            &staged(dir.path()),
            &mut rollback,
        )
        .await
        .expect("converging over an established credential must succeed");
        assert!(rollback.registrar_internal_cert_auth_entry_backup.is_some());
        assert!(rollback.registrar_internal_policy_backup.is_some());

        // The publication: root-only in production, so stood in for by
        // the bytes it would leave.
        for path in paths.all() {
            std::fs::write(&path, "PUBLISHED").expect("a published member");
        }
        let mut signalled = Vec::new();
        settle_internal_publication(&mut rollback, provisioning, dir.path(), |secrets_dir| {
            signalled.push(secrets_dir.to_path_buf());
            Ok(())
        })
        .expect("the reload signal succeeds");
        assert_eq!(
            signalled,
            [dir.path().to_path_buf()],
            "the daemon on this secrets directory is signalled once"
        );
        assert_eq!(rollback.registrar_internal_cert_auth_entry_backup, None);
        assert_eq!(rollback.registrar_internal_policy_backup, None);

        // A later step fails, and the envelope unwinds.
        rollback.rollback(&client, "secret", &test_messages()).await;

        let entries = posted(&server, ENTRY_PATH).await;
        assert_eq!(
            entries.len(),
            1,
            "no restoring write reaches the entry: {entries:?}"
        );
        assert_eq!(entries[0]["certificate"], STAGED_LEAF);
        assert_eq!(
            posted(&server, POLICY_PATH).await.len(),
            1,
            "no restoring write reaches the policy"
        );
        assert_eq!(
            set_contents(&paths),
            vec!["PUBLISHED".to_string(); paths.all().len()],
            "the published files are kept"
        );
        // `established_host` refuses every delete, on drop.
    }

    /// A reload that cannot be sent fails `init`, as any later step
    /// does — with the new pair already settled, so the unwinding that
    /// follows keeps it.
    #[tokio::test]
    async fn a_failed_reload_signal_fails_the_run_and_keeps_the_new_pair() {
        let server = established_host(&prior_entry()).await;
        let dir = secrets_dir();
        let context = context(dir.path());
        let mut rollback = InitRollback::default();
        let client = client(&server);
        provisioned_host(dir.path());
        let provisioning = register_internal_rollback(&mut rollback, dir.path());
        provision_internal_auth(
            &client,
            &context.inputs(),
            &staged(dir.path()),
            &mut rollback,
        )
        .await
        .expect("the convergence succeeds");

        let err = settle_internal_publication(&mut rollback, provisioning, dir.path(), |_| {
            anyhow::bail!("pkill -HUP failed")
        })
        .expect_err("a failed signal is a failed run");
        assert!(err.to_string().contains("pkill"), "{err}");

        rollback.rollback(&client, "secret", &test_messages()).await;
        assert_eq!(posted(&server, ENTRY_PATH).await.len(), 1);
        assert_eq!(posted(&server, POLICY_PATH).await.len(), 1);
    }

    /// A first provisioning has no daemon on a credential that did not
    /// exist, so it sends no signal — and its rollback is unchanged: the
    /// directory, the entry and the policy it created are all still
    /// registered for removal.
    #[tokio::test]
    async fn a_first_provisioning_sends_no_signal_and_keeps_its_teardown() {
        let server = MockServer::start().await;
        for target in [ENTRY_PATH, POLICY_PATH] {
            Mock::given(method("GET"))
                .and(path(target))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(target))
                .respond_with(ResponseTemplate::new(204))
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/v1/sys/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "cert/": { "type": "cert" } }
            })))
            .mount(&server)
            .await;

        let dir = secrets_dir();
        let context = context(dir.path());
        let mut rollback = InitRollback::default();
        let provisioning = register_internal_rollback(&mut rollback, dir.path());
        assert_eq!(provisioning, InternalProvisioning::First);
        provision_internal_auth(
            &client(&server),
            &context.inputs(),
            &staged(dir.path()),
            &mut rollback,
        )
        .await
        .expect("the convergence succeeds");

        let mut signals = 0;
        settle_internal_publication(&mut rollback, provisioning, dir.path(), |_| {
            signals += 1;
            Ok(())
        })
        .expect("nothing to settle");
        assert_eq!(signals, 0, "a first provisioning reloads nothing");
        assert_eq!(
            rollback.registrar_internal_dir.as_deref(),
            Some(InternalPaths::new(dir.path()).dir())
        );
        assert_eq!(
            rollback.registrar_internal_cert_auth_entry.as_deref(),
            Some("bootroot-registrar-internal")
        );
        assert!(
            rollback
                .created_policies
                .iter()
                .any(|name| name == "bootroot-registrar-internal")
        );
    }
}

#[cfg(test)]
mod publication_tests {
    use bootroot::fs_util::current_process_euid;
    use bootroot::registrar::internal::material::PRIOR_DIR;
    use bootroot::registrar::internal::{
        AGENT_CONFIG_FILE, AcmeAccountKey, InternalMaterial, InternalPaths, KEY_FILE, PrivateKeyPem,
    };
    use tempfile::TempDir;

    use super::{
        RegistrarInternalContext, RegistrarInternalIntent, StagedInternal, internal_agent_config,
        publish_internal_agent_config, publish_internal_set, staging_dir,
    };
    use crate::i18n::test_messages;

    const ACTIVE_ROOT: &str = "aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900";
    const ACTIVE_INT: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const OLD_ROOT: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const OLD_INT: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    fn bundle(label: &str) -> String {
        format!("-----BEGIN CERTIFICATE-----\n{label}\n-----END CERTIFICATE-----\n")
    }

    fn context(dir: &std::path::Path) -> RegistrarInternalContext {
        RegistrarInternalContext {
            intent: RegistrarInternalIntent {
                domain: "example.internal".to_string(),
                host: "bootroot-01".to_string(),
            },
            secrets_dir: dir.to_path_buf(),
            docker: std::path::PathBuf::from("/nonexistent/docker"),
            kv_mount: "secret".to_string(),
            acme_server: "https://localhost:9000/acme/acme/directory".to_string(),
            email: "ops@example.internal".to_string(),
            responder_url: "http://127.0.0.1:8080".to_string(),
            responder_hmac: "hmac".into(),
            eab: None,
            endpoint_tables: None,
        }
    }

    fn staged(dir: &std::path::Path) -> StagedInternal {
        let paths = InternalPaths::new(dir);
        StagedInternal {
            staging: staging_dir(&paths),
            paths,
            material: InternalMaterial {
                key: PrivateKeyPem::new(
                    "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n".to_string(),
                ),
                chain: bundle("TEVBRg"),
                acme_account: AcmeAccountKey::new("{\"account_key_pkcs8\":\"QUJD\"}".to_string()),
                root_fingerprint: ACTIVE_ROOT.to_string(),
            },
            bundle_pem: bundle("QUNUSVZF"),
            fingerprints: vec![ACTIVE_ROOT.to_string(), ACTIVE_INT.to_string()],
        }
    }

    /// A host that already carries a complete set, under bytes no
    /// publication below writes, so a member left on its prior contents
    /// is distinguishable from one that was rewritten.
    ///
    /// Written directly rather than through `publish_material`: that
    /// publisher establishes `root:root` on every protected file and
    /// refuses when it cannot, which is what the tests below are about
    /// and not something an unprivileged fixture can drive.
    fn provisioned_host(paths: &InternalPaths) {
        std::fs::create_dir_all(paths.dir()).expect("the internal directory");
        std::fs::write(
            paths.key(),
            "-----BEGIN PRIVATE KEY-----\nUFJJT1I\n-----END PRIVATE KEY-----\n",
        )
        .expect("the prior key");
        std::fs::write(paths.chain(), bundle("UFJJT1JMRUFG")).expect("the prior chain");
        std::fs::write(paths.acme_account(), "{\"account_key_pkcs8\":\"UFJJT1I\"}")
            .expect("the prior account key");
        std::fs::write(paths.root_fingerprint(), format!("{OLD_ROOT}\n"))
            .expect("the prior fingerprint");
        std::fs::write(paths.ca_bundle(), bundle("UFJJT1JCVU5ETEU")).expect("the prior bundle");
        std::fs::write(paths.agent_config(), "email = \"prior@example.internal\"\n")
            .expect("the prior config");
    }

    /// Publishing the set is root-only, and a bare host it cannot
    /// publish on is left bare.
    ///
    /// The four credential files and the generated config are `0600`
    /// `root:root` or they are not this host's credential: an
    /// unprivileged `init` must not leave a key the invoking user can
    /// read behind a set that reads as complete. The private bundle is
    /// published before them and is public trust material, so the proof
    /// that nothing survives is the rollback putting the host back as it
    /// found it.
    #[tokio::test]
    async fn a_publication_is_refused_without_the_authority_to_own_the_set() {
        assert_ne!(
            current_process_euid(),
            0,
            "this test asserts what an unprivileged process cannot do, so it must not be root"
        );
        let dir = TempDir::new().expect("tempdir");
        let context = context(dir.path());
        let staged = staged(dir.path());
        let err = publish_internal_set(&staged, &context.inputs(), &test_messages())
            .await
            .expect_err("an unprivileged process cannot publish the protected set");
        let report = format!("{err:#}");
        assert!(
            report.contains(KEY_FILE) && report.contains("root-owned"),
            "the refusal must name the root-ownership requirement and the file: {report}"
        );

        let paths = InternalPaths::new(dir.path());
        for path in paths.all() {
            assert!(
                !path.exists(),
                "a refused publication leaves no member behind: {}",
                path.display()
            );
        }
        assert!(
            !paths.dir().join(PRIOR_DIR).exists(),
            "a settled publication leaves no snapshot"
        );
    }

    /// A publication over a host that already carries a set touches no
    /// member of it unless it can own every one.
    ///
    /// The six files publish one at a time, so a failure part-way
    /// through an already-provisioned host would otherwise leave a new
    /// key beside the previous chain — a set that still reads as
    /// complete and can no longer log in — and `init`'s rollback would
    /// not repair it, because a re-run deliberately does not register
    /// the credential it found for teardown. The capture that guards
    /// against that runs first and snapshots the protected members under
    /// the ownership they are published with, so an unprivileged run is
    /// refused there: before a final name has been touched, and with no
    /// half-written snapshot left behind either.
    #[tokio::test]
    async fn a_refused_publication_leaves_the_set_it_found() {
        assert_ne!(
            current_process_euid(),
            0,
            "this test asserts what an unprivileged process cannot do, so it must not be root"
        );
        let dir = TempDir::new().expect("tempdir");
        let paths = InternalPaths::new(dir.path());
        provisioned_host(&paths);
        let before: Vec<(std::path::PathBuf, String)> = paths
            .all()
            .into_iter()
            .map(|path| {
                let contents = std::fs::read_to_string(&path).expect("prior member");
                (path, contents)
            })
            .collect();

        let context = context(dir.path());
        let staged = staged(dir.path());
        let err = publish_internal_set(&staged, &context.inputs(), &test_messages())
            .await
            .expect_err("an unprivileged process cannot publish the protected set");
        let report = format!("{err:#}");
        assert!(
            report.contains(KEY_FILE) && report.contains("root-owned"),
            "the refusal must name the root-ownership requirement and the file: {report}"
        );

        for (path, contents) in before {
            assert_eq!(
                std::fs::read_to_string(&path).expect("member after the refusal"),
                contents,
                "a refused publication must leave {} on its prior bytes",
                path.display()
            );
        }
        assert!(
            !paths.dir().join(PRIOR_DIR).exists(),
            "a capture that could not complete leaves no partial snapshot"
        );
    }

    /// `init` selects the root-owned writer for the generated config
    /// itself, independently of the material publisher beside it.
    ///
    /// Called directly, past the four credential files that would
    /// otherwise be refused first, so what fails here is this writer's
    /// own selection. The config carries the trust pins, so a host whose
    /// invoking user owns it is a host whose credential can be reissued
    /// against a CA nobody chose.
    #[tokio::test]
    async fn the_config_writer_is_root_owned_independently_of_the_material() {
        assert_ne!(
            current_process_euid(),
            0,
            "this test asserts what an unprivileged process cannot do, so it must not be root"
        );
        let dir = TempDir::new().expect("tempdir");
        let paths = InternalPaths::new(dir.path());
        std::fs::create_dir_all(paths.dir()).expect("the internal directory");

        let err = publish_internal_agent_config(
            &paths,
            "email = \"ops@example.internal\"\n",
            &test_messages(),
        )
        .await
        .expect_err("an unprivileged process cannot publish the protected config");
        let report = format!("{err:#}");
        assert!(
            report.contains(AGENT_CONFIG_FILE) && report.contains("root-owned"),
            "the refusal must name the root-ownership requirement and the file: {report}"
        );
        assert!(
            !paths.agent_config().exists(),
            "a refused publication must not create the config"
        );
    }

    /// The pins the publication writes are the trust set it was given:
    /// the active generation `init` staged, or the additive set a repair
    /// overrides it with.
    ///
    /// Asserted on the rendered config rather than on a published one,
    /// because publishing it takes the root authority the tests above
    /// prove an ordinary user does not have — and the composition is
    /// what would otherwise go unchecked outside a privileged E2E.
    /// Narrowing the repair case to the active generation would take
    /// this identity off a set the rest of the fleet still trusts.
    #[test]
    fn the_generated_config_carries_the_trust_set_the_publication_was_given() {
        let dir = TempDir::new().expect("tempdir");
        let context = context(dir.path());
        let paths = InternalPaths::new(dir.path());

        let active = settings_of(&internal_agent_config(
            &staged(dir.path()),
            &context.inputs(),
        ));
        assert_eq!(
            active.trust.trusted_ca_sha256,
            [ACTIVE_ROOT.to_string(), ACTIVE_INT.to_string()]
        );
        assert_eq!(
            active.trust.ca_bundle_path.as_deref(),
            Some(paths.ca_bundle().as_path())
        );
        assert_eq!(
            active.profiles.first().expect("one profile").paths.cert,
            paths.chain()
        );

        let additive = vec![
            OLD_ROOT.to_string(),
            OLD_INT.to_string(),
            ACTIVE_ROOT.to_string(),
            ACTIVE_INT.to_string(),
        ];
        let repaired = settings_of(&internal_agent_config(
            &staged(dir.path()).with_trust(additive.clone(), bundle("QURESVRJVkU")),
            &context.inputs(),
        ));
        assert_eq!(repaired.trust.trusted_ca_sha256, additive);
    }

    /// `init`'s publication appends the operator's two tables from
    /// `--agent-config`, and a context without them — every host but a
    /// registrar host never builds one, and a repair of a disabled
    /// host's config carries none — publishes none.
    #[test]
    fn the_generated_config_carries_the_context_endpoint_tables() {
        let dir = TempDir::new().expect("tempdir");
        let operator = super::endpoint_agent_config("rate_limit_admission_burst = 7\n");
        let mut context = context(dir.path());
        context.endpoint_tables = Some(
            bootroot::registrar::internal::EndpointTables::extract(&operator).expect("parses"),
        );
        let carried = settings_of(&internal_agent_config(
            &staged(dir.path()),
            &context.inputs(),
        ));
        let expected = settings_of_operator(&operator);
        assert_eq!(carried.registrar, expected.registrar);
        assert_eq!(carried.registrar_endpoint, expected.registrar_endpoint);
        assert!(carried.registrar_endpoint.enabled);

        context.endpoint_tables = None;
        let plain = internal_agent_config(&staged(dir.path()), &context.inputs());
        assert!(!plain.contains("\n[registrar"), "{plain}");
    }

    /// Parses an operator `--agent-config` body's two tables the way
    /// `bootroot-agent` does, under a stand-in for the rest.
    fn settings_of_operator(operator: &str) -> bootroot::config::Settings {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("operator.toml");
        std::fs::write(&path, operator).expect("write the operator config");
        bootroot::config::Settings::from_file(Some(path))
            .expect("the operator config must deserialize")
    }

    /// Parses a rendered config the way `bootroot-agent` does.
    fn settings_of(rendered: &str) -> bootroot::config::Settings {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join(AGENT_CONFIG_FILE);
        std::fs::write(&path, rendered).expect("write the rendered config");
        bootroot::config::Settings::from_file(Some(path))
            .expect("the generated config must deserialize")
    }
}

/// The offline signing: what the helper is asked to do, what is staged
/// beside its two outputs, and what a failure leaves behind.
#[cfg(test)]
mod offline_signing_tests {
    use std::os::unix::fs::PermissionsExt;

    use bootroot::registrar::internal::{ACME_ACCOUNT_FILE, InternalPaths, first_certificate_der};
    use tempfile::TempDir;

    use super::test_fixtures::{INTERNAL_SAN, TestLeaf, TestPki, write_signing_fake_docker};
    use super::{
        RegistrarInternalContext, RegistrarInternalIntent, issue_internal_material, staging_dir,
    };
    use crate::commands::init::constants::REGISTRAR_INTERNAL_NOT_AFTER;
    use crate::i18n::test_messages;

    /// A host with its CA certificates in place and a fake `docker`
    /// standing in for the signing helper.
    struct Host {
        dir: TempDir,
        secrets_dir: std::path::PathBuf,
        args_log: std::path::PathBuf,
        pki: TestPki,
        leaf: TestLeaf,
        context: RegistrarInternalContext,
    }

    impl Host {
        fn new() -> Self {
            let dir = TempDir::new().expect("tempdir");
            let secrets_dir = dir.path().join("secrets");
            std::fs::create_dir_all(&secrets_dir).expect("secrets dir");
            let pki = TestPki::new();
            pki.write_ca(&secrets_dir);
            let leaf = pki.fresh_leaf();
            let args_log = dir.path().join("docker_args.log");
            let docker = write_signing_fake_docker(dir.path(), &args_log, &leaf);
            let context = RegistrarInternalContext {
                intent: RegistrarInternalIntent {
                    domain: "example.internal".to_string(),
                    host: "bootroot-01".to_string(),
                },
                secrets_dir: secrets_dir.clone(),
                docker,
                kv_mount: "secret".to_string(),
                // Nothing listens on either: the offline signing must
                // not dial them, and an attempt would fail the run.
                acme_server: "https://127.0.0.1:1/acme/acme/directory".to_string(),
                email: "ops@example.internal".to_string(),
                responder_url: "http://127.0.0.1:1".to_string(),
                responder_hmac: "hmac".into(),
                eab: None,
                endpoint_tables: None,
            };
            Self {
                dir,
                secrets_dir,
                args_log,
                pki,
                leaf,
                context,
            }
        }

        fn paths(&self) -> InternalPaths {
            InternalPaths::new(&self.secrets_dir)
        }

        fn invocations(&self) -> Vec<Vec<String>> {
            std::fs::read_to_string(&self.args_log)
                .unwrap_or_default()
                .lines()
                .map(|line| line.split_whitespace().map(str::to_string).collect())
                .collect()
        }
    }

    /// The value following `flag` in `args`, for every occurrence.
    fn values_of<'a>(args: &'a [String], flag: &str) -> Vec<&'a str> {
        args.windows(2)
            .filter(|pair| pair[0] == flag)
            .map(|pair| pair[1].as_str())
            .collect()
    }

    /// The helper is asked for exactly the leaf the entry will be pinned
    /// to: the internal SAN as subject and as the only SAN, signed by
    /// the intermediate with its key and password file, valid for ten
    /// years, written as the owner of the secrets directory into the
    /// staging directory. And no ACME order is placed: the directory and
    /// responder the context names are unreachable, and the run
    /// succeeds.
    #[tokio::test]
    async fn the_leaf_is_signed_offline_against_the_intermediate() {
        use std::os::unix::fs::MetadataExt;

        let host = Host::new();
        issue_internal_material(&host.context.inputs(), &test_messages())
            .await
            .expect("the offline signing succeeds without ACME");

        let invocations = host.invocations();
        assert_eq!(
            invocations.len(),
            2,
            "the scoped chown and then the signing: {invocations:?}"
        );
        let staging = std::fs::canonicalize(staging_dir(&host.paths())).expect("staging exists");
        let staging_mount = format!("{}:/output", staging.display());
        let meta = std::fs::metadata(&host.secrets_dir).expect("secrets dir");
        let owner = format!("{}:{}", meta.uid(), meta.gid());

        let chown = &invocations[0];
        assert!(
            chown
                .windows(2)
                .any(|pair| pair == ["--entrypoint", "chown"])
                && chown.iter().any(|arg| arg == "--no-dereference"),
            "the first container is the scoped chown: {chown:?}"
        );
        assert_eq!(values_of(chown, "-v"), [staging_mount.as_str()]);
        assert!(chown.contains(&owner));

        let create = &invocations[1];
        let image = create
            .iter()
            .position(|arg| arg == "step")
            .and_then(|step| step.checked_sub(1))
            .and_then(|index| create.get(index))
            .expect("the image precedes the `step` command");
        crate::runtime_image_declaration::assert_declared_image(
            "step-ca",
            image,
            "registrar internal leaf signing",
        );
        let command = create
            .iter()
            .position(|arg| arg == "create")
            .expect("step certificate create");
        assert_eq!(
            &create[command - 2..command + 4],
            [
                "step",
                "certificate",
                "create",
                INTERNAL_SAN,
                "/output/leaf.pem",
                "/output/key.pem"
            ]
        );
        assert_eq!(values_of(create, "--san"), [INTERNAL_SAN]);
        assert_eq!(
            values_of(create, "--ca"),
            ["/home/step/certs/intermediate_ca.crt"]
        );
        assert_eq!(
            values_of(create, "--ca-key"),
            ["/home/step/secrets/intermediate_ca_key"]
        );
        assert_eq!(
            values_of(create, "--ca-password-file"),
            ["/home/step/password.txt"]
        );
        assert_eq!(REGISTRAR_INTERNAL_NOT_AFTER, "87600h");
        assert_eq!(values_of(create, "--not-after"), ["87600h"]);
        assert_eq!(values_of(create, "--user"), [owner.as_str()]);
        let secrets_mount = format!(
            "{}:/home/step",
            std::fs::canonicalize(&host.secrets_dir)
                .expect("secrets dir")
                .display()
        );
        assert_eq!(
            values_of(create, "-v"),
            [secrets_mount.as_str(), staging_mount.as_str()]
        );
        for flag in ["--no-password", "--insecure", "--force"] {
            assert!(create.iter().any(|arg| arg == flag), "{flag}");
        }
    }

    /// What is staged is the helper's leaf followed by the intermediate,
    /// with the helper's key and the active root's fingerprint — and the
    /// leaf alone is what the entry gets. Nothing is published, and the
    /// staged key is left at the mode the helper created it at.
    #[tokio::test]
    async fn the_signed_leaf_is_staged_and_nothing_is_published() {
        let host = Host::new();
        let staged = issue_internal_material(&host.context.inputs(), &test_messages())
            .await
            .expect("the offline signing succeeds");
        let staging = staging_dir(&host.paths());

        assert_eq!(staged.leaf_pem().expect("a leaf"), host.leaf.cert_pem);
        assert_eq!(
            staged.material.chain,
            format!("{}{}", host.leaf.cert_pem, host.pki.intermediate_pem)
        );
        assert_eq!(staged.material.key.expose(), host.leaf.key_pem);
        assert_eq!(
            staged.material.root_fingerprint,
            bootroot::registrar::internal::active_root_fingerprint(&host.secrets_dir)
                .expect("the active root")
        );
        first_certificate_der(&staging.join("leaf.pem"), &staged.material.chain)
            .expect("the chain opens with a certificate");

        for path in host.paths().all() {
            assert!(!path.exists(), "{} was published", path.display());
        }
        let key_mode = std::fs::metadata(staging.join("key.pem"))
            .expect("the staged key")
            .permissions()
            .mode();
        assert_eq!(key_mode & 0o777, 0o600);
    }

    /// With no published set there is no account key to carry, so a new
    /// one is created in staging: well-formed, and at `0600`.
    #[tokio::test]
    async fn a_first_provisioning_creates_an_account_key() {
        let host = Host::new();
        let staged = issue_internal_material(&host.context.inputs(), &test_messages())
            .await
            .expect("the offline signing succeeds");

        let account = staged.material.acme_account.expose();
        assert!(
            bootroot::acme::is_account_key(account),
            "the new account key is one the ACME client reads back"
        );
        let staged_path = staging_dir(&host.paths()).join(ACME_ACCOUNT_FILE);
        assert_eq!(
            std::fs::read_to_string(&staged_path).expect("the staged account key"),
            account
        );
        assert_eq!(
            std::fs::metadata(&staged_path)
                .expect("the staged account key")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    /// A replacement keeps the ACME account: the published key is
    /// carried into the staged set byte for byte, whitespace and all.
    #[tokio::test]
    async fn a_published_account_key_is_carried_over_unchanged() {
        let host = Host::new();
        let paths = host.paths();
        std::fs::create_dir_all(paths.dir()).expect("the internal directory");
        let existing = format!(
            "{}\n\n",
            bootroot::acme::create_account_key().expect("an account key")
        );
        std::fs::write(paths.acme_account(), &existing).expect("the published account key");

        let staged = issue_internal_material(&host.context.inputs(), &test_messages())
            .await
            .expect("the offline signing succeeds");
        assert_eq!(staged.material.acme_account.expose(), existing);
        assert_eq!(
            std::fs::read_to_string(staging_dir(&paths).join(ACME_ACCOUNT_FILE))
                .expect("the staged account key"),
            existing
        );
        assert_eq!(
            std::fs::read_to_string(paths.acme_account()).expect("the published account key"),
            existing,
            "staging does not touch the published key"
        );
    }

    /// A published account key the ACME client could not read back is
    /// not carried: the daemon would be refused at its first order.
    #[tokio::test]
    async fn an_unreadable_published_account_key_is_replaced() {
        let host = Host::new();
        let paths = host.paths();
        std::fs::create_dir_all(paths.dir()).expect("the internal directory");
        std::fs::write(paths.acme_account(), "not an account key").expect("a broken key");

        let staged = issue_internal_material(&host.context.inputs(), &test_messages())
            .await
            .expect("the offline signing succeeds");
        assert!(bootroot::acme::is_account_key(
            staged.material.acme_account.expose()
        ));
    }

    /// The warning for a replaced account key names the file it replaces
    /// in both locales, and only the file: it is handed the path alone,
    /// so neither the broken contents nor the new key can reach it.
    #[test]
    fn the_account_key_replacement_warning_names_the_path_in_each_locale() {
        let dir = TempDir::new().expect("a temporary directory");
        let published = dir.path().join(ACME_ACCOUNT_FILE);
        let path = published.display().to_string();
        let broken = "not an account key";
        std::fs::write(&published, broken).expect("a broken key");
        let fresh = bootroot::acme::create_account_key().expect("an account key");

        for (lang, expected) in [
            (
                "en",
                format!(
                    "Warning: the ACME account key at {path} is not one bootroot can read \
                     back; replacing it with a new one"
                ),
            ),
            (
                "ko",
                format!(
                    "경고: {path}의 ACME 계정 키는 bootroot가 다시 읽을 수 있는 키가 \
                     아니므로 새 키로 교체합니다"
                ),
            ),
        ] {
            let warning = crate::i18n::Messages::new(lang)
                .expect("a supported locale")
                .warning_registrar_internal_acme_file_replaced(&path);
            assert_eq!(warning, expected, "{lang}");
            assert!(
                !warning.contains(broken),
                "{lang} leaks the account contents"
            );
            assert!(
                !warning.contains("PRIVATE KEY"),
                "{lang} leaks key material"
            );
            assert!(!warning.contains(fresh.trim()), "{lang} leaks the new key");
        }
    }

    /// What an interrupted run left in staging is removed before the
    /// directory is handed to the helper's user, so that user never
    /// owns anything there but the helper's own two outputs.
    #[tokio::test]
    async fn a_stale_staging_directory_is_cleared_before_signing() {
        let host = Host::new();
        let staging = staging_dir(&host.paths());
        std::fs::create_dir_all(&staging).expect("stale staging");
        std::fs::write(staging.join("stale"), "STALE KEY").expect("a stale file");

        issue_internal_material(&host.context.inputs(), &test_messages())
            .await
            .expect("the offline signing succeeds");
        assert!(!staging.join("stale").exists());
    }

    /// A symlink at the staging directory would relocate both the root
    /// chown and the key write to its target, so it is refused before
    /// any container runs and before anything is removed.
    #[tokio::test]
    async fn a_symlinked_staging_directory_is_refused() {
        let host = Host::new();
        let paths = host.paths();
        let elsewhere = host.dir.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("the link target");
        std::fs::write(elsewhere.join("kept"), "KEPT").expect("a file behind the link");
        std::fs::create_dir_all(paths.dir()).expect("the internal directory");
        let staging = staging_dir(&paths);
        std::os::unix::fs::symlink(&elsewhere, &staging).expect("the symlink");

        let messages = test_messages();
        let err = issue_internal_material(&host.context.inputs(), &messages)
            .await
            .err()
            .expect("a symlinked staging directory is refused");
        assert!(
            format!("{err:#}").contains(
                &messages.error_registrar_internal_staging_symlink(&staging.display().to_string())
            ),
            "{err:#}"
        );
        assert!(host.invocations().is_empty(), "nothing may be mounted");
        assert!(elsewhere.join("kept").exists());
    }

    /// A helper that fails is reported as a failed signing, under the
    /// localized provisioning error, and nothing is published.
    #[tokio::test]
    async fn a_failed_signing_is_reported_and_publishes_nothing() {
        let mut host = Host::new();
        let failing = host.dir.path().join("failing-docker");
        crate::test_support::write_executable(&failing, b"#!/bin/sh\nexit 1\n");
        host.context.docker = failing;

        let messages = test_messages();
        let err = issue_internal_material(&host.context.inputs(), &messages)
            .await
            .err()
            .expect("a failing helper fails the signing");
        assert!(
            format!("{err:#}").contains(messages.error_registrar_internal_provision_failed()),
            "{err:#}"
        );
        for path in host.paths().all() {
            assert!(!path.exists());
        }
    }

    /// A host with no CA certificates fails before any container runs.
    #[tokio::test]
    async fn missing_ca_material_fails_before_any_container_runs() {
        let host = Host::new();
        std::fs::remove_dir_all(host.secrets_dir.join("certs")).expect("remove the CA");
        issue_internal_material(&host.context.inputs(), &test_messages())
            .await
            .err()
            .expect("there is nothing to sign against");
        assert!(
            host.invocations().is_empty(),
            "no container may run without CA material"
        );
    }
}

/// The two host-side endpoints the internal config names. The endpoint
/// daemon orders its certificates through both, so neither may be
/// assumed to be on the compose default, nor on loopback when a bind
/// intent moved it off.
#[cfg(test)]
mod internal_endpoint_tests {
    use super::super::http01_admin_tls::build_http01_admin_tls_sans;
    use super::super::stepca_setup::build_stepca_ca_dns_names;
    use super::{internal_acme_server_with_env, internal_responder_url_with_env};

    /// Every bind form `infra install` records: a specific IPv4 and IPv6
    /// address and each wildcard spelling, all on a port that differs
    /// from the host-port values the tests pass alongside.
    const BINDS: [&str; 5] = [
        "192.168.1.10:9443",
        "[fd12::1]:9443",
        "0.0.0.0:9443",
        "[::]:9443",
        "[::0]:9443",
    ];

    /// The host a URL names, with an IPv6 literal's brackets removed so
    /// it compares against a SAN list, which stores it bare.
    fn url_host(url: &str) -> &str {
        let authority = url
            .split_once("://")
            .map_or(url, |(_, rest)| rest)
            .split('/')
            .next()
            .unwrap_or_default();
        let (host, _port) = authority.rsplit_once(':').expect("URL names a port");
        host.strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(host)
    }

    /// An install that recorded moved ports in its `.env` is reached on
    /// the ports it actually published. A hard-coded `:9000`/`:8080`
    /// would fail the run here, and on a host co-located with a second
    /// instance it would reach that instance's step-ca and responder
    /// instead.
    #[test]
    fn both_endpoints_follow_the_recorded_published_ports() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(".env"),
            "STEPCA_HOST_PORT=19000\nHTTP01_ADMIN_HOST_PORT=18080\n",
        )
        .expect("write .env");
        assert_eq!(
            internal_acme_server_with_env("acme", None, dir.path(), None),
            "https://localhost:19000/acme/acme/directory"
        );
        assert_eq!(
            internal_responder_url_with_env(None, dir.path(), None),
            "http://127.0.0.1:18080"
        );
    }

    /// The process environment outranks the recorded `.env`, matching
    /// every other host-port derivation in the binary.
    #[test]
    fn the_environment_outranks_the_recorded_env_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(".env"),
            "STEPCA_HOST_PORT=19000\nHTTP01_ADMIN_HOST_PORT=18080\n",
        )
        .expect("write .env");
        assert_eq!(
            internal_acme_server_with_env("acme", None, dir.path(), Some("29000")),
            "https://localhost:29000/acme/acme/directory"
        );
        assert_eq!(
            internal_responder_url_with_env(None, dir.path(), Some("28080")),
            "http://127.0.0.1:28080"
        );
    }

    /// With nothing recorded, both fall back to the ports the compose
    /// files interpolate.
    #[test]
    fn both_endpoints_fall_back_to_the_compose_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            internal_acme_server_with_env("acme", None, dir.path(), None),
            "https://localhost:9000/acme/acme/directory"
        );
        assert_eq!(
            internal_responder_url_with_env(None, dir.path(), None),
            "http://127.0.0.1:8080"
        );
    }

    /// The provisioner name is still followed: an install that renamed
    /// the ACME provisioner would otherwise enrol against a directory
    /// step-ca does not serve.
    #[test]
    fn the_acme_directory_follows_the_configured_provisioner() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            internal_acme_server_with_env("bootroot-acme", None, dir.path(), None),
            "https://localhost:9000/acme/bootroot-acme/directory"
        );
    }

    /// A recorded `--stepca-bind` replaces step-ca's loopback
    /// publication, so the ACME directory is reached on the bind — a
    /// specific address as it is, a wildcard as loopback — and on the
    /// bind's own port rather than `STEPCA_HOST_PORT`, which describes a
    /// loopback publish that no longer exists.
    #[test]
    fn a_recorded_stepca_bind_is_where_the_acme_directory_is_reached() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".env"), "STEPCA_HOST_PORT=19000\n").expect("write .env");
        let expected = [
            "https://192.168.1.10:9443/acme/bootroot-acme/directory",
            "https://[fd12::1]:9443/acme/bootroot-acme/directory",
            "https://127.0.0.1:9443/acme/bootroot-acme/directory",
            "https://[::1]:9443/acme/bootroot-acme/directory",
            "https://[::1]:9443/acme/bootroot-acme/directory",
        ];
        for (bind, expected) in BINDS.into_iter().zip(expected) {
            assert_eq!(
                internal_acme_server_with_env(
                    "bootroot-acme",
                    Some(bind),
                    dir.path(),
                    Some("29000")
                ),
                expected,
                "bind {bind}"
            );
        }
    }

    /// A recorded `--http01-admin-bind` replaces the responder's
    /// loopback publication and puts its admin API behind TLS, so the
    /// responder is reached over `https://` on the bind, with the same
    /// wildcard mapping and the bind's own port.
    #[test]
    fn a_recorded_http01_admin_bind_is_where_the_responder_is_reached() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".env"), "HTTP01_ADMIN_HOST_PORT=18080\n")
            .expect("write .env");
        let expected = [
            "https://192.168.1.10:9443",
            "https://[fd12::1]:9443",
            "https://127.0.0.1:9443",
            "https://[::1]:9443",
            "https://[::1]:9443",
        ];
        for (bind, expected) in BINDS.into_iter().zip(expected) {
            assert_eq!(
                internal_responder_url_with_env(Some(bind), dir.path(), Some("28080")),
                expected,
                "bind {bind}"
            );
        }
    }

    /// The host each URL names is one the certificate behind it was
    /// issued for, so the internal profile's TLS verification accepts
    /// it. Built from the same bind strings on both sides: a change to
    /// the URL mapping or to either SAN builder that pulls them apart
    /// fails here rather than as a hostname mismatch at issuance.
    #[test]
    fn every_bind_derived_host_is_in_the_certificate_that_bind_serves() {
        let dir = tempfile::tempdir().expect("tempdir");
        for bind in BINDS {
            let acme = internal_acme_server_with_env("acme", Some(bind), dir.path(), None);
            let stepca_names = build_stepca_ca_dns_names(Some(bind), None, "bootroot-ca");
            assert!(
                stepca_names.iter().any(|name| name == url_host(&acme)),
                "bind {bind}: {acme} names a host outside step-ca's {stepca_names:?}"
            );

            let responder = internal_responder_url_with_env(Some(bind), dir.path(), None);
            let admin_sans = build_http01_admin_tls_sans(bind, None, "bootroot-http01");
            assert!(
                admin_sans.iter().any(|name| name == url_host(&responder)),
                "bind {bind}: {responder} names a host outside the admin certificate's \
                 {admin_sans:?}"
            );
        }
    }
}
