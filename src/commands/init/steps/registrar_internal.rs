//! Provisioning the bootroot-internal privileged credential, inside
//! `init`'s existing rollback transaction.
//!
//! The order below is a correctness requirement, not a preference:
//!
//! 1. **Prerequisites.** `OpenBao` is bootstrapped, step-ca is
//!    initialized and the agent EAB (if the deployment has one) has been
//!    acquired. Nothing here runs before them, because the leaf is
//!    issued through the ordinary outbound ACME path to step-ca and the
//!    `auth/cert` entry trusts the deployment root those steps created.
//! 2. **Authority.** Under the init root token: enable `auth/cert` if it
//!    is absent, write the exact-allowlist policy, and create the one
//!    trusted entry.
//! 3. **Material.** Under the same root token: create or load the
//!    persistent ACME account key and issue the internal leaf — into a
//!    staging directory, so nothing is published yet.
//! 4. **Listener.** The existing `OpenBao` TLS transition runs, and the
//!    HTTPS URL is recorded.
//! 5. **Proof.** A real `auth/cert/login` over that HTTPS URL, with the
//!    staged material, must succeed.
//! 6. **Publication.** Only then are the four credential files, the
//!    dedicated config and the private CA bundle moved into place.
//!
//! Every step registers its undo with [`InitRollback`] *before* it acts,
//! so a failure at any point restores the prior listener, the prior
//! state URL, the `OpenBao` artifacts this run created, and leaves no
//! file behind. A host whose endpoint predicate is false performs none
//! of it.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;
use bootroot::registrar::internal::{
    AcmeAccountKey, CERT_AUTH_MOUNT, CERT_AUTH_ROLE, InternalAgentConfigParams, InternalCredential,
    InternalMaterial, InternalPaths, MaterialStatus, PrivateKeyPem, SetSnapshot,
    build_registrar_internal_policy, capture_set, internal_registration_id, material_status,
    publish_material, render_internal_agent_config,
};
use bootroot::registrar::registrar_internal_identity;
use bootroot::{cert_group, config, fs_util};

use super::InitRollback;
use super::ca_certs::{compute_ca_bundle_pem, compute_ca_fingerprints};
use crate::commands::init::constants::openbao_constants::{
    POLICY_BOOTROOT_REGISTRAR_INTERNAL, TOKEN_TTL,
};
use crate::commands::init::{CA_CERTS_DIR, CA_INTERMEDIATE_CERT_FILENAME, CA_ROOT_CERT_FILENAME};
use crate::i18n::Messages;
use crate::state::StateFile;

/// The staging directory the leaf is issued into before it is proven and
/// published.
///
/// A sibling of the published names rather than a temporary elsewhere:
/// the publish is a rename, and a rename is only atomic within one
/// filesystem.
const STAGING_DIR: &str = ".staging";

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
/// **This issue consumes the predicate; it does not define, store or
/// switch it.** An absent or disabled entry means the endpoint is off,
/// and `init` then alters no listener and creates no internal artifact.
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
    /// The KV v2 mount the exact-allowlist policy is scoped to.
    pub(crate) kv_mount: String,
    /// The step-ca ACME directory URL.
    pub(crate) acme_server: String,
    /// The deployment contact email.
    pub(crate) email: String,
    /// The HTTP-01 responder admin URL.
    pub(crate) responder_url: String,
    /// The HTTP-01 responder shared HMAC.
    pub(crate) responder_hmac: String,
    /// The EAB credentials, when the deployment registered any.
    pub(crate) eab: Option<crate::commands::init::types::EabCredentials>,
}

impl RegistrarInternalContext {
    /// Borrows the context as the inputs both stages take.
    pub(crate) fn inputs(&self) -> RegistrarInternalInputs<'_> {
        RegistrarInternalInputs {
            intent: &self.intent,
            secrets_dir: &self.secrets_dir,
            kv_mount: &self.kv_mount,
            acme_server: &self.acme_server,
            email: &self.email,
            responder_url: &self.responder_url,
            responder_hmac: &self.responder_hmac,
            eab: self.eab.as_ref(),
        }
    }
}

/// The staging directory the internal leaf is issued into.
///
/// A sibling of the published names rather than a temporary elsewhere:
/// the publish is a rename, and a rename is only atomic within one
/// filesystem.
pub(crate) fn staging_dir(paths: &InternalPaths) -> PathBuf {
    paths.dir().join(STAGING_DIR)
}

/// Everything provisioning needs, all of it already resolved by `init`.
pub(crate) struct RegistrarInternalInputs<'a> {
    /// The identity's two parts.
    pub(crate) intent: &'a RegistrarInternalIntent,
    /// The state-recorded secrets directory.
    pub(crate) secrets_dir: &'a Path,
    /// The KV v2 mount the exact-allowlist policy is scoped to.
    pub(crate) kv_mount: &'a str,
    /// The step-ca ACME directory URL.
    pub(crate) acme_server: &'a str,
    /// The deployment contact email.
    pub(crate) email: &'a str,
    /// The HTTP-01 responder admin URL.
    pub(crate) responder_url: &'a str,
    /// The HTTP-01 responder shared HMAC.
    pub(crate) responder_hmac: &'a str,
    /// The EAB credentials, when the deployment registered any.
    pub(crate) eab: Option<&'a crate::commands::init::types::EabCredentials>,
}

/// Material issued into the staging directory, plus the trust state it
/// was issued against.
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
pub(super) fn register_internal_rollback(rollback: &mut InitRollback, secrets_dir: &Path) {
    let paths = InternalPaths::new(secrets_dir);
    if matches!(material_status(&paths), MaterialStatus::Absent) {
        rollback.registrar_internal_dir = Some(paths.dir().to_path_buf());
    }
    rollback.registrar_internal_staging = Some(staging_dir(&paths));
}

/// Creates the `auth/cert` mount, the exact-allowlist policy and the one
/// trusted entry, under the init root token.
///
/// Every artifact is registered for rollback before it is created, so a
/// later failure removes exactly what this run added and leaves an
/// `auth/cert` mount the deployment already had alone.
///
/// # Errors
///
/// Returns an error if any `OpenBao` write fails or the deployment root
/// certificate cannot be read.
pub(super) async fn provision_internal_auth(
    client: &OpenBaoClient,
    inputs: &RegistrarInternalInputs<'_>,
    rollback: &mut InitRollback,
    messages: &Messages,
) -> Result<()> {
    // Registered before the write, not after: a failure between the two
    // must still be undone. Each artifact is registered only when this
    // run is what creates it — a re-run of `init` over an
    // already-provisioned host must not have its rollback delete the
    // working entry and policy it found, which is the one way this
    // teardown could take a healthy deployment down.
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
    if existing_entry.is_none() {
        rollback.registrar_internal_cert_auth_entry = Some(CERT_AUTH_ROLE.to_string());
    }
    if !client
        .policy_exists(POLICY_BOOTROOT_REGISTRAR_INTERNAL)
        .await
        .context("reading the bootroot-registrar-internal policy")?
    {
        rollback
            .created_policies
            .push(POLICY_BOOTROOT_REGISTRAR_INTERNAL.to_string());
    }
    // The mount registers itself the moment it exists, from inside
    // `converge_internal_auth`: the policy and the entry are written
    // after it, and a failure at either would otherwise leave a backend
    // this run enabled with nothing recorded to disable it.
    converge_internal_auth(
        client,
        inputs,
        messages,
        &mut rollback.registrar_internal_cert_auth_mount_created,
    )
    .await
}

/// Converges the `auth/cert` mount, the exact-allowlist policy and the
/// one trusted entry.
///
/// Shared by `init`'s provisioning and by the rotation and recovery
/// repairs, so the entry the three write cannot drift: one root, one
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
/// Returns an error if any `OpenBao` write fails or the deployment root
/// certificate cannot be read.
pub(crate) async fn converge_internal_auth(
    client: &OpenBaoClient,
    inputs: &RegistrarInternalInputs<'_>,
    messages: &Messages,
    mounted_now: &mut bool,
) -> Result<()> {
    let root_pem = read_root_ca_pem(inputs.secrets_dir, messages).await?;
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
            &root_pem,
            &inputs.intent.san(),
            &[POLICY_BOOTROOT_REGISTRAR_INTERNAL],
            TOKEN_TTL,
        )
        .await
        .context("creating the bootroot-registrar-internal cert auth entry")?;
    Ok(())
}

/// Issues the internal leaf and its persistent ACME account key into the
/// staging directory.
///
/// Nothing is published: the staged files sit under
/// [`STAGING_DIR`], registered for rollback, until a real certificate
/// login over the TLS listener has proved they work.
///
/// # Errors
///
/// Returns an error if the CA material cannot be read, the staging
/// directory cannot be created, or ACME issuance fails.
pub(crate) async fn issue_internal_material(
    inputs: &RegistrarInternalInputs<'_>,
    messages: &Messages,
) -> Result<StagedInternal> {
    let paths = InternalPaths::new(inputs.secrets_dir);
    let staging = staging_dir(&paths);

    fs_util::ensure_secrets_dir(&staging)
        .await
        .with_context(|| messages.error_write_file_failed(&staging.display().to_string()))?;

    let fingerprints = compute_ca_fingerprints(inputs.secrets_dir, messages).await?;
    let bundle_pem = compute_ca_bundle_pem(inputs.secrets_dir, messages).await?;
    let staged_bundle = staging.join("ca-bundle.pem");
    fs_util::write_ca_bundle(
        &staged_bundle,
        &bundle_pem,
        cert_group::CertGroupPolicy::none(),
    )
    .await
    .with_context(|| messages.error_write_file_failed(&staged_bundle.display().to_string()))?;

    let staged_cert = staging.join("leaf.pem");
    let staged_key = staging.join("key.pem");
    let staged_account = staging.join("acme-account.json");

    let settings = issuance_settings(
        inputs,
        &staged_bundle,
        &staged_account,
        &fingerprints,
        &staged_cert,
        &staged_key,
    );
    let profile = settings
        .profiles
        .first()
        .ok_or_else(|| anyhow::anyhow!("the internal issuance profile was not built"))?;
    let eab = inputs.eab.map(|creds| bootroot::eab::EabCredentials {
        kid: creds.kid.clone(),
        hmac: creds.hmac.clone(),
    });
    bootroot::acme::issue_certificate(&settings, profile, eab, false)
        .await
        .context("issuing the bootroot-internal leaf through step-ca's ACME endpoint")?;

    let leaf_pem = tokio::fs::read_to_string(&staged_cert)
        .await
        .with_context(|| messages.error_read_file_failed(&staged_cert.display().to_string()))?;
    let intermediate_pem = read_ca_file(
        &inputs
            .secrets_dir
            .join(CA_CERTS_DIR)
            .join(CA_INTERMEDIATE_CERT_FILENAME),
        messages,
    )
    .await?;
    let key_pem = tokio::fs::read_to_string(&staged_key)
        .await
        .with_context(|| messages.error_read_file_failed(&staged_key.display().to_string()))?;
    let account = tokio::fs::read_to_string(&staged_account)
        .await
        .with_context(|| messages.error_read_file_failed(&staged_account.display().to_string()))?;
    let root_fingerprint = fingerprints
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("the deployment root fingerprint was not computed"))?;

    Ok(StagedInternal {
        paths,
        staging,
        material: InternalMaterial {
            key: PrivateKeyPem::new(key_pem),
            chain: format!("{leaf_pem}{intermediate_pem}"),
            acme_account: AcmeAccountKey::new(account),
            root_fingerprint,
        },
        bundle_pem,
        fingerprints,
    })
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
    let credential =
        InternalCredential::from_parts(openbao_url, &staged.material, &staged.bundle_pem)?;
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
async fn discard_snapshot(snapshot: SetSnapshot) {
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

    let config = render_internal_agent_config(
        &staged.paths,
        &InternalAgentConfigParams {
            email: inputs.email,
            server: inputs.acme_server,
            domain: &inputs.intent.domain,
            hostname: &inputs.intent.host,
            responder_url: inputs.responder_url,
            responder_hmac: inputs.responder_hmac,
            eab_kid: inputs.eab.map(|creds| creds.kid.as_str()),
            eab_hmac: inputs.eab.map(|creds| creds.hmac.as_str()),
            trusted_ca_sha256: &staged.fingerprints,
        },
    );
    fs_util::atomic_write(
        fs_util::Destination::bootroot_owned(&staged.paths.agent_config()),
        config.as_bytes(),
        fs_util::StagedMode::Policy(fs_util::KEY_FILE_MODE),
    )
    .await
    .with_context(|| {
        messages.error_write_file_failed(&staged.paths.agent_config().display().to_string())
    })?;
    Ok(())
}

/// Builds the in-memory `Settings` the staged ACME issuance runs under.
///
/// Deliberately not the generated `agent.toml`: that file points at the
/// *published* paths, which do not exist yet. The two agree on
/// everything the CA sees — the SAN, the account key, the EAB and the
/// trust anchors — and differ only in where the bytes land.
fn issuance_settings(
    inputs: &RegistrarInternalInputs<'_>,
    bundle: &Path,
    account_key: &Path,
    fingerprints: &[String],
    cert: &Path,
    key: &Path,
) -> config::Settings {
    config::Settings {
        email: inputs.email.to_string(),
        server: inputs.acme_server.to_string(),
        domain: inputs.intent.domain.clone(),
        eab: inputs.eab.map(|creds| config::Eab {
            kid: creds.kid.clone(),
            hmac: creds.hmac.clone(),
        }),
        acme: config::AcmeSettings {
            http_responder_url: inputs.responder_url.to_string(),
            http_responder_hmac: inputs.responder_hmac.to_string(),
            http_responder_timeout_secs: 5,
            http_responder_token_ttl_secs: 300,
            directory_fetch_attempts: 10,
            directory_fetch_base_delay_secs: 1,
            directory_fetch_max_delay_secs: 10,
            poll_attempts: 15,
            poll_interval_secs: 2,
            account_key_path: Some(account_key.to_path_buf()),
        },
        retry: config::RetrySettings {
            backoff_secs: vec![5, 15, 60],
        },
        trust: config::TrustSettings {
            ca_bundle_path: Some(bundle.to_path_buf()),
            trusted_ca_sha256: fingerprints.to_vec(),
        },
        scheduler: config::SchedulerSettings {
            max_concurrent_issuances: 1,
        },
        profiles: vec![config::DaemonProfileSettings {
            registration_id: internal_registration_id(&inputs.intent.host),
            service_name: bootroot::registrar::REGISTRAR_INTERNAL_LABEL.to_string(),
            instance_id: bootroot::registrar::internal::agent_config::INTERNAL_INSTANCE_ID
                .to_string(),
            hostname: inputs.intent.host.clone(),
            paths: config::Paths {
                cert: cert.to_path_buf(),
                key: key.to_path_buf(),
            },
            daemon: config::DaemonRuntimeSettings::default(),
            retry: None,
            hooks: config::HookSettings::default(),
            eab: None,
            cert_group_gid: None,
        }],
        openbao: None,
        registrar_endpoint: config::RegistrarEndpointSettings::default(),
    }
}

async fn read_root_ca_pem(secrets_dir: &Path, messages: &Messages) -> Result<String> {
    read_ca_file(
        &secrets_dir.join(CA_CERTS_DIR).join(CA_ROOT_CERT_FILENAME),
        messages,
    )
    .await
}

async fn read_ca_file(path: &Path, messages: &Messages) -> Result<String> {
    tokio::fs::read_to_string(path)
        .await
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))
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
    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{RegistrarInternalContext, RegistrarInternalIntent, provision_internal_auth};
    use crate::commands::init::steps::InitRollback;
    use crate::commands::init::{CA_CERTS_DIR, CA_ROOT_CERT_FILENAME};
    use crate::i18n::test_messages;

    const ENTRY_PATH: &str = "/v1/auth/cert/certs/bootroot-registrar-internal";
    const POLICY_PATH: &str = "/v1/sys/policies/acl/bootroot-registrar-internal";

    /// A secrets directory carrying the deployment root the entry
    /// trusts, which `converge_internal_auth` reads before it mounts
    /// anything.
    fn secrets_dir() -> TempDir {
        let dir = TempDir::new().expect("tempdir");
        let certs = dir.path().join(CA_CERTS_DIR);
        std::fs::create_dir_all(&certs).expect("certs dir");
        std::fs::write(
            certs.join(CA_ROOT_CERT_FILENAME),
            "-----BEGIN CERTIFICATE-----\nUk9PVA\n-----END CERTIFICATE-----\n",
        )
        .expect("root CA");
        dir
    }

    fn context(dir: &std::path::Path) -> RegistrarInternalContext {
        RegistrarInternalContext {
            intent: RegistrarInternalIntent {
                domain: "example.internal".to_string(),
                host: "bootroot-01".to_string(),
            },
            secrets_dir: dir.to_path_buf(),
            kv_mount: "secret".to_string(),
            acme_server: "https://localhost:9000/acme/acme/directory".to_string(),
            email: "ops@example.internal".to_string(),
            responder_url: "http://127.0.0.1:8080".to_string(),
            responder_hmac: "hmac".to_string(),
            eab: None,
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
            &mut rollback,
            &test_messages(),
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
                "data": { "name": "bootroot-registrar-internal" }
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
            &mut rollback,
            &test_messages(),
        )
        .await
        .expect_err("a lookup failure must fail the run");
        assert!(
            format!("{err:#}").contains("cert auth entry"),
            "the refusal must name what could not be read: {err:#}"
        );
        assert_eq!(rollback.registrar_internal_cert_auth_entry, None);
        assert!(rollback.created_policies.is_empty());
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
            &mut rollback,
            &test_messages(),
        )
        .await
        .expect_err("a lookup failure must fail the run");
        assert!(
            format!("{err:#}").contains("policy"),
            "the refusal must name what could not be read: {err:#}"
        );
        assert!(rollback.created_policies.is_empty());
        assert!(!rollback.registrar_internal_cert_auth_mount_created);
    }

    /// A re-run over a host that already carries the entry, the policy
    /// and the mount registers none of the three: rollback restores the
    /// prior state, and the prior state is a working credential.
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
                "data": { "name": "bootroot-registrar-internal" }
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
            &mut rollback,
            &test_messages(),
        )
        .await
        .expect("converging what is already there must succeed");

        assert_eq!(rollback.registrar_internal_cert_auth_entry, None);
        assert!(rollback.created_policies.is_empty());
        assert!(!rollback.registrar_internal_cert_auth_mount_created);
    }
}

#[cfg(test)]
mod publication_tests {
    use bootroot::registrar::internal::material::PRIOR_DIR;
    use bootroot::registrar::internal::{
        AcmeAccountKey, InternalMaterial, InternalPaths, PrivateKeyPem, load_material,
        publish_material,
    };
    use tempfile::TempDir;

    use super::{
        RegistrarInternalContext, RegistrarInternalIntent, StagedInternal, publish_internal_set,
        staging_dir,
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
            kv_mount: "secret".to_string(),
            acme_server: "https://localhost:9000/acme/acme/directory".to_string(),
            email: "ops@example.internal".to_string(),
            responder_url: "http://127.0.0.1:8080".to_string(),
            responder_hmac: "hmac".to_string(),
            eab: None,
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
    async fn provisioned_host(paths: &InternalPaths) {
        publish_material(
            paths,
            &InternalMaterial {
                key: PrivateKeyPem::new(
                    "-----BEGIN PRIVATE KEY-----\nUFJJT1I\n-----END PRIVATE KEY-----\n".to_string(),
                ),
                chain: bundle("UFJJT1JMRUFG"),
                acme_account: AcmeAccountKey::new(
                    "{\"account_key_pkcs8\":\"UFJJT1I\"}".to_string(),
                ),
                root_fingerprint: OLD_ROOT.to_string(),
            },
        )
        .await
        .expect("the prior material");
        std::fs::write(paths.ca_bundle(), bundle("UFJJT1JCVU5ETEU")).expect("the prior bundle");
        std::fs::write(paths.agent_config(), "email = \"prior@example.internal\"\n")
            .expect("the prior config");
    }

    /// `init` publishes the active generation: the bundle and the pins
    /// are what the issuance staged.
    #[tokio::test]
    async fn publication_writes_the_staged_trust_set() {
        let dir = TempDir::new().expect("tempdir");
        let context = context(dir.path());
        let staged = staged(dir.path());
        publish_internal_set(&staged, &context.inputs(), &test_messages())
            .await
            .expect("publish");

        let paths = InternalPaths::new(dir.path());
        assert_eq!(
            std::fs::read_to_string(paths.ca_bundle()).expect("bundle"),
            bundle("QUNUSVZF")
        );
        let settings = bootroot::config::Settings::from_file(Some(paths.agent_config()))
            .expect("the generated config must parse");
        assert_eq!(
            settings.trust.trusted_ca_sha256,
            [ACTIVE_ROOT.to_string(), ACTIVE_INT.to_string()]
        );
        let material = load_material(&paths).expect("the published set must load");
        assert_eq!(material.root_fingerprint, ACTIVE_ROOT);
        assert!(
            !paths.dir().join(PRIOR_DIR).exists(),
            "a completed publication discards its snapshot"
        );
    }

    /// The six files publish one at a time, so a failure part-way
    /// through an already-provisioned host would otherwise leave a new
    /// key beside the previous chain — a set that still reads as
    /// complete and can no longer log in — and `init`'s rollback would
    /// not repair it, because a re-run deliberately does not register
    /// the credential it found for teardown.
    ///
    /// One case per published member, each failing at that member: a
    /// directory at a credential name is something no rename can
    /// replace. What survives is what the run started with.
    #[tokio::test]
    async fn a_failed_publication_restores_the_set_it_found() {
        for member in [
            "ca-bundle.pem",
            "key.pem",
            "chain.pem",
            "acme-account.json",
            "root-fingerprint",
            "agent.toml",
        ] {
            let dir = TempDir::new().expect("tempdir");
            let paths = InternalPaths::new(dir.path());
            provisioned_host(&paths).await;
            let failing = paths.dir().join(member);
            let untouched: Vec<(std::path::PathBuf, String)> = paths
                .all()
                .into_iter()
                .filter(|path| path != &failing)
                .map(|path| {
                    let contents = std::fs::read_to_string(&path).expect("prior member");
                    (path, contents)
                })
                .collect();
            std::fs::remove_file(&failing).expect("remove the member");
            std::fs::create_dir_all(failing.join("nested")).expect("a directory at the member");

            let context = context(dir.path());
            let staged = staged(dir.path());
            let err = publish_internal_set(&staged, &context.inputs(), &test_messages())
                .await
                .expect_err("a member that cannot be written must fail the publication");
            assert!(
                err.to_string().contains(member) || format!("{err:#}").contains(member),
                "the failure must name the member it could not publish: {err:#}"
            );

            for (path, contents) in untouched {
                assert_eq!(
                    std::fs::read_to_string(&path).expect("member after the failure"),
                    contents,
                    "publishing over {member} must leave {} on its prior bytes",
                    path.display()
                );
            }
            assert!(
                failing.join("nested").is_dir(),
                "the restore must not delete what it could not capture"
            );
            assert!(
                !paths.dir().join(PRIOR_DIR).exists(),
                "a completed restore discards its snapshot"
            );
        }
    }

    /// A repair overrides the trust set before publishing, so the
    /// Phase-4 tail replaces the credential while leaving the additive
    /// set in place. Narrowing here would take this identity off a
    /// generation the rest of the fleet still trusts.
    #[tokio::test]
    async fn a_repair_publishes_the_trust_set_it_was_given() {
        let dir = TempDir::new().expect("tempdir");
        let context = context(dir.path());
        let additive = vec![
            OLD_ROOT.to_string(),
            OLD_INT.to_string(),
            ACTIVE_ROOT.to_string(),
            ACTIVE_INT.to_string(),
        ];
        let staged = staged(dir.path()).with_trust(additive.clone(), bundle("QURESVRJVkU"));
        publish_internal_set(&staged, &context.inputs(), &test_messages())
            .await
            .expect("publish");

        let paths = InternalPaths::new(dir.path());
        assert_eq!(
            std::fs::read_to_string(paths.ca_bundle()).expect("bundle"),
            bundle("QURESVRJVkU")
        );
        let settings = bootroot::config::Settings::from_file(Some(paths.agent_config()))
            .expect("the generated config must parse");
        assert_eq!(settings.trust.trusted_ca_sha256, additive);
        // The credential itself is still replaced: the stored root
        // fingerprint is the freshly issued one, not a trust-set member
        // chosen for the bundle.
        assert_eq!(
            load_material(&paths)
                .expect("the published set must load")
                .root_fingerprint,
            ACTIVE_ROOT
        );
    }
}
