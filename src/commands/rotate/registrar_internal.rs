//! The bootroot-internal credential's rotation and recovery paths.
//!
//! Three call sites drive this module, and each one does exactly one
//! thing:
//!
//! - **Full-rotation Phase 3** publishes the additive trust set —
//!   old root, old intermediate, new root, new intermediate — into the
//!   dedicated private bundle and the internal config's pins, and
//!   `SIGHUP`s the internal agent. It changes no entry, no leaf and no
//!   stored fingerprint.
//! - **The mandatory tail after full-rotation Phase 4**, which runs
//!   after step-ca restarts and before Phase 4 is recorded. It replaces
//!   the `auth/cert` entry, the leaf material and the stored root
//!   fingerprint under explicit root-token authority, while *keeping*
//!   the Phase-3 additive trust set. `--skip reissue` cannot skip it,
//!   and a failure retains the pre-Phase-4 state so a resume repeats
//!   restart and repair.
//! - **Full-rotation Phase 6** narrows the bundle and the pins to the
//!   finalized new-root/new-intermediate pair — only after the existing
//!   finalization checks pass, and before Phase 6 is recorded. Skipped
//!   finalization keeps the additive set.
//!
//! An intermediate-only rotation reaches none of them: the internal
//! entry trusts the *root*, which an intermediate-only rotation does not
//! replace, so the entry, the material, the config and the bundle are
//! all still correct and are left untouched.
//!
//! `bootroot rotate registrar-internal-credential` reuses the tail as
//! its whole body. It repairs expired, interrupted or unusable material
//! and stale config trust, never re-runs install, and never touches a
//! service credential.

use std::path::Path;

use anyhow::{Context, Result};
use bootroot::eab::EabCredentials;
use bootroot::openbao::OpenBaoClient;
use bootroot::registrar::internal::{
    AGENT_CONFIG_FILE, CA_BUNDLE_FILE, CERT_AUTH_MOUNT, CERT_AUTH_ROLE, InternalPaths,
    MaterialStatus, capture_members, load_material, material_status, require_https,
    require_root_authority, upsert_internal_trust,
};
use bootroot::{cert_group, fs_util};

use super::RotateContext;
use super::helpers::signal_internal_registrar_agent;
use crate::commands::init::registrar_internal::{
    RegistrarInternalContext, RegistrarInternalInputs, RegistrarInternalIntent, StagedInternal,
    converge_internal_auth, discard_snapshot, issue_internal_material, publish_internal_set,
    staging_dir, verify_internal_login,
};
use crate::commands::init::{
    DEFAULT_STEPCA_PROVISIONER, PATH_AGENT_EAB, PATH_RESPONDER_HMAC,
    POLICY_BOOTROOT_REGISTRAR_INTERNAL, compute_ca_bundle_pem, read_ca_cert_fingerprint,
};
use crate::commands::trust::RotationMode;
use crate::i18n::Messages;

/// The trust set the internal bundle and the internal config's pins must
/// carry.
///
/// The same values the rotation publishes to `OpenBao` KV for ordinary
/// services — additive in Phases 3–4, narrowed in Phase 6 — so the
/// internal identity is never on a different generation from the fleet.
#[derive(Debug, Clone)]
pub(super) struct InternalTrustState {
    /// The fingerprints the config pins.
    pub(super) fingerprints: Vec<String>,
    /// The PEM bundle those fingerprints cover.
    pub(super) bundle_pem: String,
}

/// Reports whether this host carries a bootroot-internal credential.
///
/// A host without one — every host but a bootroot registrar host —
/// reaches none of the rotation work below. A *partial* set is reported
/// as present, so a rotation repairs it rather than silently skipping a
/// host whose credential is half there.
pub(super) fn internal_credential_present(secrets_dir: &Path) -> bool {
    !matches!(
        material_status(&InternalPaths::new(secrets_dir)),
        MaterialStatus::Absent
    )
}

/// Reports whether a rotation in `mode` has internal work to do on this
/// host.
///
/// The gate every internal rotation call site is written behind, so the
/// two halves of the condition are stated once. An intermediate-only
/// rotation is excluded whatever the host carries: the `auth/cert` entry
/// trusts the *root*, which that rotation does not replace, so the
/// entry, the leaf, the config and the bundle are all still correct and
/// rewriting them would be a change to artifacts the rotation is
/// specified to leave alone.
pub(super) fn internal_rotation_applies(mode: &RotationMode, secrets_dir: &Path) -> bool {
    *mode == RotationMode::Full && internal_credential_present(secrets_dir)
}

/// Publishes a trust set into the dedicated bundle and the internal
/// config's pins, then reloads the internal agent.
///
/// Both files are published by rename, so an agent reading either while
/// this runs sees the whole previous version or the whole new one.
///
/// # Errors
///
/// Returns an error when the config is missing or unparseable, when
/// either file cannot be published, or when the reload signal fails for
/// a reason other than "no such process".
pub(super) async fn publish_internal_trust(
    secrets_dir: &Path,
    trust: &InternalTrustState,
    messages: &Messages,
) -> Result<()> {
    write_internal_trust(secrets_dir, trust, messages).await?;
    signal_internal_registrar_agent(secrets_dir, messages)
}

/// Writes the trust set without signalling.
///
/// Split from [`publish_internal_trust`] so the two halves are separable:
/// the write is what a test can assert, and the signal is a `pkill` that
/// has nothing to match in one.
///
/// The bundle and the pins are **one** update. Each file publishes
/// atomically on its own, but a Phase-3 or Phase-6 run that replaced one
/// and failed on the other would leave the pair describing two different
/// generations — a bundle the pins do not cover — with the phase
/// unrecorded and nothing registered to undo it. So the pair is captured
/// first and put back on any failure, exactly as the credential set's
/// publication does, and the rewritten config is computed before either
/// file is touched so an unparseable one fails with the pair still
/// intact.
///
/// # Errors
///
/// Returns an error when the config is missing or unparseable, when the
/// pair cannot be captured, or when either file cannot be published. In
/// the last case the previous pair has been restored, or the failure to
/// restore it is reported beside the failure that caused it.
async fn write_internal_trust(
    secrets_dir: &Path,
    trust: &InternalTrustState,
    messages: &Messages,
) -> Result<()> {
    let paths = InternalPaths::new(secrets_dir);
    let config_path = paths.agent_config();
    let current = tokio::fs::read_to_string(&config_path)
        .await
        .with_context(|| messages.error_read_file_failed(&config_path.display().to_string()))?;
    let next = upsert_internal_trust(&current, &paths, &trust.fingerprints)?;

    let snapshot = capture_members(&paths, &[AGENT_CONFIG_FILE, CA_BUNDLE_FILE])
        .await
        .context("capturing the bootroot-internal trust pair the rotation replaces")?;
    if let Err(err) = write_trust_pair(&paths, &trust.bundle_pem, &next, messages).await {
        if let Err(restore_err) = snapshot.restore().await {
            eprintln!(
                "Warning: the bootroot-internal trust pair could not be fully restored after \
                 a failed rotation: {restore_err}; the previous files are kept at {}",
                snapshot.dir().display()
            );
            return Err(err);
        }
        discard_snapshot(snapshot).await;
        return Err(err);
    }
    discard_snapshot(snapshot).await;
    Ok(())
}

/// Publishes the config and then the bundle, with no undo of its own.
///
/// Split out so [`write_internal_trust`] can hold the prior pair around
/// both renames rather than around each one.
async fn write_trust_pair(
    paths: &InternalPaths,
    bundle_pem: &str,
    config: &str,
    messages: &Messages,
) -> Result<()> {
    let config_path = paths.agent_config();
    fs_util::atomic_write(
        fs_util::Destination::bootroot_owned(&config_path),
        config.as_bytes(),
        fs_util::StagedMode::Policy(fs_util::KEY_FILE_MODE),
    )
    .await
    .with_context(|| messages.error_write_file_failed(&config_path.display().to_string()))?;

    fs_util::write_ca_bundle(
        &paths.ca_bundle(),
        bundle_pem,
        cert_group::CertGroupPolicy::none(),
    )
    .await
    .with_context(|| messages.error_write_file_failed(&paths.ca_bundle().display().to_string()))
}

/// Confirms the internal bundle and config still carry `expected`.
///
/// The Phase-4 tail runs this before it replaces anything: a host whose
/// Phase-3 publication did not land must not have its credential
/// reissued against a trust set the daemon is not on.
///
/// # Errors
///
/// Returns an error when the config cannot be read, or when its pins
/// differ from `expected`.
pub(super) fn ensure_internal_trust_is(
    secrets_dir: &Path,
    expected: &[String],
    messages: &Messages,
) -> Result<()> {
    let paths = InternalPaths::new(secrets_dir);
    let config_path = paths.agent_config();
    let settings = bootroot::config::Settings::from_file(Some(config_path.clone()))
        .with_context(|| messages.error_read_file_failed(&config_path.display().to_string()))?;
    if settings.trust.trusted_ca_sha256 == expected {
        return Ok(());
    }
    anyhow::bail!(
        "the bootroot-internal config at {} does not carry the transitional trust set; \
         re-run the rotation from Phase 3",
        config_path.display()
    )
}

/// Replaces the `auth/cert` entry, the leaf material and the stored root
/// fingerprint, keeping whatever trust set `trust` names.
///
/// Runs under explicit root-token authority: the token is checked with
/// a self-lookup *before* anything is mutated, so an `AppRole` or any
/// other non-root token is refused with a typed error rather than
/// discovered half-way through by a 403.
///
/// # Errors
///
/// Returns an error when the token does not carry `root`, when the
/// recorded `OpenBao` URL is plaintext, when the endpoint predicate is
/// absent, when the ACME issuance fails, or when any file cannot be
/// published.
pub(super) async fn repair_internal_credential(
    ctx: &RotateContext,
    client: &OpenBaoClient,
    trust: &InternalTrustState,
    messages: &Messages,
) -> Result<()> {
    require_root_authority(client).await?;
    // A host that carries this credential runs `OpenBao` over TLS, because
    // the credential authenticates at `auth/cert` and nothing else can.
    // A recorded `http://` URL means the listener transition never
    // completed, and republishing material against it would leave a
    // credential that cannot log in — so refuse before anything is
    // written, with the same typed error the load path uses.
    require_https(&ctx.openbao_url)?;

    let context = repair_context(ctx, client).await?;
    replace_internal_credential(client, &context, &ctx.openbao_url, trust, messages).await
}

/// The body of a repair, past the two refusals.
///
/// Separated from [`repair_internal_credential`] so the ordering below
/// can be driven in a test without a TLS listener: everything up to the
/// convergence is reachable over a plain-HTTP mock, because none of it
/// authenticates with the credential.
///
/// # Errors
///
/// Returns an error when the ACME issuance fails, when the `auth/cert`
/// entry cannot be converged, when the replacement cannot log in, or
/// when any file cannot be published.
async fn replace_internal_credential(
    client: &OpenBaoClient,
    context: &RegistrarInternalContext,
    openbao_url: &str,
    trust: &InternalTrustState,
    messages: &Messages,
) -> Result<()> {
    let inputs = context.inputs();

    // The replacement is staged **before** anything in `OpenBao`
    // changes. The convergence below rewrites the entry to trust the
    // active root, and during a full rotation that is the *new* root:
    // an entry replaced ahead of a leaf that is then never issued
    // rejects the on-disk credential the internal daemon is still using,
    // turning a retryable ACME failure into a host that cannot
    // authenticate. Issuance needs no `auth/cert` entry — it runs over
    // ACME against step-ca — so it costs nothing to prove it first.
    //
    // The publication carries `trust`, not the active generation the
    // issuance staged: the Phase-4 tail replaces the credential while
    // the fleet is still on the additive set, and a repair mid-rotation
    // has to restore that same set.
    //
    // A repair runs outside `init`'s rollback envelope, so the staging
    // directory has no undo registered for it. It holds an unpublished
    // private key, so a failed repair sweeps it here rather than leaving
    // it beside the credential until the next successful run happens to
    // overwrite it.
    let staged = match issue_internal_material(&inputs, messages).await {
        Ok(staged) => staged.with_trust(trust.fingerprints.clone(), trust.bundle_pem.clone()),
        Err(err) => {
            sweep_staging(&context.secrets_dir).await;
            return Err(err);
        }
    };

    // Captured before the convergence and put back if anything after it
    // fails, so the auth artifacts and the material move together:
    // either the host ends on the new set, or it ends on the set it
    // started with. Both members are captured, because the convergence
    // rewrites both: `init` puts both back and a repair needs the same
    // symmetry, or a failed `--force` run would restore the entry and
    // leave a policy it replaced.
    let prior = match PriorInternalAuth::capture(client).await {
        Ok(prior) => prior,
        Err(err) => {
            sweep_staging(&context.secrets_dir).await;
            return Err(err);
        }
    };

    if let Err(err) = converge_and_publish(client, &staged, &inputs, openbao_url, messages).await {
        prior.restore(client).await;
        sweep_staging(&context.secrets_dir).await;
        return Err(err);
    }
    signal_internal_registrar_agent(&context.secrets_dir, messages)
}

/// Rewrites the `auth/cert` entry to the active root, proves the staged
/// leaf logs in against it, and publishes the set.
///
/// One unit, because its caller undoes it as one: the login is what
/// makes the new entry and the new leaf provably a pair, and the
/// publication is what makes that pair the host's.
///
/// # Errors
///
/// Returns an error when the convergence, the login or the publication
/// fails.
async fn converge_and_publish(
    client: &OpenBaoClient,
    staged: &StagedInternal,
    inputs: &RegistrarInternalInputs<'_>,
    openbao_url: &str,
    messages: &Messages,
) -> Result<()> {
    // A repair runs outside a rollback envelope, so the mount flag has
    // nothing to undo by: an `auth/cert` backend a repair enables is
    // left enabled, which is the state a working credential needs and
    // the state the next repair converges on regardless.
    let mut mounted_now = false;
    converge_internal_auth(client, inputs, messages, &mut mounted_now).await?;
    verify_internal_login(staged, openbao_url).await?;
    publish_internal_set(staged, inputs, messages).await
}

/// The `auth/cert` artifacts a repair is about to rewrite, exactly as
/// it found them.
///
/// `converge_internal_auth` rewrites the policy *and* the entry
/// unconditionally, so a repair that captures only one of them puts only
/// one of them back. On a host whose policy this repair did not create —
/// one written by an older release, or widened by hand — a failed
/// `bootroot rotate registrar-internal-credential --force` would then
/// restore the entry and leave that policy permanently replaced. Both
/// members are captured together and restored together for that reason.
///
/// A repair runs outside `init`'s rollback envelope, so this is the
/// whole undo: there is no `InitRollback` behind it to catch what is
/// missed here.
struct PriorInternalAuth {
    /// The trusted entry's body, or `None` when the host had none.
    entry: Option<serde_json::Value>,
    /// The exact-allowlist policy's body, or `None` when the host had
    /// none.
    policy: Option<String>,
}

impl PriorInternalAuth {
    /// Reads both artifacts before anything is written.
    ///
    /// A lookup that does not answer is not read as "absent" — that
    /// would register a deletion for an artifact the host depends on —
    /// so it fails the repair here, with nothing yet changed in
    /// `OpenBao`.
    ///
    /// # Errors
    ///
    /// Returns an error when either lookup fails for a reason other than
    /// a clean not-found.
    async fn capture(client: &OpenBaoClient) -> Result<Self> {
        let entry = client
            .read_cert_auth_entry(CERT_AUTH_MOUNT, CERT_AUTH_ROLE)
            .await
            .context("reading the bootroot-registrar-internal cert auth entry")?;
        let policy = client
            .read_policy(POLICY_BOOTROOT_REGISTRAR_INTERNAL)
            .await
            .context("reading the bootroot-registrar-internal policy")?;
        Ok(Self { entry, policy })
    }

    /// Puts both artifacts back the way a failed repair found them.
    ///
    /// In the reverse of the order the convergence writes them — entry
    /// first, then the policy it names — so the window in which the
    /// entry points at a policy body this run wrote is closed before the
    /// policy itself moves.
    async fn restore(&self, client: &OpenBaoClient) {
        restore_cert_auth_entry(client, self.entry.as_ref()).await;
        restore_internal_policy(client, self.policy.as_deref()).await;
    }
}

/// Puts the `auth/cert` entry back the way a failed repair found it.
///
/// Best effort and never fatal: the repair has already failed, and an
/// error raised here would displace the one that matters. What it must
/// not do is stay silent — an entry left trusting a root no on-disk leaf
/// chains to is exactly the state that stops the internal daemon
/// authenticating, so a restore that does not land is reported with the
/// command that repairs it.
async fn restore_cert_auth_entry(client: &OpenBaoClient, prior: Option<&serde_json::Value>) {
    let outcome = match prior {
        Some(entry) => {
            client
                .write_cert_auth_entry_raw(CERT_AUTH_MOUNT, CERT_AUTH_ROLE, entry)
                .await
        }
        // Nothing was there, so nothing is left behind: a repair on a
        // host whose entry had been removed puts it back to removed.
        None => client
            .delete_cert_auth_entry(CERT_AUTH_MOUNT, CERT_AUTH_ROLE)
            .await
            .or_else(|err| {
                // A delete of an entry the convergence never got as far
                // as creating is not a failure to report.
                if err.to_string().contains("404") {
                    Ok(())
                } else {
                    Err(err)
                }
            }),
    };
    if let Err(err) = outcome {
        eprintln!(
            "Warning: the bootroot-registrar-internal cert auth entry could not be restored \
             after a failed repair: {err}; re-run \
             `bootroot rotate registrar-internal-credential --force`"
        );
    }
}

/// Puts the exact-allowlist policy back the way a failed repair found
/// it.
///
/// Best effort and never fatal, for the same reason as the entry above:
/// the repair has already failed, and an error raised here would
/// displace the one that matters. Silence is what it must not be — a
/// policy left on this run's body is an authority change nothing
/// recorded, so a restore that does not land is reported with the
/// command that repairs it.
async fn restore_internal_policy(client: &OpenBaoClient, prior: Option<&str>) {
    let outcome = match prior {
        Some(body) => {
            client
                .write_policy(POLICY_BOOTROOT_REGISTRAR_INTERNAL, body)
                .await
        }
        // Nothing was there, so nothing is left behind: a repair on a
        // host whose policy had been removed puts it back to removed.
        None => client
            .delete_policy(POLICY_BOOTROOT_REGISTRAR_INTERNAL)
            .await
            .or_else(|err| {
                // A delete of a policy the convergence never got as far
                // as writing is not a failure to report.
                if err.to_string().contains("404") {
                    Ok(())
                } else {
                    Err(err)
                }
            }),
    };
    if let Err(err) = outcome {
        eprintln!(
            "Warning: the bootroot-registrar-internal policy could not be restored after a \
             failed repair: {err}; re-run \
             `bootroot rotate registrar-internal-credential --force`"
        );
    }
}

/// Removes the staging directory a failed repair left behind.
///
/// Best effort and never fatal: the repair has already failed, and the
/// error a sweep would add would displace the one that matters. A
/// directory that survives is reported so the unpublished key it holds
/// is not silent.
async fn sweep_staging(secrets_dir: &Path) {
    let staging = staging_dir(&InternalPaths::new(secrets_dir));
    if !staging.exists() {
        return;
    }
    if let Err(err) = tokio::fs::remove_dir_all(&staging).await {
        eprintln!(
            "Warning: failed to remove the staging directory {}: {err}",
            staging.display()
        );
    }
}

/// Builds the repair's context from the recorded state, the existing
/// generated config and — for the EAB the internal ACME account needs —
/// the root-token client.
///
/// The existing config is the record of the values `init` chose (the
/// ACME directory, the contact email, the responder URL), so a repair
/// keeps them. A host whose config was lost falls back to the same
/// defaults `init` used, and reads the responder HMAC and the EAB out of
/// `OpenBao` rather than inventing them.
async fn repair_context(
    ctx: &RotateContext,
    client: &OpenBaoClient,
) -> Result<RegistrarInternalContext> {
    let recorded = ctx
        .state
        .registrar_endpoint
        .as_ref()
        .filter(|recorded| recorded.enabled)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "state.json records no enabled registrar endpoint, so this host has no \
                 bootroot-internal credential to repair"
            )
        })?;
    let intent = RegistrarInternalIntent {
        domain: recorded.domain.clone(),
        host: recorded.host.clone(),
    };
    let secrets_dir = ctx.paths.secrets_dir().to_path_buf();
    let paths = InternalPaths::new(&secrets_dir);
    let existing = bootroot::config::Settings::from_file(Some(paths.agent_config())).ok();
    // Only reached when the generated config is gone: the config is the
    // record of what `init` chose, and a repair keeps it. The fallbacks
    // below rebuild those endpoints the same way `init` derived them —
    // from this install's own published ports — rather than from the
    // compose defaults, which on a host that moved its ports name
    // nothing, and on a co-located host name another instance.
    let compose_dir = crate::commands::compose_file::compose_file_dir(&ctx.compose_file);

    let responder_hmac = read_kv_string(client, &ctx.kv_mount, PATH_RESPONDER_HMAC, "value")
        .await?
        .or_else(|| {
            existing
                .as_ref()
                .map(|settings| settings.acme.http_responder_hmac.clone())
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the HTTP-01 responder HMAC is neither in OpenBao nor in the \
                 bootroot-internal config; repair it with `bootroot rotate responder-hmac` first"
            )
        })?;

    let eab = read_eab(client, &ctx.kv_mount).await?;

    Ok(RegistrarInternalContext {
        intent,
        secrets_dir,
        kv_mount: ctx.kv_mount.clone(),
        acme_server: existing.as_ref().map_or_else(
            || {
                let port = bootroot::host_port::resolve_stepca_host_port(&compose_dir);
                format!("https://localhost:{port}/acme/{DEFAULT_STEPCA_PROVISIONER}/directory")
            },
            |settings| settings.server.clone(),
        ),
        email: existing.as_ref().map_or_else(
            || crate::commands::service::DEFAULT_AGENT_EMAIL.to_string(),
            |settings| settings.email.clone(),
        ),
        responder_url: existing.as_ref().map_or_else(
            || {
                let port = bootroot::host_port::resolve_http01_admin_host_port(&compose_dir);
                format!("http://127.0.0.1:{port}")
            },
            |settings| settings.acme.http_responder_url.clone(),
        ),
        responder_hmac,
        eab,
    })
}

/// Reads one string field out of a KV record, treating an absent record
/// as `None`.
async fn read_kv_string(
    client: &OpenBaoClient,
    kv_mount: &str,
    path: &str,
    field: &str,
) -> Result<Option<String>> {
    let Some(value) = client
        .try_read_kv(kv_mount, path)
        .await
        .with_context(|| format!("reading {kv_mount}/{path}"))?
    else {
        return Ok(None);
    };
    Ok(value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string))
}

/// Reads the deployment's agent EAB, treating an absent or cleared
/// record as "no EAB".
async fn read_eab(client: &OpenBaoClient, kv_mount: &str) -> Result<Option<EabCredentials>> {
    let Some(value) = client
        .try_read_kv(kv_mount, PATH_AGENT_EAB)
        .await
        .with_context(|| format!("reading {kv_mount}/{PATH_AGENT_EAB}"))?
    else {
        return Ok(None);
    };
    let kid = value.get("kid").and_then(serde_json::Value::as_str);
    let hmac = value.get("hmac").and_then(serde_json::Value::as_str);
    match (kid, hmac) {
        (Some(kid), Some(hmac)) if !kid.is_empty() && !hmac.is_empty() => {
            Ok(Some(EabCredentials {
                kid: kid.to_string(),
                hmac: hmac.to_string(),
            }))
        }
        _ => Ok(None),
    }
}

/// The finalized trust set: the active root and intermediate on disk.
///
/// # Errors
///
/// Returns an error when either CA certificate cannot be read.
pub(super) async fn finalized_trust(
    secrets_dir: &Path,
    root_fp: &str,
    intermediate_fp: &str,
    messages: &Messages,
) -> Result<InternalTrustState> {
    Ok(InternalTrustState {
        fingerprints: vec![root_fp.to_string(), intermediate_fp.to_string()],
        bundle_pem: compute_ca_bundle_pem(secrets_dir, messages).await?,
    })
}

/// Reads the fingerprint of the root currently on disk.
///
/// # Errors
///
/// Returns an error when the root certificate cannot be read or parsed.
pub(super) async fn active_root_fingerprint(
    secrets_dir: &Path,
    messages: &Messages,
) -> Result<String> {
    read_ca_cert_fingerprint(
        &secrets_dir
            .join(crate::commands::init::CA_CERTS_DIR)
            .join(crate::commands::init::CA_ROOT_CERT_FILENAME),
        messages,
    )
    .await
}

/// Reports whether the stored root fingerprint still matches the active
/// root, without touching `OpenBao`.
///
/// # Errors
///
/// Returns an error when the material cannot be loaded or the active
/// root cannot be read.
pub(super) async fn stored_root_matches_active(
    secrets_dir: &Path,
    messages: &Messages,
) -> Result<bool> {
    let material = load_material(&InternalPaths::new(secrets_dir))?;
    let active = active_root_fingerprint(secrets_dir, messages).await?;
    Ok(material.root_fingerprint.eq_ignore_ascii_case(&active))
}

/// The phase at which a full rotation has narrowed trust back to the
/// finalized generation.
///
/// Below it the rotation is still on the additive set, so a recovery run
/// mid-rotation must restore that set rather than the finalized one — a
/// credential narrowed early would stop trusting the generation the rest
/// of the fleet is still on.
const FINALIZED_PHASE: u8 = 6;

/// Resolves the trust state a repair must restore from the recorded
/// rotation state.
///
/// An unfinished full rotation is on the additive
/// old-root/old-intermediate/new-root/new-intermediate set; everything
/// else — no rotation in progress, an intermediate-only rotation, a
/// finished one — is on the finalized active generation.
///
/// # Errors
///
/// Returns an error when the rotation state or the CA material cannot be
/// read.
pub(super) async fn trust_state_for_repair(
    ctx: &RotateContext,
    messages: &Messages,
) -> Result<InternalTrustState> {
    let recorded = crate::commands::trust::load_rotation_state(&ctx.state_dir, messages)?;
    if let Some(state) = recorded
        && state.mode == crate::commands::trust::RotationMode::Full
        && state.phase < FINALIZED_PHASE
    {
        return Ok(InternalTrustState {
            fingerprints: vec![
                state.old_root_fp.clone(),
                state.old_intermediate_fp.clone(),
                state.new_root_fp.clone(),
                state.new_intermediate_fp.clone(),
            ],
            bundle_pem: super::ca::concat_unique_ca_certs_for_repair(ctx, messages).await?,
        });
    }
    let root_fp = active_root_fingerprint(ctx.paths.secrets_dir(), messages).await?;
    let intermediate_fp =
        read_ca_cert_fingerprint(&ctx.paths.intermediate_cert(), messages).await?;
    finalized_trust(
        ctx.paths.secrets_dir(),
        &root_fp,
        &intermediate_fp,
        messages,
    )
    .await
}

/// Repairs the bootroot-internal credential on operator demand.
///
/// The command form of the Phase-4 tail: the same root-authority check,
/// the same entry/leaf/fingerprint replacement, and the same trust
/// publication — but with the trust state derived from whatever the
/// recorded rotation state says is current rather than from a rotation
/// this process is running.
///
/// # Errors
///
/// Returns an error when the token is not root-authorized, when this
/// host records no enabled registrar endpoint, or when any step of the
/// repair fails.
pub(super) async fn rotate_registrar_internal_credential(
    ctx: &RotateContext,
    client: &OpenBaoClient,
    args: &crate::cli::args::RotateRegistrarInternalArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    // The authority check runs first, before the credential is even
    // read: an AppRole token must be refused without having learned
    // anything about the host's internal state.
    require_root_authority(client).await?;

    let secrets_dir = ctx.paths.secrets_dir().to_path_buf();
    if !args.force
        && matches!(
            material_status(&InternalPaths::new(&secrets_dir)),
            MaterialStatus::Present
        )
        && stored_root_matches_active(&secrets_dir, messages)
            .await
            .unwrap_or(false)
    {
        println!("{}", messages.rotate_registrar_internal_up_to_date());
        return Ok(());
    }

    super::helpers::confirm_action(
        messages.prompt_rotate_registrar_internal(),
        auto_confirm,
        messages,
    )?;

    let trust = trust_state_for_repair(ctx, messages).await?;
    repair_internal_credential(ctx, client, &trust, messages).await?;
    println!("{}", messages.rotate_registrar_internal_complete());
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use bootroot::registrar::internal::{
        AcmeAccountKey, InternalAgentConfigParams, InternalMaterial, PrivateKeyPem,
        publish_material, render_internal_agent_config,
    };
    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::{
        CERT_AUTH_MOUNT, CERT_AUTH_ROLE, InternalPaths, InternalTrustState,
        POLICY_BOOTROOT_REGISTRAR_INTERNAL, PriorInternalAuth, RegistrarInternalContext,
        RotationMode, converge_internal_auth, ensure_internal_trust_is,
        internal_credential_present, internal_rotation_applies, repair_internal_credential,
        replace_internal_credential, restore_cert_auth_entry, staging_dir, sweep_staging,
        write_internal_trust,
    };
    use crate::i18n::test_messages;

    const ROOT_FP: &str = "aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900";
    const OLD_ROOT_FP: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const OLD_INT_FP: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const NEW_INT_FP: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    fn bundle_pem(label: &str) -> String {
        format!("-----BEGIN CERTIFICATE-----\n{label}\n-----END CERTIFICATE-----\n")
    }

    async fn provisioned_host() -> (TempDir, InternalPaths) {
        let dir = TempDir::new().expect("tempdir");
        let paths = InternalPaths::new(dir.path());
        publish_material(
            &paths,
            &InternalMaterial {
                key: PrivateKeyPem::new(
                    "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n".to_string(),
                ),
                chain: bundle_pem("TEVBRg"),
                acme_account: AcmeAccountKey::new("{\"account_key_pkcs8\":\"QUJD\"}".to_string()),
                root_fingerprint: ROOT_FP.to_string(),
            },
        )
        .await
        .expect("publish");
        std::fs::write(paths.ca_bundle(), bundle_pem("Uk9PVA")).expect("bundle");
        std::fs::write(
            paths.agent_config(),
            render_internal_agent_config(
                &paths,
                &InternalAgentConfigParams {
                    email: "ops@example.internal",
                    server: "https://localhost:9000/acme/acme/directory",
                    domain: "example.internal",
                    hostname: "bootroot-01",
                    responder_url: "http://127.0.0.1:8080",
                    responder_hmac: "hmac",
                    eab_kid: None,
                    eab_hmac: None,
                    trusted_ca_sha256: &[ROOT_FP.to_string()],
                },
            ),
        )
        .expect("config");
        (dir, paths)
    }

    /// The repair inputs every test below drives, pointed at a
    /// provisioned host's secrets directory.
    ///
    /// The ACME and responder endpoints are unreachable on purpose: no
    /// test here gets as far as issuing, and one that did would be
    /// reaching the network rather than asserting anything.
    fn repair_inputs(secrets_dir: &std::path::Path) -> RegistrarInternalContext {
        RegistrarInternalContext {
            intent: super::RegistrarInternalIntent {
                domain: "example.internal".to_string(),
                host: "bootroot-01".to_string(),
            },
            secrets_dir: secrets_dir.to_path_buf(),
            kv_mount: "secret".to_string(),
            acme_server: "https://127.0.0.1:1/acme/acme/directory".to_string(),
            email: "ops@example.internal".to_string(),
            responder_url: "http://127.0.0.1:1".to_string(),
            responder_hmac: "hmac".to_string(),
            eab: None,
        }
    }

    /// A policy body deliberately unlike the one this crate writes, so
    /// a restore that reproduces it cannot be a convergence that
    /// happened to land on the same text.
    const PRIOR_POLICY: &str = "path \"secret/data/legacy\" {\n  capabilities = [\"read\"]\n}\n";

    /// The `auth/cert` entry a host is carrying before a repair runs.
    fn prior_entry() -> serde_json::Value {
        serde_json::json!({
            "certificate": "-----BEGIN CERTIFICATE-----\nT0xE\n-----END CERTIFICATE-----\n",
            "allowed_dns_sans": ["001.bootroot-registrar-internal.bootroot-01.example.internal"],
            "token_policies": ["bootroot-registrar-internal"],
            "token_no_default_policy": true,
            "token_ttl": 3600,
        })
    }

    /// Every body written to the policy and the entry, in order.
    struct ConvergeWrites {
        policies: Arc<Mutex<Vec<String>>>,
        entries: Arc<Mutex<Vec<serde_json::Value>>>,
    }

    /// An `OpenBao` already carrying the cert backend, a distinct policy
    /// and a distinct entry, recording every write over them.
    async fn converge_mock_server() -> (MockServer, ConvergeWrites) {
        let policy_path = format!("/v1/sys/policies/acl/{POLICY_BOOTROOT_REGISTRAR_INTERNAL}");
        let entry_path = format!("/v1/auth/{CERT_AUTH_MOUNT}/certs/{CERT_AUTH_ROLE}");
        let server = MockServer::start().await;
        // The backend is already enabled, so the convergence goes
        // straight to the two writes this fixture is about.
        Mock::given(method("GET"))
            .and(path("/v1/sys/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "cert/": { "type": "cert" } }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(policy_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "policy": PRIOR_POLICY }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(entry_path.clone()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "data": prior_entry() })),
            )
            .mount(&server)
            .await;

        let policies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let policy_sink = Arc::clone(&policies);
        Mock::given(method("POST"))
            .and(path(policy_path))
            .respond_with(move |request: &Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).expect("json");
                policy_sink.lock().expect("capture").push(
                    body.get("policy")
                        .and_then(serde_json::Value::as_str)
                        .expect("a policy body")
                        .to_string(),
                );
                ResponseTemplate::new(204)
            })
            .mount(&server)
            .await;
        let entries: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let entry_sink = Arc::clone(&entries);
        Mock::given(method("POST"))
            .and(path(entry_path))
            .respond_with(move |request: &Request| {
                entry_sink
                    .lock()
                    .expect("capture")
                    .push(serde_json::from_slice(&request.body).expect("json"));
                ResponseTemplate::new(204)
            })
            .mount(&server)
            .await;
        (server, ConvergeWrites { policies, entries })
    }

    /// Every host but a bootroot registrar host has no internal
    /// credential, and every rotation phase below is gated on this.
    #[tokio::test]
    async fn presence_gates_every_rotation_phase() {
        let empty = TempDir::new().expect("tempdir");
        assert!(!internal_credential_present(empty.path()));

        let (dir, paths) = provisioned_host().await;
        assert!(internal_credential_present(dir.path()));

        // A partial set counts as present, so a rotation repairs it
        // rather than silently skipping the host.
        std::fs::remove_file(paths.key()).expect("remove");
        assert!(internal_credential_present(dir.path()));
    }

    /// An intermediate-only rotation leaves every internal artifact
    /// alone, on a provisioned host as much as on a bare one.
    ///
    /// The `auth/cert` entry trusts the *root*, and an intermediate-only
    /// rotation does not replace it — so the entry, the leaf, the stored
    /// fingerprint, the config's pins and the private bundle are all
    /// still correct. Phase 3, the Phase-4 tail and Phase 6 are each
    /// written behind this predicate, so a host that carries a working
    /// credential must still select no internal work in that mode.
    #[tokio::test]
    async fn an_intermediate_only_rotation_selects_no_internal_work() {
        let (dir, _paths) = provisioned_host().await;
        assert!(
            internal_credential_present(dir.path()),
            "the fixture must be a provisioned host, or this proves nothing"
        );

        assert!(
            !internal_rotation_applies(&RotationMode::IntermediateOnly, dir.path()),
            "an intermediate-only rotation must not touch internal artifacts"
        );
        assert!(
            internal_rotation_applies(&RotationMode::Full, dir.path()),
            "a full rotation on a provisioned host must select the internal work"
        );

        // The other half of the gate: a full rotation on an ordinary
        // host still selects nothing.
        let bare = TempDir::new().expect("tempdir");
        assert!(!internal_rotation_applies(&RotationMode::Full, bare.path()));
        assert!(!internal_rotation_applies(
            &RotationMode::IntermediateOnly,
            bare.path()
        ));
    }

    /// Phase 3 publishes the additive set into the private bundle and
    /// the config's pins, and leaves the identity and the paths alone.
    #[tokio::test]
    async fn publishing_trust_rewrites_the_private_bundle_and_the_pins() {
        let (dir, paths) = provisioned_host().await;
        let additive = InternalTrustState {
            fingerprints: vec![
                OLD_ROOT_FP.to_string(),
                OLD_INT_FP.to_string(),
                ROOT_FP.to_string(),
                NEW_INT_FP.to_string(),
            ],
            bundle_pem: bundle_pem("QURESVRJVkU"),
        };
        write_internal_trust(dir.path(), &additive, &test_messages())
            .await
            .expect("publish the additive trust set");

        assert_eq!(
            std::fs::read_to_string(paths.ca_bundle()).expect("bundle"),
            additive.bundle_pem
        );
        let settings = bootroot::config::Settings::from_file(Some(paths.agent_config()))
            .expect("the rewritten config must still parse");
        assert_eq!(settings.trust.trusted_ca_sha256, additive.fingerprints);
        assert_eq!(
            settings.trust.ca_bundle_path.as_deref(),
            Some(paths.ca_bundle().as_path())
        );
        // Untouched by a trust publication.
        let profile = settings.profiles.first().expect("one profile");
        assert_eq!(profile.service_name, "bootroot-registrar-internal");
        assert_eq!(profile.paths.cert, paths.chain());
        assert_eq!(
            settings.acme.account_key_path.as_deref(),
            Some(paths.acme_account().as_path())
        );
        // The stored root fingerprint is *not* a Phase-3 concern.
        assert_eq!(
            std::fs::read_to_string(paths.root_fingerprint())
                .expect("fingerprint")
                .trim(),
            ROOT_FP
        );
    }

    /// A repair never runs against a plaintext `OpenBao` URL. A host
    /// that carries this credential runs `OpenBao` over TLS, so an
    /// `http://` URL means the listener transition never completed;
    /// republishing material against it would leave a credential that
    /// cannot log in. The refusal is typed, names TLS, and lands before
    /// a single file is rewritten.
    #[tokio::test]
    async fn a_repair_over_plaintext_is_refused_before_anything_is_written() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/auth/token/lookup-self"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "policies": ["root"] }
            })))
            .mount(&server)
            .await;
        let mut client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());

        let (dir, paths) = provisioned_host().await;
        let before = std::fs::read_to_string(paths.agent_config()).expect("config");
        let ctx = super::RotateContext {
            openbao_url: "http://127.0.0.1:8200".to_string(),
            kv_mount: "secret".to_string(),
            compose_file: dir.path().join("docker-compose.yml"),
            state: crate::state::StateFile::default(),
            paths: crate::commands::rotate::StatePaths::new(dir.path().to_path_buf()),
            state_dir: dir.path().to_path_buf(),
            state_file: dir.path().join("state.json"),
            docker: std::path::PathBuf::from(crate::commands::compose_project::DOCKER_BIN),
        };
        let err = repair_internal_credential(
            &ctx,
            &client,
            &InternalTrustState {
                fingerprints: vec![ROOT_FP.to_string()],
                bundle_pem: bundle_pem("Uk9PVA"),
            },
            &test_messages(),
        )
        .await
        .expect_err("a plaintext OpenBao URL must be refused");
        assert!(
            err.to_string().contains("certificate login requires TLS"),
            "{err}"
        );
        assert_eq!(
            std::fs::read_to_string(paths.agent_config()).expect("config"),
            before,
            "nothing may be rewritten before the refusal"
        );
    }

    /// A repair runs outside `init`'s rollback envelope, so a failure
    /// after the leaf was staged has nothing registered to undo it. The
    /// staging directory holds an unpublished private key, so the repair
    /// sweeps it itself rather than leaving it beside the credential.
    #[tokio::test]
    async fn a_failed_repair_sweeps_its_staging_directory() {
        let (dir, paths) = provisioned_host().await;
        let staging = staging_dir(&paths);
        std::fs::create_dir_all(&staging).expect("staging");
        std::fs::write(staging.join("key.pem"), "STAGED KEY").expect("staged key");

        sweep_staging(dir.path()).await;
        assert!(!staging.exists(), "the staged key must not survive");
        // The published credential is untouched by the sweep.
        assert!(paths.key().exists());
        assert!(paths.agent_config().exists());

        // A host that never reached the staging stage is a no-op.
        sweep_staging(dir.path()).await;
        assert!(!staging.exists());
    }

    /// A trust publication that cannot complete leaves the pair as it
    /// found it.
    ///
    /// Phase 3 and Phase 6 move the private bundle and the config's pins
    /// together. Each file publishes atomically on its own, so the state
    /// worth guarding against is the one *between* them: a bundle on the
    /// new generation with pins that still name the old one, with the
    /// phase unrecorded and nothing registered to undo it. Here the
    /// bundle is a directory, so its publication fails after the config's
    /// succeeded — and the config comes back.
    #[tokio::test]
    async fn a_half_written_trust_pair_is_restored() {
        let (dir, paths) = provisioned_host().await;
        let before = std::fs::read_to_string(paths.agent_config()).expect("config");

        // A bundle name that cannot be published over: the rename at the
        // end of the publication has a directory in its way.
        std::fs::remove_file(paths.ca_bundle()).expect("remove the bundle");
        std::fs::create_dir(paths.ca_bundle()).expect("a directory at the bundle name");

        let additive = InternalTrustState {
            fingerprints: vec![
                OLD_ROOT_FP.to_string(),
                OLD_INT_FP.to_string(),
                ROOT_FP.to_string(),
                NEW_INT_FP.to_string(),
            ],
            bundle_pem: bundle_pem("QURESVRJVkU"),
        };
        write_internal_trust(dir.path(), &additive, &test_messages())
            .await
            .expect_err("the bundle cannot be published over a directory");

        assert_eq!(
            std::fs::read_to_string(paths.agent_config()).expect("config"),
            before,
            "the pins must not be left on a generation the bundle is not on"
        );
        let settings = bootroot::config::Settings::from_file(Some(paths.agent_config()))
            .expect("the restored config must parse");
        assert_eq!(settings.trust.trusted_ca_sha256, vec![ROOT_FP.to_string()]);
        assert!(
            !paths.dir().join(".prior").exists(),
            "the snapshot is discarded once the pair is settled"
        );
    }

    /// A config that cannot be rewritten fails before the bundle is
    /// touched at all.
    ///
    /// The cheapest half of the same guarantee: the rewritten config is
    /// computed first, so an unparseable one costs nothing and leaves
    /// both members exactly as they were.
    #[tokio::test]
    async fn an_unparseable_config_fails_before_the_bundle_moves() {
        let (dir, paths) = provisioned_host().await;
        std::fs::write(paths.agent_config(), "trust = [[[\n").expect("write");
        let bundle_before = std::fs::read_to_string(paths.ca_bundle()).expect("bundle");

        write_internal_trust(
            dir.path(),
            &InternalTrustState {
                fingerprints: vec![OLD_ROOT_FP.to_string()],
                bundle_pem: bundle_pem("QURESVRJVkU"),
            },
            &test_messages(),
        )
        .await
        .expect_err("an unparseable config must fail the publication");

        assert_eq!(
            std::fs::read_to_string(paths.ca_bundle()).expect("bundle"),
            bundle_before,
            "the bundle must not move ahead of the pins"
        );
    }

    /// A repair proves its replacement before it touches the entry the
    /// running credential authenticates against.
    ///
    /// The convergence rewrites the `auth/cert` entry to trust the
    /// *active* root, which during a full rotation is the new one. Doing
    /// that ahead of a leaf that is then never issued would leave the
    /// on-disk credential chained to a root the entry no longer trusts —
    /// a retryable ACME failure turned into a host that cannot log in.
    /// So an issuance failure must reach no `auth/` write at all.
    #[tokio::test]
    async fn an_issuance_failure_reaches_no_cert_auth_write() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let mut client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());

        // No CA material below the secrets directory, so the issuance
        // fails at its first step — before ACME, and long before any
        // `OpenBao` write.
        let (dir, paths) = provisioned_host().await;
        let context = repair_inputs(dir.path());

        replace_internal_credential(
            &client,
            &context,
            &server.uri(),
            &InternalTrustState {
                fingerprints: vec![ROOT_FP.to_string()],
                bundle_pem: bundle_pem("Uk9PVA"),
            },
            &test_messages(),
        )
        .await
        .expect_err("issuance must fail without CA material");

        let seen = server
            .received_requests()
            .await
            .expect("the mock records every request");
        assert!(
            seen.iter()
                .all(|request| !request.url.path().contains("/auth/")),
            "no auth surface may be touched before the replacement exists: {:?}",
            seen.iter()
                .map(|request| request.url.path().to_string())
                .collect::<Vec<_>>()
        );
        assert!(
            !staging_dir(&paths).exists(),
            "the unpublished key must not survive a failed repair"
        );
    }

    /// A repair that fails after the entry changed puts the entry back.
    ///
    /// The entry and the material move as one: either the host ends on
    /// the new pair, or on the pair it started with. An entry left
    /// trusting a root no on-disk leaf chains to is the one state that
    /// stops the internal daemon authenticating, so the captured body
    /// goes back verbatim — and a host whose entry did not exist before
    /// gets it removed again.
    #[tokio::test]
    async fn a_failed_repair_puts_the_previous_cert_auth_entry_back() {
        use std::sync::{Arc, Mutex};

        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, ResponseTemplate};

        let entry_path = format!(
            "/v1/auth/{}/certs/{}",
            bootroot::registrar::internal::CERT_AUTH_MOUNT,
            bootroot::registrar::internal::CERT_AUTH_ROLE
        );

        let server = MockServer::start().await;
        let captured: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
        let sink = Arc::clone(&captured);
        Mock::given(method("POST"))
            .and(path(entry_path.clone()))
            .respond_with(move |request: &Request| {
                *sink.lock().expect("capture") =
                    Some(serde_json::from_slice(&request.body).expect("json"));
                ResponseTemplate::new(204)
            })
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(entry_path))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let mut client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());

        let prior = serde_json::json!({
            "certificate": "-----BEGIN CERTIFICATE-----\nT0xE\n-----END CERTIFICATE-----\n",
            "allowed_dns_sans": ["001.bootroot-registrar-internal.bootroot-01.example.internal"],
            "token_policies": ["bootroot-registrar-internal"],
            "token_no_default_policy": true,
            "token_ttl": 3600,
        });
        restore_cert_auth_entry(&client, Some(&prior)).await;
        assert_eq!(
            captured.lock().expect("capture").clone().expect("a body"),
            prior,
            "the captured entry goes back exactly as it was read"
        );

        // A host that had no entry before ends with none.
        restore_cert_auth_entry(&client, None).await;
        let deletes = server
            .received_requests()
            .await
            .expect("recorded")
            .into_iter()
            .filter(|request| request.method == wiremock::http::Method::DELETE)
            .count();
        assert_eq!(deletes, 1, "an absent entry is restored by removing it");
    }

    /// A repair that fails after the convergence puts the *policy* back
    /// too, not just the entry.
    ///
    /// `converge_internal_auth` rewrites the exact-allowlist policy and
    /// the trusted entry in one breath, so an undo covering only the
    /// entry leaves an authority change nothing recorded: a host whose
    /// policy this run did not create — an older release's body, or one
    /// widened by hand — would come out of a failed `--force` repair
    /// permanently on this run's body. `init` puts both back; this
    /// proves the repair, which runs outside `init`'s rollback envelope
    /// and is therefore its own whole undo, does too.
    #[tokio::test]
    async fn a_failed_repair_puts_the_previous_policy_back_as_well() {
        let (server, writes) = converge_mock_server().await;
        let mut client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());

        let (dir, _paths) = provisioned_host().await;
        std::fs::create_dir_all(dir.path().join("certs")).expect("ca dir");
        std::fs::write(
            dir.path().join("certs").join("root_ca.crt"),
            bundle_pem("Uk9PVA"),
        )
        .expect("root CA");
        let context = repair_inputs(dir.path());

        // What a repair does around a login or a publication that
        // failed: capture, converge, put back what it found.
        let prior = PriorInternalAuth::capture(&client)
            .await
            .expect("both artifacts are readable");
        let mut mounted_now = false;
        converge_internal_auth(
            &client,
            &context.inputs(),
            &test_messages(),
            &mut mounted_now,
        )
        .await
        .expect("the convergence writes both artifacts");
        prior.restore(&client).await;

        let policies = writes.policies.lock().expect("capture").clone();
        assert_eq!(
            policies.len(),
            2,
            "the convergence writes the policy and the restore puts it back: {policies:?}"
        );
        assert_ne!(
            policies.first().expect("the converged body"),
            PRIOR_POLICY,
            "the convergence really does replace the pre-existing policy"
        );
        assert_eq!(
            policies.last().expect("the restored body"),
            PRIOR_POLICY,
            "the policy the repair found goes back exactly as it was read"
        );
        assert_eq!(
            writes.entries.lock().expect("capture").last(),
            Some(&prior_entry()),
            "the entry is still restored alongside it"
        );
    }

    /// The Phase-4 tail refuses to replace anything on a host whose
    /// Phase-3 publication did not land.
    #[tokio::test]
    async fn the_tail_refuses_a_host_that_is_not_on_the_additive_set() {
        let (dir, _paths) = provisioned_host().await;
        let additive = vec![
            OLD_ROOT_FP.to_string(),
            OLD_INT_FP.to_string(),
            ROOT_FP.to_string(),
            NEW_INT_FP.to_string(),
        ];
        let err = ensure_internal_trust_is(dir.path(), &additive, &test_messages())
            .expect_err("a stale config must be refused");
        assert!(err.to_string().contains("Phase 3"), "{err}");

        write_internal_trust(
            dir.path(),
            &InternalTrustState {
                fingerprints: additive.clone(),
                bundle_pem: bundle_pem("QURESVRJVkU"),
            },
            &test_messages(),
        )
        .await
        .expect("publish");
        ensure_internal_trust_is(dir.path(), &additive, &test_messages())
            .expect("the additive set is now in place");
    }
}
