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
    InternalPaths, MaterialStatus, load_material, material_status, require_https,
    require_root_authority, upsert_internal_trust,
};
use bootroot::{cert_group, fs_util};

use super::RotateContext;
use super::helpers::signal_internal_registrar_agent;
use crate::commands::init::registrar_internal::{
    RegistrarInternalContext, RegistrarInternalIntent, converge_internal_auth,
    issue_internal_material, publish_internal_set,
};
use crate::commands::init::{
    DEFAULT_STEPCA_PROVISIONER, PATH_AGENT_EAB, PATH_RESPONDER_HMAC, compute_ca_bundle_pem,
    read_ca_cert_fingerprint,
};
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
/// # Errors
///
/// Returns an error when the config is missing or unparseable, or when
/// either file cannot be published.
async fn write_internal_trust(
    secrets_dir: &Path,
    trust: &InternalTrustState,
    messages: &Messages,
) -> Result<()> {
    let paths = InternalPaths::new(secrets_dir);
    fs_util::write_ca_bundle(
        &paths.ca_bundle(),
        &trust.bundle_pem,
        cert_group::CertGroupPolicy::none(),
    )
    .await
    .with_context(|| messages.error_write_file_failed(&paths.ca_bundle().display().to_string()))?;

    let config_path = paths.agent_config();
    let current = tokio::fs::read_to_string(&config_path)
        .await
        .with_context(|| messages.error_read_file_failed(&config_path.display().to_string()))?;
    let next = upsert_internal_trust(&current, &paths, &trust.fingerprints)?;
    fs_util::atomic_write(
        fs_util::Destination::bootroot_owned(&config_path),
        next.as_bytes(),
        fs_util::StagedMode::Policy(fs_util::KEY_FILE_MODE),
    )
    .await
    .with_context(|| messages.error_write_file_failed(&config_path.display().to_string()))?;
    Ok(())
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
    let inputs = context.inputs();

    converge_internal_auth(client, &inputs, messages).await?;
    // The publication carries `trust`, not the active generation the
    // issuance staged: the Phase-4 tail replaces the credential while
    // the fleet is still on the additive set, and a repair mid-rotation
    // has to restore that same set.
    let staged = issue_internal_material(&inputs, messages)
        .await?
        .with_trust(trust.fingerprints.clone(), trust.bundle_pem.clone());
    publish_internal_set(&staged, &inputs, messages).await?;
    signal_internal_registrar_agent(&context.secrets_dir, messages)
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
    use bootroot::registrar::internal::{
        AcmeAccountKey, InternalAgentConfigParams, InternalMaterial, PrivateKeyPem,
        publish_material, render_internal_agent_config,
    };
    use tempfile::TempDir;

    use super::{
        InternalPaths, InternalTrustState, ensure_internal_trust_is, internal_credential_present,
        repair_internal_credential, write_internal_trust,
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
