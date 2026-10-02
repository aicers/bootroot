use std::io::{self, BufRead};

use anyhow::{Context, Result};
use base64::Engine;
use bootroot::openbao::{KvCreateIfAbsent, OpenBaoClient};

use super::super::constants::SECRET_BYTES;
use super::super::constants::openbao_constants::PATH_AGENT_EAB;
use super::super::types::EabCredentials;
use super::prompts::{prompt_text, prompt_yes_no, read_prompt_text};
use super::{InitRollback, InitSecrets};
use crate::cli::args::{InitArgs, InitFeature};
use crate::i18n::Messages;

/// Minimum decoded length for an ACME EAB HMAC (typical step-ca / Boulder
/// HMACs are 32 bytes; we accept down to 16 to tolerate other CAs).
const MIN_EAB_HMAC_BYTES: usize = 16;

pub(super) fn resolve_init_secrets(
    args: &InitArgs,
    messages: &Messages,
    db_dsn: String,
) -> Result<InitSecrets> {
    // In reinit mode, if `password.txt` already exists, prefer the
    // stored password so that step-ca CA material (encrypted with that
    // password) remains usable.  Without this, the auto-gen path below
    // would overwrite the existing password and lock the operator out
    // of the preserved root_ca_key / intermediate_ca_key.
    let preserved_stepca_password = if args.reinit_mode {
        let password_path = args.secrets_dir.secrets_dir.join("password.txt");
        if password_path.exists() {
            Some(
                std::fs::read_to_string(&password_path)
                    .with_context(|| {
                        messages.error_read_file_failed(&password_path.display().to_string())
                    })?
                    .trim_end_matches('\n')
                    .to_string(),
            )
        } else {
            None
        }
    } else {
        None
    };
    // Under reinit mode the previous step-ca password and HTTP-01 HMAC
    // are either preserved from the source tree (`password.txt`) or are
    // gone with the wiped OpenBao KV (`http_hmac`, previously at
    // PATH_AGENT_HTTP01). Reinit does not re-prompt operators for fresh
    // secrets, so when a secret cannot be preserved verbatim, generate a
    // replacement non-interactively even without the operator opting
    // into the global `auto-generate` feature.  For the step-ca
    // password this matters specifically when `password.txt` is absent
    // (rsync-clone path or operator-removed): without the reinit_mode
    // bypass, `reinit --yes` would stall on the interactive step-ca
    // password prompt.  An existing `password.txt` still wins above so
    // the preserved CA material remains decryptable.
    let auto_generate_secret = args.has_feature(InitFeature::AutoGenerate) || args.reinit_mode;
    let stepca_password = if let Some(existing) = preserved_stepca_password {
        existing
    } else {
        resolve_secret(
            messages.prompt_stepca_password(),
            args.stepca_password.as_deref(),
            auto_generate_secret,
            messages,
        )?
    };
    let http_hmac = resolve_secret(
        messages.prompt_http_hmac(),
        args.http_hmac.as_deref(),
        auto_generate_secret,
        messages,
    )?;
    let eab = resolve_eab(args, messages)?;

    Ok(InitSecrets {
        stepca_password,
        db_dsn,
        http_hmac,
        eab,
    })
}

fn resolve_secret(
    label: &str,
    value: Option<&str>,
    auto_generate: bool,
    messages: &Messages,
) -> Result<String> {
    if let Some(value) = value {
        return Ok(value.to_string());
    }
    if auto_generate {
        return bootroot::utils::generate_secret(SECRET_BYTES)
            .with_context(|| messages.error_generate_secret_failed());
    }
    prompt_text(&format!("{label}: "), messages)
}

fn resolve_eab(args: &InitArgs, messages: &Messages) -> Result<Option<EabCredentials>> {
    if args.no_eab {
        return Ok(None);
    }
    match (&args.eab_kid, &args.eab_hmac) {
        (Some(kid), Some(hmac)) => {
            let validated = validate_eab(kid, hmac)?;
            Ok(Some(validated))
        }
        (None, None) => Ok(None),
        _ => anyhow::bail!(messages.error_eab_requires_both()),
    }
}

pub(super) async fn maybe_register_eab(
    client: &OpenBaoClient,
    args: &InitArgs,
    messages: &Messages,
    rollback: &mut InitRollback,
    secrets: &InitSecrets,
) -> Result<Option<EabCredentials>> {
    if secrets.eab.is_some() {
        return Ok(None);
    }
    if args.no_eab {
        return Ok(None);
    }
    // Reinit does not re-prompt for EAB credentials: the previous EAB
    // material was wiped with OpenBao's KV mount, and `bootroot reinit`
    // intentionally has no EAB CLI surface.  Operators who want to
    // re-register EAB run a follow-up step out of band.
    if args.reinit_mode {
        return Ok(None);
    }
    if !prompt_yes_no(messages.prompt_eab_register_now(), messages)? {
        return Ok(None);
    }
    println!("{}", messages.eab_prompt_instructions());
    // The lock is a temporary that dies with this statement: holding it
    // in a local across the `register_eab_secret` await below would make
    // this future non-`Send`.
    let credentials = prompt_eab_with_validation(&mut io::stdin().lock(), messages)?;
    register_eab_secret(
        client,
        &args.openbao.kv_mount,
        rollback,
        &credentials,
        messages,
    )
    .await?;
    Ok(Some(credentials))
}

/// Re-prompts the operator until both `kid` and `hmac` validate. The
/// operator who realises mid-prompt that they don't have EAB material
/// aborts with Ctrl-C and re-runs `init` (eventually with `--no-eab`).
/// Coercing blank-to-"no EAB" silently here would leak the same garbage
/// (kid="", hmac="") into KV that issue #588 §3 closes.
///
/// This is the only `init` prompt that retries, so it is the only one
/// that needs the reader threaded in: an EOF that the primitive turns
/// into an error terminates the loop here instead of spinning on an
/// answer that will never arrive.
fn prompt_eab_with_validation(
    input: &mut dyn BufRead,
    messages: &Messages,
) -> Result<EabCredentials> {
    loop {
        let kid = read_prompt_text(input, messages.prompt_eab_kid(), messages)?;
        let hmac = read_prompt_text(input, messages.prompt_eab_hmac(), messages)?;
        match validate_eab(&kid, &hmac) {
            Ok(creds) => return Ok(creds),
            Err(err) => {
                eprintln!("{err}");
            }
        }
    }
}

/// Validates EAB inputs to close the symptom from issue #588 §3a:
/// today's parser silently accepts `y` of length 1 as the HMAC, and
/// step-ca only fails at first issuance with `Failed to decode EAB key:
/// Invalid input length: 1`. Validation: `kid` non-empty after trim;
/// `hmac` base64url-decodable to >= 16 bytes.
fn validate_eab(kid: &str, hmac: &str) -> Result<EabCredentials> {
    let kid = kid.trim();
    let hmac = hmac.trim();
    if kid.is_empty() {
        anyhow::bail!("EAB kid must not be empty");
    }
    if hmac.is_empty() {
        anyhow::bail!("EAB hmac must not be empty");
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(hmac)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(hmac))
        .map_err(|err| anyhow::anyhow!("EAB hmac must be base64url-encoded: {err}"))?;
    if decoded.len() < MIN_EAB_HMAC_BYTES {
        anyhow::bail!(
            "EAB hmac decodes to {} bytes; expected at least {MIN_EAB_HMAC_BYTES}",
            decoded.len()
        );
    }
    Ok(EabCredentials {
        kid: kid.to_string(),
        hmac: bootroot::secret::HmacSecret::new(hmac.to_string()),
    })
}

async fn register_eab_secret(
    client: &OpenBaoClient,
    kv_mount: &str,
    rollback: &mut InitRollback,
    credentials: &EabCredentials,
    messages: &Messages,
) -> Result<()> {
    if !client
        .kv_exists(kv_mount, PATH_AGENT_EAB)
        .await
        .with_context(|| messages.error_openbao_kv_exists_failed())?
    {
        rollback.written_kv_paths.push(PATH_AGENT_EAB.to_string());
    }
    client
        .write_kv(
            kv_mount,
            PATH_AGENT_EAB,
            serde_json::json!({ "kid": credentials.kid, "hmac": credentials.hmac }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    Ok(())
}

/// Records the explicit "no EAB" payload at the agent EAB path on an
/// endpoint-enabled host that registered none, unless the path already
/// holds an entry.
///
/// `endpoint_enabled` is the recorded predicate and `registered` the EAB
/// this run wrote, if any. A disabled or absent predicate, or a run that
/// registered an EAB, makes no request at all.
///
/// The registrar endpoint daemon's surface issuance reads this path
/// unconditionally and accepts only a populated payload or the explicit
/// cleared one; an absent entry is an error it refuses on, on purpose,
/// because "never written" and "deliberately empty" are different
/// deployments. A `--no-eab` endpoint host is the second, so `init`
/// says so here — in the shape `rotate eab-clear` writes — rather than
/// leaving a daemon that can never start its first issuance.
///
/// An existing entry is never overwritten, populated or cleared: it is
/// a decision someone already recorded. The write is a KV v2
/// create-if-absent (`cas: 0`) rather than a check followed by a plain
/// write, so an entry another writer creates between the two cannot be
/// replaced: `OpenBao` admits the create only while the path carries no
/// version. The path joins the same KV rollback every other `init` KV
/// write uses only once this call is the one that created it, so a
/// failed run removes the cleared payload it wrote and never an entry
/// someone else did.
///
/// # Errors
///
/// Returns an error when the create fails for any reason other than the
/// path already carrying a version.
pub(super) async fn record_cleared_agent_eab(
    client: &OpenBaoClient,
    kv_mount: &str,
    endpoint_enabled: bool,
    registered: Option<&EabCredentials>,
    rollback: &mut InitRollback,
    messages: &Messages,
) -> Result<()> {
    if !endpoint_enabled || registered.is_some() {
        return Ok(());
    }
    let outcome = client
        .create_kv_if_absent(
            kv_mount,
            PATH_AGENT_EAB,
            serde_json::json!({ "kid": "", "hmac": "" }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    if let KvCreateIfAbsent::Created(_) = outcome {
        rollback.written_kv_paths.push(PATH_AGENT_EAB.to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::super::test_support::test_messages;
    use super::*;

    const KV_MOUNT: &str = "secret";

    /// An `OpenBao` whose agent EAB path already carries a version when
    /// `exists` is set, recording every body posted to it.
    ///
    /// A post to an existing path answers with the KV v2 check-and-set
    /// mismatch, exactly as `OpenBao` does for `cas: 0`, so a writer that
    /// omitted the option would still see its body recorded.
    async fn eab_mock_server(exists: bool) -> (MockServer, Arc<Mutex<Vec<serde_json::Value>>>) {
        let server = MockServer::start().await;
        let writes: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&writes);
        Mock::given(method("POST"))
            .and(path(format!("/v1/{KV_MOUNT}/data/{PATH_AGENT_EAB}")))
            .respond_with(move |request: &Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).expect("json");
                sink.lock().expect("capture").push(body);
                if exists {
                    ResponseTemplate::new(400).set_body_json(serde_json::json!({
                        "errors": ["check-and-set parameter did not match the current version"]
                    }))
                } else {
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({ "data": { "version": 1 } }))
                }
            })
            .mount(&server)
            .await;
        (server, writes)
    }

    /// An absent agent EAB path on an endpoint-enabled host receives
    /// the cleared payload, in exactly the shape the surface issuance
    /// reads as a deliberate "no EAB", and the write is registered for
    /// rollback.
    #[tokio::test]
    async fn an_absent_agent_eab_is_recorded_as_cleared() {
        let (server, writes) = eab_mock_server(false).await;
        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());
        let mut rollback = InitRollback::default();
        record_cleared_agent_eab(
            &client,
            KV_MOUNT,
            true,
            None,
            &mut rollback,
            &test_messages(),
        )
        .await
        .expect("the cleared payload is recorded");

        let writes = writes.lock().expect("capture").clone();
        let [body] = writes.as_slice() else {
            panic!("exactly one write is expected: {writes:?}");
        };
        assert_eq!(
            body.get("options"),
            Some(&serde_json::json!({ "cas": 0 })),
            "the write is a create-if-absent"
        );
        let data = body.get("data").expect("a KV v2 data envelope");
        assert_eq!(data, &serde_json::json!({ "kid": "", "hmac": "" }));
        assert_eq!(
            bootroot::kv_payload::parse_eab_payload(data).expect("parse"),
            bootroot::kv_payload::EabPayload::Clear
        );
        assert_eq!(rollback.written_kv_paths, vec![PATH_AGENT_EAB.to_string()]);
    }

    /// An existing entry — populated or already cleared, and whether it
    /// was there all along or another writer created it a moment ago —
    /// is a decision already recorded. The only request is a
    /// create-if-absent `OpenBao` refuses, and the path is not
    /// registered for rollback, so a failed run cannot delete it.
    #[tokio::test]
    async fn an_existing_agent_eab_is_left_untouched() {
        let (server, writes) = eab_mock_server(true).await;
        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());
        let mut rollback = InitRollback::default();
        record_cleared_agent_eab(
            &client,
            KV_MOUNT,
            true,
            None,
            &mut rollback,
            &test_messages(),
        )
        .await
        .expect("an existing entry is not an error");

        let writes = writes.lock().expect("capture").clone();
        assert!(
            writes
                .iter()
                .all(|body| body.get("options") == Some(&serde_json::json!({ "cas": 0 }))),
            "every write is a create-if-absent: {writes:?}"
        );
        assert_eq!(rollback.written_kv_paths, Vec::<String>::new());
    }

    /// A disabled or absent predicate writes nothing new, and neither
    /// does a run that registered an EAB of its own: neither run so much
    /// as asks whether the path exists.
    #[tokio::test]
    async fn a_disabled_predicate_or_a_registered_eab_writes_nothing() {
        let (server, writes) = eab_mock_server(false).await;
        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());
        let registered = EabCredentials {
            kid: "kid-1".to_string(),
            hmac: bootroot::secret::HmacSecret::new("aG1hYy1ieXRlcy1mb3ItdGVzdHM".to_string()),
        };
        let mut rollback = InitRollback::default();
        for (enabled, eab) in [
            (false, None),
            (false, Some(&registered)),
            (true, Some(&registered)),
        ] {
            record_cleared_agent_eab(
                &client,
                KV_MOUNT,
                enabled,
                eab,
                &mut rollback,
                &test_messages(),
            )
            .await
            .expect("nothing to record is not an error");
        }

        assert!(writes.lock().expect("capture").is_empty());
        assert_eq!(rollback.written_kv_paths, Vec::<String>::new());
        assert!(
            server
                .received_requests()
                .await
                .expect("recording is enabled")
                .is_empty(),
            "no request at all is made"
        );
    }

    #[test]
    fn test_resolve_secret_prefers_value() {
        let messages = test_messages();
        let value = resolve_secret("step-ca password", Some("value"), false, &messages).unwrap();
        assert_eq!(value, "value");
    }

    #[test]
    fn test_resolve_secret_auto_generates() {
        let messages = test_messages();
        let value = resolve_secret("HTTP-01 HMAC", None, true, &messages).unwrap();
        assert_ne!(value, "");
    }

    #[test]
    fn validate_eab_rejects_single_char_hmac() {
        let err = validate_eab("kid-1", "y").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("base64url") || msg.contains("at least"),
            "expected validation message, got: {msg}"
        );
    }

    #[test]
    fn validate_eab_rejects_empty_kid() {
        let err = validate_eab("   ", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap_err();
        assert!(err.to_string().contains("kid"));
    }

    /// Regression: when `reinit_mode` is set and `password.txt` already
    /// exists, `resolve_init_secrets` must return the stored password
    /// verbatim — auto-gen would lock the operator out of the preserved
    /// step-ca CA material that's encrypted with the old password.
    #[test]
    fn resolve_init_secrets_preserves_password_in_reinit_mode() {
        use std::fs;

        use tempfile::tempdir;

        use crate::cli::args::InitFeature;

        let messages = test_messages();
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        fs::create_dir_all(&secrets).unwrap();
        fs::write(secrets.join("password.txt"), "preserved-secret\n").unwrap();

        let mut args = super::super::test_support::default_init_args();
        args.secrets_dir.secrets_dir = secrets;
        args.reinit_mode = true;
        // Auto-generate would normally win — assert it does NOT.
        args.enable = vec![InitFeature::AutoGenerate];
        args.no_eab = true;
        args.http_hmac = Some("provided-hmac".to_string());

        let resolved =
            resolve_init_secrets(&args, &messages, "ignored-dsn".to_string()).expect("resolve");
        assert_eq!(
            resolved.stepca_password, "preserved-secret",
            "reinit_mode must preserve existing password.txt verbatim"
        );
    }

    /// Regression: outside of reinit mode the preserve-password
    /// fast-path must not engage; auto-generation should produce a
    /// fresh secret as before.
    #[test]
    fn resolve_init_secrets_auto_generates_when_not_reinit_mode() {
        use std::fs;

        use tempfile::tempdir;

        use crate::cli::args::InitFeature;

        let messages = test_messages();
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        fs::create_dir_all(&secrets).unwrap();
        fs::write(secrets.join("password.txt"), "should-be-ignored\n").unwrap();

        let mut args = super::super::test_support::default_init_args();
        args.secrets_dir.secrets_dir = secrets;
        args.reinit_mode = false;
        args.enable = vec![InitFeature::AutoGenerate];
        args.no_eab = true;
        args.http_hmac = Some("provided-hmac".to_string());

        let resolved = resolve_init_secrets(&args, &messages, "dsn".to_string()).expect("resolve");
        assert_ne!(
            resolved.stepca_password, "should-be-ignored",
            "outside reinit_mode, auto-generate must run"
        );
        assert_ne!(resolved.stepca_password, "");
    }

    /// Regression: in reinit mode the previous HTTP-01 HMAC was wiped
    /// along with `OpenBao`'s KV mount, and `bootroot reinit` does not
    /// re-prompt operators for fresh secrets.  Without auto-generating
    /// the HMAC, `reinit --yes` would stall on `prompt_text` for HTTP
    /// HMAC even though the caller has opted into the non-interactive
    /// recovery flow.
    #[test]
    fn resolve_init_secrets_auto_generates_http_hmac_in_reinit_mode() {
        use std::fs;

        use tempfile::tempdir;

        let messages = test_messages();
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        fs::create_dir_all(&secrets).unwrap();
        fs::write(secrets.join("password.txt"), "preserved\n").unwrap();

        let mut args = super::super::test_support::default_init_args();
        args.secrets_dir.secrets_dir = secrets;
        args.reinit_mode = true;
        args.no_eab = true;
        // Crucially: no --http-hmac on the CLI, no AutoGenerate feature
        // — only reinit_mode should drive the auto-gen branch.
        args.http_hmac = None;
        args.enable = Vec::new();

        let resolved =
            resolve_init_secrets(&args, &messages, "ignored-dsn".to_string()).expect("resolve");
        assert!(
            !resolved.http_hmac.is_empty(),
            "reinit_mode must auto-generate a fresh HTTP HMAC instead of prompting"
        );
    }

    /// Regression for #601 §2: under `reinit_mode`, when
    /// `secrets/password.txt` is absent (rsync-clone path or operator
    /// removed it), the step-ca password generation must NOT fall back
    /// to an interactive prompt. The existing `http_hmac`
    /// `|| args.reinit_mode` pattern is mirrored here so `reinit --yes`
    /// without `--enable auto-generate` produces a fresh step-ca
    /// password non-interactively.
    #[test]
    fn resolve_init_secrets_auto_generates_stepca_password_when_missing_in_reinit_mode() {
        use tempfile::tempdir;

        let messages = test_messages();
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        // Crucially: NO password.txt exists.
        assert!(!secrets.join("password.txt").exists());

        let mut args = super::super::test_support::default_init_args();
        args.secrets_dir.secrets_dir = secrets;
        args.reinit_mode = true;
        args.no_eab = true;
        // No --stepca-password, no --enable auto-generate. Only
        // reinit_mode should drive the auto-gen branch.
        args.stepca_password = None;
        args.enable = Vec::new();
        args.http_hmac = Some("provided-hmac".to_string());

        let resolved =
            resolve_init_secrets(&args, &messages, "ignored-dsn".to_string()).expect("resolve");
        assert!(
            !resolved.stepca_password.is_empty(),
            "reinit_mode must auto-generate a fresh step-ca password instead of prompting"
        );
    }

    /// Regression for the reported symptom: with stdin at EOF the EAB
    /// prompt used to read `""` for both fields forever, printing the
    /// validation error once per iteration (gigabytes of it) until the
    /// process was killed.  It must terminate on the first read instead.
    #[test]
    fn prompt_eab_with_validation_errors_on_eof_without_looping() {
        use std::io::Cursor;

        let messages = test_messages();
        let err = prompt_eab_with_validation(&mut Cursor::new(""), &messages)
            .expect_err("EOF must error instead of looping");
        assert_eq!(err.to_string(), messages.error_prompt_eof());
    }

    /// The shape a piped answer sequence actually runs out in: the
    /// `kid` is answered and the `hmac` is not.  A partially answered
    /// attempt must fail on the missing read rather than complete the
    /// pair with `""` and retry, which is how the loop used to spin.
    #[test]
    fn prompt_eab_with_validation_errors_on_eof_midway_through_a_pair() {
        use std::io::Cursor;

        let messages = test_messages();
        let err = prompt_eab_with_validation(&mut Cursor::new("kid-1\n"), &messages)
            .expect_err("a half-answered pair must error, not retry");
        assert_eq!(err.to_string(), messages.error_prompt_eof());
    }

    /// The EOF fix must not turn a recoverable typo into a hard failure:
    /// a rejected attempt followed by a valid pair still loops once and
    /// returns the valid credentials.
    #[test]
    fn prompt_eab_with_validation_retries_after_a_rejected_attempt() {
        use std::io::Cursor;

        let messages = test_messages();
        let hmac = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xCD; 32]);
        // First attempt: a one-character HMAC, the #588 §3a symptom.
        let script = format!("kid-1\ny\nkid-2\n{hmac}\n");
        let creds = prompt_eab_with_validation(&mut Cursor::new(script), &messages)
            .expect("a rejected attempt must be retried, not fatal");
        assert_eq!(creds.kid, "kid-2");
        assert_eq!(creds.hmac.expose(), hmac);
    }

    #[test]
    fn validate_eab_accepts_32_byte_base64url() {
        // 32 bytes → 43 base64url-no-pad chars.
        let bytes = [0xAB; 32];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let creds = validate_eab("kid-1", &encoded).expect("valid EAB");
        assert_eq!(creds.kid, "kid-1");
        assert_eq!(creds.hmac.expose(), encoded);
    }
}
