//! Plaintext → TLS transition for the `OpenBao` listener.
//!
//! `init` rewrites `openbao/openbao.hcl` with the freshly issued server
//! certificate and then has to make the running process pick it up.
//! `openbao.hcl` is a bind-mounted file, so Docker Compose does not hash
//! its contents: a plain `docker compose up -d openbao` recreates the
//! container only when the *compose configuration* changed.  Whenever
//! the `openbao-exposed` override was already applied before `init` ran
//! there is no such delta, `up -d` is a no-op, and the container keeps
//! serving plaintext from its old configuration while `state.json` is
//! advanced to `https://` (issue #737).
//!
//! This module owns the three gates that close that hole: an
//! unconditional recreate, a TLS probe against the exact URL that is
//! about to be recorded, and the unseal that a recreate makes necessary
//! (`SIGHUP` cannot enable TLS on a plaintext listener, so the process
//! has to restart, and a restart brings the Shamir-sealed vault back
//! sealed).

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use super::prompts::prompt_unseal_keys;
use crate::commands::compose_project::{ComposeIdentity, ComposeInvocation};
use crate::commands::infra::{
    build_openbao_client, run_compose, wait_for_openbao_api_reachable_within,
};
use crate::commands::openbao_unseal::read_unseal_keys_from_file;
use crate::i18n::Messages;

/// Compose service name of the `OpenBao` server.
const OPENBAO_SERVICE_NAME: &str = "openbao";
/// Budget for the post-recreate TLS probe.  The listener has to be
/// reachable *and* speaking TLS within it; a plaintext listener never
/// becomes reachable over HTTPS, so this doubles as the plaintext
/// timeout.
const TLS_PROBE_ATTEMPTS: u32 = 60;
const TLS_PROBE_DELAY: Duration = Duration::from_millis(500);

/// Where the keys used for the post-recreate unseal came from.
///
/// Carried alongside the keys so a failure can name the source the
/// operator actually pointed `init` at, instead of a generic "still
/// sealed".
#[derive(Debug, Clone, PartialEq, Eq)]
enum UnsealKeySource {
    /// The keys this `init` run already holds — the fresh-install case,
    /// where `init` itself initialised the vault (or the operator passed
    /// `--unseal-key` / answered the bootstrap prompt).
    InMemory,
    /// A file on disk: either `--openbao-unseal-from-file` or the
    /// default `<secrets_dir>/openbao/unseal-keys.txt`.
    File(PathBuf),
    /// The interactive prompt.  Its keys are read after the recreate,
    /// once `sys/seal-status` has confirmed the vault actually needs
    /// them and has reported the threshold.
    Prompt,
}

impl UnsealKeySource {
    fn describe(&self, messages: &Messages) -> String {
        match self {
            Self::InMemory => messages.openbao_unseal_source_in_memory().to_string(),
            Self::File(path) => path.display().to_string(),
            Self::Prompt => messages.openbao_unseal_source_prompt().to_string(),
        }
    }
}

/// An unseal key source that has been confirmed available, with its
/// material already read where the source is a file.
struct PreparedUnsealKeys {
    source: UnsealKeySource,
    /// Empty exactly for [`UnsealKeySource::Prompt`].
    keys: Vec<String>,
}

/// Redacts the key material.  `Debug` is required — `expect_err` on a
/// `Result<PreparedUnsealKeys>` needs it — but a derived one would put
/// live unseal keys into any panic message or `{:?}` that ever touches
/// this struct.
impl std::fmt::Debug for PreparedUnsealKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedUnsealKeys")
            .field("source", &self.source)
            .field("keys", &format_args!("<{} redacted>", self.keys.len()))
            .finish()
    }
}

/// The candidate unseal key sources, in the order they are consulted.
pub(super) struct UnsealKeyInputs<'a> {
    /// `InitBootstrap::unseal_keys`; empty when `OpenBao` was already
    /// initialised and unsealed before this run.
    pub(super) in_memory: &'a [String],
    /// `--openbao-unseal-from-file`, when the operator passed it.
    pub(super) explicit_file: Option<&'a Path>,
    /// `<secrets_dir>/openbao/unseal-keys.txt`.
    pub(super) default_file: PathBuf,
    /// Whether stdin is a terminal, i.e. whether prompting is possible.
    pub(super) interactive: bool,
}

/// Selects the unseal key source and reads its material.
///
/// A source is skipped only when it is *absent*: the in-memory list is
/// empty, the flag was not passed, the default file does not exist, or
/// stdin is not a terminal.  A source that is present but unusable —
/// unreadable or empty — is terminal, so an operator who pointed
/// `--openbao-unseal-from-file` at the wrong file gets that file named
/// in the error instead of a silent fallback to a stale default or a
/// prompt.
///
/// Runs *before* the container is recreated so a deployment is never
/// knocked into a sealed state `init` cannot recover from.  Key
/// validity is only observable after the recreate; availability is what
/// this establishes.
///
/// # Errors
///
/// Returns an error when the selected source cannot be read, and when
/// every source is absent.
fn prepare_unseal_keys(
    inputs: &UnsealKeyInputs<'_>,
    messages: &Messages,
) -> Result<PreparedUnsealKeys> {
    if !inputs.in_memory.is_empty() {
        return Ok(PreparedUnsealKeys {
            source: UnsealKeySource::InMemory,
            keys: inputs.in_memory.to_vec(),
        });
    }
    // `init` already confirmed `--openbao-unseal-from-file` once on the
    // bootstrap unseal path.  Re-reading the same file here must not
    // prompt again: scripted callers feed a fixed number of answers on
    // stdin, and a second confirmation would consume one meant for a
    // later prompt.
    if let Some(path) = inputs.explicit_file {
        return read_prepared_keys(path, messages);
    }
    if inputs.default_file.exists() {
        return read_prepared_keys(&inputs.default_file, messages);
    }
    if inputs.interactive {
        return Ok(PreparedUnsealKeys {
            source: UnsealKeySource::Prompt,
            keys: Vec::new(),
        });
    }
    anyhow::bail!(
        messages
            .error_openbao_unseal_source_unavailable(&inputs.default_file.display().to_string())
    )
}

fn read_prepared_keys(path: &Path, messages: &Messages) -> Result<PreparedUnsealKeys> {
    let keys = read_unseal_keys_from_file(path, messages)?;
    Ok(PreparedUnsealKeys {
        source: UnsealKeySource::File(path.to_path_buf()),
        keys,
    })
}

/// Builds the Docker Compose arguments that put the rewritten
/// `openbao.hcl` and the freshly issued certificate into the running
/// process.
///
/// `--force-recreate` is the whole point: without it the recreate
/// depends on a compose-configuration delta, which exists only when
/// this very invocation is the one adding the `openbao-exposed`
/// override.  Both files stay on the command line so the published bind
/// address is unchanged by the recreate.
fn openbao_recreate_invocation(
    identity: &ComposeIdentity,
    compose_file: &Path,
    override_path: &Path,
) -> ComposeInvocation {
    identity.compose(
        &[
            &compose_file.to_string_lossy(),
            &override_path.to_string_lossy(),
        ],
        None,
        &["up", "-d", "--force-recreate", OPENBAO_SERVICE_NAME],
    )
}

/// The plaintext → TLS transition of the `OpenBao` listener.
pub(super) struct OpenBaoTlsTransition<'a> {
    compose_file: &'a Path,
    override_path: &'a Path,
    /// The URL that is about to be written to `state.openbao_url`, i.e.
    /// `client_url_from_bind_addr(&bind_addr)` — never the advertise
    /// address, which local commands must not depend on.
    https_url: &'a str,
    secrets_dir: &'a Path,
    probe_attempts: u32,
    probe_delay: Duration,
}

impl<'a> OpenBaoTlsTransition<'a> {
    pub(super) fn new(
        compose_file: &'a Path,
        override_path: &'a Path,
        https_url: &'a str,
        secrets_dir: &'a Path,
    ) -> Self {
        Self {
            compose_file,
            override_path,
            https_url,
            secrets_dir,
            probe_attempts: TLS_PROBE_ATTEMPTS,
            probe_delay: TLS_PROBE_DELAY,
        }
    }

    /// Recreates `OpenBao`, confirms the listener answers over TLS at
    /// [`Self::https_url`], and leaves the vault unsealed.
    ///
    /// Returns before touching Docker when no unseal key source is
    /// available, so the running deployment is left as it was.
    /// `recreated` is set to `true` the moment the recreate is
    /// dispatched — and only then — so the caller's rollback undoes the
    /// container work exactly when there is container work to undo.
    ///
    /// # Errors
    ///
    /// Returns an error when no unseal key source is available, when the
    /// recreate fails, when the listener does not answer over TLS within
    /// the probe budget, or when the vault is still sealed after the
    /// keys have been applied.
    pub(super) async fn run(
        &self,
        inputs: &UnsealKeyInputs<'_>,
        recreated: &mut bool,
        messages: &Messages,
    ) -> Result<()> {
        let prepared = prepare_unseal_keys(inputs, messages)?;

        println!("{}", messages.init_openbao_tls_recreate());
        *recreated = true;
        let identity = ComposeIdentity::resolve(self.compose_file, None, messages)?;
        let invocation =
            openbao_recreate_invocation(&identity, self.compose_file, self.override_path);
        run_compose(&invocation, "docker compose up -d openbao (tls)", messages)?;

        let client = self.probe_tls(messages).await?;
        ensure_unsealed(&client, prepared, messages).await
    }

    /// Polls `sys/seal-status` over TLS until the listener answers.
    ///
    /// `sys/seal-status` answers while the vault is sealed, which is
    /// what makes this a listener check rather than a vault check.  The
    /// client trusts the local step-ca root and intermediate bundles;
    /// certificate verification is never disabled, so a listener still
    /// answering plaintext fails here with its transport error attached.
    async fn probe_tls(&self, messages: &Messages) -> Result<OpenBaoClient> {
        let client = build_openbao_client(self.https_url, Some(self.secrets_dir), messages)?;
        wait_for_openbao_api_reachable_within(
            &client,
            self.probe_attempts,
            self.probe_delay,
            messages,
        )
        .await
        .with_context(|| messages.error_openbao_tls_probe_failed(self.https_url))?;
        println!("{}", messages.init_openbao_tls_verified(self.https_url));
        Ok(client)
    }
}

/// Submits the prepared unseal keys, unless the vault already reports
/// itself unsealed.
async fn ensure_unsealed(
    client: &OpenBaoClient,
    prepared: PreparedUnsealKeys,
    messages: &Messages,
) -> Result<()> {
    let status = client
        .seal_status()
        .await
        .with_context(|| messages.error_openbao_seal_status_failed())?;
    if !status.sealed {
        println!("{}", messages.init_openbao_already_unsealed());
        return Ok(());
    }

    // The prompt is the one source whose material is read here rather
    // than in `prepare_unseal_keys`: the threshold is known only now,
    // and an operator is not asked for keys the vault turns out not to
    // need.  Its *availability* was established before the recreate.
    let from_prompt = matches!(prepared.source, UnsealKeySource::Prompt);
    let source = prepared.source.describe(messages);
    println!("{}", messages.init_openbao_unseal_from_source(&source));
    let keys = if from_prompt {
        prompt_unseal_keys(status.t, messages)?
    } else {
        prepared.keys
    };

    for key in &keys {
        // A key `OpenBao` rejects outright is the same "present but
        // unusable" source as one that leaves the vault sealed — a stale
        // share from a previous Shamir set is the common case, and it
        // fails on the submit rather than on the seal-status check below.
        // Name the source on that path too, so the operator is not left
        // with a bare transport error for a key file they can go fix.
        let status = client
            .unseal(key)
            .await
            .with_context(|| messages.error_openbao_unseal_failed())
            .with_context(|| messages.error_openbao_unseal_source_still_sealed(&source))?;
        if !status.sealed {
            return Ok(());
        }
    }
    let status = client
        .seal_status()
        .await
        .with_context(|| messages.error_openbao_seal_status_failed())?;
    if status.sealed {
        anyhow::bail!(messages.error_openbao_unseal_source_still_sealed(&source));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::tempdir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::commands::rotate::test_support::{
        ScopedEnvVar, TEST_DOCKER_ARGS_ENV, env_lock, path_with_prepend, write_fake_docker_script,
    };
    use crate::i18n::test_messages;

    const PROBE_ATTEMPTS: u32 = 1;
    const PROBE_DELAY: Duration = Duration::from_millis(1);
    /// A port nothing listens on, so the TLS probe fails fast instead of
    /// handshaking with a real server.
    const UNREACHABLE_HTTPS_URL: &str = "https://127.0.0.1:1";

    fn inputs<'a>(
        in_memory: &'a [String],
        explicit_file: Option<&'a Path>,
        default_file: PathBuf,
        interactive: bool,
    ) -> UnsealKeyInputs<'a> {
        UnsealKeyInputs {
            in_memory,
            explicit_file,
            default_file,
            interactive,
        }
    }

    #[test]
    fn recreate_args_do_not_depend_on_a_compose_delta() {
        let compose = PathBuf::from("docker-compose.yml");
        let override_path = PathBuf::from("secrets/openbao/docker-compose.openbao-exposed.yml");
        let dir = tempfile::tempdir().expect("tempdir");
        let identity = ComposeIdentity::resolve_for_dir(
            dir.path(),
            Some("bootroot"),
            &crate::i18n::test_messages(),
        )
        .expect("identity");
        let command = openbao_recreate_invocation(&identity, &compose, &override_path).command(&[]);
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert!(
            args.contains(&"--force-recreate".to_string()),
            "the TLS bring-up must recreate unconditionally: {args:?}"
        );
        assert!(
            args.contains(&"up".to_string()) && args.contains(&"-d".to_string()),
            "the TLS bring-up must still be an `up -d`: {args:?}"
        );
        assert!(
            args.iter().any(|a| a.ends_with("docker-compose.yml"))
                && args
                    .iter()
                    .any(|a| a.ends_with("docker-compose.openbao-exposed.yml")),
            "both compose files must stay applied so the bind address is unchanged: {args:?}"
        );
        assert_eq!(
            args.last().map(String::as_str),
            Some("openbao"),
            "the recreate must target only the openbao service: {args:?}"
        );
    }

    #[test]
    fn in_memory_keys_win_over_every_file() {
        let dir = tempdir().expect("temp dir");
        let explicit = dir.path().join("explicit.txt");
        fs::write(&explicit, "explicit-key\n").expect("write");
        let default_file = dir.path().join("unseal-keys.txt");
        fs::write(&default_file, "default-key\n").expect("write");
        let in_memory = vec!["memory-key".to_string()];

        let prepared = prepare_unseal_keys(
            &inputs(&in_memory, Some(&explicit), default_file, true),
            &test_messages(),
        )
        .expect("in-memory keys are available");

        assert_eq!(prepared.source, UnsealKeySource::InMemory);
        assert_eq!(prepared.keys, in_memory);
    }

    #[test]
    fn explicit_file_wins_over_the_default_file() {
        let dir = tempdir().expect("temp dir");
        let explicit = dir.path().join("explicit.txt");
        fs::write(&explicit, "explicit-key\n").expect("write");
        let default_file = dir.path().join("unseal-keys.txt");
        fs::write(&default_file, "default-key\n").expect("write");

        let prepared = prepare_unseal_keys(
            &inputs(&[], Some(&explicit), default_file, true),
            &test_messages(),
        )
        .expect("the explicit file is available");

        assert_eq!(prepared.source, UnsealKeySource::File(explicit));
        assert_eq!(prepared.keys, vec!["explicit-key".to_string()]);
    }

    #[test]
    fn default_file_is_used_when_no_flag_was_passed() {
        let dir = tempdir().expect("temp dir");
        let default_file = dir.path().join("unseal-keys.txt");
        fs::write(&default_file, "default-key\n").expect("write");

        let prepared = prepare_unseal_keys(
            &inputs(&[], None, default_file.clone(), true),
            &test_messages(),
        )
        .expect("the default file is available");

        assert_eq!(prepared.source, UnsealKeySource::File(default_file));
        assert_eq!(prepared.keys, vec!["default-key".to_string()]);
    }

    #[test]
    fn prompt_is_the_last_resort_and_reads_nothing_up_front() {
        let dir = tempdir().expect("temp dir");
        let default_file = dir.path().join("unseal-keys.txt");

        let prepared =
            prepare_unseal_keys(&inputs(&[], None, default_file, true), &test_messages())
                .expect("an interactive stdin is a source");

        assert_eq!(prepared.source, UnsealKeySource::Prompt);
        assert!(
            prepared.keys.is_empty(),
            "prompt material is read after the recreate, not before"
        );
    }

    /// An operator who pointed `--openbao-unseal-from-file` at the wrong
    /// file must see that file named, not a silent fallback to a stale
    /// default or a prompt.
    #[test]
    fn unreadable_explicit_file_does_not_fall_through() {
        let dir = tempdir().expect("temp dir");
        let missing = dir.path().join("nowhere.txt");
        let default_file = dir.path().join("unseal-keys.txt");
        fs::write(&default_file, "default-key\n").expect("write");

        let err = prepare_unseal_keys(
            &inputs(&[], Some(&missing), default_file, true),
            &test_messages(),
        )
        .expect_err("an unreadable explicit file is terminal");

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("nowhere.txt"),
            "the error must name the file the operator supplied: {rendered}"
        );
        assert!(
            !rendered.contains("unseal-keys.txt"),
            "the default file must not be consulted: {rendered}"
        );
    }

    #[test]
    fn empty_explicit_file_does_not_fall_through() {
        let dir = tempdir().expect("temp dir");
        let explicit = dir.path().join("explicit.txt");
        fs::write(&explicit, "\n\n").expect("write");
        let default_file = dir.path().join("unseal-keys.txt");
        fs::write(&default_file, "default-key\n").expect("write");

        let err = prepare_unseal_keys(
            &inputs(&[], Some(&explicit), default_file, true),
            &test_messages(),
        )
        .expect_err("an empty explicit file is terminal");

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("explicit.txt"),
            "the error must name the empty file: {rendered}"
        );
        assert!(
            !rendered.contains("unseal-keys.txt"),
            "the default file must not be consulted: {rendered}"
        );
    }

    #[test]
    fn every_source_absent_is_terminal() {
        let dir = tempdir().expect("temp dir");
        let default_file = dir.path().join("unseal-keys.txt");

        let err = prepare_unseal_keys(
            &inputs(&[], None, default_file.clone(), false),
            &test_messages(),
        )
        .expect_err("no source is available");

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("--openbao-unseal-from-file"),
            "the error must name the ways to supply keys: {rendered}"
        );
        assert!(
            rendered.contains(&default_file.display().to_string()),
            "the error must name the default key file: {rendered}"
        );
    }

    /// The availability pre-check runs before Docker is touched, so a
    /// deployment is never knocked into a sealed state `init` cannot
    /// recover from.
    #[test]
    fn no_available_source_fails_before_any_docker_call() {
        let dir = tempdir().expect("temp dir");
        let bin_dir = dir.path().join("bin");
        fs::create_dir_all(&bin_dir).expect("bin dir");
        write_fake_docker_script(&bin_dir.join("docker"));
        let args_log = dir.path().join("docker_args.log");
        let compose = dir.path().join("docker-compose.yml");
        let override_path = dir.path().join("docker-compose.openbao-exposed.yml");
        let default_file = dir.path().join("unseal-keys.txt");
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");

        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _log = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, &args_log);

        let transition = OpenBaoTlsTransition {
            probe_attempts: PROBE_ATTEMPTS,
            probe_delay: PROBE_DELAY,
            ..OpenBaoTlsTransition::new(&compose, &override_path, UNREACHABLE_HTTPS_URL, dir.path())
        };
        let mut recreated = false;
        // `block_on` rather than `#[tokio::test]`: the environment lock
        // has to stay held across the whole run so a parallel test
        // cannot swap PATH out from under the fake `docker`.
        let err = runtime
            .block_on(transition.run(
                &inputs(&[], None, default_file, false),
                &mut recreated,
                &test_messages(),
            ))
            .expect_err("no unseal key source is available");

        assert!(
            format!("{err:#}").contains("--openbao-unseal-from-file"),
            "the failure must be the missing-source diagnostic: {err:#}"
        );
        assert!(
            !args_log.exists(),
            "no docker command may be emitted before the pre-check passes"
        );
        assert!(
            !recreated,
            "rollback must not tear down a container this run never recreated"
        );
    }

    /// A vault that already reports itself unsealed after the recreate
    /// must short-circuit: submitting keys it does not need would fail
    /// the run for no reason.
    #[tokio::test]
    async fn already_unsealed_vault_receives_no_keys() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/sys/seal-status"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"sealed": false})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/sys/unseal"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let client = OpenBaoClient::new(&server.uri()).expect("client");
        let prepared = PreparedUnsealKeys {
            source: UnsealKeySource::InMemory,
            keys: vec!["memory-key".to_string()],
        };
        ensure_unsealed(&client, prepared, &test_messages())
            .await
            .expect("an unsealed vault needs nothing submitted");

        // Verified on drop, but assert eagerly so the failure points here.
        server.verify().await;
    }

    /// The happy path the whole module exists for: the recreate left the
    /// vault sealed, the prepared keys open it, and submission stops at
    /// the share that crosses the threshold rather than pushing the rest
    /// of the set at a vault that no longer needs them.
    #[tokio::test]
    async fn sealed_vault_is_unsealed_from_the_prepared_keys() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/sys/seal-status"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"sealed": true, "t": 2, "n": 3})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/sys/unseal"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"sealed": false})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = OpenBaoClient::new(&server.uri()).expect("client");
        let prepared = PreparedUnsealKeys {
            source: UnsealKeySource::InMemory,
            keys: vec![
                "memory-key-1".to_string(),
                "memory-key-2".to_string(),
                "memory-key-3".to_string(),
            ],
        };
        ensure_unsealed(&client, prepared, &test_messages())
            .await
            .expect("the prepared keys unseal the vault");

        server.verify().await;
    }

    /// Keys that leave the vault sealed are a *present but unusable*
    /// source, and the error has to name it.
    #[tokio::test]
    async fn keys_that_leave_the_vault_sealed_name_their_source() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/sys/seal-status"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"sealed": true})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/sys/unseal"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"sealed": true})),
            )
            .mount(&server)
            .await;

        let client = OpenBaoClient::new(&server.uri()).expect("client");
        let key_file = PathBuf::from("/tmp/bootroot-test/unseal-keys.txt");
        let prepared = PreparedUnsealKeys {
            source: UnsealKeySource::File(key_file.clone()),
            keys: vec!["stale-key".to_string()],
        };
        let err = ensure_unsealed(&client, prepared, &test_messages())
            .await
            .expect_err("the vault is still sealed");

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains(&key_file.display().to_string()),
            "the error must name the key source: {rendered}"
        );
    }

    /// A key `OpenBao` rejects outright — a stale share from a previous
    /// Shamir set — fails on the submit, before the seal-status check
    /// that names the source.  That path has to name the source too:
    /// a bare transport error does not tell the operator which key file
    /// to go fix.
    #[tokio::test]
    async fn keys_openbao_rejects_name_their_source() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/sys/seal-status"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"sealed": true})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/sys/unseal"))
            .respond_with(
                ResponseTemplate::new(400).set_body_json(
                    serde_json::json!({"errors": ["unseal failed, invalid key share"]}),
                ),
            )
            .mount(&server)
            .await;

        let client = OpenBaoClient::new(&server.uri()).expect("client");
        let key_file = PathBuf::from("/tmp/bootroot-test/stale-unseal-keys.txt");
        let prepared = PreparedUnsealKeys {
            source: UnsealKeySource::File(key_file.clone()),
            keys: vec!["stale-share".to_string()],
        };
        let err = ensure_unsealed(&client, prepared, &test_messages())
            .await
            .expect_err("OpenBao rejects the key");

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains(&key_file.display().to_string()),
            "the error must name the key source: {rendered}"
        );
        assert!(
            rendered.contains("invalid key share"),
            "the error must still surface OpenBao's own diagnostic: {rendered}"
        );
    }

    /// With a source available the recreate is emitted, and the TLS
    /// probe is what fails against a listener that is not there — the
    /// same failure a listener still answering plaintext produces.
    /// `state.openbao_url` is advanced by the caller only after this
    /// returns `Ok`, so the pre-TLS plaintext URL survives.
    #[test]
    fn tls_probe_failure_stops_before_the_url_is_recorded() {
        let dir = tempdir().expect("temp dir");
        let bin_dir = dir.path().join("bin");
        fs::create_dir_all(&bin_dir).expect("bin dir");
        write_fake_docker_script(&bin_dir.join("docker"));
        let args_log = dir.path().join("docker_args.log");
        let compose = dir.path().join("docker-compose.yml");
        let override_path = dir.path().join("docker-compose.openbao-exposed.yml");
        let state_path = dir.path().join("state.json");
        let plaintext_state = "{\"openbao_url\":\"http://127.0.0.1:8200\"}\n";
        fs::write(&state_path, plaintext_state).expect("write state");
        let in_memory = vec!["memory-key".to_string()];
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");

        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _log = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, &args_log);

        let transition = OpenBaoTlsTransition {
            probe_attempts: PROBE_ATTEMPTS,
            probe_delay: PROBE_DELAY,
            ..OpenBaoTlsTransition::new(&compose, &override_path, UNREACHABLE_HTTPS_URL, dir.path())
        };
        let mut recreated = false;
        // See `no_available_source_fails_before_any_docker_call` for why
        // this drives the future with `block_on`.
        let err = runtime
            .block_on(transition.run(
                &inputs(&in_memory, None, dir.path().join("unseal-keys.txt"), false),
                &mut recreated,
                &test_messages(),
            ))
            .expect_err("nothing is listening on the probed URL");

        assert!(
            recreated,
            "the container was recreated, so rollback must undo it"
        );
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains(UNREACHABLE_HTTPS_URL),
            "the probe failure must name the URL it targeted: {rendered}"
        );
        let log = fs::read_to_string(&args_log).expect("docker must have been called");
        assert!(
            log.contains("--force-recreate"),
            "the recreate must not depend on a compose delta: {log}"
        );
        assert_eq!(
            fs::read_to_string(&state_path).expect("state"),
            plaintext_state,
            "state.json must still carry the pre-TLS plaintext URL"
        );
    }
}
