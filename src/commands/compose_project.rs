//! The install identity and the `docker compose` project it selects.
//!
//! Two bootroot installs on one host used to land in the same Compose
//! project — Compose derives the default project name from the compose
//! file's directory basename, and both installs are conventionally called
//! `bootroot` — so the second one adopted the first's volumes.  An install
//! now declares an identity (`infra install --instance-name`), records it
//! in the compose directory's `.env`, and every `docker compose`
//! invocation is scoped to it with an explicit `-p`.

use std::path::Path;

use anyhow::Result;

use crate::commands::compose_file::compose_file_dir;
use crate::commands::dotenv::read_dotenv;
use crate::i18n::Messages;

/// The `docker` subcommand every Compose invocation starts with.
///
/// Declared here — and only here — so that
/// `every_compose_vector_is_built_by_the_shared_constructor` can assert
/// the literal appears nowhere else in the tree: a hand-built vector at
/// any one call site would silently lose the `-p` scoping.
pub(crate) const DOCKER_COMPOSE_SUBCOMMAND: &str = "compose";

/// `.env` key recording the install's instance identity.
pub(crate) const INSTANCE_NAME_ENV_KEY: &str = "BOOTROOT_INSTANCE";

/// Compose's own per-invocation project-name override.  It is a Compose
/// feature, not a second identity: it is used verbatim, is never
/// validated against the instance-name rules, and is never recorded.
pub(crate) const COMPOSE_PROJECT_NAME_ENV: &str = "COMPOSE_PROJECT_NAME";

/// Identity an install takes when it declares none.
///
/// A fixed literal rather than the compose directory's basename, so the
/// identity is a property of the install and not of where it happens to
/// sit: renaming the directory or checking the tree out elsewhere would
/// otherwise silently orphan the previous project's volumes.
pub(crate) const DEFAULT_INSTANCE_NAME: &str = "bootroot";

/// Longest DNS label, in octets (RFC 1035).
pub(crate) const DNS_LABEL_LIMIT: usize = 63;

/// Longest suffix appended to the instance name when container names are
/// made to follow the identity: `bootroot-openbao-agent-responder` minus
/// the `bootroot` prefix.
pub(crate) const LONGEST_CONTAINER_NAME_SUFFIX: &str = "-openbao-agent-responder";

/// Maximum instance-name length.
///
/// Derived, not chosen: the name becomes a prefix on container names,
/// which serve as DNS names on the compose network and as certificate
/// SANs, so `<name><suffix>` must fit a DNS label.
pub(crate) const MAX_INSTANCE_NAME_LEN: usize =
    DNS_LABEL_LIMIT - LONGEST_CONTAINER_NAME_SUFFIX.len();

/// Validates an `--instance-name` value.
///
/// Accepts lowercase ASCII letters, digits and `-`, starting with a
/// letter or digit, up to [`MAX_INSTANCE_NAME_LEN`] characters.  Rejects
/// anything else rather than silently normalising it, so an operator who
/// mistypes an identity learns of it before the install creates a project
/// under a name they did not ask for.
pub(crate) fn validate_instance_name(name: &str, messages: &Messages) -> Result<()> {
    let valid_charset = name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    let valid_first = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    if !valid_charset || !valid_first || name.len() > MAX_INSTANCE_NAME_LEN {
        anyhow::bail!(messages.error_instance_name_invalid(name, MAX_INSTANCE_NAME_LEN));
    }
    Ok(())
}

/// Reads `BOOTROOT_INSTANCE` from the `.env` beside the compose file.
///
/// Returns `Ok(None)` when the file is absent or records no (non-empty)
/// value; a malformed `.env` surfaces as an error rather than being
/// silently treated as "no identity", which would target the default
/// project instead of the recorded one.
fn recorded_instance_name(compose_dir: &Path, messages: &Messages) -> Result<Option<String>> {
    let env_path = compose_dir.join(".env");
    if !env_path.exists() {
        return Ok(None);
    }
    let entries = read_dotenv(&env_path, messages)?;
    Ok(entries
        .get(INSTANCE_NAME_ENV_KEY)
        .filter(|value| !value.is_empty())
        .cloned())
}

/// Returns `COMPOSE_PROJECT_NAME` from the invoking environment when it
/// is set and non-empty.
fn compose_project_name_override() -> Option<String> {
    std::env::var(COMPOSE_PROJECT_NAME_ENV)
        .ok()
        .filter(|value| !value.is_empty())
}

/// Resolves the Compose project every command must operate on, given the
/// directory of the compose file it was handed.
///
/// 1. `instance_name` — the `--instance-name` value, which only
///    `infra install` can supply;
/// 2. `COMPOSE_PROJECT_NAME` from the invoking environment, when
///    non-empty.  Used verbatim and deliberately not validated: the E2E
///    harness's per-run project names are longer than an instance name
///    may be, and they must keep working;
/// 3. `BOOTROOT_INSTANCE` from `<compose dir>/.env`;
/// 4. the literal [`DEFAULT_INSTANCE_NAME`].
pub(crate) fn resolve_compose_project_for_dir(
    compose_dir: &Path,
    instance_name: Option<&str>,
    messages: &Messages,
) -> Result<String> {
    if let Some(name) = instance_name {
        return Ok(name.to_string());
    }
    if let Some(project) = compose_project_name_override() {
        return Ok(project);
    }
    if let Some(recorded) = recorded_instance_name(compose_dir, messages)? {
        return Ok(recorded);
    }
    Ok(DEFAULT_INSTANCE_NAME.to_string())
}

/// [`resolve_compose_project_for_dir`] for callers holding the compose
/// file itself.  The `.env` consulted is always the one beside that file,
/// never one in the process working directory.
pub(crate) fn resolve_compose_project(
    compose_file: &Path,
    instance_name: Option<&str>,
    messages: &Messages,
) -> Result<String> {
    resolve_compose_project_for_dir(&compose_file_dir(compose_file), instance_name, messages)
}

/// Resolves the identity an `infra install` run must record in `.env`.
///
/// Deliberately ignores `COMPOSE_PROJECT_NAME`: that override selects the
/// project for a single invocation and is not an identity, so an install
/// run under one records the identity it would have had without it.  A
/// re-run without `--instance-name` keeps whatever the `.env` already
/// records instead of resetting it to the default.
pub(crate) fn resolve_recorded_instance_name(
    compose_dir: &Path,
    instance_name: Option<&str>,
    messages: &Messages,
) -> Result<String> {
    if let Some(name) = instance_name {
        return Ok(name.to_string());
    }
    if let Some(recorded) = recorded_instance_name(compose_dir, messages)? {
        return Ok(recorded);
    }
    Ok(DEFAULT_INSTANCE_NAME.to_string())
}

/// Builds a `docker compose` argument vector scoped to `project`.
///
/// The single constructor for every Compose invocation bootroot makes.
/// `-p` is emitted as a compose-level flag — after the `-f` and
/// `--profile` arguments, before the subcommand — because Compose only
/// accepts it there.  Building a vector by hand at a call site instead
/// would silently fall back to Compose's directory-derived default
/// project and operate on another install's containers and volumes.
pub(crate) fn compose_args(
    project: &str,
    files: &[&str],
    profile: Option<&str>,
    subcommand: &[&str],
) -> Vec<String> {
    let mut args = Vec::with_capacity(subcommand.len() + files.len() * 2 + 5);
    args.push(DOCKER_COMPOSE_SUBCOMMAND.to_string());
    for file in files {
        args.push("-f".to_string());
        args.push((*file).to_string());
    }
    if let Some(profile) = profile {
        args.push("--profile".to_string());
        args.push(profile.to_string());
    }
    args.push("-p".to_string());
    args.push(project.to_string());
    args.extend(subcommand.iter().map(|arg| (*arg).to_string()));
    args
}

/// Test-only helpers for the process-global `COMPOSE_PROJECT_NAME`.
///
/// One lock for the whole crate: the resolver is exercised from several
/// modules' tests, and a per-module mutex would let two of them mutate
/// the same process-global variable concurrently.
#[cfg(test)]
pub(crate) mod test_env {
    use std::ffi::OsString;
    use std::sync::{LazyLock, Mutex, MutexGuard};

    use super::COMPOSE_PROJECT_NAME_ENV;

    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    /// Serialises tests that mutate `COMPOSE_PROJECT_NAME`.
    ///
    /// A panicking test poisons the mutex; recovering the guard rather
    /// than propagating the poison keeps one failure from cascading into
    /// every other test that touches the variable.
    pub(crate) fn env_lock() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// RAII guard restoring `COMPOSE_PROJECT_NAME` on drop, so a failing
    /// assertion cannot leave the shared environment mutated.
    pub(crate) struct ComposeProjectEnv {
        prior: Option<OsString>,
    }

    impl ComposeProjectEnv {
        /// Sets (or clears) `COMPOSE_PROJECT_NAME` for the duration of a
        /// test.  Callers must hold [`env_lock`].
        pub(crate) fn set(value: Option<&str>) -> Self {
            let prior = std::env::var_os(COMPOSE_PROJECT_NAME_ENV);
            match value {
                // SAFETY: every call site holds `env_lock()`.
                Some(value) => unsafe { std::env::set_var(COMPOSE_PROJECT_NAME_ENV, value) },
                // SAFETY: as above.
                None => unsafe { std::env::remove_var(COMPOSE_PROJECT_NAME_ENV) },
            }
            Self { prior }
        }
    }

    impl Drop for ComposeProjectEnv {
        fn drop(&mut self) {
            match self.prior.take() {
                // SAFETY: the caller still holds `env_lock()`.
                Some(prior) => unsafe { std::env::set_var(COMPOSE_PROJECT_NAME_ENV, prior) },
                // SAFETY: as above.
                None => unsafe { std::env::remove_var(COMPOSE_PROJECT_NAME_ENV) },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_env::{ComposeProjectEnv, env_lock};
    use super::*;
    use crate::i18n::test_messages;

    fn write_dotenv_with_instance(dir: &Path, instance: &str) {
        std::fs::write(
            dir.join(".env"),
            format!("{INSTANCE_NAME_ENV_KEY}={instance}\n"),
        )
        .expect("write .env");
    }

    #[test]
    fn instance_name_accepts_the_documented_character_set() {
        let messages = test_messages();
        for name in ["bootroot", "insight", "a", "0", "a-b-c", "x9-7"] {
            validate_instance_name(name, &messages)
                .unwrap_or_else(|err| panic!("{name} must be accepted: {err}"));
        }
    }

    #[test]
    fn instance_name_rejects_invalid_values() {
        let messages = test_messages();
        for name in [
            "Insight",
            "in sight",
            "-insight",
            "insight_1",
            "in.sight",
            "",
        ] {
            assert!(
                validate_instance_name(name, &messages).is_err(),
                "{name:?} must be rejected"
            );
        }
    }

    #[test]
    fn instance_name_length_boundaries() {
        let messages = test_messages();
        let accepted = "a".repeat(MAX_INSTANCE_NAME_LEN);
        let rejected = "a".repeat(MAX_INSTANCE_NAME_LEN + 1);
        validate_instance_name(&accepted, &messages).expect("39 characters must be accepted");
        assert!(validate_instance_name(&rejected, &messages).is_err());
        assert_eq!(MAX_INSTANCE_NAME_LEN, 39);
    }

    /// The error has to tell an operator both halves of the rule; a bare
    /// "invalid name" leaves them guessing which one they broke.
    #[test]
    fn instance_name_error_names_the_charset_and_the_limit() {
        for locale in ["en", "ko"] {
            let messages = crate::i18n::Messages::new(locale).unwrap();
            let err = validate_instance_name("Insight", &messages)
                .unwrap_err()
                .to_string();
            assert!(err.contains("Insight"), "{locale}: {err}");
            assert!(err.contains("39"), "{locale}: {err}");
            assert!(!err.contains('{'), "{locale} left a placeholder: {err}");
        }
    }

    #[test]
    fn flag_wins_over_compose_project_name() {
        let _guard = env_lock();
        let _env = ComposeProjectEnv::set(Some("env-project"));
        let dir = tempfile::tempdir().unwrap();
        write_dotenv_with_instance(dir.path(), "recorded");
        let project =
            resolve_compose_project_for_dir(dir.path(), Some("flag"), &test_messages()).unwrap();
        assert_eq!(project, "flag");
    }

    #[test]
    fn compose_project_name_wins_over_dotenv() {
        let _guard = env_lock();
        let _env = ComposeProjectEnv::set(Some("env-project"));
        let dir = tempfile::tempdir().unwrap();
        write_dotenv_with_instance(dir.path(), "recorded");
        let project = resolve_compose_project_for_dir(dir.path(), None, &test_messages()).unwrap();
        assert_eq!(project, "env-project");
    }

    #[test]
    fn dotenv_wins_over_the_default() {
        let _guard = env_lock();
        let _env = ComposeProjectEnv::set(None);
        let dir = tempfile::tempdir().unwrap();
        write_dotenv_with_instance(dir.path(), "recorded");
        let project = resolve_compose_project_for_dir(dir.path(), None, &test_messages()).unwrap();
        assert_eq!(project, "recorded");
    }

    /// The fallback is a fixed literal, not the directory basename: an
    /// install must land in the same project however its directory is
    /// named.
    #[test]
    fn default_is_the_fixed_literal_regardless_of_directory_name() {
        let _guard = env_lock();
        let _env = ComposeProjectEnv::set(None);
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("clumit-insight");
        std::fs::create_dir(&dir).unwrap();
        let project = resolve_compose_project_for_dir(&dir, None, &test_messages()).unwrap();
        assert_eq!(project, DEFAULT_INSTANCE_NAME);
    }

    #[test]
    fn empty_compose_project_name_is_treated_as_unset() {
        let _guard = env_lock();
        let _env = ComposeProjectEnv::set(Some(""));
        let dir = tempfile::tempdir().unwrap();
        write_dotenv_with_instance(dir.path(), "recorded");
        let project = resolve_compose_project_for_dir(dir.path(), None, &test_messages()).unwrap();
        assert_eq!(project, "recorded");
    }

    /// The E2E harness exports project names longer than an instance name
    /// may be; the override is a Compose feature, not an identity, so it
    /// is used verbatim without validation.
    #[test]
    fn compose_project_name_is_not_validated_as_an_instance_name() {
        const HARNESS_PROJECT: &str = "bootroot-e2e-ci-openbao-tls-no-delta-1234567";
        let _guard = env_lock();
        let _env = ComposeProjectEnv::set(Some(HARNESS_PROJECT));
        let messages = test_messages();
        assert!(HARNESS_PROJECT.len() > MAX_INSTANCE_NAME_LEN);
        assert!(validate_instance_name(HARNESS_PROJECT, &messages).is_err());
        let dir = tempfile::tempdir().unwrap();
        let project = resolve_compose_project_for_dir(dir.path(), None, &messages).unwrap();
        assert_eq!(project, HARNESS_PROJECT);
    }

    /// The resolver must read the `.env` beside the compose file it was
    /// handed, not one in the process working directory — a `clean`
    /// pointed at another install's compose file would otherwise wipe the
    /// wrong project's volumes.
    #[test]
    fn resolver_reads_the_dotenv_beside_the_given_compose_file() {
        let _guard = env_lock();
        let _env = ComposeProjectEnv::set(None);
        let root = tempfile::tempdir().unwrap();
        let here = root.path().join("here");
        let there = root.path().join("there");
        std::fs::create_dir(&here).unwrap();
        std::fs::create_dir(&there).unwrap();
        write_dotenv_with_instance(&here, "here-instance");
        write_dotenv_with_instance(&there, "there-instance");

        let project =
            resolve_compose_project(&there.join("docker-compose.yml"), None, &test_messages())
                .unwrap();
        assert_eq!(project, "there-instance");
    }

    /// The recorded identity must ignore `COMPOSE_PROJECT_NAME`: a
    /// throwaway harness project must not become the install's identity.
    #[test]
    fn recorded_identity_ignores_compose_project_name() {
        let _guard = env_lock();
        let _env = ComposeProjectEnv::set(Some("bootroot-e2e-ci-reinit-42"));
        let dir = tempfile::tempdir().unwrap();
        let recorded = resolve_recorded_instance_name(dir.path(), None, &test_messages()).unwrap();
        assert_eq!(recorded, DEFAULT_INSTANCE_NAME);
    }

    #[test]
    fn recorded_identity_preserves_the_existing_value_without_the_flag() {
        let _guard = env_lock();
        let _env = ComposeProjectEnv::set(Some("bootroot-e2e-ci-reinit-42"));
        let dir = tempfile::tempdir().unwrap();
        write_dotenv_with_instance(dir.path(), "insight");
        let recorded = resolve_recorded_instance_name(dir.path(), None, &test_messages()).unwrap();
        assert_eq!(recorded, "insight");
    }

    #[test]
    fn recorded_identity_takes_the_flag_over_the_existing_value() {
        let _guard = env_lock();
        let _env = ComposeProjectEnv::set(None);
        let dir = tempfile::tempdir().unwrap();
        write_dotenv_with_instance(dir.path(), "insight");
        let recorded =
            resolve_recorded_instance_name(dir.path(), Some("security"), &test_messages()).unwrap();
        assert_eq!(recorded, "security");
    }

    /// Collects every `.rs` file under `src/`.
    fn rust_sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("src tree must be readable") {
            let path = entry.expect("directory entry must be readable").path();
            if path.is_dir() {
                rust_sources(&path, out);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    /// Every Compose invocation must come from [`compose_args`]: a
    /// hand-built vector loses the `-p` scoping silently and falls back
    /// to Compose's directory-derived default project, so it would
    /// operate on another install's containers and volumes.  The
    /// subcommand literal is therefore written once, in this module, and
    /// this test fails as soon as it reappears in argument position
    /// anywhere else.
    ///
    /// The needles are the two shapes an argument vector puts it in — a
    /// `&str` element (`"compose", "-f", …`) and an owned one
    /// (`"compose".to_string()`).  A bare `"compose"` elsewhere (a
    /// directory name in a fixture, a substring assertion on an error
    /// message) is not an invocation and is deliberately not matched.
    #[test]
    fn every_compose_vector_is_built_by_the_shared_constructor() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let this_file = src.join("commands").join("compose_project.rs");
        let mut files = Vec::new();
        rust_sources(&src, &mut files);
        assert!(
            files.contains(&this_file),
            "the source walk must reach this module"
        );

        let needles = [
            format!("\"{DOCKER_COMPOSE_SUBCOMMAND}\","),
            format!("\"{DOCKER_COMPOSE_SUBCOMMAND}\".to_string()"),
        ];
        let mut offenders = Vec::new();
        for file in files {
            if file == this_file {
                continue;
            }
            let contents = std::fs::read_to_string(&file).expect("source file must be readable");
            for (index, line) in contents.lines().enumerate() {
                if needles.iter().any(|needle| line.contains(needle.as_str())) {
                    offenders.push(format!("{}:{}", file.display(), index + 1));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "docker compose argument vectors must be built by \
             `compose_project::compose_args`, which is what emits `-p`; \
             found the subcommand literal in argument position at: {}",
            offenders.join(", ")
        );
    }

    /// The guard above is only worth having if it actually fires; pin
    /// that by running the same needles over a hand-built vector.
    #[test]
    fn the_constructor_guard_detects_a_hand_built_vector() {
        let hand_built = r#"    let args = ["compose", "-f", &compose_str, "up", "-d"];"#;
        let needle = format!("\"{DOCKER_COMPOSE_SUBCOMMAND}\",");
        assert!(hand_built.contains(needle.as_str()));
    }

    /// Representative of the vectors dispatched through
    /// `infra::run_docker_with_env` — `infra install`'s `up` and `pull`,
    /// `init`'s service restarts, `clean`'s `down`.
    #[test]
    fn constructor_emits_project_at_the_compose_flag_position() {
        let args = compose_args("insight", &["docker-compose.yml"], None, &["up", "-d"]);
        assert_eq!(
            args,
            vec![
                DOCKER_COMPOSE_SUBCOMMAND,
                "-f",
                "docker-compose.yml",
                "-p",
                "insight",
                "up",
                "-d",
            ]
        );
    }

    /// The readiness probe reaches Docker only through
    /// `infra::docker_compose_output`, so this is the vector that decides
    /// whether `status` reports on the project it was pointed at.
    #[test]
    fn constructor_scopes_the_readiness_probe_vector() {
        let args = compose_args(
            "insight",
            &["docker-compose.yml"],
            None,
            &["ps", "-q", "openbao"],
        );
        let flags: Vec<&String> = args.iter().take_while(|arg| arg.as_str() != "ps").collect();
        assert!(
            flags.iter().any(|arg| arg.as_str() == "-p"),
            "readiness probe lost its project scoping: {args:?}"
        );
        assert_eq!(args.last().map(String::as_str), Some("openbao"));
    }

    /// Representative of the vectors dispatched through the private
    /// `monitoring::run_docker_with_env`, which are the only ones
    /// carrying `--profile`: `-p` has to land after it and still before
    /// the subcommand.
    #[test]
    fn constructor_places_project_after_files_and_profile() {
        let args = compose_args(
            "insight",
            &["docker-compose.yml", "override.yml"],
            Some("lan"),
            &["ps", "-q", "grafana"],
        );
        assert_eq!(
            args,
            vec![
                DOCKER_COMPOSE_SUBCOMMAND,
                "-f",
                "docker-compose.yml",
                "-f",
                "override.yml",
                "--profile",
                "lan",
                "-p",
                "insight",
                "ps",
                "-q",
                "grafana",
            ]
        );
    }
}
