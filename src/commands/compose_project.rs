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
use std::process::Command as ProcessCommand;

use anyhow::Result;

use crate::commands::compose_file::compose_file_dir;
use crate::commands::container_name::BootrootContainer;
pub(crate) use crate::commands::container_name::LONGEST_CONTAINER_NAME_SUFFIX;
use crate::commands::dotenv::read_dotenv;
use crate::i18n::Messages;

/// The executable every Docker invocation runs.
const DOCKER_BIN: &str = "docker";

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

/// The identity a compose-driving command operates under.
///
/// It carries two values that are equal only by default and must not be
/// confused: the Compose *project* (`-p`), which an exported
/// `COMPOSE_PROJECT_NAME` overrides for a single invocation, and the
/// recorded *instance name*, which every container bootroot creates is
/// named after.  Resolving them together is what keeps a call site from
/// reaching for the `project` already in scope where the container
/// identity is meant — the E2E harness exports project names that are
/// longer than an instance name may be and would produce oversized,
/// non-DNS-safe container names.
#[derive(Debug, Clone)]
pub(crate) struct ComposeIdentity {
    project: String,
    instance_name: String,
}

impl ComposeIdentity {
    /// Resolves both halves of the identity for a compose directory.
    pub(crate) fn resolve_for_dir(
        compose_dir: &Path,
        instance_name: Option<&str>,
        messages: &Messages,
    ) -> Result<Self> {
        Ok(Self {
            project: resolve_compose_project_for_dir(compose_dir, instance_name, messages)?,
            instance_name: resolve_recorded_instance_name(compose_dir, instance_name, messages)?,
        })
    }

    /// [`ComposeIdentity::resolve_for_dir`] for callers holding the
    /// compose file itself.
    pub(crate) fn resolve(
        compose_file: &Path,
        instance_name: Option<&str>,
        messages: &Messages,
    ) -> Result<Self> {
        Self::resolve_for_dir(&compose_file_dir(compose_file), instance_name, messages)
    }

    /// The Compose project every invocation is scoped to with `-p`.
    pub(crate) fn project(&self) -> &str {
        &self.project
    }

    /// Returns the name of one of bootroot's own containers under this
    /// identity.
    pub(crate) fn container(&self, container: BootrootContainer) -> String {
        container.name(&self.instance_name)
    }

    /// Builds a `docker compose` invocation under this identity.
    pub(crate) fn compose(
        &self,
        files: &[&str],
        profile: Option<&str>,
        subcommand: &[&str],
    ) -> ComposeInvocation {
        ComposeInvocation {
            args: compose_args(&self.project, files, profile, subcommand),
            instance_name: self.instance_name.clone(),
        }
    }
}

/// A `docker compose` invocation: the argument vector together with the
/// instance identity Compose has to see while it renders the file.
///
/// The two travel as one value on purpose.  `container_name:` in the
/// compose files is an interpolation of `BOOTROOT_INSTANCE`, and Compose
/// reads the invoking process's environment *ahead of* the project
/// directory's `.env`, so a vector spawned without the variable pinned
/// would silently adopt whatever the operator's shell exports — naming
/// another install's containers.  The argument vector is deliberately
/// not reachable from outside this module: [`ComposeInvocation::command`]
/// is the only way to turn one into something spawnable, and it always
/// sets the variable.
#[derive(Debug, Clone)]
pub(crate) struct ComposeInvocation {
    args: Vec<String>,
    instance_name: String,
}

impl ComposeInvocation {
    /// Builds the `docker` command for this invocation, pinning the
    /// instance identity in the child environment alongside `extra_env`.
    pub(crate) fn command(&self, extra_env: &[(&str, &str)]) -> ProcessCommand {
        let mut command = ProcessCommand::new(DOCKER_BIN);
        command.args(&self.args);
        command.env(INSTANCE_NAME_ENV_KEY, &self.instance_name);
        for (key, value) in extra_env {
            command.env(key, value);
        }
        command
    }
}

/// Builds a `docker compose` argument vector scoped to `project`.
///
/// The single constructor for every Compose invocation bootroot makes,
/// and private to this module so it can only be reached through
/// [`ComposeIdentity::compose`], which bundles the environment with it.
/// `-p` is emitted as a compose-level flag — after the `-f` and
/// `--profile` arguments, before the subcommand — because Compose only
/// accepts it there.  Building a vector by hand at a call site instead
/// would silently fall back to Compose's directory-derived default
/// project and operate on another install's containers and volumes.
fn compose_args(
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

    /// RAII guard restoring a process-global variable on drop, so a
    /// failing assertion cannot leave the shared environment mutated.
    pub(crate) struct ScopedEnv {
        key: &'static str,
        prior: Option<OsString>,
    }

    impl ScopedEnv {
        /// Sets (or clears) `key` for the duration of a test.  Callers
        /// must hold [`env_lock`].
        pub(crate) fn set(key: &'static str, value: Option<&str>) -> Self {
            let prior = std::env::var_os(key);
            match value {
                // SAFETY: every call site holds `env_lock()`.
                Some(value) => unsafe { std::env::set_var(key, value) },
                // SAFETY: as above.
                None => unsafe { std::env::remove_var(key) },
            }
            Self { key, prior }
        }
    }

    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            match self.prior.take() {
                // SAFETY: the caller still holds `env_lock()`.
                Some(prior) => unsafe { std::env::set_var(self.key, prior) },
                // SAFETY: as above.
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    /// [`ScopedEnv`] pinned to `COMPOSE_PROJECT_NAME`, the variable most
    /// of these tests scope.
    pub(crate) struct ComposeProjectEnv;

    impl ComposeProjectEnv {
        pub(crate) fn set(value: Option<&str>) -> ScopedEnv {
            ScopedEnv::set(COMPOSE_PROJECT_NAME_ENV, value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_env::{ComposeProjectEnv, ScopedEnv, env_lock};
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

        let identity =
            ComposeIdentity::resolve(&there.join("docker-compose.yml"), None, &test_messages())
                .unwrap();
        assert_eq!(identity.project(), "there-instance");
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

    /// Collects a built command's argument vector for assertions.
    fn command_args(command: &ProcessCommand) -> Vec<String> {
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    /// Collects a built command's explicitly set environment.
    fn command_envs(command: &ProcessCommand) -> Vec<(String, Option<String>)> {
        command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect()
    }

    /// `container_name:` in the compose files interpolates
    /// `BOOTROOT_INSTANCE`, so a spawned vector that does not carry it
    /// renders another install's container names.
    #[test]
    fn every_compose_command_carries_the_instance_environment() {
        let identity = ComposeIdentity {
            project: "bootroot-e2e-ci-openbao-tls-no-delta-1234567".to_string(),
            instance_name: "insight".to_string(),
        };
        for subcommand in [
            vec!["up", "-d"],
            vec!["pull", "--ignore-pull-failures"],
            vec!["ps", "-q", "openbao"],
            vec!["down", "-v", "--remove-orphans"],
        ] {
            let command = identity
                .compose(&["docker-compose.yml"], None, &subcommand)
                .command(&[]);
            assert_eq!(
                command_envs(&command),
                vec![(
                    INSTANCE_NAME_ENV_KEY.to_string(),
                    Some("insight".to_string())
                )],
                "{subcommand:?} must pin the recorded instance, not the project"
            );
        }
    }

    /// `infra install` adds host-port overrides and `monitoring up` adds
    /// `GRAFANA_ADMIN_PASSWORD`; neither may displace the instance.
    #[test]
    fn caller_supplied_environment_travels_alongside_the_instance() {
        let identity = ComposeIdentity {
            project: "insight".to_string(),
            instance_name: "insight".to_string(),
        };
        let command = identity
            .compose(&["docker-compose.yml"], Some("lan"), &["up", "-d"])
            .command(&[
                ("BOOTROOT_OPENBAO_HOST_PORT", "18200"),
                ("GRAFANA_ADMIN_PASSWORD", "secret"),
            ]);
        let envs = command_envs(&command);
        assert!(envs.contains(&(
            INSTANCE_NAME_ENV_KEY.to_string(),
            Some("insight".to_string())
        )));
        assert!(envs.contains(&(
            "BOOTROOT_OPENBAO_HOST_PORT".to_string(),
            Some("18200".to_string())
        )));
        assert!(envs.contains(&(
            "GRAFANA_ADMIN_PASSWORD".to_string(),
            Some("secret".to_string())
        )));
        assert!(command_args(&command).contains(&"--profile".to_string()));
    }

    /// The guard that makes the property above unbypassable: the
    /// invocation hands out no argument vector, so `command()` — the one
    /// method that sets the environment — is the only way to spawn one.
    /// A new accessor returning the args would let a call site build a
    /// compose vector and spawn it bare, which is exactly what this
    /// module exists to prevent.
    #[test]
    fn compose_invocation_exposes_only_the_command_builder() {
        let source = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join("commands")
                .join("compose_project.rs"),
        )
        .expect("this module must be readable");
        let start = source
            .find("impl ComposeInvocation {")
            .expect("the invocation impl block must exist");
        let block = source
            .get(start..)
            .and_then(|rest| rest.find("\n}").map(|end| rest.get(..end)))
            .flatten()
            .expect("the invocation impl block must be terminated");
        let methods: Vec<&str> = block
            .lines()
            .filter_map(|line| line.trim().strip_prefix("pub(crate) fn "))
            .filter_map(|rest| rest.split('(').next())
            .collect();
        assert_eq!(
            methods,
            vec!["command"],
            "`ComposeInvocation` must expose nothing but `command`, which is \
             what pins `{INSTANCE_NAME_ENV_KEY}`; found {methods:?}"
        );
    }

    /// An inherited `BOOTROOT_INSTANCE` must never reach Compose: it
    /// would outrank the compose directory's `.env` and rename the
    /// containers of the install being acted on.
    #[test]
    fn recorded_instance_overrides_an_inherited_variable() {
        let _guard = env_lock();
        let _project = ComposeProjectEnv::set(None);
        let _inherited = ScopedEnv::set(INSTANCE_NAME_ENV_KEY, Some("other"));
        let dir = tempfile::tempdir().unwrap();
        write_dotenv_with_instance(dir.path(), "insight");
        let identity =
            ComposeIdentity::resolve_for_dir(dir.path(), None, &test_messages()).unwrap();
        // The child value is set unconditionally, so the exported
        // `other` is replaced rather than inherited.
        let command = identity
            .compose(&["docker-compose.yml"], None, &["up", "-d"])
            .command(&[]);
        assert_eq!(
            command_envs(&command),
            vec![(
                INSTANCE_NAME_ENV_KEY.to_string(),
                Some("insight".to_string())
            )]
        );
        assert_eq!(
            identity.container(BootrootContainer::OpenBao),
            "insight-openbao"
        );
    }

    /// With an exported harness project the stack still has to come up
    /// as `bootroot-*` containers inside that project.
    #[test]
    fn long_compose_project_scopes_the_project_but_not_the_containers() {
        const HARNESS_PROJECT: &str = "bootroot-e2e-ci-openbao-tls-no-delta-1234567";
        let _guard = env_lock();
        let _env = ComposeProjectEnv::set(Some(HARNESS_PROJECT));
        let dir = tempfile::tempdir().unwrap();
        write_dotenv_with_instance(dir.path(), DEFAULT_INSTANCE_NAME);
        let identity =
            ComposeIdentity::resolve_for_dir(dir.path(), None, &test_messages()).unwrap();
        assert_eq!(identity.project(), HARNESS_PROJECT);
        assert_eq!(
            identity.container(BootrootContainer::OpenBao),
            "bootroot-openbao"
        );
        let command = identity
            .compose(&["docker-compose.yml"], None, &["up", "-d"])
            .command(&[]);
        assert!(command_args(&command).contains(&HARNESS_PROJECT.to_string()));
        assert_eq!(
            command_envs(&command),
            vec![(
                INSTANCE_NAME_ENV_KEY.to_string(),
                Some(DEFAULT_INSTANCE_NAME.to_string())
            )]
        );
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
