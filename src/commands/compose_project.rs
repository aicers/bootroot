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

/// The executable every Docker invocation runs when the caller names
/// none.
///
/// The only spelling of the literal the executable seam uses: the
/// spawn helpers default to it, and the context values production
/// builds start out holding it.  A spawn site never reads it — it
/// spawns whatever its caller supplied.
pub(crate) const DOCKER_BIN: &str = "docker";

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
///
/// The crate's single read of that variable.  Every resolver below takes
/// the value as a parameter, so the commands at the composition root
/// call this once and the resolvers stay steerable without the
/// process-global environment.
pub(crate) fn compose_project_name_override() -> Option<String> {
    std::env::var(COMPOSE_PROJECT_NAME_ENV)
        .ok()
        .filter(|value| !value.is_empty())
}

/// Resolves the Compose project every command must operate on, given the
/// directory of the compose file it was handed.
///
/// 1. `project_override` — what the invoking environment's
///    `COMPOSE_PROJECT_NAME` held, per
///    [`compose_project_name_override`].  Used verbatim and deliberately
///    not validated: the E2E harness's per-run project names are longer
///    than an instance name may be, and they must keep working;
/// 2. `instance_name` — the `--instance-name` value, which only
///    `infra install` can supply;
/// 3. `BOOTROOT_INSTANCE` from `<compose dir>/.env`;
/// 4. the literal [`DEFAULT_INSTANCE_NAME`].
///
/// The override outranks the declared identity because it is the only
/// rank that leaves an install and the commands run against it
/// afterwards in agreement.  Every later command resolves the project
/// from that same variable, so an install that ignored it created the
/// stack in one project while the whole shell it was run from addressed
/// another — a `clean` that removed nothing and a `status` that reported
/// on nothing.  The identity itself is untouched by it: the name every
/// container is called after comes from
/// [`resolve_recorded_instance_name`], which takes no override at all.
pub(crate) fn resolve_compose_project_for_dir(
    compose_dir: &Path,
    instance_name: Option<&str>,
    project_override: Option<&str>,
    messages: &Messages,
) -> Result<String> {
    if let Some(project) = project_override.filter(|value| !value.is_empty()) {
        return Ok(project.to_string());
    }
    if let Some(name) = instance_name {
        return Ok(name.to_string());
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
    /// The identity a named install takes with no project override in
    /// play.
    ///
    /// Both halves are that name: `--instance-name` outranks everything
    /// left once `COMPOSE_PROJECT_NAME` is out of the picture, so
    /// nothing is read from disk.  Infallible for the same reason, which
    /// is what lets the best-effort `init` rollback fall back to the
    /// default identity without a `Result` to handle.  A caller that may
    /// see an override wants
    /// [`ComposeIdentity::resolve_for_dir`] instead, which keeps the two
    /// halves apart.
    pub(crate) fn for_instance(name: &str) -> Self {
        Self {
            project: name.to_string(),
            instance_name: name.to_string(),
        }
    }

    /// Resolves both halves of the identity for a compose directory,
    /// reading `COMPOSE_PROJECT_NAME` from the invoking environment.
    ///
    /// The composition root for that variable: the resolvers underneath
    /// take it as a parameter.
    pub(crate) fn resolve_for_dir(
        compose_dir: &Path,
        instance_name: Option<&str>,
        messages: &Messages,
    ) -> Result<Self> {
        Self::resolve_for_dir_with_override(
            compose_dir,
            instance_name,
            compose_project_name_override().as_deref(),
            messages,
        )
    }

    /// [`ComposeIdentity::resolve_for_dir`] with the
    /// `COMPOSE_PROJECT_NAME` override supplied by the caller.
    fn resolve_for_dir_with_override(
        compose_dir: &Path,
        instance_name: Option<&str>,
        project_override: Option<&str>,
        messages: &Messages,
    ) -> Result<Self> {
        Ok(Self {
            project: resolve_compose_project_for_dir(
                compose_dir,
                instance_name,
                project_override,
                messages,
            )?,
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
        Self::resolve_with_override(
            compose_file,
            instance_name,
            compose_project_name_override().as_deref(),
            messages,
        )
    }

    /// [`ComposeIdentity::resolve`] with the `COMPOSE_PROJECT_NAME`
    /// override supplied by the caller.
    fn resolve_with_override(
        compose_file: &Path,
        instance_name: Option<&str>,
        project_override: Option<&str>,
        messages: &Messages,
    ) -> Result<Self> {
        Self::resolve_for_dir_with_override(
            &compose_file_dir(compose_file),
            instance_name,
            project_override,
            messages,
        )
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
    ///
    /// `extra_env` is applied *first* so that the instance pin is the
    /// last write and wins: `ProcessCommand::env` overwrites, so a
    /// caller that passed `BOOTROOT_INSTANCE` — by mistake, or by
    /// forwarding a variable set it did not filter — would otherwise
    /// rename this invocation's containers out from under the recorded
    /// identity.  The order is the enforcement; there is no other guard.
    pub(crate) fn command(&self, extra_env: &[(&str, &str)]) -> ProcessCommand {
        self.command_with_exec(extra_env, Path::new(DOCKER_BIN))
    }

    /// Builds the command for this invocation, spawning the executable
    /// `docker` names rather than whatever `PATH` resolves.
    ///
    /// The executable is the only thing that varies: `extra_env`, the
    /// argument vector and the instance pin behave exactly as they do
    /// in [`ComposeInvocation::command`], which is this function with
    /// the default supplied.
    pub(crate) fn command_with_exec(
        &self,
        extra_env: &[(&str, &str)],
        docker: &Path,
    ) -> ProcessCommand {
        let mut command = ProcessCommand::new(docker);
        command.args(&self.args);
        for (key, value) in extra_env {
            command.env(key, value);
        }
        command.env(INSTANCE_NAME_ENV_KEY, &self.instance_name);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::test_messages;

    fn write_dotenv_with_instance(dir: &Path, instance: &str) {
        std::fs::write(
            dir.join(".env"),
            format!("{INSTANCE_NAME_ENV_KEY}={instance}\n"),
        )
        .expect("write .env");
    }

    /// The compose spawn site runs whatever the caller named, and
    /// [`ComposeInvocation::command`] is that call with the default
    /// supplied — so the program the two build differs only by what was
    /// asked for, and nothing else about the invocation moves.
    #[test]
    fn compose_command_runs_the_supplied_executable() {
        let identity = ComposeIdentity::for_instance(DEFAULT_INSTANCE_NAME);
        let invocation = identity.compose(&["docker-compose.yml"], None, &["up", "-d"]);

        let default = invocation.command(&[]);
        assert_eq!(default.get_program(), "docker");

        let supplied = invocation.command_with_exec(&[], Path::new("/tmp/fake-docker"));
        assert_eq!(supplied.get_program(), "/tmp/fake-docker");
        assert_eq!(
            supplied.get_args().collect::<Vec<_>>(),
            default.get_args().collect::<Vec<_>>(),
            "only the executable may differ from the default path"
        );
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

    /// The override outranks the declared identity for the project, and
    /// reaches the recorded identity not at all.  Ranking them the other
    /// way round is what used to leave an install in a project the shell
    /// that ran it never addressed again.
    ///
    /// The E2E lifecycle harness depends on this ranking: it declares a
    /// length-bounded `--instance-name` and exports a separately derived
    /// project, and a resolver that put the flag first would install
    /// into one project while the harness scoped its own `docker
    /// compose` calls to another.  `scripts/validate-e2e-run-scope.sh`
    /// asserts this test still exists for that reason.
    #[test]
    fn compose_project_name_wins_over_the_flag_for_the_project_only() {
        let dir = tempfile::tempdir().unwrap();
        write_dotenv_with_instance(dir.path(), "recorded");
        let identity = ComposeIdentity::resolve_for_dir_with_override(
            dir.path(),
            Some("flag"),
            Some("env-project"),
            &test_messages(),
        )
        .unwrap();
        assert_eq!(identity.project(), "env-project");
        assert_eq!(
            identity.container(BootrootContainer::OpenBao),
            "flag-openbao"
        );
    }

    /// Without an override the declared identity is both halves, which
    /// is [`ComposeIdentity::for_instance`] — and the two paths must not
    /// drift apart.
    #[test]
    fn the_flag_alone_is_both_halves() {
        let dir = tempfile::tempdir().unwrap();
        write_dotenv_with_instance(dir.path(), "recorded");
        for project_override in [None, Some("")] {
            let identity = ComposeIdentity::resolve_for_dir_with_override(
                dir.path(),
                Some("flag"),
                project_override,
                &test_messages(),
            )
            .unwrap();
            assert_eq!(identity.project(), "flag");
            assert_eq!(
                identity.container(BootrootContainer::OpenBao),
                ComposeIdentity::for_instance("flag").container(BootrootContainer::OpenBao)
            );
        }
    }

    /// The E2E harness's shape: an install declares a length-bounded
    /// instance and exports a project derived separately from the same
    /// run identifier, longer than an instance name may legally be.
    /// Both must survive the install intact.
    #[test]
    fn a_declared_instance_and_a_longer_exported_project_stay_separate() {
        const RUN_PROJECT: &str = "bootroot-e2e-local-no-hosts-18446744073709551615-99999";
        const RUN_INSTANCE: &str = "e2e-local-nohosts18446744073709551615";
        let messages = test_messages();
        assert!(RUN_PROJECT.len() > MAX_INSTANCE_NAME_LEN);
        validate_instance_name(RUN_INSTANCE, &messages)
            .expect("the derived instance must be legal");
        let dir = tempfile::tempdir().unwrap();
        let identity = ComposeIdentity::resolve_for_dir_with_override(
            dir.path(),
            Some(RUN_INSTANCE),
            Some(RUN_PROJECT),
            &messages,
        )
        .unwrap();
        assert_eq!(identity.project(), RUN_PROJECT);
        assert_eq!(
            identity.container(BootrootContainer::OpenBaoAgentResponder),
            format!("{RUN_INSTANCE}-openbao-agent-responder")
        );
        let command = identity
            .compose(&["docker-compose.yml"], None, &["up", "-d"])
            .command(&[]);
        assert!(command_args(&command).contains(&RUN_PROJECT.to_string()));
        assert_eq!(
            command_envs(&command),
            vec![(
                INSTANCE_NAME_ENV_KEY.to_string(),
                Some(RUN_INSTANCE.to_string())
            )]
        );
    }

    #[test]
    fn compose_project_name_wins_over_dotenv() {
        let dir = tempfile::tempdir().unwrap();
        write_dotenv_with_instance(dir.path(), "recorded");
        let project = resolve_compose_project_for_dir(
            dir.path(),
            None,
            Some("env-project"),
            &test_messages(),
        )
        .unwrap();
        assert_eq!(project, "env-project");
    }

    #[test]
    fn dotenv_wins_over_the_default() {
        let dir = tempfile::tempdir().unwrap();
        write_dotenv_with_instance(dir.path(), "recorded");
        let project =
            resolve_compose_project_for_dir(dir.path(), None, None, &test_messages()).unwrap();
        assert_eq!(project, "recorded");
    }

    /// The fallback is a fixed literal, not the directory basename: an
    /// install must land in the same project however its directory is
    /// named.
    #[test]
    fn default_is_the_fixed_literal_regardless_of_directory_name() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("clumit-insight");
        std::fs::create_dir(&dir).unwrap();
        let project = resolve_compose_project_for_dir(&dir, None, None, &test_messages()).unwrap();
        assert_eq!(project, DEFAULT_INSTANCE_NAME);
    }

    /// `COMPOSE_PROJECT_NAME=` is how a shell clears the variable for
    /// one command, so an empty value has to fall through exactly as an
    /// absent one does — both at the read
    /// ([`compose_project_name_override`]) and at the resolver, which
    /// is reachable with a value the read never filtered.
    #[test]
    fn empty_compose_project_name_is_treated_as_unset() {
        let dir = tempfile::tempdir().unwrap();
        write_dotenv_with_instance(dir.path(), "recorded");
        let project =
            resolve_compose_project_for_dir(dir.path(), None, Some(""), &test_messages()).unwrap();
        assert_eq!(project, "recorded");
    }

    /// The E2E harness exports project names longer than an instance name
    /// may be; the override is a Compose feature, not an identity, so it
    /// is used verbatim without validation.
    #[test]
    fn compose_project_name_is_not_validated_as_an_instance_name() {
        const HARNESS_PROJECT: &str = "bootroot-e2e-ci-openbao-tls-no-delta-1234567";
        let messages = test_messages();
        assert!(HARNESS_PROJECT.len() > MAX_INSTANCE_NAME_LEN);
        assert!(validate_instance_name(HARNESS_PROJECT, &messages).is_err());
        let dir = tempfile::tempdir().unwrap();
        let project =
            resolve_compose_project_for_dir(dir.path(), None, Some(HARNESS_PROJECT), &messages)
                .unwrap();
        assert_eq!(project, HARNESS_PROJECT);
    }

    /// The resolver must read the `.env` beside the compose file it was
    /// handed, not one in the process working directory — a `clean`
    /// pointed at another install's compose file would otherwise wipe the
    /// wrong project's volumes.
    #[test]
    fn resolver_reads_the_dotenv_beside_the_given_compose_file() {
        let root = tempfile::tempdir().unwrap();
        let here = root.path().join("here");
        let there = root.path().join("there");
        std::fs::create_dir(&here).unwrap();
        std::fs::create_dir(&there).unwrap();
        write_dotenv_with_instance(&here, "here-instance");
        write_dotenv_with_instance(&there, "there-instance");

        let identity = ComposeIdentity::resolve_with_override(
            &there.join("docker-compose.yml"),
            None,
            None,
            &test_messages(),
        )
        .unwrap();
        assert_eq!(identity.project(), "there-instance");
    }

    /// The recorded identity must ignore `COMPOSE_PROJECT_NAME`: a
    /// throwaway harness project must not become the install's identity.
    #[test]
    fn recorded_identity_ignores_compose_project_name() {
        const HARNESS_PROJECT: &str = "bootroot-e2e-ci-reinit-42";
        let messages = test_messages();
        let dir = tempfile::tempdir().unwrap();
        // The contrast is the point: the same override that decides the
        // project has no way into the recorded identity, because
        // `resolve_recorded_instance_name` does not take one.
        assert_eq!(
            resolve_compose_project_for_dir(dir.path(), None, Some(HARNESS_PROJECT), &messages)
                .unwrap(),
            HARNESS_PROJECT
        );
        let recorded = resolve_recorded_instance_name(dir.path(), None, &messages).unwrap();
        assert_eq!(recorded, DEFAULT_INSTANCE_NAME);
    }

    #[test]
    fn recorded_identity_preserves_the_existing_value_without_the_flag() {
        let dir = tempfile::tempdir().unwrap();
        write_dotenv_with_instance(dir.path(), "insight");
        let recorded = resolve_recorded_instance_name(dir.path(), None, &test_messages()).unwrap();
        assert_eq!(recorded, "insight");
    }

    #[test]
    fn recorded_identity_takes_the_flag_over_the_existing_value() {
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

    /// `extra_env` must not be able to rename the invocation's
    /// containers.  A caller passing `BOOTROOT_INSTANCE` — by mistake or
    /// by forwarding an unfiltered variable set — would otherwise
    /// silently address another install, which is the whole failure this
    /// seam exists to close.
    #[test]
    fn caller_supplied_environment_cannot_displace_the_instance() {
        let identity = ComposeIdentity {
            project: "insight".to_string(),
            instance_name: "insight".to_string(),
        };
        let command = identity
            .compose(&["docker-compose.yml"], None, &["up", "-d"])
            .command(&[
                (INSTANCE_NAME_ENV_KEY, "other"),
                ("GRAFANA_ADMIN_PASSWORD", "secret"),
            ]);
        let envs = command_envs(&command);
        assert!(
            envs.contains(&(
                INSTANCE_NAME_ENV_KEY.to_string(),
                Some("insight".to_string())
            )),
            "the recorded instance must survive a caller-supplied override: {envs:?}"
        );
        assert!(
            !envs.contains(&(INSTANCE_NAME_ENV_KEY.to_string(), Some("other".to_string()))),
            "the caller's instance value must not reach the child: {envs:?}"
        );
        assert!(envs.contains(&(
            "GRAFANA_ADMIN_PASSWORD".to_string(),
            Some("secret".to_string())
        )));
    }

    /// The guard that makes the property above unbypassable: the
    /// invocation hands out no argument vector, so the command builders
    /// — the only methods that set the environment — are the only way to
    /// spawn one.  A new accessor returning the args would let a call
    /// site build a compose vector and spawn it bare, which is exactly
    /// what this module exists to prevent.
    ///
    /// `command_with_exec` is on the list because it is the same builder
    /// with the executable named; `command` delegates to it, so the
    /// instance pin is applied once, in one place, on both paths.
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
        // Any visibility wider than private counts: `pub(super)` and
        // `pub(crate)` reach a call site just as well as `pub`, so
        // matching one spelling would leave the other a way out.  A
        // private helper is not a way out and is allowed.
        let methods: Vec<&str> = block
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("pub"))
            .filter_map(|line| line.split_once(" fn "))
            .filter_map(|(_, rest)| rest.split('(').next())
            .collect();
        assert_eq!(
            methods,
            vec!["command", "command_with_exec"],
            "`ComposeInvocation` must expose nothing but its command \
             builders, which are what pin `{INSTANCE_NAME_ENV_KEY}`; \
             found {methods:?}"
        );
    }

    /// An inherited `BOOTROOT_INSTANCE` must never reach Compose: it
    /// would outrank the compose directory's `.env` and rename the
    /// containers of the install being acted on.
    ///
    /// What closes that is unconditional: `command()` sets the variable
    /// on every invocation it builds, so whatever the invoking
    /// environment exported is replaced rather than inherited.  The
    /// assertion is therefore on the child environment the builder
    /// declares, which is the only thing the ambient value could have
    /// competed with.
    #[test]
    fn recorded_instance_overrides_an_inherited_variable() {
        let dir = tempfile::tempdir().unwrap();
        write_dotenv_with_instance(dir.path(), "insight");
        let identity = ComposeIdentity::resolve_for_dir_with_override(
            dir.path(),
            None,
            None,
            &test_messages(),
        )
        .unwrap();
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
        let dir = tempfile::tempdir().unwrap();
        write_dotenv_with_instance(dir.path(), DEFAULT_INSTANCE_NAME);
        let identity = ComposeIdentity::resolve_for_dir_with_override(
            dir.path(),
            None,
            Some(HARNESS_PROJECT),
            &test_messages(),
        )
        .unwrap();
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
