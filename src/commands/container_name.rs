//! Names of the containers bootroot itself creates.
//!
//! Container names are global to the Docker daemon, so a literal name
//! cannot be shared by two installs on one host.  Every container
//! bootroot creates is therefore named `<instance name><suffix>`, where
//! the instance name is the install identity recorded in the compose
//! directory's `.env` (see [`crate::commands::compose_project`]) and the
//! suffix is fixed per container.  The same string is also the
//! in-network DNS name and the certificate SAN, because inside the
//! compose network the container name is what resolves.
//!
//! Only containers bootroot creates belong here.  A reload hook naming a
//! container an operator supplied (`crate::commands::service::resolve`,
//! `src/bin/bootroot-remote/`) names one of the products bootroot
//! manages, not bootroot itself, and is passed through verbatim.

use std::path::Path;

use anyhow::Result;

use crate::commands::compose_file::compose_file_dir;
use crate::commands::compose_project::resolve_recorded_instance_name;
use crate::i18n::Messages;

/// A container bootroot creates and later addresses by name.
///
/// The seven compose services are pinned by `container_name:` in
/// `docker-compose.yml` / `docker-compose.deploy.yml`; the two `OpenBao`
/// Agent sidecars are pinned by the override `init` generates.  All nine
/// derive their name here, so the compose files and the code cannot
/// disagree about what a container is called.
// The set is deliberately complete rather than only the containers
// bootroot addresses by name today: the instance-name length limit and
// the compose-file agreement check in `init::constants` are both derived
// from it, so a container missing here would silently escape both.  The
// containers bootroot only ever reaches through Compose therefore have
// no production caller of their own.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootrootContainer {
    OpenBao,
    Postgres,
    StepCa,
    Http01,
    Prometheus,
    Grafana,
    GrafanaPublic,
    OpenBaoAgentStepCa,
    OpenBaoAgentResponder,
}

impl BootrootContainer {
    /// Every container bootroot creates.
    ///
    /// The instance-name length limit is derived from this set (see
    /// [`LONGEST_CONTAINER_NAME_SUFFIX`]), so a container added without
    /// being listed here would silently escape that derivation.
    // Consumed by the derivation tests rather than by a production call
    // site; see the note on the enum.
    #[allow(dead_code)]
    pub(crate) const ALL: [Self; 9] = [
        Self::OpenBao,
        Self::Postgres,
        Self::StepCa,
        Self::Http01,
        Self::Prometheus,
        Self::Grafana,
        Self::GrafanaPublic,
        Self::OpenBaoAgentStepCa,
        Self::OpenBaoAgentResponder,
    ];

    /// Returns the fixed part appended to the instance name.
    pub(crate) const fn suffix(self) -> &'static str {
        match self {
            Self::OpenBao => "-openbao",
            Self::Postgres => "-postgres",
            Self::StepCa => "-ca",
            Self::Http01 => "-http01",
            Self::Prometheus => "-prometheus",
            Self::Grafana => "-grafana",
            Self::GrafanaPublic => "-grafana-public",
            Self::OpenBaoAgentStepCa => "-openbao-agent-stepca",
            Self::OpenBaoAgentResponder => "-openbao-agent-responder",
        }
    }

    /// Returns this container's name for `instance_name`.
    pub(crate) fn name(self, instance_name: &str) -> String {
        format!("{instance_name}{}", self.suffix())
    }
}

/// Longest suffix any container name appends to the instance name.
///
/// The instance-name limit is derived from it: `<instance><suffix>`
/// serves as a DNS name on the compose network and as a certificate SAN,
/// so it has to fit a DNS label.
pub(crate) const LONGEST_CONTAINER_NAME_SUFFIX: &str =
    BootrootContainer::OpenBaoAgentResponder.suffix();

/// Resolves `container`'s name for the install the given compose file
/// belongs to.
///
/// For the paths that address a container by name and bypass Compose —
/// `reinit`'s scope check, the `rotate` sidecar restarts — this is what
/// keeps an action against one install from reaching another install's
/// containers.
///
/// The identity comes from [`resolve_recorded_instance_name`], never
/// from the Compose project: an exported `COMPOSE_PROJECT_NAME` selects
/// the project for one invocation and is not an identity, and the E2E
/// harness exports values that are not valid instance names at all.
pub(crate) fn resolve_container_name(
    compose_file: &Path,
    container: BootrootContainer,
    messages: &Messages,
) -> Result<String> {
    let instance_name =
        resolve_recorded_instance_name(&compose_file_dir(compose_file), None, messages)?;
    Ok(container.name(&instance_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::compose_project::{
        DEFAULT_INSTANCE_NAME, INSTANCE_NAME_ENV_KEY, test_env,
    };
    use crate::i18n::test_messages;

    /// The default identity has to keep rendering the `bootroot-*`
    /// literals the scripts, tests, docs and monitoring config still
    /// contain, so the default install needs no mechanical rename.
    #[test]
    fn default_instance_renders_the_historical_literals() {
        let names: Vec<String> = BootrootContainer::ALL
            .iter()
            .map(|container| container.name(DEFAULT_INSTANCE_NAME))
            .collect();
        assert_eq!(
            names,
            vec![
                "bootroot-openbao",
                "bootroot-postgres",
                "bootroot-ca",
                "bootroot-http01",
                "bootroot-prometheus",
                "bootroot-grafana",
                "bootroot-grafana-public",
                "bootroot-openbao-agent-stepca",
                "bootroot-openbao-agent-responder",
            ]
        );
    }

    #[test]
    fn non_default_instance_prefixes_every_container() {
        let names: Vec<String> = BootrootContainer::ALL
            .iter()
            .map(|container| container.name("insight"))
            .collect();
        assert_eq!(
            names,
            vec![
                "insight-openbao",
                "insight-postgres",
                "insight-ca",
                "insight-http01",
                "insight-prometheus",
                "insight-grafana",
                "insight-grafana-public",
                "insight-openbao-agent-stepca",
                "insight-openbao-agent-responder",
            ]
        );
    }

    /// The daemon-free proxy for the two-instance property: two installs
    /// can only coexist if no container name is shared between them.
    #[test]
    fn two_instances_share_no_container_name() {
        let first: Vec<String> = BootrootContainer::ALL
            .iter()
            .map(|container| container.name(DEFAULT_INSTANCE_NAME))
            .collect();
        let second: Vec<String> = BootrootContainer::ALL
            .iter()
            .map(|container| container.name("insight"))
            .collect();
        assert!(
            !first.iter().any(|name| second.contains(name)),
            "container names must be disjoint across instances: {first:?} vs {second:?}"
        );
    }

    #[test]
    fn suffixes_are_distinct() {
        let mut suffixes: Vec<&str> = BootrootContainer::ALL
            .iter()
            .map(|container| container.suffix())
            .collect();
        suffixes.sort_unstable();
        let count = suffixes.len();
        suffixes.dedup();
        assert_eq!(count, suffixes.len(), "two containers share a suffix");
    }

    #[test]
    fn longest_suffix_is_the_longest_declared_one() {
        let longest = BootrootContainer::ALL
            .iter()
            .map(|container| container.suffix().len())
            .max()
            .expect("the container set is never empty");
        assert_eq!(longest, LONGEST_CONTAINER_NAME_SUFFIX.len());
    }

    #[test]
    fn resolve_reads_the_identity_recorded_beside_the_compose_file() {
        let _guard = test_env::env_lock();
        let _env = test_env::ComposeProjectEnv::set(None);
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(".env"),
            format!("{INSTANCE_NAME_ENV_KEY}=insight\n"),
        )
        .expect("write .env");
        let name = resolve_container_name(
            &dir.path().join("docker-compose.yml"),
            BootrootContainer::OpenBao,
            &test_messages(),
        )
        .expect("resolving the container name must succeed");
        assert_eq!(name, "insight-openbao");
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

    /// `rotate` used to re-declare the two sidecar container names.  A
    /// second declaration is what let a rotation restart
    /// `bootroot-openbao-agent-*` on a non-default instance, so exactly
    /// one derivation may exist: this module's suffixes.
    ///
    /// Test assertions naming a concrete instance's sidecar (which is
    /// what a scoped name looks like) are allowed; a bare `bootroot-`
    /// sidecar literal anywhere in `src/` is not.
    #[test]
    fn no_second_declaration_of_the_sidecar_names_exists() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let this_file = src.join("commands").join("container_name.rs");
        let mut files = Vec::new();
        rust_sources(&src, &mut files);
        assert!(
            files.contains(&this_file),
            "the source walk must reach this module"
        );

        let needles = [
            format!(
                "{DEFAULT_INSTANCE_NAME}{}",
                BootrootContainer::OpenBaoAgentStepCa.suffix()
            ),
            format!(
                "{DEFAULT_INSTANCE_NAME}{}",
                BootrootContainer::OpenBaoAgentResponder.suffix()
            ),
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
            "the OpenBao Agent sidecar names must come from \
             `BootrootContainer`, which is what makes them follow the \
             install identity; found a literal at: {}",
            offenders.join(", ")
        );
    }

    /// A container name follows the recorded instance, never the
    /// Compose project: the E2E harness exports project names longer
    /// than an instance name may be.
    #[test]
    fn resolve_ignores_the_compose_project_override() {
        let _guard = test_env::env_lock();
        let _env =
            test_env::ComposeProjectEnv::set(Some("bootroot-e2e-ci-openbao-tls-no-delta-1234567"));
        let dir = tempfile::tempdir().expect("tempdir");
        let name = resolve_container_name(
            &dir.path().join("docker-compose.yml"),
            BootrootContainer::Http01,
            &test_messages(),
        )
        .expect("resolving the container name must succeed");
        assert_eq!(name, "bootroot-http01");
    }
}
