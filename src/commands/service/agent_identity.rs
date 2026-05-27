use std::process::Command as ProcessCommand;

use anyhow::{Context, Result};

use crate::i18n::Messages;

/// Docker container label whose value identifies a bootroot-agent
/// container. The docker-compose snippet shipped by bootroot sets
/// `bootroot.role: "agent"` so that `service add --deploy-type=docker`
/// can confirm `--container-name` actually points at an agent without
/// relying on fragile cmdline parsing.
pub(super) const BOOTROOT_AGENT_LABEL_KEY: &str = "bootroot.role";
pub(super) const BOOTROOT_AGENT_LABEL_VALUE: &str = "agent";

/// Substring searched in the container image, entrypoint, and cmdline
/// when the identifying label is missing. Pre-existing deployments
/// rendered before the label landed still surface here as long as the
/// binary keeps its `bootroot-agent` name.
const BOOTROOT_AGENT_BINARY_HINT: &str = "bootroot-agent";

/// Outcome of inspecting a container for the bootroot-agent identity.
pub(super) enum AgentIdentity {
    /// The container looks like a bootroot-agent.
    Match,
    /// `docker inspect` succeeded but no signal matched.
    NoMatch,
    /// `docker inspect` could not be executed or returned an error.
    InspectFailed(String),
}

/// Classifies whether `container` looks like a bootroot-agent by
/// shelling out to `docker inspect`. Label-first; falls back to the
/// `bootroot-agent` substring in the image / entrypoint / cmd.
pub(super) fn classify_agent_container(container: &str) -> AgentIdentity {
    classify_with_inspect(container, &inspect_via_docker)
}

fn classify_with_inspect<F>(container: &str, inspect: &F) -> AgentIdentity
where
    F: Fn(&str) -> Result<DockerInspect>,
{
    match inspect(container) {
        Ok(info) => {
            if info.label_matches(BOOTROOT_AGENT_LABEL_VALUE) {
                return AgentIdentity::Match;
            }
            if info.cmdline_or_image_contains(BOOTROOT_AGENT_BINARY_HINT) {
                return AgentIdentity::Match;
            }
            AgentIdentity::NoMatch
        }
        Err(err) => AgentIdentity::InspectFailed(err.to_string()),
    }
}

#[derive(Debug, Default)]
pub(super) struct DockerInspect {
    pub(super) label: Option<String>,
    pub(super) image: String,
    pub(super) entrypoint: String,
    pub(super) cmd: String,
}

impl DockerInspect {
    fn label_matches(&self, expected: &str) -> bool {
        self.label
            .as_deref()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case(expected))
    }

    fn cmdline_or_image_contains(&self, needle: &str) -> bool {
        self.image.contains(needle) || self.entrypoint.contains(needle) || self.cmd.contains(needle)
    }
}

/// Renders a one-line warning for `print_service_add_identity_warning`
/// when classification did not produce a clean match.
pub(super) fn render_warning(
    identity: &AgentIdentity,
    container: &str,
    messages: &Messages,
) -> Option<String> {
    match identity {
        AgentIdentity::Match => None,
        AgentIdentity::NoMatch => Some(messages.warn_service_docker_agent_unidentified(container)),
        AgentIdentity::InspectFailed(details) => {
            Some(messages.warn_service_docker_agent_inspect_failed(container, details))
        }
    }
}

fn inspect_via_docker(container: &str) -> Result<DockerInspect> {
    // `docker inspect --format` with one combined Go template keeps the
    // call to a single subprocess. Each field is separated by `\x1f`
    // (unit separator) so embedded whitespace in image names or
    // entrypoints does not split the output.
    let label_key = BOOTROOT_AGENT_LABEL_KEY;
    let format_arg = format!(
        "{{{{index .Config.Labels \"{label_key}\"}}}}\x1f{{{{.Config.Image}}}}\x1f{{{{join .Config.Entrypoint \" \"}}}}\x1f{{{{join .Config.Cmd \" \"}}}}",
    );
    let output = ProcessCommand::new("docker")
        .args(["inspect", "--format", &format_arg, container])
        .output()
        .with_context(|| "failed to run `docker inspect`")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        anyhow::bail!(if stderr.is_empty() {
            "`docker inspect` failed".to_string()
        } else {
            stderr
        });
    }
    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let mut parts = raw.split('\x1f');
    let label_raw = parts.next().unwrap_or_default().trim().to_string();
    let image = parts.next().unwrap_or_default().trim().to_string();
    let entrypoint = parts.next().unwrap_or_default().trim().to_string();
    let cmd = parts.next().unwrap_or_default().trim().to_string();
    let label = if label_raw.is_empty() || label_raw == "<no value>" {
        None
    } else {
        Some(label_raw)
    };
    Ok(DockerInspect {
        label,
        image,
        entrypoint,
        cmd,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inspect_with(info: DockerInspect) -> impl Fn(&str) -> Result<DockerInspect> {
        move |_| {
            Ok(DockerInspect {
                label: info.label.clone(),
                image: info.image.clone(),
                entrypoint: info.entrypoint.clone(),
                cmd: info.cmd.clone(),
            })
        }
    }

    #[test]
    fn label_match_short_circuits() {
        let info = DockerInspect {
            label: Some("agent".to_string()),
            image: "nginx".to_string(),
            entrypoint: "/docker-entrypoint.sh".to_string(),
            cmd: "nginx -g daemon off;".to_string(),
        };
        let identity = classify_with_inspect("bootroot-agent", &inspect_with(info));
        assert!(matches!(identity, AgentIdentity::Match));
    }

    #[test]
    fn label_match_ignores_case() {
        let info = DockerInspect {
            label: Some(" AGENT ".to_string()),
            ..DockerInspect::default()
        };
        let identity = classify_with_inspect("bootroot-agent", &inspect_with(info));
        assert!(matches!(identity, AgentIdentity::Match));
    }

    #[test]
    fn image_fallback_matches_on_substring() {
        let info = DockerInspect {
            label: None,
            image: "ghcr.io/aicers/bootroot-agent:latest".to_string(),
            entrypoint: "/app/whatever".to_string(),
            cmd: String::new(),
        };
        let identity = classify_with_inspect("svc", &inspect_with(info));
        assert!(matches!(identity, AgentIdentity::Match));
    }

    #[test]
    fn entrypoint_fallback_matches_on_substring() {
        let info = DockerInspect {
            label: None,
            image: "debian:bookworm-slim".to_string(),
            entrypoint: "./bootroot-agent".to_string(),
            cmd: String::new(),
        };
        let identity = classify_with_inspect("svc", &inspect_with(info));
        assert!(matches!(identity, AgentIdentity::Match));
    }

    #[test]
    fn cmd_fallback_matches_on_substring() {
        let info = DockerInspect {
            label: None,
            image: "alpine".to_string(),
            entrypoint: "/bin/sh".to_string(),
            cmd: "-c exec /app/bootroot-agent --config=/etc/agent.toml".to_string(),
        };
        let identity = classify_with_inspect("svc", &inspect_with(info));
        assert!(matches!(identity, AgentIdentity::Match));
    }

    #[test]
    fn no_match_when_no_signal_present() {
        let info = DockerInspect {
            label: None,
            image: "nginx:1.27".to_string(),
            entrypoint: "/docker-entrypoint.sh".to_string(),
            cmd: "nginx -g daemon off;".to_string(),
        };
        let identity = classify_with_inspect("web-app", &inspect_with(info));
        assert!(matches!(identity, AgentIdentity::NoMatch));
    }

    #[test]
    fn inspect_failure_surfaces_details() {
        let inspect =
            |_: &str| -> Result<DockerInspect> { anyhow::bail!("no such object: web-app") };
        let identity = classify_with_inspect("web-app", &inspect);
        match identity {
            AgentIdentity::InspectFailed(msg) => assert!(msg.contains("no such object")),
            _ => panic!("expected InspectFailed"),
        }
    }
}
