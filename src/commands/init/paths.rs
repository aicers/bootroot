use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::constants::DEFAULT_RESPONDER_ADMIN_URL;
use crate::cli::args::InitArgs;
use crate::i18n::Messages;

pub(crate) struct ResponderPaths {
    pub(crate) template_path: PathBuf,
    pub(crate) config_path: PathBuf,
}

pub(crate) struct StepCaTemplatePaths {
    pub(crate) password_template_path: PathBuf,
    pub(crate) ca_json_template_path: PathBuf,
}

pub(crate) struct OpenBaoAgentPaths {
    pub(crate) stepca_agent_config: PathBuf,
    pub(crate) responder_agent_config: PathBuf,
    pub(crate) compose_override_path: Option<PathBuf>,
}

pub(crate) fn to_container_path(
    secrets_dir: &Path,
    path: &Path,
    messages: &Messages,
) -> Result<String> {
    let relative = path
        .strip_prefix(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&path.display().to_string()))?;
    Ok(format!("/openbao/secrets/{}", relative.to_string_lossy()))
}

pub(crate) fn compose_has_responder(compose_file: &Path, messages: &Messages) -> Result<bool> {
    let compose_contents = std::fs::read_to_string(compose_file)
        .with_context(|| messages.error_read_file_failed(&compose_file.display().to_string()))?;
    Ok(compose_contents.contains("bootroot-http01"))
}

pub(crate) fn compose_has_openbao(compose_file: &Path, messages: &Messages) -> Result<bool> {
    let compose_contents = std::fs::read_to_string(compose_file)
        .with_context(|| messages.error_read_file_failed(&compose_file.display().to_string()))?;
    Ok(compose_contents.contains("openbao"))
}

pub(crate) fn resolve_responder_url(
    args: &InitArgs,
    compose_has_responder: bool,
) -> Option<String> {
    if let Some(responder_url) = args.responder_url.as_ref() {
        return Some(responder_url.clone());
    }
    if compose_has_responder {
        Some(DEFAULT_RESPONDER_ADMIN_URL.to_string())
    } else {
        None
    }
}

pub(crate) fn resolve_openbao_agent_addr(openbao_url: &str, compose_has_openbao: bool) -> String {
    if !compose_has_openbao {
        return openbao_url.to_string();
    }
    openbao_url
        .replace("localhost", "openbao")
        .replace("127.0.0.1", "openbao")
}
