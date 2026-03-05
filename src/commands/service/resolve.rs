use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::cli::args::ServiceAddArgs;
use crate::cli::prompt::Prompt;
use crate::commands::openbao_auth::{
    RuntimeAuthResolved, resolve_runtime_auth, resolve_runtime_auth_optional,
};
use crate::i18n::Messages;
use crate::state::{DeliveryMode, DeployType};

#[derive(Debug)]
pub(crate) struct ResolvedServiceAdd {
    pub(crate) service_name: String,
    pub(crate) deploy_type: DeployType,
    pub(crate) delivery_mode: DeliveryMode,
    pub(crate) hostname: String,
    pub(crate) domain: String,
    pub(crate) agent_config: PathBuf,
    pub(crate) cert_path: PathBuf,
    pub(crate) key_path: PathBuf,
    pub(crate) instance_id: Option<String>,
    pub(crate) container_name: Option<String>,
    pub(crate) runtime_auth: Option<RuntimeAuthResolved>,
    pub(crate) notes: Option<String>,
}

pub(super) fn resolve_service_add_args(
    args: &ServiceAddArgs,
    messages: &Messages,
    preview: bool,
) -> Result<ResolvedServiceAdd> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let mut prompt = Prompt::new(&mut input, &mut output, messages);

    let service_name = match &args.service_name {
        Some(value) => value.clone(),
        None => prompt.prompt_with_validation(messages.prompt_service_name(), None, |value| {
            ensure_non_empty(value, messages)
        })?,
    };

    let deploy_type = match args.deploy_type {
        Some(value) => value,
        None => prompt.prompt_with_validation(
            messages.prompt_deploy_type(),
            Some("daemon"),
            |value| parse_deploy_type(value, messages),
        )?,
    };
    let delivery_mode = args.delivery_mode.unwrap_or_default();

    let hostname = match &args.hostname {
        Some(value) => value.clone(),
        None => prompt.prompt_with_validation(messages.prompt_hostname(), None, |value| {
            ensure_non_empty(value, messages)
        })?,
    };

    let domain = match &args.domain {
        Some(value) => value.clone(),
        None => prompt.prompt_with_validation(messages.prompt_domain(), None, |value| {
            ensure_non_empty(value, messages)
        })?,
    };

    let agent_config = resolve_path(
        args.agent_config.clone(),
        messages.prompt_agent_config(),
        &mut prompt,
        false,
        messages,
    )?;

    let cert_path = resolve_path(
        args.cert_path.clone(),
        messages.prompt_cert_path(),
        &mut prompt,
        false,
        messages,
    )?;

    let key_path = resolve_path(
        args.key_path.clone(),
        messages.prompt_key_path(),
        &mut prompt,
        false,
        messages,
    )?;

    let instance_id = match &args.instance_id {
        Some(value) => value.clone(),
        None => prompt.prompt_with_validation(messages.prompt_instance_id(), None, |value| {
            ensure_non_empty(value, messages)
        })?,
    };
    let container_name = match deploy_type {
        DeployType::Daemon => None,
        DeployType::Docker => Some(match &args.container_name {
            Some(value) => value.clone(),
            None => {
                prompt.prompt_with_validation(messages.prompt_container_name(), None, |value| {
                    ensure_non_empty(value, messages)
                })?
            }
        }),
    };

    let runtime_auth = if preview {
        resolve_runtime_auth_optional(&args.runtime_auth)?
    } else {
        Some(resolve_runtime_auth(&args.runtime_auth, true, messages)?)
    };

    Ok(ResolvedServiceAdd {
        service_name,
        deploy_type,
        delivery_mode,
        hostname,
        domain,
        agent_config,
        cert_path,
        key_path,
        instance_id: Some(instance_id),
        container_name,
        runtime_auth,
        notes: args.notes.clone(),
    })
}

pub(super) fn validate_service_add(args: &ResolvedServiceAdd, messages: &Messages) -> Result<()> {
    if args.service_name.trim().is_empty() {
        anyhow::bail!(messages.error_value_required());
    }
    if args.hostname.trim().is_empty() {
        anyhow::bail!(messages.error_value_required());
    }
    if args.domain.trim().is_empty() {
        anyhow::bail!(messages.error_value_required());
    }
    if args.instance_id.as_deref().unwrap_or_default().is_empty() {
        anyhow::bail!(messages.error_service_instance_id_required());
    }
    if matches!(args.deploy_type, DeployType::Docker)
        && args
            .container_name
            .as_deref()
            .unwrap_or_default()
            .is_empty()
    {
        anyhow::bail!(messages.error_service_container_name_required());
    }
    Ok(())
}

fn ensure_non_empty(value: &str, messages: &Messages) -> Result<String> {
    if value.trim().is_empty() {
        anyhow::bail!(messages.error_value_required());
    }
    Ok(value.trim().to_string())
}

fn parse_deploy_type(value: &str, messages: &Messages) -> Result<DeployType> {
    match value.trim().to_ascii_lowercase().as_str() {
        "daemon" => Ok(DeployType::Daemon),
        "docker" => Ok(DeployType::Docker),
        _ => anyhow::bail!(messages.error_invalid_deploy_type()),
    }
}

fn resolve_path(
    value: Option<PathBuf>,
    label: &str,
    prompt: &mut Prompt<'_>,
    must_exist: bool,
    messages: &Messages,
) -> Result<PathBuf> {
    let path = match value {
        Some(path) => path,
        None => prompt.prompt_with_validation(label, None, |input| {
            let candidate = PathBuf::from(input);
            validate_path(&candidate, must_exist, messages)?;
            Ok(candidate)
        })?,
    };
    validate_path(&path, must_exist, messages)?;
    Ok(path)
}

fn validate_path(path: &Path, must_exist: bool, messages: &Messages) -> Result<()> {
    if must_exist && !path.exists() {
        anyhow::bail!(messages.error_path_not_found(&path.display().to_string()));
    }
    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!(messages.error_parent_not_found(&path.display().to_string()))
    })?;
    if !parent.as_os_str().is_empty() && !parent.exists() {
        anyhow::bail!(messages.error_parent_not_found(&parent.display().to_string()));
    }
    Ok(())
}
