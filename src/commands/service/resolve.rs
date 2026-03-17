use std::path::{Path, PathBuf};

use anyhow::Result;
use bootroot::input_validation::{
    ValidationError, validate_dns_label, validate_domain_name, validate_numeric_instance_id,
};

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
        Some(value) => validate_service_name(value, messages)?,
        None => prompt.prompt_with_validation(messages.prompt_service_name(), None, |value| {
            validate_service_name(value, messages)
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
        Some(value) => validate_hostname(value, messages)?,
        None => prompt.prompt_with_validation(messages.prompt_hostname(), None, |value| {
            validate_hostname(value, messages)
        })?,
    };

    let domain = match &args.domain {
        Some(value) => validate_domain(value, messages)?,
        None => prompt.prompt_with_validation(messages.prompt_domain(), None, |value| {
            validate_domain(value, messages)
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
        Some(value) => validate_instance_id(value, messages)?,
        None => prompt.prompt_with_validation(messages.prompt_instance_id(), None, |value| {
            validate_instance_id(value, messages)
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
    validate_service_name(&args.service_name, messages)?;
    validate_hostname(&args.hostname, messages)?;
    validate_domain(&args.domain, messages)?;
    validate_instance_id(args.instance_id.as_deref().unwrap_or_default(), messages)?;
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

fn validate_service_name(value: &str, messages: &Messages) -> Result<String> {
    validate_dns_label(value).map_err(|err| service_name_error(err, messages))?;
    Ok(value.to_string())
}

fn validate_hostname(value: &str, messages: &Messages) -> Result<String> {
    validate_dns_label(value).map_err(|err| hostname_error(err, messages))?;
    Ok(value.to_string())
}

fn validate_domain(value: &str, messages: &Messages) -> Result<String> {
    validate_domain_name(value).map_err(|err| domain_error(err, messages))?;
    Ok(value.to_string())
}

fn validate_instance_id(value: &str, messages: &Messages) -> Result<String> {
    validate_numeric_instance_id(value).map_err(|err| instance_id_error(err, messages))?;
    Ok(value.to_string())
}

fn service_name_error(err: ValidationError, messages: &Messages) -> anyhow::Error {
    match err {
        ValidationError::Empty => anyhow::anyhow!(messages.error_value_required()),
        ValidationError::InvalidDnsLabel
        | ValidationError::InvalidDomainName
        | ValidationError::NonNumeric => anyhow::anyhow!(messages.error_service_name_invalid()),
    }
}

fn hostname_error(err: ValidationError, messages: &Messages) -> anyhow::Error {
    match err {
        ValidationError::Empty => anyhow::anyhow!(messages.error_value_required()),
        ValidationError::InvalidDnsLabel
        | ValidationError::InvalidDomainName
        | ValidationError::NonNumeric => anyhow::anyhow!(messages.error_hostname_invalid()),
    }
}

fn domain_error(err: ValidationError, messages: &Messages) -> anyhow::Error {
    match err {
        ValidationError::Empty => anyhow::anyhow!(messages.error_value_required()),
        ValidationError::InvalidDnsLabel
        | ValidationError::InvalidDomainName
        | ValidationError::NonNumeric => anyhow::anyhow!(messages.error_domain_invalid()),
    }
}

fn instance_id_error(err: ValidationError, messages: &Messages) -> anyhow::Error {
    match err {
        ValidationError::Empty => anyhow::anyhow!(messages.error_service_instance_id_required()),
        ValidationError::InvalidDnsLabel
        | ValidationError::InvalidDomainName
        | ValidationError::NonNumeric => anyhow::anyhow!(messages.error_instance_id_invalid()),
    }
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
