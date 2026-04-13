use std::path::{Path, PathBuf};

use anyhow::Result;
use bootroot::input_validation::{
    ValidationError, validate_dns_label, validate_domain_name, validate_numeric_instance_id,
};

use crate::cli::args::{HookFailurePolicyArg, ReloadStyle, ServiceAddArgs};
use crate::cli::prompt::Prompt;
use crate::commands::constants::DEFAULT_SECRET_ID_WRAP_TTL;
use crate::commands::openbao_auth::{
    RuntimeAuthResolved, resolve_runtime_auth, resolve_runtime_auth_optional,
};
use crate::i18n::Messages;
use crate::state::{
    DEFAULT_HOOK_TIMEOUT_SECS, DeliveryMode, DeployType, HookFailurePolicyEntry, PostRenewHookEntry,
};

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
    pub(crate) post_renew_hooks: Vec<PostRenewHookEntry>,
    pub(crate) secret_id_ttl: Option<String>,
    pub(crate) secret_id_wrap_ttl: Option<String>,
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

    let post_renew_hooks = resolve_post_renew_hooks(args)?;

    let secret_id_wrap_ttl = if args.no_wrap {
        Some("0".to_string())
    } else {
        args.secret_id_wrap_ttl.clone()
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
        post_renew_hooks,
        secret_id_ttl: args.secret_id_ttl.clone(),
        secret_id_wrap_ttl,
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

/// Resolves the effective wrap TTL from the stored `Option`.
///
/// - `None` → default (`"30m"`)
/// - `Some("0")` → wrapping disabled → returns `None`
/// - `Some(ttl)` → explicit override
pub(crate) fn effective_wrap_ttl(stored: Option<&str>) -> Option<&str> {
    match stored {
        None => Some(DEFAULT_SECRET_ID_WRAP_TTL),
        Some("0") => None,
        Some(ttl) => Some(ttl),
    }
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

fn resolve_post_renew_hooks(args: &ServiceAddArgs) -> Result<Vec<PostRenewHookEntry>> {
    let has_preset = args.reload_style.is_some();
    let has_low_level = args.post_renew_command.is_some()
        || !args.post_renew_arg.is_empty()
        || args.post_renew_timeout_secs.is_some()
        || args.post_renew_on_failure.is_some();

    if has_preset && has_low_level {
        anyhow::bail!(
            "--reload-style and --post-renew-* flags are mutually exclusive; use one or the other"
        );
    }

    if let Some(style) = args.reload_style {
        return resolve_reload_preset(style, args.reload_target.as_deref());
    }

    if let Some(command) = args.post_renew_command.as_deref() {
        if command.trim().is_empty() {
            anyhow::bail!("--post-renew-command must not be empty");
        }
        let timeout = args
            .post_renew_timeout_secs
            .unwrap_or(DEFAULT_HOOK_TIMEOUT_SECS);
        if timeout == 0 {
            anyhow::bail!("--post-renew-timeout-secs must be greater than 0");
        }
        let on_failure = args.post_renew_on_failure.map_or(
            HookFailurePolicyEntry::default(),
            HookFailurePolicyArg::into_entry,
        );
        return Ok(vec![PostRenewHookEntry {
            command: command.to_string(),
            args: args.post_renew_arg.clone(),
            timeout_secs: timeout,
            on_failure,
        }]);
    }

    if args.reload_target.is_some() {
        anyhow::bail!("--reload-target requires --reload-style");
    }
    if !args.post_renew_arg.is_empty()
        || args.post_renew_timeout_secs.is_some()
        || args.post_renew_on_failure.is_some()
    {
        anyhow::bail!(
            "--post-renew-arg, --post-renew-timeout-secs, and --post-renew-on-failure require --post-renew-command"
        );
    }

    Ok(Vec::new())
}

fn resolve_reload_preset(
    style: ReloadStyle,
    target: Option<&str>,
) -> Result<Vec<PostRenewHookEntry>> {
    match style {
        ReloadStyle::None => Ok(Vec::new()),
        ReloadStyle::Systemd => {
            let unit = target.ok_or_else(|| {
                anyhow::anyhow!("--reload-style systemd requires --reload-target <unit-name>")
            })?;
            Ok(vec![PostRenewHookEntry {
                command: "systemctl".to_string(),
                args: vec!["reload".to_string(), unit.to_string()],
                timeout_secs: DEFAULT_HOOK_TIMEOUT_SECS,
                on_failure: HookFailurePolicyEntry::default(),
            }])
        }
        ReloadStyle::Sighup => {
            let name = target.ok_or_else(|| {
                anyhow::anyhow!("--reload-style sighup requires --reload-target <process-name>")
            })?;
            Ok(vec![PostRenewHookEntry {
                command: "pkill".to_string(),
                args: vec!["-HUP".to_string(), name.to_string()],
                timeout_secs: DEFAULT_HOOK_TIMEOUT_SECS,
                on_failure: HookFailurePolicyEntry::default(),
            }])
        }
        ReloadStyle::DockerRestart => {
            let container = target.ok_or_else(|| {
                anyhow::anyhow!(
                    "--reload-style docker-restart requires --reload-target <container-name>"
                )
            })?;
            Ok(vec![PostRenewHookEntry {
                command: "docker".to_string(),
                args: vec!["restart".to_string(), container.to_string()],
                timeout_secs: DEFAULT_HOOK_TIMEOUT_SECS,
                on_failure: HookFailurePolicyEntry::default(),
            }])
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::{AuthMode, RuntimeAuthArgs};

    fn empty_args() -> ServiceAddArgs {
        ServiceAddArgs {
            service_name: None,
            deploy_type: None,
            delivery_mode: None,
            dry_run: false,
            print_only: false,
            hostname: None,
            domain: None,
            agent_config: None,
            cert_path: None,
            key_path: None,
            instance_id: None,
            container_name: None,
            runtime_auth: RuntimeAuthArgs {
                auth_mode: AuthMode::Auto,
                root_token: None,
                approle_role_id: None,
                approle_secret_id: None,
                approle_role_id_file: None,
                approle_secret_id_file: None,
            },
            notes: None,
            reload_style: None,
            reload_target: None,
            post_renew_command: None,
            post_renew_arg: Vec::new(),
            post_renew_timeout_secs: None,
            post_renew_on_failure: None,
            secret_id_ttl: None,
            secret_id_wrap_ttl: None,
            no_wrap: false,
        }
    }

    #[test]
    fn resolve_hooks_no_flags_returns_empty() {
        let args = empty_args();
        let hooks = resolve_post_renew_hooks(&args).unwrap();
        assert!(hooks.is_empty());
    }

    #[test]
    fn resolve_hooks_preset_and_low_level_command_are_mutually_exclusive() {
        let mut args = empty_args();
        args.reload_style = Some(ReloadStyle::Systemd);
        args.reload_target = Some("nginx".to_string());
        args.post_renew_command = Some("systemctl".to_string());

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("mutually exclusive"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_preset_and_low_level_timeout_are_mutually_exclusive() {
        let mut args = empty_args();
        args.reload_style = Some(ReloadStyle::Systemd);
        args.reload_target = Some("nginx".to_string());
        args.post_renew_timeout_secs = Some(60);

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("mutually exclusive"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_preset_and_low_level_on_failure_are_mutually_exclusive() {
        let mut args = empty_args();
        args.reload_style = Some(ReloadStyle::Systemd);
        args.reload_target = Some("nginx".to_string());
        args.post_renew_on_failure = Some(HookFailurePolicyArg::Stop);

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("mutually exclusive"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_preset_and_low_level_arg_are_mutually_exclusive() {
        let mut args = empty_args();
        args.reload_style = Some(ReloadStyle::None);
        args.post_renew_arg = vec!["reload".to_string()];

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("mutually exclusive"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_reload_target_without_style_errors() {
        let mut args = empty_args();
        args.reload_target = Some("nginx".to_string());

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("--reload-target requires"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_systemd_preset_expands_correctly() {
        let mut args = empty_args();
        args.reload_style = Some(ReloadStyle::Systemd);
        args.reload_target = Some("nginx".to_string());

        let hooks = resolve_post_renew_hooks(&args).unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].command, "systemctl");
        assert_eq!(hooks[0].args, vec!["reload", "nginx"]);
        assert_eq!(hooks[0].timeout_secs, DEFAULT_HOOK_TIMEOUT_SECS);
        assert_eq!(hooks[0].on_failure, HookFailurePolicyEntry::Continue);
    }

    #[test]
    fn resolve_hooks_sighup_preset_expands_correctly() {
        let mut args = empty_args();
        args.reload_style = Some(ReloadStyle::Sighup);
        args.reload_target = Some("myproc".to_string());

        let hooks = resolve_post_renew_hooks(&args).unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].command, "pkill");
        assert_eq!(hooks[0].args, vec!["-HUP", "myproc"]);
    }

    #[test]
    fn resolve_hooks_docker_restart_preset_expands_correctly() {
        let mut args = empty_args();
        args.reload_style = Some(ReloadStyle::DockerRestart);
        args.reload_target = Some("my-ctr".to_string());

        let hooks = resolve_post_renew_hooks(&args).unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].command, "docker");
        assert_eq!(hooks[0].args, vec!["restart", "my-ctr"]);
    }

    #[test]
    fn resolve_hooks_none_preset_returns_empty() {
        let mut args = empty_args();
        args.reload_style = Some(ReloadStyle::None);

        let hooks = resolve_post_renew_hooks(&args).unwrap();
        assert!(hooks.is_empty());
    }

    #[test]
    fn resolve_hooks_systemd_without_target_errors() {
        let mut args = empty_args();
        args.reload_style = Some(ReloadStyle::Systemd);

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("--reload-target"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_low_level_with_defaults() {
        let mut args = empty_args();
        args.post_renew_command = Some("/usr/bin/reload.sh".to_string());

        let hooks = resolve_post_renew_hooks(&args).unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].command, "/usr/bin/reload.sh");
        assert!(hooks[0].args.is_empty());
        assert_eq!(hooks[0].timeout_secs, DEFAULT_HOOK_TIMEOUT_SECS);
        assert_eq!(hooks[0].on_failure, HookFailurePolicyEntry::Continue);
    }

    #[test]
    fn resolve_hooks_low_level_with_all_overrides() {
        let mut args = empty_args();
        args.post_renew_command = Some("systemctl".to_string());
        args.post_renew_arg = vec!["reload".to_string(), "nginx".to_string()];
        args.post_renew_timeout_secs = Some(60);
        args.post_renew_on_failure = Some(HookFailurePolicyArg::Stop);

        let hooks = resolve_post_renew_hooks(&args).unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].command, "systemctl");
        assert_eq!(hooks[0].args, vec!["reload", "nginx"]);
        assert_eq!(hooks[0].timeout_secs, 60);
        assert_eq!(hooks[0].on_failure, HookFailurePolicyEntry::Stop);
    }

    #[test]
    fn resolve_hooks_empty_command_is_rejected() {
        let mut args = empty_args();
        args.post_renew_command = Some(String::new());

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_whitespace_only_command_is_rejected() {
        let mut args = empty_args();
        args.post_renew_command = Some("   ".to_string());

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_zero_timeout_is_rejected() {
        let mut args = empty_args();
        args.post_renew_command = Some("reload.sh".to_string());
        args.post_renew_timeout_secs = Some(0);

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("greater than 0"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_post_renew_arg_without_command_errors() {
        let mut args = empty_args();
        args.post_renew_arg = vec!["reload".to_string()];

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("--post-renew-command"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_post_renew_timeout_without_command_errors() {
        let mut args = empty_args();
        args.post_renew_timeout_secs = Some(60);

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("--post-renew-command"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_hooks_post_renew_on_failure_without_command_errors() {
        let mut args = empty_args();
        args.post_renew_on_failure = Some(HookFailurePolicyArg::Stop);

        let err = resolve_post_renew_hooks(&args).unwrap_err();
        assert!(
            err.to_string().contains("--post-renew-command"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn effective_wrap_ttl_none_returns_default() {
        assert_eq!(effective_wrap_ttl(None), Some("30m"));
    }

    #[test]
    fn effective_wrap_ttl_custom_returns_custom() {
        assert_eq!(effective_wrap_ttl(Some("10m")), Some("10m"));
    }

    #[test]
    fn effective_wrap_ttl_zero_disables_wrapping() {
        assert_eq!(effective_wrap_ttl(Some("0")), None);
    }
}
