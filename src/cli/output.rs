use crate::commands::init::{InitPlan, InitSummary};
use crate::i18n::{
    Messages, ServiceNextStepsDaemon, ServiceNextStepsDocker, ServiceOpenBaoAgentSteps,
};
use crate::state::{DeployType, ServiceEntry};

pub(crate) struct ServiceAddPlan<'a> {
    pub(crate) service_name: &'a str,
    pub(crate) deploy_type: DeployType,
    pub(crate) delivery_mode: crate::state::DeliveryMode,
    pub(crate) hostname: &'a str,
    pub(crate) domain: &'a str,
    pub(crate) agent_config: &'a str,
    pub(crate) cert_path: &'a str,
    pub(crate) key_path: &'a str,
    pub(crate) instance_id: Option<&'a str>,
    pub(crate) container_name: Option<&'a str>,
    pub(crate) notes: Option<&'a str>,
}

pub(crate) struct ServiceAddAppliedPaths<'a> {
    pub(crate) agent_config: &'a str,
    pub(crate) openbao_agent_config: &'a str,
    pub(crate) openbao_agent_template: &'a str,
}

pub(crate) struct ServiceAddRemoteBootstrap<'a> {
    pub(crate) bootstrap_file: &'a str,
    pub(crate) remote_run_command: &'a str,
    pub(crate) control_sync_command: &'a str,
}

pub(crate) struct ServiceAddSummaryOptions<'a> {
    pub(crate) applied: Option<ServiceAddAppliedPaths<'a>>,
    pub(crate) remote: Option<ServiceAddRemoteBootstrap<'a>>,
    pub(crate) trusted_ca_sha256: Option<&'a [String]>,
    pub(crate) show_snippets: bool,
    pub(crate) note: Option<String>,
}

pub(crate) fn print_init_summary(summary: &InitSummary, messages: &Messages) {
    print_init_header(summary, messages);
    print_init_secrets(summary, messages);
    print_responder_check(summary, messages);
    print_db_check(summary, messages);
    print_kv_paths(messages);
    print_approles(summary, messages);
    print_next_steps(summary, messages);
}

pub(crate) fn print_init_plan(plan: &InitPlan, messages: &Messages) {
    println!("{}", messages.init_plan_title());
    println!("{}", messages.summary_openbao_url(&plan.openbao_url));
    println!("{}", messages.summary_kv_mount(&plan.kv_mount));
    // codeql[rust/cleartext-logging]: output is a filesystem path, not a secret value.
    println!(
        "{}",
        messages.summary_secrets_dir(&plan.secrets_dir.display().to_string())
    );
    if plan.overwrite_password {
        // codeql[rust/cleartext-logging]: output is a non-secret overwrite prompt.
        println!("{}", messages.init_plan_overwrite_password());
    }
    if plan.overwrite_ca_json {
        // codeql[rust/cleartext-logging]: output is a non-secret overwrite prompt.
        println!("{}", messages.init_plan_overwrite_ca_json());
    }
    if plan.overwrite_state {
        println!("{}", messages.init_plan_overwrite_state());
    }
}

pub(crate) fn print_service_add_summary(
    entry: &ServiceEntry,
    secret_id_path: &std::path::Path,
    options: ServiceAddSummaryOptions<'_>,
    messages: &Messages,
) {
    println!("{}", messages.service_add_summary());
    print_service_fields(entry, messages);
    println!(
        "{}",
        messages.service_summary_policy(&entry.approle.policy_name)
    );
    println!(
        "{}",
        messages.service_summary_approle(&entry.approle.role_name)
    );
    println!("{}", messages.summary_role_id(&entry.approle.role_id));
    println!(
        "{}",
        messages.service_summary_secret_path(&secret_id_path.display().to_string())
    );
    println!(
        "{}",
        messages.service_summary_openbao_path(&entry.service_name)
    );
    if let Some(paths) = options.applied {
        print_local_apply_summary(&paths, messages);
    }
    if let Some(remote) = options.remote {
        print_remote_handoff_summary(&remote, &entry.service_name, messages);
    }
    if let Some(note) = options.note.as_deref() {
        println!("{note}");
    }
    if !options.show_snippets {
        return;
    }
    print_service_add_snippets(entry, secret_id_path, options.trusted_ca_sha256, messages);
}

fn print_local_apply_summary(paths: &ServiceAddAppliedPaths<'_>, messages: &Messages) {
    println!("{}", messages.service_scope_bootroot_managed());
    println!(
        "{}",
        messages.service_summary_auto_applied_agent_config(paths.agent_config)
    );
    println!(
        "{}",
        messages.service_summary_auto_applied_openbao_config(paths.openbao_agent_config)
    );
    println!(
        "{}",
        messages.service_summary_auto_applied_openbao_template(paths.openbao_agent_template)
    );
}

fn print_remote_handoff_summary(
    remote: &ServiceAddRemoteBootstrap<'_>,
    service_name: &str,
    messages: &Messages,
) {
    println!("{}", messages.service_scope_bootroot_managed());
    println!(
        "{}",
        messages.service_summary_remote_bootstrap_file(remote.bootstrap_file)
    );
    println!("{}", messages.service_scope_operator_required());
    println!(
        "{}",
        messages.service_summary_remote_run_command(remote.remote_run_command)
    );
    println!(
        "{}",
        messages.service_summary_remote_sync_command(remote.control_sync_command)
    );
    println!("{}", messages.service_summary_remote_handoff_title());
    println!(
        "{}",
        messages.service_summary_remote_handoff_service_host(remote.remote_run_command)
    );
    println!(
        "{}",
        messages.service_summary_remote_handoff_control_host(remote.control_sync_command)
    );
    println!("{}", messages.service_scope_operator_recommended());
    let status_check_command = format!("bootroot service info --service-name '{service_name}'");
    println!(
        "{}",
        messages.service_summary_remote_handoff_status_check(&status_check_command)
    );
}

fn print_service_add_snippets(
    entry: &ServiceEntry,
    secret_id_path: &std::path::Path,
    trusted_ca_sha256: Option<&[String]>,
    messages: &Messages,
) {
    println!("{}", messages.service_summary_next_steps());
    println!("{}", messages.service_scope_operator_required());
    print_service_openbao_agent_steps(entry, secret_id_path, messages);
    match entry.deploy_type {
        DeployType::Daemon => {
            let cert_path = entry.cert_path.display().to_string();
            let key_path = entry.key_path.display().to_string();
            let config_path = entry.agent_config_path.display().to_string();
            let data = ServiceNextStepsDaemon {
                service_name: &entry.service_name,
                instance_id: entry.instance_id.as_deref().unwrap_or_default(),
                hostname: &entry.hostname,
                domain: &entry.domain,
                cert_path: &cert_path,
                key_path: &key_path,
                config_path: &config_path,
            };
            println!("{}", messages.service_next_steps_daemon_profile(&data));
            print_daemon_snippet(entry, messages);
        }
        DeployType::Docker => {
            let cert_path = entry.cert_path.display().to_string();
            let key_path = entry.key_path.display().to_string();
            let config_path = entry.agent_config_path.display().to_string();
            let secret_id_path_value = secret_id_path.display().to_string();
            let data = ServiceNextStepsDocker {
                service_name: &entry.service_name,
                container_name: entry.container_name.as_deref().unwrap_or_default(),
                instance_id: entry.instance_id.as_deref().unwrap_or_default(),
                hostname: &entry.hostname,
                domain: &entry.domain,
                cert_path: &cert_path,
                key_path: &key_path,
                config_path: &config_path,
                role_name: &entry.approle.role_name,
                secret_id_path: &secret_id_path_value,
            };
            println!("{}", messages.service_next_steps_docker_sidecar(&data));
            print_docker_snippet(entry, messages);
        }
    }
    if let Some(trusted) = trusted_ca_sha256 {
        println!("{}", messages.service_scope_operator_optional());
        print_trust_snippet(entry, trusted, messages);
    }
}

pub(crate) fn print_service_add_plan(plan: &ServiceAddPlan<'_>, messages: &Messages) {
    println!("{}", messages.service_add_plan_title());
    print_service_plan_fields(plan, messages);
    println!(
        "{}",
        messages.service_summary_agent_config(plan.agent_config)
    );
    println!("{}", messages.service_summary_cert_path(plan.cert_path));
    println!("{}", messages.service_summary_key_path(plan.key_path));
}

pub(crate) fn print_service_info_summary(entry: &ServiceEntry, messages: &Messages) {
    println!("{}", messages.service_info_summary());
    print_service_fields(entry, messages);
    if let Some(instance_id) = entry.instance_id.as_deref() {
        println!("{}", messages.service_summary_instance_id(instance_id));
    }
    if let Some(container_name) = entry.container_name.as_deref() {
        println!(
            "{}",
            messages.service_summary_container_name(container_name)
        );
    }
    println!(
        "{}",
        messages.service_summary_policy(&entry.approle.policy_name)
    );
    println!(
        "{}",
        messages.service_summary_approle(&entry.approle.role_name)
    );
    println!("{}", messages.summary_role_id(&entry.approle.role_id));
    println!(
        "{}",
        messages.service_summary_openbao_path(&entry.service_name)
    );
    println!(
        "{}",
        messages.service_summary_agent_config(&entry.agent_config_path.display().to_string())
    );
    println!(
        "{}",
        messages.service_summary_cert_path(&entry.cert_path.display().to_string())
    );
    println!(
        "{}",
        messages.service_summary_key_path(&entry.key_path.display().to_string())
    );
    println!(
        "{}",
        messages.service_summary_secret_path(&entry.approle.secret_id_path.display().to_string())
    );
    println!("{}", messages.service_summary_next_steps());
    print_service_openbao_agent_steps(entry, &entry.approle.secret_id_path, messages);
}

fn print_service_fields(entry: &ServiceEntry, messages: &Messages) {
    println!("{}", messages.service_summary_kind(&entry.service_name));
    println!(
        "{}",
        messages.service_summary_deploy_type(match entry.deploy_type {
            DeployType::Daemon => "daemon",
            DeployType::Docker => "docker",
        })
    );
    println!("{}", messages.service_summary_hostname(&entry.hostname));
    println!("{}", messages.service_summary_domain(&entry.domain));
    println!(
        "{}",
        messages.service_summary_delivery_mode(entry.delivery_mode.as_str())
    );
    println!(
        "{}",
        messages.service_summary_sync_status("secret_id", entry.sync_status.secret_id.as_str())
    );
    println!(
        "{}",
        messages.service_summary_sync_status("eab", entry.sync_status.eab.as_str())
    );
    println!(
        "{}",
        messages.service_summary_sync_status(
            "responder_hmac",
            entry.sync_status.responder_hmac.as_str(),
        )
    );
    println!(
        "{}",
        messages.service_summary_sync_status("trust_sync", entry.sync_status.trust_sync.as_str())
    );
    if let Some(notes) = entry.notes.as_deref() {
        println!("{}", messages.service_summary_notes(notes));
    }
}

fn print_service_plan_fields(plan: &ServiceAddPlan<'_>, messages: &Messages) {
    println!("{}", messages.service_summary_kind(plan.service_name));
    println!(
        "{}",
        messages.service_summary_deploy_type(match plan.deploy_type {
            DeployType::Daemon => "daemon",
            DeployType::Docker => "docker",
        })
    );
    println!("{}", messages.service_summary_hostname(plan.hostname));
    println!("{}", messages.service_summary_domain(plan.domain));
    println!(
        "{}",
        messages.service_summary_delivery_mode(plan.delivery_mode.as_str())
    );
    if let Some(instance_id) = plan.instance_id {
        println!("{}", messages.service_summary_instance_id(instance_id));
    }
    if let Some(container_name) = plan.container_name {
        println!(
            "{}",
            messages.service_summary_container_name(container_name)
        );
    }
    if let Some(notes) = plan.notes {
        println!("{}", messages.service_summary_notes(notes));
    }
}

fn print_service_openbao_agent_steps(
    entry: &ServiceEntry,
    secret_id_path: &std::path::Path,
    messages: &Messages,
) {
    let service_dir = secret_id_path.parent().unwrap_or(std::path::Path::new("."));
    let role_id_path = service_dir.join("role_id");
    let secrets_dir = service_dir
        .parent()
        .and_then(|parent| parent.parent())
        .unwrap_or(std::path::Path::new("."));
    let openbao_agent_config = secrets_dir
        .join("openbao")
        .join("services")
        .join(&entry.service_name)
        .join("agent.hcl");
    let openbao_steps = ServiceOpenBaoAgentSteps {
        service_name: &entry.service_name,
        config_path: &openbao_agent_config.display().to_string(),
        role_id_path: &role_id_path.display().to_string(),
        secret_id_path: &secret_id_path.display().to_string(),
        service_dir: &service_dir.display().to_string(),
    };
    println!("{}", messages.service_next_steps_openbao_agent_title());
    println!(
        "{}",
        messages.service_next_steps_openbao_agent_config(&openbao_steps)
    );
    println!(
        "{}",
        messages.service_next_steps_openbao_agent_role_id_path(&openbao_steps)
    );
    println!(
        "{}",
        messages.service_next_steps_openbao_agent_secret_id_path(&openbao_steps)
    );
    println!(
        "{}",
        messages.service_next_steps_openbao_agent_permissions(&openbao_steps)
    );
    match entry.deploy_type {
        DeployType::Daemon => {
            println!(
                "{}",
                messages.service_next_steps_openbao_agent_daemon_run(&openbao_steps)
            );
        }
        DeployType::Docker => {
            println!(
                "{}",
                messages.service_next_steps_openbao_agent_docker_run(&openbao_steps)
            );
        }
    }
}

fn print_daemon_snippet(entry: &ServiceEntry, messages: &Messages) {
    let instance_id = entry.instance_id.as_deref().unwrap_or_default();
    println!("{}", messages.service_snippet_daemon_title());
    println!("[[profiles]]");
    println!(
        "service_name = \"{service_name}\"",
        service_name = entry.service_name
    );
    println!("instance_id = \"{instance_id}\"");
    println!("hostname = \"{hostname}\"", hostname = entry.hostname);
    println!(
        "paths.cert = \"{cert_path}\"",
        cert_path = entry.cert_path.display()
    );
    println!(
        "paths.key = \"{key_path}\"",
        key_path = entry.key_path.display()
    );
    println!("[profiles.daemon]");
    println!("check_interval = \"1h\"");
    println!("renew_before = \"720h\"");
    println!("check_jitter = \"0s\"");
    println!("{}", messages.service_snippet_domain_hint(&entry.domain));
}

fn print_docker_snippet(entry: &ServiceEntry, messages: &Messages) {
    let container = entry.container_name.as_deref().unwrap_or("bootroot-agent");
    let config_path = entry.agent_config_path.display();
    let cert_parent = entry
        .cert_path
        .parent()
        .unwrap_or(std::path::Path::new("."));
    println!("{}", messages.service_snippet_docker_title());
    println!("docker run --rm \\");
    println!("  --name {container} \\");
    println!("  -v {config_path}:/app/agent.toml:ro \\");
    // codeql[rust/cleartext-logging]: output is a filesystem path used in a run snippet.
    println!(
        "  -v {cert_dir}:/app/certs \\",
        cert_dir = cert_parent.display()
    );
    println!("  <bootroot-agent-image> \\");
    println!("  bootroot-agent --config /app/agent.toml --oneshot");
}

fn print_trust_snippet(entry: &ServiceEntry, trusted: &[String], messages: &Messages) {
    let cert_dir = entry
        .cert_path
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let bundle_path = cert_dir.join("ca-bundle.pem");
    println!("{}", messages.service_snippet_trust_title());
    println!("[trust]");
    println!("verify_certificates = true");
    println!("ca_bundle_path = \"{}\"", bundle_path.display());
    println!(
        "trusted_ca_sha256 = [{}]",
        trusted
            .iter()
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

pub(crate) fn print_verify_plan(
    service_name: &str,
    agent_config: &std::path::Path,
    messages: &Messages,
) {
    println!("{}", messages.verify_plan_title());
    println!("{}", messages.verify_service_name(service_name));
    println!(
        "{}",
        messages.verify_agent_config(&agent_config.display().to_string())
    );
}

fn print_init_header(summary: &InitSummary, messages: &Messages) {
    println!("{}", messages.summary_title());
    println!("{}", messages.summary_openbao_url(&summary.openbao_url));
    println!("{}", messages.summary_kv_mount(&summary.kv_mount));
    // codeql[rust/cleartext-logging]: output is a filesystem path, not a secret value.
    println!(
        "{}",
        messages.summary_secrets_dir(&summary.secrets_dir.display().to_string())
    );
    match summary.step_ca_result {
        crate::commands::init::StepCaInitResult::Initialized => {
            println!("{}", messages.summary_stepca_completed());
        }
        crate::commands::init::StepCaInitResult::Skipped => {
            println!("{}", messages.summary_stepca_skipped());
        }
    }

    if summary.init_response {
        println!(
            "{}",
            messages.summary_openbao_init_completed(
                crate::commands::init::INIT_SECRET_SHARES,
                crate::commands::init::INIT_SECRET_THRESHOLD
            )
        );
    } else {
        println!("{}", messages.summary_openbao_init_skipped());
    }
}

fn print_init_secrets(summary: &InitSummary, messages: &Messages) {
    println!(
        "{}",
        messages.summary_root_token(&display_secret(&summary.root_token, summary.show_secrets))
    );

    if !summary.unseal_keys.is_empty() {
        for (idx, key) in summary.unseal_keys.iter().enumerate() {
            println!(
                "{}",
                messages.summary_unseal_key(idx + 1, &display_secret(key, summary.show_secrets))
            );
        }
    }

    // codeql[rust/cleartext-logging]: secrets can be shown intentionally via --show-secrets.
    println!(
        "{}",
        messages.summary_stepca_password(&display_secret(
            &summary.stepca_password,
            summary.show_secrets
        ))
    );
    println!(
        "{}",
        messages.summary_db_dsn(&display_secret(&summary.db_dsn, summary.show_secrets))
    );
    println!(
        "{}",
        messages.summary_responder_hmac(&display_secret(&summary.http_hmac, summary.show_secrets))
    );
    if let Some(eab) = summary.eab.as_ref() {
        println!(
            "{}",
            messages.summary_eab_kid(&display_secret(&eab.kid, summary.show_secrets))
        );
        println!(
            "{}",
            messages.summary_eab_hmac(&display_secret(&eab.hmac, summary.show_secrets))
        );
    } else {
        println!("{}", messages.summary_eab_missing());
    }
}

fn print_responder_check(summary: &InitSummary, messages: &Messages) {
    match summary.responder_check {
        crate::commands::init::ResponderCheck::Ok => {
            println!("{}", messages.summary_responder_check_ok());
        }
        crate::commands::init::ResponderCheck::Skipped => {
            println!("{}", messages.summary_responder_check_skipped());
        }
    }
}

fn print_db_check(summary: &InitSummary, messages: &Messages) {
    match summary.db_check {
        crate::commands::init::DbCheckStatus::Ok => {
            println!("{}", messages.summary_db_check_ok());
        }
        crate::commands::init::DbCheckStatus::Skipped => {
            println!("{}", messages.summary_db_check_skipped());
        }
    }
    println!(
        "{}",
        messages.summary_db_host_resolution(
            &summary.db_dsn_host_original,
            &summary.db_dsn_host_effective
        )
    );
}

fn print_kv_paths(messages: &Messages) {
    println!("{}", messages.summary_kv_paths());
    println!("  - {}", crate::commands::init::PATH_STEPCA_PASSWORD);
    println!("  - {}", crate::commands::init::PATH_STEPCA_DB);
    println!("  - {}", crate::commands::init::PATH_RESPONDER_HMAC);
    println!("  - {}", crate::commands::init::PATH_CA_TRUST);
    println!("  - {}", crate::commands::init::PATH_AGENT_EAB);
}

fn print_approles(summary: &InitSummary, messages: &Messages) {
    println!("{}", messages.summary_approles());
    for role in &summary.approles {
        println!("  - {} ({})", role.label, role.role_name);
        // codeql[rust/cleartext-logging]: secrets can be shown intentionally via --show-secrets.
        println!(
            "{}",
            messages.summary_role_id(&display_secret(&role.role_id, summary.show_secrets))
        );
        println!(
            "{}",
            messages.summary_secret_id(&display_secret(&role.secret_id, summary.show_secrets))
        );
    }
}

fn print_next_steps(summary: &InitSummary, messages: &Messages) {
    println!("{}", messages.summary_next_steps());
    println!("{}", messages.next_steps_configure_templates());
    println!(
        "{}",
        messages
            .next_steps_responder_template(&summary.responder_template_path.display().to_string())
    );
    println!(
        "{}",
        messages.next_steps_responder_config(&summary.responder_config_path.display().to_string())
    );
    println!(
        "{}",
        messages.next_steps_openbao_agent_stepca_config(
            &summary
                .openbao_agent_stepca_config_path
                .display()
                .to_string()
        )
    );
    println!(
        "{}",
        messages.next_steps_openbao_agent_responder_config(
            &summary
                .openbao_agent_responder_config_path
                .display()
                .to_string()
        )
    );
    if let Some(path) = summary.openbao_agent_override_path.as_ref() {
        println!(
            "{}",
            messages.next_steps_openbao_agent_override(&path.display().to_string())
        );
    }
    if let Some(url) = summary.responder_url.as_deref() {
        println!("{}", messages.next_steps_responder_url(url));
    }
    println!("{}", messages.next_steps_reload_services());
    println!("{}", messages.next_steps_run_status());
    if summary.eab.is_none() {
        println!("{}", messages.next_steps_eab_issue());
        println!(
            "{}",
            messages.next_steps_eab_hint(crate::commands::init::PATH_AGENT_EAB)
        );
    }
}

pub(crate) fn display_secret(value: &str, show_secrets: bool) -> String {
    if show_secrets {
        value.to_string()
    } else {
        mask_value(value)
    }
}

pub(crate) fn mask_value(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() <= 4 {
        "****".to_string()
    } else {
        format!("****{}", &trimmed[trimmed.len() - 4..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_secret_masks_when_hidden() {
        assert_eq!(display_secret("supersecret", false), "****cret");
        assert_eq!(display_secret("showme", true), "showme");
    }

    #[test]
    fn test_mask_value_short() {
        assert_eq!(mask_value("abc"), "****");
    }

    #[test]
    fn test_mask_value_long() {
        assert_eq!(mask_value("secretvalue"), "****alue");
    }
}
