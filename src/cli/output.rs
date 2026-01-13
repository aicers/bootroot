use crate::commands::init::{InitPlan, InitSummary};
use crate::i18n::{AppNextStepsDaemon, AppNextStepsDocker, Messages};
use crate::state::{AppEntry, DeployType};

pub(crate) struct AppAddPlan<'a> {
    pub(crate) service_name: &'a str,
    pub(crate) deploy_type: DeployType,
    pub(crate) hostname: &'a str,
    pub(crate) domain: &'a str,
    pub(crate) agent_config: &'a str,
    pub(crate) cert_path: &'a str,
    pub(crate) key_path: &'a str,
    pub(crate) instance_id: Option<&'a str>,
    pub(crate) container_name: Option<&'a str>,
    pub(crate) notes: Option<&'a str>,
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
    println!(
        "{}",
        messages.summary_secrets_dir(&plan.secrets_dir.display().to_string())
    );
    if plan.overwrite_password {
        println!("{}", messages.init_plan_overwrite_password());
    }
    if plan.overwrite_ca_json {
        println!("{}", messages.init_plan_overwrite_ca_json());
    }
    if plan.overwrite_state {
        println!("{}", messages.init_plan_overwrite_state());
    }
}

pub(crate) fn print_app_add_summary(
    entry: &AppEntry,
    secret_id_path: &std::path::Path,
    messages: &Messages,
) {
    println!("{}", messages.app_add_summary());
    print_app_fields(entry, messages);
    println!(
        "{}",
        messages.app_summary_policy(&entry.approle.policy_name)
    );
    println!("{}", messages.app_summary_approle(&entry.approle.role_name));
    println!("{}", messages.summary_role_id(&entry.approle.role_id));
    println!(
        "{}",
        messages.app_summary_secret_path(&secret_id_path.display().to_string())
    );
    println!("{}", messages.app_summary_openbao_path(&entry.service_name));
    println!("{}", messages.app_summary_next_steps());
    match entry.deploy_type {
        DeployType::Daemon => {
            let cert_path = entry.cert_path.display().to_string();
            let key_path = entry.key_path.display().to_string();
            let config_path = entry.agent_config_path.display().to_string();
            let data = AppNextStepsDaemon {
                service_name: &entry.service_name,
                instance_id: entry.instance_id.as_deref().unwrap_or_default(),
                hostname: &entry.hostname,
                domain: &entry.domain,
                cert_path: &cert_path,
                key_path: &key_path,
                config_path: &config_path,
            };
            println!("{}", messages.app_next_steps_daemon_profile(&data));
            print_daemon_snippet(entry, messages);
        }
        DeployType::Docker => {
            let cert_path = entry.cert_path.display().to_string();
            let key_path = entry.key_path.display().to_string();
            let config_path = entry.agent_config_path.display().to_string();
            let secret_id_path_value = secret_id_path.display().to_string();
            let data = AppNextStepsDocker {
                service_name: &entry.service_name,
                container_name: entry.container_name.as_deref().unwrap_or_default(),
                hostname: &entry.hostname,
                domain: &entry.domain,
                cert_path: &cert_path,
                key_path: &key_path,
                config_path: &config_path,
                role_name: &entry.approle.role_name,
                secret_id_path: &secret_id_path_value,
            };
            println!("{}", messages.app_next_steps_docker_sidecar(&data));
            print_docker_snippet(entry, messages);
        }
    }
}

pub(crate) fn print_app_add_plan(plan: &AppAddPlan<'_>, messages: &Messages) {
    println!("{}", messages.app_add_plan_title());
    print_app_plan_fields(plan, messages);
    println!("{}", messages.app_summary_agent_config(plan.agent_config));
    println!("{}", messages.app_summary_cert_path(plan.cert_path));
    println!("{}", messages.app_summary_key_path(plan.key_path));
}

pub(crate) fn print_app_info_summary(entry: &AppEntry, messages: &Messages) {
    println!("{}", messages.app_info_summary());
    print_app_fields(entry, messages);
    if let Some(instance_id) = entry.instance_id.as_deref() {
        println!("{}", messages.app_summary_instance_id(instance_id));
    }
    if let Some(container_name) = entry.container_name.as_deref() {
        println!("{}", messages.app_summary_container_name(container_name));
    }
    println!(
        "{}",
        messages.app_summary_policy(&entry.approle.policy_name)
    );
    println!("{}", messages.app_summary_approle(&entry.approle.role_name));
    println!("{}", messages.summary_role_id(&entry.approle.role_id));
    println!("{}", messages.app_summary_openbao_path(&entry.service_name));
    println!(
        "{}",
        messages.app_summary_agent_config(&entry.agent_config_path.display().to_string())
    );
    println!(
        "{}",
        messages.app_summary_cert_path(&entry.cert_path.display().to_string())
    );
    println!(
        "{}",
        messages.app_summary_key_path(&entry.key_path.display().to_string())
    );
    println!("{}", messages.app_summary_secret_path_hidden());
}

fn print_app_fields(entry: &AppEntry, messages: &Messages) {
    println!("{}", messages.app_summary_kind(&entry.service_name));
    println!(
        "{}",
        messages.app_summary_deploy_type(match entry.deploy_type {
            DeployType::Daemon => "daemon",
            DeployType::Docker => "docker",
        })
    );
    println!("{}", messages.app_summary_hostname(&entry.hostname));
    println!("{}", messages.app_summary_domain(&entry.domain));
    if let Some(notes) = entry.notes.as_deref() {
        println!("{}", messages.app_summary_notes(notes));
    }
}

fn print_app_plan_fields(plan: &AppAddPlan<'_>, messages: &Messages) {
    println!("{}", messages.app_summary_kind(plan.service_name));
    println!(
        "{}",
        messages.app_summary_deploy_type(match plan.deploy_type {
            DeployType::Daemon => "daemon",
            DeployType::Docker => "docker",
        })
    );
    println!("{}", messages.app_summary_hostname(plan.hostname));
    println!("{}", messages.app_summary_domain(plan.domain));
    if let Some(instance_id) = plan.instance_id {
        println!("{}", messages.app_summary_instance_id(instance_id));
    }
    if let Some(container_name) = plan.container_name {
        println!("{}", messages.app_summary_container_name(container_name));
    }
    if let Some(notes) = plan.notes {
        println!("{}", messages.app_summary_notes(notes));
    }
}

fn print_daemon_snippet(entry: &AppEntry, messages: &Messages) {
    let instance_id = entry.instance_id.as_deref().unwrap_or_default();
    println!("{}", messages.app_snippet_daemon_title());
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
    println!("{}", messages.app_snippet_domain_hint(&entry.domain));
}

fn print_docker_snippet(entry: &AppEntry, messages: &Messages) {
    let container = entry.container_name.as_deref().unwrap_or("bootroot-agent");
    let config_path = entry.agent_config_path.display();
    let cert_parent = entry
        .cert_path
        .parent()
        .unwrap_or(std::path::Path::new("."));
    println!("{}", messages.app_snippet_docker_title());
    println!("docker run --rm \\");
    println!("  --name {container} \\");
    println!("  -v {config_path}:/app/agent.toml:ro \\");
    println!(
        "  -v {cert_dir}:/app/certs \\",
        cert_dir = cert_parent.display()
    );
    println!("  <bootroot-agent-image> \\");
    println!("  bootroot-agent --config /app/agent.toml --oneshot");
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
}

fn print_kv_paths(messages: &Messages) {
    println!("{}", messages.summary_kv_paths());
    println!("  - {}", crate::commands::init::PATH_STEPCA_PASSWORD);
    println!("  - {}", crate::commands::init::PATH_STEPCA_DB);
    println!("  - {}", crate::commands::init::PATH_RESPONDER_HMAC);
    println!("  - {}", crate::commands::init::PATH_AGENT_EAB);
}

fn print_approles(summary: &InitSummary, messages: &Messages) {
    println!("{}", messages.summary_approles());
    for role in &summary.approles {
        println!("  - {} ({})", role.label, role.role_name);
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
