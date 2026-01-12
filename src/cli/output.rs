use crate::commands::init::InitSummary;
use crate::i18n::Messages;
use crate::state::{AppEntry, DeployType};

pub(crate) fn print_init_summary(summary: &InitSummary, messages: &Messages) {
    print_init_header(summary, messages);
    print_init_secrets(summary, messages);
    print_responder_check(summary, messages);
    print_kv_paths(messages);
    print_approles(summary, messages);
    print_next_steps(summary, messages);
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
    println!("{}", messages.app_summary_next_steps());
    println!(
        "{}",
        messages.app_next_steps_use_approle(&entry.approle.role_name)
    );
}

pub(crate) fn print_app_info_summary(entry: &AppEntry, messages: &Messages) {
    println!("{}", messages.app_info_summary());
    print_app_fields(entry, messages);
    println!(
        "{}",
        messages.app_summary_policy(&entry.approle.policy_name)
    );
    println!("{}", messages.app_summary_approle(&entry.approle.role_name));
    println!("{}", messages.summary_role_id(&entry.approle.role_id));
    println!("{}", messages.app_summary_secret_path_hidden());
}

fn print_app_fields(entry: &AppEntry, messages: &Messages) {
    println!("{}", messages.app_summary_kind(&entry.app_kind));
    println!(
        "{}",
        messages.app_summary_deploy_type(match entry.deploy_type {
            DeployType::Daemon => "daemon",
            DeployType::Docker => "docker",
        })
    );
    println!("{}", messages.app_summary_hostname(&entry.hostname));
    if let Some(notes) = entry.notes.as_deref() {
        println!("{}", messages.app_summary_notes(notes));
    }
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
