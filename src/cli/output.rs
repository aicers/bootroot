use crate::commands::init::InitSummary;

pub(crate) fn print_init_summary(summary: &InitSummary) {
    println!("bootroot init: summary");
    println!("- OpenBao URL: {}", summary.openbao_url);
    println!("- KV mount: {}", summary.kv_mount);
    println!("- Secrets dir: {}", summary.secrets_dir.display());
    match summary.step_ca_result {
        crate::commands::init::StepCaInitResult::Initialized => {
            println!("- step-ca init: completed");
        }
        crate::commands::init::StepCaInitResult::Skipped => {
            println!("- step-ca init: skipped (already initialized)");
        }
    }

    if summary.init_response {
        println!(
            "- OpenBao init: completed (shares={}, threshold={})",
            crate::commands::init::INIT_SECRET_SHARES,
            crate::commands::init::INIT_SECRET_THRESHOLD
        );
    } else {
        println!("- OpenBao init: skipped (already initialized)");
    }

    println!(
        "- root token: {}",
        display_secret(&summary.root_token, summary.show_secrets)
    );

    if !summary.unseal_keys.is_empty() {
        for (idx, key) in summary.unseal_keys.iter().enumerate() {
            println!(
                "- unseal key {}: {}",
                idx + 1,
                display_secret(key, summary.show_secrets)
            );
        }
    }

    println!(
        "- step-ca password: {}",
        display_secret(&summary.stepca_password, summary.show_secrets)
    );
    println!(
        "- db dsn: {}",
        display_secret(&summary.db_dsn, summary.show_secrets)
    );
    println!(
        "- responder hmac: {}",
        display_secret(&summary.http_hmac, summary.show_secrets)
    );
    if let Some(eab) = summary.eab.as_ref() {
        println!(
            "- eab kid: {}",
            display_secret(&eab.kid, summary.show_secrets)
        );
        println!(
            "- eab hmac: {}",
            display_secret(&eab.hmac, summary.show_secrets)
        );
    } else {
        println!("- eab: not configured");
    }

    println!("- OpenBao KV paths:");
    println!("  - {}", crate::commands::init::PATH_STEPCA_PASSWORD);
    println!("  - {}", crate::commands::init::PATH_STEPCA_DB);
    println!("  - {}", crate::commands::init::PATH_RESPONDER_HMAC);
    println!("  - {}", crate::commands::init::PATH_AGENT_EAB);

    println!("- AppRoles:");
    for role in &summary.approles {
        println!("  - {} ({})", role.label, role.role_name);
        println!(
            "    role_id: {}",
            display_secret(&role.role_id, summary.show_secrets)
        );
        println!(
            "    secret_id: {}",
            display_secret(&role.secret_id, summary.show_secrets)
        );
    }

    println!("next steps:");
    println!("  - Configure OpenBao Agent templates for step-ca, responder, and bootroot-agent.");
    println!("  - Start or reload step-ca and responder to consume rendered secrets.");
    println!("  - Run `bootroot status` to verify services.");
    if summary.eab.is_none() {
        println!(
            "  - If you need ACME EAB, store kid/hmac at {} or rerun with --eab-kid/--eab-hmac.",
            crate::commands::init::PATH_AGENT_EAB
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
