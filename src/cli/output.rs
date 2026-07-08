use crate::commands::init::{InitPlan, InitSummary};
use crate::commands::service::{SERVICE_EAB_FILENAME, display_policy_value, display_wrap_ttl};
use crate::i18n::{Messages, ServiceNextStepsDaemon};
use crate::state::{DeliveryMode, PostRenewHookEntry, ServiceEntry};

pub(crate) struct ServiceAddPlan<'a> {
    pub(crate) service_name: &'a str,
    pub(crate) delivery_mode: crate::state::DeliveryMode,
    pub(crate) hostname: &'a str,
    pub(crate) domain: &'a str,
    pub(crate) agent_config: &'a str,
    pub(crate) cert_path: &'a str,
    pub(crate) key_path: &'a str,
    pub(crate) instance_id: Option<&'a str>,
    pub(crate) notes: Option<&'a str>,
    pub(crate) post_renew_hooks: &'a [PostRenewHookEntry],
}

pub(crate) struct ServiceAddAppliedPaths<'a> {
    pub(crate) agent_config: &'a str,
    pub(crate) eab_file: &'a str,
}

pub(crate) struct ServiceAddRemoteBootstrap<'a> {
    pub(crate) bootstrap_file: &'a str,
    pub(crate) remote_run_command: &'a str,
    pub(crate) wrapped: bool,
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
        messages.service_summary_auto_applied_eab_file(paths.eab_file)
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
    println!("{}", messages.service_summary_remote_handoff_title());
    if remote.wrapped {
        println!(
            "{}",
            messages.service_summary_remote_handoff_service_host(remote.remote_run_command)
        );
    } else {
        println!(
            "{}",
            messages.service_summary_remote_handoff_service_host_no_wrap(remote.remote_run_command)
        );
    }
    println!("{}", messages.service_summary_remote_placeholder_warning());
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
    match entry.delivery_mode {
        // Remote-bootstrap hosts run `bootroot-agent` self-auth fast-poll (no
        // OpenBao Agent). The one-shot `bootroot-remote bootstrap`
        // handoff is already printed above; here we only remind the operator to
        // keep the agent running so trust and secret_id self-heal.
        DeliveryMode::RemoteBootstrap => print_remote_selfheal_next_steps(messages),
        DeliveryMode::LocalFile => {
            print_local_deploy_snippet(entry, secret_id_path, messages);
            if let Some(trusted) = trusted_ca_sha256 {
                println!("{}", messages.service_scope_operator_optional());
                print_trust_snippet(entry, trusted, messages);
            }
        }
    }
}

fn print_remote_selfheal_next_steps(messages: &Messages) {
    println!("{}", messages.service_next_steps_remote_selfheal_keep());
    println!("{}", messages.service_next_steps_remote_selfheal_note());
}

fn print_local_deploy_snippet(
    entry: &ServiceEntry,
    secret_id_path: &std::path::Path,
    messages: &Messages,
) {
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
    print_daemon_snippet(entry, secret_id_path, messages);
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
    println!(
        "{}",
        messages.service_summary_policy(&entry.approle.policy_name)
    );
    println!(
        "{}",
        messages.service_summary_approle(&entry.approle.role_name)
    );
    println!("{}", messages.summary_role_id(&entry.approle.role_id));
    let secret_id_ttl_display =
        display_policy_value(entry.approle.secret_id_ttl.as_deref(), messages);
    // codeql[rust/cleartext-logging]: output is a non-secret TTL duration label.
    println!(
        "{}",
        messages.service_info_secret_id_ttl(&secret_id_ttl_display)
    );
    let wrap_ttl_display = display_wrap_ttl(entry.approle.secret_id_wrap_ttl.as_deref(), messages);
    // codeql[rust/cleartext-logging]: output is a non-secret wrap-TTL duration label.
    println!(
        "{}",
        messages.service_info_secret_id_wrap_ttl(&wrap_ttl_display)
    );
    if let Some(ref cidrs) = entry.approle.token_bound_cidrs {
        println!(
            "{}",
            messages.service_info_token_bound_cidrs(&cidrs.join(", "))
        );
    }
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
    match entry.delivery_mode {
        DeliveryMode::RemoteBootstrap => print_remote_selfheal_next_steps(messages),
        DeliveryMode::LocalFile => {
            print_daemon_run_snippet(entry, &entry.approle.secret_id_path, messages);
        }
    }
}

fn print_service_fields(entry: &ServiceEntry, messages: &Messages) {
    let delivery_mode = entry.delivery_mode.to_string();
    println!("{}", messages.service_summary_kind(&entry.service_name));
    println!("{}", messages.service_summary_hostname(&entry.hostname));
    println!("{}", messages.service_summary_domain(&entry.domain));
    println!("{}", messages.service_summary_delivery_mode(&delivery_mode));
    if let Some(notes) = entry.notes.as_deref() {
        println!("{}", messages.service_summary_notes(notes));
    }
    for hook in &entry.post_renew_hooks {
        println!(
            "{}",
            messages.service_summary_post_renew_hook(&format_hook(hook))
        );
    }
}

fn print_service_plan_fields(plan: &ServiceAddPlan<'_>, messages: &Messages) {
    let delivery_mode = plan.delivery_mode.to_string();
    println!("{}", messages.service_summary_kind(plan.service_name));
    println!("{}", messages.service_summary_hostname(plan.hostname));
    println!("{}", messages.service_summary_domain(plan.domain));
    println!("{}", messages.service_summary_delivery_mode(&delivery_mode));
    if let Some(instance_id) = plan.instance_id {
        println!("{}", messages.service_summary_instance_id(instance_id));
    }
    if let Some(notes) = plan.notes {
        println!("{}", messages.service_summary_notes(notes));
    }
    for hook in plan.post_renew_hooks {
        println!(
            "{}",
            messages.service_summary_post_renew_hook(&format_hook(hook))
        );
    }
}

fn print_daemon_snippet(
    entry: &ServiceEntry,
    secret_id_path: &std::path::Path,
    messages: &Messages,
) {
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
    println!("renew_before = \"16h\"");
    println!("check_jitter = \"0s\"");
    println!("{}", messages.service_snippet_domain_hint(&entry.domain));
    print_daemon_run_snippet(entry, secret_id_path, messages);
}

/// Prints the host-daemon run command for the local `bootroot-agent`.
/// `--eab-file` must be part of the documented invocation: the fast-poll
/// EAB refresh only applies when the agent was started with that flag,
/// so omitting it turns `rotate eab-clear` / EAB KV updates into silent
/// no-ops for this service.
fn print_daemon_run_snippet(
    entry: &ServiceEntry,
    secret_id_path: &std::path::Path,
    messages: &Messages,
) {
    let eab_path = service_eab_file_path(secret_id_path);
    println!("{}", messages.service_snippet_daemon_run_title());
    println!(
        "bootroot-agent --config {config} --eab-file {eab}",
        config = entry.agent_config_path.display(),
        eab = eab_path.display()
    );
}

/// Derives the service's `eab.json` path (adjacent to its `secret_id`),
/// matching what `apply_local_service_configs` provisions.
fn service_eab_file_path(secret_id_path: &std::path::Path) -> std::path::PathBuf {
    secret_id_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join(SERVICE_EAB_FILENAME)
}

fn print_trust_snippet(entry: &ServiceEntry, trusted: &[String], messages: &Messages) {
    let cert_dir = entry
        .cert_path
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let bundle_path = cert_dir.join("ca-bundle.pem");
    println!("{}", messages.service_snippet_trust_title());
    println!("[trust]");
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

    // codeql[rust/cleartext-logging]: secrets can be shown intentionally via --enable show-secrets.
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
        // codeql[rust/cleartext-logging]: secrets can be shown intentionally via --enable show-secrets.
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
        println!(
            "{}",
            messages.next_steps_eab_hint(crate::commands::init::PATH_AGENT_EAB)
        );
    }
}

pub(crate) fn format_hook(hook: &PostRenewHookEntry) -> String {
    let mut parts = vec![hook.command.clone()];
    parts.extend(hook.args.iter().cloned());
    parts.join(" ")
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
