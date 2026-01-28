use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use bootroot::db::{check_auth_sync, check_tcp_sync, parse_db_dsn};

use crate::cli::args::VerifyArgs;
use crate::cli::output::print_verify_plan;
use crate::cli::prompt::Prompt;
use crate::i18n::Messages;
use crate::state::{AppEntry, DeployType, StateFile};

pub(crate) fn run_verify(args: &VerifyArgs, messages: &Messages) -> Result<()> {
    let state_path = StateFile::default_path();
    if !state_path.exists() {
        anyhow::bail!(messages.error_state_missing());
    }
    let state = StateFile::load(&state_path)?;
    let service_name = resolve_verify_service_name(args, messages)?;
    let entry = state
        .apps
        .get(&service_name)
        .ok_or_else(|| anyhow::anyhow!(messages.error_app_not_found(&service_name)))?;

    let agent_config = args
        .agent_config
        .as_ref()
        .unwrap_or(&entry.agent_config_path);

    print_verify_plan(&entry.service_name, agent_config, messages);

    let status = Command::new("bootroot-agent")
        .args([
            "--config",
            agent_config.to_string_lossy().as_ref(),
            "--oneshot",
        ])
        .status()
        .with_context(|| messages.error_bootroot_agent_run_failed())?;

    if !status.success() {
        anyhow::bail!(messages.verify_agent_failed());
    }

    if !entry.cert_path.exists() {
        anyhow::bail!(messages.verify_missing_cert(&entry.cert_path.display().to_string()));
    }
    if !entry.key_path.exists() {
        anyhow::bail!(messages.verify_missing_key(&entry.key_path.display().to_string()));
    }
    verify_file_non_empty(
        &entry.cert_path,
        &messages.verify_empty_cert(&entry.cert_path.display().to_string()),
    )?;
    verify_file_non_empty(
        &entry.key_path,
        &messages.verify_empty_key(&entry.key_path.display().to_string()),
    )?;
    verify_cert_san(entry, messages)?;

    if args.db_check {
        verify_db_connectivity(&state, args.db_timeout.timeout_secs, messages)?;
    }

    println!("{}", messages.verify_summary_title());
    println!("{}", messages.verify_service_name(&entry.service_name));
    println!(
        "{}",
        messages.verify_agent_config(&agent_config.display().to_string())
    );
    println!(
        "{}",
        messages.verify_cert_path(&entry.cert_path.display().to_string())
    );
    println!(
        "{}",
        messages.verify_key_path(&entry.key_path.display().to_string())
    );
    if args.db_check {
        println!("{}", messages.summary_db_check_ok());
    }
    println!("{}", messages.verify_result_ok());
    Ok(())
}

fn verify_db_connectivity(state: &StateFile, timeout_secs: u64, messages: &Messages) -> Result<()> {
    let secrets_dir = state
        .secrets_dir()
        .canonicalize()
        .with_context(|| messages.error_secrets_dir_resolve_failed())?;
    let ca_path = secrets_dir.join("config").join("ca.json");
    let contents = std::fs::read_to_string(&ca_path)
        .with_context(|| messages.error_read_file_failed(&ca_path.display().to_string()))?;
    let value: serde_json::Value =
        serde_json::from_str(&contents).context(messages.error_parse_ca_json_failed())?;
    let db_type = value["db"]["type"].as_str().unwrap_or_default();
    if db_type != "postgresql" {
        anyhow::bail!(messages.error_db_type_unsupported());
    }
    let dsn = value["db"]["dataSource"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let parsed =
        parse_db_dsn(&dsn).map_err(|_| anyhow::anyhow!(messages.error_invalid_db_dsn()))?;
    let timeout = std::time::Duration::from_secs(timeout_secs);
    check_tcp_sync(&parsed.host, parsed.port, timeout)
        .with_context(|| messages.error_db_check_failed())?;
    check_auth_sync(&dsn, timeout).with_context(|| messages.error_db_auth_failed())?;
    Ok(())
}

fn resolve_verify_service_name(args: &VerifyArgs, messages: &Messages) -> Result<String> {
    if let Some(value) = args.service_name.clone() {
        if value.trim().is_empty() {
            anyhow::bail!(messages.error_value_required());
        }
        return Ok(value);
    }
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let mut prompt = Prompt::new(&mut input, &mut output, messages);
    prompt.prompt_with_validation(messages.prompt_service_name(), None, |value| {
        if value.trim().is_empty() {
            anyhow::bail!(messages.error_value_required());
        }
        Ok(value.trim().to_string())
    })
}

fn verify_file_non_empty(path: &Path, message: &str) -> Result<()> {
    let metadata = std::fs::metadata(path).with_context(|| message.to_string())?;
    if metadata.len() == 0 {
        anyhow::bail!(message.to_string());
    }
    Ok(())
}

fn verify_cert_san(entry: &AppEntry, messages: &Messages) -> Result<()> {
    let expected = expected_dns_name(entry, messages)?;
    let contents = std::fs::read(&entry.cert_path)
        .with_context(|| messages.error_read_file_failed(&entry.cert_path.display().to_string()))?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&contents)
        .map_err(|_| anyhow::anyhow!(messages.verify_cert_parse_failed()))?;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents)
        .map_err(|_| anyhow::anyhow!(messages.verify_cert_parse_failed()))?;
    let mut dns_names = Vec::new();
    for extension in cert.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            extension.parsed_extension()
        {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(dns_name) = name {
                    dns_names.push(dns_name.to_string());
                }
            }
        }
    }
    if dns_names.is_empty() {
        anyhow::bail!(messages.verify_cert_missing_san());
    }
    if !dns_names.iter().any(|name| name == &expected) {
        anyhow::bail!(messages.verify_cert_san_mismatch(&expected, &dns_names.join(", ")));
    }
    Ok(())
}

fn expected_dns_name(entry: &AppEntry, messages: &Messages) -> Result<String> {
    match entry.deploy_type {
        DeployType::Daemon => {
            let instance_id = entry
                .instance_id
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!(messages.error_app_instance_id_required()))?;
            Ok(format!(
                "{}.{}.{}.{}",
                instance_id, entry.service_name, entry.hostname, entry.domain
            ))
        }
        DeployType::Docker => {
            let instance_id = entry
                .instance_id
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!(messages.error_app_instance_id_required()))?;
            if entry
                .container_name
                .as_deref()
                .unwrap_or_default()
                .is_empty()
            {
                anyhow::bail!(messages.error_app_container_name_required());
            }
            Ok(format!(
                "{}.{}.{}.{}",
                instance_id, entry.service_name, entry.hostname, entry.domain
            ))
        }
    }
}
