use anyhow::{Context, Result};

mod cli;
mod commands;
mod i18n;
mod state;

use clap::Parser;

use crate::cli::args::{
    CaCommand, Cli, CliCommand, InfraCommand, MonitoringCommand, OpenbaoCommand, ServiceCommand,
    ServiceOpenbaoSidecarCommand,
};
use crate::i18n::Messages;

fn main() {
    let cli = Cli::parse();
    let messages = match Messages::new(&cli.lang) {
        Ok(messages) => messages,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    if let Err(err) = run(cli, &messages) {
        let message = err
            .chain()
            .next()
            .map_or_else(|| "bootroot error".to_string(), ToString::to_string);
        eprintln!("{message}");
        for cause in err.chain().skip(1) {
            eprintln!("{}", messages.error_details(&cause.to_string()));
        }
        std::process::exit(1);
    }
}

/// Creates a Tokio runtime and passes it to `f`, returning its result.
///
/// # Errors
///
/// Returns an error if the runtime cannot be created.
fn with_runtime<F, R>(command: &str, messages: &Messages, f: F) -> Result<R>
where
    F: FnOnce(&tokio::runtime::Runtime) -> R,
{
    let runtime = tokio::runtime::Runtime::new()
        .with_context(|| messages.error_runtime_init_failed(command))?;
    Ok(f(&runtime))
}

fn run(cli: Cli, messages: &Messages) -> Result<()> {
    match cli.command {
        CliCommand::Infra(InfraCommand::Up(args)) => {
            commands::infra::run_infra_up(&args, messages)
                .with_context(|| messages.error_infra_failed())?;
        }
        CliCommand::Infra(InfraCommand::Install(args)) => {
            commands::infra::run_infra_install(&args, messages)
                .with_context(|| messages.error_infra_install_failed())?;
        }
        CliCommand::Monitoring(MonitoringCommand::Up(args)) => {
            commands::monitoring::run_monitoring_up(&args, messages)
                .with_context(|| messages.error_monitoring_failed())?;
        }
        CliCommand::Monitoring(MonitoringCommand::Status(args)) => {
            commands::monitoring::run_monitoring_status(&args, messages)
                .with_context(|| messages.error_monitoring_failed())?;
        }
        CliCommand::Monitoring(MonitoringCommand::Down(args)) => {
            commands::monitoring::run_monitoring_down(&args, messages)
                .with_context(|| messages.error_monitoring_failed())?;
        }
        CliCommand::Init(args) => {
            with_runtime("init", messages, |rt| {
                rt.block_on(commands::init::run_init(&args, messages))
            })?
            .with_context(|| messages.error_init_failed())?;
        }
        CliCommand::Status(args) => {
            with_runtime("status", messages, |rt| {
                rt.block_on(commands::status::run_status(&args, messages))
            })?
            .with_context(|| messages.error_status_failed())?;
        }
        CliCommand::Service(ServiceCommand::Add(args)) => {
            with_runtime("service add", messages, |rt| {
                rt.block_on(commands::service::run_service_add(&args, messages))
            })?
            .with_context(|| messages.error_service_add_failed())?;
        }
        CliCommand::Service(ServiceCommand::Info(args)) => {
            commands::service::run_service_info(&args, messages)
                .with_context(|| messages.error_service_info_failed())?;
        }
        CliCommand::Service(ServiceCommand::Update(args)) => {
            commands::service::run_service_update(&args, messages)
                .with_context(|| messages.error_service_update_failed())?;
        }
        CliCommand::Service(ServiceCommand::OpenbaoSidecar(
            ServiceOpenbaoSidecarCommand::Start(args),
        )) => {
            commands::service::openbao_sidecar_start::run_service_openbao_sidecar_start(
                &args, messages,
            )
            .with_context(|| messages.error_service_openbao_sidecar_start_failed())?;
        }
        CliCommand::Service(ServiceCommand::Agent(ServiceOpenbaoSidecarCommand::Start(args))) => {
            eprintln!("{}", messages.warn_service_agent_alias_deprecated());
            commands::service::openbao_sidecar_start::run_service_openbao_sidecar_start(
                &args, messages,
            )
            .with_context(|| messages.error_service_openbao_sidecar_start_failed())?;
        }
        CliCommand::Verify(args) => commands::verify::run_verify(&args, messages)
            .with_context(|| messages.error_verify_failed())?,
        CliCommand::Rotate(args) => {
            with_runtime("rotate", messages, |rt| {
                rt.block_on(commands::rotate::run_rotate(&args, messages))
            })?
            .with_context(|| messages.error_rotate_failed())?;
        }
        CliCommand::Clean(args) => {
            commands::clean::run_clean(&args, messages)
                .with_context(|| messages.error_clean_failed())?;
        }
        CliCommand::Openbao(OpenbaoCommand::SaveUnsealKeys(args)) => {
            commands::openbao_unseal::run_save_unseal_keys(&args, messages)
                .with_context(|| messages.error_openbao_save_unseal_keys_failed())?;
        }
        CliCommand::Openbao(OpenbaoCommand::DeleteUnsealKeys(args)) => {
            commands::openbao_unseal::delete_unseal_keys(&args.secrets_dir, messages)
                .with_context(|| messages.error_openbao_delete_unseal_keys_failed())?;
        }
        CliCommand::Ca(CaCommand::Update(args)) => {
            commands::ca::run_ca_update(&args, messages)
                .with_context(|| "ca update failed".to_string())?;
        }
        CliCommand::Ca(CaCommand::Restart(args)) => {
            commands::ca::run_ca_restart(&args, messages)
                .with_context(|| "ca restart failed".to_string())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_runtime_executes_closure() {
        let messages = Messages::new("en").expect("failed to load messages");
        let result = with_runtime("test", &messages, |rt| rt.block_on(async { 1 + 1 })).unwrap();
        assert_eq!(result, 2);
    }
}
