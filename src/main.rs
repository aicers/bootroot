use anyhow::{Context, Result};

mod cli;
mod commands;
mod i18n;
mod state;

use clap::Parser;

use crate::cli::args::{Cli, CliCommand, InfraCommand, MonitoringCommand, ServiceCommand};
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
        if let Some(detail) = err.chain().nth(1) {
            eprintln!("{}", messages.error_details(&detail.to_string()));
        }
        std::process::exit(1);
    }
}

fn run(cli: Cli, messages: &Messages) -> Result<()> {
    match cli.command {
        CliCommand::Infra(InfraCommand::Up(args)) => {
            commands::infra::run_infra_up(&args, messages)
                .with_context(|| messages.error_infra_failed())?;
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
            let runtime = tokio::runtime::Runtime::new()
                .with_context(|| messages.error_runtime_init_failed("init"))?;
            runtime
                .block_on(commands::init::run_init(&args, messages))
                .with_context(|| messages.error_init_failed())?;
        }
        CliCommand::Status(args) => {
            let runtime = tokio::runtime::Runtime::new()
                .with_context(|| messages.error_runtime_init_failed("status"))?;
            runtime
                .block_on(commands::status::run_status(&args, messages))
                .with_context(|| messages.error_status_failed())?;
        }
        CliCommand::Service(ServiceCommand::Add(args)) => {
            let runtime = tokio::runtime::Runtime::new()
                .with_context(|| messages.error_runtime_init_failed("service add"))?;
            runtime
                .block_on(commands::service::run_service_add(&args, messages))
                .with_context(|| messages.error_service_add_failed())?;
        }
        CliCommand::Service(ServiceCommand::Info(args)) => {
            commands::service::run_service_info(&args, messages)
                .with_context(|| messages.error_service_info_failed())?;
        }
        CliCommand::Service(ServiceCommand::SyncStatus(args)) => {
            commands::service::run_service_sync_status(&args, messages)
                .with_context(|| messages.error_service_info_failed())?;
        }
        CliCommand::Verify(args) => commands::verify::run_verify(&args, messages)
            .with_context(|| messages.error_verify_failed())?,
        CliCommand::Rotate(args) => {
            let runtime = tokio::runtime::Runtime::new()
                .with_context(|| messages.error_runtime_init_failed("rotate"))?;
            runtime
                .block_on(commands::rotate::run_rotate(&args, messages))
                .with_context(|| messages.error_rotate_failed())?;
        }
    }
    Ok(())
}
