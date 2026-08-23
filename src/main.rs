use std::process::ExitCode;

use anyhow::{Context, Result};

mod cli;
mod commands;
mod i18n;
mod state;
#[cfg(test)]
mod test_support;

use clap::Parser;

use crate::cli::args::{
    CaCommand, Cli, CliCommand, InfraCommand, MonitoringCommand, OpenbaoCommand, ServiceCommand,
};
use crate::commands::rotate::RotateOutcome;
use crate::i18n::Messages;

/// GNU `timeout(1)` convention: 124 signals the wait window elapsed
/// before the operation finished. Returned from `bootroot rotate
/// force-reissue --wait` so scripted callers can distinguish a
/// successful reissue from one that was merely queued for the agent.
const EXIT_CODE_WAIT_TIMEOUT: u8 = 124;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let messages = match Messages::new(&cli.lang) {
        Ok(messages) => messages,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    match run(cli, &messages) {
        Ok(code) => code,
        Err(err) => {
            let message = err
                .chain()
                .next()
                .map_or_else(|| "bootroot error".to_string(), ToString::to_string);
            eprintln!("{message}");
            for cause in err.chain().skip(1) {
                eprintln!("{}", messages.error_details(&cause.to_string()));
            }
            ExitCode::from(1)
        }
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

#[allow(clippy::too_many_lines)] // Top-level CLI dispatcher.
fn run(cli: Cli, messages: &Messages) -> Result<ExitCode> {
    match cli.command {
        CliCommand::Infra(InfraCommand::Up(args)) => {
            with_runtime("infra up", messages, |rt| {
                rt.block_on(commands::infra::run_infra_up(&args, messages))
            })?
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
        CliCommand::Reinit(args) => {
            with_runtime("reinit", messages, |rt| {
                rt.block_on(commands::reinit::run_reinit(&args, messages))
            })?
            .with_context(|| messages.error_reinit_failed())?;
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
        CliCommand::Service(ServiceCommand::Remove(args)) => {
            with_runtime("service remove", messages, |rt| {
                rt.block_on(commands::service::run_service_remove(&args, messages))
            })?
            .with_context(|| messages.error_service_remove_failed())?;
        }
        CliCommand::Verify(args) => commands::verify::run_verify(&args, messages)
            .with_context(|| messages.error_verify_failed())?,
        CliCommand::Rotate(args) => {
            let outcome = with_runtime("rotate", messages, |rt| {
                rt.block_on(commands::rotate::run_rotate(&args, messages))
            })?
            .with_context(|| messages.error_rotate_failed())?;
            if matches!(outcome, RotateOutcome::WaitTimedOut) {
                return Ok(ExitCode::from(EXIT_CODE_WAIT_TIMEOUT));
            }
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
    Ok(ExitCode::SUCCESS)
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

    /// The registrar audit format is reachable — and complete — from
    /// outside the library, through `bootroot::registrar::audit` and
    /// nothing else.
    ///
    /// This binary crate is the nearest stand-in for the reader the
    /// format exists for: it links the library the same way any other
    /// consumer does, so a record type, a field, an append API or the
    /// error type that stopped being public fails to compile here rather
    /// than in somebody else's tree. It writes nothing — opening a store
    /// is deliberately not public — and asserts only that the whole
    /// format can be named and round-tripped.
    #[test]
    fn the_registrar_audit_format_is_reachable_from_the_binary_crate() {
        // Named so the handle type itself stays public; constructing one
        // is not part of the public surface.
        fn _names_the_handle(_: &AuditRecordStore) {}

        use bootroot::registrar::audit::{
            ACTIVE_FILE_NAME, AUDIT_RECORD_VERSION, AuditOutcome, AuditPhase, AuditRecord,
            AuditRecordStore, AuditStoreError, AuditVerb, MAX_RECORD_FIELD_BYTES,
            MAX_SERIALIZED_RECORD_BYTES, MIN_AUDIT_MAX_FILE_BYTES, PathCondition, RefusalReason,
            RequestedIdentity, TruncationDigest, Truncations, canonical_timestamp,
            format_millisecond_rfc3339,
        };
        use time::format_description::well_known::Rfc3339;
        use time::{OffsetDateTime, UtcOffset};

        let ts = OffsetDateTime::parse("2026-08-23T12:34:56.789Z", &Rfc3339).expect("a timestamp");
        let record: AuditRecord = AuditRecord::outcome(
            ts,
            "req-1".to_string(),
            AuditVerb::Mint,
            "spiffe://review/manager#7f3a".to_string(),
            RequestedIdentity {
                service_name: "review".to_string(),
                host: "h1".to_string(),
                instance: Some(7),
            },
            Some("review-h1-007".to_string()),
            AuditOutcome::Refused {
                reason: RefusalReason::ComponentNotConfigured,
                detail: Some("component review has no entry".to_string()),
            },
        );
        assert_eq!(record.record_version, AUDIT_RECORD_VERSION);
        assert_eq!(record.phase, AuditPhase::Outcome);
        assert_eq!(record.phase.as_str(), "outcome");
        assert_eq!(
            format_millisecond_rfc3339(record.ts),
            "2026-08-23T12:34:56.789Z"
        );

        // Appending refuses a `ts` that is not already a UTC
        // millisecond rather than dropping the remainder or converting
        // the offset, so the helper that canonicalizes a clock reading
        // is public too — and the builders already apply it.
        let ragged = ts
            .replace_nanosecond(789_654_321)
            .expect("a nanosecond")
            .to_offset(UtcOffset::from_hms(9, 0, 0).expect("an offset"));
        assert_eq!(canonical_timestamp(ragged), ts);
        assert_eq!(canonical_timestamp(ragged).offset(), UtcOffset::UTC);
        let built = AuditRecord::intent(
            ragged,
            "req-2".to_string(),
            AuditVerb::Mint,
            "spiffe://review/manager#7f3a".to_string(),
            RequestedIdentity {
                service_name: "review".to_string(),
                host: "h1".to_string(),
                instance: None,
            },
        );
        assert_eq!(built.ts, ts);
        assert_eq!(built.ts.offset(), UtcOffset::UTC);

        let line: Vec<u8> = record.clone().into_bounded().to_line().expect("a line");
        assert_eq!(line.last().copied(), Some(b'\n'));
        assert!(line.len() <= MAX_SERIALIZED_RECORD_BYTES);
        let parsed: AuditRecord =
            serde_json::from_slice(&line[..line.len() - 1]).expect("a line round-trips");
        assert_eq!(parsed, record);

        // The names a reader needs to find the files, size them, and
        // report what a truncated field really was.
        assert_eq!(ACTIVE_FILE_NAME, "registrar-audit.jsonl");
        assert_eq!(MAX_RECORD_FIELD_BYTES, 512);
        assert_eq!(MIN_AUDIT_MAX_FILE_BYTES, 65_536);
        let digest = TruncationDigest {
            full_sha256: "0".repeat(64),
            full_bytes: 600,
        };
        let truncations = Truncations {
            caller_identity: Some(digest),
            ..Truncations::default()
        };
        assert!(!truncations.is_empty());

        // The typed error and its path condition are public too, so a
        // consumer can report a rejection rather than a string.
        let error: AuditStoreError = AuditStoreError::UnsafePath {
            path: std::path::PathBuf::from("/var/lib/bootroot/registrar-audit"),
            condition: PathCondition::Symlink,
        };
        assert!(error.to_string().contains("symbolic link"));
    }
}
