use std::io::IsTerminal;
use std::path::Path;
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use crate::cli::args::{InfraInstallArgs, InfraUpArgs};
use crate::commands::constants::RESPONDER_SERVICE_NAME;
use crate::commands::dns_alias::replay_dns_aliases;
use crate::commands::dotenv::write_dotenv;
use crate::commands::guardrails::{
    client_url_from_bind_addr, ensure_all_services_localhost_binding, is_loopback_bind,
    is_wildcard_bind, reject_advertise_addr_for_specific_bind,
    reject_http01_admin_advertise_addr_for_specific_bind, validate_http01_admin_advertise_addr,
    validate_http01_admin_bind, validate_http01_admin_tls, validate_http01_override_binding,
    validate_http01_override_scope, validate_openbao_advertise_addr, validate_openbao_bind,
    validate_openbao_override_binding, validate_openbao_override_scope, validate_openbao_tls,
    write_http01_exposed_override, write_openbao_exposed_override,
};
use crate::commands::init::{
    DEFAULT_KV_MOUNT, HTTP01_ADMIN_INFRA_CERT_KEY, HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME,
    OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME, OPENBAO_INFRA_CERT_KEY, RESPONDER_COMPOSE_OVERRIDE_NAME,
    RESPONDER_CONFIG_DIR, compose_has_responder,
};
use crate::commands::openbao_unseal::{prompt_unseal_keys_interactive, read_unseal_keys_from_file};
use crate::i18n::Messages;
use crate::state::StateFile;

const DEFAULT_GRAFANA_ADMIN_PASSWORD: &str = "admin";
// Keep in sync with docker-compose.yml POSTGRES_USER / POSTGRES_DB.
const DEFAULT_POSTGRES_USER: &str = "step";
const DEFAULT_POSTGRES_DB: &str = "stepca";
const UNSEAL_KEYS_PATH: &str = "secrets/openbao/unseal-keys.txt";

#[allow(clippy::too_many_lines)]
pub(crate) fn run_infra_up(args: &InfraUpArgs, messages: &Messages) -> Result<()> {
    ensure_all_services_localhost_binding(&args.compose_file.compose_file, messages)?;

    // Check for stored OpenBao non-loopback bind intent.
    let compose_dir = args
        .compose_file
        .compose_file
        .parent()
        .unwrap_or(Path::new("."));
    let state_path = StateFile::default_path();
    let openbao_override = resolve_openbao_exposed_override(&state_path, compose_dir, messages)?;
    // Skip responder overrides when the compose file does not declare
    // the responder service — a stored intent from a previous install
    // must not cause a hard failure against a custom compose file.
    let has_responder =
        compose_has_responder(&args.compose_file.compose_file, messages).unwrap_or(false);
    let responder_config_override = if has_responder {
        resolve_responder_compose_override(&state_path, compose_dir)?
    } else {
        None
    };
    let http01_override = if has_responder {
        resolve_http01_exposed_override(&state_path, compose_dir, messages)?
    } else {
        None
    };

    // Derive the effective OpenBao URL.  When the non-loopback override
    // is active, OpenBao listens on the bind address with TLS, so the
    // default http://localhost:8200 no longer reaches it.
    let effective_openbao_url = if openbao_override.is_some() {
        effective_openbao_url_from_state(&state_path).unwrap_or_else(|| args.openbao_url.clone())
    } else {
        args.openbao_url.clone()
    };

    let loaded_archives = if let Some(dir) = args.image_archive_dir.as_deref() {
        load_local_images(dir, messages)?
    } else {
        0
    };

    let compose_str = args.compose_file.compose_file.to_string_lossy();
    let svc_refs: Vec<&str> = args.services.iter().map(String::as_str).collect();

    if loaded_archives == 0 {
        let mut pull_args: Vec<&str> = vec![
            "compose",
            "-f",
            &compose_str,
            "pull",
            "--ignore-pull-failures",
        ];
        pull_args.extend(&svc_refs);
        run_docker(&pull_args, "docker compose pull", messages)?;
    }

    let openbao_override_str = openbao_override
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned());
    let responder_config_override_str = responder_config_override
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned());
    let http01_override_str = http01_override
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned());
    let mut up_args: Vec<&str> = vec!["compose", "-f", &compose_str];
    if let Some(ref s) = openbao_override_str {
        up_args.extend(["-f", s.as_str()]);
    }
    // Mount the TLS-enabled responder config before applying the
    // exposed-port override so the container starts with TLS active.
    if let Some(ref s) = responder_config_override_str {
        up_args.extend(["-f", s.as_str()]);
    }
    if let Some(ref s) = http01_override_str {
        up_args.extend(["-f", s.as_str()]);
    }
    up_args.extend(["up", "-d"]);
    up_args.extend(&svc_refs);
    run_docker(&up_args, "docker compose up", messages)?;

    // Auto-detect unseal key file if not explicitly specified.
    // Resolve relative to the compose file directory so custom
    // --compose-file layouts work correctly.
    let compose_dir = args
        .compose_file
        .compose_file
        .parent()
        .unwrap_or(Path::new("."));
    let unseal_file = args.openbao_unseal_from_file.clone().or_else(|| {
        let default_path = compose_dir.join(UNSEAL_KEYS_PATH);
        if default_path.exists() {
            Some(default_path)
        } else {
            None
        }
    });
    if let Some(path) = unseal_file.as_deref() {
        auto_unseal_openbao(path, &effective_openbao_url, messages)?;
    } else {
        // No key file found — check if OpenBao is sealed and prompt
        // interactively so `infra up` works without --openbao-unseal-from-file.
        maybe_interactive_unseal(&effective_openbao_url, messages)?;
    }

    let readiness = collect_readiness(
        &args.compose_file.compose_file,
        None,
        &args.services,
        messages,
    )?;

    for entry in &readiness {
        let update_args = [
            "update",
            "--restart",
            &*args.restart_policy,
            &*entry.container_id,
        ];
        run_docker(&update_args, "docker update", messages)?;
    }

    print_readiness_summary(&readiness, messages);
    ensure_all_healthy(&readiness, messages)?;

    let state_path = StateFile::default_path();
    if state_path.exists()
        && let Ok(state) = StateFile::load(&state_path)
    {
        replay_dns_aliases(&state, messages)?;
    }

    println!("{}", messages.infra_up_completed());
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(crate) fn run_infra_install(args: &InfraInstallArgs, messages: &Messages) -> Result<()> {
    ensure_all_services_localhost_binding(&args.compose_file.compose_file, messages)?;

    // Validate and resolve OpenBao non-loopback bind intent.
    let openbao_bind = if let Some(ref bind_addr) = args.openbao_bind {
        validate_openbao_bind(bind_addr, args.openbao_bind_wildcard, messages)?;
        if is_loopback_bind(bind_addr) {
            reject_advertise_addr_for_specific_bind(
                bind_addr,
                args.openbao_advertise_addr.as_deref(),
                messages,
            )?;
            None
        } else {
            if !args.openbao_tls_required {
                anyhow::bail!(messages.error_openbao_bind_tls_flag_required());
            }
            if is_wildcard_bind(bind_addr) {
                match args.openbao_advertise_addr {
                    Some(ref addr) => validate_openbao_advertise_addr(addr, messages)?,
                    None => anyhow::bail!(messages.error_openbao_advertise_addr_required()),
                }
            } else {
                reject_advertise_addr_for_specific_bind(
                    bind_addr,
                    args.openbao_advertise_addr.as_deref(),
                    messages,
                )?;
            }
            Some(bind_addr.clone())
        }
    } else {
        None
    };

    // Reject --http01-admin-bind when the compose file lacks the
    // responder service — there is nothing to bind TLS to.
    if args.http01_admin_bind.is_some()
        && !compose_has_responder(&args.compose_file.compose_file, messages)?
    {
        anyhow::bail!(messages.error_http01_admin_bind_requires_responder());
    }

    // Validate and resolve HTTP-01 admin non-loopback bind intent.
    // Runs before any state writes so that a validation failure does not
    // leave behind partial OpenBao or HTTP-01 state.
    let http01_admin_bind = if let Some(ref bind_addr) = args.http01_admin_bind {
        validate_http01_admin_bind(bind_addr, args.http01_admin_bind_wildcard, messages)?;
        if is_loopback_bind(bind_addr) {
            reject_http01_admin_advertise_addr_for_specific_bind(
                bind_addr,
                args.http01_admin_advertise_addr.as_deref(),
                messages,
            )?;
            None
        } else {
            if !args.http01_admin_tls_required {
                anyhow::bail!(messages.error_http01_admin_bind_tls_flag_required());
            }
            if is_wildcard_bind(bind_addr) {
                match args.http01_admin_advertise_addr {
                    Some(ref addr) => validate_http01_admin_advertise_addr(addr, messages)?,
                    None => anyhow::bail!(messages.error_http01_admin_advertise_addr_required()),
                }
            } else {
                reject_http01_admin_advertise_addr_for_specific_bind(
                    bind_addr,
                    args.http01_admin_advertise_addr.as_deref(),
                    messages,
                )?;
            }
            Some(bind_addr.clone())
        }
    } else {
        None
    };

    // --- All input validation is complete; begin side-effects. ---

    // Docker Compose resolves relative bind-mount paths (e.g. ./secrets)
    // from the compose file's parent directory, not the process cwd.
    // Create directories there so Docker does not auto-create them as root.
    let compose_dir = args
        .compose_file
        .compose_file
        .parent()
        .unwrap_or(Path::new("."));
    let secrets_dir = compose_dir.join("secrets");
    let certs_dir = compose_dir.join("certs");
    for dir in [&secrets_dir, &certs_dir] {
        if !dir.exists() {
            std::fs::create_dir_all(dir)
                .with_context(|| messages.error_write_file_failed(&dir.display().to_string()))?;
        }
    }
    println!("{}", messages.infra_install_dirs_created());

    // Generate compose override and persist bind intent when the operator
    // opts into a non-loopback OpenBao address.  The override is NOT
    // applied yet — OpenBao starts on 127.0.0.1:8200 as usual.  The
    // override is first applied by `bootroot init` / `infra up` after
    // TLS is validated.
    if let Some(ref bind_addr) = openbao_bind {
        write_openbao_exposed_override(compose_dir, bind_addr, messages)?;
        save_openbao_bind_intent(
            compose_dir,
            bind_addr,
            args.openbao_advertise_addr.as_deref(),
            &args.openbao_url,
            messages,
        )?;
        println!("{}", messages.info_openbao_bind_intent_recorded(bind_addr));
    } else {
        clear_openbao_bind_intent(compose_dir, &args.openbao_url, messages)?;
    }

    if let Some(ref bind_addr) = http01_admin_bind {
        write_http01_exposed_override(compose_dir, bind_addr, messages)?;
        save_http01_admin_bind_intent(
            compose_dir,
            bind_addr,
            args.http01_admin_advertise_addr.as_deref(),
            &args.openbao_url,
            messages,
        )?;
        println!(
            "{}",
            messages.info_http01_admin_bind_intent_recorded(bind_addr)
        );
    } else {
        clear_http01_admin_bind_intent(compose_dir, messages)?;
    }

    // Docker Compose reads .env from the compose file's directory.
    let env_path = compose_dir.join(".env");
    if !env_path.exists() {
        let postgres_password = bootroot::utils::generate_secret(32)
            .with_context(|| messages.error_generate_secret_failed())?;
        write_dotenv(
            &env_path,
            &[
                ("POSTGRES_USER", DEFAULT_POSTGRES_USER),
                ("POSTGRES_PASSWORD", &postgres_password),
                ("POSTGRES_DB", DEFAULT_POSTGRES_DB),
                ("GRAFANA_ADMIN_PASSWORD", DEFAULT_GRAFANA_ADMIN_PASSWORD),
            ],
            messages,
        )?;
        println!("{}", messages.infra_install_env_written());
    }

    // Load local images or pull + build.
    let loaded_archives = if let Some(dir) = args.image_archive_dir.as_deref() {
        load_local_images(dir, messages)?
    } else {
        0
    };

    let compose_str = args.compose_file.compose_file.to_string_lossy();
    let svc_refs: Vec<&str> = args.services.iter().map(String::as_str).collect();

    if loaded_archives == 0 {
        let mut pull_args: Vec<&str> = vec![
            "compose",
            "-f",
            &compose_str,
            "pull",
            "--ignore-pull-failures",
        ];
        pull_args.extend(&svc_refs);
        run_docker(&pull_args, "docker compose pull", messages)?;
    }

    // Use --build to build local images (step-ca, bootroot-http01).
    let mut up_args: Vec<&str> = vec!["compose", "-f", &compose_str, "up", "--build", "-d"];
    up_args.extend(&svc_refs);
    run_docker(&up_args, "docker compose up --build", messages)?;

    // Collect readiness but skip step-ca (it has no config yet).
    let prereq_services: Vec<String> = args
        .services
        .iter()
        .filter(|s| s.as_str() != "step-ca")
        .cloned()
        .collect();
    let readiness = collect_readiness(
        &args.compose_file.compose_file,
        None,
        &prereq_services,
        messages,
    )?;

    for entry in &readiness {
        let update_args = [
            "update",
            "--restart",
            &*args.restart_policy,
            &*entry.container_id,
        ];
        run_docker(&update_args, "docker update", messages)?;
    }

    // Also set restart policy for step-ca if it's in the service list.
    if args.services.iter().any(|s| s == "step-ca") {
        let stepca_services = vec!["step-ca".to_string()];
        if let Ok(stepca_readiness) = collect_readiness(
            &args.compose_file.compose_file,
            None,
            &stepca_services,
            messages,
        ) {
            for entry in &stepca_readiness {
                let update_args = [
                    "update",
                    "--restart",
                    &*args.restart_policy,
                    &*entry.container_id,
                ];
                let _ = run_docker(&update_args, "docker update", messages);
            }
        }
    }

    print_readiness_summary(&readiness, messages);
    ensure_all_healthy(&readiness, messages)?;
    println!("{}", messages.infra_install_stepca_not_checked());

    println!("{}", messages.infra_install_completed());
    Ok(())
}

/// Checks that `OpenBao` and `PostgreSQL` are running and healthy.
///
/// Unlike `ensure_infra_ready`, this does not check step-ca because
/// it may not be bootstrapped yet during the `init` flow.
pub(crate) fn ensure_init_prereqs_ready(compose_file: &Path, messages: &Messages) -> Result<()> {
    let services = vec!["openbao".to_string(), "postgres".to_string()];
    let readiness = collect_readiness(compose_file, None, &services, messages)?;
    ensure_all_healthy(&readiness, messages)?;
    Ok(())
}

fn auto_unseal_openbao(path: &Path, openbao_url: &str, messages: &Messages) -> Result<()> {
    println!("{}", messages.warning_openbao_unseal_from_file());
    let keys = read_unseal_keys_from_file(path, messages)?;
    let runtime = tokio::runtime::Runtime::new()
        .with_context(|| messages.error_runtime_init_failed("infra up"))?;
    runtime.block_on(async {
        let client = OpenBaoClient::new(openbao_url)
            .with_context(|| messages.error_openbao_client_create_failed())?;

        // An uninitialized instance always reports sealed=true but has
        // no unseal keys yet.  A stale key file from a previous run
        // would cause an unseal error, so skip gracefully.
        if !client
            .is_initialized()
            .await
            .with_context(|| messages.error_openbao_init_status_failed())?
        {
            return Ok(());
        }

        for key in &keys {
            client
                .unseal(key)
                .await
                .with_context(|| messages.error_openbao_unseal_failed())?;
        }
        let status = client
            .seal_status()
            .await
            .with_context(|| messages.error_openbao_seal_status_failed())?;
        if status.sealed {
            anyhow::bail!(messages.error_openbao_sealed());
        }
        Ok(())
    })
}

/// Checks whether `OpenBao` is sealed and, if so, prompts the user
/// for unseal keys interactively.
///
/// Skips the prompt when `OpenBao` has not been initialized yet (fresh
/// `infra install`) or when stdin is not a terminal (CI / scripted
/// usage).
fn maybe_interactive_unseal(openbao_url: &str, messages: &Messages) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()
        .with_context(|| messages.error_runtime_init_failed("infra up"))?;
    runtime.block_on(async {
        let client = OpenBaoClient::new(openbao_url)
            .with_context(|| messages.error_openbao_client_create_failed())?;

        // An uninitialized instance always reports sealed=true but has
        // no unseal keys, so prompting is nonsensical.
        if !client
            .is_initialized()
            .await
            .with_context(|| messages.error_openbao_init_status_failed())?
        {
            return Ok(());
        }

        let status = client
            .seal_status()
            .await
            .with_context(|| messages.error_openbao_seal_status_failed())?;
        if !status.sealed {
            return Ok(());
        }

        if !std::io::stdin().is_terminal() {
            eprintln!("{}", messages.warning_openbao_sealed_non_interactive());
            return Ok(());
        }

        let keys = prompt_unseal_keys_interactive(status.t, messages)?;
        for key in &keys {
            client
                .unseal(key)
                .await
                .with_context(|| messages.error_openbao_unseal_failed())?;
        }
        let final_status = client
            .seal_status()
            .await
            .with_context(|| messages.error_openbao_seal_status_failed())?;
        if final_status.sealed {
            anyhow::bail!(messages.error_openbao_sealed());
        }
        Ok(())
    })
}

/// Returns the `OpenBao` exposed compose override path when a
/// non-loopback bind intent is stored in `StateFile`.
///
/// Does **not** validate TLS — call [`validate_openbao_tls`] separately
/// before applying the override.  Returns `None` when no non-loopback
/// intent is stored or the override file does not exist.
#[cfg(test)]
fn find_openbao_exposed_override(
    state_path: &Path,
    compose_dir: &Path,
) -> Option<std::path::PathBuf> {
    if !state_path.exists() {
        return None;
    }
    let state = StateFile::load(state_path).ok()?;
    state.openbao_bind_addr.as_ref()?;
    let override_path = compose_dir
        .join("secrets")
        .join("openbao")
        .join(OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME);
    if override_path.exists() {
        Some(override_path)
    } else {
        None
    }
}

/// Resolves the `OpenBao` exposed compose override path if a
/// non-loopback bind intent is stored in `StateFile`.
///
/// Validates TLS before returning the override path.  Returns `None`
/// when no non-loopback intent is stored.  Returns a hard error when
/// the stored intent exists but the override file is missing or TLS
/// prerequisites are not met.
///
/// # Errors
///
/// Returns a hard error when:
/// - The stored intent exists but the override file is missing.
/// - The override file contains non-`OpenBao` non-loopback bindings.
/// - TLS prerequisites are not met.
pub(crate) fn resolve_openbao_exposed_override(
    state_path: &Path,
    compose_dir: &Path,
    messages: &Messages,
) -> Result<Option<std::path::PathBuf>> {
    if !state_path.exists() {
        return Ok(None);
    }
    let state = StateFile::load(state_path)?;
    let Some(bind_addr) = state.openbao_bind_addr.as_deref() else {
        return Ok(None);
    };
    let override_path = compose_dir
        .join("secrets")
        .join("openbao")
        .join(OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME);
    if !override_path.exists() {
        anyhow::bail!(messages.error_openbao_override_file_missing());
    }
    validate_openbao_override_scope(&override_path, messages)?;
    validate_openbao_override_binding(&override_path, bind_addr, messages)?;
    validate_openbao_tls(compose_dir, state.secrets_dir(), messages)?;
    Ok(Some(override_path))
}

/// Resolves the HTTP-01 admin exposed compose override path if a
/// non-loopback bind intent is stored in `StateFile`.
///
/// Validates TLS before returning the override path.  Returns `None`
/// when no non-loopback intent is stored.  Returns a hard error when
/// the stored intent exists but the override file is missing or TLS
/// prerequisites are not met.
pub(crate) fn resolve_http01_exposed_override(
    state_path: &Path,
    compose_dir: &Path,
    messages: &Messages,
) -> Result<Option<std::path::PathBuf>> {
    if !state_path.exists() {
        return Ok(None);
    }
    let state = StateFile::load(state_path)?;
    let Some(bind_addr) = state.http01_admin_bind_addr.as_deref() else {
        return Ok(None);
    };
    let override_path = compose_dir
        .join("secrets")
        .join("responder")
        .join(HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME);
    if !override_path.exists() {
        anyhow::bail!(messages.error_http01_admin_override_file_missing());
    }
    validate_http01_override_scope(&override_path, messages)?;
    validate_http01_override_binding(&override_path, bind_addr, messages)?;
    let secrets_dir = state.secrets_dir();
    let secrets_base = if secrets_dir.is_relative() {
        compose_dir.join(secrets_dir)
    } else {
        secrets_dir.to_path_buf()
    };
    validate_http01_admin_tls(&secrets_base, messages)?;
    Ok(Some(override_path))
}

/// Resolves the responder compose config override path when HTTP-01
/// admin TLS is active.
///
/// Returns `None` when no HTTP-01 admin bind intent is stored or the
/// override file does not exist (e.g. before `bootroot init` runs).
/// Returns the path when the override is present so that `infra up`
/// mounts the TLS-enabled responder config and cert directory into the
/// container.
fn resolve_responder_compose_override(
    state_path: &Path,
    compose_dir: &Path,
) -> Result<Option<std::path::PathBuf>> {
    if !state_path.exists() {
        return Ok(None);
    }
    let state = StateFile::load(state_path)?;
    if state.http01_admin_bind_addr.is_none() {
        return Ok(None);
    }
    // Derive the override path from the persisted secrets_dir so that
    // non-default --secrets-dir installs are resolved correctly.
    let secrets_dir = state.secrets_dir();
    let secrets_base = if secrets_dir.is_relative() {
        compose_dir.join(secrets_dir)
    } else {
        secrets_dir.to_path_buf()
    };
    let override_path = secrets_base
        .join(RESPONDER_CONFIG_DIR)
        .join(RESPONDER_COMPOSE_OVERRIDE_NAME);
    if override_path.exists() {
        Ok(Some(override_path))
    } else {
        Ok(None)
    }
}

/// Derives the effective `OpenBao` URL from a stored non-loopback bind
/// address.
///
/// Derives the CN-side `OpenBao` URL from the stored bind address.
///
/// Uses `openbao_bind_addr` (not `openbao_advertise_addr`) so that
/// local commands (auto-unseal, service, rotate) reach `OpenBao` via
/// the bind address — mapping wildcards to loopback via
/// `client_url_from_bind_addr`.  The advertise address is consumed
/// separately by remote bootstrap artifact generation.
///
/// Returns `https://<addr>` when state contains a non-loopback bind
/// address, or `None` when no intent is recorded or the state file is
/// missing/unreadable.
fn effective_openbao_url_from_state(state_path: &Path) -> Option<String> {
    if !state_path.exists() {
        return None;
    }
    let state = StateFile::load(state_path).ok()?;
    let addr = state.openbao_bind_addr.as_deref()?;
    Some(client_url_from_bind_addr(addr))
}

/// Returns whether `StateFile` contains a non-loopback `OpenBao` bind
/// intent.
///
/// # Errors
///
/// Returns an error when the state file exists but cannot be read or
/// parsed.  A corrupted state file must not be silently treated as
/// "no intent" because stored intent is the authoritative TLS safety
/// gate.
pub(crate) fn has_openbao_bind_intent(state_path: &Path) -> Result<bool> {
    if !state_path.exists() {
        return Ok(false);
    }
    let state = StateFile::load(state_path)?;
    Ok(state.openbao_bind_addr.is_some())
}

/// Persists the `OpenBao` non-loopback bind address to `StateFile`.
///
/// Creates or updates the state file so that subsequent commands
/// (`bootroot init`, `infra up`) can discover the stored intent.
///
/// # Errors
///
/// Returns a hard error when an existing state file cannot be read or
/// parsed.  A corrupted state file must not be silently replaced,
/// because stored intent is the authoritative TLS safety gate.
fn save_openbao_bind_intent(
    compose_dir: &Path,
    bind_addr: &str,
    advertise_addr: Option<&str>,
    openbao_url: &str,
    messages: &Messages,
) -> Result<()> {
    save_openbao_bind_intent_to(
        &StateFile::default_path(),
        compose_dir,
        bind_addr,
        advertise_addr,
        openbao_url,
        messages,
    )
}

/// Inner implementation that accepts explicit paths for testability.
fn save_openbao_bind_intent_to(
    state_path: &Path,
    compose_dir: &Path,
    bind_addr: &str,
    advertise_addr: Option<&str>,
    openbao_url: &str,
    messages: &Messages,
) -> Result<()> {
    use std::collections::BTreeMap;

    let mut state = if state_path.exists() {
        StateFile::load(state_path)?
    } else {
        StateFile {
            openbao_url: openbao_url.to_string(),
            kv_mount: DEFAULT_KV_MOUNT.to_string(),
            secrets_dir: None,
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: BTreeMap::new(),
        }
    };
    // Always reset openbao_url to the install-time loopback URL so that a
    // reinstall over an already-initialized exposed setup does not leave the
    // old `https://…` endpoint in state before the next `bootroot init`.
    state.openbao_url = openbao_url.to_string();
    state.openbao_bind_addr = Some(bind_addr.to_string());
    state.openbao_advertise_addr = advertise_addr.map(str::to_string);
    // Clear stale infra-cert entry — the previous cert has the wrong SANs
    // for this (possibly different) bind address.  A fresh cert will be
    // issued by the next `bootroot init`.
    state.infra_certs.remove(OPENBAO_INFRA_CERT_KEY);
    state
        .save(state_path)
        .with_context(|| messages.error_serialize_state_failed())?;
    // Restore openbao.hcl to plaintext so that OpenBao does not start with
    // TLS enabled while state says `http://…`.  The next `bootroot init`
    // will re-enable TLS after issuing a fresh certificate.
    crate::commands::init::write_openbao_hcl_plaintext(compose_dir, messages)?;
    Ok(())
}

/// Clears a previously stored non-loopback `OpenBao` bind intent and
/// removes the compose override file so that a subsequent `infra up`
/// does not re-expose `OpenBao` on a non-loopback address.
///
/// This is called when `infra install` runs without `--openbao-bind`,
/// ensuring the latest install always reflects the operator's current
/// intent.
fn clear_openbao_bind_intent(
    compose_dir: &Path,
    openbao_url: &str,
    messages: &Messages,
) -> Result<()> {
    clear_openbao_bind_intent_to(
        &StateFile::default_path(),
        compose_dir,
        openbao_url,
        messages,
    )
}

/// Inner implementation that accepts explicit paths for testability.
fn clear_openbao_bind_intent_to(
    state_path: &Path,
    compose_dir: &Path,
    openbao_url: &str,
    messages: &Messages,
) -> Result<()> {
    if !state_path.exists() {
        return Ok(());
    }
    let mut state = StateFile::load(state_path)?;
    if state.openbao_bind_addr.is_none() {
        return Ok(());
    }
    state.openbao_bind_addr = None;
    state.openbao_advertise_addr = None;
    state.infra_certs.remove(OPENBAO_INFRA_CERT_KEY);
    // Reset the stored URL back to the loopback endpoint so that
    // commands consuming `state.openbao_url` (service, rotate,
    // remote-bootstrap) do not keep talking to the retired external
    // address after a plain reinstall.
    state.openbao_url = openbao_url.to_string();
    state
        .save(state_path)
        .with_context(|| messages.error_serialize_state_failed())?;
    let override_path = compose_dir
        .join("secrets")
        .join("openbao")
        .join(OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME);
    if override_path.exists() {
        std::fs::remove_file(&override_path).with_context(|| {
            messages.error_remove_file_failed(&override_path.display().to_string())
        })?;
    }
    // Restore openbao.hcl to plaintext so OpenBao does not try to
    // load TLS certificates that are no longer issued or renewed.
    crate::commands::init::write_openbao_hcl_plaintext(compose_dir, messages)?;
    println!("{}", messages.info_openbao_bind_intent_cleared());
    Ok(())
}

/// Persists the HTTP-01 admin non-loopback bind address to `StateFile`.
fn save_http01_admin_bind_intent(
    compose_dir: &Path,
    bind_addr: &str,
    advertise_addr: Option<&str>,
    openbao_url: &str,
    messages: &Messages,
) -> Result<()> {
    save_http01_admin_bind_intent_to(
        &StateFile::default_path(),
        compose_dir,
        bind_addr,
        advertise_addr,
        openbao_url,
        messages,
    )
}

fn save_http01_admin_bind_intent_to(
    state_path: &Path,
    compose_dir: &Path,
    bind_addr: &str,
    advertise_addr: Option<&str>,
    openbao_url: &str,
    messages: &Messages,
) -> Result<()> {
    use std::collections::BTreeMap;

    let mut state = if state_path.exists() {
        StateFile::load(state_path)?
    } else {
        StateFile {
            openbao_url: openbao_url.to_string(),
            kv_mount: DEFAULT_KV_MOUNT.to_string(),
            secrets_dir: None,
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: BTreeMap::new(),
        }
    };
    state.http01_admin_bind_addr = Some(bind_addr.to_string());
    state.http01_admin_advertise_addr = advertise_addr.map(str::to_string);
    // Clear stale infra-cert entry — the previous cert has the wrong
    // SANs for this (possibly different) bind address.  A fresh cert
    // will be issued by the next `bootroot init`.
    state.infra_certs.remove(HTTP01_ADMIN_INFRA_CERT_KEY);
    state
        .save(state_path)
        .with_context(|| messages.error_serialize_state_failed())?;
    // Strip TLS from responder config so that `infra up` cannot
    // re-expose the admin API with a stale certificate before the
    // next `bootroot init` issues a fresh one.
    let secrets_dir = state.secrets_dir();
    let secrets_base = if secrets_dir.is_relative() {
        compose_dir.join(secrets_dir)
    } else {
        secrets_dir.to_path_buf()
    };
    crate::commands::init::strip_responder_tls_config(&secrets_base, messages)?;
    Ok(())
}

/// Clears a previously stored HTTP-01 admin non-loopback bind intent.
fn clear_http01_admin_bind_intent(compose_dir: &Path, messages: &Messages) -> Result<()> {
    clear_http01_admin_bind_intent_to(&StateFile::default_path(), compose_dir, messages)
}

fn clear_http01_admin_bind_intent_to(
    state_path: &Path,
    compose_dir: &Path,
    messages: &Messages,
) -> Result<()> {
    if !state_path.exists() {
        return Ok(());
    }
    let mut state = StateFile::load(state_path)?;
    if state.http01_admin_bind_addr.is_none() {
        return Ok(());
    }
    state.http01_admin_bind_addr = None;
    state.http01_admin_advertise_addr = None;
    state.infra_certs.remove(HTTP01_ADMIN_INFRA_CERT_KEY);
    state
        .save(state_path)
        .with_context(|| messages.error_serialize_state_failed())?;
    let override_path = compose_dir
        .join("secrets")
        .join("responder")
        .join(HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME);
    if override_path.exists() {
        std::fs::remove_file(&override_path).with_context(|| {
            messages.error_remove_file_failed(&override_path.display().to_string())
        })?;
    }
    println!("{}", messages.info_http01_admin_bind_intent_cleared());
    Ok(())
}

/// Returns whether `StateFile` contains a non-loopback HTTP-01 admin bind
/// intent.
pub(crate) fn has_http01_admin_bind_intent(state_path: &Path) -> Result<bool> {
    if !state_path.exists() {
        return Ok(false);
    }
    let state = StateFile::load(state_path)?;
    Ok(state.http01_admin_bind_addr.is_some())
}

pub(crate) fn default_infra_services() -> Vec<String> {
    vec![
        "openbao".to_string(),
        "postgres".to_string(),
        "step-ca".to_string(),
        RESPONDER_SERVICE_NAME.to_string(),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContainerReadiness {
    pub(crate) service: String,
    pub(crate) container_id: String,
    pub(crate) status: String,
    pub(crate) health: Option<String>,
}

pub(crate) fn collect_readiness(
    compose_file: &Path,
    profile: Option<&str>,
    services: &[String],
    messages: &Messages,
) -> Result<Vec<ContainerReadiness>> {
    let mut readiness = Vec::with_capacity(services.len());
    for service in services {
        let container_id =
            docker_compose_output(compose_file, profile, &["ps", "-q", service], messages)?;
        let container_id = container_id.trim().to_string();
        if container_id.is_empty() {
            anyhow::bail!(messages.error_service_no_container(service));
        }
        let inspect_output = docker_output(
            &[
                "inspect",
                "--format",
                "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}",
                &container_id,
            ],
            messages,
        )?;
        let (status, health) = parse_container_state(&inspect_output);
        readiness.push(ContainerReadiness {
            service: service.clone(),
            container_id,
            status,
            health,
        });
    }
    Ok(readiness)
}

pub(crate) fn parse_container_state(raw: &str) -> (String, Option<String>) {
    let trimmed = raw.trim();
    let mut parts = trimmed.splitn(2, '|');
    let status = parts.next().unwrap_or_default().to_string();
    let health = parts.next().and_then(|value| {
        let value = value.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    });
    (status, health)
}

fn print_readiness_summary(readiness: &[ContainerReadiness], messages: &Messages) {
    println!("{}", messages.infra_readiness_summary());
    for entry in readiness {
        match entry.health.as_deref() {
            Some(health) => println!(
                "{}",
                messages.readiness_entry_with_health(&entry.service, &entry.status, health)
            ),
            None => println!(
                "{}",
                messages.readiness_entry_without_health(&entry.service, &entry.status)
            ),
        }
    }
}

pub(crate) fn collect_container_failures(readiness: &[ContainerReadiness]) -> Vec<String> {
    let mut failures = Vec::new();
    for entry in readiness {
        if entry.status != "running" {
            failures.push(format!("{} status={}", entry.service, entry.status));
            continue;
        }
        if let Some(health) = entry.health.as_deref()
            && health != "healthy"
        {
            failures.push(format!("{} health={}", entry.service, health));
        }
    }
    failures
}

fn ensure_all_healthy(readiness: &[ContainerReadiness], messages: &Messages) -> Result<()> {
    let failures = collect_container_failures(readiness);
    if failures.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(messages.infra_unhealthy(&failures.join(", ")))
    }
}

fn load_local_images(dir: &Path, messages: &Messages) -> Result<usize> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| messages.error_read_dir_failed(&dir.display().to_string()))?;
    let mut loaded = 0;
    for entry in entries {
        let entry = entry.with_context(|| messages.error_read_dir_entry_failed())?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if !is_image_archive(&path) {
            continue;
        }
        println!("Loading image archive: {}", path.display());
        let path_str = path.to_string_lossy();
        let args = ["load", "-i", path_str.as_ref()];
        run_docker(&args, "docker load", messages)?;
        loaded += 1;
    }
    Ok(loaded)
}

fn is_image_archive(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let ext = Path::new(name).extension().and_then(|ext| ext.to_str());
    if let Some(ext) = ext
        && (ext.eq_ignore_ascii_case("tar") || ext.eq_ignore_ascii_case("tgz"))
    {
        return true;
    }
    name.to_ascii_lowercase().ends_with(".tar.gz")
}

pub(crate) fn run_docker(args: &[&str], context: &str, messages: &Messages) -> Result<()> {
    let status = ProcessCommand::new("docker")
        .args(args)
        .status()
        .with_context(|| messages.error_command_run_failed(context))?;
    if !status.success() {
        anyhow::bail!(messages.error_command_failed_status(context, &status.to_string()));
    }
    Ok(())
}

pub(crate) fn docker_compose_output(
    compose_file: &Path,
    profile: Option<&str>,
    args: &[&str],
    messages: &Messages,
) -> Result<String> {
    let compose_str = compose_file.to_string_lossy();
    let mut cmd = ProcessCommand::new("docker");
    cmd.args(["compose", "-f", compose_str.as_ref()]);
    if let Some(profile) = profile {
        cmd.args(["--profile", profile]);
    }
    cmd.args(args);
    let output = cmd
        .output()
        .with_context(|| messages.error_command_run_failed("docker compose"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(messages.error_docker_compose_failed(&stderr));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub(crate) fn docker_output(args: &[&str], messages: &Messages) -> Result<String> {
    let output = ProcessCommand::new("docker")
        .args(args)
        .output()
        .with_context(|| messages.error_command_run_failed("docker"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(messages.error_docker_command_failed(&stderr));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_image_archive_extensions() {
        assert!(is_image_archive(Path::new("image.tar")));
        assert!(is_image_archive(Path::new("image.TAR")));
        assert!(is_image_archive(Path::new("image.tgz")));
        assert!(is_image_archive(Path::new("image.TGZ")));
        assert!(is_image_archive(Path::new("image.tar.gz")));
        assert!(is_image_archive(Path::new("image.TAR.GZ")));
        assert!(!is_image_archive(Path::new("image.zip")));
        assert!(!is_image_archive(Path::new("image")));
    }

    #[test]
    fn test_parse_container_state_with_health() {
        let (status, health) = parse_container_state("running|healthy\n");
        assert_eq!(status, "running");
        assert_eq!(health.as_deref(), Some("healthy"));
    }

    #[test]
    fn test_parse_container_state_without_health() {
        let (status, health) = parse_container_state("exited|\n");
        assert_eq!(status, "exited");
        assert!(health.is_none());
    }

    #[test]
    fn test_parse_container_state_missing_delimiter() {
        let (status, health) = parse_container_state("running");
        assert_eq!(status, "running");
        assert!(health.is_none());
    }

    #[test]
    fn resolve_override_returns_none_when_no_state_file() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let result = resolve_openbao_exposed_override(&state_path, dir.path(), &messages);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn resolve_override_returns_none_when_no_bind_addr() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        let result = resolve_openbao_exposed_override(&state_path, dir.path(), &messages);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn find_override_returns_none_when_no_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        assert!(find_openbao_exposed_override(&state_path, dir.path()).is_none());
    }

    #[test]
    fn find_override_returns_none_when_no_bind_addr() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        assert!(find_openbao_exposed_override(&state_path, dir.path()).is_none());
    }

    #[test]
    fn find_override_returns_path_when_bind_addr_and_override_present() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        write_openbao_exposed_override(dir.path(), "192.168.1.10:8200", &messages).unwrap();
        assert!(find_openbao_exposed_override(&state_path, dir.path()).is_some());
    }

    #[test]
    fn resolve_override_errors_when_bind_addr_set_but_override_missing() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        // No override file generated — resolve must error, not silently skip.
        let result = resolve_openbao_exposed_override(&state_path, dir.path(), &messages);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("override") && err.contains("missing"),
            "error: {err}"
        );
    }

    #[test]
    fn has_openbao_bind_intent_errors_on_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        std::fs::write(&state_path, "NOT VALID JSON").unwrap();
        let result = has_openbao_bind_intent(&state_path);
        assert!(result.is_err(), "corrupted state must be a hard error");
    }

    #[test]
    fn has_openbao_bind_intent_errors_on_unreadable_state() {
        // Point at a path inside a non-existent directory so the file
        // "exists" check passes but reading fails.  We simulate this by
        // creating a file then removing read permissions.
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        std::fs::write(&state_path, r#"{"openbao_url":"x","kv_mount":"y"}"#).unwrap();
        // Remove read permissions.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o000)).unwrap();
            let result = has_openbao_bind_intent(&state_path);
            // Restore permissions for cleanup.
            std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(result.is_err(), "unreadable state must be a hard error");
        }
    }

    #[test]
    fn resolve_override_errors_on_corrupted_state() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        std::fs::write(&state_path, "{{CORRUPT}}").unwrap();
        let result = resolve_openbao_exposed_override(&state_path, dir.path(), &messages);
        assert!(
            result.is_err(),
            "corrupted state must not be treated as no intent"
        );
    }

    #[test]
    fn resolve_override_errors_when_bind_addr_set_but_tls_missing() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        // Override file must exist for resolve to reach TLS validation.
        write_openbao_exposed_override(dir.path(), "192.168.1.10:8200", &messages).unwrap();
        let result = resolve_openbao_exposed_override(&state_path, dir.path(), &messages);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_override_returns_path_when_tls_and_override_present() {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

        use crate::commands::guardrails::write_openbao_exposed_override;
        use crate::commands::init::{
            CA_CERTS_DIR, CA_ROOT_CERT_FILENAME, OPENBAO_HCL_PATH, OPENBAO_TLS_CERT_PATH,
            OPENBAO_TLS_KEY_PATH,
        };

        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: Some(dir.path().join("secrets")),
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();

        // Generate a proper CA-signed server certificate.
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec!["root.test".to_string()]).unwrap();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Bootroot Root CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.clone().self_signed(&ca_key).unwrap();
        let ca_issuer = Issuer::new(ca_params, ca_key);

        let server_key = KeyPair::generate().unwrap();
        let mut server_params = CertificateParams::new(vec!["server.test".to_string()]).unwrap();
        server_params
            .distinguished_name
            .push(DnType::CommonName, "server.test");
        let server_cert = server_params.signed_by(&server_key, &ca_issuer).unwrap();

        // Create TLS prerequisites with real certs.
        let cert_path = dir.path().join(OPENBAO_TLS_CERT_PATH);
        let key_path = dir.path().join(OPENBAO_TLS_KEY_PATH);
        let hcl = dir.path().join(OPENBAO_HCL_PATH);
        std::fs::create_dir_all(cert_path.parent().unwrap()).unwrap();
        std::fs::write(&cert_path, server_cert.pem()).unwrap();
        std::fs::write(&key_path, server_key.serialize_pem()).unwrap();
        std::fs::create_dir_all(hcl.parent().unwrap()).unwrap();
        std::fs::write(
            &hcl,
            r#"listener "tcp" { tls_cert_file = "/openbao/config/tls/server.crt" tls_key_file = "/openbao/config/tls/server.key" }"#,
        )
        .unwrap();

        // Write step-ca root CA cert.
        let certs_dir = dir.path().join("secrets").join(CA_CERTS_DIR);
        std::fs::create_dir_all(&certs_dir).unwrap();
        std::fs::write(certs_dir.join(CA_ROOT_CERT_FILENAME), ca_cert.pem()).unwrap();

        // Create the override file.
        write_openbao_exposed_override(dir.path(), "192.168.1.10:8200", &messages).unwrap();

        let result = resolve_openbao_exposed_override(&state_path, dir.path(), &messages);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    /// Regression: `save_openbao_bind_intent_to` must fail when an existing
    /// state file is malformed, not silently replace it with a fresh state.
    #[test]
    fn save_bind_intent_errors_on_malformed_state() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        std::fs::write(&state_path, "NOT VALID JSON").unwrap();
        let result = save_openbao_bind_intent_to(
            &state_path,
            dir.path(),
            "192.168.1.10:8200",
            None,
            "http://localhost:8200",
            &messages,
        );
        assert!(
            result.is_err(),
            "malformed state file must be a hard error during install"
        );
    }

    /// Regression: `save_openbao_bind_intent_to` must fail when the state
    /// file exists but is not readable, not silently replace it.
    #[test]
    fn save_bind_intent_errors_on_unreadable_state() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let messages = crate::i18n::test_messages();
        std::fs::write(&state_path, r#"{"openbao_url":"x","kv_mount":"y"}"#).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o000)).unwrap();
            let result = save_openbao_bind_intent_to(
                &state_path,
                dir.path(),
                "192.168.1.10:8200",
                None,
                "http://localhost:8200",
                &messages,
            );
            std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(
                result.is_err(),
                "unreadable state file must be a hard error during install"
            );
        }
    }

    #[test]
    fn save_bind_intent_succeeds_without_existing_state() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let result = save_openbao_bind_intent_to(
            &state_path,
            dir.path(),
            "192.168.1.10:8200",
            None,
            "http://localhost:8200",
            &messages,
        );
        assert!(result.is_ok());
        let state = StateFile::load(&state_path).unwrap();
        assert_eq!(
            state.openbao_bind_addr.as_deref(),
            Some("192.168.1.10:8200")
        );
    }

    #[test]
    fn save_bind_intent_preserves_existing_state() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::from([("svc".to_string(), "pol".to_string())]),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        save_openbao_bind_intent_to(
            &state_path,
            dir.path(),
            "10.0.0.5:8200",
            None,
            "http://localhost:8200",
            &messages,
        )
        .unwrap();
        let reloaded = StateFile::load(&state_path).unwrap();
        assert_eq!(reloaded.openbao_bind_addr.as_deref(), Some("10.0.0.5:8200"));
        assert!(
            reloaded.policies.contains_key("svc"),
            "existing state fields must be preserved"
        );
    }

    /// Regression: re-running `infra install --openbao-bind` over an
    /// already-initialized exposed setup must reset `openbao_url` to
    /// the install-time loopback URL, not leave the old `https://…`
    /// endpoint from a previous `bootroot init`.
    #[test]
    fn save_bind_intent_resets_openbao_url_on_reinstall() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "https://192.168.1.10:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        save_openbao_bind_intent_to(
            &state_path,
            dir.path(),
            "192.168.1.10:8200",
            None,
            "http://localhost:8200",
            &messages,
        )
        .unwrap();
        let reloaded = StateFile::load(&state_path).unwrap();
        assert_eq!(
            reloaded.openbao_url, "http://localhost:8200",
            "reinstall must reset openbao_url to the install-time loopback URL"
        );
    }

    /// Regression: re-running `infra install --openbao-bind` over an
    /// already-TLS-enabled setup must restore `openbao.hcl` to plaintext
    /// and clear the stale infra-cert entry, so the next `bootroot init`
    /// starts from HTTP as intended.
    #[test]
    fn save_bind_intent_restores_plaintext_hcl_on_reinstall() {
        use crate::commands::init::OPENBAO_HCL_PATH;
        use crate::state::{InfraCertEntry, ReloadStrategy};

        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");

        // Simulate a previous `bootroot init` that enabled TLS.
        let hcl_path = dir.path().join(OPENBAO_HCL_PATH);
        std::fs::create_dir_all(hcl_path.parent().unwrap()).unwrap();
        std::fs::write(
            &hcl_path,
            r#"listener "tcp" { tls_cert_file = "/openbao/config/tls/server.crt" }"#,
        )
        .unwrap();

        let mut infra_certs = std::collections::BTreeMap::new();
        infra_certs.insert(
            OPENBAO_INFRA_CERT_KEY.to_string(),
            InfraCertEntry {
                cert_path: "openbao/tls/server.crt".into(),
                key_path: "openbao/tls/server.key".into(),
                sans: vec!["openbao.internal".to_string()],
                renew_before: "720h".to_string(),
                reload_strategy: ReloadStrategy::ContainerRestart {
                    container_name: "openbao".to_string(),
                },
                issued_at: None,
                expires_at: None,
            },
        );
        let state = StateFile {
            openbao_url: "https://192.168.1.10:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs,
        };
        state.save(&state_path).unwrap();

        // Re-run save_openbao_bind_intent_to (simulates `infra install
        // --openbao-bind` over the already-TLS-enabled setup).
        save_openbao_bind_intent_to(
            &state_path,
            dir.path(),
            "192.168.1.10:8200",
            None,
            "http://localhost:8200",
            &messages,
        )
        .unwrap();

        // HCL must be restored to plaintext.
        let content = std::fs::read_to_string(&hcl_path).unwrap();
        assert!(
            content.contains("tls_disable = 1"),
            "HCL must be restored to plaintext after reinstall with --openbao-bind"
        );
        assert!(
            !content.contains("tls_cert_file"),
            "TLS config must be removed from HCL after reinstall with --openbao-bind"
        );

        // Stale infra-cert entry must be cleared.
        let reloaded = StateFile::load(&state_path).unwrap();
        assert!(
            !reloaded.infra_certs.contains_key(OPENBAO_INFRA_CERT_KEY),
            "stale infra-cert entry must be cleared on reinstall"
        );
    }

    /// Regression: re-running `infra install` without `--openbao-bind`
    /// must clear a previously stored bind intent and remove the compose
    /// override so that `infra up` does not re-expose `OpenBao`.
    #[test]
    fn clear_bind_intent_removes_state_and_override() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let loopback_url = "http://127.0.0.1:8200";
        let state = StateFile {
            openbao_url: loopback_url.to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        let override_dir = dir.path().join("secrets").join("openbao");
        std::fs::create_dir_all(&override_dir).unwrap();
        let override_path = override_dir.join(OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME);
        std::fs::write(&override_path, "placeholder").unwrap();

        clear_openbao_bind_intent_to(&state_path, dir.path(), loopback_url, &messages).unwrap();

        let reloaded = StateFile::load(&state_path).unwrap();
        assert!(
            reloaded.openbao_bind_addr.is_none(),
            "bind intent must be cleared from state"
        );
        assert!(
            !override_path.exists(),
            "compose override file must be removed"
        );
    }

    /// `clear_openbao_bind_intent_to` is a no-op when no bind intent
    /// exists.
    #[test]
    fn clear_bind_intent_noop_without_existing_intent() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();

        clear_openbao_bind_intent_to(&state_path, dir.path(), "http://127.0.0.1:8200", &messages)
            .unwrap();

        let reloaded = StateFile::load(&state_path).unwrap();
        assert!(reloaded.openbao_bind_addr.is_none());
    }

    /// `clear_openbao_bind_intent_to` is a no-op when no state file
    /// exists.
    #[test]
    fn clear_bind_intent_noop_without_state_file() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");

        clear_openbao_bind_intent_to(&state_path, dir.path(), "http://127.0.0.1:8200", &messages)
            .unwrap();

        assert!(!state_path.exists());
    }

    /// Regression: a plain `infra install` after a previous
    /// `--openbao-bind` + `bootroot init` cycle must reset
    /// `openbao_url` back to the loopback endpoint.  Without this,
    /// commands that consume `state.openbao_url` (service, rotate,
    /// remote-bootstrap) keep talking to the retired external address.
    #[test]
    fn clear_bind_intent_resets_openbao_url() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        // Simulate state left behind by `bootroot init` after a
        // non-loopback install: `openbao_url` points to the external
        // HTTPS endpoint and `openbao_bind_addr` records the intent.
        let state = StateFile {
            openbao_url: "https://192.168.1.10:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        let override_dir = dir.path().join("secrets").join("openbao");
        std::fs::create_dir_all(&override_dir).unwrap();
        std::fs::write(
            override_dir.join(OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME),
            "placeholder",
        )
        .unwrap();

        let loopback_url = "http://127.0.0.1:8200";
        clear_openbao_bind_intent_to(&state_path, dir.path(), loopback_url, &messages).unwrap();

        let reloaded = StateFile::load(&state_path).unwrap();
        assert!(
            reloaded.openbao_bind_addr.is_none(),
            "bind intent must be cleared"
        );
        assert_eq!(
            reloaded.openbao_url, loopback_url,
            "openbao_url must be reset to the loopback endpoint"
        );
    }

    /// Regression: `resolve_openbao_exposed_override` must reject an
    /// override whose port mapping has been edited to differ from the
    /// bind address stored in state, preventing wildcard-confirmation
    /// bypass and host-port drift.
    #[test]
    fn resolve_override_rejects_mismatched_binding() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        // Write an override with a widened wildcard binding.
        let override_dir = dir.path().join("secrets").join("openbao");
        std::fs::create_dir_all(&override_dir).unwrap();
        std::fs::write(
            override_dir.join(OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME),
            "\
services:
  openbao:
    ports: !reset
      - \"0.0.0.0:8200:8200\"
",
        )
        .unwrap();
        let result = resolve_openbao_exposed_override(&state_path, dir.path(), &messages);
        assert!(result.is_err(), "widened override must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("does not match"),
            "error should mention mismatch: {err}"
        );
    }

    /// Regression: `effective_openbao_url_from_state` must derive the
    /// HTTPS URL from the stored bind address so `infra up` unseals
    /// against the correct endpoint after the non-loopback override is
    /// applied.
    #[test]
    fn effective_url_derived_from_bind_intent() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        let url = effective_openbao_url_from_state(&state_path);
        assert_eq!(url.as_deref(), Some("https://192.168.1.10:8200"));
    }

    #[test]
    fn effective_url_none_without_bind_intent() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        assert!(effective_openbao_url_from_state(&state_path).is_none());
    }

    #[test]
    fn effective_url_none_without_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        assert!(effective_openbao_url_from_state(&state_path).is_none());
    }

    /// Regression: `effective_openbao_url_from_state` must handle
    /// bracketed IPv6 bind addresses correctly.
    #[test]
    fn effective_url_ipv6_bind_address() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: Some("[fd12::1]:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        let url = effective_openbao_url_from_state(&state_path);
        assert_eq!(url.as_deref(), Some("https://[fd12::1]:8200"));
    }

    /// Regression: wildcard bind (`0.0.0.0`) must produce a loopback
    /// client URL (`https://127.0.0.1:8200`), not `https://0.0.0.0:8200`
    /// which is not a usable endpoint.
    #[test]
    fn effective_url_wildcard_bind_maps_to_loopback() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: Some("0.0.0.0:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        let url = effective_openbao_url_from_state(&state_path);
        assert_eq!(url.as_deref(), Some("https://127.0.0.1:8200"));
    }

    /// Regression: IPv6 wildcard bind (`[::]`) must produce an IPv6
    /// loopback client URL.
    #[test]
    fn effective_url_ipv6_wildcard_bind_maps_to_loopback() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: Some("[::]:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        let url = effective_openbao_url_from_state(&state_path);
        assert_eq!(url.as_deref(), Some("https://[::1]:8200"));
    }

    /// `effective_openbao_url_from_state` returns the CN-side URL
    /// derived from the bind address — even when an advertise address
    /// is stored.  The advertise address is consumed separately by
    /// remote bootstrap artifact generation, not by local commands.
    #[test]
    fn effective_url_uses_bind_addr_ignoring_advertise() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: Some("0.0.0.0:8200".to_string()),
            openbao_advertise_addr: Some("192.168.1.10:8200".to_string()),
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        let url = effective_openbao_url_from_state(&state_path);
        assert_eq!(
            url.as_deref(),
            Some("https://127.0.0.1:8200"),
            "CN-side URL must use bind addr (wildcard mapped to loopback), \
             not the advertise addr which is for remote artifacts only"
        );
    }

    /// Regression (#508): `save_openbao_bind_intent_to` must persist
    /// the advertise address so that subsequent `init` and `infra up`
    /// derive a reachable URL for remote bootstrap artifacts.
    #[test]
    fn save_bind_intent_persists_advertise_addr() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        save_openbao_bind_intent_to(
            &state_path,
            dir.path(),
            "0.0.0.0:8200",
            Some("10.0.0.5:8200"),
            "http://localhost:8200",
            &messages,
        )
        .unwrap();
        let state = StateFile::load(&state_path).unwrap();
        assert_eq!(state.openbao_bind_addr.as_deref(), Some("0.0.0.0:8200"));
        assert_eq!(
            state.openbao_advertise_addr.as_deref(),
            Some("10.0.0.5:8200")
        );
    }

    /// Regression: `clear_openbao_bind_intent_to` must remove the
    /// `OpenBao` infra-cert entry so that `rotate infra-cert` does not
    /// keep renewing a certificate for a now-loopback-only install.
    #[test]
    fn clear_bind_intent_removes_openbao_infra_cert() {
        use crate::state::{InfraCertEntry, ReloadStrategy};

        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let mut infra_certs = std::collections::BTreeMap::new();
        infra_certs.insert(
            OPENBAO_INFRA_CERT_KEY.to_string(),
            InfraCertEntry {
                cert_path: dir.path().join("openbao/tls/server.crt"),
                key_path: dir.path().join("openbao/tls/server.key"),
                sans: vec!["openbao.internal".to_string()],
                renew_before: "720h".to_string(),
                reload_strategy: ReloadStrategy::ContainerRestart {
                    container_name: "bootroot-openbao".to_string(),
                },
                issued_at: None,
                expires_at: None,
            },
        );
        let state = StateFile {
            openbao_url: "https://192.168.1.10:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs,
        };
        state.save(&state_path).unwrap();
        let override_dir = dir.path().join("secrets").join("openbao");
        std::fs::create_dir_all(&override_dir).unwrap();
        std::fs::write(
            override_dir.join(OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME),
            "placeholder",
        )
        .unwrap();

        clear_openbao_bind_intent_to(&state_path, dir.path(), "http://127.0.0.1:8200", &messages)
            .unwrap();

        let reloaded = StateFile::load(&state_path).unwrap();
        assert!(
            !reloaded.infra_certs.contains_key(OPENBAO_INFRA_CERT_KEY),
            "openbao infra cert entry must be removed on loopback reinstall"
        );
    }

    /// Regression: `clear_openbao_bind_intent_to` must restore
    /// `openbao.hcl` to the plaintext form so that a loopback
    /// reinstall does not leave `OpenBao` configured for TLS.
    #[test]
    fn clear_bind_intent_restores_plaintext_hcl() {
        use crate::commands::init::OPENBAO_HCL_PATH;

        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "https://192.168.1.10:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        // Write a TLS-enabled HCL to simulate a previous init.
        let hcl_path = dir.path().join(OPENBAO_HCL_PATH);
        std::fs::create_dir_all(hcl_path.parent().unwrap()).unwrap();
        std::fs::write(
            &hcl_path,
            r#"listener "tcp" { tls_cert_file = "/openbao/config/tls/server.crt" }"#,
        )
        .unwrap();
        let override_dir = dir.path().join("secrets").join("openbao");
        std::fs::create_dir_all(&override_dir).unwrap();
        std::fs::write(
            override_dir.join(OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME),
            "placeholder",
        )
        .unwrap();

        clear_openbao_bind_intent_to(&state_path, dir.path(), "http://127.0.0.1:8200", &messages)
            .unwrap();

        let content = std::fs::read_to_string(&hcl_path).unwrap();
        assert!(
            content.contains("tls_disable = 1"),
            "HCL must be restored to plaintext after loopback reinstall"
        );
        assert!(
            !content.contains("tls_cert_file"),
            "TLS config must be removed from HCL after loopback reinstall"
        );
    }

    /// Regression: `clear_openbao_bind_intent_to` must also clear
    /// the advertise address alongside the bind address.
    #[test]
    fn clear_bind_intent_clears_advertise_addr() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "https://192.168.1.10:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: Some("0.0.0.0:8200".to_string()),
            openbao_advertise_addr: Some("192.168.1.10:8200".to_string()),
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        let override_dir = dir.path().join("secrets").join("openbao");
        std::fs::create_dir_all(&override_dir).unwrap();
        std::fs::write(
            override_dir.join(OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME),
            "placeholder",
        )
        .unwrap();

        clear_openbao_bind_intent_to(&state_path, dir.path(), "http://127.0.0.1:8200", &messages)
            .unwrap();

        let reloaded = StateFile::load(&state_path).unwrap();
        assert!(reloaded.openbao_bind_addr.is_none());
        assert!(
            reloaded.openbao_advertise_addr.is_none(),
            "advertise addr must be cleared alongside bind addr"
        );
    }

    // --- HTTP-01 admin bind intent tests ---

    #[test]
    fn save_http01_bind_intent_succeeds_without_existing_state() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        save_http01_admin_bind_intent_to(
            &state_path,
            dir.path(),
            "192.168.1.10:8080",
            None,
            "http://localhost:8200",
            &messages,
        )
        .unwrap();
        let state = StateFile::load(&state_path).unwrap();
        assert_eq!(
            state.http01_admin_bind_addr.as_deref(),
            Some("192.168.1.10:8080")
        );
    }

    #[test]
    fn save_http01_bind_intent_preserves_existing_state() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::from([("svc".to_string(), "pol".to_string())]),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        save_http01_admin_bind_intent_to(
            &state_path,
            dir.path(),
            "10.0.0.5:8080",
            None,
            "http://localhost:8200",
            &messages,
        )
        .unwrap();
        let reloaded = StateFile::load(&state_path).unwrap();
        assert_eq!(
            reloaded.http01_admin_bind_addr.as_deref(),
            Some("10.0.0.5:8080")
        );
        assert!(
            reloaded.policies.contains_key("svc"),
            "existing state fields must be preserved"
        );
    }

    #[test]
    fn save_http01_bind_intent_errors_on_malformed_state() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        std::fs::write(&state_path, "NOT VALID JSON").unwrap();
        let result = save_http01_admin_bind_intent_to(
            &state_path,
            dir.path(),
            "192.168.1.10:8080",
            None,
            "http://localhost:8200",
            &messages,
        );
        assert!(result.is_err(), "malformed state file must be a hard error");
    }

    #[test]
    fn clear_http01_bind_intent_removes_state_and_override() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: Some("192.168.1.10:8080".to_string()),
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        let override_dir = dir.path().join("secrets").join("responder");
        std::fs::create_dir_all(&override_dir).unwrap();
        let override_path = override_dir.join(HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME);
        std::fs::write(&override_path, "placeholder").unwrap();

        clear_http01_admin_bind_intent_to(&state_path, dir.path(), &messages).unwrap();

        let reloaded = StateFile::load(&state_path).unwrap();
        assert!(
            reloaded.http01_admin_bind_addr.is_none(),
            "bind intent must be cleared from state"
        );
        assert!(
            !override_path.exists(),
            "compose override file must be removed"
        );
    }

    /// Regression: clearing the HTTP-01 admin bind intent must remove
    /// the `bootroot-http01` infra-cert entry so that `rotate infra-cert`
    /// does not keep renewing a certificate for a now-loopback-only install.
    #[test]
    fn clear_http01_bind_intent_removes_infra_cert() {
        use crate::state::{InfraCertEntry, ReloadStrategy};

        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let mut infra_certs = std::collections::BTreeMap::new();
        infra_certs.insert(
            HTTP01_ADMIN_INFRA_CERT_KEY.to_string(),
            InfraCertEntry {
                cert_path: dir.path().join("bootroot-http01/tls/server.crt"),
                key_path: dir.path().join("bootroot-http01/tls/server.key"),
                sans: vec!["responder.internal".to_string()],
                renew_before: "720h".to_string(),
                reload_strategy: ReloadStrategy::ContainerSignal {
                    container_name: "bootroot-http01".to_string(),
                    signal: "SIGHUP".to_string(),
                },
                issued_at: None,
                expires_at: None,
            },
        );
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: Some("192.168.1.10:8080".to_string()),
            http01_admin_advertise_addr: None,
            infra_certs,
        };
        state.save(&state_path).unwrap();
        let override_dir = dir.path().join("secrets").join("responder");
        std::fs::create_dir_all(&override_dir).unwrap();
        std::fs::write(
            override_dir.join(HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME),
            "placeholder",
        )
        .unwrap();

        clear_http01_admin_bind_intent_to(&state_path, dir.path(), &messages).unwrap();

        let reloaded = StateFile::load(&state_path).unwrap();
        assert!(
            !reloaded
                .infra_certs
                .contains_key(HTTP01_ADMIN_INFRA_CERT_KEY),
            "http01 infra cert entry must be removed on loopback reinstall"
        );
    }

    /// Regression: re-running `infra install --http01-admin-bind` must
    /// clear a stale `bootroot-http01` infra-cert entry so that the old
    /// SAN set does not survive until the next `bootroot init`.
    #[test]
    fn save_http01_bind_intent_clears_stale_infra_cert() {
        use crate::state::{InfraCertEntry, ReloadStrategy};

        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let mut infra_certs = std::collections::BTreeMap::new();
        infra_certs.insert(
            HTTP01_ADMIN_INFRA_CERT_KEY.to_string(),
            InfraCertEntry {
                cert_path: dir.path().join("bootroot-http01/tls/server.crt"),
                key_path: dir.path().join("bootroot-http01/tls/server.key"),
                sans: vec!["responder.internal".to_string(), "192.168.1.10".to_string()],
                renew_before: "720h".to_string(),
                reload_strategy: ReloadStrategy::ContainerSignal {
                    container_name: "bootroot-http01".to_string(),
                    signal: "SIGHUP".to_string(),
                },
                issued_at: None,
                expires_at: None,
            },
        );
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: Some("192.168.1.10:8080".to_string()),
            http01_admin_advertise_addr: None,
            infra_certs,
        };
        state.save(&state_path).unwrap();

        save_http01_admin_bind_intent_to(
            &state_path,
            dir.path(),
            "10.0.0.5:8080",
            None,
            "http://localhost:8200",
            &messages,
        )
        .unwrap();

        let reloaded = StateFile::load(&state_path).unwrap();
        assert!(
            !reloaded
                .infra_certs
                .contains_key(HTTP01_ADMIN_INFRA_CERT_KEY),
            "stale infra-cert entry must be cleared on reinstall"
        );
    }

    /// Regression: re-running `infra install --http01-admin-bind B` over
    /// an already-initialized install at bind A must strip TLS from the
    /// responder config so that `infra up` before the next `init` cannot
    /// re-expose the admin API with the stale certificate from A.
    #[test]
    fn save_http01_bind_intent_strips_tls_from_responder_config() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let secrets_dir = dir.path().join("secrets");

        // Simulate an already-initialized install: state + TLS-enabled
        // responder config.
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: Some("192.168.1.10:8080".to_string()),
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();

        let config_dir = secrets_dir.join("responder");
        let template_dir = secrets_dir.join("templates");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::create_dir_all(&template_dir).unwrap();

        let tls_config = "\
listen_addr = \"0.0.0.0:80\"\n\
admin_addr = \"0.0.0.0:8080\"\n\
hmac_secret = \"test-hmac\"\n\
tls_cert_path = \"/app/bootroot-http01/tls/server.crt\"\n\
tls_key_path = \"/app/bootroot-http01/tls/server.key\"\n";
        std::fs::write(config_dir.join("responder.toml"), tls_config).unwrap();
        std::fs::write(template_dir.join("responder.toml.ctmpl"), tls_config).unwrap();

        // Re-install with a different bind address.
        save_http01_admin_bind_intent_to(
            &state_path,
            dir.path(),
            "10.0.0.5:8080",
            None,
            "http://localhost:8200",
            &messages,
        )
        .unwrap();

        // Responder config must no longer contain TLS paths.
        let config = std::fs::read_to_string(config_dir.join("responder.toml")).unwrap();
        assert!(
            !config.contains("tls_cert_path"),
            "TLS must be stripped from responder config after reinstall: {config}"
        );
        assert!(
            !config.contains("tls_key_path"),
            "TLS must be stripped from responder config after reinstall: {config}"
        );
        assert!(
            config.contains("hmac_secret"),
            "non-TLS fields must be preserved: {config}"
        );

        let template = std::fs::read_to_string(template_dir.join("responder.toml.ctmpl")).unwrap();
        assert!(
            !template.contains("tls_cert_path"),
            "TLS must be stripped from responder template after reinstall: {template}"
        );
    }

    #[test]
    fn clear_http01_bind_intent_noop_without_state_file() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        clear_http01_admin_bind_intent_to(&state_path, dir.path(), &messages).unwrap();
        assert!(!state_path.exists());
    }

    #[test]
    fn save_http01_bind_intent_persists_advertise_addr() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        save_http01_admin_bind_intent_to(
            &state_path,
            dir.path(),
            "0.0.0.0:8080",
            Some("10.0.0.5:8080"),
            "http://localhost:8200",
            &messages,
        )
        .unwrap();
        let state = StateFile::load(&state_path).unwrap();
        assert_eq!(
            state.http01_admin_bind_addr.as_deref(),
            Some("0.0.0.0:8080")
        );
        assert_eq!(
            state.http01_admin_advertise_addr.as_deref(),
            Some("10.0.0.5:8080")
        );
    }

    #[test]
    fn clear_http01_bind_intent_clears_advertise_addr() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: Some("0.0.0.0:8080".to_string()),
            http01_admin_advertise_addr: Some("192.168.1.10:8080".to_string()),
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        let override_dir = dir.path().join("secrets").join("responder");
        std::fs::create_dir_all(&override_dir).unwrap();
        let override_path = override_dir.join(HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME);
        std::fs::write(&override_path, "placeholder").unwrap();

        clear_http01_admin_bind_intent_to(&state_path, dir.path(), &messages).unwrap();

        let reloaded = StateFile::load(&state_path).unwrap();
        assert!(reloaded.http01_admin_bind_addr.is_none());
        assert!(
            reloaded.http01_admin_advertise_addr.is_none(),
            "advertise addr must be cleared alongside bind addr"
        );
    }

    #[test]
    fn has_http01_admin_bind_intent_returns_false_without_state() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        assert!(!has_http01_admin_bind_intent(&state_path).unwrap());
    }

    #[test]
    fn has_http01_admin_bind_intent_returns_true_when_set() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: Some("192.168.1.10:8080".to_string()),
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        assert!(has_http01_admin_bind_intent(&state_path).unwrap());
    }

    #[test]
    fn has_http01_admin_bind_intent_errors_on_corrupted_state() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        std::fs::write(&state_path, "NOT VALID JSON").unwrap();
        assert!(
            has_http01_admin_bind_intent(&state_path).is_err(),
            "corrupted state must be a hard error"
        );
    }

    #[test]
    fn resolve_http01_override_returns_none_when_no_state_file() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let result = resolve_http01_exposed_override(&state_path, dir.path(), &messages);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn resolve_http01_override_returns_none_when_no_bind_addr() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        let result = resolve_http01_exposed_override(&state_path, dir.path(), &messages);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn resolve_http01_override_errors_when_bind_addr_set_but_override_missing() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: Some("192.168.1.10:8080".to_string()),
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        let result = resolve_http01_exposed_override(&state_path, dir.path(), &messages);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("override") && err.contains("missing"),
            "error: {err}"
        );
    }

    #[test]
    fn resolve_http01_override_returns_path_when_tls_and_override_present() {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

        use crate::commands::guardrails::write_http01_exposed_override;
        use crate::commands::init::{
            CA_CERTS_DIR, CA_ROOT_CERT_FILENAME, RESPONDER_CONFIG_DIR, RESPONDER_CONFIG_NAME,
        };

        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: Some(dir.path().join("secrets")),
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: Some("192.168.1.10:8080".to_string()),
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();

        // Generate a proper CA-signed server certificate.
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec!["root.test".to_string()]).unwrap();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Bootroot Root CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.clone().self_signed(&ca_key).unwrap();
        let ca_issuer = Issuer::new(ca_params, ca_key);

        let server_key = KeyPair::generate().unwrap();
        let mut server_params = CertificateParams::new(vec!["server.test".to_string()]).unwrap();
        server_params
            .distinguished_name
            .push(DnType::CommonName, "server.test");
        let server_cert = server_params.signed_by(&server_key, &ca_issuer).unwrap();

        // Create TLS prerequisites with real certs.
        let responder_dir = dir.path().join("secrets").join(RESPONDER_CONFIG_DIR);
        std::fs::create_dir_all(&responder_dir).unwrap();
        let tls_dir = dir
            .path()
            .join("secrets")
            .join("bootroot-http01")
            .join("tls");
        std::fs::create_dir_all(&tls_dir).unwrap();
        std::fs::write(tls_dir.join("server.crt"), server_cert.pem()).unwrap();
        std::fs::write(tls_dir.join("server.key"), server_key.serialize_pem()).unwrap();

        // Write responder.toml with TLS paths.
        std::fs::write(
            responder_dir.join(RESPONDER_CONFIG_NAME),
            "\
hmac_secret = \"test\"
tls_cert_path = \"/app/bootroot-http01/tls/server.crt\"
tls_key_path = \"/app/bootroot-http01/tls/server.key\"
",
        )
        .unwrap();

        // Write step-ca root CA cert.
        let certs_dir = dir.path().join("secrets").join(CA_CERTS_DIR);
        std::fs::create_dir_all(&certs_dir).unwrap();
        std::fs::write(certs_dir.join(CA_ROOT_CERT_FILENAME), ca_cert.pem()).unwrap();

        // Create the override file.
        write_http01_exposed_override(dir.path(), "192.168.1.10:8080", &messages).unwrap();

        let result = resolve_http01_exposed_override(&state_path, dir.path(), &messages);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn resolve_http01_override_errors_when_tls_missing() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: Some("192.168.1.10:8080".to_string()),
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        // Override file must exist for resolve to reach TLS validation.
        write_http01_exposed_override(dir.path(), "192.168.1.10:8080", &messages).unwrap();
        let result = resolve_http01_exposed_override(&state_path, dir.path(), &messages);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_responder_config_override_returns_none_without_state() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let result = resolve_responder_compose_override(&state_path, dir.path());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn resolve_responder_config_override_returns_none_without_bind_intent() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        let result = resolve_responder_compose_override(&state_path, dir.path());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn resolve_responder_config_override_returns_none_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: Some("192.168.1.10:8080".to_string()),
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();
        // Bind intent present but init has not run yet — override
        // file does not exist.
        let result = resolve_responder_compose_override(&state_path, dir.path());
        assert!(result.unwrap().is_none());
    }

    /// Regression: `infra up` must include the responder config compose
    /// override when HTTP-01 admin TLS is active so the container
    /// restarts with the TLS-enabled config and cert mounts.
    #[test]
    fn resolve_responder_config_override_returns_path_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: Some("192.168.1.10:8080".to_string()),
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();

        // Simulate init having written the override file.
        let override_dir = dir.path().join("secrets").join(RESPONDER_CONFIG_DIR);
        std::fs::create_dir_all(&override_dir).unwrap();
        std::fs::write(
            override_dir.join(RESPONDER_COMPOSE_OVERRIDE_NAME),
            "services: {}",
        )
        .unwrap();

        let result = resolve_responder_compose_override(&state_path, dir.path());
        assert!(
            result.unwrap().is_some(),
            "must return the override path when bind intent and file both exist"
        );
    }

    /// Regression: when `bootroot init` used a non-default `--secrets-dir`,
    /// `resolve_responder_compose_override` must look for the override
    /// file under the persisted `secrets_dir`, not the hardcoded
    /// `<compose_dir>/secrets`.
    #[test]
    fn resolve_responder_config_override_uses_nondefault_secrets_dir() {
        let dir = tempfile::tempdir().unwrap();
        let compose_dir = dir.path().join("compose");
        std::fs::create_dir_all(&compose_dir).unwrap();
        let custom_secrets = dir.path().join("custom-secrets");
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: Some(custom_secrets.clone()),
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: Some("192.168.1.10:8080".to_string()),
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();

        // Write the override under the custom secrets dir (where init
        // would have placed it), NOT under compose_dir/secrets.
        let override_dir = custom_secrets.join(RESPONDER_CONFIG_DIR);
        std::fs::create_dir_all(&override_dir).unwrap();
        std::fs::write(
            override_dir.join(RESPONDER_COMPOSE_OVERRIDE_NAME),
            "services: {}",
        )
        .unwrap();

        let result = resolve_responder_compose_override(&state_path, &compose_dir);
        assert!(
            result.unwrap().is_some(),
            "must find override under custom secrets_dir, not hardcoded compose_dir/secrets"
        );
    }

    /// Regression: `infra install --http01-admin-bind` must reject
    /// early when the compose file lacks `bootroot-http01`, and must
    /// not leave behind any `OpenBao` state from other flags.
    #[test]
    fn infra_install_rejects_http01_admin_bind_without_responder() {
        use crate::cli::args::ComposeFileArgs;

        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        // Compose file without the responder service.
        let compose_path = dir.path().join("docker-compose.yml");
        std::fs::write(&compose_path, "services:\n  openbao:\n    image: openbao\n").unwrap();

        let args = InfraInstallArgs {
            compose_file: ComposeFileArgs {
                compose_file: compose_path,
            },
            services: vec!["openbao".to_string()],
            image_archive_dir: None,
            restart_policy: "always".to_string(),
            openbao_url: "http://localhost:8200".to_string(),
            openbao_bind: None,
            openbao_tls_required: false,
            openbao_bind_wildcard: false,
            openbao_advertise_addr: None,
            http01_admin_bind: Some("192.168.1.10:8080".to_string()),
            http01_admin_tls_required: true,
            http01_admin_bind_wildcard: false,
            http01_admin_advertise_addr: None,
        };
        let err = run_infra_install(&args, &messages).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("bootroot-http01"),
            "expected responder-missing error, got: {msg}"
        );
    }

    /// Regression: `resolve_http01_exposed_override` must resolve a
    /// relative `secrets_dir` against `compose_dir`, not the process
    /// cwd, so that `infra up` from a different directory validates
    /// TLS against the correct path.
    #[test]
    fn resolve_http01_exposed_override_resolves_relative_secrets_dir() {
        let dir = tempfile::tempdir().unwrap();
        let compose_dir = dir.path().join("compose");
        std::fs::create_dir_all(&compose_dir).unwrap();

        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            // Default relative secrets_dir — should resolve against
            // compose_dir, not cwd.
            secrets_dir: None,
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: Some("192.168.1.10:8080".to_string()),
            http01_admin_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
        };
        state.save(&state_path).unwrap();

        // Write the exposed override file (required by the function).
        let override_dir = compose_dir.join("secrets").join("responder");
        std::fs::create_dir_all(&override_dir).unwrap();
        std::fs::write(
            override_dir.join(HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME),
            "services:\n  bootroot-http01:\n    ports: !reset\n      - \"192.168.1.10:8080:8080\"\n",
        )
        .unwrap();

        // The function should look for TLS artefacts under
        // compose_dir/secrets, not ./secrets.  Without the relative-
        // path fix it would resolve against cwd.
        let messages = crate::i18n::test_messages();
        let result = resolve_http01_exposed_override(&state_path, &compose_dir, &messages);
        // We expect a TLS validation error (cert files missing under the
        // correct path), NOT a "config not found" error pointing at cwd.
        let err = result.unwrap_err().to_string();
        let secrets_path = compose_dir.join("secrets");
        assert!(
            err.contains(&secrets_path.display().to_string())
                || err.contains("tls_cert_path")
                || err.contains("responder.toml")
                || err.contains("responder config"),
            "error must reference compose_dir-relative path, got: {err}"
        );
    }
}
