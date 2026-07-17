use std::io::IsTerminal;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::Duration;

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use crate::cli::args::{InfraInstallArgs, InfraUpArgs};
use crate::commands::constants::RESPONDER_SERVICE_NAME;
use crate::commands::dns_alias::replay_dns_aliases;
use crate::commands::dotenv::write_dotenv;
use crate::commands::guardrails::{
    client_url_from_bind_addr, ensure_all_services_localhost_binding, is_loopback_bind,
    is_wildcard_bind, reject_advertise_addr_for_specific_bind,
    reject_http01_admin_advertise_addr_for_specific_bind,
    reject_stepca_advertise_addr_for_specific_bind, validate_http01_admin_advertise_addr,
    validate_http01_admin_bind, validate_http01_admin_tls, validate_http01_override_binding,
    validate_http01_override_scope, validate_openbao_advertise_addr, validate_openbao_bind,
    validate_openbao_override_binding, validate_openbao_override_scope, validate_openbao_tls,
    validate_stepca_advertise_addr, validate_stepca_bind, validate_stepca_override_binding,
    validate_stepca_override_scope, write_http01_exposed_override, write_openbao_exposed_override,
    write_stepca_exposed_override,
};
use crate::commands::init::{
    DEFAULT_KV_MOUNT, HTTP01_ADMIN_INFRA_CERT_KEY, HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME,
    OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME, OPENBAO_INFRA_CERT_KEY, RESPONDER_COMPOSE_OVERRIDE_NAME,
    RESPONDER_CONFIG_DIR, STEPCA_EXPOSED_COMPOSE_OVERRIDE_NAME, compose_has_responder,
    compose_has_stepca,
};
use crate::commands::openbao_unseal::{prompt_unseal_keys_interactive, read_unseal_keys_from_file};
use crate::i18n::Messages;
use crate::state::StateFile;

const DEFAULT_GRAFANA_ADMIN_PASSWORD: &str = "admin";
// Keep in sync with docker-compose.yml POSTGRES_USER / POSTGRES_DB.
const DEFAULT_POSTGRES_USER: &str = "step";
const DEFAULT_POSTGRES_DB: &str = "stepca";
const UNSEAL_KEYS_PATH: &str = "secrets/openbao/unseal-keys.txt";

/// Total budget for the post-`docker compose up -d` wait that gives the
/// `OpenBao` listener time to bind before the unseal helpers issue their
/// first API call.  Docker reports the container `Started` as soon as
/// the entrypoint runs — for a TLS-enabled non-loopback bind (the
/// reinit-recovery path), several seconds typically elapse before the
/// kernel accepts a TCP connection on the published port.  Mirrors the
/// `OPENBAO_READY_ATTEMPTS * OPENBAO_READY_DELAY_SECS` budget used by
/// `scripts/impl/run-reinit-recovery.sh`'s `wait_for_openbao_listening`.
const OPENBAO_API_WAIT_ATTEMPTS: u32 = 60;
const OPENBAO_API_WAIT_DELAY: Duration = Duration::from_millis(500);

/// Assembles the `docker compose up` argv for `infra install`.
///
/// When `no_build` is `false` (the default), the command builds local
/// images (`--build`), preserving the fresh-clone developer experience.
/// When `no_build` is `true`, it passes `--no-build --pull never` so a
/// pre-loaded image is used exactly as-is and the command fails loudly
/// when a tagged image is absent — the semantics an air-gapped install
/// needs. `--no-build` alone only suppresses building; for an image-only
/// service (as in the deploy compose) Compose's default `missing` pull
/// policy would still fetch an absent image from a registry, which both
/// reaches the network under an air-gapped install and would silently
/// substitute a registry image for the preloaded/release payload. Plain
/// `up` (no `--no-build`) would instead silently build a missing image.
fn build_compose_up_args<'a>(
    compose_str: &'a str,
    no_build: bool,
    svc_refs: &[&'a str],
) -> Vec<&'a str> {
    let mut up_args: Vec<&str> = vec!["compose", "-f", compose_str, "up"];
    if no_build {
        up_args.extend(["--no-build", "--pull", "never"]);
    } else {
        up_args.push("--build");
    }
    up_args.push("-d");
    up_args.extend(svc_refs);
    up_args
}

/// Determines whether `infra install` runs the preliminary `docker compose
/// pull --ignore-pull-failures` before `up`.
///
/// The pull refreshes floating image tags from a registry, so it is skipped
/// when local archives were loaded (`loaded_archives > 0`). It is also
/// skipped whenever `--no-build` is set: that mode implements the air-gapped
/// contract and must never contact a registry, so an absent image fails the
/// install loudly at `up --pull never` rather than being silently fetched or
/// substituted for the preloaded release payload.
fn should_pull_before_up(loaded_archives: usize, no_build: bool) -> bool {
    loaded_archives == 0 && !no_build
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn run_infra_up(args: &InfraUpArgs, messages: &Messages) -> Result<()> {
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
    // Skip the step-ca override when the compose file does not declare
    // the step-ca service — a stored intent from a previous install
    // must not cause a hard failure against a custom compose file.
    let stepca_override =
        if compose_has_stepca(&args.compose_file.compose_file, messages).unwrap_or(false) {
            resolve_stepca_exposed_override(&state_path, compose_dir, messages)?
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
    let stepca_override_str = stepca_override
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
    if let Some(ref s) = stepca_override_str {
        up_args.extend(["-f", s.as_str()]);
    }
    up_args.extend(["up", "-d"]);
    up_args.extend(&svc_refs);
    run_docker(&up_args, "docker compose up", messages)?;

    // Converge secrets ownership so an operator who upgrades and then only
    // ever runs `infra up` also repairs any root-owned CA material. Runs
    // after `up` so the step-ca server image it reuses already exists;
    // step-ca still runs as root here, so a briefly root-owned key does
    // not stop it, and the readiness check below is unaffected. On a
    // legacy tree with `ca.json` the server stays up throughout.
    if should_sweep_secrets_ownership(&args.services, &args.compose_file.compose_file, messages)? {
        let sweep_secrets_dir = resolve_effective_secrets_dir(&state_path, compose_dir)
            .unwrap_or_else(|| compose_dir.join("secrets"));
        let image = resolve_stepca_image(&args.compose_file.compose_file, messages)?;
        sweep_secrets_ownership(&sweep_secrets_dir, &image, messages)?;
    }

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
    // Resolve the secrets_dir from state when present so the unseal
    // helpers can anchor TLS trust on the step-ca root/intermediate
    // bundle.  Without this, the rustls client built by
    // `OpenBaoClient::new` rejects the step-ca-signed OpenBao server
    // cert with `UnknownIssuer` on the reinit-recovery path where
    // OpenBao listens on `https://<non-loopback>:8200`.
    let effective_secrets_dir = resolve_effective_secrets_dir(&state_path, compose_dir);
    if let Some(path) = unseal_file.as_deref() {
        auto_unseal_openbao(
            path,
            &effective_openbao_url,
            effective_secrets_dir.as_deref(),
            messages,
        )
        .await?;
    } else {
        // No key file found — check if OpenBao is sealed and prompt
        // interactively so `infra up` works without --openbao-unseal-from-file.
        maybe_interactive_unseal(
            &effective_openbao_url,
            effective_secrets_dir.as_deref(),
            messages,
        )
        .await?;
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

    // Reject --stepca-bind when the compose file lacks the step-ca
    // service — the generated override defines only
    // `services.step-ca.ports`, which cannot merge into a compose file
    // that never declares the service.
    if args.stepca_bind.is_some() && !compose_has_stepca(&args.compose_file.compose_file, messages)?
    {
        anyhow::bail!(messages.error_stepca_bind_requires_stepca());
    }

    // Validate and resolve step-ca non-loopback bind intent.  step-ca's
    // ACME directory already terminates TLS with the step-ca certificate,
    // so no TLS acknowledgement flag is required.
    let stepca_bind = if let Some(ref bind_addr) = args.stepca_bind {
        validate_stepca_bind(bind_addr, args.stepca_bind_wildcard, messages)?;
        if is_loopback_bind(bind_addr) {
            reject_stepca_advertise_addr_for_specific_bind(
                bind_addr,
                args.stepca_advertise_addr.as_deref(),
                messages,
            )?;
            None
        } else {
            if is_wildcard_bind(bind_addr) {
                match args.stepca_advertise_addr {
                    Some(ref addr) => validate_stepca_advertise_addr(addr, messages)?,
                    None => anyhow::bail!(messages.error_stepca_advertise_addr_required()),
                }
            } else {
                reject_stepca_advertise_addr_for_specific_bind(
                    bind_addr,
                    args.stepca_advertise_addr.as_deref(),
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

    if let Some(ref bind_addr) = stepca_bind {
        write_stepca_exposed_override(compose_dir, bind_addr, messages)?;
        save_stepca_bind_intent(
            bind_addr,
            args.stepca_advertise_addr.as_deref(),
            &args.openbao_url,
            messages,
        )?;
        println!("{}", messages.info_stepca_bind_intent_recorded(bind_addr));
    } else {
        clear_stepca_bind_intent(compose_dir, messages)?;
    }

    // Docker Compose reads .env from the compose file's directory.
    let env_path = compose_dir.join(".env");
    if !env_path.exists() {
        let postgres_password = bootroot::utils::generate_secret(32)
            .with_context(|| messages.error_generate_secret_failed())?;
        let mut entries: Vec<(&str, &str)> = vec![
            ("POSTGRES_USER", DEFAULT_POSTGRES_USER),
            ("POSTGRES_PASSWORD", &postgres_password),
            ("POSTGRES_DB", DEFAULT_POSTGRES_DB),
            ("GRAFANA_ADMIN_PASSWORD", DEFAULT_GRAFANA_ADMIN_PASSWORD),
        ];
        let host_port_str = args.postgres_host_port.map(|p| p.to_string());
        if let Some(ref s) = host_port_str {
            entries.push(("POSTGRES_HOST_PORT", s));
        }
        write_dotenv(&env_path, &entries, messages)?;
        println!("{}", messages.infra_install_env_written());
    } else if let Some(port) = args.postgres_host_port {
        crate::commands::dotenv::update_dotenv_key(
            &env_path,
            "POSTGRES_HOST_PORT",
            &port.to_string(),
            messages,
        )?;
    }

    // Pre-bind the host-side ports the active compose stack will publish
    // so that a collision aborts before `docker compose up` half-creates
    // containers (the §4a half-up state). The flag wins over .env and
    // the process env for postgres.
    //
    // `infra install` always invokes `docker compose up` with the base
    // compose file only — the openbao / http01 / step-ca override files
    // written above are NOT applied here (`infra up` / `init` are the
    // first commands to layer them in).  So even when `--openbao-bind` /
    // `--http01-admin-bind` / `--stepca-bind` is set, the install-time
    // bind is still on 127.0.0.1; the preflight must check those
    // localhost ports regardless of whether an override intent was
    // recorded.
    let postgres_host_port = args
        .postgres_host_port
        .unwrap_or_else(|| bootroot::db::resolve_postgres_host_port(compose_dir));
    preflight_compose_published_ports(&args.services, postgres_host_port)?;

    // Load local images or pull + build.
    let loaded_archives = if let Some(dir) = args.image_archive_dir.as_deref() {
        load_local_images(dir, messages)?
    } else {
        0
    };

    let compose_str = args.compose_file.compose_file.to_string_lossy();
    let svc_refs: Vec<&str> = args.services.iter().map(String::as_str).collect();

    // Build the compose process environment.  When the operator passed
    // `--postgres-host-port`, override any inherited `POSTGRES_HOST_PORT`
    // for the compose subprocess so the flag wins regardless of shell
    // env (Docker Compose otherwise prefers shell env over `.env`).
    let host_port_env: Vec<(String, String)> = args
        .postgres_host_port
        .map(|p| vec![("POSTGRES_HOST_PORT".to_string(), p.to_string())])
        .unwrap_or_default();
    let host_port_env_refs: Vec<(&str, &str)> = host_port_env
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    if should_pull_before_up(loaded_archives, args.no_build) {
        let mut pull_args: Vec<&str> = vec![
            "compose",
            "-f",
            &compose_str,
            "pull",
            "--ignore-pull-failures",
        ];
        pull_args.extend(&svc_refs);
        run_docker_with_env(
            &pull_args,
            &host_port_env_refs,
            "docker compose pull",
            messages,
        )?;
    }

    // Default builds local images (step-ca, bootroot-http01); `--no-build`
    // with `--pull never` uses the pre-loaded images exactly as-is for an
    // air-gapped install, never reaching a registry.
    let up_args = build_compose_up_args(&compose_str, args.no_build, &svc_refs);
    let up_label = if args.no_build {
        "docker compose up --no-build --pull never"
    } else {
        "docker compose up --build"
    };
    run_docker_with_env(&up_args, &host_port_env_refs, up_label, messages)?;

    // Converge secrets ownership before returning so the stack this
    // command brings up has no root-owned CA material left by an earlier
    // rotation or manual init. Runs after `up` so the step-ca server
    // image it reuses exists (loaded from archive or built by `up`).
    if should_sweep_secrets_ownership(&args.services, &args.compose_file.compose_file, messages)? {
        let image = resolve_stepca_image(&args.compose_file.compose_file, messages)?;
        sweep_secrets_ownership(&secrets_dir, &image, messages)?;
    }

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

/// Mount point for the secrets directory inside the ownership-sweep
/// container. Only the host secrets directory is mounted here — nothing
/// else in the tree is reachable from inside the sweep.
const OWNERSHIP_SWEEP_MOUNT: &str = "/secrets";

/// Returns whether the secrets-ownership sweep should run for an `infra`
/// flow.
///
/// Gated on step-ca being genuinely in play: both requested via
/// `--services` and declared by the compose file. On a topology without
/// step-ca there is no CA material under `secrets/` to repair, and the
/// step-ca server image the sweep reuses does not exist there either, so
/// an ungated sweep would fail rather than merely no-op.
fn should_sweep_secrets_ownership(
    services: &[String],
    compose_file: &Path,
    messages: &Messages,
) -> Result<bool> {
    if !services.iter().any(|s| s == "step-ca") {
        return Ok(false);
    }
    compose_has_stepca(compose_file, messages)
}

/// Builds the `docker run` argv for the ownership sweep.
///
/// Kept pure so tests can assert it mounts ONLY the secrets directory and
/// uses `--no-dereference`, so `chown -R` never follows a symlink out of
/// that mount.
fn build_ownership_sweep_args<'a>(
    mount: &'a str,
    user_arg: &'a str,
    image: &'a str,
) -> Vec<&'a str> {
    vec![
        "run",
        "--rm",
        // Intentional root: this container runs `chown`, NOT a `step`
        // subcommand. The `step` helpers must run as the secrets-directory
        // owner; this one needs root to repair files that a prior
        // `--user root` run (an old rotation or the pre-fix manual-init
        // example) left root-owned. A running bootroot process cannot
        // chown files it does not own, which is why the repair needs a
        // container at all. Do not "fix" this to a non-root user.
        "--user",
        "root",
        // Run `chown` directly instead of through the image's default
        // entrypoint. The `rotate` flows reuse the `smallstep/step-ca`
        // helper image here, whose entrypoint would otherwise print a
        // spurious "there is no ca.json config file" warning — the sweep
        // deliberately mounts only the secrets subtree, not `/home/step`.
        // Overriding the entrypoint keeps the sweep visibly just a scoped
        // `chown` container and off the step-ca init path.
        "--entrypoint",
        "chown",
        "-v",
        mount,
        image,
        "-R",
        // Change the symlink itself rather than its referent, so the
        // sweep never follows a link out of the mounted secrets tree.
        "--no-dereference",
        user_arg,
        OWNERSHIP_SWEEP_MOUNT,
    ]
}

/// Resolves the image the compose stack uses for its `step-ca` service by
/// inspecting the container Compose created for it.
///
/// Reusing exactly that image is what keeps the sweep from introducing
/// any image a flow did not already bring up: it is loaded from the
/// archive on the air-gapped path and built by `up --build` on the
/// fresh-source path, and in both the sweep runs only after `up`, so the
/// image already exists.
fn resolve_stepca_image(compose_file: &Path, messages: &Messages) -> Result<String> {
    let container_id =
        docker_compose_output(compose_file, None, &["ps", "-a", "-q", "step-ca"], messages)?;
    let container_id = container_id.trim();
    if container_id.is_empty() {
        anyhow::bail!(messages.error_service_no_container("step-ca"));
    }
    let image = docker_output(
        &["inspect", "--format", "{{.Config.Image}}", container_id],
        messages,
    )?;
    Ok(image.trim().to_string())
}

/// Re-owns every entry under `secrets/` to the directory's own uid/gid
/// via a one-shot root container, repairing files a prior `--user root`
/// step helper (rotation or the documented manual init) left root-owned.
///
/// This is the single intentional root container in the CA tooling: it
/// runs `chown`, so it needs root, whereas every `step` helper runs as
/// the secrets-directory owner. See [`build_ownership_sweep_args`] for
/// the scoping guarantees — it mounts only the secrets directory and does
/// not follow symlinks out of it. The sweep is a no-op on a tree whose
/// ownership is already correct.
///
/// `image` names the container image to run `chown` in. Callers pass an
/// image the flow already has on hand so the sweep introduces no new
/// dependency: the `infra` flows resolve the compose step-ca server image
/// (see [`resolve_stepca_image`]) after `up` has made it available, while
/// the `rotate` flows pass the same `smallstep/step-ca` image their `step`
/// helpers already run.
pub(crate) fn sweep_secrets_ownership(
    secrets_dir: &Path,
    image: &str,
    messages: &Messages,
) -> Result<()> {
    let mount_root = std::fs::canonicalize(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let mount = format!("{}:{OWNERSHIP_SWEEP_MOUNT}", mount_root.display());
    // Ownership follows the directory's own owner, never a fixed uid: the
    // host user and the OpenBao Agents share this directory.
    let meta = std::fs::metadata(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let user_arg = format!("{}:{}", meta.uid(), meta.gid());
    let args = build_ownership_sweep_args(&mount, &user_arg, image);
    run_docker(&args, "docker secrets ownership sweep", messages)?;
    Ok(())
}

/// Aborts when `host:port` is already bound on the local machine. The
/// preflight closes the half-up state where `bootroot-openbao` is
/// running while postgres failed to bind, recovered today only by
/// `docker compose down` + `.env` edit + retry.
///
/// Implementation note: a successful TCP bind means the port was free
/// at this instant; a subsequent `docker compose up` could still race a
/// just-started peer. Acceptable: the diagnostic catches >99% of the
/// recurring symptom and offers an actionable recovery instead.
fn preflight_host_port(host: &str, port: u16, remediation: &str) -> Result<()> {
    let addr = format!("{host}:{port}");
    match std::net::TcpListener::bind(&addr) {
        Ok(listener) => {
            drop(listener);
            Ok(())
        }
        Err(err) => {
            let pid_hint = best_effort_listening_pid(port)
                .map(|hint| format!(" (listener: {hint})"))
                .unwrap_or_default();
            anyhow::bail!("host port {addr} is already in use ({err}){pid_hint}; {remediation}");
        }
    }
}

/// Pre-binds every host-side port the active compose stack will publish.
/// The bound services list is derived from `services` so a partial install
/// (e.g. `--services openbao`) only checks the ports it will actually
/// expose.
///
/// This is called only from `run_infra_install`, which always runs
/// `docker compose up` against the base `docker-compose.yml` only — the
/// openbao / http01 non-loopback override files are deliberately not
/// layered in until `infra up` / `init`.  So the install-time bind is
/// always on 127.0.0.1, and the preflight always checks the localhost
/// ports regardless of any recorded override intent.
fn preflight_compose_published_ports(services: &[String], postgres_host_port: u16) -> Result<()> {
    // Static map of compose-declared host ports for the core services.
    // Kept in sync with docker-compose.yml — adding a published port to
    // a core service requires a matching entry here.
    let postgres_remediation = format!(
        "free port {postgres_host_port}, set POSTGRES_HOST_PORT=<unused-port> in .env, \
         or pass --postgres-host-port <unused-port>"
    );
    let openbao_remediation = "free port 8200 or stop the conflicting listener before retrying \
         `bootroot infra install`"
        .to_string();
    let stepca_remediation = "free port 9000 or stop the conflicting listener before retrying \
         `bootroot infra install`"
        .to_string();
    let http01_remediation = "free port 8080 or stop the conflicting listener before retrying \
         `bootroot infra install`"
        .to_string();

    for service in services {
        match service.as_str() {
            "postgres" => {
                preflight_host_port("127.0.0.1", postgres_host_port, &postgres_remediation)?;
            }
            "openbao" => {
                preflight_host_port("127.0.0.1", 8200, &openbao_remediation)?;
            }
            "step-ca" => {
                preflight_host_port("127.0.0.1", 9000, &stepca_remediation)?;
            }
            "bootroot-http01" => {
                preflight_host_port("127.0.0.1", 8080, &http01_remediation)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Best-effort lookup of the PID/command listening on `port`. Uses
/// `lsof` when available and silently returns `None` when not — the
/// hint is purely additive on top of the failed-bind diagnostic.
fn best_effort_listening_pid(port: u16) -> Option<String> {
    let output = ProcessCommand::new("lsof")
        .args([
            "-nP",
            "-iTCP",
            &format!("-i:{port}"),
            "-sTCP:LISTEN",
            "-Fpcn",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut pid: Option<String> = None;
    let mut command: Option<String> = None;
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix('p') {
            pid = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix('c') {
            command = Some(rest.trim().to_string());
        }
    }
    match (pid, command) {
        (Some(p), Some(c)) => Some(format!("pid {p} ({c})")),
        (Some(p), None) => Some(format!("pid {p}")),
        _ => None,
    }
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

/// Returns the absolute path of the `secrets_dir` recorded in
/// `state.json` when present.  Used so the unseal helpers can build an
/// `OpenBao` client anchored on the step-ca root/intermediate bundle
/// for the non-loopback TLS path.  Returns `None` when the state file
/// is absent or fails to parse — the caller then falls back to the
/// default `OpenBaoClient::new`, which is the right choice for the
/// fresh-install plaintext-loopback flow that has no bundle on disk
/// yet.
fn resolve_effective_secrets_dir(state_path: &Path, compose_dir: &Path) -> Option<PathBuf> {
    if !state_path.exists() {
        return None;
    }
    let state = StateFile::load(state_path).ok()?;
    let secrets_dir = state.secrets_dir();
    if secrets_dir.is_absolute() {
        Some(secrets_dir.to_path_buf())
    } else {
        Some(compose_dir.join(secrets_dir))
    }
}

/// Builds an [`OpenBaoClient`] for the unseal helpers.  When a
/// `secrets_dir` is supplied, prefers [`OpenBaoClient::with_local_trust`]
/// so the rustls trust store includes the step-ca root and intermediate
/// bundles — required to verify the `OpenBao` server cert issued by
/// step-ca on the non-loopback TLS path.  Falls back to
/// [`OpenBaoClient::new`] for the plaintext-loopback / fresh-install
/// path where no bundle exists yet.
fn build_openbao_client(
    openbao_url: &str,
    secrets_dir: Option<&Path>,
    messages: &Messages,
) -> Result<OpenBaoClient> {
    if let Some(dir) = secrets_dir {
        OpenBaoClient::with_local_trust(openbao_url, dir)
            .with_context(|| messages.error_openbao_client_create_failed())
    } else {
        OpenBaoClient::new(openbao_url)
            .with_context(|| messages.error_openbao_client_create_failed())
    }
}

/// Polls `sys/seal-status` until the `OpenBao` listener responds or the
/// budget is exhausted.  Any successful HTTP response (sealed or
/// unsealed, initialized or not) proves the listener is up, so the
/// caller can proceed with `is_initialized()` / `seal_status()` /
/// `unseal()` without racing the post-recreate startup.
///
/// On the final attempt, propagates the underlying transport error so
/// the operator sees the real cause (e.g. TLS handshake failure with
/// `UnknownIssuer` when the trust bundle is wrong) rather than a
/// generic "API never became reachable" message.
async fn wait_for_openbao_api_reachable(client: &OpenBaoClient, messages: &Messages) -> Result<()> {
    for attempt in 0..OPENBAO_API_WAIT_ATTEMPTS {
        match client.seal_status().await {
            Ok(_) => return Ok(()),
            Err(err) => {
                if attempt + 1 == OPENBAO_API_WAIT_ATTEMPTS {
                    return Err(err).with_context(|| messages.error_openbao_seal_status_failed());
                }
            }
        }
        tokio::time::sleep(OPENBAO_API_WAIT_DELAY).await;
    }
    unreachable!("loop above returns on every iteration")
}

async fn auto_unseal_openbao(
    path: &Path,
    openbao_url: &str,
    secrets_dir: Option<&Path>,
    messages: &Messages,
) -> Result<()> {
    println!("{}", messages.warning_openbao_unseal_from_file());
    let keys = read_unseal_keys_from_file(path, messages)?;
    let client = build_openbao_client(openbao_url, secrets_dir, messages)?;

    // `docker compose up -d` returns once the container is Started, not
    // when the OpenBao listener is bound.  Poll a public endpoint until
    // the API answers so the immediately-following `is_initialized()`
    // does not race the listener and fail with `Connection refused`.
    wait_for_openbao_api_reachable(&client, messages).await?;

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
}

/// Checks whether `OpenBao` is sealed and, if so, prompts the user
/// for unseal keys interactively.
///
/// Skips the prompt when `OpenBao` has not been initialized yet (fresh
/// `infra install`) or when stdin is not a terminal (CI / scripted
/// usage).
async fn maybe_interactive_unseal(
    openbao_url: &str,
    secrets_dir: Option<&Path>,
    messages: &Messages,
) -> Result<()> {
    let client = build_openbao_client(openbao_url, secrets_dir, messages)?;

    // See `auto_unseal_openbao` — the OpenBao listener can be slower
    // than `docker compose up -d` returning, so wait for the API to
    // answer before the first `is_initialized()` call.
    wait_for_openbao_api_reachable(&client, messages).await?;

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

/// Resolves the step-ca exposed compose override path if a
/// non-loopback bind intent is stored in `StateFile`.
///
/// Returns `None` when no non-loopback intent is stored.  Returns a
/// hard error when the stored intent exists but the override file is
/// missing or its content does not match the stored intent.  Unlike
/// the `OpenBao` / HTTP-01 admin overrides there is no TLS gate —
/// step-ca's ACME directory always terminates TLS with the step-ca
/// certificate.
pub(crate) fn resolve_stepca_exposed_override(
    state_path: &Path,
    compose_dir: &Path,
    messages: &Messages,
) -> Result<Option<std::path::PathBuf>> {
    if !state_path.exists() {
        return Ok(None);
    }
    let state = StateFile::load(state_path)?;
    let Some(bind_addr) = state.stepca_bind_addr.as_deref() else {
        return Ok(None);
    };
    let override_path = compose_dir
        .join("secrets")
        .join("step-ca")
        .join(STEPCA_EXPOSED_COMPOSE_OVERRIDE_NAME);
    if !override_path.exists() {
        anyhow::bail!(messages.error_stepca_override_file_missing());
    }
    validate_stepca_override_scope(&override_path, messages)?;
    validate_stepca_override_binding(&override_path, bind_addr, messages)?;
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: BTreeMap::new(),
            ..Default::default()
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

/// Persists the step-ca non-loopback bind address to `StateFile`.
fn save_stepca_bind_intent(
    bind_addr: &str,
    advertise_addr: Option<&str>,
    openbao_url: &str,
    messages: &Messages,
) -> Result<()> {
    save_stepca_bind_intent_to(
        &StateFile::default_path(),
        bind_addr,
        advertise_addr,
        openbao_url,
        messages,
    )
}

fn save_stepca_bind_intent_to(
    state_path: &Path,
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: BTreeMap::new(),
            ..Default::default()
        }
    };
    state.stepca_bind_addr = Some(bind_addr.to_string());
    state.stepca_advertise_addr = advertise_addr.map(str::to_string);
    state
        .save(state_path)
        .with_context(|| messages.error_serialize_state_failed())
}

/// Clears a previously stored step-ca non-loopback bind intent and
/// removes the compose override file so that a subsequent `infra up`
/// reverts step-ca's ACME directory to the default loopback publish.
fn clear_stepca_bind_intent(compose_dir: &Path, messages: &Messages) -> Result<()> {
    clear_stepca_bind_intent_to(&StateFile::default_path(), compose_dir, messages)
}

fn clear_stepca_bind_intent_to(
    state_path: &Path,
    compose_dir: &Path,
    messages: &Messages,
) -> Result<()> {
    if !state_path.exists() {
        return Ok(());
    }
    let mut state = StateFile::load(state_path)?;
    if state.stepca_bind_addr.is_none() {
        return Ok(());
    }
    state.stepca_bind_addr = None;
    state.stepca_advertise_addr = None;
    state
        .save(state_path)
        .with_context(|| messages.error_serialize_state_failed())?;
    let override_path = compose_dir
        .join("secrets")
        .join("step-ca")
        .join(STEPCA_EXPOSED_COMPOSE_OVERRIDE_NAME);
    if override_path.exists() {
        std::fs::remove_file(&override_path).with_context(|| {
            messages.error_remove_file_failed(&override_path.display().to_string())
        })?;
    }
    println!("{}", messages.info_stepca_bind_intent_cleared());
    Ok(())
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
    run_docker_with_env(args, &[], context, messages)
}

pub(crate) fn run_docker_with_env(
    args: &[&str],
    env: &[(&str, &str)],
    context: &str,
    messages: &Messages,
) -> Result<()> {
    let mut cmd = ProcessCommand::new("docker");
    cmd.args(args);
    for (key, value) in env {
        cmd.env(key, value);
    }
    let status = cmd
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
    use tempfile::tempdir;

    use super::*;
    use crate::i18n::test_messages;

    const COMPOSE_WITH_STEPCA: &str = "services:\n  openbao:\n    image: openbao/openbao\n  \
        step-ca:\n    image: bootroot-step-ca:0.29.0\n";
    const COMPOSE_WITHOUT_STEPCA: &str =
        "services:\n  openbao:\n    image: openbao/openbao\n  postgres:\n    image: postgres\n";

    fn write_compose(contents: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("docker-compose.yml");
        std::fs::write(&path, contents).expect("write compose");
        (dir, path)
    }

    /// The sweep must run only when step-ca is both requested via
    /// `--services` and declared by the compose file — otherwise there is
    /// no CA material to repair and the reused image does not exist.
    #[test]
    fn should_sweep_secrets_ownership_requires_service_and_compose() {
        let messages = test_messages();
        let (_dir, with_stepca) = write_compose(COMPOSE_WITH_STEPCA);
        let (_dir2, without_stepca) = write_compose(COMPOSE_WITHOUT_STEPCA);
        let with_service = vec!["openbao".to_string(), "step-ca".to_string()];
        let without_service = vec!["openbao".to_string(), "postgres".to_string()];

        assert!(
            should_sweep_secrets_ownership(&with_service, &with_stepca, &messages).unwrap(),
            "runs when step-ca is requested and declared"
        );
        assert!(
            !should_sweep_secrets_ownership(&without_service, &with_stepca, &messages).unwrap(),
            "skipped when step-ca absent from --services"
        );
        assert!(
            !should_sweep_secrets_ownership(&with_service, &without_stepca, &messages).unwrap(),
            "skipped when compose declares no step-ca service"
        );
    }

    /// The sweep container must mount ONLY the secrets directory and chown
    /// with `--no-dereference` so it never follows a symlink out of the
    /// mount. It is also the one deliberately-root container.
    #[test]
    fn build_ownership_sweep_args_scoped_and_no_symlink_following() {
        let mount = "/host/secrets:/secrets";
        let image = "bootroot-step-ca:0.29.0";
        let args = build_ownership_sweep_args(mount, "1000:1000", image);
        let image_pos = args.iter().position(|a| *a == image).expect("image");

        // Exactly one bind mount, and it is the secrets directory.
        let mounts: Vec<&&str> = args
            .iter()
            .zip(args.iter().skip(1))
            .filter_map(|(a, b)| (*a == "-v").then_some(b))
            .collect();
        assert_eq!(mounts, vec![&mount]);
        assert!(
            !args.iter().any(|a| a.contains(":/host") || *a == "/"),
            "no host-root or extra mounts"
        );

        // The sweep overrides the image entrypoint so it runs `chown`
        // directly, never the step-ca init path that would warn about a
        // missing ca.json under the (deliberately unmounted) /home/step.
        let ep_pos = args
            .iter()
            .position(|a| *a == "--entrypoint")
            .expect("--entrypoint");
        assert_eq!(args.get(ep_pos + 1), Some(&"chown"));
        assert!(ep_pos < image_pos, "--entrypoint precedes the image");

        // chown recurses but does not dereference symlinks.
        assert!(args.contains(&"-R"));
        assert!(args.contains(&"--no-dereference"));
        assert!(args.contains(&"1000:1000"));

        // The sweep is the intentional root container.
        let user_pos = args.iter().position(|a| *a == "--user").expect("--user");
        assert_eq!(args.get(user_pos + 1), Some(&"root"));

        // The chown target is the mount point, nothing outside it.
        assert_eq!(args.last(), Some(&OWNERSHIP_SWEEP_MOUNT));
    }

    #[test]
    fn build_compose_up_args_defaults_to_build() {
        let svc_refs = ["openbao", "postgres"];
        let args = build_compose_up_args("docker-compose.yml", false, &svc_refs);
        assert_eq!(
            args,
            vec![
                "compose",
                "-f",
                "docker-compose.yml",
                "up",
                "--build",
                "-d",
                "openbao",
                "postgres",
            ]
        );
    }

    #[test]
    fn build_compose_up_args_no_build_selects_no_build_flag() {
        let svc_refs = ["openbao", "postgres"];
        let args = build_compose_up_args("docker-compose.deploy.yml", true, &svc_refs);
        assert_eq!(
            args,
            vec![
                "compose",
                "-f",
                "docker-compose.deploy.yml",
                "up",
                "--no-build",
                "--pull",
                "never",
                "-d",
                "openbao",
                "postgres",
            ]
        );
        assert!(!args.contains(&"--build"));
    }

    #[test]
    fn should_pull_before_up_pulls_only_without_archives_or_no_build() {
        // Default build path with no local archives: refresh floating tags.
        assert!(should_pull_before_up(0, false));
        // Local archives loaded: images are already present, skip the pull.
        assert!(!should_pull_before_up(3, false));
        // `--no-build` is the air-gapped contract: never reach a registry,
        // even when no archives were loaded (e.g. images preloaded
        // externally, or an empty/wrong --image-archive-dir).
        assert!(!should_pull_before_up(0, true));
        assert!(!should_pull_before_up(2, true));
    }

    #[test]
    fn resolve_effective_secrets_dir_returns_none_without_state() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        assert!(resolve_effective_secrets_dir(&state_path, dir.path()).is_none());
    }

    #[test]
    fn resolve_effective_secrets_dir_returns_absolute_when_state_uses_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let abs_secrets = dir.path().join("custom-secrets");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: Some(abs_secrets.clone()),
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
        };
        state.save(&state_path).unwrap();
        assert_eq!(
            resolve_effective_secrets_dir(&state_path, dir.path()),
            Some(abs_secrets)
        );
    }

    #[test]
    fn resolve_effective_secrets_dir_joins_relative_path_with_compose_dir() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: Some(PathBuf::from("secrets")),
            policies: std::collections::BTreeMap::new(),
            approles: std::collections::BTreeMap::new(),
            services: std::collections::BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
        };
        state.save(&state_path).unwrap();
        assert_eq!(
            resolve_effective_secrets_dir(&state_path, dir.path()),
            Some(dir.path().join("secrets"))
        );
    }

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

    /// Closes #588 §4a: a port collision on the host-side `PostgreSQL`
    /// publish must abort with an actionable message before
    /// `docker compose up` half-creates containers.
    #[test]
    fn preflight_host_port_aborts_when_already_bound() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind sentinel");
        let port = listener.local_addr().expect("addr").port();
        let remediation = "set POSTGRES_HOST_PORT=<unused-port> in .env, \
             or pass --postgres-host-port <unused-port>";
        let err = preflight_host_port("127.0.0.1", port, remediation).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(&port.to_string()),
            "diagnostic must name the busy port, got: {msg}"
        );
        assert!(
            msg.contains("POSTGRES_HOST_PORT"),
            "diagnostic must name the env var to override, got: {msg}"
        );
        assert!(
            msg.contains("--postgres-host-port"),
            "diagnostic must name the CLI flag, got: {msg}"
        );
    }

    #[test]
    fn preflight_host_port_succeeds_when_free() {
        // Pick a free port by binding+dropping the listener. The OS may
        // reassign that ephemeral port to another process before
        // `preflight_host_port` re-binds it (CI runners with high port
        // churn hit this), so retry a handful of times before failing —
        // the goal is to assert the success path, not the kernel's
        // ephemeral-port allocator.
        let mut last_err: Option<anyhow::Error> = None;
        for _ in 0..16 {
            let port = {
                let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
                l.local_addr().expect("addr").port()
            };
            match preflight_host_port("127.0.0.1", port, "free the listener and retry") {
                Ok(()) => return,
                Err(err) => last_err = Some(err),
            }
        }
        panic!(
            "free port must pass preflight after retries: {}",
            last_err.expect("at least one attempt failed")
        );
    }

    /// Closes #588 §4a: `infra install` only invokes `docker compose
    /// up` against the base compose file (the override files written
    /// when `--openbao-bind` / `--http01-admin-bind` is set are not
    /// layered in until `infra up` / `init`), so the install-time bind
    /// is always on 127.0.0.1.  The preflight must therefore check the
    /// localhost openbao / http01 ports unconditionally — skipping them
    /// based on a recorded override intent reintroduces the half-up
    /// state where openbao starts but http01 fails to bind 127.0.0.1:8080.
    #[test]
    fn preflight_compose_published_ports_checks_openbao_localhost_during_install() {
        let listener = std::net::TcpListener::bind("127.0.0.1:8200");
        if listener.is_err() {
            // Port already in use on this host (e.g. a real openbao
            // running locally); the preflight must still detect the
            // collision rather than skip it.
            let err = preflight_compose_published_ports(&["openbao".to_string()], 5433)
                .expect_err("preflight must abort when 8200 is busy");
            assert!(err.to_string().contains("8200"), "{err}");
            return;
        }
        drop(listener);
        // 8200 free: the preflight succeeds without any "override skip".
        preflight_compose_published_ports(&["openbao".to_string()], 5433)
            .expect("free 8200 must pass preflight");
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs,
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
    ports: !override
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs,
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs,
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs,
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
        };
        state.save(&state_path).unwrap();
        // Override file must exist for resolve to reach TLS validation.
        write_http01_exposed_override(dir.path(), "192.168.1.10:8080", &messages).unwrap();
        let result = resolve_http01_exposed_override(&state_path, dir.path(), &messages);
        assert!(result.is_err());
    }

    // --- step-ca bind intent tests ---

    /// Builds a `StateFile` with only the step-ca bind fields set.
    fn state_with_stepca_bind(bind_addr: Option<&str>, advertise_addr: Option<&str>) -> StateFile {
        StateFile {
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
            stepca_bind_addr: bind_addr.map(str::to_string),
            stepca_advertise_addr: advertise_addr.map(str::to_string),
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
        }
    }

    #[test]
    fn save_stepca_bind_intent_succeeds_without_existing_state() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        save_stepca_bind_intent_to(
            &state_path,
            "192.168.1.10:9000",
            None,
            "http://localhost:8200",
            &messages,
        )
        .unwrap();
        let state = StateFile::load(&state_path).unwrap();
        assert_eq!(state.stepca_bind_addr.as_deref(), Some("192.168.1.10:9000"));
        assert!(state.stepca_advertise_addr.is_none());
    }

    #[test]
    fn save_stepca_bind_intent_preserves_existing_state() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let mut state = state_with_stepca_bind(None, None);
        state.policies.insert("svc".to_string(), "pol".to_string());
        state.save(&state_path).unwrap();
        save_stepca_bind_intent_to(
            &state_path,
            "10.0.0.5:9000",
            None,
            "http://localhost:8200",
            &messages,
        )
        .unwrap();
        let reloaded = StateFile::load(&state_path).unwrap();
        assert_eq!(reloaded.stepca_bind_addr.as_deref(), Some("10.0.0.5:9000"));
        assert!(
            reloaded.policies.contains_key("svc"),
            "existing state fields must be preserved"
        );
    }

    #[test]
    fn save_stepca_bind_intent_persists_advertise_addr() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        save_stepca_bind_intent_to(
            &state_path,
            "0.0.0.0:9000",
            Some("192.168.1.10:9000"),
            "http://localhost:8200",
            &messages,
        )
        .unwrap();
        let state = StateFile::load(&state_path).unwrap();
        assert_eq!(state.stepca_bind_addr.as_deref(), Some("0.0.0.0:9000"));
        assert_eq!(
            state.stepca_advertise_addr.as_deref(),
            Some("192.168.1.10:9000")
        );
    }

    #[test]
    fn save_stepca_bind_intent_errors_on_malformed_state() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        std::fs::write(&state_path, "NOT VALID JSON").unwrap();
        let result = save_stepca_bind_intent_to(
            &state_path,
            "192.168.1.10:9000",
            None,
            "http://localhost:8200",
            &messages,
        );
        assert!(result.is_err(), "malformed state file must be a hard error");
    }

    #[test]
    fn clear_stepca_bind_intent_removes_state_and_override() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        state_with_stepca_bind(Some("192.168.1.10:9000"), None)
            .save(&state_path)
            .unwrap();
        let override_dir = dir.path().join("secrets").join("step-ca");
        std::fs::create_dir_all(&override_dir).unwrap();
        let override_path = override_dir.join(STEPCA_EXPOSED_COMPOSE_OVERRIDE_NAME);
        std::fs::write(&override_path, "placeholder").unwrap();

        clear_stepca_bind_intent_to(&state_path, dir.path(), &messages).unwrap();

        let reloaded = StateFile::load(&state_path).unwrap();
        assert!(
            reloaded.stepca_bind_addr.is_none(),
            "bind intent must be cleared from state"
        );
        assert!(
            !override_path.exists(),
            "compose override file must be removed"
        );
    }

    #[test]
    fn clear_stepca_bind_intent_clears_advertise_addr() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        state_with_stepca_bind(Some("0.0.0.0:9000"), Some("192.168.1.10:9000"))
            .save(&state_path)
            .unwrap();

        clear_stepca_bind_intent_to(&state_path, dir.path(), &messages).unwrap();

        let reloaded = StateFile::load(&state_path).unwrap();
        assert!(reloaded.stepca_bind_addr.is_none());
        assert!(
            reloaded.stepca_advertise_addr.is_none(),
            "advertise addr must be cleared together with bind intent"
        );
    }

    #[test]
    fn clear_stepca_bind_intent_noop_without_state_file() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        assert!(clear_stepca_bind_intent_to(&state_path, dir.path(), &messages).is_ok());
    }

    #[test]
    fn resolve_stepca_override_returns_none_when_no_state_file() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let result = resolve_stepca_exposed_override(&state_path, dir.path(), &messages);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn resolve_stepca_override_returns_none_when_no_bind_addr() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        state_with_stepca_bind(None, None)
            .save(&state_path)
            .unwrap();
        let result = resolve_stepca_exposed_override(&state_path, dir.path(), &messages);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn resolve_stepca_override_errors_when_bind_addr_set_but_override_missing() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        state_with_stepca_bind(Some("192.168.1.10:9000"), None)
            .save(&state_path)
            .unwrap();
        let result = resolve_stepca_exposed_override(&state_path, dir.path(), &messages);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("override") && err.contains("missing"),
            "error: {err}"
        );
    }

    /// Unlike the `OpenBao` / HTTP-01 admin overrides, step-ca needs no
    /// TLS prerequisites — a stored intent plus a matching override file
    /// is sufficient for `infra up` to replay the exposure.
    #[test]
    fn resolve_stepca_override_returns_path_when_override_present() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        state_with_stepca_bind(Some("192.168.1.10:9000"), None)
            .save(&state_path)
            .unwrap();
        write_stepca_exposed_override(dir.path(), "192.168.1.10:9000", &messages).unwrap();
        let result = resolve_stepca_exposed_override(&state_path, dir.path(), &messages);
        let path = result.unwrap().expect("override path must be resolved");
        assert!(path.ends_with("secrets/step-ca/docker-compose.stepca-exposed.yml"));
    }

    /// Regression: the documented fresh path `infra install
    /// --stepca-bind` -> `bootroot init` must expose `:9000` without a
    /// separate `infra up`.  This pins the handoff seam: the state and
    /// override exactly as the install side writes them
    /// (`save_stepca_bind_intent_to` + `write_stepca_exposed_override`)
    /// must resolve through `resolve_stepca_exposed_override`, which
    /// init layers into its `docker compose up -d --no-deps step-ca`
    /// invocation.
    #[test]
    fn stepca_install_intent_resolves_for_init_application() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        save_stepca_bind_intent_to(
            &state_path,
            "192.168.1.10:9000",
            None,
            "http://localhost:8200",
            &messages,
        )
        .unwrap();
        write_stepca_exposed_override(dir.path(), "192.168.1.10:9000", &messages).unwrap();
        let result = resolve_stepca_exposed_override(&state_path, dir.path(), &messages);
        let path = result
            .unwrap()
            .expect("install-recorded intent must resolve for init");
        assert!(path.ends_with("secrets/step-ca/docker-compose.stepca-exposed.yml"));
    }

    #[test]
    fn resolve_stepca_override_errors_on_binding_mismatch() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        state_with_stepca_bind(Some("192.168.1.10:9000"), None)
            .save(&state_path)
            .unwrap();
        // Override binds a different address than the stored intent.
        write_stepca_exposed_override(dir.path(), "10.0.0.5:9000", &messages).unwrap();
        let result = resolve_stepca_exposed_override(&state_path, dir.path(), &messages);
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
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
            stepca_bind: None,
            stepca_bind_wildcard: false,
            stepca_advertise_addr: None,
            postgres_host_port: None,
            no_build: false,
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: std::collections::BTreeMap::new(),
            ..Default::default()
        };
        state.save(&state_path).unwrap();

        // Write the exposed override file (required by the function).
        let override_dir = compose_dir.join("secrets").join("responder");
        std::fs::create_dir_all(&override_dir).unwrap();
        std::fs::write(
            override_dir.join(HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME),
            "services:\n  bootroot-http01:\n    ports: !override\n      - \"192.168.1.10:8080:8080\"\n",
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
