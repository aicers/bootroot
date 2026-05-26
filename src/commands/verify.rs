use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use bootroot::db::{check_auth_sync, check_tcp_sync, for_host_runtime, parse_db_dsn};
use ring::digest;
use x509_parser::pem::Pem;

use crate::cli::args::VerifyArgs;
use crate::cli::output::print_verify_plan;
use crate::cli::prompt::Prompt;
use crate::i18n::Messages;
use crate::state::{DeployType, ServiceEntry, StateFile};

const AGENT_BINARY_NAME: &str = "bootroot-agent";

pub(crate) fn run_verify(args: &VerifyArgs, messages: &Messages) -> Result<()> {
    let state_path = StateFile::default_path();
    if !state_path.exists() {
        anyhow::bail!(messages.error_state_missing());
    }
    let state = StateFile::load(&state_path)?;
    let service_name = resolve_verify_service_name(args, messages)?;
    let entry = state
        .services
        .get(&service_name)
        .ok_or_else(|| anyhow::anyhow!(messages.error_service_not_found(&service_name)))?;

    let agent_config = args
        .agent_config
        .as_ref()
        .unwrap_or(&entry.agent_config_path);

    print_verify_plan(&entry.service_name, agent_config, messages);

    let agent_binary = resolve_agent_binary(args.agent_binary.as_deref(), messages)?;
    let status = Command::new(&agent_binary)
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
    verify_ca_bundle(&entry.cert_path, agent_config, messages)?;

    if args.db_check {
        let compose_dir = args
            .compose_file
            .compose_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        verify_db_connectivity(&state, &compose_dir, args.db_timeout.timeout_secs, messages)?;
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

fn verify_db_connectivity(
    state: &StateFile,
    compose_dir: &Path,
    timeout_secs: u64,
    messages: &Messages,
) -> Result<()> {
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
    let stored_dsn = value["db"]["dataSource"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    // ca.json holds the compose-internal DSN (host `postgres`, port `5432`).
    // `verify --db-check` runs on the host, so translate to the host-side
    // pair before any TCP / auth check — otherwise host name resolution
    // fails and `POSTGRES_HOST_PORT` is silently ignored.
    let dsn = for_host_runtime(&stored_dsn, compose_dir)
        .map_err(|_| anyhow::anyhow!(messages.error_invalid_db_dsn()))?;
    let parsed =
        parse_db_dsn(&dsn).map_err(|_| anyhow::anyhow!(messages.error_invalid_db_dsn()))?;
    let timeout = std::time::Duration::from_secs(timeout_secs);
    check_tcp_sync(&parsed.host, parsed.port, timeout)
        .with_context(|| messages.error_db_check_failed())?;
    check_auth_sync(&dsn, timeout).with_context(|| messages.error_db_auth_failed())?;
    Ok(())
}

fn resolve_agent_binary(override_path: Option<&Path>, messages: &Messages) -> Result<PathBuf> {
    let mut candidates = Vec::new();

    if let Some(path) = override_path {
        candidates.push(path.display().to_string());
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
    }

    let sibling = match std::env::current_exe() {
        Ok(exe) => exe.parent().map(|dir| dir.join(AGENT_BINARY_NAME)),
        Err(_) => None,
    };
    if let Some(sibling_path) = sibling.as_ref() {
        candidates.push(sibling_path.display().to_string());
        if sibling_path.is_file() {
            return Ok(sibling_path.clone());
        }
    }

    let (found, path_candidates) = find_on_path(AGENT_BINARY_NAME);
    for candidate in &path_candidates {
        candidates.push(candidate.display().to_string());
    }
    if let Some(path) = found {
        return Ok(path);
    }
    if path_candidates.is_empty() {
        candidates.push(format!("$PATH (unset; searched for {AGENT_BINARY_NAME})"));
    }

    anyhow::bail!(messages.error_bootroot_agent_not_found(&candidates.join(", ")));
}

fn find_on_path(name: &str) -> (Option<PathBuf>, Vec<PathBuf>) {
    let mut checked = Vec::new();
    let Some(path_var) = std::env::var_os("PATH") else {
        return (None, checked);
    };
    let mut found = None;
    for dir in std::env::split_paths(&path_var) {
        // POSIX treats an empty PATH entry (leading/trailing/doubled `:`) as
        // the current working directory, so normalise before searching.
        let search_dir = if dir.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            dir
        };
        let candidate = search_dir.join(name);
        checked.push(candidate.clone());
        if found.is_none() && candidate.is_file() {
            found = Some(candidate);
        }
    }
    (found, checked)
}

fn resolve_verify_service_name(args: &VerifyArgs, messages: &Messages) -> Result<String> {
    if let Some(value) = args.service_name.as_deref() {
        if value.trim().is_empty() {
            anyhow::bail!(messages.error_value_required());
        }
        return Ok(value.to_string());
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

fn verify_cert_san(entry: &ServiceEntry, messages: &Messages) -> Result<()> {
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

/// Asserts that every fingerprint pinned in the agent's
/// `[trust].trusted_ca_sha256` appears in the bundle at
/// `[trust].ca_bundle_path` and that the on-disk leaf chain-verifies
/// against the bundle.
///
/// Closes two distinct silent-failure surfaces:
///
/// - #622: an agent run that shrank the bundle to the intermediate-only
///   chain used to pass `bootroot verify` (which only re-ran the agent
///   and asserted cert/key existence). Downstream TLS clients with
///   default trust behaviour then failed with `unable to get issuer
///   certificate` at request time.
/// - #627: after a destructive trust-anchor rotation, the pinned
///   fingerprints in agent.toml and the bundle on disk both reflect the
///   new generation, but the leaf may still be signed by the previous
///   intermediate. The fingerprint check passes; the chain check
///   surfaces the drift so the operator does not learn about it from a
///   downstream TLS handshake error.
fn verify_ca_bundle(cert_path: &Path, agent_config: &Path, messages: &Messages) -> Result<()> {
    let settings =
        bootroot::config::Settings::new(Some(agent_config.to_path_buf())).map_err(|e| {
            anyhow::anyhow!(messages.verify_agent_config_load_failed(
                &agent_config.display().to_string(),
                &e.to_string()
            ))
        })?;
    let Some(bundle_path) = settings.trust.ca_bundle_path.as_ref() else {
        return Ok(());
    };
    if !settings.trust.trusted_ca_sha256.is_empty() {
        check_ca_bundle_contains_trusted(bundle_path, &settings.trust.trusted_ca_sha256, messages)?;
    }
    check_leaf_chains_to_bundle(cert_path, bundle_path, messages)
}

fn check_leaf_chains_to_bundle(
    cert_path: &Path,
    bundle_path: &Path,
    messages: &Messages,
) -> Result<()> {
    let cert_bytes = std::fs::read(cert_path)
        .with_context(|| messages.error_read_file_failed(&cert_path.display().to_string()))?;
    let bundle_bytes = std::fs::read(bundle_path).map_err(|_| {
        anyhow::anyhow!(messages.verify_ca_bundle_read_failed(&bundle_path.display().to_string()))
    })?;
    let chains = bootroot::cert_chain::leaf_chains_to_bundle(&cert_bytes, &bundle_bytes)
        .map_err(|_| anyhow::anyhow!(messages.verify_cert_parse_failed()))?;
    if !chains {
        anyhow::bail!(messages.verify_cert_chain_failed(
            &cert_path.display().to_string(),
            &bundle_path.display().to_string()
        ));
    }
    Ok(())
}

fn check_ca_bundle_contains_trusted(
    bundle_path: &Path,
    trusted: &[String],
    messages: &Messages,
) -> Result<()> {
    let contents = std::fs::read(bundle_path).map_err(|_| {
        anyhow::anyhow!(messages.verify_ca_bundle_read_failed(&bundle_path.display().to_string()))
    })?;
    let mut present: HashSet<String> = HashSet::new();
    let mut parsed_any = false;
    for pem in Pem::iter_from_buffer(&contents) {
        let pem = pem.map_err(|_| {
            anyhow::anyhow!(
                messages.verify_ca_bundle_parse_failed(&bundle_path.display().to_string())
            )
        })?;
        if pem.label == "CERTIFICATE" {
            present.insert(sha256_hex(&pem.contents));
            parsed_any = true;
        }
    }
    if !parsed_any {
        anyhow::bail!(messages.verify_ca_bundle_parse_failed(&bundle_path.display().to_string()));
    }
    let mut missing: Vec<String> = trusted
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .filter(|fingerprint| !present.contains(fingerprint))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    missing.sort_unstable();
    anyhow::bail!(messages.verify_ca_bundle_missing_fingerprints(
        &bundle_path.display().to_string(),
        &missing.join(", ")
    ));
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = digest::digest(&digest::SHA256, bytes);
    let mut output = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        use std::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn expected_dns_name(entry: &ServiceEntry, messages: &Messages) -> Result<String> {
    match entry.deploy_type {
        DeployType::Daemon => {
            let instance_id = entry
                .instance_id
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!(messages.error_service_instance_id_required()))?;
            Ok(format!(
                "{}.{}.{}.{}",
                instance_id, entry.service_name, entry.hostname, entry.domain
            ))
        }
        DeployType::Docker => {
            let instance_id = entry
                .instance_id
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!(messages.error_service_instance_id_required()))?;
            if entry
                .container_name
                .as_deref()
                .unwrap_or_default()
                .is_empty()
            {
                anyhow::bail!(messages.error_service_container_name_required());
            }
            Ok(format!(
                "{}.{}.{}.{}",
                instance_id, entry.service_name, entry.hostname, entry.domain
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tempfile::tempdir;

    use super::*;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn test_cert_pem(common_name: &str) -> String {
        let mut params = rcgen::CertificateParams::new(vec![common_name.to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.pem()
    }

    fn pem_der(pem: &str) -> Vec<u8> {
        let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        parsed.contents
    }

    #[test]
    fn check_ca_bundle_passes_when_all_trusted_present() {
        let messages = crate::i18n::test_messages();
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("ca-bundle.pem");
        let root_pem = test_cert_pem("root.example");
        let intermediate_pem = test_cert_pem("intermediate.example");
        std::fs::write(&bundle_path, format!("{root_pem}{intermediate_pem}")).unwrap();
        let trusted = vec![
            sha256_hex(&pem_der(&root_pem)),
            sha256_hex(&pem_der(&intermediate_pem)),
        ];

        check_ca_bundle_contains_trusted(&bundle_path, &trusted, &messages).unwrap();
    }

    /// #622: an intermediate-only bundle (the exact post-issuance state
    /// the agent used to leave behind) must trip `bootroot verify` so
    /// the silent failure stops being silent.
    #[test]
    fn check_ca_bundle_fails_when_trusted_fingerprint_missing() {
        let messages = crate::i18n::test_messages();
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("ca-bundle.pem");
        let root_pem = test_cert_pem("root.example");
        let intermediate_pem = test_cert_pem("intermediate.example");
        std::fs::write(&bundle_path, &intermediate_pem).unwrap();
        let root_fp = sha256_hex(&pem_der(&root_pem));
        let trusted = vec![root_fp.clone(), sha256_hex(&pem_der(&intermediate_pem))];

        let err = check_ca_bundle_contains_trusted(&bundle_path, &trusted, &messages).unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains(&root_fp),
            "missing fingerprint must be named: {rendered}"
        );
        assert!(rendered.contains(&bundle_path.display().to_string()));
    }

    fn build_test_ca(label: &str) -> (rcgen::Certificate, rcgen::Issuer<'static, rcgen::KeyPair>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, format!("{label}-root"));
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let cert = params.self_signed(&key).unwrap();
        let issuer = rcgen::Issuer::new(params, key);
        (cert, issuer)
    }

    fn sign_leaf_pem(common_name: &str, issuer: &rcgen::Issuer<'static, rcgen::KeyPair>) -> String {
        let mut params = rcgen::CertificateParams::new(vec![common_name.to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        let key = rcgen::KeyPair::generate().unwrap();
        params.signed_by(&key, issuer).unwrap().pem()
    }

    /// Regression for issue #627: a pinned-fingerprint bundle that
    /// matches the new PKI generation must not mask the fact that the
    /// leaf still chains to the previous one.
    #[test]
    fn check_leaf_chains_fails_when_leaf_signed_by_previous_generation() {
        let messages = crate::i18n::test_messages();
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let bundle_path = dir.path().join("ca-bundle.pem");

        let (_, old_issuer) = build_test_ca("gen1");
        let (new_root, _) = build_test_ca("gen2");
        std::fs::write(&cert_path, sign_leaf_pem("svc.example", &old_issuer)).unwrap();
        std::fs::write(&bundle_path, new_root.pem()).unwrap();

        let err = check_leaf_chains_to_bundle(&cert_path, &bundle_path, &messages).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains(&cert_path.display().to_string()));
        assert!(rendered.contains(&bundle_path.display().to_string()));
    }

    #[test]
    fn check_leaf_chains_passes_when_bundle_matches() {
        let messages = crate::i18n::test_messages();
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let bundle_path = dir.path().join("ca-bundle.pem");

        let (root, issuer) = build_test_ca("gen1");
        std::fs::write(&cert_path, sign_leaf_pem("svc.example", &issuer)).unwrap();
        std::fs::write(&bundle_path, root.pem()).unwrap();

        check_leaf_chains_to_bundle(&cert_path, &bundle_path, &messages).unwrap();
    }

    /// Trusted fingerprints are stored lowercase in agent.toml, but
    /// nothing prevents an operator from typing them uppercase. The
    /// comparison must be case-insensitive so verify does not flag a
    /// false positive on a healthy bundle.
    #[test]
    fn check_ca_bundle_normalises_trusted_fingerprint_case() {
        let messages = crate::i18n::test_messages();
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("ca-bundle.pem");
        let root_pem = test_cert_pem("root.example");
        std::fs::write(&bundle_path, &root_pem).unwrap();
        let trusted = vec![sha256_hex(&pem_der(&root_pem)).to_uppercase()];

        check_ca_bundle_contains_trusted(&bundle_path, &trusted, &messages).unwrap();
    }

    #[test]
    fn check_ca_bundle_fails_when_file_missing() {
        let messages = crate::i18n::test_messages();
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("nope.pem");

        let err = check_ca_bundle_contains_trusted(&bundle_path, &["00".repeat(32)], &messages)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains(&bundle_path.display().to_string()));
    }

    #[test]
    fn check_ca_bundle_fails_when_no_pem_blocks() {
        let messages = crate::i18n::test_messages();
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("ca-bundle.pem");
        std::fs::write(&bundle_path, b"not a pem file").unwrap();

        let err = check_ca_bundle_contains_trusted(&bundle_path, &["00".repeat(32)], &messages)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains(&bundle_path.display().to_string()));
    }

    #[cfg(unix)]
    fn write_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }

    #[cfg(not(unix))]
    fn write_executable(path: &Path) {
        std::fs::write(path, "").unwrap();
    }

    #[test]
    fn resolve_agent_binary_prefers_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        let messages = crate::i18n::test_messages();
        let dir = tempdir().unwrap();
        let explicit = dir.path().join("bootroot-agent");
        write_executable(&explicit);

        let resolved = resolve_agent_binary(Some(&explicit), &messages).unwrap();
        assert_eq!(resolved, explicit);
    }

    #[test]
    fn resolve_agent_binary_falls_back_to_path() {
        let _guard = ENV_LOCK.lock().unwrap();
        let messages = crate::i18n::test_messages();
        let dir = tempdir().unwrap();
        let path_entry = dir.path().to_path_buf();
        let binary = path_entry.join(AGENT_BINARY_NAME);
        write_executable(&binary);

        let original_path = std::env::var_os("PATH");
        // SAFETY: Serialized via ENV_LOCK so no other test mutates PATH concurrently.
        unsafe {
            std::env::set_var("PATH", path_entry.as_os_str());
        }
        let resolved = resolve_agent_binary(None, &messages);
        // SAFETY: Same serialization guarantee as above.
        unsafe {
            match original_path {
                Some(value) => std::env::set_var("PATH", value),
                None => std::env::remove_var("PATH"),
            }
        }

        let resolved = resolved.unwrap();
        assert_eq!(resolved, binary);
    }

    #[test]
    fn resolve_agent_binary_error_names_candidates() {
        let _guard = ENV_LOCK.lock().unwrap();
        let messages = crate::i18n::test_messages();
        let dir = tempdir().unwrap();
        let missing = dir.path().join("no-such-agent");
        let path_dir_a = dir.path().join("path-a");
        let path_dir_b = dir.path().join("path-b");
        std::fs::create_dir_all(&path_dir_a).unwrap();
        std::fs::create_dir_all(&path_dir_b).unwrap();
        let path_value = std::env::join_paths([&path_dir_a, &path_dir_b]).unwrap();

        let original_path = std::env::var_os("PATH");
        // SAFETY: Serialized via ENV_LOCK so no other test mutates PATH concurrently.
        unsafe {
            std::env::set_var("PATH", &path_value);
        }
        let err = resolve_agent_binary(Some(&missing), &messages).unwrap_err();
        // SAFETY: Same serialization guarantee as above.
        unsafe {
            match original_path {
                Some(value) => std::env::set_var("PATH", value),
                None => std::env::remove_var("PATH"),
            }
        }

        let rendered = err.to_string();
        assert!(
            rendered.contains(&missing.display().to_string()),
            "expected override path listed in error, got: {rendered}"
        );
        let expected_a = path_dir_a.join(AGENT_BINARY_NAME);
        let expected_b = path_dir_b.join(AGENT_BINARY_NAME);
        assert!(
            rendered.contains(&expected_a.display().to_string()),
            "expected first PATH candidate listed in error, got: {rendered}"
        );
        assert!(
            rendered.contains(&expected_b.display().to_string()),
            "expected second PATH candidate listed in error, got: {rendered}"
        );
    }

    #[test]
    fn resolve_agent_binary_error_lists_empty_path_segment_as_cwd() {
        let _guard = ENV_LOCK.lock().unwrap();
        let messages = crate::i18n::test_messages();
        let dir = tempdir().unwrap();
        let missing = dir.path().join("no-such-agent");
        let path_dir = dir.path().join("path-dir");
        std::fs::create_dir_all(&path_dir).unwrap();
        // Leading separator yields an empty segment, which POSIX treats as `.`.
        let path_value = std::env::join_paths([PathBuf::new(), path_dir.clone()]).unwrap();

        let original_path = std::env::var_os("PATH");
        // SAFETY: Serialized via ENV_LOCK so no other test mutates PATH concurrently.
        unsafe {
            std::env::set_var("PATH", &path_value);
        }
        let err = resolve_agent_binary(Some(&missing), &messages).unwrap_err();
        // SAFETY: Same serialization guarantee as above.
        unsafe {
            match original_path {
                Some(value) => std::env::set_var("PATH", value),
                None => std::env::remove_var("PATH"),
            }
        }

        let rendered = err.to_string();
        let cwd_candidate = PathBuf::from(".").join(AGENT_BINARY_NAME);
        assert!(
            rendered.contains(&cwd_candidate.display().to_string()),
            "expected empty PATH segment to surface as `{}` candidate, got: {rendered}",
            cwd_candidate.display()
        );
        assert!(
            rendered.contains(&path_dir.join(AGENT_BINARY_NAME).display().to_string()),
            "expected non-empty PATH candidate listed in error, got: {rendered}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_agent_binary_uses_cwd_for_empty_path_segment() {
        let _guard = ENV_LOCK.lock().unwrap();
        let messages = crate::i18n::test_messages();
        let dir = tempdir().unwrap();
        let agent = dir.path().join(AGENT_BINARY_NAME);
        write_executable(&agent);
        let path_dir = dir.path().join("path-dir");
        std::fs::create_dir_all(&path_dir).unwrap();
        // Trailing separator yields an empty segment after the non-empty entry.
        let path_value = std::env::join_paths([path_dir, PathBuf::new()]).unwrap();

        let original_path = std::env::var_os("PATH");
        let original_cwd = std::env::current_dir().unwrap();
        // SAFETY: Serialized via ENV_LOCK; cwd and PATH restored below.
        unsafe {
            std::env::set_var("PATH", &path_value);
        }
        std::env::set_current_dir(dir.path()).unwrap();
        let resolved = resolve_agent_binary(None, &messages);
        std::env::set_current_dir(&original_cwd).unwrap();
        // SAFETY: Same serialization guarantee as above.
        unsafe {
            match original_path {
                Some(value) => std::env::set_var("PATH", value),
                None => std::env::remove_var("PATH"),
            }
        }

        let resolved = resolved.expect("empty PATH segment should resolve via cwd");
        // Relative candidate; resolution used the cwd we set above.
        assert_eq!(resolved, PathBuf::from(".").join(AGENT_BINARY_NAME));
        assert!(agent.is_file());
    }

    #[test]
    fn resolve_agent_binary_error_handles_unset_path() {
        let _guard = ENV_LOCK.lock().unwrap();
        let messages = crate::i18n::test_messages();
        let dir = tempdir().unwrap();
        let missing = dir.path().join("no-such-agent");

        let original_path = std::env::var_os("PATH");
        // SAFETY: Serialized via ENV_LOCK so no other test mutates PATH concurrently.
        unsafe {
            std::env::remove_var("PATH");
        }
        let err = resolve_agent_binary(Some(&missing), &messages).unwrap_err();
        // SAFETY: Same serialization guarantee as above.
        unsafe {
            if let Some(value) = original_path {
                std::env::set_var("PATH", value);
            }
        }

        let rendered = err.to_string();
        assert!(
            rendered.contains("$PATH"),
            "expected unset $PATH noted in error, got: {rendered}"
        );
    }
}
