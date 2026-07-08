use std::path::Path;

use anyhow::{Context, Result};

use super::io::{read_required_string, read_secret_file, write_secret_file};
use super::openbao_client::build_openbao_client;
use super::summary::{ApplyStatus, status_to_str};
use super::validation::validate_service_name;
use super::{ApplySecretIdArgs, Locale, OutputFormat, SECRET_ID_KEY, SERVICE_KV_BASE, localized};

/// Resolves the CA-bundle PEM for the `AppRole` login transport.
///
/// For an `https://` URL a private CA is mandatory — the operator supplies it
/// via `--ca-bundle-path`, pointing at the same file `bootroot-remote
/// bootstrap` wrote and that the fast-poll agent reads via
/// `[openbao].ca_bundle_path`. Absence fails fast with a clear, localized
/// error instead of an opaque TLS handshake failure. For `http://` no CA is
/// needed and the flag is ignored.
async fn resolve_ca_bundle_pem(
    openbao_url: &str,
    ca_bundle_path: Option<&Path>,
    lang: Locale,
) -> Result<Option<String>> {
    if !bootroot::config::openbao_url_is_https(openbao_url) {
        return Ok(None);
    }
    let path = ca_bundle_path.ok_or_else(|| {
        anyhow::anyhow!(
            "{}",
            localized(
                lang,
                "--ca-bundle-path is required when --openbao-url is https://",
                "--openbao-url이 https://일 때는 --ca-bundle-path가 필요합니다",
            )
        )
    })?;
    let pem = read_secret_file(path, lang).await.with_context(|| {
        localized(
            lang,
            &format!("Failed to read CA bundle from {}", path.display()),
            &format!("CA 번들 파일을 읽지 못했습니다: {}", path.display()),
        )
    })?;
    Ok(Some(pem))
}

// This function intentionally keeps all apply-secret-id logic in one place
// so the single-value variant stays easy to audit and modify separately.
#[allow(clippy::too_many_lines)]
pub(super) async fn run_apply_secret_id(args: ApplySecretIdArgs, lang: Locale) -> Result<i32> {
    validate_service_name(&args.service_name, lang)?;
    let role_id = read_secret_file(&args.role_id_path, lang)
        .await
        .with_context(|| {
            localized(
                lang,
                &format!(
                    "Failed to read role_id from {}",
                    args.role_id_path.display()
                ),
                &format!(
                    "role_id 파일을 읽지 못했습니다: {}",
                    args.role_id_path.display()
                ),
            )
        })?;
    let current_secret_id = read_secret_file(&args.secret_id_path, lang)
        .await
        .with_context(|| {
            localized(
                lang,
                &format!(
                    "Failed to read current secret_id from {}",
                    args.secret_id_path.display()
                ),
                &format!(
                    "현재 secret_id 파일을 읽지 못했습니다: {}",
                    args.secret_id_path.display()
                ),
            )
        })?;

    let ca_bundle_pem =
        resolve_ca_bundle_pem(&args.openbao_url, args.ca_bundle_path.as_deref(), lang).await?;
    // `apply-secret-id` has only a `--ca-bundle-path` PEM and no fingerprint
    // source, so it passes empty pins and stays bundle-anchored (issue #695).
    let mut client = build_openbao_client(&args.openbao_url, ca_bundle_pem.as_deref(), &[], lang)?;
    let token = client
        .login_approle(&role_id, &current_secret_id)
        .await
        .with_context(|| {
            localized(
                lang,
                "OpenBao AppRole login failed",
                "OpenBao AppRole 로그인에 실패했습니다",
            )
        })?;
    client.set_token(token);

    let kv_path = format!("{SERVICE_KV_BASE}/{}/secret_id", args.service_name);
    let data = client
        .read_kv(&args.kv_mount, &kv_path)
        .await
        .with_context(|| {
            localized(
                lang,
                "Failed to read service secret_id from OpenBao",
                "OpenBao에서 서비스 secret_id를 읽지 못했습니다",
            )
        })?;
    let new_secret_id = read_required_string(&data, &[SECRET_ID_KEY, "value"], lang)?;
    let status = write_secret_file(&args.secret_id_path, &new_secret_id)
        .await
        .with_context(|| {
            localized(
                lang,
                &format!(
                    "Failed to write secret_id to {}",
                    args.secret_id_path.display()
                ),
                &format!(
                    "secret_id 파일을 쓰지 못했습니다: {}",
                    args.secret_id_path.display()
                ),
            )
        })?;

    match args.output {
        OutputFormat::Text => {
            let label = match status {
                ApplyStatus::Applied => "applied",
                ApplyStatus::Unchanged => "unchanged",
                ApplyStatus::Skipped => "skipped",
                ApplyStatus::Failed => "failed",
            };
            println!(
                "{}",
                localized(
                    lang,
                    &format!("secret_id: {label}"),
                    &format!("secret_id: {label}"),
                )
            );
        }
        OutputFormat::Json => {
            let payload = serde_json::to_string_pretty(
                &serde_json::json!({ "secret_id": status_to_str(status) }),
            )?;
            println!("{payload}");
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rcgen::{CertificateParams, DnType, IsCa, Issuer, KeyPair};
    use rustls::ServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    /// Generates a private CA and a `localhost` leaf it signs, returning the
    /// CA PEM (as an operator would pass via `--ca-bundle-path`) alongside the
    /// leaf cert/key DER for the test TLS server.
    fn generate_ca_and_leaf() -> (String, Vec<u8>, Vec<u8>) {
        let ca_key = KeyPair::generate().expect("generate CA key");
        let mut ca_params = CertificateParams::new(Vec::new()).expect("CA params");
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed CA");
        let ca_pem = ca_cert.pem();
        let issuer = Issuer::new(ca_params, ca_key);

        let leaf_key = KeyPair::generate().expect("generate leaf key");
        let mut leaf_params =
            CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        leaf_params.is_ca = IsCa::NoCa;
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("signed leaf");
        (ca_pem, leaf_cert.der().to_vec(), leaf_key.serialize_der())
    }

    /// Starts a minimal HTTPS server that answers `200 OK` to any request and
    /// returns its `127.0.0.1` port.
    async fn start_tls_server(cert_der: Vec<u8>, key_der: Vec<u8>) -> u16 {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = CertificateDer::from(cert_der);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("server TLS config");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local addr").port();

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut buf = vec![0u8; 4096];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });

        port
    }

    #[tokio::test]
    async fn build_openbao_client_https_with_ca_trusts_server() {
        let (ca_pem, cert_der, key_der) = generate_ca_and_leaf();
        let port = start_tls_server(cert_der, key_der).await;

        let client = build_openbao_client(
            &format!("https://localhost:{port}"),
            Some(&ca_pem),
            &[],
            Locale::En,
        )
        .expect("https client built from the supplied CA bundle");

        client
            .health_check()
            .await
            .expect("health check succeeds when TLS is anchored to the supplied CA");
    }

    #[tokio::test]
    async fn resolve_ca_bundle_pem_errors_for_https_without_path() {
        let err = resolve_ca_bundle_pem("https://openbao.example:8200", None, Locale::En)
            .await
            .expect_err("https without --ca-bundle-path must fail fast");
        assert!(
            err.to_string().contains("--ca-bundle-path"),
            "error must point operators at --ca-bundle-path, got: {err}"
        );
    }

    #[tokio::test]
    async fn resolve_ca_bundle_pem_returns_none_for_http() {
        // http:// needs no CA bundle even when a path is (harmlessly) supplied.
        let resolved = resolve_ca_bundle_pem(
            "http://openbao.example:8200",
            Some(Path::new("/nonexistent/ca.pem")),
            Locale::En,
        )
        .await
        .expect("http requires no CA bundle");
        assert!(resolved.is_none());
    }

    #[tokio::test]
    async fn resolve_ca_bundle_pem_reads_file_for_https() {
        let dir = tempdir().expect("tempdir");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, "-----BEGIN CERTIFICATE-----\npem\n").expect("write ca");

        let resolved =
            resolve_ca_bundle_pem("https://openbao.example:8200", Some(&ca_path), Locale::En)
                .await
                .expect("https with a readable CA bundle succeeds");
        assert_eq!(
            resolved.as_deref(),
            Some("-----BEGIN CERTIFICATE-----\npem")
        );
    }

    #[tokio::test]
    async fn build_openbao_client_https_without_ca_is_rejected() {
        let err = build_openbao_client("https://openbao.example:8200", None, &[], Locale::En)
            .expect_err("https client without a CA bundle must be rejected");
        assert!(
            err.to_string().contains("CA bundle"),
            "unexpected error: {err}"
        );
    }
}
