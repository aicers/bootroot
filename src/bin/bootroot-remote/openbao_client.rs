use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use super::{Locale, localized};

/// Creates an [`OpenBaoClient`] for the given URL, anchoring TLS to the
/// supplied CA-bundle PEM when the URL uses HTTPS.
///
/// For an `https://` URL the caller must provide the PEM of the private CA
/// that signed the `OpenBao` leaf certificate; without it the TLS handshake
/// would only trust the Mozilla webpki roots and fail. For an `http://` URL
/// no CA bundle is needed and one is not required.
///
/// `pins` restricts the HTTPS trust anchors to the pinned subset of the
/// bundle (`trusted_ca_sha256`); an empty slice keeps the bundle-anchored
/// behavior. `pins` is ignored for a plaintext URL (issue #695).
pub(super) fn build_openbao_client(
    openbao_url: &str,
    ca_bundle_pem: Option<&str>,
    pins: &[String],
    lang: Locale,
) -> Result<OpenBaoClient> {
    if bootroot::config::openbao_url_is_https(openbao_url) {
        let pem = ca_bundle_pem.ok_or_else(|| {
            anyhow::anyhow!(
                "{}",
                localized(
                    lang,
                    "HTTPS openbao_url requires a CA bundle",
                    "HTTPS openbao_url은 CA 번들이 필요합니다",
                )
            )
        })?;
        OpenBaoClient::with_pem_trust(openbao_url, pem, pins).with_context(|| {
            localized(
                lang,
                "Failed to build TLS client from CA bundle",
                "CA 번들로 TLS 클라이언트를 생성하지 못했습니다",
            )
        })
    } else {
        OpenBaoClient::new(openbao_url).with_context(|| {
            localized(
                lang,
                "Failed to create OpenBao client",
                "OpenBao 클라이언트를 생성하지 못했습니다",
            )
        })
    }
}
