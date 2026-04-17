//! Provides a reloadable TLS cert resolver and a poem-compatible TLS listener
//! for the admin API.
//!
//! The `ReloadableCertResolver` implements `rustls::server::ResolvesServerCert`
//! with an atomically-swappable cert store.  SIGHUP reads new cert/key files
//! from disk and swaps the store so the next TLS handshake picks up the new
//! material while existing connections complete naturally.

use std::fmt;
use std::future::Future;
use std::io::{BufReader, Result as IoResult};
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context as TaskContext, Poll};

use anyhow::{Context, Result};
use http::uri::Scheme;
use poem::Addr;
use poem::listener::{Acceptor, Listener};
use poem::web::{LocalAddr, RemoteAddr};
use rustls::ServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsAcceptor;
use tracing::debug;

/// Cert resolver that allows atomic swap of the `CertifiedKey` on SIGHUP.
pub(super) struct ReloadableCertResolver {
    certified_key: RwLock<Arc<CertifiedKey>>,
}

impl fmt::Debug for ReloadableCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReloadableCertResolver").finish()
    }
}

impl ReloadableCertResolver {
    fn new(key: CertifiedKey) -> Self {
        Self {
            certified_key: RwLock::new(Arc::new(key)),
        }
    }

    /// Atomically swaps the stored cert/key pair.
    pub(super) fn swap(&self, key: CertifiedKey) {
        let mut guard = self
            .certified_key
            .write()
            .expect("ReloadableCertResolver lock poisoned");
        *guard = Arc::new(key);
    }
}

impl ResolvesServerCert for ReloadableCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let guard = self
            .certified_key
            .read()
            .expect("ReloadableCertResolver lock poisoned");
        Some(Arc::clone(&guard))
    }
}

/// Loads a `CertifiedKey` from PEM-encoded cert and key files.
///
/// Verifies that the private key matches the leaf certificate by signing
/// a test payload and verifying the signature against the certificate's
/// public key.
pub(super) fn load_certified_key(cert_path: &Path, key_path: &Path) -> Result<CertifiedKey> {
    let cert_bytes =
        std::fs::read(cert_path).with_context(|| format!("read {}", cert_path.display()))?;
    let key_bytes =
        std::fs::read(key_path).with_context(|| format!("read {}", key_path.display()))?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_bytes.as_slice()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parse PEM certs from {}", cert_path.display()))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", cert_path.display());
    }

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_bytes.as_slice()))
        .with_context(|| format!("parse PEM key from {}", key_path.display()))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path.display()))?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| anyhow::anyhow!("unsupported private key type: {e}"))?;

    verify_cert_key_match(certs.first().expect("non-empty certs"), &*signing_key)?;

    Ok(CertifiedKey::new(certs, signing_key))
}

/// Verifies that a private key matches the leaf certificate by signing a
/// test payload and verifying the signature against the certificate's
/// public key.
fn verify_cert_key_match(
    leaf_cert: &rustls::pki_types::CertificateDer<'_>,
    signing_key: &dyn rustls::sign::SigningKey,
) -> Result<()> {
    let schemes = [
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
        rustls::SignatureScheme::RSA_PSS_SHA256,
        rustls::SignatureScheme::ED25519,
    ];
    let signer = signing_key
        .choose_scheme(&schemes)
        .ok_or_else(|| anyhow::anyhow!("no supported signature scheme for cert/key match"))?;
    let scheme = signer.scheme();

    let test_message = b"bootroot-cert-key-match-check";
    let signature = signer
        .sign(test_message)
        .map_err(|e| anyhow::anyhow!("test signature for cert/key match failed: {e}"))?;

    let (_, cert) = x509_parser::parse_x509_certificate(leaf_cert.as_ref())
        .map_err(|e| anyhow::anyhow!("parse leaf certificate for key match: {e}"))?;
    let public_key_bytes: &[u8] = cert.public_key().subject_public_key.as_ref();

    let ring_alg: &dyn ring::signature::VerificationAlgorithm = match scheme {
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256 => &ring::signature::ECDSA_P256_SHA256_ASN1,
        rustls::SignatureScheme::ECDSA_NISTP384_SHA384 => &ring::signature::ECDSA_P384_SHA384_ASN1,
        rustls::SignatureScheme::RSA_PSS_SHA256 => &ring::signature::RSA_PSS_2048_8192_SHA256,
        rustls::SignatureScheme::ED25519 => &ring::signature::ED25519,
        other => anyhow::bail!("unsupported scheme for cert/key match: {other:?}"),
    };
    let verifier = ring::signature::UnparsedPublicKey::new(ring_alg, public_key_bytes);
    verifier
        .verify(test_message, &signature)
        .map_err(|_| anyhow::anyhow!("private key does not match the leaf certificate"))?;

    Ok(())
}

/// Builds a `ReloadableCertResolver` and the corresponding `ServerConfig`.
pub(super) fn build_tls_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Arc<ReloadableCertResolver>, Arc<ServerConfig>)> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certified_key = load_certified_key(cert_path, key_path)?;
    let resolver = Arc::new(ReloadableCertResolver::new(certified_key));

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::clone(&resolver) as Arc<dyn ResolvesServerCert>);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok((resolver, Arc::new(config)))
}

// ---------------------------------------------------------------------------
// Poem Listener / Acceptor that wraps TCP + TLS
// ---------------------------------------------------------------------------

/// A poem-compatible listener that binds a TCP socket and performs TLS
/// handshakes using the provided `ServerConfig`.
pub(super) struct TlsListener {
    addr: SocketAddr,
    server_config: Arc<ServerConfig>,
}

impl TlsListener {
    pub(super) fn new(addr: SocketAddr, server_config: Arc<ServerConfig>) -> Self {
        Self {
            addr,
            server_config,
        }
    }
}

impl Listener for TlsListener {
    type Acceptor = TlsAcceptorWrapper;

    async fn into_acceptor(self) -> IoResult<Self::Acceptor> {
        let tcp = tokio::net::TcpListener::bind(self.addr).await?;
        let local_addr = tcp.local_addr()?;
        debug!("TLS admin listener bound to {local_addr}");
        Ok(TlsAcceptorWrapper {
            tcp,
            tls: TlsAcceptor::from(self.server_config),
            local_addr,
        })
    }
}

/// Accepts TCP connections and yields `LazyTlsStream` handles whose TLS
/// handshake runs in the per-connection task, not the accept loop.
pub(super) struct TlsAcceptorWrapper {
    tcp: tokio::net::TcpListener,
    tls: TlsAcceptor,
    local_addr: SocketAddr,
}

impl Acceptor for TlsAcceptorWrapper {
    type Io = LazyTlsStream;

    fn local_addr(&self) -> Vec<LocalAddr> {
        vec![LocalAddr(Addr::SocketAddr(self.local_addr))]
    }

    async fn accept(&mut self) -> IoResult<(Self::Io, LocalAddr, RemoteAddr, Scheme)> {
        let (tcp_stream, remote_addr) = self.tcp.accept().await?;
        Ok((
            LazyTlsStream::Handshaking(self.tls.accept(tcp_stream)),
            LocalAddr(Addr::SocketAddr(self.local_addr)),
            RemoteAddr(Addr::SocketAddr(remote_addr)),
            Scheme::HTTPS,
        ))
    }
}

// ---------------------------------------------------------------------------
// Lazy TLS stream — defers the handshake to the per-connection task
// ---------------------------------------------------------------------------

/// A TLS stream that defers the handshake to the first I/O poll.
///
/// Returning this from `Acceptor::accept` instead of an already-negotiated
/// `TlsStream` prevents the serial accept loop from blocking while a
/// remote peer stalls the TLS handshake.
pub(super) enum LazyTlsStream {
    /// TLS handshake in progress; driven on each I/O poll.
    Handshaking(tokio_rustls::server::Accept<tokio::net::TcpStream>),
    /// TLS handshake completed; connection is ready.
    Established(tokio_rustls::server::TlsStream<tokio::net::TcpStream>),
    /// Sentinel used during enum variant swap.
    Transitioning,
}

impl LazyTlsStream {
    /// Drives the TLS handshake until it completes or yields `Pending`.
    fn poll_handshake(&mut self, cx: &mut TaskContext<'_>) -> Poll<IoResult<()>> {
        let mut accept = match std::mem::replace(self, Self::Transitioning) {
            Self::Handshaking(a) => a,
            other => {
                *self = other;
                return Poll::Ready(Ok(()));
            }
        };
        match Pin::new(&mut accept).poll(cx) {
            Poll::Ready(Ok(stream)) => {
                *self = Self::Established(stream);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                *self = Self::Handshaking(accept);
                Poll::Pending
            }
        }
    }
}

impl AsyncRead for LazyTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        let this = self.get_mut();
        loop {
            match this {
                Self::Established(stream) => return Pin::new(stream).poll_read(cx, buf),
                Self::Handshaking(_) => match this.poll_handshake(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                },
                Self::Transitioning => {
                    return Poll::Ready(Err(std::io::Error::other("TLS stream in invalid state")));
                }
            }
        }
    }
}

impl AsyncWrite for LazyTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        let this = self.get_mut();
        loop {
            match this {
                Self::Established(stream) => return Pin::new(stream).poll_write(cx, buf),
                Self::Handshaking(_) => match this.poll_handshake(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                },
                Self::Transitioning => {
                    return Poll::Ready(Err(std::io::Error::other("TLS stream in invalid state")));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<IoResult<()>> {
        let this = self.get_mut();
        loop {
            match this {
                Self::Established(stream) => return Pin::new(stream).poll_flush(cx),
                Self::Handshaking(_) => match this.poll_handshake(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                },
                Self::Transitioning => {
                    return Poll::Ready(Err(std::io::Error::other("TLS stream in invalid state")));
                }
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<IoResult<()>> {
        let this = self.get_mut();
        loop {
            match this {
                Self::Established(stream) => return Pin::new(stream).poll_shutdown(cx),
                Self::Handshaking(_) => match this.poll_handshake(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                },
                Self::Transitioning => {
                    return Poll::Ready(Err(std::io::Error::other("TLS stream in invalid state")));
                }
            }
        }
    }
}
