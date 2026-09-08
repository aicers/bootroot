pub(crate) mod client;
pub(crate) mod flow;
pub mod http01_protocol;
pub mod responder_client;
pub(crate) mod types;

// The selectable outbound path and its options belong to the registrar
// surface issuance, which is inside this crate; only the ordinary
// `issue_certificate` is reached from the binary crates.
pub(crate) use flow::{
    CsrShape, IssuanceOptions, IssuedMaterial, LeafPublication, issue_certificate_material,
    issue_certificate_with_bootstrap,
};
pub use flow::{build_registrar_client_csr_params, issue_certificate};
// The two publication helpers a renewal stages its merged CA bundle
// with, so the staged bytes are computed by the same code the ordinary
// publication merges with rather than by a second rule. Their only
// consumer is the renewal adapter, which exists on Linux alone.
#[cfg(target_os = "linux")]
pub(crate) use flow::{merge_ca_bundle, verify_chain_fingerprints};

/// Issues the registrar's own client leaf,
/// `<instance>.bootroot-registrar.<host>.<domain>`, at the profile's
/// configured paths.
///
/// The one entry point the provisioning CLI has into the registrar
/// client shape, and the reason the issuance-options type itself stays
/// crate-private: a caller outside this crate selects *this leaf*, not
/// an arbitrary pair of issuance options. The name is composed from
/// `profile.instance_id`, `profile.hostname` and `settings.domain` —
/// never from a name handed in — and the CSR requests `clientAuth`,
/// which an ordinary service CSR does not.
///
/// The leaf is published **with** its issuer chain, exactly as the
/// daemon's own start-time issuance of this pair publishes it, so a
/// credential the CLI issued and one the daemon re-issued have the same
/// shape on disk.
///
/// # Errors
///
/// Returns an error when the ACME protocol fails, when the returned
/// chain carries a fingerprint that is not in
/// `trust.trusted_ca_sha256`, when `trust.ca_bundle_path` cannot be
/// read or merged, or when the leaf and key cannot be written.
pub async fn issue_registrar_client_certificate(
    settings: &crate::config::Settings,
    profile: &crate::config::DaemonProfileSettings,
    eab_creds: Option<crate::eab::EabCredentials>,
) -> anyhow::Result<()> {
    flow::issue_certificate_with(
        settings,
        profile,
        eab_creds,
        IssuanceOptions {
            csr_shape: CsrShape::RegistrarClient,
            leaf_publication: LeafPublication::LeafWithChain,
        },
    )
    .await
}
