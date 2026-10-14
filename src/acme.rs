pub(crate) mod client;
pub(crate) mod flow;
pub mod http01_protocol;
pub mod responder_client;
pub(crate) mod types;

pub use client::{create_account_key, is_account_key};
// The selectable outbound path and its options belong to the registrar
// surface issuance, which is inside this crate; only the ordinary
// `issue_certificate` is reached from the binary crates. That issuance
// reaches the exchange and the publication separately, so it can hold
// `crate::publication_lock` across the second and not the first.
pub(crate) use flow::{
    CsrShape, GenerationPublication, IssuanceOptions, IssuedMaterial, LeafPublication,
    issue_certificate_material, publish_issued_material,
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
        registrar_client_issuance_options(),
    )
    .await
}

/// The options [`issue_registrar_client_certificate`] issues under.
///
/// No generation: the registrar surface publishes its pairs under its
/// own lock and rollback, and they are not moved into generation trees.
fn registrar_client_issuance_options() -> IssuanceOptions {
    IssuanceOptions {
        csr_shape: CsrShape::RegistrarClient,
        leaf_publication: LeafPublication::LeafWithChain,
        generation: GenerationPublication::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registrar client leaf is issued in its own shape, published
    /// with its chain, and asks for no generation tree.
    #[test]
    fn the_registrar_client_issuance_publishes_no_generation() {
        assert_eq!(
            registrar_client_issuance_options(),
            IssuanceOptions {
                csr_shape: CsrShape::RegistrarClient,
                leaf_publication: LeafPublication::LeafWithChain,
                generation: GenerationPublication::None,
            }
        );
    }
}
