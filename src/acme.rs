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
