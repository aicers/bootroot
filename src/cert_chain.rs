//! Trust-chain verification for an on-disk leaf against the local CA
//! bundle.
//!
//! Both the bootroot-agent renewal predicate and `bootroot verify` need
//! to answer the same question: does the leaf certificate sitting at
//! `paths.cert` still chain to a self-signed root inside the bundle
//! at `[trust].ca_bundle_path`?
//!
//! A cold-rebuild rotation of the step-ca trust anchor produces a new
//! root + intermediate keypair with the *same* Subject/Issuer DN as
//! the previous generation (`O=Bootroot CA, CN=Bootroot CA Root CA` /
//! `Intermediate CA`). DN-based inspection cannot tell the two apart;
//! the bug at issue #627 is exactly that a leaf signed by the previous
//! intermediate looks valid against the new bundle on subject/issuer
//! comparison alone. Verifying the leaf's signature against each
//! candidate CA's public key, instead of by name, is the discriminator
//! that catches the rotation.

use anyhow::{Context, Result};
use x509_parser::pem::Pem;

/// Returns `Ok(true)` when the leaf at `leaf_pem` chain-verifies
/// against a self-signed root inside `bundle_pem` by public-key
/// signature.
///
/// `Ok(false)` means the leaf parsed but no path to a self-signed root
/// could be built from the CAs in the bundle — the on-disk leaf was
/// issued by a CA generation the bundle no longer trusts.
///
/// `Err` is reserved for hard parse failures on the leaf or bundle.
/// Callers in the renewal predicate treat `Err` as "force a reissue"
/// rather than aborting the loop.
///
/// # Errors
/// Returns an error if either input cannot be parsed as a PEM
/// certificate (or, for the bundle, a sequence of PEM blocks).
pub fn leaf_chains_to_bundle(leaf_pem: &[u8], bundle_pem: &[u8]) -> Result<bool> {
    let (_, leaf_pem) = x509_parser::pem::parse_x509_pem(leaf_pem)
        .map_err(|e| anyhow::anyhow!("Failed to parse leaf PEM: {e}"))?;
    let leaf = x509_parser::parse_x509_certificate(&leaf_pem.contents)
        .map_err(|e| anyhow::anyhow!("Failed to parse leaf X509: {e}"))?
        .1;

    let bundle_pems = parse_bundle_pems(bundle_pem)?;
    let mut bundle_certs = Vec::with_capacity(bundle_pems.len());
    for pem in &bundle_pems {
        let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents)
            .map_err(|e| anyhow::anyhow!("Failed to parse CA X509 in bundle: {e}"))?;
        bundle_certs.push(cert);
    }

    // Walk leaf → issuer → ... → self-signed. The depth bound is the
    // bundle size: any longer walk would have revisited a cert and is
    // proof of a loop, not a real chain.
    let mut current = &leaf;
    for _ in 0..=bundle_certs.len() {
        if current.verify_signature(None).is_ok() {
            return Ok(true);
        }
        let next = bundle_certs
            .iter()
            .find(|ca| current.verify_signature(Some(ca.public_key())).is_ok());
        let Some(next) = next else {
            return Ok(false);
        };
        current = next;
    }
    Ok(false)
}

fn parse_bundle_pems(bundle_pem: &[u8]) -> Result<Vec<Pem>> {
    let mut pems = Vec::new();
    for pem in Pem::iter_from_buffer(bundle_pem) {
        let pem = pem.context("Failed to parse PEM block from CA bundle")?;
        if pem.label == "CERTIFICATE" {
            pems.push(pem);
        }
    }
    Ok(pems)
}

#[cfg(test)]
mod tests {
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DnType, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };

    use super::*;

    struct CaGeneration {
        root_cert: Certificate,
        root_issuer: Issuer<'static, KeyPair>,
        intermediate_cert: Certificate,
        intermediate_issuer: Issuer<'static, KeyPair>,
    }

    fn build_ca(label: &str) -> CaGeneration {
        let root_key = KeyPair::generate().unwrap();
        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(DnType::CommonName, format!("{label}-root"));
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_issuer = Issuer::new(root_params, root_key);

        let intermediate_key = KeyPair::generate().unwrap();
        let mut int_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        int_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        int_params
            .distinguished_name
            .push(DnType::CommonName, format!("{label}-intermediate"));
        int_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let intermediate_cert = int_params
            .signed_by(&intermediate_key, &root_issuer)
            .unwrap();
        let intermediate_issuer = Issuer::new(int_params, intermediate_key);

        CaGeneration {
            root_cert,
            root_issuer,
            intermediate_cert,
            intermediate_issuer,
        }
    }

    fn sign_leaf(common_name: &str, ca: &CaGeneration) -> String {
        let mut params = CertificateParams::new(vec![common_name.to_string()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = params
            .signed_by(&leaf_key, &ca.intermediate_issuer)
            .unwrap();
        leaf.pem()
    }

    fn bundle(ca: &CaGeneration) -> String {
        format!("{}{}", ca.root_cert.pem(), ca.intermediate_cert.pem())
    }

    #[test]
    fn leaf_chains_when_bundle_matches_generation() {
        let ca = build_ca("gen1");
        let leaf = sign_leaf("svc.example", &ca);

        let ok = leaf_chains_to_bundle(leaf.as_bytes(), bundle(&ca).as_bytes()).unwrap();

        assert!(ok);
    }

    #[test]
    fn leaf_does_not_chain_against_rotated_bundle() {
        let old = build_ca("gen1");
        let new = build_ca("gen2");
        let leaf = sign_leaf("svc.example", &old);

        let ok = leaf_chains_to_bundle(leaf.as_bytes(), bundle(&new).as_bytes()).unwrap();

        assert!(!ok, "leaf signed by previous intermediate must not chain");
    }

    #[test]
    fn intermediate_only_bundle_returns_false_when_no_root_terminates_chain() {
        // The bundle's contract per `merge_ca_bundle` is that the root
        // survives across issuances. An intermediate-only bundle has
        // nothing self-signed to terminate the walk on, so the
        // predicate returns false and the renewal loop will reissue.
        let ca = build_ca("gen1");
        let leaf = sign_leaf("svc.example", &ca);

        let ok =
            leaf_chains_to_bundle(leaf.as_bytes(), ca.intermediate_cert.pem().as_bytes()).unwrap();

        assert!(!ok);
    }

    #[test]
    fn leaf_chains_against_root_only_bundle_when_signed_directly_by_root() {
        let ca = build_ca("gen1");
        let mut params = CertificateParams::new(vec!["svc.example".to_string()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "svc.example");
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = params.signed_by(&leaf_key, &ca.root_issuer).unwrap();

        let ok =
            leaf_chains_to_bundle(leaf.pem().as_bytes(), ca.root_cert.pem().as_bytes()).unwrap();

        assert!(ok);
    }

    #[test]
    fn invalid_leaf_pem_errors() {
        let ca = build_ca("gen1");

        let err = leaf_chains_to_bundle(b"not a pem", bundle(&ca).as_bytes()).unwrap_err();

        assert!(err.to_string().contains("leaf PEM"));
    }

    #[test]
    fn empty_bundle_returns_false() {
        let ca = build_ca("gen1");
        let leaf = sign_leaf("svc.example", &ca);

        let ok = leaf_chains_to_bundle(leaf.as_bytes(), b"").unwrap();

        assert!(!ok);
    }
}
