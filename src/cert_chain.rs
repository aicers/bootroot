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
use x509_parser::certificate::X509Certificate;
use x509_parser::pem::Pem;

/// Returns `Ok(true)` when the leaf at `leaf_pem` chain-verifies
/// against a self-signed trust anchor inside `bundle_pem` by
/// public-key signature.
///
/// The walk only terminates on a self-signed certificate that is
/// *present in the bundle*. A self-signed `leaf_pem` whose key is
/// not also in the bundle is rejected, since the bundle would not
/// trust it. Intermediate hops must carry the X.509 CA basic
/// constraint (and, if a `KeyUsage` extension is present, the
/// `keyCertSign` bit), and the issuer DN of each hop must match the
/// subject DN of the next, mirroring what a normal TLS client
/// enforces.
///
/// `Ok(false)` means the leaf parsed but no path to a self-signed
/// trust anchor could be built from the CAs in the bundle — the
/// on-disk leaf was issued by a CA generation the bundle no longer
/// trusts.
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

    // Walk leaf → issuer → ... → self-signed trust anchor in the
    // bundle. Termination is only valid on a bundle certificate; a
    // self-signature on the leaf itself does not count. The depth
    // bound is the bundle size: any longer walk would have revisited
    // a cert and is proof of a loop, not a real chain.
    let mut current = &leaf;
    for _ in 0..=bundle_certs.len() {
        let Some(next) = bundle_certs.iter().find(|ca| issued_by(current, ca)) else {
            return Ok(false);
        };
        if is_self_signed(next) {
            return Ok(true);
        }
        current = next;
    }
    Ok(false)
}

fn issued_by(child: &X509Certificate<'_>, ca: &X509Certificate<'_>) -> bool {
    if !is_ca_capable(ca) {
        return false;
    }
    if child.issuer() != ca.subject() {
        return false;
    }
    child.verify_signature(Some(ca.public_key())).is_ok()
}

fn is_self_signed(cert: &X509Certificate<'_>) -> bool {
    cert.subject() == cert.issuer() && cert.verify_signature(None).is_ok()
}

fn is_ca_capable(cert: &X509Certificate<'_>) -> bool {
    // RFC 5280: an issuer of certificates must carry BasicConstraints
    // with cA=TRUE. If a KeyUsage extension is present it must assert
    // keyCertSign; absent KeyUsage we accept the BasicConstraints
    // signal alone, matching common TLS-client leniency.
    let Ok(Some(bc)) = cert.basic_constraints() else {
        return false;
    };
    if !bc.value.ca {
        return false;
    }
    match cert.key_usage() {
        Ok(Some(ku)) => ku.value.key_cert_sign(),
        Ok(None) => true,
        Err(_) => false,
    }
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

    #[test]
    fn self_signed_leaf_does_not_satisfy_unrelated_bundle() {
        // A self-signed cert whose key is not part of the bundle must
        // not be treated as chaining: the bundle would not trust it.
        // Earlier the walk accepted any self-signature on the
        // starting cert, so a self-signed leaf passed against an
        // unrelated bundle. Regression cover for #627 review.
        let ca = build_ca("gen1");
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["svc.example".to_string()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "svc.example");
        let self_signed = params.self_signed(&key).unwrap();

        let ok =
            leaf_chains_to_bundle(self_signed.pem().as_bytes(), bundle(&ca).as_bytes()).unwrap();

        assert!(!ok, "self-signed leaf must not chain to unrelated bundle");
    }

    #[test]
    fn non_ca_bundle_certificate_cannot_act_as_issuer() {
        // A leaf-shaped certificate that happens to verify a child's
        // signature must not satisfy the chain walk: trust anchors
        // and intermediates need the X.509 cA basic constraint. The
        // earlier code only looked at signature validity, so a
        // non-CA bundle entry whose key matched would have been
        // accepted. Regression cover for #627 review.
        let ca = build_ca("gen1");

        // Construct a non-CA "issuer" using the gen1 intermediate
        // keypair: it can produce a valid signature on a child, but
        // is itself not flagged as a CA. Pair it with a child signed
        // by that same key and present only the non-CA cert as the
        // bundle.
        let masquerade_key = KeyPair::generate().unwrap();
        let mut masquerade_params =
            CertificateParams::new(vec!["evil.example".to_string()]).unwrap();
        masquerade_params
            .distinguished_name
            .push(DnType::CommonName, "evil.example");
        // is_ca defaults to NoCa; do not flip it.
        let masquerade = masquerade_params
            .signed_by(&masquerade_key, &ca.root_issuer)
            .unwrap();
        let masquerade_issuer = Issuer::new(masquerade_params, masquerade_key);

        let mut child_params = CertificateParams::new(vec!["svc.example".to_string()]).unwrap();
        child_params
            .distinguished_name
            .push(DnType::CommonName, "svc.example");
        let child_key = KeyPair::generate().unwrap();
        let child = child_params
            .signed_by(&child_key, &masquerade_issuer)
            .unwrap();

        let ok =
            leaf_chains_to_bundle(child.pem().as_bytes(), masquerade.pem().as_bytes()).unwrap();

        assert!(
            !ok,
            "non-CA bundle entry must not be accepted as a trust anchor"
        );
    }
}
