//! The `[registrar_endpoint]` material paths are a published contract,
//! and the passages describing them must not outlive the behaviour they
//! describe.
//!
//! The four paths reach another repository — the co-located registrar
//! reads the client pair, and the provisioning tool writes the initial
//! certificate to it — so the settings are asserted from outside the
//! library crate, as a consumer would see them.
//!
//! The sweep below is the other half. Every claim it looks for was true
//! before the daemon issued these leaves for itself and is false now.
//! None of them is caught by a unit test: they are prose and comments,
//! and a stale one sends an operator to put a file in place that
//! bootroot creates, or to look for a startup refusal that has become a
//! repair.

use std::path::{Path, PathBuf};

use bootroot::config::{RegistrarEndpointSettings, check_registrar_endpoint_reload};

/// The files that state the `[registrar_endpoint]` contract in prose,
/// in comments, or as an example an operator copies.
const SCANNED_FILES: [&str; 6] = [
    "agent.toml.example",
    "src/config.rs",
    "docs/en/configuration.md",
    "docs/ko/configuration.md",
    "docs/en/operations.md",
    "docs/ko/operations.md",
];

/// Claims that were true while both leaves were supplied out of band,
/// or while a repairable bundle and an unwritten EAB record were still
/// described as refusals, paired with what makes each one false now.
const SUPERSEDED_CLAIMS: [(&str, &str); 15] = [
    (
        "supplied out of band",
        "the daemon issues both leaves itself",
    ),
    ("대역 외로 공급", "the daemon issues both leaves itself"),
    ("exactly three keys", "the table takes five"),
    ("정확히 세 개", "the table takes five"),
    ("None of the three keys", "the table takes five"),
    ("two certificate paths are fixed", "there are four"),
    ("두 인증서 경로", "there are four"),
    ("The two certificate paths", "there are four"),
    (
        "never issues one for itself",
        "issuing one for itself is now what the daemon does",
    ),
    (
        "스스로 발급하지도",
        "issuing one for itself is now what the daemon does",
    ),
    (
        "answer rather than a failure",
        "an absent EAB record is a failed read; the cleared payload is the answer",
    ),
    (
        "실패가 아니라 답입니다",
        "an absent EAB record is a failed read; the cleared payload is the answer",
    ),
    (
        "refuses before the flow starts",
        "a missing or unparseable bundle is restored from the internal one and issued over",
    ),
    (
        "and refuses first",
        "a missing or unparseable bundle is restored from the internal one and issued over",
    ),
    (
        "세 경우 모두",
        "a missing or unparseable bundle is restored from the internal one and issued over",
    ),
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn the_four_material_paths_are_reachable_outside_the_library_crate() {
    let defaults = RegistrarEndpointSettings::default();
    assert!(!defaults.enabled);
    for path in [
        defaults.server_cert_path.as_deref(),
        defaults.server_key_path.as_deref(),
        defaults.client_cert_path.as_deref(),
        defaults.client_key_path.as_deref(),
    ] {
        assert!(path.is_none(), "no material path has a default");
    }

    let running = RegistrarEndpointSettings {
        enabled: true,
        server_cert_path: Some(PathBuf::from("/etc/bootroot/certs/endpoint.crt")),
        server_key_path: Some(PathBuf::from("/etc/bootroot/certs/endpoint.key")),
        client_cert_path: Some(PathBuf::from("/etc/bootroot/certs/client.crt")),
        client_key_path: Some(PathBuf::from("/etc/bootroot/certs/client.key")),
    };
    check_registrar_endpoint_reload(&running, &running.clone())
        .expect("an unchanged table reloads");

    let moved = RegistrarEndpointSettings {
        client_cert_path: Some(PathBuf::from("/etc/bootroot/certs/elsewhere.crt")),
        ..running.clone()
    };
    let err = check_registrar_endpoint_reload(&running, &moved)
        .expect_err("a moved client certificate is rejected");
    assert!(
        err.to_string()
            .contains("registrar_endpoint.client_cert_path"),
        "{err}"
    );
}

/// The pin file's directory follows the client certificate's, which is
/// the reason that setting is a contract rather than an internal detail.
#[test]
fn the_pin_file_follows_the_client_certificate() {
    let cert = Path::new("/etc/bootroot/certs/registrar-client.crt");
    let pin = bootroot::registrar::endpoint_pin::anchor_pin_path_for_client_certificate(cert);
    assert_eq!(
        pin,
        Path::new("/etc/bootroot/certs/registrar-endpoint-anchors.sha256")
    );
}

#[test]
fn no_superseded_claim_about_the_endpoint_material_survives() {
    let root = repo_root();
    for name in SCANNED_FILES {
        let path = root.join(name);
        let contents = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("{name} must be readable: {err}"));
        for (claim, why) in SUPERSEDED_CLAIMS {
            assert!(
                !contents.contains(claim),
                "{name} still says {claim:?}, but {why}"
            );
        }
    }
}

/// Issuance runs **before** the endpoint's TLS material is loaded, which
/// is what keeps an endpoint from ever coming up presenting or holding
/// an expired leaf. The ordering lives in one place — the composition
/// boundary in `bootroot-agent` — and is asserted there, because a test
/// that started a real daemon would need a systemd activation contract.
#[test]
fn issuance_precedes_the_endpoints_activation_in_the_agent_binary() {
    let source = std::fs::read_to_string(repo_root().join("src/bin/bootroot-agent.rs"))
        .expect("the agent binary must be readable");
    let issuance = source
        .find("ensure_registrar_surface_certificates")
        .expect("the agent issues the registrar surface's certificates");
    let activation = source
        .find("RegistrarEndpoint::activate")
        .expect("the agent activates the endpoint");
    assert!(
        issuance < activation,
        "issuance must run before the endpoint loads its TLS material"
    );
}

/// The shipped example carries all four keys, so an operator who copies
/// it has every path an enabled endpoint requires in front of them.
#[test]
fn the_shipped_example_carries_all_four_material_paths_commented_out() {
    let contents = std::fs::read_to_string(repo_root().join("agent.toml.example"))
        .expect("agent.toml.example must be readable");
    for key in [
        "server_cert_path",
        "server_key_path",
        "client_cert_path",
        "client_key_path",
    ] {
        assert!(
            contents.contains(&format!("# {key} = ")),
            "agent.toml.example must carry {key} commented out"
        );
    }
}

/// Every file that publishes the four paths also states that they must
/// name four distinct files.
///
/// A shared path is refused at configuration-validation time and is
/// invisible everywhere else: each file the daemon leaves on disk is
/// individually well-formed, so nothing downstream reports it. An
/// operator who copies a path twice therefore learns why only from these
/// passages, and a file that lists the four without the rule reads as
/// though repeating one were allowed.
#[test]
fn the_four_paths_are_published_with_the_rule_that_they_are_distinct() {
    /// Each file that states the contract, and the phrase in its own
    /// language that states the distinctness rule.
    const STATED: [(&str, &str); 6] = [
        ("agent.toml.example", "four distinct files"),
        ("src/config.rs", "four distinct files"),
        ("docs/en/configuration.md", "four distinct files"),
        ("docs/en/operations.md", "four distinct files"),
        ("docs/ko/configuration.md", "서로 다른 네 개의 파일"),
        ("docs/ko/operations.md", "서로 다른 네 개의 파일"),
    ];

    let root = repo_root();
    for (name, stated) in STATED {
        let contents = std::fs::read_to_string(root.join(name))
            .unwrap_or_else(|err| panic!("{name} must be readable: {err}"));
        // Whitespace-normalised, and the comment and emphasis markers
        // these files wrap the sentence in dropped with it, so a rewrap
        // cannot hide the rule the way it cannot hide a stale claim.
        let flat = contents
            .replace(['*', '#'], " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            flat.contains(stated),
            "{name} publishes the four material paths, so it must state that they name distinct \
             files"
        );
    }
}

/// The written shape is stated everywhere, and so is the one case that
/// does not produce it.
///
/// What the daemon publishes is whatever chain the CA returned, and the
/// preserved empty-chain path publishes a bare leaf after a warning
/// alone. A passage claiming the chain unconditionally sends an operator
/// looking for a file bootroot did not write and cannot repair by
/// issuing again, so both halves are held here: the unqualified claim
/// must be gone, and the case it hid must be present in every file that
/// describes the shape.
///
/// The comparison is whitespace-normalised because these passages are
/// hard-wrapped prose and a TOML comment: the same sentence breaks at
/// different columns in each, and a line-anchored match would pass on a
/// stale claim that merely rewrapped.
#[test]
fn the_written_shape_is_qualified_by_the_empty_chain_case() {
    /// Claims that assert the issuer chain without qualification.
    const UNQUALIFIED: [&str; 4] = [
        "it writes holds the leaf followed by its issuer chain",
        "daemon writes carries the leaf followed by its issuer chain",
        "it writes carries the leaf followed by its issuer chain",
        "리프 다음에 발급자 체인",
    ];
    /// Each file that states the shape, and the phrase in its own
    /// language that states the empty-chain case beside it.
    const STATED: [(&str, &str); 5] = [
        ("agent.toml.example", "with no issuer at all"),
        ("docs/en/configuration.md", "with no issuer at all"),
        ("docs/en/operations.md", "with no issuer at all"),
        ("docs/ko/configuration.md", "발급자를 하나도 붙이지 않고"),
        ("docs/ko/operations.md", "발급자를 하나도 붙이지 않고"),
    ];

    fn normalise(contents: &str) -> String {
        contents
            .replace(['*', '#'], " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    let root = repo_root();
    for name in SCANNED_FILES {
        let contents = std::fs::read_to_string(root.join(name))
            .unwrap_or_else(|err| panic!("{name} must be readable: {err}"));
        let flat = normalise(&contents);
        for claim in UNQUALIFIED {
            assert!(
                !flat.contains(claim),
                "{name} still claims {claim:?} without qualification, but a CA that returns no \
                 issuer publishes a bare leaf after a warning alone"
            );
        }
    }
    for (name, stated) in STATED {
        let contents = std::fs::read_to_string(root.join(name))
            .unwrap_or_else(|err| panic!("{name} must be readable: {err}"));
        assert!(
            normalise(&contents).contains(stated),
            "{name} states what the daemon writes, so it must state the empty-chain case too"
        );
    }
}
