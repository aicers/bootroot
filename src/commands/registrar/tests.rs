//! Unit tests for the registrar provisioning surface.
//!
//! Everything here runs against `tempfile::tempdir()` and the units this
//! repository ships. Nothing reaches the network, nothing reads this
//! host's `/etc`, and no test mutates the process environment.

use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::*;

/// The shipped socket unit, as a path rather than as embedded text, so a
/// test can assert the two agree.
fn shipped_socket_unit() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("systemd")
        .join(SOCKET_UNIT_FILE)
}

/// Writes a socket unit binding `listen_stream` into `dir`.
fn write_socket_unit(dir: &Path, listen_stream: &str) -> PathBuf {
    let path = dir.join(SOCKET_UNIT_FILE);
    std::fs::write(
        &path,
        format!(
            "# A fixture unit.\n\
             [Unit]\n\
             Description=fixture\n\
             \n\
             [Socket]\n\
             ListenStream={listen_stream}\n\
             SocketMode=0700\n\
             Accept=no\n\
             \n\
             [Install]\n\
             WantedBy=sockets.target\n"
        ),
    )
    .expect("write the fixture socket unit");
    path
}

/// Reads `ListenStream=` out of a unit file with a parser that shares no
/// code with the one under test, so an assertion cannot be satisfied by
/// the same bug twice.
fn listen_stream_of_file(path: &Path) -> String {
    let text = std::fs::read_to_string(path).expect("read the unit");
    text.lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("ListenStream="))
        .map(str::to_string)
        .expect("the unit binds a ListenStream")
}

// ---------------------------------------------------------------------
// capabilities
// ---------------------------------------------------------------------

/// The three fields, with `socket_path` taken from a fixture unit rather
/// than from a literal spelled here.
#[test]
fn capabilities_answers_the_socket_units_listen_stream() {
    let dir = TempDir::new().expect("tempdir");
    let unit = write_socket_unit(dir.path(), "/run/fixture/registrar.sock");

    let response = capabilities(Some(&unit), &[]).expect("capabilities");

    assert_eq!(response.api_version, REGISTRAR_API_VERSION);
    assert_eq!(response.api_version, "bootroot.registrar.v1");
    assert_eq!(response.socket_path, listen_stream_of_file(&unit));
    assert_eq!(response.verbs, SURFACE_VERBS.to_vec());
}

/// The unit this repository ships is the answer on a host that has
/// installed no unit at all, and the embedded copy and the checked-in
/// file cannot disagree: both go through the same parser and the
/// embedded one is the file.
#[test]
fn capabilities_falls_back_to_the_shipped_socket_unit() {
    let empty = TempDir::new().expect("tempdir");

    let response =
        capabilities(None, &[empty.path().to_path_buf()]).expect("capabilities with no unit");

    assert_eq!(
        response.socket_path,
        listen_stream_of_file(&shipped_socket_unit())
    );
}

/// An installed unit outranks the shipped one: the reported value is
/// what is true of this host, not what this build was compiled with.
#[test]
fn an_installed_unit_outranks_the_shipped_one() {
    let dir = TempDir::new().expect("tempdir");
    write_socket_unit(dir.path(), "/run/elsewhere/registrar.sock");

    let response = capabilities(None, &[dir.path().to_path_buf()]).expect("capabilities");

    assert_eq!(response.socket_path, "/run/elsewhere/registrar.sock");
    assert_ne!(
        response.socket_path,
        listen_stream_of_file(&shipped_socket_unit())
    );
}

/// The directories are searched in order, so an operator's `/etc` unit
/// wins over a packaged one.
#[test]
fn the_first_directory_carrying_a_unit_wins() {
    let first = TempDir::new().expect("tempdir");
    let second = TempDir::new().expect("tempdir");
    let empty = TempDir::new().expect("tempdir");
    write_socket_unit(first.path(), "/run/first/registrar.sock");
    write_socket_unit(second.path(), "/run/second/registrar.sock");

    let dirs = vec![
        empty.path().to_path_buf(),
        first.path().to_path_buf(),
        second.path().to_path_buf(),
    ];
    let response = capabilities(None, &dirs).expect("capabilities");

    assert_eq!(response.socket_path, "/run/first/registrar.sock");
}

/// The search order this build actually uses is systemd's own, so an
/// operator-installed unit under `/etc` outranks a packaged one.
#[test]
fn the_searched_unit_directories_are_in_systemds_precedence_order() {
    assert_eq!(
        UNIT_DIRECTORIES,
        [
            "/etc/systemd/system",
            "/run/systemd/system",
            "/usr/local/lib/systemd/system",
            "/lib/systemd/system",
            "/usr/lib/systemd/system",
        ]
    );
}

/// A named unit is authoritative, so its failures are refusals rather
/// than a silent fall-through to the shipped value — an operator who
/// named a file meant that file.
#[test]
fn a_named_unit_that_cannot_be_read_is_a_refusal() {
    let dir = TempDir::new().expect("tempdir");
    let missing = dir.path().join("not-installed.socket");

    let err = capabilities(Some(&missing), &[]).expect_err("a named unit that is not there");

    assert!(
        err.to_string().contains("registrar socket unit"),
        "unexpected error: {err}"
    );
}

/// A named unit carrying no `ListenStream=` is a refusal too: there is
/// no pathname to report and reporting the shipped one would answer for
/// a host this is not.
#[test]
fn a_named_unit_with_no_listen_stream_is_a_refusal() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join(SOCKET_UNIT_FILE);
    std::fs::write(&path, "[Socket]\nAccept=no\n").expect("write the unit");

    let err = capabilities(Some(&path), &[]).expect_err("a unit binding nothing");

    assert!(
        err.to_string().contains("ListenStream"),
        "unexpected error: {err}"
    );
}

/// The verbs are the contract's three, in the contract's order. Spelled
/// out here rather than compared against the constant, so a verb that
/// disappeared from the surface fails this test instead of shortening
/// the list it is compared with.
#[test]
fn the_surface_carries_three_verbs_in_a_fixed_order() {
    let dir = TempDir::new().expect("tempdir");
    let unit = write_socket_unit(dir.path(), "/run/fixture/registrar.sock");

    let response = capabilities(Some(&unit), &[]).expect("capabilities");

    assert_eq!(
        response.verbs,
        vec!["registrar.issue", "registrar.mint", "registrar.deregister",]
    );
    assert_eq!(response.verbs.len(), 3);
}

/// The JSON body carries exactly the three fields, with the wire
/// spellings a caller parses.
#[test]
fn the_capabilities_body_serializes_to_the_three_wire_fields() {
    let dir = TempDir::new().expect("tempdir");
    let unit = write_socket_unit(dir.path(), "/run/fixture/registrar.sock");
    let response = capabilities(Some(&unit), &[]).expect("capabilities");

    let value: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&response).expect("serialize"))
            .expect("parse back");

    let object = value.as_object().expect("a JSON object");
    assert_eq!(object.len(), 3);
    assert_eq!(object["api_version"], "bootroot.registrar.v1");
    assert_eq!(object["socket_path"], "/run/fixture/registrar.sock");
    assert_eq!(
        object["verbs"],
        serde_json::json!(["registrar.issue", "registrar.mint", "registrar.deregister"])
    );
}

/// `capabilities` reads no configuration at all, so there is nothing for
/// a disabled endpoint or an absent daemon to change. The same fixture
/// answers identically whatever the host is doing, which is the
/// property: it describes the surface, not the runtime.
#[test]
fn capabilities_is_independent_of_configuration_and_of_a_running_daemon() {
    let dir = TempDir::new().expect("tempdir");
    let unit = write_socket_unit(dir.path(), "/run/fixture/registrar.sock");

    // A secrets tree with no agent config, no state file and nothing
    // listening — the host a provisioning tool probes before bootroot's
    // endpoint has ever been enabled.
    let host = TempDir::new().expect("tempdir");
    std::fs::create_dir_all(host.path().join("secrets")).expect("an empty secrets tree");

    let first = capabilities(Some(&unit), &[]).expect("capabilities");
    let second = capabilities(Some(&unit), &[]).expect("capabilities again");

    assert_eq!(first, second);
    assert_eq!(first.socket_path, "/run/fixture/registrar.sock");
}

// ---------------------------------------------------------------------
// The unit parser
// ---------------------------------------------------------------------

/// `ListenStream=` outside `[Socket]` is not the socket's, and neither
/// is a commented-out one.
#[test]
fn the_parser_reads_listen_stream_out_of_the_socket_section_alone() {
    let unit = "[Unit]\n\
                ListenStream=/run/not-the-socket.sock\n\
                \n\
                [Socket]\n\
                # ListenStream=/run/commented-out.sock\n\
                ListenStream=/run/bootroot/registrar.sock\n\
                \n\
                [Install]\n\
                ListenStream=/run/also-not.sock\n";
    assert_eq!(
        listen_stream(unit).as_deref(),
        Some("/run/bootroot/registrar.sock")
    );
}

/// An empty assignment resets the list, which is systemd's own
/// semantics: a drop-in that clears the value and sets another must not
/// leave the cleared one answering.
#[test]
fn an_empty_assignment_resets_the_listen_stream_list() {
    let unit = "[Socket]\n\
                ListenStream=/run/first.sock\n\
                ListenStream=\n\
                ListenStream=/run/second.sock\n";
    assert_eq!(listen_stream(unit).as_deref(), Some("/run/second.sock"));

    let cleared = "[Socket]\nListenStream=/run/first.sock\nListenStream=\n";
    assert_eq!(listen_stream(cleared), None);
}

/// A unit that binds nothing yields nothing rather than an empty string.
#[test]
fn a_unit_binding_nothing_yields_nothing() {
    assert_eq!(listen_stream("[Socket]\nAccept=no\n"), None);
    assert_eq!(listen_stream(""), None);
}

/// The embedded unit is the checked-in file, so the fallback answer and
/// the file an operator installs cannot drift apart.
#[test]
fn the_embedded_socket_unit_is_the_checked_in_file() {
    let on_disk = std::fs::read_to_string(shipped_socket_unit()).expect("read the shipped unit");
    assert_eq!(SHIPPED_SOCKET_UNIT, on_disk);
    assert_eq!(
        listen_stream(SHIPPED_SOCKET_UNIT).as_deref(),
        Some("/run/bootroot/registrar.sock")
    );
}

// ---------------------------------------------------------------------
// Identity composition
// ---------------------------------------------------------------------

/// The name is composed from the parts, at the fixed instance label and
/// under the reserved service label, at every domain label count.
#[test]
fn the_identity_is_composed_from_the_parts() {
    for domain in ["internal", "example.internal", "corp.example.internal"] {
        let composed = compose_identity("h1", domain).expect("a composed identity");
        assert_eq!(composed, format!("001.bootroot-registrar.h1.{domain}"));
        assert_eq!(
            composed,
            registrar_client_identity(REGISTRAR_SURFACE_INSTANCE, "h1", domain)
        );
        assert_eq!(
            composed.split('.').count(),
            3 + domain.split('.').count(),
            "the label count is derived from the domain: {composed}"
        );
    }
}

/// The composed name is the one `recognize_registrar_client` accepts —
/// the rule the endpoint's verifier applies — and it is refused under
/// any other domain.
#[test]
fn the_composed_name_is_the_one_the_verifier_recognizes() {
    let composed = compose_identity("h1", "corp.example.internal").expect("a composed identity");

    let identity =
        bootroot::registrar::recognize_registrar_client_name(&composed, "corp.example.internal")
            .expect("the composed name is recognized");
    assert_eq!(identity.instance, "001");
    assert_eq!(identity.host, "h1");
    assert_eq!(identity.domain, "corp.example.internal");

    assert!(
        bootroot::registrar::recognize_registrar_client_name(&composed, "other.internal").is_err(),
        "the name must not be recognized under another domain"
    );
}

/// A caller that tries to pass a composed identity through `--host` is
/// refused: the two-label name a provisioning tool pinned, the full
/// four-label name, and anything else carrying a dot are all not single
/// DNS labels.
#[test]
fn a_caller_supplied_composed_name_is_refused() {
    for host in [
        "registrar.h1",
        "registrar.h1.example.internal",
        "001.bootroot-registrar.h1",
        "001.bootroot-registrar.h1.example.internal",
    ] {
        let err = compose_identity(host, "example.internal")
            .expect_err("a composed name is not a host label");
        assert!(
            err.to_string().contains("--host"),
            "unexpected error for {host}: {err}"
        );
    }
}

/// The parts are validated before anything is composed, so a bad domain
/// is a refusal rather than a name nothing could ever recognize.
#[test]
fn an_invalid_part_is_refused_rather_than_composed() {
    assert!(compose_identity("", "example.internal").is_err());
    assert!(compose_identity("h1", "").is_err());
    assert!(compose_identity("h1", "bad_domain").is_err());
    assert!(compose_identity("under_score", "example.internal").is_err());
}

// ---------------------------------------------------------------------
// Placement
// ---------------------------------------------------------------------

/// The CA bundle is the certificate path's sibling, which is where
/// `service add --cert-path` puts it.
#[test]
fn the_ca_bundle_is_the_certificate_paths_sibling() {
    assert_eq!(
        ca_bundle_path_for(Path::new("/opt/roxyd/registrar/registrar-cert.pem")),
        PathBuf::from("/opt/roxyd/registrar/ca-bundle.pem")
    );
    // A bare filename has an empty parent, not none, so the sibling
    // stays relative to the working directory rather than acquiring a
    // `./` the caller never wrote.
    assert_eq!(
        ca_bundle_path_for(Path::new("registrar-cert.pem")),
        PathBuf::from("ca-bundle.pem")
    );
}

/// The staging directory is named per process, so two invocations racing
/// below the same secrets tree cannot read back or sweep each other's
/// material — one run's leaf published beside another's key would be a
/// pair that is neither half-written nor usable.
#[test]
fn the_staging_directory_is_named_per_process() {
    let secrets = Path::new("/var/lib/bootroot/secrets");
    let staging = staging_dir(secrets);

    assert_eq!(staging.parent(), Some(secrets));
    let name = staging
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .expect("a UTF-8 directory name");
    assert_eq!(
        name,
        format!("{STAGING_DIR_PREFIX}.{}", std::process::id()),
        "the name carries this process's id"
    );
    assert_ne!(
        name, STAGING_DIR_PREFIX,
        "the prefix alone is not the directory: a fixed path is one two runs would share"
    );
    assert!(
        name.starts_with(STAGING_DIR_PREFIX),
        "the prefix is what a sweep and a leftover check match on: {name}"
    );
}

// ---------------------------------------------------------------------
// The issued leaf's expiry
// ---------------------------------------------------------------------

/// `not_after` is read off the **leaf**, which is the first certificate
/// in a file this publication writes the issuer chain into. An expiry
/// read off the issuer would report a CA's lifetime as the credential's.
#[test]
fn not_after_is_read_off_the_leaf_and_not_the_chain() {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair,
        KeyUsagePurpose, SanType,
    };

    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Registrar Test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let now = time::OffsetDateTime::now_utc();
    ca_params.not_before = now - time::Duration::days(1);
    ca_params.not_after = now + time::Duration::days(3650);
    let issuer = CertifiedIssuer::self_signed(ca_params, ca_key).expect("self-signed CA");

    let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.subject_alt_names = vec![SanType::DnsName(
        "001.bootroot-registrar.h1.example.internal"
            .to_string()
            .try_into()
            .expect("a DNS SAN"),
    )];
    leaf_params.not_before = now - time::Duration::days(1);
    leaf_params.not_after = now + time::Duration::days(30);
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("issued leaf");

    let file = format!("{}{}", leaf.pem(), issuer.pem());
    let not_after = leaf_not_after(&file).expect("an expiry");

    let parsed =
        time::OffsetDateTime::parse(&not_after, &time::format_description::well_known::Rfc3339)
            .expect("not_after parses as RFC 3339");
    assert!(parsed > now, "the expiry must lie in the future");
    assert!(
        parsed < now + time::Duration::days(60),
        "the expiry must be the leaf's, not the issuer's: {not_after}"
    );
}

/// A file that is not a certificate is a refusal rather than a
/// zero-valued expiry.
#[test]
fn a_certificate_that_does_not_parse_has_no_expiry() {
    assert!(leaf_not_after("not a certificate").is_err());
    assert!(leaf_not_after("").is_err());
}
