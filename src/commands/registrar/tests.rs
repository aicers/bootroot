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
// Drop-ins
// ---------------------------------------------------------------------

/// Writes a drop-in `name` into `dropin_dir` under the unit directory
/// `dir` — the unit's own `.d`, a dash-truncated one, or the type-wide
/// `socket.d`.
fn write_dropin_in(dir: &Path, dropin_dir: &str, name: &str, body: &str) -> PathBuf {
    let dropin_dir = dir.join(dropin_dir);
    std::fs::create_dir_all(&dropin_dir).expect("create the drop-in directory");
    let path = dropin_dir.join(name);
    std::fs::write(&path, body).expect("write the drop-in");
    path
}

/// Writes a drop-in `name` into the unit's own `.d` directory in `dir`.
fn write_dropin(dir: &Path, name: &str, body: &str) -> PathBuf {
    write_dropin_in(
        dir,
        &format!("{SOCKET_UNIT_FILE}{DROPIN_DIR_SUFFIX}"),
        name,
        body,
    )
}

/// The type-wide drop-in directory every socket unit on the host
/// shares, and the dash-truncated one this unit's name generates.
const TYPE_DROPIN_DIR: &str = "socket.d";
const DASH_DROPIN_DIR: &str = "bootroot-.socket.d";

/// The override `systemctl edit bootroot-registrar.socket` writes: the
/// unit's value is reset and another is bound. Reporting the unit file
/// alone would name a socket systemd is not listening on, and the
/// caller would connect to nothing.
#[test]
fn a_drop_in_override_is_merged_onto_the_installed_unit() {
    let dir = TempDir::new().expect("tempdir");
    write_socket_unit(dir.path(), "/run/packaged/registrar.sock");
    write_dropin(
        dir.path(),
        "override.conf",
        "[Socket]\nListenStream=\nListenStream=/run/edited/registrar.sock\n",
    );

    let response = capabilities(None, &[dir.path().to_path_buf()]).expect("capabilities");

    assert_eq!(response.socket_path, "/run/edited/registrar.sock");
}

/// A drop-in in a lower-precedence directory still applies to a unit
/// found higher up: systemd merges the drop-ins from every unit
/// directory, not only from the one the unit file came from.
#[test]
fn a_drop_in_below_the_unit_still_applies() {
    let high = TempDir::new().expect("tempdir");
    let low = TempDir::new().expect("tempdir");
    write_socket_unit(high.path(), "/run/packaged/registrar.sock");
    write_dropin(
        low.path(),
        "override.conf",
        "[Socket]\nListenStream=\nListenStream=/run/from-below/registrar.sock\n",
    );

    let dirs = vec![high.path().to_path_buf(), low.path().to_path_buf()];
    let response = capabilities(None, &dirs).expect("capabilities");

    assert_eq!(response.socket_path, "/run/from-below/registrar.sock");
}

/// Drop-ins apply sorted by filename, wherever each came from, so `20-`
/// lands after `10-` even when the `10-` is the one under `/etc`.
#[test]
fn drop_ins_apply_in_filename_order_across_directories() {
    let high = TempDir::new().expect("tempdir");
    let low = TempDir::new().expect("tempdir");
    write_socket_unit(high.path(), "/run/packaged/registrar.sock");
    write_dropin(
        high.path(),
        "10-early.conf",
        "[Socket]\nListenStream=\nListenStream=/run/early/registrar.sock\n",
    );
    write_dropin(
        low.path(),
        "20-late.conf",
        "[Socket]\nListenStream=\nListenStream=/run/late/registrar.sock\n",
    );

    let dirs = vec![high.path().to_path_buf(), low.path().to_path_buf()];
    let response = capabilities(None, &dirs).expect("capabilities");

    assert_eq!(response.socket_path, "/run/late/registrar.sock");
}

/// Two drop-ins of the same name are one drop-in: the higher-precedence
/// directory's copy is applied and the other is discarded, which is
/// what lets an operator neutralise a packaged drop-in with an empty
/// file of the same name under `/etc`.
#[test]
fn a_higher_precedence_drop_in_masks_a_lower_one_of_the_same_name() {
    let high = TempDir::new().expect("tempdir");
    let low = TempDir::new().expect("tempdir");
    write_socket_unit(low.path(), "/run/packaged/registrar.sock");
    write_dropin(
        low.path(),
        "override.conf",
        "[Socket]\nListenStream=\nListenStream=/run/masked/registrar.sock\n",
    );
    write_dropin(high.path(), "override.conf", "# neutralised\n");

    let dirs = vec![high.path().to_path_buf(), low.path().to_path_buf()];
    let response = capabilities(None, &dirs).expect("capabilities");

    assert_eq!(response.socket_path, "/run/packaged/registrar.sock");
}

/// systemd reads `*.conf` and nothing else out of a `.d` directory, so
/// a file an editor left behind overrides nothing here either.
#[test]
fn a_drop_in_directory_entry_that_is_not_conf_is_ignored() {
    let dir = TempDir::new().expect("tempdir");
    write_socket_unit(dir.path(), "/run/packaged/registrar.sock");
    write_dropin(
        dir.path(),
        "override.conf.bak",
        "[Socket]\nListenStream=\nListenStream=/run/backup/registrar.sock\n",
    );

    let response = capabilities(None, &[dir.path().to_path_buf()]).expect("capabilities");

    assert_eq!(response.socket_path, "/run/packaged/registrar.sock");
}

/// A unit named directly is the whole answer. It is not a unit systemd
/// has loaded, so the host's drop-ins are not its.
#[test]
fn a_named_unit_is_not_extended_by_drop_ins() {
    let dir = TempDir::new().expect("tempdir");
    let unit = write_socket_unit(dir.path(), "/run/named/registrar.sock");
    write_dropin(
        dir.path(),
        "override.conf",
        "[Socket]\nListenStream=\nListenStream=/run/edited/registrar.sock\n",
    );

    let response = capabilities(Some(&unit), &[dir.path().to_path_buf()]).expect("capabilities");

    assert_eq!(response.socket_path, "/run/named/registrar.sock");
}

/// systemd honours a top-level `socket.d/`, which alters every socket
/// unit on the host. An operator who resets and rebinds
/// `ListenStream=` there has moved this host's socket, and reporting
/// the unit's own path would name one nothing is listening on.
#[test]
fn a_type_wide_drop_in_rebinds_the_socket() {
    let dir = TempDir::new().expect("tempdir");
    write_socket_unit(dir.path(), "/run/packaged/registrar.sock");
    write_dropin_in(
        dir.path(),
        TYPE_DROPIN_DIR,
        "override.conf",
        "[Socket]\nListenStream=\nListenStream=/run/type-wide/registrar.sock\n",
    );

    let response = capabilities(None, &[dir.path().to_path_buf()]).expect("capabilities");

    assert_eq!(response.socket_path, "/run/type-wide/registrar.sock");
}

/// A type-wide drop-in in a lower-precedence directory reaches a unit
/// found higher up, exactly as a unit-specific one does.
#[test]
fn a_type_wide_drop_in_below_the_unit_still_applies() {
    let high = TempDir::new().expect("tempdir");
    let low = TempDir::new().expect("tempdir");
    write_socket_unit(high.path(), "/run/packaged/registrar.sock");
    write_dropin_in(
        low.path(),
        TYPE_DROPIN_DIR,
        "override.conf",
        "[Socket]\nListenStream=\nListenStream=/run/type-below/registrar.sock\n",
    );

    let dirs = vec![high.path().to_path_buf(), low.path().to_path_buf()];
    let response = capabilities(None, &dirs).expect("capabilities");

    assert_eq!(response.socket_path, "/run/type-below/registrar.sock");
}

/// The dash-truncated `bootroot-.socket.d/`, which systemd derives from
/// the unit's own name, applies too.
#[test]
fn a_dash_prefix_drop_in_applies() {
    let dir = TempDir::new().expect("tempdir");
    write_socket_unit(dir.path(), "/run/packaged/registrar.sock");
    write_dropin_in(
        dir.path(),
        DASH_DROPIN_DIR,
        "override.conf",
        "[Socket]\nListenStream=\nListenStream=/run/dash-prefix/registrar.sock\n",
    );

    let response = capabilities(None, &[dir.path().to_path_buf()]).expect("capabilities");

    assert_eq!(response.socket_path, "/run/dash-prefix/registrar.sock");
}

/// Equally named drop-ins are one drop-in, and the more specific
/// directory wins: the unit's own beats the dash-truncated one, which
/// beats the type-wide one.
#[test]
fn the_more_specific_drop_in_directory_wins_the_name() {
    for (weaker, expected) in [
        (DASH_DROPIN_DIR, "/run/from-the-unit/registrar.sock"),
        (TYPE_DROPIN_DIR, "/run/from-the-unit/registrar.sock"),
    ] {
        let dir = TempDir::new().expect("tempdir");
        write_socket_unit(dir.path(), "/run/packaged/registrar.sock");
        write_dropin(
            dir.path(),
            "override.conf",
            "[Socket]\nListenStream=\nListenStream=/run/from-the-unit/registrar.sock\n",
        );
        write_dropin_in(
            dir.path(),
            weaker,
            "override.conf",
            "[Socket]\nListenStream=\nListenStream=/run/from-the-generic/registrar.sock\n",
        );

        let response = capabilities(None, &[dir.path().to_path_buf()]).expect("capabilities");

        assert_eq!(response.socket_path, expected, "weaker directory {weaker}");
    }
}

/// A type-wide drop-in is ordered among the rest by filename, wherever
/// it came from: a `20-` in `socket.d/` lands after a `10-` in the
/// unit's own directory.
#[test]
fn a_type_wide_drop_in_applies_in_filename_order() {
    let dir = TempDir::new().expect("tempdir");
    write_socket_unit(dir.path(), "/run/packaged/registrar.sock");
    write_dropin(
        dir.path(),
        "10-early.conf",
        "[Socket]\nListenStream=\nListenStream=/run/early/registrar.sock\n",
    );
    write_dropin_in(
        dir.path(),
        TYPE_DROPIN_DIR,
        "20-late.conf",
        "[Socket]\nListenStream=\nListenStream=/run/late/registrar.sock\n",
    );

    let response = capabilities(None, &[dir.path().to_path_buf()]).expect("capabilities");

    assert_eq!(response.socket_path, "/run/late/registrar.sock");
}

/// systemd's own way of cancelling a drop-in for one unit is a symlink
/// to `/dev/null` of the same name in a higher-precedence directory. It
/// masks by occupying the name, so the type-wide file below it never
/// applies and the unit's own value stands.
#[test]
fn a_dev_null_symlink_masks_a_type_wide_drop_in() {
    let dir = TempDir::new().expect("tempdir");
    write_socket_unit(dir.path(), "/run/packaged/registrar.sock");
    write_dropin_in(
        dir.path(),
        TYPE_DROPIN_DIR,
        "10-all.conf",
        "[Socket]\nListenStream=\nListenStream=/run/type-wide/registrar.sock\n",
    );
    let masked = dir
        .path()
        .join(format!("{SOCKET_UNIT_FILE}{DROPIN_DIR_SUFFIX}"))
        .join("10-all.conf");
    std::fs::create_dir_all(masked.parent().expect("the drop-in directory"))
        .expect("create the drop-in directory");
    std::os::unix::fs::symlink("/dev/null", &masked).expect("mask the drop-in");

    let response = capabilities(None, &[dir.path().to_path_buf()]).expect("capabilities");

    assert_eq!(response.socket_path, "/run/packaged/registrar.sock");
}

/// The same mask reaches a lower-precedence directory's copy of the
/// name: a `/dev/null` symlink under `/etc` neutralises the packaged
/// drop-in below it, and the unit's own value stands.
#[test]
fn a_dev_null_mask_neutralises_a_lower_precedence_drop_in() {
    let high = TempDir::new().expect("tempdir");
    let low = TempDir::new().expect("tempdir");
    write_socket_unit(low.path(), "/run/packaged/registrar.sock");
    write_dropin(
        low.path(),
        "override.conf",
        "[Socket]\nListenStream=\nListenStream=/run/masked/registrar.sock\n",
    );
    let masked = high
        .path()
        .join(format!("{SOCKET_UNIT_FILE}{DROPIN_DIR_SUFFIX}"))
        .join("override.conf");
    std::fs::create_dir_all(masked.parent().expect("the drop-in directory"))
        .expect("create the drop-in directory");
    std::os::unix::fs::symlink("/dev/null", &masked).expect("mask the drop-in");

    let dirs = vec![high.path().to_path_buf(), low.path().to_path_buf()];
    let response = capabilities(None, &dirs).expect("capabilities");

    assert_eq!(response.socket_path, "/run/packaged/registrar.sock");
}

/// The drop-in directory names, in systemd's own order: the unit's own
/// first, then the names generated by truncating after each dash, and
/// the type-wide one is not among them because it is searched apart,
/// after every unit directory has contributed these.
#[test]
fn the_drop_in_names_follow_systemds_prefix_hierarchy() {
    assert_eq!(
        unit_dropin_names(SOCKET_UNIT_FILE),
        vec![SOCKET_UNIT_FILE.to_string(), "bootroot-.socket".to_string()]
    );
    assert_eq!(
        unit_dropin_names("foo-bar-baz.service"),
        vec![
            "foo-bar-baz.service".to_string(),
            "foo-bar-.service".to_string(),
            "foo-.service".to_string()
        ]
    );
    // A trailing dash is chopped once rather than emitted, and a
    // leading one ends the hierarchy.
    assert_eq!(
        unit_dropin_names("foo--.service"),
        vec!["foo--.service".to_string(), "foo-.service".to_string()]
    );
    assert_eq!(
        unit_dropin_names("-foo.service"),
        vec!["-foo.service".to_string()]
    );
    assert_eq!(
        unit_dropin_names("plain.service"),
        vec!["plain.service".to_string()]
    );
}

/// Every directory systemd would search, in the order it searches them:
/// each unit directory contributes the unit's own `.d` and then its
/// dash-truncated prefixes, and the type-wide directories come last
/// across all of them, because that one is meant to be overridden by
/// anything named after the unit.
#[test]
fn the_drop_in_directories_are_in_systemds_precedence_order() {
    let dirs = vec![
        PathBuf::from("/etc/systemd/system"),
        PathBuf::from("/run/systemd/system"),
    ];

    let resolved: Vec<String> = dropin_dirs(&dirs)
        .iter()
        .map(|path| path.display().to_string())
        .collect();

    assert_eq!(
        resolved,
        vec![
            "/etc/systemd/system/bootroot-registrar.socket.d",
            "/etc/systemd/system/bootroot-.socket.d",
            "/run/systemd/system/bootroot-registrar.socket.d",
            "/run/systemd/system/bootroot-.socket.d",
            "/etc/systemd/system/socket.d",
            "/run/systemd/system/socket.d",
        ]
    );
}

/// systemd loads exactly one unit file, so the highest-precedence one
/// masks the rest. A unit under `/etc` that binds nothing means the
/// host binds nothing, and answering with a packaged unit's path would
/// name a socket that is not there.
#[test]
fn an_installed_unit_binding_nothing_masks_the_ones_below_it() {
    let high = TempDir::new().expect("tempdir");
    let low = TempDir::new().expect("tempdir");
    std::fs::write(high.path().join(SOCKET_UNIT_FILE), "[Socket]\nAccept=no\n")
        .expect("write the masking unit");
    write_socket_unit(low.path(), "/run/packaged/registrar.sock");

    let dirs = vec![high.path().to_path_buf(), low.path().to_path_buf()];
    let err = capabilities(None, &dirs).expect_err("a unit that binds nothing");

    assert!(
        err.to_string().contains("ListenStream"),
        "unexpected error: {err}"
    );
}

/// A drop-in that resets the list and binds nothing after it leaves the
/// host binding nothing, and that is a refusal rather than a fall-back
/// to the value the unit file alone carried.
#[test]
fn a_drop_in_that_clears_the_list_is_a_refusal() {
    let dir = TempDir::new().expect("tempdir");
    write_socket_unit(dir.path(), "/run/packaged/registrar.sock");
    write_dropin(dir.path(), "override.conf", "[Socket]\nListenStream=\n");

    let err = capabilities(None, &[dir.path().to_path_buf()]).expect_err("a cleared list");

    assert!(
        err.to_string().contains("drop-ins"),
        "unexpected error: {err}"
    );
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

// ---------------------------------------------------------------------
// Output destinations
// ---------------------------------------------------------------------

/// Builds `issue` arguments for the three destinations under test.
fn issue_args(cert_path: PathBuf, key_path: PathBuf, secrets_dir: PathBuf) -> RegistrarIssueArgs {
    RegistrarIssueArgs {
        host: "h1".to_string(),
        domain: "example.internal".to_string(),
        cert_path,
        key_path,
        secrets_dir: crate::cli::args::SecretsDirArgs { secrets_dir },
        json: true,
    }
}

/// The three ordinary destinations are accepted.
#[test]
fn three_distinct_destinations_are_accepted() {
    let dir = TempDir::new().expect("tempdir");
    let cert = dir.path().join("registrar.pem");
    let key = dir.path().join("registrar-key.pem");

    ensure_distinct_outputs(&cert, &key, &ca_bundle_path_for(&cert))
        .expect("three distinct destinations");
}

/// One path for both halves of the pair publishes the certificate and
/// then overwrites it with the private key, and reports success. It is
/// refused instead.
#[test]
fn one_path_for_the_certificate_and_the_key_is_refused() {
    let dir = TempDir::new().expect("tempdir");
    let both = dir.path().join("registrar.pem");

    let err = ensure_distinct_outputs(&both, &both, &ca_bundle_path_for(&both))
        .expect_err("one path for both");

    assert!(err.to_string().contains("--cert-path"), "unexpected: {err}");
    assert!(err.to_string().contains("--key-path"), "unexpected: {err}");
}

/// The derived bundle is a destination like the other two: a key
/// written there is a private key published `0644` into the
/// deployment's trust store.
#[test]
fn a_key_path_on_the_derived_bundle_is_refused() {
    let dir = TempDir::new().expect("tempdir");
    let cert = dir.path().join("registrar.pem");
    let key = dir.path().join(CA_BUNDLE_FILE);

    let err = ensure_distinct_outputs(&cert, &key, &ca_bundle_path_for(&cert))
        .expect_err("the key on the bundle");

    assert!(
        err.to_string().contains(CA_BUNDLE_FILE),
        "unexpected: {err}"
    );
}

/// A certificate path that is itself the bundle collides with the
/// bundle derived beside it.
#[test]
fn a_certificate_path_on_the_bundle_name_is_refused() {
    let dir = TempDir::new().expect("tempdir");
    let cert = dir.path().join(CA_BUNDLE_FILE);
    let key = dir.path().join("registrar-key.pem");

    let err = ensure_distinct_outputs(&cert, &key, &ca_bundle_path_for(&cert))
        .expect_err("the certificate on the bundle");

    assert!(err.to_string().contains("--cert-path"), "unexpected: {err}");
}

/// Two spellings of one file are one destination. Comparing the flags
/// as they were typed would let `certs/../certs/leaf.pem` through.
#[test]
fn two_spellings_of_one_file_are_refused() {
    let dir = TempDir::new().expect("tempdir");
    let certs = dir.path().join("certs");
    std::fs::create_dir_all(&certs).expect("create the material directory");
    let cert = certs.join("registrar.pem");
    let key = certs.join("..").join("certs").join("registrar.pem");

    let err =
        ensure_distinct_outputs(&cert, &key, &ca_bundle_path_for(&cert)).expect_err("one file");

    assert!(err.to_string().contains("--key-path"), "unexpected: {err}");
}

/// A directory the publication is about to *create* is a destination
/// like any other. `--cert-path <symlink>/new/registrar.pem` and
/// `--key-path <target>/new/registrar.pem` name one file the moment
/// `new/` is created through the link, which is what the publication
/// does; comparing them against the nearest ancestor that exists is
/// what sees it before a certificate is minted.
#[test]
fn two_spellings_through_a_link_to_a_directory_not_yet_created_are_refused() {
    let dir = TempDir::new().expect("tempdir");
    let real = dir.path().join("real");
    std::fs::create_dir_all(&real).expect("create the material directory");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("link the material directory");

    let cert = link.join("new").join("registrar.pem");
    let key = real.join("new").join("registrar.pem");

    let err = ensure_distinct_outputs(&cert, &key, &ca_bundle_path_for(&cert))
        .expect_err("one file below a link");

    assert!(err.to_string().contains("--key-path"), "unexpected: {err}");
}

/// The bundle derived beside a certificate below an unborn directory is
/// held to the same rule: `--key-path` naming it through the link is
/// the private key published `0644` into the trust store.
#[test]
fn a_key_path_on_the_bundle_through_a_link_is_refused() {
    let dir = TempDir::new().expect("tempdir");
    let real = dir.path().join("real");
    std::fs::create_dir_all(&real).expect("create the material directory");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("link the material directory");

    let cert = real.join("new").join("registrar.pem");
    let key = link.join("new").join(CA_BUNDLE_FILE);

    let err = ensure_distinct_outputs(&cert, &key, &ca_bundle_path_for(&cert))
        .expect_err("the key on the bundle below a link");

    assert!(
        err.to_string().contains(CA_BUNDLE_FILE),
        "unexpected: {err}"
    );
}

/// Two genuinely different destinations below directories that do not
/// exist yet stay two: resolving the nearest existing ancestor must not
/// collapse paths that only share one.
#[test]
fn distinct_destinations_below_unborn_directories_are_accepted() {
    let dir = TempDir::new().expect("tempdir");
    let cert = dir.path().join("certs").join("deep").join("registrar.pem");
    let key = dir
        .path()
        .join("keys")
        .join("deep")
        .join("registrar-key.pem");

    ensure_distinct_outputs(&cert, &key, &ca_bundle_path_for(&cert))
        .expect("two destinations below unborn directories");
}

/// The components below the nearest existing ancestor are normalised
/// lexically, `..` included. They cannot be anything else: a directory
/// that is not there is not a symlink, so `..` past it can only be the
/// level above.
#[test]
fn the_unborn_tail_is_normalised_onto_the_resolved_ancestor() {
    let dir = TempDir::new().expect("tempdir");
    let real = dir.path().join("real");
    std::fs::create_dir_all(&real).expect("create the material directory");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("link the material directory");

    let resolved = resolve_existing_ancestor(&link.join("a").join("b").join("..").join("c"));

    let anchor = std::fs::canonicalize(&real).expect("canonicalize the material directory");
    assert_eq!(resolved, anchor.join("a").join("c"));
}

// ---------------------------------------------------------------------
// Publication and rollback
// ---------------------------------------------------------------------

/// Material with recognisable contents, so a rollback can be told from
/// a publication by reading the files back.
fn staged_material(tag: &str) -> StagedMaterial {
    StagedMaterial {
        cert_pem: format!("cert:{tag}\n"),
        key_pem: PrivateKeyPem::new(format!("key:{tag}\n")),
        bundle_pem: format!("bundle:{tag}\n"),
        not_after: "2099-01-01T00:00:00.000Z".to_string(),
    }
}

/// The publication step a test appends to induce a failure after the
/// real writers have already replaced every destination.
fn fail_after_publishing<'a>(
    _dest: &'a Destinations,
    _material: &'a StagedMaterial,
) -> PublishFuture<'a> {
    Box::pin(async move { Err(anyhow::anyhow!("induced failure after the last write")) })
}

/// Returns a file's permission bits.
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
}

/// The three files land at the modes `service add` establishes.
#[tokio::test]
async fn a_publication_writes_the_three_files_at_their_modes() {
    let dir = TempDir::new().expect("tempdir");
    let args = issue_args(
        dir.path().join("registrar.pem"),
        dir.path().join("registrar-key.pem"),
        dir.path().join("secrets"),
    );
    let material = staged_material("new");

    publish_material(&args, &material, &crate::i18n::test_messages())
        .await
        .expect("publish");

    let bundle = ca_bundle_path_for(&args.cert_path);
    assert_eq!(
        std::fs::read_to_string(&args.cert_path).expect("cert"),
        material.cert_pem
    );
    assert_eq!(
        std::fs::read_to_string(&args.key_path).expect("key"),
        material.key_pem.expose()
    );
    assert_eq!(
        std::fs::read_to_string(&bundle).expect("bundle"),
        material.bundle_pem
    );
    assert_eq!(mode_of(&args.cert_path), 0o644);
    assert_eq!(mode_of(&args.key_path), 0o600);
    assert_eq!(mode_of(&bundle), 0o644);
}

/// A failure after the last destination has been replaced puts all
/// three back. Without the rollback the previous key would be left
/// beside the new certificate — a pair that is complete, readable and
/// useless, with nothing on disk saying so.
#[tokio::test]
async fn a_late_publication_failure_puts_every_destination_back() {
    let dir = TempDir::new().expect("tempdir");
    let args = issue_args(
        dir.path().join("registrar.pem"),
        dir.path().join("registrar-key.pem"),
        dir.path().join("secrets"),
    );
    let previous = staged_material("previous");
    publish_material(&args, &previous, &crate::i18n::test_messages())
        .await
        .expect("the previous publication");

    let steps: Vec<PublishStep> = vec![publish_bundle, publish_pair, fail_after_publishing];
    let err = publish_with_steps(
        &Destinations::from_args(&args),
        &staged_material("new"),
        &steps,
        &crate::i18n::test_messages(),
    )
    .await
    .expect_err("the induced failure");

    assert!(
        format!("{err:#}").contains("left as they were"),
        "unexpected error: {err:#}"
    );
    let bundle = ca_bundle_path_for(&args.cert_path);
    assert_eq!(
        std::fs::read_to_string(&args.cert_path).expect("cert"),
        previous.cert_pem
    );
    assert_eq!(
        std::fs::read_to_string(&args.key_path).expect("key"),
        previous.key_pem.expose()
    );
    assert_eq!(
        std::fs::read_to_string(&bundle).expect("bundle"),
        previous.bundle_pem
    );
    assert_eq!(mode_of(&args.cert_path), 0o644);
    assert_eq!(mode_of(&args.key_path), 0o600);
    assert_eq!(mode_of(&bundle), 0o644);
}

/// On a first provisioning there is nothing to put back, so the
/// rollback removes what the failed run published rather than leaving a
/// key on a host whose certificate never arrived.
#[tokio::test]
async fn a_late_publication_failure_removes_what_the_run_created() {
    let dir = TempDir::new().expect("tempdir");
    let args = issue_args(
        dir.path().join("material").join("registrar.pem"),
        dir.path().join("material").join("registrar-key.pem"),
        dir.path().join("secrets"),
    );

    let steps: Vec<PublishStep> = vec![publish_bundle, publish_pair, fail_after_publishing];
    publish_with_steps(
        &Destinations::from_args(&args),
        &staged_material("new"),
        &steps,
        &crate::i18n::test_messages(),
    )
    .await
    .expect_err("the induced failure");

    assert!(!args.cert_path.exists(), "the certificate was left behind");
    assert!(!args.key_path.exists(), "the key was left behind");
    assert!(
        !ca_bundle_path_for(&args.cert_path).exists(),
        "the bundle was left behind"
    );
}

/// A failure in the middle of the pair is the one the issue's
/// "never leaves a half-written pair" is about: the certificate has
/// already been replaced and the key has not.
#[tokio::test]
async fn a_failure_writing_the_key_puts_the_certificate_back() {
    let dir = TempDir::new().expect("tempdir");
    let args = issue_args(
        dir.path().join("registrar.pem"),
        dir.path().join("registrar-key.pem"),
        dir.path().join("secrets"),
    );
    let previous = staged_material("previous");
    publish_material(&args, &previous, &crate::i18n::test_messages())
        .await
        .expect("the previous publication");

    // The key's parent is a regular file, so the pair's directory
    // preparation fails once the bundle has already been replaced.
    let blocked = dir.path().join("blocked");
    std::fs::write(&blocked, "not a directory").expect("write the blocking file");
    let dest = Destinations {
        bundle: ca_bundle_path_for(&args.cert_path),
        cert: args.cert_path.clone(),
        key: blocked.join("registrar-key.pem"),
    };

    publish_with_steps(
        &dest,
        &staged_material("new"),
        &PUBLISH_STEPS,
        &crate::i18n::test_messages(),
    )
    .await
    .expect_err("the pair could not be written");

    assert_eq!(
        std::fs::read_to_string(&dest.bundle).expect("bundle"),
        previous.bundle_pem,
        "the bundle was not put back"
    );
    assert_eq!(
        std::fs::read_to_string(&args.cert_path).expect("cert"),
        previous.cert_pem
    );
}

/// Returns a file's uid and gid.
fn owner_of(path: &Path) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).expect("stat");
    (meta.uid(), meta.gid())
}

/// Sets a file's permission bits.
fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

/// A rollback restores the mode each destination actually carried, not
/// the one this surface's writers establish. An operator who tightened
/// the certificate, or a deployment whose key is `0400`, gets that file
/// back — the previous test cannot see the difference, because every
/// file it starts from was written by those same fixed-mode writers.
#[tokio::test]
async fn a_late_publication_failure_puts_back_the_modes_the_files_had() {
    let dir = TempDir::new().expect("tempdir");
    let args = issue_args(
        dir.path().join("registrar.pem"),
        dir.path().join("registrar-key.pem"),
        dir.path().join("secrets"),
    );
    let previous = staged_material("previous");
    publish_material(&args, &previous, &crate::i18n::test_messages())
        .await
        .expect("the previous publication");

    // None of the three is the mode `publish_bundle` and `publish_pair`
    // write, so a rollback that went back through them is visible.
    let bundle = ca_bundle_path_for(&args.cert_path);
    chmod(&args.cert_path, 0o640);
    chmod(&args.key_path, 0o400);
    chmod(&bundle, 0o600);

    let steps: Vec<PublishStep> = vec![publish_bundle, publish_pair, fail_after_publishing];
    publish_with_steps(
        &Destinations::from_args(&args),
        &staged_material("new"),
        &steps,
        &crate::i18n::test_messages(),
    )
    .await
    .expect_err("the induced failure");

    assert_eq!(
        std::fs::read_to_string(&args.cert_path).expect("cert"),
        previous.cert_pem
    );
    assert_eq!(
        std::fs::read_to_string(&args.key_path).expect("key"),
        previous.key_pem.expose()
    );
    assert_eq!(
        std::fs::read_to_string(&bundle).expect("bundle"),
        previous.bundle_pem
    );
    assert_eq!(mode_of(&args.cert_path), 0o640, "the certificate's mode");
    assert_eq!(mode_of(&args.key_path), 0o400, "the key's mode");
    assert_eq!(mode_of(&bundle), 0o600, "the bundle's mode");
}

/// The snapshot carries the ownership beside the mode, and a rollback
/// re-establishes it. An unprivileged test cannot hand a file to
/// another account, so what is asserted here is the restore's own
/// contract: putting back the ids the snapshot captured is a no-op
/// exactly when they are the ones the file already carries, and any
/// other pair reaches the `chown` — which is the call that would have
/// been absent altogether before.
#[tokio::test]
async fn a_rollback_re_establishes_the_ownership_it_captured() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("registrar-key.pem");
    std::fs::write(&path, "previous").expect("seed the destination");
    chmod(&path, 0o400);

    let PriorState::Present(prior) = snapshot_destination(&path).await.expect("snapshot") else {
        panic!("an existing destination was captured as absent");
    };
    assert_eq!(prior.mode, 0o400, "the captured mode");
    assert_eq!(
        (prior.uid, prior.gid),
        owner_of(&path),
        "the captured ownership"
    );

    chmod(&path, 0o644);
    std::fs::write(&path, "the failed run's file").expect("replace the destination");
    restore_prior(&path, &prior).await.expect("restore");

    assert_eq!(std::fs::read_to_string(&path).expect("read"), "previous");
    assert_eq!(mode_of(&path), 0o400);

    // A uid the file does not carry is what an operator-owned
    // destination looks like to a rollback. An unprivileged process
    // cannot grant it, and the refusal is what puts the path in the
    // "check by hand" list rather than leaving it silently re-owned.
    // Root can grant it, so the assertion is the one that holds for the
    // process actually running the test.
    let elsewhere = PriorFile {
        contents: prior.contents.clone(),
        mode: prior.mode,
        uid: prior.uid.wrapping_add(1),
        gid: prior.gid,
    };
    let outcome = restore_prior(&path, &elsewhere).await;
    if bootroot::fs_util::current_process_euid() == 0 {
        outcome.expect("root can hand the file to another uid");
        assert_eq!(
            owner_of(&path),
            (elsewhere.uid, elsewhere.gid),
            "the captured ownership was not re-established"
        );
    } else {
        assert!(
            outcome.is_err(),
            "an unprivileged chown to another uid must be reported, not skipped"
        );
    }
}

// ---------------------------------------------------------------------
// Special permission bits
// ---------------------------------------------------------------------

/// Returns a file's permission bits including setuid, setgid and the
/// sticky bit, which [`mode_of`] deliberately masks off.
fn full_mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).expect("stat").permissions().mode() & 0o7777
}

/// Returns a gid this process may hand a file to and that differs from
/// `current`, or `None` on a host that offers the test neither.
///
/// Root may hand a file to any gid, so the neighbouring one will do.
/// An unprivileged process may only name a group it is a member of.
fn a_gid_this_process_can_chown_to(current: u32) -> Option<u32> {
    if bootroot::fs_util::current_process_euid() == 0 {
        return Some(current.wrapping_add(1));
    }
    bootroot::cert_group::one_supplementary_test_gid().filter(|gid| *gid != current)
}

/// A rollback puts back a mode carrying a special bit, which the chown
/// that follows the rename clears. Restoring the bits with the rename
/// and then re-owning the file loses them silently: the file comes back
/// at its access bits alone, and nothing says the rest went missing.
///
/// The `chown` has to actually run for the loss to happen, so the
/// captured ownership names a gid this process can grant and that the
/// file does not already carry. A host that offers neither cannot
/// exercise the path at all, and says so rather than asserting nothing.
#[tokio::test]
async fn a_rollback_puts_back_a_mode_carrying_a_special_bit() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("registrar-key.pem");
    std::fs::write(&path, "previous").expect("seed the destination");

    // setuid on a file its owner may not execute: the bit is preserved
    // by chmod on both platforms this crate builds for, where the
    // sticky bit on a regular file is the superuser's alone.
    chmod(&path, 0o4600);
    if full_mode_of(&path) != 0o4600 {
        eprintln!("skipping: this host's chmod does not keep setuid on a regular file");
        return;
    }
    let (uid, gid) = owner_of(&path);
    let Some(other_gid) = a_gid_this_process_can_chown_to(gid) else {
        eprintln!("skipping: this process has no second gid to restore ownership to");
        return;
    };

    let PriorState::Present(mut prior) = snapshot_destination(&path).await.expect("snapshot")
    else {
        panic!("an existing destination was captured as absent");
    };
    assert_eq!(
        prior.mode, 0o4600,
        "the captured mode carries the setuid bit"
    );
    prior.uid = uid;
    prior.gid = other_gid;

    chmod(&path, 0o644);
    std::fs::write(&path, "the failed run's file").expect("replace the destination");
    restore_prior(&path, &prior).await.expect("restore");

    assert_eq!(std::fs::read_to_string(&path).expect("read"), "previous");
    assert_eq!(
        owner_of(&path).1,
        other_gid,
        "the captured ownership was not re-established"
    );
    assert_eq!(
        full_mode_of(&path),
        0o4600,
        "the chown cleared the setuid bit the snapshot captured"
    );
}

// ---------------------------------------------------------------------
// Concurrent publications
// ---------------------------------------------------------------------

/// Attempts the publication lock in `dir` without waiting, and answers
/// whether it was granted.
///
/// The attempt is made on a descriptor of its own, which is what a
/// second `bootroot registrar issue` opens: `flock(2)` associates a
/// lock with the open file description rather than with the process, so
/// a lock held on another descriptor refuses this one exactly as it
/// refuses another process's. That is what lets a single-process test
/// assert the property the fix is about.
fn publication_lock_is_free(dir: &Path) -> bool {
    use std::os::unix::io::AsRawFd;

    let path = dir.join(publication_lock::LOCK_FILE_NAME);
    let Ok(file) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
    else {
        return false;
    };
    // SAFETY: `file` owns an open descriptor that outlives the call, and
    // `flock` dereferences nothing. The lock, if taken, is released as
    // `file` is dropped at the end of this function.
    let outcome = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    outcome == 0
}

/// A publication step that refuses unless the publication is holding
/// the lock on every directory it writes into.
fn require_the_lock_is_held<'a>(
    dest: &'a Destinations,
    _material: &'a StagedMaterial,
) -> PublishFuture<'a> {
    Box::pin(async move {
        for dir in [dest.bundle.parent(), dest.cert.parent(), dest.key.parent()]
            .into_iter()
            .flatten()
        {
            if publication_lock_is_free(dir) {
                anyhow::bail!(
                    "the publication is not holding the lock in {}",
                    dir.display()
                );
            }
        }
        Ok(())
    })
}

/// One destination set is one lock, and a disjoint one is another.
///
/// Asserted with a non-blocking attempt rather than by watching a
/// second acquisition fail to finish: whether a queued acquisition has
/// had time to reach its `flock` is a question about the scheduler, and
/// `LOCK_NB` answers the question about the lock instead.
#[tokio::test]
async fn one_destination_set_is_one_lock_and_two_are_two() {
    let dir = TempDir::new().expect("tempdir");
    let material = dir.path().join("material");
    let elsewhere = dir.path().join("elsewhere");

    let held = publication_lock::hold(&[
        &material.join("registrar.pem"),
        &material.join("registrar-key.pem"),
    ])
    .await
    .expect("the acquisition");

    assert!(
        !publication_lock_is_free(&material),
        "a second run must not take a lock this one holds"
    );
    // A second spelling of the one directory is the one lock: the lock
    // is taken on the resolved path, so `material/../material` cannot
    // hand a concurrent run a lock of its own.
    assert!(
        !publication_lock_is_free(&material.join("..").join("material")),
        "a second spelling of the directory took a lock of its own"
    );
    publication_lock::hold(&[&elsewhere.join("registrar.pem")])
        .await
        .expect("a disjoint destination set is a different lock");

    drop(held);
    assert!(
        publication_lock_is_free(&material),
        "the lock was not released"
    );
}

/// The publication holds that lock across every one of its steps, which
/// is what stops two runs interleaving into a mismatched set: one run
/// publishing certificate A, another publishing certificate B and key
/// B, and the first then publishing key A leaves certificate B beside
/// key A with both runs reporting success and neither having anything
/// to roll back.
///
/// Asserted from inside the publication, by a step that tries the lock
/// on its own descriptor and refuses if it is granted. A publication
/// that took no lock fails this at its first step.
#[tokio::test]
async fn a_publication_holds_the_lock_across_every_step() {
    let dir = TempDir::new().expect("tempdir");
    let args = issue_args(
        dir.path().join("material").join("registrar.pem"),
        dir.path().join("keys").join("registrar-key.pem"),
        dir.path().join("secrets"),
    );
    let dest = Destinations::from_args(&args);

    let steps: Vec<PublishStep> = vec![
        require_the_lock_is_held,
        publish_bundle,
        require_the_lock_is_held,
        publish_pair,
        require_the_lock_is_held,
    ];
    publish_with_steps(
        &dest,
        &staged_material("new"),
        &steps,
        &crate::i18n::test_messages(),
    )
    .await
    .expect("the publication holds its lock from before the snapshot to after the last write");

    assert!(
        publication_lock_is_free(dest.cert.parent().expect("the certificate's directory")),
        "the certificate's directory stayed locked after the publication"
    );
    assert!(
        publication_lock_is_free(dest.key.parent().expect("the key's directory")),
        "the key's directory stayed locked after the publication"
    );
}

/// A publication that had to wait publishes the whole set once it is
/// let through, rather than failing or landing in the middle of the run
/// it waited for.
#[tokio::test]
async fn a_publication_that_waited_publishes_every_destination() {
    let dir = TempDir::new().expect("tempdir");
    let args = issue_args(
        dir.path().join("material").join("registrar.pem"),
        dir.path().join("material").join("registrar-key.pem"),
        dir.path().join("secrets"),
    );
    let bundle = ca_bundle_path_for(&args.cert_path);
    let held = publication_lock::hold(&[&bundle, &args.cert_path, &args.key_path])
        .await
        .expect("the other run's lock");

    let publishing = tokio::spawn({
        let args = issue_args(
            args.cert_path.clone(),
            args.key_path.clone(),
            args.secrets_dir.secrets_dir.clone(),
        );
        async move {
            publish_material(
                &args,
                &staged_material("new"),
                &crate::i18n::test_messages(),
            )
            .await
        }
    });
    // Nothing of the waiting run can have landed: it is queued on the
    // lock, which the previous test asserts it takes before its first
    // snapshot.
    assert!(!args.cert_path.exists(), "the certificate was published");
    assert!(!args.key_path.exists(), "the key was published");
    assert!(!bundle.exists(), "the bundle was published");

    drop(held);
    publishing
        .await
        .expect("the publication task")
        .expect("the publication proceeds once the lock is released");

    let material = staged_material("new");
    assert_eq!(
        std::fs::read_to_string(&args.cert_path).expect("cert"),
        material.cert_pem
    );
    assert_eq!(
        std::fs::read_to_string(&args.key_path).expect("key"),
        material.key_pem.expose()
    );
    assert_eq!(
        std::fs::read_to_string(&bundle).expect("bundle"),
        material.bundle_pem
    );
}

/// The lock file is not a destination. Publishing over it would leave
/// this run's `flock` on an inode no longer at that name, so the next
/// run would create a fresh one and take it while this one still holds
/// the old — two runs holding "the" lock at once.
#[test]
fn a_destination_naming_the_publication_lock_is_refused() {
    let dir = TempDir::new().expect("tempdir");
    let cert = dir.path().join("registrar.pem");
    let key = dir.path().join(publication_lock::LOCK_FILE_NAME);
    let err = ensure_no_destination_is_the_lock(&cert, &key, &ca_bundle_path_for(&cert))
        .expect_err("a destination on the lock file");
    assert!(
        format!("{err:#}").contains("--key-path"),
        "unexpected error: {err:#}"
    );
    ensure_no_destination_is_the_lock(&cert, &dir.path().join("k.pem"), &ca_bundle_path_for(&cert))
        .expect("three ordinary destinations");
}
