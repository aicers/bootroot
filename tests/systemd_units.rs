#![cfg(target_os = "linux")]
//! The checked-in systemd units are part of the endpoint's security
//! boundary, not documentation of it.
//!
//! `SocketMode`, `SocketUser`, `RuntimeDirectoryMode` and `Accept=no` are
//! exactly what the daemon's startup policy checks for, and the daemon
//! refuses to serve when they disagree. A unit that drifted from that
//! policy would not fail here, in a second, but on a host, at boot,
//! after a deployment — so every directive the daemon depends on is
//! asserted from the shipped file rather than trusted.
//!
//! These tests parse the units as `systemd` reads them: `[Section]`
//! headers, `Key=Value` lines, `#` comments, and a key that may legally
//! appear more than once (`After=`).
//!
//! The policy these units are asserted against is compiled only on
//! Linux, so this target is gated the same way: on any other host it
//! builds to an empty test binary. The units themselves stay checked in
//! everywhere, for the Linux build and for the documentation that tells
//! operators where to install them.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// Where the units live, relative to the repository root.
const SYSTEMD_DIR: &str = "systemd";
const SOCKET_UNIT: &str = "bootroot-registrar.socket";
const SERVICE_UNIT: &str = "bootroot-registrar.service";

/// One parsed unit: section name to key to the values under it, in file
/// order.
type Unit = BTreeMap<String, BTreeMap<String, Vec<String>>>;

fn unit_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(SYSTEMD_DIR)
        .join(name)
}

fn parse_unit(name: &str) -> Unit {
    let path = unit_path(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("{} must be checked in: {err}", path.display()));
    let mut unit: Unit = BTreeMap::new();
    let mut section = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = header.to_string();
            unit.entry(section.clone()).or_default();
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("{}: not a directive: {line}", path.display()));
        unit.entry(section.clone())
            .or_default()
            .entry(key.trim().to_string())
            .or_default()
            .push(value.trim().to_string());
    }
    unit
}

/// Asserts a directive appears exactly once in a section, with `value`.
fn assert_directive(unit: &Unit, section: &str, key: &str, value: &str) {
    let values = unit
        .get(section)
        .unwrap_or_else(|| panic!("the unit must carry a [{section}] section"))
        .get(key)
        .unwrap_or_else(|| panic!("[{section}] must carry {key}="));
    assert_eq!(
        values,
        &vec![value.to_string()],
        "[{section}] {key}= must be exactly {value}"
    );
}

/// Asserts a directive appears among a key's values, for a key systemd
/// lets a unit repeat.
fn assert_has_value(unit: &Unit, section: &str, key: &str, value: &str) {
    let values = unit
        .get(section)
        .unwrap_or_else(|| panic!("the unit must carry a [{section}] section"))
        .get(key)
        .unwrap_or_else(|| panic!("[{section}] must carry {key}="));
    assert!(
        values.iter().any(|found| found == value),
        "[{section}] {key}= must include {value}, saw {values:?}"
    );
}

/// The socket's own directives: the pathname the daemon resolves with
/// `getsockname()`, and the mode and owner its startup policy checks.
#[test]
fn the_socket_unit_creates_the_root_owned_0700_endpoint() {
    let unit = parse_unit(SOCKET_UNIT);
    assert_directive(
        &unit,
        "Socket",
        "ListenStream",
        "/run/bootroot/registrar.sock",
    );
    assert_directive(&unit, "Socket", "SocketMode", "0700");
    assert_directive(&unit, "Socket", "SocketUser", "root");
    assert_directive(&unit, "Socket", "SocketGroup", "root");
}

/// `Accept=no` is what makes the inherited descriptor a *listening*
/// socket. With `Accept=yes` systemd would pass one connected socket per
/// connection and spawn a service instance for each, which is a second
/// long-running process model this endpoint does not have.
#[test]
fn the_socket_unit_passes_one_listening_descriptor() {
    let unit = parse_unit(SOCKET_UNIT);
    assert_directive(&unit, "Socket", "Accept", "no");
}

/// The runtime directory must survive a service restart, or a reload
/// takes the pathname with it. Its mode is checked by mask, so `0755`
/// passes while anything group- or other-writable does not.
#[test]
fn the_socket_unit_preserves_a_runtime_directory_the_daemon_accepts() {
    let unit = parse_unit(SOCKET_UNIT);
    assert_directive(&unit, "Socket", "RuntimeDirectory", "bootroot");
    assert_directive(&unit, "Socket", "RuntimeDirectoryPreserve", "yes");

    let values = unit
        .get("Socket")
        .and_then(|section| section.get("RuntimeDirectoryMode"))
        .expect("[Socket] must carry RuntimeDirectoryMode=");
    let mode = values.first().expect("one RuntimeDirectoryMode value");
    assert_eq!(mode, "0755");
    let parsed = u32::from_str_radix(mode, 8).expect("an octal mode");
    assert_eq!(
        parsed & 0o022,
        0,
        "the runtime directory must be neither group- nor other-writable"
    );
}

#[test]
fn the_socket_unit_is_installed_into_sockets_target() {
    let unit = parse_unit(SOCKET_UNIT);
    assert_directive(&unit, "Install", "WantedBy", "sockets.target");
}

/// The service depends on the socket for ordering and for the
/// descriptor, and runs as root because the verbs need the privileged
/// internal credential.
#[test]
fn the_service_unit_orders_after_the_socket_and_runs_as_root() {
    let unit = parse_unit(SERVICE_UNIT);
    assert_directive(&unit, "Unit", "Requires", "bootroot-registrar.socket");
    assert_has_value(&unit, "Unit", "After", "bootroot-registrar.socket");
    assert_directive(&unit, "Service", "User", "root");
    assert_directive(&unit, "Service", "Group", "root");
    assert_directive(&unit, "Service", "Restart", "on-failure");
}

/// It starts at boot rather than being started lazily by a connection:
/// the renewal and fast-poll loops must run whether or not a registrar
/// ever connects.
#[test]
fn the_service_unit_starts_at_boot() {
    let unit = parse_unit(SERVICE_UNIT);
    assert_directive(&unit, "Install", "WantedBy", "multi-user.target");
}

/// One `ExecStart`, running the existing agent binary against the
/// existing config path. A second daemon, a helper process or a
/// different binary would all show up here.
#[test]
fn the_service_unit_runs_the_existing_agent_binary() {
    let unit = parse_unit(SERVICE_UNIT);
    assert_directive(
        &unit,
        "Service",
        "ExecStart",
        "/usr/local/bin/bootroot-agent --config /etc/bootroot/agent.toml",
    );
}

/// Rotating EAB credentials need the provisioned `--eab-file` path added
/// to `ExecStart`, and the shipped unit says so where an operator
/// editing it will see it.
#[test]
fn the_service_unit_documents_the_eab_file_customization() {
    let text = std::fs::read_to_string(unit_path(SERVICE_UNIT)).expect("read the service unit");
    assert!(
        text.contains("--eab-file"),
        "the unit must tell a rotating-EAB deployment to add --eab-file to ExecStart"
    );
}

/// Nothing in either unit exposes the endpoint on a network socket.
#[test]
fn neither_unit_listens_on_tcp() {
    for name in [SOCKET_UNIT, SERVICE_UNIT] {
        let unit = parse_unit(name);
        for (section, directives) in &unit {
            for key in directives.keys() {
                assert!(
                    !matches!(
                        key.as_str(),
                        "ListenDatagram"
                            | "ListenFIFO"
                            | "ListenNetlink"
                            | "ListenSequentialPacket"
                            | "ListenSpecial"
                    ),
                    "{name}: [{section}] {key}= is not a Unix stream listener"
                );
            }
        }
        let text = std::fs::read_to_string(unit_path(name)).expect("read the unit");
        for line in text.lines().map(str::trim) {
            if let Some(value) = line.strip_prefix("ListenStream=") {
                assert!(
                    value.starts_with('/'),
                    "{name}: ListenStream must be an absolute Unix pathname, saw {value}"
                );
            }
        }
    }
}
