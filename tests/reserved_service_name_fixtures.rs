//! The repository's own fixtures must stay outside the reserved
//! `bootroot-` service-name namespace.
//!
//! `bootroot service add` and `bootroot-remote bootstrap` refuse a
//! `service_name` under that prefix, because it is the SAN's second
//! label and the registrar's identities are recognized by it. A CI
//! workflow, preflight script or shipped example config that registers
//! such a name is not caught by any unit test — it fails much later, in
//! a Docker E2E job, as a `service add` that suddenly exits non-zero.
//! This test is that check, and it runs in `cargo test`.

use std::fs;
use std::path::{Path, PathBuf};

use bootroot::registrar::{RESERVED_SERVICE_NAME_PREFIX, is_reserved_service_name};

/// Roots walked in full. Everything under them that names a
/// `service_name` names one bootroot itself will register.
const SCANNED_DIRS: [&str; 2] = [".github/workflows", "scripts"];

/// Individual files outside those roots that carry the same values.
const SCANNED_FILES: [&str; 3] = [
    "agent.toml.compose",
    "agent.toml.example",
    "docker-compose.test.yml",
];

/// `tests/` is deliberately not scanned: the guard's own tests pass
/// reserved names on purpose.
fn scanned_paths() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths: Vec<PathBuf> = SCANNED_FILES.iter().map(|name| root.join(name)).collect();
    for dir in SCANNED_DIRS {
        collect_files(&root.join(dir), &mut paths);
    }
    paths
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// A value spelled as a shell or template expansion names nothing here;
/// whatever it expands to is set elsewhere in the same file.
fn is_literal(value: &str) -> bool {
    !value.is_empty() && !value.starts_with('$') && !value.starts_with('{')
}

/// Pulls every literal `--service-name <value>` and `service_name =
/// "<value>"` out of one file.
fn service_names(contents: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut tokens = contents.split_whitespace().peekable();
    while let Some(token) = tokens.next() {
        if let Some(value) = token.strip_prefix("--service-name=") {
            found.push(value.trim_matches('"').to_string());
        } else if token == "--service-name" {
            // A shell line continuation between the flag and its value
            // would otherwise make the scan read `\` as the name and
            // skip the real one in silence -- the one failure mode a
            // guard-against-drift test must not have.
            while tokens.peek().is_some_and(|next| *next == "\\") {
                tokens.next();
            }
            if let Some(value) = tokens.peek() {
                found.push(value.trim_matches('"').to_string());
            }
        }
    }
    for line in contents.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("service_name") else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let mut quoted = rest.trim().split('"');
        if quoted.next().is_some_and(str::is_empty)
            && let Some(value) = quoted.next()
        {
            found.push(value.to_string());
        }
    }
    found.retain(|value| is_literal(value));
    found
}

/// The scan has to see the value in every spelling the fixtures use, or
/// it reports a clean sweep of names it never read. The line-continuation
/// form is the one that fails silently: without the skip above, `\` is
/// recorded as the name and the real one is never examined.
#[test]
fn the_scan_reads_a_service_name_in_every_spelling() {
    assert_eq!(
        service_names("  --service-name agent-selftest \\\n  --hostname h1\n"),
        vec!["agent-selftest".to_string()]
    );
    assert_eq!(
        service_names("  --service-name \\\n    agent-selftest \\\n"),
        vec!["agent-selftest".to_string()]
    );
    assert_eq!(
        service_names("--service-name=agent-selftest\n"),
        vec!["agent-selftest".to_string()]
    );
    assert_eq!(
        service_names("service_name = \"agent-selftest\"\n"),
        vec!["agent-selftest".to_string()]
    );
    // A value the shell expands names nothing here.
    assert!(service_names("--service-name \"$SERVICE_NAME\"\n").is_empty());
}

#[test]
fn no_shipped_fixture_registers_a_reserved_service_name() {
    let mut checked = 0_usize;
    for path in scanned_paths() {
        let Ok(contents) = fs::read_to_string(&path) else {
            // Binary or unreadable files carry no service name.
            continue;
        };
        for value in service_names(&contents) {
            checked += 1;
            assert!(
                !is_reserved_service_name(&value),
                "{}: service_name `{value}` is inside the reserved \
                 `{RESERVED_SERVICE_NAME_PREFIX}` namespace, so the \
                 `service add` that registers it is refused",
                path.display()
            );
        }
    }
    assert!(
        checked > 0,
        "the scan found no service name at all — it stopped matching \
         what the fixtures spell, and would no longer catch a reserved one"
    );
}

/// The HTTP-01 responder's compose aliases are the names step-ca
/// resolves during a challenge, so each mirrors one registration's SAN.
/// Their second label is that registration's `service_name`.
#[test]
fn no_compose_alias_carries_a_reserved_service_label() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docker-compose.test.yml");
    let contents = fs::read_to_string(&path).expect("read docker-compose.test.yml");
    let mut checked = 0_usize;
    for line in contents.lines() {
        let Some(alias) = line.trim().strip_prefix("- ") else {
            continue;
        };
        let Some(label) = alias.split('.').nth(1) else {
            continue;
        };
        checked += 1;
        assert!(
            !is_reserved_service_name(label),
            "{alias}: the SAN's second label is inside the reserved \
             `{RESERVED_SERVICE_NAME_PREFIX}` namespace"
        );
    }
    assert!(checked > 0, "no alias was examined");
}
