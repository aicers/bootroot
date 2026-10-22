//! `bootroot-agent`'s start-up errors under the systemd journal: each is
//! one prefixed ERROR line on standard output, with nothing on standard
//! error the journal would store at priority 6.

use std::fs::{self, File};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const JOURNAL_STREAM_VAR: &str = "JOURNAL_STREAM";
const RUST_LOG_VAR: &str = "RUST_LOG";
const MALFORMED_CONFIG: &str = "[[profiles";

struct AgentRun {
    status: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Runs the agent with `args` and standard output redirected to a file;
/// with `journal`, `JOURNAL_STREAM` names that file, as systemd names the
/// stream it connects a unit's output to.
fn run_agent(dir: &Path, args: &[&str], journal: bool) -> AgentRun {
    let stdout_path = dir.join("stdout");
    let stdout = File::create(&stdout_path).expect("create stdout file");
    let metadata = stdout.metadata().expect("stat stdout file");
    let mut command = Command::new(env!("CARGO_BIN_EXE_bootroot-agent"));
    command
        .args(args)
        .env_remove(RUST_LOG_VAR)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::piped());
    if journal {
        command.env(
            JOURNAL_STREAM_VAR,
            format!("{}:{}", metadata.dev(), metadata.ino()),
        );
    } else {
        command.env_remove(JOURNAL_STREAM_VAR);
    }
    let Output { status, stderr, .. } = command.output().expect("run bootroot-agent");
    AgentRun {
        status: status.code(),
        stdout: fs::read_to_string(&stdout_path).expect("read stdout file"),
        stderr: String::from_utf8(stderr).expect("utf-8 stderr"),
    }
}

fn write_malformed_config(dir: &Path) -> String {
    let config = dir.join("agent.toml");
    fs::write(&config, MALFORMED_CONFIG).expect("write agent.toml");
    config.display().to_string()
}

fn error_lines(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .filter(|line| line.starts_with("<3>"))
        .collect()
}

fn assert_every_line_prefixed(stdout: &str) {
    assert!(!stdout.contains('\u{1b}'), "ESC byte: {stdout:?}");
    for line in stdout.lines() {
        assert!(
            ["<3>", "<4>", "<6>", "<7>"]
                .iter()
                .any(|prefix| line.starts_with(prefix)),
            "unprefixed line: {line:?}"
        );
    }
}

#[test]
fn a_config_that_does_not_parse_is_one_error_line_under_the_journal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_malformed_config(dir.path());
    let run = run_agent(dir.path(), &["--config", &config], true);

    assert_eq!(run.status, Some(1), "{}", run.stdout);
    assert!(run.stderr.is_empty(), "stderr: {}", run.stderr);
    assert_every_line_prefixed(&run.stdout);
    let errors = error_lines(&run.stdout);
    assert_eq!(errors.len(), 1, "{}", run.stdout);
    assert!(
        errors.iter().all(|line| line.contains(&config)),
        "the error names the file: {errors:?}"
    );
    assert!(
        run.stdout
            .lines()
            .any(|line| line.starts_with("<6>") && line.contains("Starting Bootroot Agent")),
        "INFO is the default level: {}",
        run.stdout
    );
}

#[test]
fn a_config_that_does_not_parse_is_reported_as_today_elsewhere() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_malformed_config(dir.path());
    let run = run_agent(dir.path(), &["--config", &config], false);

    assert_eq!(run.status, Some(1), "{}", run.stderr);
    assert!(run.stderr.starts_with("Error: "), "stderr: {}", run.stderr);
    assert!(run.stderr.contains(&config), "stderr: {}", run.stderr);
    assert!(error_lines(&run.stdout).is_empty(), "{}", run.stdout);
    assert!(!run.stdout.contains('\u{1b}'), "ANSI codes to a file");
}

#[test]
fn an_unknown_flag_is_one_error_line_under_the_journal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let run = run_agent(dir.path(), &["--no-such-flag"], true);

    assert_eq!(run.status, Some(2), "{}", run.stdout);
    assert!(run.stderr.is_empty(), "stderr: {}", run.stderr);
    assert_every_line_prefixed(&run.stdout);
    let errors = error_lines(&run.stdout);
    assert_eq!(errors.len(), 1, "{}", run.stdout);
    assert!(
        errors.iter().all(|line| line.contains("--no-such-flag")),
        "{errors:?}"
    );
}

#[test]
fn help_and_version_are_printed_as_clap_prints_them_under_the_journal() {
    let dir = tempfile::tempdir().expect("tempdir");
    for (flag, expected) in [
        ("--help", "Usage:"),
        ("--version", env!("CARGO_PKG_VERSION")),
    ] {
        let run = run_agent(dir.path(), &[flag], true);

        assert_eq!(run.status, Some(0), "{flag}: {}", run.stdout);
        assert!(run.stderr.is_empty(), "{flag}: stderr: {}", run.stderr);
        assert!(run.stdout.contains(expected), "{flag}: {}", run.stdout);
        assert!(
            error_lines(&run.stdout).is_empty(),
            "{flag}: {}",
            run.stdout
        );
    }
}

#[test]
fn an_unknown_flag_is_refused_as_today_elsewhere() {
    let dir = tempfile::tempdir().expect("tempdir");
    let run = run_agent(dir.path(), &["--no-such-flag"], false);

    assert_eq!(run.status, Some(2), "{}", run.stderr);
    assert!(
        run.stderr.contains("--no-such-flag"),
        "stderr: {}",
        run.stderr
    );
    assert!(run.stdout.is_empty(), "{}", run.stdout);
}
