//! Log output for `bootroot-agent`, native to the systemd journal when the
//! process's output is the journal.
//!
//! Under systemd, a unit's standard output and error are a stream socket
//! to `systemd-journald`, which stores each line as one entry and reads a
//! leading `<N>` as the entry's syslog priority (`SyslogLevelPrefix=`,
//! on by default). An unprefixed line is stored at priority 6 whatever
//! its level, and a timestamp or colour codes only duplicate or garble
//! what the journal records itself. So under the journal every event is
//! written as one prefixed line without either; elsewhere the output is
//! the `fmt` subscriber's usual one.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, IsTerminal as _, Write as _};
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::fs::MetadataExt as _;

use tracing::level_filters::LevelFilter;
use tracing::{Level, Metadata};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::{Directive, ParseError};
use tracing_subscriber::fmt::MakeWriter;

/// The variable systemd sets to the `<dev>:<ino>` of the stream it
/// connects a unit's output to.
pub const JOURNAL_STREAM_VAR: &str = "JOURNAL_STREAM";

const PRIORITY_ERR: u8 = 3;
const PRIORITY_WARNING: u8 = 4;
const PRIORITY_INFO: u8 = 6;
const PRIORITY_DEBUG: u8 = 7;
const UNNAMED_THREAD: &str = "<unnamed>";

/// Where the process's log output goes, as detected at start-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogDestination {
    /// Standard output or standard error is the systemd journal's stream.
    Journal,
    /// Anything else: a terminal, a pipe, a file.
    Other,
}

/// The `(st_dev, st_ino)` of an open descriptor.
type StreamIdentity = (u64, u64);

/// Sets up the process's logging and returns where it goes.
///
/// `journal_stream` is the value of [`JOURNAL_STREAM_VAR`], read once by
/// the caller. The level is INFO unless `RUST_LOG` says otherwise. Under
/// the journal, every event is one `<N>`-prefixed line on standard
/// output, and a panic hook replacing the default one logs a panic as
/// one ERROR event; elsewhere the output is the `fmt` subscriber's, with
/// ANSI colour only when standard output is a terminal.
///
/// # Panics
///
/// Panics if a global `tracing` subscriber is already installed, as
/// `tracing_subscriber::fmt::init` does.
pub fn init(journal_stream: Option<&OsStr>) -> LogDestination {
    let destination = detect(journal_stream);
    let filter_builder = EnvFilter::builder().with_default_directive(LevelFilter::INFO.into());
    match destination {
        LogDestination::Journal => {
            let (filter, rejected) = journal_filter(
                &filter_builder,
                &std::env::var(EnvFilter::DEFAULT_ENV).unwrap_or_default(),
            );
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .without_time()
                .with_ansi(false)
                .with_writer(JournalWriter)
                .init();
            std::panic::set_hook(Box::new(log_panic));
            for (directive, err) in rejected {
                tracing::error!("ignoring `{directive}`: {err}");
            }
        }
        LogDestination::Other => {
            tracing_subscriber::fmt()
                .with_env_filter(filter_builder.from_env_lossy())
                .with_ansi(io::stdout().is_terminal())
                .with_writer(io::stdout)
                .init();
        }
    }
    destination
}

/// Returns the filter `directives` (a `RUST_LOG` value) gives, and each
/// directive it ignores with the reason.
///
/// `from_env_lossy` reports an invalid directive with `eprintln!`, an
/// unprefixed line the journal would store at priority 6, before any
/// subscriber exists to carry it. So the directives are checked here
/// first and only the valid ones reach the builder, which then has
/// nothing to print; the caller logs the rejected ones once the
/// subscriber is installed. The filter is the one `from_env_lossy`
/// builds from the same value, the default directive included when no
/// directive is valid.
fn journal_filter(
    builder: &tracing_subscriber::filter::Builder,
    directives: &str,
) -> (EnvFilter, Vec<(String, ParseError)>) {
    let mut valid = Vec::new();
    let mut rejected = Vec::new();
    for directive in directives.split(',').filter(|s| !s.is_empty()) {
        match directive.parse::<Directive>() {
            Ok(_) => valid.push(directive),
            Err(err) => rejected.push((directive.to_string(), err)),
        }
    }
    (builder.parse_lossy(valid.join(",")), rejected)
}

/// Returns where this process's output goes, given the value of
/// [`JOURNAL_STREAM_VAR`].
fn detect(journal_stream: Option<&OsStr>) -> LogDestination {
    let descriptors = [
        stream_identity(io::stdout().as_fd()),
        stream_identity(io::stderr().as_fd()),
    ];
    if journal_stream_matches(journal_stream, &descriptors) {
        LogDestination::Journal
    } else {
        LogDestination::Other
    }
}

/// Returns the `(st_dev, st_ino)` of `fd`, or `None` when it is closed
/// or cannot be stat'ed.
fn stream_identity(fd: BorrowedFd<'_>) -> Option<StreamIdentity> {
    let metadata = File::from(fd.try_clone_to_owned().ok()?).metadata().ok()?;
    Some((metadata.dev(), metadata.ino()))
}

/// Returns true when `journal_stream` names one of `descriptors`.
///
/// A wrapper that redirects a unit's output to a file or a pipe leaves
/// `JOURNAL_STREAM` set but pointing at a stream the process no longer
/// writes to, so the variable alone does not make the output the
/// journal.
fn journal_stream_matches(
    journal_stream: Option<&OsStr>,
    descriptors: &[Option<StreamIdentity>],
) -> bool {
    let Some(stream) = journal_stream.and_then(parse_journal_stream) else {
        return false;
    };
    descriptors
        .iter()
        .flatten()
        .any(|identity| *identity == stream)
}

/// Parses `<dev>:<ino>`, two decimal integers.
fn parse_journal_stream(value: &OsStr) -> Option<StreamIdentity> {
    let (dev, ino) = value.to_str()?.split_once(':')?;
    Some((parse_decimal(dev)?, parse_decimal(ino)?))
}

fn parse_decimal(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

/// Returns the syslog priority the journal stores an event of `level` at.
fn priority(level: Level) -> u8 {
    match level {
        Level::ERROR => PRIORITY_ERR,
        Level::WARN => PRIORITY_WARNING,
        Level::INFO => PRIORITY_INFO,
        Level::DEBUG | Level::TRACE => PRIORITY_DEBUG,
    }
}

/// Returns `event`, one formatted event, as the one journal line that
/// carries it: `<N>`, the event with each line feed written as `\n` and
/// each NUL as `\0`, and a single final line feed.
///
/// The journal splits its stream at every line feed and refuses a NUL,
/// so neither can reach it raw; a backslash is written as it is.
fn journal_line(priority: u8, event: &[u8]) -> Vec<u8> {
    let event = event.strip_suffix(b"\n").unwrap_or(event);
    let mut line = Vec::with_capacity(event.len() + 8);
    line.extend_from_slice(format!("<{priority}>").as_bytes());
    for &byte in event {
        match byte {
            b'\n' => line.extend_from_slice(b"\\n"),
            0 => line.extend_from_slice(b"\\0"),
            other => line.push(other),
        }
    }
    line.push(b'\n');
    line
}

/// A [`MakeWriter`] that writes each event to standard output as one
/// journal line at the event's priority.
struct JournalWriter;

impl<'a> MakeWriter<'a> for JournalWriter {
    type Writer = JournalLine;

    fn make_writer(&'a self) -> Self::Writer {
        JournalLine::new(PRIORITY_INFO)
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Self::Writer {
        JournalLine::new(priority(*meta.level()))
    }
}

/// One event, buffered whole and written as one line when dropped.
///
/// The `fmt` layer makes one writer per event and drops it once the
/// event is written, so the drop is where the event is complete.
struct JournalLine {
    priority: u8,
    event: Vec<u8>,
}

impl JournalLine {
    fn new(priority: u8) -> Self {
        Self {
            priority,
            event: Vec::new(),
        }
    }
}

impl io::Write for JournalLine {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.event.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for JournalLine {
    fn drop(&mut self) {
        if self.event.is_empty() {
            return;
        }
        // One `write_all` of a line that ends in a line feed: standard
        // output is line-buffered, so the line leaves in one piece and
        // nothing waits in the buffer for an `exit`. A log line that
        // cannot be written has nowhere else to be reported.
        let _ = io::stdout()
            .lock()
            .write_all(&journal_line(self.priority, &self.event));
    }
}

/// Logs a panic as one ERROR event, in place of the default hook's
/// plain-text report on standard error.
fn log_panic(info: &std::panic::PanicHookInfo<'_>) {
    let thread = std::thread::current();
    let thread_name = thread.name().unwrap_or(UNNAMED_THREAD);
    let message = info
        .payload()
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
        .unwrap_or("Box<dyn Any>");
    let location = info.location().map_or_else(
        || "<unknown>".to_string(),
        |location| {
            format!(
                "{}:{}:{}",
                location.file(),
                location.line(),
                location.column()
            )
        },
    );
    tracing::error!("thread '{thread_name}' panicked at {location}: {message}");
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::process::{Command, Output, Stdio};

    use tracing::{debug, error, info, warn};

    use super::*;

    /// Marks a re-run of the test binary as the child that sets logging
    /// up and emits the events.
    const CHILD_MARKER: &str = "BOOTROOT_LOGGING_TEST_CHILD";
    const RUST_LOG_VAR: &str = "RUST_LOG";
    const ESC: u8 = 0x1b;

    /// What the child's `JOURNAL_STREAM` is set to.
    enum Stream {
        /// The `dev:ino` of the file its standard output goes to.
        Matching,
        /// A well-formed value naming another stream.
        Mismatched,
        /// Removed.
        Unset,
    }

    struct ChildRun {
        /// Standard output, libtest's own lines left out.
        lines: Vec<String>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    }

    fn in_child() -> bool {
        std::env::var_os(CHILD_MARKER).is_some()
    }

    /// The child's own set-up: what the agent's `main` does.
    fn child_init() -> LogDestination {
        init(std::env::var_os(JOURNAL_STREAM_VAR).as_deref())
    }

    /// The lines libtest's terse format writes around a passing test:
    /// `running 1 test`, the test's `.`, `test result: …` and blank lines.
    fn is_libtest_line(line: &str) -> bool {
        line.is_empty()
            || line == "."
            || line.starts_with("running ")
            || line.starts_with("test result: ")
    }

    /// Re-runs this test binary for the test `name` alone, with standard
    /// output redirected to a file, and returns what it wrote.
    fn run_child(name: &str, stream: &Stream, rust_log: Option<&str>) -> ChildRun {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("stdout");
        let file = File::create(&path).expect("create stdout file");
        let metadata = file.metadata().expect("stat stdout file");
        let full_name = format!("logging::tests::{name}");
        let mut command = Command::new(std::env::current_exe().expect("current test binary"));
        // The terse format writes nothing when a test starts, so no
        // libtest text shares a line with the child's first log line,
        // whatever thread count `RUST_TEST_THREADS` asks for.
        command
            .args(["--exact", &full_name, "--nocapture", "--quiet"])
            .env(CHILD_MARKER, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::from(file))
            .stderr(Stdio::piped());
        match stream {
            Stream::Matching => {
                command.env(
                    JOURNAL_STREAM_VAR,
                    format!("{}:{}", metadata.dev(), metadata.ino()),
                );
            }
            Stream::Mismatched => {
                command.env(
                    JOURNAL_STREAM_VAR,
                    format!("{}:{}", metadata.dev(), metadata.ino().wrapping_add(1)),
                );
            }
            Stream::Unset => {
                command.env_remove(JOURNAL_STREAM_VAR);
            }
        }
        match rust_log {
            Some(value) => command.env(RUST_LOG_VAR, value),
            None => command.env_remove(RUST_LOG_VAR),
        };
        let Output { status, stderr, .. } = command.output().expect("run child test");
        let stdout = std::fs::read(&path).expect("read child stdout");
        let text = String::from_utf8_lossy(&stdout).into_owned();
        assert!(
            status.success(),
            "child {full_name} failed: {status}\nstdout:\n{text}\nstderr:\n{}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(
            text.lines()
                .any(|line| line.starts_with("test result: ok. 1 passed;")),
            "child must run exactly {full_name}: {text}"
        );
        let lines = text
            .lines()
            .filter(|line| !is_libtest_line(line))
            .map(str::to_string)
            .collect();
        ChildRun {
            lines,
            stdout,
            stderr,
        }
    }

    fn assert_journal_lines(run: &ChildRun) {
        assert!(!run.stdout.contains(&ESC), "ESC byte in {:?}", run.lines);
        for line in &run.lines {
            assert!(
                ["<3>", "<4>", "<6>", "<7>"]
                    .iter()
                    .any(|prefix| line.starts_with(prefix)),
                "unprefixed line: {line:?}"
            );
            let after = line.get(3..).unwrap_or_default().trim_start();
            assert!(
                after.starts_with(['E', 'W', 'I', 'D', 'T']),
                "the level must follow the prefix, not a timestamp: {line:?}"
            );
        }
    }

    fn line_with<'a>(run: &'a ChildRun, needle: &str) -> &'a str {
        run.lines
            .iter()
            .find(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("no line carries {needle:?}: {:?}", run.lines))
    }

    #[test]
    fn journal_lines_carry_each_level_as_its_priority() {
        if in_child() {
            assert_eq!(child_init(), LogDestination::Journal);
            error!("error-event");
            warn!("warn-event");
            info!("info-event");
            debug!("debug-event");
            return;
        }
        let run = run_child(
            "journal_lines_carry_each_level_as_its_priority",
            &Stream::Matching,
            Some("debug"),
        );
        assert_journal_lines(&run);
        assert!(line_with(&run, "error-event").starts_with("<3>"));
        assert!(line_with(&run, "warn-event").starts_with("<4>"));
        assert!(line_with(&run, "info-event").starts_with("<6>"));
        assert!(line_with(&run, "debug-event").starts_with("<7>"));
        assert!(
            line_with(&run, "info-event").contains("INFO bootroot::logging::tests: info-event"),
            "level and target stay as fmt writes them: {:?}",
            run.lines
        );
        assert!(run.stderr.is_empty(), "{:?}", run.stderr);
    }

    #[test]
    fn journal_lines_escape_line_feeds_and_nuls_only() {
        if in_child() {
            assert_eq!(child_init(), LogDestination::Journal);
            info!("first\nsecond\0third \\ end");
            return;
        }
        let run = run_child(
            "journal_lines_escape_line_feeds_and_nuls_only",
            &Stream::Matching,
            None,
        );
        assert_journal_lines(&run);
        let line = line_with(&run, "first");
        assert!(
            line.ends_with("first\\nsecond\\0third \\ end"),
            "line feed and NUL escaped, backslash kept: {line:?}"
        );
        assert_eq!(run.lines.len(), 1, "one event, one line: {:?}", run.lines);
        assert!(!run.stdout.contains(&0), "a raw NUL reached the stream");
    }

    #[test]
    fn output_is_plain_without_a_matching_journal_stream() {
        if in_child() {
            assert_eq!(child_init(), LogDestination::Other);
            info!("plain-event");
            return;
        }
        for stream in [Stream::Mismatched, Stream::Unset] {
            let run = run_child(
                "output_is_plain_without_a_matching_journal_stream",
                &stream,
                None,
            );
            let line = line_with(&run, "plain-event");
            assert!(!line.starts_with('<'), "priority prefix: {line:?}");
            assert!(
                line.starts_with(|c: char| c.is_ascii_digit()),
                "today's format leads with a timestamp: {line:?}"
            );
            assert!(line.contains("INFO bootroot::logging::tests: plain-event"));
            assert!(!run.stdout.contains(&ESC), "ANSI codes to a file: {line:?}");
        }
    }

    #[test]
    fn journal_panic_is_one_error_line() {
        if in_child() {
            assert_eq!(child_init(), LogDestination::Journal);
            let joined = std::thread::Builder::new()
                .name("journal-panic".to_string())
                .spawn(|| panic!("journal panic\nsecond line"))
                .expect("spawn panicking thread")
                .join();
            assert!(joined.is_err());
            return;
        }
        let run = run_child("journal_panic_is_one_error_line", &Stream::Matching, None);
        assert_journal_lines(&run);
        assert_eq!(run.lines.len(), 1, "{:?}", run.lines);
        let line = line_with(&run, "journal panic");
        assert!(line.starts_with("<3>"), "{line:?}");
        assert!(line.contains("journal panic\\nsecond line"), "{line:?}");
        assert!(line.contains("thread 'journal-panic'"), "{line:?}");
        assert!(line.contains(&format!("{}:", file!())), "{line:?}");
        assert!(
            run.stderr.is_empty(),
            "the default hook must not run: {}",
            String::from_utf8_lossy(&run.stderr)
        );
    }

    #[test]
    fn info_is_the_default_level_and_rust_log_overrides_it() {
        if in_child() {
            child_init();
            info!("info-event");
            debug!("debug-event");
            return;
        }
        let name = "info_is_the_default_level_and_rust_log_overrides_it";
        let default = run_child(name, &Stream::Matching, None);
        line_with(&default, "info-event");
        assert!(
            !default
                .lines
                .iter()
                .any(|line| line.contains("debug-event")),
            "{:?}",
            default.lines
        );

        let debug = run_child(name, &Stream::Matching, Some("debug"));
        line_with(&debug, "debug-event");

        let error_only = run_child(name, &Stream::Unset, Some("error"));
        assert!(
            !error_only
                .lines
                .iter()
                .any(|line| line.contains("info-event")),
            "{:?}",
            error_only.lines
        );
    }

    #[test]
    fn journal_logs_an_ignored_rust_log_directive_as_one_error_line() {
        if in_child() {
            assert_eq!(child_init(), LogDestination::Journal);
            info!("info-event");
            debug!("debug-event");
            return;
        }
        let run = run_child(
            "journal_logs_an_ignored_rust_log_directive_as_one_error_line",
            &Stream::Matching,
            Some("bootroot=bogus,debug"),
        );
        assert_journal_lines(&run);
        let line = line_with(&run, "ignoring `bootroot=bogus`");
        assert!(line.starts_with("<3>"), "{line:?}");
        line_with(&run, "debug-event");
        assert!(
            run.stderr.is_empty(),
            "nothing may bypass the journal format: {}",
            String::from_utf8_lossy(&run.stderr)
        );
    }

    #[test]
    fn journal_filter_keeps_the_valid_directives_and_returns_the_rest() {
        let builder = EnvFilter::builder().with_default_directive(LevelFilter::INFO.into());
        let rejected_of = |directives: &str| -> Vec<String> {
            journal_filter(&builder, directives)
                .1
                .into_iter()
                .map(|(directive, _)| directive)
                .collect()
        };
        assert_eq!(rejected_of(""), Vec::<String>::new());
        assert_eq!(rejected_of("debug,bootroot=trace"), Vec::<String>::new());
        assert_eq!(rejected_of("a=bogus,,debug,b=nope"), ["a=bogus", "b=nope"]);

        let (filter, _) = journal_filter(&builder, "");
        assert_eq!(filter.max_level_hint(), Some(LevelFilter::INFO));
        let (filter, _) = journal_filter(&builder, "a=bogus");
        assert_eq!(
            filter.max_level_hint(),
            Some(LevelFilter::INFO),
            "no valid directive leaves the default"
        );
        let (filter, _) = journal_filter(&builder, "a=bogus,debug");
        assert_eq!(filter.max_level_hint(), Some(LevelFilter::DEBUG));
    }

    #[test]
    fn journal_stream_matches_either_descriptor() {
        let stdout = Some((10, 20));
        let stderr = Some((10, 30));
        let value = |s: &str| OsString::from(s);
        assert!(journal_stream_matches(
            Some(&value("10:20")),
            &[stdout, stderr]
        ));
        assert!(journal_stream_matches(
            Some(&value("10:30")),
            &[stdout, stderr]
        ));
        assert!(journal_stream_matches(
            Some(&value("10:30")),
            &[None, stderr]
        ));
        assert!(!journal_stream_matches(
            Some(&value("10:40")),
            &[stdout, stderr]
        ));
        assert!(!journal_stream_matches(
            Some(&value("10:20")),
            &[None, None]
        ));
        for malformed in ["12", "a:b", "1:2:3", "", ":", "+10:20", "10:-20", " 10:20"] {
            assert!(
                !journal_stream_matches(Some(&value(malformed)), &[Some((1, 2)), stdout]),
                "{malformed:?}"
            );
        }
        assert!(!journal_stream_matches(None, &[stdout, stderr]));
    }

    #[test]
    fn journal_line_escapes_line_feeds_and_nuls() {
        assert_eq!(
            journal_line(6, b"INFO a: one\ntwo\0three \\ four\n"),
            b"<6>INFO a: one\\ntwo\\0three \\ four\n".to_vec()
        );
        assert_eq!(journal_line(3, b"no final feed"), b"<3>no final feed\n");
        assert_eq!(journal_line(4, b"two\n\n"), b"<4>two\\n\n");
    }

    #[test]
    fn priority_follows_the_level() {
        assert_eq!(priority(Level::ERROR), 3);
        assert_eq!(priority(Level::WARN), 4);
        assert_eq!(priority(Level::INFO), 6);
        assert_eq!(priority(Level::DEBUG), 7);
        assert_eq!(priority(Level::TRACE), 7);
    }
}
