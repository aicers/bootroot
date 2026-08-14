//! Helpers shared by the tests that write an executable and then run
//! it, or hand it to production to run.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

/// Mode every fake is written with: executable by its writer and by
/// production spawning it on that writer's behalf, and by nobody else.
const FAKE_MODE: u32 = 0o700;

/// Writes `contents` at `path` and makes it executable, without this
/// process ever holding a descriptor open on it for writing.
///
/// That last part is the reason this helper exists rather than an
/// `fs::write` at each call site. Tests write these fakes on threads of
/// one process, and a `fork` for any spawn — a test's own, or one
/// production makes for a different fake — duplicates every descriptor
/// the process holds at that instant. A duplicate keeps the open file
/// description alive until that child reaches its `exec`, and the
/// kernel refuses to execute a file any process holds open for writing,
/// so a fake whose writer closed it long ago could still be refused
/// with `ETXTBSY` through a stranger's inherited copy
/// (rust-lang/rust#74214).
///
/// Handing the write to a child process removes the descriptor from
/// this process's table, and a `fork` copies only the forking process's
/// own descriptors. So no fork here can inherit a write descriptor on a
/// fake, whatever the threads are doing: the race is gone rather than
/// waited out, and no spawn of `path` — production's included — needs a
/// retry.
///
/// # Panics
///
/// Panics if the writer cannot be spawned, if it fails, or if the mode
/// cannot be applied.
pub(crate) fn write_executable(path: &Path, contents: &[u8]) {
    // `$1` carries the destination as an argument rather than through
    // the script text: a Unix path is an arbitrary NUL-free byte
    // sequence, and one holding a quote, a space or a byte that is not
    // UTF-8 reaches `sh` intact this way and needs no quoting.
    let mut writer = Command::new("/bin/sh")
        .arg("-c")
        .arg(r#"cat > "$1""#)
        .arg("sh")
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap_or_else(|err| panic!("the writer for {} must spawn: {err}", path.display()));

    {
        let mut stdin = writer
            .stdin
            .take()
            .expect("stdin was piped, so it is present until taken");
        stdin
            .write_all(contents)
            .unwrap_or_else(|err| panic!("{} must be writable: {err}", path.display()));
        // Dropping the pipe is what ends `cat`; the wait below would
        // otherwise block on a writer that never sees end of file.
    }

    let status = writer
        .wait()
        .unwrap_or_else(|err| panic!("the writer for {} must be waitable: {err}", path.display()));
    assert!(
        status.success(),
        "the writer for {} must succeed, got {status}",
        path.display()
    );

    // A chmod names the path and opens nothing, so it cannot reopen the
    // window the write was handed off to close.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(FAKE_MODE))
        .unwrap_or_else(|err| panic!("{} must be made executable: {err}", path.display()));
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    use super::{FAKE_MODE, write_executable};

    #[test]
    fn a_written_fake_is_byte_identical_and_runnable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fake = dir.path().join("fake");
        let script = b"#!/bin/sh\nprintf 'ran'\n";

        write_executable(&fake, script);

        assert_eq!(std::fs::read(&fake).expect("the fake is readable"), script);
        assert_eq!(
            std::fs::metadata(&fake)
                .expect("the fake exists")
                .permissions()
                .mode()
                & 0o777,
            FAKE_MODE
        );
        let output = Command::new(&fake).output().expect("the fake must run");
        assert_eq!(output.stdout, b"ran");
    }

    /// The destination travels as an argument rather than in the script
    /// text, so a name the shell would otherwise re-read — a quote, a
    /// space, a `$` — lands at the path asked for rather than at
    /// another one.
    #[test]
    fn a_hostile_file_name_lands_at_the_path_asked_for() {
        let dir = tempfile::tempdir().expect("tempdir");
        let name = OsString::from_vec(br#"fa'ke $x "docker""#.to_vec());

        write_executable(&dir.path().join(&name), b"#!/bin/sh\nexit 0\n");

        assert_eq!(written_names(dir.path()), vec![name]);
    }

    /// A Unix file name is bytes, not text, and `TMPDIR` may hold any
    /// of them, so the destination must reach the writer as bytes too.
    ///
    /// The name is only creatable where the filesystem takes it: APFS
    /// and other UTF-8-enforcing filesystems answer `EILSEQ`, and there
    /// the property is unobservable rather than broken.
    #[test]
    fn a_non_utf8_file_name_lands_at_the_path_asked_for() {
        let dir = tempfile::tempdir().expect("tempdir");
        let name = OsString::from_vec(b"fake\xffdocker".to_vec());
        let fake = dir.path().join(&name);
        if std::fs::File::create(&fake).is_err() {
            return;
        }

        write_executable(&fake, b"#!/bin/sh\nexit 0\n");

        assert_eq!(written_names(dir.path()), vec![name]);
    }

    fn written_names(dir: &std::path::Path) -> Vec<OsString> {
        std::fs::read_dir(dir)
            .expect("the directory is readable")
            .map(|entry| entry.expect("the entry is readable").file_name())
            .collect()
    }

    /// A fake is rewritten in place by some tests, so a second write
    /// must leave the file holding the second script alone rather than
    /// appending to the first.
    #[test]
    fn a_second_write_replaces_the_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fake = dir.path().join("fake");

        write_executable(&fake, b"#!/bin/sh\nexit 1\n");
        write_executable(&fake, b"#!/bin/sh\nexit 0\n");

        assert_eq!(
            std::fs::read(&fake).expect("the fake is readable"),
            b"#!/bin/sh\nexit 0\n"
        );
    }
}
