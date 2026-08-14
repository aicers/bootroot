//! Helpers shared by the tests that write an executable and then run
//! it, or hand it to production to run.

use std::io::ErrorKind;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Argument that tells one of those fakes to exit without recording
/// the invocation, so [`wait_until_spawnable`] can run it as a probe
/// without appearing in what the test decodes afterwards.
pub(crate) const EXEC_PROBE_ARG: &str = "__bootroot_exec_probe";

/// Blocks until `path` can be executed.
///
/// Tests write these fakes on threads of one process, and a `fork` for
/// any spawn duplicates every descriptor the process holds open at
/// that instant — including the one another thread is writing its own
/// fake through. The copy lives until that child reaches its own
/// `exec`, and the kernel refuses to execute a file that any process
/// holds open for writing, so a fake whose writer has already closed
/// it can still be refused with `ETXTBSY` through a stranger's
/// inherited copy (rust-lang/rust#74214).
///
/// Nothing opens the file for writing after the writer is done with
/// it, so a probe that execs it proves no such copy is outstanding and
/// none can appear afterwards: every later spawn of `path` succeeds.
/// That is why the wait belongs to the writer rather than to each
/// spawn — production spawns some of these fakes on a test's behalf,
/// and must not grow a retry to serve the tests.
///
/// # Panics
///
/// Panics if the probe cannot run for any other reason, if the fake
/// does not exit 0 for [`EXEC_PROBE_ARG`], or if the file is still
/// busy once the attempts are spent.
pub(crate) fn wait_until_spawnable(path: &Path) {
    // Long enough to outlast a scheduling delay on a loaded CI runner,
    // since what is being waited out is another thread's `fork`
    // reaching its `exec`.
    const ATTEMPTS: u32 = 200;
    const BACKOFF: Duration = Duration::from_millis(5);

    for _ in 0..ATTEMPTS {
        match Command::new(path).arg(EXEC_PROBE_ARG).status() {
            Ok(status) => {
                assert!(
                    status.success(),
                    "the exec probe must exit 0, got {status} from {}",
                    path.display()
                );
                return;
            }
            // Not a `sleep` standing in for synchronisation: there is
            // no condition here to await, only an errno that stops
            // being returned once the racing child execs, which it
            // does with no help from this thread.
            Err(err) if err.kind() == ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(BACKOFF);
            }
            Err(err) => panic!("the fake at {} must be spawnable: {err}", path.display()),
        }
    }
    panic!(
        "the fake at {} was still busy after {ATTEMPTS} probes",
        path.display()
    );
}
