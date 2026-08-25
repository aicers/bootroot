//! Tests for the registrar endpoint.
//!
//! Split the way the module is:
//!
//! - the **pure** tiers — activation values, descriptor facts, address
//!   classification, pathname policy, the non-root warning decision,
//!   peer authorization, identity rendering and the envelope's name
//!   rules — are plain unit tests over values. None of them touches this
//!   process's environment, and none needs a socket;
//! - the **stream** tier drives the real connection state machine over
//!   an in-memory duplex, with `tokio::time` paused, and reads the far
//!   end to prove that a refusal writes zero bytes and closes cleanly.
//!   The diagnostic fields are read back out of a captured `tracing`
//!   subscriber, so "typed logging with the connection diagnostic id" is
//!   asserted rather than assumed;
//! - the **socket** tier binds a listener *in the harness*, under
//!   `tempfile::tempdir()`, and hands its descriptor through the very
//!   activation seam production uses. Code under test never binds,
//!   unlinks or chmods anything.

use std::collections::BTreeMap;
use std::future::Future;
use std::os::fd::RawFd;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration as StdDuration;

use tempfile::TempDir;
use time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, SubscriberExt as _};
use wiremock::MockServer;

use super::activation::{
    ActivationContract, ActivationError, ActivationValues, DescriptorError, DescriptorFacts,
    UnixAddressKind, check_descriptor, classify_unix_address, is_cloexec,
};
use super::frame::{
    MalformedNameCause, Operation, check_operation_name, check_operation_name_length,
    escape_name_bytes,
};
use super::handler::{HANDLER_REJECTED_PAYLOAD, HandlerRefusal, RegistrarRequestHandler};
use super::policy::{self, SocketMetadata, SocketPolicyViolation};
use super::refusal::{ConnectionId, UNREAD_OPERATION, refuse};
use super::serve::{self, authorize_peer, caller_identity, serve_request};
use super::{
    ActivatedEndpoint, CONNECTION_DRAIN_TIMEOUT, HEADER_IDLE_TIMEOUT, MAX_CONCURRENT_CONNECTIONS,
    MAX_FRAME_PAYLOAD_BYTES, MAX_RESPONSE_PAYLOAD_BYTES, REQUIRED_SOCKET_MODE,
    UNPRIVILEGED_DAEMON_WARNING, current_effective_uid, warns_about_unprivileged_daemon,
};
use crate::openbao::{OpenBaoClient, SecretIdOptions};
use crate::registrar::ReloadSpec;
use crate::registrar::audit::AuditRecordStore;
use crate::registrar::config::RegistrarConfig;
use crate::registrar::fixture::RegistrarConfigFixture;
use crate::registrar::identity::RequestedSpec;
use crate::registrar::verbs::limiter::{VerbRateLimiter, VerbRateLimiterSettings};
use crate::registrar::verbs::outcome::CallerIdentity;
use crate::registrar::verbs::wrap_ttl::WrapTtlPolicy;
use crate::registrar::verbs::{
    DeregisterRequest, MintRequest, RegistrarVerbs, RegistrarVerbsConfig,
};

/// A pid no test process can have, for the mismatch arm.
const OTHER_PID: u32 = 424_242;
/// A uid no test process runs as, for the peer and owner arms.
const OTHER_UID: u32 = 999_001;
/// The duplex buffer, comfortably larger than any frame these tests
/// write, so a write never blocks on a reader that has not run yet.
const DUPLEX_CAPACITY: usize = 256 * 1024;
/// A component the fixture does not declare, so both verbs refuse it at
/// their first stage and reach `OpenBao` not at all.
const UNCONFIGURED_COMPONENT: &str = "no-such-component";

/// The mode a test's socket directory is put into explicitly.
///
/// `tempfile::tempdir()` creates its directory as `0o777` masked by the
/// process umask, so what it lands on is the *environment's* choice, not
/// the test's: under the umask `002` that a user-private-group account
/// gets, the directory is `0775` and the endpoint's directory policy
/// rightly refuses it. A test that means to bind a conforming listener
/// says so instead of hoping.
const TEST_DIRECTORY_MODE: u32 = 0o700;

/// A temporary directory the socket policy accepts, whatever the umask.
fn conforming_tempdir() -> std::io::Result<TempDir> {
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(
        dir.path(),
        std::fs::Permissions::from_mode(TEST_DIRECTORY_MODE),
    )?;
    Ok(dir)
}

/// Clears `FD_CLOEXEC`, which is how a harness reproduces the state
/// `systemd` hands an activation descriptor over in.
///
/// It is deliberately the *only* thing in these tests that touches the
/// flag. `std::os::unix::net::UnixListener::bind` opens its socket with
/// `SOCK_CLOEXEC`, so a harness that passed its listener straight
/// through would hand [`super::adopt`] a descriptor that was already
/// close-on-exec and would assert nothing about
/// [`super::activation::set_cloexec`] — the one call production depends
/// on, because `systemd` clears the flag before `exec`.
fn clear_cloexec(fd: RawFd) {
    // SAFETY: `F_GETFD` and `F_SETFD` read and write only this
    // descriptor's flags and touch no caller memory; `fd` is owned by a
    // live socket in the caller.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(flags >= 0, "F_GETFD");
    // SAFETY: as above.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    assert!(result >= 0, "F_SETFD");
}

/// Hands a harness-bound listener's descriptor over the way `systemd`
/// does: close-on-exec cleared, so setting it again is the production
/// code's job and not the harness's.
fn activation_descriptor(listener: std::os::unix::net::UnixListener) -> ActivationContract {
    let fd = super::into_raw_fd(listener);
    clear_cloexec(fd);
    ActivationContract::from_test_descriptor(fd)
}

// ---------------------------------------------------------------------
// Activation: the pure contract
// ---------------------------------------------------------------------

fn this_pid() -> u32 {
    std::process::id()
}

#[test]
fn activation_accepts_exactly_one_descriptor_addressed_to_this_process() {
    let values = ActivationValues::new(Some(&this_pid().to_string()), Some("1"));
    let contract = ActivationContract::consume(&values, this_pid()).expect("a valid contract");
    assert_eq!(contract.into_descriptor(), super::SD_LISTEN_FDS_START);
}

#[test]
fn activation_rejects_a_missing_contract() {
    let pid = this_pid().to_string();
    assert_eq!(
        ActivationContract::consume(&ActivationValues::new(None, Some("1")), this_pid())
            .expect_err("LISTEN_PID is required"),
        ActivationError::MissingListenPid
    );
    assert_eq!(
        ActivationContract::consume(&ActivationValues::new(Some(&pid), None), this_pid())
            .expect_err("LISTEN_FDS is required"),
        ActivationError::MissingListenFds
    );
    assert_eq!(
        ActivationContract::consume(&ActivationValues::default(), this_pid())
            .expect_err("neither variable is set"),
        ActivationError::MissingListenPid
    );
}

/// A contract addressed to another pid is the case a child inheriting
/// the environment produces, and it must never be adopted.
#[test]
fn activation_rejects_a_contract_addressed_to_another_process() {
    let values = ActivationValues::new(Some(&OTHER_PID.to_string()), Some("1"));
    assert_eq!(
        ActivationContract::consume(&values, this_pid()).expect_err("the pid must match"),
        ActivationError::PidMismatch {
            announced: OTHER_PID,
            actual: this_pid(),
        }
    );
}

#[test]
fn activation_rejects_any_count_but_one() {
    for count in ["0", "2", "3"] {
        let values = ActivationValues::new(Some(&this_pid().to_string()), Some(count));
        let error = ActivationContract::consume(&values, this_pid())
            .expect_err("only one descriptor is accepted");
        assert_eq!(
            error,
            ActivationError::DescriptorCount {
                count: count.parse().expect("a decimal count"),
            },
            "LISTEN_FDS={count}"
        );
    }
}

/// The values are compared as bare decimals: no sign, no padding, no
/// whitespace, nothing systemd would not write.
#[test]
fn activation_rejects_values_that_are_not_bare_decimals() {
    for pid in ["", " 1", "+1", "-1", "1 ", "0x1", "one"] {
        let values = ActivationValues::new(Some(pid), Some("1"));
        assert!(
            matches!(
                ActivationContract::consume(&values, this_pid()),
                Err(ActivationError::UnparsableListenPid { .. })
            ),
            "LISTEN_PID={pid:?}"
        );
    }
    for fds in ["", " 1", "+1", "-1", "one"] {
        let values = ActivationValues::new(Some(&this_pid().to_string()), Some(fds));
        assert!(
            matches!(
                ActivationContract::consume(&values, this_pid()),
                Err(ActivationError::UnparsableListenFds { .. })
            ),
            "LISTEN_FDS={fds:?}"
        );
    }
}

// ---------------------------------------------------------------------
// Activation: descriptor facts
// ---------------------------------------------------------------------

fn valid_facts() -> DescriptorFacts {
    DescriptorFacts {
        domain: libc::AF_UNIX,
        sock_type: libc::SOCK_STREAM,
        accepting: true,
        cloexec: true,
    }
}

#[test]
fn descriptor_check_accepts_a_listening_unix_stream() {
    assert_eq!(check_descriptor(valid_facts()), Ok(()));
}

#[test]
fn descriptor_check_rejects_every_wrong_fact() {
    assert_eq!(
        check_descriptor(DescriptorFacts {
            domain: libc::AF_INET,
            ..valid_facts()
        }),
        Err(DescriptorError::Family {
            domain: libc::AF_INET
        })
    );
    assert_eq!(
        check_descriptor(DescriptorFacts {
            sock_type: libc::SOCK_DGRAM,
            ..valid_facts()
        }),
        Err(DescriptorError::Kind {
            sock_type: libc::SOCK_DGRAM
        })
    );
    assert_eq!(
        check_descriptor(DescriptorFacts {
            accepting: false,
            ..valid_facts()
        }),
        Err(DescriptorError::NotListening)
    );
    assert_eq!(
        check_descriptor(DescriptorFacts {
            cloexec: false,
            ..valid_facts()
        }),
        Err(DescriptorError::NotCloexec)
    );
}

// ---------------------------------------------------------------------
// Activation: address classification
// ---------------------------------------------------------------------

/// The two-byte `sun_family` that precedes `sun_path` in a
/// `sockaddr_un`, which every reported length includes.
const FAMILY_BYTES: usize = 2;
/// `sun_path`'s length on Linux.
const SUN_PATH_LEN: usize = 108;

fn sun_path_of(value: &[u8]) -> [u8; SUN_PATH_LEN] {
    let mut path = [0u8; SUN_PATH_LEN];
    path.get_mut(..value.len())
        .expect("the test value fits sun_path")
        .copy_from_slice(value);
    path
}

#[test]
fn address_classification_accepts_a_pathname() {
    let path = sun_path_of(b"/run/bootroot/registrar.sock");
    let kind = classify_unix_address(
        libc::AF_UNIX,
        &path,
        FAMILY_BYTES + b"/run/bootroot/registrar.sock".len() + 1,
    );
    assert_eq!(
        kind,
        UnixAddressKind::Pathname(PathBuf::from("/run/bootroot/registrar.sock"))
    );
}

#[test]
fn address_classification_rejects_everything_that_is_not_a_pathname() {
    let empty = sun_path_of(b"");
    assert_eq!(
        classify_unix_address(libc::AF_UNIX, &empty, FAMILY_BYTES),
        UnixAddressKind::Unnamed
    );

    let mut abstract_name = sun_path_of(b"\0bootroot");
    abstract_name[0] = 0;
    assert_eq!(
        classify_unix_address(libc::AF_UNIX, &abstract_name, FAMILY_BYTES + 9),
        UnixAddressKind::Abstract
    );

    // A reported length past the buffer: the kernel had more to say than
    // fitted, so the name that would be checked is not the name bound.
    assert_eq!(
        classify_unix_address(libc::AF_UNIX, &empty, FAMILY_BYTES + SUN_PATH_LEN + 1),
        UnixAddressKind::Truncated
    );

    // A name that fills `sun_path` with no terminator is equally
    // untrustworthy.
    let full = [b'a'; SUN_PATH_LEN];
    assert_eq!(
        classify_unix_address(libc::AF_UNIX, &full, FAMILY_BYTES + SUN_PATH_LEN),
        UnixAddressKind::Truncated
    );

    assert_eq!(
        classify_unix_address(libc::AF_INET, &empty, FAMILY_BYTES),
        UnixAddressKind::WrongFamily {
            family: libc::AF_INET
        }
    );
}

#[test]
fn only_a_pathname_address_yields_a_path() {
    assert!(
        UnixAddressKind::Pathname(PathBuf::from("/run/x.sock"))
            .into_pathname()
            .is_ok()
    );
    for kind in [
        UnixAddressKind::Unnamed,
        UnixAddressKind::Abstract,
        UnixAddressKind::Truncated,
        UnixAddressKind::WrongFamily {
            family: libc::AF_INET,
        },
    ] {
        assert!(kind.clone().into_pathname().is_err(), "{kind:?}");
    }
}

// ---------------------------------------------------------------------
// Pathname policy
// ---------------------------------------------------------------------

fn conforming_metadata(uid: u32) -> SocketMetadata {
    SocketMetadata {
        socket_path: PathBuf::from("/run/bootroot/registrar.sock"),
        socket_mode: REQUIRED_SOCKET_MODE,
        socket_uid: uid,
        directory_path: PathBuf::from("/run/bootroot"),
        directory_mode: 0o755,
        directory_uid: uid,
    }
}

/// The shipped unit's `RuntimeDirectoryMode=0755` and a hand-made `0700`
/// both pass: the directory check is a bitmask over the write bits, not
/// an equality.
#[test]
fn policy_accepts_both_documented_directory_modes() {
    for directory_mode in [0o700, 0o755, 0o555, 0o750] {
        let metadata = SocketMetadata {
            directory_mode,
            ..conforming_metadata(0)
        };
        assert_eq!(policy::check(&metadata, 0), Ok(()), "{directory_mode:04o}");
    }
}

/// A listener created by an unprivileged user conforms under that user's
/// uid, which is what lets the socket tier below run as anybody.
#[test]
fn policy_accepts_a_conforming_socket_under_any_daemon_uid() {
    for uid in [0, 1000, OTHER_UID] {
        assert_eq!(
            policy::check(&conforming_metadata(uid), uid),
            Ok(()),
            "{uid}"
        );
    }
}

#[test]
fn policy_rejects_a_socket_mode_that_is_not_exactly_0700() {
    for mode in [0o600, 0o750, 0o755, 0o777, 0o070, 0o000] {
        let metadata = SocketMetadata {
            socket_mode: mode,
            ..conforming_metadata(0)
        };
        assert!(
            matches!(
                policy::check(&metadata, 0),
                Err(SocketPolicyViolation::SocketMode { found, required, .. })
                    if found == mode && required == REQUIRED_SOCKET_MODE
            ),
            "{mode:04o}"
        );
    }
}

#[test]
fn policy_rejects_a_socket_owned_by_another_account() {
    let metadata = SocketMetadata {
        socket_uid: OTHER_UID,
        ..conforming_metadata(0)
    };
    assert!(matches!(
        policy::check(&metadata, 0),
        Err(SocketPolicyViolation::SocketOwner {
            found: OTHER_UID,
            expected: 0,
            ..
        })
    ));
}

#[test]
fn policy_rejects_a_directory_owned_by_another_account() {
    let metadata = SocketMetadata {
        directory_uid: OTHER_UID,
        ..conforming_metadata(0)
    };
    assert!(matches!(
        policy::check(&metadata, 0),
        Err(SocketPolicyViolation::DirectoryOwner {
            found: OTHER_UID,
            expected: 0,
            ..
        })
    ));
}

#[test]
fn policy_rejects_a_group_or_world_writable_directory() {
    for mode in [0o770, 0o707, 0o777, 0o733, 0o722] {
        let metadata = SocketMetadata {
            directory_mode: mode,
            ..conforming_metadata(0)
        };
        assert!(
            matches!(
                policy::check(&metadata, 0),
                Err(SocketPolicyViolation::DirectoryWritable { found, .. }) if found == mode
            ),
            "{mode:04o}"
        );
    }
}

/// A real directory tree, so the collector and the decision agree about
/// what `stat` reports.
#[test]
fn policy_collects_the_socket_and_its_parent_from_the_filesystem() {
    let dir = conforming_tempdir().expect("tempdir");
    let socket_path = dir.path().join("registrar.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket_path).expect("bind");
    std::fs::set_permissions(
        &socket_path,
        std::fs::Permissions::from_mode(REQUIRED_SOCKET_MODE),
    )
    .expect("chmod");

    let metadata = policy::collect(&socket_path).expect("collect");
    assert_eq!(metadata.socket_path, socket_path);
    assert_eq!(metadata.socket_mode, REQUIRED_SOCKET_MODE);
    assert_eq!(metadata.socket_uid, current_effective_uid());
    assert_eq!(metadata.directory_path, dir.path());
    assert_eq!(metadata.directory_uid, current_effective_uid());
    assert_eq!(policy::check(&metadata, current_effective_uid()), Ok(()));
    drop(listener);
}

// ---------------------------------------------------------------------
// The non-root warning, peer authorization and identity
// ---------------------------------------------------------------------

#[test]
fn the_unprivileged_warning_is_a_pure_function_of_enablement_and_uid() {
    assert!(warns_about_unprivileged_daemon(true, 1000));
    assert!(warns_about_unprivileged_daemon(true, OTHER_UID));
    assert!(!warns_about_unprivileged_daemon(true, 0));
    assert!(!warns_about_unprivileged_daemon(false, 1000));
    assert!(!warns_about_unprivileged_daemon(false, 0));
}

/// The warning states the consequence — the verbs cannot succeed —
/// rather than merely observing the uid.
#[test]
fn the_unprivileged_warning_names_the_consequence() {
    for fragment in [
        "mint",
        "deregister",
        "cannot succeed",
        "privileged internal credential",
    ] {
        assert!(
            UNPRIVILEGED_DAEMON_WARNING.contains(fragment),
            "the warning must mention {fragment:?}: {UNPRIVILEGED_DAEMON_WARNING}"
        );
    }
}

#[test]
fn only_the_daemons_own_uid_is_authorized() {
    assert!(authorize_peer(0, 0));
    assert!(authorize_peer(1000, 1000));
    assert!(!authorize_peer(0, 1000));
    assert!(!authorize_peer(1000, 0));
    assert!(!authorize_peer(OTHER_UID, 1000));
}

#[test]
fn the_caller_identity_is_the_uid_and_nothing_else() {
    assert_eq!(caller_identity(0).as_str(), "unix-peer:uid=0");
    assert_eq!(caller_identity(1000).as_str(), "unix-peer:uid=1000");
    // Stable for a uid: two renderings of one uid are one identity.
    assert_eq!(caller_identity(1000), caller_identity(1000));
    // And distinct between uids.
    assert_ne!(caller_identity(1000), caller_identity(1001));
}

// ---------------------------------------------------------------------
// The envelope's name rules
// ---------------------------------------------------------------------

#[test]
fn the_only_operations_are_mint_and_deregister() {
    assert_eq!(Operation::from_name("mint"), Some(Operation::Mint));
    assert_eq!(
        Operation::from_name("deregister"),
        Some(Operation::Deregister)
    );
    for name in [
        "",
        "Mint",
        "mint_",
        "rotate",
        "list",
        "mintx",
        "de_register",
    ] {
        assert_eq!(Operation::from_name(name), None, "{name}");
    }
    assert_eq!(Operation::Mint.as_str(), "mint");
    assert_eq!(Operation::Deregister.as_str(), "deregister");
}

#[test]
fn the_name_length_rule_rejects_zero_and_over_thirty_two() {
    assert_eq!(
        check_operation_name_length(0),
        Err(MalformedNameCause::EmptyName)
    );
    assert_eq!(check_operation_name_length(1), Ok(1));
    assert_eq!(check_operation_name_length(32), Ok(32));
    assert_eq!(
        check_operation_name_length(33),
        Err(MalformedNameCause::NameTooLong { declared: 33 })
    );
    assert_eq!(
        check_operation_name_length(255),
        Err(MalformedNameCause::NameTooLong { declared: 255 })
    );
}

#[test]
fn the_name_alphabet_is_exactly_lowercase_and_underscore() {
    assert_eq!(check_operation_name(b"mint"), Ok("mint"));
    assert_eq!(check_operation_name(b"a_b"), Ok("a_b"));
    for bytes in [
        b"Mint".as_slice(),
        b"mint1",
        b"mint-",
        b"mi nt",
        b"mint\0",
        &[0xffu8],
    ] {
        assert_eq!(
            check_operation_name(bytes),
            Err(MalformedNameCause::NonNameByte),
            "{bytes:?}"
        );
    }
}

#[test]
fn name_bytes_are_escaped_and_capped_for_logging() {
    assert_eq!(escape_name_bytes(b"mint"), "mint");
    assert_eq!(escape_name_bytes(b"a\nb"), "a\\x0ab");
    assert_eq!(escape_name_bytes(b"a b"), "a\\x20b");
    assert_eq!(escape_name_bytes(b"\\"), "\\x5c");
    let long = [b'a'; 40];
    let escaped = escape_name_bytes(&long);
    assert_eq!(escaped, format!("{}...", "a".repeat(32)));
}

// ---------------------------------------------------------------------
// Captured logging, so a refusal's diagnostic fields are assertable
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CapturedEvent {
    message: String,
    fields: BTreeMap<String, String>,
}

impl CapturedEvent {
    fn field(&self, name: &str) -> &str {
        self.fields
            .get(name)
            .map_or("", std::string::String::as_str)
    }
}

#[derive(Clone, Default)]
struct CapturedLogs(Arc<StdMutex<Vec<CapturedEvent>>>);

impl CapturedLogs {
    fn events(&self) -> Vec<CapturedEvent> {
        self.0
            .lock()
            .expect("the capture mutex is only held to push and read")
            .clone()
    }

    /// The one refusal event, which every refusal path emits exactly
    /// once.
    fn refusal(&self) -> CapturedEvent {
        let mut matching: Vec<CapturedEvent> = self
            .events()
            .into_iter()
            .filter(|event| {
                event
                    .message
                    .starts_with("Registrar endpoint refused a connection")
            })
            .collect();
        assert_eq!(
            matching.len(),
            1,
            "expected exactly one refusal event, saw {matching:?}"
        );
        matching.remove(0)
    }
}

struct FieldCollector(BTreeMap<String, String>);

impl Visit for FieldCollector {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}"));
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CapturedLogs {
    fn on_event(&self, event: &tracing::Event<'_>, _context: Context<'_, S>) {
        let mut collector = FieldCollector(BTreeMap::new());
        event.record(&mut collector);
        let message = collector
            .0
            .remove("message")
            .unwrap_or_default()
            .trim_matches('"')
            .to_string();
        self.0
            .lock()
            .expect("the capture mutex is only held to push and read")
            .push(CapturedEvent {
                message,
                fields: collector.0,
            });
    }
}

/// Installs a capturing subscriber for the current thread.
///
/// Every test that uses it runs on a current-thread runtime, so the
/// whole future stays on the thread the guard was taken on.
fn capture_logs() -> (CapturedLogs, tracing::subscriber::DefaultGuard) {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::registry().with(logs.clone());
    let guard = tracing::subscriber::set_default(subscriber);
    (logs, guard)
}

// ---------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------

/// A handler that refuses everything, for the [`HandlerRefusal`] path.
struct RejectingHandler;

impl RegistrarRequestHandler for RejectingHandler {
    fn handle<'a>(
        &'a self,
        _operation: Operation,
        _payload: &'a [u8],
        _caller: CallerIdentity,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, HandlerRefusal>> + Send + 'a>> {
        Box::pin(async { Err(HandlerRefusal) })
    }
}

/// A handler that echoes a fixed body, for the transport tiers that do
/// not care what a verb would have said.
struct EchoHandler {
    response: Vec<u8>,
}

impl RegistrarRequestHandler for EchoHandler {
    fn handle<'a>(
        &'a self,
        operation: Operation,
        payload: &'a [u8],
        caller: CallerIdentity,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, HandlerRefusal>> + Send + 'a>> {
        let mut response = format!(
            "{}|{}|{}|",
            operation.as_str(),
            payload.len(),
            caller.as_str()
        )
        .into_bytes();
        response.extend_from_slice(&self.response);
        Box::pin(async move { Ok(response) })
    }
}

/// A handler that parks until it is released, for the capacity and
/// drain tiers.
struct BlockingHandler {
    entered: mpsc::UnboundedSender<()>,
    release: Arc<Semaphore>,
}

impl RegistrarRequestHandler for BlockingHandler {
    fn handle<'a>(
        &'a self,
        _operation: Operation,
        _payload: &'a [u8],
        _caller: CallerIdentity,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, HandlerRefusal>> + Send + 'a>> {
        let entered = self.entered.clone();
        let release = Arc::clone(&self.release);
        Box::pin(async move {
            let _ = entered.send(());
            if let Ok(permit) = release.acquire().await {
                permit.forget();
            }
            Ok(b"released".to_vec())
        })
    }
}

/// The `cfg(test)` handler that drives the **real** in-process verbs.
///
/// Its payload shape is internal to these tests and is deliberately not
/// a protocol: `service_name|host|instance`, with an empty instance
/// meaning none. The versioned request and response schemas belong to
/// the protocol module, and this transport-focused test handler must not
/// invent a second wire format.
struct VerbHandler {
    verbs: RegistrarVerbs,
}

impl RegistrarRequestHandler for VerbHandler {
    fn handle<'a>(
        &'a self,
        operation: Operation,
        payload: &'a [u8],
        caller: CallerIdentity,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, HandlerRefusal>> + Send + 'a>> {
        Box::pin(async move {
            if payload.is_empty() {
                // A zero-length payload is a valid frame. What it means
                // is the payload schema's business; here it is simply
                // acknowledged, which is enough to prove it traversed
                // the transport.
                return Ok(b"empty".to_vec());
            }
            let text = std::str::from_utf8(payload).map_err(|_| HandlerRefusal)?;
            let mut parts = text.split('|');
            let (Some(service_name), Some(host), Some(instance), None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                return Err(HandlerRefusal);
            };
            let instance = if instance.is_empty() {
                None
            } else {
                Some(instance.parse::<u32>().map_err(|_| HandlerRefusal)?)
            };

            let rendered = match operation {
                Operation::Mint => {
                    let request = MintRequest {
                        caller,
                        service_name: service_name.to_string(),
                        host: host.to_string(),
                        instance,
                        spec: RequestedSpec::new(ReloadSpec::none(), None),
                        wrap_ttl: Duration::minutes(5),
                    };
                    match self.verbs.mint(&request).await {
                        Ok(_) => "mint|minted|".to_string(),
                        Err(refusal) => format!(
                            "mint|refused:{:?}|{}",
                            refusal.context().arm(),
                            refusal.context().caller().as_str()
                        ),
                    }
                }
                Operation::Deregister => {
                    let request = DeregisterRequest {
                        caller,
                        service_name: service_name.to_string(),
                        host: host.to_string(),
                        instance,
                    };
                    match self.verbs.deregister(&request).await {
                        Ok(_) => "deregister|torn-down|".to_string(),
                        Err(refusal) => format!(
                            "deregister|refused:{:?}|{}",
                            refusal.context().arm(),
                            refusal.context().caller().as_str()
                        ),
                    }
                }
            };
            Ok(rendered.into_bytes())
        })
    }
}

/// Builds a verb service over a `Wiremock` with no mounted responses, so
/// any `OpenBao` request at all is visible in its recorded requests.
fn verb_handler(server: &MockServer) -> (TempDir, Arc<dyn RegistrarRequestHandler>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = RegistrarConfigFixture::new()
        .write_to(dir.path())
        .expect("write the rendered registrar config");
    let config = RegistrarConfig::load(&path).expect("the fixture must load");
    let mut client = OpenBaoClient::new(&server.uri()).expect("client");
    client.set_token("test-token".to_string());
    let verbs = RegistrarVerbs::new(RegistrarVerbsConfig {
        client,
        kv_mount: "secret".to_string(),
        config,
        secret_id_options: SecretIdOptions {
            ttl: Some("10m".to_string()),
            num_uses: Some(1),
            ..Default::default()
        },
        token_ttl: "1h".to_string(),
        secret_id_ttl: "24h".to_string(),
        wrap_ttl_policy: WrapTtlPolicy::new(Duration::minutes(30)).expect("policy maximum"),
        audit_store: AuditRecordStore::open_temporary().expect("a temporary audit store"),
        limiter: VerbRateLimiter::with_counting_sink(VerbRateLimiterSettings::default()).0,
    });
    (dir, Arc::new(VerbHandler { verbs }))
}

// ---------------------------------------------------------------------
// The stream tier: one connection over an in-memory duplex
// ---------------------------------------------------------------------

/// Builds a request frame: four-byte big-endian payload length, one-byte
/// name length, the name, the payload.
fn frame_of(name: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("a test payload fits u32")
            .to_be_bytes(),
    );
    out.push(u8::try_from(name.len()).expect("a test name fits u8"));
    out.extend_from_slice(name);
    out.extend_from_slice(payload);
    out
}

/// A frame whose declared payload length is whatever the test says,
/// regardless of how many payload bytes actually follow.
fn frame_declaring(declared: u32, name: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&declared.to_be_bytes());
    out.push(u8::try_from(name.len()).expect("a test name fits u8"));
    out.extend_from_slice(name);
    out.extend_from_slice(payload);
    out
}

/// Drives one request through the production connection state machine
/// and returns everything the caller could observe on the wire.
async fn drive(handler: &dyn RegistrarRequestHandler, request: &[u8]) -> Vec<u8> {
    drive_with(handler, request, true).await
}

/// As [`drive`], but `close_after` decides whether the caller half is
/// shut down before the endpoint reads — which is the difference between
/// an EOF and a deadline.
async fn drive_with(
    handler: &dyn RegistrarRequestHandler,
    request: &[u8],
    close_after: bool,
) -> Vec<u8> {
    let (mut client, mut server) = tokio::io::duplex(DUPLEX_CAPACITY);
    client
        .write_all(request)
        .await
        .expect("the duplex accepts the request");
    if close_after {
        client.shutdown().await.expect("the caller half closes");
    }
    serve_request(
        &mut server,
        &ConnectionId::next(),
        &caller_identity(current_effective_uid()),
        handler,
        Instant::now(),
    )
    .await;
    let mut observed = Vec::new();
    client
        .read_to_end(&mut observed)
        .await
        .expect("the caller half reads to EOF");
    observed
}

/// Decodes a response frame, asserting the declared length matches.
fn decode_response(bytes: &[u8]) -> Vec<u8> {
    let (prefix, body) = bytes.split_at(4);
    let declared = u32::from_be_bytes(prefix.try_into().expect("four length bytes"));
    assert_eq!(
        usize::try_from(declared).expect("a test response fits usize"),
        body.len(),
        "the declared response length must match the bytes that followed"
    );
    body.to_vec()
}

#[tokio::test]
async fn a_valid_request_gets_one_response_and_a_close() {
    let handler = EchoHandler {
        response: b"body".to_vec(),
    };
    let observed = drive(&handler, &frame_of(b"mint", b"payload")).await;
    let body = decode_response(&observed);
    assert_eq!(
        String::from_utf8(body).expect("utf-8"),
        format!("mint|7|unix-peer:uid={}|body", current_effective_uid())
    );
}

#[tokio::test]
async fn a_zero_length_payload_is_a_valid_frame() {
    let handler = EchoHandler {
        response: b"ok".to_vec(),
    };
    let observed = drive(&handler, &frame_of(b"deregister", b"")).await;
    let body = decode_response(&observed);
    assert_eq!(
        String::from_utf8(body).expect("utf-8"),
        format!("deregister|0|unix-peer:uid={}|ok", current_effective_uid())
    );
}

/// A refusal writes **zero** bytes: not a wire error, not an empty
/// frame, not a status. The caller reads EOF and nothing else.
#[tokio::test]
async fn no_header_is_a_zero_byte_clean_close_with_an_unread_operation() {
    let (logs, _guard) = capture_logs();
    let handler = EchoHandler {
        response: Vec::new(),
    };
    let observed = drive(&handler, b"").await;
    assert!(
        observed.is_empty(),
        "a refusal writes no bytes: {observed:?}"
    );

    let event = logs.refusal();
    assert_eq!(event.field("reason"), "no-header");
    assert_eq!(event.field("operation"), UNREAD_OPERATION);
    assert_eq!(event.field("received_name"), UNREAD_OPERATION);
    assert!(
        event.field("connection").starts_with("endpoint-conn-"),
        "the connection diagnostic id must be logged: {event:?}"
    );
}

#[tokio::test]
async fn a_partial_prefix_is_a_partial_frame() {
    let (logs, _guard) = capture_logs();
    let handler = EchoHandler {
        response: Vec::new(),
    };
    let observed = drive(&handler, &[0u8, 0, 0]).await;
    assert!(observed.is_empty());

    let event = logs.refusal();
    assert_eq!(event.field("reason"), "partial-frame");
    assert_eq!(event.field("operation"), UNREAD_OPERATION);
}

/// A name that stopped short has no identifier to log — but the bytes
/// that did arrive are not nothing, so they are logged as received
/// bytes. The unread marker belongs to the identifier, which was never
/// completed, and not to a stage that produced bytes.
#[tokio::test]
async fn a_partial_operation_name_is_a_partial_frame_logging_the_bytes_that_arrived() {
    let (logs, _guard) = capture_logs();
    let handler = EchoHandler {
        response: Vec::new(),
    };
    // Declares a four-byte name and supplies two of them.
    let observed = drive(&handler, &[0u8, 0, 0, 0, 4, b'm', b'i']).await;
    assert!(observed.is_empty());

    let event = logs.refusal();
    assert_eq!(event.field("reason"), "partial-frame");
    assert_eq!(event.field("operation"), UNREAD_OPERATION);
    assert_eq!(event.field("received_name"), "mi");
}

/// The same stage with *no* byte read is where the unread marker is
/// right: there is nothing to escape and nothing to invent.
#[tokio::test]
async fn an_operation_name_with_no_byte_read_logs_the_unread_marker() {
    let (logs, _guard) = capture_logs();
    let handler = EchoHandler {
        response: Vec::new(),
    };
    // Declares a four-byte name and supplies none of them.
    let observed = drive(&handler, &[0u8, 0, 0, 0, 4]).await;
    assert!(observed.is_empty());

    let event = logs.refusal();
    assert_eq!(event.field("reason"), "partial-frame");
    assert_eq!(event.field("operation"), UNREAD_OPERATION);
    assert_eq!(event.field("received_name"), UNREAD_OPERATION);
}

/// Received name bytes reach the log escaped, whatever they are, and a
/// partial name is no exception.
#[tokio::test]
async fn a_partial_operation_name_is_escaped_in_the_log() {
    let (logs, _guard) = capture_logs();
    let handler = EchoHandler {
        response: Vec::new(),
    };
    let observed = drive(&handler, &[0u8, 0, 0, 0, 4, b'm', 0x00]).await;
    assert!(observed.is_empty());
    assert_eq!(logs.refusal().field("received_name"), "m\\x00");
}

#[tokio::test]
async fn a_partial_payload_is_a_partial_frame_naming_its_operation() {
    let (logs, _guard) = capture_logs();
    let handler = EchoHandler {
        response: Vec::new(),
    };
    let observed = drive(&handler, &frame_declaring(16, b"mint", b"short")).await;
    assert!(observed.is_empty());

    let event = logs.refusal();
    assert_eq!(event.field("reason"), "partial-frame");
    assert_eq!(event.field("operation"), "mint");
}

/// An over-long declaration is refused on the prefix alone: the name
/// bytes that follow it are never read, and nothing is allocated for the
/// payload.
#[tokio::test]
async fn an_over_long_declared_payload_is_refused_before_the_name_is_read() {
    let (logs, _guard) = capture_logs();
    let handler = EchoHandler {
        response: Vec::new(),
    };
    let declared = u32::try_from(MAX_FRAME_PAYLOAD_BYTES + 1).expect("the limit fits u32");
    let observed = drive(&handler, &frame_declaring(declared, b"mint", b"")).await;
    assert!(observed.is_empty());

    let event = logs.refusal();
    assert_eq!(event.field("reason"), "over-long-frame");
    // The name bytes were on the wire but were never read, so there is
    // no identifier to log and the unread marker stands in for one.
    assert_eq!(event.field("operation"), UNREAD_OPERATION);
    assert_eq!(event.field("received_name"), UNREAD_OPERATION);
}

/// The largest accepted payload is exactly the limit, not one less.
#[tokio::test]
async fn a_payload_at_the_limit_is_accepted() {
    let handler = EchoHandler {
        response: Vec::new(),
    };
    let payload = vec![b'x'; MAX_FRAME_PAYLOAD_BYTES];
    let observed = drive(&handler, &frame_of(b"mint", &payload)).await;
    let body = decode_response(&observed);
    assert!(
        String::from_utf8_lossy(&body).contains(&format!("|{MAX_FRAME_PAYLOAD_BYTES}|")),
        "the whole payload must reach the handler"
    );
}

#[tokio::test]
async fn a_zero_or_over_long_name_length_is_a_malformed_header() {
    for declared in [0u8, 33, 255] {
        let (logs, _guard) = capture_logs();
        let handler = EchoHandler {
            response: Vec::new(),
        };
        let observed = drive(&handler, &[0u8, 0, 0, 0, declared]).await;
        assert!(observed.is_empty(), "{declared}");

        let event = logs.refusal();
        assert_eq!(event.field("reason"), "malformed-header", "{declared}");
        assert_eq!(event.field("operation"), UNREAD_OPERATION, "{declared}");
    }
}

#[tokio::test]
async fn a_non_name_byte_is_a_malformed_header_logging_the_escaped_bytes() {
    let (logs, _guard) = capture_logs();
    let handler = EchoHandler {
        response: Vec::new(),
    };
    let observed = drive(&handler, &frame_of(b"Mi\nt", b"")).await;
    assert!(observed.is_empty());

    let event = logs.refusal();
    assert_eq!(event.field("reason"), "malformed-header");
    assert_eq!(event.field("operation"), UNREAD_OPERATION);
    assert_eq!(event.field("received_name"), "Mi\\x0at");
}

/// Unrecognized applies only to a syntactically valid, complete name,
/// and the identifier is logged as received.
#[tokio::test]
async fn an_unknown_but_well_formed_name_is_an_unrecognized_operation() {
    let (logs, _guard) = capture_logs();
    let handler = EchoHandler {
        response: Vec::new(),
    };
    let observed = drive(&handler, &frame_of(b"rotate", b"")).await;
    assert!(observed.is_empty());

    let event = logs.refusal();
    assert_eq!(event.field("reason"), "unrecognized-operation");
    assert_eq!(event.field("received_name"), "rotate");
    // Not a recognized operation, so there is no operation to name.
    assert_eq!(event.field("operation"), UNREAD_OPERATION);
}

#[tokio::test]
async fn a_handler_refusal_is_a_zero_byte_clean_close_under_its_fixed_cause() {
    let (logs, _guard) = capture_logs();
    let observed = drive(&RejectingHandler, &frame_of(b"mint", b"anything")).await;
    assert!(observed.is_empty(), "a handler refusal writes no bytes");

    let event = logs.refusal();
    assert_eq!(event.field("reason"), "handler-rejected-payload");
    assert_eq!(event.field("operation"), "mint");
    assert!(
        event.message.contains(HANDLER_REJECTED_PAYLOAD),
        "the fixed diagnostic cause must be logged: {event:?}"
    );
}

/// An over-long response is a post-verb internal failure: it is logged
/// at error and the connection closes with nothing written, rather than
/// travelling the pre-verb refusal taxonomy.
#[tokio::test]
async fn an_over_long_response_closes_without_a_response_and_without_a_refusal() {
    let (logs, _guard) = capture_logs();
    let handler = EchoHandler {
        response: vec![b'y'; MAX_RESPONSE_PAYLOAD_BYTES + 1],
    };
    let observed = drive(&handler, &frame_of(b"mint", b"")).await;
    assert!(
        observed.is_empty(),
        "nothing is written: {}",
        observed.len()
    );
    assert!(
        logs.events()
            .iter()
            .all(|event| !event.message.starts_with("Registrar endpoint refused")),
        "an over-long response is not a refusal: {:?}",
        logs.events()
    );
    assert!(
        logs.events()
            .iter()
            .any(|event| event.message.contains("over-long response")),
        "the internal failure must be logged: {:?}",
        logs.events()
    );
}

#[tokio::test]
async fn the_refusal_helper_writes_nothing_and_closes() {
    let (mut client, mut server) = tokio::io::duplex(64);
    let connection = ConnectionId::next();
    refuse(
        &mut server,
        &connection,
        &super::refusal::Refusal::transport(super::refusal::TransportRefusalReason::OverCapacity),
    )
    .await;
    let mut observed = Vec::new();
    client
        .read_to_end(&mut observed)
        .await
        .expect("read to EOF");
    assert!(observed.is_empty());
}

/// Every one of the seven typed reasons takes the *same* path.
///
/// The tiers above reach six of them by driving a connection into the
/// state they describe. `UnauthorizedPeer` cannot be reached that way —
/// it needs a peer running as a second uid, which a test cannot conjure
/// without privileges — so the closed taxonomy is asserted here at the
/// helper instead, where each reason is one value. What is asserted is
/// what the reasons are required to have in common: zero response bytes,
/// a clean close, the daemon-generated connection id, a stable label,
/// and the explicit unread marker wherever no operation was read.
#[tokio::test]
async fn every_transport_reason_refuses_through_the_common_helper() {
    use super::refusal::{FrameEnd, PartialStage, Refusal, TransportRefusalReason as Reason};

    let reasons = [
        (Reason::OverCapacity, "over-capacity"),
        (
            Reason::UnauthorizedPeer {
                peer_uid: OTHER_UID,
                expected_uid: current_effective_uid(),
            },
            "unauthorized-peer",
        ),
        (
            Reason::NoHeader {
                end: FrameEnd::Deadline,
            },
            "no-header",
        ),
        (
            Reason::OverLongFrame {
                declared: u32::MAX,
                limit: MAX_FRAME_PAYLOAD_BYTES,
            },
            "over-long-frame",
        ),
        (
            Reason::PartialFrame {
                stage: PartialStage::Prefix,
                end: FrameEnd::Eof,
                received: 1,
                expected: 5,
            },
            "partial-frame",
        ),
        (
            Reason::MalformedHeader {
                cause: MalformedNameCause::EmptyName,
            },
            "malformed-header",
        ),
        (Reason::UnrecognizedOperation, "unrecognized-operation"),
    ];

    let mut labels = Vec::new();
    for (reason, label) in reasons {
        let (logs, guard) = capture_logs();
        let (mut client, mut server) = tokio::io::duplex(64);
        let connection = ConnectionId::next();
        refuse(&mut server, &connection, &Refusal::transport(reason)).await;
        drop(guard);

        let mut observed = Vec::new();
        client
            .read_to_end(&mut observed)
            .await
            .expect("the helper closes cleanly, so the far end reads to EOF");
        assert!(
            observed.is_empty(),
            "{label} must write zero response bytes, saw {observed:?}"
        );

        let event = logs.refusal();
        assert_eq!(event.field("reason"), label);
        assert_eq!(
            event.field("connection"),
            connection.as_str(),
            "{label} must carry the daemon-generated connection id"
        );
        assert_eq!(
            event.field("operation"),
            UNREAD_OPERATION,
            "{label} read no operation, so it must log the explicit unread marker"
        );
        assert_eq!(
            event.field("received_name"),
            UNREAD_OPERATION,
            "{label} read no name bytes, so it must log the explicit unread marker"
        );
        labels.push(label);
    }

    labels.sort_unstable();
    labels.dedup();
    assert_eq!(
        labels.len(),
        7,
        "the taxonomy is closed at seven distinct labels: {labels:?}"
    );
}

/// The connection diagnostic id is daemon-generated and never repeats
/// within a process.
#[test]
fn connection_ids_are_distinct_and_shaped_unlike_a_verb_request_id() {
    let first = ConnectionId::next();
    let second = ConnectionId::next();
    assert_ne!(first, second);
    assert!(first.as_str().starts_with("endpoint-conn-"));
    assert!(second.as_str().starts_with("endpoint-conn-"));
}

// ---------------------------------------------------------------------
// Cumulative deadlines
// ---------------------------------------------------------------------

/// The header deadline is cumulative from acceptance: a caller that
/// holds the connection open without sending a byte is refused as
/// no-header when it expires.
#[tokio::test(start_paused = true)]
async fn the_header_deadline_expires_with_no_header_when_no_byte_arrives() {
    let (logs, _guard) = capture_logs();
    let handler = EchoHandler {
        response: Vec::new(),
    };
    let observed = drive_with(&handler, b"", false).await;
    assert!(observed.is_empty());

    let event = logs.refusal();
    assert_eq!(event.field("reason"), "no-header");
}

/// Once one byte has arrived, the same expiry is a partial frame rather
/// than a missing one.
#[tokio::test(start_paused = true)]
async fn the_header_deadline_expires_as_a_partial_frame_after_one_byte() {
    let (logs, _guard) = capture_logs();
    let handler = EchoHandler {
        response: Vec::new(),
    };
    let observed = drive_with(&handler, &[0u8], false).await;
    assert!(observed.is_empty());
    assert_eq!(logs.refusal().field("reason"), "partial-frame");
}

/// The body deadline is its own budget, cumulative from header
/// completion.
#[tokio::test(start_paused = true)]
async fn the_body_deadline_expires_as_a_partial_frame() {
    let (logs, _guard) = capture_logs();
    let handler = EchoHandler {
        response: Vec::new(),
    };
    let observed = drive_with(&handler, &frame_declaring(8, b"mint", b""), false).await;
    assert!(observed.is_empty());

    let event = logs.refusal();
    assert_eq!(event.field("reason"), "partial-frame");
    assert_eq!(event.field("operation"), "mint");
}

/// The response deadline is the third cumulative budget, and it is
/// post-verb: a caller that stops reading cannot hold a connection open
/// past it, and what ends the connection is a diagnostic rather than a
/// refusal — the verb already ran, so there is nothing left to refuse.
#[tokio::test(start_paused = true)]
async fn the_response_deadline_closes_the_connection_without_a_refusal() {
    let (logs, _guard) = capture_logs();
    // A duplex far smaller than the response, with nothing draining it,
    // is a caller that stopped reading: `write_all` cannot finish and
    // only the deadline ends it.
    let (mut client, mut server) = tokio::io::duplex(64);
    let handler = EchoHandler {
        response: vec![b'z'; 8 * 1024],
    };
    client
        .write_all(&frame_of(b"mint", b""))
        .await
        .expect("the duplex accepts the request");

    let started = Instant::now();
    serve_request(
        &mut server,
        &ConnectionId::next(),
        &caller_identity(current_effective_uid()),
        &handler,
        started,
    )
    .await;

    assert!(
        started.elapsed() >= super::RESPONSE_WRITE_TIMEOUT,
        "the write must be given its whole budget before it is abandoned"
    );
    assert!(
        logs.events()
            .iter()
            .all(|event| !event.message.starts_with("Registrar endpoint refused")),
        "an abandoned response is not a pre-verb refusal: {:?}",
        logs.events()
    );
    assert!(
        logs.events()
            .iter()
            .any(|event| event.message.contains("within the write timeout")),
        "the abandoned write must be logged: {:?}",
        logs.events()
    );
}

// ---------------------------------------------------------------------
// The drain contract
// ---------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn drain_joins_connections_that_finish_in_time() {
    let mut set: JoinSet<()> = JoinSet::new();
    for _ in 0..4 {
        set.spawn(async { tokio::time::sleep(StdDuration::from_secs(1)).await });
    }
    serve::drain(set).await;
}

/// A connection that outlasts the drain window is aborted and joined —
/// the set is never merely dropped, which would leave the stop
/// unobserved.
#[tokio::test(start_paused = true)]
async fn drain_aborts_connections_that_outlast_the_window() {
    let started = Instant::now();
    let mut set: JoinSet<()> = JoinSet::new();
    set.spawn(async { std::future::pending::<()>().await });
    serve::drain(set).await;
    assert!(
        started.elapsed() >= CONNECTION_DRAIN_TIMEOUT,
        "the drain window must be honoured before the abort"
    );
}

// ---------------------------------------------------------------------
// The socket tier: a harness-bound listener through the production seam
// ---------------------------------------------------------------------

/// A listener bound by the harness and adopted through the production
/// activation seam.
struct Harness {
    _dir: TempDir,
    socket_path: PathBuf,
    endpoint: Arc<ActivatedEndpoint>,
}

impl Harness {
    /// Binds a conforming listener under `tempfile::tempdir()` and hands
    /// its descriptor to [`super::adopt`].
    ///
    /// The bind, the `chmod` and the tempdir are all the harness's.
    /// Nothing under test creates, unlinks or re-permissions a socket.
    fn bind(handler: Arc<dyn RegistrarRequestHandler>) -> anyhow::Result<Self> {
        let dir = conforming_tempdir()?;
        let socket_path = dir.path().join("registrar.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
        std::fs::set_permissions(
            &socket_path,
            std::fs::Permissions::from_mode(REQUIRED_SOCKET_MODE),
        )?;
        let endpoint = super::adopt(
            activation_descriptor(listener),
            current_effective_uid(),
            handler,
        )?;
        Ok(Self {
            _dir: dir,
            socket_path,
            endpoint,
        })
    }

    fn inode(&self) -> u64 {
        std::fs::metadata(&self.socket_path)
            .expect("the activated socket is on the filesystem")
            .ino()
    }
}

/// Runs one accept loop until the returned sender is told to stop, and
/// joins it.
struct RunningEndpoint {
    shutdown: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl RunningEndpoint {
    fn start(endpoint: &Arc<ActivatedEndpoint>) -> Self {
        let (shutdown, receiver) = watch::channel(false);
        let endpoint = Arc::clone(endpoint);
        let handle = tokio::spawn(async move { serve::run(endpoint, receiver).await });
        Self { shutdown, handle }
    }

    async fn stop(self) {
        let _ = self.shutdown.send(true);
        self.handle
            .await
            .expect("the accept task must join")
            .expect("the accept task must not fail");
    }
}

/// Sends one framed request and reads everything the endpoint writes.
async fn round_trip(socket_path: &Path, request: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .expect("the activated socket accepts a connection");
    stream.write_all(request).await.expect("write the request");
    read_until_closed(&mut stream).await
}

/// Reads everything a peer writes before it closes.
///
/// A refusal that closes without reading the request the caller already
/// sent leaves unread bytes in the receive queue, and the kernel answers
/// a close in that state with an `RST` rather than a `FIN`. That is the
/// caller observing "closed with nothing written" through the one
/// mechanism the kernel has for it, so a reset is folded in here rather
/// than being a distinct outcome a test has to know about.
async fn read_until_closed(stream: &mut UnixStream) -> Vec<u8> {
    let mut observed = Vec::new();
    match stream.read_to_end(&mut observed).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(err) => panic!("reading the endpoint's answer: {err}"),
    }
    observed
}

/// Reads exactly one response frame: the four-byte length, then that
/// many bytes.
async fn read_response_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut prefix = [0u8; 4];
    stream
        .read_exact(&mut prefix)
        .await
        .expect("a response frame's length prefix");
    let declared = usize::try_from(u32::from_be_bytes(prefix)).expect("a test response fits usize");
    let mut body = vec![0u8; declared];
    stream
        .read_exact(&mut body)
        .await
        .expect("a response frame's body");
    body
}

/// The harness hands its listener over with `FD_CLOEXEC` cleared, as
/// `systemd` does, so what is asserted here is that
/// [`super::activation::set_cloexec`] put it back before the descriptor
/// was retained.
#[tokio::test]
async fn the_adopted_descriptor_is_close_on_exec_before_it_is_served() {
    let harness = Harness::bind(Arc::new(EchoHandler {
        response: Vec::new(),
    }))
    .expect("the harness listener must be adoptable");
    let fd = std::os::fd::AsRawFd::as_raw_fd(harness.endpoint.listener());
    assert!(
        is_cloexec(fd).expect("F_GETFD"),
        "a hook child must not be able to inherit the listening socket"
    );
}

/// The flag is only worth having if it survives an `exec`, so the same
/// listener is held against a real child rather than against `F_GETFD`
/// alone.
///
/// The child is spawned exactly as `hooks::run_hook` spawns a post-renew
/// hook — `tokio::process::Command`, no descriptor handling of its own —
/// and asked whether the listening descriptor is still in its table
/// after the `exec`. `Command` closes nothing it did not open, so with
/// the flag unset the answer would be yes, and a post-renew hook could
/// accept on the registrar socket.
#[tokio::test]
async fn a_hook_child_cannot_inherit_the_adopted_descriptor() {
    let harness = Harness::bind(Arc::new(EchoHandler {
        response: Vec::new(),
    }))
    .expect("the harness listener must be adoptable");
    let fd = std::os::fd::AsRawFd::as_raw_fd(harness.endpoint.listener());

    let status = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("test -e /proc/self/fd/{fd}"))
        .status()
        .await
        .expect("a hook child must be spawnable");
    assert!(
        !status.success(),
        "fd {fd} survived the exec into a hook child, which could then accept on the registrar \
         socket"
    );

    // The negative control: an fd without the flag *is* inherited, so
    // the assertion above is about `FD_CLOEXEC` and not about `/proc`
    // being unreadable or `sh` being missing.
    let (inheritable, _peer) = std::os::unix::net::UnixStream::pair().expect("socketpair");
    let inheritable_fd = std::os::fd::AsRawFd::as_raw_fd(&inheritable);
    clear_cloexec(inheritable_fd);
    let status = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("test -e /proc/self/fd/{inheritable_fd}"))
        .status()
        .await
        .expect("a hook child must be spawnable");
    assert!(
        status.success(),
        "a descriptor without FD_CLOEXEC must be inherited, or the test above proves nothing"
    );
}

#[tokio::test]
async fn adoption_rejects_a_socket_whose_mode_is_not_0700() {
    let dir = conforming_tempdir().expect("tempdir");
    let socket_path = dir.path().join("registrar.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket_path).expect("bind");
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let contract = activation_descriptor(listener);
    let error = super::adopt(
        contract,
        current_effective_uid(),
        Arc::new(EchoHandler {
            response: Vec::new(),
        }),
    )
    .expect_err("a 0755 socket must be refused");
    assert!(
        error.to_string().contains("0755") || format!("{error:#}").contains("0755"),
        "the refusal must name the mode it found: {error:#}"
    );
}

#[tokio::test]
async fn adoption_rejects_a_socket_owned_by_another_account() {
    let harness_dir = conforming_tempdir().expect("tempdir");
    let socket_path = harness_dir.path().join("registrar.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket_path).expect("bind");
    std::fs::set_permissions(
        &socket_path,
        std::fs::Permissions::from_mode(REQUIRED_SOCKET_MODE),
    )
    .expect("chmod");
    let contract = activation_descriptor(listener);
    // The socket belongs to this account, so claiming to be another one
    // is the same refusal a socket owned by somebody else produces.
    let error = super::adopt(
        contract,
        current_effective_uid().wrapping_add(1),
        Arc::new(EchoHandler {
            response: Vec::new(),
        }),
    )
    .expect_err("a socket owned by another account must be refused");
    assert!(
        format!("{error:#}").contains("owned by uid"),
        "the refusal must name the ownership mismatch: {error:#}"
    );
}

#[tokio::test]
async fn adoption_rejects_a_descriptor_that_is_not_a_listening_unix_stream() {
    // A connected pair: AF_UNIX and SOCK_STREAM, but not listening.
    let (connected, _peer) = std::os::unix::net::UnixStream::pair().expect("socketpair");
    let contract = ActivationContract::from_test_descriptor(
        std::os::unix::io::IntoRawFd::into_raw_fd(connected),
    );
    let error = super::adopt(
        contract,
        current_effective_uid(),
        Arc::new(EchoHandler {
            response: Vec::new(),
        }),
    )
    .expect_err("a connected socket must be refused");
    assert!(
        format!("{error:#}").contains("listening"),
        "the refusal must name the listening state: {error:#}"
    );
}

/// An abstract-namespace listener has no filesystem presence, so no mode
/// or owner can be checked on it. The other three non-pathname kinds are
/// covered by [`classify_unix_address`], which is where they are
/// reachable without conjuring a socket into that state.
#[tokio::test]
async fn adoption_rejects_a_non_pathname_address() {
    use std::os::linux::net::SocketAddrExt as _;

    let name = format!("bootroot-endpoint-test-{}", std::process::id());
    let listener = std::os::unix::net::UnixListener::bind_addr(
        &std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())
            .expect("an abstract name"),
    )
    .expect("bind an abstract listener");
    let contract = activation_descriptor(listener);
    let error = super::adopt(
        contract,
        current_effective_uid(),
        Arc::new(EchoHandler {
            response: Vec::new(),
        }),
    )
    .expect_err("an abstract-namespace socket must be refused");
    assert!(
        format!("{error:#}").contains("pathname"),
        "the refusal must say a pathname is required: {error:#}"
    );
}

#[tokio::test]
async fn one_connection_serves_exactly_one_request() {
    let harness = Harness::bind(Arc::new(EchoHandler {
        response: b"one".to_vec(),
    }))
    .expect("harness");
    let running = RunningEndpoint::start(&harness.endpoint);

    let mut stream = UnixStream::connect(&harness.socket_path)
        .await
        .expect("connect");
    stream
        .write_all(&frame_of(b"mint", b""))
        .await
        .expect("first request");
    let first = read_response_frame(&mut stream).await;
    assert!(String::from_utf8_lossy(&first).starts_with("mint|"));

    // A second request on the same connection. The endpoint has already
    // answered and closed, so nothing reads it and nothing answers it.
    let _ = stream.write_all(&frame_of(b"mint", b"")).await;
    let second = read_until_closed(&mut stream).await;
    assert!(
        second.is_empty(),
        "one connection carries exactly one request: {second:?}"
    );
    running.stop().await;
}

/// The listener is held across a reload, so the next invocation resumes
/// accepting on the very same socket inode.
#[tokio::test]
async fn the_listener_survives_a_reload_with_its_inode_unchanged() {
    let harness = Harness::bind(Arc::new(EchoHandler {
        response: b"served".to_vec(),
    }))
    .expect("harness");
    let inode_before = harness.inode();

    let first = RunningEndpoint::start(&harness.endpoint);
    let observed = round_trip(&harness.socket_path, &frame_of(b"mint", b"")).await;
    assert!(!observed.is_empty(), "the first invocation must answer");
    first.stop().await;

    // The reload: a new invocation over the retained listener.
    let second = RunningEndpoint::start(&harness.endpoint);
    let observed = round_trip(&harness.socket_path, &frame_of(b"deregister", b"")).await;
    let body = decode_response(&observed);
    assert!(
        String::from_utf8_lossy(&body).starts_with("deregister|"),
        "the second invocation must answer on the same socket"
    );
    second.stop().await;

    assert_eq!(
        harness.inode(),
        inode_before,
        "a reload must not replace the socket inode"
    );
}

/// How many connections beyond the bound the over-capacity test offers.
///
/// Several times the bound, because one proves only that the refusal
/// happens: what is at stake is that an over-capacity peer cannot make
/// the daemon *accumulate* anything, so the interesting question is
/// whether the fifty-first attempt costs any more than the first.
const OVER_CAPACITY_ATTEMPTS: usize = 3 * MAX_CONCURRENT_CONNECTIONS;

/// Capacity bounds the daemon, not merely the handlers.
///
/// The permit is taken on the accept loop's own task, before anything is
/// spawned, so a connection that cannot have one is refused there and
/// then. What a test can observe of that is what this asserts: any
/// number of over-capacity connections are closed with zero bytes, none
/// of them consumes a permit — the endpoint serves normally the moment
/// the held ones let go — and the accept loop is still accepting
/// throughout rather than having been buried under refusal work.
#[tokio::test]
async fn the_endpoint_refuses_every_connection_over_capacity_without_accumulating() {
    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
    let release = Arc::new(Semaphore::new(0));
    let harness = Harness::bind(Arc::new(BlockingHandler {
        entered: entered_tx,
        release: Arc::clone(&release),
    }))
    .expect("harness");
    let running = RunningEndpoint::start(&harness.endpoint);

    // Fill every permit, and wait until each connection is inside the
    // handler so the permits are certainly held.
    let mut held = Vec::new();
    for _ in 0..MAX_CONCURRENT_CONNECTIONS {
        let mut stream = UnixStream::connect(&harness.socket_path)
            .await
            .expect("connect");
        stream
            .write_all(&frame_of(b"mint", b""))
            .await
            .expect("request");
        held.push(stream);
        entered_rx.recv().await.expect("the handler was entered");
    }

    for attempt in 0..OVER_CAPACITY_ATTEMPTS {
        let observed = round_trip(&harness.socket_path, &frame_of(b"mint", b"")).await;
        assert!(
            observed.is_empty(),
            "over-capacity connection {attempt} must be closed with no bytes: {observed:?}"
        );
    }

    // Nothing above took a permit, so releasing the held connections is
    // enough for the next caller to be served.
    release.add_permits(MAX_CONCURRENT_CONNECTIONS);
    for mut stream in held.drain(..) {
        let answered = read_until_closed(&mut stream).await;
        assert!(
            !answered.is_empty(),
            "a connection that held a permit must still be answered"
        );
    }
    release.add_permits(1);
    let observed = round_trip(&harness.socket_path, &frame_of(b"mint", b"")).await;
    assert!(
        !observed.is_empty(),
        "the endpoint must serve again once capacity is free: {observed:?}"
    );

    running.stop().await;
}

/// The header deadline runs from acceptance, and it runs at the
/// listener rather than only inside [`serve_request`].
///
/// A peer that connects and then says nothing is given
/// [`HEADER_IDLE_TIMEOUT`] from the instant the accept loop took it, and
/// is then refused as a missing header: zero bytes, a clean close. The
/// timestamp the deadline is measured from is stamped in the accept
/// branch, so a connection whose task is scheduled late is not thereby
/// given a longer budget than the contract states.
#[tokio::test(start_paused = true)]
async fn a_silent_connection_is_refused_once_its_header_budget_is_spent() {
    let (logs, _guard) = capture_logs();
    let harness = Harness::bind(Arc::new(EchoHandler {
        response: b"served".to_vec(),
    }))
    .expect("harness");
    let running = RunningEndpoint::start(&harness.endpoint);

    let started = Instant::now();
    let mut stream = UnixStream::connect(&harness.socket_path)
        .await
        .expect("connect");
    let observed = read_until_closed(&mut stream).await;
    assert!(
        observed.is_empty(),
        "a refused connection writes no bytes: {observed:?}"
    );
    assert!(
        started.elapsed() >= HEADER_IDLE_TIMEOUT,
        "the connection must be given its whole header budget"
    );

    let event = logs.refusal();
    assert_eq!(event.field("reason"), "no-header");
    assert_eq!(event.field("operation"), UNREAD_OPERATION);

    running.stop().await;
}

/// Shutdown stops accepting and joins every task, and the accept loop
/// reports success rather than being torn down under it.
#[tokio::test]
async fn shutdown_stops_accepting_and_joins_every_task() {
    let harness = Harness::bind(Arc::new(EchoHandler {
        response: b"served".to_vec(),
    }))
    .expect("harness");
    let running = RunningEndpoint::start(&harness.endpoint);
    let observed = round_trip(&harness.socket_path, &frame_of(b"mint", b"")).await;
    assert!(!observed.is_empty());
    running.stop().await;

    // The listener is still open — it belongs to the handle, not to the
    // invocation — so a connect succeeds and is simply never served.
    let mut stream = UnixStream::connect(&harness.socket_path)
        .await
        .expect("the retained listener still holds the pathname");
    let _ = stream.write_all(&frame_of(b"mint", b"")).await;
}

// ---------------------------------------------------------------------
// The `cfg(test)` handler over the real verbs
// ---------------------------------------------------------------------

/// Both operation arms reach the real in-process verbs, carrying the
/// transport-authenticated identity unchanged, and neither touches
/// `OpenBao`.
#[tokio::test]
async fn both_operation_arms_reach_the_real_verbs_with_the_transport_identity() {
    let server = MockServer::start().await;
    let (_config_dir, handler) = verb_handler(&server);
    let harness = Harness::bind(handler).expect("harness");
    let running = RunningEndpoint::start(&harness.endpoint);
    let expected_caller = format!("unix-peer:uid={}", current_effective_uid());

    for operation in [b"mint".as_slice(), b"deregister".as_slice()] {
        let payload = format!("{UNCONFIGURED_COMPONENT}|h1|");
        let observed = round_trip(
            &harness.socket_path,
            &frame_of(operation, payload.as_bytes()),
        )
        .await;
        let body = String::from_utf8(decode_response(&observed)).expect("utf-8");
        let expected_prefix = format!(
            "{}|refused:PreDerivation|",
            String::from_utf8_lossy(operation)
        );
        assert!(
            body.starts_with(&expected_prefix),
            "{operation:?} must reach the verb and be refused there: {body}"
        );
        assert!(
            body.ends_with(&expected_caller),
            "the verb must see the transport identity verbatim: {body}"
        );
    }

    running.stop().await;
    assert!(
        server
            .received_requests()
            .await
            .expect("the mock records requests")
            .is_empty(),
        "a pre-derivation refusal must reach OpenBao not at all"
    );
}

#[tokio::test]
async fn the_verb_handler_accepts_a_zero_length_payload() {
    let server = MockServer::start().await;
    let (_config_dir, handler) = verb_handler(&server);
    let harness = Harness::bind(handler).expect("harness");
    let running = RunningEndpoint::start(&harness.endpoint);

    let observed = round_trip(&harness.socket_path, &frame_of(b"mint", b"")).await;
    assert_eq!(decode_response(&observed), b"empty");

    running.stop().await;
}

/// A payload the handler cannot make sense of is a [`HandlerRefusal`],
/// which is a zero-byte clean close and not an eighth transport reason.
#[tokio::test]
async fn a_payload_the_handler_rejects_closes_with_no_bytes() {
    let server = MockServer::start().await;
    let (_config_dir, handler) = verb_handler(&server);
    let harness = Harness::bind(handler).expect("harness");
    let running = RunningEndpoint::start(&harness.endpoint);

    let observed = round_trip(&harness.socket_path, &frame_of(b"mint", b"not-the-shape")).await;
    assert!(observed.is_empty(), "{observed:?}");

    running.stop().await;
}

// ---------------------------------------------------------------------
// Production wiring
// ---------------------------------------------------------------------

/// A disabled endpoint reads nothing and yields nothing. It cannot
/// consult an activation variable, because it returns before either is
/// read.
#[test]
fn a_disabled_endpoint_activates_to_nothing() {
    let activated = super::activate(false).expect("a disabled endpoint never fails");
    assert!(activated.is_none());
}

/// There is no production handler, so an enabled endpoint refuses to
/// start — and it refuses on the handler, before any activation
/// variable is looked at, so the diagnostic is about the missing handler
/// rather than about a descriptor that was never going to be used.
#[test]
fn an_enabled_endpoint_without_a_handler_refuses_startup() {
    let error = super::activate(true).expect_err("there is no production handler");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("no registrar request handler is registered"),
        "the refusal must name the missing handler: {rendered}"
    );
    assert!(
        rendered.contains("unsupported"),
        "the refusal must say enabling the endpoint is unsupported: {rendered}"
    );
    assert!(
        !rendered.contains("LISTEN_PID") && !rendered.contains("LISTEN_FDS"),
        "the handler check must come before the activation contract: {rendered}"
    );
}

/// The two halves an unprivileged start produces: the consequence-focused
/// warning first, then the refusal for the missing handler.
#[test]
fn a_non_root_enabled_start_warns_and_then_refuses() {
    let (logs, _guard) = capture_logs();
    let error = super::activate(true).expect_err("there is no production handler");
    assert!(format!("{error:#}").contains("no registrar request handler is registered"));

    let warned = logs
        .events()
        .iter()
        .any(|event| event.message.contains(UNPRIVILEGED_DAEMON_WARNING));
    assert_eq!(
        warned,
        warns_about_unprivileged_daemon(true, current_effective_uid()),
        "the warning must fire exactly when the pure decision says it should"
    );
}
