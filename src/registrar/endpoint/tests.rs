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
//!
//! The certificate material the last two tiers rest on, and the
//! `tracing` capture the stream tier reads its diagnostics back out of,
//! live in [`super::test_support`] rather than here. They are shared
//! with the client's tests, so that neither module grows a second
//! `rcgen` CA builder or a second capturing subscriber and keeps passing
//! against material — or against a capture — the other no longer
//! produces.

use std::future::Future;
use std::os::fd::RawFd;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration as StdDuration;

use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tempfile::TempDir;
use time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
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
use super::test_support::{
    CapturedEvent, CapturedLogs, DIAL_NAME, NEAR_MISS_DOMAIN, Pki, TEST_DOMAIN, TEST_HOST,
    TEST_INSTANCE, capture_logs, client_config_pinning, client_material_from, dns_san,
    endpoint_name, generate_ca, registrar_client_name, valid_ca,
};
use super::tls::{
    CA_BUNDLE_SETTING, EndpointCertResolver, EndpointTlsError, SERVER_CERT_SETTING,
    SERVER_KEY_SETTING, TRUSTED_CA_SETTING, build_server_config,
};
use super::{
    ActivatedEndpoint, CONNECTION_DRAIN_TIMEOUT, HANDSHAKE_TIMEOUT, HEADER_IDLE_TIMEOUT,
    HandshakeCompleted, MAX_CONCURRENT_CONNECTIONS, MAX_FRAME_PAYLOAD_BYTES,
    MAX_RESPONSE_PAYLOAD_BYTES, REQUIRED_SOCKET_MODE, UNPRIVILEGED_DAEMON_WARNING,
    current_effective_uid, warns_about_unprivileged_daemon,
};
use crate::openbao::{OpenBaoClient, SecretIdOptions};
use crate::registrar::audit::AuditRecordStore;
use crate::registrar::config::RegistrarConfig;
use crate::registrar::endpoint::production::ProductionHandler;
use crate::registrar::endpoint::protocol;
use crate::registrar::endpoint::refusing::RefusingHandler;
use crate::registrar::endpoint_pin::EndpointVerifyRejection;
use crate::registrar::fixture::RegistrarConfigFixture;
use crate::registrar::identity::RequestedSpec;
use crate::registrar::internal::InternalCredential;
use crate::registrar::verbs::limiter::{
    CountingLimitedInvocationSink, LimiterBucket, NoopLimitedInvocationSink, VerbRateLimiter,
    VerbRateLimiterSettings,
};
use crate::registrar::verbs::outcome::CallerIdentity;
use crate::registrar::verbs::wrap_ttl::WrapTtlPolicy;
use crate::registrar::verbs::{
    DeregisterRequest, MintRequest, RegistrarVerbs, RegistrarVerbsConfig,
};
use crate::registrar::{RegistrarIdentityError, ReloadSpec, registrar_client_identity};

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

/// The caller of record is the certificate name, and carries no peer
/// credential at all.
#[test]
fn the_caller_identity_is_the_certificate_san_and_nothing_else() {
    let san = registrar_client_name();
    assert_eq!(
        caller_identity(&san).as_str(),
        format!("registrar-client:{san}")
    );
    // DNS names compare case-insensitively, so one name is one identity
    // however it was spelled on the wire.
    assert_eq!(
        caller_identity(&san.to_ascii_uppercase()),
        caller_identity(&san)
    );
    // And distinct between names.
    assert_ne!(
        caller_identity(&registrar_client_identity("002", TEST_HOST, TEST_DOMAIN)),
        caller_identity(&san)
    );
    // The uid-derived rendering is gone: nothing here can produce one.
    assert!(!caller_identity(&san).as_str().contains("unix-peer:"));
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
// The production handler over real verbs
// ---------------------------------------------------------------------

/// The mount the production-handler harness resolves for its verbs and
/// its anchor read. The daemon resolves it one level up and passes it
/// down; nothing in this layer knows where it was recorded.
const HARNESS_KV_MOUNT: &str = "secret";

/// Builds the **production** handler over **real** verbs pointed at a
/// `wiremock::MockServer`, with a real internal credential over the same
/// server.
///
/// No trait double, no injection slot and no `#[cfg(test)]` branch in
/// the production type: the seam is the handler's constructor taking
/// built dependencies, which is production's own construction path.
/// What differs from the daemon's build is only where the two clients
/// come from — `RegistrarVerbs::new` and `InternalCredential::for_test`
/// rather than the credential on disk.
fn production_handler(
    server: &MockServer,
) -> (TempDir, AuditRecordStore, Arc<dyn RegistrarRequestHandler>) {
    production_handler_with_limiter(
        server,
        VerbRateLimiter::new(
            VerbRateLimiterSettings::default(),
            Arc::new(NoopLimitedInvocationSink),
        ),
        Arc::new(StdMutex::new(protocol::RegistrarHealth::default())),
    )
}

/// Builds the production handler with the supplied limiter and shared health
/// snapshot, so a test can observe daemon-maintained endpoint health.
fn production_handler_with_limiter(
    server: &MockServer,
    limiter: VerbRateLimiter,
    health: Arc<StdMutex<protocol::RegistrarHealth>>,
) -> (TempDir, AuditRecordStore, Arc<dyn RegistrarRequestHandler>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = RegistrarConfigFixture::new()
        .write_to(dir.path())
        .expect("write the rendered registrar config");
    let config = RegistrarConfig::load(&path).expect("the fixture must load");
    let mut client = OpenBaoClient::new(&server.uri()).expect("client");
    client.set_token("test-token".to_string());
    let audit_store = AuditRecordStore::open_temporary().expect("a temporary audit store");
    let verbs = RegistrarVerbs::new(RegistrarVerbsConfig {
        client,
        kv_mount: HARNESS_KV_MOUNT.to_string(),
        config,
        secret_id_options: SecretIdOptions {
            num_uses: Some(0),
            ..Default::default()
        },
        token_ttl: "3600s".to_string(),
        secret_id_ttl: "86400s".to_string(),
        wrap_ttl_policy: WrapTtlPolicy::new(Duration::minutes(30)).expect("policy maximum"),
        audit_store: audit_store.clone(),
        limiter,
    });

    let secrets_dir = dir.path().join("secrets");
    let fingerprint = write_harness_root(&secrets_dir);
    let credential = InternalCredential::for_test(&server.uri(), &secrets_dir, &fingerprint)
        .expect("the harness credential");

    (
        dir,
        audit_store,
        Arc::new(ProductionHandler::with_health(
            verbs,
            credential,
            HARNESS_KV_MOUNT.to_string(),
            health,
        )),
    )
}

/// The audit trail one invocation wrote, which is where the caller
/// identity the verbs were handed is observable.
fn audit_trail(store: &AuditRecordStore) -> Vec<serde_json::Value> {
    let path = store.active_path();
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => panic!("read {}: {err}", path.display()),
    };
    contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("every trail line parses"))
        .collect()
}

/// Writes the one deployment-root certificate the credential re-reads
/// before every acquisition, and returns its fingerprint.
fn write_harness_root(secrets_dir: &Path) -> String {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

    let key = KeyPair::generate().expect("generate the root key");
    let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
    params
        .distinguished_name
        .push(DnType::CommonName, "Bootroot Endpoint Test Root");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key).expect("self-signed root");
    let path = crate::registrar::internal::active_root_cert_path(secrets_dir);
    std::fs::create_dir_all(path.parent().expect("the certs directory")).expect("mkdir certs");
    std::fs::write(&path, cert.pem()).expect("write the root certificate");
    crate::tls::sha256_hex(cert.der().as_ref())
}

/// Builds one register payload at the endpoint's v1 protocol.
fn register_payload(service_name: &str, host: &str, idempotency_key: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "protocol_version": 1,
        "service_name": service_name,
        "delivery_mode": "RemoteBootstrap",
        "host": host,
        "spec": {
            "component": service_name,
            "service_name": service_name,
            "reload": "any-form-at-all",
        },
        "wrap_ttl": 300,
        "idempotency_key": idempotency_key,
    }))
    .expect("the payload encodes")
}

/// Builds one deregister payload at the endpoint's v1 protocol.
fn deregister_payload(service_name: &str, host: &str, idempotency_key: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "protocol_version": 1,
        "service_name": service_name,
        "host": host,
        "idempotency_key": idempotency_key,
    }))
    .expect("the payload encodes")
}

/// Reads the health snapshot from any serialized registrar response shape.
fn response_health(response: &[u8]) -> protocol::RegistrarHealth {
    let value: serde_json::Value =
        serde_json::from_slice(response).expect("the production response is JSON");
    serde_json::from_value(
        value
            .get("registrar_health")
            .expect("every response carries registrar health")
            .clone(),
    )
    .expect("registrar health has the documented shape")
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
        &caller_identity(&registrar_client_name()),
        handler,
        HandshakeCompleted::now(),
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
        format!("mint|7|registrar-client:{}|body", registrar_client_name())
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
        format!(
            "deregister|0|registrar-client:{}|ok",
            registrar_client_name()
        )
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

/// The header deadline is cumulative from handshake completion — the
/// instant `serve_request` is handed here, and the instant the serving
/// path stamps after its handshake: a caller that holds the connection
/// open without sending a byte is refused as no-header when it expires.
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
        &caller_identity(&registrar_client_name()),
        &handler,
        HandshakeCompleted::now(),
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

/// Opens one TLS connection to the endpoint, or reports why the
/// handshake did not complete.
async fn tls_connect(
    socket_path: &Path,
    config: ClientConfig,
) -> std::io::Result<tokio_rustls::client::TlsStream<UnixStream>> {
    let stream = UnixStream::connect(socket_path).await?;
    TlsConnector::from(Arc::new(config))
        .connect(
            ServerName::try_from(DIAL_NAME).expect("a valid dial name"),
            stream,
        )
        .await
}

/// Sends one framed request over TLS and reads everything the endpoint
/// writes before it closes.
async fn tls_round_trip(socket_path: &Path, config: ClientConfig, request: &[u8]) -> Vec<u8> {
    let mut stream = tls_connect(socket_path, config)
        .await
        .expect("the endpoint completes a handshake with the registrar client");
    stream.write_all(request).await.expect("write the request");
    read_tls_until_closed(&mut stream).await
}

/// Runs a whole exchange and returns what the caller observed, or the
/// first error it saw.
///
/// In TLS 1.3 the client's handshake finishes when it has sent its own
/// `Finished` — *before* the server has validated the client
/// certificate — so a rejected client learns of the rejection from its
/// next read rather than from `connect`. Anything that asserts a client
/// certificate was refused therefore has to drive the exchange, not the
/// connect.
async fn tls_exchange(
    socket_path: &Path,
    config: ClientConfig,
    request: &[u8],
) -> std::io::Result<Vec<u8>> {
    let mut stream = tls_connect(socket_path, config).await?;
    stream.write_all(request).await?;
    stream.flush().await?;
    let mut observed = Vec::new();
    stream.read_to_end(&mut observed).await?;
    Ok(observed)
}

/// Reads to the end of an application stream, asserting the end is an
/// orderly one.
///
/// This is where "zero application bytes, then a clean close" is
/// asserted rather than assumed: `rustls` reports a peer that vanished
/// without `close_notify` as [`std::io::ErrorKind::UnexpectedEof`], so a
/// truncation, a reset or a broken pipe fails here instead of being
/// folded into an empty answer.
async fn read_tls_until_closed<S>(stream: &mut S) -> Vec<u8>
where
    S: AsyncRead + Unpin,
{
    let mut observed = Vec::new();
    stream
        .read_to_end(&mut observed)
        .await
        .expect("the endpoint must end the stream cleanly");
    observed
}

// ---------------------------------------------------------------------
// The socket tier: a harness-bound listener through the production seam
// ---------------------------------------------------------------------

/// A listener bound by the harness and adopted through the production
/// activation seam, serving mTLS over material the harness generated.
struct Harness {
    _dir: TempDir,
    pki: Pki,
    socket_path: PathBuf,
    endpoint: Arc<ActivatedEndpoint>,
}

impl Harness {
    /// Binds a conforming listener under `tempfile::tempdir()`, over a
    /// conforming deployment PKI, and hands the descriptor and the built
    /// configuration to [`super::adopt`].
    ///
    /// The bind, the `chmod`, the certificate material and the tempdirs
    /// are all the harness's. Nothing under test creates, unlinks or
    /// re-permissions a socket, and nothing under `adopt` reads a
    /// certificate file: the configuration arrives as a value.
    fn bind() -> anyhow::Result<Self> {
        Self::bind_over(Pki::new())
    }

    fn bind_over(pki: Pki) -> anyhow::Result<Self> {
        let (config, resolver) = pki.conforming();
        Self::bind_with(pki, config, resolver)
    }

    fn bind_with(
        pki: Pki,
        config: Arc<rustls::ServerConfig>,
        resolver: Arc<EndpointCertResolver>,
    ) -> anyhow::Result<Self> {
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
            config,
            resolver,
            TEST_DOMAIN.to_string(),
        )?;
        Ok(Self {
            _dir: dir,
            pki,
            socket_path,
            endpoint,
        })
    }

    /// Sends one framed request as the registrar client and returns
    /// everything the endpoint wrote before it closed.
    async fn round_trip(&self, request: &[u8]) -> Vec<u8> {
        tls_round_trip(
            &self.socket_path,
            self.pki.registrar_client_config(),
            request,
        )
        .await
    }

    fn inode(&self) -> u64 {
        std::fs::metadata(&self.socket_path)
            .expect("the activated socket is on the filesystem")
            .ino()
    }
}

/// Adopts a harness-bound listener over a throwaway conforming PKI, for
/// the adoption tests that are about the descriptor rather than the
/// material.
///
/// The material is read before this returns, so the PKI's temporary
/// directory going away with it changes nothing.
fn adopt_for_test(
    contract: ActivationContract,
    effective_uid: u32,
) -> anyhow::Result<Arc<ActivatedEndpoint>> {
    let pki = Pki::new();
    let (config, resolver) = pki.conforming();
    super::adopt(
        contract,
        effective_uid,
        config,
        resolver,
        TEST_DOMAIN.to_string(),
    )
}

/// Runs one accept loop until the returned sender is told to stop, and
/// joins it.
struct RunningEndpoint {
    shutdown: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl RunningEndpoint {
    fn start(endpoint: &Arc<ActivatedEndpoint>, handler: Arc<dyn RegistrarRequestHandler>) -> Self {
        let (shutdown, receiver) = watch::channel(false);
        let endpoint = Arc::clone(endpoint);
        let handle = tokio::spawn(async move { serve::run(endpoint, handler, receiver).await });
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
async fn read_response_frame<S>(stream: &mut S) -> Vec<u8>
where
    S: AsyncRead + Unpin,
{
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
    let harness = Harness::bind().expect("the harness listener must be adoptable");
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
    let harness = Harness::bind().expect("the harness listener must be adoptable");
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
    let error = adopt_for_test(contract, current_effective_uid())
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
    let error = adopt_for_test(contract, current_effective_uid().wrapping_add(1))
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
    let error = adopt_for_test(contract, current_effective_uid())
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
    let error = adopt_for_test(contract, current_effective_uid())
        .expect_err("an abstract-namespace socket must be refused");
    assert!(
        format!("{error:#}").contains("pathname"),
        "the refusal must say a pathname is required: {error:#}"
    );
}

#[tokio::test]
async fn one_connection_serves_exactly_one_request() {
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(
        &harness.endpoint,
        Arc::new(EchoHandler {
            response: b"one".to_vec(),
        }),
    );

    let mut stream = tls_connect(&harness.socket_path, harness.pki.registrar_client_config())
        .await
        .expect("handshake");
    stream
        .write_all(&frame_of(b"mint", b""))
        .await
        .expect("first request");
    let first = read_response_frame(&mut stream).await;
    assert!(String::from_utf8_lossy(&first).starts_with("mint|"));

    // A second request on the same connection. The endpoint has already
    // answered and closed, so nothing reads it and nothing answers it.
    let _ = stream.write_all(&frame_of(b"mint", b"")).await;
    let second = read_tls_until_closed(&mut stream).await;
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
    let harness = Harness::bind().expect("harness");
    let inode_before = harness.inode();

    // Each invocation builds its own handler: the endpoint carries none,
    // so a reload cannot be a handler swap under a live accept loop.
    let first = RunningEndpoint::start(
        &harness.endpoint,
        Arc::new(EchoHandler {
            response: b"served".to_vec(),
        }),
    );
    let observed = harness.round_trip(&frame_of(b"mint", b"")).await;
    assert!(!observed.is_empty(), "the first invocation must answer");
    first.stop().await;

    // The reload: a new invocation over the retained listener, with a
    // freshly built handler of its own.
    let second = RunningEndpoint::start(
        &harness.endpoint,
        Arc::new(EchoHandler {
            response: b"reloaded".to_vec(),
        }),
    );
    let observed = harness.round_trip(&frame_of(b"deregister", b"")).await;
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
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(
        &harness.endpoint,
        Arc::new(BlockingHandler {
            entered: entered_tx,
            release: Arc::clone(&release),
        }),
    );

    // Fill every permit, and wait until each connection is inside the
    // handler so the permits are certainly held.
    let mut held = Vec::new();
    for _ in 0..MAX_CONCURRENT_CONNECTIONS {
        let mut stream = tls_connect(&harness.socket_path, harness.pki.registrar_client_config())
            .await
            .expect("handshake");
        stream
            .write_all(&frame_of(b"mint", b""))
            .await
            .expect("request");
        held.push(stream);
        entered_rx.recv().await.expect("the handler was entered");
    }

    // Capacity is refused *before* the handshake, on the accept loop's
    // own task, so an over-capacity caller does not even get a TLS
    // session — which is the point: it costs the daemon no handshake.
    for attempt in 0..OVER_CAPACITY_ATTEMPTS {
        let outcome =
            tls_connect(&harness.socket_path, harness.pki.registrar_client_config()).await;
        assert!(
            outcome.is_err(),
            "over-capacity connection {attempt} must be closed before a handshake completes"
        );
    }

    // Nothing above took a permit, so releasing the held connections is
    // enough for the next caller to be served.
    release.add_permits(MAX_CONCURRENT_CONNECTIONS);
    for mut stream in held.drain(..) {
        let answered = read_tls_until_closed(&mut stream).await;
        assert!(
            !answered.is_empty(),
            "a connection that held a permit must still be answered"
        );
    }
    release.add_permits(1);
    let observed = harness.round_trip(&frame_of(b"mint", b"")).await;
    assert!(
        !observed.is_empty(),
        "the endpoint must serve again once capacity is free: {observed:?}"
    );

    running.stop().await;
}

/// A peer that opens a connection and never sends a `ClientHello` is
/// dropped at [`HANDSHAKE_TIMEOUT`], which ends its task and releases
/// its capacity permit.
///
/// It has authenticated itself with nothing at this point, so the
/// alternative is one of sixteen connection slots held for as long as
/// the peer likes. Nothing is written and there is no application stream
/// to close: the only diagnosis is the daemon's log, which is why the
/// typed reason is asserted here rather than merely the closure.
#[tokio::test(start_paused = true)]
async fn a_connection_that_never_handshakes_is_dropped_at_the_handshake_timeout() {
    let (logs, _guard) = capture_logs();
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(
        &harness.endpoint,
        Arc::new(EchoHandler {
            response: b"served".to_vec(),
        }),
    );

    let started = Instant::now();
    let mut stream = UnixStream::connect(&harness.socket_path)
        .await
        .expect("connect");
    let observed = read_until_closed(&mut stream).await;
    assert!(
        observed.is_empty(),
        "a dropped connection writes no bytes: {observed:?}"
    );
    assert!(
        started.elapsed() >= HANDSHAKE_TIMEOUT,
        "the connection must be given its whole handshake budget"
    );
    assert_eq!(handshake_reason(&logs), "handshake-timeout");

    // The permit went back, so the endpoint still serves.
    let served = harness.round_trip(&frame_of(b"mint", b"")).await;
    assert!(!served.is_empty(), "{served:?}");

    running.stop().await;
}

/// The message the endpoint logs once a TLS handshake has completed.
///
/// It is the only signal a test has that the *server* is past the
/// handshake deadline and inside the header one: the client's own
/// handshake future resolves as soon as it has written its last flight,
/// which is before the server has read it.
const HANDSHAKE_COMPLETED_MESSAGE: &str = "Registrar endpoint completed a TLS handshake.";

/// How many scheduler turns [`await_log_message`] will spin for.
///
/// Only a bound on a hang: the connection task needs a handful of turns
/// to reach the event above, and the clock is running wherever this is
/// used, so an endpoint that never gets there fails with the message
/// below rather than blocking the suite forever.
const LOG_BARRIER_TURNS: usize = 100_000;

/// Yields until the endpoint has logged `message`.
///
/// Nothing sleeps and nothing waits on a timeout: the loop hands the
/// runtime back to the connection task until the event appears. It must
/// be called with the clock running, because what it waits for is
/// progress the endpoint makes under a live deadline.
async fn await_log_message(logs: &CapturedLogs, message: &str) {
    for _ in 0..LOG_BARRIER_TURNS {
        if logs.events().iter().any(|event| event.message == message) {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("the endpoint never logged {message:?}");
}

/// How many scheduler turns [`settle`] hands back before its caller
/// asserts that nothing has happened.
///
/// Far more than the refusal path needs — it logs before it closes, so
/// a handful of polls carry it from an elapsed deadline to a captured
/// event — and cheap enough that the margin costs nothing.
const SETTLE_TURNS: usize = 1_000;

/// Hands the runtime back until any work already in motion has run.
///
/// Callable only under a paused clock, and it is the caller's task that
/// stays ready throughout, so no timer can elapse while it spins: an
/// assertion after it reads a state the clock did not move on.
async fn settle() {
    for _ in 0..SETTLE_TURNS {
        tokio::task::yield_now().await;
    }
}

/// The margin the header-budget advances below carry, for the timer
/// wheel's millisecond granularity.
///
/// A deadline is rounded up to the next millisecond, so advancing by
/// exactly the budget can land short of it and leave the connection
/// open. One millisecond covers the whole of that rounding: it is held
/// back from the advance that must not reach the deadline, and added to
/// the one that must.
const TIMER_ROUNDING: StdDuration = StdDuration::from_millis(1);

/// A connection that *does* complete a handshake gets a whole
/// [`HEADER_IDLE_TIMEOUT`] measured from that completion, and is then
/// refused as a missing header rather than as a handshake that never
/// finished.
///
/// Everything up to and including the handshake runs under a live
/// clock, against the production deadlines: the endpoint has real
/// progress to make there, and pausing across it would let auto-advance
/// fire mid-flight, jump to the handshake deadline and refuse a
/// connection that was getting on with it. Only once the server has
/// logged the handshake — the client's future resolves earlier than
/// that — is the clock paused, and from there the header budget is
/// spent by moving it rather than by waiting.
///
/// The two advances bound that budget from both sides. What the test
/// cannot read is the endpoint's own stamp, so the first advance bounds
/// it instead: the stamp is taken after a handshake that had not begun
/// at `dialed_at`, so no more of the budget has gone at the pause than
/// has elapsed since then. Deducting that bound and the wheel's
/// rounding leaves an advance that cannot reach the deadline, however
/// long the handshake took, and the connection is still open after it.
/// The second carries the clock a millisecond past a whole
/// [`HEADER_IDLE_TIMEOUT`] from the pause, which is at or past the
/// deadline for the same reason — so a budget an order of magnitude too
/// generous would fail here rather than pass.
///
/// The origin itself is not what this test pins down: over a loopback
/// socket acceptance and handshake completion are microseconds apart,
/// and no advance can be aimed between deadlines that close together
/// without moving the clock before the handshake, which this test is
/// required not to do. That is [`HandshakeCompleted`]'s job in the
/// serving path, where measuring the header budget from acceptance is a
/// compile error.
#[tokio::test]
async fn a_completed_handshake_gets_the_whole_header_budget_from_that_completion() {
    let (logs, _guard) = capture_logs();
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(
        &harness.endpoint,
        Arc::new(EchoHandler {
            response: b"served".to_vec(),
        }),
    );

    // A real handshake through the production endpoint, under a running
    // clock and under the real handshake deadline.
    let dialed_at = Instant::now();
    let mut stream = tls_connect(&harness.socket_path, harness.pki.registrar_client_config())
        .await
        .expect("the registrar client completes a handshake");
    await_log_message(&logs, HANDSHAKE_COMPLETED_MESSAGE).await;

    // The handshake is behind the endpoint and the header deadline is
    // the only one armed, so the budget can be spent without waiting.
    tokio::time::pause();

    // How much of that budget has already gone is the endpoint's stamp
    // against this pause, and the test can read neither. It can bound
    // the difference: the stamp comes after a handshake that had not
    // begun at `dialed_at`.
    let spent_at_most = dialed_at.elapsed();
    let inside = HEADER_IDLE_TIMEOUT
        .checked_sub(spent_at_most + TIMER_ROUNDING)
        .expect("a loopback handshake completes far inside the header budget");
    tokio::time::advance(inside).await;
    settle().await;
    assert!(
        logs.refusals().is_empty(),
        "a completed handshake keeps its connection through {inside:?} of \
         a {HEADER_IDLE_TIMEOUT:?} header budget"
    );

    // The rest of that budget, and the wheel's rounding. Asserted before
    // the close is awaited, because this is the only point at which the
    // budget is bounded from above: the read below parks the runtime
    // under a paused clock, so auto-advance carries it to whatever the
    // next timer is, however far away that is, and reports it as
    // no-header just the same.
    let whole_budget = HEADER_IDLE_TIMEOUT + TIMER_ROUNDING;
    let rest = whole_budget
        .checked_sub(inside)
        .expect("the advance above is a whole budget less what preceded it");
    tokio::time::advance(rest).await;
    settle().await;
    assert_eq!(
        logs.refusals().len(),
        1,
        "the header deadline must end the connection inside the budget \
         advanced here"
    );

    let observed = read_tls_until_closed(&mut stream).await;
    assert!(
        observed.is_empty(),
        "a refused connection writes no bytes: {observed:?}"
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
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(
        &harness.endpoint,
        Arc::new(EchoHandler {
            response: b"served".to_vec(),
        }),
    );
    let observed = harness.round_trip(&frame_of(b"mint", b"")).await;
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
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(&harness.endpoint, handler);
    let expected_caller = format!("registrar-client:{}", registrar_client_name());

    for operation in [b"mint".as_slice(), b"deregister".as_slice()] {
        let payload = format!("{UNCONFIGURED_COMPONENT}|h1|");
        let observed = harness
            .round_trip(&frame_of(operation, payload.as_bytes()))
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
            "the verb must see the authenticated identity verbatim: {body}"
        );
        assert!(
            !body.contains("unix-peer:"),
            "no peer-credential value may reach a verb: {body}"
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
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(&harness.endpoint, handler);

    let observed = harness.round_trip(&frame_of(b"mint", b"")).await;
    assert_eq!(decode_response(&observed), b"empty");

    running.stop().await;
}

/// A payload the handler cannot make sense of is a [`HandlerRefusal`],
/// which is a zero-byte clean close and not an eighth transport reason.
#[tokio::test]
async fn a_payload_the_handler_rejects_closes_with_no_bytes() {
    let server = MockServer::start().await;
    let (_config_dir, handler) = verb_handler(&server);
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(&harness.endpoint, handler);

    let observed = harness
        .round_trip(&frame_of(b"mint", b"not-the-shape"))
        .await;
    assert!(observed.is_empty(), "{observed:?}");

    running.stop().await;
}

fn assert_audit_store_unavailable_response(body: &[u8], idempotency_key: &str) -> String {
    let raw: serde_json::Value =
        serde_json::from_slice(body).expect("the refusal response is JSON");
    let mut members: Vec<_> = raw
        .as_object()
        .expect("the refusal response is an object")
        .keys()
        .map(String::as_str)
        .collect();
    members.sort_unstable();
    assert_eq!(
        members,
        [
            "class",
            "error",
            "protocol_version",
            "registrar_health",
            "request_id",
        ],
        "the unavailable handler preserves the existing refusal envelope"
    );
    assert_eq!(
        raw.get("registrar_health"),
        Some(&serde_json::json!({})),
        "the unavailable handler exposes no production health state"
    );
    assert!(
        raw.get("registrar_health")
            .and_then(|health| health.get("limiter"))
            .is_none(),
        "the unavailable handler exposes no limiter counters"
    );
    let response =
        protocol::decode_refusal_response(body).expect("the refusal uses the registrar protocol");
    assert_eq!(response.class, protocol::RefusalClass::Permanent);
    assert_eq!(
        response.error,
        Some(protocol::EnrollError::RegistrarUnavailable {
            reason: protocol::RegistrarUnavailableReason::AuditUnwritable,
        })
    );
    assert!(response.registration_id.is_none());
    assert_eq!(
        response.registrar_health,
        protocol::RegistrarHealth::default()
    );
    assert!(!response.request_id.is_empty());
    assert_ne!(response.request_id, idempotency_key);
    response.request_id
}

/// An unavailable filesystem audit store still receives each request and
/// answers it through the ordinary protocol refusal shape.
#[tokio::test(flavor = "current_thread")]
async fn an_unmounted_audit_store_returns_typed_refusals_with_log_handles() {
    let (logs, _guard) = capture_logs();
    let audit_store = PathBuf::from("/var/lib/bootroot/audit-store");
    let mount_unit = "var-lib-bootroot-audit\\x2dstore.mount".to_string();
    let handler = Arc::new(RefusingHandler::new(
        audit_store.clone(),
        mount_unit.clone(),
        crate::daemon_messages::DaemonMessages::default(),
    ));
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(&harness.endpoint, handler);

    let mut request_ids = Vec::new();
    for (operation, payload, idempotency_key) in [
        (
            b"mint".as_slice(),
            register_payload("roxyd", "h1", "repeat-key"),
            "repeat-key",
        ),
        (
            b"mint".as_slice(),
            register_payload("roxyd", "h1", "repeat-key"),
            "repeat-key",
        ),
        (
            b"deregister".as_slice(),
            deregister_payload("roxyd", "h1", "repeat-key"),
            "repeat-key",
        ),
    ] {
        let observed = harness.round_trip(&frame_of(operation, &payload)).await;
        let body = decode_response(&observed);
        request_ids.push(assert_audit_store_unavailable_response(
            &body,
            idempotency_key,
        ));
    }
    assert_eq!(request_ids.len(), 3);
    assert!(
        request_ids.windows(2).all(|ids| ids[0] != ids[1]),
        "each refusal receives a fresh request id, even when the request repeats"
    );

    let events: Vec<_> = logs
        .events()
        .into_iter()
        .filter(|event| {
            event.message
                == "Registrar endpoint refused a request because the audit store is not mounted"
        })
        .collect();
    assert_eq!(events.len(), 3, "one event is emitted for each refusal");
    for (event, request_id) in events.iter().zip(&request_ids) {
        assert_eq!(event.level, "DEBUG", "refusals are not warnings");
        assert_eq!(event.field("request_id"), request_id);
        assert_eq!(
            event.field("audit_store"),
            audit_store.display().to_string()
        );
        assert_eq!(event.field("mount_unit"), mount_unit);
        assert!(!event.field("caller").is_empty());
        assert!(!event.field("operation").is_empty());
    }

    let malformed = harness.round_trip(&frame_of(b"mint", b"not-json")).await;
    assert!(
        malformed.is_empty(),
        "malformed payloads retain the handler-refusal path"
    );
    running.stop().await;
}

// ---------------------------------------------------------------------
// The production handler over the socket
// ---------------------------------------------------------------------

/// A deregistration driven over the real socket, through the real
/// framing, the real production handler and the real codec, over real
/// verbs pointed at a `wiremock` with nothing mounted — which is how a
/// deployment with no such binding answers.
#[tokio::test]
async fn a_socket_carried_deregister_returns_a_framed_codec_response() {
    let server = MockServer::start().await;
    let (_dir, _audit, handler) = production_handler(&server);
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(&harness.endpoint, handler);

    let observed = harness
        .round_trip(&frame_of(
            b"deregister",
            &deregister_payload("roxyd", "h1", "key-1"),
        ))
        .await;
    let body = decode_response(&observed);
    let response = protocol::decode_deregister_response(&body)
        .expect("the response is the codec's own deregister shape");
    assert_eq!(response.registration_id, "h1-roxyd");
    assert_eq!(
        response.outcome,
        protocol::DeregisterWireOutcome::AlreadyAbsent
    );
    assert_eq!(
        response.registrar_health,
        protocol::RegistrarHealth::default()
    );

    running.stop().await;
}

/// A typed verb refusal is framed as a wire refusal carrying its
/// identifier and its class, and the health container rides it. The
/// refusal is produced by the verbs themselves — a pre-derivation arm
/// needs no mounted response at all — never by substituting something
/// else behind the handler.
#[tokio::test]
async fn a_verb_refusal_is_framed_as_a_wire_refusal_with_its_identifier_and_class() {
    let server = MockServer::start().await;
    let (_dir, _audit, handler) = production_handler(&server);
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(&harness.endpoint, handler);

    let observed = harness
        .round_trip(&frame_of(
            b"deregister",
            &deregister_payload(UNCONFIGURED_COMPONENT, "h1", "key-1"),
        ))
        .await;
    let body = decode_response(&observed);
    let response = protocol::decode_refusal_response(&body)
        .expect("the response is the codec's own refusal shape");
    assert_eq!(
        response.error,
        Some(protocol::EnrollError::ServiceInstanceMismatch),
        "the wire identifier is the one the codec maps this verb refusal onto"
    );
    assert_eq!(response.class, protocol::RefusalClass::Permanent);
    assert!(
        response.registration_id.is_none(),
        "a pre-derivation refusal carries no registration_id"
    );
    assert_eq!(
        response.registrar_health,
        protocol::RegistrarHealth::default()
    );

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

/// The daemon refreshes a single health snapshot between requests rather than
/// assembling limiter values while serializing each response.
#[tokio::test]
async fn limited_events_reach_responses_only_after_daemon_maintenance() {
    let server = MockServer::start().await;
    let counts = Arc::new(CountingLimitedInvocationSink::new());
    let health = Arc::new(StdMutex::new(protocol::RegistrarHealth::default()));
    let limiter = VerbRateLimiter::new(
        VerbRateLimiterSettings {
            admission_burst: 1,
            admission_refill_interval_ms: 600_000,
            predecision_refusal_burst: 1,
            predecision_refusal_refill_interval_ms: 600_000,
        },
        counts.clone(),
    );
    let (_dir, _audit, handler) = production_handler_with_limiter(&server, limiter, health.clone());
    let caller = CallerIdentity::new("daemon-maintenance-test");
    let predecision = deregister_payload(UNCONFIGURED_COMPONENT, "h1", "predecision");
    let admission = deregister_payload("roxyd", "h1", "admission");

    handler
        .handle(Operation::Deregister, &predecision, caller.clone())
        .await
        .expect("the first pre-decision refusal encodes");
    let limited_predecision = handler
        .handle(Operation::Deregister, &predecision, caller.clone())
        .await
        .expect("the limited pre-decision refusal encodes");
    assert_eq!(
        response_health(&limited_predecision),
        protocol::RegistrarHealth::default(),
        "responses retain the daemon snapshot before maintenance"
    );
    assert_eq!(counts.count(LimiterBucket::PredecisionRefusal), 1);
    assert_eq!(counts.count(LimiterBucket::Admission), 0);

    crate::daemon::refresh_registrar_health(&health, &counts);
    let after_predecision_refresh = handler
        .handle(Operation::Deregister, &admission, caller.clone())
        .await
        .expect("the admitted request encodes");
    assert_eq!(
        response_health(&after_predecision_refresh).limiter,
        protocol::LimiterHealth {
            limited_predecision_refusal: 1,
            limited_admission: 0,
        },
        "refreshing pre-decision limits leaves admission at zero"
    );

    let limited_admission = handler
        .handle(Operation::Deregister, &admission, caller.clone())
        .await
        .expect("the limited admission refusal encodes");
    let limited_admission = protocol::decode_refusal_response(&limited_admission)
        .expect("the limited admission refusal decodes");
    assert!(
        matches!(
            limited_admission.error,
            Some(protocol::EnrollError::RegistrarBusy { .. })
        ),
        "an admission limit returns the retryable throttle"
    );
    assert_eq!(
        limited_admission.registrar_health.limiter,
        protocol::LimiterHealth {
            limited_predecision_refusal: 1,
            limited_admission: 0,
        },
        "the admission event waits for the next maintenance refresh"
    );
    assert_eq!(counts.count(LimiterBucket::PredecisionRefusal), 1);
    assert_eq!(counts.count(LimiterBucket::Admission), 1);

    crate::daemon::refresh_registrar_health(&health, &counts);
    let after_admission_refresh = handler
        .handle(Operation::Deregister, &predecision, caller)
        .await
        .expect("the next limited pre-decision refusal encodes");
    assert_eq!(
        response_health(&after_admission_refresh).limiter,
        protocol::LimiterHealth {
            limited_predecision_refusal: 1,
            limited_admission: 1,
        },
        "refreshing admission limits leaves the pre-decision count intact"
    );
}

/// The capacity and record signals reach a response from the daemon's
/// snapshot and from nowhere else.
///
/// The reader computes its counts by reading the store's files on
/// demand, so calling it inside the request path would make every
/// successful mint and deregister read up to the store's full ceiling.
/// Asserted on a snapshot the handler's own store could not have
/// produced: the response follows the snapshot, so no scan of its own
/// ran. Driven over the deregister and refusal shapes, which is every
/// shape this build's production handler encodes — `Operation::Mint`
/// is still refused at the transport seam with no response bytes, so
/// the mint shape's carriage of the member is covered by the
/// `mint-success.json` golden fixture instead.
#[tokio::test]
async fn responses_relay_the_last_capacity_snapshot_without_scanning_the_store() {
    use crate::config::AuditStoreEnforcement;
    use crate::registrar::audit_store::capacity::AuditCapacityState;

    let server = MockServer::start().await;
    let health = Arc::new(StdMutex::new(protocol::RegistrarHealth::default()));
    let (_dir, audit, handler) = production_handler_with_limiter(
        &server,
        VerbRateLimiter::new(
            VerbRateLimiterSettings::default(),
            Arc::new(NoopLimitedInvocationSink),
        ),
        health.clone(),
    );
    let measured_at = time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1_700_000_000);
    let snapshot = protocol::AuditCapacityHealth {
        state: AuditCapacityState::LowWater,
        enforcement: AuditStoreEnforcement::Directory,
        reserve_bytes: 2_147_483_648,
        low_water_bytes: 536_870_912,
        used_bytes: Some(1_700_000_000),
        headroom_bytes: Some(447_483_648),
        measured_at: Some(measured_at),
        intent_without_outcome: Some(4),
        malformed_records: Some(7),
        retention_shortfall: Some(true),
        records_measured_at: Some(measured_at),
    };
    health
        .lock()
        .expect("the snapshot lock is not poisoned")
        .audit_capacity = snapshot.clone();

    let caller = CallerIdentity::new("capacity-relay-test");
    let response = handler
        .handle(
            Operation::Deregister,
            &deregister_payload("roxyd", "h1", "relay"),
            caller.clone(),
        )
        .await
        .expect("the deregister response encodes");
    assert_eq!(
        response_health(&response).audit_capacity,
        snapshot,
        "the response relays the daemon-held snapshot verbatim"
    );

    // The handler's own store now holds records, and the snapshot does
    // not change: a response reads no store of its own.
    assert!(
        std::fs::read(
            audit
                .directory()
                .join(crate::registrar::audit::ACTIVE_FILE_NAME)
        )
        .is_ok_and(|bytes| !bytes.is_empty()),
        "the invocation wrote to the store the reader would have scanned"
    );
    let unchanged = handler
        .handle(
            Operation::Deregister,
            &deregister_payload("roxyd", "h1", "relay-2"),
            caller.clone(),
        )
        .await
        .expect("the second deregister response encodes");
    assert_eq!(response_health(&unchanged).audit_capacity, snapshot);

    // Only a maintenance tick moves it.
    health
        .lock()
        .expect("the snapshot lock is not poisoned")
        .audit_capacity
        .malformed_records = Some(9);
    let refreshed = handler
        .handle(
            Operation::Deregister,
            &deregister_payload("roxyd", "h1", "relay-3"),
            caller,
        )
        .await
        .expect("the third deregister response encodes");
    assert_eq!(
        response_health(&refreshed).audit_capacity.malformed_records,
        Some(9)
    );
}

/// The identity that reaches the verb layer is the one the transport
/// supplied, and no payload member naming an identity influences it.
/// Asserted on what the verbs carried into the audit trail — which
/// records the caller unchanged — rather than on a recording double.
#[tokio::test]
async fn the_verb_sees_the_transport_identity_and_not_a_payload_field() {
    let server = MockServer::start().await;
    let (_dir, audit, handler) = production_handler(&server);
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(&harness.endpoint, handler);

    // The payload names an identity of its own, which must reach
    // nothing: the transport takes the caller from the presented client
    // certificate and this seam passes that value through unchanged.
    let mut payload: serde_json::Value =
        serde_json::from_slice(&deregister_payload("roxyd", "h1", "key-1")).expect("json");
    payload["caller"] = serde_json::json!("registrar-client:impostor.example.com");
    let encoded = serde_json::to_vec(&payload).expect("re-encode");

    let observed = harness.round_trip(&frame_of(b"deregister", &encoded)).await;
    let body = decode_response(&observed);
    let response =
        protocol::decode_deregister_response(&body).expect("a framed deregister response");
    running.stop().await;

    let expected = caller_identity(&registrar_client_name());
    let lines: Vec<serde_json::Value> = audit_trail(&audit)
        .into_iter()
        .filter(|line| line["request_id"] == serde_json::json!(response.request_id))
        .collect();
    assert_eq!(
        lines.len(),
        2,
        "one invocation owes an intent and an outcome"
    );
    for line in &lines {
        assert_eq!(
            line["caller_identity"],
            serde_json::json!(expected.as_str()),
            "the verb must see the transport identity verbatim: {line}"
        );
    }
}

/// Two requests differing only in `idempotency_key` produce identical
/// verb inputs: the same entry point, the same arguments and the same
/// recorded request, differing in nothing but the per-invocation request
/// id the verb layer generates.
#[tokio::test]
async fn the_idempotency_key_reaches_nothing_downstream() {
    let server = MockServer::start().await;
    let (_dir, audit, handler) = production_handler(&server);
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(&harness.endpoint, handler);

    let mut responses = Vec::new();
    for key in ["key-one", "a-completely-different-key"] {
        let observed = harness
            .round_trip(&frame_of(
                b"deregister",
                &deregister_payload("roxyd", "h1", key),
            ))
            .await;
        let body = decode_response(&observed);
        responses.push(
            protocol::decode_deregister_response(&body).expect("a framed deregister response"),
        );
    }
    running.stop().await;

    let (first, second) = (&responses[0], &responses[1]);
    assert_eq!(first.registration_id, second.registration_id);
    assert_eq!(first.outcome, second.outcome);
    assert_ne!(
        first.request_id, second.request_id,
        "the request id is per invocation and is not the idempotency key"
    );

    // The intent line is what the verb was handed. Blanking the one
    // per-invocation member leaves two records that must be identical:
    // the difference between the two requests survived in nothing the
    // handler built.
    let normalized: Vec<serde_json::Value> = [first, second]
        .iter()
        .map(|response| {
            let mut line = audit_trail(&audit)
                .into_iter()
                .find(|line| {
                    line["request_id"] == serde_json::json!(response.request_id)
                        && line["phase"] == serde_json::json!("intent")
                })
                .expect("every invocation writes an intent line");
            line["request_id"] = serde_json::json!("");
            line["ts"] = serde_json::json!("");
            line
        })
        .collect();
    assert_eq!(
        normalized[0], normalized[1],
        "two requests differing only in idempotency_key produce identical verb inputs"
    );

    let bodies: Vec<String> = server
        .received_requests()
        .await
        .expect("the mock records requests")
        .iter()
        .map(|request| String::from_utf8_lossy(&request.body).into_owned())
        .collect();
    assert!(
        bodies
            .iter()
            .all(|body| !body.contains("key-one") && !body.contains("a-completely-different-key")),
        "no idempotency key may reach OpenBao: {bodies:?}"
    );
}

/// A payload the codec cannot decode is a [`HandlerRefusal`]: zero
/// response bytes, the transport's own fixed line, a clean close, and no
/// wire error identifier of any kind.
#[tokio::test]
async fn an_undecodable_payload_is_zero_bytes_and_the_fixed_transport_line() {
    let cases: [(&str, Vec<u8>); 3] = [
        (
            "an absent protocol_version",
            serde_json::to_vec(&serde_json::json!({
                "service_name": "roxyd",
                "host": "h1",
                "idempotency_key": "key-1",
            }))
            .expect("json"),
        ),
        (
            "a version this daemon does not implement",
            serde_json::to_vec(&serde_json::json!({
                "protocol_version": 2,
                "service_name": "roxyd",
                "host": "h1",
                "idempotency_key": "key-1",
            }))
            .expect("json"),
        ),
        ("bytes that are not JSON at all", b"not-json".to_vec()),
    ];

    for (what, payload) in cases {
        let (logs, _guard) = capture_logs();
        let server = MockServer::start().await;
        let (_dir, _audit, handler) = production_handler(&server);
        let harness = Harness::bind().expect("harness");
        let running = RunningEndpoint::start(&harness.endpoint, handler);

        let observed = harness.round_trip(&frame_of(b"deregister", &payload)).await;
        assert!(observed.is_empty(), "{what} must write zero bytes");
        running.stop().await;

        let event = logs.refusal();
        assert_eq!(event.field("reason"), "handler-rejected-payload");
        assert!(
            event.message.contains(HANDLER_REJECTED_PAYLOAD),
            "{what} takes the transport's unchanged fixed line: {event:?}"
        );
    }
}

/// The mint path stops at the wire `spec`, because the grammar its two
/// strings are spelled under is settled nowhere. What the caller sees is
/// the ordinary undecodable-payload answer; what the handler logs is its
/// own line saying which conversion failed, on its own side of the call.
#[tokio::test]
async fn a_mint_refuses_until_the_wire_spec_grammar_is_settled() {
    let (logs, _guard) = capture_logs();
    let server = MockServer::start().await;
    let (_dir, _audit, handler) = production_handler(&server);
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(&harness.endpoint, handler);

    let observed = harness
        .round_trip(&frame_of(
            b"mint",
            &register_payload("roxyd", "h1", "key-1"),
        ))
        .await;
    assert!(observed.is_empty(), "a refused mint writes no bytes");
    running.stop().await;

    // The transport's line is the unchanged fixed one, and the
    // handler's own line — which carries no connection id — is separate.
    let transport = logs.refusal();
    assert_eq!(transport.field("reason"), "handler-rejected-payload");
    assert!(
        transport.message.contains(HANDLER_REJECTED_PAYLOAD),
        "the transport's line is byte-for-byte the fixed one: {transport:?}"
    );
    assert!(
        !transport.message.contains("registrar-wire-contract.md"),
        "nothing the handler knows reaches the transport's line: {transport:?}"
    );
    let handler_line = logs
        .events()
        .iter()
        .find(|event| event.message.contains("could not convert the wire spec"))
        .expect("the handler logs what it knows on its own side of the call")
        .clone();
    assert!(
        handler_line.message.contains("registrar-wire-contract.md"),
        "the handler's line must point at the settlement: {}",
        handler_line.message
    );
    assert!(
        handler_line.field("connection").is_empty(),
        "no connection diagnostic id crosses the trait"
    );

    assert!(
        server
            .received_requests()
            .await
            .expect("the mock records requests")
            .is_empty(),
        "a mint refused before the verb creates nothing"
    );
}

// ---------------------------------------------------------------------
// Signatures: what carries a handler, and what cannot be built without
// one
// ---------------------------------------------------------------------

/// [`ActivatedEndpoint`] carries what has to outlive a `SIGHUP` and
/// nothing else: the socket, its path, the daemon uid and the TLS
/// material consumed once above the reload loop. A handler among them
/// would be a value replaced under a live accept loop, which is the
/// coupling this endpoint deliberately does not have.
#[test]
fn the_activated_endpoint_carries_no_handler() {
    let source = include_str!("../endpoint.rs");
    let declaration = source
        .split("pub(crate) struct ActivatedEndpoint {")
        .nth(1)
        .expect("the struct is declared in this file")
        .split('}')
        .next()
        .expect("the struct body ends");
    let fields: Vec<&str> = declaration
        .lines()
        .map(str::trim)
        .filter(|line| line.ends_with(','))
        .collect();
    assert!(
        !fields.iter().any(|field| field.contains("handler")),
        "the adopted endpoint holds no handler: {fields:?}"
    );
    assert_eq!(
        fields,
        vec![
            "listener: UnixListener,",
            "socket_path: PathBuf,",
            "daemon_uid: u32,",
            "active: RwLock<Arc<ActiveTls>>,",
            "domain: String,",
        ],
        "the adopted endpoint holds the socket, its path, the daemon uid and the TLS material — \
         and no handler"
    );
    assert!(
        !source.contains("fn production_handler"),
        "the missing-handler refusal is gone, not relocated"
    );
    assert!(
        !source.contains("handler: Arc<dyn RegistrarRequestHandler>"),
        "no construction field and no `adopt` parameter carries a handler"
    );
}

/// The accept task cannot be spawned without a handler, because
/// [`serve::run`] takes one. That is a signature rather than a runtime
/// invariant, so it needs no slot, no lock and no interior mutability.
#[test]
fn the_accept_task_cannot_be_spawned_without_a_handler() {
    let source = include_str!("serve.rs");
    let signature = source
        .split("pub(crate) async fn run(")
        .nth(1)
        .expect("the accept loop is declared in this file")
        .split(')')
        .next()
        .expect("the parameter list ends");
    assert!(
        signature.contains("handler: Arc<dyn RegistrarRequestHandler>"),
        "the accept loop takes its handler as an argument: {signature}"
    );
    for forbidden in ["Mutex", "RwLock", "OnceCell", "RefCell", "OnceLock"] {
        assert!(
            !source.contains(forbidden),
            "the transport grew no {forbidden} to hold a handler in"
        );
    }
}

/// The trait's whole contract is unchanged: [`HandlerRefusal`] is still
/// a zero-data marker, `handle` still takes exactly the operation, the
/// payload and the caller, and no connection diagnostic id crosses it.
#[test]
fn the_handler_seam_gained_nothing() {
    // A unit struct: this line would not compile against a payload.
    let refusal = HandlerRefusal;
    assert_eq!(refusal, HandlerRefusal);

    let source = include_str!("handler.rs");
    let signature = source
        .split("fn handle<'a>(")
        .nth(1)
        .expect("the trait method is declared in this file")
        .split("-> Pin<")
        .next()
        .expect("the parameter list ends at the return type");
    assert!(
        !signature.contains("connection"),
        "no connection diagnostic id crosses the trait: {signature}"
    );
    assert_eq!(
        signature.matches(':').count(),
        3,
        "handle takes exactly the operation, the payload and the caller: {signature}"
    );
}

// ---------------------------------------------------------------------
// Production wiring
// ---------------------------------------------------------------------

/// Settings carrying nothing but what the endpoint reads, so an
/// activation test needs no configuration file.
fn endpoint_settings(enabled: bool) -> crate::config::Settings {
    crate::config::Settings {
        email: "test@example.com".to_string(),
        server: "https://example.com/acme/directory".to_string(),
        domain: TEST_DOMAIN.to_string(),
        eab: None,
        acme: crate::config::AcmeSettings {
            directory_fetch_attempts: 1,
            directory_fetch_base_delay_secs: 1,
            directory_fetch_max_delay_secs: 1,
            poll_attempts: 1,
            poll_interval_secs: 1,
            account_key_path: None,
            http_responder_url: "http://localhost:8080".to_string(),
            http_responder_hmac: "dev-hmac".into(),
            http_responder_timeout_secs: 5,
            http_responder_token_ttl_secs: 300,
        },
        retry: crate::config::RetrySettings {
            backoff_secs: vec![1],
        },
        trust: crate::config::TrustSettings::default(),
        scheduler: crate::config::SchedulerSettings {
            max_concurrent_issuances: 1,
        },
        profiles: Vec::new(),
        openbao: None,
        registrar_endpoint: crate::config::RegistrarEndpointSettings {
            enabled,
            ..crate::config::RegistrarEndpointSettings::default()
        },
        registrar: crate::config::RegistrarSettings::default(),
    }
}

/// A disabled endpoint reads nothing and yields nothing. It cannot
/// consult an activation variable, and it loads no certificate material,
/// because it returns before either is looked at.
#[test]
fn a_disabled_endpoint_activates_to_nothing() {
    let activated =
        super::activate(&endpoint_settings(false)).expect("a disabled endpoint never fails");
    assert!(activated.is_none());
}

/// The missing-handler refusal is gone. An enabled endpoint now goes
/// straight to the certificate material, so what it fails on under
/// settings that name none is the material — and nothing anywhere is
/// about a handler.
#[test]
fn an_enabled_endpoint_no_longer_refuses_for_a_missing_handler() {
    let error = super::activate(&endpoint_settings(true))
        .expect_err("these settings name no server certificate material");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains(SERVER_CERT_SETTING),
        "the refusal must be the certificate material's: {rendered}"
    );
    assert!(
        !rendered.contains("handler"),
        "no refusal mentions a handler any more: {rendered}"
    );
    assert!(
        !rendered.contains("unsupported"),
        "enabling the endpoint is no longer unsupported: {rendered}"
    );
}

/// The unprivileged-daemon warning still comes before every other
/// endpoint check, so an operator sees *why* the verbs would fail even
/// when the startup then stops for a different reason.
#[test]
fn a_non_root_enabled_start_warns_before_the_certificate_material_is_read() {
    let (logs, _guard) = capture_logs();
    let error = super::activate(&endpoint_settings(true))
        .expect_err("these settings name no server certificate material");
    assert!(format!("{error:#}").contains(SERVER_CERT_SETTING));

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

// ---------------------------------------------------------------------
// mTLS: what completes a handshake, and what is served afterwards
// ---------------------------------------------------------------------

/// The `reason` field of the one handshake diagnostic in `logs`.
///
/// A handshake that never completed writes nothing and has no
/// application stream to close, so this log line is the only diagnosis
/// there is — which is what makes reading it back the assertion rather
/// than an extra.
fn handshake_reason(logs: &CapturedLogs) -> String {
    let mut matching: Vec<CapturedEvent> = logs
        .events()
        .into_iter()
        .filter(|event| {
            event
                .message
                .starts_with("Registrar endpoint could not complete a TLS handshake")
                || event.message.starts_with(
                    "Registrar endpoint dropped a connection that did not complete a TLS handshake",
                )
        })
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "expected exactly one handshake diagnostic, saw {:?}",
        logs.events()
    );
    assert!(
        !matching[0].field("connection").is_empty(),
        "a handshake diagnostic must carry the connection id"
    );
    matching.remove(0).field("reason").to_string()
}

/// A client certificate is mandatory: the verifier is built without
/// `allow_unauthenticated()`, so a caller that presents none does not
/// arrive unauthenticated, it fails the handshake.
#[tokio::test]
async fn a_caller_presenting_no_client_certificate_fails_the_handshake() {
    let (logs, _guard) = capture_logs();
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(
        &harness.endpoint,
        Arc::new(EchoHandler {
            response: b"served".to_vec(),
        }),
    );

    let outcome = tls_exchange(
        &harness.socket_path,
        harness.pki.client_config(None),
        &frame_of(b"mint", b""),
    )
    .await;
    assert!(
        outcome.is_err(),
        "a caller with no client certificate must be refused: {outcome:?}"
    );
    assert_eq!(handshake_reason(&logs), "no-client-certificate");

    running.stop().await;
}

/// A leaf from a CA the deployment never trusted does not verify, and is
/// logged as a chain rejection rather than as a missing certificate.
#[tokio::test]
async fn a_client_leaf_from_a_foreign_ca_fails_the_handshake() {
    let (logs, _guard) = capture_logs();
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(
        &harness.endpoint,
        Arc::new(EchoHandler {
            response: b"served".to_vec(),
        }),
    );

    let foreign = valid_ca();
    let material = client_material_from(&foreign, vec![dns_san(&registrar_client_name())]);
    let outcome = tls_exchange(
        &harness.socket_path,
        harness.pki.client_config(Some(material)),
        &frame_of(b"mint", b""),
    )
    .await;
    assert!(
        outcome.is_err(),
        "a leaf from a foreign CA must be refused: {outcome:?}"
    );
    assert_eq!(handshake_reason(&logs), "client-chain-rejected");

    running.stop().await;
}

/// The roots are the *pinned subset* of the bundle, not the bundle. A CA
/// an operator added to `ca_bundle_path` without pinning it cannot widen
/// who may connect.
#[tokio::test]
async fn a_client_leaf_from_an_unpinned_bundle_ca_fails_the_handshake() {
    let (logs, _guard) = capture_logs();
    let unpinned = valid_ca();
    let mut pki = Pki::new();
    pki.add_unpinned(&unpinned);
    let harness = Harness::bind_over(pki).expect("harness");
    let running = RunningEndpoint::start(
        &harness.endpoint,
        Arc::new(EchoHandler {
            response: b"served".to_vec(),
        }),
    );

    let material = client_material_from(&unpinned, vec![dns_san(&registrar_client_name())]);
    let outcome = tls_exchange(
        &harness.socket_path,
        harness.pki.client_config(Some(material)),
        &frame_of(b"mint", b""),
    )
    .await;
    assert!(
        outcome.is_err(),
        "a bundle certificate that is not pinned must not admit its leaves: {outcome:?}"
    );
    assert_eq!(handshake_reason(&logs), "client-chain-rejected");

    // The pinned CA still works, so what was refused is the pin and not
    // the bundle file.
    let served = harness.round_trip(&frame_of(b"mint", b"")).await;
    assert!(!served.is_empty(), "{served:?}");

    running.stop().await;
}

/// A certificate that verified against the deployment CA but is not the
/// registrar client identity is refused after the handshake and before
/// any request byte, through the one refusal path, with the
/// [`RegistrarIdentityError`] in the log.
#[tokio::test]
async fn a_verified_leaf_that_is_not_the_registrar_client_is_refused() {
    for (label, sans, expected) in [
        (
            "an ordinary service leaf issued for the registrar's own host",
            vec![dns_san(&format!("001.roxyd.{TEST_HOST}.{TEST_DOMAIN}"))],
            RegistrarIdentityError::NotRegistrarClient,
        ),
        (
            "a leaf carrying two names",
            vec![
                dns_san(&registrar_client_name()),
                dns_san(&format!("001.roxyd.{TEST_HOST}.{TEST_DOMAIN}")),
            ],
            RegistrarIdentityError::San(crate::registrar::SanShapeError::Multiple),
        ),
        (
            "a name whose domain is only a string suffix of the configured one",
            vec![dns_san(&registrar_client_identity(
                TEST_INSTANCE,
                TEST_HOST,
                NEAR_MISS_DOMAIN,
            ))],
            RegistrarIdentityError::DomainMismatch,
        ),
        (
            "a leaf under the registrar label on a host with a non-numeric instance",
            vec![dns_san(&registrar_client_identity(
                "not-numeric",
                TEST_HOST,
                TEST_DOMAIN,
            ))],
            RegistrarIdentityError::InvalidInstanceLabel,
        ),
    ] {
        let (logs, _guard) = capture_logs();
        let harness = Harness::bind().expect("harness");
        let running = RunningEndpoint::start(
            &harness.endpoint,
            Arc::new(EchoHandler {
                response: b"served".to_vec(),
            }),
        );

        let material = client_material_from(&harness.pki.ca, sans);
        let mut stream = tls_connect(
            &harness.socket_path,
            harness.pki.client_config(Some(material)),
        )
        .await
        .unwrap_or_else(|err| panic!("{label} must verify against the CA: {err}"));
        // Nothing is written by the caller: the refusal happens before
        // any request byte is read, so the stream simply ends.
        let observed = read_tls_until_closed(&mut stream).await;
        assert!(observed.is_empty(), "{label}: {observed:?}");

        let event = logs.refusal();
        assert_eq!(event.field("reason"), "not-registrar-client", "{label}");
        assert_eq!(event.field("operation"), UNREAD_OPERATION, "{label}");
        assert!(
            event.message.contains(&expected.to_string()),
            "{label}: the log must name the identity error {expected}: {}",
            event.message
        );

        running.stop().await;
    }
}

/// The peer-credential check stays first and stays a gate of its own: a
/// connection failing it is refused even when its client certificate is
/// the registrar's, and no handshake is paid for.
#[tokio::test]
async fn a_mismatched_peer_is_refused_even_with_the_registrar_certificate() {
    let (logs, _guard) = capture_logs();
    let dir = conforming_tempdir().expect("tempdir");
    let socket_path = dir.path().join("registrar.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket_path).expect("bind");
    std::fs::set_permissions(
        &socket_path,
        std::fs::Permissions::from_mode(REQUIRED_SOCKET_MODE),
    )
    .expect("chmod");
    let pki = Pki::new();
    let (config, resolver) = pki.conforming();
    let endpoint = super::adopt(
        activation_descriptor(listener),
        current_effective_uid(),
        config,
        resolver,
        TEST_DOMAIN.to_string(),
    )
    .expect("adoption");
    // The socket policy requires the *socket* to be owned by the daemon
    // uid, so the mismatch cannot be introduced through `adopt`. It is
    // introduced here instead, on the adopted value: this test is about
    // the per-connection peer check, which the socket policy cannot
    // stand in for.
    let mut endpoint = Arc::into_inner(endpoint).expect("the adopted endpoint is solely owned");
    endpoint.daemon_uid = current_effective_uid().wrapping_add(1);
    let endpoint = Arc::new(endpoint);
    let running = RunningEndpoint::start(
        &endpoint,
        Arc::new(EchoHandler {
            response: b"served".to_vec(),
        }),
    );

    let outcome = tls_connect(&socket_path, pki.registrar_client_config()).await;
    assert!(
        outcome.is_err(),
        "a peer that fails the credential check must not reach a handshake"
    );
    let event = logs.refusal();
    assert_eq!(event.field("reason"), "unauthorized-peer");

    running.stop().await;
}

/// The whole pre-verb refusal shape still holds once the stream is TLS.
///
/// The caller reads **zero** application bytes and its read ends
/// cleanly: [`read_tls_until_closed`] fails on an `UnexpectedEof`, which
/// is what a peer that vanished without `close_notify` produces, so an
/// orderly end is asserted rather than assumed. No error identifier is
/// emitted, and the typed refusal carries the connection id and the
/// operation identifier exactly as it arrived.
#[tokio::test]
async fn the_pre_verb_refusal_shape_survives_the_tls_wrap() {
    let (logs, _guard) = capture_logs();
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(
        &harness.endpoint,
        Arc::new(EchoHandler {
            response: b"served".to_vec(),
        }),
    );

    let mut stream = tls_connect(&harness.socket_path, harness.pki.registrar_client_config())
        .await
        .expect("handshake");
    stream
        .write_all(&frame_of(b"reissue", b""))
        .await
        .expect("write the request");
    let observed = read_tls_until_closed(&mut stream).await;
    assert!(
        observed.is_empty(),
        "a refused caller reads zero application bytes: {observed:?}"
    );

    let event = logs.refusal();
    assert_eq!(event.field("reason"), "unrecognized-operation");
    assert_eq!(event.field("received_name"), "reissue");
    assert_eq!(event.field("operation"), UNREAD_OPERATION);
    assert!(
        event.field("connection").starts_with("endpoint-conn-"),
        "the refusal must carry the connection id: {event:?}"
    );

    running.stop().await;
}

/// The end-to-end proof that the chain the endpoint loaded is one a
/// pinned caller accepts: a client built from
/// [`endpoint_server_verifier`] against a pin file the test wrote
/// completes both verbs, and a client whose pin set does not match
/// refuses without sending a request.
#[tokio::test]
async fn a_pinned_caller_is_served_and_an_unpinned_one_refuses_before_a_request() {
    let server = MockServer::start().await;
    let (_config_dir, handler) = verb_handler(&server);
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(&harness.endpoint, handler);

    for operation in [b"mint".as_slice(), b"deregister".as_slice()] {
        let payload = format!("{UNCONFIGURED_COMPONENT}|{TEST_HOST}|");
        let observed = harness
            .round_trip(&frame_of(operation, payload.as_bytes()))
            .await;
        let body = String::from_utf8(decode_response(&observed)).expect("utf-8");
        assert!(
            body.starts_with(&format!(
                "{}|refused:PreDerivation|",
                String::from_utf8_lossy(operation)
            )),
            "a pinned caller must reach the verb: {body}"
        );
    }

    // A caller whose pin file names a certificate this endpoint never
    // presents refuses the server, so it never sends a request byte.
    let foreign = valid_ca();
    let foreign_pin = crate::tls::sha256_hex(foreign.der().as_ref());
    let pin_file = harness.pki.pin_file_over(&[foreign_pin]);
    let config = client_config_pinning(&pin_file, Some(harness.pki.registrar_client_material()));
    let outcome = tls_connect(&harness.socket_path, config).await;
    assert!(
        outcome.is_err(),
        "a caller whose pin set does not match must refuse the endpoint"
    );

    running.stop().await;
}

/// The renewal seam is reachable from what the daemon holds.
///
/// The resolver is taken from the [`ActivatedEndpoint`] the harness
/// produced — not from one the test built — because that is the whole
/// point: a test that swapped its own resolver would pass while renewal
/// remained unable to reach one. After the swap the endpoint presents a
/// chain under a different anchor, which the caller pinned to the first
/// anchor now refuses and a caller pinned to the second now accepts,
/// with no restart in between.
#[tokio::test]
async fn swapping_the_resolver_through_the_activated_endpoint_changes_the_presented_chain() {
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(
        &harness.endpoint,
        Arc::new(EchoHandler {
            response: b"served".to_vec(),
        }),
    );

    let first = harness.round_trip(&frame_of(b"mint", b"")).await;
    assert!(!first.is_empty(), "the original leaf must serve: {first:?}");

    // A second deployment PKI, and material for the same endpoint name
    // under its anchor.
    let renewed = Pki::new();
    let (cert_path, key_path) = renewed.server_material();
    let certified_key = super::tls::load_certified_key(&cert_path, &key_path)
        .expect("the renewed material must load");
    harness.endpoint.cert_resolver().swap(certified_key);

    // The caller pinned to the first anchor no longer accepts what is
    // presented, and the caller pinned to the second one does.
    let outcome = tls_connect(&harness.socket_path, harness.pki.registrar_client_config()).await;
    assert!(
        outcome.is_err(),
        "the previous anchor must no longer match the presented chain"
    );

    let config = client_config_pinning(
        &renewed.pin_file_path(),
        Some(harness.pki.registrar_client_material()),
    );
    let served = tls_round_trip(&harness.socket_path, config, &frame_of(b"mint", b"")).await;
    assert!(
        !served.is_empty(),
        "the renewed leaf must be presented with no restart: {served:?}"
    );

    running.stop().await;
}

/// Exchanging the whole active configuration changes both halves of the
/// handshake at once: what the endpoint presents *and* which client
/// anchors it accepts.
///
/// Replacing the resolver alone could not do this. The acceptor retains
/// the client verifier it was built with, so a trust-anchor rotation
/// that widened or narrowed who may connect would go on being decided by
/// the old verifier until a restart. The whole configuration is
/// replaced instead, and the accept loop loads it immediately before
/// each handshake.
///
/// The socket is not rebound — its inode is asserted unchanged — no
/// signal is sent, and a connection established before the swap is still
/// connected after it.
#[tokio::test]
async fn exchanging_the_active_configuration_changes_the_presented_chain_and_the_accepted_anchors()
{
    let harness = Harness::bind().expect("harness");
    let running = RunningEndpoint::start(
        &harness.endpoint,
        Arc::new(EchoHandler {
            response: b"served".to_vec(),
        }),
    );
    let inode_before = std::fs::metadata(&harness.socket_path)
        .expect("stat the socket")
        .ino();

    let first = harness.round_trip(&frame_of(b"mint", b"")).await;
    assert!(!first.is_empty(), "the original configuration serves");

    // A connection opened before the exchange and held across it.
    let held = tokio::net::UnixStream::connect(&harness.socket_path)
        .await
        .expect("connect before the exchange");

    // The next trust generation: new server material for the same
    // endpoint name, and a client leaf under the new anchor. The old
    // generation's client is not in the new anchor set at all.
    let rotated = Pki::new();
    let (config, resolver) = rotated.conforming();
    harness.endpoint.swap_active_tls(config, resolver);

    assert_eq!(
        inode_before,
        std::fs::metadata(&harness.socket_path)
            .expect("stat the socket")
            .ino(),
        "a TLS replacement never rebinds or replaces the socket"
    );
    assert!(
        held.peer_addr().is_ok(),
        "a connection already in flight is not dropped"
    );

    // The caller pinned to the old anchor, presenting the old client
    // leaf, is refused on both counts.
    let outcome = tls_connect(&harness.socket_path, harness.pki.registrar_client_config()).await;
    assert!(
        outcome.is_err(),
        "the previous generation must no longer complete a handshake"
    );

    // The caller of the new generation is accepted: its leaf verifies
    // against the rebuilt incoming verifier, and the chain it is
    // presented matches the new pin file.
    let config = client_config_pinning(
        &rotated.pin_file_path(),
        Some(rotated.registrar_client_material()),
    );
    let served = tls_round_trip(&harness.socket_path, config, &frame_of(b"mint", b"")).await;
    assert!(
        !served.is_empty(),
        "the exchanged configuration serves the new generation with no restart: {served:?}"
    );

    drop(held);
    running.stop().await;
}

// ---------------------------------------------------------------------
// The configuration builder: every startup refusal, over its inputs
// ---------------------------------------------------------------------

/// Conforming material builds a configuration *and* a resolver — the
/// typed handle survives assembly rather than being lost inside the
/// `Arc<dyn ResolvesServerCert>` the configuration keeps.
///
/// What the resolver holds is asserted where it is observable: through a
/// real handshake, and through the swap seam driven from the
/// [`ActivatedEndpoint`]. `resolve` cannot be called directly, because
/// there is no way to construct a `rustls::server::ClientHello` outside
/// `rustls`.
#[test]
fn conforming_material_builds_a_configuration_and_a_resolver() {
    let pki = Pki::new();
    let (cert_path, key_path) = pki.server_material();
    let (_config, resolver) = pki.build(&cert_path, &key_path).expect("a configuration");
    // That the client verifier is mandatory is not readable off a built
    // `ServerConfig` — `rustls` keeps the verifier private — so it is
    // asserted where it is observable, in
    // `a_caller_presenting_no_client_certificate_fails_the_handshake`.
    let renewed = super::tls::load_certified_key(&cert_path, &key_path).expect("reload");
    resolver.swap(renewed);
}

/// A leaf with no issuer chain loads cleanly, matches its key and
/// carries the right name — and is refused here, because every correctly
/// pinned caller would otherwise reject it with no local symptom to
/// read.
#[test]
fn leaf_only_material_is_refused_by_the_builder() {
    let pki = Pki::new();
    let (cert_path, key_path) =
        pki.server_material_from(&pki.ca, "bare", vec![dns_san(&endpoint_name())], false);
    let error = pki
        .build(&cert_path, &key_path)
        .expect_err("a bare leaf must be refused");
    assert!(
        matches!(
            error,
            EndpointTlsError::SelfCheck {
                source: EndpointVerifyRejection::AnchorMismatch,
                ..
            }
        ),
        "{error:#}"
    );
    assert_diagnostic_names(&error, SERVER_CERT_SETTING, Some(&cert_path));
}

/// A chain that builds only to a CA nobody pinned is the same failure a
/// caller would see, caught at the daemon.
#[test]
fn material_whose_chain_builds_only_to_an_unpinned_ca_is_refused() {
    let pki = Pki::new();
    let foreign = valid_ca();
    let (cert_path, key_path) =
        pki.server_material_from(&foreign, "foreign", vec![dns_san(&endpoint_name())], true);
    let error = pki
        .build(&cert_path, &key_path)
        .expect_err("an unpinned chain must be refused");
    assert!(
        matches!(
            error,
            EndpointTlsError::SelfCheck {
                source: EndpointVerifyRejection::AnchorMismatch,
                ..
            }
        ),
        "{error:#}"
    );
}

/// An anchor whose validity window has passed is diagnosed as itself,
/// not folded into "the chain did not build".
#[test]
fn material_under_an_expired_anchor_is_refused() {
    let pki = Pki::over(generate_ca((2020, 1, 1), (2021, 1, 1)));
    let (cert_path, key_path) = pki.server_material();
    let error = pki
        .build(&cert_path, &key_path)
        .expect_err("an expired anchor must be refused");
    assert!(
        matches!(
            error,
            EndpointTlsError::SelfCheck {
                source: EndpointVerifyRejection::AnchorExpired,
                ..
            }
        ),
        "{error:#}"
    );
}

/// Asserts a diagnostic names the setting at fault, and the configured
/// path when the setting has one.
fn assert_diagnostic_names(
    error: &EndpointTlsError,
    setting: &str,
    path: Option<&std::path::Path>,
) {
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains(setting),
        "the diagnostic must name {setting}: {rendered}"
    );
    match path {
        Some(path) => assert!(
            rendered.contains(&path.display().to_string()),
            "the diagnostic must name the configured path: {rendered}"
        ),
        None => assert!(
            rendered.contains("is required when the registrar endpoint is enabled"),
            "an absent setting must say it is required: {rendered}"
        ),
    }
}

/// Every startup refusal the builder can produce, asserted directly on
/// it: it opens no socket, touches no descriptor and reads no process
/// environment, so each case is a plain function call.
#[test]
// One table of every startup refusal, each entry a call plus the
// diagnostic it must produce. Splitting it would put the cases in one
// place and the assertion in another for no gain.
#[allow(clippy::too_many_lines)]
fn every_startup_refusal_names_the_setting_at_fault_and_generates_nothing() {
    let pki = Pki::new();
    let (cert_path, key_path) = pki.server_material();
    let bundle = pki.ca_bundle_path();
    let pins = pki.pins();
    let missing = pki.path("absent.pem");
    let directory = pki.path("a-directory");
    std::fs::create_dir(&directory).expect("create a directory in place of a file");

    // A second key, and a leaf whose name is not an endpoint identity.
    let (_other_cert, other_key) = pki.server_material_from(
        &pki.ca,
        "other",
        vec![dns_san(&registrar_client_name())],
        true,
    );
    let (wrong_name_cert, wrong_name_key) = pki.server_material_from(
        &pki.ca,
        "wrong-name",
        vec![dns_san(&format!("001.roxyd.{TEST_HOST}.{TEST_DOMAIN}"))],
        true,
    );

    let before = directory_entries(pki.dir.path());

    let cases: Vec<(&str, EndpointTlsError, &str, Option<PathBuf>)> = vec![
        (
            "an absent server_cert_path",
            build_server_config(None, Some(&key_path), Some(&bundle), &pins, TEST_DOMAIN)
                .expect_err("absent server_cert_path"),
            SERVER_CERT_SETTING,
            None,
        ),
        (
            "an absent server_key_path",
            build_server_config(Some(&cert_path), None, Some(&bundle), &pins, TEST_DOMAIN)
                .expect_err("absent server_key_path"),
            SERVER_KEY_SETTING,
            None,
        ),
        (
            "a missing certificate file",
            build_server_config(
                Some(&missing),
                Some(&key_path),
                Some(&bundle),
                &pins,
                TEST_DOMAIN,
            )
            .expect_err("missing certificate"),
            SERVER_CERT_SETTING,
            Some(missing.clone()),
        ),
        (
            "an unreadable certificate file",
            build_server_config(
                Some(&directory),
                Some(&key_path),
                Some(&bundle),
                &pins,
                TEST_DOMAIN,
            )
            .expect_err("unreadable certificate"),
            SERVER_CERT_SETTING,
            Some(directory.clone()),
        ),
        (
            "a missing key file",
            build_server_config(
                Some(&cert_path),
                Some(&missing),
                Some(&bundle),
                &pins,
                TEST_DOMAIN,
            )
            .expect_err("missing key"),
            SERVER_KEY_SETTING,
            Some(missing.clone()),
        ),
        (
            "an unreadable key file",
            build_server_config(
                Some(&cert_path),
                Some(&directory),
                Some(&bundle),
                &pins,
                TEST_DOMAIN,
            )
            .expect_err("unreadable key"),
            SERVER_KEY_SETTING,
            Some(directory.clone()),
        ),
        (
            "a key that is not the leaf's",
            build_server_config(
                Some(&cert_path),
                Some(&other_key),
                Some(&bundle),
                &pins,
                TEST_DOMAIN,
            )
            .expect_err("key mismatch"),
            SERVER_KEY_SETTING,
            Some(other_key.clone()),
        ),
        (
            "a leaf whose name is not an endpoint identity",
            build_server_config(
                Some(&wrong_name_cert),
                Some(&wrong_name_key),
                Some(&bundle),
                &pins,
                TEST_DOMAIN,
            )
            .expect_err("SAN mismatch"),
            SERVER_CERT_SETTING,
            Some(wrong_name_cert.clone()),
        ),
        (
            "an absent trust.ca_bundle_path",
            build_server_config(Some(&cert_path), Some(&key_path), None, &pins, TEST_DOMAIN)
                .expect_err("absent bundle"),
            CA_BUNDLE_SETTING,
            None,
        ),
        (
            "an absent trust.trusted_ca_sha256",
            build_server_config(
                Some(&cert_path),
                Some(&key_path),
                Some(&bundle),
                &[],
                TEST_DOMAIN,
            )
            .expect_err("absent pins"),
            TRUSTED_CA_SETTING,
            None,
        ),
        (
            "a missing trust bundle",
            build_server_config(
                Some(&cert_path),
                Some(&key_path),
                Some(&missing),
                &pins,
                TEST_DOMAIN,
            )
            .expect_err("missing bundle"),
            CA_BUNDLE_SETTING,
            Some(missing.clone()),
        ),
        (
            "an unreadable trust bundle",
            build_server_config(
                Some(&cert_path),
                Some(&key_path),
                Some(&directory),
                &pins,
                TEST_DOMAIN,
            )
            .expect_err("unreadable bundle"),
            CA_BUNDLE_SETTING,
            Some(directory.clone()),
        ),
        (
            "a bundle in which nothing is pinned",
            build_server_config(
                Some(&cert_path),
                Some(&key_path),
                Some(&bundle),
                &["00".repeat(32)],
                TEST_DOMAIN,
            )
            .expect_err("unpinned bundle"),
            CA_BUNDLE_SETTING,
            Some(bundle.clone()),
        ),
    ];

    for (label, error, setting, path) in &cases {
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(*setting),
            "{label}: the diagnostic must name {setting}: {rendered}"
        );
        match path {
            Some(path) => assert!(
                rendered.contains(&path.display().to_string()),
                "{label}: the diagnostic must name the configured path: {rendered}"
            ),
            None => assert!(
                rendered.contains("is required when the registrar endpoint is enabled"),
                "{label}: an absent setting must say it is required: {rendered}"
            ),
        }
    }

    assert_eq!(
        directory_entries(pki.dir.path()),
        before,
        "no refusal may generate a certificate: the material directory must be untouched"
    );
}

/// A bundle that is not PEM at all is refused as unparseable rather than
/// being read as a bundle with no certificates in it.
#[test]
fn a_trust_bundle_that_is_not_pem_is_refused() {
    let pki = Pki::new();
    let (cert_path, key_path) = pki.server_material();
    let garbage = pki.path("garbage.pem");
    std::fs::write(&garbage, b"not a certificate").expect("write");
    let error = build_server_config(
        Some(&cert_path),
        Some(&key_path),
        Some(&garbage),
        &pki.pins(),
        TEST_DOMAIN,
    )
    .expect_err("a non-PEM bundle must be refused");
    assert_diagnostic_names(&error, CA_BUNDLE_SETTING, Some(&garbage));
}

/// The endpoint's own material is read as finely as the diagnostic
/// needs: a PEM block that does not decode is an unparseable file, a
/// file carrying no PEM block at all holds no certificate, and a key
/// that decodes into something this build cannot sign with is neither
/// of those.
///
/// Each sends an operator somewhere different — a truncated copy, the
/// wrong file, a key from a stack this build does not carry — so a
/// single "bad file" would be the least useful of the three.
#[test]
fn malformed_server_material_is_diagnosed_by_what_is_wrong_with_it() {
    // The body of the corrupt key file, so the diagnostic can be
    // asserted not to quote it.
    const KEY_BODY_MARKER: &str = "not-base64-key-body";

    let pki = Pki::new();
    let (cert_path, key_path) = pki.server_material();
    let bundle = pki.ca_bundle_path();
    let pins = pki.pins();

    let corrupt_cert = pki.path("corrupt.crt");
    std::fs::write(
        &corrupt_cert,
        "-----BEGIN CERTIFICATE-----\n!!! not base64 !!!\n-----END CERTIFICATE-----\n",
    )
    .expect("write a corrupt certificate PEM");
    let error = build_server_config(
        Some(&corrupt_cert),
        Some(&key_path),
        Some(&bundle),
        &pins,
        TEST_DOMAIN,
    )
    .expect_err("a certificate PEM that does not decode must be refused");
    assert!(
        matches!(error, EndpointTlsError::Unparsable { .. }),
        "{error:#}"
    );
    assert_diagnostic_names(&error, SERVER_CERT_SETTING, Some(&corrupt_cert));

    let not_pem = pki.path("not-pem.crt");
    std::fs::write(&not_pem, b"this file is not PEM at all\n").expect("write a non-PEM file");
    let error = build_server_config(
        Some(&not_pem),
        Some(&key_path),
        Some(&bundle),
        &pins,
        TEST_DOMAIN,
    )
    .expect_err("a certificate setting pointing at a non-PEM file must be refused");
    assert!(
        matches!(error, EndpointTlsError::NoCertificate { .. }),
        "{error:#}"
    );
    assert_diagnostic_names(&error, SERVER_CERT_SETTING, Some(&not_pem));

    // The key diagnostics have to say what is wrong without quoting the
    // bytes they failed on: this input is key material, and an error
    // that echoed it would put it in a log.
    let corrupt_key = pki.path("corrupt.key");
    std::fs::write(
        &corrupt_key,
        format!("-----BEGIN PRIVATE KEY-----\n!!{KEY_BODY_MARKER}!!\n-----END PRIVATE KEY-----\n"),
    )
    .expect("write a corrupt key PEM");
    let error = build_server_config(
        Some(&cert_path),
        Some(&corrupt_key),
        Some(&bundle),
        &pins,
        TEST_DOMAIN,
    )
    .expect_err("a key PEM that does not decode must be refused");
    assert!(
        matches!(error, EndpointTlsError::Unparsable { .. }),
        "{error:#}"
    );
    assert_diagnostic_names(&error, SERVER_KEY_SETTING, Some(&corrupt_key));
    assert!(
        !format!("{error:#}").contains(KEY_BODY_MARKER),
        "a key diagnostic must not quote the material it failed on: {error:#}"
    );

    let unsupported_key = pki.path("unsupported.key");
    std::fs::write(
        &unsupported_key,
        "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n",
    )
    .expect("write a well-formed PEM block holding no usable key");
    let error = build_server_config(
        Some(&cert_path),
        Some(&unsupported_key),
        Some(&bundle),
        &pins,
        TEST_DOMAIN,
    )
    .expect_err("a key this build cannot sign with must be refused");
    assert!(
        matches!(error, EndpointTlsError::UnsupportedKey { .. }),
        "{error:#}"
    );
    assert_diagnostic_names(&error, SERVER_KEY_SETTING, Some(&unsupported_key));
}

/// The two paths transposed is the likeliest way to get this wrong, and
/// each half of it is diagnosed as what it is: a certificate setting
/// pointing at something holding no certificate, and a key setting
/// pointing at something holding no key.
///
/// Both files parse as PEM, so neither case can be reported as an
/// unparseable file — the diagnostic has to name the setting whose
/// content is missing, or an operator reads it as a corrupt file and
/// goes looking in the wrong place.
#[test]
fn transposed_certificate_and_key_paths_are_each_diagnosed_as_themselves() {
    let pki = Pki::new();
    let (cert_path, key_path) = pki.server_material();
    let bundle = pki.ca_bundle_path();
    let pins = pki.pins();

    let error = build_server_config(
        Some(&key_path),
        Some(&key_path),
        Some(&bundle),
        &pins,
        TEST_DOMAIN,
    )
    .expect_err("a key file in the certificate setting must be refused");
    assert!(
        matches!(error, EndpointTlsError::NoCertificate { .. }),
        "{error:#}"
    );
    assert_diagnostic_names(&error, SERVER_CERT_SETTING, Some(&key_path));

    let error = build_server_config(
        Some(&cert_path),
        Some(&cert_path),
        Some(&bundle),
        &pins,
        TEST_DOMAIN,
    )
    .expect_err("a certificate file in the key setting must be refused");
    assert!(
        matches!(error, EndpointTlsError::NoPrivateKey { .. }),
        "{error:#}"
    );
    assert_diagnostic_names(&error, SERVER_KEY_SETTING, Some(&cert_path));
}

fn directory_entries(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("the material directory is readable")
        .map(|entry| {
            entry
                .expect("a readable entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort_unstable();
    names
}
