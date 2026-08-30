//! Tests for the capacity probe, its walk and the low-water alarm.
//!
//! Everything a plain [`tempfile::tempdir`] makes deterministic runs
//! against the real filesystem, so the security properties are proven
//! against real syscalls: the symlink, hard-link, sparse-file,
//! special-file, nested-subdirectory and same-device cases, the root
//! link, the `.`/`..` skip and the real `fstatvfs`. Only the five
//! behaviours that are a race, a privilege assumption or a
//! process-global observation go through [`RecordingWalkOps`].

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use tempfile::TempDir;

use super::*;

/// The default `audit_store_reserve_bytes`, 2 GiB.
const DEFAULT_RESERVE: u64 = 2_147_483_648;
/// The default `audit_store_low_water_bytes`, 512 MiB.
const DEFAULT_LOW_WATER: u64 = 536_870_912;
/// Far more room than any assertion here needs from the device.
const AMPLE_AVAILABLE: u64 = u64::MAX / 4;

// -----------------------------------------------------------------
// Doubles
// -----------------------------------------------------------------

/// A [`CapacityProbe`] that answers with a value a test chose.
///
/// The alarm and its hysteresis are driven through this so "the alarm
/// fires before the reserve is consumed" needs no special filesystem,
/// no root and no container.
struct FixedProbe {
    reading: Option<CapacityMeasurement>,
}

impl FixedProbe {
    fn reporting(used_bytes: u64, available_bytes: u64) -> Self {
        Self {
            reading: Some(CapacityMeasurement {
                used_bytes,
                available_bytes,
            }),
        }
    }

    const fn failing() -> Self {
        Self { reading: None }
    }
}

impl CapacityProbe for FixedProbe {
    fn measure(
        &self,
        _store_dir: &Path,
        _enforcement: AuditStoreEnforcement,
    ) -> io::Result<CapacityMeasurement> {
        self.reading
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EACCES))
    }
}

/// Which syscall of the seam a test is failing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeamOp {
    /// The `openat` half of the open-directory operation, before the
    /// descriptor is handed to `fdopendir`.
    OpenAt,
    /// The `fdopendir` half, after `openat` already produced a
    /// descriptor. The descriptor has a different owner on either side
    /// of that transfer, which is why the two are separately nameable.
    FdOpenDir,
    NextEntry,
    StatDir,
    StatEntry,
}

/// One named failure: one operation, on one entry name, with one
/// `errno`.
#[derive(Debug, Clone)]
struct Injection {
    op: SeamOp,
    entry: OsString,
    errno: i32,
}

/// An open directory that remembers which name opened it, so an
/// injection can name the entry it applies to.
struct NamedDir {
    name: OsString,
    inner: DirStream,
}

impl AsFd for NamedDir {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

/// The real syscalls, wrapped so one named operation on one named entry
/// can fail and so opens and closes can be counted.
///
/// The counters are the double's own: an `openat` that succeeded counts
/// one open, and the release that follows counts one close, whether the
/// walk asked for it through [`WalkOps::close_dir`] or the injected
/// `fdopendir` failure released it here the way production's
/// [`open_stream`] does. Counting them here rather than in
/// `/proc/self/fd` is what makes the assertion hold under `cargo test`'s
/// default parallelism, where a process-global count would observe every
/// other thread the runner has in flight.
struct RecordingWalkOps {
    inner: SyscallWalkOps,
    injection: Option<Injection>,
    opens: Cell<u32>,
    closes: Cell<u32>,
    entries_read: Cell<u32>,
}

impl RecordingWalkOps {
    fn new() -> Self {
        Self {
            inner: SyscallWalkOps,
            injection: None,
            opens: Cell::new(0),
            closes: Cell::new(0),
            entries_read: Cell::new(0),
        }
    }

    fn failing(op: SeamOp, entry: &str, errno: i32) -> Self {
        Self {
            injection: Some(Injection {
                op,
                entry: OsString::from(entry),
                errno,
            }),
            ..Self::new()
        }
    }

    /// Returns the injected failure for `op` on `entry`, if any.
    fn injected(&self, op: SeamOp, entry: &OsStr) -> Option<io::Error> {
        self.injection.as_ref().and_then(|injection| {
            (injection.op == op && injection.entry == entry)
                .then(|| io::Error::from_raw_os_error(injection.errno))
        })
    }

    fn balanced(&self) -> bool {
        self.opens.get() == self.closes.get()
    }
}

/// Keys an injection on the entry's own name rather than on a full path.
fn entry_key(name: &OsStr) -> OsString {
    Path::new(name)
        .file_name()
        .map_or_else(|| name.to_os_string(), OsStr::to_os_string)
}

impl WalkOps for RecordingWalkOps {
    type Dir = NamedDir;

    fn open_dir(&self, parent: Option<&Self::Dir>, name: &OsStr) -> io::Result<Self::Dir> {
        let key = entry_key(name);
        if let Some(error) = self.injected(SeamOp::OpenAt, &key) {
            // Before the ownership transfer: no descriptor exists, so
            // nothing is counted and nothing is owed a close.
            return Err(error);
        }
        let inner = self.inner.open_dir(parent.map(|dir| &dir.inner), name)?;
        self.opens.set(self.opens.get() + 1);
        if let Some(error) = self.injected(SeamOp::FdOpenDir, &key) {
            // After it: the descriptor exists and the caller still owns
            // it, so it is released here exactly as `open_stream`
            // releases it on a null return.
            drop(inner);
            self.closes.set(self.closes.get() + 1);
            return Err(error);
        }
        Ok(NamedDir { name: key, inner })
    }

    fn next_entry(&self, dir: &mut Self::Dir) -> io::Result<Option<OsString>> {
        if let Some(error) = self.injected(SeamOp::NextEntry, &dir.name) {
            return Err(error);
        }
        self.entries_read.set(self.entries_read.get() + 1);
        self.inner.next_entry(&mut dir.inner)
    }

    fn stat_dir(&self, dir: &Self::Dir) -> io::Result<EntryFacts> {
        if let Some(error) = self.injected(SeamOp::StatDir, &dir.name) {
            return Err(error);
        }
        self.inner.stat_dir(&dir.inner)
    }

    fn stat_entry(&self, parent: &Self::Dir, name: &OsStr) -> io::Result<EntryFacts> {
        if let Some(error) = self.injected(SeamOp::StatEntry, name) {
            return Err(error);
        }
        self.inner.stat_entry(&parent.inner, name)
    }

    fn close_dir(&self, dir: Self::Dir) {
        self.closes.set(self.closes.get() + 1);
        self.inner.close_dir(dir.inner);
    }
}

/// An open directory for [`FactWalkOps`].
///
/// The file is only a descriptor-shaped stand-in for the root open. The
/// test-only space source means this fixture never supplies it to
/// `fstatvfs`; the scripted facts below control every value the walk uses.
struct FactDir {
    file: fs::File,
}

impl AsFd for FactDir {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

/// A controlled walk fixture for entry facts that a real filesystem cannot
/// represent, such as an overflowing `st_blocks * 512` product.
struct FactWalkOps {
    root: EntryFacts,
    entries: RefCell<VecDeque<OsString>>,
    entry_facts: HashMap<OsString, EntryFacts>,
    entries_read: Cell<u32>,
}

impl FactWalkOps {
    fn root_only(root: EntryFacts) -> Self {
        Self {
            root,
            entries: RefCell::new(VecDeque::new()),
            entry_facts: HashMap::new(),
            entries_read: Cell::new(0),
        }
    }

    fn with_entry(root: EntryFacts, name: &str, facts: EntryFacts) -> Self {
        let name = OsString::from(name);
        let mut entry_facts = HashMap::new();
        entry_facts.insert(name.clone(), facts);
        Self {
            root,
            entries: RefCell::new(VecDeque::from([name])),
            entry_facts,
            entries_read: Cell::new(0),
        }
    }

    fn entries_read(&self) -> u32 {
        self.entries_read.get()
    }
}

impl WalkOps for FactWalkOps {
    type Dir = FactDir;

    fn open_dir(&self, parent: Option<&Self::Dir>, name: &OsStr) -> io::Result<Self::Dir> {
        if parent.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "the overflow fixture has no child directories",
            ));
        }
        fs::File::open(Path::new(name)).map(|file| FactDir { file })
    }

    fn next_entry(&self, _dir: &mut Self::Dir) -> io::Result<Option<OsString>> {
        self.entries_read.set(self.entries_read.get() + 1);
        Ok(self.entries.borrow_mut().pop_front())
    }

    fn stat_dir(&self, _dir: &Self::Dir) -> io::Result<EntryFacts> {
        Ok(self.root)
    }

    fn stat_entry(&self, _parent: &Self::Dir, name: &OsStr) -> io::Result<EntryFacts> {
        self.entry_facts.get(name).copied().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "the overflow fixture has no facts for this entry",
            )
        })
    }

    fn close_dir(&self, dir: Self::Dir) {
        drop(dir);
    }
}

// -----------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------

/// Returns a store directory inside a temporary directory, so a test
/// can also write beside it.
fn store_under_parent() -> (TempDir, PathBuf) {
    let parent = tempfile::tempdir().expect("a temporary directory");
    let store = parent.path().join("audit-store");
    fs::create_dir(&store).expect("the store directory is created");
    (parent, store)
}

fn write_bytes(path: &Path, len: usize) {
    fs::write(path, vec![b'r'; len]).expect("the fixture file is written");
}

/// Returns an entry's own allocated bytes, from its own `st_blocks`.
fn allocated_of(path: &Path) -> u64 {
    fs::symlink_metadata(path)
        .expect("the fixture entry stats")
        .blocks()
        * ST_BLOCKS_UNIT_BYTES
}

fn make_fifo(path: &Path) {
    let raw = CString::new(path.as_os_str().as_bytes()).expect("the fixture path holds no NUL");
    // SAFETY: `raw` is a NUL-terminated C string that outlives the call,
    // which creates one FIFO at that path and touches nothing else.
    let rc = unsafe { libc::mkfifo(raw.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "the fixture FIFO is created");
}

/// Reads the filesystem behind `path` through the same call the probe
/// makes, for a test that has to compare against an independent reading.
fn space_of(path: &Path) -> FsSpaceFacts {
    let dir = fs::File::open(path).expect("the directory opens");
    filesystem_space(dir.as_fd()).expect("the filesystem reports its space")
}

fn measure_directory_mode(store: &Path) -> io::Result<CapacityMeasurement> {
    HostCapacityProbe::new().measure(store, AuditStoreEnforcement::Directory)
}

// -----------------------------------------------------------------
// The alarm
// -----------------------------------------------------------------

/// Drives one probe through the abstraction and returns the reading.
fn read_through(
    probe: &dyn CapacityProbe,
    store: &Path,
    previous: AuditCapacityState,
    reserve: u64,
    low_water: u64,
) -> Option<CapacityReading> {
    probe
        .measure(store, AuditStoreEnforcement::Directory)
        .ok()
        .map(|measurement| evaluate(previous, measurement, reserve, low_water))
}

#[test]
fn the_alarm_is_on_at_the_threshold_and_off_one_byte_above_it() {
    let (_parent, store) = store_under_parent();
    let at_threshold = FixedProbe::reporting(DEFAULT_RESERVE - DEFAULT_LOW_WATER, AMPLE_AVAILABLE);
    let reading = read_through(
        &at_threshold,
        &store,
        AuditCapacityState::Unknown,
        DEFAULT_RESERVE,
        DEFAULT_LOW_WATER,
    )
    .expect("the probe succeeds");
    assert_eq!(
        reading.headroom_bytes,
        i64::try_from(DEFAULT_LOW_WATER).expect("the threshold fits"),
    );
    assert_eq!(
        reading.state,
        AuditCapacityState::LowWater,
        "the alarm is on at exactly the configured threshold"
    );

    let above = FixedProbe::reporting(DEFAULT_RESERVE - DEFAULT_LOW_WATER - 1, AMPLE_AVAILABLE);
    assert_eq!(
        read_through(
            &above,
            &store,
            AuditCapacityState::Unknown,
            DEFAULT_RESERVE,
            DEFAULT_LOW_WATER,
        )
        .expect("the probe succeeds")
        .state,
        AuditCapacityState::Ok,
        "a cold start has no alarm to clear, so one byte above the threshold is ok"
    );
}

#[test]
fn the_alarm_holds_until_the_hysteresis_margin_is_reached() {
    let (_parent, store) = store_under_parent();
    let margin = hysteresis_margin_bytes(DEFAULT_LOW_WATER);
    let below_clear = FixedProbe::reporting(
        DEFAULT_RESERVE - DEFAULT_LOW_WATER - margin + 1,
        AMPLE_AVAILABLE,
    );
    assert_eq!(
        read_through(
            &below_clear,
            &store,
            AuditCapacityState::LowWater,
            DEFAULT_RESERVE,
            DEFAULT_LOW_WATER,
        )
        .expect("the probe succeeds")
        .state,
        AuditCapacityState::LowWater,
        "an alarm does not clear between the threshold and the clear threshold"
    );

    let at_clear = FixedProbe::reporting(
        DEFAULT_RESERVE - DEFAULT_LOW_WATER - margin,
        AMPLE_AVAILABLE,
    );
    assert_eq!(
        read_through(
            &at_clear,
            &store,
            AuditCapacityState::LowWater,
            DEFAULT_RESERVE,
            DEFAULT_LOW_WATER,
        )
        .expect("the probe succeeds")
        .state,
        AuditCapacityState::Ok,
        "the alarm clears at threshold + margin"
    );
}

#[test]
fn a_failed_probe_yields_no_reading_at_all() {
    let (_parent, store) = store_under_parent();
    assert!(
        read_through(
            &FixedProbe::failing(),
            &store,
            AuditCapacityState::LowWater,
            DEFAULT_RESERVE,
            DEFAULT_LOW_WATER,
        )
        .is_none(),
        "a failed probe produces nothing for a caller to overwrite a state with"
    );
}

#[test]
fn the_state_table_follows_the_three_ordered_rules() {
    let threshold = DEFAULT_LOW_WATER;
    let signed = i64::try_from(threshold).expect("the threshold fits");
    let margin = i64::try_from(hysteresis_margin_bytes(threshold)).expect("the margin fits");

    assert_eq!(AuditCapacityState::default(), AuditCapacityState::Unknown);

    // Rule 1, ahead of everything else.
    for previous in [
        AuditCapacityState::Unknown,
        AuditCapacityState::Ok,
        AuditCapacityState::LowWater,
        AuditCapacityState::Exhausted,
    ] {
        assert_eq!(
            next_state(previous, 0, threshold),
            AuditCapacityState::Exhausted
        );
        assert_eq!(
            next_state(previous, -1, threshold),
            AuditCapacityState::Exhausted
        );
        assert_eq!(
            next_state(previous, i64::MIN, threshold),
            AuditCapacityState::Exhausted
        );
    }

    // Rule 3, from a cold start and from ok.
    for previous in [AuditCapacityState::Unknown, AuditCapacityState::Ok] {
        assert_eq!(
            next_state(previous, signed, threshold),
            AuditCapacityState::LowWater
        );
        assert_eq!(
            next_state(previous, signed - 1, threshold),
            AuditCapacityState::LowWater
        );
        assert_eq!(
            next_state(previous, signed + 1, threshold),
            AuditCapacityState::Ok
        );
    }

    // Rule 2, from either alarm state.
    for previous in [AuditCapacityState::LowWater, AuditCapacityState::Exhausted] {
        assert_eq!(
            next_state(previous, 1, threshold),
            AuditCapacityState::LowWater
        );
        assert_eq!(
            next_state(previous, signed + margin - 1, threshold),
            AuditCapacityState::LowWater
        );
        assert_eq!(
            next_state(previous, signed + margin, threshold),
            AuditCapacityState::Ok,
            "the clear threshold gates a return from an alarm, and reaching it is enough"
        );
    }
}

#[test]
fn the_hysteresis_margin_floors_at_one_mebibyte_and_saturates_near_the_signed_bound() {
    assert_eq!(
        hysteresis_margin_bytes(9),
        AUDIT_STORE_MIN_HYSTERESIS_MARGIN_BYTES,
        "a threshold whose tenth truncates to zero still gets the floor"
    );
    assert_eq!(
        hysteresis_margin_bytes(DEFAULT_LOW_WATER),
        DEFAULT_LOW_WATER / 10,
        "the ten per cent term applies at the default"
    );

    // A threshold near the reserve's own `i64::MAX` bound pushes the
    // clear sum past it; a saturating add keeps the comparison from
    // wrapping into a spurious clear.
    let huge = u64::try_from(i64::MAX).expect("i64::MAX fits") - 1;
    assert_eq!(
        next_state(AuditCapacityState::LowWater, i64::MAX / 2, huge),
        AuditCapacityState::LowWater,
        "a clear sum that saturates stays out of reach; a wrapped one would read as negative and \
         clear the alarm on any positive headroom"
    );
}

#[test]
fn headroom_clamps_rather_than_wrapping_on_values_past_the_signed_bound() {
    let past_signed = u64::MAX;
    assert!(
        headroom_bytes(DEFAULT_RESERVE, past_signed, past_signed) < 0,
        "an implausible usage stays negative rather than wrapping positive"
    );
    assert_eq!(
        next_state(
            AuditCapacityState::Ok,
            headroom_bytes(DEFAULT_RESERVE, past_signed, past_signed),
            DEFAULT_LOW_WATER
        ),
        AuditCapacityState::Exhausted,
        "a usage past the signed bound is not a spurious ok"
    );
    assert_eq!(
        headroom_bytes(DEFAULT_RESERVE, 0, past_signed),
        i64::try_from(DEFAULT_RESERVE).expect("the reserve fits"),
        "an available figure past the signed bound stops binding, leaving the reserve to decide"
    );
    assert_eq!(
        next_state(
            AuditCapacityState::Ok,
            headroom_bytes(DEFAULT_RESERVE, 0, past_signed),
            DEFAULT_LOW_WATER
        ),
        AuditCapacityState::Ok,
        "an available figure past the signed bound is not a spurious exhausted"
    );
}

#[test]
fn every_block_count_product_saturates_rather_than_wrapping() {
    let overflowing = FsSpaceFacts {
        blocks: u64::MAX,
        blocks_free: 0,
        blocks_available: u64::MAX,
        fragment_size: 4_096,
    };
    assert_eq!(available_bytes(&overflowing), u64::MAX);
    assert_eq!(filesystem_used_bytes(&overflowing), u64::MAX);
    assert_eq!(allocated_bytes(u64::MAX), u64::MAX);

    // The probe still succeeds on all three: turning an
    // implausible-but-harmless filesystem report into `unknown` would
    // drop the alarm entirely.
    assert_eq!(
        next_state(
            AuditCapacityState::Ok,
            headroom_bytes(DEFAULT_RESERVE, 0, available_bytes(&overflowing)),
            DEFAULT_LOW_WATER
        ),
        AuditCapacityState::Ok
    );
}

#[test]
fn the_host_probe_succeeds_when_available_bytes_overflow() {
    let (_parent, store) = store_under_parent();
    let space = FsSpaceFacts {
        blocks: 1,
        blocks_free: 1,
        blocks_available: u64::MAX,
        fragment_size: 2,
    };
    let probe = HostCapacityProbe::with_ops_and_space(
        FactWalkOps::root_only(EntryFacts {
            dev: 1,
            ino: 1,
            blocks: 0,
            is_dir: true,
        }),
        space,
    );

    let measured = probe
        .measure(&store, AuditStoreEnforcement::Filesystem)
        .expect("an overflowing f_bavail product does not fail the probe");

    assert_eq!(measured.available_bytes, u64::MAX);
    assert_eq!(
        probe.ops.entries_read(),
        0,
        "filesystem mode does not enumerate the store"
    );
}

#[test]
fn the_host_probe_succeeds_when_filesystem_used_bytes_overflow() {
    let (_parent, store) = store_under_parent();
    let space = FsSpaceFacts {
        blocks: u64::MAX,
        blocks_free: 0,
        blocks_available: 1,
        fragment_size: 2,
    };
    let probe = HostCapacityProbe::with_ops_and_space(
        FactWalkOps::root_only(EntryFacts {
            dev: 1,
            ino: 1,
            blocks: 0,
            is_dir: true,
        }),
        space,
    );

    let measured = probe
        .measure(&store, AuditStoreEnforcement::Filesystem)
        .expect("an overflowing f_blocks product does not fail the probe");

    assert_eq!(measured.used_bytes, u64::MAX);
    assert_eq!(
        probe.ops.entries_read(),
        0,
        "filesystem mode does not enumerate the store"
    );
}

#[test]
fn the_host_probe_succeeds_when_a_walked_entry_bytes_overflow() {
    let (_parent, store) = store_under_parent();
    let probe = HostCapacityProbe::with_ops_and_space(
        FactWalkOps::with_entry(
            EntryFacts {
                dev: 1,
                ino: 1,
                blocks: 0,
                is_dir: true,
            },
            "audit.log",
            EntryFacts {
                dev: 1,
                ino: 2,
                blocks: u64::MAX,
                is_dir: false,
            },
        ),
        FsSpaceFacts {
            blocks: 1,
            blocks_free: 1,
            blocks_available: 1,
            fragment_size: 1,
        },
    );

    let measured = probe
        .measure(&store, AuditStoreEnforcement::Directory)
        .expect("an overflowing walked entry does not fail the probe");

    assert_eq!(measured.used_bytes, u64::MAX);
}

#[test]
fn available_bytes_come_from_the_unprivileged_count_and_not_the_root_one() {
    let space = FsSpaceFacts {
        blocks: 1_000,
        blocks_free: 400,
        blocks_available: 100,
        fragment_size: 4_096,
    };
    assert_eq!(available_bytes(&space), 100 * 4_096);
    assert_ne!(available_bytes(&space), 400 * 4_096);
    assert_eq!(filesystem_used_bytes(&space), 600 * 4_096);
}

// -----------------------------------------------------------------
// The real probe over a real filesystem
// -----------------------------------------------------------------

#[test]
fn the_real_probe_reports_plausible_non_zero_values() {
    let (_parent, store) = store_under_parent();
    write_bytes(&store.join("records.log"), 64 * 1_024);

    let measured = measure_directory_mode(&store).expect("the real probe succeeds");
    assert!(
        measured.used_bytes > 0,
        "a store holding a file uses blocks"
    );
    assert!(
        measured.available_bytes > 0,
        "a writable temporary directory has room"
    );

    // The two readings are separate `statvfs` calls on a filesystem the
    // rest of the suite is also writing to, so they are compared with a
    // tolerance; that the figure is the `f_bavail` product and not the
    // `f_bfree` one is asserted exactly by the unit test above.
    let space = space_of(&store);
    assert!(
        measured.available_bytes.abs_diff(available_bytes(&space)) < 1_024 * 1_024 * 1_024,
        "available bytes are this filesystem's f_bavail product"
    );
    assert_eq!(
        measured.available_bytes % space.fragment_size,
        0,
        "available bytes are a block-count product, not a byte figure of their own"
    );
}

#[test]
fn directory_mode_walks_the_store_and_tracks_a_written_file() {
    let (_parent, store) = store_under_parent();
    let before = measure_directory_mode(&store).expect("the probe succeeds");

    let payload = store.join("records").join("audit.log");
    fs::create_dir(store.join("records")).expect("the records directory is created");
    write_bytes(&payload, 1_024 * 1_024);

    let after = measure_directory_mode(&store).expect("the probe succeeds");
    assert_eq!(
        after.used_bytes,
        allocated_of(&store) + allocated_of(&store.join("records")) + allocated_of(&payload),
        "the walk reports the store root plus every entry below it"
    );
    assert!(
        after.used_bytes >= before.used_bytes + 1_024 * 1_024,
        "usage tracks a file written into the store"
    );
}

#[test]
fn filesystem_mode_takes_usage_from_the_root_statvfs_and_walks_nothing() {
    let (_parent, store) = store_under_parent();
    write_bytes(&store.join("audit.log"), 256 * 1_024);

    let ops = RecordingWalkOps::new();
    let probe = HostCapacityProbe::with_ops(ops);
    let measured = probe
        .measure(&store, AuditStoreEnforcement::Filesystem)
        .expect("the probe succeeds");

    assert_eq!(
        probe.ops.entries_read.get(),
        0,
        "filesystem mode enumerates nothing"
    );
    assert_eq!(probe.ops.opens.get(), 1, "only the store root is opened");
    assert!(probe.ops.balanced(), "the root is closed again");

    let space = space_of(&store);
    assert!(
        measured.available_bytes.abs_diff(available_bytes(&space)) < 1_024 * 1_024 * 1_024,
        "available bytes are the f_bavail product in this mode too"
    );
    let expected = filesystem_used_bytes(&space);
    // The two readings are separated by the rest of this test, so a
    // busy filesystem can move between them; what is asserted is that
    // the figure is the filesystem's and not the subtree's, which
    // differ by orders of magnitude.
    assert!(
        measured.used_bytes.abs_diff(expected) < 512 * 1_024 * 1_024,
        "filesystem mode reports the filesystem's used space"
    );
    let walked = measure_directory_mode(&store).expect("the walk succeeds");
    assert!(
        measured.used_bytes >= walked.used_bytes,
        "the filesystem's usage is at least the store subtree's"
    );
}

#[test]
fn a_symbolic_link_at_the_store_root_fails_the_probe_in_both_modes() {
    let parent = tempfile::tempdir().expect("a temporary directory");
    let real = parent.path().join("real-store");
    fs::create_dir(&real).expect("the real directory is created");
    write_bytes(&real.join("known.log"), 512 * 1_024);
    let link = parent.path().join("audit-store");
    std::os::unix::fs::symlink(&real, &link).expect("the store path is a symbolic link");

    for enforcement in [
        AuditStoreEnforcement::Filesystem,
        AuditStoreEnforcement::Directory,
    ] {
        let error = HostCapacityProbe::new()
            .measure(&link, enforcement)
            .expect_err("a symbolic link at the store root fails the probe");
        assert!(
            matches!(
                error.raw_os_error(),
                Some(libc::ELOOP | libc::EMLINK | libc::ENOTDIR)
            ),
            "the root open refuses the link rather than following it: {error}"
        );
    }
}

#[test]
fn the_walk_resolves_no_symlink_counts_no_file_twice_and_reads_no_special_file() {
    let (parent, store) = store_under_parent();
    let outside_file = parent.path().join("outside.bin");
    write_bytes(&outside_file, 4 * 1_024 * 1_024);
    let outside_dir = parent.path().join("outside-dir");
    fs::create_dir(&outside_dir).expect("the outside directory is created");
    write_bytes(&outside_dir.join("hidden.bin"), 2 * 1_024 * 1_024);

    let regular = store.join("a.bin");
    write_bytes(&regular, 128 * 1_024);
    let hard_link = store.join("a-hardlink.bin");
    fs::hard_link(&regular, &hard_link).expect("the hard link is created");
    let file_link = store.join("file-link");
    std::os::unix::fs::symlink(&outside_file, &file_link).expect("the file link is created");
    let dir_link = store.join("dir-link");
    std::os::unix::fs::symlink(&outside_dir, &dir_link).expect("the directory link is created");
    let fifo = store.join("fifo");
    make_fifo(&fifo);
    let sparse = store.join("sparse.bin");
    fs::File::create(&sparse)
        .expect("the sparse file is created")
        .set_len(16 * 1_024 * 1_024)
        .expect("the sparse file is extended");
    let nested = store.join("nested");
    fs::create_dir(&nested).expect("the nested directory is created");
    let nested_file = nested.join("inner.bin");
    write_bytes(&nested_file, 64 * 1_024);

    // Computed from each fixture's own reported `st_blocks`, never from
    // an assumption that a class of entry contributes nothing.
    let expected = [
        &store,
        &regular,
        &file_link,
        &dir_link,
        &fifo,
        &sparse,
        &nested,
        &nested_file,
    ]
    .into_iter()
    .map(|path| allocated_of(path))
    .sum::<u64>();

    let measured = measure_directory_mode(&store).expect("the probe succeeds");
    assert_eq!(
        measured.used_bytes, expected,
        "the hard-linked file counts once, the links count as their own entries only, and the \
         sparse file counts by allocated blocks"
    );

    write_bytes(&outside_file, 32 * 1_024 * 1_024);
    write_bytes(&outside_dir.join("hidden.bin"), 32 * 1_024 * 1_024);
    assert_eq!(
        measure_directory_mode(&store)
            .expect("the probe succeeds")
            .used_bytes,
        expected,
        "growing what the links point at moves nothing"
    );
}

#[test]
fn the_walk_never_counts_or_descends_into_its_own_parent() {
    let (parent, store) = store_under_parent();
    let inside = store.join("inside.bin");
    write_bytes(&inside, 256 * 1_024);
    let expected = allocated_of(&store) + allocated_of(&inside);

    let beside = parent.path().join("beside.bin");
    write_bytes(&beside, 8 * 1_024 * 1_024);
    let beside_dir = parent.path().join("beside-dir");
    fs::create_dir(&beside_dir).expect("the sibling directory is created");
    write_bytes(&beside_dir.join("more.bin"), 8 * 1_024 * 1_024);

    assert_eq!(
        measure_directory_mode(&store)
            .expect("the probe succeeds")
            .used_bytes,
        expected,
        "the walk reports the store subtree only"
    );

    write_bytes(&beside, 64 * 1_024 * 1_024);
    write_bytes(&beside_dir.join("more.bin"), 64 * 1_024 * 1_024);
    assert_eq!(
        measure_directory_mode(&store)
            .expect("the probe succeeds")
            .used_bytes,
        expected,
        "growing the parent's own bytes moves nothing, so `.` and `..` are neither counted nor \
         descended into"
    );
}

// -----------------------------------------------------------------
// The five behaviours that go through the seam
// -----------------------------------------------------------------

/// Builds a store with one subdirectory holding one file.
fn seam_fixture() -> (TempDir, PathBuf) {
    let (parent, store) = store_under_parent();
    let nested = store.join("openbao");
    fs::create_dir(&nested).expect("the nested directory is created");
    write_bytes(&nested.join("audit.log"), 128 * 1_024);
    write_bytes(&store.join("top.bin"), 64 * 1_024);
    (parent, store)
}

fn measure_through(
    store: &Path,
    ops: RecordingWalkOps,
) -> (
    io::Result<CapacityMeasurement>,
    HostCapacityProbe<RecordingWalkOps>,
) {
    let probe = HostCapacityProbe::with_ops(ops);
    let outcome = probe.measure(store, AuditStoreEnforcement::Directory);
    (outcome, probe)
}

#[test]
fn a_substituted_directory_fails_the_probe_and_contributes_no_usage() {
    let (_parent, store) = seam_fixture();
    for errno in [libc::ELOOP, libc::ENOTDIR] {
        let (outcome, probe) = measure_through(
            &store,
            RecordingWalkOps::failing(SeamOp::OpenAt, "openbao", errno),
        );
        let error = outcome.expect_err("a substituted directory fails the probe");
        assert_eq!(error.raw_os_error(), Some(errno));
        assert!(probe.ops.balanced(), "every opened directory was closed");
    }
}

#[test]
fn an_entry_that_vanished_under_the_walk_is_skipped_and_the_probe_succeeds() {
    let (_parent, store) = seam_fixture();
    let full = measure_directory_mode(&store).expect("the undisturbed probe succeeds");

    let (outcome, probe) = measure_through(
        &store,
        RecordingWalkOps::failing(SeamOp::StatEntry, "top.bin", libc::ENOENT),
    );
    let measured = outcome.expect("a vanished entry is an ordinary rotation race, not a failure");
    assert_eq!(
        measured.used_bytes,
        full.used_bytes - allocated_of(&store.join("top.bin")),
        "the vanished entry contributes nothing and the rest is still counted"
    );
    assert!(probe.ops.balanced());

    let (outcome, probe) = measure_through(
        &store,
        RecordingWalkOps::failing(SeamOp::OpenAt, "openbao", libc::ENOENT),
    );
    let measured = outcome.expect("a subdirectory that vanished after its stat is skipped");
    assert!(measured.used_bytes < full.used_bytes);
    assert!(probe.ops.balanced());
}

#[test]
fn an_unreadable_subdirectory_fails_the_probe_rather_than_summing_as_zero() {
    let (_parent, store) = seam_fixture();
    let (outcome, probe) = measure_through(
        &store,
        RecordingWalkOps::failing(SeamOp::OpenAt, "openbao", libc::EACCES),
    );
    let error = outcome.expect_err("an unreadable subdirectory fails the probe");
    assert_eq!(error.raw_os_error(), Some(libc::EACCES));
    assert!(
        probe.ops.balanced(),
        "a walk that failed part-way through a subdirectory still closed what it opened"
    );
}

#[test]
fn a_readdir_error_fails_the_probe_rather_than_reading_as_a_short_directory() {
    let (_parent, store) = seam_fixture();
    let (outcome, probe) = measure_through(
        &store,
        RecordingWalkOps::failing(SeamOp::NextEntry, "openbao", libc::EIO),
    );
    let error = outcome.expect_err("a failed directory read fails the probe");
    assert_eq!(error.raw_os_error(), Some(libc::EIO));
    assert!(probe.ops.balanced());
}

#[test]
fn a_failed_directory_stream_open_fails_the_probe_and_leaks_no_descriptor() {
    let (_parent, store) = seam_fixture();
    let (outcome, probe) = measure_through(
        &store,
        RecordingWalkOps::failing(SeamOp::FdOpenDir, "openbao", libc::ENOMEM),
    );
    let error = outcome.expect_err("a failed stream open fails the probe");
    assert_eq!(error.raw_os_error(), Some(libc::ENOMEM));
    assert!(
        probe.ops.balanced(),
        "the descriptor its openat produced was closed before the failure propagated"
    );
}

#[test]
fn a_failed_root_stat_fails_the_probe_and_closes_the_root() {
    let (_parent, store) = seam_fixture();
    let (outcome, probe) = measure_through(
        &store,
        RecordingWalkOps::failing(SeamOp::StatDir, "audit-store", libc::EIO),
    );
    assert!(
        outcome.is_err(),
        "a root that cannot be stat-ed fails the probe"
    );
    assert!(probe.ops.balanced());
}

/// A directory is classified from the descriptor the walk holds open,
/// not from the `fstatat` that decided to open it, so that a directory
/// substituted between the two calls cannot be counted as one object and
/// walked as another. Asserted by failing the descriptor stat on an
/// enumerated subdirectory: nothing else in the walk performs that call,
/// so the injection can only fire if the rule holds.
#[test]
fn an_enumerated_directory_is_classified_from_its_own_descriptor() {
    let (_parent, store) = seam_fixture();
    let (outcome, probe) = measure_through(
        &store,
        RecordingWalkOps::failing(SeamOp::StatDir, "openbao", libc::EIO),
    );
    let error = outcome.expect_err("a subdirectory that cannot be stat-ed fails the probe");
    assert_eq!(error.raw_os_error(), Some(libc::EIO));
    assert!(
        probe.ops.balanced(),
        "the descriptor whose stat failed was closed before the failure propagated"
    );
}

#[test]
fn a_successful_walk_closes_every_directory_it_opened() {
    let (_parent, store) = seam_fixture();
    let (outcome, probe) = measure_through(&store, RecordingWalkOps::new());
    outcome.expect("the walk succeeds");
    assert_eq!(
        probe.ops.opens.get(),
        2,
        "the root and its one subdirectory"
    );
    assert!(probe.ops.balanced());
}

#[tokio::test]
async fn the_off_runtime_probe_reports_what_the_blocking_one_does() {
    let (_parent, store) = store_under_parent();
    write_bytes(&store.join("audit.log"), 256 * 1_024);

    let direct = measure_directory_mode(&store).expect("the blocking probe succeeds");
    let off_runtime = probe_capacity_off_runtime(store.clone(), AuditStoreEnforcement::Directory)
        .await
        .expect("the spawn_blocking probe succeeds");
    assert_eq!(
        direct.used_bytes, off_runtime.used_bytes,
        "moving the walk off the runtime worker changes nothing it measures"
    );

    // A store that is not there fails the probe rather than reporting a
    // healthy-looking zero, on the blocking path as on the direct one.
    assert!(
        probe_capacity_off_runtime(store.join("not-there"), AuditStoreEnforcement::Directory)
            .await
            .is_err()
    );
}
