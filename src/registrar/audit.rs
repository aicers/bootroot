//! The daemon-owned, append-only record store the registrar's audit
//! trail is written to, and the versioned JSON Lines format it writes.
//!
//! `OpenBao`'s mandatory file audit device records what `OpenBao` was
//! asked to do. It cannot record a registrar request that was refused
//! *before* any `OpenBao` write, and it cannot say which caller asked
//! for which `(service_name, host, instance)`. This store is the second,
//! bootroot-local artifact that can. It does not replace the `OpenBao`
//! device and does not weaken it; the two are independent and both are
//! required.
//!
//! # Who owns it
//!
//! The **daemon** owns the store. The registrar supplies request values
//! and nothing else: it cannot read, append to, delete, redirect or
//! select the artifact, and no field of a request reaches the path, the
//! modes, the rotation policy or the retention policy. Those come from
//! the daemon's own `agent.toml` `[registrar]` table
//! ([`crate::config::RegistrarSettings`]), which is validated before a
//! store is opened.
//!
//! # The format
//!
//! One file family, one versioned line format, no index and no
//! sidecar. The active file is [`ACTIVE_FILE_NAME`]; every rotated
//! generation is `registrar-audit-<YYYYMMDDTHHMMSSZ>-<NNNNNN>.jsonl`,
//! whose names sort lexicographically from oldest to newest. Each line
//! is one complete [`AuditRecord`] serialized as a single JSON object
//! followed by `\n`; hostile quotes, backslashes, control bytes and
//! newlines are JSON-escaped, so one record is always one line.
//!
//! Both phases — `intent` and `outcome` — carry the full identity
//! fields, so a line stays readable after its counterpart has rotated
//! out of the retained window.
//!
//! `ts` is supplied by whoever constructs the record. Appending
//! preserves it and reads no clock of its own, which is what lets a
//! fixture pin exact bytes. Preserving it is why a record whose `ts`
//! is not already in the format's one shape — a UTC millisecond — is
//! refused rather than written with its remainder dropped or its
//! offset rewritten; the builders put a clock reading into that shape
//! through [`canonical_timestamp`] before the record exists, and the
//! format reader accepts only the spelling the writer produces.
//!
//! Everything else about what a durable line may say is the store's,
//! not the caller's: the byte caps are applied by the store, a record
//! whose `record_version` is not [`AUDIT_RECORD_VERSION`] is refused
//! rather than written, so every line in the family is at the version
//! this build's readers expect, and so is one whose `phase` and
//! `outcome` contradict each other — an `intent` line never carries an
//! outcome and an `outcome` line always does.
//!
//! # What this module deliberately does not do
//!
//! There is no best-effort mode, no buffering, no fire-and-forget path
//! and no caller-selectable suppression: [`AuditRecordStore::append`]
//! either durably wrote one line or returns a typed
//! [`AuditStoreError`]. Writing records around the two verbs — where
//! the intent and outcome lines go relative to the `OpenBao` work, and
//! what a failed write returns to a caller — is not here either. The
//! verb layer holds the store as a fixed dependency and the sibling
//! issue that adds those call sites owns that ordering.

use std::fs::{DirBuilder, File, OpenOptions, Permissions};
use std::io::Write as _;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{fmt, io};

use serde::{Deserialize, Serialize};
use time::{Date, Month, OffsetDateTime, Time, UtcOffset};
use tokio::sync::Mutex as TokioMutex;
use tokio::task::JoinHandle;

use crate::fs_util::sync_parent_dir;
use crate::tls::sha256_hex;

/// The version every record this build writes declares.
///
/// [`AuditRecordStore::append`] refuses a record carrying any other
/// value, so this is not merely what the builders set but what the
/// files actually hold.
pub const AUDIT_RECORD_VERSION: u32 = 1;

/// The name of the file appends land in.
pub const ACTIVE_FILE_NAME: &str = "registrar-audit.jsonl";

/// The prefix every rotated generation's name starts with.
const ROTATED_PREFIX: &str = "registrar-audit-";

/// The suffix every file in the family ends with.
const FILE_SUFFIX: &str = ".jsonl";

/// Digits in a rotated generation's collision sequence. Fixed width, so
/// the names sort lexicographically in the order they were produced.
const SEQUENCE_DIGITS: usize = 6;

/// The largest collision sequence [`SEQUENCE_DIGITS`] can spell.
const MAX_SEQUENCE: u32 = 999_999;

/// Bytes in the `YYYYMMDDTHHMMSSZ` timestamp half of a rotated
/// generation's name.
const ROTATION_STAMP_LEN: usize = "YYYYMMDDTHHMMSSZ".len();

/// Mode of a path component this store creates above its own directory.
const ANCESTOR_DIR_MODE: u32 = 0o755;

/// Mode of the store directory itself.
const STORE_DIR_MODE: u32 = 0o700;

/// Mode the active file is created with.
const ACTIVE_FILE_MODE: u32 = 0o600;

/// The uid production requires every audited path to be owned by.
const PRODUCTION_UID: u32 = 0;

/// Directory the daemon writes registrar audit records to unless
/// `agent.toml` says otherwise.
pub const DEFAULT_AUDIT_RECORD_DIR: &str = "/var/lib/bootroot/registrar-audit";

/// Default size at which the active file is rotated, in bytes (8 MiB).
pub const DEFAULT_AUDIT_MAX_FILE_BYTES: u64 = 8_388_608;

/// Default number of rotated generations retained beside the active
/// file.
pub const DEFAULT_AUDIT_MAX_RETAINED_FILES: u32 = 16;

/// Default retention target in days. Recorded for later reporting work;
/// the hard [`DEFAULT_AUDIT_MAX_RETAINED_FILES`] capacity wins over it.
pub const DEFAULT_AUDIT_MIN_RETAIN_DAYS: u32 = 90;

/// The smallest `audit_max_file_bytes` a configuration may declare
/// (64 KiB).
///
/// The floor exists so one maximum-size record always fits in a freshly
/// rotated file: it is checked against [`MAX_SERIALIZED_RECORD_BYTES`]
/// in this module's tests rather than left as a number somebody has to
/// re-derive.
pub const MIN_AUDIT_MAX_FILE_BYTES: u64 = 65_536;

/// The cap every attacker-influenced string in a record is held to, in
/// bytes of the original value.
pub const MAX_RECORD_FIELD_BYTES: usize = 512;

/// Worst-case JSON expansion of one source byte.
///
/// A control byte has no short escape, so `serde_json` writes it as
/// `\u00XX` — six bytes out for one in. Every bound below multiplies by
/// this rather than by the source-byte cap, because a record made
/// entirely of control bytes is exactly what a hostile caller would
/// send.
const MAX_JSON_ESCAPE_EXPANSION: usize = 6;

/// Bytes one capped attacker-influenced string can occupy once escaped.
const MAX_ESCAPED_FIELD_BYTES: usize = MAX_RECORD_FIELD_BYTES * MAX_JSON_ESCAPE_EXPANSION;

/// How many attacker-influenced strings one record can carry:
/// `caller_identity`, `requested.service_name`, `requested.host` and
/// `outcome.detail`.
const ATTACKER_INFLUENCED_FIELDS: usize = 4;

/// Upper bound on a `request_id`.
///
/// Not attacker-influenced: the handle is generated inside the verb
/// layer from a random half and a process-monotonic tail, so it is
/// short, ASCII, and never escapes. The generous bound is here so the
/// record ceiling stays sound if that spelling ever grows.
const MAX_REQUEST_ID_BYTES: usize = 128;

/// Upper bound on a `registration_id`.
///
/// The derivation refuses any key longer than this or outside
/// `[a-z0-9-]`, so it contributes no escaping at all.
const MAX_REGISTRATION_ID_BYTES: usize = 131;

/// Bytes one `truncated` entry can occupy: the longest field path, a
/// 64-hex digest, a 20-digit byte count, and the punctuation around
/// them.
const MAX_TRUNCATION_ENTRY_BYTES: usize = 192;

/// Bytes every fixed part of a record can occupy: the keys, the
/// punctuation, the enum spellings, the timestamp and the instance
/// number.
const MAX_RECORD_SCAFFOLD_BYTES: usize = 512;

/// The ceiling on one serialized record, newline included.
///
/// Every term is a worst case rather than a typical one, and the
/// attacker-influenced terms are counted **after** JSON escaping. This
/// is what makes [`MIN_AUDIT_MAX_FILE_BYTES`] demonstrably large enough
/// to hold one maximum-size record in a freshly rotated file.
pub const MAX_SERIALIZED_RECORD_BYTES: usize = MAX_RECORD_SCAFFOLD_BYTES
    + ATTACKER_INFLUENCED_FIELDS * MAX_ESCAPED_FIELD_BYTES
    + ATTACKER_INFLUENCED_FIELDS * MAX_TRUNCATION_ENTRY_BYTES
    + MAX_REQUEST_ID_BYTES * MAX_JSON_ESCAPE_EXPANSION
    + MAX_REGISTRATION_ID_BYTES;

// ---------------------------------------------------------------------
// The record format
// ---------------------------------------------------------------------

/// Which half of one verb invocation a record describes.
///
/// Exactly two values, and deliberately no `#[serde(other)]` arm: a
/// third phase must break every downstream `match` at compile time
/// rather than be silently folded into one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditPhase {
    /// The request as it arrived, recorded before the work it asks for.
    Intent,
    /// What the invocation produced.
    Outcome,
}

impl AuditPhase {
    /// Returns the phase spelled exactly as it is serialized.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Outcome => "outcome",
        }
    }
}

impl fmt::Display for AuditPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which registrar verb a record belongs to.
///
/// Named after `RegistrarVerbs::mint` and `RegistrarVerbs::deregister`.
/// `register` is not a verb this repository has and is never
/// serialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditVerb {
    /// `mint`.
    Mint,
    /// `deregister`.
    Deregister,
}

/// The identity parts a request asked about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedIdentity {
    /// The component's plain keyword, exactly as the caller sent it.
    pub service_name: String,
    /// The target host label, exactly as the caller sent it.
    pub host: String,
    /// The instance number, written as a JSON number. Omitted entirely
    /// when the request carried none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<u32>,
}

/// Why a request was refused.
///
/// One value per source variant, across all three refusal enums the
/// verb layer can produce: `VerbError`'s own variants, every
/// [`crate::registrar::RegistrarError`] its `Registrar` arm carries, and
/// every `WrapTtlRefusal` its `InvalidWrapTtl` arm carries. The mapping
/// is one-to-one and total — nothing is pruned by inferred
/// reachability, nothing is merged, no wire identifier appears here, and
/// there is no fallback variant — so a new refusal upstream breaks the
/// conversion at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    // `VerbError`'s own variants.
    /// `VerbError::ReservedServiceName`.
    ReservedServiceName,
    /// `VerbError::RegistrationIdCollision`.
    RegistrationIdCollision,
    /// `VerbError::StoredSpecConflict`.
    StoredSpecConflict,
    /// `VerbError::HostMismatch`.
    HostMismatch,
    /// `VerbError::Unavailable`.
    Unavailable,

    // Everything `VerbError::Registrar` carries.
    /// `RegistrarError::ConfigUnreadable`.
    ConfigUnreadable,
    /// `RegistrarError::FingerprintLineMalformed`.
    FingerprintLineMalformed,
    /// `RegistrarError::FingerprintMismatch`.
    FingerprintMismatch,
    /// `RegistrarError::ConfigMalformed`.
    ConfigMalformed,
    /// `RegistrarError::UnsupportedSchemaVersion`.
    UnsupportedSchemaVersion,
    /// `RegistrarError::UnknownMultiplicity`.
    UnknownMultiplicity,
    /// `RegistrarError::UnknownReloadKind`.
    UnknownReloadKind,
    /// `RegistrarError::InvalidReloadTarget`.
    InvalidReloadTarget,
    /// `RegistrarError::InvalidDomain`.
    InvalidDomain,
    /// `RegistrarError::InvalidComponentKey`.
    InvalidComponentKey,
    /// `RegistrarError::InvalidServiceName`.
    InvalidServiceName,
    /// `RegistrarError::InvalidHost`.
    InvalidHost,
    /// `RegistrarError::ComponentNotConfigured`.
    ComponentNotConfigured,
    /// `RegistrarError::ServiceInstanceMismatch`.
    ServiceInstanceMismatch,
    /// `RegistrarError::DerivedKeyInvalid`.
    DerivedKeyInvalid,
    /// `RegistrarError::SpecIdentityDisagreement`.
    SpecIdentityDisagreement,
    /// `RegistrarError::ServiceSpecOutsideSafeSet`.
    ServiceSpecOutsideSafeSet,

    // Everything `VerbError::InvalidWrapTtl` carries.
    /// `WrapTtlRefusal::Zero`.
    Zero,
    /// `WrapTtlRefusal::Negative`.
    Negative,
    /// `WrapTtlRefusal::NotWholeSeconds`.
    NotWholeSeconds,
    /// `WrapTtlRefusal::ExceedsOpenBaoRange`. Spelled out rather than
    /// left to `rename_all`, because the serialized value is a
    /// downstream contract and must not move if the Rust name is ever
    /// re-cased.
    #[serde(rename = "exceeds_open_bao_range")]
    ExceedsOpenBaoRange,
}

/// What one invocation produced.
///
/// Serialized as an internally tagged object, so a success class is
/// `{"class":"first_mint"}` and a refusal is
/// `{"class":"refused","reason":"..."}` with an optional `detail`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case")]
pub enum AuditOutcome {
    /// `MintKind::FirstMint`: the identity did not exist and this
    /// request claimed it.
    FirstMint,
    /// `MintKind::IdempotentReMint`. Spelled out rather than left to
    /// `rename_all`, which would produce `idempotent_re_mint`.
    #[serde(rename = "idempotent_remint")]
    IdempotentReMint,
    /// `DeregisterKind::IdentityRemoved`.
    IdentityRemoved,
    /// `DeregisterKind::AlreadyAbsent`. Spelled out rather than left to
    /// `rename_all`, which would produce `already_absent` and lose the
    /// idempotence the class is named for.
    #[serde(rename = "idempotent_already_absent")]
    AlreadyAbsent,
    /// The request was refused.
    Refused {
        /// Which refusal, flattened from the verb layer's three
        /// refusal enums.
        reason: RefusalReason,
        /// Optional operator-facing detail. Capped like every other
        /// attacker-influenced string, and never an error chain.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
}

/// What a shortened string was before it was shortened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TruncationDigest {
    /// Lowercase hex SHA-256 of the complete original bytes.
    pub full_sha256: String,
    /// Length of the complete original value, in bytes.
    pub full_bytes: u64,
}

/// The shortened fields of one record, keyed by field path.
///
/// A struct rather than a map, so the four permitted field paths are
/// the only ones that can ever appear and a fifth needs a code change
/// here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Truncations {
    /// Set when `caller_identity` was shortened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_identity: Option<TruncationDigest>,
    /// Set when `requested.service_name` was shortened.
    #[serde(
        rename = "requested.service_name",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub requested_service_name: Option<TruncationDigest>,
    /// Set when `requested.host` was shortened.
    #[serde(
        rename = "requested.host",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub requested_host: Option<TruncationDigest>,
    /// Set when `outcome.detail` was shortened.
    #[serde(
        rename = "outcome.detail",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub outcome_detail: Option<TruncationDigest>,
}

impl Truncations {
    /// Reports whether nothing at all was shortened, which is when the
    /// whole `truncated` object is omitted from the record.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.caller_identity.is_none()
            && self.requested_service_name.is_none()
            && self.requested_host.is_none()
            && self.outcome_detail.is_none()
    }
}

/// One line of the registrar audit trail.
///
/// Fields serialize in declaration order, which is the order the
/// documented format lists them in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    /// The format version this line was written under.
    ///
    /// Both builders set it to [`AUDIT_RECORD_VERSION`], and
    /// [`AuditRecordStore::append`] refuses anything else, so the
    /// field's being public cannot put another version on disk. It is
    /// public because deserializing an existing line has to read it.
    pub record_version: u32,
    /// Which half of the invocation this line is.
    ///
    /// It must agree with `outcome`, and
    /// [`AuditRecordStore::append`] refuses the record when it does
    /// not: an `intent` line carries no outcome and an `outcome` line
    /// carries one.
    pub phase: AuditPhase,
    /// An RFC 3339 UTC timestamp at millisecond precision, supplied by
    /// whoever built the record. Appending preserves it and reads no
    /// clock.
    ///
    /// The field is public and `OffsetDateTime` carries both an offset
    /// and nanoseconds, so a value can hold precision the format
    /// cannot and an offset the format does not write. Both builders
    /// run it through [`canonical_timestamp`], and
    /// [`AuditRecordStore::append`] refuses a record whose `ts` is not
    /// already canonical rather than dropping the remainder or
    /// converting the offset on the way to disk: a written line has to
    /// deserialize back to the record that produced it.
    #[serde(with = "millisecond_rfc3339")]
    pub ts: OffsetDateTime,
    /// The invocation's correlation handle.
    pub request_id: String,
    /// Which verb was invoked.
    pub verb: AuditVerb,
    /// The caller identity, verbatim as it arrived, subject only to the
    /// byte cap.
    pub caller_identity: String,
    /// The identity parts the request asked about.
    pub requested: RequestedIdentity,
    /// The derived key, omitted entirely until derivation has produced
    /// one. Never `null` and never an empty string: an empty value is
    /// not a key, so it is written the same way as no key at all.
    #[serde(default, skip_serializing_if = "registration_id_is_absent")]
    pub registration_id: Option<String>,
    /// What the invocation produced. Present on an `outcome` line and
    /// absent on an `intent` one; a record pairing it the other way is
    /// refused by [`AuditRecordStore::append`] rather than written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<AuditOutcome>,
    /// What was shortened, if anything. Omitted entirely when nothing
    /// was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated: Option<Truncations>,
}

impl AuditRecord {
    /// Builds the `intent` line for one invocation.
    ///
    /// `ts` is put into the shape the format holds — the UTC offset,
    /// at millisecond precision — so a value straight off a nanosecond
    /// clock at any offset builds a record the store accepts.
    #[must_use]
    pub fn intent(
        ts: OffsetDateTime,
        request_id: String,
        verb: AuditVerb,
        caller_identity: String,
        requested: RequestedIdentity,
    ) -> Self {
        Self {
            record_version: AUDIT_RECORD_VERSION,
            phase: AuditPhase::Intent,
            ts: canonical_timestamp(ts),
            request_id,
            verb,
            caller_identity,
            requested,
            registration_id: None,
            outcome: None,
            truncated: None,
        }
    }

    /// Builds the `outcome` line for one invocation.
    ///
    /// `registration_id` is `None` for every outcome produced before
    /// derivation; it is omitted from the line rather than written as
    /// `null`. An empty `Some` says the same thing and is normalized to
    /// `None` here, so the format never carries `""` either. `ts` is
    /// put into the shape the format holds, exactly as in
    /// [`AuditRecord::intent`].
    #[must_use]
    pub fn outcome(
        ts: OffsetDateTime,
        request_id: String,
        verb: AuditVerb,
        caller_identity: String,
        requested: RequestedIdentity,
        registration_id: Option<String>,
        outcome: AuditOutcome,
    ) -> Self {
        Self {
            record_version: AUDIT_RECORD_VERSION,
            phase: AuditPhase::Outcome,
            ts: canonical_timestamp(ts),
            request_id,
            verb,
            caller_identity,
            requested,
            registration_id: registration_id.filter(|id| !id.is_empty()),
            outcome: Some(outcome),
            truncated: None,
        }
    }

    /// Returns this record with every attacker-influenced string capped
    /// at [`MAX_RECORD_FIELD_BYTES`] and a `truncated` entry recorded
    /// for each one that was shortened.
    ///
    /// Recomputed from scratch, so a `truncated` value a caller set by
    /// hand never survives into a written line: the store applies this
    /// itself, and a caller cannot opt out of it.
    #[must_use]
    pub fn into_bounded(mut self) -> Self {
        // Not a bound, but the same reasoning: the store decides what
        // the durable line may say, and an empty derived key is the
        // absence of one however the record was built.
        self.registration_id = self.registration_id.filter(|id| !id.is_empty());
        let mut truncated = Truncations::default();
        self.caller_identity = bound_field(self.caller_identity, &mut truncated.caller_identity);
        self.requested.service_name = bound_field(
            self.requested.service_name,
            &mut truncated.requested_service_name,
        );
        self.requested.host = bound_field(self.requested.host, &mut truncated.requested_host);
        if let Some(AuditOutcome::Refused {
            detail: Some(detail),
            ..
        }) = &mut self.outcome
        {
            *detail = bound_field(std::mem::take(detail), &mut truncated.outcome_detail);
        }
        self.truncated = if truncated.is_empty() {
            None
        } else {
            Some(truncated)
        };
        self
    }

    /// Serializes this record as one newline-terminated JSON object.
    ///
    /// # Errors
    ///
    /// Returns [`AuditStoreError::Serialize`] if the record cannot be
    /// serialized.
    pub fn to_line(&self) -> Result<Vec<u8>, AuditStoreError> {
        let mut line = serde_json::to_vec(self).map_err(AuditStoreError::Serialize)?;
        line.push(b'\n');
        Ok(line)
    }
}

/// Reports whether a `registration_id` has nothing to say, which is
/// either that derivation has not produced one yet or that a caller
/// handed over an empty string. The format admits neither `null` nor
/// `""`, so both spellings omit the key.
// `serde`'s `skip_serializing_if` hands the field by reference and
// accepts no other shape, so the idiomatic `Option<&String>` is not
// available here.
#[allow(clippy::ref_option)]
fn registration_id_is_absent(value: &Option<String>) -> bool {
    value.as_deref().is_none_or(str::is_empty)
}

/// Caps `value` at [`MAX_RECORD_FIELD_BYTES`] without splitting a UTF-8
/// sequence, recording the original digest and length in `slot` when it
/// had to be shortened.
fn bound_field(value: String, slot: &mut Option<TruncationDigest>) -> String {
    if value.len() <= MAX_RECORD_FIELD_BYTES {
        *slot = None;
        return value;
    }
    *slot = Some(TruncationDigest {
        full_sha256: sha256_hex(value.as_bytes()),
        // Infallible on every target this crate builds for; a length
        // that somehow did not fit would still have to produce *some*
        // record, and the saturating value cannot be mistaken for a
        // real one.
        full_bytes: u64::try_from(value.len()).unwrap_or(u64::MAX),
    });
    let mut end = MAX_RECORD_FIELD_BYTES;
    // `is_char_boundary(0)` is always true, so this terminates.
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut shortened = value;
    shortened.truncate(end);
    shortened
}

/// Nanoseconds in one millisecond, the precision a record's `ts` is
/// held to.
const NANOS_PER_MILLISECOND: u32 = 1_000_000;

/// Returns `ts` in the one shape [`AuditRecordStore::append`] accepts:
/// at the UTC offset the format writes, with any sub-millisecond
/// remainder removed.
///
/// A clock reading is nanosecond-precise and may be at any offset,
/// while the format holds a UTC millisecond. Both conversions happen
/// here, before the record exists, rather than inside the store: a
/// record that reached disk having quietly lost part of its `ts`, or
/// having had its offset rewritten under it, no longer reads back as
/// the value its caller held.
///
/// # Panics
///
/// Does not panic. Rounding a valid nanosecond-of-second down to a
/// whole millisecond leaves it inside the range it came from, which is
/// the only way the replacement below can fail.
#[must_use]
pub fn canonical_timestamp(ts: OffsetDateTime) -> OffsetDateTime {
    let utc = ts.to_offset(UtcOffset::UTC);
    let whole = utc.nanosecond() / NANOS_PER_MILLISECOND * NANOS_PER_MILLISECOND;
    utc.replace_nanosecond(whole)
        // Rounding a valid nanosecond-of-second down to a whole
        // millisecond cannot leave the 0..1_000_000_000 range it came
        // from.
        .expect("a truncated nanosecond is still a valid nanosecond")
}

/// Reports whether `ts` carries no precision finer than the
/// millisecond the format writes.
#[must_use]
fn is_millisecond_aligned(ts: OffsetDateTime) -> bool {
    ts.nanosecond().is_multiple_of(NANOS_PER_MILLISECOND)
}

/// Formats `ts` as an RFC 3339 UTC timestamp at exactly millisecond
/// precision, which is the one spelling the record format accepts.
///
/// Written out by hand rather than through a format description so the
/// subsecond field is always three digits: the well-known RFC 3339
/// description emits as many digits as the value happens to carry, and
/// a format whose width moved with the value would not be pinnable.
///
/// A value that is not already canonical — finer than a millisecond,
/// or at an offset other than UTC — is converted here, so this stays a
/// total function on `OffsetDateTime`. Nothing on the durable path
/// relies on that conversion: [`AuditRecordStore::append`] refuses
/// such a record outright, and both builders put `ts` through
/// [`canonical_timestamp`] first. A record that reached this function
/// needing conversion would be one whose written line no longer reads
/// back as the value its caller held, which is exactly what append
/// will not allow.
#[must_use]
pub fn format_millisecond_rfc3339(ts: OffsetDateTime) -> String {
    let utc = ts.to_offset(UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second(),
        utc.millisecond()
    )
}

mod millisecond_rfc3339 {
    use serde::de::Error as _;
    use serde::{Deserialize as _, Deserializer, Serializer};
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    pub(super) fn serialize<S>(value: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&super::format_millisecond_rfc3339(*value))
    }

    /// Reads the one spelling the format writes, and only that one.
    ///
    /// RFC 3339 admits a great deal this format does not: any offset,
    /// a lowercase `z`, `+00:00` for UTC, and any number of subsecond
    /// digits. Accepting those would make the reader disagree with the
    /// writer about what a record's `ts` is — a line saying
    /// `...T21:34:56.789+09:00` would deserialize into a record this
    /// store would then refuse to append. So the parsed value is
    /// formatted back and compared: anything that is not byte-for-byte
    /// what [`super::format_millisecond_rfc3339`] would have produced
    /// is not a line this store wrote, and is rejected as such.
    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        let parsed = OffsetDateTime::parse(&raw, &Rfc3339).map_err(D::Error::custom)?;
        if super::format_millisecond_rfc3339(parsed) != raw {
            return Err(D::Error::custom(format!(
                "expected an RFC 3339 UTC timestamp at millisecond precision, \
                 spelled as in `2026-08-23T12:34:56.789Z`, found `{raw}`"
            )));
        }
        Ok(parsed)
    }
}

// ---------------------------------------------------------------------
// The verb-layer bridge
// ---------------------------------------------------------------------

/// Conversions from the verb layer's in-process outcome types into
/// record values.
///
/// Kept here, beside the format, rather than in the verb layer: there
/// is one definition of "which reason is this" in the repository and a
/// second copy in `verbs.rs` would drift from the format it is supposed
/// to spell.
// Transitional. The sibling issue that writes intent and outcome
// records around the two verbs is the first production caller of every
// function here; until it lands nothing but this module's own tests
// calls them. Widening them to `pub` to silence the lint would put a
// crate-private control plane's refusal taxonomy on the library's
// public surface, which is the opposite of what the visibility rule
// asks for.
#[allow(dead_code)]
pub(crate) mod bridge {
    use super::{AuditOutcome, RefusalReason};
    use crate::registrar::RegistrarError;
    use crate::registrar::verbs::outcome::{DeregisterKind, MintKind, VerbError};
    use crate::registrar::verbs::wrap_ttl::WrapTtlRefusal;

    /// Returns the record outcome for a successful mint.
    pub(crate) fn mint_outcome(kind: MintKind) -> AuditOutcome {
        match kind {
            MintKind::FirstMint => AuditOutcome::FirstMint,
            MintKind::IdempotentReMint => AuditOutcome::IdempotentReMint,
        }
    }

    /// Returns the record outcome for a successful deregister.
    pub(crate) fn deregister_outcome(kind: DeregisterKind) -> AuditOutcome {
        match kind {
            DeregisterKind::IdentityRemoved => AuditOutcome::IdentityRemoved,
            DeregisterKind::AlreadyAbsent => AuditOutcome::AlreadyAbsent,
        }
    }

    /// Returns the record outcome for a refusal: its flattened reason
    /// and the operator-facing detail that goes with it.
    ///
    /// The detail is the refusal's *own* message and never a formatted
    /// error chain. `VerbError::Unavailable` is taken from its explicit
    /// `activity` field rather than its `Display`, so its `anyhow`
    /// source — which can carry anything at all, including values from
    /// other systems — cannot reach a durable record even if that
    /// `Display` were later changed to interpolate it.
    pub(crate) fn refusal_outcome(error: &VerbError) -> AuditOutcome {
        let (reason, detail) = match error {
            VerbError::ReservedServiceName { .. } => {
                (RefusalReason::ReservedServiceName, Some(error.to_string()))
            }
            VerbError::Registrar(inner) => (registrar_reason(inner), Some(inner.to_string())),
            VerbError::RegistrationIdCollision { .. } => (
                RefusalReason::RegistrationIdCollision,
                Some(error.to_string()),
            ),
            VerbError::StoredSpecConflict { .. } => {
                (RefusalReason::StoredSpecConflict, Some(error.to_string()))
            }
            VerbError::HostMismatch { .. } => {
                (RefusalReason::HostMismatch, Some(error.to_string()))
            }
            VerbError::InvalidWrapTtl(inner) => (wrap_ttl_reason(*inner), Some(inner.to_string())),
            VerbError::Unavailable { activity, .. } => {
                (RefusalReason::Unavailable, Some(activity.clone()))
            }
        };
        AuditOutcome::Refused { reason, detail }
    }

    /// Flattens every refusal the config loader and the derivation
    /// library produce.
    fn registrar_reason(error: &RegistrarError) -> RefusalReason {
        match error {
            RegistrarError::ConfigUnreadable { .. } => RefusalReason::ConfigUnreadable,
            RegistrarError::FingerprintLineMalformed { .. } => {
                RefusalReason::FingerprintLineMalformed
            }
            RegistrarError::FingerprintMismatch { .. } => RefusalReason::FingerprintMismatch,
            RegistrarError::ConfigMalformed { .. } => RefusalReason::ConfigMalformed,
            RegistrarError::UnsupportedSchemaVersion { .. } => {
                RefusalReason::UnsupportedSchemaVersion
            }
            RegistrarError::UnknownMultiplicity { .. } => RefusalReason::UnknownMultiplicity,
            RegistrarError::UnknownReloadKind { .. } => RefusalReason::UnknownReloadKind,
            RegistrarError::InvalidReloadTarget { .. } => RefusalReason::InvalidReloadTarget,
            RegistrarError::InvalidDomain { .. } => RefusalReason::InvalidDomain,
            RegistrarError::InvalidComponentKey { .. } => RefusalReason::InvalidComponentKey,
            RegistrarError::InvalidServiceName { .. } => RefusalReason::InvalidServiceName,
            RegistrarError::InvalidHost { .. } => RefusalReason::InvalidHost,
            RegistrarError::ComponentNotConfigured { .. } => RefusalReason::ComponentNotConfigured,
            RegistrarError::ServiceInstanceMismatch { .. } => {
                RefusalReason::ServiceInstanceMismatch
            }
            RegistrarError::DerivedKeyInvalid { .. } => RefusalReason::DerivedKeyInvalid,
            RegistrarError::SpecIdentityDisagreement { .. } => {
                RefusalReason::SpecIdentityDisagreement
            }
            RegistrarError::ServiceSpecOutsideSafeSet { .. } => {
                RefusalReason::ServiceSpecOutsideSafeSet
            }
        }
    }

    /// Flattens every wrap-TTL refusal.
    fn wrap_ttl_reason(refusal: WrapTtlRefusal) -> RefusalReason {
        match refusal {
            WrapTtlRefusal::Zero => RefusalReason::Zero,
            WrapTtlRefusal::Negative => RefusalReason::Negative,
            WrapTtlRefusal::NotWholeSeconds => RefusalReason::NotWholeSeconds,
            WrapTtlRefusal::ExceedsOpenBaoRange => RefusalReason::ExceedsOpenBaoRange,
        }
    }
}

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

/// What was wrong with an audited path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathCondition {
    /// The path is a symbolic link. Never followed, never replaced.
    Symlink,
    /// The path exists but is not a directory.
    NotADirectory,
    /// The path exists but is not a regular file.
    NotARegularFile,
    /// The path is owned by the wrong uid.
    Owner {
        /// The uid the store requires.
        expected: u32,
        /// The uid the path actually has.
        found: u32,
    },
    /// The directory is writable by its group or by the world.
    GroupOrWorldWritable {
        /// The permission bits the directory actually has.
        mode: u32,
    },
}

impl fmt::Display for PathCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Symlink => f.write_str("it is a symbolic link"),
            Self::NotADirectory => f.write_str("it is not a directory"),
            Self::NotARegularFile => f.write_str("it is not a regular file"),
            Self::Owner { expected, found } => {
                write!(f, "it is owned by uid {found}, not uid {expected}")
            }
            Self::GroupOrWorldWritable { mode } => {
                write!(f, "its mode {mode:04o} is group- or world-writable")
            }
        }
    }
}

/// Every failure the registrar audit record store produces.
///
/// Each one is individually matchable on purpose: opening a store that
/// is not safe to write to, an append that did not land, a `sync_data`
/// that did not return, a rotation the pending record required but that
/// did not complete, and a directory flush a new name required are
/// different operational problems with different responses.
#[derive(Debug, thiserror::Error)]
pub enum AuditStoreError {
    /// A configured value cannot produce a usable store.
    #[error("registrar audit setting {setting} is invalid: {message}")]
    InvalidSetting {
        /// The `[registrar]` key at fault.
        setting: &'static str,
        /// Why it was refused.
        message: String,
    },

    /// A directory the store needs could not be created.
    #[error("failed to create the registrar audit directory {path}")]
    CreateDirectory {
        /// The directory that could not be created.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },

    /// A path the store must audit could not be inspected.
    #[error("failed to inspect the registrar audit path {path}")]
    Inspect {
        /// The path that could not be inspected.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },

    /// A path the store must audit is not safe to use.
    #[error("refusing the registrar audit path {path}: {condition}")]
    UnsafePath {
        /// The rejected path.
        path: PathBuf,
        /// What was wrong with it.
        condition: PathCondition,
    },

    /// The active file could not be opened or created.
    #[error("failed to open the registrar audit file {path}")]
    OpenActiveFile {
        /// The active file's path.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },

    /// The record could not be written.
    #[error("failed to append a registrar audit record to {path}")]
    Append {
        /// The active file's path.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },

    /// Part of the record reached the file, the write then failed, and
    /// the partial bytes were not demonstrably taken back off again.
    ///
    /// Two failures land here, because both leave the same doubt. The
    /// truncation itself can fail, in which case the active file ends
    /// in an incomplete line right now and the next append extends it
    /// rather than starting a new one. Or the truncation can succeed
    /// and the flush that makes its new length durable can fail, in
    /// which case this process reads a whole trail but a power failure
    /// before the next flush can bring the partial bytes back. It is
    /// reported apart from [`AuditStoreError::Append`] because that one
    /// promises neither can happen.
    #[error(
        "failed to undo a partial write to the registrar audit file {path} back to \
         {length} bytes, which can leave an incomplete line: {message}"
    )]
    PartialAppend {
        /// The active file's path.
        path: PathBuf,
        /// The length the file had before the write, and was not
        /// demonstrably returned to.
        length: u64,
        /// What went wrong, starting with the write that failed.
        message: String,
    },

    /// The record was written but could not be flushed to stable
    /// storage, so it is not durable and the append did not succeed.
    #[error("failed to sync the registrar audit file {path}")]
    Sync {
        /// The active file's path.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },

    /// The pending record required a rotation that did not complete, so
    /// no record was written.
    ///
    /// Every step of a rotation lands here, the directory flush its two
    /// new names need included. That flush failing is
    /// [`AuditStoreError::DirectorySync`] only when it follows a record
    /// that was written; inside a rotation nothing has been written
    /// yet, and the two say opposite things about whether retrying the
    /// record duplicates it.
    #[error("failed to rotate the registrar audit file {path}: {message}")]
    Rotate {
        /// The path the rotation was operating on.
        path: PathBuf,
        /// What went wrong.
        message: String,
    },

    /// A new directory entry could not be flushed, so it could be lost
    /// to a power failure.
    ///
    /// Returned only once the record itself is written and flushed, so
    /// retrying it would write it twice. A flush that fails during a
    /// rotation is an [`AuditStoreError::Rotate`] instead, because no
    /// record has been written at that point.
    #[error("failed to flush the registrar audit directory holding {path}: {message}")]
    DirectorySync {
        /// The file whose new directory entry needed flushing.
        path: PathBuf,
        /// What went wrong.
        message: String,
    },

    /// The record does not fit in an empty file of the configured size.
    ///
    /// Decided from the serialized length alone, before the store opens
    /// or creates anything, so the refusal leaves the directory exactly
    /// as it found it.
    #[error("a registrar audit record of {bytes} bytes exceeds the {limit}-byte file limit")]
    RecordTooLarge {
        /// The serialized record's length.
        bytes: usize,
        /// The configured `audit_max_file_bytes`.
        limit: u64,
    },

    /// A retained generation could not be deleted.
    #[error("failed to remove the retained registrar audit generation {path}")]
    RemoveGeneration {
        /// The generation that could not be deleted.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },

    /// The record does not carry the format version this build writes.
    ///
    /// The store owns what a durable line says, exactly as it owns the
    /// byte caps: `record_version` is a public field, so a record that
    /// arrives at another version is refused here rather than written
    /// under a version no reader of this format is prepared for.
    #[error(
        "refusing a registrar audit record at format version {version}; \
         this build writes version {expected}"
    )]
    UnsupportedRecordVersion {
        /// The version the record carried.
        version: u32,
        /// The only version this build writes.
        expected: u32,
    },

    /// The record's `phase` and its `outcome` field contradict each
    /// other.
    ///
    /// Both fields are public, so a record built by hand or
    /// deserialized from somewhere else can claim to be an `intent`
    /// line while carrying an outcome, or an `outcome` line while
    /// carrying none. Neither shape is in the documented format, and
    /// refusing them here is the same rule as the version check: what a
    /// durable line may say is the store's to decide, not its caller's.
    #[error("refusing a registrar audit record: an {phase} line {requirement}")]
    InconsistentPhase {
        /// The phase the record declared.
        phase: AuditPhase,
        /// What that phase requires of `outcome`, and this record did
        /// not do.
        requirement: &'static str,
    },

    /// The record's `ts` carries an offset other than UTC, which the
    /// format does not write.
    ///
    /// `ts` is a public field of an offset-carrying type, so a record
    /// built by hand can hold a local-time offset. The line has only
    /// one spelling and it is UTC, so writing such a record would
    /// rewrite `21:34:56.789+09:00` to `12:34:56.789Z` on the way to
    /// disk: the same instant, but no longer the wall-clock reading
    /// its caller held, and no longer a value the line reads back as.
    /// It is refused here instead. Both builders put the value through
    /// [`canonical_timestamp`], which is what a caller holding a clock
    /// reading should do.
    #[error(
        "refusing a registrar audit record whose timestamp {ts} is at offset {offset}: \
         the format holds UTC timestamps only"
    )]
    NonUtcTimestamp {
        /// The timestamp the record carried.
        ts: OffsetDateTime,
        /// Its offset, which is not UTC.
        offset: UtcOffset,
    },

    /// The record's `ts` carries precision finer than a millisecond,
    /// which the format cannot hold.
    ///
    /// `ts` is a public field of a nanosecond-precise type, so a record
    /// built by hand can carry a remainder the line has no room for.
    /// Writing it anyway would silently drop the digits and leave a
    /// durable line that no longer deserializes back to the record that
    /// produced it, so it is refused here instead. Both builders align
    /// the value through [`canonical_timestamp`], which is what a
    /// caller holding a clock reading should do.
    #[error(
        "refusing a registrar audit record whose timestamp {ts} carries {nanosecond} ns: \
         the format holds millisecond precision only"
    )]
    UnalignedTimestamp {
        /// The timestamp the record carried.
        ts: OffsetDateTime,
        /// Its nanosecond-of-second, which is not a whole millisecond.
        nanosecond: u32,
    },

    /// The record could not be serialized.
    #[error("failed to serialize a registrar audit record")]
    Serialize(#[source] serde_json::Error),

    /// The blocking filesystem task did not run to completion.
    #[error("the registrar audit store's filesystem task failed: {message}")]
    TaskJoin {
        /// What the runtime reported.
        message: String,
    },
}

// ---------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------

/// The fixed values a store is opened with.
///
/// Every one of them comes from the daemon's own configuration. None is
/// reachable from a registrar request.
// Transitional, exactly like the bridge above. This codebase does not
// construct a registrar verb service outside tests yet, so the
// provisioner that opens a store from the daemon's `[registrar]` table
// does not exist and nothing but this module's own tests reaches the
// construction path. Publishing it instead would put the daemon's
// filesystem trust boundary on the library's public surface, where any
// consumer could open a store over a directory of its choosing.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct AuditStoreSettings {
    /// The absolute directory the file family lives in.
    pub(crate) dir: PathBuf,
    /// The size at which the active file is rotated.
    pub(crate) max_file_bytes: u64,
    /// How many rotated generations are retained beside it.
    pub(crate) max_retained_files: u32,
}

struct StoreInner {
    dir: PathBuf,
    active_path: PathBuf,
    max_file_bytes: u64,
    max_retained_files: u32,
    expected_uid: u32,
    /// Serializes append-and-sync, and owns the blocking task running
    /// one. Held for exactly that operation and never across a verb
    /// lock or an `OpenBao` call.
    ///
    /// The handle lives *inside* the lock rather than on the awaiting
    /// future's stack because [`AuditRecordStore::append`] can be
    /// cancelled: a losing `select!` branch or a dropped request future
    /// takes the guard with it while the blocking work it spawned keeps
    /// going — `spawn_blocking` work cannot be aborted. Kept here, the
    /// handle outlives the future that made it, so the next append
    /// finds it under the same lock and waits for it instead of
    /// starting a second write into the same file. Nothing can hold
    /// this lock while a blocking append is still live.
    append_lock: TokioMutex<Option<JoinHandle<Result<(), AuditStoreError>>>>,
    /// Set when this store creates a name in its directory — the active
    /// file, or a rotated generation — and cleared only by a directory
    /// flush that succeeded. A failed flush therefore stays owed: the
    /// next append flushes the directory again instead of concluding,
    /// from the file already being there, that its entry is durable.
    ///
    /// The debt is process-local and cannot be otherwise: nothing on
    /// disk distinguishes a flushed directory entry from an unflushed
    /// one. A store that is dropped owing a flush therefore hands the
    /// debt to [`StoreInner::prepare`], which flushes the directory
    /// once on every open rather than trusting the flag it starts out
    /// with.
    pending_dir_sync: AtomicBool,
    /// Keeps a throwaway store directory alive for exactly as long as
    /// the handles writing into it. Only
    /// [`AuditRecordStore::open_temporary`] ever sets it; a production
    /// store is opened over an operator-provisioned directory that
    /// outlives the process.
    #[cfg(test)]
    tempdir: Option<tempfile::TempDir>,
    /// Test-only fault switches.
    #[cfg(test)]
    faults: FaultInjection,
}

/// Switches a test flips to make one filesystem step fail.
///
/// A failed `sync_data` or a failed directory flush cannot be provoked
/// from outside the process, and "the write returned an error" is
/// exactly the case the store must not report as success — so the
/// switches exist rather than leaving those branches untested. Every
/// check that reads one is `#[cfg(test)]`, so a shipped build contains
/// neither the field nor the branch and has no way at all to be told to
/// fail.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct FaultInjection {
    /// Fail the record write before any of it reaches the file.
    pub(crate) append: std::sync::atomic::AtomicBool,
    /// Fail the record write *after* part of the line has reached the
    /// file, which is what a short device or a signal produces and what
    /// `write_all` reports as one plain error.
    pub(crate) partial_append: std::sync::atomic::AtomicBool,
    /// Fail the truncation that takes those partial bytes back off.
    pub(crate) truncate: std::sync::atomic::AtomicBool,
    /// Fail the flush that makes that truncation durable, which is the
    /// difference between the partial bytes being gone and only looking
    /// gone until the next power failure.
    pub(crate) recovery_sync: std::sync::atomic::AtomicBool,
    /// Fail the `sync_data` that makes the record durable.
    pub(crate) sync: std::sync::atomic::AtomicBool,
    /// Fail a rotation the pending record required.
    pub(crate) rotate: std::sync::atomic::AtomicBool,
    /// Fail the directory flush a new name required.
    pub(crate) directory_sync: std::sync::atomic::AtomicBool,
    /// Hold the blocking half of every append open until a test lets
    /// it go.
    pub(crate) gate: std::sync::Mutex<Option<AppendGate>>,
    /// Blocking appends inside their critical section right now.
    live_appends: std::sync::atomic::AtomicUsize,
    /// The most that were ever in it at once, which is the number the
    /// store's serialization guarantee is about.
    peak_appends: std::sync::atomic::AtomicUsize,
}

/// A test's hold on the blocking half of an append.
///
/// What the store serializes is filesystem work on a blocking thread,
/// not the future awaiting it — so a test that has to prove a cancelled
/// append still owns the lock needs a way to stop that work in the
/// middle of it and look.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct AppendGate {
    /// Signalled once per blocking append, as it enters.
    entered: tokio::sync::mpsc::UnboundedSender<()>,
    /// Holds it there until the test sends it on. Shared rather than
    /// owned by the gate, so waiting on it does not also hold the gate
    /// itself and hide a second append behind the first.
    release: Arc<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>,
}

#[cfg(test)]
impl AppendGate {
    /// Builds a gate and the two ends a test drives it from: entry
    /// notifications, and the sender that releases one waiting append
    /// per value.
    pub(crate) fn new() -> (
        Self,
        tokio::sync::mpsc::UnboundedReceiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (entered, entries) = tokio::sync::mpsc::unbounded_channel();
        let (releases, release) = std::sync::mpsc::channel();
        (
            Self {
                entered,
                release: Arc::new(std::sync::Mutex::new(release)),
            },
            entries,
            releases,
        )
    }
}

/// Counts one blocking append for as long as it is in its critical
/// section, however it leaves.
#[cfg(test)]
struct AppendPresence<'a> {
    faults: &'a FaultInjection,
}

#[cfg(test)]
impl Drop for AppendPresence<'_> {
    fn drop(&mut self) {
        self.faults
            .live_appends
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
impl FaultInjection {
    fn armed(flag: &std::sync::atomic::AtomicBool) -> bool {
        flag.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Records a blocking append entering its critical section, and
    /// holds it there while a test's gate is closed.
    ///
    /// The count is taken before the gate, so an append that should
    /// never have started is counted even if it then blocks.
    fn enter_append(&self) -> AppendPresence<'_> {
        use std::sync::atomic::Ordering::SeqCst;

        let live = self.live_appends.fetch_add(1, SeqCst) + 1;
        self.peak_appends.fetch_max(live, SeqCst);
        let presence = AppendPresence { faults: self };
        // Both ends are taken out from under the gate lock before
        // anything is waited on, so a second append blocks where the
        // test can see it rather than behind the gate itself.
        let ends = self
            .gate
            .lock()
            .expect("the gate mutex is never poisoned")
            .as_ref()
            .map(|gate| (gate.entered.clone(), Arc::clone(&gate.release)));
        if let Some((entered, release)) = ends {
            // Announced before waiting, so an append that should never
            // have started is visible even when it then queues behind
            // another one. A send error is ignored on purpose: a test
            // that has stopped watching must not panic a store thread.
            let _ = entered.send(());
            let release = release.lock().expect("the release mutex is never poisoned");
            let _ = release.recv();
        }
        presence
    }

    /// Returns the most blocking appends that were ever in their
    /// critical section at the same moment.
    pub(crate) fn peak_concurrent_appends(&self) -> usize {
        self.peak_appends.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// A handle on the daemon's append-only registrar audit record store.
///
/// Cloning is cheap and every clone shares one serialization lock, so a
/// handle can be held by whatever constructs the registrar surface and
/// cloned into the verb layer without two writers racing.
#[derive(Clone)]
pub struct AuditRecordStore {
    inner: Arc<StoreInner>,
}

impl fmt::Debug for AuditRecordStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditRecordStore")
            .field("dir", &self.inner.dir)
            .field("max_file_bytes", &self.inner.max_file_bytes)
            .field("max_retained_files", &self.inner.max_retained_files)
            .finish_non_exhaustive()
    }
}

impl AuditRecordStore {
    /// Opens the store, creating whatever is missing and refusing
    /// whatever is not safe to write to.
    ///
    /// Production requires every audited path to be owned by uid 0.
    ///
    /// # Errors
    ///
    /// Returns [`AuditStoreError`] if a setting is unusable, a
    /// directory cannot be created, an audited path is a symlink, is
    /// owned by another uid or is group- or world-writable, an
    /// already-oversized active file cannot be rotated, or the store
    /// directory cannot be flushed — which is what settles a directory
    /// entry an earlier process created and never made durable.
    #[allow(dead_code)] // Transitional; see `AuditStoreSettings`.
    pub(crate) async fn open(settings: AuditStoreSettings) -> Result<Self, AuditStoreError> {
        Self::open_as(settings, PRODUCTION_UID).await
    }

    /// Opens a store over a caller-provided directory, accepting the
    /// test process's own uid instead of uid 0.
    ///
    /// Deliberately `#[cfg(test)]`: no configuration key and no
    /// production entry point can relax the uid-0 requirement
    /// [`AuditRecordStore::open`] enforces.
    ///
    /// # Errors
    ///
    /// As [`AuditRecordStore::open`].
    #[cfg(test)]
    pub(crate) async fn open_for_tests(
        settings: AuditStoreSettings,
    ) -> Result<Self, AuditStoreError> {
        Self::open_as(settings, current_uid()).await
    }

    /// Opens a store with its fault switches already flipped, so a test
    /// can make a step of construction itself fail.
    ///
    /// [`AuditRecordStore::faults`] cannot reach the ones `open`
    /// consults: they are read while the handle is still being built,
    /// which is exactly the window a test of the store's own durability
    /// needs to get into.
    ///
    /// # Errors
    ///
    /// As [`AuditRecordStore::open`].
    #[cfg(test)]
    pub(crate) async fn open_for_tests_with_faults(
        settings: AuditStoreSettings,
        faults: FaultInjection,
    ) -> Result<Self, AuditStoreError> {
        let mut inner = Self::build(settings, current_uid())?;
        inner.faults = faults;
        let inner = Arc::new(inner);
        let prepared = Arc::clone(&inner);
        spawn_fs(move || prepared.prepare()).await?;
        Ok(Self { inner })
    }

    /// Opens a store in a throwaway directory the handle itself keeps
    /// alive, for a test that needs a working store but does not care
    /// where it is.
    ///
    /// Synchronous, because the verb-layer fixtures that need one build
    /// their service outside an `async` context.
    ///
    /// # Errors
    ///
    /// As [`AuditRecordStore::open`].
    #[cfg(test)]
    pub(crate) fn open_temporary() -> Result<Self, AuditStoreError> {
        let tempdir = tempfile::tempdir().map_err(|source| AuditStoreError::CreateDirectory {
            path: std::env::temp_dir(),
            source,
        })?;
        // The temporary directory is the store's immediate parent, so
        // it is audited — and `tempfile` creates it under the ambient
        // umask, which is `002` on a Debian-style host and would make
        // it group-writable. Stated here rather than inherited, so a
        // test's result does not depend on the umask it was run under.
        std::fs::set_permissions(tempdir.path(), Permissions::from_mode(STORE_DIR_MODE)).map_err(
            |source| AuditStoreError::CreateDirectory {
                path: tempdir.path().to_path_buf(),
                source,
            },
        )?;
        // A subdirectory rather than the temporary directory itself:
        // the store audits its immediate parent, and the temporary
        // directory's own parent is the world-writable system temporary
        // directory.
        let settings = AuditStoreSettings {
            dir: tempdir.path().join("registrar-audit"),
            max_file_bytes: DEFAULT_AUDIT_MAX_FILE_BYTES,
            max_retained_files: DEFAULT_AUDIT_MAX_RETAINED_FILES,
        };
        let mut inner = Self::build(settings, current_uid())?;
        inner.tempdir = Some(tempdir);
        let inner = Arc::new(inner);
        inner.prepare()?;
        Ok(Self { inner })
    }

    async fn open_as(
        settings: AuditStoreSettings,
        expected_uid: u32,
    ) -> Result<Self, AuditStoreError> {
        let inner = Arc::new(Self::build(settings, expected_uid)?);
        let prepared = Arc::clone(&inner);
        spawn_fs(move || prepared.prepare()).await?;
        Ok(Self { inner })
    }

    /// Validates the settings and assembles the shared state, touching
    /// no filesystem at all.
    fn build(
        settings: AuditStoreSettings,
        expected_uid: u32,
    ) -> Result<StoreInner, AuditStoreError> {
        validate_store_settings(&settings)?;
        Ok(StoreInner {
            active_path: settings.dir.join(ACTIVE_FILE_NAME),
            dir: settings.dir,
            max_file_bytes: settings.max_file_bytes,
            max_retained_files: settings.max_retained_files,
            expected_uid,
            append_lock: TokioMutex::new(None),
            pending_dir_sync: AtomicBool::new(false),
            #[cfg(test)]
            tempdir: None,
            #[cfg(test)]
            faults: FaultInjection::default(),
        })
    }

    /// Rotates the active file now, at a caller-chosen instant, so a
    /// test can drive the collision sequence without waiting on a
    /// clock.
    #[cfg(test)]
    pub(crate) fn rotate_for_test(&self, now: OffsetDateTime) -> Result<PathBuf, AuditStoreError> {
        self.inner.rotate(now)
    }

    /// Runs the retention trim now, reporting a failure the way an
    /// append does: through `tracing`, not to the caller.
    #[cfg(test)]
    pub(crate) fn trim_for_test(&self) {
        self.inner.trim_logging_failures();
    }

    /// Returns the store's test-only fault switches.
    #[cfg(test)]
    pub(crate) fn faults(&self) -> &FaultInjection {
        &self.inner.faults
    }

    /// Reports whether a name this store created is still waiting on a
    /// directory flush, so a test can see the debt outlive a failed one
    /// — and see a reopened store start out owing nothing because its
    /// construction flushed the directory.
    #[cfg(test)]
    pub(crate) fn dir_sync_pending(&self) -> bool {
        self.inner.pending_dir_sync.load(Ordering::SeqCst)
    }

    /// Returns the directory the file family lives in.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.inner.dir
    }

    /// Returns the path appends land in.
    #[must_use]
    pub fn active_path(&self) -> &Path {
        &self.inner.active_path
    }

    /// Appends one complete record as a single newline-terminated JSON
    /// object and returns only after the bytes have been flushed with
    /// `sync_data`.
    ///
    /// Every attacker-influenced string is capped by the store itself
    /// before the line is built, so a caller cannot write an unbounded
    /// value through this. The record's `ts` is preserved exactly as it
    /// was supplied; no clock is read here.
    ///
    /// # Cancellation
    ///
    /// Dropping this future — a losing `select!` branch, a request that
    /// went away — does not stop the write. The filesystem work runs in
    /// a blocking task, which nothing can abort, so cancelling only
    /// abandons the *answer*: the record may still be written, and what
    /// became of it is logged rather than returned. What cancellation
    /// cannot do is let a second append start beside the first. The
    /// store keeps the running task under its own lock, so the next
    /// append waits for the abandoned one before touching the file, and
    /// two appends never overlap however their callers are cancelled.
    /// A store dropped with such a task still running leaves it to the
    /// runtime, which waits for outstanding blocking tasks as it shuts
    /// down rather than tearing one apart mid-record.
    ///
    /// The record is checked against the format before anything is
    /// written. Its fields are public, so a line under a version this
    /// build does not write, one whose `phase` and `outcome`
    /// contradict each other, or one whose `ts` is not already the UTC
    /// millisecond the format holds, is refused rather than made
    /// durable. Refusing the last of those is what makes "preserved
    /// exactly" true: the alternative is writing the value with its
    /// remainder dropped or its offset converted — a line reading
    /// `12:34:56.789Z` for a record that said `21:34:56.789+09:00`,
    /// which no longer reads back as the record that produced it. Both
    /// builders put `ts` through [`canonical_timestamp`], so a caller
    /// holding a clock reading has nothing extra to do.
    ///
    /// # Errors
    ///
    /// Returns [`AuditStoreError`] if the record is not at
    /// [`AUDIT_RECORD_VERSION`], its phase and outcome disagree, its
    /// `ts` is at an offset other than UTC or at a precision finer
    /// than a millisecond, it
    /// cannot be serialized, the active file is not safe to write to, a
    /// rotation this record required did not complete, the write
    /// failed, or the flush failed. Two of them do not leave the trail
    /// exactly as it was:
    ///
    /// - [`AuditStoreError::DirectorySync`] is returned after the
    ///   record has been written and flushed, when a name this store
    ///   created — the active file, or a generation it rotated — could
    ///   not be made durable. The line is there; what may not survive a
    ///   power failure is the directory entry naming the file it is in.
    ///   Retrying the record would therefore write it twice. The flush
    ///   stays owed, so a later append retries it rather than
    ///   concluding from the file already existing that its entry is
    ///   durable — and if the process exits still owing it, opening the
    ///   store again flushes the directory before the first append can
    ///   reach the file. The same flush failing *during* a rotation this
    ///   record required is [`AuditStoreError::Rotate`] instead: no
    ///   record was written there, and retrying is exactly what a
    ///   caller should do.
    /// - [`AuditStoreError::PartialAppend`] means part of the line
    ///   reached the file and either could not be taken back off, or
    ///   was taken back off without that removal reaching stable
    ///   storage — in which case a power failure can bring the partial
    ///   bytes back. Either way the active file may end in an
    ///   incomplete record. Nothing else leaves a half-written line: a
    ///   write that fails after a partial write is undone, and the
    ///   undo flushed, before [`AuditStoreError::Append`] is returned.
    pub async fn append(&self, record: AuditRecord) -> Result<(), AuditStoreError> {
        if record.record_version != AUDIT_RECORD_VERSION {
            return Err(AuditStoreError::UnsupportedRecordVersion {
                version: record.record_version,
                expected: AUDIT_RECORD_VERSION,
            });
        }
        // Exhaustive on purpose: a third phase must be decided about
        // here at compile time rather than fall through a catch-all
        // into the file.
        match (record.phase, record.outcome.is_some()) {
            (AuditPhase::Intent, true) => {
                return Err(AuditStoreError::InconsistentPhase {
                    phase: AuditPhase::Intent,
                    requirement: "must not carry an outcome",
                });
            }
            (AuditPhase::Outcome, false) => {
                return Err(AuditStoreError::InconsistentPhase {
                    phase: AuditPhase::Outcome,
                    requirement: "must carry an outcome",
                });
            }
            (AuditPhase::Intent, false) | (AuditPhase::Outcome, true) => {}
        }
        if !record.ts.offset().is_utc() {
            return Err(AuditStoreError::NonUtcTimestamp {
                ts: record.ts,
                offset: record.ts.offset(),
            });
        }
        if !is_millisecond_aligned(record.ts) {
            return Err(AuditStoreError::UnalignedTimestamp {
                ts: record.ts,
                nanosecond: record.ts.nanosecond(),
            });
        }
        let line = record.into_bounded().to_line()?;
        // Held for the append-and-sync operation only. The blocking
        // work below is the entire critical section, so this guard
        // never spans a verb lock or an `OpenBao` call.
        let mut in_flight = self.inner.append_lock.lock().await;
        // An append whose caller went away left its blocking task
        // running and its handle here. Wait for it before starting
        // another: that task is still writing into the same file, and
        // nothing can abort it.
        Self::settle_abandoned(&mut in_flight).await;
        let inner = Arc::clone(&self.inner);
        let handle = in_flight.insert(tokio::task::spawn_blocking(move || {
            inner.append_blocking(&line)
        }));
        // Awaited *through* the slot rather than taken out of it:
        // dropping this future here has to leave the handle where the
        // next append looks for it.
        let joined = handle.await;
        *in_flight = None;
        match joined {
            Ok(result) => result,
            Err(err) => Err(AuditStoreError::TaskJoin {
                message: err.to_string(),
            }),
        }
    }

    /// Waits for the blocking half of an append whose caller was
    /// cancelled, and reports what it did.
    ///
    /// A cancelled append leaves one record's fate decided by work
    /// nobody is waiting on any more. Dropping that outcome is exactly
    /// the silence the no-orphan-task rule exists to prevent, so it is
    /// logged here — the caller that would have received it is gone.
    ///
    /// Cancel-safe in turn: dropped at its own `await`, it leaves the
    /// handle in the slot for the next append to settle.
    async fn settle_abandoned(in_flight: &mut Option<JoinHandle<Result<(), AuditStoreError>>>) {
        let Some(handle) = in_flight.as_mut() else {
            return;
        };
        let outcome = handle.await;
        *in_flight = None;
        match outcome {
            Ok(Ok(())) => tracing::warn!(
                "a cancelled registrar audit append finished writing its record after its caller went away"
            ),
            Ok(Err(err)) => tracing::error!(
                error = %err,
                "a cancelled registrar audit append failed after its caller went away"
            ),
            Err(err) => tracing::error!(
                error = %err,
                "a cancelled registrar audit append did not complete"
            ),
        }
    }
}

/// Returns the real uid of this process, which is the ownership a
/// test-only store accepts in place of uid 0.
#[cfg(test)]
fn current_uid() -> u32 {
    // SAFETY: `getuid` takes no arguments, reads no memory the caller
    // owns, cannot fail and has no side effects; POSIX specifies it as
    // always successful.
    unsafe { libc::getuid() }
}

/// Runs one batch of synchronous filesystem work off the runtime's
/// worker threads.
async fn spawn_fs<F, T>(work: F) -> Result<T, AuditStoreError>
where
    F: FnOnce() -> Result<T, AuditStoreError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result,
        Err(err) => Err(AuditStoreError::TaskJoin {
            message: err.to_string(),
        }),
    }
}

/// Refuses a configuration that cannot produce a usable store.
fn validate_store_settings(settings: &AuditStoreSettings) -> Result<(), AuditStoreError> {
    if !settings.dir.is_absolute() {
        return Err(AuditStoreError::InvalidSetting {
            setting: "audit_record_dir",
            message: format!("{} is not an absolute path", settings.dir.display()),
        });
    }
    if settings.dir.parent().is_none() {
        return Err(AuditStoreError::InvalidSetting {
            setting: "audit_record_dir",
            message: format!("{} has no parent directory", settings.dir.display()),
        });
    }
    if settings.max_file_bytes < MIN_AUDIT_MAX_FILE_BYTES {
        return Err(AuditStoreError::InvalidSetting {
            setting: "audit_max_file_bytes",
            message: format!(
                "{} is below the {MIN_AUDIT_MAX_FILE_BYTES}-byte minimum",
                settings.max_file_bytes
            ),
        });
    }
    if settings.max_retained_files == 0 {
        return Err(AuditStoreError::InvalidSetting {
            setting: "audit_max_retained_files",
            message: "must retain at least one rotated generation".to_string(),
        });
    }
    Ok(())
}

impl StoreInner {
    /// Creates what is missing, audits what already exists, rotates an
    /// active file that is already at its limit, settles whatever
    /// directory flush an earlier process may still have owed, and
    /// trims the retained generations down to the configured count.
    fn prepare(&self) -> Result<(), AuditStoreError> {
        let Some(parent) = self.dir.parent() else {
            return Err(AuditStoreError::InvalidSetting {
                setting: "audit_record_dir",
                message: format!("{} has no parent directory", self.dir.display()),
            });
        };
        create_ancestors(parent)?;
        // The immediate parent is audited *before* the store directory
        // is created inside it, so a planted symlink or a
        // world-writable parent is refused rather than written through.
        check_directory(parent, self.expected_uid)?;
        create_dir_with_mode(&self.dir, STORE_DIR_MODE)?;
        check_directory(&self.dir, self.expected_uid)?;

        for generation in self.rotated_generations()? {
            check_file(&generation, self.expected_uid)?;
        }

        match std::fs::symlink_metadata(&self.active_path) {
            Ok(meta) => {
                check_metadata_file(&self.active_path, &meta, self.expected_uid)?;
                if meta.len() >= self.max_file_bytes {
                    self.rotate(OffsetDateTime::now_utc())?;
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(AuditStoreError::Inspect {
                    path: self.active_path.clone(),
                    source,
                });
            }
        }

        // The owed-flush debt above lives in this process, so it dies
        // with it: an earlier daemon could have created the active file
        // or renamed a generation, failed the flush that makes that
        // name durable, and exited — and the file being there now says
        // nothing about its directory entry surviving a power failure.
        // One flush per open settles every such name at once, before a
        // single append can look at the file and conclude the entry is
        // already durable. It also covers a name this very `prepare`
        // put there, since the rotation above recreates the active file.
        //
        // Failing it is a construction failure: a store whose directory
        // entries are not durable cannot keep the promise its appends
        // make.
        self.sync_dir(&self.active_path)?;

        self.trim_logging_failures();
        Ok(())
    }

    /// Writes `line`, rotating first when it would push the active file
    /// past its limit.
    fn append_blocking(&self, line: &[u8]) -> Result<(), AuditStoreError> {
        // Counts this operation for as long as it lasts, and lets a
        // test stop it here, so overlapping appends are observable
        // rather than merely improbable.
        #[cfg(test)]
        let _presence = self.faults.enter_append();

        // Infallible on every target this crate builds for; the
        // saturating value only ever forces a refusal or a rotation
        // that would have been forced anyway.
        let pending = u64::try_from(line.len()).unwrap_or(u64::MAX);
        // Decided before the active file is touched, because it is
        // arithmetic rather than a fact about the file: a record longer
        // than the whole file fits neither the file that is there nor
        // the empty one a rotation would put in its place. Opening
        // first would create the active file — a new directory entry
        // owing a flush — on the way to refusing a record that was
        // never going to be written into it, leaving durability work
        // behind for an operation that did nothing.
        if pending > self.max_file_bytes {
            return Err(AuditStoreError::RecordTooLarge {
                bytes: line.len(),
                limit: self.max_file_bytes,
            });
        }

        // Two passes at most: the first may find the file full and
        // rotate, and the second writes into the file that rotation
        // created. A record that the check above let through fits an
        // empty file, so a third pass could add nothing.
        for pass in 0..2 {
            let mut file = self.open_active()?;
            let meta = file.metadata().map_err(|source| AuditStoreError::Inspect {
                path: self.active_path.clone(),
                source,
            })?;
            // Re-audited from the opened descriptor, not from the path
            // that was inspected a moment ago.
            check_metadata_file(&self.active_path, &meta, self.expected_uid)?;

            let projected = meta.len().saturating_add(pending);
            if projected > self.max_file_bytes {
                // The record fits an empty file, so the only way a
                // second pass gets here is a file that rotation did not
                // empty — something outside this store writing into it.
                if pass == 1 {
                    return Err(AuditStoreError::Rotate {
                        path: self.active_path.clone(),
                        message: "the rotated active file is still too full for this record"
                            .to_string(),
                    });
                }
                drop(file);
                self.rotate(OffsetDateTime::now_utc())?;
                self.trim_logging_failures();
                continue;
            }

            if let Err(source) = self.write_record(&mut file, line) {
                // `write_all` can fail with part of the line already in
                // the file, and the next append opens the same file
                // `O_APPEND`: without this the two would run together
                // into one unparseable line and every record after them
                // would be unreadable. The length is the one taken from
                // this descriptor a few lines above, under the same
                // store mutex, so nothing else can have written between
                // the two.
                return Err(self.undo_partial_write(&mut file, meta.len(), source));
            }
            #[cfg(test)]
            if FaultInjection::armed(&self.faults.sync) {
                return Err(AuditStoreError::Sync {
                    path: self.active_path.clone(),
                    source: io::Error::from(io::ErrorKind::Other),
                });
            }
            file.sync_data().map_err(|source| AuditStoreError::Sync {
                path: self.active_path.clone(),
                source,
            })?;
            if self.pending_dir_sync.load(Ordering::SeqCst) {
                // A brand-new active file is a brand-new directory
                // entry: without this the record survives a crash but
                // the name pointing at it may not. The flag outlives a
                // failed flush, so an append that finds the file
                // already there still owes the flush the attempt that
                // created it did not complete.
                self.sync_dir(&self.active_path)?;
            }
            return Ok(());
        }
        Err(AuditStoreError::Rotate {
            path: self.active_path.clone(),
            message: "rotation did not make room for the pending record".to_string(),
        })
    }

    /// Writes the whole line, or reports the write that failed.
    // `self` carries the test-only fault switches this consults; a
    // production build reads nothing from it here.
    #[cfg_attr(not(test), allow(clippy::unused_self))]
    fn write_record(&self, file: &mut File, line: &[u8]) -> Result<(), io::Error> {
        #[cfg(test)]
        if FaultInjection::armed(&self.faults.append) {
            return Err(io::Error::from(io::ErrorKind::StorageFull));
        }
        #[cfg(test)]
        if FaultInjection::armed(&self.faults.partial_append) {
            // Exactly the shape the recovery below exists for: some of
            // the line is in the file and the call still reports an
            // error, which no real device can be made to do on demand.
            file.write_all(&line[..line.len() / 2])?;
            return Err(io::Error::from(io::ErrorKind::StorageFull));
        }
        file.write_all(line)
    }

    /// Puts the active file back to `length` after a write that may
    /// have left part of a line in it, makes that removal durable, and
    /// reports the failure that got here.
    ///
    /// Returns [`AuditStoreError::Append`] when the file is back to
    /// where it was and will still be there after a power failure, and
    /// [`AuditStoreError::PartialAppend`] when either half of that
    /// could not be established, because those two say opposite things
    /// about what the next reader of the file finds.
    fn undo_partial_write(
        &self,
        file: &mut File,
        length: u64,
        source: io::Error,
    ) -> AuditStoreError {
        // Cutting the file back only reaches the page cache. Some of
        // the partial bytes may already have been written back, so
        // without flushing the new length a power failure here can
        // leave exactly the torn line this recovery exists to remove,
        // under an error that promises it is gone.
        match self
            .truncate_active(file, length)
            .and_then(|()| self.sync_recovery(file))
        {
            Ok(()) => AuditStoreError::Append {
                path: self.active_path.clone(),
                source,
            },
            Err(undo) => AuditStoreError::PartialAppend {
                path: self.active_path.clone(),
                length,
                message: format!("{source}; undoing it failed too: {undo}"),
            },
        }
    }

    /// Cuts the active file back to `length`.
    // `self` carries the test-only fault switch this consults; a
    // production build reads nothing from it here.
    #[cfg_attr(not(test), allow(clippy::unused_self))]
    fn truncate_active(&self, file: &mut File, length: u64) -> Result<(), io::Error> {
        #[cfg(test)]
        if FaultInjection::armed(&self.faults.truncate) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        file.set_len(length)
    }

    /// Makes a completed rollback durable.
    ///
    /// `sync_all` rather than `sync_data`, because what has to survive
    /// here is the file's new length, which is metadata: `sync_data` is
    /// only required to persist the metadata needed to read the data
    /// back, and a shorter file has no data to reach.
    // `self` carries the test-only fault switch this consults; a
    // production build reads nothing from it here.
    #[cfg_attr(not(test), allow(clippy::unused_self))]
    fn sync_recovery(&self, file: &File) -> Result<(), io::Error> {
        #[cfg(test)]
        if FaultInjection::armed(&self.faults.recovery_sync) {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        file.sync_all()
    }

    /// Opens the active file for appending, creating it if it is not
    /// there.
    ///
    /// Creating it is attempted first, with `O_CREAT | O_EXCL`, which
    /// the kernel refuses to satisfy through a symbolic link. Opening an
    /// existing one is audited by path first — so a link planted since
    /// the store was opened is reported as the typed refusal it is
    /// rather than as an `errno` — and then opened `O_NOFOLLOW`, which
    /// closes the window between that check and the open.
    ///
    /// Creating it owes the directory a flush, which is recorded before
    /// the caller writes anything: a record that is written and then
    /// fails to flush must not leave the debt behind with it.
    fn open_active(&self) -> Result<File, AuditStoreError> {
        match create_active_file(&self.active_path) {
            Ok(file) => {
                self.pending_dir_sync.store(true, Ordering::SeqCst);
                Ok(file)
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                check_file(&self.active_path, self.expected_uid)?;
                OpenOptions::new()
                    .append(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&self.active_path)
                    .map_err(|source| AuditStoreError::OpenActiveFile {
                        path: self.active_path.clone(),
                        source,
                    })
            }
            Err(source) => Err(AuditStoreError::OpenActiveFile {
                path: self.active_path.clone(),
                source,
            }),
        }
    }

    /// Renames the active file to a fresh generation and puts an empty
    /// active file back in its place.
    ///
    /// Every way this can fail is an [`AuditStoreError::Rotate`],
    /// including the two flushes at the end: a rotation is not
    /// something a record was written into, so no failure of it may
    /// report itself as one that touched a record.
    fn rotate(&self, now: OffsetDateTime) -> Result<PathBuf, AuditStoreError> {
        #[cfg(test)]
        if FaultInjection::armed(&self.faults.rotate) {
            return Err(AuditStoreError::Rotate {
                path: self.active_path.clone(),
                message: "injected rotation failure".to_string(),
            });
        }
        let stamp = rotation_stamp(now);
        let sequence = self.next_sequence(&stamp)?;
        let target = self.dir.join(rotated_file_name(&stamp, sequence));
        std::fs::rename(&self.active_path, &target).map_err(|err| AuditStoreError::Rotate {
            path: self.active_path.clone(),
            message: format!("renaming it to {}: {err}", target.display()),
        })?;
        // Two new names from here on — the generation and the active
        // file put back in its place — and neither is durable until the
        // directory is flushed. Recorded before that flush is attempted
        // so a rotation that fails halfway leaves the debt behind.
        self.pending_dir_sync.store(true, Ordering::SeqCst);
        let file =
            create_active_file(&self.active_path).map_err(|err| AuditStoreError::Rotate {
                path: self.active_path.clone(),
                message: format!("recreating it after rotation: {err}"),
            })?;
        // A flush that fails here is a rotation that did not complete,
        // not an append whose record did not reach the disk: no record
        // has been written at this point, and reporting it as `Sync`
        // would tell a caller the opposite.
        file.sync_all().map_err(|err| AuditStoreError::Rotate {
            path: self.active_path.clone(),
            message: format!("flushing the file recreated after rotation: {err}"),
        })?;
        // One flush covers both new names: the rotated generation and
        // the fresh active file are entries in the same directory.
        //
        // Reported as a rotation failure for the same reason the file
        // flush above is. `DirectorySync` says the record is on disk
        // and only its directory entry is not, which is why `append`
        // tells a caller not to retry it; here nothing has been written
        // yet, and passing that error up would talk a caller out of the
        // retry that is the correct response. The debt itself survives:
        // `sync_dir` clears it only on success, so the next append
        // still owes the flush these two names need.
        self.sync_dir(&self.active_path).map_err(|err| {
            let message = match err {
                AuditStoreError::DirectorySync { message, .. } => message,
                other => other.to_string(),
            };
            AuditStoreError::Rotate {
                path: self.active_path.clone(),
                message: format!("flushing the directory the rotation renamed in: {message}"),
            }
        })?;
        Ok(target)
    }

    /// Returns the next collision sequence for `stamp`, which is
    /// `000000` unless a generation already carries that timestamp.
    fn next_sequence(&self, stamp: &str) -> Result<u32, AuditStoreError> {
        let mut next = 0;
        for path in self.rotated_generations()? {
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some((found_stamp, sequence)) = parse_rotated_name(name) else {
                continue;
            };
            if found_stamp == stamp && sequence >= next {
                next = sequence + 1;
            }
        }
        if next > MAX_SEQUENCE {
            return Err(AuditStoreError::Rotate {
                path: self.active_path.clone(),
                message: format!("every {stamp} collision sequence is already taken"),
            });
        }
        Ok(next)
    }

    /// Returns every rotated generation, sorted lexicographically —
    /// which, given the fixed-width timestamp and sequence, is oldest
    /// first.
    fn rotated_generations(&self) -> Result<Vec<PathBuf>, AuditStoreError> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(AuditStoreError::Inspect {
                    path: self.dir.clone(),
                    source,
                });
            }
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| AuditStoreError::Inspect {
                path: self.dir.clone(),
                source,
            })?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if parse_rotated_name(name).is_some() {
                names.push(name.to_string());
            }
        }
        names.sort_unstable();
        Ok(names.into_iter().map(|name| self.dir.join(name)).collect())
    }

    /// Deletes the lexically oldest generations until at most
    /// `max_retained_files` remain.
    fn trim(&self) -> Result<(), AuditStoreError> {
        let generations = self.rotated_generations()?;
        let retained = usize::try_from(self.max_retained_files).unwrap_or(usize::MAX);
        if generations.len() <= retained {
            return Ok(());
        }
        let excess = generations.len() - retained;
        for path in generations.into_iter().take(excess) {
            std::fs::remove_file(&path).map_err(|source| AuditStoreError::RemoveGeneration {
                path: path.clone(),
                source,
            })?;
        }
        self.sync_dir(&self.active_path)
    }

    /// Flushes the directory holding `path`, so a name created in it
    /// survives a power failure.
    ///
    /// A flush that succeeds settles every name this store has created
    /// in that directory, not only the one that prompted it, so it is
    /// where the pending debt is cleared. A flush that fails clears
    /// nothing.
    fn sync_dir(&self, path: &Path) -> Result<(), AuditStoreError> {
        #[cfg(test)]
        if FaultInjection::armed(&self.faults.directory_sync) {
            return Err(AuditStoreError::DirectorySync {
                path: path.to_path_buf(),
                message: "injected directory flush failure".to_string(),
            });
        }
        sync_parent_dir(path).map_err(|err| AuditStoreError::DirectorySync {
            path: path.to_path_buf(),
            message: format!("{err:#}"),
        })?;
        self.pending_dir_sync.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Trims, reporting a failure through `tracing` instead of failing
    /// the caller.
    ///
    /// Retention is a capacity target; an append that fits the current
    /// file is correct whether or not an old generation could be
    /// deleted, and refusing it would turn a full disk into a silent
    /// hole in the audit trail.
    fn trim_logging_failures(&self) {
        if let Err(err) = self.trim() {
            tracing::warn!(
                directory = %self.dir.display(),
                error = %err,
                "failed to trim retained registrar audit generations"
            );
        }
    }
}

// ---------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------

/// Creates every missing component of `path` at [`ANCESTOR_DIR_MODE`],
/// leaving whatever already exists exactly as it is.
fn create_ancestors(path: &Path) -> Result<(), AuditStoreError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        if current.parent().is_none() {
            // The filesystem root is nobody's to create.
            continue;
        }
        create_dir_with_mode(&current, ANCESTOR_DIR_MODE)?;
    }
    Ok(())
}

/// Creates `path` at `mode`, and does nothing at all when it already
/// exists.
fn create_dir_with_mode(path: &Path, mode: u32) -> Result<(), AuditStoreError> {
    match DirBuilder::new().mode(mode).create(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
        Err(source) => {
            return Err(AuditStoreError::CreateDirectory {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    // `mkdir` masks its mode with the process umask, so the directory
    // this store just created may be tighter than the mode the format
    // documents. Restating it here applies only to a directory that did
    // not exist a line ago, so no pre-existing entry is touched.
    std::fs::set_permissions(path, Permissions::from_mode(mode)).map_err(|source| {
        AuditStoreError::CreateDirectory {
            path: path.to_path_buf(),
            source,
        }
    })
}

/// Creates the active file at [`ACTIVE_FILE_MODE`], stating that mode
/// rather than leaving it to the process umask.
///
/// `O_CREAT | O_EXCL` is what makes this safe against a planted name:
/// the kernel refuses to satisfy it through a symbolic link, and it
/// fails outright on a file that already exists. What it is *not* safe
/// against is the umask, which `open(2)` subtracts from the mode it is
/// given: under `0277` the file the store just created would be `0400`,
/// which is neither the mode the format documents nor one the daemon
/// can reopen for the next append. Restating it on the descriptor opens
/// no window — the file was never more permissive than `0600` — and
/// touches only a file created a line above, so no existing entry can
/// be reached this way.
fn create_active_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .create_new(true)
        .append(true)
        .mode(ACTIVE_FILE_MODE)
        .open(path)?;
    file.set_permissions(Permissions::from_mode(ACTIVE_FILE_MODE))?;
    Ok(file)
}

/// Audits a directory: never a symlink, owned by `expected_uid`, and
/// not writable by group or world.
fn check_directory(path: &Path, expected_uid: u32) -> Result<(), AuditStoreError> {
    // `symlink_metadata` does not follow the final component, so a
    // planted link is seen as a link rather than as whatever it points
    // at.
    let meta = std::fs::symlink_metadata(path).map_err(|source| AuditStoreError::Inspect {
        path: path.to_path_buf(),
        source,
    })?;
    match directory_condition(
        meta.file_type().is_symlink(),
        meta.is_dir(),
        meta.uid(),
        meta.mode(),
        expected_uid,
    ) {
        Some(condition) => Err(AuditStoreError::UnsafePath {
            path: path.to_path_buf(),
            condition,
        }),
        None => Ok(()),
    }
}

/// Audits a file by path.
fn check_file(path: &Path, expected_uid: u32) -> Result<(), AuditStoreError> {
    let meta = std::fs::symlink_metadata(path).map_err(|source| AuditStoreError::Inspect {
        path: path.to_path_buf(),
        source,
    })?;
    check_metadata_file(path, &meta, expected_uid)
}

/// Audits a file from metadata that has already been read — from a path
/// with `symlink_metadata`, or from an opened descriptor.
fn check_metadata_file(
    path: &Path,
    meta: &std::fs::Metadata,
    expected_uid: u32,
) -> Result<(), AuditStoreError> {
    match file_condition(
        meta.file_type().is_symlink(),
        meta.is_file(),
        meta.uid(),
        expected_uid,
    ) {
        Some(condition) => Err(AuditStoreError::UnsafePath {
            path: path.to_path_buf(),
            condition,
        }),
        None => Ok(()),
    }
}

/// The whole directory rejection decision, over values rather than over
/// a filesystem, so every branch is reachable in a test that is not
/// root.
fn directory_condition(
    is_symlink: bool,
    is_dir: bool,
    uid: u32,
    mode: u32,
    expected_uid: u32,
) -> Option<PathCondition> {
    if is_symlink {
        return Some(PathCondition::Symlink);
    }
    if !is_dir {
        return Some(PathCondition::NotADirectory);
    }
    if uid != expected_uid {
        return Some(PathCondition::Owner {
            expected: expected_uid,
            found: uid,
        });
    }
    if mode & 0o022 != 0 {
        return Some(PathCondition::GroupOrWorldWritable {
            mode: mode & 0o7777,
        });
    }
    None
}

/// The whole file rejection decision, over values for the same reason.
fn file_condition(
    is_symlink: bool,
    is_file: bool,
    uid: u32,
    expected_uid: u32,
) -> Option<PathCondition> {
    if is_symlink {
        return Some(PathCondition::Symlink);
    }
    if !is_file {
        return Some(PathCondition::NotARegularFile);
    }
    if uid != expected_uid {
        return Some(PathCondition::Owner {
            expected: expected_uid,
            found: uid,
        });
    }
    None
}

/// Formats the UTC, second-precision timestamp half of a rotated
/// generation's name.
fn rotation_stamp(now: OffsetDateTime) -> String {
    let utc = now.to_offset(UtcOffset::UTC);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second()
    )
}

/// Composes a rotated generation's name from its timestamp and its
/// collision sequence.
fn rotated_file_name(stamp: &str, sequence: u32) -> String {
    format!("{ROTATED_PREFIX}{stamp}-{sequence:0SEQUENCE_DIGITS$}{FILE_SUFFIX}")
}

/// Splits a rotated generation's name back into its timestamp and its
/// collision sequence, or returns `None` for anything that is not one.
///
/// Both halves are held to their exact documented shape. A name this
/// accepts is validated on opening, counted towards the retained
/// generation limit and, once it is the lexically oldest, deleted by a
/// trim — so a neighbouring file that merely starts `registrar-audit-`
/// and ends `.jsonl` must not be mistaken for one.
fn parse_rotated_name(name: &str) -> Option<(&str, u32)> {
    let body = name
        .strip_prefix(ROTATED_PREFIX)?
        .strip_suffix(FILE_SUFFIX)?;
    let (stamp, sequence) = body.rsplit_once('-')?;
    if sequence.len() != SEQUENCE_DIGITS || !sequence.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if !is_rotation_stamp(stamp) {
        return None;
    }
    Some((stamp, sequence.parse().ok()?))
}

/// Answers whether `stamp` is the exact `YYYYMMDDTHHMMSSZ` UTC form
/// [`rotation_stamp`] writes, naming a real instant.
///
/// The shape carries the lexical ordering the retention policy depends
/// on: fixed-width fields in most-significant-first order. Checking the
/// calendar too costs nothing here and rejects a name that sorts where
/// no such instant ever fell.
fn is_rotation_stamp(stamp: &str) -> bool {
    if stamp.len() != ROTATION_STAMP_LEN
        || stamp.get(8..9) != Some("T")
        || stamp.get(15..16) != Some("Z")
    {
        return false;
    }
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        stamp.get(0..4).and_then(decimal::<i32>),
        stamp.get(4..6).and_then(decimal::<u8>),
        stamp.get(6..8).and_then(decimal::<u8>),
        stamp.get(9..11).and_then(decimal::<u8>),
        stamp.get(11..13).and_then(decimal::<u8>),
        stamp.get(13..15).and_then(decimal::<u8>),
    ) else {
        return false;
    };
    let Ok(month) = Month::try_from(month) else {
        return false;
    };
    Date::from_calendar_date(year, month, day).is_ok()
        && Time::from_hms(hour, minute, second).is_ok()
}

/// Parses `text` when it is nothing but ASCII digits.
///
/// `str::parse` accepts a leading sign, which would let `-1` and `+9`
/// through a fixed-width field that has room for neither.
fn decimal<T: FromStr>(text: &str) -> Option<T> {
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

#[cfg(test)]
mod tests;
