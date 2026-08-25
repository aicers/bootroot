//! Tests for the registrar audit record store and its on-disk format.
//!
//! Two tiers, and the split is deliberate.
//!
//! **Format.** Table-driven golden fixtures that pin the exact bytes of
//! one line, plus the round trip back through the `serde` types. These
//! touch no filesystem at all: the format is a downstream contract, and
//! a test that only asserted "it parses" would let a renamed key ship.
//!
//! **Store.** Everything that needs a real directory, under
//! `tempfile::tempdir()`. Ownership is the test process's own, through
//! the `#[cfg(test)]` constructor; the uid-0 requirement production
//! enforces is asserted separately, on the decision function rather than
//! by running as root.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use tempfile::TempDir;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime, UtcOffset};

use super::bridge::{deregister_outcome, mint_outcome, refusal_outcome};
use super::{
    ACTIVE_FILE_NAME, AUDIT_RECORD_VERSION, AppendGate, AuditOutcome, AuditPhase, AuditRecord,
    AuditRecordStore, AuditStoreError, AuditStoreSettings, AuditVerb, FaultInjection,
    MAX_RECORD_FIELD_BYTES, MAX_SERIALIZED_RECORD_BYTES, MIN_AUDIT_MAX_FILE_BYTES, PathCondition,
    RefusalReason, RequestedIdentity, TruncationDigest, Truncations, canonical_timestamp,
    current_uid, directory_condition, file_condition, format_millisecond_rfc3339,
    parse_rotated_name, rotated_file_name, rotation_stamp,
};
use crate::input_validation::ValidationError;
use crate::registrar::config::{Multiplicity, ReloadKind};
use crate::registrar::error::{RegistrarError, SpecIdentityField};
use crate::registrar::verbs::outcome::{DeregisterKind, MintKind, VerbError};
use crate::registrar::verbs::wrap_ttl::WrapTtlRefusal;
use crate::tls::sha256_hex;

/// A fixed instant every fixture pins, so the bytes never move.
const TS: &str = "2026-08-23T12:34:56.789Z";

/// A caller identity with a `#` and a `/` in it, so the fixtures show an
/// opaque value carried through unchanged.
const CALLER: &str = "spiffe://review/manager#7f3a";

fn ts() -> OffsetDateTime {
    OffsetDateTime::parse(TS, &Rfc3339).expect("the pinned timestamp parses")
}

fn requested(instance: Option<u32>) -> RequestedIdentity {
    RequestedIdentity {
        service_name: "review".to_string(),
        host: "h1".to_string(),
        instance,
    }
}

// ---------------------------------------------------------------------
// Format: golden fixtures
// ---------------------------------------------------------------------

/// One expected line per shape the format has to keep stable.
///
/// Derived from the record values rather than copied out of a captured
/// blob: each entry constructs the record the production types would
/// produce and states the bytes it must serialize to, so a renamed key
/// or a reordered field fails here rather than in a downstream reader.
// One entry per shape; splitting it would only scatter the contract.
#[allow(clippy::too_many_lines)]
fn golden_fixtures() -> Vec<(&'static str, AuditRecord, String)> {
    let mut fixtures: Vec<(&'static str, AuditRecord, String)> = Vec::new();

    fixtures.push((
        "intent with an instance",
        AuditRecord::intent(
            ts(),
            "req-1".to_string(),
            AuditVerb::Mint,
            CALLER.to_string(),
            requested(Some(7)),
        ),
        format!(
            r#"{{"record_version":1,"phase":"intent","ts":"{TS}","request_id":"req-1","verb":"mint","caller_identity":"{CALLER}","requested":{{"service_name":"review","host":"h1","instance":7}}}}"#
        ),
    ));

    fixtures.push((
        "intent with no instance and no derived id",
        AuditRecord::intent(
            ts(),
            "req-2".to_string(),
            AuditVerb::Deregister,
            CALLER.to_string(),
            requested(None),
        ),
        format!(
            r#"{{"record_version":1,"phase":"intent","ts":"{TS}","request_id":"req-2","verb":"deregister","caller_identity":"{CALLER}","requested":{{"service_name":"review","host":"h1"}}}}"#
        ),
    ));

    for (name, verb, outcome, spelling) in [
        (
            "outcome first_mint",
            AuditVerb::Mint,
            AuditOutcome::FirstMint,
            r#"{"class":"first_mint"}"#,
        ),
        (
            "outcome idempotent_remint",
            AuditVerb::Mint,
            AuditOutcome::IdempotentReMint,
            r#"{"class":"idempotent_remint"}"#,
        ),
        (
            "outcome identity_removed",
            AuditVerb::Deregister,
            AuditOutcome::IdentityRemoved,
            r#"{"class":"identity_removed"}"#,
        ),
        (
            "outcome idempotent_already_absent",
            AuditVerb::Deregister,
            AuditOutcome::AlreadyAbsent,
            r#"{"class":"idempotent_already_absent"}"#,
        ),
    ] {
        let verb_name = if matches!(verb, AuditVerb::Mint) {
            "mint"
        } else {
            "deregister"
        };
        fixtures.push((
            name,
            AuditRecord::outcome(
                ts(),
                "req-3".to_string(),
                verb,
                CALLER.to_string(),
                requested(Some(7)),
                Some("review-h1-007".to_string()),
                outcome,
            ),
            format!(
                r#"{{"record_version":1,"phase":"outcome","ts":"{TS}","request_id":"req-3","verb":"{verb_name}","caller_identity":"{CALLER}","requested":{{"service_name":"review","host":"h1","instance":7}},"registration_id":"review-h1-007","outcome":{spelling}}}"#
            ),
        ));
    }

    fixtures.push((
        "refusal with a detail",
        AuditRecord::outcome(
            ts(),
            "req-4".to_string(),
            AuditVerb::Mint,
            CALLER.to_string(),
            requested(None),
            None,
            AuditOutcome::Refused {
                reason: RefusalReason::ComponentNotConfigured,
                detail: Some("component review has no entry in the registrar config".to_string()),
            },
        ),
        format!(
            r#"{{"record_version":1,"phase":"outcome","ts":"{TS}","request_id":"req-4","verb":"mint","caller_identity":"{CALLER}","requested":{{"service_name":"review","host":"h1"}},"outcome":{{"class":"refused","reason":"component_not_configured","detail":"component review has no entry in the registrar config"}}}}"#
        ),
    ));

    fixtures.push((
        "refusal with no detail",
        AuditRecord::outcome(
            ts(),
            "req-5".to_string(),
            AuditVerb::Mint,
            CALLER.to_string(),
            requested(None),
            None,
            AuditOutcome::Refused {
                reason: RefusalReason::ExceedsOpenBaoRange,
                detail: None,
            },
        ),
        format!(
            r#"{{"record_version":1,"phase":"outcome","ts":"{TS}","request_id":"req-5","verb":"mint","caller_identity":"{CALLER}","requested":{{"service_name":"review","host":"h1"}},"outcome":{{"class":"refused","reason":"exceeds_open_bao_range"}}}}"#
        ),
    ));

    // Every one of the four permitted `truncated` field paths at once,
    // so the key names and the digest object's shape are pinned
    // together.
    let long_caller = "A".repeat(600);
    let long_service = "가".repeat(200);
    let long_host = "h".repeat(513);
    let long_detail = "d".repeat(700);
    let mut everything = AuditRecord::outcome(
        ts(),
        "req-6".to_string(),
        AuditVerb::Mint,
        long_caller,
        RequestedIdentity {
            service_name: long_service,
            host: long_host,
            instance: Some(7),
        },
        Some("review-h1-007".to_string()),
        AuditOutcome::Refused {
            reason: RefusalReason::Unavailable,
            detail: Some(long_detail),
        },
    );
    everything = everything.into_bounded();
    let expected_everything = format!(
        concat!(
            r#"{{"record_version":1,"phase":"outcome","ts":"{ts}","request_id":"req-6","#,
            r#""verb":"mint","caller_identity":"{caller}","requested":{{"service_name":"{service}","#,
            r#""host":"{host}","instance":7}},"registration_id":"review-h1-007","#,
            r#""outcome":{{"class":"refused","reason":"unavailable","detail":"{detail}"}},"#,
            r#""truncated":{{"caller_identity":{{"full_sha256":"{caller_digest}","full_bytes":600}},"#,
            r#""requested.service_name":{{"full_sha256":"{service_digest}","full_bytes":600}},"#,
            r#""requested.host":{{"full_sha256":"{host_digest}","full_bytes":513}},"#,
            r#""outcome.detail":{{"full_sha256":"{detail_digest}","full_bytes":700}}}}}}"#
        ),
        ts = TS,
        caller = "A".repeat(512),
        service = "가".repeat(170),
        host = "h".repeat(512),
        detail = "d".repeat(512),
        caller_digest = "277f872a2452b2107bf050002df32bb79ec2603a8e741d45abc4e01d4690dd14",
        service_digest = "92f3b16fca213b4a13931584820344933380682e13b4f34fd58cca290e7d4650",
        host_digest = "05546052f11ed6a0453bbe1a623fcf7516dbe17c4898b88d5363611fdb186b6b",
        detail_digest = "1e18cc4b4378dd3038cf7a218c5181dd758bb3d6d2906cb443aea5e54ed6e94f",
    );
    fixtures.push((
        "every truncated field path",
        everything,
        expected_everything,
    ));

    fixtures
}

#[test]
fn golden_fixtures_pin_exact_bytes_and_round_trip() {
    for (name, record, expected) in golden_fixtures() {
        let rendered = serde_json::to_string(&record).expect("a record serializes");
        assert_eq!(rendered, expected, "{name}");

        let parsed: AuditRecord = serde_json::from_str(&rendered).expect("a record round-trips");
        assert_eq!(parsed, record, "{name}");
        assert_eq!(parsed.record_version, AUDIT_RECORD_VERSION, "{name}");

        let line = record.to_line().expect("a record serializes to a line");
        assert_eq!(line.last().copied(), Some(b'\n'), "{name}");
        assert!(
            !line[..line.len() - 1].contains(&b'\n'),
            "{name}: a record is exactly one line"
        );
    }
}

/// An offset of nine hours, so a shifted value's wall-clock reading
/// differs from its UTC one and a normalisation cannot hide in an
/// instant comparison.
fn plus_nine() -> UtcOffset {
    UtcOffset::from_hms(9, 0, 0).expect("a valid offset")
}

#[test]
fn the_timestamp_is_utc_at_millisecond_precision() {
    let parsed = ts();
    assert_eq!(format_millisecond_rfc3339(parsed), TS);

    // The formatter is total, so it converts a value that is not
    // already canonical. Nothing durable relies on that: `append`
    // refuses such a record outright, which the tests below pin.
    let shifted = parsed.to_offset(plus_nine());
    assert_eq!(format_millisecond_rfc3339(shifted), TS);
    // `OffsetDateTime` equality compares instants, so it says nothing
    // about the offset — the wall-clock reading is what moved.
    assert_eq!(shifted, parsed);
    assert_eq!(shifted.hour(), 21);
    assert_eq!(parsed.hour(), 12);

    // Whole seconds still carry three subsecond digits, so the field
    // width never moves with the value.
    let whole = OffsetDateTime::parse("2026-08-23T12:34:56Z", &Rfc3339).expect("parses");
    assert_eq!(
        format_millisecond_rfc3339(whole),
        "2026-08-23T12:34:56.000Z"
    );
}

#[test]
fn a_clock_reading_is_canonicalized_to_the_formats_shape() {
    let ragged = ts()
        .replace_nanosecond(789_654_321)
        .expect("a valid nanosecond")
        .to_offset(plus_nine());
    let canonical = canonical_timestamp(ragged);
    assert_eq!(canonical, ts());
    assert_eq!(canonical.nanosecond(), 789_000_000);
    assert_eq!(canonical.offset(), UtcOffset::UTC);
    assert_eq!(canonical.hour(), 12);
    // Idempotent, so an already-canonical value is left alone.
    assert_eq!(canonical_timestamp(canonical), canonical);

    // Both builders apply it, so a caller handing over a nanosecond
    // clock reading at a local offset still builds a record the store
    // accepts.
    let intent = AuditRecord::intent(
        ragged,
        "req-1".to_string(),
        AuditVerb::Mint,
        CALLER.to_string(),
        requested(None),
    );
    assert_eq!(intent.ts, ts());
    assert_eq!(intent.ts.offset(), UtcOffset::UTC);
    let outcome = AuditRecord::outcome(
        ragged,
        "req-1".to_string(),
        AuditVerb::Mint,
        CALLER.to_string(),
        requested(None),
        None,
        AuditOutcome::FirstMint,
    );
    assert_eq!(outcome.ts, ts());
    assert_eq!(outcome.ts.offset(), UtcOffset::UTC);
}

/// The format has one spelling, so the reader accepts one spelling.
/// RFC 3339 itself admits a lowercase `z`, `+00:00` for UTC, any other
/// offset, and any number of subsecond digits; a reader taking those
/// would hand back records the writer would then refuse.
#[test]
fn the_format_reader_accepts_only_the_spelling_the_writer_produces() {
    let line = |ts: &str| {
        format!(
            r#"{{"record_version":1,"phase":"intent","ts":"{ts}","request_id":"req-1","verb":"mint","caller_identity":"{CALLER}","requested":{{"service_name":"review","host":"h1"}}}}"#
        )
    };

    let parsed: AuditRecord = serde_json::from_str(&line(TS)).expect("the written spelling parses");
    assert_eq!(parsed.ts, ts());
    assert_eq!(parsed.ts.offset(), UtcOffset::UTC);

    for rejected in [
        // The same instant at a local offset.
        "2026-08-23T21:34:56.789+09:00",
        // The same instant, UTC spelled as a zero offset.
        "2026-08-23T12:34:56.789+00:00",
        // A lowercase zone designator.
        "2026-08-23T12:34:56.789z",
        // Fewer and more subsecond digits than the format writes.
        "2026-08-23T12:34:56.78Z",
        "2026-08-23T12:34:56Z",
        "2026-08-23T12:34:56.789123Z",
        // Not a timestamp at all.
        "yesterday",
    ] {
        let err = serde_json::from_str::<AuditRecord>(&line(rejected))
            .expect_err("a noncanonical timestamp is not readable");
        assert!(
            err.to_string().contains("timestamp") || err.is_data(),
            "expected a timestamp rejection for {rejected}, got {err}"
        );
    }
}

#[test]
fn appending_preserves_the_caller_supplied_timestamp() {
    let store = AuditRecordStore::open_temporary().expect("a temporary store");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        for offset in [0, 3_600, 86_400] {
            let moment = ts() + Duration::seconds(offset);
            let record = AuditRecord::intent(
                moment,
                format!("req-{offset}"),
                AuditVerb::Mint,
                CALLER.to_string(),
                requested(None),
            );
            store.append(record).await.expect("append");
        }
        let written = fs::read_to_string(store.active_path()).expect("read back");
        for (index, line) in written.lines().enumerate() {
            let parsed: AuditRecord = serde_json::from_str(line).expect("a written line parses");
            let expected = ts()
                + Duration::seconds(match index {
                    0 => 0,
                    1 => 3_600,
                    _ => 86_400,
                });
            assert_eq!(parsed.ts, expected);
        }
    });
}

// ---------------------------------------------------------------------
// Format: the flattened refusal table
// ---------------------------------------------------------------------

/// Every variant of the three source enums that a durable line can
/// hold, paired with the record reason it must flatten to.
///
/// The list is the test's definition of "all of them": adding a variant
/// upstream without adding it here leaves `refusal_outcome`'s `match`
/// failing to compile, and adding it here without adding a reason fails
/// the distinctness assertion below.
///
/// Three variants are deliberately **not** in this table and have no
/// [`RefusalReason`]. `VerbError::AuditUnwritable` and
/// `VerbError::PostMintUnrecordable` are produced by a failed record
/// write, so the record that would carry one is the record whose write
/// just failed. `VerbError::Throttled` is produced by the limiter
/// *before* the intent write, on an invocation whose records are
/// suppressed by construction, so it never reaches an outcome write at
/// all. `refusal_outcome` returns `None` for exactly those three, which
/// is covered by
/// [`the_audit_failures_and_the_throttle_are_the_only_unrecordable_refusals`]
/// rather than here.
// One entry per source variant; the exhaustiveness is the point.
#[allow(clippy::too_many_lines)]
fn every_refusal() -> Vec<(VerbError, RefusalReason, &'static str)> {
    fn validation() -> ValidationError {
        ValidationError::Empty
    }
    let registrar = vec![
        (
            RegistrarError::ConfigUnreadable {
                path: PathBuf::from("/etc/clumit-security/provisioning.toml"),
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            },
            RefusalReason::ConfigUnreadable,
            "config_unreadable",
        ),
        (
            RegistrarError::FingerprintLineMalformed {
                path: PathBuf::from("/p"),
            },
            RefusalReason::FingerprintLineMalformed,
            "fingerprint_line_malformed",
        ),
        (
            RegistrarError::FingerprintMismatch {
                path: PathBuf::from("/p"),
                declared: "a".to_string(),
                computed: "b".to_string(),
            },
            RefusalReason::FingerprintMismatch,
            "fingerprint_mismatch",
        ),
        (
            RegistrarError::ConfigMalformed {
                path: PathBuf::from("/p"),
                message: "bad toml".to_string(),
            },
            RefusalReason::ConfigMalformed,
            "config_malformed",
        ),
        (
            RegistrarError::UnsupportedSchemaVersion {
                path: PathBuf::from("/p"),
                found: 9,
                supported: 1,
            },
            RefusalReason::UnsupportedSchemaVersion,
            "unsupported_schema_version",
        ),
        (
            RegistrarError::UnknownMultiplicity {
                component: "review".to_string(),
                value: "many".to_string(),
            },
            RefusalReason::UnknownMultiplicity,
            "unknown_multiplicity",
        ),
        (
            RegistrarError::UnknownReloadKind {
                component: "review".to_string(),
                value: "poke".to_string(),
            },
            RefusalReason::UnknownReloadKind,
            "unknown_reload_kind",
        ),
        (
            RegistrarError::InvalidReloadTarget {
                component: "review".to_string(),
                kind: ReloadKind::Systemd,
            },
            RefusalReason::InvalidReloadTarget,
            "invalid_reload_target",
        ),
        (
            RegistrarError::InvalidDomain {
                domain: "bad_domain".to_string(),
                kind: validation(),
            },
            RefusalReason::InvalidDomain,
            "invalid_domain",
        ),
        (
            RegistrarError::InvalidComponentKey {
                component: "bad key".to_string(),
                kind: validation(),
            },
            RefusalReason::InvalidComponentKey,
            "invalid_component_key",
        ),
        (
            RegistrarError::InvalidServiceName {
                value: "bad name".to_string(),
                kind: validation(),
            },
            RefusalReason::InvalidServiceName,
            "invalid_service_name",
        ),
        (
            RegistrarError::InvalidHost {
                value: "bad host".to_string(),
                kind: validation(),
            },
            RefusalReason::InvalidHost,
            "invalid_host",
        ),
        (
            RegistrarError::ComponentNotConfigured {
                component: "review".to_string(),
            },
            RefusalReason::ComponentNotConfigured,
            "component_not_configured",
        ),
        (
            RegistrarError::ServiceInstanceMismatch {
                component: "review".to_string(),
                multiplicity: Multiplicity::OnePerHost,
                instance_supplied: true,
            },
            RefusalReason::ServiceInstanceMismatch,
            "service_instance_mismatch",
        ),
        (
            RegistrarError::DerivedKeyInvalid {
                key: "BAD".to_string(),
                kind: validation(),
            },
            RefusalReason::DerivedKeyInvalid,
            "derived_key_invalid",
        ),
        (
            RegistrarError::SpecIdentityDisagreement {
                field: SpecIdentityField::Both,
                expected: "review".to_string(),
                spec_component: None,
                spec_service_name: None,
            },
            RefusalReason::SpecIdentityDisagreement,
            "spec_identity_disagreement",
        ),
        (
            RegistrarError::ServiceSpecOutsideSafeSet {
                component: "review".to_string(),
            },
            RefusalReason::ServiceSpecOutsideSafeSet,
            "service_spec_outside_safe_set",
        ),
    ];

    let wrap_ttl = [
        (WrapTtlRefusal::Zero, RefusalReason::Zero, "zero"),
        (
            WrapTtlRefusal::Negative,
            RefusalReason::Negative,
            "negative",
        ),
        (
            WrapTtlRefusal::NotWholeSeconds,
            RefusalReason::NotWholeSeconds,
            "not_whole_seconds",
        ),
        (
            WrapTtlRefusal::ExceedsOpenBaoRange,
            RefusalReason::ExceedsOpenBaoRange,
            "exceeds_open_bao_range",
        ),
    ];

    let mut all = vec![
        (
            VerbError::ReservedServiceName {
                service_name: "bootroot-decoy".to_string(),
            },
            RefusalReason::ReservedServiceName,
            "reserved_service_name",
        ),
        (
            VerbError::RegistrationIdCollision {
                registration_id: "review-h1".to_string(),
                stored_host: "h1".to_string(),
                requested_host: "h2".to_string(),
            },
            RefusalReason::RegistrationIdCollision,
            "registration_id_collision",
        ),
        (
            VerbError::StoredSpecConflict {
                registration_id: "review-h1".to_string(),
            },
            RefusalReason::StoredSpecConflict,
            "stored_spec_conflict",
        ),
        (
            VerbError::HostMismatch {
                registration_id: "review-h1".to_string(),
                stored_host: "h1".to_string(),
                requested_host: "h2".to_string(),
            },
            RefusalReason::HostMismatch,
            "host_mismatch",
        ),
        (
            VerbError::unavailable("reading the binding", anyhow::anyhow!("connection refused")),
            RefusalReason::Unavailable,
            "unavailable",
        ),
    ];
    all.extend(
        registrar
            .into_iter()
            .map(|(error, reason, name)| (VerbError::Registrar(error), reason, name)),
    );
    all.extend(
        wrap_ttl
            .into_iter()
            .map(|(refusal, reason, name)| (VerbError::InvalidWrapTtl(refusal), reason, name)),
    );
    all
}

#[test]
fn every_source_refusal_maps_to_one_distinct_record_reason() {
    let table = every_refusal();
    assert_eq!(
        table.len(),
        26,
        "the flattened table must cover every VerbError, RegistrarError and WrapTtlRefusal variant"
    );

    let mut seen: Vec<String> = Vec::new();
    for (error, expected_reason, expected_name) in table {
        let outcome = refusal_outcome(&error).expect("a recordable refusal produces an outcome");
        let AuditOutcome::Refused { reason, .. } = &outcome else {
            panic!("a refusal must produce the refused class, got {outcome:?}");
        };
        assert_eq!(*reason, expected_reason, "{expected_name}");
        let rendered = serde_json::to_string(reason).expect("a reason serializes");
        assert_eq!(rendered, format!("\"{expected_name}\""));
        seen.push(expected_name.to_string());
    }
    let mut sorted = seen.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), seen.len(), "every reason must be distinct");
}

/// Three refusals can never reach the trail, and that is enforced by
/// the return type rather than by prose.
///
/// For the two audit failures, the record that would carry one of them
/// is the record whose write just failed, so a call site that met a
/// `Some` here would answer a failed write with a second write of the
/// same kind. `Throttled` is `None` for the opposite reason: the
/// limiter produces it before the intent write, on an invocation whose
/// records are suppressed by construction, so no outcome write is ever
/// reached. Both halves are asserted together: `None` for exactly these
/// three, and `Some` for every other refusal the verb layer produces.
#[test]
fn the_audit_failures_and_the_throttle_are_the_only_unrecordable_refusals() {
    let unrecordable = [
        VerbError::AuditUnwritable {
            phase: AuditPhase::Intent,
            source: AuditStoreError::RecordTooLarge {
                bytes: 1,
                limit: MIN_AUDIT_MAX_FILE_BYTES,
            },
        },
        VerbError::AuditUnwritable {
            phase: AuditPhase::Outcome,
            source: AuditStoreError::Sync {
                path: PathBuf::from("/var/lib/bootroot/registrar-audit/registrar-audit.jsonl"),
                source: std::io::Error::from(std::io::ErrorKind::StorageFull),
            },
        },
        VerbError::PostMintUnrecordable {
            source: AuditStoreError::Append {
                path: PathBuf::from("/var/lib/bootroot/registrar-audit/registrar-audit.jsonl"),
                source: std::io::Error::from(std::io::ErrorKind::StorageFull),
            },
        },
        VerbError::Throttled { retry_after: 1 },
    ];
    for error in &unrecordable {
        assert!(
            refusal_outcome(error).is_none(),
            "{error:?} must produce no record at all"
        );
    }

    for (error, _, name) in every_refusal() {
        assert!(
            refusal_outcome(&error).is_some(),
            "{name} is a durable reason and must still be recordable"
        );
    }
}

#[test]
fn a_refusal_reason_round_trips_through_the_record_types() {
    for (error, _, name) in every_refusal() {
        let record = AuditRecord::outcome(
            ts(),
            "req".to_string(),
            AuditVerb::Mint,
            CALLER.to_string(),
            requested(None),
            None,
            refusal_outcome(&error).expect("a recordable refusal produces an outcome"),
        );
        let rendered = serde_json::to_string(&record).expect("serializes");
        assert!(
            rendered.contains(&format!(r#""reason":"{name}""#)),
            "{name} must appear verbatim in {rendered}"
        );
        let parsed: AuditRecord = serde_json::from_str(&rendered).expect("round-trips");
        assert_eq!(parsed, record, "{name}");
    }
}

#[test]
fn the_success_classes_use_their_explicit_spellings() {
    for (outcome, expected) in [
        (
            mint_outcome(MintKind::FirstMint),
            r#"{"class":"first_mint"}"#,
        ),
        (
            mint_outcome(MintKind::IdempotentReMint),
            r#"{"class":"idempotent_remint"}"#,
        ),
        (
            deregister_outcome(DeregisterKind::IdentityRemoved),
            r#"{"class":"identity_removed"}"#,
        ),
        (
            deregister_outcome(DeregisterKind::AlreadyAbsent),
            r#"{"class":"idempotent_already_absent"}"#,
        ),
    ] {
        assert_eq!(
            serde_json::to_string(&outcome).expect("serializes"),
            expected
        );
    }
}

#[test]
fn an_unavailable_refusal_records_its_activity_and_nothing_else() {
    let error = VerbError::unavailable(
        "reading the durable binding",
        anyhow::anyhow!("connection refused").context("dialling openbao at https://vault.internal"),
    );
    let Some(AuditOutcome::Refused { reason, detail }) = refusal_outcome(&error) else {
        panic!("an unavailable refusal must produce the refused class");
    };
    assert_eq!(reason, RefusalReason::Unavailable);
    assert_eq!(detail.as_deref(), Some("reading the durable binding"));

    let record = AuditRecord::outcome(
        ts(),
        "req".to_string(),
        AuditVerb::Mint,
        CALLER.to_string(),
        requested(None),
        None,
        refusal_outcome(&error).expect("an unavailable refusal is recordable"),
    );
    let rendered = serde_json::to_string(&record).expect("serializes");
    for leaked in ["connection refused", "vault.internal", "dialling openbao"] {
        assert!(
            !rendered.contains(leaked),
            "the source chain must not reach the record: {rendered}"
        );
    }
}

// ---------------------------------------------------------------------
// Format: escaping, bounds and truncation
// ---------------------------------------------------------------------

#[test]
fn hostile_strings_stay_inside_one_record_line() {
    let hostile = "quote\" backslash\\ newline\n carriage\r tab\t nul\u{0} end";
    let record = AuditRecord::outcome(
        ts(),
        "req".to_string(),
        AuditVerb::Mint,
        hostile.to_string(),
        RequestedIdentity {
            service_name: hostile.to_string(),
            host: hostile.to_string(),
            instance: None,
        },
        None,
        AuditOutcome::Refused {
            reason: RefusalReason::InvalidServiceName,
            detail: Some(hostile.to_string()),
        },
    );
    let line = record.clone().into_bounded().to_line().expect("a line");
    assert_eq!(line.last().copied(), Some(b'\n'));
    assert!(
        !line[..line.len() - 1].contains(&b'\n'),
        "the only newline is the terminator"
    );

    let text = String::from_utf8(line).expect("a line is UTF-8");
    assert!(text.contains(r"\n"), "a newline is escaped: {text}");
    assert!(text.contains("\\u0000"), "a NUL is escaped: {text}");
    let parsed: AuditRecord = serde_json::from_str(text.trim_end()).expect("parses");
    assert_eq!(parsed.caller_identity, hostile);
    assert!(
        parsed.truncated.is_none(),
        "a short hostile string is not truncated"
    );
}

#[test]
fn an_untruncated_record_omits_the_truncated_object() {
    let record = AuditRecord::intent(
        ts(),
        "req".to_string(),
        AuditVerb::Mint,
        "x".repeat(MAX_RECORD_FIELD_BYTES),
        requested(None),
    )
    .into_bounded();
    assert!(record.truncated.is_none(), "512 bytes is inside the cap");
    let rendered = serde_json::to_string(&record).expect("serializes");
    assert!(!rendered.contains("truncated"), "{rendered}");
}

#[test]
fn truncation_never_splits_a_utf8_sequence() {
    // Three bytes per character, so the 512-byte cap falls inside a
    // character and the preview has to stop at 510.
    let value = "가".repeat(200);
    let record = AuditRecord::intent(
        ts(),
        "req".to_string(),
        AuditVerb::Mint,
        value.clone(),
        requested(None),
    )
    .into_bounded();

    assert_eq!(record.caller_identity, "가".repeat(170));
    assert_eq!(record.caller_identity.len(), 510);
    let digest = record
        .truncated
        .as_ref()
        .and_then(|truncated| truncated.caller_identity.as_ref())
        .expect("caller_identity was shortened");
    assert_eq!(digest.full_bytes, 600);
    assert_eq!(digest.full_sha256, sha256_hex(value.as_bytes()));
    assert_eq!(
        digest.full_sha256,
        "92f3b16fca213b4a13931584820344933380682e13b4f34fd58cca290e7d4650"
    );
}

#[test]
fn a_caller_supplied_truncated_object_is_recomputed_by_the_store() {
    let mut record = AuditRecord::intent(
        ts(),
        "req".to_string(),
        AuditVerb::Mint,
        "short".to_string(),
        requested(None),
    );
    record.truncated = Some(Truncations {
        caller_identity: Some(TruncationDigest {
            full_sha256: "0".repeat(64),
            full_bytes: 999_999,
        }),
        ..Truncations::default()
    });
    assert!(
        record.into_bounded().truncated.is_none(),
        "a fabricated truncation record must not survive"
    );
}

#[test]
fn the_record_ceiling_bounds_a_worst_case_escaped_record() {
    // Every attacker-influenced field is control bytes, which is the
    // six-bytes-out-for-one-in case, and every one of them is over the
    // cap so a `truncated` entry is written for it too.
    let hostile = "\u{0}".repeat(1024);
    let record = AuditRecord::outcome(
        ts(),
        "r".repeat(64),
        AuditVerb::Deregister,
        hostile.clone(),
        RequestedIdentity {
            service_name: hostile.clone(),
            host: hostile.clone(),
            instance: Some(u32::MAX),
        },
        Some("a".repeat(131)),
        AuditOutcome::Refused {
            reason: RefusalReason::ServiceSpecOutsideSafeSet,
            detail: Some(hostile),
        },
    )
    .into_bounded();

    let line = record.to_line().expect("a line");
    assert!(
        line.len() <= MAX_SERIALIZED_RECORD_BYTES,
        "a worst-case record is {} bytes, over the {MAX_SERIALIZED_RECORD_BYTES}-byte ceiling",
        line.len()
    );
    // The escaping really did happen: 512 NULs become 512 six-byte
    // escapes in each of the four fields.
    assert!(
        line.len() > 4 * 512 * 6,
        "a worst-case record must actually be escaped, got {} bytes",
        line.len()
    );
}

#[test]
fn the_minimum_file_size_holds_one_maximum_size_record() {
    assert!(
        u64::try_from(MAX_SERIALIZED_RECORD_BYTES).expect("the ceiling fits u64")
            < MIN_AUDIT_MAX_FILE_BYTES,
        "the {MIN_AUDIT_MAX_FILE_BYTES}-byte floor must exceed the \
         {MAX_SERIALIZED_RECORD_BYTES}-byte record ceiling"
    );
}

/// The sizing the documentation quotes, checked as arithmetic rather
/// than by appending forty thousand records.
#[test]
fn the_reference_deployment_fits_the_default_capacity() {
    const ORDINARY_RECORD_BYTES: u64 = 400;
    const INITIAL_INVOCATIONS: u64 = 2_000;
    const DAILY_INVOCATIONS: u64 = 200;
    const RETENTION_DAYS: u64 = 90;

    // Two lines per invocation: one intent, one outcome.
    let records = 2 * (INITIAL_INVOCATIONS + RETENTION_DAYS * DAILY_INVOCATIONS);
    assert_eq!(records, 40_000);
    let bytes = records * ORDINARY_RECORD_BYTES;
    assert_eq!(bytes, 16_000_000);

    let capacity = super::DEFAULT_AUDIT_MAX_FILE_BYTES
        * u64::from(super::DEFAULT_AUDIT_MAX_RETAINED_FILES + 1);
    assert_eq!(capacity, 142_606_336);
    assert!(
        bytes < capacity,
        "the reference deployment ({bytes} bytes) must fit the default ceiling ({capacity} bytes)"
    );
}

// ---------------------------------------------------------------------
// Store: names
// ---------------------------------------------------------------------

#[test]
fn a_rotated_generation_name_is_stamped_and_sequenced() {
    let moment = OffsetDateTime::parse("2026-08-23T12:34:56.789Z", &Rfc3339).expect("parses");
    let stamp = rotation_stamp(moment);
    assert_eq!(stamp, "20260823T123456Z");
    assert_eq!(
        rotated_file_name(&stamp, 0),
        "registrar-audit-20260823T123456Z-000000.jsonl"
    );
    assert_eq!(
        rotated_file_name(&stamp, 42),
        "registrar-audit-20260823T123456Z-000042.jsonl"
    );
    assert_eq!(
        parse_rotated_name("registrar-audit-20260823T123456Z-000042.jsonl"),
        Some(("20260823T123456Z", 42))
    );
    // The active file is not a generation, and neither is anything else
    // that happens to share the directory. A name accepted here is
    // validated on opening, counted against the retained limit and
    // eventually deleted by a trim, so the timestamp is held to its
    // documented shape rather than merely to being nonempty.
    for other in [
        ACTIVE_FILE_NAME,
        "registrar-audit-20260823T123456Z-42.jsonl",
        "registrar-audit-20260823T123456Z-00004x.jsonl",
        "registrar-audit--000000.jsonl",
        "notes.txt",
        // The timestamp half, wrong in every way it can be.
        "registrar-audit-not-a-timestamp-000000.jsonl",
        "registrar-audit-20260823T12345Z-000000.jsonl",
        "registrar-audit-20260823T1234567Z-000000.jsonl",
        "registrar-audit-20260823t123456Z-000000.jsonl",
        "registrar-audit-20260823T123456-000000.jsonl",
        "registrar-audit-20260823T123456z-000000.jsonl",
        "registrar-audit-2026-08-23T1234Z-000000.jsonl",
        "registrar-audit-+0260823T123456Z-000000.jsonl",
        // Shaped right, but naming no instant that ever happened.
        "registrar-audit-20260230T123456Z-000000.jsonl",
        "registrar-audit-20261323T123456Z-000000.jsonl",
        "registrar-audit-20260823T243456Z-000000.jsonl",
        "registrar-audit-20260823T126056Z-000000.jsonl",
        "registrar-audit-20260823T123460Z-000000.jsonl",
    ] {
        assert_eq!(parse_rotated_name(other), None, "{other}");
    }
    // A leap day the calendar does have, so the validity check is not
    // just rejecting everything unusual.
    assert_eq!(
        parse_rotated_name("registrar-audit-20240229T000000Z-000000.jsonl"),
        Some(("20240229T000000Z", 0))
    );
}

#[test]
fn rotated_names_sort_oldest_first() {
    let mut names = vec![
        rotated_file_name("20260823T123457Z", 0),
        rotated_file_name("20260823T123456Z", 10),
        rotated_file_name("20260823T123456Z", 2),
        rotated_file_name("20260824T000000Z", 0),
    ];
    names.sort_unstable();
    assert_eq!(
        names,
        vec![
            rotated_file_name("20260823T123456Z", 2),
            rotated_file_name("20260823T123456Z", 10),
            rotated_file_name("20260823T123457Z", 0),
            rotated_file_name("20260824T000000Z", 0),
        ]
    );
}

// ---------------------------------------------------------------------
// Store: the rejection decisions
// ---------------------------------------------------------------------

#[test]
fn every_directory_rejection_branch_is_decided_the_same_way() {
    // Accepted: a real directory, right owner, no group or world write.
    assert_eq!(directory_condition(false, true, 0, 0o040_700, 0), None);
    assert_eq!(directory_condition(false, true, 501, 0o040_755, 501), None);

    assert_eq!(
        directory_condition(true, true, 0, 0o040_700, 0),
        Some(PathCondition::Symlink),
        "a symlink is refused before anything else is looked at"
    );
    assert_eq!(
        directory_condition(false, false, 0, 0o100_600, 0),
        Some(PathCondition::NotADirectory)
    );
    assert_eq!(
        directory_condition(false, true, 501, 0o040_700, 0),
        Some(PathCondition::Owner {
            expected: 0,
            found: 501
        }),
        "production accepts uid 0 and nothing else"
    );
    assert_eq!(
        directory_condition(false, true, 0, 0o040_770, 0),
        Some(PathCondition::GroupOrWorldWritable { mode: 0o770 })
    );
    assert_eq!(
        directory_condition(false, true, 0, 0o041_777, 0),
        Some(PathCondition::GroupOrWorldWritable { mode: 0o1777 }),
        "the sticky bit does not make a world-writable directory safe"
    );
}

#[test]
fn every_file_rejection_branch_is_decided_the_same_way() {
    assert_eq!(file_condition(false, true, 0, 0), None);
    assert_eq!(
        file_condition(true, false, 0, 0),
        Some(PathCondition::Symlink)
    );
    assert_eq!(
        file_condition(false, false, 0, 0),
        Some(PathCondition::NotARegularFile)
    );
    assert_eq!(
        file_condition(false, true, 501, 0),
        Some(PathCondition::Owner {
            expected: 0,
            found: 501
        })
    );
}

#[test]
fn a_path_condition_names_what_was_wrong() {
    assert_eq!(PathCondition::Symlink.to_string(), "it is a symbolic link");
    assert_eq!(
        PathCondition::Owner {
            expected: 0,
            found: 501
        }
        .to_string(),
        "it is owned by uid 501, not uid 0"
    );
    assert_eq!(
        PathCondition::GroupOrWorldWritable { mode: 0o777 }.to_string(),
        "its mode 0777 is group- or world-writable"
    );
}

// ---------------------------------------------------------------------
// Store: construction over a real directory
// ---------------------------------------------------------------------

/// A store directory two levels below a temporary directory, so both
/// the ancestor-creation and the store-directory-creation paths run.
fn store_settings(root: &Path) -> AuditStoreSettings {
    AuditStoreSettings {
        dir: root.join("var/lib/bootroot/registrar-audit"),
        max_file_bytes: MIN_AUDIT_MAX_FILE_BYTES,
        max_retained_files: 3,
    }
}

/// Creates `path` and every missing component between `root` and it,
/// stating the mode of each rather than leaving it to the umask.
///
/// `fs::create_dir_all` applies `0o777 & ~umask`, and a Debian-style
/// account runs under a `002` umask, so a tree a test builds for itself
/// would be group-writable — and the store would refuse it for *that*
/// rather than for whatever the test planted. Only the scaffolding is
/// tightened here; a test that plants a loose mode sets it afterwards.
fn create_tree(root: &Path, path: &Path) {
    fs::create_dir_all(path).expect("create the directory tree");
    let mut current = path.to_path_buf();
    while current.starts_with(root) {
        fs::set_permissions(&current, fs::Permissions::from_mode(0o755)).expect("chmod");
        if current == root || !current.pop() {
            break;
        }
    }
}

async fn open_in(root: &Path) -> AuditRecordStore {
    AuditRecordStore::open_for_tests(store_settings(root))
        .await
        .expect("a store opens over a fresh temporary directory")
}

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path).expect("stat").mode() & 0o7777
}

fn outcome_record(request_id: &str, registration_id: Option<String>) -> AuditRecord {
    AuditRecord::outcome(
        ts(),
        request_id.to_string(),
        AuditVerb::Mint,
        CALLER.to_string(),
        requested(Some(7)),
        registration_id,
        AuditOutcome::FirstMint,
    )
}

fn intent(request_id: &str) -> AuditRecord {
    AuditRecord::intent(
        ts(),
        request_id.to_string(),
        AuditVerb::Mint,
        CALLER.to_string(),
        requested(Some(7)),
    )
}

#[tokio::test]
async fn opening_creates_the_tree_with_the_documented_modes() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;

    assert_eq!(mode_of(&root.path().join("var")), 0o755);
    assert_eq!(mode_of(&root.path().join("var/lib")), 0o755);
    assert_eq!(mode_of(&root.path().join("var/lib/bootroot")), 0o755);
    assert_eq!(mode_of(store.directory()), 0o700);
    assert!(
        !store.active_path().exists(),
        "opening a store writes no record"
    );
}

/// The mode of the active file is stated, not inherited. `open(2)`
/// subtracts the process umask from the mode it is handed, so
/// `.mode(0o600)` alone leaves a `0277` host with a `0400` file — not
/// the mode the format documents, and not one the daemon can reopen for
/// the next append. Both files the store creates are covered: the first
/// active file, and the one it puts back after a rotation.
///
/// `umask` belongs to the process rather than to a thread, so this runs
/// in a process of its own; the temporary directory is made before the
/// umask changes, since `tempdir` would otherwise come out unusable.
#[test]
fn active_files_are_created_0600_under_a_restrictive_umask() {
    if crate::fs_util::umask_test_ran_in_child(
        "registrar::audit::tests::active_files_are_created_0600_under_a_restrictive_umask",
    ) {
        return;
    }

    let root = tempfile::tempdir().expect("tempdir");
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    // SAFETY: this is the child spawned above, with no other test
    // sharing the process, and the prior umask is restored immediately
    // after the store work that has to observe this one.
    let previous = unsafe { libc::umask(0o277) };
    let outcome = runtime.block_on(async {
        let store = open_in(root.path()).await;
        store.append(intent("first")).await.expect("append");
        let created = mode_of(store.active_path());

        fill_to_limit(&store).await;
        store.append(padded(FILLER, 400)).await.expect("append");
        let names = generations(store.directory());
        let rotated = mode_of(&store.directory().join(&names[0]));
        (created, mode_of(store.active_path()), rotated, names.len())
    });
    unsafe { libc::umask(previous) };

    let (created, recreated, rotated, generation_count) = outcome;
    assert_eq!(created, 0o600, "the first active file");
    assert_eq!(generation_count, 1, "exactly one rotation happened");
    assert_eq!(recreated, 0o600, "the active file recreated after rotation");
    assert_eq!(rotated, 0o600, "the generation the rotation renamed");
}

#[tokio::test]
async fn opening_leaves_an_existing_ancestor_exactly_as_it_was() {
    let root = tempfile::tempdir().expect("tempdir");
    let existing = root.path().join("var/lib");
    fs::create_dir_all(&existing).expect("create the ancestor");
    fs::set_permissions(&existing, fs::Permissions::from_mode(0o751)).expect("chmod");
    let before = fs::symlink_metadata(&existing).expect("stat");

    let _store = open_in(root.path()).await;

    let after = fs::symlink_metadata(&existing).expect("stat");
    assert_eq!(
        after.mode(),
        before.mode(),
        "an existing ancestor is left alone"
    );
    assert_eq!(after.uid(), before.uid());
}

#[tokio::test]
async fn a_symlinked_store_directory_is_refused() {
    let root = tempfile::tempdir().expect("tempdir");
    let elsewhere = root.path().join("elsewhere");
    fs::create_dir_all(&elsewhere).expect("create the decoy");
    let settings = store_settings(root.path());
    create_tree(root.path(), settings.dir.parent().expect("a parent"));
    std::os::unix::fs::symlink(&elsewhere, &settings.dir).expect("plant the symlink");

    let err = AuditRecordStore::open_for_tests(settings.clone())
        .await
        .expect_err("a symlinked store directory must be refused");
    assert!(
        matches!(
            &err,
            AuditStoreError::UnsafePath { path, condition }
                if *path == settings.dir && *condition == PathCondition::Symlink
        ),
        "expected a symlink refusal naming the path, got {err:?}"
    );
}

#[tokio::test]
async fn a_symlinked_parent_is_refused_before_the_store_directory_is_created() {
    let root = tempfile::tempdir().expect("tempdir");
    let elsewhere = root.path().join("elsewhere");
    fs::create_dir_all(&elsewhere).expect("create the decoy");
    let settings = store_settings(root.path());
    let parent = settings.dir.parent().expect("a parent").to_path_buf();
    fs::create_dir_all(parent.parent().expect("a grandparent")).expect("create the grandparent");
    std::os::unix::fs::symlink(&elsewhere, &parent).expect("plant the symlink");

    let err = AuditRecordStore::open_for_tests(settings.clone())
        .await
        .expect_err("a symlinked parent must be refused");
    assert!(
        matches!(
            &err,
            AuditStoreError::UnsafePath { path, condition }
                if *path == parent && *condition == PathCondition::Symlink
        ),
        "expected a symlink refusal naming the parent, got {err:?}"
    );
    assert!(
        !elsewhere.join("registrar-audit").exists(),
        "nothing may be created through a rejected parent"
    );
}

#[tokio::test]
async fn a_world_writable_parent_is_refused() {
    let root = tempfile::tempdir().expect("tempdir");
    let settings = store_settings(root.path());
    let parent = settings.dir.parent().expect("a parent").to_path_buf();
    fs::create_dir_all(&parent).expect("create the parent");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).expect("chmod");

    let err = AuditRecordStore::open_for_tests(settings)
        .await
        .expect_err("a world-writable parent must be refused");
    assert!(
        matches!(
            &err,
            AuditStoreError::UnsafePath { path, condition }
                if *path == parent
                    && matches!(condition, PathCondition::GroupOrWorldWritable { .. })
        ),
        "expected a writability refusal naming the parent, got {err:?}"
    );
}

/// The store directory's own mode is audited as well as its parent's.
///
/// A pre-existing directory is never chmod'ed back into shape — the
/// creation path is skipped entirely for one that is already there — so
/// this is the branch that decides whether an operator who provisioned
/// the directory too loosely gets a refusal or a group-writable audit
/// trail. Driven end to end rather than only through
/// `directory_condition`, because it is the reachability of the check,
/// not the decision, that is in question here.
#[tokio::test]
async fn a_world_writable_store_directory_is_refused() {
    let root = tempfile::tempdir().expect("tempdir");
    let settings = store_settings(root.path());
    create_tree(root.path(), &settings.dir);
    fs::set_permissions(&settings.dir, fs::Permissions::from_mode(0o777)).expect("chmod");

    let err = AuditRecordStore::open_for_tests(settings.clone())
        .await
        .expect_err("a world-writable store directory must be refused");
    assert!(
        matches!(
            &err,
            AuditStoreError::UnsafePath { path, condition }
                if *path == settings.dir
                    && matches!(condition, PathCondition::GroupOrWorldWritable { .. })
        ),
        "expected a writability refusal naming the store directory, got {err:?}"
    );
    assert_eq!(
        mode_of(&settings.dir),
        0o777,
        "a refused directory is reported, never quietly tightened"
    );
    assert!(
        !settings.dir.join(ACTIVE_FILE_NAME).exists(),
        "no record file may be created inside a refused directory"
    );
}

/// A group-writable store directory is refused for the same reason a
/// world-writable one is: anybody in the group could plant or replace a
/// generation.
#[tokio::test]
async fn a_group_writable_store_directory_is_refused() {
    let root = tempfile::tempdir().expect("tempdir");
    let settings = store_settings(root.path());
    create_tree(root.path(), &settings.dir);
    fs::set_permissions(&settings.dir, fs::Permissions::from_mode(0o770)).expect("chmod");

    let err = AuditRecordStore::open_for_tests(settings.clone())
        .await
        .expect_err("a group-writable store directory must be refused");
    assert!(
        matches!(
            &err,
            AuditStoreError::UnsafePath { path, condition }
                if *path == settings.dir
                    && *condition == PathCondition::GroupOrWorldWritable { mode: 0o770 }
        ),
        "expected a writability refusal naming the store directory, got {err:?}"
    );
}

#[tokio::test]
async fn a_symlinked_active_file_is_refused() {
    let root = tempfile::tempdir().expect("tempdir");
    let settings = store_settings(root.path());
    create_tree(root.path(), &settings.dir);
    fs::set_permissions(&settings.dir, fs::Permissions::from_mode(0o700)).expect("chmod");
    let decoy = root.path().join("decoy.jsonl");
    fs::write(&decoy, b"").expect("write the decoy");
    let active = settings.dir.join(ACTIVE_FILE_NAME);
    std::os::unix::fs::symlink(&decoy, &active).expect("plant the symlink");

    let err = AuditRecordStore::open_for_tests(settings)
        .await
        .expect_err("a symlinked active file must be refused");
    assert!(
        matches!(
            &err,
            AuditStoreError::UnsafePath { path, condition }
                if *path == active && *condition == PathCondition::Symlink
        ),
        "expected a symlink refusal naming the active file, got {err:?}"
    );
}

#[tokio::test]
async fn a_symlinked_rotated_generation_is_refused() {
    let root = tempfile::tempdir().expect("tempdir");
    let settings = store_settings(root.path());
    create_tree(root.path(), &settings.dir);
    fs::set_permissions(&settings.dir, fs::Permissions::from_mode(0o700)).expect("chmod");
    let decoy = root.path().join("decoy.jsonl");
    fs::write(&decoy, b"").expect("write the decoy");
    let generation = settings.dir.join(rotated_file_name("20260823T123456Z", 0));
    std::os::unix::fs::symlink(&decoy, &generation).expect("plant the symlink");

    let err = AuditRecordStore::open_for_tests(settings)
        .await
        .expect_err("a symlinked generation must be refused");
    assert!(
        matches!(
            &err,
            AuditStoreError::UnsafePath { path, condition }
                if *path == generation && *condition == PathCondition::Symlink
        ),
        "expected a symlink refusal naming the generation, got {err:?}"
    );
}

#[tokio::test]
async fn unusable_settings_are_refused_before_anything_is_created() {
    for (settings, setting) in [
        (
            AuditStoreSettings {
                dir: PathBuf::from("relative/registrar-audit"),
                max_file_bytes: MIN_AUDIT_MAX_FILE_BYTES,
                max_retained_files: 1,
            },
            "audit_record_dir",
        ),
        (
            AuditStoreSettings {
                dir: PathBuf::from("/var/lib/bootroot/registrar-audit"),
                max_file_bytes: MIN_AUDIT_MAX_FILE_BYTES - 1,
                max_retained_files: 1,
            },
            "audit_max_file_bytes",
        ),
        (
            AuditStoreSettings {
                dir: PathBuf::from("/var/lib/bootroot/registrar-audit"),
                max_file_bytes: MIN_AUDIT_MAX_FILE_BYTES,
                max_retained_files: 0,
            },
            "audit_max_retained_files",
        ),
    ] {
        let err = AuditRecordStore::open_for_tests(settings)
            .await
            .expect_err("an unusable setting must be refused");
        assert!(
            matches!(&err, AuditStoreError::InvalidSetting { setting: named, .. } if *named == setting),
            "expected {setting} to be named, got {err:?}"
        );
    }
}

// ---------------------------------------------------------------------
// Store: appending
// ---------------------------------------------------------------------

#[tokio::test]
async fn an_append_writes_exactly_one_parseable_line() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    let record = intent("req-1");

    store.append(record.clone()).await.expect("append");

    let written = fs::read_to_string(store.active_path()).expect("read back");
    assert_eq!(written.matches('\n').count(), 1);
    assert!(written.ends_with('\n'));
    let parsed: AuditRecord = serde_json::from_str(written.trim_end()).expect("parses");
    assert_eq!(parsed, record);
    assert_eq!(mode_of(store.active_path()), 0o600);
}

/// An empty `registration_id` is not a derived key, and the format
/// forbids writing one as `""` just as it forbids `null`. Every way a
/// record can come to carry one is covered: the builder a caller is
/// meant to use, the public field it could set afterwards and then
/// append, and the public serializer used without the store at all.
#[tokio::test]
async fn an_empty_registration_id_is_never_written() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;

    let built = outcome_record("req-empty-built", Some(String::new()));
    assert_eq!(
        built.registration_id, None,
        "the builder normalizes an empty derived key away"
    );
    store.append(built).await.expect("append");

    let mut planted = outcome_record("req-empty-planted", None);
    planted.registration_id = Some(String::new());
    store.append(planted.clone()).await.expect("append");

    let written = fs::read_to_string(store.active_path()).expect("read back");
    assert_eq!(written.lines().count(), 2);
    for line in written.lines() {
        assert!(
            !line.contains("registration_id"),
            "an empty derived key must be omitted from the line, got {line}"
        );
        let parsed: AuditRecord = serde_json::from_str(line).expect("every line parses");
        assert_eq!(parsed.registration_id, None);
        assert_eq!(parsed.outcome, Some(AuditOutcome::FirstMint));
    }

    let direct = String::from_utf8(planted.to_line().expect("serializes")).expect("utf-8");
    assert!(
        !direct.contains("registration_id"),
        "serializing without the store must omit it too, got {direct}"
    );
}

/// `record_version` is a public field on a public record type, so a
/// caller can set it to anything before appending. The format says
/// every line is at [`AUDIT_RECORD_VERSION`], and the store is what
/// makes that true: the record is refused before any of it reaches the
/// file.
#[tokio::test]
async fn a_record_at_another_format_version_is_refused_and_writes_nothing() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    store.append(intent("req-current")).await.expect("append");
    let before = fs::read_to_string(store.active_path()).expect("read back");

    for version in [0, AUDIT_RECORD_VERSION + 1, u32::MAX] {
        let mut planted = intent("req-versioned");
        planted.record_version = version;
        let err = store
            .append(planted)
            .await
            .expect_err("a record at another version is not appendable");
        assert!(
            matches!(
                &err,
                AuditStoreError::UnsupportedRecordVersion { version: got, expected }
                    if *got == version && *expected == AUDIT_RECORD_VERSION
            ),
            "expected a version refusal naming both versions, got {err:?}"
        );
    }

    assert_eq!(
        fs::read_to_string(store.active_path()).expect("read back"),
        before,
        "a refused version leaves the trail exactly as it was"
    );
    for line in before.lines() {
        let parsed: AuditRecord = serde_json::from_str(line).expect("every line parses");
        assert_eq!(parsed.record_version, AUDIT_RECORD_VERSION);
    }
}

/// `phase` and `outcome` are public fields too, and the builders are
/// not the only way to reach `append`: a record can be assembled by
/// hand or deserialized from elsewhere. The format says an `intent`
/// line carries no outcome and an `outcome` line carries one, so both
/// contradictions are refused before anything is written, exactly as an
/// off-version record is.
#[tokio::test]
async fn a_record_whose_phase_and_outcome_disagree_is_refused_and_writes_nothing() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    store.append(intent("req-intent")).await.expect("append");
    store
        .append(outcome_record("req-outcome", None))
        .await
        .expect("append");
    let before = fs::read_to_string(store.active_path()).expect("read back");

    let mut intent_with_outcome = intent("req-intent-with-outcome");
    intent_with_outcome.outcome = Some(AuditOutcome::FirstMint);
    let mut outcome_without_outcome = outcome_record("req-outcome-without-outcome", None);
    outcome_without_outcome.outcome = None;

    for (planted, phase, requirement) in [
        (
            intent_with_outcome,
            AuditPhase::Intent,
            "must not carry an outcome",
        ),
        (
            outcome_without_outcome,
            AuditPhase::Outcome,
            "must carry an outcome",
        ),
    ] {
        let err = store
            .append(planted)
            .await
            .expect_err("a record whose phase and outcome disagree is not appendable");
        assert!(
            matches!(
                &err,
                AuditStoreError::InconsistentPhase { phase: got, requirement: said }
                    if *got == phase && *said == requirement
            ),
            "expected a phase refusal naming the phase and what it requires, got {err:?}"
        );
    }

    assert_eq!(
        fs::read_to_string(store.active_path()).expect("read back"),
        before,
        "a refused pairing leaves the trail exactly as it was"
    );
    for line in before.lines() {
        let parsed: AuditRecord = serde_json::from_str(line).expect("every line parses");
        assert_eq!(
            parsed.phase == AuditPhase::Outcome,
            parsed.outcome.is_some(),
            "every written line pairs its phase and outcome"
        );
    }
}

/// `ts` is public and `OffsetDateTime` is nanosecond-precise, so a
/// record assembled by hand can carry precision the line has no room
/// for. Writing it would drop the remainder and leave a durable line
/// that no longer deserializes back to the record that produced it, so
/// it is refused before anything is written — and the same record,
/// aligned, round-trips exactly.
#[tokio::test]
async fn a_sub_millisecond_timestamp_is_refused_and_writes_nothing() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    store.append(intent("req-aligned")).await.expect("append");
    let before = fs::read_to_string(store.active_path()).expect("read back");

    let mut planted = intent("req-ragged");
    planted.ts = planted
        .ts
        .replace_nanosecond(789_654_321)
        .expect("a valid nanosecond");
    let err = store
        .append(planted.clone())
        .await
        .expect_err("a sub-millisecond timestamp is not appendable");
    assert!(
        matches!(
            &err,
            AuditStoreError::UnalignedTimestamp { ts, nanosecond }
                if *ts == planted.ts && *nanosecond == 789_654_321
        ),
        "expected a timestamp refusal naming the value and its nanosecond, got {err:?}"
    );
    assert_eq!(
        fs::read_to_string(store.active_path()).expect("read back"),
        before,
        "a refused timestamp leaves the trail exactly as it was"
    );

    let aligned = AuditRecord {
        ts: canonical_timestamp(planted.ts),
        ..planted
    };
    store.append(aligned.clone()).await.expect("append");
    let written = fs::read_to_string(store.active_path()).expect("read back");
    let last = written.lines().last().expect("a line was written");
    let parsed: AuditRecord = serde_json::from_str(last).expect("a written line parses");
    assert_eq!(
        parsed, aligned,
        "an aligned record deserializes back to exactly what was appended"
    );
}

/// `ts` is public and `OffsetDateTime` carries an offset, so a record
/// assembled by hand can hold a local-time reading. The line has only
/// the UTC spelling, so writing it would turn `21:34:56.789+09:00`
/// into `12:34:56.789Z` — the same instant, but not the value its
/// caller held, and not one the line reads back as. It is refused
/// before anything is written, and the same record at UTC round-trips
/// exactly.
#[tokio::test]
async fn a_non_utc_timestamp_is_refused_and_writes_nothing() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    store.append(intent("req-utc")).await.expect("append");
    let before = fs::read_to_string(store.active_path()).expect("read back");

    let mut planted = intent("req-shifted");
    planted.ts = planted.ts.to_offset(plus_nine());
    assert_eq!(planted.ts.hour(), 21, "the wall-clock reading moved");
    let err = store
        .append(planted.clone())
        .await
        .expect_err("a non-UTC timestamp is not appendable");
    assert!(
        matches!(
            &err,
            AuditStoreError::NonUtcTimestamp { ts, offset }
                if *ts == planted.ts && *offset == plus_nine()
        ),
        "expected a timestamp refusal naming the value and its offset, got {err:?}"
    );
    assert!(
        err.to_string().contains("+09:00"),
        "the refusal identifies the rejected offset, got {err}"
    );
    assert_eq!(
        fs::read_to_string(store.active_path()).expect("read back"),
        before,
        "a refused timestamp leaves the trail exactly as it was"
    );

    let canonical = AuditRecord {
        ts: canonical_timestamp(planted.ts),
        ..planted
    };
    store.append(canonical.clone()).await.expect("append");
    let written = fs::read_to_string(store.active_path()).expect("read back");
    let last = written.lines().last().expect("a line was written");
    let parsed: AuditRecord = serde_json::from_str(last).expect("a written line parses");
    assert_eq!(
        parsed, canonical,
        "a canonical record deserializes back to exactly what was appended"
    );
    assert_eq!(parsed.ts.offset(), UtcOffset::UTC);
}

#[tokio::test]
async fn concurrent_appends_produce_intact_independent_records() {
    const WRITERS: usize = 16;
    const PER_WRITER: usize = 8;

    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;

    let mut handles = Vec::new();
    for writer in 0..WRITERS {
        let store = store.clone();
        handles.push(tokio::spawn(async move {
            for index in 0..PER_WRITER {
                store
                    .append(intent(&format!("w{writer}-{index}")))
                    .await
                    .expect("append");
            }
        }));
    }
    for handle in handles {
        handle.await.expect("a writer task completes");
    }

    let written = fs::read_to_string(store.active_path()).expect("read back");
    let mut ids: Vec<String> = Vec::new();
    for line in written.lines() {
        let parsed: AuditRecord =
            serde_json::from_str(line).expect("every line parses independently");
        ids.push(parsed.request_id);
    }
    assert_eq!(ids.len(), WRITERS * PER_WRITER);
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        ids.len(),
        WRITERS * PER_WRITER,
        "no record may be lost or duplicated"
    );
}

/// Cancelling an append does not hand the next one a free lock.
///
/// The guard used to live on the awaiting future's stack, so dropping
/// that future released it while the blocking task it had spawned went
/// on writing — and `spawn_blocking` work cannot be aborted. The next
/// append could then open the same file beside it. The handle now lives
/// under the lock instead, so this proves what a caller going away can
/// and cannot do: the record it abandoned is still written, and nothing
/// else touches the file until it is.
#[tokio::test]
async fn a_cancelled_append_keeps_the_next_one_from_overlapping_it() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    let (gate, mut entries, releases) = AppendGate::new();
    *store.faults().gate.lock().expect("arm the gate") = Some(gate);

    // Get one append as far as the gate, inside its critical section
    // with the store's lock held...
    let cancelled = store.clone();
    let mut first = Box::pin(async move { cancelled.append(intent("cancelled")).await });
    tokio::select! {
        _ = &mut first => panic!("a gated append cannot have finished"),
        entered = entries.recv() => entered.expect("the first append reaches the gate"),
    }
    // ...and then throw its caller away, exactly as a losing `select!`
    // branch or an abandoned request does.
    drop(first);

    let overlapping = store.clone();
    let second = tokio::spawn(async move { overlapping.append(intent("after-cancel")).await });

    // A bounded wait, because what is being proved is that nothing
    // happens: there is no event to await for a second append that must
    // not start. The gate signals on entry, so a released lock shows up
    // here as a value rather than as a timeout.
    let overlapped =
        tokio::time::timeout(std::time::Duration::from_millis(250), entries.recv()).await;
    assert!(
        overlapped.is_err(),
        "the second append entered the store while the cancelled one was still writing"
    );

    releases.send(()).expect("release the cancelled append");
    entries
        .recv()
        .await
        .expect("the second append reaches the gate once the first has left it");
    releases.send(()).expect("release the second append");
    second
        .await
        .expect("the second append task completes")
        .expect("the second append succeeds");

    assert_eq!(
        store.faults().peak_concurrent_appends(),
        1,
        "two appends were inside the store's critical section at once"
    );
    let written = fs::read_to_string(store.active_path()).expect("read back");
    let ids: Vec<String> = written
        .lines()
        .map(|line| {
            serde_json::from_str::<AuditRecord>(line)
                .expect("every line parses independently")
                .request_id
        })
        .collect();
    assert_eq!(
        ids,
        vec!["cancelled".to_string(), "after-cancel".to_string()],
        "the abandoned record is written, once, before the record that followed it"
    );
}

#[tokio::test]
async fn an_injected_append_failure_is_individually_matchable() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    store.faults().append.store(true, Ordering::SeqCst);

    let err = store
        .append(intent("req"))
        .await
        .expect_err("a failed write is not a success");
    assert!(
        matches!(&err, AuditStoreError::Append { path, .. } if path == store.active_path()),
        "expected an append failure, got {err:?}"
    );
    assert_eq!(
        fs::read_to_string(store.active_path()).expect("read back"),
        "",
        "a failed append leaves no record"
    );
}

#[tokio::test]
async fn an_injected_sync_failure_is_individually_matchable() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    store.faults().sync.store(true, Ordering::SeqCst);

    let err = store
        .append(intent("req"))
        .await
        .expect_err("a record that was not flushed is not durable");
    assert!(
        matches!(&err, AuditStoreError::Sync { path, .. } if path == store.active_path()),
        "expected a sync failure, got {err:?}"
    );
}

#[tokio::test]
async fn an_injected_directory_flush_failure_is_individually_matchable() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    store.faults().directory_sync.store(true, Ordering::SeqCst);

    let err = store
        .append(intent("req"))
        .await
        .expect_err("a new directory entry that was not flushed is not durable");
    assert!(
        matches!(&err, AuditStoreError::DirectorySync { path, .. } if path == store.active_path()),
        "expected a directory flush failure, got {err:?}"
    );
    // The one error that does not leave the trail as it was, and the
    // reason `append` documents it separately: the record itself was
    // written and flushed, and only the directory entry naming the file
    // it landed in is not yet durable. A caller that retried this record
    // would write it twice.
    let written = fs::read_to_string(store.active_path()).expect("read back");
    assert_eq!(written.lines().count(), 1, "the record itself was written");
    serde_json::from_str::<AuditRecord>(written.trim_end()).expect("and it is a whole record");
}

#[tokio::test]
async fn a_write_that_fails_halfway_leaves_no_partial_line() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    store.append(intent("first")).await.expect("append");
    let before = fs::read_to_string(store.active_path()).expect("read back");

    store.faults().partial_append.store(true, Ordering::SeqCst);
    let err = store
        .append(intent("torn"))
        .await
        .expect_err("a write that failed is not a success");
    assert!(
        matches!(&err, AuditStoreError::Append { path, .. } if path == store.active_path()),
        "a recovered partial write is an ordinary append failure, got {err:?}"
    );
    assert_eq!(
        fs::read_to_string(store.active_path()).expect("read back"),
        before,
        "the half-written line must be cut back off"
    );

    // The point of cutting it back off: the next record is a whole line
    // of its own rather than the tail of a broken one.
    store.faults().partial_append.store(false, Ordering::SeqCst);
    store.append(intent("second")).await.expect("append");
    let written = fs::read_to_string(store.active_path()).expect("read back");
    let ids: Vec<String> = written
        .lines()
        .map(|line| {
            serde_json::from_str::<AuditRecord>(line)
                .expect("every line parses independently")
                .request_id
        })
        .collect();
    assert_eq!(ids, vec!["first".to_string(), "second".to_string()]);
}

#[tokio::test]
async fn a_recovered_partial_write_is_flushed_before_it_is_reported_as_recovered() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    store.append(intent("first")).await.expect("append");
    let before = fs::read_to_string(store.active_path()).expect("read back");

    // The truncation lands, the flush that makes its new length durable
    // does not. Reading the file back would show the partial bytes
    // gone, because they are gone from the page cache; what is not
    // established is that they are gone from the disk, so a power
    // failure here could bring them back under an `Append` error that
    // promises it cannot.
    store.faults().partial_append.store(true, Ordering::SeqCst);
    store.faults().recovery_sync.store(true, Ordering::SeqCst);
    let err = store
        .append(intent("torn"))
        .await
        .expect_err("a write that failed is not a success");
    let AuditStoreError::PartialAppend { path, length, .. } = &err else {
        panic!("an unflushed recovery is not an ordinary append failure, got {err:?}");
    };
    assert_eq!(path, store.active_path());
    assert_eq!(
        *length,
        u64::try_from(before.len()).expect("fits u64"),
        "the error names the length the file was not demonstrably returned to"
    );
    assert_eq!(
        fs::read_to_string(store.active_path()).expect("read back"),
        before,
        "the truncation itself did land; only its durability is in doubt"
    );

    // With the flush working, the same recovery is an ordinary append
    // failure again, which is what makes the variant above the report
    // of the flush and not of the truncation.
    store.faults().recovery_sync.store(false, Ordering::SeqCst);
    let err = store
        .append(intent("torn again"))
        .await
        .expect_err("a write that failed is not a success");
    assert!(
        matches!(&err, AuditStoreError::Append { path, .. } if path == store.active_path()),
        "a recovery that was flushed is an ordinary append failure, got {err:?}"
    );
}

#[tokio::test]
async fn a_partial_write_that_cannot_be_undone_is_individually_matchable() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    store.append(intent("first")).await.expect("append");
    let before = fs::read_to_string(store.active_path()).expect("read back");

    store.faults().partial_append.store(true, Ordering::SeqCst);
    store.faults().truncate.store(true, Ordering::SeqCst);
    let err = store
        .append(intent("torn"))
        .await
        .expect_err("a write that failed is not a success");
    let AuditStoreError::PartialAppend { path, length, .. } = &err else {
        panic!("expected an unrecoverable partial write, got {err:?}");
    };
    assert_eq!(path, store.active_path());
    assert_eq!(
        *length,
        u64::try_from(before.len()).expect("fits u64"),
        "the error names the length the file could not be returned to"
    );
    // Reported as its own variant precisely because this is the one
    // case an `Append` error would describe wrongly.
    assert!(
        fs::read_to_string(store.active_path())
            .expect("read back")
            .len()
            > before.len(),
        "the partial bytes are still there, which is what the variant says"
    );
}

#[tokio::test]
async fn a_failed_directory_flush_is_retried_by_the_next_append() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    store.faults().directory_sync.store(true, Ordering::SeqCst);

    store
        .append(intent("first"))
        .await
        .expect_err("a new directory entry that was not flushed is not durable");
    assert!(
        store.dir_sync_pending(),
        "the flush the created file owes is still owed"
    );

    // The second append finds the active file already there. Without
    // the retained debt it would take the entry for durable and return
    // success, so this failing again is what proves it tried.
    let err = store
        .append(intent("second"))
        .await
        .expect_err("the entry is still not durable");
    assert!(
        matches!(&err, AuditStoreError::DirectorySync { path, .. } if path == store.active_path()),
        "expected the directory flush to be retried, got {err:?}"
    );

    store.faults().directory_sync.store(false, Ordering::SeqCst);
    store.append(intent("third")).await.expect("append");
    assert!(
        !store.dir_sync_pending(),
        "a flush that succeeded settles the debt"
    );

    let written = fs::read_to_string(store.active_path()).expect("read back");
    assert_eq!(
        written.lines().count(),
        3,
        "every record itself was written, as `append` documents"
    );
    for line in written.lines() {
        serde_json::from_str::<AuditRecord>(line).expect("and each is a whole record");
    }
}

/// Arms the directory flush failure on a store that is not built yet.
fn directory_sync_fault() -> FaultInjection {
    let faults = FaultInjection::default();
    faults.directory_sync.store(true, Ordering::SeqCst);
    faults
}

/// The owed-flush debt is a field in a process, and the disk holds no
/// trace of it. A daemon that exits owing one would otherwise hand the
/// next daemon an active file that looks settled: the file is there, so
/// an append reopens it, `sync_data`s its record and returns success
/// over a directory entry that may still not survive a power failure.
/// Construction flushing the directory once is what closes that.
#[tokio::test]
async fn a_reopened_store_settles_a_flush_the_previous_one_owed() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    store.faults().directory_sync.store(true, Ordering::SeqCst);
    store
        .append(intent("first"))
        .await
        .expect_err("the entry naming the file the record is in is not durable");
    assert!(store.dir_sync_pending(), "the flush is owed");
    let active = store.active_path().to_path_buf();
    drop(store);

    // The debt cannot be read off the disk, so the reopen does not try
    // to: it flushes unconditionally. Arming the failure through the
    // constructor is what proves the flush is attempted at all — the
    // handle that would otherwise expose the switch does not exist yet.
    let err = AuditRecordStore::open_for_tests_with_faults(
        store_settings(root.path()),
        directory_sync_fault(),
    )
    .await
    .expect_err("a store whose directory entries cannot be made durable is not usable");
    assert!(
        matches!(&err, AuditStoreError::DirectorySync { path, .. } if path == &active),
        "expected construction to fail on the directory flush, got {err:?}"
    );

    let reopened = open_in(root.path()).await;
    assert!(
        !reopened.dir_sync_pending(),
        "the flush construction performed settled the previous process's debt"
    );
    reopened.append(intent("second")).await.expect("append");
    assert!(
        !reopened.dir_sync_pending(),
        "and the append owed nothing further"
    );

    let written = fs::read_to_string(&active).expect("read back");
    assert_eq!(
        written.lines().count(),
        2,
        "the record the failed flush was reported for is still there"
    );
    for line in written.lines() {
        serde_json::from_str::<AuditRecord>(line).expect("and each is a whole record");
    }
}

#[tokio::test]
async fn a_required_rotation_that_fails_writes_no_record() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    fill_to_limit(&store).await;
    let before = fs::read_to_string(store.active_path()).expect("read back");

    store.faults().rotate.store(true, Ordering::SeqCst);
    let err = store
        .append(padded(FILLER, 400))
        .await
        .expect_err("a required rotation that fails must not write");
    assert!(
        matches!(&err, AuditStoreError::Rotate { .. }),
        "expected a rotation failure, got {err:?}"
    );
    assert_eq!(
        fs::read_to_string(store.active_path()).expect("read back"),
        before,
        "the pending record must not be appended"
    );
}

/// The directory flush is the last step of a rotation, and failing it
/// is still a rotation that did not complete. Reporting it as
/// `DirectorySync` would tell a caller what that error documents —
/// the record is written, do not retry it — about a record that was
/// never written at all, and the audit line would be lost to a caller
/// following the contract.
#[tokio::test]
async fn a_required_rotation_whose_directory_flush_fails_writes_no_record() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    let filled = fill_to_limit(&store).await;
    let before = fs::read_to_string(store.active_path()).expect("read back");
    assert!(
        !store.dir_sync_pending(),
        "the flushes the filling records owed all succeeded"
    );

    store.faults().directory_sync.store(true, Ordering::SeqCst);
    let err = store
        .append(padded(FILLER, 400))
        .await
        .expect_err("a rotation whose directory flush fails did not complete");
    assert!(
        matches!(&err, AuditStoreError::Rotate { path, .. } if path == store.active_path()),
        "expected a rotation failure rather than a post-write flush failure, got {err:?}"
    );
    assert!(
        store.dir_sync_pending(),
        "the flush the rotation's two new names owe is still owed"
    );

    // The rename and the fresh active file both happened; what did not
    // is the record, which is the whole difference between the two
    // errors.
    let names = generations(store.directory());
    assert_eq!(names.len(), 1, "the rename went through: {names:?}");
    assert_eq!(
        fs::read_to_string(store.directory().join(&names[0])).expect("read"),
        before,
        "the generation holds exactly what the active file held"
    );
    assert_eq!(
        fs::read_to_string(store.active_path()).expect("read back"),
        "",
        "the pending record was not written anywhere"
    );
    assert!(filled > 0, "the fill has to have written something");

    // And with the flush working again the same record is appendable,
    // which is the retry the `Rotate` spelling leaves open.
    store.faults().directory_sync.store(false, Ordering::SeqCst);
    store.append(padded(FILLER, 400)).await.expect("append");
    assert_eq!(
        fs::read_to_string(store.active_path())
            .expect("read back")
            .lines()
            .count(),
        1,
        "the retried record lands in the file the rotation created"
    );
    assert!(
        !store.dir_sync_pending(),
        "the flush that succeeded settles the rotation's debt too"
    );
}

#[tokio::test]
async fn a_record_that_cannot_fit_an_empty_file_is_refused() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    // Nothing the store itself can produce reaches this, because every
    // string it writes is capped — but the branch exists so a
    // misconfiguration cannot spin.
    let mut record = intent("req");
    record.request_id = "r".repeat(usize::try_from(MIN_AUDIT_MAX_FILE_BYTES).expect("fits usize"));
    let err = store
        .append(record)
        .await
        .expect_err("a record larger than the whole file is refused");
    assert!(
        matches!(&err, AuditStoreError::RecordTooLarge { .. }),
        "expected an oversize refusal, got {err:?}"
    );
}

/// An oversize record is refused from its own length, before anything
/// on disk is opened or created. Creating the active file on the way to
/// that refusal would leave a new directory entry behind — one the
/// refusal has no record to flush alongside, and that a process exiting
/// afterwards would leave unflushed — for an operation that wrote
/// nothing. The refusal has to be inert instead.
#[tokio::test]
async fn an_oversize_refusal_creates_no_name_to_settle() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    let active = store.active_path().to_path_buf();
    assert!(!active.exists(), "nothing has created the active file yet");

    let mut record = intent("req");
    record.request_id = "r".repeat(usize::try_from(MIN_AUDIT_MAX_FILE_BYTES).expect("fits usize"));
    let err = store
        .append(record)
        .await
        .expect_err("a record larger than the whole file is refused");
    assert!(
        matches!(&err, AuditStoreError::RecordTooLarge { .. }),
        "expected an oversize refusal, got {err:?}"
    );
    assert!(
        !active.exists(),
        "the refusal created no active file to flush"
    );
    assert!(
        !store.dir_sync_pending(),
        "and so left the directory owing nothing"
    );
    assert_eq!(
        generations(store.directory()),
        Vec::<String>::new(),
        "nor did it rotate anything"
    );

    // The store is untouched rather than merely unwritten: the next
    // fitting record creates the active file and settles its own entry,
    // exactly as it would have on a store the refusal never reached.
    store.append(intent("after")).await.expect("append");
    assert_eq!(
        fs::read_to_string(&active)
            .expect("read back")
            .lines()
            .count(),
        1,
        "the first record to fit is the one that creates the file"
    );
    assert!(
        !store.dir_sync_pending(),
        "and it flushed the entry it created"
    );
}

// ---------------------------------------------------------------------
// Store: rotation and retention
// ---------------------------------------------------------------------

/// A record whose serialized line is a known, comfortable size, so a
/// test can drive the active file to an exact boundary.
fn padded(request_id: &str, pad: usize) -> AuditRecord {
    AuditRecord::intent(
        ts(),
        request_id.to_string(),
        AuditVerb::Mint,
        "c".repeat(pad),
        requested(None),
    )
}

/// The request id every filler record carries, so each line is exactly
/// the same length and the boundary can be driven precisely.
const FILLER: &str = "filler";

/// Appends [`padded`] records until one more of them would cross the
/// limit, and returns the size the active file reached.
async fn fill_to_limit(store: &AuditRecordStore) -> u64 {
    let record = u64::try_from(padded(FILLER, 400).to_line().expect("a line").len())
        .expect("a line length fits u64");
    let mut appended = 0;
    loop {
        let current = match fs::metadata(store.active_path()) {
            Ok(meta) => meta.len(),
            Err(_) => 0,
        };
        if current + record > MIN_AUDIT_MAX_FILE_BYTES {
            assert!(
                generations(store.directory()).is_empty(),
                "filling to the boundary must not rotate"
            );
            return current;
        }
        store.append(padded(FILLER, 400)).await.expect("append");
        appended += 1;
        assert!(
            appended < 10_000,
            "the file must fill well inside 10000 records"
        );
    }
}

fn generations(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("read the store directory")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| parse_rotated_name(name).is_some())
        .collect();
    names.sort_unstable();
    names
}

#[tokio::test]
async fn the_active_file_rotates_before_it_would_exceed_its_limit() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    let before = fill_to_limit(&store).await;
    let record = padded(FILLER, 400).to_line().expect("a line").len();

    assert!(before > 0);
    assert!(
        before + u64::try_from(record).expect("fits u64") > MIN_AUDIT_MAX_FILE_BYTES,
        "the next record must be the one that would cross the limit"
    );

    store.append(padded(FILLER, 400)).await.expect("append");

    let names = generations(store.directory());
    assert_eq!(names.len(), 1, "exactly one rotation happened");
    let (_, sequence) = parse_rotated_name(&names[0]).expect("a generation name");
    assert_eq!(sequence, 0, "the first generation at a timestamp is 000000");
    assert!(names[0].ends_with("-000000.jsonl"), "{}", names[0]);

    let rotated = fs::read_to_string(store.directory().join(&names[0])).expect("read");
    assert_eq!(
        rotated.len(),
        usize::try_from(before).expect("fits usize"),
        "the rotated generation holds exactly what the active file held"
    );
    let live = fs::read_to_string(store.active_path()).expect("read back");
    assert_eq!(
        live.lines().count(),
        1,
        "the pending record went to the fresh file"
    );
    assert!(
        u64::try_from(live.len()).expect("fits u64") <= MIN_AUDIT_MAX_FILE_BYTES,
        "the active file never exceeds its limit"
    );
}

#[tokio::test]
async fn same_second_rotations_increment_the_six_digit_sequence() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;

    // Rotating three times inside the same second is what the sequence
    // exists for, so the stamp is held fixed and the sequence has to do
    // all the distinguishing.
    let moment = OffsetDateTime::parse("2026-08-23T12:34:56Z", &Rfc3339).expect("parses");
    for expected in 0..3_u32 {
        store
            .append(intent(&format!("r{expected}")))
            .await
            .expect("append");
        let produced = store
            .rotate_for_test(moment)
            .expect("a rotation inside the same second");
        assert_eq!(
            produced.file_name().expect("a name").to_string_lossy(),
            rotated_file_name("20260823T123456Z", expected)
        );
    }

    let names = generations(store.directory());
    assert_eq!(
        names,
        vec![
            rotated_file_name("20260823T123456Z", 0),
            rotated_file_name("20260823T123456Z", 1),
            rotated_file_name("20260823T123456Z", 2),
        ],
        "the sequence keeps the names sorting oldest first"
    );
}

#[tokio::test]
async fn rotation_trims_the_lexically_oldest_generations_first() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    let moment = OffsetDateTime::parse("2026-08-23T12:34:56Z", &Rfc3339).expect("parses");

    for index in 0..6_u32 {
        store
            .append(intent(&format!("r{index}")))
            .await
            .expect("append");
        store
            .rotate_for_test(moment + Duration::seconds(i64::from(index)))
            .expect("rotate");
        store.trim_for_test();
    }

    let names = generations(store.directory());
    assert_eq!(
        names.len(),
        3,
        "at most max_retained_files remain: {names:?}"
    );
    assert_eq!(
        names,
        vec![
            rotated_file_name("20260823T123459Z", 0),
            rotated_file_name("20260823T123500Z", 0),
            rotated_file_name("20260823T123501Z", 0),
        ],
        "the newest generations are the ones kept"
    );
}

#[tokio::test]
async fn opening_rotates_an_active_file_that_is_already_at_its_limit() {
    let root = tempfile::tempdir().expect("tempdir");
    let settings = store_settings(root.path());
    create_tree(root.path(), &settings.dir);
    fs::set_permissions(&settings.dir, fs::Permissions::from_mode(0o700)).expect("chmod");
    let active = settings.dir.join(ACTIVE_FILE_NAME);
    let oversized = vec![b'x'; usize::try_from(MIN_AUDIT_MAX_FILE_BYTES).expect("fits usize")];
    fs::write(&active, &oversized).expect("plant an already-full active file");

    let store = AuditRecordStore::open_for_tests(settings)
        .await
        .expect("the store opens by rotating");
    let names = generations(store.directory());
    assert_eq!(names.len(), 1, "the full file was rotated out of the way");
    assert_eq!(
        fs::metadata(store.active_path()).expect("stat").len(),
        0,
        "the fresh active file is empty"
    );
    assert_eq!(
        fs::read(store.directory().join(&names[0])).expect("read"),
        oversized
    );
}

#[tokio::test]
async fn opening_enforces_the_retained_generation_limit() {
    let root = tempfile::tempdir().expect("tempdir");
    let settings = store_settings(root.path());
    create_tree(root.path(), &settings.dir);
    fs::set_permissions(&settings.dir, fs::Permissions::from_mode(0o700)).expect("chmod");
    for index in 0..6_u32 {
        let name = rotated_file_name(&format!("2026082{index}T000000Z"), 0);
        fs::write(settings.dir.join(name), b"{}\n").expect("plant a generation");
    }

    let store = AuditRecordStore::open_for_tests(settings)
        .await
        .expect("the store opens");
    let names = generations(store.directory());
    assert_eq!(names.len(), 3, "opening re-enforces the limit: {names:?}");
    assert_eq!(
        names,
        vec![
            rotated_file_name("20260823T000000Z", 0),
            rotated_file_name("20260824T000000Z", 0),
            rotated_file_name("20260825T000000Z", 0),
        ]
    );
}

/// A neighbouring file whose name only looks like a generation is not
/// one. Retention deletes the lexically oldest generations, so treating
/// a lookalike as a member of the family would make the store delete a
/// file it does not own — and would let an unparseable timestamp decide
/// where the deletion boundary falls.
#[tokio::test]
async fn a_lookalike_name_is_neither_retained_nor_trimmed() {
    let root = tempfile::tempdir().expect("tempdir");
    let settings = store_settings(root.path());
    create_tree(root.path(), &settings.dir);
    fs::set_permissions(&settings.dir, fs::Permissions::from_mode(0o700)).expect("chmod");
    let lookalikes = [
        "registrar-audit-not-a-timestamp-000000.jsonl",
        "registrar-audit-20260230T123456Z-000000.jsonl",
    ];
    for name in lookalikes {
        fs::write(settings.dir.join(name), b"not ours\n").expect("plant a lookalike");
    }
    for index in 0..6_u32 {
        let name = rotated_file_name(&format!("2026082{index}T000000Z"), 0);
        fs::write(settings.dir.join(name), b"{}\n").expect("plant a generation");
    }

    let store = AuditRecordStore::open_for_tests(settings)
        .await
        .expect("the store opens");

    assert_eq!(
        generations(store.directory()),
        vec![
            rotated_file_name("20260823T000000Z", 0),
            rotated_file_name("20260824T000000Z", 0),
            rotated_file_name("20260825T000000Z", 0),
        ],
        "only real generations are counted, and the oldest three went"
    );
    for name in lookalikes {
        assert_eq!(
            fs::read(store.directory().join(name)).expect("the lookalike survives"),
            b"not ours\n",
            "{name}"
        );
    }
}

/// Retention is a capacity target, not a precondition on writing. A
/// trim that cannot delete anything is logged and the append that
/// follows — which fits the current file and needs nothing the trim
/// failed at — still succeeds.
///
/// The failure is injected by taking write permission off the store
/// directory, so the unlink really does fail rather than being mocked.
/// `root` ignores directory permissions entirely, so the failing half
/// is asserted only where it can actually fail.
#[tokio::test]
async fn a_trim_failure_is_logged_and_does_not_fail_a_fitting_append() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    store.append(intent("first")).await.expect("append");

    // Twice the retained limit, so a working trim would have plenty to
    // delete.
    for index in 0..6_u32 {
        let name = rotated_file_name(&format!("2026082{index}T000000Z"), 0);
        fs::write(store.directory().join(name), b"{}\n").expect("plant a generation");
    }

    if current_uid() == 0 {
        // Running as root: assert the ordinary path instead, and say so
        // rather than reporting a skipped branch as a pass.
        store.trim_for_test();
        assert_eq!(generations(store.directory()).len(), 3);
    } else {
        fs::set_permissions(store.directory(), fs::Permissions::from_mode(0o500))
            .expect("take write permission off the store directory");
        store.trim_for_test();
        assert_eq!(
            generations(store.directory()).len(),
            6,
            "the trim really did fail: nothing was deleted"
        );
        // The append still fits the file it already has, and needs
        // neither a rotation nor a new directory entry.
        store
            .append(intent("second"))
            .await
            .expect("a fitting append must survive a failed trim");
        fs::set_permissions(store.directory(), fs::Permissions::from_mode(0o700))
            .expect("restore the store directory");
    }

    store.append(intent("third")).await.expect("append");
    let written = fs::read_to_string(store.active_path()).expect("read back");
    assert!(
        written.lines().count() >= 2,
        "the records written around the failed trim are all there"
    );
    for line in written.lines() {
        serde_json::from_str::<AuditRecord>(line).expect("every line parses");
    }
}

// ---------------------------------------------------------------------
// Store: the public consumer surface
// ---------------------------------------------------------------------

/// A reader outside this module sees the whole format through
/// `bootroot::registrar::audit` and nothing else: the record types, the
/// append API and the typed error. This names them the way such a
/// reader would.
#[test]
fn the_public_surface_names_the_whole_format() {
    let record: AuditRecord = AuditRecord::outcome(
        ts(),
        "req".to_string(),
        AuditVerb::Deregister,
        CALLER.to_string(),
        RequestedIdentity {
            service_name: "review".to_string(),
            host: "h1".to_string(),
            instance: None,
        },
        Some("review-h1".to_string()),
        AuditOutcome::Refused {
            reason: RefusalReason::HostMismatch,
            detail: None,
        },
    );
    assert_eq!(record.phase, AuditPhase::Outcome);
    assert_eq!(record.phase.as_str(), "outcome");
    assert_eq!(AuditPhase::Intent.to_string(), "intent");
    let line: Vec<u8> = record.to_line().expect("a line");
    let parsed: AuditRecord = serde_json::from_slice(&line[..line.len() - 1]).expect("parses");
    assert_eq!(parsed.verb, AuditVerb::Deregister);
    let error: AuditStoreError = AuditStoreError::RecordTooLarge {
        bytes: 1,
        limit: MIN_AUDIT_MAX_FILE_BYTES,
    };
    assert!(error.to_string().contains("exceeds"));
}

/// The active file's name and the temporary-store helper are what the
/// store tests above lean on; asserting them here keeps a rename from
/// being invisible.
#[test]
fn the_temporary_store_helper_uses_the_documented_names() {
    let store = AuditRecordStore::open_temporary().expect("a temporary store");
    assert_eq!(
        store.active_path(),
        store.directory().join(ACTIVE_FILE_NAME)
    );
    assert_eq!(mode_of(store.directory()), 0o700);
}

/// The temporary store's directory goes away with the last handle, so a
/// verb fixture that holds one leaves nothing behind.
#[test]
fn a_temporary_store_directory_lives_exactly_as_long_as_its_handles() {
    let path: PathBuf;
    {
        let store = AuditRecordStore::open_temporary().expect("a temporary store");
        path = store.directory().to_path_buf();
        assert!(path.is_dir());
        let clone = store.clone();
        drop(store);
        assert!(path.is_dir(), "a surviving clone keeps the directory alive");
        drop(clone);
    }
    assert!(
        !path.exists(),
        "the last handle takes the directory with it"
    );
}

/// A store opened over a directory the test process does not own is
/// refused. Built by pointing the store at a directory whose uid is
/// asserted directly, so the branch is exercised without needing a
/// second uid to chown to.
#[test]
fn production_requires_uid_zero_ownership() {
    let dir = TempDir::new().expect("tempdir");
    let uid = fs::symlink_metadata(dir.path()).expect("stat").uid();
    let expected = directory_condition(false, true, uid, 0o040_700, 0);
    if uid == 0 {
        assert_eq!(expected, None, "a root-owned directory passes");
    } else {
        assert_eq!(
            expected,
            Some(PathCondition::Owner {
                expected: 0,
                found: uid
            }),
            "a non-root directory is refused by the production constructor"
        );
    }
}

/// A file planted by another writer inside the store directory is
/// re-audited from the descriptor the append opened, not only from the
/// path that was inspected before it.
#[tokio::test]
async fn the_active_file_is_re_audited_from_the_opened_descriptor() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    store.append(intent("first")).await.expect("append");

    // A directory in the active file's place is neither a regular file
    // nor something an append may write into.
    fs::remove_file(store.active_path()).expect("remove the active file");
    fs::create_dir(store.active_path()).expect("plant a directory");
    let err = store
        .append(intent("second"))
        .await
        .expect_err("a directory in the active file's place must be refused");
    assert!(
        matches!(
            &err,
            AuditStoreError::OpenActiveFile { path, .. } | AuditStoreError::UnsafePath { path, .. }
                if path == store.active_path()
        ),
        "expected the active path to be named, got {err:?}"
    );
}

/// A symbolic link planted at the active path after the store was
/// opened is refused at append time, not followed.
#[tokio::test]
async fn an_active_file_symlinked_after_opening_is_refused() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    store.append(intent("first")).await.expect("append");

    let decoy = root.path().join("decoy.jsonl");
    fs::write(&decoy, b"").expect("write the decoy");
    fs::remove_file(store.active_path()).expect("remove the active file");
    std::os::unix::fs::symlink(&decoy, store.active_path()).expect("plant the symlink");

    let err = store
        .append(intent("second"))
        .await
        .expect_err("a symlinked active file must be refused");
    assert!(
        matches!(
            &err,
            AuditStoreError::UnsafePath { path, condition }
                if path == store.active_path() && *condition == PathCondition::Symlink
        ),
        "expected a symlink refusal naming the active path, got {err:?}"
    );
    assert_eq!(
        fs::read(&decoy).expect("read the decoy"),
        b"",
        "the link's target must not be written through"
    );
}

/// An append that has to create the active file writes a record that
/// parses, which is the path a fresh store takes on its very first
/// record.
#[tokio::test]
async fn the_first_append_creates_the_active_file() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = open_in(root.path()).await;
    assert!(!store.active_path().exists());
    store.append(intent("first")).await.expect("append");
    assert!(store.active_path().is_file());

    // And a second append reuses it rather than truncating it.
    store.append(intent("second")).await.expect("append");
    let mut handle = fs::OpenOptions::new()
        .append(true)
        .open(store.active_path())
        .expect("open");
    handle.flush().expect("flush");
    assert_eq!(
        fs::read_to_string(store.active_path())
            .expect("read back")
            .lines()
            .count(),
        2
    );
}
