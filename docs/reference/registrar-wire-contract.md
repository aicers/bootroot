<!-- markdownlint-configure-file {
  "MD013": { "tables": false, "code_blocks": false }
} -->

# Registrar endpoint wire contract (mirrored)

**Mirror rule.** This repository *mirrors* these names and does not author
them; where this reference and `aicers/review-protocol` disagree, that
repository wins and this file is corrected.

This file is the single source of truth **inside this repository** for the
caller-facing spellings of the `node.enroll` family: the codec is written
against it, the golden serialization fixtures are generated from it, and the
acceptance suite asserts identifiers against it rather than against a spelling
restated in an issue body. It is checked in outside the mirrored
`docs/en/` + `docs/ko/` operator pair, on the precedent of `docs/rfcs/`: it is
not operator documentation and not translatable, so `mkdocs.yml` lists it in
neither locale's nav and there is no `docs/ko/` counterpart. Its path —
`docs/reference/registrar-wire-contract.md` — is stable and is what a test
reads it by.

The transcribed half below is written as tables with stable columns, one row
per name, so a downstream test can recover every name and every identifier's
class from the rows alone. **No externally owned name appears only in prose.**
Commentary is commentary; the rows are the contract.

## 1. Provenance

One revision line covers everything read from the source document. Items
obtained any other way carry their own pointer in the `Provenance` column.

| Code | Repository | File / location | Section | Revision (read 2026-08-05) |
| --- | --- | --- | --- | --- |
| `RFC-C §5` | `aicers/review-protocol` | `docs/rfcs/0001-node-package-and-enroll.md` | §5 `node.enroll` (proposed code 110) | `4612d05eba6684881f72c7ace95840bbc37d6cfb` |
| `RFC-C §6` | `aicers/review-protocol` | `docs/rfcs/0001-node-package-and-enroll.md` | §6 Version negotiation and compatibility | `4612d05eba6684881f72c7ace95840bbc37d6cfb` |
| `RFC-C §7` | `aicers/review-protocol` | `docs/rfcs/0001-node-package-and-enroll.md` | §7 Remaining details and in-repo ratification | `4612d05eba6684881f72c7ace95840bbc37d6cfb` |
| `RFC-C §8` | `aicers/review-protocol` | `docs/rfcs/0001-node-package-and-enroll.md` | §8 Acceptance criteria | `4612d05eba6684881f72c7ace95840bbc37d6cfb` |
| `RP#218` | `aicers/review-protocol` | issue [#218](https://github.com/aicers/review-protocol/issues/218) body | Scope / Constraints / Acceptance criteria | body revision of 2026-08-05T00:08:28Z (issue open, unimplemented) |
| `RFC-F §5.1` | `aicers/bootroot` | `docs/rfcs/0001-registrar-role-and-non-self-propagation.md` | §5.1 Restricted registrar mint verb | this repository, working tree |
| `RFC-F §5.6` | `aicers/bootroot` | `docs/rfcs/0001-registrar-role-and-non-self-propagation.md` | §5.6 Audit record for both verbs | this repository, working tree |
| `BR#759` | `aicers/bootroot` | issue [#759](https://github.com/aicers/bootroot/issues/759) body | Scope | this repository's own expectation, **not** transcribed from the source |
| `bootroot` | `aicers/bootroot` | source paths cited per row | — | this repository, working tree |

The source document has exactly one commit in its history — `7a6c7e2`, the
revision it was read at when `aicers/bootroot` issue #759 was written — so the
content at `4612d05` (`origin/main` at the time of transcription) is byte
identical to the revision that issue pinned. Re-reading it later means
re-reading `origin/main` and updating the revision cell above.

The source is an **accepted RFC whose code does not exist yet**. There is no
crate release and no importable type to check a spelling against; this
reference is pinned to the document and its revision, never to a crate
version.

## 2. Types

| Name | Kind | Owner | Provenance |
| --- | --- | --- | --- |
| `NodeEnrollRequest` | enum (request) | review-protocol | `RFC-C §5` |
| `NodeEnrollResponse` | enum (response) | review-protocol | `RFC-C §5` |
| `NodeEnrollError` | enum (typed failure) | review-protocol | `RP#218` |
| `RegistrarUnavailableReason` | enum (closed reason set) | review-protocol | `RP#218` |
| `ServiceSpec` | struct | review-protocol (contents externally owned, see §8.3) | `RFC-C §5` |
| `DeliveryMode` | enum | review-protocol | `RFC-C §5` |
| `BootstrapMaterial` | struct | review-protocol (`ca_anchor` contents bootroot-owned, see §8.1) | `RFC-C §5` |
| `ReloadHook` | newtype over `String`, opaque | review-protocol | `RP#218` |
| `CertGroup` | newtype over `String`, opaque | review-protocol | `RP#218` |
| `AgentInfo` | struct (handshake), not part of the `node.enroll` family | review-protocol | `RFC-C §7`, `RFC-C §8` |

`RFC-C §5` names the six typed errors in prose bullets and does **not** spell
an enclosing enum type for them; `NodeEnrollError` and
`RegistrarUnavailableReason` are the names `RP#218` gives those two enums, and
they are recorded here on that pointer rather than on the RFC's.

## 3. Family identifiers and request code

| Name | Kind | Value | Provenance |
| --- | --- | --- | --- |
| `node.enroll` | ServiceId (family) | — | `RFC-C §5` |
| `node.enroll.register` | ServiceId (method) | — | `RFC-C §5` |
| `node.enroll.deregister` | ServiceId (method) | — | `RFC-C §5` |
| `NodeEnroll` | RequestCode variant | `110` | `RFC-C §5`, `RP#218` |

## 4. Requests

### 4.1 `NodeEnrollRequest` variants

| Variant | Meaning | Provenance |
| --- | --- | --- |
| `Register` | Mint a service identity and return its bootstrap material. | `RFC-C §5` |
| `Deregister` | Tear down a service identity on uninstall. | `RFC-C §5` |

### 4.2 `Register` fields

Seven fields. The request carries the identity's **parts**, never a composed
name.

| Field | Type | Owner | Notes | Provenance |
| --- | --- | --- | --- | --- |
| `service_name` | `String` | review-protocol | The component's plain keyword; a single DNS label (see §7, property `service_name shape`). | `RFC-C §5` |
| `delivery_mode` | `DeliveryMode` | review-protocol | See §4.5; bootroot's local counterpart in §8.2. | `RFC-C §5` |
| `host` | `String` | review-protocol | The target host's single DNS label. | `RFC-C §5` |
| `instance` | `Option<u32>` | review-protocol | Instance number scoped by `{service_name}.{hostname}`; `None` for a component whose multiplicity class has no instance dimension. | `RFC-C §5` |
| `spec` | `ServiceSpec` | mirrored field name, externally owned contents (§4.4) | Applied on a first mint and compared on a re-register. | `RFC-C §5` |
| `wrap_ttl` | `Duration` | review-protocol | *Requested* lifetime of the wrapped material; the registrar MAY clamp it. | `RFC-C §5` |
| `idempotency_key` | `String` | review-protocol | Correlation handle, not a response cache (see §7). | `RFC-C §5` |

### 4.3 `Deregister` fields

Four fields.

| Field | Type | Owner | Notes | Provenance |
| --- | --- | --- | --- | --- |
| `service_name` | `String` | review-protocol | Same meaning and shape as on `Register`. | `RFC-C §5` |
| `host` | `String` | review-protocol | Refused when it is not the identity's registrar-bound host. | `RFC-C §5` |
| `instance` | `Option<u32>` | review-protocol | Same meaning as on `Register`. | `RFC-C §5` |
| `idempotency_key` | `String` | review-protocol | Correlation handle. | `RFC-C §5` |

### 4.4 `ServiceSpec` fields

Four fields, and four is the whole shape. The field *name* `spec` is
review-protocol's; its *contents* mirror the provisioning tool's
(**bootler**) `ServiceRegistration` (`core/src/product.rs:730`) — **externally
owned content inside a mirrored field name**, authored by neither
review-protocol nor bootroot. There is deliberately **no** privilege field.

| Field | Type | Owner | Notes | Provenance |
| --- | --- | --- | --- | --- |
| `component` | `String` | bootler (`ServiceRegistration`) | Canonical package id. **Not** validated against the safe-set. | `RFC-C §5` |
| `service_name` | `String` | bootler (`ServiceRegistration`) | The component's plain keyword. **Not** validated against the safe-set. | `RFC-C §5` |
| `reload` | `ReloadHook` | bootler (`ServiceRegistration`) | Validated against the registrar's rendered safe-set. | `RFC-C §5`, `RFC-F §5.1` |
| `cert_group` | `Option<CertGroup>` | bootler (`ServiceRegistration`) | Validated against the registrar's rendered safe-set. | `RFC-C §5`, `RFC-F §5.1` |

What the pinned source states is the safe-set half: `RFC-C §5` and `RFC-F §5.1`
both say the registrar safe-set validates **`cert_group` and `reload`** and
name no rule for the other two. **The source states nothing about how
`component` and `spec.service_name` are checked.** This repository's own
expectation — that they are compared for agreement with the wire
`service_name` rather than against the safe-set — is recorded here on
`BR#759`, not transcribed from the source; if the registrar's verb work
settles it differently, that is a change to this repository, not a drift from
review-protocol.

Either way, all four field names ride the wire and a codec must carry them: one
that narrowed `spec` to an opaque blob, or to the safe-set pair alone, would
drop a payload the other two checks depend on.

### 4.5 `DeliveryMode` variants

| Variant | Meaning | Provenance |
| --- | --- | --- |
| `LocalFile` | Material placed on the host out of band. | `RFC-C §5` |
| `RemoteBootstrap` | `bootroot-remote` enrollment via the on-host agent. | `RFC-C §5` |

## 5. Responses

### 5.1 `NodeEnrollResponse` variants

`RFC-C §5` models the success surface as a **single response enum with two
variants**. `RP#218` adds a third, `Failed`, so a typed failure rides the
response rather than the `Result<_, String>` channel; it is recorded here on
its own pointer, and `RP#218` states that reconciling the RFC's text with it is
a later document-sync pass in that repository, not a contradiction to resolve
here.

| Variant | Payload | For | Wire index | Provenance |
| --- | --- | --- | --- | --- |
| `Material` | `BootstrapMaterial` | `Register` | 0 | `RFC-C §5` |
| `Done` | **none — a bare acknowledgement carrying no fields at all** | `Deregister` | 1 | `RFC-C §5` |
| `Failed` | `NodeEnrollError` | both verbs | 2 | `RP#218` |

`Done` carries **no payload**. There is no deregister response body to look
for, and a codec models it as a unit variant rather than inventing an empty
struct for it.

### 5.2 `BootstrapMaterial` fields

Four fields.

| Field | Type | Owner | Notes | Provenance |
| --- | --- | --- | --- | --- |
| `role_id` | `String` | review-protocol | The service `AppRole` role id. | `RFC-C §5` |
| `wrapped_secret_id` | `String` | review-protocol | Response-wrapped `secret_id`; single-use, short-TTL, persisted nowhere. | `RFC-C §5` |
| `ca_anchor` | `Vec<u8>` | mirrored field name, **bootroot-owned contents** (§8.1) | The CA anchor the target verifies with. | `RFC-C §5` |
| `expires_at` | `DateTime<Utc>` | review-protocol | The **granted absolute deadline** after any registrar clamp — not the requested `wrap_ttl` echoed back. | `RFC-C §5` |

## 6. Typed enroll errors

### 6.1 The identifier set

Seven identifiers: the **six** the source's acceptance section counts, plus
the **one** addition this repository raised and `aicers/review-protocol`
landed (§6.3). `Class` is `permanent` or `retryable`. `Teardown owed` is
whether the manager's pre-armed teardown obligation survives the failure.
`Wire index` is the bincode declaration index, which is the wire encoding.

| Identifier | Payload | Class | Teardown owed | Wire index | Provenance |
| --- | --- | --- | --- | --- | --- |
| `ServiceSpecConflict` | none | permanent | no | 0 | `RFC-C §5`, `RFC-C §8` |
| `ServiceNameCollision` | none | permanent | no | 1 | `RFC-C §5`, `RFC-C §8` |
| `ServiceInstanceMismatch` | none | permanent | no | 2 | `RFC-C §5`, `RFC-C §8` |
| `ServiceHostMismatch` | none | permanent | no | 3 | `RFC-C §5`, `RFC-C §8` |
| `RegistrarUnavailable` | `reason: RegistrarUnavailableReason` | permanent | only for `PostMintUnrecordable` | 4 | `RFC-C §5`, `RFC-C §8` |
| `RegistrarBusy` | `retry_after: Duration` | retryable | no | 5 | `RFC-C §5`, `RFC-C §8` |
| `ServiceLabelInvalid` | none (unit variant) | permanent | no | 6 | `RP#218` |

The split is the property the whole set exists for: **`RegistrarBusy` is the
only retryable identifier**, and every permanent one means *until an operator
acts*. Wire indices come from `RP#218`, which fixes the declaration order and
states that `ServiceLabelInvalid` appends at index 6 rather than being grouped
with the other `Service*` variants; reordering either enum silently remaps
already-encoded bytes.

### 6.2 What each identifier refuses

| Identifier | Refusal | Provenance |
| --- | --- | --- |
| `ServiceSpecConflict` | Same identity, same bound host, different `spec` (`cert_group` or `reload`). Mints nothing. | `RFC-C §5` |
| `ServiceNameCollision` | The derived registration identity is already bound to a **different** host. Raised before the spec match. | `RFC-C §5` |
| `ServiceInstanceMismatch` | `instance` contradicts the component's multiplicity class — **and**, intentionally, a component with **no entry** in the multiplicity table (§6.4). Raised before any mint. | `RFC-C §5`, `RFC-F §5.1`, `RP#218` |
| `ServiceHostMismatch` | A `Deregister` whose `host` is not the identity's bound host. Never performs a teardown. | `RFC-C §5` |
| `RegistrarUnavailable` | A fail-closed condition, carrying one reason from the closed set in §6.5. | `RFC-C §5` |
| `RegistrarBusy` | The registrar's rate limit, with the delay to honour. | `RFC-C §5`, `RFC-F §5.6` |
| `ServiceLabelInvalid` | The `service_name` or the `host` is not a single DNS label, so the registrar refused **before** deriving the registration identity at all. Nothing minted, nothing probed. | `RP#218` |

### 6.3 The added identifier, and where it landed

**Settled: the spelling is `ServiceLabelInvalid`.** This repository proposed
it for the pre-derivation, non-DNS-label refusal, which the existing six
identifiers do not carry. `aicers/review-protocol` landed that spelling in the
scope of issue
[#218](https://github.com/aicers/review-protocol/issues/218) — the issue body
revised 2026-08-05T00:08:28Z defines `NodeEnrollError` with seven variants,
names `ServiceLabelInvalid` as the seventh, fixes it as a payload-free unit
variant at declaration index 6, classifies it as not retryable with no
teardown owed, and records that it originates in `aicers/bootroot` issue
[#759](https://github.com/aicers/bootroot/issues/759). The row in §6.1 records
the landed spelling and no other. Implementing it is that repository's work,
tracked on that issue.

### 6.4 Absent multiplicity entry keeps `ServiceInstanceMismatch`

A component with **no entry** in the multiplicity table maps to
`ServiceInstanceMismatch`. **This is intentional — a second meaning of an
existing identifier, not a collision to be resolved later.** It is fixed by
three merged design documents, and this effort's rate-limit rationale is
written around `ServiceInstanceMismatch` being the cheapest refusal. Do not
"fix" it by adding an eighth identifier, and do not widen `ServiceLabelInvalid`
to take it: the two refusals are neighbours on the registrar's pre-derivation
arm, which is exactly why they get confused. (`RFC-C §5`, `RFC-F §5.1`,
`RP#218`.)

### 6.5 `RegistrarUnavailable` reason set (closed)

Six reasons. The source states the set is **closed**.

| Reason | Condition | Nothing minted | Teardown owed | Source | Wire index | Provenance |
| --- | --- | --- | --- | --- | --- | --- |
| `CredentialInvalid` | The registrar's client certificate lapsed or was rejected by the endpoint. | yes | no | registrar response | 0 | `RFC-C §5`, `RFC-C §8` |
| `NotProvisioned` | The bootler-rendered file carrying the safe-set, multiplicity map and `domain` is missing or unreadable — a deliberate hard failure. | yes | no | registrar response | 1 | `RFC-C §5`, `RFC-C §8` |
| `AuditUnwritable` | The **intent** audit record cannot be written, so the verb refuses before creating anything. Intent phase only. | yes | no | registrar response | 2 | `RFC-C §5`, `RFC-C §8` |
| `EndpointUnreachable` | The bootroot daemon endpoint is down or not listening. | yes | no | registrar response | 3 | `RFC-C §5`, `RFC-C §8` |
| `PostMintUnrecordable` | The **outcome** audit record could not be written *after* a successful mint. | no | **yes** | registrar response | 4 | `RFC-C §5`, `RFC-C §8` |
| `RegistrarUnreachable` | Review could not reach the registrar agent at all — **synthesized by the manager**, never returned by the registrar. | yes | no | manager-synthesized | 5 | `RFC-C §5`, `RFC-C §8` |

`PostMintUnrecordable` is the only reason that leaves a teardown owed and the
only one under which something was minted; `RegistrarUnreachable` is the only
one the manager produces without any registrar response.

The reasons' order is the source's; that the order *is* the wire encoding comes
from `RP#218`, on the same terms as §6.1 — `RegistrarUnavailableReason` is its
own bincode-encoded enum, so reordering it silently remaps already-encoded
bytes.

## 7. Recorded properties

Load-bearing facts transcribed as their own rows, so a later upstream change
surfaces as a diff to this file rather than as an inference nobody re-read.

| Property | Value | Provenance |
| --- | --- | --- |
| `generic or catch-all error member` | **None. The set has no generic, catch-all, `Other` or `Unknown` member.** See §7.1. | `RFC-C §5`, `RFC-C §8`, `RP#218` |
| `RegistrarUnavailable reason set closed` | yes — and the reason set likewise has no catch-all member | `RFC-C §5`, `RFC-C §8` |
| `service_name shape` | **The source states it:** the component's *plain keyword* (`piglet`, `roxyd`), a single DNS label, **never host- or instance-qualified** — not a composed `<component>-<host>` name. | `RFC-C §5` |
| `host shape` | **The source states it:** the target host's single DNS label. | `RFC-C §5` |
| `composed name on the wire` | None. The request carries the identity's parts and the registrar derives both the certificate name and the namespace key from them. | `RFC-C §5` |
| `name-does-not-match-host error` | Does not exist, deliberately — with no caller-supplied composed name there is no such mismatch to express. | `RFC-C §5` |
| `Deregister of an absent identity` | For the **matching host**, returns `Done` — not an error. This is the idempotent re-drive the verb pair is built around. | `RFC-C §5` |
| `Deregister for a wrong host` | Refused with `ServiceHostMismatch`, never a `Done` teardown. | `RFC-C §5` |
| `Done payload` | None. `Done` carries no fields at all. | `RFC-C §5` |
| `expires_at semantics` | The **granted absolute deadline** after any registrar clamp; the manager MUST NOT assume it equals the requested `wrap_ttl`. | `RFC-C §5` |
| `idempotency_key semantics` | A correlation handle only. `Register` always returns **fresh** material; the key is **not** a response cache and no material is persisted. | `RFC-C §5` |
| `retryable identifiers` | Exactly one: `RegistrarBusy`. | `RFC-C §8` |
| `teardown-owed failures` | Exactly one: `RegistrarUnavailable { reason: PostMintUnrecordable }`. | `RFC-C §5`, `RFC-C §8` |
| `absent multiplicity entry` | Maps to `ServiceInstanceMismatch`, intentionally (§6.4). | `RFC-C §5`, `RFC-F §5.1`, `RP#218` |
| `typed errors on the error channel` | Never. Typed failures ride `NodeEnrollResponse::Failed`; `Result<_, String>` is left to transport and parse failures. | `RP#218` |

### 7.1 There is no generic or catch-all identifier

Stated explicitly, because a mapping downstream depends on the answer: **the
typed enroll error set has no generic, catch-all, `Other` or `Unknown`
member.** `RFC-C §8` enumerates the set as exactly six and treats it as
complete; `RFC-C §5` uses "generic error" throughout to mean the *untyped*
failure that arrives when no typed identifier applies — the outcome the whole
family was typed to prevent — never as a member of the set. `RP#218`'s
seven-variant `NodeEnrollError` likewise has none.

That absence is what makes the endpoint codec's mapping sound: a transient verb
failure (a briefly unreachable OpenBao, a daemon-side invariant violation) maps
onto **no typed identifier at all**, and a failure carrying none is what the
manager reads as generic and classifies as transient. Every permanent
identifier means *until an operator acts*, so there is nothing else for a
retryable failure to become.

**If a generic member is ever added upstream, that mapping must be
re-specified before it is implemented** — the codec would emit that member
instead of an absent identifier. This row is the trip-wire: a member added
upstream shows up as a change to this file.

## 8. Locally owned contents inside mirrored field names

Two fields carry names this repository mirrors and contents this repository
owns. Both are recorded here so the codec narrows neither.

### 8.1 `ca_anchor` — bootroot-owned contents

`RFC-C §5` types the field `ca_anchor: Vec<u8>`, describes its payload as this
repository's existing bootstrap material (`bootstrap.json`) and points back
here rather than specifying bytes. What this repository puts in it:

| Item | Encoding | Source | Provenance |
| --- | --- | --- | --- |
| `trusted_ca_sha256` | A list of 64-character **lowercase hex** SHA-256 digests, one per CA certificate, each taken over the certificate's **DER** bytes. Validated at exactly 64 hex characters and matched case-insensitively against the bundle. | `src/trust_bootstrap.rs:12` (`TRUSTED_CA_KEY`), `src/kv_payload.rs:19`, `:179`, `src/tls.rs:406` (`sha256_hex`) | `bootroot` |
| `ca_bundle_pem` | The CA bundle as **PEM text** (UTF-8): one or more `CERTIFICATE` blocks, which must parse to at least one certificate. | `src/trust_bootstrap.rs:13` (`CA_BUNDLE_PEM_KEY`), `src/tls.rs:208` (`parse_pem_to_cert_list`) | `bootroot` |

Both values must stay mutually consistent: every `trusted_ca_sha256` entry
matches the SHA-256 of some certificate in `ca_bundle_pem`
(`src/kv_payload.rs:64`). This repository's existing bootstrap artifact carries
them as two separate JSON fields under exactly these two names
(`src/bin/bootroot-remote/main.rs:336`, `BootstrapArtifact`). The **byte
framing** that packs the two into the single `ca_anchor` byte string is the one
open item — see §10.

### 8.2 `delivery_mode` — mirrored variants, local counterpart

| Wire variant | bootroot counterpart | bootroot serialized form | Provenance |
| --- | --- | --- | --- |
| `LocalFile` | `DeliveryMode::LocalFile` (`src/state.rs:188`) | `local-file` (serde `kebab-case`, bootroot's own TOML/JSON) | `RFC-C §5`, `bootroot` |
| `RemoteBootstrap` | `DeliveryMode::RemoteBootstrap` (`src/state.rs:188`) | `remote-bootstrap` (serde `kebab-case`, bootroot's own TOML/JSON) | `RFC-C §5`, `bootroot` |

The wire spellings are the variant names above; the kebab-case strings are
bootroot's local serialization and are **not** the wire encoding.

### 8.3 `spec` — externally owned contents

Recorded in §4.4: the field name is review-protocol's, the four-field shape is
bootler's `ServiceRegistration`, and neither is this repository's to change.

## 9. `AgentInfo` tail — `audit_health`

Mirrored on the same terms as everything above, so this repository has the
spelling on record. **Nothing in this repository ever writes this tail.** The
bootroot daemon exposes its audit-store low-water state and its
intent-without-outcome count on the mint/deregister endpoint; the co-located
registrar roxyd relays them onto the tail field below, and rendering them is
the control plane's. Only the registrar populates it.

| Tail field | Populated by | Relevance here | Provenance |
| --- | --- | --- | --- |
| `capabilities` | every agent | none | `RFC-C §7`, `RFC-C §8` |
| `active_trust_epoch` | every agent | none | `RFC-C §7`, `RFC-C §8` |
| `manifest_formats` | every agent | none | `RFC-C §7`, `RFC-C §8` |
| `provisioning_fingerprint` | the registrar only | none — relayed, not written here | `RFC-C §7`, `RFC-C §8` |
| `audit_health` | the registrar only | carries values read from the bootroot endpoint; bootroot's half of the path ends at the endpoint | `RFC-C §7`, `RFC-C §8`, `RFC-F §5.6` |

**Transcribed as found:** the source disagrees with itself on the tail's
*order*. `RFC-C §7` appends `manifest_formats`, `audit_health`,
`provisioning_fingerprint` "in this order", while `RFC-C §8` states the tail as
`capabilities`, `active_trust_epoch`, `manifest_formats`,
`provisioning_fingerprint`, `audit_health` — the order used in the table above.
Nothing in this repository writes or decodes that tail, so the discrepancy is
recorded rather than resolved; resolving it is `aicers/review-protocol`'s.

## 10. Resolved local item

The pinned source types `ca_anchor` as `Vec<u8>` and delegates its contents to
this repository. The registrar endpoint's v1 codec resolves that byte framing.

| Item | State | Owner | Where it is decided |
| --- | --- | --- | --- |
| `ca_anchor` byte framing | resolved — compact UTF-8 JSON `{"trusted_ca_sha256":[...],"ca_bundle_pem":"..."}` in that member order, standard padded RFC 4648 base64 encoded for the wire | `aicers/bootroot` | `src/registrar/endpoint/protocol.rs` |

The JSON requires both non-empty members, one lowercase SHA-256 DER digest per
PEM certificate in the same order, LF-only PEM with one trailing LF, and no
additional member. The codec decodes the base64 bytes to `serde_json::Value`
and validates them with `parse_trust_payload` before applying these stricter
framing checks.

## 10.1 Bootroot endpoint protocol v1

The endpoint uses one `serde_json` object per framed payload. Every request
and response carries the required integer `protocol_version: 1`; unknown
members are accepted when decoding, but absent or unsupported versions are
rejected. Data-carrying errors use an internally tagged object with `id` as
the tag, while fieldless enums retain their exact externally owned spelling.

The version rule belongs to the `ProtocolVersion` value type, not to a
direction-specific decoder: both requests and responses reject an absent or
unsupported version. An unsupported version is a meaning this build does not
implement, whereas an unknown member is an additive extension. The canonical
version is the `PROTOCOL_VERSION` constant, currently `1`.

Requests carry `protocol_version` followed by the members of §§4.2 and 4.3 in
their table order, and no bootroot-owned member beyond the version. The
externally owned request strings remain strings in JSON; `instance` is an
unquoted unsigned `u32`, and the lifetime is an unquoted non-negative whole
second integer. Optional `instance` and `spec.cert_group` are omitted rather
than `null`. The delivery-mode spelling and every member name remain the
transcribed source vocabulary in §4; this endpoint does not recase or
interpret them. In particular, the idempotency key is opaque and the reload
and certificate-group strings are passed through without validation.

The canonical response member orders are:

| Shape | Member order |
| --- | --- |
| Mint success | `protocol_version`, `request_id`, `registration_id`, `outcome`, `material`, `registrar_health` |
| Deregister success | `protocol_version`, `request_id`, `registration_id`, `outcome`, `registrar_health` |
| Refusal | `protocol_version`, `request_id`, optional `registration_id`, `class`, optional `error`, `registrar_health` |

`request_id` and `registration_id` are JSON strings. The mint and deregister
`outcome` values and the refusal `class` values are the bootroot-owned
snake-case vocabulary. `material` contains exactly the §5.2 members in that
table's order. Its deadline is the granted `MintOutcome::expires_at` instant,
formatted by `time`'s `Rfc3339` formatter as a UTC `Z` string, not the
requested lifetime. The optional response members are omitted rather than
serialized as `null`. An `error` is omitted for an unclassified refusal; when
present it is the internally tagged object whose `id` and payload members come
from §6.1. A retry-after value is an unquoted non-negative whole-second
integer.

The encoder emits those orders byte-stably, while decoders are
order-insensitive. Serialization emits no members outside the listed shapes;
deserialization tolerates an unknown member at the implemented version. The
frame's operation alone selects which request shape is decoded, so a member
named only by the other operation's shape is an unknown member like any other
and is ignored rather than rejected; a deregistration frame therefore decodes
to the same `Deregister` whether or not it also carries `delivery_mode`,
`spec`, or `wrap_ttl`, and re-encodes with the §4.3 members only. A
request payload that cannot be decoded into its selected typed shape returns a
typed codec error only: it does not construct a refusal or emit response bytes,
because no verb invocation or request id exists yet. Request shapes carry no
caller identity, request id, registration id, composed name, domain, token
policy, or policy body; the authenticated caller identity stays on the
transport seam.

`ca_anchor` is a standard padded RFC 4648 base64 JSON string. Its decoded
bytes are the compact UTF-8 object `{"trusted_ca_sha256":[...],"ca_bundle_pem":"..."}`
in that member order, with no BOM, insignificant whitespace, trailing newline,
or additional member. Both members are non-empty; the fingerprints are
lowercase SHA-256 digests of DER certificate bytes, positionally aligned with
the LF-only PEM bundle, which has exactly one trailing LF. The codec owns both
directions: it serializes `TrustPayload` to compact JSON and base64, and it
base64-decodes, parses a `serde_json::Value`, passes it to
`parse_trust_payload`, and then applies the stricter canonical framing checks.
Any failure in that path is a decode error, never a wire refusal.

`registrar_health` is the endpoint-local, snapshot-supplied container. Its
additive `limiter` member is present on mint-success, deregister-success, and
refusal responses, in the response position shown above:

```json
{"limiter":{"limited_predecision_refusal":0,"limited_admission":0}}
```

Both members are JSON `u64` counters since this daemon process started.
`limited_predecision_refusal` counts suppression after a permanent local
refusal was known; `limited_admission` counts suppression that produces the
retryable admission throttle. A response encoder receives one daemon-held
`RegistrarHealth` snapshot and has no other source for it; the protocol module
does not read audit, limiter, or certificate state.

The refusal mapping is exhaustive over the current bootroot verb errors. Every
row is an explicit `match` arm; there is no wildcard arm. `none` means the
unclassified form, with no `error` member and class `retryable`.

| Internal variant | Wire identifier | Class |
| --- | --- | --- |
| `ReservedServiceName` | none | `retryable` |
| `Registrar(ConfigUnreadable)` | `RegistrarUnavailable { reason: NotProvisioned }` | `permanent` |
| `Registrar(FingerprintLineMalformed)` | `RegistrarUnavailable { reason: NotProvisioned }` | `permanent` |
| `Registrar(FingerprintMismatch)` | `RegistrarUnavailable { reason: NotProvisioned }` | `permanent` |
| `Registrar(ConfigMalformed)` | `RegistrarUnavailable { reason: NotProvisioned }` | `permanent` |
| `Registrar(UnsupportedSchemaVersion)` | `RegistrarUnavailable { reason: NotProvisioned }` | `permanent` |
| `Registrar(UnknownMultiplicity)` | `RegistrarUnavailable { reason: NotProvisioned }` | `permanent` |
| `Registrar(UnknownReloadKind)` | `RegistrarUnavailable { reason: NotProvisioned }` | `permanent` |
| `Registrar(InvalidReloadTarget)` | `RegistrarUnavailable { reason: NotProvisioned }` | `permanent` |
| `Registrar(InvalidDomain)` | `RegistrarUnavailable { reason: NotProvisioned }` | `permanent` |
| `Registrar(InvalidComponentKey)` | `RegistrarUnavailable { reason: NotProvisioned }` | `permanent` |
| `Registrar(InvalidServiceName)` | `ServiceLabelInvalid` | `permanent` |
| `Registrar(InvalidHost)` | `ServiceLabelInvalid` | `permanent` |
| `Registrar(ComponentNotConfigured)` | `ServiceInstanceMismatch` | `permanent` |
| `Registrar(ServiceInstanceMismatch)` | `ServiceInstanceMismatch` | `permanent` |
| `Registrar(DerivedKeyInvalid)` | none | `retryable` |
| `Registrar(SpecIdentityDisagreement)` | `ServiceSpecConflict` | `permanent` |
| `Registrar(ServiceSpecOutsideSafeSet)` | `ServiceSpecConflict` | `permanent` |
| `RegistrationIdCollision` | `ServiceNameCollision` | `permanent` |
| `StoredSpecConflict` | `ServiceSpecConflict` | `permanent` |
| `HostMismatch` | `ServiceHostMismatch` | `permanent` |
| `InvalidWrapTtl(Zero)` | none | `retryable` |
| `InvalidWrapTtl(Negative)` | none | `retryable` |
| `InvalidWrapTtl(NotWholeSeconds)` | none | `retryable` |
| `InvalidWrapTtl(ExceedsOpenBaoRange)` | none | `retryable` |
| `AuditUnwritable { phase: Intent }` | `RegistrarUnavailable { reason: AuditUnwritable }` | `permanent` |
| `AuditUnwritable { phase: Outcome }` | `RegistrarUnavailable { reason: AuditUnwritable }` | `permanent` |
| `PostMintUnrecordable` | `RegistrarUnavailable { reason: PostMintUnrecordable }` | `permanent` |
| `Unavailable` | none | `retryable` |
| Future registrar rate-limit refusal | `RegistrarBusy { retry_after }` | `retryable` |

The two named collapses are deliberate: `ServiceSpecConflict` carries
`SpecIdentityDisagreement`, `ServiceSpecOutsideSafeSet`, and
`StoredSpecConflict`; `ServiceInstanceMismatch` carries
`ComponentNotConfigured` and `ServiceInstanceMismatch`. The internal variants
remain distinct in audit records. `Registrar(DerivedKeyInvalid)` is reachable:
a ten-digit instance with 63-octet service and host labels produces a 138-octet
candidate, beyond the 131-octet registration-id limit. Its response omits both
`registration_id` and `error`.

Both `AuditUnwritable` phases map onto the one transcribed `AuditUnwritable`
reason. The §6.5 row transcribes the source's intent-phase condition and is
not edited here; that this endpoint also produces the reason for an
outcome-phase failure on an invocation that changed no `OpenBao` state is
this repository's own expectation, not transcribed from the source. The
caller-visible facts are the intent case's — nothing minted, no teardown
owed, the audit store unwritable — where `PostMintUnrecordable` would
falsely owe a teardown and the unclassified form would drop the audit-store
signal. `PostMintUnrecordable` itself carries every outcome-write failure
whose invocation did, or may have, changed `OpenBao` state — refusals and
completed removals included — which is wider than the reason's name; the
variant's own documentation records that width.

The final row describes a refusal that does not exist yet. Its introducing
change must add an explicit mapping arm; matching coincident internal and
external names is not permitted. The rate-limit payload is whole seconds.

## 11. Counts

A transcription that comes up short is incomplete, not a shorter contract.

| Set | Count | Provenance |
| --- | --- | --- |
| `Register` fields | 7 | `RFC-C §5` |
| `Deregister` fields | 4 | `RFC-C §5` |
| `ServiceSpec` fields | 4 | `RFC-C §5` |
| `DeliveryMode` variants | 2 | `RFC-C §5` |
| `NodeEnrollResponse` variants | 2 in the source; 3 with `Failed` | `RFC-C §5`, `RP#218` |
| `BootstrapMaterial` fields | 4 | `RFC-C §5` |
| typed enroll errors | 6 in the source's acceptance count, 7 with `ServiceLabelInvalid` | `RFC-C §8`, `RP#218` |
| `RegistrarUnavailable` reasons | 6 | `RFC-C §8` |
| retryable typed errors | 1 | `RFC-C §8` |
