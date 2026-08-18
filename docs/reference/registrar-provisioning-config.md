<!-- markdownlint-configure-file {
  "MD013": { "tables": false, "code_blocks": false }
} -->

# Registrar provisioning config (`provisioning.toml`)

**Writer rule.** This repository *reads* this file and never writes it in
production. It is rendered by the provisioning tool, `aicers/bootler`, whose
issue [#200](https://github.com/aicers/bootler/issues/200) owns the path, the
envelope, the field set, the ordering and the digest rule. Where this file and
that issue disagree, **#200 wins and this file is corrected.** A change made
here that is not also made there breaks every enrollment in the deployment, and
breaks it at deploy time rather than in either repository's tests.

Like `registrar-wire-contract.md`, this reference sits outside the mirrored
`docs/en/` + `docs/ko/` operator pair: it is a cross-repository contract rather
than operator documentation, so `mkdocs.yml` lists it in neither locale's nav
and there is no `docs/ko/` counterpart. Its path is stable and is what a test
reads it by.

## 1. Path

| Item | Value |
| --- | --- |
| Absolute path | `/etc/clumit-security/provisioning.toml` |
| Constant | `bootroot::registrar::DEFAULT_CONFIG_PATH` |
| Rendered onto | the bootroot/registrar host **and** the REView host, at the same path on each |

The path is the writer's product-namespaced one, deliberately **not** under
`/etc/bootroot/`. The same file is rendered onto the REView host — the
upload-time safe-set check runs there — and that host has no bootroot and no
`/etc/bootroot`. One product-namespaced path is what lets both readers use one
constant. `clumit-security` is the Security product's namespace, the same one
bootler stamps into its managed `/etc/hosts` block.

`RegistrarConfig::load` takes the path as a parameter, so no test reads the
real one.

## 2. Envelope

One TOML file, not three and not a format the writer picks independently. A
single file makes the render atomic: with a partial render, `domain` could be
present while the component table was missing, which is exactly the fail-open
the digest gate exists to close.

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `fingerprint` | 64 lowercase hex characters | yes | SHA-256 of the file's body. **Must be the first line**, exactly `fingerprint = "<64 lowercase hex>"` followed by one `\n`. Not part of the digested body. |
| `schema_version` | `u32` | yes | Compatibility gate. This build implements **1**. Never defaulted when absent. |
| `domain` | dot-separated DNS name | yes | The deployment-wide domain, the SAN's fourth segment. Read only from this file, never from the wire. |
| `components` | table of tables | yes in practice | One entry per component, keyed by package-id. |

### 2.1 The two integrity gates

Both are load-bearing on this side, not the writer's business alone.

1. **The digest is validated before the body is parsed.** Split at the first
   `\n`, SHA-256 the remaining bytes **verbatim as written**, compare with the
   declared value, and only then parse. The digested region is a byte range;
   nothing is re-serialized to compute it. A truncated file can still parse as
   valid TOML with entries missing, and under the no-entry rule those
   components would then be refused *individually* — a silent per-component
   enrollment outage indistinguishable from a component that was never
   provisioned. The digest turns that into one loud failure,
   `RegistrarError::FingerprintMismatch`, carrying both the declared and the
   computed digest.
2. **An unimplemented `schema_version` is refused** with
   `RegistrarError::UnsupportedSchemaVersion`, carrying the found version and
   the one this build implements. It is never best-effort parsed, and never
   defaulted when absent.

The declared fingerprint is reachable only through a successfully validated
load (`RegistrarConfig::fingerprint`), so no caller can report a digest it did
not check.

A missing or unreadable file is a **hard failure**, never a default: minting
under a guessed domain would issue a certificate no peer will ever verify.

## 3. Component entries

`[components.<package-id>]`, one per component. The key is spent twice — a
wire `service_name` selects the entry, and the same value is the
`<component>` segment of every `registration_id` derived for it — so it must
be both a single DNS label and path-safe: lowercase letters, digits and
hyphens, starting and ending alphanumeric, at most 63 octets. A key that is
not is `RegistrarError::InvalidComponentKey` at load, rather than an entry
that loads and then refuses every one of its enrollments at the derivation
step.

A component **absent** from this file is refused, never defaulted — fail-open
would let a module whose `instance` was wrongly omitted mint a
valid-but-phantom two-part identity that a later correct request then
duplicates. `bootroot` has no entry: it is the
issuer and never enrolls through the registrar.

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `multiplicity` | enum, see §3.1 | yes | How many times the component may be installed. Selects the `registration_id` derivation arm. |
| `cert_group` | bare `u32` | no | Numeric gid. **Omitting the key means "registrations carry no cert-group policy"** — not "any gid is allowed". |
| `reload` | inline table, see §3.2 | yes | The post-renew hook. |

`cert_group` mirrors `cert_group_gid: Option<u32>`, the type this repository
already applies to a service certificate (`src/commands/service/resolve.rs`,
`src/state.rs`), and it is the policy `src/cert_group.rs` applies at issuance
and at every rotation. It is a bare number, never a tagged table.

### 3.1 `multiplicity`

| Value | `registration_id` arm |
| --- | --- |
| `one-per-deployment` | `<component>` |
| `one-per-host` | `<host>-<component>` |
| `many-per-host` | `<host>-<component>-<instance>` |

An unrecognised value is a typed load failure carrying the offending string
(`RegistrarError::UnknownMultiplicity`), never an unknown-variant fallback and
never stored as a bare string.

### 3.2 `reload`

An inline table `{ kind, target }`, mirroring `ReloadStyle`
(`src/cli/args.rs`) — the type this repository already applies to a **service**
certificate.

| `kind` | Meaning | `target` |
| --- | --- | --- |
| `sighup` | Send `SIGHUP` to a process by name | required |
| `systemd` | Reload a systemd unit | required |
| `docker-restart` | Restart a Docker container | required |
| `none` | No post-renew hook | must be absent |

`ReloadStrategy` in `src/state.rs` is **not** this type. It is the
*infrastructure*-certificate rotation strategy, and its
`container_restart` / `container_signal` vocabulary must not appear here.

An unrecognised `kind` is `RegistrarError::UnknownReloadKind`, carrying the
offending string.

`target` is compared **literally**. There is no template language, no
placeholder, no glob, no regex and no per-instance parameterization: a rendered
`target` of `piglet-{instance}` is the literal string `piglet-{instance}`, and
a request presenting the expanded `piglet-001` is outside the safe-set. A
component's rendered spec is instance-independent and every registration of
that component — including each instance of a many-per-host one — must present
it byte-for-byte. A component that genuinely needs a per-instance container
name is a coordinated format change in the provisioning repository, not
something this validator pattern-matches around.

## 4. The safe-set

A component has **exactly one** allowed spec: its rendered `cert_group` and
`reload`. A requested spec is inside the safe-set only when **both** are equal
to it.

It is not a per-field allow-list — independent per-field sets would admit
cross-products no component ever declares, an allowed `cert_group` paired with
a `reload` it never co-occurs with. It is not a list of allowed pairs either:
RFC-F §5.1 makes the spec **host-agnostic**, the same `cert_group`/`reload` for
every host of a component, and a `version-invariant` property of the package-id
— which only means something if the component has one canonical shape for an
uploaded template to be compared against.

Where a component's rendered spec **omits** `cert_group`, its registrations
must carry none: a request supplying any gid is refused with
`RegistrarError::ServiceSpecOutsideSafeSet`.

The safe-set reference is this locally rendered file, never a signed package —
the registrar is the bootroot-co-located roxyd, which never receives the signed
package and cannot read the review-host module store. It is fixed at install
and has no runtime-update channel.

## 5. What the file does **not** decide

| Not here | Where it lives |
| --- | --- |
| A privilege field | Does not exist. bootroot derives every service's authority from the fixed derived policy, so no component differs from another on a privilege dimension. |
| The composed identity name | Derived on this side from the wire's parts (§6). The wire carries no composed name. |
| A conflict with a previously stored spec | The verb layer's `ServiceSpecConflict`. Nothing in this library reads registration state. |

## 6. What this repository derives from it

`bootroot::registrar::identity` owns the derivation. There is exactly one
keyword: the wire `service_name` selects the config entry, supplies the
`<component>` segment of the derived `registration_id`, and supplies the
`<service>` segment of the SAN. There is no second selector, and
`spec.service_name` is never any of those three.

| Output | Rule |
| --- | --- |
| `registration_id` | The multiplicity arm in §3.1, with `instance` rendered three digits zero-padded. |
| SAN | `<instance>.<service>.<host>.<domain>`, always four segments. A request that correctly omits `instance` takes the literal `001` in the first segment. |

The `001` default is **SAN-only**. A one-per-host component's id stays
`<host>-<component>` and a one-per-deployment component's stays `<component>`;
the default is applied only when composing the SAN, after the id has been
derived.

`host` is required on every request and validated as a DNS label regardless of
class. The one-per-deployment arm ignores it, but the SAN's third segment still
needs it, so "not used by the id arm" is not "optional".

### 6.1 The SAN composition sites

This repository composes `<instance>.<service>.<host>.<domain>` in **four**
places, and they must agree byte for byte or the fleet gets certificates whose
name the verification path rejects.

| Site | Takes | Kept in step by |
| --- | --- | --- |
| `bootroot::registrar::identity::compose_san` | the four parts | this table, and the test below |
| `bootroot::config::profile_domain` | a `Settings` plus a `DaemonProfileSettings` | a test asserting byte-identical output for the same four values |
| `commands::verify::expected_dns_name` | a `ServiceEntry` | this table alone — it is private to the binary crate and no test here can call it |
| `commands::dns_alias::dns_alias_for_entry` | a `ServiceEntry` | this table alone, for the same reason |

The last one composes the HTTP-01 DNS alias rather than the certificate SAN,
but from the same four values and in the same shape, so a change to the shape
that misses it desynchronises the alias from the name the certificate carries.

`RegistrarConfig::san_for` is the same composer with the domain taken from
the loaded file, and is what a verb should call: it makes composing under a
wire-supplied domain structurally impossible.

## 7. The example

`docs/reference/provisioning.toml.example` is the shipped example, and a test
loads it through the production loader so the documented contract and the
parser cannot drift apart. Its `fingerprint` is a real digest of its own
body. The block below is that file verbatim, and a test asserts the two have
not drifted.

```toml
fingerprint = "62299a244c4b3833c4cb3a36b4d3da763bd87f664c7d31845f48e53be4170f3e"
# Rendered by the provisioning tool (bootler) onto BOTH the
# bootroot/registrar host and the REView host at install, at the same
# absolute path on each. bootroot only reads this file; nothing in this
# repository writes it in production.
#
# The first line is the fingerprint and is NOT part of the digested body.
schema_version = 1
domain = "trusted.domain"

# One table per component, keyed by package-id. A component absent from
# this file is refused, never defaulted. `bootroot` has no entry: it is
# the issuer and never enrolls through the registrar.
[components.review]
multiplicity = "one-per-deployment"   # | "one-per-host" | "many-per-host"
cert_group = 3000                     # numeric gid; omit the key to mean
                                      # "registrations carry no cert-group policy"
reload = { kind = "docker-restart", target = "review" }

[components.roxyd]
multiplicity = "one-per-host"
# cert_group omitted on purpose
reload = { kind = "systemd", target = "roxyd.service" }

[components.piglet]
multiplicity = "many-per-host"
cert_group = 3001
reload = { kind = "docker-restart", target = "piglet" }
```

## 8. The test fixture

`bootroot::registrar::fixture::RegistrarConfigFixture` is the canonical way to
fabricate this file in a test. Nothing in this repository renders it in
production, so without a shared fixture the verb, endpoint and acceptance-suite
tests would each hand-write their own approximation of an artifact this
repository never produces, and the three would drift from each other and from
the real one.

It renders the three components above under the domain `trusted.domain`, and a
test overrides only what it varies: `with_domain`, `with_multiplicity`,
`with_spec`, `with_component`, `without_component`, `with_schema_version`,
`with_fingerprint` (for a deliberate digest mismatch) and `with_raw_component`
(for a `multiplicity` or `reload.kind` the loader must refuse).
`write_to(dir)` places it as `provisioning.toml` inside a caller-supplied
directory and returns the path.
