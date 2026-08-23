<!-- markdownlint-configure-file {
  "MD013": { "tables": false, "code_blocks": false }
} -->

# Registrar client identity, endpoint identity, and the endpoint pin file

This file is the contract between bootroot and the provisioning tool that
installs a registrar. bootroot **consumes** the pin file described here; it does
not write it. It is checked in outside the mirrored `docs/en/` + `docs/ko/`
operator pair, on the precedent of `docs/rfcs/` and
`docs/reference/registrar-wire-contract.md`: it is a cross-repository contract
rather than operator documentation, so `mkdocs.yml` lists it in neither locale's
nav and there is no `docs/ko/` counterpart.

## 1. The two reserved identities

bootroot issues one certificate shape for ordinary services: a single DNS SAN
`<instance>.<service_name>.<host>.<domain>`, repeated as the common name, with no
extended key usage requested (`src/acme/flow.rs::build_csr_params`). The
registrar surface needs two names that an ordinary `bootroot service add` cannot
produce. They reuse that composition exactly and differ in the **second label
only**:

| Identity | Name | Defined as |
| --- | --- | --- |
| Registrar client — the leaf the registrar authenticates to the host-local endpoint with | `<instance>.bootroot-registrar.<host>.<domain>` | `bootroot::registrar::REGISTRAR_CLIENT_LABEL` |
| Endpoint server — the leaf the daemon's endpoint presents, and the name a client pins | `<instance>.bootroot-registrar-endpoint.<host>.<domain>` | `bootroot::registrar::REGISTRAR_ENDPOINT_LABEL` |

A **third** reserved name shares the same composition and the same prefix guard
but is not part of this contract, because nothing outside bootroot ever sees it:
`<instance>.bootroot-registrar-internal.<host>.<domain>`
(`bootroot::registrar::REGISTRAR_INTERNAL_LABEL`) is the leaf bootroot's own
daemon presents to `OpenBao` at `auth/cert` in order to run the verbs. Its
instance label is fixed at `001`, it appears on no caller-facing wire, and no
provisioning tool writes or reads anything about it. See
`docs/reference/registrar-internal-credential.md`.

For the v1 single registrar per bootroot host, `<instance>` is `001` and
`<host>` is that host's single DNS label. With `domain = example.internal` the
two names are:

```text
001.bootroot-registrar.h1.example.internal
001.bootroot-registrar-endpoint.h1.example.internal
```

**`<domain>` is a suffix, not a label.** It is the configured `network.domain`,
and `validate_domain_name` accepts any number of labels — `internal` is one,
`example.internal` is two, `corp.example.internal` is three. Both names are
therefore *three fixed leading labels followed by the configured domain suffix*,
and their total label count is `3 + <label count of the configured domain>`.
Never hard-code a total label count and never treat the domain as a single
trailing label.

Both names carry **exactly one** SAN, of type DNS, and no SAN of any other type,
and repeat the SAN string as the common name — exactly like today's service
leaves.

How this differs from an ordinary service leaf on the same host: roxyd's leaf
there is `001.roxyd.h1.example.internal`, its plain component keyword in the
second label. The `registration_id` split keys bootroot's namespaces and does
not change the SAN label. The registrar client identity differs in the second
label alone.

## 2. The reserved-prefix guard on operator-supplied service names

`bootroot service add` refuses a `--service-name` whose ASCII-lowercased form
starts with **`bootroot-`** (`bootroot::registrar::RESERVED_SERVICE_NAME_PREFIX`),
alongside the existing DNS-label check, with its own error rather than the
DNS-label one. The comparison is case-insensitive because `validate_dns_label`
admits mixed case and DNS labels compare case-insensitively, so
`BOOTROOT-Registrar` is refused too.

`bootroot-remote bootstrap --service-name` is held to the same rule, through the
same predicate. That flag becomes `[[profiles]].service_name` in the `agent.toml`
the bootstrap writes, and therefore the second label of the SAN the agent orders;
a run without `--artifact` takes it straight from the command line rather than
from an artifact `service add` already vetted, so it is a second way into the
same name. Both call
`bootroot::registrar::is_reserved_service_name` — one predicate, so there is no
second list of reserved names to drift.

Ordinary component keywords — `roxyd`, `piglet`, `edge-proxy` — are unaffected,
as is the bare name `bootroot`: the prefix includes the hyphen.

**Where the guard is deliberately not applied.** It sits on the two operator
inputs that create a registration, not on `[[profiles]].service_name` as the
daemon loads it: `src/config/validation.rs` still holds that field to the
DNS-label rule alone. Every writer of a `[[profiles]]` block is one of the two
guarded commands, so only a hand-edited `agent.toml` can reach the daemon with a
reserved label — and that config belongs to the host's own root, which already
holds the agent's credentials. Guarding it there would also stand in the way of
bootroot's own identities, which are ordered under this very prefix. So the
guard's claim is precise: a name under the prefix cannot be obtained by
*registering a service*. It is not a claim that no ACME order for such a name can
ever be placed by a host against itself, and an endpoint that scopes
authorization by the `host` label recognition returns (§3) is the layer that
decides what a recognized identity may then do.

This guard is what makes recognition (§3) sound. Without it anyone able to call
`service add` could mint the registrar's own name. The **whole `bootroot-`
namespace** is reserved rather than the two labels above, so a later
bootroot-internal identity picks a name under the same prefix and is covered by
this one guard — there is deliberately no second list of reserved names that
could drift from it. `bootroot-` was already bootroot's own namespace prefix
(`bootroot-service-`, `bootroot-runtime-`), and the product is pre-release, so
nothing needs migrating. One fixture did sit under it: the agent's own
self-test registration in CI and in the `agent.toml.compose` smoke profile
registered `service_name = "bootroot-agent"`. Its SAN label is now
`agent-selftest`; its `registration_id`, `hostname` and certificate paths are
unchanged, since only the second label is reserved.
`tests/reserved_service_name_fixtures.rs` keeps that from drifting back —
a workflow, script or example config that registers a reserved name fails
`cargo test` rather than a Docker E2E job.

## 3. The recognition rule

`bootroot::registrar::recognize_registrar_client(end_entity_der, domain)` is the
single implementation a server-side verifier calls. Given an **already-verified**
peer certificate and the locally configured `domain`, it accepts only when all
of the following hold:

1. the certificate carries **exactly one** SAN, of type DNS;
2. that name ends with the configured `domain` **on a label boundary** — the name
   equals `<something>.<domain>`, never a bare string suffix, so the domain
   `example.internal` does not accept `…​.evil-example.internal`;
3. stripping the domain suffix leaves **exactly three** labels (equivalently:
   the total label count is `3 + <label count of domain>`, derived from the
   configured value);
4. of those three, the **second** is `bootroot-registrar`;
5. the **first** is a numeric instance label and the **third** a valid DNS label.

Every label and suffix comparison is ASCII-case-insensitive. The common name is
**not** consulted: today's leaves mirror the SAN into the CN, but recognition is
SAN-only.

On success the rule returns the parsed `instance`, `host` and `domain`, each
ASCII-lowercased, so the endpoint can scope authorization by host. **Which**
recognized identity may invoke **which** operation is the endpoint's decision,
not this rule's. Every failure is its own typed rejection
(`RegistrarIdentityError`).

The rule performs no chain building and no time validation — it is a name rule
applied to a peer certificate something else has already verified. It also
**never consults the extended key usage**, for the reason recorded in §5: every
leaf this CA issues carries the same EKU set, so that attribute cannot
discriminate. Recognition is by name.

## 4. The endpoint pin file

### 4.1 What is pinned

**Trust anchors, plus an exact expected SAN on the presented leaf.** Not the
endpoint leaf's DER and not its SPKI: every bootroot issuance generates a fresh
key pair, so a leaf-shaped pin goes stale at the next daemon renewal, while the
writer of this file runs once at install and lives in another repository. Anchor
pinning is also the one pinning idiom this tree already has
(`trust.trusted_ca_sha256`, `tls::ca_bundle_fingerprints`), so the existing
`PinnedCertVerifier` semantics are reused rather than a second scheme grown
beside them.

Pinning the anchor alone would admit any leaf that CA ever issued, so the anchor
pin is paired with a **mandatory** check that the presented end-entity
certificate's single DNS SAN is exactly the endpoint server identity name from
§1 — a name the §2 guard makes unmintable through `service add`.

### 4.2 Where the file lives

bootroot has **no fixed certificate directory**: every certificate and key path
is configured per profile (`[[profiles]].paths`). This contract therefore fixes
the **basename** and a **derivation rule**, and no absolute directory:

- basename: **`registrar-endpoint-anchors.sha256`**
  (`bootroot::registrar::endpoint_pin::REGISTRAR_ENDPOINT_ANCHORS_FILE`);
- location: the **parent directory of the registrar client certificate**, joined
  with that basename —
  `bootroot::registrar::endpoint_pin::anchor_pin_path_for_client_certificate`
  computes exactly this and touches no filesystem and no configuration.

So the file's absolute directory **follows the configured registrar client
certificate path** and is not fixed here; it is settled by whatever provisions
that certificate. bootroot's own pinning helper takes the pin-file path as an
explicit argument, with no built-in default and no configuration lookup.

### 4.3 Format

UTF-8 text, LF-separated lines.

- Each significant line is exactly **64 ASCII hex characters** — the SHA-256 of
  one trust anchor certificate's **DER**, i.e. the value
  `tls::ca_bundle_fingerprints` produces and `trust.trusted_ca_sha256` carries.
- Leading and trailing ASCII whitespace on a line is trimmed before
  interpretation.
- Blank lines, and lines whose first non-whitespace character is `#`, are
  ignored.
- Uppercase hex is accepted and normalized to lowercase on read; entries are
  written lowercase.
- Order is irrelevant and duplicates collapse.
- **Multiple entries must be supported.** CA rotation
  (`RotationMode::IntermediateOnly` / `Full`) means the old and the new anchor
  have to be pinnable at the same time.
- At least one valid entry must be present, and **any** non-ignored line that is
  not 64 hex characters rejects the **whole file**. There is no partial
  acceptance.

Worked example:

```text
# bootrootd registrar endpoint — pinned trust anchors (SHA-256 of certificate DER)
# written by the provisioning tool at install; one anchor per line
3b1f0c9a5d2e47b8c6a1f0e93d7b425c8e6a09f31d4b7c25e8a06f93b1d4c72e
# second entry present only during a CA rotation
9d4c72e1b0a538f6c2e94b7d051a63f8c4b29e0d75a1f386c0b9e24d7f513a6b
```

### 4.4 Writer-side contract

The **provisioning tool writes this file at install**; nothing in this
repository writes it. bootroot only reads it.

Pin the digests of certificates the endpoint actually **presents**. The pin file
carries digests and no certificate material, so a pinned anchor has to arrive on
the wire for a chain to be built to it — in a bootroot deployment that is the CA
bundle the server sends alongside its leaf, whose fingerprints are exactly what
`tls::ca_bundle_fingerprints` returns for `trust.ca_bundle_path`. During a CA
rotation, keep both generations in the file until the endpoint's leaf has been
reissued under the new anchor.

## 5. Observed extended key usage on issued certificates

The CSR is where this repository's decision ends. On the CSR
(`rcgen::CertificateParams`) the two shapes differ exactly as intended, and this
is asserted by unit tests with no CA involved:

| Shape | `subject_alt_names` | `extended_key_usages` |
| --- | --- | --- |
| ordinary service | one DNS SAN, `<instance>.<service_name>.<host>.<domain>` | **empty** |
| registrar client | one DNS SAN, `<instance>.bootroot-registrar.<host>.<domain>` | `ClientAuth` |

What the **issued** leaf carries is decided by step-ca's certificate template,
not by this repository: there is no `extKeyUsage` string and no x509 template
anywhere in this tree, so issuance runs on step-ca's defaults.

**Observed**, against `smallstep/step-ca:0.30.2` — the image
`docker-compose.yml` pins — with the default configuration (`"template": {}` in
`ca.json`, empty `templates/` directory):

| Shape | How it was issued | Issued `X509v3 Extended Key Usage` | Issued `X509v3 Key Usage` | Issued SAN |
| --- | --- | --- | --- | --- |
| ordinary service | bootroot's own ACME path — `scripts/impl/run-local-lifecycle.sh`, reading `edge-proxy.crt` and `web-app.crt` out of the run's workspace | `TLS Web Server Authentication, TLS Web Client Authentication` | `Digital Signature` (critical) | the requested DNS SAN, unchanged |
| ordinary service | `step ca sign` of the CSR `build_csr_params` produces, ACME and JWK provisioners on one CA | `Server Authentication, Client Authentication` | `Digital Signature` (critical) | the requested DNS SAN, unchanged |
| registrar client | `step ca sign` of the CSR `build_registrar_client_csr_params` produces | `Server Authentication, Client Authentication` | `Digital Signature` (critical) | the requested DNS SAN, unchanged |

The first row is the real path — bootroot's agent ordering a certificate over
ACME from the step-ca the compose stack runs. The other two exist because no
ACME order can be placed for the registrar client name until the issue that
provisions that certificate lands, so the two shapes were put through the same
CA side by side to compare them; the ACME and JWK provisioners on that CA
returned the same extensions, which is expected when neither carries a template
of its own.

Two things follow, and both are why no test in this repository asserts an issued
EKU set:

- step-ca's default leaf template **ignores the EKU the CSR requests**. The
  service CSR requests none and comes back with both usages; the client CSR
  requests `clientAuth` and comes back with both. Requesting `ClientAuth` is
  correct and cost-free — it is what the CSR should say, and it is what a
  template-carrying CA would honour — but it is not what makes the issued leaf
  usable as a client certificate here.
- **An ordinary service leaf is `clientAuth`-capable too.** An EKU set every leaf
  carries cannot distinguish the registrar from any other service, which is why
  §3's rule is a name rule and consults no EKU at all.

Asserting a particular issued EKU set would be asserting an upstream default
this repository does not pin, and would fail the day that default moves. The
**SAN** is asserted on an issued certificate; the EKU is only observed, here.
