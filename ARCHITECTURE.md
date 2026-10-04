# bootroot - Architectural Contract and Implementation Context

## 1. Purpose

This document defines the **architectural contract** of the `bootroot`
repository.

`bootroot` is a **product-embedded PKI bootstrap and trust foundation** whose
sole purpose is to establish, operate, and enforce **system identity and trust**
across environments.

This document serves as:

- a long-lived architectural reference,
- a contract for human developers and coding agents,
- a guardrail against accidental deviation from the trust model,
- and a compliance-facing explanation of design intent.

The architecture defined here is designed to remain valid under
**ISMS-P, CSAP, N2SF, SOC 2, and NIST-aligned security reviews**.

## 2. What bootroot Is

`bootroot` is responsible for:

- bootstrapping a **private Certificate Authority (CA)** using step-ca
- defining **system identity** via X.509 certificates
- enforcing **mTLS-only system authentication**
- automating certificate lifecycle management
- providing **observable and auditable certificate operations**
- packaging CA tooling as a **product component**, not an external dependency

`bootroot` establishes the **root of trust** for all internal
system-to-system communication.

## 3. What bootroot Is Not (Explicit Non-Goals)

`bootroot` is **not**:

- a user authentication system
- an identity provider (IdP)
- a general-purpose PKI service
- a secrets manager
- a replacement for application-level authorization
- a UI or workflow product

User authentication (JWT, OIDC, sessions) is explicitly **out of scope**.

## 4. Trust Model

### 4.1 Trust Boundary

- Trust is established **only** through X.509 certificates
- Certificates are issued by a **private CA controlled by the operator**
- Trust domains are **environment-scoped and never shared**

There is no implicit trust between environments.

### 4.2 Identity Model

- **SAN-based identity is mandatory**
- Common Name (CN) is not used for identity decisions
- Each certificate represents a **single system identity**

Examples:

- `001.giganto.node-01.customer-a.internal`
- `002.aice-web-next.node-01.customer-a.internal`
- `001.aimer-web.node-02.company-prod.internal`

## 5. System Authentication Model

### 5.1 mTLS as the Only System Authentication

All system-to-system communication **must use mutual TLS (mTLS)**.

- JWTs are never used for system authentication
- API keys are never used for system authentication
- Network-level trust is not relied upon

mTLS is the **only allowed mechanism**.

### 5.2 Allowed Communication Patterns

| Source        | Destination | Authentication |
| ------------- | ----------- | -------------- |
| aice-web-next | REview      | mTLS           |
| aice-web-next | Giganto     | mTLS           |
| aimer-web     | Aimer       | mTLS           |

## 6. Certificate Authority Model

### 6.1 step-ca as the CA Implementation

- step-ca is the **only supported CA implementation**
- step-ca is treated as a **product component**
- Operators do not bring their own CA

This ensures:

- consistent policy enforcement
- predictable automation
- explainable security posture during audits

### 6.2 Environment Separation

Each environment has an **independent CA**:

| Environment              | CA Ownership               |
| ------------------------ | -------------------------- |
| Customer closed network  | Customer-operated step-ca  |
| Internet-facing services | Company-operated step-ca   |

CA keys and trust roots are **never shared** across environments.

## 7. Certificate Issuance and Renewal Model (ACME)

### 7.1 ACME as the Primary Mechanism

`bootroot` adopts **ACME (Automatic Certificate Management Environment)** as
the **primary and recommended mechanism** for certificate issuance and
renewal.

Rationale:

- fully automated, non-interactive lifecycle management
- industry-standard protocol
- broad ecosystem tooling (cert-manager, ACME clients)
- reduced operational risk of certificate expiration
- clear compliance explainability

In normal operation:

- certificates are issued and renewed automatically via ACME clients
- no human interaction or manual CLI invocation is required
- renewal is driven by clients and enforced by CA policy

step-ca acts as a **private ACME server** enforcing:

- explicit issuance policies
- SAN-based identity rules
- short-lived certificates
- environment-scoped trust domains

### 7.2 Non-ACME Mechanisms (Restricted Use)

Non-ACME mechanisms provided by step-ca (e.g., step CLI or direct CA APIs)
**must not be used for steady-state operations**.

They are permitted only for:

- initial CA bootstrap
- controlled administrative operations
- exceptional recovery scenarios

Using CLI-based issuance for routine renewal is considered a
**design violation**.

## 8. Certificate Lifetime and Rotation

- Certificates are intentionally **short-lived**
- Typical lifetime: hours to days, not months
- Rotation is automatic and continuous

Human-managed renewal is explicitly disallowed.

## 9. Monitoring and Operational Safety

### 9.1 Certificate Expiration Detection

Each system component is expected to:

- check its own certificate expiration (`NotAfter`)
- check peer certificate expiration during mTLS handshakes
- emit warnings when expiration approaches (1-3 days)

This acts as a **last-resort safety net** in case automated renewal fails.

### 9.2 Metrics and Observability

`bootroot` integrates with:

- **Prometheus** for metrics
- **Grafana** for visualization

Tracked signals include:

- certificate issuance success/failure
- renewal latency
- time-to-expiration
- CA availability

## 10. Dependency Adaptation Policy

`bootroot` is expected to evolve alongside its core dependencies:

- step-ca
- Prometheus
- Grafana

Lagging behind dependency evolution is considered a **defect, not a feature**.

Version upgrades are treated as normal maintenance, not exceptional events.

## 11. On-disk Format Compatibility

An installed deployment holds files and stored values that one `bootroot`
version writes and a later one reads. A move between two versions updates
the deployment in place only when every one of them still works across
the move. Any other move is a reinstall, which builds a new Trust Anchor
and makes every onboarded host re-join.

### 11.1 The Formats

- `state.json`
- `agent.toml`: a service's, and the registrar-internal one
- `responder.toml`
- the remote-bootstrap artifact
- the registrar binding KV record
- the per-service KV payloads an agent reads

A format only the server reads still counts: an in-place update keeps the
stored binding records, and the new server reads them. A file `bootroot`
only reads and another tool owns, such as bootler's `provisioning.toml`,
is that tool's contract and not on this list.

### 11.2 Additive or Breaking

A change to any of these formats is **additive** when every file or value
the previous code wrote still loads and means the same under the new
code, and the previous code still accepts what the new code writes.
Anything else is **breaking**, including:

- a new required field
- a renamed or removed field, or a changed meaning
- a new key in a table that refuses unknown keys: `[trust]`,
  `[registrar]` and `[registrar_endpoint]` in `agent.toml`
- a change to a per-service KV payload that an older agent cannot read
- a change to `ARTIFACT_SCHEMA_VERSION`
- a bump of the binding record's `schema_version`

A breaking change may land. It is not updatable in place, and its
`CHANGELOG.md` entry says that it needs a reinstall.

The same holds for the images a deployment runs: a postgres major version
change, or an OpenBao or step-ca release whose upstream upgrade notes
require a manual step, is breaking in the same sense.

### 11.3 Format Fixtures

`tests/fixtures/formats/` holds samples of the file formats, generated by
the production code that writes them. `v1/` has one of each:
`state.json`, a service's `agent.toml`, `registrar-internal-agent.toml`,
`responder.toml`, `remote-bootstrap.json` and `registrar-binding.json`.
`cargo test` loads every sample in every version directory through its
production loader, and holds the artifact's `schema_version` to
`ARTIFACT_SCHEMA_VERSION`, the one version `bootroot-remote` accepts.

- An additive change keeps every existing sample passing unchanged. When
  it adds a field worth covering, it adds a new directory (`v2/`, …)
  holding the new shape. It never edits an existing sample.
- A change that stops the new code reading an old file has to modify or
  delete an existing sample to pass. Before declaring a move between two
  pins updatable in place, the release maker lists exactly those
  samples:

  ```sh
  git diff --no-renames --diff-filter=MD <installed pin>..<new pin> -- tests/fixtures/formats/
  ```

The samples cover one direction only: the new code reading what older
code wrote. They cannot detect an older binary refusing what the new code
writes, such as a new key in a table that refuses unknown keys, and the
per-service KV payloads have no sample at all. Such a change is breaking,
and its `CHANGELOG.md` entry is its only signal.

## 12. Compliance and Audit Positioning

This architecture is designed to be explainable under:

- ISMS-P
- CSAP
- N2SF
- SOC 2 Type II
- NIST SP 800-53

Key audit-friendly properties:

- explicit trust boundaries
- automated, policy-driven certificate management
- reduced human error surface
- deterministic and reviewable behavior

## 13. Final Statement

`bootroot` exists to ensure that **system identity is never an afterthought**.

Trust is:

- explicit
- automated
- observable
- and enforced by architecture, not convention.

Any implementation that violates this contract should be treated as
**architecturally incorrect**.
