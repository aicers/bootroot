# RFC-F: bootroot — the runtime registrar surface and its non-self-propagation guarantee

Status: draft. This is an **`aicers/bootroot`** in-repo RFC (its first —
filing home `docs/rfcs/`). It is the ecosystem install/update set's
**RFC-F**, the companion that supplies the one **bootroot-owned** change the
runtime-enrollment design depends on. Current-state claims are verified
against `aicers/bootroot` `origin/main` @ `36d61e9` (v0.2.0); re-verify
before relying.

**Consumed by** bootler RFC-A §6 (which provisions the registrar and states
"a small, bootroot-owned change is required — a dedicated registrar
role/policy **and its non-self-propagation guarantee**"), roxyd RFC-B §6
(the registrar `node.enroll` handler), and review RFC-D2 §4d (registrar
orchestration). Those three assume this guarantee exists; this RFC is where
it is designed.

## 1. Summary

The runtime **registrar** — the bootroot-co-located roxyd — must, long after
the one-shot bootler CLI is gone, mint (`service add`) and tear down
(`service remove`) `bootroot-service-*` identities for per-service install
and host onboarding (RFC-A §6, RFC-B §6). RFC-A §6 grants it a minimal
OpenBao AppRole policy for exactly that. But that minimal policy, as written,
still lets its holder **mint another registrar** and turn a single-host
compromise into fleet-wide identity minting. RFC-A §6 flags closing this a
**v1 requirement** and punts the mechanism to bootroot. This RFC designs it:

1. it pins the exact escalation path (§3);
2. it defines the **non-self-propagation guarantee** and recommends the
   mechanism — a **restricted registrar surface** that never hands the
   registrar raw role/policy write (§4);
3. it makes the guarantee a **v1 acceptance criterion** with a concrete
   red-team test (§6).

It then carries a **second, independent** bootroot change the same runtime
path needs (§5.5): today `service_name` is both the SAN's service label and
the sole key of every per-service namespace bootroot owns, which allows a
component exactly **one** registration deployment-wide. Modules are
installed per host and may run several instances on one host, so the
namespace key is split out as **`registration_id`** and the label is left
plain.

The confinement work (§3–§4, §5.1–§5.4) does not change bootroot's
install-time behaviour; it constrains only the **runtime** credential the
registrar authenticates with. The `registration_id` split (§5.5) does touch
the existing `service add` / `service remove` paths, but is arranged to
default to today's behaviour so existing registrations need no migration.

## 2. Current state (grounded, `origin/main` @ `36d61e9`)

- **`service add` derives a safe, fixed policy — the code is not the hole.**
  `ensure_service_approle` (`src/commands/service/approle.rs:15`) writes the
  per-service policy `bootroot-service-<name>`
  (`SERVICE_ROLE_PREFIX = "bootroot-service-"`, `commands/service.rs:26`;
  derived by `service_policy_name` / `service_role_name`,
  `commands/service/approle.rs:107`/`:103` — both yield the same string) via
  `write_policy`, then
  `create_approle(role_name, &[policy_name], …)` (`approle.rs:34`) — the new
  role's `token_policies` is **always** the derived `bootroot-service-<name>`
  policy, **never caller-supplied**. `service remove`
  (`commands/service/remove.rs:68`) idempotently deletes the KV
  (`delete_kv_if_present`), the AppRole (`delete_approle_if_present:120`),
  and the policy (`delete_policy_if_present:126`).
- **The AppRole/policy writes underneath are raw OpenBao API.**
  `OpenBaoClient::create_approle` (`src/openbao.rs:642`) — whose
  `AppRoleRequest` (`:650-657`) carries `token_policies` (`:652`), `token_ttl`,
  `token_max_ttl`, `token_renewable`, `secret_id_ttl` — and `write_policy`
  (`:608`) target the raw paths `auth/approle/role/<name>` and
  `sys/policies/acl/<name>`. Whatever credential runs `service add` must be able
  to write those paths.
- **bootroot already runs a daemon** (`src/daemon.rs::run_daemon:68`, the
  fast-poll / ACME renewal loop, `fast_poll.rs`) on the bootroot host — an
  existing place a narrow privileged operation can live without inventing a
  new long-running process.
- **The issued leaf's name is composed from four inputs, and `service add`
  takes three of them as flags.** A profile's certificate carries exactly one
  SAN, and the same string as its CN:
  `<instance_id>.<service_name>.<hostname>.<domain>`
  (`src/config.rs::profile_domain`, used by
  `src/acme/flow.rs::build_csr_params`, which sets `subject_alt_names` to that
  single `DnsName`; re-derived for verification by
  `src/commands/verify.rs::expected_dns_name`). `ServiceAddArgs`
  (`src/cli/args.rs`) accordingly takes `--hostname` ("Hostname used for DNS
  SAN"), `--domain` ("DNS domain for SAN construction"), and `--instance-id`
  ("required"), and `ServiceEntry` (`src/state.rs`) persists all four fields
  separately. **`hostname` is validated as a single DNS label**, exactly like
  `service_name` (`src/i18n/en.rs`, `error_hostname_invalid`;
  `src/bin/bootroot-remote/validation.rs`), so **no bootroot input accepts a
  dotted name** — a caller cannot pass an FQDN anywhere in this identity.
- **The registry keys on `service_name` ALONE, and so does every per-service
  namespace derived from it.** `state.services` is a
  `BTreeMap<String, ServiceEntry>` (`src/state.rs`) looked up by name
  (`require_service_entry`, `src/commands/service/remove.rs`), and the same
  string names the AppRole and policy (`bootroot-service-<name>`,
  `src/commands/service/approle.rs`), the KV namespace
  (`bootroot/services/<name>/…`, `src/trust_bootstrap.rs`,
  `src/fast_poll.rs`), the policy **body**'s paths
  (`build_service_policy`), the agent-config managed block markers and the
  fast-poll state filename (`src/bin/bootroot-remote/agent_config.rs`), the
  default cert/key filenames, and the remote-bootstrap artifact directory
  (`src/commands/service/remote_bootstrap.rs`). A registration is therefore
  unique **per name across the whole deployment**, not per host — which is
  why bootler registers each host's roxyd as `roxyd-<host>` rather than the
  static `roxyd`.
- **CIDR binding exists** — `token_bound_cidrs` is a **`SecretIdOptions`** field
  (`openbao.rs:98`, tested `:1452`) applied at **secret-id issuance**
  (`create_secret_id`), and role-level CIDRs are plumbed through
  `commands/service/resolve.rs` onto those secret-id options. (There is **no**
  `secret_id_bound_cidrs` symbol in bootroot and **no** `token_bound_cidrs`
  parameter on `create_approle` — CIDR confinement is applied when the
  `secret_id` is minted, not at role creation.)

## 3. The escalation path (why the minimal policy is not enough)

RFC-A §6's minimal registrar policy grants (among the KV/CA reads):

```hcl
path "sys/policies/acl/bootroot-service-*" {
  capabilities = ["create", "update", "delete"]
}
path "auth/approle/role/bootroot-service-*" {
  capabilities = ["create", "update", "delete"]
}
```

These are **raw** capabilities on the same paths `create_approle` /
`write_policy` use. A holder of the registrar credential is therefore **not**
confined to the safe `ensure_service_approle` code path — it can call the
OpenBao API directly and:

1. `write_policy("bootroot-service-evil", <a policy body granting anything>)`
   — the ACL grant restricts the policy *name* (`bootroot-service-*`) but
   **not its contents**; the registrar authors an arbitrarily powerful policy
   under a permitted name; **and/or**
2. `create_approle("bootroot-service-evil", token_policies =
   ["<the registrar policy>"] )` — bypassing the code's derived
   `token_policies`, binding the new role to the registrar policy itself.

Either yields a **second registrar**. Because runtime identity minting is the
registrar's whole purpose, this converts a compromise of the one co-located
roxyd into **fleet-wide** identity minting. **Co-location and CIDR binding do
not close this** — the attacker already controls a process *on* the bootroot
host, inside the bound CIDR. The confinement must be on **what the credential
can express**, not where it lives.

## 4. The guarantee and the mechanism

**[DECISION] Non-self-propagation guarantee (the v1 requirement).** A holder
of the runtime registrar credential must be **unable to create or modify any
OpenBao role or policy such that the result grants registrar authority** —
i.e. it cannot produce a role whose effective `token_policies` include the
registrar policy, any `bootroot-runtime-*` policy, or any policy that itself
writes `sys/policies/acl/*` or `auth/approle/role/*`. Minting and tearing
down ordinary `bootroot-service-<name>` identities must still work.

Two mechanisms were considered:

- **[REJECTED as sole fix] (a) Constrained ACL policy.** Keep the raw path
  grants but add OpenBao `denied_parameters` / `allowed_parameters` so
  `token_policies` cannot be set to registrar / `bootroot-runtime-*` values.
  This is **insufficient alone**: ACL parameter constraints match parameter
  *values*, so (i) they cannot express "`token_policies` must equal this
  path's own `bootroot-service-<name>`" (only deny an enumerated set, which a
  new privileged policy name evades), and (ii) they do **not** constrain
  `write_policy` **body content** at all — escalation path 1 in §3 (author a
  powerful policy under a permitted name) stays wide open. A value-deny list
  is a brittle patch over a design that still hands out raw authoring.

- **[RECOMMENDATION] (b) Restricted registrar surface.** The registrar
  **does not hold raw `sys/policies/acl/*` or `auth/approle/role/*` write at
  all.** Instead bootroot exposes a **narrow mint/deregister operation** — its
  existing `ensure_service_approle` (`approle.rs:15`) and `run_service_remove`
  (`remove.rs:68`) logic, which **always** derives the safe
  `bootroot-service-<name>` policy+role — executed **under bootroot's own
  privileged internal credential**, never the registrar's. The registrar
  credential authorizes only *"mint / deregister a `bootroot-service-<name>`
  identity"*, taking a service name (and host, delivery mode, wrap TTL) and
  returning the wrapped material — it can pass a **name**, never a role
  definition or a policy body. Escalation is removed **by construction**: the
  registrar has no primitive that writes an arbitrary `token_policies` or an
  arbitrary policy body, because it never writes roles or policies directly —
  it invokes a bootroot operation that does, and that operation only ever
  produces the derived per-service artifacts.

**[DECISION] Recommend (b).** It closes both escalation paths (role
`token_policies` **and** policy-body authoring), reuses the already-proven
safe derivation, and shrinks the registrar's authority from "raw ACL/AppRole
authoring" to "invoke one constrained verb." (a) may be layered on as
defense-in-depth but is not the guarantee.

**[DECISION] Where the privileged authority lives.** The broad
role/policy-write capability stays **inside bootroot** — held by a
bootroot-internal credential the daemon uses, never issued to the registrar.
bootroot already runs a host-local daemon (`daemon.rs:68`) that is the natural
host for the mint/deregister endpoint; the registrar authenticates to it (its
mTLS identity or a scoped AppRole) over localhost. bootroot remains the only
principal that can write a `bootroot-service-*` role or policy.

**[DECISION] Deregister rides the same surface.** `node.enroll` `Deregister`
(RFC-C §5, RFC-B §6) maps to the restricted `run_service_remove` verb (idempotent
per `remove.rs`), so the registrar tears down an identity without holding raw
`delete` on roles/policies either.

**[DECISION] Threat-model scope — the guarantee bounds the CREDENTIAL, not a
root-compromised host (honest residual).** §3 frames the threat as "a
compromise of the one co-located roxyd," and the mechanism keeps the broad
authority in a bootroot-internal credential **on that same host** while roxyd
runs as root (RFC-B §2 verifies effective UID 0). Root on the bootroot host
can read that credential off disk or out of the daemon's address space, so
against a **full host compromise** the escalation is not removed — the
attacker obtains the internal credential directly. What the restricted surface
**does** guarantee is against a *credential-level* attacker: a leaked, copied,
or relayed registrar credential, an exploited request handler, or a
compromised REView driving the registrar — none of which can author a policy
body or a `token_policies` set. That is the realistic and common case, and it
is what §6's red-team test exercises. Full root compromise of the bootroot
host is **out of scope** and is bounded instead by co-location: the blast
radius is the host that already holds the CA-adjacent material, not the fleet
reached through it. This is a known limitation, stated so no one reads
"removed by construction" as broader than it is.

**[DECISION] Delivery of the restricted surface: a bootroot daemon endpoint,
with the registrar authenticating by mTLS.** The two verbs are exposed on
bootroot's **existing** host-local daemon (`daemon.rs::run_daemon:68`, already
running the fast-poll / ACME renewal loop), so no new long-running process is
introduced. The registrar authenticates to it with an **identity-scoped client
certificate over localhost**.

Why not the alternatives:

- **OpenBao policy-templating** cannot express this surface at all. Every
  requirement in §5.1 is **stateful application logic** — a durable
  `label → host` binding, a collision check that must run *before* the
  spec-match, a per-`service_name` mutex spanning mint **and** deregister,
  validation against a bootler-rendered safe-set file, and re-deriving the
  label from the supplied `host`. An ACL policy matches paths and parameter
  values; it cannot hold state, order operations, or take a lock.
- **An OpenBao plugin** could hold that logic, but it would have to be loaded
  into the OpenBao binary — changing the deployment and **restarting OpenBao**.
  bootroot's OpenBao is **shamir-sealed**, and not restarting it is a standing
  operational rule; making the registrar surface depend on a restart-and-unseal
  cycle trades a contained problem for an unsealing risk.
- **Response-wrapping / control-group** was considered and dropped earlier:
  response wrapping hands over a secret rather than publishing a callable verb,
  and a control group needs a second human approver per request — unusable for
  unattended runtime enrollment.

The **contract** above (registrar passes a name, never a role/policy body;
broad authority stays inside bootroot) holds regardless, but §5.3 and §6 are
now written against this one form.

**[DECISION] Network confinement + non-expiry, in the decided mTLS form.**
The registrar's credential is **(1) confined to the bootroot host's network**
and **(2) kept alive so runtime use never dies on expiry**: its client
certificate is scoped to the registrar identity, the mint / deregister endpoint
is reachable **only over localhost / the bootroot host's confined network**, and
the certificate is **renewal-maintained** so it does not expire out from under
runtime use. The broad OpenBao authority lives in the **daemon's**
bootroot-internal credential, never in the registrar's certificate — so there is
**no registrar `secret_id`** at all, and therefore nothing to CIDR-bind or
rotate. (The AppRole-authenticated variant — a `token_bound_cidrs`-bound
`secret_id`, `openbao.rs:98`, kept alive by the rotation loop — was the
alternative under the same contract; it is not used, because it reintroduces an
expiring secret to keep alive for no gain once the endpoint is already
localhost-confined.)

These are defense-in-depth **around** the guarantee, not a substitute for it
(§3).

## 5. What bootroot must provide (the change)

### 5.1 Restricted registrar mint verb

A **restricted, idempotent registrar mint verb** — input
`(service_name, host, instance, delivery_mode, wrap_ttl, spec)`, output the
wrapped `BootstrapMaterial`; internally runs the existing
`ensure_service_approle` derivation under a bootroot-internal privileged
credential.

**[DECISION] The caller supplies the identity's PARTS; the verb derives the
names.** `service_name` on the wire is the component's **plain keyword**
(`piglet`, `roxyd`) — a single DNS label, and the verb rejects anything
that is not one, just as it rejects (or has no way to express) a
caller-named policy or role body. `host` is the target's single DNS label.
`instance` is the number REView allocated for that `(component, host)`
pair, and is absent for a component installed once per host or once per
deployment. From those the verb **derives the `registration_id`** with
RFC-A §4's rule and uses it as the namespace key (§5.5); the SAN it
composes from `service_name`, `host`, `instance` and `domain`.

**[DECISION] `--domain` is read from the LOCAL bootler-rendered file, never
from the caller.** §2 shows `service add` needs it to compose the SAN, yet
it is absent from the verb's input above. That is deliberate: the domain is
a **deployment-wide constant** (one `network.domain` per install, RFC-A §4)
and the caller is a semi-trusted REView. Taking it from the wire would let
a compromised manager mint identities under a name suffix of its choosing,
which the spec safe-set does not cover. bootler renders it onto the
registrar host in the **same file as the per-component registration
safe-set** (RFC-A §7), and the verb reads it there. A missing or unreadable
file is a **hard failure**, not a default: minting under a guessed domain
would issue a certificate no peer will ever verify. `--instance-id` is
different — it is genuinely per-installation, so it arrives on the wire as
`instance` and is rendered three digits zero-padded (RFC-A §4); a component
whose class has no instance dimension takes the default `001`.

**[DECISION] The verb validates `instance` presence against the component's
multiplicity, which bootler provisions in the same local file.** Deriving
`registration_id` picks one of the three arms by multiplicity class (§5.5),
so from the parts alone the verb cannot tell a legitimate singleton
(`review`, no `instance`) from a **module whose `instance` was wrongly
omitted** (`piglet`, no `instance` → the 2-part `piglet-h1` instead of
`piglet-h1-1`) — which would mint a valid-but-phantom identity a later
correct `instance` then duplicates. Since deriving replaced the old "reject
a caller-composed name" check (below), that gap must not be left open. So
bootler records each component's **multiplicity class** alongside the domain
and safe-set (RFC-A §6/§7), and the verb **refuses a `Register` whose
`instance` presence does not match**: present for a many-per-host component,
absent for a one-per-host or one-per-deployment one. This is the identity
**shape** check; the host-collision check below is the **uniqueness** check;
neither substitutes for the other.

**Deriving rather than accepting removes a failure mode outright.** Were
the caller to send a composed name instead, a buggy or compromised REView
sending `{ service_name: "piglet-h1", host: "h2" }` would mint cleanly and
bind `piglet-h1 → h2` — after which h1 could **never** install piglet
(`ServiceNameCollision` forever) while the teardown for h1's name was
refused with `ServiceHostMismatch`, which REView reads as "this host owns
nothing" and discharges, leaving the bogus identity uncleaned. With the
composed name derived on this side, there is no caller-supplied value to
disagree with. **The derivation is defined once, in RFC-A §4, and both
sides reference it** — REView derives the same names for its own
bookkeeping and the registrar re-derives them here; two independent
implementations would fail *every* `Register`, so it must not be restated
per repo.

The verb **still rejects a derived `registration_id` already bound to a
*different* host**, because the derivation is **not injective**: component
names can be prefixes of one another and host labels may themselves contain
hyphens and digits, so `aimer` on host `web-h1` and `aimer-web` on host
`h1` — both instance 2 — derive the same `aimer-web-h1-2` (RFC-A §4). Two
distinct installations must never be re-issued **one** identity. This
collision check has three hard requirements, because
the naive control flow is exploitable:

- **(ordering) The collision check runs FIRST — before, and independently
  of, the idempotent spec-match below.** The `spec` is **host-agnostic** (the
  same `cert_group`/`reload` for every host of a component), so two
  distinct hosts of the same component present the **identical** spec; if the
  spec-match ran first it would MATCH and re-wrap host1's identity for host2.
  So: probe the existing identity's **bound host**; if it is a *different*
  host, reject (`ServiceNameCollision`) and mint nothing — never fall through
  to the spec-match.
- **(durable binding) Persist the requesting `host` per identity** in the
  per-service KV (bootroot keys the registry on the derived
  `registration_id` alone, §2/§5.5 — the very cause of the collision), so
  the check compares the requesting `host` against the identity's
  **stored** host and **survives a registrar restart** (otherwise it
  silently degrades to shape-validation only).
- **(atomicity) Serialize the verb — the lock spans mint AND deregister
  (§5.2) per `registration_id`.** The collision-check-then-mint is atomic (a
  lock, or a compare-and-set on the durable `registration_id → host`
  record): two concurrent `Register`s deriving the same `registration_id`
  must not both probe "absent" and both mint (`ensure_service_approle` is
  idempotent, so the
  second would otherwise succeed as an update and hand both callers material
  for one identity). **The same per-`registration_id` mutex also serializes
  `Deregister`**, so a `Register` and a `Deregister` for one identity never
  interleave (a remove-then-reinstall, or a cleanup-discharge `Deregister`
  racing a resume `Register`, could otherwise interleave
  `write_policy`/`create_approle` with `delete_policy`/`delete_approle`/
  `delete_kv` and leave a **half-existing identity** — role re-created but
  trust material deleted, or a fresh `secret_id` minted on a role being torn
  down).
The **`spec`** is the **bootler** `ServiceRegistration` shape the verb
applies on a first mint and **compares** on a re-mint. **It is a bootler
type, not a bootroot one** — bootroot has no `ServiceRegistration` symbol;
its own persisted per-service shapes are `ServiceEntry` (`src/state.rs:140`)
and `ServiceRoleEntry` (`:201`). The type lives at bootler
`core/src/product.rs:730` and carries **four** fields — `component`,
`service_name`, `reload: ReloadHook`, `cert_group: Option<CertGroup>`.
**There is no privilege field, and none is being added** (RFC-A §4
[DECISION]): bootroot derives every service's authority from the fixed
`bootroot-service-<name>` policy, whose `token_policies` is always the derived
value and never caller-supplied (`approle.rs:34`), so no component differs
from another on a privilege dimension. **The safe-set therefore validates
`cert_group` and `reload`** — the fields that do vary per component. An
implementation that assumes a privilege field exists will not compile.
   The spec is **REView-supplied** on the `node.enroll` `Register` request
(RFC-C §5), never a raw policy/role body the caller authors: `spec` selects
*which registration* within the fixed `bootroot-service-<name>` derivation,
not arbitrary OpenBao authority. **Because REView is only semi-trusted
(a compromised REView could otherwise mint an identity with attacker-chosen
`cert_group`/`reload`), the verb validates the supplied `spec` against a
bootler-provisioned per-component safe-set** rather than applying an
arbitrary wire-supplied `spec` verbatim, even on a first mint. **The
corroboration reference is a local, bootler-rendered allow-list, NOT the
signed `.pkg`:** the registrar is the bootroot-co-located roxyd, which never
receives the signed package (that streams only to the target host over
`node.package`, RFC-C §4) and cannot read the review-host module store — so
it has no signed template to compare against on the wire. Instead **bootler
renders a per-component registration safe-set (the allowed `cert_group` /
`reload` shape per component) onto the bootroot/registrar host at install**
(symmetric with the review-side placement map, RFC-A §7); the verb rejects a
`spec` outside that safe-set. **This safe-set is fixed at install and has no
runtime-update channel, so the registration spec (`cert_group`/`reload`)
is a `version-invariant` property of the package-id (RFC-A §7): an uploaded
package whose registration template deviates from the component's safe-set
shape is rejected at the store receiver (RFC-D2 §4a), turning what would be a
mysterious enroll-time false-deny into a clear upload rejection.**
(A stronger alternative — carry the signed
registration-template member + signature on the `node.enroll` wire and have
the registrar verify it against its release-signing generation — is possible
since the registrar now holds a generation, RFC-A §5; the safe-set is the
primary mechanism because it needs no wire change and no `.pkg` at the
registrar.)
**`bootroot-service-*` is an internal role/policy naming prefix, NOT the
input contract** — bootroot derives the role/policy names
`bootroot-service-<registration_id>` itself (`service_policy_name` /
`SERVICE_ROLE_PREFIX`, §2, now keyed on the derived id per §5.5); the caller
never sees or supplies that prefix.
**Idempotent re-mint on a matching spec, error on a conflicting one
(RFC-C §5 / RFC-B §6) — reached only AFTER the collision check passes (same
bound host):** if the service already exists **for the same host**, **compare
the existing role/policy/registration spec against the requested one** — on a
**match**, reuse its role and policy and mint only a **fresh wrapped
`secret_id`** (a re-driven `Register` from the same host never errors and
never double-mints, so a first-install crash between mint and a completed
`node.package` `Install` is recoverable by re-minting — the single-use
wrapped material is never persisted); on a **conflict** (same name, same
host, different spec), return **`ServiceSpecConflict`** and mint nothing, so
a stale/wrong-shape
service is never silently re-issued. `ensure_service_approle` already
`write_policy`/`create_approle` idempotently and `create_secret_id[_wrapped]`
mints a fresh secret_id, so the matching re-mint reuses proven paths; the
spec comparison is the added guard.

### 5.2 Restricted registrar deregister verb

A **restricted registrar deregister verb** — input
`(service_name, host, instance)`, idempotent, wrapping
`run_service_remove`. It derives the `registration_id` from those inputs
exactly as the mint verb does (§5.1), then **reads the durable
`registration_id → host` binding and verifies
`stored_host == requested_host` before removing anything.** This is
essential because `run_service_remove` keys on the registration name
**alone** (`remove.rs:74`,
`require_service_entry(&state, &args.service_name, messages)`), so a bare
teardown would delete
whichever host owns it. If it is bound to a **different** host
— the derivation collision the mint verb rejects (§5.1), yet which a stale
onboarding `cleanup_state` could still drive a teardown for — the deregister
is **refused with the distinct typed error `ServiceHostMismatch`** (no
`run_service_remove`, no binding delete), so a `Deregister` for host2 can
never tear down host1's identity. The error is **distinct from a transient
registrar/network failure** so REView can discharge the owed teardown (this
host owns nothing) on `ServiceHostMismatch` but retry on a transient error
(RFC-C §5, RFC-D2 §4d) — a real owed teardown is never dropped, a genuine
refusal never loops. Only when the requested host
**is** the bound host does it call `run_service_remove` **and** remove the
durable `registration_id → host` binding (`delete_kv_if_present`), so a
decommissioned host's id — and, for a module, the instance number REView
allocated — is legitimately reusable. It shares the
**per-`registration_id` mutex with the mint verb** (§5.1), so a `Register`
and a `Deregister` for one
identity never interleave and the read-verify-delete is atomic under that
mutex. (An identity **already absent** for the **matching** host is still the
idempotent `Done` re-drive of RFC-C §5; only a **wrong-host** teardown is
refused.)

### 5.3 Registrar credential

A **registrar credential** whose policy authorizes **only invoking those
two verbs** — and **NOT** raw `sys/policies/acl/*` or `auth/approle/role/*`
write, **and NOT direct CA / responder-HMAC / agent-EAB reads**. The CA /
responder-HMAC / agent-EAB reads that assembling per-service trust material
requires (RFC-A §6) are performed **inside the verbs under the
bootroot-internal privileged credential** (item 4), not granted to the
registrar credential itself. (This matches RFC-A §12: the §6 HCL block is
the bootroot-internal *authority envelope* the verbs run under, not a grant
issued to the registrar.)

### 5.4 Bootroot-internal privileged credential

The bootroot-internal privileged credential that the verbs run under —
which holds the CA / responder-HMAC / agent-EAB reads and the role/policy
derivation authority — never issued outside bootroot.

RFC-A §6's provisioning is then adjusted: bootler provisions the registrar
credential against **this restricted surface**, not the raw-path policy.

### 5.5 Separate the namespace key from the SAN label: `registration_id`

This is the **second** bootroot-owned change this RFC carries, independent
of the confinement above. It is what lets a component be installed more
than once.

**The problem.** Today `service_name` does two jobs at once. It is the
SAN's second label — so it wants to be the component's plain keyword,
because REView projects `<instance>.<service>` as an agent's id and matches
`app_name` against `"piglet"` — **and** it is the sole key of every
per-service namespace bootroot owns (§2): the registry entry, the AppRole
and policy names, the paths inside the policy body, the KV namespace, the
agent-config managed-block markers, the fast-poll state filename, the
default cert/key filenames, and the remote-bootstrap artifact directory.
That second job demands deployment-wide uniqueness. **The two demands are
compatible only while a component is installed exactly once.**

bootler already hit this and chose the key over the label: each host's
roxyd registers as `roxyd-<host>`, which is why roxyd's SAN reads
`001.roxyd-h1.h1.<domain>` with the host in it twice. Modules make the
compromise untenable — they are per-host **and** may run several instances
on one host, so no single string satisfies both jobs.

**The change.** Split the second job into a new field:

- **`service_name`** keeps only the first job. It is the component's plain
  keyword and remains the SAN label.
- **`registration_id`** is the namespace key. **Every consumer listed in §2
  reads it instead of `service_name`.** It is *not* a certificate field.

**[DECISION] Scope — this exists for the five modules.** `review` and
`aice-web-next` are installed once per deployment and `roxyd` once per
host, so their `registration_id` carries no instance segment and their
registrations are exactly what they are today. Only `piglet`, `giganto`,
`hog`, `reconverge` and `crusher` take an instance dimension. The field is
introduced uniformly all the same, because a uniform key is simpler than a
conditional one and it is what makes the singleton default (below) exact.

**[DECISION] Derivation is owned by RFC-A §4, not restated here.** RFC-A §4
is the single definition of both the `registration_id` derivation (per
multiplicity class: `<component>` / `<component>-<host>` /
`<component>-<host>-<instance>`) and the instance numbering it uses
(a number scoped by `{service_name}.{hostname}`). Two implementations that
disagreed would fail every `Register` in the fleet, and only after
deployment, so bootroot references that rule rather than paraphrasing it.
The **caller never supplies** `registration_id`: the mint verb derives it
(§5.1) from the component, the host, and the instance, so there is no
attacker-chosen value to validate.

**[DECISION] `registration_id` is not a SAN segment, so it is not bound by
the 63-octet DNS-label limit** — but it is used as an OpenBao path segment,
an AppRole/policy name, and a filename, so it keeps the same conservative
charset (lowercase alphanumeric and hyphen) and a bounded length.

**[DECISION] Backward compatibility: `registration_id` defaults to
`service_name`.** `ServiceEntry`'s existing optional fields already carry
`#[serde(default)]`, so adding an `Option<String>` is state-format
compatible, and a registration that omits it behaves exactly as today.
Every existing singleton — `review`, `aice-web-next`, `aimer` — therefore
keeps byte-identical OpenBao paths, AppRole and policy names, markers and
filenames: **no migration.** The values diverge only for roxyd (whose
`registration_id` is the string it already registers under, so its
namespace is unchanged and only its **SAN** improves to
`001.roxyd.h1.<domain>`, requiring a certificate re-issue) and for the
net-new module registrations.

**[DECISION] The agent profile must carry it too, and that ordering is a
real hazard.** `bootroot-agent` builds its fast-poll KV paths from the
profile's service name (§2), so an agent that does not know
`registration_id` will read the **wrong** paths. `deny_unknown_fields` is
set only on `TrustSettings` (`src/config.rs`), **not** on the profile — so
an older agent handed a newer `agent.toml` does not fail loudly; it
**silently ignores the field and polls the old namespace**. Therefore the
`[[profiles]]` schema gains `registration_id` (defaulting to the profile's
`service_name`), and for roxyd — the one existing consumer whose value
changes — **the agent is upgraded before its configuration is rewritten**.
Modules are net-new and have no deployed agent, so they are unaffected.

**What does not change.** SAN composition still reads `service_name`,
`hostname`, `instance_id` and `domain` (§2). REView and roxyd never see
`registration_id`: REView identifies an agent from the certificate
(`<instance>.<service>` scoped by host) and drives enrollment with
`service_name`, `host` and `instance` (RFC-C §5). Nothing outside bootroot
needs the key.

## 6. Acceptance criteria

- **Red-team (the core test):** holding only the runtime registrar credential,
  it is **impossible** to create or update any OpenBao role or policy whose
  effect grants registrar authority — specifically, an attempt to (a) create
  an AppRole with `token_policies` naming the registrar policy or any
  `bootroot-runtime-*` policy, or (b) write a policy body granting
  `sys/policies/acl/*` or `auth/approle/role/*`, **fails**. A test exercises
  both attempts against a live registrar credential and asserts denial.
  **This test is credential-level by design** — it models a leaked/relayed
  credential, an exploited handler, or a compromised REView, which is the case
  the guarantee covers. It deliberately does **not** model root on the bootroot
  host, which can read the daemon's internal credential directly and is
  out of scope per §4.
- **Functionality preserved:** with the same credential, **minting a service
  identity** succeeds and **creates the internal role/policy
  `bootroot-service-<registration_id>`**; deregistering it succeeds; both are
  idempotent (re-mint / re-deregister return success, matching
  `run_service_remove`'s `_if_present` behavior). The caller passes only the
  identity's parts, never the `bootroot-service-` prefix.
- **The composed names are DERIVED here, not taken from the wire (§5.1,
  §5.5):** the verb takes `service_name` (the component's plain keyword),
  `host` and `instance`, and computes the `registration_id` and the SAN
  itself, so there is no caller-supplied composed name to disagree with. A
  test asserts a `Register` carrying **no** `registration_id` and **no**
  domain still mints under the expected id, with the SAN using the
  locally-rendered domain and the requested instance; a second asserts that a
  missing or unreadable rendered file **fails the mint** rather than
  defaulting to a guessed domain. Both sides derive with the **single** rule
  in RFC-A §4.
- **Identity-shape check (§5.1):** the verb reads the component's
  bootler-provisioned multiplicity class and **refuses a `Register` whose
  `instance` presence contradicts it** — a many-per-host component with
  **no** `instance`, or a one-per-host / one-per-deployment component **with**
  one. A test drives both mismatches and asserts the mint is refused (no
  phantom identity created), and asserts the matching shapes still mint.
- **Namespace key vs SAN label (§5.5):** every namespace in §2 — registry
  entry, AppRole and policy names, policy-body paths, KV namespace,
  agent-config markers, state filename, default cert/key filenames,
  remote-bootstrap artifact directory — is keyed on `registration_id`, while
  the SAN's service label is the plain `service_name`. Tests: **two instances
  of one component on one host** get distinct registry entries, AppRoles,
  policies, KV namespaces, state filenames and cert/key paths, and distinct
  SANs differing only in the instance label; **a registration that omits
  `registration_id` behaves exactly as today**, so an existing singleton's
  paths and names are byte-identical (no migration).
- **Injective identity:** minting a derived `registration_id` that collides
  with a **different** already-registered host is **rejected** — the
  collision check runs **before** the spec-match, compares against a **durable
  per-identity bound host** (survives registrar restart), and the mint verb is
  **serialized** so concurrent colliding registrations cannot both mint. Tests
  cover the genuinely non-injective case — `aimer` on host `web-h1` versus
  `aimer-web` on host `h1`, both instance 2, which derive the same
  `aimer-web-h1-2` — (a) **sequentially** (second refused), (b)
  **concurrently** (exactly one succeeds), and (c) with a **restart** between
  the two (second still refused). A re-mint from the **same** host still
  succeeds (crash-resume unaffected). **Deregister is host-verified:** it
  reads the durable `registration_id → host` binding and **refuses** when
  `requested_host != stored_host` (no `run_service_remove`, no binding delete,
  §5.2), so a cleanup `Deregister` for a *colliding* host2 can never tear down
  host1's identity; only a matching host removes the identity and the binding
  (making the id, and a module's instance number, reusable). A test drives a
  wrong-host `Deregister` against an id bound to host1 and asserts it is
  **refused** and host1's identity survives.
- **Mint/deregister serialization:** the per-`registration_id` mutex spans both
  verbs — a **concurrent `Register` + `Deregister` of the same identity** never
  interleaves into a half-existing identity (role without trust material, or a
  `secret_id` minted on a role being torn down); a red-team test drives both
  concurrently and asserts a consistent end state.
- **Spec safe-set:** on a first mint the verb does **not** apply an arbitrary
  wire-supplied `spec` verbatim — it validates the `spec` against a
  **bootler-provisioned per-component safe-set rendered onto the registrar
  host** (not the signed `.pkg`, which the registrar never holds), so a caller
  supplying an attacker-chosen `cert_group`/`reload` is rejected. The spec is
  **version-invariant** per package-id; an uploaded package whose registration
  template deviates from the safe-set is rejected at the store receiver
  (RFC-D2 §4a), not at enroll time.
- **Derived policy only:** every role the registrar mints has
  `token_policies == ["bootroot-service-<name>"]` (the internal derived name)
  and no other — verified by
  reading the created role back.
- **Authority containment.** The registrar wields **only** the two verbs; the
  broad role/policy-write capability **and** the CA / responder-HMAC /
  agent-EAB reads are never handed to it (those reads happen *inside* the verbs
  under the bootroot-internal credential, RFC-A §12). Concretely, for the
  decided daemon-endpoint form (§4): the registrar's client certificate is
  accepted **only** at the mint / deregister endpoints (`daemon.rs`) and at no
  other daemon verb; the registrar holds **no OpenBao credential at all**, so
  there is nothing that could grant raw role/policy write or a CA / HMAC / EAB
  read. A test asserts the registrar's identity is rejected at every other
  daemon endpoint, and that no OpenBao credential is provisioned to it.
- **Network confinement + non-expiry intact (§4).** The registrar's certificate
  is scoped to the registrar identity, the endpoint is reachable only over
  localhost / the bootroot host's confined network, and the certificate is
  renewal-maintained — verified by asserting the endpoint refuses a connection
  from off-host and that renewal keeps the identity valid across the
  certificate's original lifetime. There is **no registrar `secret_id`**, so
  there is no expiring secret to rotate.

## 7. Issue decomposition (AgentCoop)

Self-contained issues; dependency order:

0. **The `registration_id` split** (§5.5) — add the field to `ServiceEntry`
   (`Option<String>`, defaulting to `service_name`) and move **every**
   namespace listed in §2 onto it: registry key, AppRole and policy names,
   the policy body's KV paths, the KV namespace, the agent-config managed
   block markers, the fast-poll state filename, the default cert/key
   filenames, and the remote-bootstrap artifact directory. Add the matching
   `[[profiles]]` field so `bootroot-agent` polls the right namespace, and
   note the rollout order it forces (an older agent silently ignores the
   field and reads the old paths, §5.5). Derivation is RFC-A §4's rule,
   referenced not restated. Independent of 1–4 and of the confinement work;
   this is what admits more than one registration per component.
1. **Restricted registrar verbs** (§5.1–§5.2) — the mint + deregister
   operations wrapping `ensure_service_approle` / `run_service_remove` under a
   bootroot-internal privileged credential, exposed on the existing daemon
   (`daemon.rs::run_daemon:68`, §4) with DNS-label / prefix validation,
   **derivation of the `registration_id` and the SAN from the supplied
   `(service_name, host, instance)` plus the locally-rendered `domain`**, the
   **identity-shape check** (refuse a `Register` whose `instance` presence
   contradicts the component's locally-rendered `multiplicity` class, §5.1),
   and no caller-supplied role/policy body or composed name. The delivery form is
   **decided** (§4), so this has no blocking prerequisite; it consumes 0.
2. **Registrar credential policy** (§5.3) — the scoped policy authorizing only
   invoking the two verbs (NOT the CA/HMAC/EAB reads, which live inside the
   verbs under the bootroot-internal credential — RFC-A §12), **network-confined
   to the bootroot host and non-expiring across runtime in the form the delivery
   allows** (AppRole: CIDR-bound + `secret_id` rotation; mTLS: identity-scoped
   cert, localhost-confined endpoint, renewal-maintained — §4/§6).
   Depends on 1.
3. **Bootroot-internal privileged credential** (§5.4) — held by the daemon,
   never issued out. Depends on 1.
4. **Red-team + functional tests** (§6) — the escalation-denied and
   functionality-preserved assertions. Depends on 1–3.

Cross-repo: bootler RFC-A §6 provisioning switches to target this restricted
surface; roxyd RFC-B §6 and review RFC-D2 §4d call it unchanged (they already
speak `node.enroll` Register/Deregister and never touched raw OpenBao paths).

## 8. Non-goals

- **The mTLS PKI itself, ACME/EAB issuance, cert rotation** — unchanged; this
  RFC touches only the runtime *identity-minting* authority.
- **Install-time `service add`** run by the bootler CLI (with a privileged
  operator/init token) — unchanged; the confinement is on the **runtime**
  registrar credential only.
- **bootroot's own update** — out of scope (installer-managed trust anchor,
  never UI-updated — RFC-A §4, RFC-D2 §4e).
