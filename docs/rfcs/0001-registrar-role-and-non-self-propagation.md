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

Nothing here changes bootroot's install-time behavior or its existing
`service add`/`service remove` code paths; it constrains only the
**runtime** credential the registrar authenticates with.

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
`(service_name, host, delivery_mode, wrap_ttl, spec)`, output the wrapped
`BootstrapMaterial`; internally runs the existing `ensure_service_approle`
derivation under a bootroot-internal privileged credential. The
`service_name` on the wire is the **`<component>-<host>` identity**
(e.g. `piglet-host1`, `roxyd-newhost`) — a **single DNS label**; the verb
**rejects any `service_name` that is not a valid single DNS label** and
rejects (or has no way to express) a caller-named policy/role body.
**DNS-label validity is necessary but not sufficient — the verb MUST also
re-derive the label from the supplied `host` and reject a mismatch.**
`service_name` and `host` arrive as **independent** wire fields, and nothing
else ties them together: the collision check below compares the requesting
`host` against the identity's **stored** host, and that stored value is
simply whatever the *first* mint supplied. So a buggy or compromised REView
sending `{ service_name: "piglet-h1", host: "h2" }` mints cleanly and binds
`piglet-h1 → h2` — after which h1 can **never** install piglet
(`ServiceNameCollision` forever) and the teardown for h1's label is refused
with `ServiceHostMismatch`, which REView reads as "this host owns nothing"
and **discharges**, so the bogus identity is never cleaned up. Therefore the
verb recomputes `<component>-<flatten(host)>` from the supplied `host` and
rejects a mismatch with a distinct error **before** the collision check.
**The flattening rule is defined once, in RFC-A §4, and both sides
reference it** — REView derives the label with it and the registrar
re-derives with it; two independent implementations of the flattening would
fail *every* `Register`, so it must not be restated per repo.
The verb **also
rejects a `service_name` whose derived `<component>-<host>` label collides
with a *different* already-registered host** (the flattening of a hostname
into a dot-free label is not injective — `h.dc1`/`h.dc2`→`h`, `a.b-c`/
`a-b.c`→`a-b-c` — RFC-A §4), so two distinct hosts can never be re-issued
**one** identity. This collision check has three hard requirements, because
the naive control flow is exploitable:

- **(ordering) The collision check runs FIRST — before, and independently
  of, the idempotent spec-match below.** The `spec` is **host-agnostic** (the
  same `cert_group`/`reload` for every host of a component), so two
  distinct hosts of the same component present the **identical** spec; if the
  spec-match ran first it would MATCH and re-wrap host1's identity for host2.
  So: probe the existing identity's **bound host**; if it is a *different*
  host, reject (`ServiceNameCollision`) and mint nothing — never fall through
  to the spec-match.
- **(durable binding) Persist the pre-flattening `host` per identity** in the
  per-service KV (bootroot keys the registry on the flattened `service_name`
  alone, §2 — the very cause of the collision), so the check compares the
  requesting `host` against the identity's **stored** original host and
  **survives a registrar restart** (otherwise it silently degrades to
  DNS-label-format-only).
- **(atomicity) Serialize the verb — the lock spans mint AND deregister
  (§5.2) per `service_name`.** The collision-check-then-mint is atomic (a
  lock, or a compare-and-set on the durable `label → host` record): two
  concurrent `Register`s that flatten to the same label must not both probe
  "absent" and both mint (`ensure_service_approle` is idempotent, so the
  second would otherwise succeed as an update and hand both callers material
  for one identity). **The same per-`service_name` mutex also serializes
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
`bootroot-service-<service_name>` itself (`service_policy_name` /
`SERVICE_ROLE_PREFIX`, §2); the caller never sees or supplies that prefix.
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

A **restricted registrar deregister verb** — input `(service_name, host)`,
idempotent, wrapping `run_service_remove`. **It first reads the durable
`label → host` binding and verifies `stored_host == requested_host` before
removing anything.** This is essential because `run_service_remove` keys on
`service_name` **alone** (`remove.rs:74`,
`require_service_entry(&state, &args.service_name, messages)`), so a bare
teardown would delete
whichever host owns the label. If the label is bound to a **different** host
— the flatten-collision the mint verb rejects (§5.1), yet which a stale
onboarding `cleanup_state` could still drive a teardown for — the deregister
is **refused with the distinct typed error `ServiceHostMismatch`** (no
`run_service_remove`, no binding delete), so a `Deregister` for host2 can
never tear down host1's identity. The error is **distinct from a transient
registrar/network failure** so REView can discharge the owed teardown (this
host owns nothing) on `ServiceHostMismatch` but retry on a transient error
(RFC-C §5, RFC-D2 §4d) — a real owed teardown is never dropped, a genuine
refusal never loops. Only when the requested host
**is** the bound host does it call `run_service_remove` **and** remove the
durable `label → host` binding (`delete_kv_if_present`), so a decommissioned
host's label is legitimately reusable. It shares the **per-`service_name`
mutex with the mint verb** (§5.1), so a `Register` and a `Deregister` for one
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
  identity `<name>`** (a `<component>-<host>` DNS label, returning wrapped
  material) succeeds and **creates the internal role/policy
  `bootroot-service-<name>`**; deregistering it succeeds; both are idempotent
  (re-mint / re-deregister return success, matching `run_service_remove`'s
  `_if_present` behavior). The caller passes only `<name>`, never the
  `bootroot-service-` prefix.
- **Label is re-derived from `host`, not trusted from the wire:** a `Register`
  whose `service_name` is not `<component>-<flatten(host)>` for the supplied
  `host` is **rejected before the collision check**, with a distinct error. A
  test drives `{ service_name: "piglet-h1", host: "h2" }` as a **first** mint
  and asserts nothing is minted and no `label → host` binding is written — the
  case that would otherwise permanently wedge h1's piglet install *and* leave
  an identity that `Deregister` refuses and REView discharges (§5.1). Both
  sides derive the label with the **single** flattening rule in RFC-A §4.
- **Injective identity:** minting a `<component>-<host>` whose derived label
  collides with a **different** already-registered host is **rejected** — the
  collision check runs **before** the spec-match, compares against a **durable
  per-identity bound host** (survives registrar restart), and the mint verb is
  **serialized** so concurrent colliding onboards cannot both mint. Tests cover
  (a) two hostnames that flatten to the same label onboarded **sequentially**
  (second refused), (b) the same **concurrently** (exactly one succeeds), and
  (c) a **restart** between the two (second still refused). A re-mint from the
  **same** host still succeeds (crash-resume unaffected). **Deregister is
  host-verified:** it reads the durable `label → host` binding and **refuses**
  when `requested_host != stored_host` (no `run_service_remove`, no binding
  delete, §5.2), so a cleanup `Deregister` for a *colliding* host2 can never tear
  down host1's identity; only a matching host removes the identity and the
  `label → host` binding (making the label reusable). A test drives
  `Deregister(service_name, host2)` against a label bound to host1 and asserts it
  is **refused** and host1's identity survives.
- **Mint/deregister serialization:** the per-`service_name` mutex spans both
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

1. **Restricted registrar verbs** (§5.1–§5.2) — the mint + deregister
   operations wrapping `ensure_service_approle` / `run_service_remove` under a
   bootroot-internal privileged credential, exposed on the existing daemon
   (`daemon.rs::run_daemon:68`, §4) with DNS-label / prefix validation, label
   re-derivation from `host`, and no caller-supplied role/policy body. The
   delivery form is **decided** (§4), so this has no blocking prerequisite.
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
