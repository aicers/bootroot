# RFC-F: bootroot — the runtime registrar surface and its non-self-propagation guarantee

Status: accepted; implementation is decomposed from §7. This is an
**`aicers/bootroot`** in-repo RFC (its first —
filing home `docs/rfcs/`). It is the ecosystem install/update set's
**RFC-F**, the companion that supplies the one **bootroot-owned** change the
runtime-enrollment design depends on. Current-state claims are verified
against `aicers/bootroot` `origin/main` @ `36d61e9` (v0.2.0); re-verify
before relying.

**Consumed by** bootler RFC-A §6 (which provisions the registrar and states
"a small, bootroot-owned change is required — a **restricted registrar
surface** **and its non-self-propagation guarantee**"), roxyd RFC-B §6
(the registrar `node.enroll` handler), and review RFC-D2 §4d (registrar
orchestration). Those three assume this guarantee exists; this RFC is where
it is designed.

## 1. Summary

The runtime **registrar** — the bootroot-co-located roxyd — must, long after
the one-shot bootler CLI is gone, mint (`service add`) and tear down
(`service remove`) `bootroot-service-*` identities for per-service install
and host onboarding (RFC-A §6, RFC-B §6). RFC-A §6 documents a minimal
OpenBao policy as the **authority envelope** those operations exercise. But
that minimal policy, as written, still lets its holder **mint another
registrar** and turn one compromised credential into fleet-wide minting.
RFC-A §6 flags closing this a **v1 requirement** and punts the mechanism to
bootroot. This RFC designs it:

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
be a single key shape with no legacy arm — the product is pre-release, so
registrations are re-created by re-installing rather than migrated.

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

Either yields a **second registrar** — and because runtime identity minting
is the registrar's whole purpose, that turns one credential into
**fleet-wide** identity minting.

**[DECISION] The threat this closes is CREDENTIAL-LEVEL, not a
root-compromised host — and it is a NARROWER set than it first appears.**
The holder of the registrar credential need not be the registrar process,
but two candidate cases have to be struck honestly before the remaining ones
carry the argument:

- **An exploited request handler is NOT one of them.** The handler is
  roxyd's, and roxyd runs as root on this host, so exploiting it *is* root
  here — the case §4 puts out of scope.
- **A compromised REView is NOT one of them either.** REView never holds the
  registrar credential; it can only send `node.enroll` `Register` /
  `Deregister`. What bounds it is the **verb's input contract** — the
  bootler-rendered safe-set, the locally-read `domain`, the derivation, the
  collision check and the shape check (§5.1) — all of which would bound it
  identically even if the registrar held raw `sys/policies/acl/*` write,
  because roxyd offers REView no "write this policy body" verb. Those checks
  matter a great deal (an attacker-chosen `cert_group` hands a service's
  private key to a chosen group), but they are the **safe-set**, not
  non-self-propagation. Conflating the two overstates what this section
  delivers.

What genuinely remains, and is enough:

1. **The guarantee does not rest on roxyd's code being correct.** bootroot
   stops being one memory-safety bug in a different repository away from
   fleet-wide identity minting. This is the strongest of the three.
2. **The offline-copy path is real and is not root on the live host.** A
   disk image, a filesystem-level backup, or a backup agent's output
   restored elsewhere yields the credential without anyone ever holding root
   on the running bootroot host.
3. **It is the precondition for ever moving the registrar off this host.**
   While the registrar holds raw ACL authoring, relocating it only moves the
   escalation; once it holds nothing but a call to a constrained verb,
   relocation becomes a deployment change rather than a redesign.

In all three the payoff is the same shape: **any** path that reaches the
credential — including ones not foreseen here — is bounded to minting
ordinary `bootroot-service-<name>` identities rather than escalating to the
authority that mints registrars.

**Locating that honestly, because it bounds the claim.** In the v1 placement
the registrar **is** roxyd, and roxyd runs as **root on the bootroot host**
(RFC-B §2 verifies effective UID 0). Root there can read the daemon's
bootroot-internal credential off disk or out of its address space, so **full
root compromise of that host is closed by nothing in this RFC** and is out of
scope — §4 states the same residual, and §6's red-team test is
credential-level by design. A materially stronger boundary would need the
registrar to be neither root nor co-located with bootroot: a placement
change, not a policy one, and not v1 scope.

**Co-location does not close the escalation either** — the attacker already
controls a process *on* the bootroot host. The confinement must therefore be
on **what the credential can express**, not on where it lives. That is the
guarantee §4 defines.

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
host for the mint/deregister endpoint; the registrar authenticates to it with
its **mTLS identity** over localhost (the delivery form decided below).
bootroot remains the only principal that can write a `bootroot-service-*`
role or policy.

**[DECISION] Deregister rides the same surface.** `node.enroll` `Deregister`
(RFC-C §5, RFC-B §6) maps to the restricted `run_service_remove` verb (idempotent
per `remove.rs`), so the registrar tears down an identity without holding raw
`delete` on roles/policies either.

**[DECISION] Threat-model scope — the guarantee bounds the CREDENTIAL, not a
root-compromised host (honest residual).** §3 already locates this: the
mechanism keeps the broad authority in a bootroot-internal credential **on
the same host** where roxyd runs as root (RFC-B §2 verifies effective UID 0),
so root there can read that credential off disk or out of the daemon's
address space and the escalation is **not** removed against a **full host
compromise** — the attacker obtains the internal credential directly. What
the restricted surface **does** guarantee is what §3 enumerates: a
credential that leaks or is copied off the host (a disk image, a backup),
independence from roxyd's code being correct, and the ability to relocate the
registrar later — none of which can author a policy body or a
`token_policies` set. That is what §6's red-team test exercises. Full root
compromise of the bootroot host is **out of scope** and is bounded instead by
co-location: the blast radius is the host that already holds the CA-adjacent
material, not the fleet reached through it. This is a known limitation,
stated so no one reads "removed by construction" as broader than it is.

**[DECISION] Delivery of the restricted surface: a bootroot daemon endpoint,
with the registrar authenticating by mTLS.** The two verbs are exposed on
bootroot's **existing** host-local daemon (`daemon.rs::run_daemon:68`, already
running the fast-poll / ACME renewal loop), so no new long-running **process**
is introduced. The registrar authenticates to it with an **identity-scoped
client certificate over localhost**.

**[DECISION] What that costs, stated honestly — "no new process" is not "no
new server."** Verified against `origin/main` @ `36d61e9`, the following are
all **net-new**, and an estimate that reads "expose two verbs on a daemon that
already exists" will be wrong:

- **There is no listener.** `run_daemon` binds nothing; the agent is a pure
  outbound client (OpenBao HTTPS + ACME). Every `TcpListener::bind` in the
  crate outside `#[cfg(test)]` belongs to the separate
  `bootroot-http01-responder` binary or to `commands/infra.rs`'s port probes.
- **There is no client-certificate verification anywhere in bootroot.** Every
  rustls configuration in the repo — including the one `ServerConfig`, in the
  http01 responder — is `with_no_client_auth()`. mTLS **server** support is a
  capability this codebase does not have today.
- **A request/response protocol and handler** for the two verbs.
- **The daemon does not hold the privileged credential the verbs need.**
  `bootroot-agent` authenticates with the **per-service AppRole** read from
  `role_id_path` / `secret_id_path` (`src/config.rs`), whose policy is the
  narrow `bootroot-service-<name>` body; the role/policy-write authority
  (`POLICY_BOOTROOT_RUNTIME_SERVICE_ADD`) is exercised by the **`bootroot`
  CLI** process, not the agent. §5.4's credential must be provisioned to the
  daemon.
- **`bootroot-agent` is a fleet-wide binary**, running on every service host,
  not a bootroot-control-host-only daemon. The endpoint must therefore be
  **conditional** — present only where bootroot itself runs — or it becomes
  an attack surface on every host in the deployment.

None of this changes the decision; the alternatives below are worse for
reasons that still hold. It changes the estimate, and it means §5.1-§5.2 are
specifying a small server, not a callback.

**[DECISION] The daemon SELF-ISSUES and renews the registrar certificate
under its own internal credential — there is no AppRole in that loop.**
"Renewal-maintained" needs an actor, and the only renewal machinery bootroot
has today is the per-service ACME agent loop, which authenticates with a
`role_id` + `secret_id`. Routing the registrar's certificate through it would
make the top-level claim — *no `secret_id` at all* (§5.3, §6, RFC-A §6/§12) —
**false one layer down**, reintroducing precisely the expiring-secret trap
this design chose the certificate form to escape, and hiding it where it
would surface months later as an unrelated failure. So the daemon, which
already holds the privileged internal credential (§5.4) and sits beside the
CA, issues the registrar's certificate and renews it on its own schedule.

Two consequences worth stating:

- **The identity must be distinguishable from an ordinary service leaf.**
  `build_csr_params` (`src/acme/flow.rs`) sets **no** `extended_key_usages`
  today and the SAN shape is fixed to `<instance>.<service>.<host>.<domain>`
  — a server-shaped identity. Making the registrar "distinct from roxyd's own
  certificate identity" (RFC-A §6) therefore requires an explicit client
  identity, not merely another `service add`. Pinning its exact form is
  implementation work; that it must be distinguishable is a decision.
- **Lapse recovery is bootrootd's, NOT bootler's — and the renewal must be
  handed off to the registrar.** Because the daemon issues and renews the
  certificate under its own credential, it needs nothing from the registrar to
  do so: a lapsed registrar is repaired by **bootrootd running and reaching
  its next renewal tick**, not by re-provisioning the host. (An earlier
  draft said the sole recovery was re-running bootler; that was the
  pre-self-issue model and is wrong under this decision. bootler provisions
  the **initial** certificate and nothing more. RFC-E §9's `CredentialInvalid`
  remedy names bootrootd for the same reason.)
  **The renewal needs a reload contract or it fails exactly as this deployment
  has already failed once:** the daemon writes a renewed certificate to disk
  and, absent a handoff, **nothing tells roxyd to reload it**, so roxyd keeps
  presenting the expired leaf, the endpoint rejects it, and a fleet-wide
  enrollment outage is reported as `CredentialInvalid`. That is renewal
  decoupled from reload — the nginx-reload class of bug this product fixed
  once already. So either the renewal notifies the registrar, or **roxyd
  re-reads the certificate from disk on every dial**; the latter is preferred
  because it needs no cross-process signal.
  Ordering trap worth stating: if bootrootd is down **through** the renewal
  deadline, the registrar first reports `EndpointUnreachable` and only after
  the operator starts it does it report `CredentialInvalid` — one cause, two
  remediations, the second historically wrong. Both must point at bootrootd.
  The daemon surfaces the certificate's remaining lifetime so a failing
  renewal is reported rather than discovered when the next install fails.

**[DECISION] The endpoint is a root-owned UNIX-DOMAIN SOCKET, because the
registrar must authenticate the SERVER too.** Everything above specifies one
direction — the registrar's client certificate, its identity scoping, which
endpoints accept it. The other direction was unspecified, and it matters
because of what the mint verb **returns**: `BootstrapMaterial` carries a
**`ca_anchor`** (RFC-C §5) that REView relays to a target host and that, for
onboarding, becomes that host's **mTLS trust root** (RFC-B §7). Anything that
can impersonate the endpoint injects a CA anchor of its choosing into a
freshly enrolled service or a freshly joined host.

With a TCP-on-localhost endpoint that is reachable: an unprivileged local
process can bind a free high loopback port during any window in which the
daemon is not listening — a restart, a failed start, or a boot-ordering race
where roxyd comes up before bootrootd — and this is **not** the
root-compromise case §3 puts out of scope. A **root-owned `0700` unix-domain
socket** removes the port and that bind race, while disturbing none of the
"no new long-running process" rationale above.

Three requirements follow, because the socket alone does not close what it
looks like it closes (mechanism is an impl-doc detail; these are the
properties):

- **The parent directory, not the socket mode, is what prevents path
  occupation.** `0700` on the socket says nothing about who may replace the
  path, and a daemon that `unlink()`s a stale socket before `bind()` opens the
  window itself. So the socket lives in a **root-owned, non-world-writable
  directory**, and the listener must **exist before any client can run** —
  socket activation ordered ahead of roxyd, rather than the daemon unlinking
  and re-binding.
- **The callee is authenticated by peer credentials taken from the connected
  socket**, not by inspecting the path before connecting, which is a TOCTOU.
  The registrar's client certificate authenticates the caller; the peer
  credential and the directory authenticate the callee.
- **Both mTLS identities need an issuance path, and neither exists today.**
  `build_csr_params` sets **no** EKU and the SAN shape is fixed to
  `<instance>.<service>.<host>.<domain>` — a server-shaped leaf — so the
  registrar's *client* identity cannot come from an ordinary `service add`,
  and a TLS handshake over `AF_UNIX` has no hostname for the registrar to
  match the *server* against. So: the registrar leaf must be
  **distinguishable** as a client identity, and the registrar must pin the
  daemon's server identity by a **fingerprint bootler writes beside the client
  certificate** — mirroring the `--expect-sha` / `--expect-trust` idiom RFC-B
  §7 already uses, and avoiding the custom verifier that otherwise gets
  written as "accept any certificate". §6 tests the refusal.

Also state plainly: the daemon runs **as root on the bootroot host**, which is
what lets it own the socket and hold the privileged credential of §5.4.

Why not the alternatives:

- **OpenBao policy-templating** cannot express this surface at all. Every
  requirement in §5.1 is **stateful application logic** — a durable
  `registration_id → host` binding, a collision check that must run *before*
  the
  spec-match, a per-`registration_id` mutex spanning mint **and** deregister,
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
is a **root-owned `0700` unix-domain socket on the bootroot host** and is
reachable from nowhere else, and the certificate is **renewed by the daemon**
(below) so it does not expire out from under runtime use. The broad OpenBao
authority lives in the **daemon's**
bootroot-internal credential, never in the registrar's certificate — so there is
**no registrar `secret_id`** at all, and therefore nothing to CIDR-bind or
rotate. (The AppRole-authenticated variant — a `token_bound_cidrs`-bound
`secret_id`, `openbao.rs:98`, kept alive by the rotation loop — was the
alternative under the same contract; it is not used, because it reintroduces an
expiring secret to keep alive for no gain once the endpoint is already a
host-local socket.)

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
omitted** (`piglet`, no `instance` → the 2-part `h1-piglet` instead of
`h1-piglet-001`) — which would mint a valid-but-phantom identity a later
correct `instance` then duplicates. Since deriving replaced the old "reject
a caller-composed name" check (below), that gap must not be left open. So
bootler records each component's **multiplicity class** alongside the domain
and safe-set (RFC-A §6/§7), and the verb **refuses a `Register` whose
`instance` presence does not match** with the typed
**`ServiceInstanceMismatch`** (RFC-C §5): present for a many-per-host
component, absent for a one-per-host or one-per-deployment one. A component
with **no entry** is refused too, never defaulted — fail-open would restore
the phantom-identity gap this closes. This is the identity
**shape** check; the host-collision check below is the **uniqueness** check;
neither substitutes for the other.

**Deriving rather than accepting removes a failure mode outright.** Were
the caller to send a composed name instead, a buggy or compromised REView
sending `{ service_name: "h1-piglet", host: "h2" }` would mint cleanly and
bind `h1-piglet → h2` — after which h1 could **never** install piglet
(`ServiceNameCollision` forever) while the teardown for h1's name was
refused with `ServiceHostMismatch`, which REView reads as "this host owns
nothing" and discharges, leaving the bogus identity uncleaned. With the
composed name derived on this side, there is no caller-supplied value to
disagree with. **The derivation is defined once, in RFC-A §4** — the
registrar derives it here, and it is derived **nowhere else**: REView carries
the parts and records the instance number, never a composed key (RFC-D1 §4d,
RFC-D2 §4d). Two independent implementations of this rule would fail *every*
`Register`, so it must not be restated per repo. (REView does compose a
**peer's SAN** for the Giganto config push and for role corroboration — a
different composition, over the same parts plus its own copy of the rendered
`domain`, RFC-D2 §4b/§4c. The two must not be conflated.)

The verb **still rejects a derived `registration_id` already bound to a
*different* host**, because the derivation is **not injective in general**:
component names and host labels both admit hyphens, so two pairs collide
whenever one component name is `<something>-<another component name>` — with
components `web` and `aimer-web`, `web` on host `h1-aimer` and `aimer-web` on
host `h1` derive the same `h1-aimer-web-001` (RFC-A §4). **Today's registry
happens to contain no such pair**, so the derivation is injective *now*; that
is a property of the registry's contents, not of the scheme, and it lapses
the day a component named `web` or `next` is added. Two
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
compromise untenable — they are per-host **and** are meant to run several
instances on one host, so no single string satisfies both jobs.

**The change.** Split the second job into a new field:

- **`service_name`** keeps only the first job. It is the component's plain
  keyword and remains the SAN label.
- **`registration_id`** is the namespace key. **Every consumer listed in §2
  reads it instead of `service_name`.** It is *not* a certificate field.

**[DECISION] Scope — this exists for the five modules.** `review` and
`aice-web-next` are installed once per deployment and `roxyd` once per
host, so their `registration_id` carries no instance segment. Only
`piglet`, `giganto`, `hog`, `reconverge` and `crusher` take an instance
dimension. The field is introduced uniformly all the same, because a
uniform key is simpler than a conditional one.

**[DECISION] The split ships in v1 even though v1 installs one instance
per host.** RFC-A §4 pins the instance to `001` for v1 and defers
allocation — but the split is not deferred with it, because it is the part
that would be expensive to add later. Without it bootroot keys every
namespace on `service_name` alone, which admits exactly one registration of
a component **deployment-wide**; adding instances afterwards would rename
every AppRole, policy, KV path, marker and filename a module owns. With it,
a module registers as `<host>-<component>-001` from the first release and
v2 changes only **which numbers are allowed** — no rename, no re-issued
certificate, no state conversion. This RFC therefore delivers the key
shape; it delivers no allocator, and the mint verb simply derives whatever
`instance` the caller sends (§5.1).

**[DECISION] Derivation is owned by RFC-A §4, not restated here.** RFC-A §4
is the single definition of both the `registration_id` derivation (per
multiplicity class: `<component>` / `<host>-<component>` /
`<host>-<component>-<instance>`) and the instance numbering it uses
(a number scoped by `{service_name}.{hostname}`). Two implementations that
disagreed would fail every `Register` in the fleet, and only after
deployment, so bootroot references that rule rather than paraphrasing it.
The **caller never supplies** `registration_id`: the mint verb derives it
(§5.1) from the component, the host, and the instance, so there is no
attacker-chosen value to validate.

**[DECISION] `registration_id` is not a SAN segment, so it is not bound by
the 63-octet DNS-label limit** — but it is used as an OpenBao path segment,
an AppRole/policy name, and a filename, so it keeps the same conservative
charset (lowercase alphanumeric and hyphen) and a bounded length. **The
bound is 131 octets** — the structural maximum of
`<63-octet host>-<63-octet component>-<3-digit instance>` (RFC-A §4), so it
is derived rather than picked. **The mint verb enforces it explicitly**
instead of inferring it from the inputs, since the inputs are what a caller
controls. The bound and the arithmetic behind it are owned by **RFC-A §4**
and not restated here; the longest *filename* derived from the key is 161
octets (`src/fast_poll.rs`, `FastPollState::save` appends `.tmp`), inside
`NAME_MAX`.

**[DECISION] Adopting the bound ADDS a validator and SPLITS the field — it is
not a relaxation.** The ≤63 rule is **one shared function**,
`input_validation::validate_dns_label`, reached by per-field wrappers that
guard `service_name`, `hostname` **and every `domain` label**
(`src/bin/bootroot-remote/validation.rs` from `apply_secret_id.rs` and
`bootstrap.rs`; `src/commands/service/resolve.rs`), so it cannot be widened
without silently widening the certificate's own name. `service_name` must stay
≤63 **permanently**: it is a DNS label in the ACME/X.509 common name
(`config.rs::profile_domain` → `acme/flow.rs::build_csr_params`) and in the
HTTP-01 Docker network alias (`commands/dns_alias.rs`). So the work is (a)
**add** a path-safe ≤131 validator, (b) repoint only the wrappers guarding the
namespace key, and (c) carry `registration_id` **beside** `service_name` on
`ServiceEntry` and in `[[profiles]]`, with each key-derivation site choosing
which it reads. A fourth consumer — the agent-side `config/validation.rs`
check on `profiles.service_name` — enforces only non-empty + ASCII today and
gains the new bound.

**[DECISION] No migration and no compatibility shim — the product is
pre-release.** Every registration is (re)created by an install, so the
change lands by re-installing, not by converting state. `registration_id`
is therefore a **required** field rather than an `Option` defaulting to
`service_name`, and nothing has to keep reading the old key: a deployment
carried across the change is re-provisioned. What that gives up is **state
continuity** — registrations are re-created rather than migrated — and, for
roxyd alone, the derived key *string* itself, which becomes `<host>-roxyd`
with the SAN `001.roxyd.<host>.<domain>`. It does **not** change the derived
strings for the one-per-deployment singletons (`review`, `aice-web-next`,
`aimer`): their `registration_id` is still `<component>`, so their OpenBao
paths, AppRole names and filenames stay byte-identical to today's (RFC-A §12
asserts exactly that). The trade is one key shape with no legacy arm.

**[DECISION] The agent profile carries it too.** `bootroot-agent` builds
its fast-poll KV paths from the profile's service name (§2), so the
`[[profiles]]` schema gains `registration_id` and the agent reads its
namespace from that. Because there is no compatibility arm, an agent and
the `agent.toml` written for it move together at install; there is no
window in which an older agent is handed a newer profile and silently
polls a namespace that no longer exists.

**What does not change.** SAN composition still reads `service_name`,
`hostname`, `instance_id` and `domain` (§2). REView and roxyd never see
`registration_id`: REView identifies an agent from the certificate
(`<instance>.<service>` scoped by host) and drives enrollment with
`service_name`, `host` and `instance` (RFC-C §5). Nothing outside bootroot
needs the key.

### 5.6 Audit record for both verbs

RFC-A §6 rests a live security argument on a mechanism this RFC did not
supply. A compromised REView's minting capability is bounded in **what** it
can mint but not in **how often** or **for whom**, so repeated mints and a
`Deregister` against a live instance are **detected, not prevented** — and
the detection is an audit trail "on the bootroot side … where the registrar
cannot erase it." Nothing else in the set provides that: RFC-E §9's record is
written by REView, so a compromised REView simply omits it. The mechanism
belongs here, and it is mostly already present.

**[DECISION] The tamper-resistant substrate already exists.** bootroot
**requires** a file-based OpenBao audit device and verifies it at init:
`verify_audit_file` queries `sys/audit` and fails when no `file`-type device
is present (`src/openbao.rs:560-602`), and its caller in
`commands/init/steps/openbao_setup.rs:162-165` propagates that failure, so
init **aborts** rather than warning. The `openbao.hcl` audit stanza is
**preserved by the TLS rewrite** (`commands/init/steps/openbao_tls.rs`, with
tests asserting the rewrite does not drop it), and the device has its own
volume (`openbao-audit`, `commands/clean.rs:34`). So
every OpenBao write a mint performs — the policy write, the AppRole create,
the secret-id issuance, the per-service KV write, and the deletes on
deregister — is **already** recorded there, under the **bootroot-internal**
credential. Because the registrar holds **no OpenBao credential at all**
(§5.3), it can neither forge an entry nor erase one. That is what makes
RFC-A §6's "the registrar cannot erase it" true rather than aspirational.

**[DECISION] A verb-level record is added on top, because the device alone
does not carry the argument.** Two gaps:

- **A refused mint writes nothing to OpenBao**, so it leaves no trace at all.
  `ServiceNameCollision`, `ServiceSpecConflict`, `ServiceInstanceMismatch`
  and `ServiceHostMismatch` are exactly what an attacker probing the verb
  generates, and they are invisible in the device.
- **The device sees paths, not the request.** `host`, `instance` and the
  registrar's client-certificate identity never appear in an OpenBao write,
  so the device cannot answer "who asked for what" — which is the question
  the mint-storm signal is made of.

So the daemon writes a record per invocation of either verb, under the
bootroot-internal credential and never through the registrar's connection:
timestamp; verb (`Register` / `Deregister`); the requested
`(service_name, host, instance)`; the derived `registration_id`; the
registrar client-certificate identity; and the **outcome** — first mint,
idempotent re-mint, idempotent already-absent, or the specific typed refusal.
**Refused invocations are recorded exactly like accepted ones**; a record
covering only successes would miss the probing case above.

**[DECISION] The record is written in TWO PHASES, because "unrecordable ⇒
refused" is otherwise not implementable.** The outcome is only known *after*
`ensure_service_approle` has written the policy, the AppRole, the per-service
KV and the durable `registration_id → host` binding. A single
write-after-the-fact that fails at that point leaves the identity **already
live in OpenBao** while the caller is told "refused" — and REView's owed
teardown (RFC-D2 §4d) would then drive a `Deregister` that must itself write
a record and fails the same way, leaving a live, unrecorded, undeletable
identity. So, under the per-`registration_id` mutex (§5.1):

1. write an **intent** record — request id, the requested parts, the derived
   `registration_id`, the registrar certificate identity — **before any
   OpenBao write**. This is the point at which refusing is free, and a
   failure here refuses the invocation with nothing yet created.
2. perform the verb.
3. append an **outcome** record referencing the same request id.

An intent with no matching outcome is itself an anomaly worth surfacing —
it is what a crash mid-mint looks like, and what a suppressed outcome would
look like.

**[DECISION] There is a PRE-DERIVATION arm, and the rate limiter runs BEFORE
any write on it.** Several refusals happen before a `registration_id` can
exist at all — `service_name`/`host` is not a DNS label (§5.6 records the raw
string by design, which is why escaping exists), and a component with **no
multiplicity entry**, where the class needed to select the derivation arm is
missing. For those there is no id to key the per-`registration_id` mutex on
and none to put in the record, yet they are the **cheapest** refusals and
therefore the flood path — §5.6's own rate-limit rationale names
`ServiceInstanceMismatch` precisely because it is refused before any OpenBao
work. So: validate the labels and resolve the multiplicity class **first**, on
a single global lock, keying that arm's record on a **request id** alone; and
on this arm the **limiter runs before any intent write**, so a throttled
invocation costs one coalesced counter increment rather than a durable record.
Otherwise the intent record — introduced to make the refusal free — becomes
the amplifier for the exhaustion the limiter exists to stop.

**[DECISION] Both verbs are RATE-LIMITED per client identity, or the audit
record is the resource the attack exhausts.** With a record required for
every invocation including refusals, and **no limit anywhere on either verb**
(RFC-A §6 deferred a per-`(component, host)` ceiling), a compromised REView —
in the threat model for this very mechanism — floods refused invocations
(`ServiceInstanceMismatch` is cheapest, refused before any OpenBao work) and
grows the log without bound. When the filesystem fills, every subsequent mint
is refused, so **fleet-wide enrollment stops**; worse, the OpenBao file audit
device this section builds on is **mandatory**, and OpenBao fails requests
when it cannot write its audit device — so a full disk can stop OpenBao
serving, which is the renewal path for every certificate in the deployment,
on the one host that must not be restarted. "Mints are rare in steady state"
is true of legitimate mints and irrelevant to the attacker. A **ceiling** and
a **rate limit** are different objects: the first guesses how many instances
a deployment may legitimately run (rightly deferred), the second bounds how
fast one client identity may drive the verbs (required here). Repeated
identical refusals from one identity are additionally **coalesced into a
counted record within a window** — an explicit **exception** to "a record per
invocation" above, and the intent/outcome anomaly is therefore defined over
coalesced records (N intents against one counted outcome), not over a strict
1:1 pairing.

**[DECISION] There is exactly ONE registrar identity, so the limiter must be
sized from the legitimate fan-out and must be REPORTED as retryable.** "Per
client identity" is effectively global: throttling an attacker throttles the
control plane in the same bucket, and an ordinary bring-up — an onboarding
wave plus five modules per host — is a burst against a limiter sized by "mints
are rare in steady state". So the limiter is sized from what REView can
legitimately generate (hosts × modules + onboarding waves, stated in the
impl-doc), and it uses **per-`(verb, outcome-class)` buckets** so refusals
throttle without starving accepted mints. Crucially, a throttled invocation
returns **`RegistrarBusy { retry_after }`** (RFC-C §5) — a **retryable** error
distinct from `RegistrarUnavailable`, whose four reasons all mean *permanent
until an operator acts*. Without a distinct type it arrives as generic, review
classifies generic as transient and retries (RFC-D2 §4b), and the retry storm
feeds the limiter.

**[DECISION] Retention is bounded and stated, and the audit store has
reserved capacity.** These records are the only detection for an abuse whose
signature is a *rate*, so they must outlive the window an operator would look
back over: rotation is size- and age-bounded, and the retained set covers
**at least 90 days** of normal operation. The verb-level records **and** the
OpenBao audit device live on a **reserved, quota'd filesystem** separate from
everything else on the bootroot host, with a **low-water alarm and an
intent-without-outcome count that must actually reach an operator** — a
fail-closed control with no capacity monitor is a scheduled outage, and an
anomaly nothing reads is not a control. **bootrootd is not a review-protocol
peer and has no channel to review at all**, so the daemon exposes both values
on the mint/deregister endpoint, the registrar roxyd relays them as an
`audit_health` `AgentInfo` tail field (RFC-C §6, same conditional-tail
discipline), and RFC-D2 §4a surfaces them beside the trust-generation lag it
already renders.
**Writing the INTENT record is part of the verb, not best-effort:** an
invocation whose **intent** record cannot be written is refused (step 1
above), because an unrecordable mint is precisely the one an attacker wants.
**This applies to the intent record only.** An **outcome** record that cannot
be written arrives after the identity already exists in OpenBao, so refusing
there would report "refused" for a live identity: instead the verb returns the
distinct **`RegistrarUnavailable { PostMintUnrecordable }`** (RFC-C §5), which
**keeps REView's owed teardown armed** rather than voiding it (RFC-D2 §4d) —
the obligation must survive precisely because the compensating `Deregister`
also needs a writable audit store and will fail until an operator frees
space. Rotation failure
alone does not refuse a mint; only an unwritable record does.

**[DECISION] Recorded fields are escaped.** `service_name`, `host` and the
certificate identity are attacker-influenced strings arriving from a
semi-trusted caller, and refusals are recorded **including** the "not a DNS
label" refusal — so the raw untrusted string reaches the log by design. The
record is written in a structured single-line encoding with escaping, or an
attacker forges records and breaks the parser on the one artifact this whole
argument rests on.

## 6. Acceptance criteria

- **Red-team (the core test):** holding only the runtime registrar credential,
  it is **impossible** to create or update any OpenBao role or policy whose
  effect grants registrar authority — specifically, an attempt to (a) create
  an AppRole with `token_policies` naming the registrar policy or any
  `bootroot-runtime-*` policy, or (b) write a policy body granting
  `sys/policies/acl/*` or `auth/approle/role/*`, **fails**. A test exercises
  both attempts against a live registrar credential and asserts denial.
  **This test is credential-level by design** — it models a credential leaked
  or copied off the host (a disk image, a filesystem backup restored
  elsewhere), which is the case §3's surviving legs cover. It deliberately
  does **not** model an exploited request handler or a compromised REView:
  §3 strikes both, the first because the handler is roxyd's and roxyd is root
  here, the second because REView never holds this credential and is bounded
  by the verb's input contract instead. It deliberately does **not** model
  root on the bootroot
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
  `instance` presence contradicts it, with `ServiceInstanceMismatch`** — a
  many-per-host component with
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
  SANs differing only in the instance label; and the components with no
  instance dimension follow that **same one key shape** — a one-per-
  deployment singleton's `registration_id` is `<component>` (`review`) and a
  one-per-host component's is `<host>-<component>` (`h1-roxyd`), each
  **written explicitly**. A test asserts the field is **required**: a
  registration constructed without it does not exist as a state — there is
  no `Option`, no `service_name` default, and no legacy arm to exercise
  (§5.5).
- **Injective identity:** minting a derived `registration_id` that collides
  with a **different** already-registered host is **rejected** — the
  collision check runs **before** the spec-match, compares against a **durable
  per-identity bound host** (survives registrar restart), and the mint verb is
  **serialized** so concurrent colliding registrations cannot both mint. Tests
  cover a genuinely colliding pair. Today's registry contains none (§5.1), so
  the test uses a **synthetic** pair: components `web` and `aimer-web`, with
  `web` on host `h1-aimer` versus `aimer-web` on host `h1`, both deriving
  `h1-aimer-web-001` — (a) **sequentially** (second refused), (b)
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
- **Audit record (§5.6).** Every invocation of either verb — **accepted and
  refused alike** — produces bootroot-side records carrying the timestamp,
  the verb, the requested `(service_name, host, instance)`, the derived
  `registration_id`, the registrar's client-certificate identity, and the
  outcome. Tests: a `ServiceNameCollision` (which performs **no** OpenBao
  write, so the OpenBao audit device alone shows nothing) still produces a
  record; the record survives anything the registrar can do, since it holds no
  OpenBao credential; and the init check that the file audit device exists
  (`verify_audit_file`) still holds, since the verb-level record sits on top
  of it rather than replacing it.
- **Audit two-phase ordering (§5.6).** The **intent** record is written
  before any OpenBao write and the **outcome** record after, both under the
  per-`registration_id` mutex. Tests: an invocation whose **intent** record
  cannot be written is refused **with nothing created in OpenBao** — an
  implementation that writes one record after the fact and refuses on failure
  does **not** satisfy this, because it leaves a live identity the caller was
  told does not exist; and an intent with no outcome (a crash mid-mint) is
  surfaced as an anomaly rather than being silently equivalent to no
  invocation.
- **Verb rate limit + reserved audit capacity (§5.6).** A single client
  identity driving a flood of **refused** invocations is rate-limited and its
  repeated identical refusals are coalesced into a counted record; a test
  asserts the log does not grow proportionally to the flood. The verb-level
  records and the OpenBao audit device sit on a **reserved, quota'd**
  filesystem with a low-water alarm, so exhausting them cannot stop OpenBao
  serving — a test asserts the alarm fires before the quota is reached, and
  that the alarm and the intent-without-outcome count reach review over the
  `audit_health` tail field (RFC-C §6, RFC-D2 §4a) rather than staying on the
  bootroot host. A further test drives the **pre-derivation** arm (a
  non-DNS-label `service_name`; a component with no multiplicity entry) and
  asserts the rate limiter runs **before** any intent write, so a flood on
  that path produces coalesced counters and not one durable record per
  request; and asserts a throttled invocation returns the **retryable**
  `RegistrarBusy { retry_after }`, never one of `RegistrarUnavailable`'s
  permanent reasons.
- **Outcome-record failure keeps the teardown owed (§5.6).** A test makes the
  **outcome** write fail after a successful mint and asserts the verb returns
  `PostMintUnrecordable`, that the identity exists, and that REView's owed
  `Deregister` remains armed and is re-driven once the audit store recovers —
  an implementation that reports plain `AuditUnwritable` there leaves an
  invisible orphaned identity.
  Recorded attacker-influenced fields (`service_name`, `host`, certificate
  identity) are escaped: a test drives a refusal carrying newlines and
  delimiter characters and asserts the record cannot be forged or made
  unparseable.
- **Network confinement + non-expiry intact (§4).** The registrar's certificate
  is scoped to the registrar identity, the endpoint is a **root-owned `0700`
  unix-domain socket in a root-owned, non-world-writable directory**, created
  by socket activation **ordered ahead of roxyd** so the daemon never unlinks
  and re-binds a live path, and the certificate is renewed by the daemon —
  verified by asserting the **directory** permissions as well as the socket's,
  that an unprivileged local process can neither connect nor occupy the path
  during a daemon restart, that the callee is authenticated from the
  **connected** socket's peer credentials rather than by a pre-connect `stat`,
  and that the registrar **refuses a server identity it cannot match against
  the bootler-written fingerprint**, and that renewal keeps the identity
  valid past the certificate's original lifetime. There is **no registrar
  `secret_id`**, so there is no expiring secret to rotate — **and a test
  asserts that holds one layer down**: the renewal path uses the daemon's
  bootroot-internal credential and **no AppRole**, so an implementation that
  renews through the per-service ACME agent path (which authenticates with a
  `role_id` + `secret_id`) does not satisfy this criterion.
- **The endpoint authenticates itself, not only the caller (§4).** A test
  asserts an unprivileged local process cannot occupy the endpoint's socket
  path during a daemon restart or a boot-ordering window, and that the
  registrar refuses to speak to an endpoint it cannot authenticate. This
  matters because the mint response carries a **`ca_anchor`** (RFC-C §5) that
  becomes a newly joined host's trust root (RFC-B §7); an impersonated
  endpoint injects a CA of its choosing.
- **Registrar lapse is visible, not silent (§4).** The daemon surfaces the
  registrar certificate's remaining lifetime and reports a failing renewal. A
  test asserts a lapsed registrar produces the typed, non-retryable
  `RegistrarUnavailable` (RFC-C §5) rather than a generic error, since a lapse
  stops every enrollment in the deployment and the registrar cannot re-mint
  itself.

## 7. Issue decomposition (AgentCoop)

Self-contained issues; dependency order:

0. **The `registration_id` split** (§5.5) — add a **required**
   `registration_id` to `ServiceEntry` — **not** an `Option`, and **not**
   defaulting to `service_name`: the product is pre-release, so every
   registration is re-created by re-installing and there is no legacy arm to
   carry (§5.5). Move **every**
   namespace listed in §2 onto it: registry key, AppRole and policy names,
   the policy body's KV paths, the KV namespace, the agent-config managed
   block markers, the fast-poll state filename, the default cert/key
   filenames, and the remote-bootstrap artifact directory. Add the matching
   `[[profiles]]` field so `bootroot-agent` polls the right namespace.
   Because there is no compatibility arm, an agent and the `agent.toml`
   written for it move together at install, so **this forces no agent-first
   rollout order** — there is no window in which an older agent is handed a
   newer profile (§5.5). Derivation is RFC-A §4's rule,
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
1a. **Verb-level audit record** (§5.6) — **two-phase** (intent before any
   OpenBao write, outcome after, both under the per-`registration_id` mutex),
   for every invocation of either verb, accepted **and** refused, written
   under the bootroot-internal credential with the timestamp, verb, requested
   `(service_name, host, instance)`, derived `registration_id`, registrar
   certificate identity and outcome; escaped structured encoding; bounded
   rotation retaining at least 90 days on a **reserved, quota'd** filesystem;
   the **pre-derivation arm** (global lock, request-id-keyed record, limiter
   **before** any write); **rate limiting** on both verbs with
   per-`(verb, outcome-class)` buckets, coalesced repeated refusals, and a
   retryable `RegistrarBusy { retry_after }`; and the `audit_health` relay of
   the low-water alarm and the intent-without-outcome count. An invocation
   whose **intent** record cannot be written is refused before anything is
   created; a failed **outcome** write returns `PostMintUnrecordable` and
   leaves the teardown owed. This is the mechanism
   RFC-A §6's "detected, not prevented" argument depends on, and the rate
   limit is what stops that mechanism from being the resource an attacker
   exhausts. Depends on 1.
2. **Registrar credential policy** (§5.3) — the scoped policy authorizing only
   invoking the two verbs (NOT the CA/HMAC/EAB reads, which live inside the
   verbs under the bootroot-internal credential — RFC-A §12), in the decided
   form (§4/§6): an identity-scoped **client** leaf (distinguishable from a
   service leaf), the **root-owned `0700` unix-domain socket** in a root-owned
   directory with socket activation ordered ahead of roxyd, peer-credential
   authentication of the callee, the registrar pinning the daemon's server
   identity by the bootler-written fingerprint, and daemon-side renewal with
   roxyd re-reading the certificate on every dial. There is **no registrar
   `secret_id`**, so nothing to CIDR-bind and nothing to rotate.
   Depends on 1.
3. **Bootroot-internal privileged credential** (§5.4) — held by the daemon,
   never issued out. Also covers the daemon **self-issuing and renewing the
   registrar's client certificate** under that credential, with **no AppRole
   in the renewal loop** (§4), and surfacing its remaining lifetime. Depends
   on 1.
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
