<!-- markdownlint-configure-file {
  "MD013": { "tables": false, "code_blocks": false }
} -->

# The bootroot-internal registrar credential

The registrar's `mint` and `deregister` verbs write derived service policies and
`AppRole`s and read the deployment's CA, responder-HMAC and agent-EAB material.
This file describes the credential that authority lives in, where its files are,
how it is provisioned, renewed, rotated, reloaded and repaired — and it contains
no secret material of any kind.

It is checked in outside the mirrored `docs/en/` + `docs/ko/` operator pair, on
the same precedent as its sibling reference documents: the operator-facing
subset is in `docs/en/installation.md` and `docs/en/operations.md` (and their
Korean counterparts), and this file is the whole contract in one place.

## 1. The authority boundary

**The credential never leaves bootroot.** No caller-visible response, no
generated config a caller reads, no non-secret artifact and no request input
transports it or selects the client that holds it. A registrar supplies an
identity's *parts* and nothing else; the privileged client is constructed inside
bootroot from the credential on disk.

Three properties make that structural rather than a convention:

- The verb service's production factory,
  `bootroot::registrar::verbs::RegistrarVerbs::internal`, **takes no client and
  no caller**. It is handed a secrets directory, an `OpenBao` URL, a KV mount,
  the rendered registrar config and the fixed TTL/wrap policies, and it builds
  the client itself. The injected-client constructor is retained for tests.
- The credential is a **certificate**, not an `AppRole`. Login is
  `auth/cert/login` over TLS. No path in the credential, renewal or verb layers
  reads a `role_id` or a `secret_id`.
- The token that login mints carries **one** policy —
  `bootroot-registrar-internal` — and `token_no_default_policy` is set, so the
  exact allowlist in §5 is the whole grant.

The guarantee bounds the *credential*, not a root-compromised host. The daemon
runs as root on the bootroot host and root there can read the key. That is
explicitly out of scope; what is in scope is a credential leaked or copied off
the host, and independence from the registrar's own code being correct.

## 2. The identity

One name, fixed:

```text
001.bootroot-registrar-internal.<host>.<domain>
```

composed through `bootroot::registrar::registrar_internal_identity`, which is
`compose_san(Some(1), REGISTRAR_INTERNAL_LABEL, host, domain)` — the same
composition every ordinary service leaf goes through
(`docs/reference/registrar-provisioning-config.md` §6.1). `<domain>` is the
configured deployment domain and is a **suffix** of whatever label count it was
configured with, never a single trailing label.

The second label falls inside `bootroot::registrar::RESERVED_SERVICE_NAME_PREFIX`
(`bootroot-`), so no operator-driven `bootroot service add` can mint it — the
same guard that protects the registrar client and endpoint identities described
in `docs/reference/registrar-client-identity.md`.

Unlike those two, this name never appears on a caller-facing wire. It is
presented to `OpenBao` and to nothing else.

## 3. The fixed paths

All of them sit in the fixed `registrar-internal/` subdirectory below the
**state-recorded** secrets directory (`state.json`'s `secrets_dir`). None of
them is configurable: a path an operator could move is a path that provisioning,
rotation, recovery and the `pkill -HUP` pattern would each have to rediscover,
and the four would drift.

| File | Holds | Mode |
| --- | --- | --- |
| `registrar-internal/key.pem` | the internal leaf's private key | root-owned, `0600` |
| `registrar-internal/chain.pem` | the leaf and the chain it was issued with | root-owned, `0600` |
| `registrar-internal/acme-account.json` | the persistent ACME account signing key | root-owned, `0600` |
| `registrar-internal/root-fingerprint` | SHA-256 of the root the `auth/cert` entry trusts | root-owned, `0600` |
| `registrar-internal/agent.toml` | the endpoint daemon's `bootroot-agent` config | root-owned, `0600` |
| `registrar-internal/ca-bundle.pem` | this identity's **private** CA bundle | `0644` |

The chain and the stored fingerprint are public certificate data — they
are never redacted in a log or an error — but they are still written
`0600`, because the one process that reads them runs as root and a
narrower mode costs nothing. The private bundle takes `0644` from
`fs_util::write_ca_bundle`, the same writer every other bundle goes
through.

The six are an **all-or-none** set on an endpoint-enabled host. Missing, partial
or invalid material, config or bundle is a typed failure, never a
half-usable credential. Every secret file is published by writing a temporary in
the same directory at `0600` and renaming it into place, so none of them is ever
observable at its final path under a wider mode.

"Invalid" covers the two non-credential members as well, and it is checked by the
one shared loader every caller reaches the credential through — the verb factory,
the rotation's up-to-date check and the repair — rather than by each of them in
turn. The private bundle has to hold at least one certificate, and the generated
config has to parse and still describe *this* identity: exactly one profile,
named `bootroot-registrar-internal` at instance `001`, with
`profiles.paths.cert`, `profiles.paths.key` and `acme.account_key_path` on the
fixed paths above, `[trust].ca_bundle_path` on the private bundle beside them,
and a non-empty `[trust].trusted_ca_sha256`. A host that fails any of those is
refused with `InternalCredentialError::Invalid` naming the file: the six files
are all present, but the `bootroot-agent` process that renews this certificate
— the registrar endpoint daemon, §7 — cannot start, and serving the privileged
verbs over a credential
nothing renews is exactly what the all-or-none rule exists to prevent. The pin
list and the bundle path are what Phases 3 and 6 rewrite, so they are held to
their shape rather than to a particular value.

Each file publishes atomically, but so does the **set**. A publication over a
host that already carries a credential first copies every existing member into a
`registrar-internal/.prior` snapshot, and puts the whole set back if any member
fails to publish — otherwise a failure part-way through would leave a new key
beside the previous chain, which still reads as complete and can no longer log
in. Members that were not there before are removed again instead, which is the
bare host a first provisioning started from. The snapshot is discarded once the
set is settled either way; a snapshot that outlives a crash is cleared by the
next publication before it captures, so a restore can never reinstate bytes from
an older run.

The bundle is **this identity's alone**. It is never the shared
`secrets/certs/ca-bundle.pem` and never a KV-rendered service bundle, which is
what lets a rotation narrow this identity's trust without touching anything a
service reads.

## 4. Endpoint gating and TLS

Everything here is gated on the registrar endpoint-enablement predicate, which
bootroot reads from `state.json`. `bootroot infra install
--registrar-endpoint-host <label> --registrar-endpoint-domain <domain>` is what
records it; `bootroot init` and `bootroot reinit` only **consume** it and carry
the recorded value through, and never set or change it:

```json
{
  "registrar_endpoint": {
    "enabled": true,
    "domain": "example.internal",
    "host": "bootroot-01"
  }
}
```

`infra install` records the entry when there is none or it is `false`, leaves
an identical enabled entry alone, and refuses — before any other work — to
change the `host` or `domain` of an enabled one, since this identity's SAN is
composed from them. Run without the two flags, it leaves the recorded entry
exactly as it is. Switching an endpoint off stays the manual procedure the
operations guide describes.

An absent or `false` entry means the endpoint is off. Such a host keeps its
plaintext loopback listener and its `http://` `state.openbao_url` exactly as they
were and creates none of the six files. An `enabled` entry that omits `host` or
`domain` fails the run rather than guessing a SAN the deployment's CA never
issues.

The entry is deployment intent, so it survives the rewrites of `state.json` that
preserve intent: `bootroot init` carries it through verbatim, and `bootroot
reinit` snapshots it into the minimal state it writes. A host that lost it would
be re-initialized as an ordinary one — plaintext listener, `http://` URL — while
the previous run's credential files were still on disk, and
`bootroot rotate registrar-internal-credential` would refuse to repair that,
because it reads the same predicate.

`auth/cert` requires TLS, so `bootroot init`'s TLS gate is
`bind_intent || registrar_endpoint_enabled`. An endpoint-enabled **loopback**
host therefore terminates TLS on `:8200` too. It reuses the same server
certificate issuance, `openbao.hcl` rewrite, container recreate, live TLS probe,
unseal, state update and rollback envelope as a non-loopback bind; it differs
only in carrying no exposed-port compose override and in recording the same host
and port it already answered on with the scheme changed to `https`.

**No listener-side client-certificate option is introduced.** `tls_client_ca_file`,
`tls_require_and_verify_client_cert` and `tls_disable_client_certs` are all
absent. A TLS listener requests client certificates by default and `auth/cert`
validates the presented chain against its own trusted entry; listener-side
verification would break the certificate-less `AppRole` agents and every
token-authenticated command against the same port.

Certificate login is **never** attempted over plaintext. A recorded
`http://` URL is a typed refusal (`InternalCredentialError::PlaintextOpenBaoUrl`)
raised before the credential is even read. A repair — the Phase-4 tail or
`bootroot rotate registrar-internal-credential` — raises the same refusal before
it writes anything, because material republished against a plaintext URL would
be a credential that cannot log in.

The token that login mints is a bearer secret in its own right, and it is
wrapped as one at the boundary it arrives on. The `auth/cert/login` response body
deserializes straight into `bootroot::secret::ClientToken`, whose `Debug` prints
`<redacted>` and which derives no `PartialEq`, so it is never a bare `String` at
any point between the wire and `OpenBaoClient::set_token` — the one call that
takes its bytes. The client holds it in that form too, which is why a `{:?}` on
an `OpenBaoClient`, on the login result, or on any type that a
`#[derive(Debug)]` encloses either one in cannot render a token. It is the
same reasoning, and the same module, as the `HmacSecret` wrapper in §7.

## 5. The `auth/cert` entry and the policy

`bootroot init` enables the `cert` auth backend when it is absent and creates one
entry, `auth/cert/certs/bootroot-registrar-internal`. The entry:

- trusts the deployment **root** CA and nothing else;
- allows exactly the one DNS SAN of §2 (`allowed_dns_sans`), so an ordinary
  service leaf and a registrar client or endpoint leaf are both rejected;
- assigns exactly `["bootroot-registrar-internal"]` with
  `token_no_default_policy = true`.

The policy body is
`bootroot::registrar::internal::build_registrar_internal_policy` and is an exact
allowlist:

| Path | Capabilities | Why |
| --- | --- | --- |
| `sys/policies/acl/bootroot-service-*` | create, read, update, delete | the derived per-registration policy |
| `auth/approle/role/bootroot-service-*` | create, read, update, delete | the derived role, its `role-id` read and its `secret-id` issuance |
| `<kv>/data/bootroot/services/*` | create, read, update, delete | the durable registrar binding and the service material |
| `<kv>/metadata/bootroot/services/*` | read, delete | existence checks and the destroying delete |
| `<kv>/data/bootroot/ca` | read | trust material for a minted identity's bootstrap |
| `<kv>/data/bootroot/responder/hmac` | read | the same |
| `<kv>/data/bootroot/agent/eab` | read | the same |

There is no `sys/policies/acl/*` or `auth/approle/role/*` wildcard, no `sys/auth`
grant, no step-ca password or database path, and no grant over the internal
policy itself. The prefix confinement is what stops the credential from
authoring a policy under a name it did not derive, or binding a role to one.

`token_no_default_policy` means the table above is the *whole* grant, and one
consequence is worth stating because it looks like a fault: the minted token
cannot call `auth/token/lookup-self`. That path is granted by `default`, which
this token deliberately does not carry, so a `403` there is the mechanism
working rather than a misconfigured entry. Nothing in bootroot looks this token
up — the root-authority check in §11 runs against the operator's root token, not
this one — and `scripts/impl/run-registrar-internal-e2e.sh` asserts the denial
against a live backend precisely because it is the clearest available proof
that `default` is absent.

## 6. Provisioning order

`bootroot init` performs the sequence below on an endpoint-enabled host, entirely
inside its existing rollback transaction:

1. `OpenBao` bootstrap, step-ca initialization and agent-EAB acquisition — the
   existing steps, unchanged.
2. Under the init **root token**: enable `auth/cert` if absent, write the policy,
   create the entry.
3. The internal SAN is attached to the running HTTP-01 responder as a Docker
   network alias. step-ca validates a challenge by fetching
   `http://<identifier>/.well-known/acme-challenge/…`, and inside the compose
   network that name resolves only if the responder answers to it. Every
   service leaf gets this from `service add`; the internal identity has no
   `ServiceEntry`, so `init` attaches it from the recorded predicate. A
   responder it cannot be attached to fails the run here rather than as a
   challenge timeout in the next step.
4. Under the same root token: create or load the persistent ACME account key and
   issue the internal leaf through the ordinary outbound ACME path to step-ca —
   never with step-ca signing-key material. Everything lands in a staging
   directory; nothing is published.
5. The listener TLS transition, and the resulting `https://` URL is recorded.
6. Reconnect through that recorded URL and prove `auth/cert/login` succeeds with
   the staged material.
7. Only then publish the private bundle, the four credential files and the
   dedicated config — as one set, over a snapshot of whatever was there, so a
   failure mid-publication leaves the previous credential intact.

The alias is part of the shared set `state.json` drives, not a one-off: `infra
up` replays it and `service remove` reconciles it, so a responder restart or an
unrelated deregistration cannot leave the internal identity unresolvable and
break its next renewal.

The step-ca ACME directory and the responder admin URL the internal profile is
issued and configured against both follow **this install's own published
ports** (`STEPCA_HOST_PORT` and `HTTP01_ADMIN_HOST_PORT`, from the process
environment, then the compose directory's `.env`, then the compose default),
never a fixed `:9000`/`:8080`. On a host that moved those ports a fixed value
reaches nothing; on a host co-located with a second instance it reaches that
instance.

Every artifact is registered for undo **before** it is written — the `auth/cert`
mount the moment it is enabled, which is before the policy and the entry are
written over it. A failure at any point restores the prior listener, the prior
state URL and the prior `OpenBao` artifacts, and removes the layout directory
whole — staging included. There is no half-provisioned credential and no
TLS-upgraded state URL after a rollback. An `auth/cert` mount the deployment
already had is left alone; only a mount this run enabled is disabled again.

What a run found is not a run's to *delete*, so ownership is decided by a lookup
that answered. A read that fails — a transient error against the entry or the
policy — fails the run before anything is created, rather than being read as
"absent" and registering the deletion of an artifact the deployment already
depends on. A re-run over an already-provisioned host therefore registers
neither the entry, nor the policy, nor the layout directory it found for
deletion: its rollback sweeps only its own staging directory, and its
publication restores the credential from the snapshot above.

Found is not the same as untouched, though. The convergence rewrites the policy
and the entry whether or not this run created them — a re-run points the entry
at the recorded predicate's SAN and the active root — so both bodies are read
back and kept before they are replaced, and a rollback writes them back exactly
as they were read. Without that, a re-run that failed after the convergence and
before the new leaf was published would leave the host trusting a certificate it
does not have, and its policy permanently replaced.

## 7. The generated config, and starting its daemon

`registrar-internal/agent.toml` is bootroot's own file with exactly one author,
so it is rendered whole rather than upserted. It carries the required global
agent settings `init` already resolved — the step-ca ACME directory URL, the
deployment domain and contact email, the responder URL and HMAC, the retry and
scheduler settings and the `[eab]` credentials when the deployment has any —
plus:

- `[acme].account_key_path` pointing at `registrar-internal/acme-account.json`,
  which is what keeps one stable ACME account across renewals;
- `[trust].ca_bundle_path` pointing at `registrar-internal/ca-bundle.pem`, with
  `trusted_ca_sha256` covering every certificate in that copy;
- one `[[profiles]]` entry naming the fixed identity, with
  `paths.cert = registrar-internal/chain.pem` and
  `paths.key = registrar-internal/key.pem`;
- after everything above, the operator's `[registrar]` and
  `[registrar_endpoint]` tables.

Two of those values are bearer secrets: the HTTP-01 responder HMAC, which
authenticates a token placement at the responder, and the `[eab]` HMAC, which
authorises account creation at the CA. The file has to carry them — the daemon
authenticates with them — so the mode is what protects them there, and the
redaction is what protects them once they are read back. Both are held in memory
as `bootroot::secret::HmacSecret`, whose `Debug` prints `<redacted>`, so a
`#[derive(Debug)]` on anything holding the loaded `Settings` — a `tracing`
field, a `{:?}` in an error context, an `anyhow` chain — cannot render either
one. The raw bytes are reachable only through the explicit `expose()` the
responder signer and the account binder call. That type is not specific to this
credential: it is the same wrapper every `bootroot-agent` config's responder and
EAB HMACs now live in.

The `[registrar]` and `[registrar_endpoint]` tables are the only part of the
file that comes from the operator. The operator writes them in the
`bootroot-agent` configuration file `init` is given with `--agent-config`,
which is mandatory on an endpoint-enabled run, and `init` copies both into this
file with the same keys and values. A key the operator left out stays out, so it
keeps its default. Nothing else in the operator's file is copied — its
`[[profiles]]`, `[acme]`, `[trust]` and top-level keys are ignored — and
nothing in it can override a key `init` renders, because the two tables are
disjoint from every other table here.

Before it creates the audit store, renders or deletes its Compose override, or
makes any Docker call, an endpoint-enabled `init` holds the two tables to every
requirement an enabled endpoint has: `[registrar] state_file`, `agent_server`
and `agent_responder_url`, the four `[registrar_endpoint]` material paths
(`server_cert_path`, `server_key_path`, `client_cert_path`, `client_key_path`),
and each value's own rules. A missing or invalid key refuses the run, names the
key, and leaves the host as it found it. These are the daemon's own checks; only
the platform rule — an enabled endpoint is served on Linux alone — is left to
the daemon. `bootroot reinit` runs the same check before its wipe. A disabled or
absent predicate renders no internal config at all, whatever the operator's file
holds.

Each `init` takes the tables from that run's `--agent-config` file. Re-running
`init` on an already-initialized host is not a supported way to change them.
Every other rebuild of this file keeps them, §9.

On an endpoint-enabled host, **the registrar endpoint daemon is the process
that runs on this file**:

```sh
bootroot-agent --config <secrets-directory>/registrar-internal/agent.toml
```

One process does both jobs: it renews the internal credential through the one
profile above, and it serves the registrar endpoint under the operator's two
tables. There is no second `bootroot-agent` process for the internal credential
on such a host, and no other file carrying the endpoint's configuration. The
internal profile is not added to a service agent config and requires no
`ServiceEntry`.

`bootroot-registrar.service` runs that process. The shipped unit's `ExecStart`
names a placeholder path, because the secrets directory is per deployment, so an
installer overrides it with a drop-in — an empty `ExecStart=` followed by the
real one (see the operations guide's registrar endpoint section). As with every
other `bootroot-agent` host daemon, `bootroot init` neither starts it nor
installs the unit.

**Ordinary renewal begins once that process starts.** A host where it has not
been started is a host with nothing to reload, which is why a `HUP` that matches
no process is a successful outcome and not proof that a renewal happened.

On a deployment initialized with `--no-eab`, the endpoint daemon's first surface
issuance reads the agent EAB entry in `OpenBao` and accepts only a populated
payload or the explicit cleared one, refusing an absent entry. So an
endpoint-enabled `init` that registers no EAB records the cleared payload
`{"kid": "", "hmac": ""}` at `bootroot/agent/eab` — the shape
`bootroot rotate eab-clear` writes — when the path does not exist yet. The
write is a KV v2 create-if-absent (`cas: 0`), so an existing entry, populated or
cleared, is never overwritten, even one another writer creates while `init`
runs; only a payload this run created is removed by its rollback. A disabled or
absent predicate writes nothing.

## 8. Renewal

There is no registrar-specific scheduler, registration point, lead-time constant,
retry policy or failure-reporting path, and there must not be one. The internal
profile is renewed by the ordinary `bootroot-agent` loop of the endpoint daemon
(§7), on its own config's
`daemon` and `retry` settings, through the same `daemon::should_renew` predicate
every other profile uses:

- **expiry**, always; and
- **private-bundle drift**, because the generated config always sets
  `[trust].ca_bundle_path`, so `cert_chain::leaf_chains_to_bundle` is consulted.
  A configuration that leaves `ca_bundle_path` unset stays expiry-only in the
  generic predicate — that is the predicate's behaviour, not a special case.

That loop has one precondition, and it is a precondition rather than a second
scheduler: before any issuance it starts, the daemon compares the stored root
fingerprint with the deployment's active root and refuses on a mismatch with the
typed repair-required error of §11, having made no ACME request, no login and no
write. It is needed because the two do not move together on purpose. A full
rotation replaces the root in Phase 2 and reloads this daemon in Phase 3, but the
`auth/cert` entry, the leaf and the stored fingerprint are only replaced in the
tail after Phase 4 — so inside that window a leaf that fell due would otherwise
be reissued under a root the entry does not yet trust, and the repair would then
have to unpick a credential it could have simply replaced.

The refusal travels out through the same post-renew failure hooks any other
issuance failure takes, and the daemon keeps ticking. The tick after the repair
— whether the rotation's own tail or `bootroot rotate
registrar-internal-credential` — renews normally, with no restart.

## 9. Rotation

**An intermediate-only rotation changes nothing here.** The `auth/cert` entry
trusts the *root*, which an intermediate-only rotation does not replace, so the
entry, the material, the config and the private bundle are all still correct.

A **full** rotation touches the internal artifacts at three points. The phase
numbers are unchanged; nothing is renumbered.

| Point | What happens |
| --- | --- |
| **Phase 3** | The private bundle is atomically rewritten and the config's pins upserted to the same additive old-root / old-intermediate / new-root / new-intermediate set and PEM bundle the rotation publishes to `OpenBao` KV, then the internal daemon is reloaded. The entry, the leaf and the stored root fingerprint are **not** touched. |
| **The tail after Phase 4** | An unnumbered, mandatory step that runs after step-ca restarts and **before** Phase 4 is recorded, under explicit root-token authority. It verifies the bundle and config are still on the Phase-3 additive set, replaces the `auth/cert` entry, the leaf material and the stored root fingerprint, and notifies the daemon. `--skip reissue` skips Phase 5, not this. A failure retains the pre-Phase-4 state, so a resume repeats the restart and the repair together. |
| **Phase 6** | Only when finalization is not skipped, and only after its existing migration checks pass: the private bundle and `[trust].trusted_ca_sha256` are atomically narrowed to the finalized new-root / new-intermediate pair and the daemon is reloaded, before Phase 6 is recorded. A run that skips finalization keeps the additive internal trust set, exactly as it keeps the additive KV set. |

The bundle and the pins move as **one** update in both Phase 3 and Phase 6. Each
file publishes atomically on its own, which is not enough: a run that replaced
one and failed on the other would leave the pair describing two different
generations — a bundle the pins do not cover — with the phase unrecorded and
nothing registered to undo it. So the rewritten config is computed before either
file is touched, the existing pair is captured into the same
`registrar-internal/.prior` snapshot the credential publication uses, and any
failure puts both members back. Only the reload is outside that: a signal that
fails leaves a pair that is already consistent, and the resume repeats the whole
phase anyway.

**Every rotation keeps the operator's `[registrar]` and `[registrar_endpoint]`
tables.** Phases 3 and 6 rewrite the `[trust]` keys in place and leave every
other byte of the file, both tables included, as it was. The tail after Phase 4
and `bootroot rotate registrar-internal-credential` instead republish the whole
set, `agent.toml` rendered afresh; that rebuild carries both tables over from
the file it replaces, with their values unchanged, and never asks the operator
for them. A file without them — an endpoint-disabled host — is rebuilt without
them. A file that exists but cannot be read or parsed refuses the repair, naming
the file, before anything is issued, converged or published: a republication
that silently dropped the tables would leave a daemon that no longer serves the
endpoint. Parsed means what the daemon means by it — the whole file must
deserialize as the daemon's settings — so a file that is valid TOML but holds a
value the daemon would reject, in either table or anywhere else, is refused
rather than carried into a set the daemon cannot start on. The same parse is
the record of the ACME directory, contact email and responder URL `init` chose,
which the rebuild keeps; it falls back to rebuilding them the way `init` derived
them only when the file is absent, never when it is present and does not parse.

**`rotate responder-hmac` and `rotate eab-clear` touch the config too.** The
config has no `[openbao]` section and polls nothing, so the fast-poll loop that
carries a rotated responder HMAC or a cleared EAB to every other agent never
reaches the endpoint daemon — and a daemon still signing its HTTP-01 token
placements with the old HMAC fails every issuance it makes, the internal
credential's renewal and both endpoint surface leaves' included. So, on a host
that carries the config:

| Rotation | What happens to the config |
| --- | --- |
| `rotate responder-hmac` | `[acme].http_responder_hmac` is set to the value written to `bootroot/responder/hmac`, after that write and every fan-out write and before `openbao-agent-responder` is restarted. |
| `rotate eab-clear` | The `[eab]` table is removed, after the cleared EAB is written everywhere else. A file with no `[eab]` table — including one whose `eab` key holds something other than a table — is left byte for byte as it was, and not rewritten. Removing it keeps the file in agreement with `OpenBao`, from which a repair would rebuild it without `[eab]` anyway. |

Both rewrite that one key in place and keep every other byte of the file — both
operator tables and the `[trust]` pins included — publish it root-owned at
`0600` by one rename, and then reload the daemon (§10). Which hosts this applies
to is decided by reading the file, before the rotation's first `OpenBao` write:
an absent file means the host has none and the rotation does exactly what it
does on any other host; a file that exists but cannot be read — including the
permission error an unprivileged run gets, which the refusal answers by asking
for a re-run as root — does not parse as TOML, or, for `rotate responder-hmac`,
has an `acme` that is not a table refuses the rotation, naming the file, with
nothing written anywhere. `[acme]` is rewritten in whichever form the file
spells it — a `[acme]` header, dotted `acme.` keys or an inline table — since
the agent loads all three alike, and only the value is replaced: a comment
trailing the old HMAC stays where it was. A failure after the `OpenBao` writes is
reported rather than rolled back: the new value is already the source of
truth, so re-running the rotation, or running
`bootroot rotate registrar-internal-credential --force` to re-render the file
from `OpenBao`, converges it. Once the control-node record —
`bootroot/responder/hmac` or `bootroot/agent/eab` — carries the new value, every
remaining step runs even when an earlier one fails, and the rotation reports all
the failures together:
a failed fan-out write to one service's record still leaves the config
rewritten and, for `rotate responder-hmac`, the responder handed the new HMAC.
`rotate responder-hmac` hands the responder the new HMAC before it reports any
such failure: the service agents are already converging on it, and the
`--force` repair issues over ACME with the value it reads from `OpenBao`, which
a responder left on the old one would refuse.

**Every rotation that writes the config serializes on one lock.** Rotations can
overlap — scheduled rotation units run on timers — and each writer is a
read–modify–write that an atomic rename does not make atomic. A repair, for
example, reads the responder HMAC and the EAB from `OpenBao`, issues over ACME,
and only then republishes the set: a responder-HMAC rotation landing in between
would be overwritten with the old value. So `rotate responder-hmac`,
`rotate eab-clear`, Phases 3 and 6, the tail after Phase 4 and
`bootroot rotate registrar-internal-credential` each hold an exclusive advisory
lock on `registrar-internal/agent.toml.lock` from reading the value they will
write until they have published it:

- Phases 3 and 6 hold it from before reading the config until after the rename,
  or the restore on failure.
- A repair holds it from after its root-authority and TLS refusals, before it
  reads `OpenBao`, until the set is published — across the ACME issuance.
- `rotate responder-hmac` holds it from before its first `OpenBao` write until
  it has restarted `openbao-agent-responder`, seen the new value rendered into
  the responder config and, where the compose file runs a responder, sent the
  responder `SIGHUP` — including when a fan-out write or the config rewrite
  failed on the way. A repair waiting on it therefore issues only against a
  responder that has been handed the HMAC it read. The responder applying that
  `SIGHUP` is not awaited.
- `rotate eab-clear` holds it from before its first `OpenBao` write until the
  config is published and the daemon signalled, including when a per-service
  write failed on the way.

Under the lock the two rotations re-read the file and apply their change to what
they read, so a `[trust]` change published while they waited survives them. The
lock file holds no data, is created `0600` and never removed, and is not a member
of the internal set; the daemon only reads the config and never takes the lock.
A host without the config takes no lock.

**`bootroot init` does not take the lock.** `init` provisions the deployment
the rotations operate on, and running a rotation while `init` is still running
is not supported for any file `init` writes. If it happens anyway, the config
can end on the value `init` read; `bootroot rotate registrar-internal-credential
--force` re-renders it from `OpenBao`.

## 10. Signalling

Reloading the internal agent is its own helper. It takes no `ServiceEntry` — the
internal profile is not a registered service and never will be — and addresses
the process by the fixed `registrar-internal/agent.toml` path below the
state-recorded secrets directory, which is the only thing that distinguishes its
command line from every other `bootroot-agent` on the host. On an
endpoint-enabled host that process is the registrar endpoint daemon, so the one
signal reaches the one process that both renews the credential and serves the
endpoint:

```sh
pkill -HUP -f <secrets-directory>/registrar-internal/agent.toml
```

`pkill` exit status **1** means *no process matched* and is a **success** here,
for the reason in §7. Any other non-zero status is a real failure and aborts the
rotation phase or the recovery that sent it.

`bootroot-agent` already reloads its settings and restarts its daemon task on
`SIGHUP` without exiting, so a reload picks up rewritten trust pins, a rotated
responder HMAC, a removed EAB and replaced material in place. No rotation
changes a key in the operator's `[registrar]` or `[registrar_endpoint]` table
(§9), so a rotation's reload never asks the daemon to apply a changed endpoint
setting.

## 11. Root mismatch and recovery

Before any renewal or login, the stored root fingerprint is compared with the
active root. A mismatch returns a typed **repair-required** error and performs no
ACME request, no login and no write — a mismatched root means the entry no longer
trusts this leaf, so attempting any of them would turn a clean refusal into a
partial change.

The active root is re-read from `<secrets>/certs/root_ca.crt` at each of those
points rather than captured once. The credential is long-lived and the root under
it is not: a full rotation replaces the root in Phase 2 and this credential only
in the tail after Phase 4, so anything holding a verb service across that window
holds one whose leaf the entry has stopped trusting. The comparison is therefore
a precondition of *use*. It runs ahead of the cached login too, so a token still
inside its lease is not handed out after the root changed — that would be a write
under a superseded credential, which is worse than a login that would have been
refused. A root certificate that cannot be read is itself a refusal, never an
assumption that the stored one still matches.

```sh
bootroot rotate registrar-internal-credential
```

repairs it. The command:

- requires an `OpenBao` token carrying the **`root`** policy, confirmed by token
  self-lookup **before** anything is mutated. An `AppRole` token — including the
  runtime-rotate one — is refused with a typed root-authority-required error;
- determines the trust material from the recorded rotation state: the additive
  bundle and pins while a full rotation is unfinished, the finalized
  active-generation bundle and pins otherwise;
- atomically updates the private bundle and the config before reloading, then
  replaces the material and the stored fingerprint and resumes the daemon;
- issues and proves the replacement **before** it touches the `auth/cert` entry.
  The convergence rewrites that entry to trust the *active* root, which during a
  full rotation is the new one, so an entry replaced ahead of a leaf that is then
  never issued would leave the on-disk credential chained to a root the entry no
  longer trusts — a retryable ACME failure turned into a host whose internal
  daemon cannot log in. Issuance runs over ACME against step-ca and needs no
  entry, so it goes first; the entry is then converged, the staged leaf is proved
  with a real `auth/cert/login`, and only then is the set published. The entry
  **and the policy** read before the convergence are put back verbatim if the
  login or the publication fails, so the auth artifacts and the material move
  together: the host ends either on the new set or on the set it started with.
  Both are captured, because the convergence rewrites both — an undo covering
  only the entry would leave a host whose policy this run did not create, an
  older release's body or one widened by hand, permanently on this run's body,
  with nothing recording the change. A repair runs outside `init`'s rollback
  envelope, so this capture is the whole undo. As there, a lookup that does not
  answer fails the repair before anything is written rather than being read as
  "absent";
- never re-runs install and never changes a service credential;
- is a no-op that says so when the set is complete and the stored root already
  matches the active one, unless `--force` is passed.
