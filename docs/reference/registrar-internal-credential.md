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
| `registrar-internal/agent.toml` | the dedicated `bootroot-agent` config | root-owned, `0600` |
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

The bundle is **this identity's alone**. It is never the shared
`secrets/certs/ca-bundle.pem` and never a KV-rendered service bundle, which is
what lets a rotation narrow this identity's trust without touching anything a
service reads.

## 4. Endpoint gating and TLS

Everything here is gated on the registrar endpoint-enablement predicate. bootroot
**consumes** that predicate — defining, storing and switching it belongs to the
registrar endpoint work — and reads it from `state.json`:

```json
{
  "registrar_endpoint": {
    "enabled": true,
    "domain": "example.internal",
    "host": "bootroot-01"
  }
}
```

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
3. Under the same root token: create or load the persistent ACME account key and
   issue the internal leaf through the ordinary outbound ACME path to step-ca —
   never with step-ca signing-key material. Everything lands in a staging
   directory; nothing is published.
4. The listener TLS transition, and the resulting `https://` URL is recorded.
5. Reconnect through that recorded URL and prove `auth/cert/login` succeeds with
   the staged material.
6. Only then publish the private bundle, the four credential files and the
   dedicated config.

Every artifact is registered for undo **before** it is created. A failure at any
point restores the prior listener, the prior state URL and the `OpenBao`
artifacts this run created, and removes the layout directory whole — staging
included. There is no half-provisioned credential and no TLS-upgraded state URL
after a rollback. An `auth/cert` mount the deployment already had is left alone;
only a mount this run enabled is disabled again.

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
  `paths.key = registrar-internal/key.pem`.

The internal profile runs in a **dedicated second `bootroot-agent` host
process**. It is not added to a service agent config and requires no
`ServiceEntry`. As with every other `bootroot-agent` host daemon, the operator
supervises it — `bootroot init` neither starts it nor installs a supervisor:

```sh
bootroot-agent --config <secrets-directory>/registrar-internal/agent.toml
```

**Ordinary renewal begins once the operator starts that process.** A host where
it has not been started is a host with nothing to reload, which is why a `HUP`
that matches no process is a successful outcome and not proof that a renewal
happened.

## 8. Renewal

There is no registrar-specific scheduler, registration point, lead-time constant,
retry policy or failure-reporting path, and there must not be one. The internal
profile is renewed by the ordinary `bootroot-agent` loop, on its own config's
`daemon` and `retry` settings, through the same `daemon::should_renew` predicate
every other profile uses:

- **expiry**, always; and
- **private-bundle drift**, because the generated config always sets
  `[trust].ca_bundle_path`, so `cert_chain::leaf_chains_to_bundle` is consulted.
  A configuration that leaves `ca_bundle_path` unset stays expiry-only in the
  generic predicate — that is the predicate's behaviour, not a special case.

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

## 10. Signalling

Reloading the internal agent is its own helper. It takes no `ServiceEntry` — the
internal profile is not a registered service and never will be — and addresses
the process by the fixed `registrar-internal/agent.toml` path below the
state-recorded secrets directory, which is the only thing that distinguishes its
command line from every other `bootroot-agent` on the host:

```sh
pkill -HUP -f <secrets-directory>/registrar-internal/agent.toml
```

`pkill` exit status **1** means *no process matched* and is a **success** here,
for the reason in §7. Any other non-zero status is a real failure and aborts the
rotation phase or the recovery that sent it.

`bootroot-agent` already reloads its settings and restarts its daemon task on
`SIGHUP` without exiting, so a reload picks up rewritten trust pins and replaced
material in place.

## 11. Root mismatch and recovery

Before any renewal or login, the stored root fingerprint is compared with the
active root. A mismatch returns a typed **repair-required** error and performs no
ACME request, no login and no write — a mismatched root means the entry no longer
trusts this leaf, so attempting any of them would turn a clean refusal into a
partial change.

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
- never re-runs install and never changes a service credential;
- is a no-op that says so when the set is complete and the stored root already
  matches the active one, unless `--force` is passed.
