# Operations

This section focuses on operational checks and incident response procedures.
See **Installation** and **Configuration** for full setup steps and options.
For CLI command syntax, see [CLI](cli.md).

For CI/test operations, see [CI & E2E](e2e-ci.md).

## Automation boundary (must read)

Bootroot-managed scope:

- generation and updates of config/material files (`agent.toml`, `agent.hcl`,
  `agent.toml.ctmpl`, `token`, and bootstrap-related files)
- per-delivery-mode state recording and bootstrap input preparation
  during service add
- operational command flow entry points (`rotate`, `verify`, `status`)

Operator-managed scope:

- binary installation/update (`bootroot`, `bootroot-agent`, `bootroot-remote`,
  OpenBao Agent)
- process supervision for always-on behavior (start/restart/boot startup)
- runtime setup (for example, `docker compose` service definitions or
  `systemd` units/timers) and boot-time start/restart policies

Policy summary:

- recommended runtime differs by deployment target:
  step-ca/OpenBao/HTTP-01 responder run as independent services
  (Compose or systemd).
  For services added via `bootroot service add`, Docker services are best
  operated with per-service agent sidecars, while daemon services are best
  operated as host daemons (systemd).
- in all paths, operators must satisfy reliability requirements directly
  (always-on, restart, dependency ordering).
- In both paths, bootroot does not fully manage the entire process lifecycle.

## Core operational checks

Run these regularly for fast health checks:

```bash
bootroot status
bootroot verify --service-name <service> --db-check
bootroot service info --service-name <service>
bootroot monitoring status
```

- `bootroot status`: overall state from OpenBao/step-ca/state file perspective
- `bootroot verify --service-name <service> --db-check`:
  non-interactive issuance/verification/DB/responder checks
- `bootroot service info --service-name <service>`:
  current per-service state including delivery mode
- `bootroot monitoring status`: Prometheus/Grafana container status

## bootroot-agent

- Monitor logs for issuance, authorization, and hook results.
- Ensure key/secret permissions stay `0600`/`0700` on disk.
- Use hooks to reload dependent services after renewals
  (hook definitions live in **Configuration**).
  Hooks can be configured at service onboarding time via
  `bootroot service add --reload-style`/`--reload-target` (presets) or
  `--post-renew-command`/`--post-renew-arg` (low-level), which write the
  `[profiles.hooks.post_renew]` entry into the managed `agent.toml` profile.
- Services that use mTLS must be able to read the CA bundle
  (for example, `trust.ca_bundle_path`).

## step-ca + PostgreSQL

- Back up the PostgreSQL database regularly.
- Test restores in a staging environment.
- Store backups in a secure location with restricted access.

## HTTP-01 responder

- Ensure port 80 is reachable from step-ca to the responder.
- Ensure the admin API (default 8080) is reachable from bootroot-agent.
- Keep `acme.http_responder_hmac` consistent with the responder secret.
- If binding to port 80 under systemd, run as root or grant
  `cap_net_bind_service`.

## OpenBao

- Regularly check OpenBao seal status.
- Store unseal keys and the root token securely and separately.
- Keep AppRole/policies scoped to the minimum required paths.
- Include KV v2 data in backup/snapshot policies.
- Confirm reload/restart behavior for bootroot-agent/step-ca after rotations.

### Audit logging

A file-based audit backend is declared in `openbao/openbao.hcl` and
enabled automatically when the OpenBao container starts. The audit log
captures every OpenBao API request (authentication, secret reads/writes,
policy changes) and is essential for post-incident investigation.

`bootroot init` verifies that the audit backend is active. If no file
audit device is found (e.g. the audit stanza was removed from
`openbao.hcl`, or the `openbao-audit` volume is not mounted), init
fails. Restore the audit configuration and re-run init.

- **Log location (inside container):** `/openbao/audit/audit.log`
- **Host access:** the log is persisted on the `openbao-audit` Docker
  volume. Inspect it with
  `docker compose exec openbao cat /openbao/audit/audit.log`.
- **Rotation:** OpenBao does not rotate the audit log itself. Use an
  external log rotation tool (e.g. `logrotate` on a bind-mount, or a
  sidecar that tails the volume) and send `SIGHUP` to the OpenBao
  process after rotation so it reopens the file handle.
- **Verification:** confirm the audit device is active with
  `docker compose exec openbao bao audit list`.

## Monitoring operations

- Use `bootroot monitoring up --profile lan|public` to start monitoring.
- `bootroot monitoring status` prints running profile status plus
  Grafana URL/admin-password status.
- Use `bootroot monitoring down` to stop/remove monitoring containers.
- To reset Grafana admin password to the initial state, run
  `bootroot monitoring down --reset-grafana-admin-password`.

## Compose operations procedure (recommended)

- Keep workload containers and required sidecars/agents running continuously.
- Set explicit restart policy (`restart: always` or `restart: unless-stopped`).
- Ensure Docker/Compose itself is managed by systemd (or equivalent) so
  services recover after host reboot.
- Basic triage flow:
  `docker compose ps` -> `docker compose logs --tail=200 <service>`
  -> `bootroot verify --service-name <service>`.

## systemd operations procedure (supported)

- Register `bootroot-agent` as a long-running service with
  `Restart=on-failure` and `WantedBy=multi-user.target`.
- If OpenBao Agent is systemd-managed, split it per service and define
  dependency ordering such as `After=network-online.target`.
- Run `bootroot-remote bootstrap` once per service at initial setup. A
  *running* agent then keeps itself current: its fast-poll loop refreshes
  its own `secret_id` and re-renders trust from OpenBao KV with no manual
  step. `bootroot-remote apply-secret-id` is only needed to recover an agent
  that was offline past its `secret_id_ttl` (its credential already expired,
  so it cannot self-refresh).
- **Multiple distinct services on one host**: use one `bootroot-agent`
  plus one agent config per service, each with its own `[openbao]`
  credential and its own unique `state_path`. Distinct services cannot
  share one config — the `[openbao]` section holds a single AppRole
  credential and the fast-poll loop logs in once and reads every
  service's KV with that one token, so cross-service reads return `403`
  under per-service AppRole policies. Bootstrap keys the provisioned
  `state_path` basename on the service name so per-service configs may
  share a directory without their fast-poll state files colliding; it
  warns if two sibling configs still resolve to the same `state_path`.
  See `docs/en/remote-bootstrap.md`.
- Triage flow:
  `systemctl status <unit>` -> `journalctl -u <unit> -n 200`
  -> `bootroot verify --service-name <service>`.

## Rotation scheduling

Run `bootroot rotate ...` on a schedule (cron/systemd timer). Keep secrets out
of command history; use environment files or secure stores.
For day-2 automation, use runtime AppRole auth (`--auth-mode approle`) instead
of root token. Root token should be kept for bootstrap/break-glass only.
`bootroot` does not include a built-in persistent root-token store.

Example (cron; a crontab entry must be a single physical line — cron
does not join `\` continuations — and variable assignments may sit on
their own lines):

```cron
OPENBAO_APPROLE_ROLE_ID=...
OPENBAO_APPROLE_SECRET_ID=...
0 3 * * 0 bootroot rotate --auth-mode approle stepca-password --yes
```

Example (systemd timer):

```ini
[Unit]
Description=Rotate step-ca password weekly

[Service]
Type=oneshot
EnvironmentFile=/etc/bootroot/rotate.env
ExecStart=/usr/local/bin/bootroot rotate stepca-password --yes
```

```ini
[Unit]
Description=Weekly step-ca password rotation

[Timer]
OnCalendar=Sun 03:00
Persistent=true

[Install]
WantedBy=timers.target
```

### Scheduling AppRole secret_id rotation

Every AppRole `secret_id` bootroot mints carries a short TTL (default
`24h`), so `secret_id` rotation must be a scheduled job, not a manual
task — otherwise OpenBao Agent logins start failing with `403 invalid
role or secret ID` within one TTL of the last rotation. The cadence
invariant (TTL ≥ 2× rotation interval) and the TTL knobs are documented
in [SecretID TTL and rotation cadence](#secretid-ttl-and-rotation-cadence);
this section provides the worked scheduled job.

The model is **one scheduled job, few invocations**. Services and infra
roles use deliberately separate credentials (`bootroot-runtime-rotate-role`
cannot touch the infra roles, `bootroot-infra-rotate-role` cannot touch
service roles or KV — a privilege-escalation boundary), and a single
`rotate` invocation authenticates exactly once, so the job fires one
invocation per credential surface instead of mixing them:

- **One batch service invocation**: `bootroot rotate approle-secret-id
  --all-services --yes` rotates every service registered in
  `state.json` (both `local-file` and `remote-bootstrap` delivery
  modes) under the runtime-rotate credential. Because it follows the
  registry, services added after the scheduler was written are picked
  up automatically — no per-service unit to keep in sync. It continues
  past per-service failures, prints a per-target summary, and exits
  non-zero if any target failed; an empty registry is a no-op success.
- **Two per-target infra invocations** (`--infra stepca`,
  `--infra responder`) under the infra-rotate credential; see
  [Infra AppRole secret_id rotation](#infra-approle-secret_id-rotation-stepca-responder).
  Do **not** schedule the service batch alone: the infra roles share
  the same TTL, and skipping them stalls the cert-issuance machinery
  behind the sidecars.

With the default `24h` TTL, run the job **every 8–12 hours**. With
per-service `--secret-id-ttl` overrides, the schedule must satisfy the
invariant for the **smallest** TTL among all targets (services and
infra roles alike).

Store each rotate credential's `role_id`/`secret_id` in root-owned
files (mode `0600`), e.g. `/etc/bootroot/runtime-rotate/{role_id,secret_id}`
and `/etc/bootroot/infra-rotate/{role_id,secret_id}`, and pass them via
`--approle-role-id-file`/`--approle-secret-id-file` so the secrets stay
out of unit files, crontabs, and process listings. `bootroot init`
prints both credentials (masked unless `--show-secrets`); on
deployments initialized before `bootroot-infra-rotate-role` existed, a
root-token `--infra` run provisions it and prints the credential (see
the upgrade note in the infra section). File-based auth is also what
keeps the rotate credentials themselves fresh: each successful
invocation re-mints its own `secret_id` and atomically replaces the
`--approle-secret-id-file` file (see
[the self-mint section](#the-rotate-credentials-own-secret_ids-self-mint)),
so the files seeded once at setup never need a routine manual re-mint.

Worked example — systemd timer + oneshot unit
(`bootroot-rotate-secret-ids.service`):

```ini
[Unit]
Description=Rotate bootroot AppRole secret_ids (services + infra)

[Service]
Type=oneshot
ExecStart=/usr/local/bin/bootroot rotate --auth-mode approle \
  --approle-role-id-file /etc/bootroot/runtime-rotate/role_id \
  --approle-secret-id-file /etc/bootroot/runtime-rotate/secret_id \
  approle-secret-id --all-services --yes
ExecStart=/usr/local/bin/bootroot rotate --auth-mode approle \
  --approle-role-id-file /etc/bootroot/infra-rotate/role_id \
  --approle-secret-id-file /etc/bootroot/infra-rotate/secret_id \
  approle-secret-id --infra stepca --yes
ExecStart=/usr/local/bin/bootroot rotate --auth-mode approle \
  --approle-role-id-file /etc/bootroot/infra-rotate/role_id \
  --approle-secret-id-file /etc/bootroot/infra-rotate/secret_id \
  approle-secret-id --infra responder --yes
```

```ini
[Unit]
Description=bootroot AppRole secret_id rotation every 8 hours

[Timer]
OnCalendar=00/8:00
Persistent=true

[Install]
WantedBy=timers.target
```

With `Type=oneshot`, a failing `ExecStart` line stops the remaining
lines and marks the unit failed. Rotation is idempotent (old
`secret_id`s stay valid until their TTL) and the ≥2× TTL buffer absorbs
a single missed run, but alert on unit failures so consecutive misses
cannot ride past the TTL.

Cron equivalent. A crontab entry must be a single physical line (cron
does not join `\` continuations), so put the three invocations in a
small wrapper script — e.g. `/usr/local/sbin/bootroot-rotate-secret-ids`,
root-owned, mode `0700` — and point one cron entry at it. Unlike the
`Type=oneshot` unit, the script continues past a failing invocation
and exits non-zero if any invocation failed:

```bash
#!/bin/sh
set -u
status=0
/usr/local/bin/bootroot rotate --auth-mode approle \
  --approle-role-id-file /etc/bootroot/runtime-rotate/role_id \
  --approle-secret-id-file /etc/bootroot/runtime-rotate/secret_id \
  approle-secret-id --all-services --yes || status=1
/usr/local/bin/bootroot rotate --auth-mode approle \
  --approle-role-id-file /etc/bootroot/infra-rotate/role_id \
  --approle-secret-id-file /etc/bootroot/infra-rotate/secret_id \
  approle-secret-id --infra stepca --yes || status=1
/usr/local/bin/bootroot rotate --auth-mode approle \
  --approle-role-id-file /etc/bootroot/infra-rotate/role_id \
  --approle-secret-id-file /etc/bootroot/infra-rotate/secret_id \
  approle-secret-id --infra responder --yes || status=1
exit "$status"
```

```cron
0 */8 * * * /usr/local/sbin/bootroot-rotate-secret-ids
```

### The rotate credentials' own secret_ids (self-mint)

The scheduled job authenticates with two AppRoles whose `secret_id`s
are subject to the same TTL as everything else. Each rotate policy
grants `update` on its **own** `auth/approle/role/<self>/secret-id`
path (and only that — no cross-mint: neither rotate credential can
reach the other's surface, preserving the privilege-separation
boundary), and every `approle-secret-id` invocation **re-mints the
credential it authenticated with as its final step**, after all
targets of that invocation succeeded, then atomically replaces the
credential file the scheduler reads
([#672](https://github.com/aicers/bootroot/issues/672)). Normal
operation therefore never touches the root token; the root token stays
strictly break-glass.

How the self-mint behaves:

- **Per invocation, mint-own-last.** Each invocation re-mints its own
  credential only after every target succeeded. For runtime-rotate
  (one batch invocation per job) this equals job-level mint-own-last;
  for infra-rotate — consumed by two invocations (`--infra stepca`,
  `--infra responder`) — the credential file is replaced at the end of
  each successful invocation and the next invocation reads the fresh
  file at startup. The extra mint per job is harmless: orphaned
  `secret_id`s expire by TTL.
- **File contract.** The self-mint replaces the file passed via
  `--approle-secret-id-file` — the form the worked scheduler examples
  above already use. When the `secret_id` was supplied inline
  (`--approle-secret-id`) or via `OPENBAO_APPROLE_SECRET_ID`, there is
  no file to replace: the run prints a prominent warning and skips the
  self-mint (the credential then still expires at its TTL). Root-token
  runs perform no self-mint — a root run has no "own credential" to
  extend; re-minting the rotate credentials under root auth is the
  break-glass recovery procedure below.
- **Verified before the swap, never eagerly revoked.** The fresh
  `secret_id` must pass a login verification before the file is
  replaced, and the previous `secret_id` is never revoked (it expires
  by TTL). Multiple `secret_id`s are concurrently valid, so a crash or
  failure at any point self-heals: the next run logs in with the old,
  still-valid credential and re-mints.
- **Bounded uses.** Self-minted rotate `secret_id`s carry
  `num_uses = 6`: 3× the logins enumerated per re-mint cycle (the next
  invocation's base login plus the new credential's verification
  login), leaving headroom for transient-error retries and the
  crash-recovery login. A stolen snapshot of the credential is a
  wasting asset; the legitimate cycle is never starved. Pair this with
  a generous role TTL (`--secret-id-ttl`, up to the `168h` cap) so a
  stalled scheduler has a wide recovery window.

#### CIDR binding (`--rotate-bound-cidrs`)

Optionally bind the rotate credentials to the control-plane host:
`bootroot init --rotate-bound-cidrs <cidr>` binds both rotate
credentials; the root-token infra provisioning run accepts the same
flag for `bootroot-infra-rotate-role`. The binding is recorded in
`state.json` and re-applied to every self-minted `secret_id`.

The value is **operator-supplied, never auto-derived**: the source IP
OpenBao sees for the control-plane host varies by deployment mode —
with the default loopback-published OpenBao port it is typically
`127.0.0.1/32` (Linux) or the Docker bridge gateway (Docker Desktop);
with a non-loopback bind it is the host's LAN address. Verify what
OpenBao actually sees (e.g. the `remote_address` field of a login
entry in the audit log) before binding, because a wrong CIDR locks the
scheduled job out — the self-mint's login verification catches this
(the run fails and keeps the old, working credential file), but the
binding must then be fixed before the TTL runs out: re-run the
root-token infra provisioning with a corrected `--rotate-bound-cidrs`,
or with `--clear-rotate-bound-cidrs` to drop the binding entirely.
When the flag is omitted, no binding is applied (opt-in); a later
provisioning run without the flag keeps whatever binding is recorded
and prints it, so the hardening is never dropped silently.

This is a **host-boundary control, not process isolation**: OpenBao
sees only source IPs, so processes co-located on the control-plane
host are indistinguishable from the rotation job.

#### Audit alerting for rotate-credential mints

The file audit backend is enabled and verified at init, but bootroot
ships no alert pipeline — wire this rule into your own log pipeline.
Alert on `secret_id` mint requests against the two rotate role paths,
i.e. audit entries where `request.path` equals:

- `auth/approle/role/bootroot-runtime-rotate-role/secret-id`
- `auth/approle/role/bootroot-infra-rotate-role/secret-id`

Expect exactly one mint per rotate credential per scheduled run (plus
one extra infra-rotate mint per job under the two-invocation flow, and
operator-driven mints during init/provisioning). Anything outside the
scheduler's cadence or from an unexpected `remote_address` is a signal
worth paging on: it is the exact surface a stolen rotate credential
would use to extend itself.

#### Dead-man monitoring and break-glass recovery

A timer that silently stops firing is the one remaining lockout path,
and its failure mode is pure absence — no run means no failure log.
Every successful `approle-secret-id` invocation therefore records a
timestamp in `state.json` (`last_secret_id_rotation`), and `bootroot
status` prints the last rotation success and **warns when it is older
than half the rotate roles' `secret_id` TTL** (a one-missed-run budget
under the ≥2× cadence invariant; default TTL `24h` → warns past
`12h`). Check `bootroot status` from a monitoring hook, or alert on
the scheduler unit itself.

If the job misses runs beyond the TTL, the rotate credentials expire
and scheduled runs fail with `403 invalid role or secret ID`. Recover
with the **break-glass root token** (this is the recovery path, not a
routine task):

- infra-rotate: run one root-token `--infra` rotation
  (`bootroot rotate --auth-mode root --root-token-file <path>
  --show-secrets approle-secret-id --infra stepca --yes`) — every
  root-token run mints and prints a fresh infra-rotate credential
  (re-supply `--rotate-bound-cidrs` here only to change the recorded
  binding; omitting it keeps the recorded one, and the run prints the
  binding it re-applied). If the recorded CIDR itself is what locked
  the job out, pass `--clear-rotate-bound-cidrs` to remove it and
  mint unbound.
- runtime-rotate: mint directly against OpenBao with the root token,
  e.g. `docker compose exec -e BAO_TOKEN=<root-token> openbao bao
  write -f auth/approle/role/bootroot-runtime-rotate-role/secret-id`.

After the re-mint, write the fresh values into the credential files
referenced by the scheduled job (e.g. under `/etc/bootroot/`); the
next scheduled run takes over and resumes self-minting. Deployments
whose compliance regime prohibits self-mint grants can keep this
root-token re-mint as the routine procedure instead, on a schedule
shorter than the TTL.

## Rotation and the in-FD pitfall

`bootroot rotate ca-key` and `bootroot rotate force-reissue` delete each
`local-file` service's configured cert/key pair on disk
(`entry.cert_path` and `entry.key_path`, e.g. `/opt/<svc>-mtls/{cert,key}.pem`)
and signal **only** the local `bootroot-agent`. They do **not** signal
the consumer process that is currently serving from those files.

Native daemons (`review`, `aimer`, etc.) that were started before the
rotation keep serving the **previous** leaf certificate via their
already-open file descriptors, even though the file on disk has been
replaced. Meanwhile, the `bootroot-agent` for *other* consumers writes
the new CA bundle (signed by the new PKI generation) to their trust
stores. The result is a silent post-rotation failure: the trusted
bundle and the served leaf belong to different PKI generations, mTLS
handshakes fail with `UNABLE_TO_GET_ISSUER_CERT`, and nothing in the
logs flags it because the two intermediates share an identical
`Subject DN` / `Issuer DN`.

Concretely, the discriminator is **not** the DN — it is the Authority
Key Identifier (AKI) on the leaf versus the Subject Key Identifier
(SKI) on the trusted intermediate. See
[Troubleshooting → Silent rotation FD desync](troubleshooting.md#silent-rotation-fd-desync-issue-614)
for the diagnostic recipe.

### Configure a post-renew hook at registration time

The reliable fix is to declare a post-renew hook when registering the
service. `bootroot-agent` runs the hook on every successful issuance
(see `[profiles.hooks.post_renew]` in the rendered `agent.toml`), so
the consumer process picks up the new cert without operator
intervention.

```bash
# native daemon under systemd
bootroot service add --service-name review \
  --reload-style systemd --reload-target review.service ...

# native daemon launched directly (uses pkill -HUP <process-name>)
bootroot service add --service-name review \
  --reload-style sighup --reload-target review ...

# containerised consumer (issues `docker restart <container>`)
bootroot service add --service-name aice-web-next \
  --reload-style docker-restart --reload-target aice-web-next ...
```

Use `--reload-style none` to explicitly opt out, or the low-level
`--post-renew-command` / `--post-renew-arg` /
`--post-renew-timeout-secs` / `--post-renew-on-failure` flags for
arbitrary commands.

### Retrofitting a hook on an existing service

If the service was registered without `--reload-style`, you no longer
have to remove and re-add it: `bootroot service update` accepts the
same hook flags and rewrites the managed `agent.toml` profile block in
place. This is the canonical one-liner remediation that the CLI hint
on `service add`, `rotate ca-key`, and `rotate force-reissue` points
operators at.

```bash
bootroot service update --service-name review \
  --reload-style sighup --reload-target review
```

For `remote-bootstrap` services, the same `service update` call updates
`state.json`, but the remote agent reads from the bootstrap-rendered
`agent.toml` on the remote host. `service update` prints a warning
when this case applies; the operator must re-emit the bootstrap
artifact via `bootroot service add` and re-run `bootroot-remote
bootstrap --artifact <path>` on the remote host so the new hook lands
in the remote agent config.

Use `--reload-style none` to clear a previously registered hook.

### Completion-time hint

`service add`, `rotate ca-key` (phase 5), and `rotate force-reissue`
print a per-service "Consumer reload/restart required" hint listing
the affected services and their post-renew hook status. Services
without a hook are flagged explicitly and accompanied by the
`service update --reload-style ...` remediation pointer.

For `rotate ca-key` specifically, the hint only lists services whose
cert was actually wiped and re-signaled by this invocation. Services
already issued by the new intermediate (the skip-migrated branch on
resumed or retried rotations) are not included, since this rotation
did not change their on-disk leaf and their consumers do not need to
reload.

`bootroot reinit` wipes the service registry rather than the cert
files — its completion hint reminds the operator to re-register each
consumer with `bootroot service add ... --reload-style ...` so the
post-renew hook is in place before the consumer's next renewal cycle.

## SecretID TTL and rotation cadence

Service AppRole `secret_id` values are reusable runtime credentials. They
survive normal restarts and re-authentication until the next planned
rotation. The `secret_id_ttl` controls how long a SecretID remains valid
after issuance.

**Default TTL model:**

- `24h` is the role-level default set during `bootroot init`. This is the
  security-conservative choice: a shorter lifetime limits exposure when a
  SecretID leaks.
- `48h` (`RECOMMENDED_SECRET_ID_TTL`) is the CLI warning threshold. Values
  above `48h` emit a CLI warning; values above `168h` (7 days) are rejected.
  Use `48h` or longer when surviving missed rotation runs, maintenance
  windows, and restart recovery is more important than minimising the
  exposure window.

**Rotation cadence rule:**

Set the `secret_id_ttl` to at least **2× your rotation interval**. This
buffer ensures that a single missed or delayed rotation run does not expire
credentials and leave services unable to re-authenticate.

| Rotation interval | Minimum recommended TTL |
|-------------------|-------------------------|
| 8h                | 16h                     |
| 12h               | 24h (default)           |
| 24h               | 48h                     |

For example, with a 12-hour rotation schedule, the default `24h` TTL
provides exactly one missed-run buffer. If your automation cannot
guarantee timely execution, increase the TTL or shorten the rotation
interval.

See
[Scheduling AppRole secret_id rotation](#scheduling-approle-secret_id-rotation)
for the worked scheduled job (systemd timer / cron) that implements
this cadence across all services and the infra roles.

**Per-service overrides:**

- `bootroot service add --secret-id-ttl 48h` sets the TTL at issuance time.
- `bootroot service update --secret-id-ttl 48h` changes the stored policy
  (run `bootroot rotate approle-secret-id` afterward to apply).
- Use `--secret-id-ttl inherit` to clear a per-service override and fall
  back to the role-level default.

When `--secret-id-ttl` is omitted during `service add`, the service
inherits the role-level TTL configured during `bootroot init`.

When per-service overrides are in play, the rotation schedule must
satisfy the ≥2× invariant for the **smallest** TTL among all targets —
a single service overridden down to `12h` forces the whole job to run
at least every 6 hours.

## Updating service secret_id policy

Use `bootroot service update` to change per-service `secret_id` policy
without re-running `service add`:

```bash
bootroot service update --service-name edge-proxy --secret-id-ttl 12h
bootroot service update --service-name edge-proxy --no-wrap
```

The command modifies `state.json` only. To apply the updated policy to
the actual `secret_id`, run `rotate approle-secret-id` afterward:

```bash
bootroot rotate approle-secret-id --service-name edge-proxy
```

Use `"inherit"` to clear a per-service override and fall back to the
role-level default configured on the AppRole in OpenBao:

```bash
bootroot service update --service-name edge-proxy --secret-id-ttl inherit
bootroot service update --service-name edge-proxy --secret-id-wrap-ttl inherit
```

## Remote bootstrap and secret_id handoff operations

For targets added with `--delivery-mode remote-bootstrap`, the operational
model is one-shot bootstrap; a running agent is then self-sufficient:

1. Run `bootroot-remote bootstrap` once on the service machine after
   `bootroot service add` to apply the initial configuration bundle,
   including trust settings and the CA bundle, before the first
   `bootroot-agent` run.
2. Thereafter the running `bootroot-agent`'s fast-poll loop keeps itself
   current with no per-host operator action: it refreshes its own
   `secret_id` from `bootroot/services/<service>/secret_id` (surviving past
   `secret_id_ttl`) and re-renders the `agent.toml` `[trust]` pins +
   `ca-bundle.pem` from `bootroot/services/<service>/trust` after a
   `bootroot rotate approle-secret-id` or a CA/trust rotation on the control
   node. `bootroot-remote apply-secret-id` and a re-run of `bootroot-remote
   bootstrap` are recovery paths only — needed when an agent was offline
   past its `secret_id_ttl` and its credential already expired, so it can no
   longer self-refresh.

Minimum environment/config checklist:

- OpenBao endpoint and KV mount
- service name and AppRole file paths (`role_id`, `secret_id`)
- EAB file path (only used when the ACME CA requires EAB; bootroot skips
  this step when no EAB credentials are in OpenBao KV) and `agent.toml` path
- profile identity/path fields (hostname, instance_id, cert/key paths)
- CA bundle output path for the managed step-ca trust bundle

Security notes:

- secret directories `0700`, secret files `0600`
- limit service account access to service-specific paths only
- treat `bootroot init --summary-json` output as sensitive because it may
  include `root_token`
- when wrapping is enabled (the default), `bootstrap.json` contains a
  `wrap_token` and must be treated as a sensitive credential file with
  the same handling as `secret_id`

### Idempotent service add rerun

Re-running `bootroot service add` on an existing `remote-bootstrap`
service with the same arguments is idempotent. When wrapping is enabled
(the default), the rerun issues a fresh `secret_id` with wrapping and
regenerates the bootstrap artifact with a new `wrap_token`. The operator
must ship the updated `bootstrap.json` to the remote host and re-run
`bootroot-remote bootstrap`.

If the arguments differ only in policy fields (`--secret-id-ttl`,
`--secret-id-wrap-ttl`, `--no-wrap`), the command rejects the request
and directs the operator to `bootroot service update` instead.

### OpenBao Agent rotation propagation

For `local-file` services, `bootroot rotate approle-secret-id` writes
the new `secret_id` atomically to disk and reloads the per-service
OpenBao Agent. For daemon-mode deployments the agent receives a `SIGHUP`
and re-reads the credential without restarting. For Docker deployments
the agent container is restarted (`docker restart`).

The active rotate signal path requires the **sidecar** model — that
is, the OpenBao Agent running as a `bootroot-openbao-agent-<service>`
container started by `bootroot service openbao-sidecar start`. When the
operator runs the OpenBao Agent as a host daemon instead, `rotate`
falls back to the passive path: the agent re-reads `secret_id` on
its next `static_secret_render_interval` poll (default 30 seconds),
so propagation latency increases accordingly. See
[CLI > bootroot service openbao-sidecar start](cli.md#bootroot-service-openbao-sidecar-start)
for the sidecar vs. host-daemon trade-off.

For `remote-bootstrap` services, the rotated `secret_id` is written to
the per-service KV path (`bootroot/services/<service>/secret_id`). A
*running* remote `bootroot-agent` needs no operator action: its fast-poll
loop reads that path with its still-valid credential, writes the rotated
`secret_id` atomically to the agent's local file, and re-authenticates via
AppRole on its next re-login — so the loop survives past `secret_id_ttl`
without any manual step. The same loop reads
`bootroot/services/<service>/trust` and re-renders the `agent.toml`
`[trust]` pins + `ca-bundle.pem`, so a CA/trust rotation propagates the
same way.

`bootroot-remote apply-secret-id` is the **recovery** path, not the steady
state: it delivers a fresh `secret_id` to an agent that was offline past
its `secret_id_ttl` (whose credential already expired, so it cannot
self-refresh):

```bash
bootroot-remote apply-secret-id --openbao-url https://<ip>:8200 \
  --service-name <svc> --role-id-path <dir>/role_id \
  --secret-id-path <dir>/secret_id --ca-bundle-path <dir>/ca-bundle.pem
```

When OpenBao is served over HTTPS with a private CA — the required
posture for any non-loopback `--openbao-bind` — pass `--ca-bundle-path`
pointing at the same CA file `bootroot-remote bootstrap` wrote (the
agent's `[openbao].ca_bundle_path`); it anchors TLS to that private CA.
Omit it only when `--openbao-url` is `http://`.

Note: `bootroot-agent` does not depend on a token file maintained by a
separate OpenBao Agent in the `remote-bootstrap` flow. It performs the
AppRole login directly from its fast-poll loop, and the OpenBao Agent
sidecar artifacts are no longer generated for `remote-bootstrap` services.

### Wrap token expiry recovery

When wrapping is enabled, the `wrap_token` embedded in `bootstrap.json`
has a limited TTL (default 30 minutes). If the operator does not run
`bootroot-remote bootstrap` before the token expires, the unwrap call
fails with an **expired** error.

Recovery procedure:

1. Re-run `bootroot service add` with the same arguments on the control
   node. Because the service already exists, this is an idempotent rerun
   that issues a fresh `wrap_token`.
2. Ship the updated `bootstrap.json` to the remote host.
3. Run `bootroot-remote bootstrap --artifact <path>` on the remote host.

If the unwrap call fails because the token was **already unwrapped**
(consumed by an unauthorized party), `bootroot-remote` flags the event
as a potential security incident. In this case, rotate the `secret_id`
immediately and investigate the unauthorized access.

## Infra AppRole secret_id rotation (stepca, responder)

The infra AppRoles bootroot creates at init (`bootroot-stepca-role`,
`bootroot-responder-role`) are consumed by the long-running OpenBao
Agent sidecars (`openbao-agent-stepca`, `openbao-agent-responder`) and
share the same `secret_id` TTL as services, so their `secret_id`s must
be rotated on a cadence too — otherwise the sidecars eventually fail
OpenBao login with `403 invalid role or secret ID` and the
cert-issuance machinery behind them stalls. Schedule these two
invocations in the same job as the service batch — see
[Scheduling AppRole secret_id rotation](#scheduling-approle-secret_id-rotation).

Rotate them with the `--infra` selector:

```bash
bootroot rotate \
  --auth-mode approle \
  --approle-role-id "$INFRA_ROTATE_ROLE_ID" \
  --approle-secret-id "$INFRA_ROTATE_SECRET_ID" \
  approle-secret-id --infra stepca
bootroot rotate \
  --auth-mode approle \
  --approle-role-id "$INFRA_ROTATE_ROLE_ID" \
  --approle-secret-id "$INFRA_ROTATE_SECRET_ID" \
  approle-secret-id --infra responder
```

Infra targets require the dedicated `bootroot-infra-rotate-role`
credential (created at `bootroot init` alongside the other roles). The
general `bootroot-runtime-rotate-role` credential is intentionally
denied on the infra role paths: the infra roles read CA core secrets,
so a credential able to mint their `secret_id`s could escalate to those
secrets. Conversely, the infra-rotate credential can only mint the two
infra `secret_id`s (plus read their `role_id`s) and has no KV access.

The command writes the new `secret_id` atomically (mode `0600`) to
`<secrets_dir>/openbao/<stepca|responder>/secret_id`, restarts the
matching sidecar container so it re-authenticates, and verifies the
fresh credential with an AppRole login before reporting success.

**Upgrade note for deployments initialized before this role existed:**
`bootroot-infra-rotate-role` and its policy are missing on such stacks,
and the command does not silently assume they exist. Provision them by
running an `--infra` rotation with the root token:

```bash
bootroot rotate \
  --auth-mode root --root-token-file <path> --show-secrets \
  approle-secret-id --infra stepca
```

This creates the policy and role, records them in `state.json`, prints
the new role's `role_id`/`secret_id` (masked without `--show-secrets`),
and performs the requested rotation. Store the printed credential and
use it for subsequent `--infra` rotations.

The provisioning is idempotent: every root-token `--infra` run rewrites
the policy, reapplies the role configuration, backfills missing
`state.json` entries, and mints a fresh operator `secret_id`. If an
earlier attempt failed partway, or the printed credential was lost
before it could be stored, simply re-run the command with the root
token — the fresh credential replaces the lost one (previously issued
`secret_id`s stay valid until their TTL).

## OpenBao restart/recovery checklist

- If OpenBao is `sealed`, unseal it first with unseal keys.
- After unseal, provide runtime auth for operational commands:
  - day-2 `service add`/`rotate`: prefer AppRole (`--auth-mode approle`)
  - bootstrap/break-glass admin tasks: root token (`--auth-mode root`)
- Keep unseal and runtime-auth steps separate in runbooks: unseal completion
  does not satisfy OpenBao auth requirements by itself.

## CA bundle (trust) operations

This section covers how to operate two trust settings together:
`trust.ca_bundle_path` and `trust.trusted_ca_sha256`.

- When `trust.ca_bundle_path` and `trust.trusted_ca_sha256` are configured,
  bootroot-agent splits the ACME issuance response into leaf + chain.
  The leaf cert/key are stored in service paths, and the chain
  (intermediate/root) is written to `trust.ca_bundle_path`.
- If `trust.trusted_ca_sha256` is set, bundle write is allowed only when the
  chain fingerprint check passes. A mismatch fails issuance.
- If the response has no chain, the CA bundle is not updated and a warning
  is logged.
- bootroot-agent normally verifies the ACME server (step-ca) TLS
  certificate. If trust settings are configured, it uses the managed CA
  bundle and pins; otherwise it uses the system CA store.
- CLI override: `bootroot-agent --insecure` disables verification only for
  that run.
- In the managed onboarding flow, trust is prepared before the first
  `bootroot-agent` run:
  - `local-file`: `bootroot service add` writes trust settings and
    `ca-bundle.pem` locally, and the per-service OpenBao Agent keeps them
    synchronized.
  - `remote-bootstrap`: `bootroot service add` writes trust state to
    OpenBao, and `bootroot-remote bootstrap` applies the trust config and
    CA bundle on the service machine.

Permissions/ownership:

- The **service consuming** the CA bundle must be able to read the file.
- The simplest setup is running bootroot-agent and the service as the **same
  user or group**.

## Trust rotation

After renewing or replacing CA certificates, run `bootroot rotate trust-sync`
to propagate the updated fingerprints and bundle PEM:

```bash
bootroot rotate trust-sync --yes
```

This command:

1. Computes SHA-256 fingerprints for root and intermediate CA certs under
   `secrets/certs/`.
2. Writes the fingerprints and concatenated PEM bundle to OpenBao
   (`bootroot/ca`).
3. For each remote service, writes the trust payload to
   `bootroot/services/<name>/trust`.
4. For each local service, updates the `[trust]` section in the agent config
   and writes `ca-bundle.pem` to disk.

After `trust-sync`:

- `local-file`: the local service host already has the updated trust config
  and bundle on disk.
- `remote-bootstrap`: no per-host action is needed. A running
  `bootroot-agent`'s fast-poll loop reads the updated
  `bootroot/services/<name>/trust` payload, re-renders the `agent.toml`
  `[trust]` pins, and rewrites `ca-bundle.pem` within roughly one fast-poll
  interval. Re-running `bootroot-remote bootstrap` is only a recovery path
  for an agent that was offline past its `secret_id_ttl` and can no longer
  self-refresh.

## Force reissue

To delete a service's certificate and key and trigger bootroot-agent to
reissue:

```bash
bootroot rotate force-reissue --service-name edge-proxy --yes
```

For local services (daemon/docker), the command signals bootroot-agent after
deleting the files. For remote services, it prints a hint to run
`bootroot-remote bootstrap` on the service host.

## Migrating existing docker-deploy services to a long-running sidecar

Before the fix for issue #552, `bootroot service add --deploy-type docker`
printed a sidecar snippet that ran bootroot-agent as a one-shot container
(`docker run --rm ... bootroot-agent --config /app/agent.toml --oneshot`).
Such containers exited immediately after the initial issuance. For those
installs, `bootroot rotate ca-key` Phase 5 cannot signal renewal because
there is no container to `docker restart`, and the rotation fails with
`No such container: <container_name>`.

Recreate the sidecar as a long-running daemon, keeping the same
`--container-name` recorded in `state.json`:

```bash
# Remove the old one-shot sidecar if anything is still lingering.
docker rm -f <container_name> 2>/dev/null || true

# Print the current recommended snippet for an existing registration
# without modifying state.
bootroot service add --print-only \
  --deploy-type docker \
  --service-name <service> \
  --container-name <container_name> \
  ... other flags as originally registered ...
```

Run the printed `docker run -d --restart unless-stopped ...` command. The
container will stay `Up` after startup and across host reboots, so
`docker restart <container_name>` (issued by Phase 5 of
`bootroot rotate ca-key`) becomes a meaningful signal-renewal action.

If you try to rotate first, Phase 5 now fails fast with a dedicated error
that names the missing container and points at this procedure instead of
the generic `exit status: 1` from the old code path.
