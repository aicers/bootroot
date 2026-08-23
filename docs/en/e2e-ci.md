<!-- markdownlint-configure-file {
  "MD013": { "tables": false, "code_blocks": false }
} -->

# CI & E2E

This page explains bootroot CI/E2E validation structure, scenario execution
flows, local preflight steps, and failure check criteria.

## CI workflow layout

PR-critical CI (`.github/workflows/ci.yml`) runs:

- `test-core`: unit/integration smoke path
- `test-docker-e2e-matrix`: Docker E2E test set for end-to-end flow +
  rotation/recovery (11 scenarios run in parallel via matrix strategy)

Extended E2E (`.github/workflows/e2e-extended.yml`) runs separately:

- `workflow_dispatch` (manual trigger)
- scheduled trigger at `23:30 KST` (UTC cron), gated by same-day `main` commit
  activity (KST)

The extended workflow is for heavier resilience/stress testing and is kept
outside the PR-critical path.

## E2E terms and scenario axes

Term definitions:

- `control node`: machine that runs `bootroot`, hosts step-ca and OpenBao,
  and handles infra initialization plus service state recording
- `remote node`: machine that runs `bootroot-remote` and applies local
  file/config updates for the service

E2E scenarios are defined by combining two independent axes:

1. delivery mode (`bootroot service add --delivery-mode`)
2. host name mapping mode (E2E script run mode)

Delivery mode (`--delivery-mode`):

- `local-file`: a `--delivery-mode` option. Used when the service is added on
  the same machine where step-ca/OpenBao/responder run.
- `remote-bootstrap`: a `--delivery-mode` option. Used when the service is
  added on a different machine; it combines control-node `bootroot` with
  service-node `bootroot-remote bootstrap`.

Host name mapping mode (E2E run mode):

- `no-hosts`: an E2E script mode name. It does not modify host-machine
  `/etc/hosts`; it connects to step-ca and responder via `localhost`/IP.
- `hosts`: an E2E script mode name. It adds host-machine `/etc/hosts`
  entries for `stepca.internal` and `responder.internal`, then connects by
  those names. In E2E, entries are added during the run and removed in cleanup;
  in production, DNS/hosts must be managed continuously.

Common behavior: both mapping modes add service FQDN -> responder IP mappings
in the step-ca container `/etc/hosts` so SAN targets are reachable.

Operational note: host-entry add/remove behavior in E2E is for test
convenience. In production, maintain DNS/hosts mappings and always-on runtime
state for services/agents continuously.

## Docker E2E test scope

PR-critical Docker test set validates:

- local-delivery E2E scenario (`no-hosts`)
- local-delivery E2E scenario (`hosts`)
- remote-delivery E2E scenario (`no-hosts`)
- remote-delivery E2E scenario (`hosts`)
- rotation/recovery matrix (`secret_id,eab,responder_hmac,trust_sync`)
- reinit recovery
- step-ca certificate SANs and the Prometheus metrics listener
- OpenBao TLS transition with no compose delta
- OpenBao TLS re-issuance after `secrets/` is re-owned
- two co-located instances stay independent (install, containers, volumes,
  published ports and HTTP-01 responder DNS aliases)
- the registrar's mint and deregister verbs against a live OpenBao (durable
  bindings, the KV v2 compare-and-set claim, re-mint, wrong-host refusal, the
  absent-binding sweep and both concurrency properties)

Primary scripts:

- `scripts/impl/run-local-lifecycle.sh`
- `scripts/impl/run-remote-lifecycle.sh`
- `scripts/impl/run-rotation-recovery.sh`
- `scripts/impl/run-reinit-recovery.sh`
- `scripts/impl/run-stepca-san.sh`
- `scripts/impl/run-openbao-tls-no-delta.sh`
- `scripts/impl/run-openbao-tls-reown.sh`
- `scripts/impl/run-two-instance-isolation.sh`
- `scripts/impl/run-registrar-verbs-e2e.sh`
- `scripts/impl/run-registrar-internal-e2e.sh`
- `scripts/impl/run-registrar-internal-init-e2e.sh`

Three of those scripts are handed no project name at all, and derive their
own instead. `run-two-instance-isolation.sh` installs two instances into two
compose directories that share a basename and must resolve each instance's
Compose project from that instance's own `.env`, so a caller-supplied
`COMPOSE_PROJECT_NAME` would collapse both into one. The two lifecycle
scripts derive one identity per run for the reason the next section gives.
All three pick run-scoped `--instance-name` values and free host ports
themselves, and every teardown and leftover check is scoped to those exact
names — they are safe to run on a host that already has a default `bootroot`
install.

The two registrar scenarios are outside that discussion entirely: each stands a
single OpenBao container up on a free loopback port and needs no compose
project, no secrets wiring and none of the bootroot binaries.
`run-registrar-verbs-e2e.sh` is the gate for the `#[ignore]`d
`registrar::verbs::tests` library tests, and `run-registrar-internal-e2e.sh`
for the `#[ignore]`d `registrar::internal::tests::live` ones. Both pass the
container's connection details in on the child process's environment.

The internal-credential scenario differs in one respect: its container serves
TLS. `auth/cert` authenticates a *client certificate*, so there has to be a
handshake to present one in. The container generates its own server
certificate into a mounted directory (`-dev-tls`), which keeps the two trust
anchors as separate as they are in a deployment — that certificate's CA
verifies the server, and a CA each test mints is what the `auth/cert` entry
trusts for clients. Those tests assert what a mock cannot: that the SAN
allowlist really refuses the deployment's other registrar names, that
`token_no_default_policy` really keeps `default` off the minted token, and
that the policy body means to the real ACL engine what it looks like it means.

`run-registrar-internal-init-e2e.sh` is the provisioning half, and needs a whole
deployment rather than one container: `bootroot init` on an endpoint-enabled
loopback host, with the endpoint predicate seeded into `state.json` first
(nothing writes it yet — that belongs to the registrar endpoint work). It
installs under a run-scoped instance name into a temporary directory on four
freshly allocated ports, so it is safe beside a default install — and the moved
ports are the point rather than a concession: on the compose defaults a
hard-coded step-ca or responder endpoint is indistinguishable from a derived
one. It asserts the listener transition, the recorded `https://` URL, the
six-file credential set — the five protected members as uid 0, gid 0 and `0600`,
the private CA bundle beside them — the responder alias the internal SAN
resolves through, and a real `auth/cert/login` with the credential `init` just
published — plus that the same login without the client certificate is refused.
It also asserts the other side of that split: the `OpenBao` Agent sidecars'
configuration, `AppRole` pair, templates and the directories holding them still
belong to the owner of `secrets/`, which a root-run `init` must not take over.

`init` runs as root here, through `sudo -n env`, because an endpoint-enabled
`init` publishes those five files `root:root` and refuses to publish any of them
otherwise. **Passwordless sudo is therefore a prerequisite of this scenario**,
checked in its prerequisite block before anything is installed; the reads that
touch the root-owned `0700` internal directory afterwards go through `sudo -n`
one call at a time rather than the whole run being elevated.

It then runs `bootroot infra up` over the deployment it just provisioned and
asserts both ownership checks a second time. `infra up` ends in a recursive
ownership sweep — a one-shot root container that chowns everything below
`secrets/` to that directory's own owner — so it is the routine command that
could undo the root ownership without republishing anything. The bootroot-internal
directory is held back from that sweep, and this is where that holds: the
protected five are still `0:0:600` afterwards, and the sidecar tree is still the
sweep's to repair. `reinit` and the CA and step-ca-password rotations reach the
same sweep.

The endpoint-*disabled* case is not a scenario of its own. Every other arm is an
endpoint-disabled host and drives its whole run over the plaintext `http://` URL
`init` recorded, so a listener that transitioned when it should not have fails
them outright.

### Two lifecycle runs can share a host

`run-local-lifecycle.sh` and `run-remote-lifecycle.sh` derive their whole
identity per run, so a second run — another worktree, another agent session,
a developer checking something by hand — no longer has to wait for the first
to finish. Each run:

- derives an instance name from its artifact directory's basename and its own
  pid, prefixed `e2e-local-` or `e2e-remote-` and cut to the 39 characters
  `infra install` accepts. The pid sits at the tail, which is the part the cut
  keeps, so two runs whose artifact basenames agree still get different names.
- hands that name to `infra install --instance-name` and exports it as
  `BOOTROOT_INSTANCE`, so Compose and the binary name every container
  identically.
- derives its Compose project from the same identifier, separately and under
  its own rule: prefixed `bootroot-e2e-local-` or `bootroot-e2e-remote-`, and
  never truncated, because a project has no DNS label to fit inside. Under a
  CI-length `GITHUB_RUN_ID` it is therefore longer than an instance name is
  allowed to be. The project reaches the binary as an exported
  `COMPOSE_PROJECT_NAME`, which outranks `--instance-name` for the project and
  for nothing else, so every `bootroot` invocation in the run is scoped to the
  same project as the script's own raw `docker compose` calls. The run reads
  that project back off a real container's `com.docker.compose.project` label
  rather than assuming it.
- picks four free `127.0.0.1` ports and passes them to `infra install` as
  `--postgres-host-port`, `--openbao-host-port`, `--stepca-host-port` and
  `--http01-admin-host-port`, so the `.env` the install writes records them for
  every later `bootroot` invocation in the same run.
- exports `BOOTROOT_HTTP01_IMAGE` as `bootroot-http01-responder:<instance>`,
  because the responder is the one image `docker-compose.yml` builds and its
  `image:` is the tag that build is written to. Left at the shipped default,
  two runs write to one tag in turn, and the recreate that applies a run's
  HTTP-01 DNS aliases resolves it again — and starts the other run's build.
  The run removes the tag on the way out; `down` removes containers, never
  images.
- records the instance, the project, the image and the four ports in
  `<artifact dir>/run-identity.json`, so a failed run can be read afterwards.

### `hosts` mode still runs one at a time

The entries a run adds are keyed by fixed host names (`stepca.internal`,
`responder.internal`) and removed by a fixed marker literal, and rewriting
`/etc/hosts` is an unlocked read-modify-write on one file the whole machine
shares — which no spelling of the marker fixes.

That mode used to be serialised by accident, and only by accident: two runs
collided on the Compose project, the container names and the ports long before
either reached that file. Nothing stops them now, and what they would do to
each other there is silent rather than loud — the second run finds the host
names already present and adds nothing, then the first run's cleanup strips
both marker lines while the second is still resolving through them.

So the serialisation is stated instead of inherited. A run in `hosts` mode
takes an exclusive `flock(2)` on `/etc/hosts` itself after its `sudo` checks
and before its first edit, and releases it once its own entries are gone. A
second such run is refused there, before it touches the file, and told which
run holds it where it can tell. A run that was refused, or that failed before
taking the lock, leaves `/etc/hosts` alone on the way out: the cleanup rewrite
drops every line carrying the script's marker, so it cannot tell one run's
entries from another's.

The lock is the resource, and that is the whole of the design. Two properties
carry it, and each covers a failure the other does not.

Ownership is the kernel's and lasts exactly as long as the run does, so there
is no such thing as a stale lock: a run killed with `SIGKILL` releases it at
the instant it stops being able to write `/etc/hosts`, and the next run takes
it with nothing to reclaim and nothing to judge. That is what a lock file whose
ownership is "this path exists" cannot do — recovering one means removing a
file on the strength of a pid read from it a moment earlier, and a second run
arriving at the same stale lock can take it in between, whereupon the recovery
destroys a live run's lock and both runs edit `/etc/hosts` believing they hold
the mutex.

And the inode is one nobody can swap. `flock(2)` locks an inode, and a path
names one only for as long as nobody changes what it names, so a lock file of
the harness's own at a predictable name in a world-writable `/tmp` is a mutex
that can be split: the test that refuses a symbolic link and the `open` that
follows it are two calls, and anyone on the machine can put a link there in
between. One run locks whatever it points at; the next, arriving after the link
has been swapped back for an ordinary file, locks a different inode and takes a
mutex the first believes it holds. `O_NOFOLLOW` narrows that without closing
it, because a file another user owns in a sticky `/tmp` is still theirs to
unlink and create again between two opens. `/etc/hosts` sits in a directory
that is root's, so no unprivileged user can put another inode at that path —
and the run that locks it is the run about to edit it.

Nothing is created, written or re-moded by the lock. The open is read-only,
which is all `flock(2)` needs and all any run has to `/etc/hosts` without
`sudo`, and it is also what makes a missing file a refusal rather than a lock
on something the run has just brought into being. The harnesses' own edits keep
the inode — `cp` over the file and `tee -a` onto it, never a rename — so what a
run locked at the start is what it is still editing at the end. Beyond the
`sudo -n` the mode already requires, the lock asks for nothing.

Who holds it is recorded separately, in the run-marker directory below, and is
advisory: a label naming a live process names the holder, one left by a killed
run reads as nothing, and another user's sits in a directory of their own that
this run cannot read. Then the refusal says so rather than naming the wrong
run. Nothing is read out of that label and acted on.

Every child a run starts inherits the descriptor, so the harnesses close it
(`9>&-`) on the `bootroot-agent` daemons they start: one that outlived a killed
run would otherwise go on holding the lock.

Taking the lock needs `flock(1)`, `perl` or `python3` — whichever the host has,
in that order. Linux runners have all three and macOS has the last two; a host
with none of them is refused in `hosts` mode, naming what to install.

One lock covers both harnesses, because both add the same two host names — a
local run and a remote run overwrite each other exactly as two local runs
would. It is machine-wide rather than per-user like the run-marker directory,
because `/etc/hosts` is.

`no-hosts` runs take no lock and are unaffected. Use that mode when you need
two lifecycle runs at once.

### Collecting the runs that were killed

Unique naming costs the accident that used to clean up after a killed run:
nothing is ever named the same as its leftovers again, so no later run tears
them down on the way in, and they would otherwise accumulate for as long as
the machine runs.

Each run records its liveness explicitly instead. On start it writes
`${TMPDIR:-/tmp}/bootroot-e2e-runs-<uid>/<instance>` holding its own pid and its
Compose project, and on the way out it removes that file — only ever the one
recording its own pid, and only once its own teardown has left nothing
behind. Before doing any work it reads every marker in that
directory, skips the ones whose pid is still alive, and for each dead one
removes that instance's nine container names and its responder image tag,
along with the volumes and networks carrying its project label, then drops the
marker. A marker it could not fully collect survives, so the next run retries
rather than stranding what was left.

A recycled pid can spare a dead run's containers for one further run, which is
acceptable: the next run collects them and nothing is removed wrongly. The
sweep never matches a prefix or a wildcard — `bootroot-*` would reach into a
real default-identity install on the same host — so it can only touch
instances a run recorded.

Every one of those removals is read out of a marker, so what confines the sweep
is which markers it will act on. A marker is honoured only when both of its
halves sit inside one derived namespace: its filename must be an instance under
`e2e-local-` or `e2e-remote-`, and its `project` field a Compose project under
the matching `bootroot-e2e-local-` or `bootroot-e2e-remote-`. Anything else —
a stale marker from an older naming rule, a file made by hand, a half-written
record from something that picked the same path — is reported and left exactly
as it was found, neither swept nor deleted. That is what makes the default
identity unreachable by construction rather than by the absence of a marker
naming it: `bootroot` cannot be spelled with any of those prefixes, so a file
called `bootroot` recording `project=bootroot` and a dead pid cannot aim the
sweep at a real install's containers, volumes, networks or `:latest` responder
image. The same pairing is enforced where markers are written, so a run whose
identity fell outside the table is stopped before it installs anything no later
sweep would collect.

The directory is per-user and created `0700`, and a run refuses one it does not
own: a marker's filename is an instance the sweep tears down by exact container
name, so anyone who could write there would be choosing what a later run
destroys. The namespace check stands behind that rather than beside it —
ownership establishes that no other user wrote a marker, not that this harness
did. A symbolic link at that path is refused outright rather than
followed, because ownership cannot see one — every shell test but `-L` reports
on the link's target, so a link aimed at a directory this user happens to own
would pass the ownership check and hand the sweep files that were never
markers. The uid in the path is what gives Linux the separation `$TMPDIR`
already gives macOS, so two users can run the harness on one host instead of
the second being refused.

It is also where a `hosts`-mode run records that it holds the lock, under a
name no instance can carry (`hosts-lock-holder.label`), so the sweep never
reads it as a run. That record lives here rather than at a machine-wide path
of its own for the reason the lock no longer does: a predictable name in a
world-writable directory is one a run's write would truncate wherever
somebody else's link pointed.

`scripts/validate-e2e-run-scope.sh` covers the derivation, the markers, the
sweep and the `hosts` lock without Docker, and runs in the `check` CI job. It
needs nothing that job does not already have, and redirects its marker
directory and its `hosts` lock into a temporary directory of its own, so it
touches neither the runner's `/etc/hosts` nor anything another job holds.
None of what it asserts is visible to the E2E matrix: each runner gets one
run on an empty host, so a derivation that started colliding or a sweep that
began reaching past its own runs would leave every arm green.

### Leftover containers fail a run before it starts

The remaining harnesses install at the default identity, so their containers
are named after whatever the compose directory's `.env` records — `bootroot-*`
unless an install recorded something else. The two lifecycle scripts install
at the derived instance above and hand that name to the same check. Either
way the names are global to the Docker daemon, so two runs sharing a name, or
one such run and a real install, cannot share a host: they collide on
`container_name` at `up`.

Each of them therefore asserts, before doing any work, that none of the nine
container names bootroot creates (`-openbao`, `-postgres`, `-ca`, `-http01`,
`-prometheus`, `-grafana`, `-grafana-public`, `-openbao-agent-stepca`,
`-openbao-agent-responder`) exists at the resolved instance name. A run
killed with `SIGKILL` never reaches its own cleanup, and the containers it
leaves behind carry a Compose project label no later run knows to ask about,
which is why the check is by name rather than by label. The failure names
what it found and the `docker rm -f` line that removes it; establish whether
it is a killed run's leftovers or an install you need before running that
line.

The assertion comes first, ahead of the start-of-run teardown rather than
after it. That teardown is a `down -v --remove-orphans` at a Compose project
a real install on the same host holds too, so running it first would delete
that install, volumes and all, and leave the assertion reading a daemon it
had just cleaned. Nothing can tell such an install apart from a killed run's
leftovers — that is what the message asks you to establish — so the harness
removes neither. Only once the assertion has passed does the harness take
the stack over: the teardown that follows it is there for the volumes,
networks and orphans the assertion does not look at, and the EXIT trap
removes nothing before that point, so a run that stopped at the assertion
leaves the host exactly as it found it.

The same check runs again in `cleanup`, where a leftover fails the run — a
harness that leaves its own garbage behind is broken — without replacing the
status of a run that had already failed for its own reason. Teardown output
goes to the run log (`<artifact dir>/run.log`, or `runner.log` where the
harness has no `run.log`), so a teardown that removed nothing can be told
from one that removed everything.

A daemon that cannot be asked is not a clean host. Both checks list what the
daemon holds — the container names for the default-identity harnesses, the
`com.docker.compose.project` labels for the run-scoped one — and a listing
that fails fails the check, with Docker's own error alongside it. Reading a
failed query as "nothing found" would pass the start-of-run assertion, slip
past the start-of-run teardown's deliberately non-fatal `|| true`, and
resurface as the confusing mid-run failure the assertion exists to replace.

`scripts/validate-e2e-leftover-check.sh` covers all of it without Docker, and
runs in the `check` CI job.

Extended workflow validates:

- baseline scale/contention behavior
- repeated failure/recovery behavior
- rotation scheduling parity (`systemd-timer`, `cron`)
- CA key rotation failure/recovery (5 failure injection scenarios)
- infra lifecycle (full local-delivery round-trip)

Primary script:

- `scripts/impl/run-extended-suite.sh`

## Scenario details and execution steps

This section repeats key context from other manual pages on purpose.
Use this page alone as an operational guide for CI/E2E understanding and
reproduction.

### 1) local-delivery E2E scenario (`no-hosts`)

Configuration:

- Single machine baseline used by `scripts/impl/run-local-lifecycle.sh`
- `openbao`, `postgres`, `step-ca`, `bootroot-http01` run in Docker Compose
- Services are added with `--delivery-mode local-file`
- Service set in this scenario (2 services): `edge-proxy`, `web-app`
- Resolution mode is `no-hosts` (no `/etc/hosts` mutation)

Purpose:

- Validate the default same-machine onboarding path end-to-end
- Validate `bootroot init` -> `service add` -> `verify` flow
- Validate rotation + reissue behavior in the same-machine path

Execution steps:

1. `infra-up`: bring up Compose services and wait for readiness
2. `init`: run `bootroot init --summary-json` and read runtime AppRole
   credentials from JSON
3. `service-add`: add both services in `local-file` mode
4. `verify-initial`: issue/verify initial certs and snapshot fingerprints
5. `rotate-infra-secret-id`: rotate the stepca/responder infra AppRole
   secret_ids with the dedicated `infra_rotate` credential, then assert
   the `runtime_rotate` credential is denied on the infra role paths
6. `rotate-openbao-recovery`: manually rotate OpenBao root token
7. `bootstrap-after-openbao-recovery`: re-run remote bootstrap and verify
   AppRole-based access continuity
8. `rotate-responder-hmac`: run rotation and force reissue
9. `verify-after-responder-hmac`: verify certs again and confirm fingerprint changes
10. `cleanup`: capture logs/artifacts and tear down Compose

Actual commands (script excerpt):

```bash
# 1) infra-install (generates .env, starts containers)
bootroot infra install --compose-file "$COMPOSE_FILE"

# 2) init
# DB credentials are read from .env created by infra install.
# POSTGRES_HOST and POSTGRES_PORT are set by the script so that
# build_admin_dsn_from_env() connects via the host-mapped port.
# Every prompt is answered by its own flag and stdin is closed, so the
# run depends on no piped answer sequence and on no leftover file:
# an overwrite flag whose file is absent is a silent no-op. init fails
# on EOF rather than answering an unanswered prompt itself.
BOOTROOT_LANG=en bootroot init \
  --compose-file "$COMPOSE_FILE" \
  --secrets-dir "$SECRETS_DIR" \
  --summary-json "$INIT_SUMMARY_JSON" \
  --enable auto-generate,show-secrets,db-provision \
  --no-eab \
  --save-unseal-keys \
  --overwrite-password \
  --overwrite-ca-json \
  --overwrite-state \
  --confirm-db-provision \
  --db-user "step" \
  --db-name "stepca" \
  --responder-url "$RESPONDER_URL" </dev/null

# 3) service-add
# Each distinct local service gets its own agent config (one daemon
# and one [openbao] AppRole identity per service).
bootroot service add --registration-id edge-proxy --service-name edge-proxy \
  --delivery-mode local-file --agent-config "$EDGE_AGENT_CONFIG"
bootroot service add --registration-id web-app --service-name web-app \
  --delivery-mode local-file --agent-config "$WEB_AGENT_CONFIG"

# 4) verify-initial / 9) verify-after-responder-hmac
bootroot verify --registration-id edge-proxy --agent-config "$EDGE_AGENT_CONFIG"
bootroot verify --registration-id web-app --agent-config "$WEB_AGENT_CONFIG"

# 5) rotate-infra-secret-id
# from init summary
#   infra_rotate: role_id/secret_id
bootroot rotate --compose-file "$COMPOSE_FILE" \
  --openbao-url "http://127.0.0.1:8200" \
  --auth-mode approle \
  --approle-role-id "$INFRA_ROTATE_ROLE_ID" \
  --approle-secret-id "$INFRA_ROTATE_SECRET_ID" \
  --yes approle-secret-id --infra stepca   # then --infra responder
# negative check: the same command with the runtime_rotate credential
# must fail with permission denied

# 6) rotate-openbao-recovery (manual, explicit operator action)
bootroot rotate --compose-file "$COMPOSE_FILE" \
  --openbao-url "http://127.0.0.1:8200" \
  --root-token "$INIT_ROOT_TOKEN" \
  --yes \
  openbao-recovery \
  --rotate-root-token \
  --output "$OPENBAO_RECOVERY_OUTPUT_FILE"

# 8) rotate-responder-hmac
# from init summary
#   runtime_service_add: role_id/secret_id
#   runtime_rotate: role_id/secret_id
bootroot rotate --compose-file "$COMPOSE_FILE" \
  --openbao-url "http://127.0.0.1:8200" \
  --auth-mode approle \
  --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
  --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
  --yes responder-hmac
```

### 2) local-delivery E2E scenario (`hosts`)

Configuration:

- Same script and same-machine topology as above
- Same service set as `no-hosts`: `edge-proxy`, `web-app`
- Resolution mode is `hosts`
- Script writes temporary `stepca.internal` / `responder.internal` host entries
  (requires `sudo -n`)
- One `hosts`-mode run at a time, across both lifecycle scripts: a second one
  is refused at the `flock(2)` the first holds on `/etc/hosts`

Purpose:

- Validate hostname-based resolution path used by `hosts`
- Catch breakage tied to `/etc/hosts`-driven name resolution

Execution steps:

1. Take the machine-wide `hosts` lock, then add host entries for
   `stepca.internal` and `responder.internal`
2. Run the same end-to-end flow phases as `no-hosts`
3. Remove temporary host entries during cleanup

Actual commands (script excerpt):

```bash
# run in hosts mode
RESOLUTION_MODE=hosts ./scripts/impl/run-local-lifecycle.sh

# internal host-entry add/remove sequence
echo "127.0.0.1 stepca.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
echo "127.0.0.1 responder.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
sudo -n awk -v marker="$HOSTS_MARKER" 'index($0, marker) == 0 { print }' \
  /etc/hosts >"$tmp_file"
sudo -n cp "$tmp_file" /etc/hosts
```

### 3) remote-delivery E2E scenario (`no-hosts`)

Configuration:

- Two workspaces in one run: `control node` (step-ca machine role),
  `remote node` (service machine role)
- Services are added with `--delivery-mode remote-bootstrap`
- Service set in this scenario (2 services): `edge-proxy`, `web-app`
- Remote bootstrap apply is executed by `bootroot-remote bootstrap`
- Resolution mode is `no-hosts`

Purpose:

- Validate remote-bootstrap onboarding and one-shot bootstrap apply mode
- Validate bootstrap-driven delivery for `eab` and `responder_hmac`
  (the `eab` item covers the operator-provided pass-through: the harness
  writes EAB credentials to OpenBao KV directly and verifies that
  `bootroot-remote bootstrap` applies them); `trust_sync` and `secret_id`
  updates now propagate via the running agent's fast-poll self-heal instead
- Validate `secret_id` self-heal: after `rotate approle-secret-id` on the
  control node, the running `bootroot-agent` fast-poll loop refreshes its
  own on-disk `secret_id` and keeps authenticating with no manual
  `apply-secret-id` / re-bootstrap on the remote
- Validate trust self-heal: after a trust update in KV, the running agent
  re-renders the `[trust]` pins + `ca-bundle.pem` via fast-poll and keeps
  renewing, with no manual re-bootstrap
- Validate `responder_hmac` bootstrap re-apply and the remote
  rotation/recovery sequence

Execution steps:

1. `infra-up`, `init` on control node, then parse runtime AppRole credentials
   from summary JSON
2. `service-add` in `remote-bootstrap` mode for both services
3. Copy bootstrap materials (`role_id`, `secret_id`) to remote node
4. `bootstrap-initial`: run `bootroot-remote bootstrap` on remote node
   for each service
5. `verify-initial`: issue/verify certificates on remote node
6. Self-heal cycle (no manual re-bootstrap): `rotate-secret-id` and
   `rotate-trust-sync` on the control node, then `selfheal-<service>`
   asserts each running agent's fast-poll loop refreshes its own
   `secret_id` and re-renders trust, and drives a force-reissue round-trip
   (`before-selfheal` -> `after-selfheal`) on the refreshed credential
7. `responder_hmac` still delivers via bootstrap:
   `rotate-responder-hmac` -> `bootstrap-after-responder-hmac` ->
   `verify-after-responder-hmac`
8. Confirm certificate fingerprint changes between each snapshot

Actual commands (script excerpt):

```bash
# control node: infra-install / init / service-add
bootroot infra install --compose-file "$COMPOSE_FILE"
BOOTROOT_LANG=en bootroot init \
  --compose-file "$COMPOSE_FILE" --summary-json "$INIT_SUMMARY_JSON" \
  --enable auto-generate,show-secrets,db-provision \
  --no-eab --save-unseal-keys \
  --overwrite-password --overwrite-ca-json --overwrite-state \
  --confirm-db-provision \
  --db-user "step" --db-name "stepca" \
  --responder-url "$RESPONDER_URL" </dev/null
bootroot service add --registration-id edge-proxy --service-name edge-proxy \
  --delivery-mode remote-bootstrap --agent-config "$REMOTE_AGENT_CONFIG_PATH"
bootroot service add --registration-id web-app --service-name web-app \
  --delivery-mode remote-bootstrap --agent-config "$REMOTE_AGENT_CONFIG_PATH_2"

# remote node: bootstrap (per service)
bootroot-remote bootstrap --openbao-url "http://127.0.0.1:8200" \
  --registration-id "$SERVICE_NAME" \
  --service-name "$SERVICE_NAME" \
  --role-id-path "$role_id_path" --secret-id-path "$secret_id_path" \
  --agent-config-path "$REMOTE_AGENT_CONFIG_PATH" \
  --output json

# control node: rotate secret_id + publish the trust update to KV
bootroot rotate --yes approle-secret-id --registration-id edge-proxy
bootroot rotate --yes approle-secret-id --registration-id web-app
# remote node: NO manual re-apply. The running bootroot-agent fast-poll
# loop refreshes its own secret_id and re-renders trust; a force-reissue
# --wait round-trip then proves it operates on the fresh credential
# (selfheal-<service> phase).

# responder_hmac still delivers via bootstrap
bootroot rotate --yes responder-hmac
bootroot-remote bootstrap ...  # re-apply responder_hmac for each service
```

### 4) remote-delivery E2E scenario (`hosts`)

Configuration:

- Same control node/remote node model as above
- Same service set as remote `no-hosts`: `edge-proxy`, `web-app`
- Resolution mode is `hosts`
- Temporary `/etc/hosts` entries are added/removed by the script
- One `hosts`-mode run at a time, across both lifecycle scripts: this script
  and `run-local-lifecycle.sh` add the same two host names and share one lock

Purpose:

- Validate the remote-bootstrap end-to-end flow under hosts-based resolution mode
- Catch resolution-specific failures in remote sync and verification phases

Execution steps:

1. Take the machine-wide `hosts` lock, then add host entries for
   `stepca.internal` / `responder.internal`
    - Add `stepca.internal` entry
    - Add `responder.internal` entry
2. Run all remote-delivery E2E scenario phases
3. Remove temporary host entries in cleanup
    - Remove only lines tagged with `HOSTS_MARKER`

Actual commands (script excerpt):

```bash
# run remote lifecycle in hosts mode
RESOLUTION_MODE=hosts ./scripts/impl/run-remote-lifecycle.sh

# internal host-entry add/remove sequence
echo "127.0.0.1 stepca.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
echo "127.0.0.1 responder.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
sudo -n awk -v marker="$HOSTS_MARKER" 'index($0, marker) == 0 { print }' \
  /etc/hosts >"$tmp_file"
sudo -n cp "$tmp_file" /etc/hosts
```

### 5) rotation/recovery matrix

Configuration:

- Script: `scripts/impl/run-rotation-recovery.sh`
- Scenario input defaults to
  `tests/e2e/docker_harness/scenarios/scenario-c-multi-node-uneven.json`

#### Service set in this scenario (3 nodes, 8 services total)

- `node-a`: daemon-c1, daemon-c2, docker-c1
- `node-b`: daemon-c3, docker-c2, docker-c3
- `node-c`: daemon-c4, docker-c4

Each service is validated across all rotation items.

#### Rotation items

- `secret_id,eab,responder_hmac,trust_sync`

Purpose:

- Validate rotation and recovery behavior per item
- Validate targeted failure handling and subsequent recovery
- Validate re-apply after each rotation

> **Note:** This rotation/recovery matrix uses `bootroot-remote bootstrap`
> to re-apply all rotation items uniformly (including `secret_id`), which
> works because the old `secret_id` remains valid during the test window
> and both `bootstrap` and `apply-secret-id` authenticate the same way. In
> production a running `bootroot-agent` self-heals `secret_id` and trust
> through its fast-poll loop with no operator action; `apply-secret-id`
> (and re-bootstrap) is the recovery path for an agent that was offline
> past its `secret_id_ttl` and can no longer self-refresh (see the
> operations guide). The remote-delivery lifecycle scenario above exercises
> that self-heal path directly.

Execution steps (per rotation item):

1. Rotate target item on control node
2. Run `bootroot-remote bootstrap` on each remote node to re-apply
3. Verify certificate issuance still works after rotation
4. Failure cycle: inject one targeted failure and verify recovery
5. Recovery cycle: re-rotate and re-apply, confirm normal operation

Actual commands (script excerpt):

```bash
# scenario entrypoint
./scripts/impl/run-rotation-recovery.sh

# key commands used in rotation/verify loops
bootroot rotate --yes approle-secret-id --registration-id "$service"
bootroot-remote bootstrap --registration-id "$service" --service-name "$service" ...
bootroot verify --registration-id "$service" --agent-config "$agent_config_path"
```

### 6) CA key rotation failure/recovery

Configuration:

- Script: `scripts/impl/run-ca-key-rotation-recovery.sh`
- Single machine baseline with Docker Compose infra
- Service set (3 services): `edge-proxy` (`local-file`),
  `web-app` (`local-file`), `edge-proxy` (`remote-bootstrap`)
- 5 failure injection scenarios run sequentially on the same infra

Purpose:

- Validate that `bootroot rotate ca-key` resumes correctly after
  infrastructure failures at each phase
- Validate that mTLS is never disrupted during CA key rotation
- Validate `rotation-state.json` idempotent phase tracking
- Validate `--skip reissue`, `--force`, `--cleanup` flag behaviors
- Validate `trust-sync` conflict guard during active rotation

#### Scenarios

Scenario 1 — Phase 3 failure (OpenBao unreachable):

1. Stop OpenBao container so Phase 3 (additive trust write) fails
2. Run `rotate ca-key` — expect failure
3. Verify services still work (certs unchanged, step-ca running)
4. Restart OpenBao, re-run rotation — resumes and completes
5. Force-reissue and verify new certificates

Scenario 2 — Phase 4 failure (step-ca removed):

1. Remove step-ca container so Phase 4 (restart) fails
2. Run `rotate ca-key` — Phases 0-3 succeed, Phase 4 fails
3. Verify services still work (transitional trust active)
4. Bring step-ca back, re-run rotation — resumes and completes
5. Force-reissue and verify new certificates

Scenario 3 — Phase 5 partial re-issuance:

1. Run `rotate ca-key --skip reissue` — Phase 6 bails (unmigrated)
2. Force-reissue only one service (edge-proxy)
3. Verify both old-cert (web-app) and new-cert (edge-proxy) work
4. Force-reissue remaining services
5. Re-run rotation with `--force` — completes

Scenario 4 — Phase 6 entry blocked:

1. Run `rotate ca-key --skip reissue` — Phase 6 blocks
2. Verify error output mentions un-migrated service names
3. Re-run with `--force` — Phase 6 completes with warning
4. Force-reissue and verify

Scenario 5 — trust-sync conflict during active rotation:

1. Create active rotation by stopping step-ca mid-rotation
2. Verify `rotation-state.json` exists
3. Run `trust-sync` — expect abort with rotation-in-progress error
4. Recover: bring step-ca back, complete rotation
5. Verify all services

Actual commands (script excerpt):

```bash
# wrapper for rotate ca-key with AppRole auth
bootroot rotate \
  --compose-file "$COMPOSE_FILE" \
  --openbao-url "http://${STEPCA_HOST_IP}:8200" \
  --auth-mode approle \
  --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
  --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
  --yes \
  ca-key --skip reissue --force --cleanup

# failure injection via Docker manipulation
docker compose -f "$COMPOSE_FILE" stop openbao
docker compose -f "$COMPOSE_FILE" rm -sf step-ca
```

### 7) extended workflow cases

Configuration:

- Script: `scripts/impl/run-extended-suite.sh`
- Cases: `scale-contention`, `failure-recovery`, `runner-timer`, `runner-cron`,
  `ca-key-recovery`, `infra-lifecycle`
- Case results are aggregated into `extended-summary.json`
- Service set: inherited from each case's underlying scenario/script and includes
  multi-service cases (for scale/contention and failure/recovery)

Purpose:

- Keep heavier stress/recovery coverage outside PR-critical CI path
- Validate rotation scheduling parity (`systemd-timer` vs `cron`)
- Validate repeatability under higher cycle counts/time windows

Execution steps:

1. Run each case independently and capture per-case `run.log`
2. Mark each case `start/pass/fail` in `phases.log`
3. Aggregate all case results into `extended-summary.json`
4. Fail workflow when any case is `fail`

Actual commands (script excerpt):

```bash
# extended suite entrypoint
./scripts/impl/run-extended-suite.sh

# internal case dispatch
./scripts/impl/run-baseline.sh
./scripts/impl/run-rotation-recovery.sh
RUNNER_MODE=systemd-timer ./scripts/impl/run-harness-smoke.sh
RUNNER_MODE=cron ./scripts/impl/run-harness-smoke.sh
./scripts/impl/run-ca-key-rotation-recovery.sh
./scripts/impl/run-local-lifecycle.sh
```

## Local preflight standard

Before pushing code, run the standard preflight checks, which exclude
extended E2E:

```bash
./scripts/preflight/run-all.sh
```

Or run individual scripts:

| Script | CI job |
| --- | --- |
| `./scripts/preflight/ci/check.sh` | `ci.yml` Quality Check |
| `./scripts/validate-deploy-compose.sh` | `ci.yml` Validate Deploy Compose |
| `./scripts/validate-compose-instance-names.sh` | `ci.yml` Validate Compose Instance Names |
| `./scripts/validate-e2e-openssl-compat.sh` | `ci.yml` Validate E2E OpenSSL Compatibility |
| `./scripts/validate-e2e-leftover-check.sh` | `ci.yml` Validate E2E Leftover Check |
| `./scripts/validate-e2e-run-scope.sh` | `ci.yml` Validate E2E Run Scope |
| `./scripts/preflight/ci/deploy-no-build-smoke.sh` | `ci.yml` Deploy Compose No-Build Smoke |
| `./scripts/preflight/ci/test-core.sh` | `ci.yml` Unit & CLI Smoke |
| `./scripts/preflight/ci/e2e-matrix.sh` | `ci.yml` Docker E2E Matrix |
| `./scripts/preflight/ci/e2e-extended.sh` | `e2e-extended.yml` Run Extended (optional/manual scheduled coverage; `run-all.sh` does not invoke it) |

`deploy-no-build-smoke.sh` is the one entry that is not a mirror: the
`Deploy Compose No-Build Smoke` step runs this same file, so it cannot
drift from what CI does.

Local-only extras (not in any CI workflow):

| Script | Description |
| --- | --- |
| `./scripts/preflight/extra/agent-scenarios.sh` | Agent scenario tests |
| `./scripts/preflight/extra/cli-scenarios.sh` | CLI scenario tests |

When local `sudo -n` is unavailable:

- Run `./scripts/preflight/ci/e2e-matrix.sh --skip-hosts`.
- Reason: `hosts` cases add and restore host-machine `/etc/hosts` during
  the run, and that operation requires non-interactive admin privileges
  (`sudo -n`).
- This no longer makes the whole matrix runnable. The
  `registrar-internal-init` step runs `bootroot init` as root, because an
  endpoint-enabled `init` publishes the five protected credential files
  `root:root` and refuses to publish any of them otherwise, so that step has no
  unprivileged form to skip to. It fails in its prerequisite block, before
  anything is installed, and `scripts/preflight/run-all.sh` fails with it. A
  machine without passwordless sudo cannot run that scenario at all.

Use this only as a local constraint workaround. CI still executes
`hosts` variants.

`--skip-hosts` is also what lets two matrix runs share one host. The matrix
runs its own steps in sequence, so a single run never contends with itself,
but a second run reaching a `hosts` step while the first is inside one is
refused at the lock rather than made to wait. Every other step is run-scoped
and unaffected.

The harnesses also assume three host tools, and each check fails in its
prerequisite block rather than mid-run:

- The bind-host guard in `run-reinit-recovery.sh`, `run-stepca-san.sh`,
  `run-openbao-tls-no-delta.sh` and `run-openbao-tls-reown.sh` lists the
  machine's IPv4 addresses with `ip` (iproute2), falling back to
  `ifconfig`. A host with neither is told exactly that, because no value
  of `OPENBAO_BIND_HOST` / `STEPCA_BIND_HOST` fixes a check that cannot
  enumerate. Both default to `172.17.0.1`, the Docker bridge gateway on
  Linux; elsewhere (Docker Desktop has no such interface) set them to an
  address the host actually holds.
- `run-remote-lifecycle.sh` reads the remote agent's TOML config with
  `tomllib`, so its `python3` must be 3.11 or newer. The prerequisite
  block imports it before any container starts.
- The `openssl` the harness finds on `PATH` must support `x509 -ext`,
  which `run-stepca-san.sh` reads step-ca's `subjectAltName` with. The
  option arrived in OpenSSL 1.1.1, and LibreSSL 3.3.6 — what macOS
  ships as `/usr/bin/openssl` — does not have it. The check probes for
  the option rather than for the implementation's name and names the
  binary it found; the fix is to put a directory holding a capable
  `openssl` first on `PATH`. All six scripts that check for `openssl`
  check this, not only the one that calls `-ext`, because the matrix
  runs every step against one host.

## Init automation input/output rules

Lifecycle scripts consume `bootroot init --summary-json` output for automation.
Do not parse human-readable summary lines for tokens/secrets.
Local CLI scenario runs use the same rule and read runtime AppRole credentials
from `.approles[]` in `--summary-json`.
This is a **test/automation convenience rule**, not a production token custody
policy.

Minimum machine fields used by E2E:

- `.approles[]` entries for:
  - `runtime_service_add` (`role_id`, `secret_id`)
  - `runtime_rotate` (`role_id`, `secret_id`)

How E2E handles OpenBao unseal and runtime auth:

- E2E typically unseals once during `init` and does not unseal again in the
  same run
- Unseal is required again only after OpenBao returns to `sealed` state
  (for example: process/container restart, manual seal, recovery flow)
- runtime AppRole credentials are read from `init-summary.json` (`approles`)
  and passed to `service add`/`rotate` via `--auth-mode approle`
- scripts avoid long-term credential persistence; values stay in per-run shell
  context
- summary JSON contains sensitive fields (including root token and AppRole
  secret_id), so treat the artifact as sensitive in retention workflows

Operational guidance:

- treat init summary JSON as sensitive artifact
- avoid printing raw secrets in logs
- keep secret files/dirs with `0600`/`0700` permissions

## Remote bootstrap verification criteria

This section defines how E2E decides whether remote bootstrap was
actually applied.

Verification flow:

1. `bootroot service add --delivery-mode remote-bootstrap` on the control node
   records desired state.
2. `bootroot-remote bootstrap` on the remote node reads that state and applies
   it to local files/config.
3. E2E verifies the bootstrap summary JSON output shows all items as `applied`.

Per-service verification items:

- `secret_id`
- `eab` (reports `skipped` when the operator has not provisioned EAB
  credentials, which is the default for the bundled OSS step-ca topology)
- `responder_hmac`
- `trust_sync`

Pass/fail rules:

- each required bootstrap item must show `applied`, `unchanged`, or
  `skipped` (EAB only) in the summary output
- after rotation, re-apply must complete successfully (`bootstrap` in the
  rotation/recovery matrix; in production the running agent self-heals
  `secret_id`/trust via fast-poll, with `apply-secret-id` / re-bootstrap as
  the offline-recovery path)
- if any item shows `failed`, the phase fails

## E2E `phases.log` format

E2E scripts write step-progress events to `phases.log`.
The examples below describe the JSON event format in that file.

Lifecycle scripts write:

```json
{"ts":"2026-02-17T04:49:01Z","phase":"infra-up","mode":"no-hosts"}
```

Fields:

- `ts`: UTC timestamp
- `phase`: step identifier
- `mode`: resolution mode (`no-hosts` or `hosts`)

Extended suite writes:

```json
{"ts":"2026-02-17T04:49:01Z","phase":"runner-cron","status":"pass"}
```

Fields:

- `ts`: UTC timestamp
- `phase`: case identifier
- `status`: `start|pass|fail`

## Artifact locations

For general users, this is not required information.  
For users/contributors debugging CI failures directly, it is useful.

Typical PR-critical artifacts:

- `tmp/e2e/ci-local-no-hosts-<run-id>`
- `tmp/e2e/ci-local-hosts-<run-id>`
- `tmp/e2e/ci-remote-no-hosts-<run-id>`
- `tmp/e2e/ci-remote-hosts-<run-id>`
- `tmp/e2e/ci-rotation-<run-id>`

Typical extended artifacts:

- `tmp/e2e/extended-<run-id>` (contains per-case subdirectories including
  `ca-key-recovery/`, `infra-lifecycle/`, etc.)

## Failure check order

When a run fails, inspect in this order:

1. `phases.log` (where it stopped)
2. `run.log` (high-level command flow)
3. `init.raw.log` / `init.log` (init-specific failures)
4. `compose-logs.log` or per-case logs (container/service details)
5. `extended-summary.json` (extended suite case-level status)
