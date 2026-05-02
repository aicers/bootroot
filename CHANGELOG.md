# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Bumped `rustls-webpki` from 0.103.10 to 0.103.12 to address
  RUSTSEC-2026-0098 and RUSTSEC-2026-0099 (incorrect name-constraint
  validation for URI and wildcard names).

### Removed

- Removed ACME EAB auto-issuance and bootroot-side enforcement because
  the bundled OSS step-ca does not support EAB (EAB is a commercial
  Smallstep-only feature). The `bootroot rotate eab` subcommand, the
  `--enable eab-auto` flag on `bootroot init`, the auto-created empty
  EAB KV entries written during `service add`, and the mandatory EAB
  check in `bootroot-remote bootstrap` are gone. The operator-provided
  pass-through is kept: `--eab-kid` / `--eab-hmac` on `bootroot init`,
  `--eab-file-path` on `bootroot-remote bootstrap`, and `--eab-kid` /
  `--eab-hmac` / `--eab-file` on `bootroot-agent`. When credentials are
  present they are forwarded to the ACME `newAccount` request (RFC
  8555); when absent the `eab` apply step reports `applied` if a stale
  `eab.json` from a prior bootstrap had to be removed and `skipped`
  when no file existed to begin with. A present-but-malformed EAB KV
  entry (e.g., a non-string `kid` or `hmac`) fails the bootstrap
  loudly rather than being silently demoted to "absent".
  Missing-entry detection is narrow: only a `404 Not Found`
  from OpenBao is treated as "no EAB configured" via the new
  `OpenBaoClient::try_read_kv`. Transport errors, 5xx responses, and
  other unexpected failures still surface as bootstrap failures so a
  transient OpenBao outage cannot silently demote EAB to `skipped`.
  The narrow semantics also apply to `bootroot service add` when it
  reads the control-node EAB entry, so a transient OpenBao outage
  cannot silently strip EAB from a newly added service. When the KV
  entry is absent, `bootroot-remote bootstrap` also removes any
  stale `eab.json` left on the target host, preventing
  `bootroot-agent --eab-file` from forwarding credentials the
  operator has since cleared. The `--stepca-url` flag on `bootroot
  init` is also gone: it only fed the deleted auto-issuance code
  path and had no other consumer. (Closes #550)
- Removed `--secret-id-num-uses` from `bootroot service add` and from
  `rotate approle-secret-id` policy state. Service SecretIDs are now
  always issued with unlimited uses (`num_uses = 0`). The lower-level
  OpenBao client still supports bounded-use SecretIDs for non-service
  workflows.

### Fixed

- Fixed `bootroot service agent start` failing with
  `network bootroot_default declared as external, but could not be
  found` from any working directory whose name is not `bootroot` (or
  any deployment with a non-default `COMPOSE_PROJECT_NAME`). The
  command no longer hardcodes `-p bootroot` and `bootroot_default`;
  instead it discovers the docker compose project at runtime from the
  `bootroot-openbao` container's `com.docker.compose.project` label
  and derives the default network name as `<project>_default`. A new
  `--openbao-network` flag overrides the network discovery; supplying
  it is mandatory when OpenBao runs outside bootroot's compose file
  (separate host, kubernetes, managed service, etc.). Discovered and
  operator-supplied network names are validated against the docker
  network naming rules to prevent override-file injection. The check
  for whether a compose file declares an `openbao:` service now
  inspects the actual top-level service key rather than substring-
  matching the file, so external-OpenBao deployments that mention the
  word `openbao` in container names, hostnames, secret names, image
  tags, or volume paths are routed through the external branch.
  (Closes #577)
- Fixed `bootroot rotate` (responder-hmac, approle-secret-id, db,
  stepca-password) timing out for services registered with
  `--deploy-type daemon --delivery-mode local-file`. `service add` now
  emits sidecar template destinations that point at the host-side
  `agent_config_path` and CA bundle the daemon actually reads, and
  `bootroot service agent start --service-name <name>` now supports
  daemon services by bind-mounting those host directories into the
  sidecar container (`bootroot-openbao-agent-<service>`) that rotate
  signals. The `service add` summary now points daemon + local-file
  operators at `bootroot service agent start`; the host-run
  `bao agent -config=<openbao_agent_hcl_path>` remains available as
  an alternative. (Closes #541)
- Fixed `bootroot rotate ca-key` Phase 5 failing against services
  registered with `--deploy-type docker` and a custom
  `--container-name`. The restart target now reads
  `entry.container_name` from `state.json` rather than assuming a
  hardcoded `bootroot-agent-<service>` prefix, and the `service add`
  docker snippet recommends a long-running daemon container
  (`docker run -d --restart unless-stopped`, without `--oneshot`) so
  `docker restart` is a meaningful signal-renewal action. Services
  that were registered before this fix and created a one-shot sidecar
  (the old `docker run --rm ... --oneshot` snippet) will see a
  dedicated error at rotate time naming the missing container and
  pointing operators at the new long-running snippet; see
  `docs/en/operations.md` for migration steps. The pre-flight
  `docker container inspect` captures stderr and only maps the
  specific "No such container/object" response to the migration
  hint; other inspect failures (e.g. daemon unreachable, permission
  denied) surface verbatim as `docker command failed: …` so the
  real problem is not masked. If the actual `docker restart` itself
  fails after the inspect succeeds, the error now names the real
  container (e.g. `docker restart my-nginx failed with status: …`)
  instead of the removed hardcoded `bootroot-agent` label, so
  operators can identify the signaled container from the failure
  output. (Closes #552)
- Fixed `bootroot init` storing the host-side PostgreSQL port in the
  step-ca DSN written to OpenBao KV / `ca.json` when
  `POSTGRES_HOST_PORT` differed from `5432`, and fixed `bootroot rotate
  db` and `bootroot verify --db-check` reading that compose-internal
  DSN back verbatim so the host-side command could not resolve
  `postgres:5432`. A single DSN translation layer
  (`bootroot::db::for_compose_runtime` /
  `bootroot::db::for_host_runtime`) now owns the host/port rewrite at
  every step-ca DSN read/write site, and `rotate db` self-heals a
  previously-corrupted stored DSN on the next rotation. `verify
  --db-check` accepts a `--compose-file` flag (defaulting to
  `docker-compose.yml`) so its sibling `.env` can supply
  `POSTGRES_HOST_PORT` for the host-side translation. Only `sslmode`
  is preserved across translation; other query parameters are
  dropped. (Closes #542)
- Fixed `bootroot verify` failing with "No such file or directory" when
  `bootroot-agent` was not on `$PATH`. Verify now resolves the agent
  binary by checking `--agent-binary <path>` first, then the directory
  containing the running `bootroot` executable, and finally `$PATH`.
  When none resolve, the error message names every candidate that was
  tried. (Closes #553)
- Fixed `bootroot rotate openbao-recovery --rotate-unseal-keys` failing
  against OpenBao 2.5.x with `405 Method Not Allowed` /
  `unsupported operation`. The legacy unauthenticated `sys/rekey/*`
  endpoints were deprecated in OpenBao 2.4 and disabled by default in
  2.5 (`disable_unauthed_rekey_endpoints = true`). The unseal-key
  rotation flow now uses the authenticated `POST /sys/rotate/root/init`
  and `POST /sys/rotate/root/update` endpoints (with the `data`-wrapped
  response envelope) and is no longer vulnerable to the
  unauthenticated-cancel attack documented in the upstream deprecation
  notice. (Closes #556)
- Fixed daemon-mode retries silently dropping CLI overrides (`--email`,
  `--ca-url`, `--http-responder-url`, `--http-responder-hmac`). The retry
  path reloaded the config file from disk without re-applying CLI-provided
  values, causing the first attempt to succeed but subsequent attempts to
  revert to file-only defaults.
- Fixed `bootroot service add` (`local-file` mode) generating an agent config
  missing top-level `domain` and `[acme].http_responder_hmac`. The generated
  `agent.toml` is now ready to use without manual editing.
- Fixed `bootroot service add` (`local-file` mode) emitting an `agent.toml.ctmpl`
  that omitted `server` (ACME directory URL), `email`, `[acme].http_responder_url`,
  and the `[acme]` retry/timeout tunables. Operators on non-default topologies
  had to hand-edit the rendered `agent.toml` to add those fields, only to have
  the next KV-driven re-render (e.g. `rotate responder-hmac`) silently overwrite
  the edits. The local-file renderer now delegates to a new shared
  `render_agent_config_baseline` helper in `bootroot::trust_bootstrap`, so the
  fresh template carries every field the remote-bootstrap variant emits and
  re-renders preserve initial configuration instead of falling back to
  `bootroot-agent`'s compiled-in defaults. `bootroot service add` also accepts
  `--agent-email`, `--agent-server`, and `--agent-responder-url` — mirroring the
  escape hatch `bootroot-remote bootstrap` has long provided — so operators on
  step-ca or responder endpoints other than the bundled-compose defaults can
  bake their real topology into the template at service-add time, instead of
  hand-editing the rendered `agent.toml` and watching the next rotation clobber
  those edits. The same flags now also flow into `--delivery-mode
  remote-bootstrap` artifacts (the `agent_email` / `agent_server` /
  `agent_responder_url` fields of `bootstrap.json`), so the remote-bootstrap CLI
  surface no longer silently ignores them and the downstream
  `bootroot-remote bootstrap` run receives the operator's real values instead of
  the localhost compose defaults. The resolved `--agent-email` /
  `--agent-server` / `--agent-responder-url` values are now persisted on the
  `ServiceEntry` in `state.json` and are included in the
  `remote-bootstrap` idempotence comparison, so an idempotent rerun of
  `bootroot service add --delivery-mode remote-bootstrap ...` regenerates
  `bootstrap.json` from the persisted values — a rerun that omits the flag
  no longer silently reverts the artifact to the compose-topology localhost
  default, and a rerun that passes a different value is rejected as a
  duplicate instead of silently drifting the artifact away from the
  stored definition. On the local-file path, the baseline fields and
  `--agent-*` override flags also now apply when `--agent-config`
  points at a pre-existing `agent.toml` that is missing the topology
  fields — previously the existing-file branch read the file verbatim,
  so operators who started from a hand-edited file still got a
  `.ctmpl` that omitted `server` / `http_responder_url` and silently
  ignored the override flags. A new
  `trust_bootstrap::apply_agent_config_baseline_defaults` helper
  backfills only missing baseline keys (via new
  `toml_util::insert_missing_top_level_keys` /
  `insert_missing_section_keys` helpers) so operator-customised values
  in a pre-existing file survive untouched, while explicit
  `--agent-email` / `--agent-server` / `--agent-responder-url` values
  take precedence via a subsequent upsert. `bootroot-remote bootstrap`
  now applies the same baseline backfill and artifact-carried override
  treatment when the remote target already has an `agent.toml`:
  previously its existing-file branch read the file verbatim and only
  upserted `[trust]` / `acme.http_responder_hmac` / the managed
  profile, silently dropping the artifact's `agent_email` /
  `agent_server` / `agent_responder_url` values whenever the remote
  file was missing those keys. The updated renderer inserts any missing
  baseline keys and then upserts the artifact overrides (propagated from
  the upstream `bootroot service add --agent-*` flags), so the re-render
  loop stops reverting to bootroot-agent's compiled-in defaults on
  remote targets too. The `RemoteBootstrapArtifact` fields
  `agent_email` / `agent_server` / `agent_responder_url` are now
  serialized as optional keys (omitted when `bootroot service add` saw
  no `--agent-*` flags), so a downstream `bootroot-remote bootstrap`
  can distinguish "no explicit override" (preserve pre-existing remote
  values, backfill only) from "explicit override" (clobber). Without
  this signal the override path silently clobbered operator-customised
  remote `agent.toml` entries back to the localhost defaults whenever
  the artifact was produced without `--agent-*` flags. (Closes #549)
- Fixed `bootroot init` failing with "Failed to set key file permissions /
  Operation not permitted" when the step-ca compose service (running as
  root) restarted into a freshly created `ca.json` and wrote DB state
  files as root before `fix_secrets_permissions` could run. Init now
  stops the compose step-ca service before bootstrapping and restarts it
  after permissions are fixed and `ca.json` is patched.
- Fixed `bootroot-remote bootstrap` emitting an `agent.hcl` that had
  drifted from the `bootroot service add` (`local-file` mode) variant.
  The remote renderer now delegates to the shared
  `bootroot::openbao::build_agent_config` primitive, so the HCL always
  sets `remove_secret_id_file_after_reading = false` (preventing the
  OpenBao agent from deleting the `secret_id` file on first read and
  breaking subsequent restarts) and always emits both `template` blocks
  — one for `agent.toml.ctmpl` and one for `ca-bundle.pem.ctmpl` — so a
  control-plane CA rotation is picked up on remote hosts instead of
  leaving them pinned to the bootstrap-time bundle. A regression test
  pins the remote renderer output to the shared primitive so future
  option additions on one side cannot silently drop from the other.
  (Closes #547)

### Added

- `bootroot rotate force-reissue` for `--delivery-mode remote-bootstrap`
  services now publishes a versioned reissue request to OpenBao KV at
  `{kv_mount}/data/bootroot/services/<service>/reissue` with
  `requested_at` and `requester` fields, instead of just printing a hint
  to run `bootroot-remote bootstrap` on the service host. The new
  `--wait` / `--wait-timeout` flags poll `completed_at` on the same KV
  path so the operator can observe end-to-end latency, and `--requester`
  overrides the operator label written into the payload. The `--wait`
  success line also reports the computed end-to-end latency
  (`completed_at - requested_at`, pulled from the KV payload so it
  reflects what was actually committed) in a human-readable form so
  the operator does not have to subtract timestamps manually. Closes
  #548.
- `bootroot-agent` learns a required `[openbao]` section in
  `agent.toml` that drives the fast-poll loop. `bootroot-remote
  bootstrap` now auto-populates the connection fields (`url`,
  `kv_mount`, `role_id_path`, `secret_id_path`, `ca_bundle_path`) on
  every run so the control-plane KV request has a guaranteed consumer
  on every remote-bootstrap host; operator-tuned `fast_poll_interval`
  or `state_path` keys in an existing section are preserved.
  `state_path` is additionally provisioned as an absolute path
  adjacent to `agent.toml` whenever the current value is missing or
  relative, so the fast-poll restart-persistence state does not end up
  at a cwd-relative location under systemd-style supervisors where
  the working directory may change between runs or be unwritable.
  Rerunning `bootroot-remote bootstrap` therefore repairs a legacy
  config whose `state_path` was the in-tree relative default, matching
  the remediation hint that config validation prints. Config validation
  also rejects a cwd-relative `openbao.state_path` (and the now-
  cosmetic in-tree default when no value is set), so the hazard is
  caught whether `state_path` came from an operator-written config or
  from a bootstrap run where `--agent-config-path` was itself relative
  and bootstrap therefore declined to provision a same-cwd state path.
  When
  configured, the agent
  authenticates via AppRole and polls each registered service's reissue
  KV path on `fast_poll_interval` (default `30s`), triggering an
  immediate ACME renewal whenever it observes a KV v2 version newer than
  the one it last applied. After a successful renewal the agent writes
  back `completed_at` / `completed_version` and persists
  `last_reissue_seen_version` per service in `state_path` so requests
  are not re-fired across restarts. When a single host runs multiple
  `[[profiles]]` for the same `service_name`, the fast-poll tick now
  fans the renewal trigger out to every matching profile before
  marking the version consumed, so a service-scoped force-reissue
  rotates every instance instead of only the first profile observed.
  When the fan-out does not finish in one tick (a sibling profile's
  renewal fails), the profiles that already succeeded are recorded as
  per-service `in_flight_renewals` progress in `state_path`; the next
  tick retries only the failed sibling(s) against the same KV version
  and does not force a second renewal on the profiles that already
  ran. When a renewal succeeds but the completion write back to KV
  fails, the agent persists a `pending_completion_writes` entry in
  `state_path` and retries just the write on the next tick — so a
  transient OpenBao outage will not leave `bootroot rotate
  force-reissue --wait` stuck without an acknowledgement after the
  certificate has actually been rotated. `rotate force-reissue` now
  pins its `--wait` comparison on the version returned by the publish
  POST (via the new `OpenBaoClient::write_kv_with_version` helper)
  instead of a follow-up GET, so the agent's own completion write
  cannot advance the metadata version between the two reads and
  strand the waiter. On the agent side, `evaluate_observation` now
  treats any payload carrying `completed_version` as an already-
  serviced request rather than a new one, so the agent's own
  completion ack (which bumps KV metadata from `N` to `N+1` but
  carries `completed_version = N`) cannot be mistaken for an
  operator request and re-trigger a forced renewal on every
  subsequent fast-poll tick. The relogin heuristic that rearms
  `AppRole` login after an auth-related `ReadError` also matches the
  "`OpenBao token is not set`" error the client emits when no login has
  succeeded yet, so a transient startup login failure is retried on the
  next tick instead of leaving fast-poll permanently dead until the
  process restarts. The fast-poll force-reissue and the ordinary
  `check_interval` renewal paths now serialise per profile behind a
  single-flight lock held across both the `should_renew` decision and
  the ACME issuance, so a periodic tick that lands while a forced
  reissue is already in flight re-reads the rotated cert once the lock
  releases and skips the redundant second issuance instead of driving a
  parallel ACME handshake through a spare semaphore permit. Shrinks the
  worst-case force-reissue latency for remote-bootstrap services from
  one `check_interval` (default 1h) to roughly one fast-poll interval.
- Added `--cert-duration` to `bootroot init` (default `24h`) and a new
  `bootroot ca` subcommand group (`ca update`, `ca restart`) for
  configuring step-ca's `defaultTLSCertDuration`. `init` embeds the
  value as a literal into the ACME provisioner's `claims` block in
  `ca.json.ctmpl` so it survives OpenBao Agent render cycles, and
  validates that the value exceeds the daemon's default
  `renew_before` (16h) to avoid flagging every newly issued
  certificate for immediate renewal. `ca update` patches both
  `ca.json.ctmpl` and `ca.json` after initial setup; `ca restart`
  restarts only the `step-ca` compose service so the new value takes
  effect. (Closes #516)
- Added `tests/e2e_multi_host_tls_real_daemon.rs`, a real-daemon-backed
  multi-host TLS E2E suite covering the three scenarios from #521 (happy
  path, system-trust rejection, pin-enforced rejection) against a
  fully-provisioned, TLS-enabled `openbao` daemon in Docker. The RN side
  consumes a production-style `bootstrap.json` artifact that carries a
  response-wrapped `secret_id`, exercising the full unwrap/login/KV/trust
  pull over TLS plus an HTTP-01 admin registration and public challenge
  fetch. Tests skip gracefully on hosts without Docker. CI pre-pulls
  `openbao/openbao:latest` in `test-core`. (Closes #534, part of #507)
- Added automatic HTTP-01 admin API TLS certificate provisioning during
  `bootroot init`. When `--http01-admin-bind` intent is recorded,
  `bootroot init` issues a server certificate via the local step-ca,
  writes `responder.toml` with TLS enabled, and applies the compose
  override in a single restart — the admin API transitions from
  loopback-only/plain-HTTP to non-loopback/TLS atomically. The
  certificate is registered in `StateFile::infra_certs` for automated
  renewal through the rotation pipeline via SIGHUP-based reload.
  (Part of #515)
- Added `agent-docker.hcl` generation to `bootroot service add`
  (local-file mode). The Docker variant uses the Docker-internal
  OpenBao address (`bootroot-openbao:8200`) and container-side paths under
  `/openbao/secrets/`. When TLS is enabled (`https`), the config
  includes a `ca_cert` field pointing to a pre-seeded bootstrap CA
  bundle so the sidecar agent can verify the OpenBao server on first
  startup. The existing `agent.hcl` output is unchanged. (Part of
  #518)
- Added `--openbao-bind <IP>:<port>`, `--openbao-tls-required`,
  `--openbao-bind-wildcard`, and `--openbao-advertise-addr <IP>:<port>`
  flags to `bootroot infra install`. Operators can opt into non-loopback
  OpenBao binding for multi-host deployments.
  `--openbao-tls-required` acknowledges mandatory TLS enforcement;
  `--openbao-bind-wildcard` is required for both IPv4 (`0.0.0.0`) and
  IPv6 (`[::]`) wildcard addresses; `--openbao-advertise-addr` is
  required for wildcard binds to specify a routable address for remote
  bootstrap artifacts. The compose override is first applied by
  `bootroot init` or `infra up` after TLS validation passes. The TLS
  validator parses `tls_cert_file` and `tls_key_file` paths from
  `openbao.hcl` and validates the files OpenBao is actually configured
  to serve (not hardcoded defaults). The compose override is
  scope-checked to reject tampered overrides that expose non-OpenBao
  guarded services. Stored-intent revalidation on `infra up` and
  `bootroot init` is keyed off `StateFile`, not override file
  existence — a missing override with recorded intent is a hard error.
  PostgreSQL stays loopback-only. (Part of #508)
- Added `--artifact <path>` flag to `bootroot-remote bootstrap`. When
  provided, all required fields are loaded from the artifact JSON file,
  avoiding sensitive `wrap_token` exposure in shell command lines and
  `ps` output. Per-field CLI flags still work for backward compatibility.
- Added `wrap_token` and `wrap_expires_at` optional fields to
  `RemoteBootstrapArtifact`. When wrapping is enabled (default),
  `bootroot-remote` unwraps the token via `sys/wrapping/unwrap` to
  obtain `secret_id` before login. Unwrap failures are classified as
  expired (with recovery instructions) or already-unwrapped (flagged as
  a potential security incident).
- Added `schema_version` field (`u32`, currently `2`) to the
  `RemoteBootstrapArtifact` JSON written by
  `bootroot service add --delivery-mode remote-bootstrap`. Downstream
  parsers should check this field before accessing artifact fields.
- Added `ca_bundle_pem` field to `RemoteBootstrapArtifact`, embedding
  the control-plane CA PEM inline. During `bootroot-remote bootstrap`,
  the PEM is written to `ca_bundle_path` before any OpenBao call and
  used as the TLS trust anchor for HTTPS `openbao_url` endpoints.
- Added `OpenBaoClient::with_pem_trust` constructor that anchors TLS
  verification to an in-memory CA bundle with optional SHA-256 pinning,
  integrating the same `PinnedCertVerifier` path used by
  `build_http_client`. `tls::build_http_client_from_pem` now accepts
  an optional `pins` parameter. `OpenBaoClient::with_client` remains
  as an escape hatch for callers needing full `reqwest::Client` control.
- Added remote-bootstrap operator guide (`docs/en/remote-bootstrap.md`,
  `docs/ko/remote-bootstrap.md`) covering transport options (SSH,
  Ansible, cloud-init, systemd-credentials), `secret_id` hygiene,
  network requirements, and the full `RemoteBootstrapArtifact` schema
  reference.
- Added post-renew hook flags to `bootroot service add`. Services can now
  configure a hook to run after successful certificate renewal at
  registration time, removing the need to hand-edit `agent.toml`.
  Two flag styles are supported: presets (`--reload-style systemd
  --reload-target nginx`) and low-level (`--post-renew-command`,
  `--post-renew-arg`, `--post-renew-timeout-secs`,
  `--post-renew-on-failure`). Hook settings are persisted in
  `state.json` and forwarded to `bootroot-remote bootstrap` for
  remote-bootstrap delivery mode.
- Added per-issuance `secret_id` policy flags to `bootroot service add`
  (`--secret-id-ttl`, `--secret-id-wrap-ttl`, `--no-wrap`). Policy
  values are persisted in `state.json` and applied automatically during
  `rotate approle-secret-id`. Re-running `service add` with different
  policy values on an existing service produces an error directing the
  operator to use `bootroot service update`.
- Added `bootroot service update` subcommand for modifying per-service
  `secret_id` policy (`--secret-id-ttl`, `--secret-id-wrap-ttl`,
  `--no-wrap`) without re-running the full `service add` flow. Use
  `"inherit"` to restore role-level defaults. Changes take effect on
  the next `rotate approle-secret-id`.
- Added `--secret-id-ttl` flag to `bootroot init` for setting the
  role-level `secret_id` TTL on AppRole roles created during
  initialization (default `24h`, maximum `168h`). Values above the
  recommended `48h` threshold emit a warning.
- Added automatic HTTP-01 DNS alias registration on `service add`. The
  validation FQDN is registered as a Docker network alias on
  `bootroot-http01` at runtime, removing the need for a hand-written
  `docker-compose.override.yml`. Aliases are replayed automatically by
  `infra up` after container restarts.
- Added `bootroot infra install` for zero-config first-time setup:
  generates `.env` with a random PostgreSQL password, creates `secrets/`
  and `certs/` directories, and brings up Docker Compose services.
- Added `bootroot clean` for full teardown (containers, volumes, secrets,
  `.env`).
- Added `--rn-cidrs` flag to `bootroot service add` and
  `bootroot service update` for binding `secret_id` tokens to specific
  client CIDR ranges via `token_bound_cidrs`. When provided, the CIDRs
  are sent to OpenBao during `secret_id` creation and persisted in
  `state.json` for use by `rotate approle-secret-id`. Use
  `--rn-cidrs clear` in `service update` to remove an existing binding.
  Omitting the flag preserves current behavior (no CIDR binding).
- Added automatic OpenBao file audit backend during `bootroot init`.
  The audit device writes to `/openbao/audit/audit.log` inside the
  container (persisted via the `openbao-audit` Docker volume). The
  backend is enabled idempotently via the OpenBao API; re-running
  `init` on an already-audited instance is a no-op.
- Added `bootroot openbao save-unseal-keys` and
  `bootroot openbao delete-unseal-keys` for managing unseal key files
  used by automatic unseal on `infra up`.
- Added "Save unseal keys to file?" interactive prompt at the end of
  `bootroot init`.

### Changed

- Renamed `bootroot service agent start` to `bootroot service
  openbao-sidecar start`. The new name resolves two ambiguities in
  the previous spelling: which software ("agent" clashed with the
  unrelated `bootroot-agent` certificate daemon — `openbao` makes the
  identity explicit) and which deployment pattern (`agent` did not
  hint that the command manages only the sidecar variant of the
  OpenBao Agent — `sidecar` makes that explicit and leaves room for
  a future host-daemon subcommand). All docs, examples, and the
  next-steps text emitted by `bootroot service add` now use the new
  name. The previous `bootroot service agent start` form keeps
  working for one release as a hidden deprecated alias that prints a
  warning pointing at the new name; it will be removed in the
  following release. The Docker E2E matrix in
  `.github/workflows/ci.yml` gained a `local-no-hosts-host-daemon`
  arm that re-runs the no-hosts lifecycle with
  `OBA_DEPLOYMENT=host-daemon`, exercising the polling-fallback rotate
  path (`static_secret_render_interval = 30s`) the next-steps text in
  `service add` advertises as the alternative to the managed sidecar.
  `scripts/impl/run-local-lifecycle.sh` also brackets the
  `responder-hmac` rotate with a wall-clock assertion: in sidecar
  mode it must complete below `SIDECAR_ROTATE_LATENCY_LIMIT_SECS`
  (default 25s, well under the 30s polling window) so a regression
  in the active container-restart route would surface here instead
  of being masked by the polling fallback; in host-daemon mode it
  must complete within `HOST_DAEMON_RENDER_TIMEOUT_SECS` (default
  75s) since bootroot has no handle on the operator-managed daemon
  and propagation has to wait for the polling cycle. (Closes #578)
- Changed `bootroot service agent start` to take `--service-name <NAME>`
  instead of a positional `<SERVICE_NAME>` argument, matching the other
  per-service subcommands (`service add`, `service info`, `service update`).
  The positional form is no longer accepted. (Closes #553)
- `bootroot rotate db` now auto-reads the current PostgreSQL admin DSN
  from `ca.json`'s `db.dataSource` field when `--db-admin-dsn` is
  omitted. Previously operators had to copy the DSN out of `ca.json`
  manually because the password in `.env`'s `POSTGRES_PASSWORD` diverges
  from the live credential after `init --enable db-provision`. The flag
  still overrides the discovered value when explicitly provided, and the
  command falls through to the interactive prompt only when `ca.json` is
  absent. A present-but-broken `ca.json` now fails fast instead of
  prompting for a DSN that would likely be wrong. (Closes #517)
- Added rotation cadence guidance to `service add`, `service update`,
  and `init` CLI output. `init` always prints the rotation-cadence
  note; `service add` and `service update` print it when
  `--secret-id-ttl` is set explicitly. Documented the default vs
  recommended TTL model and the rotation cadence rule in the
  operations guide.
- Changed idempotent `bootroot service add` rerun behavior for
  `remote-bootstrap` mode: when wrapping is enabled (the default), a
  rerun now issues a fresh `secret_id` with wrapping and regenerates
  the bootstrap artifact with a new `wrap_token`. Previously the rerun
  only regenerated the artifact without calling OpenBao.
- Changed `bootroot init` to bootstrap step-ca automatically (no manual
  `step ca init` required). DB credentials are read from `.env` when
  available, so `--db-dsn` and `--db-password` are no longer required on
  the command line after `bootroot infra install`.
- Replaced local MkDocs theme assets with shared
  [aicers/docs-theme](https://github.com/aicers/docs-theme) `manual`
  template. Theme version and template are declared in `docs/theme.toml`
  and fetched at build time via `scripts/fetch-theme.sh`.

## [0.2.0] - 2026-03-28

### Added

- Added `bootroot rotate ca-key` for intermediate-only CA key rotation
  and `bootroot rotate ca-key --full` for root + intermediate rotation.
  Both modes use an 8-phase idempotent workflow with crash-safe resume
  via `rotation-state.json`.
- Added `bootroot rotate openbao-recovery` for manual OpenBao recovery
  credential rotation (unseal keys and/or root token), including
  operator-confirmed execution and post-rotation continuity coverage.
- Added core Bootroot CLI lifecycle foundations, including infra readiness,
  init/status, service onboarding, verify/rotate flows, and related guardrails.
- Added remote-bootstrap operations via `bootroot-remote` with pull/ack/sync,
  summary JSON handling, retry controls, and schedule templates.
- Added extended E2E workflow separation for heavier scenarios.
- Added Python quality gates with Ruff (format/lint) in CI and docs workflows.

### Changed

- Consolidated duplicate i18n entry templates:
  `infra_entry_*`/`monitoring_entry_*` merged into
  `readiness_entry_*`, and `status_infra_entry_*`/
  `monitoring_status_entry_*` merged into `status_entry_*`.
  No user-visible output changes.

- Changed DB DSN runtime handling to normalize local hosts for compose runtime
  compatibility.
- Changed service onboarding output to clarify Bootroot-managed vs
  operator-managed boundaries and trust-related behavior.
- Changed managed trust bootstrap so `bootroot service add` and
  `bootroot-remote bootstrap` stage the OpenBao-backed CA bundle and
  fingerprints before the first `bootroot-agent` run, instead of relying on
  skipped CA verification during initial issuance.
- Expanded Docker E2E coverage (baseline, rotation recovery, main lifecycle,
  remote lifecycle) and aligned local preflight paths with CI expectations.

### Fixed

- Fixed `parse_db_dsn` silently ignoring `sslmode` when it is
  not the first query parameter in the DSN string.
- Log a warning when an EAB JSON file contains empty `kid` or
  `hmac` fields instead of returning `Ok(None)` silently.
- Preserve original error chains in filesystem helpers
  (`fs_util`) by using `with_context` instead of formatting the
  error into a new string.
- Fix `bootroot rotate stepca-password` failing with TTY allocation error
  when running in non-interactive environments by adding `-f` flag to `step
  crypto change-pass` command
- Bind PostgreSQL to localhost in `docker-compose.yml` so that
  `bootroot rotate db` can connect from the host without exposing the DB
  to external interfaces. Set `POSTGRES_HOST_PORT` if the default port 5432
  conflicts with a local PostgreSQL instance.
- Fixed `bootroot rotate db` failing with SQL syntax error. PostgreSQL's
  `ALTER ROLE ... WITH PASSWORD` and `CREATE ROLE ... WITH PASSWORD` statements
  do not support parameterized queries (`$1`). The password is now properly
  escaped as a string literal.
- Fixed `bootroot rotate db` panic with "Cannot start a runtime from within a
  runtime" error by running the synchronous postgres client on a blocking
  thread via `tokio::task::spawn_blocking`.
- Fixed hosts-mode lifecycle instability and related CI reproducibility issues.
- Fixed and strengthened trust sync and trust verification behavior with
  stronger E2E assertions.

## [0.1.0] - 2026-02-01

### Added

- Initial public release of the bootroot

[Unreleased]: https://github.com/aicers/bootroot/compare/0.2.0...main
[0.2.0]: https://github.com/aicers/bootroot/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/aicers/bootroot/tree/0.1.0
