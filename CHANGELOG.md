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

- Removed `--secret-id-num-uses` from `bootroot service add` and from
  `rotate approle-secret-id` policy state. Service SecretIDs are now
  always issued with unlimited uses (`num_uses = 0`). The lower-level
  OpenBao client still supports bounded-use SecretIDs for non-service
  workflows.

### Fixed

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
- Fixed daemon-mode retries silently dropping CLI overrides (`--email`,
  `--ca-url`, `--http-responder-url`, `--http-responder-hmac`). The retry
  path reloaded the config file from disk without re-applying CLI-provided
  values, causing the first attempt to succeed but subsequent attempts to
  revert to file-only defaults.
- Fixed `bootroot service add` (`local-file` mode) generating an agent config
  missing top-level `domain` and `[acme].http_responder_hmac`. The generated
  `agent.toml` is now ready to use without manual editing.
- Fixed `bootroot init` failing with "Failed to set key file permissions /
  Operation not permitted" when the step-ca compose service (running as
  root) restarted into a freshly created `ca.json` and wrote DB state
  files as root before `fix_secrets_permissions` could run. Init now
  stops the compose step-ca service before bootstrapping and restarts it
  after permissions are fixed and `ca.json` is patched.

### Added

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
