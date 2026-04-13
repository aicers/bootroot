# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- Removed `--secret-id-num-uses` from `bootroot service add` and from
  `rotate approle-secret-id` policy state. Service SecretIDs are now
  always issued with unlimited uses (`num_uses = 0`). The lower-level
  OpenBao client still supports bounded-use SecretIDs for non-service
  workflows.

### Fixed

- Fixed daemon-mode retries silently dropping CLI overrides (`--email`,
  `--ca-url`, `--http-responder-url`, `--http-responder-hmac`). The retry
  path reloaded the config file from disk without re-applying CLI-provided
  values, causing the first attempt to succeed but subsequent attempts to
  revert to file-only defaults.
- Fixed `bootroot service add` (`local-file` mode) generating an agent config
  missing top-level `domain` and `[acme].http_responder_hmac`. The generated
  `agent.toml` is now ready to use without manual editing.

### Added

- Added `schema_version` field (`u32`, starting at `1`) to the
  `RemoteBootstrapArtifact` JSON written by
  `bootroot service add --delivery-mode remote-bootstrap`. Downstream
  parsers should check this field before accessing artifact fields.
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
  operator to use a policy update command.
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
- Added `bootroot openbao save-unseal-keys` and
  `bootroot openbao delete-unseal-keys` for managing unseal key files
  used by automatic unseal on `infra up`.
- Added "Save unseal keys to file?" interactive prompt at the end of
  `bootroot init`.

### Changed

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
