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

- Fixed `bootroot-agent` not detecting a post-`init` trust-anchor
  rotation. Its renewal predicate (`should_renew`) only checked leaf
  expiry, so after `bootroot clean` + `init` regenerated the step-ca
  root + intermediate, a still-time-valid leaf signed by the previous
  intermediate was treated as a no-op. `service add` re-seeded
  `ca-bundle.pem` with the new generation, the pinned fingerprints in
  `agent.toml` also reflected the new generation, but `cert.pem`
  remained signed by the previous intermediate — so every mTLS
  consumer hit `UNABLE_TO_VERIFY_LEAF_SIGNATURE` for the full
  remaining 24h of leaf validity. The two PKI generations share
  Subject/Issuer DN (`O=Bootroot CA, CN=Bootroot CA Root CA` /
  `Intermediate CA`), so name-based comparison cannot tell them apart;
  the new `cert_chain::leaf_chains_to_bundle` discriminates by
  public-key signature instead, walking leaf → issuer → self-signed
  root inside the bundle. `should_renew` now invokes that walk when
  `[trust].ca_bundle_path` is configured and forces a reissue when the
  walk fails (or when the bundle is missing/unreadable), so the next
  agent tick reissues the leaf and `write_cert_and_key`'s existing
  `ensure_*_parent_dir` calls re-assert the `--cert-group` parent-dir
  policy as a side effect. `bootroot verify` also gained the same
  chain check so the silent-failure surface is closed a second time
  for operators auditing post-rotation state. (Closes #627)
- Fixed `bootroot-agent` overwriting `ca-bundle.pem` with the ACME
  response chain alone, silently dropping the root that `service add`
  had seeded. For a stock step-ca deployment the ACME chain contains
  only the intermediate, so the post-issuance bundle no longer
  terminated at a self-signed anchor and default-config TLS clients
  (Node `tls.connect`, `openssl verify` without `-partial_chain`) failed
  with `unable to get issuer certificate` even though `service add`,
  `bootroot verify`, and `bootroot status` all reported green. The
  agent now reads the existing bundle, keeps every block whose DER
  SHA-256 is listed in `[trust].trusted_ca_sha256` (filtering out junk
  from prior misconfigurations), unions it with the new ACME chain
  deduped by fingerprint, and writes the merged result. The test
  helper goes through the same `write_merged_ca_bundle` path as the
  production code, so the chain-only write cannot be reintroduced in
  only one of them. The merge step also fails closed when the existing
  bundle cannot be read (permissions, ACL drift, or any I/O error other
  than `NotFound`), so a bundle the agent could not inspect is never
  silently overwritten with only the ACME chain. `bootroot verify` now
  also fails when any fingerprint in `trusted_ca_sha256` is absent from
  `ca_bundle_path`, closing the silent-failure surface so the
  truncation cannot recur unobserved. (Closes #622)
- Fixed `bootroot rotate ca-key` phase 5 listing every `local-file`
  service in its "Consumer reload/restart required" hint regardless of
  whether the rotation actually wiped and signaled the service. On a
  resumed or retried rotation, or after a partial manual migration,
  services whose cert was already issued by the new intermediate take
  the skip-migrated branch and are never re-signaled — but they still
  appeared in the printed hint, so an operator following it would
  restart consumers that did not need restarting, churning live
  traffic and eroding trust in the hint. The hint is now built from
  the services actually processed in the reissue loop, so the
  skip-migrated branch no longer contributes. (Closes #619)
- Fixed `bootroot-agent` burning its renewal retry budget against a
  transient `agent.toml` race. The retry loop introduced by #303
  re-reads `agent.toml` on every ACME attempt; if a concurrent
  `bootroot service add` or `OpenBao` Agent sidecar render was mid-write
  on that file, the reader could observe a truncated file or one that
  did not yet contain the named profile, and the daemon would fail the
  attempt with `Profile '<name>' not found in reloaded config` —
  exhausting the retry budget against a microsecond-scale file race
  rather than real ACME work. Two changes close the window:
  `apply_local_service_configs` now writes `agent.toml` via a
  same-directory temp file + atomic `rename(2)` through the new
  `fs_util::atomic_write` helper, so a concurrent reader sees either
  the previous file or the fully written new one; and on the consumer
  side, `bootroot-agent`'s retry path falls back to the previously
  loaded in-memory profile (logging at WARN) when the reload itself
  fails or the named profile is absent from the reloaded file, instead
  of failing the attempt. When the reload lands on a coherent file
  the original #303 intent is preserved — freshly-rendered KV values
  still win. Note that the separate "agent stops logging after retry
  exhaustion" diagnostic flagged in the issue is unrelated to this
  retry path and is tracked separately. (Closes #613)
- Fixed `bootroot reinit` failing immediately with
  `could not derive compose project name from` followed by a trailing
  empty string whenever `--compose-file` was left at its default relative
  `docker-compose.yml`. `Path::parent` returns `Some("")` — not `None` —
  for a relative path without a directory component, so the
  `compose_file.parent().unwrap_or(Path::new("."))` shape used by
  `reinit`, `clean --openbao-only`, the init orchestrator's `.env`
  loader and DB-password rotation, and `rotate infra-cert` all fed an
  empty path into downstream `canonicalize` / `file_name` / `.join`
  consumers. That broke the curated recovery path documented for
  partial-init failures and forced operators into the destructive
  `clean --openbao-only` + `infra install` + `init` escape hatch. The
  derivation is now funnelled through a single
  `commands::compose_file::compose_file_dir` helper that normalises the
  empty-parent case to `"."`. (Closes #611)
- Fixed `bootroot-agent` writing `ca-bundle.pem` without honoring the
  `--cert-group` policy and without re-asserting a readable mode on
  rotation. The agent now always writes the CA bundle at `0o644` and,
  when `--cert-group <gid>` is configured, `chgrp`s the bundle to the
  policy's gid on every issuance and rotation — the same treatment
  already applied to `<svc>-cert.pem` and `<svc>-key.pem`. Re-asserting
  the mode on every write also undoes any stricter mode left behind by
  an earlier writer, notably `bootroot-remote bootstrap`'s
  `write_secret_file` path which creates the bundle at `0o600`; without
  this fix, rotation overwrote the bytes but never widened the mode, so
  containerized mTLS clients hit `EACCES` on `ca-bundle.pem` at request
  time even though bring-up reported success. `0o644` is safe because
  the bundle is public trust material (issuer/CA chain PEM only, never
  private keys) — the new `CA_BUNDLE_FILE_MODE` constant documents this
  invariant. (Closes #608)
- Fixed `bootroot service add` bailing with `Parent directory not found`
  when the parent of `--agent-config`, `--cert-path`, or `--key-path`
  did not already exist. `service add` is the authoritative writer for
  those files, so requiring an out-of-band `mkdir -p` chain in sync
  with the flag values was gratuitous and was the typical first-time
  failure mode on a cold rebuild. The resolve-side gate now only
  applies to read-only inputs (`must_exist=true`); the agent-config
  parent is created at the write boundary in `local_config.rs` via
  `create_dir_all`, while cert/key parents continue to be created by
  `fs_util::write_cert_and_key` under the existing `cert_group`
  permission policy (so a `--cert-group` 0750 key parent is not
  flattened to 0755). `create_dir_all` leaves pre-existing components
  untouched, so an operator-tightened directory mode is preserved.
  `--dry-run` / `--print-only` remain side-effect-free because
  resolution does not touch the filesystem. (Closes #607)
- Fixed `bootroot init`'s second pass (the one `reinit` runs after wiping
  OpenBao) recreating the OpenBao container without its
  `openbao-exposed` compose override and dropping the non-loopback
  host-port publish mid-flow. `apply_openbao_agent_compose_override`,
  `apply_responder_compose_override`, and the inline
  responder TLS compose-up all invoked `docker compose up -d` without
  `--no-deps`, so compose re-evaluated the openbao dependency against
  a merged config that lacked the exposed override and recreated the
  container to the loopback bind. The next KV call (e.g.
  `write_ca_trust_fingerprints_with_retry`) against
  `https://<bind>:8200` then failed with `Connection refused`, blowing
  up reinit-recovery's scenario A. All three call sites now pass
  `--no-deps`; openbao is left alone, retaining the bind it was
  brought up with by `reinit`'s `infra up` step. (Part of #600)
- Fixed `bootroot reinit`'s `infra up` pass racing the OpenBao listener
  after the volume wipe and bailing with
  `OpenBao init status check failed: Connection refused`. Docker
  reports `bootroot-openbao` as Started before the OpenBao process has
  bound its listener — on the TLS-enabled non-loopback bind exercised
  by reinit-recovery, the listener typically takes several seconds to
  accept connections. `run_infra_up`'s unseal helpers
  (`auto_unseal_openbao` and `maybe_interactive_unseal`) now poll
  `/v1/sys/seal-status` until the API answers before issuing the first
  `is_initialized()` call. The same helpers also resolve the
  `secrets_dir` from `state.json` and build their `OpenBaoClient` via
  `with_local_trust`, so the post-recreate readiness probe runs over
  the same step-ca-anchored trust store as the rest of the reinit
  flow. (Part of #600)
- Fixed `bootroot service add` and `bootroot init`'s second pass (the
  one reinit runs after wiping OpenBao) failing the TLS handshake with
  `UnknownIssuer` against a TLS-enabled OpenBao bind. The CLI's
  `OpenBaoClient` constructor used webpki-roots only, so the step-ca
  private root that signs the OpenBao server cert was not trusted.
  Added `OpenBaoClient::with_local_trust(url, secrets_dir)`, which
  augments the default Mozilla webpki trust store with
  `<secrets_dir>/certs/root_ca.crt` (and
  `<secrets_dir>/certs/intermediate_ca.crt` when present) when the
  URL is `https://...` and the bundle exists, and falls back to the
  default client for HTTP (the pre-TLS loopback path) and for HTTPS
  endpoints with no local bundle (externally-trusted CAs). The local
  PEM is appended to the webpki root store rather than replacing it,
  so an externally-managed (publicly-trusted) HTTPS `OpenBao` URL
  reachable through the same state-backed code path keeps verifying
  against the public CA even after `init` has populated
  `<secrets_dir>/certs/`. The intermediate must be added as a trust
  anchor because the OpenBao TLS server cert is issued by `step
  certificate create` as a single leaf (no chain), so without the
  intermediate in the trust store rustls cannot bridge
  leaf → intermediate → root and the handshake still fails with
  `UnknownIssuer`. Wired into `service add`'s apply, preview, and
  remote-idempotent paths and into the init orchestrator so the
  post-TLS operator surface stops blackholing on the new
  `--openbao-bind` + `--openbao-tls-required` topology the
  reinit-recovery E2E exercises. `bootroot rotate` (every non-
  `infra-cert` subcommand) and `bootroot status` now go through the
  same constructor — they used `OpenBaoClient::new` and would have
  failed with `UnknownIssuer` against the same post-reinit topology.
  The reinit-recovery E2E asserts the regression by running
  `bootroot status --openbao-url https://<bind>` after each scenario.
  (Part of #600)
- Fixed `bootroot service add` leaving the per-service OpenBao Agent
  sidecar unable to render its `agent.toml` when no EAB is configured
  (e.g., `bootroot init --no-eab`, bundled OSS step-ca). The sidecar
  template references `secret/data/bootroot/services/<svc>/eab`, and
  consul-template treats a missing secret as a transient error and
  retries indefinitely (~64s with backoff), preventing the first
  render. `service add` now always writes the per-service EAB path,
  with empty `kid` / `hmac` when no global EAB is configured; the
  template's `{{ if .Data.data.kid }}` guard skips the `[eab]` block
  on empty kid so no garbage propagates to ACME. This mirrors the
  recovery path provided by `bootroot rotate eab-clear`. (Part of
  #588)
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

- `bootroot service update` now accepts the same post-renew hook flags
  as `bootroot service add` (`--reload-style`, `--reload-target`, and
  the low-level `--post-renew-command` / `--post-renew-arg` /
  `--post-renew-timeout-secs` / `--post-renew-on-failure`) so a hook
  can be retrofitted on an already-registered service without removing
  and re-adding it. Use `--reload-style none` to clear a previously
  configured hook. For `local-file` services, the managed `agent.toml`
  profile block is re-rendered in place so the new hook takes effect on
  the next agent reload / renewal. For `remote-bootstrap` services,
  `service update` updates `state.json` and prints a warning telling
  the operator to re-emit the bootstrap artifact via
  `bootroot service add` and re-run
  `bootroot-remote bootstrap --artifact <path>` on the remote host so
  the new hook lands in the remote `agent.toml`. `bootroot service add`,
  `bootroot rotate ca-key` (phase 5), and `bootroot rotate force-reissue`
  now print a per-service "Consumer reload/restart required" hint that
  lists each affected service and its post-renew hook status, and points
  services that lack a hook at the new
  `bootroot service update --reload-style ...` one-liner. `bootroot
  reinit` prints a parallel hint reminding the operator to re-register
  each consumer with `--reload-style ...` before the next renewal
  cycle. New `docs/en/operations.md` and
  `docs/en/troubleshooting.md` sections (with Korean parity) document
  the rotation in-FD pitfall — `rotate ca-key` and
  `rotate force-reissue` delete each `local-file` service's cert/key
  pair on disk and signal only the local `bootroot-agent`, so a
  consumer still serving from an open file descriptor silently keeps
  the previous leaf certificate — and provide the canonical
  AKI / SKI diagnostic and the systemd / sighup / docker-restart
  recipes. (Closes #614)
- Docker-backed E2E recovery harness for `bootroot reinit`
  (`scripts/impl/run-reinit-recovery.sh`, driven by
  `tests/docker_e2e_reinit_recovery.rs` and wired into the CI matrix
  and the extended suite). Drives a real partial-init OpenBao stack
  through all three #598 failure modes — stuck after
  `clean --openbao-only`, initialized-OpenBao-without-root-token, and
  rsync-clone stale local state — and asserts the recovery contracts
  after each scenario: step-ca root/intermediate fingerprint unchanged,
  `secrets/password.txt` not overwritten, non-loopback OpenBao bind
  preserved (compose override survives, intent persists in the
  rewritten `state.json`, post-reinit OpenBao listens on the same
  bind), and the rewritten state's service registry is empty. (Closes
  #600, Closes #598)
- `bootroot init` now accepts `--save-unseal-keys` and
  `--no-save-unseal-keys` to non-interactively answer the
  "Save unseal keys to file for automatic unseal? [y/N]" prompt,
  which was the last remaining interactive prompt on the public `init`
  surface. `--save-unseal-keys` writes the freshly generated keys to
  `<secrets_dir>/openbao/unseal-keys.txt` (mode `0600`) without
  prompting; `--no-save-unseal-keys` skips both the on-disk save and
  the cleartext-echo fallback, and requires `--summary-json <path>`
  (enforced at clap parse time) so the keys are captured in the 0600
  summary JSON instead of being lost. The two flags are mutually
  exclusive. When neither flag is set the interactive prompt (default
  `N`) is preserved, so operators see no behavior change. Reinit's
  internal auto-save path (`args.reinit_mode`) is unaffected.
  `bootroot init` also now runs the same `--summary-json` and
  `--root-token-output` preflight that `bootroot reinit` does, before
  any OpenBao work starts, so a bad output destination fails fast
  instead of being discovered post-init with the freshly issued root
  token and unseal keys already minted (recreating the partial-init
  trap `--no-save-unseal-keys` is designed to avoid through the
  summary-json recovery channel). (Closes #603)
- New `bootroot reinit` recovery command that atomically wipes
  OpenBao-owned state and re-runs init while preserving step-ca CA
  material, `password.txt`, PostgreSQL state, operator-authored compose
  overrides, and any recorded non-loopback bind intent. Covers the
  partial-init trap (init failed after OpenBao was initialised), the
  rsync-clone-to-new-host scenario, and the stuck-after-
  `clean --openbao-only` recovery path described in issue #598. With
  `--yes` the entire flow is non-interactive end-to-end: overwrite
  prompts for preserved files are suppressed, the new HTTP-01
  responder HMAC is auto-generated (the previous one lived in the
  wiped OpenBao KV mount), an absent `secrets/password.txt` (rsync-
  clone path or operator-removed) triggers non-interactive step-ca
  password generation under `reinit_mode` so `reinit --yes` never
  stalls on the step-ca password prompt (an existing `password.txt`
  is still preserved verbatim so the encrypted CA material remains
  decryptable; when `password.txt` is absent **but** any file
  `step ca init` writes — `secrets/config/ca.json`,
  `secrets/config/defaults.json`, `secrets/certs/root_ca.crt`,
  `secrets/certs/intermediate_ca.crt`,
  `secrets/secrets/root_ca_key`, or
  `secrets/secrets/intermediate_ca_key` — is still on disk, reinit
  refuses to start before any destructive operation runs. Encrypted
  CA keys are blocking because a freshly generated password cannot
  be silently written into a deployment whose `password.txt` would
  then fail to unlock the preserved CA keys; any other preserved
  `step ca init` write (the `config/` and `certs/` files above) is
  equally blocking even without encrypted key material because the
  second init pass's `step ca init` cannot complete cleanly when
  one of its targets already exists (it generates fresh cert/key
  files and then exits non-zero on TTY-bound overwrite
  confirmation), recreating the partial-init trap after OpenBao
  has already been wiped. The safe fresh-CA rebuild path remains
  open whenever every file `step ca init` writes is absent;
  otherwise the operator restores `password.txt` from a backup or
  removes every preserved step-ca artifact to opt into a clean
  rebuild),
  the EAB registration prompt is skipped, and newly
  generated unseal keys are written automatically to
  `secrets/openbao/unseal-keys.txt` (mode `0600`). The optional
  `--root-token-output <path>` is preflight-validated before any
  destructive operation begins (rejects directories, unwritable
  parents, existing world/group-readable files, and existing files
  that are not writable by the current process such as mode `0400`)
  so a bad path cannot leave the operator with a freshly reinitialised
  OpenBao plus a failed token write; if the post-init write still
  fails for any reason, the summary is printed first and the warning
  surfaces the freshly issued token on stderr in cleartext
  (prefixed with `ROOT_TOKEN=`) so it is not lost. When the
  snapshotted `openbao_bind_addr` is non-loopback and the caller left
  `--openbao-url` at its default, reinit rewrites the second `init`
  pass's client URL to the restored bind (`https://<bind>`) so the
  post-up health check reaches the TLS-enabled OpenBao without
  requiring `--openbao-url` to be re-passed. Reads the preserved
  step-ca runtime DSN from `secrets/config/ca.json` and threads it
  into the second init pass so the freshly reinitialised OpenBao KV
  receives the credentials that still match the preserved PostgreSQL
  state, instead of the dummy `rotated-use-openbao` password sitting
  in `.env` after a previous `init --enable db-provision` run. When
  the preserved `ca.json` runtime DSN is present, `reinit --enable
  db-provision` no longer trips `error_db_provision_conflict`: under
  `reinit_mode` the DSN resolver treats the snapshot-derived DSN as
  authoritative (the PostgreSQL role's password was rotated to it on
  the previous init) and skips the provisioning path so the already-
  good credential is not rotated and broken for the next rotate
  cycle. When `ca.json` is absent (rsync-clone path or a partial-
  init that crashed before `update_ca_json_with_backup` ran),
  `db-provision` behaves as in `init`. When
  the snapshot records a non-default `secrets_dir`, the snapshot
  drives all secrets-tree operations (cleanup, preserved-DSN /
  `password.txt` reads, the second init pass's `--secrets-dir`, and
  the rewritten `state.json.secrets_dir`) so a recovery does not
  silently target the wrong tree when the operator omits
  `--secrets-dir` from the reinit invocation. The pre-confirmation
  plan now echoes the snapshotted intent values themselves (effective
  `secrets_dir`, OpenBao bind/advertise, HTTP-01 admin
  bind/advertise, `infra_certs` count) so the operator can verify the
  recovery target before any destructive op runs.
  Reinit also derives the ACME provisioner name and
  `defaultTLSCertDuration` from the preserved `ca.json` so a deployment
  initialised with `bootroot init --stepca-provisioner <custom>` or a
  custom `--cert-duration` keeps those settings on the second init pass
  instead of either failing
  (`ca.json does not contain an ACME provisioner named "acme"`) or
  being silently snapped back to the default. The
  `--root-token-output` write now creates the destination atomically
  with mode `0600` via `OpenOptionsExt::mode` so a freshly minted root
  token is never observable on disk with the process umask's default
  permissions between create and chmod.
  Rejects any explicit `--openbao-url` value: only the CLI default is
  accepted, so reinit cannot wipe local state and then operate on an
  external endpoint. Legitimate non-loopback recovery is driven by the
  snapshotted `openbao_bind_addr` rewrite above. The `--summary-json`
  destination is also preflight-checked before any destructive
  operation (rejects directories, unwritable existing files, and
  uncreatable/read-only parents), so an unwritable summary path
  cannot recreate the partial-init trap by short-circuiting
  `print_init_summary`, `--root-token-output`, and the automatic
  unseal-key save when the post-init JSON write fails.
  Refuses to run against external/shared OpenBao instances
  (compose-managed local only). A container that exists but is
  missing either compose label
  (`com.docker.compose.project`,
  `com.docker.compose.service`) is rejected explicitly: the scope
  check now distinguishes "container missing" (the stuck-after-
  `clean --openbao-only` recovery path) from "container exists but
  cannot be proven to belong to this work directory's compose
  project" via a separate `docker container inspect` existence
  probe.
  When the `bootroot-openbao` container is absent (typically the
  stuck-after-`clean --openbao-only` recovery path), volume removal
  now honours `COMPOSE_PROJECT_NAME` so the `<env>_openbao-data`
  volume that the follow-up `docker compose up` will recreate is the
  same one reinit wipes. Previously the basename-fallback would have
  removed `<compose-dir-basename>_openbao-data` while `infra up`
  recreated `<env>_openbao-data`, leaving the real env-selected
  volume intact and recreating the initialized-without-root-token
  failure mode this command is meant to recover from. The container
  label (when present) still wins over the env var because it is
  authoritative for what was physically created on disk.
- Added `--cert-group <gid-or-name>` to `bootroot service add` and
  `bootroot service update` so issued service certificates can be
  delivered to non-root containerized clients without operator-side
  `chmod` workarounds. When set, the agent applies a group-readable
  policy on every issuance and rotation: parent directories become
  `0750` (or `0755` for a distinct cert parent), `<svc>-key.pem`
  becomes `0640`, `<svc>-cert.pem` stays at `0644`, and group
  ownership of all four is set to the configured gid. When unset
  (the default), the historical operator-only modes
  (`0700`/`0600`/`0644`) are preserved so existing deployments are
  unchanged. `cert_group_gid` is persisted on `ServiceEntry`,
  rendered into the managed `agent.toml` profile block, threaded
  through the remote-bootstrap artifact as a new optional field
  (no `schema_version` bump — additive change with
  `skip_serializing_if`), and surfaced on `DaemonProfileSettings`,
  so rotation re-asserts the policy instead of silently reverting
  to operator-only.
  `local-file` deployments accept either a numeric gid or a group
  name resolved on the control host; `remote-bootstrap` deployments
  accept numeric form only because the control host's NSS may differ
  from the remote agent host's. `service add` validates that the
  caller can `chown` to the target gid for `local-file` mode so the
  failure surfaces at add-time rather than at the next rotation.
  `service update --cert-group ...` re-renders the local managed
  profile block immediately for `local-file` services, and warns the
  operator to re-emit the bootstrap artifact for `remote-bootstrap`
  services. The local-file re-render runs before `state.json` is
  persisted, and re-runs of the same `--cert-group` value re-trigger
  the re-render — so a previously-failed re-render can be repaired
  by simply re-running the command, without `state.json` ever
  drifting ahead of the on-disk managed profile.
  `--cert-group 0` (root) is rejected at parse time and during
  config validation. `cert_group_gid` is also rejected when it does
  not resolve in the cert-writing host's group database
  (`getgrgid_r`): this orphan-gid case (a numeric gid that exists on
  a different host — e.g. the container's runtime user — but not on
  the host that will actually `chown` the cert/key files) is checked
  at `service add` / `service update` time on the control host for
  `local-file`, at `bootroot-remote bootstrap` time on the remote
  agent host for `remote-bootstrap`, and again at `bootroot-agent`
  config validation, so it surfaces as a loud failure instead of
  passing the kernel `chown` and reappearing as EACCES inside the
  consumer. The key file is written via stage-then-rename
  (sibling temp file created with `O_CREAT|O_EXCL` and `mode=0600`,
  `chown`d, promoted to `0640`, then renamed over the destination)
  so the destination path is never observable at a mode wider than
  the final policy — no umask-derived `0644` window before the
  clamp, and no group-readable window under the operator's primary
  gid before the chown lands. The shared cert/key parent detection
  uses kernel `(dev, ino)` identity rather than textual path
  equality, so spellings like `certs` vs `certs/.` cannot trick
  `ensure_cert_parent_dir` into widening a shared key parent from
  `0750` to `0755`. (Closes #593)
- Added a non-interactive operation surface for CI/scripted rotations
  (Closes #587):
  - `bootroot rotate --yes`/`-y` is now a global flag accepted at any
    position under `rotate` (e.g. `rotate force-reissue --yes` works in
    addition to the original `rotate --yes force-reissue`).
  - `--root-token-file <path>` on every `rotate` subcommand reads the
    OpenBao root token from a file. Resolution order is
    `--root-token-file` > `--root-token` > `OPENBAO_ROOT_TOKEN` env >
    interactive prompt. Combining `--root-token-file` with an explicit
    `--root-token` CLI flag is a parse-time error; the env-vs-flag
    distinction is enforced via clap so an env-injected token does not
    falsely trip the conflict check. The file must not be world-readable
    (`0o644` is rejected with a `chmod 0600` hint); group-readable
    (`0o640`) is permitted for shared CI/operator groups.
  - `bootroot rotate force-reissue --wait` now also covers
    `daemon + local-file` services. It captures the cert serial before
    `delete + signal`, then polls `paths.cert` (serial as the primary
    success signal, mtime as a tiebreaker for the rare same-serial
    reissue case) until the change is observed or `--wait-timeout`
    expires. The polling cadence is shared with the existing
    `remote-bootstrap` path so `--wait-timeout` semantics are identical
    across delivery modes.
  - `--post-renew-arg` on both `bootroot service add` and
    `bootroot-remote bootstrap` now sets `allow_hyphen_values = true`,
    so `--post-renew-arg -HUP` parses without forcing the `=` form.
- `bootroot init --enable db-provision` now grants `CREATE, USAGE` on
  the `public` schema to the role it provisions, closing the PG15+
  step-ca crashloop described in #588 §1 (`permission denied for
  schema public` on first `CREATE TABLE`). Ownership stays with
  `postgres`. The grant runs on every db-provision call (idempotent),
  so re-running `init --enable db-provision` on a stale install where
  the role and DB already exist is now a recovery path. When
  `admin_user == db_user` (the bundled compose topology where
  `POSTGRES_USER` and `--db-user` are both `step`), the post-ALTER
  reconnect uses the freshly-set `db_password` rather than the
  admin DSN's now-stale password — the ALTER changed the admin's own
  password, so the second connection has to follow. (#588)
- `bootroot init` persists the admin DSN it used to provision the
  runtime role/database to a new high-privilege OpenBao KV path
  (`bootroot/stepca/db_admin`). `bootroot rotate db` now reads from
  that path so the operator no longer has to pass `--db-admin-dsn`
  on every rotation; the existing `--db-admin-dsn` flag remains as
  an override for externally-managed admin credentials. `rotate db`
  no longer falls back to `ca.json.db.dataSource`, which holds the
  *runtime* (`stepca`) DSN — using it as an admin DSN was the
  original §2 self-ALTER bug. When neither the flag nor KV is
  available, the command fails fast with a message naming both
  recovery paths. When `admin_user == db_user` (the bundled compose
  topology where `POSTGRES_USER` and `--db-user` are both `step`),
  the persisted admin DSN is rebuilt with the freshly-set
  `db_password` so a later `rotate db` reading from KV does not
  authenticate with the pre-ALTER password. The same rebuild now
  also runs at the end of `rotate db` itself (KV-backed path only):
  after `provision_db_sync` ALTERs the role's password, the
  persisted admin DSN at `bootroot/stepca/db_admin` is rewritten
  with the new credential, preventing a stale-after-first-rotation
  failure on the *next* `rotate db`. The same rebuild also runs at
  the end of `init`'s post-bootstrap `.env` password rotation so
  that the persisted admin DSN reflects the post-rotation password
  before any `rotate db` ever runs; in addition, that rotation now
  resolves the host-side Postgres port from the compose dir's
  `.env`/process env (same precedence Docker Compose uses for the
  `${POSTGRES_HOST_PORT:-5433}` mapping) instead of reusing the
  compose-internal port from `ca.json`, which would otherwise
  silently skip the rotation on the new 5433 default. The
  auto-derived admin DSN built by `init --enable db-provision`
  from compose `.env` (`POSTGRES_USER`/`POSTGRES_PASSWORD`) now
  also follows the same `${POSTGRES_HOST_PORT:-5433}` precedence
  for its port and defaults its host to `127.0.0.1` (the binary
  runs from the host, not inside the compose network). The prior
  `postgres:5432` defaults caused `provision_db_sync` to fail
  before reaching the §1 PG15 schema grant whenever the operator
  did not pass `--db-admin-dsn` on the new 5433-default install
  or set a non-default `--postgres-host-port`. `POSTGRES_HOST` /
  `POSTGRES_PORT` remain explicit overrides for operator-supplied
  topologies. (#588)
- `bootroot init --no-eab` skips the EAB prompt and persists no EAB
  credentials. Recommended for OSS step-ca and CI flows. The
  interactive EAB prompt now validates inputs (non-empty `kid`,
  base64url-decodable `hmac` of at least 16 bytes) and re-prompts
  on failure instead of silently accepting `y` of length 1. (#588)
- `bootroot rotate eab-clear` writes empty `{kid: "", hmac: ""}` to
  every known EAB KV path and refreshes each affected sidecar so the
  templated `agent.toml` drops its `[eab]` block on the next cycle.
  Companion to the now-removed `rotate eab`. Local-file sidecar
  refresh failures are now fatal: the command attempts every
  service's KV write and refresh, then exits non-zero with the list
  of services whose sidecars are still rendering the old EAB so the
  operator does not silently leave §6's stale-render symptom in
  place. (#588)
- `bootroot infra install` runs a TCP bind preflight on every
  host-side port the active compose stack publishes (`postgres`,
  `openbao`, `step-ca`, `bootroot-http01`) before invoking `docker
  compose up`. On collision it aborts with the busy port, a
  best-effort PID/command hint via `lsof`, and the recommended
  remediation, instead of leaving partial containers running after
  one published port fails to bind. The preflight always checks
  the localhost ports because `infra install` invokes `docker
  compose up` against the base compose file only — the
  `--openbao-bind` / `--http01-admin-bind` override files are
  recorded for `infra up` / `init` but are not layered into the
  install-time `up`, so the install-time bind is on `127.0.0.1`
  regardless of any recorded override intent. (#588)
- `bootroot infra install --postgres-host-port <N>` overrides
  `POSTGRES_HOST_PORT` in `.env` *and* in the docker compose
  subprocess environment so scripted bootstraps no longer need an
  out-of-band file edit between commands; without the env override
  Docker Compose's "shell env wins over `.env`" precedence would
  silently publish the inherited port instead of the flag value.
  (#588)
- `bootroot init` detects a partial-init OpenBao state (initialised
  but no usable root token) and emits an actionable diagnostic
  naming the three recovery paths instead of bubbling up the opaque
  `403 permission denied`. (#588)
- `bootroot clean --openbao-only` removes only the `bootroot-openbao`
  container and its volume, leaving every other compose service,
  `secrets/`, `state.json`, and `.env` intact. (#588)
- `bootroot service openbao-sidecar refresh --service-name <name>`
  restarts the per-service `OpenBao` Agent sidecar so consul-template
  re-reads its KV sources after operator-side KV maintenance. (#588)
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

- The published `PostgreSQL` host port now defaults to **5433**
  (`POSTGRES_HOST_PORT=5433`) so bootroot does not claim the
  conventional 5432 out of the box. The conventional port stays free
  for an application-managed `PostgreSQL` instance. Operators who
  explicitly set `POSTGRES_HOST_PORT=5432` are unaffected; ones who
  relied on the implicit 5432 default will see the published port
  move on the next `infra install`. The internal `postgres:5432`
  container address is unchanged, so step-ca's compose-internal DSN
  is not affected. (#588)
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
