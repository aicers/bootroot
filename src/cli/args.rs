use std::path::PathBuf;

use clap::{ArgGroup, ValueEnum};
use clap::{Args, Parser, Subcommand};

use crate::commands::init::{
    DEFAULT_CERT_DURATION, DEFAULT_COMPOSE_FILE, DEFAULT_KV_MOUNT, DEFAULT_OPENBAO_URL,
    DEFAULT_SECRETS_DIR, DEFAULT_STEPCA_PROVISIONER, SECRET_ID_TTL,
};
use crate::state::{DeliveryMode, DeployType, HookFailurePolicyEntry};

const INFRA_AFTER_HELP: &str = "\
Teardown:
  This command brings the stack up or installs it; it does not tear it
  down. Use `bootroot clean` (top-level) to stop the compose stack and
  wipe `secrets/`, `state.json`, `.env`, and (optionally) `certs/`.
  Run `bootroot clean --help` for details.";

const CLEAN_LONG_ABOUT: &str = "\
Tears down the bootroot stack and wipes its filesystem state.

Without flags, `bootroot clean`:
  - runs `docker compose down -v --remove-orphans` against the main
    compose file plus any auto-discovered openbao-agent sidecar and
    `openbao-exposed` overrides under `secrets/openbao/`;
  - removes `secrets/`, `state.json`, and `.env`;
  - prompts before removing `certs/` (or removes it without prompting
    when `--yes` is given).

Pass `--openbao-only` to wipe just the `bootroot-openbao` container and
its named volumes (recovery from a partial-init OpenBao state); every
other compose service, `secrets/`, `state.json`, and `.env` stay
intact.";

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Operator CLI for the bootroot certificate and secret control plane",
    long_about = None,
)]
pub(crate) struct Cli {
    /// Language for CLI output (en or ko)
    #[arg(long, env = "BOOTROOT_LANG", default_value = "en", global = true)]
    pub(crate) lang: String,

    #[command(subcommand)]
    pub(crate) command: CliCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum CliCommand {
    /// Manages the infrastructure compose stack (`OpenBao`, `PostgreSQL`,
    /// step-ca, HTTP-01 responder).
    #[command(subcommand, after_help = INFRA_AFTER_HELP)]
    Infra(InfraCommand),
    /// Manages the optional Prometheus/Grafana monitoring stack.
    #[command(subcommand)]
    Monitoring(MonitoringCommand),
    /// Initializes a fresh bootroot stack: provisions `OpenBao`, step-ca,
    /// `PostgreSQL`, and the HTTP-01 responder.
    ///
    /// Runs end-to-end on an empty host: starts the compose stack,
    /// initializes and unseals `OpenBao`, provisions the step-ca PKI,
    /// renders operator-facing secrets and config under `secrets/`, and
    /// records the resulting deployment intent in `state.json`. When only
    /// `OpenBao`-owned state needs to be re-initialized, use `bootroot
    /// reinit` instead.
    Init(Box<InitArgs>),
    /// Recovers from a partial-init `OpenBao` state by wiping
    /// `OpenBao`-owned state and re-running init while preserving step-ca
    /// material, the operator's compose overrides, and recorded
    /// deployment intent (non-loopback binds).
    Reinit(Box<ReinitArgs>),
    /// Reports the runtime health of the bootroot infrastructure stack
    /// and its registered services.
    ///
    /// Inspects compose-stack container state, `OpenBao` seal/unseal
    /// status, step-ca reachability, and the registered service inventory
    /// in `state.json`. Read-only; safe to run at any time.
    Status(Box<StatusArgs>),
    /// Registers and manages bootroot-agent-driven service consumers and
    /// their per-service `OpenBao` Agent sidecars.
    #[command(subcommand)]
    Service(ServiceCommand),
    /// Verifies that a registered service's bootroot-agent configuration
    /// is internally consistent and reaches the control plane.
    ///
    /// Cross-checks the rendered `agent.toml`, the corresponding
    /// `state.json` entry, and the bootroot-agent binary itself. With
    /// `--db-check`, also confirms that the runtime DSN in `ca.json`
    /// authenticates against `PostgreSQL`.
    ///
    /// Not read-only: under the hood this invokes `bootroot-agent
    /// --oneshot`, which performs a full ACME issuance/renewal pass for
    /// every configured profile (writing the leaf cert and key back to
    /// disk and running any configured post-renew hooks) before the
    /// rendered-file and bundle checks run. Treat each invocation as a
    /// real issuance against step-ca.
    Verify(VerifyArgs),
    /// Rotates infrastructure secrets, keys, and certificates managed by
    /// bootroot.
    ///
    /// Subcommands cover distinct rotation surfaces (step-ca password,
    /// `PostgreSQL` password, HTTP-01 responder HMAC, `AppRole`
    /// `secret_id`, `OpenBao` recovery credentials, CA key,
    /// infrastructure TLS certs, EAB credentials, trust-bundle sync).
    /// Side effects vary per subcommand — most write to `OpenBao` KV
    /// and/or rendered config and restart the relevant container, while
    /// only `infra-cert` persists changes back to `state.json`. See each
    /// subcommand's `--help` for its exact contract.
    Rotate(RotateArgs),
    /// Tears down the bootroot stack and wipes its filesystem state
    /// (`secrets/`, `state.json`, `.env`, and — with confirmation or
    /// `--yes` — `certs/`).
    #[command(long_about = CLEAN_LONG_ABOUT)]
    Clean(CleanArgs),
    /// Manages `OpenBao` operator material outside the regular init and
    /// rotate flows.
    ///
    /// Currently covers persisting and deleting the on-disk
    /// `unseal-keys.txt` file under `secrets/openbao/`. Intended for
    /// post-init operator workflows; routine bootstrap is handled by
    /// `bootroot init`'s `--save-unseal-keys` / `--no-save-unseal-keys`
    /// flags.
    #[command(subcommand)]
    Openbao(OpenbaoCommand),
    /// Manages step-ca configuration that bootroot controls.
    ///
    /// Currently scoped to the ACME provisioner's
    /// `defaultTLSCertDuration` and to restarting the step-ca container
    /// so a configuration change takes effect.
    #[command(subcommand)]
    Ca(CaCommand),
}

#[derive(Subcommand, Debug)]
pub(crate) enum CaCommand {
    /// Updates step-ca `defaultTLSCertDuration`.
    ///
    /// `cert-duration` must be strictly greater than the daemon's
    /// default `renew_before` (16h) — the same conservative guardrail
    /// `bootroot init` applies. The control plane does not read
    /// `agent.toml`; ensuring per-agent `renew_before` consistency
    /// remains the operator's responsibility.
    Update(CaUpdateArgs),
    /// Restarts the step-ca container so it picks up a configuration
    /// change such as a new `defaultTLSCertDuration`.
    Restart(CaRestartArgs),
}

#[derive(Args, Debug)]
pub(crate) struct CaUpdateArgs {
    #[command(flatten)]
    pub(crate) secrets_dir: SecretsDirArgs,

    /// step-ca ACME provisioner name whose `claims.defaultTLSCertDuration`
    /// is updated
    #[arg(long, default_value = DEFAULT_STEPCA_PROVISIONER)]
    pub(crate) stepca_provisioner: String,

    /// New `defaultTLSCertDuration` value (e.g. `24h`, `48h`).
    ///
    /// Must be strictly greater than the daemon's default
    /// `renew_before` (16h) — otherwise every newly issued certificate
    /// is flagged for immediate renewal. Per-agent `renew_before`
    /// consistency is the operator's responsibility.
    #[arg(long)]
    pub(crate) cert_duration: String,
}

#[derive(Args, Debug)]
pub(crate) struct CaRestartArgs {
    #[command(flatten)]
    pub(crate) compose_file: ComposeFileArgs,
}

#[derive(Subcommand, Debug)]
pub(crate) enum InfraCommand {
    /// Starts the bootroot compose stack from the existing `secrets/`
    /// and `state.json`.
    ///
    /// Use this on a host that has already been initialized (`bootroot
    /// init` has been run and `secrets/`, `state.json`, and `.env` are
    /// present). For first-time setup use `bootroot init`; for recovering
    /// from a partial init use `bootroot reinit`.
    Up(InfraUpArgs),
    /// Installs the bootroot compose stack: writes restart-policy
    /// overrides, optionally re-binds `OpenBao` and the HTTP-01 admin
    /// API to non-loopback addresses, and brings the stack up.
    ///
    /// `--openbao-bind` and `--http01-admin-bind` require explicit TLS
    /// acknowledgement (`--openbao-tls-required`,
    /// `--http01-admin-tls-required`) and, for wildcard binds, separate
    /// `--*-bind-wildcard` and `--*-advertise-addr` flags. These are
    /// deliberate guardrails — see issue #588 for the rationale.
    Install(InfraInstallArgs),
}

#[derive(Subcommand, Debug)]
pub(crate) enum OpenbaoCommand {
    /// Persists `OpenBao` unseal keys to
    /// `<secrets_dir>/openbao/unseal-keys.txt` (mode `0600`).
    ///
    /// Useful when an operator initially declined to save the keys at
    /// init time and later decides to keep them on disk. The command
    /// interactively prompts for the unseal key threshold and the
    /// matching number of key shares — the operator must paste each
    /// share at the prompt — then writes the file atomically.
    SaveUnsealKeys(OpenbaoSaveUnsealKeysArgs),
    /// Deletes the on-disk `OpenBao` unseal-keys file under
    /// `<secrets_dir>/openbao/`.
    ///
    /// Intended for operators who initially saved the keys for
    /// convenience and now want to remove them from the host. Does not
    /// rotate the keys themselves; combine with `bootroot rotate
    /// openbao-recovery --rotate-unseal-keys` for that.
    DeleteUnsealKeys(OpenbaoDeleteUnsealKeysArgs),
}

#[derive(Subcommand, Debug)]
pub(crate) enum MonitoringCommand {
    /// Starts the Prometheus/Grafana monitoring stack with the chosen
    /// exposure profile.
    ///
    /// `lan` binds to `GRAFANA_LAN_BIND_ADDR` (default `127.0.0.1`);
    /// `public` binds to all interfaces (`0.0.0.0:3000`). The Grafana
    /// admin password defaults to `admin` on first boot and is only
    /// applied then; pass `--grafana-admin-password` before the first
    /// `monitoring up`, or run `monitoring down
    /// --reset-grafana-admin-password` to clear the Grafana volume
    /// before reseeding it. If monitoring is already running, this
    /// command is a no-op (no password change is applied).
    Up(MonitoringUpArgs),
    /// Reports the running state of the monitoring stack containers.
    Status(MonitoringStatusArgs),
    /// Stops the monitoring stack.
    ///
    /// `--reset-grafana-admin-password` clears the persisted Grafana
    /// admin password so that the next `monitoring up` reseeds it from
    /// the default or from a freshly supplied
    /// `--grafana-admin-password`.
    Down(MonitoringDownArgs),
}

#[derive(Subcommand, Debug)]
pub(crate) enum ServiceCommand {
    /// Registers a new bootroot-agent-managed service.
    ///
    /// Generates the service's `OpenBao` `AppRole` and `secret_id`,
    /// renders the agent's `agent.toml` baseline, and records the
    /// deployment intent in `state.json`. For Docker deployments with a
    /// `--container-name`, also classifies the supplied bootroot-agent
    /// container against the expected identity (skip with
    /// `--no-validate-agent`); daemon deployments have no container to
    /// validate. Use `--dry-run` to preview the diff or `--print-only`
    /// to emit the manual snippets without writing files.
    Add(Box<ServiceAddArgs>),
    /// Prints the registered configuration and `OpenBao` `AppRole`
    /// metadata for a service.
    ///
    /// Read-only; safe to run at any time. The output covers deploy type,
    /// hostname, domain, delivery mode, post-renew hooks, the `AppRole`
    /// role name and `role_id`, `secret_id` TTL / wrap TTL / token-bound
    /// CIDRs, the rendered agent config / cert / key / `secret_id` paths,
    /// the service's `OpenBao` KV path, and the next-step sidecar
    /// snippet. The `AppRole` `secret_id` itself is never printed.
    Info(ServiceInfoArgs),
    /// Edits a registered service's `secret_id` policy, post-renew hook,
    /// or cert ownership in place.
    ///
    /// Lets the operator adjust `secret_id` TTL, wrap TTL, or CIDR
    /// binding; swap the reload-style preset; or change `--cert-group`
    /// without having to remove and re-add the service. See issue #614
    /// for the in-FD reload pitfall this guards against.
    Update(ServiceUpdateArgs),
    /// Deregisters a service and tears down its `OpenBao` material.
    ///
    /// Removes the service's `AppRole`, policy, and per-service KV paths
    /// (by the names stored in `state.json`), refreshes the
    /// `bootroot-http01` responder's HTTP-01 alias set to drop the
    /// service, and finally removes the `state.json` entry. Remote
    /// cleanup runs first and the entry is dropped last, so a partial
    /// failure leaves the entry (and its stored role/policy names) for a
    /// safe re-run. On-disk cert/key/agent config are preserved unless
    /// `--delete-artifacts` is passed. This makes the "remove and re-add"
    /// flow — the supported way to change a service's `--delivery-mode` —
    /// an actual command. Use `--dry-run` to preview the teardown plan.
    Remove(ServiceRemoveArgs),
    /// Manages the per-service `OpenBao` Agent sidecar container.
    #[command(subcommand, name = "openbao-sidecar")]
    OpenbaoSidecar(ServiceOpenbaoSidecarCommand),
    /// Deprecated alias for `openbao-sidecar`.  Will be removed in a
    /// future release; use `service openbao-sidecar` instead.
    #[command(subcommand, hide = true)]
    Agent(ServiceOpenbaoSidecarCommand),
}

#[derive(Subcommand, Debug)]
pub(crate) enum ServiceOpenbaoSidecarCommand {
    /// Starts the per-service `OpenBao` Agent sidecar container.
    ///
    /// The sidecar runs `openbao agent` against a generated HCL config
    /// whose `template` blocks render the managed `agent.toml` and trust
    /// material from `OpenBao` KV into files under the host secrets
    /// directory, which is bind-mounted into the container (not a tmpfs
    /// volume). The template blocks specify only `source`, `destination`,
    /// and `perms` — the sidecar itself does not signal the consumer on
    /// re-render; consumer reload is the bootroot-agent's responsibility
    /// via its post-renew hooks. The Docker network is auto-discovered
    /// from `bootroot-openbao`'s compose project label unless
    /// `--openbao-network` is supplied.
    Start(ServiceOpenbaoSidecarStartArgs),
    /// Restarts the per-service `OpenBao` Agent sidecar so it re-reads
    /// KV templates after operator-side KV maintenance.
    Refresh(ServiceOpenbaoSidecarRefreshArgs),
}

#[derive(Args, Debug)]
pub(crate) struct ServiceOpenbaoSidecarStartArgs {
    /// Service name identifier
    #[arg(long)]
    pub(crate) service_name: String,

    #[command(flatten)]
    pub(crate) compose_file: ComposeFileArgs,

    /// Docker network the sidecar should attach to.
    ///
    /// When omitted, the network is discovered from the
    /// `bootroot-openbao` container's compose project label
    /// (`<project>_default`). Required when `OpenBao` runs outside
    /// bootroot's compose file (separate host, kubernetes, managed
    /// service, etc.).
    #[arg(long)]
    pub(crate) openbao_network: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct ServiceOpenbaoSidecarRefreshArgs {
    /// Service name identifier
    #[arg(long)]
    pub(crate) service_name: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct OpenBaoArgs {
    /// `OpenBao` API URL
    #[arg(long, default_value = DEFAULT_OPENBAO_URL)]
    pub(crate) openbao_url: String,

    /// `OpenBao` KV mount path (KV v2)
    #[arg(long, default_value = DEFAULT_KV_MOUNT)]
    pub(crate) kv_mount: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct OpenBaoOverrideArgs {
    /// `OpenBao` API URL override
    #[arg(long)]
    pub(crate) openbao_url: Option<String>,

    /// `OpenBao` KV mount path override (KV v2)
    #[arg(long)]
    pub(crate) kv_mount: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ComposeFileArgs {
    /// Path to docker-compose.yml
    #[arg(long, default_value = DEFAULT_COMPOSE_FILE)]
    pub(crate) compose_file: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct SecretsDirArgs {
    /// Secrets directory to render files into
    #[arg(long, default_value = DEFAULT_SECRETS_DIR)]
    pub(crate) secrets_dir: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct SecretsDirOverrideArgs {
    /// Secrets directory override
    #[arg(long)]
    pub(crate) secrets_dir: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct RootTokenArgs {
    /// `OpenBao` root token
    #[arg(long, env = "OPENBAO_ROOT_TOKEN")]
    pub(crate) root_token: Option<String>,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthMode {
    Auto,
    Root,
    Approle,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReloadStyle {
    /// Send SIGHUP to a process by name
    Sighup,
    /// Reload a systemd unit
    Systemd,
    /// Restart a Docker container
    DockerRestart,
    /// No post-renew hook
    None,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookFailurePolicyArg {
    Continue,
    Stop,
}

impl HookFailurePolicyArg {
    pub(crate) fn into_entry(self) -> HookFailurePolicyEntry {
        match self {
            Self::Continue => HookFailurePolicyEntry::Continue,
            Self::Stop => HookFailurePolicyEntry::Stop,
        }
    }
}

#[derive(Args, Debug, Clone)]
pub(crate) struct RuntimeAuthArgs {
    /// Runtime authentication mode (`auto`, `root`, `approle`)
    #[arg(long, value_enum, default_value = "auto")]
    pub(crate) auth_mode: AuthMode,

    /// `OpenBao` root token (CLI flag only).
    ///
    /// Resolution order: `--root-token-file` (if set, must not be combined
    /// with `--root-token`) > `--root-token` (CLI) > `OPENBAO_ROOT_TOKEN`
    /// env > interactive prompt.
    #[arg(long)]
    pub(crate) root_token: Option<String>,

    /// Path to file containing `OpenBao` root token.
    ///
    /// File takes precedence over `OPENBAO_ROOT_TOKEN` env, but errors when
    /// combined with an explicit `--root-token` CLI flag. The file must not
    /// be other-readable (mode `0o644` is rejected; use `chmod 0600 <path>`).
    #[arg(long, conflicts_with = "root_token")]
    pub(crate) root_token_file: Option<PathBuf>,

    /// `OpenBao` `AppRole` `role_id`
    #[arg(long, env = "OPENBAO_APPROLE_ROLE_ID")]
    pub(crate) approle_role_id: Option<String>,

    /// `OpenBao` `AppRole` `secret_id`
    #[arg(long, env = "OPENBAO_APPROLE_SECRET_ID")]
    pub(crate) approle_secret_id: Option<String>,

    /// Path to file containing `OpenBao` `AppRole` `role_id`
    #[arg(long, env = "OPENBAO_APPROLE_ROLE_ID_FILE")]
    pub(crate) approle_role_id_file: Option<PathBuf>,

    /// Path to file containing `OpenBao` `AppRole` `secret_id`
    #[arg(long, env = "OPENBAO_APPROLE_SECRET_ID_FILE")]
    pub(crate) approle_secret_id_file: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct DbAdminDsnArgs {
    /// `PostgreSQL` admin DSN for provisioning
    #[arg(long = "db-admin-dsn", env = "BOOTROOT_DB_ADMIN_DSN")]
    pub(crate) admin_dsn: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct DbTimeoutArgs {
    /// DB connectivity timeout in seconds
    #[arg(long = "db-timeout-secs", default_value_t = 2)]
    pub(crate) timeout_secs: u64,
}

#[derive(Args, Debug)]
pub(crate) struct RotateArgs {
    #[command(subcommand)]
    pub(crate) command: RotateCommand,

    /// Path to state.json
    #[arg(long)]
    pub(crate) state_file: Option<PathBuf>,

    #[command(flatten)]
    pub(crate) compose: ComposeFileArgs,

    #[command(flatten)]
    pub(crate) openbao: OpenBaoOverrideArgs,

    #[command(flatten)]
    pub(crate) secrets_dir: SecretsDirOverrideArgs,

    #[command(flatten)]
    pub(crate) runtime_auth: RuntimeAuthArgs,

    /// Skip confirmation prompts
    #[arg(long, short = 'y', global = true)]
    pub(crate) yes: bool,

    /// Show secrets in plaintext instead of masking them
    #[arg(long)]
    pub(crate) show_secrets: bool,
}

#[derive(Subcommand, Debug)]
pub(crate) enum RotateCommand {
    /// Rotates step-ca's encryption-key password and re-renders
    /// `password.txt`.
    ///
    /// The new password is staged as `<secrets_dir>/password.txt.new`,
    /// recorded in `OpenBao` KV, and the `OpenBao` Agent re-renders the
    /// final `<secrets_dir>/password.txt` (mode `0600`) before step-ca
    /// is restarted so the new password takes effect.
    StepcaPassword(RotateStepcaPasswordArgs),
    /// Rotates the `PostgreSQL` password used by step-ca and rewrites
    /// the runtime DSN.
    ///
    /// Alters the role's password in `PostgreSQL`, rewrites the runtime
    /// DSN in `ca.json` and `OpenBao` KV, and restarts step-ca so the
    /// new DSN takes effect. Requires an admin DSN capable of altering
    /// the step-ca role; resolved from `--db-admin-dsn` first and
    /// otherwise from `bootroot/stepca/db_admin` in `OpenBao` KV.
    /// Supply the flag to override the KV value, or when running with
    /// an `AppRole` token whose policy excludes `db_admin`.
    Db(RotateDbArgs),
    /// Rotates the HTTP-01 responder HMAC secret.
    ///
    /// Replaces the shared HMAC used by the HTTP-01 admin API on both
    /// the responder and on every client (`OpenBao` KV templates and
    /// rendered config). Restarts the `OpenBao` Agent renderer so the
    /// new HMAC is written to disk, then signals the responder with
    /// SIGHUP via `docker compose kill -s HUP` when the compose file
    /// includes the responder service so it reloads the new value
    /// without dropping in-flight challenges.
    ResponderHmac(RotateResponderHmacArgs),
    /// Rotates `OpenBao` recovery credentials manually.
    ///
    /// `--rotate-unseal-keys` requires existing unseal keys. The operator must
    /// provide at least the configured unseal threshold number of key shares
    /// (for example, 3 of 5). If existing unseal keys are lost, unseal key
    /// rotation is impossible and the operator must re-initialize `OpenBao`
    /// (which implies re-running `bootroot init` and re-bootstrapping
    /// services).
    ///
    /// `--rotate-root-token` can run without unseal key input.
    #[command(name = "openbao-recovery")]
    OpenBaoRecovery(RotateOpenBaoRecoveryArgs),
    /// Rotates the `OpenBao` `AppRole` `secret_id` for one registered
    /// service or one infra role (`--infra stepca|responder`).
    ///
    /// Generates a fresh `secret_id` on the configured `AppRole`. For
    /// local-file services, writes it atomically to the on-disk
    /// `secret_id` file and reloads the local `OpenBao` Agent so the new
    /// credential takes effect. For remote-bootstrap services, publishes
    /// it to the service's KV bootstrap path so the next bootroot-agent
    /// cycle picks it up. For infra targets, writes the `secret_id` file
    /// under `<secrets_dir>/openbao/<name>/` and restarts the matching
    /// `openbao-agent-stepca` / `openbao-agent-responder` sidecar. The
    /// previous `secret_id` is not explicitly revoked; it remains valid
    /// until it expires under the `AppRole`'s configured TTL.
    ///
    /// Service targets expect `bootroot-runtime-rotate-role` credentials;
    /// infra targets expect `bootroot-infra-rotate-role` credentials.
    /// Running an infra rotation with the root token additionally
    /// provisions `bootroot-infra-rotate-role` when it does not exist yet
    /// (upgrade path for deployments initialized before that role).
    #[command(name = "approle-secret-id")]
    AppRoleSecretId(RotateAppRoleSecretIdArgs),
    /// Republishes the current step-ca trust material to every
    /// registered service via `OpenBao` KV.
    ///
    /// Reads the mounted root/intermediate certificates from disk,
    /// computes their fingerprints and the combined CA bundle, and
    /// writes them unconditionally to each registered service's
    /// `OpenBao` KV trust path. Does not restart step-ca, does not
    /// compare against `state.json`, and does not detect drift — every
    /// run rewrites the KV entries.
    #[command(name = "trust-sync")]
    TrustSync(RotateTrustSyncArgs),
    /// Forces a registered service to re-issue its certificate on the
    /// next bootroot-agent cycle.
    ///
    /// For local-file services, removes the existing cert and key files
    /// on disk and signals the local bootroot-agent so it issues a fresh
    /// pair on its next cycle. For remote-bootstrap services, writes a
    /// versioned reissue request to the service's `OpenBao` KV path so
    /// the remote agent picks it up. With `--wait`, blocks until the
    /// agent has applied the reissue (bounded by `--wait-timeout`). Use
    /// when a certificate must be re-keyed out of band — for example
    /// after a private-key compromise scare.
    #[command(name = "force-reissue")]
    ForceReissue(RotateForceReissueArgs),
    /// Rotates step-ca's intermediate signing key (and, with `--full`,
    /// the root signing key).
    ///
    /// Issues a new intermediate (and optionally root) key, then drives
    /// reissuance for **local-file** services directly: the control
    /// plane removes their existing cert and key files and signals the
    /// local bootroot-agent to reissue on its next cycle. For
    /// **remote-bootstrap** services the control plane only prints an
    /// instruction to run `bootroot-remote bootstrap` on the service
    /// host; their reissuance is the operator's responsibility and is
    /// not verified by the finalize phase (remote-bootstrap services
    /// are skipped when checking for unmigrated certs). Skipped phases
    /// (`--skip reissue,finalize`) leave the rotation paused for
    /// operator follow-up. Use `--cleanup` to delete backup files
    /// after a successful full rotation.
    #[command(name = "ca-key")]
    CaKey(RotateCaKeyArgs),
    /// Renews infrastructure TLS certificates (e.g. `OpenBao` server cert)
    /// registered in `state.json` `infra_certs`.
    #[command(name = "infra-cert")]
    InfraCert(RotateInfraCertArgs),
    /// Clears EAB credentials from every known KV path so the next
    /// bootroot-agent cycle does not template stale or invalid EAB
    /// material into agent.toml.
    #[command(name = "eab-clear")]
    EabClear(RotateEabClearArgs),
}

#[derive(Args, Debug)]
pub(crate) struct RotateEabClearArgs {}

#[derive(Args, Debug)]
pub(crate) struct RotateInfraCertArgs {}

#[derive(Args, Debug)]
pub(crate) struct RotateStepcaPasswordArgs {
    /// New step-ca key password
    #[arg(long)]
    pub(crate) new_password: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct RotateDbArgs {
    #[command(flatten)]
    pub(crate) admin_dsn: DbAdminDsnArgs,

    /// New database password
    #[arg(long = "db-password", env = "BOOTROOT_DB_PASSWORD")]
    pub(crate) password: Option<String>,

    #[command(flatten)]
    pub(crate) timeout: DbTimeoutArgs,
}

#[derive(Args, Debug)]
pub(crate) struct RotateResponderHmacArgs {
    /// New responder HMAC
    #[arg(long)]
    pub(crate) hmac: Option<String>,
}

#[derive(Args, Debug)]
#[command(
    group(
        ArgGroup::new("recovery_targets")
            .required(true)
            .multiple(true)
            .args(["rotate_unseal_keys", "rotate_root_token"])
    )
)]
pub(crate) struct RotateOpenBaoRecoveryArgs {
    /// Rotates unseal keys via the authenticated root-key rotation API.
    ///
    /// Requires existing unseal keys. Provide at least the configured unseal
    /// threshold number of key shares. If those keys are lost, this rotation
    /// cannot proceed.
    #[arg(long)]
    pub(crate) rotate_unseal_keys: bool,

    /// Rotates `OpenBao` root token.
    ///
    /// Does not require unseal key input.
    #[arg(long)]
    pub(crate) rotate_root_token: bool,

    /// Supplies existing unseal key(s), repeat for multiple keys.
    ///
    /// Used only with `--rotate-unseal-keys`.
    #[arg(long)]
    pub(crate) unseal_key: Vec<String>,

    /// Supplies a file with existing unseal keys (one key per line).
    ///
    /// Used only with `--rotate-unseal-keys`.
    #[arg(long)]
    pub(crate) unseal_key_file: Option<PathBuf>,

    /// Output path for newly generated recovery credentials
    #[arg(long)]
    pub(crate) output: Option<PathBuf>,
}

#[derive(Args, Debug)]
#[command(
    group(
        ArgGroup::new("approle_target")
            .required(true)
            .args(["service_name", "all_services", "infra"])
    )
)]
pub(crate) struct RotateAppRoleSecretIdArgs {
    /// App service name to rotate the `AppRole` `secret_id` for.
    ///
    /// Authenticate with `bootroot-runtime-rotate-role` credentials.
    #[arg(long)]
    pub(crate) service_name: Option<String>,

    /// Rotates the `AppRole` `secret_id` of every registered service in
    /// one invocation.
    ///
    /// Authenticate with `bootroot-runtime-rotate-role` credentials.
    /// Infra roles are deliberately excluded (they use the separate
    /// `bootroot-infra-rotate-role` credential); schedule `--infra`
    /// invocations alongside this one. Continues past per-service
    /// failures and exits non-zero if any target failed. An empty
    /// service registry is a no-op success.
    #[arg(long)]
    pub(crate) all_services: bool,

    /// Infra role to rotate the `AppRole` `secret_id` for.
    ///
    /// Targets the `AppRole`s consumed by the long-running `OpenBao`
    /// Agent sidecars. Authenticate with `bootroot-infra-rotate-role`
    /// credentials (or the root token, which also provisions that role
    /// when missing).
    #[arg(long, value_enum)]
    pub(crate) infra: Option<InfraRoleTarget>,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InfraRoleTarget {
    /// `bootroot-stepca-role`, consumed by the `openbao-agent-stepca` sidecar
    Stepca,
    /// `bootroot-responder-role`, consumed by the `openbao-agent-responder` sidecar
    Responder,
}

#[derive(Args, Debug)]
pub(crate) struct RotateTrustSyncArgs {}

#[derive(Args, Debug)]
pub(crate) struct RotateForceReissueArgs {
    /// Service name to force-reissue certificates for
    #[arg(long)]
    pub(crate) service_name: String,

    /// Optional label describing the operator that requested the reissue.
    ///
    /// Written to the remote-bootstrap KV payload under `requester` for
    /// observability. When omitted, the control-plane user name (or a
    /// conservative fallback) is used.
    #[arg(long)]
    pub(crate) requester: Option<String>,

    /// Wait for the agent to apply the reissue before returning.
    ///
    /// For `--delivery-mode remote-bootstrap` services, polls the
    /// `completed_at` field on the KV reissue path. For local-file
    /// services, polls the on-disk cert (serial + mtime) until the local
    /// bootroot-agent rewrites it. Use `--wait-timeout` to bound the wait.
    #[arg(long)]
    pub(crate) wait: bool,

    /// Maximum time to wait when `--wait` is set (e.g. "2m", "90s").
    #[arg(long, default_value = "2m")]
    pub(crate) wait_timeout: String,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RotateSkipPhase {
    /// Skip service certificate re-issuance (Phase 5)
    Reissue,
    /// Skip trust finalization (Phase 6)
    Finalize,
}

#[derive(Args, Debug)]
pub(crate) struct RotateCaKeyArgs {
    /// Rotate both root and intermediate CA keys (full rotation)
    #[arg(long)]
    pub(crate) full: bool,
    /// Skip specific rotation phases
    #[arg(long, value_enum, value_delimiter = ',')]
    pub(crate) skip: Vec<RotateSkipPhase>,
    /// Force finalization even with un-migrated services
    #[arg(long)]
    pub(crate) force: bool,
    /// Delete backup files on completion
    #[arg(long)]
    pub(crate) cleanup: bool,
}

#[derive(Args, Debug)]
pub(crate) struct InfraUpArgs {
    #[command(flatten)]
    pub(crate) compose_file: ComposeFileArgs,

    /// Comma-separated list of services to start
    // Keep "bootroot-http01" in sync with RESPONDER_SERVICE_NAME.
    #[arg(
        long,
        default_value = "openbao,postgres,step-ca,bootroot-http01",
        value_delimiter = ','
    )]
    pub(crate) services: Vec<String>,

    /// Directory containing local image archives (optional)
    #[arg(long)]
    pub(crate) image_archive_dir: Option<PathBuf>,

    /// Docker restart policy to apply after containers start
    #[arg(long, default_value = "always")]
    pub(crate) restart_policy: String,

    /// `OpenBao` API URL for auto-unseal (dev/test only)
    #[arg(long, default_value = DEFAULT_OPENBAO_URL)]
    pub(crate) openbao_url: String,

    /// Auto-unseal `OpenBao` from file (dev/test only)
    #[arg(long, env = "OPENBAO_UNSEAL_FILE")]
    pub(crate) openbao_unseal_from_file: Option<PathBuf>,
}

// Each boolean flag is a deliberate, independent opt-in confirmation
// required by the guardrail checks (OpenBao bind + HTTP-01 admin bind).
#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug)]
pub(crate) struct InfraInstallArgs {
    #[command(flatten)]
    pub(crate) compose_file: ComposeFileArgs,

    /// Comma-separated list of services to start
    #[arg(
        long,
        default_value = "openbao,postgres,step-ca,bootroot-http01",
        value_delimiter = ','
    )]
    pub(crate) services: Vec<String>,

    /// Directory containing local image archives (optional)
    #[arg(long)]
    pub(crate) image_archive_dir: Option<PathBuf>,

    /// Docker restart policy to apply after containers start
    #[arg(long, default_value = "always")]
    pub(crate) restart_policy: String,

    /// `OpenBao` API URL
    #[arg(long, default_value = DEFAULT_OPENBAO_URL)]
    pub(crate) openbao_url: String,

    /// Bind `OpenBao` to a non-loopback address (requires TLS).
    /// Format: `<IP>:<port>`, e.g. `192.168.1.10:8200`
    #[arg(long)]
    pub(crate) openbao_bind: Option<String>,

    /// Acknowledge that TLS is mandatory for non-loopback `OpenBao` binding.
    /// Required when `--openbao-bind` specifies a non-loopback address
    #[arg(long)]
    pub(crate) openbao_tls_required: bool,

    /// Confirm intent to bind `OpenBao` to `0.0.0.0` (wildcard).
    /// Required when `--openbao-bind` uses `0.0.0.0`
    #[arg(long)]
    pub(crate) openbao_bind_wildcard: bool,

    /// Advertised `OpenBao` address for remote bootstrap artifacts.
    /// Required when `--openbao-bind` uses a wildcard address (`0.0.0.0`
    /// or `[::]`), because remote nodes cannot connect to a wildcard.
    /// Must be a specific reachable IP:port (not wildcard or loopback).
    #[arg(long)]
    pub(crate) openbao_advertise_addr: Option<String>,

    /// Bind the HTTP-01 admin API to a non-loopback address (requires TLS).
    /// Format: `<IP>:<port>`, e.g. `192.168.1.10:8080`
    #[arg(long)]
    pub(crate) http01_admin_bind: Option<String>,

    /// Acknowledge that TLS is mandatory for non-loopback HTTP-01 admin binding.
    /// Required when `--http01-admin-bind` specifies a non-loopback address
    #[arg(long)]
    pub(crate) http01_admin_tls_required: bool,

    /// Confirm intent to bind the HTTP-01 admin API to `0.0.0.0` (wildcard).
    /// Required when `--http01-admin-bind` uses `0.0.0.0`
    #[arg(long)]
    pub(crate) http01_admin_bind_wildcard: bool,

    /// Advertised HTTP-01 admin API address for TLS certificate SANs.
    /// Required when `--http01-admin-bind` uses a wildcard address (`0.0.0.0`
    /// or `[::]`), because clients cannot connect to a wildcard.
    /// Must be a specific reachable IP:port (not wildcard or loopback).
    #[arg(long)]
    pub(crate) http01_admin_advertise_addr: Option<String>,

    /// Bind step-ca's ACME directory to a non-loopback address.
    /// Format: `<IP>:<port>`, e.g. `192.168.1.10:9000`. step-ca already
    /// terminates TLS with its own certificate, so no TLS acknowledgement
    /// flag is required
    #[arg(long)]
    pub(crate) stepca_bind: Option<String>,

    /// Confirm intent to bind step-ca's ACME directory to `0.0.0.0`
    /// (wildcard). Required when `--stepca-bind` uses `0.0.0.0`
    #[arg(long)]
    pub(crate) stepca_bind_wildcard: bool,

    /// Advertised step-ca ACME directory address for remote nodes.
    /// Required when `--stepca-bind` uses a wildcard address (`0.0.0.0`
    /// or `[::]`), because remote nodes cannot connect to a wildcard.
    /// Must be a specific reachable IP:port (not wildcard or loopback).
    #[arg(long)]
    pub(crate) stepca_advertise_addr: Option<String>,

    /// Host-side `PostgreSQL` published port. Overrides
    /// `POSTGRES_HOST_PORT` from `.env` and the process environment.
    /// When unset, the value already in `.env` (or the compose default)
    /// applies.
    #[arg(long = "postgres-host-port")]
    pub(crate) postgres_host_port: Option<u16>,
}

#[derive(Args, Debug)]
pub(crate) struct CleanArgs {
    #[command(flatten)]
    pub(crate) compose_file: ComposeFileArgs,

    /// Skip confirmation prompts
    #[arg(long, short)]
    pub(crate) yes: bool,

    /// Removes only the `bootroot-openbao` container and its volume,
    /// leaving `bootroot-postgres`, `bootroot-http01`, `bootroot-ca`,
    /// `secrets/`, `state.json`, and `.env` intact. Useful when only
    /// the `OpenBao` state is fouled (e.g. after a partial-init
    /// failure — see issue #588 §5).
    #[arg(long = "openbao-only")]
    pub(crate) openbao_only: bool,
}

#[derive(Args, Debug)]
pub(crate) struct OpenbaoSaveUnsealKeysArgs {
    /// Secrets directory
    #[arg(long, default_value = DEFAULT_SECRETS_DIR)]
    pub(crate) secrets_dir: PathBuf,
}

#[derive(Args, Debug)]
pub(crate) struct OpenbaoDeleteUnsealKeysArgs {
    /// Secrets directory
    #[arg(long, default_value = DEFAULT_SECRETS_DIR)]
    pub(crate) secrets_dir: PathBuf,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MonitoringProfile {
    Lan,
    Public,
}

impl std::fmt::Display for MonitoringProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MonitoringProfile::Lan => write!(f, "lan"),
            MonitoringProfile::Public => write!(f, "public"),
        }
    }
}

#[derive(Args, Debug)]
pub(crate) struct MonitoringUpArgs {
    #[command(flatten)]
    pub(crate) compose_file: ComposeFileArgs,

    /// Monitoring profile to start (lan or public)
    #[arg(long, value_enum, default_value_t = MonitoringProfile::Lan)]
    pub(crate) profile: MonitoringProfile,

    /// Grafana admin password override (default: admin)
    #[arg(long, env = "GRAFANA_ADMIN_PASSWORD")]
    pub(crate) grafana_admin_password: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct MonitoringStatusArgs {
    #[command(flatten)]
    pub(crate) compose_file: ComposeFileArgs,
}

#[derive(Args, Debug)]
pub(crate) struct MonitoringDownArgs {
    #[command(flatten)]
    pub(crate) compose_file: ComposeFileArgs,

    /// Reset Grafana admin password on next up
    #[arg(long)]
    pub(crate) reset_grafana_admin_password: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InitFeature {
    /// Auto-generate secrets where possible
    AutoGenerate,
    /// Show secrets in output summaries
    ShowSecrets,
    /// Provision `PostgreSQL` role/database for step-ca
    DbProvision,
    /// Validate DB DSN connectivity and auth
    DbCheck,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InitSkipPhase {
    /// Skip HTTP-01 responder check during init
    ResponderCheck,
}

// Each boolean flag corresponds to an explicit, per-prompt
// non-interactive opt-out on the `init` surface (`--no-eab`,
// `--save-unseal-keys`, `--no-save-unseal-keys`, plus the internal
// `reinit_mode`).  Per the project pattern (#588 §3b), `init` uses
// per-prompt explicit flags rather than a global `--yes`, so refactoring
// them into a single state enum would obscure the clap-level mutual
// exclusivity (`conflicts_with`) and `requires = "summary_json"`
// constraints that this surface relies on.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug)]
pub(crate) struct InitArgs {
    #[command(flatten)]
    pub(crate) openbao: OpenBaoArgs,

    #[command(flatten)]
    pub(crate) secrets_dir: SecretsDirArgs,

    #[command(flatten)]
    pub(crate) compose: ComposeFileArgs,

    /// Enable optional features
    #[arg(long, value_enum, value_delimiter = ',')]
    pub(crate) enable: Vec<InitFeature>,

    /// Skip optional checks
    #[arg(long, value_enum, value_delimiter = ',')]
    pub(crate) skip: Vec<InitSkipPhase>,

    /// Path to init summary JSON file
    #[arg(long = "summary-json")]
    pub(crate) summary_json: Option<PathBuf>,

    #[command(flatten)]
    pub(crate) root_token: RootTokenArgs,

    /// `OpenBao` unseal key (repeatable)
    #[arg(long, env = "OPENBAO_UNSEAL_KEYS", value_delimiter = ',')]
    pub(crate) unseal_key: Vec<String>,

    /// Auto-unseal `OpenBao` from file (dev/test only)
    #[arg(long, env = "OPENBAO_UNSEAL_FILE")]
    pub(crate) openbao_unseal_from_file: Option<PathBuf>,

    /// Role-level `secret_id` TTL for `AppRole` roles created during init.
    /// Set this to at least 2× your planned rotation interval so that a
    /// missed or delayed run does not expire credentials
    #[arg(long, default_value = SECRET_ID_TTL)]
    pub(crate) secret_id_ttl: String,

    /// step-ca password (password.txt)
    #[arg(long, env = "STEPCA_PASSWORD")]
    pub(crate) stepca_password: Option<String>,

    /// `PostgreSQL` DSN for step-ca
    #[arg(long)]
    pub(crate) db_dsn: Option<String>,

    #[command(flatten)]
    pub(crate) db_admin: DbAdminDsnArgs,

    /// `PostgreSQL` user for step-ca
    #[arg(long, env = "BOOTROOT_DB_USER")]
    pub(crate) db_user: Option<String>,

    /// `PostgreSQL` password for step-ca
    #[arg(long, env = "BOOTROOT_DB_PASSWORD")]
    pub(crate) db_password: Option<String>,

    /// `PostgreSQL` database name for step-ca
    #[arg(long, env = "BOOTROOT_DB_NAME")]
    pub(crate) db_name: Option<String>,

    #[command(flatten)]
    pub(crate) db_timeout: DbTimeoutArgs,

    /// HTTP-01 responder HMAC secret
    #[arg(long, env = "HTTP01_HMAC")]
    pub(crate) http_hmac: Option<String>,

    /// HTTP-01 responder admin URL (optional)
    #[arg(long, env = "HTTP01_RESPONDER_URL")]
    pub(crate) responder_url: Option<String>,

    /// HTTP-01 responder request timeout (seconds)
    #[arg(long, default_value_t = 5)]
    pub(crate) responder_timeout_secs: u64,

    /// step-ca ACME provisioner name
    #[arg(long, default_value = DEFAULT_STEPCA_PROVISIONER)]
    pub(crate) stepca_provisioner: String,

    /// `defaultTLSCertDuration` embedded in the ACME provisioner of
    /// `ca.json` / `ca.json.ctmpl` (e.g. `24h`, `48h`).
    ///
    /// Must be greater than the daemon's `renew_before` value — otherwise
    /// every newly issued certificate is flagged for immediate renewal
    #[arg(long, default_value = DEFAULT_CERT_DURATION)]
    pub(crate) cert_duration: String,

    /// ACME EAB key ID (optional)
    #[arg(long, env = "EAB_KID")]
    pub(crate) eab_kid: Option<String>,

    /// ACME EAB HMAC (optional)
    #[arg(long, env = "EAB_HMAC")]
    pub(crate) eab_hmac: Option<String>,

    /// Skip the ACME EAB prompt and persist no EAB credentials.
    /// Recommended for OSS step-ca (which does not implement EAB)
    /// and for CI flows that never use EAB.
    #[arg(long = "no-eab", conflicts_with_all = ["eab_kid", "eab_hmac"])]
    pub(crate) no_eab: bool,

    /// Skip the save-unseal-keys prompt and persist the freshly
    /// generated unseal keys to `<secrets_dir>/openbao/unseal-keys.txt`
    /// (mode `0600`).  Equivalent to answering `y` at the prompt.
    #[arg(long = "save-unseal-keys", conflicts_with = "no_save_unseal_keys")]
    pub(crate) save_unseal_keys: bool,

    /// Skip the save-unseal-keys prompt and do NOT persist the keys to
    /// the on-disk path.  Requires `--summary-json <path>` so the freshly
    /// generated keys are captured in the 0600 summary file; without it
    /// the keys would be lost and would brick the next `OpenBao` restart.
    #[arg(
        long = "no-save-unseal-keys",
        requires = "summary_json",
        conflicts_with = "save_unseal_keys"
    )]
    pub(crate) no_save_unseal_keys: bool,

    /// Internal: invoked from `bootroot reinit`.  Suppresses overwrite
    /// prompts for files that the reinit caller has already decided to
    /// preserve (`ca.json`, `password.txt`, `state.json`) so a
    /// non-interactive `reinit --yes` does not stall on prompts and
    /// preserved files are not regenerated.
    #[arg(long, hide = true, default_value_t = false)]
    pub(crate) reinit_mode: bool,

    /// Internal: invoked from `bootroot reinit --root-token-output`.
    /// When set, the freshly issued `OpenBao` root token is written to
    /// this path with mode `0600` after init succeeds.  Hidden from
    /// `init`'s own surface; only the `reinit` wrapper sets it.
    #[arg(long, hide = true)]
    pub(crate) root_token_output: Option<PathBuf>,
}

impl InitArgs {
    pub(crate) fn has_feature(&self, feature: InitFeature) -> bool {
        self.enable.contains(&feature)
    }

    pub(crate) fn has_skip(&self, phase: InitSkipPhase) -> bool {
        self.skip.contains(&phase)
    }
}

/// Arguments accepted by `bootroot reinit`.
///
/// Most fields mirror `InitArgs` because reinit re-runs init under
/// reinit-mode semantics after wiping `OpenBao`-owned state.  Operator
/// secrets (step-ca password, DB DSN, EAB, HMAC) are NOT re-prompted —
/// reinit preserves the existing step-ca password and re-uses the
/// existing DSN/HMAC when present.
#[derive(Args, Debug)]
pub(crate) struct ReinitArgs {
    #[command(flatten)]
    pub(crate) openbao: OpenBaoArgs,

    #[command(flatten)]
    pub(crate) secrets_dir: SecretsDirArgs,

    #[command(flatten)]
    pub(crate) compose: ComposeFileArgs,

    /// Skip confirmation prompts.  With `--yes` the entire flow is
    /// non-interactive: destructive actions proceed without prompting
    /// and newly-generated `OpenBao` unseal keys are written
    /// automatically to `secrets/openbao/unseal-keys.txt` (mode `0600`).
    #[arg(long, short = 'y')]
    pub(crate) yes: bool,

    /// Optional path to persist the freshly generated `OpenBao` root
    /// token.  Off by default because persistent root token files are
    /// not recommended for production.  When set, the file is written
    /// with restricted permissions (`0600`) and an existing file with
    /// other-readable permissions is rejected.  Intended for dev/test
    /// or ephemeral automation only.
    #[arg(long)]
    pub(crate) root_token_output: Option<PathBuf>,

    /// Enable optional features passed through to the underlying init
    /// flow (e.g. `show-secrets`).
    ///
    /// `db-provision` is accepted but becomes a no-op when reinit finds
    /// a preserved `secrets/config/ca.json` runtime DSN: that DSN is
    /// authoritative (the `PostgreSQL` role's password was rotated to it
    /// on the previous init), so re-running provisioning would rotate
    /// the already-good credential and break the next rotate cycle.
    /// The preserved DSN is threaded into the second init pass and
    /// flows back into the freshly reinitialised `OpenBao` KV verbatim.
    /// When `ca.json` is absent (rsync-clone path), `db-provision`
    /// behaves as in `init`.
    #[arg(long, value_enum, value_delimiter = ',')]
    pub(crate) enable: Vec<InitFeature>,

    /// Skip optional checks (e.g. `responder-check`).
    #[arg(long, value_enum, value_delimiter = ',')]
    pub(crate) skip: Vec<InitSkipPhase>,

    /// Path to init summary JSON file
    #[arg(long = "summary-json")]
    pub(crate) summary_json: Option<PathBuf>,

    /// Skip the ACME EAB prompt and persist no EAB credentials.
    #[arg(long = "no-eab")]
    pub(crate) no_eab: bool,
}

#[derive(Args, Debug)]
pub(crate) struct StatusArgs {
    #[command(flatten)]
    pub(crate) compose: ComposeFileArgs,

    #[command(flatten)]
    pub(crate) openbao: OpenBaoArgs,

    #[command(flatten)]
    pub(crate) root_token: RootTokenArgs,
}

#[derive(Args, Debug)]
// `dry_run`, `print_only`, `no_wrap`, and `no_validate_agent` are
// independent operator-facing toggles; collapsing them into an enum
// would obscure the CLI surface and break clap's `#[arg(long)]`
// derivation, so we accept the extra bool here.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ServiceAddArgs {
    /// Service name identifier
    #[arg(long)]
    pub(crate) service_name: Option<String>,

    /// Deployment shape of the bootroot-agent process that will renew
    /// this service's certificate (daemon or docker). NOT the consumer
    /// service's deployment shape — for consumer reload on renewal, use
    /// --reload-style and --reload-target.
    #[arg(long, value_enum)]
    pub(crate) deploy_type: Option<DeployType>,

    /// Secret delivery mode (local-file or remote-bootstrap)
    #[arg(long, value_enum)]
    pub(crate) delivery_mode: Option<DeliveryMode>,

    /// Preview changes without writing files or state
    #[arg(long)]
    pub(crate) dry_run: bool,

    /// Print manual snippets only without writing files or state
    #[arg(long)]
    pub(crate) print_only: bool,

    /// Hostname used for DNS SAN
    #[arg(long)]
    pub(crate) hostname: Option<String>,

    /// DNS domain for SAN construction
    #[arg(long)]
    pub(crate) domain: Option<String>,

    /// bootroot-agent config path
    #[arg(long)]
    pub(crate) agent_config: Option<PathBuf>,

    /// Certificate output path
    #[arg(long)]
    pub(crate) cert_path: Option<PathBuf>,

    /// Private key output path
    #[arg(long)]
    pub(crate) key_path: Option<PathBuf>,

    /// Instance ID (required for daemon and docker)
    #[arg(long)]
    pub(crate) instance_id: Option<String>,

    /// Container name of the bootroot-agent itself. Required when
    /// --deploy-type=docker; ignored otherwise. NOT the consumer
    /// service's container — for consumer reload on renewal, use
    /// --reload-style docker-restart --reload-target <NAME>.
    #[arg(long)]
    pub(crate) container_name: Option<String>,

    /// Skips the docker-mode identity check that confirms the
    /// `--container-name` argument actually points at a bootroot-agent
    /// (label `bootroot.role=agent`, or `bootroot-agent` substring in
    /// the cmdline/image as a fallback). Useful when the agent
    /// container does not exist yet at `service add` time or when
    /// `docker inspect` is unreachable for legitimate reasons.
    /// Does not bypass the raw `--container-name` / `--deploy-type=daemon`
    /// conflict reject.
    #[arg(long)]
    pub(crate) no_validate_agent: bool,

    /// ACME account email persisted into the rendered `agent.toml`
    /// baseline.  Defaults to the compose-topology placeholder when
    /// omitted; override on non-default deployments so KV-driven
    /// re-renders do not revert operator edits.
    #[arg(long)]
    pub(crate) agent_email: Option<String>,

    /// ACME directory URL persisted into the rendered `agent.toml`
    /// baseline (`server` field).  Defaults to the compose-topology
    /// step-ca URL when omitted; override on non-default deployments
    /// so KV-driven re-renders do not revert operator edits.
    #[arg(long)]
    pub(crate) agent_server: Option<String>,

    /// HTTP-01 responder admin URL persisted into the rendered
    /// `agent.toml` baseline (`[acme].http_responder_url`).  Defaults
    /// to the compose-topology loopback URL when omitted; override on
    /// non-default deployments so KV-driven re-renders do not revert
    /// operator edits.
    #[arg(long)]
    pub(crate) agent_responder_url: Option<String>,

    #[command(flatten)]
    pub(crate) runtime_auth: RuntimeAuthArgs,

    /// Freeform notes (optional)
    #[arg(long)]
    pub(crate) notes: Option<String>,

    /// Reload style preset for post-renew hook
    #[arg(long, value_enum)]
    pub(crate) reload_style: Option<ReloadStyle>,

    /// Target for reload-style preset (unit name, process name, or container)
    #[arg(long)]
    pub(crate) reload_target: Option<String>,

    /// Post-renew success hook command (low-level)
    #[arg(long)]
    pub(crate) post_renew_command: Option<String>,

    /// Post-renew success hook argument (repeatable, low-level).
    ///
    /// Accepts hyphen-prefixed values like `-HUP` or `-f` directly so
    /// operators can spell `--post-renew-arg -HUP` without the `=` form.
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) post_renew_arg: Vec<String>,

    /// Post-renew success hook timeout in seconds (low-level)
    #[arg(long)]
    pub(crate) post_renew_timeout_secs: Option<u64>,

    /// Post-renew success hook failure policy (low-level)
    #[arg(long, value_enum)]
    pub(crate) post_renew_on_failure: Option<HookFailurePolicyArg>,

    /// TTL for the generated `secret_id` (inherits role default when omitted).
    /// Should be at least 2× the rotation interval
    #[arg(long)]
    pub(crate) secret_id_ttl: Option<String>,

    /// Response-wrapping TTL for the `secret_id` [default: 30m]
    #[arg(long)]
    pub(crate) secret_id_wrap_ttl: Option<String>,

    /// Disable response wrapping for the `secret_id`
    #[arg(long, conflicts_with = "secret_id_wrap_ttl")]
    pub(crate) no_wrap: bool,

    /// CIDR ranges to bind the `secret_id` token to (repeatable, e.g. `--rn-cidrs 10.0.0.0/24`)
    #[arg(long)]
    pub(crate) rn_cidrs: Vec<String>,

    /// Numeric gid or group name that should own the issued cert/key
    /// files and their parent directories.
    ///
    /// When set, the agent applies a group-readable policy
    /// (`0750`/`0640`/`0644` with group ownership) on every issuance
    /// and rotation, so non-root containerized clients can read the
    /// bind-mounted cert and key. When unset, the historical
    /// operator-only default (`0700`/`0600`/`0644`) is preserved.
    ///
    /// `local-file` deployments accept a name or numeric gid;
    /// `remote-bootstrap` deployments accept numeric form only — see
    /// issue #593 for the cross-host NSS rationale.
    #[arg(long, value_name = "GID-OR-NAME")]
    pub(crate) cert_group: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct ServiceInfoArgs {
    /// Service name identifier
    #[arg(long, required = true)]
    pub(crate) service_name: String,
}

#[derive(Args, Debug)]
pub(crate) struct ServiceUpdateArgs {
    /// Service name identifier
    #[arg(long, required = true)]
    pub(crate) service_name: String,

    /// TTL for the generated `secret_id` (use "inherit" to clear override).
    /// Should be at least 2× the rotation interval
    #[arg(long)]
    pub(crate) secret_id_ttl: Option<String>,

    /// Response-wrapping TTL for the `secret_id` (use "inherit" to restore
    /// the default wrapping behavior)
    #[arg(long, conflicts_with = "no_wrap")]
    pub(crate) secret_id_wrap_ttl: Option<String>,

    /// Disable response wrapping for the `secret_id`
    #[arg(long, conflicts_with = "secret_id_wrap_ttl")]
    pub(crate) no_wrap: bool,

    /// CIDR ranges to bind the `secret_id` token to (repeatable, e.g. `--rn-cidrs 10.0.0.0/24`).
    /// Use "clear" to remove an existing binding
    #[arg(long)]
    pub(crate) rn_cidrs: Vec<String>,

    /// Numeric gid or group name that owns the issued cert/key files
    /// and their parent directories.
    ///
    /// Use a numeric gid or group name to enable the group-readable
    /// policy (`0750`/`0640` with group ownership) on the next
    /// issuance and rotation. Use the literal string `clear` to
    /// remove an existing policy and revert to the operator-only
    /// default (`0700`/`0600`).
    ///
    /// `local-file` deployments accept names; `remote-bootstrap`
    /// deployments accept numeric form only — see issue #593.
    #[arg(long, value_name = "GID-OR-NAME-OR-CLEAR")]
    pub(crate) cert_group: Option<String>,

    /// Reload style preset for post-renew hook.
    ///
    /// Use `none` to clear any previously configured hook. Use
    /// `systemd`/`sighup`/`docker-restart` together with
    /// `--reload-target` to install a hook on an already-registered
    /// service without having to remove and re-add it. See issue
    /// #614 for the in-FD pitfall this guards against.
    #[arg(long, value_enum)]
    pub(crate) reload_style: Option<ReloadStyle>,

    /// Target for reload-style preset (unit name, process name, or container)
    #[arg(long)]
    pub(crate) reload_target: Option<String>,

    /// Post-renew success hook command (low-level)
    #[arg(long)]
    pub(crate) post_renew_command: Option<String>,

    /// Post-renew success hook argument (repeatable, low-level).
    ///
    /// Accepts hyphen-prefixed values like `-HUP` or `-f` directly so
    /// operators can spell `--post-renew-arg -HUP` without the `=` form.
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) post_renew_arg: Vec<String>,

    /// Post-renew success hook timeout in seconds (low-level)
    #[arg(long)]
    pub(crate) post_renew_timeout_secs: Option<u64>,

    /// Post-renew success hook failure policy (low-level)
    #[arg(long, value_enum)]
    pub(crate) post_renew_on_failure: Option<HookFailurePolicyArg>,
}

// Each boolean flag is a deliberate, independent CLI opt-in (skip
// confirmation, preview, delete artifacts, strip only the config block);
// they are not mutually exclusive state and do not model a state machine.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug)]
pub(crate) struct ServiceRemoveArgs {
    /// Service name identifier
    #[arg(long, required = true)]
    pub(crate) service_name: String,

    /// Skips the interactive confirmation prompt.
    ///
    /// Required for non-interactive use (CI / scripts): without it, and
    /// when stdin is not a terminal, `service remove` refuses to proceed
    /// rather than tearing down a live registration unattended.
    #[arg(long, visible_alias = "force")]
    pub(crate) yes: bool,

    /// Previews the teardown plan without mutating `state.json` or
    /// `OpenBao`.
    #[arg(long)]
    pub(crate) dry_run: bool,

    /// Also deletes bootroot-owned on-disk artifacts (cert/key files,
    /// the per-service secret and `OpenBao` config directories, and the
    /// remote-bootstrap artifact) and strips the managed profile block
    /// from `agent.toml`.
    ///
    /// Off by default: `service add` only records cert/key paths (the
    /// files are produced later by rotation / the agent), so on-disk
    /// material is preserved unless this flag is given. Even with the
    /// flag, `agent.toml` is edited in place — only bootroot's managed
    /// block is removed — so an operator-owned config file is never
    /// deleted.
    #[arg(long)]
    pub(crate) delete_artifacts: bool,

    /// Strips the managed profile block from `agent.toml` without deleting
    /// the cert/key files or the per-service secret and `OpenBao` config
    /// directories.
    ///
    /// Intended for live delivery-mode transitions: when moving a service
    /// between `local-file` and `remote-bootstrap` the operator must keep
    /// the cert/key (the service is still serving) yet wants the stale
    /// managed block gone so the subsequent bootstrap does not leave a
    /// duplicate `[[profiles]]`. `--delete-artifacts` already strips the
    /// block but also deletes the cert/key, so it cannot be used here.
    /// Implied by `--delete-artifacts`; combining the two is redundant but
    /// harmless.
    #[arg(long)]
    pub(crate) strip_config: bool,

    #[command(flatten)]
    pub(crate) runtime_auth: RuntimeAuthArgs,
}

#[derive(Args, Debug)]
pub(crate) struct VerifyArgs {
    /// Service name identifier
    #[arg(long)]
    pub(crate) service_name: Option<String>,

    /// bootroot-agent config path override
    #[arg(long)]
    pub(crate) agent_config: Option<PathBuf>,

    /// Path to the bootroot-agent binary (overrides auto-discovery)
    #[arg(long)]
    pub(crate) agent_binary: Option<PathBuf>,

    /// Verify DB connectivity and auth using ca.json DSN
    #[arg(long)]
    pub(crate) db_check: bool,

    #[command(flatten)]
    pub(crate) db_timeout: DbTimeoutArgs,

    /// Compose file whose sibling `.env` provides `POSTGRES_HOST_PORT` for
    /// host-side DSN translation when `--db-check` is set.
    #[command(flatten)]
    pub(crate) compose_file: ComposeFileArgs,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parses_services_list() {
        let cli = Cli::parse_from(["bootroot", "infra", "up", "--services", "openbao,postgres"]);
        match cli.command {
            CliCommand::Infra(InfraCommand::Up(args)) => {
                assert_eq!(args.services, vec!["openbao", "postgres"]);
            }
            _ => panic!("expected infra up"),
        }
    }

    #[test]
    fn test_cli_parses_rotate_stepca() {
        let cli = Cli::parse_from(["bootroot", "rotate", "stepca-password"]);
        assert!(matches!(cli.command, CliCommand::Rotate(_)));
    }

    #[test]
    fn test_cli_parses_rotate_ca_key_flags() {
        let cli = Cli::parse_from([
            "bootroot",
            "rotate",
            "ca-key",
            "--skip",
            "reissue",
            "--force",
            "--cleanup",
        ]);
        match cli.command {
            CliCommand::Rotate(args) => match args.command {
                RotateCommand::CaKey(ca) => {
                    assert!(!ca.full);
                    assert!(ca.skip.contains(&RotateSkipPhase::Reissue));
                    assert!(!ca.skip.contains(&RotateSkipPhase::Finalize));
                    assert!(ca.force);
                    assert!(ca.cleanup);
                }
                _ => panic!("expected CaKey subcommand"),
            },
            _ => panic!("expected Rotate command"),
        }
    }

    #[test]
    fn test_cli_parses_rotate_approle_secret_id() {
        let cli = Cli::parse_from([
            "bootroot",
            "rotate",
            "approle-secret-id",
            "--service-name",
            "api",
        ]);
        match cli.command {
            CliCommand::Rotate(args) => match args.command {
                RotateCommand::AppRoleSecretId(approle) => {
                    assert_eq!(approle.service_name.as_deref(), Some("api"));
                    assert!(approle.infra.is_none());
                }
                _ => panic!("expected AppRoleSecretId subcommand"),
            },
            _ => panic!("expected Rotate command"),
        }
    }

    #[test]
    fn test_cli_parses_rotate_approle_secret_id_infra() {
        for (value, expected) in [
            ("stepca", InfraRoleTarget::Stepca),
            ("responder", InfraRoleTarget::Responder),
        ] {
            let cli =
                Cli::parse_from(["bootroot", "rotate", "approle-secret-id", "--infra", value]);
            match cli.command {
                CliCommand::Rotate(args) => match args.command {
                    RotateCommand::AppRoleSecretId(approle) => {
                        assert!(approle.service_name.is_none());
                        assert_eq!(approle.infra, Some(expected));
                    }
                    _ => panic!("expected AppRoleSecretId subcommand"),
                },
                _ => panic!("expected Rotate command"),
            }
        }
    }

    #[test]
    fn test_cli_parses_rotate_approle_secret_id_all_services() {
        let cli = Cli::parse_from(["bootroot", "rotate", "approle-secret-id", "--all-services"]);
        match cli.command {
            CliCommand::Rotate(args) => match args.command {
                RotateCommand::AppRoleSecretId(approle) => {
                    assert!(approle.all_services);
                    assert!(approle.service_name.is_none());
                    assert!(approle.infra.is_none());
                }
                _ => panic!("expected AppRoleSecretId subcommand"),
            },
            _ => panic!("expected Rotate command"),
        }
    }

    #[test]
    fn test_cli_rotate_approle_secret_id_requires_exactly_one_target() {
        assert!(
            Cli::try_parse_from(["bootroot", "rotate", "approle-secret-id"]).is_err(),
            "a target selector must be required"
        );
        assert!(
            Cli::try_parse_from([
                "bootroot",
                "rotate",
                "approle-secret-id",
                "--service-name",
                "api",
                "--infra",
                "stepca",
            ])
            .is_err(),
            "--service-name and --infra must be mutually exclusive"
        );
        assert!(
            Cli::try_parse_from([
                "bootroot",
                "rotate",
                "approle-secret-id",
                "--all-services",
                "--service-name",
                "api",
            ])
            .is_err(),
            "--all-services and --service-name must be mutually exclusive"
        );
        assert!(
            Cli::try_parse_from([
                "bootroot",
                "rotate",
                "approle-secret-id",
                "--all-services",
                "--infra",
                "stepca",
            ])
            .is_err(),
            "--all-services and --infra must be mutually exclusive"
        );
        assert!(
            Cli::try_parse_from([
                "bootroot",
                "rotate",
                "approle-secret-id",
                "--infra",
                "not-a-role",
            ])
            .is_err(),
            "--infra must reject values outside the fixed enum"
        );
    }

    #[test]
    fn test_cli_parses_rotate_openbao_recovery() {
        let cli = Cli::parse_from([
            "bootroot",
            "rotate",
            "openbao-recovery",
            "--rotate-unseal-keys",
            "--rotate-root-token",
            "--unseal-key",
            "key-1",
            "--unseal-key",
            "key-2",
            "--output",
            "secrets/openbao-recovery.json",
        ]);
        match cli.command {
            CliCommand::Rotate(args) => match args.command {
                RotateCommand::OpenBaoRecovery(openbao_recovery) => {
                    assert!(openbao_recovery.rotate_unseal_keys);
                    assert!(openbao_recovery.rotate_root_token);
                    assert_eq!(openbao_recovery.unseal_key, vec!["key-1", "key-2"]);
                    assert_eq!(
                        openbao_recovery.output,
                        Some(PathBuf::from("secrets/openbao-recovery.json"))
                    );
                }
                _ => panic!("expected OpenBaoRecovery subcommand"),
            },
            _ => panic!("expected Rotate command"),
        }
    }

    #[test]
    fn test_cli_rejects_rotate_openbao_recovery_without_target() {
        let result = Cli::try_parse_from(["bootroot", "rotate", "openbao-recovery"]);
        assert!(result.is_err(), "expected clap validation error");
    }

    #[test]
    fn test_cli_parses_monitoring_profile() {
        let cli = Cli::parse_from(["bootroot", "monitoring", "up", "--profile", "public"]);
        match cli.command {
            CliCommand::Monitoring(MonitoringCommand::Up(args)) => {
                assert!(matches!(args.profile, MonitoringProfile::Public));
            }
            _ => panic!("expected monitoring up"),
        }
    }

    #[test]
    fn test_cli_parses_service_add_delivery_mode() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "add",
            "--delivery-mode",
            "remote-bootstrap",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert!(matches!(
                    args.delivery_mode,
                    Some(DeliveryMode::RemoteBootstrap)
                ));
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_parses_service_add_print_only_flags() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "add",
            "--print-only",
            "--dry-run",
            "--service-name",
            "edge-proxy",
            "--deploy-type",
            "daemon",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            "agent.toml",
            "--cert-path",
            "certs/edge-proxy.crt",
            "--key-path",
            "certs/edge-proxy.key",
            "--instance-id",
            "001",
            "--root-token",
            "root-token",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert!(args.print_only);
                assert!(args.dry_run);
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_parses_init_cert_duration_default() {
        let cli = Cli::parse_from(["bootroot", "init"]);
        match cli.command {
            CliCommand::Init(args) => {
                assert_eq!(args.cert_duration, "24h");
            }
            _ => panic!("expected init"),
        }
    }

    #[test]
    fn test_cli_parses_init_cert_duration_override() {
        let cli = Cli::parse_from(["bootroot", "init", "--cert-duration", "48h"]);
        match cli.command {
            CliCommand::Init(args) => {
                assert_eq!(args.cert_duration, "48h");
            }
            _ => panic!("expected init"),
        }
    }

    #[test]
    fn test_cli_parses_ca_update() {
        let cli = Cli::parse_from(["bootroot", "ca", "update", "--cert-duration", "48h"]);
        match cli.command {
            CliCommand::Ca(CaCommand::Update(args)) => {
                assert_eq!(args.cert_duration, "48h");
                assert_eq!(args.stepca_provisioner, "acme");
            }
            _ => panic!("expected ca update"),
        }
    }

    #[test]
    fn test_cli_parses_ca_restart() {
        let cli = Cli::parse_from(["bootroot", "ca", "restart"]);
        match cli.command {
            CliCommand::Ca(CaCommand::Restart(args)) => {
                assert_eq!(
                    args.compose_file.compose_file,
                    PathBuf::from("docker-compose.yml")
                );
            }
            _ => panic!("expected ca restart"),
        }
    }

    #[test]
    fn test_cli_ca_update_requires_cert_duration() {
        let result = Cli::try_parse_from(["bootroot", "ca", "update"]);
        assert!(result.is_err(), "cert-duration should be required");
    }

    #[test]
    fn test_cli_parses_init_summary_json() {
        let cli = Cli::parse_from(["bootroot", "init", "--summary-json", "init-summary.json"]);
        match cli.command {
            CliCommand::Init(args) => {
                assert_eq!(args.summary_json, Some(PathBuf::from("init-summary.json")));
            }
            _ => panic!("expected init"),
        }
    }

    /// `--save-unseal-keys` parses to the matching flag and leaves
    /// `--no-save-unseal-keys` unset.
    #[test]
    fn test_cli_parses_init_save_unseal_keys() {
        let cli = Cli::parse_from(["bootroot", "init", "--save-unseal-keys"]);
        match cli.command {
            CliCommand::Init(args) => {
                assert!(args.save_unseal_keys);
                assert!(!args.no_save_unseal_keys);
            }
            _ => panic!("expected init"),
        }
    }

    /// `--no-save-unseal-keys` requires `--summary-json`; with both set
    /// the parse succeeds.
    #[test]
    fn test_cli_parses_init_no_save_unseal_keys_with_summary_json() {
        let cli = Cli::parse_from([
            "bootroot",
            "init",
            "--no-save-unseal-keys",
            "--summary-json",
            "init-summary.json",
        ]);
        match cli.command {
            CliCommand::Init(args) => {
                assert!(args.no_save_unseal_keys);
                assert!(!args.save_unseal_keys);
                assert_eq!(args.summary_json, Some(PathBuf::from("init-summary.json")));
            }
            _ => panic!("expected init"),
        }
    }

    /// Clap must reject `--no-save-unseal-keys` without `--summary-json`
    /// at parse time so the operator does not waste a full init cycle
    /// before discovering the bad combination.
    #[test]
    fn test_cli_rejects_no_save_unseal_keys_without_summary_json() {
        let result = Cli::try_parse_from(["bootroot", "init", "--no-save-unseal-keys"]);
        assert!(
            result.is_err(),
            "--no-save-unseal-keys without --summary-json must be rejected at parse time"
        );
    }

    /// Clap must reject the mutually exclusive `--save-unseal-keys` and
    /// `--no-save-unseal-keys` combination at parse time.
    #[test]
    fn test_cli_rejects_save_and_no_save_unseal_keys_together() {
        let result = Cli::try_parse_from([
            "bootroot",
            "init",
            "--save-unseal-keys",
            "--no-save-unseal-keys",
            "--summary-json",
            "init-summary.json",
        ]);
        assert!(
            result.is_err(),
            "--save-unseal-keys and --no-save-unseal-keys must be mutually exclusive"
        );
    }

    /// Default `init` (no save-unseal-keys flag) leaves both fields
    /// false — the prompt path stays unchanged for interactive operators.
    #[test]
    fn test_cli_init_default_save_unseal_keys_flags_unset() {
        let cli = Cli::parse_from(["bootroot", "init"]);
        match cli.command {
            CliCommand::Init(args) => {
                assert!(!args.save_unseal_keys);
                assert!(!args.no_save_unseal_keys);
            }
            _ => panic!("expected init"),
        }
    }

    #[test]
    fn test_cli_parses_infra_install() {
        let cli = Cli::parse_from([
            "bootroot",
            "infra",
            "install",
            "--services",
            "openbao,postgres",
        ]);
        match cli.command {
            CliCommand::Infra(InfraCommand::Install(args)) => {
                assert_eq!(args.services, vec!["openbao", "postgres"]);
            }
            _ => panic!("expected infra install"),
        }
    }

    #[test]
    fn test_cli_parses_infra_install_openbao_bind() {
        let cli = Cli::parse_from([
            "bootroot",
            "infra",
            "install",
            "--openbao-bind",
            "192.168.1.10:8200",
        ]);
        match cli.command {
            CliCommand::Infra(InfraCommand::Install(args)) => {
                assert_eq!(args.openbao_bind.as_deref(), Some("192.168.1.10:8200"));
                assert!(!args.openbao_bind_wildcard);
            }
            _ => panic!("expected infra install"),
        }
    }

    #[test]
    fn test_cli_parses_infra_install_openbao_bind_wildcard() {
        let cli = Cli::parse_from([
            "bootroot",
            "infra",
            "install",
            "--openbao-bind",
            "0.0.0.0:8200",
            "--openbao-bind-wildcard",
        ]);
        match cli.command {
            CliCommand::Infra(InfraCommand::Install(args)) => {
                assert_eq!(args.openbao_bind.as_deref(), Some("0.0.0.0:8200"));
                assert!(args.openbao_bind_wildcard);
            }
            _ => panic!("expected infra install"),
        }
    }

    #[test]
    fn test_cli_infra_install_default_no_openbao_bind() {
        let cli = Cli::parse_from(["bootroot", "infra", "install"]);
        match cli.command {
            CliCommand::Infra(InfraCommand::Install(args)) => {
                assert!(args.openbao_bind.is_none());
                assert!(!args.openbao_bind_wildcard);
                assert!(args.openbao_advertise_addr.is_none());
            }
            _ => panic!("expected infra install"),
        }
    }

    #[test]
    fn test_cli_parses_infra_install_openbao_advertise_addr() {
        let cli = Cli::parse_from([
            "bootroot",
            "infra",
            "install",
            "--openbao-bind",
            "0.0.0.0:8200",
            "--openbao-bind-wildcard",
            "--openbao-advertise-addr",
            "192.168.1.10:8200",
        ]);
        match cli.command {
            CliCommand::Infra(InfraCommand::Install(args)) => {
                assert_eq!(args.openbao_bind.as_deref(), Some("0.0.0.0:8200"));
                assert!(args.openbao_bind_wildcard);
                assert_eq!(
                    args.openbao_advertise_addr.as_deref(),
                    Some("192.168.1.10:8200")
                );
            }
            _ => panic!("expected infra install"),
        }
    }

    #[test]
    fn test_cli_parses_infra_install_stepca_bind() {
        let cli = Cli::parse_from([
            "bootroot",
            "infra",
            "install",
            "--stepca-bind",
            "192.168.1.10:9000",
        ]);
        match cli.command {
            CliCommand::Infra(InfraCommand::Install(args)) => {
                assert_eq!(args.stepca_bind.as_deref(), Some("192.168.1.10:9000"));
                assert!(!args.stepca_bind_wildcard);
            }
            _ => panic!("expected infra install"),
        }
    }

    #[test]
    fn test_cli_infra_install_default_no_stepca_bind() {
        let cli = Cli::parse_from(["bootroot", "infra", "install"]);
        match cli.command {
            CliCommand::Infra(InfraCommand::Install(args)) => {
                assert!(args.stepca_bind.is_none());
                assert!(!args.stepca_bind_wildcard);
                assert!(args.stepca_advertise_addr.is_none());
            }
            _ => panic!("expected infra install"),
        }
    }

    #[test]
    fn test_cli_parses_infra_install_stepca_advertise_addr() {
        let cli = Cli::parse_from([
            "bootroot",
            "infra",
            "install",
            "--stepca-bind",
            "0.0.0.0:9000",
            "--stepca-bind-wildcard",
            "--stepca-advertise-addr",
            "192.168.1.10:9000",
        ]);
        match cli.command {
            CliCommand::Infra(InfraCommand::Install(args)) => {
                assert_eq!(args.stepca_bind.as_deref(), Some("0.0.0.0:9000"));
                assert!(args.stepca_bind_wildcard);
                assert_eq!(
                    args.stepca_advertise_addr.as_deref(),
                    Some("192.168.1.10:9000")
                );
            }
            _ => panic!("expected infra install"),
        }
    }

    #[test]
    fn test_cli_parses_clean() {
        let cli = Cli::parse_from(["bootroot", "clean", "--yes"]);
        match cli.command {
            CliCommand::Clean(args) => {
                assert!(args.yes);
            }
            _ => panic!("expected clean"),
        }
    }

    #[test]
    fn test_cli_parses_clean_short_yes() {
        let cli = Cli::parse_from(["bootroot", "clean", "-y"]);
        match cli.command {
            CliCommand::Clean(args) => {
                assert!(args.yes);
            }
            _ => panic!("expected clean"),
        }
    }

    #[test]
    fn test_cli_parses_openbao_save_unseal_keys() {
        let cli = Cli::parse_from(["bootroot", "openbao", "save-unseal-keys"]);
        assert!(matches!(
            cli.command,
            CliCommand::Openbao(OpenbaoCommand::SaveUnsealKeys(_))
        ));
    }

    #[test]
    fn test_cli_parses_openbao_delete_unseal_keys() {
        let cli = Cli::parse_from(["bootroot", "openbao", "delete-unseal-keys"]);
        assert!(matches!(
            cli.command,
            CliCommand::Openbao(OpenbaoCommand::DeleteUnsealKeys(_))
        ));
    }

    #[test]
    fn test_infra_up_compose_file_default() {
        let cli = Cli::parse_from(["bootroot", "infra", "up"]);
        match cli.command {
            CliCommand::Infra(InfraCommand::Up(args)) => {
                assert_eq!(
                    args.compose_file.compose_file,
                    PathBuf::from("docker-compose.yml")
                );
            }
            _ => panic!("expected infra up"),
        }
    }

    #[test]
    fn test_infra_up_compose_file_custom() {
        let cli = Cli::parse_from(["bootroot", "infra", "up", "--compose-file", "custom.yml"]);
        match cli.command {
            CliCommand::Infra(InfraCommand::Up(args)) => {
                assert_eq!(args.compose_file.compose_file, PathBuf::from("custom.yml"));
            }
            _ => panic!("expected infra up"),
        }
    }

    #[test]
    fn test_monitoring_up_compose_file_default() {
        let cli = Cli::parse_from(["bootroot", "monitoring", "up"]);
        match cli.command {
            CliCommand::Monitoring(MonitoringCommand::Up(args)) => {
                assert_eq!(
                    args.compose_file.compose_file,
                    PathBuf::from("docker-compose.yml")
                );
            }
            _ => panic!("expected monitoring up"),
        }
    }

    #[test]
    fn test_monitoring_up_compose_file_custom() {
        let cli = Cli::parse_from([
            "bootroot",
            "monitoring",
            "up",
            "--compose-file",
            "custom.yml",
        ]);
        match cli.command {
            CliCommand::Monitoring(MonitoringCommand::Up(args)) => {
                assert_eq!(args.compose_file.compose_file, PathBuf::from("custom.yml"));
            }
            _ => panic!("expected monitoring up"),
        }
    }

    #[test]
    fn test_monitoring_status_compose_file_default() {
        let cli = Cli::parse_from(["bootroot", "monitoring", "status"]);
        match cli.command {
            CliCommand::Monitoring(MonitoringCommand::Status(args)) => {
                assert_eq!(
                    args.compose_file.compose_file,
                    PathBuf::from("docker-compose.yml")
                );
            }
            _ => panic!("expected monitoring status"),
        }
    }

    #[test]
    fn test_monitoring_status_compose_file_custom() {
        let cli = Cli::parse_from([
            "bootroot",
            "monitoring",
            "status",
            "--compose-file",
            "custom.yml",
        ]);
        match cli.command {
            CliCommand::Monitoring(MonitoringCommand::Status(args)) => {
                assert_eq!(args.compose_file.compose_file, PathBuf::from("custom.yml"));
            }
            _ => panic!("expected monitoring status"),
        }
    }

    #[test]
    fn test_monitoring_down_compose_file_default() {
        let cli = Cli::parse_from(["bootroot", "monitoring", "down"]);
        match cli.command {
            CliCommand::Monitoring(MonitoringCommand::Down(args)) => {
                assert_eq!(
                    args.compose_file.compose_file,
                    PathBuf::from("docker-compose.yml")
                );
            }
            _ => panic!("expected monitoring down"),
        }
    }

    #[test]
    fn test_monitoring_down_compose_file_custom() {
        let cli = Cli::parse_from([
            "bootroot",
            "monitoring",
            "down",
            "--compose-file",
            "custom.yml",
        ]);
        match cli.command {
            CliCommand::Monitoring(MonitoringCommand::Down(args)) => {
                assert_eq!(args.compose_file.compose_file, PathBuf::from("custom.yml"));
            }
            _ => panic!("expected monitoring down"),
        }
    }

    #[test]
    fn test_cli_parses_service_add_reload_style() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "add",
            "--reload-style",
            "systemd",
            "--reload-target",
            "nginx",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert!(matches!(args.reload_style, Some(ReloadStyle::Systemd)));
                assert_eq!(args.reload_target.as_deref(), Some("nginx"));
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_parses_service_add_post_renew_low_level() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "add",
            "--post-renew-command",
            "systemctl",
            "--post-renew-arg",
            "reload",
            "--post-renew-arg",
            "nginx",
            "--post-renew-timeout-secs",
            "60",
            "--post-renew-on-failure",
            "stop",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert_eq!(args.post_renew_command.as_deref(), Some("systemctl"));
                assert_eq!(args.post_renew_arg, vec!["reload", "nginx"]);
                assert_eq!(args.post_renew_timeout_secs, Some(60));
                assert!(matches!(
                    args.post_renew_on_failure,
                    Some(HookFailurePolicyArg::Stop)
                ));
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_parses_service_add_reload_style_docker_restart() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "add",
            "--reload-style",
            "docker-restart",
            "--reload-target",
            "my-container",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert!(matches!(
                    args.reload_style,
                    Some(ReloadStyle::DockerRestart)
                ));
                assert_eq!(args.reload_target.as_deref(), Some("my-container"));
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_parses_service_add_reload_style_none() {
        let cli = Cli::parse_from(["bootroot", "service", "add", "--reload-style", "none"]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert!(matches!(args.reload_style, Some(ReloadStyle::None)));
                assert!(args.reload_target.is_none());
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_parses_service_add_secret_id_defaults() {
        let cli = Cli::parse_from(["bootroot", "service", "add"]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert!(args.secret_id_ttl.is_none());
                assert!(args.secret_id_wrap_ttl.is_none());
                assert!(!args.no_wrap);
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_parses_service_add_secret_id_overrides() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "add",
            "--secret-id-ttl",
            "1h",
            "--secret-id-wrap-ttl",
            "10m",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert_eq!(args.secret_id_ttl.as_deref(), Some("1h"));
                assert_eq!(args.secret_id_wrap_ttl.as_deref(), Some("10m"));
                assert!(!args.no_wrap);
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_parses_service_add_no_wrap() {
        let cli = Cli::parse_from(["bootroot", "service", "add", "--no-wrap"]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert!(args.no_wrap);
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_rejects_no_wrap_with_secret_id_wrap_ttl() {
        let result = Cli::try_parse_from([
            "bootroot",
            "service",
            "add",
            "--no-wrap",
            "--secret-id-wrap-ttl",
            "10m",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_parses_service_add_cert_group() {
        let cli = Cli::parse_from(["bootroot", "service", "add", "--cert-group", "5001"]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert_eq!(args.cert_group.as_deref(), Some("5001"));
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_parses_service_update_cert_group_clear() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--cert-group",
            "clear",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Update(args)) => {
                assert_eq!(args.cert_group.as_deref(), Some("clear"));
            }
            _ => panic!("expected service update"),
        }
    }

    #[test]
    fn test_cli_parses_service_remove_defaults() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "remove",
            "--service-name",
            "edge-proxy",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Remove(args)) => {
                assert_eq!(args.service_name, "edge-proxy");
                assert!(!args.yes);
                assert!(!args.dry_run);
                assert!(!args.delete_artifacts);
                assert!(!args.strip_config);
            }
            _ => panic!("expected service remove"),
        }
    }

    #[test]
    fn test_cli_parses_service_remove_flags() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "remove",
            "--service-name",
            "edge-proxy",
            "--yes",
            "--dry-run",
            "--delete-artifacts",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Remove(args)) => {
                assert!(args.yes);
                assert!(args.dry_run);
                assert!(args.delete_artifacts);
                assert!(!args.strip_config);
            }
            _ => panic!("expected service remove"),
        }
    }

    #[test]
    fn test_cli_parses_service_remove_force_alias() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "remove",
            "--service-name",
            "edge-proxy",
            "--force",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Remove(args)) => {
                assert!(args.yes);
            }
            _ => panic!("expected service remove"),
        }
    }

    #[test]
    fn test_cli_parses_service_remove_strip_config() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "remove",
            "--service-name",
            "edge-proxy",
            "--strip-config",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Remove(args)) => {
                assert!(args.strip_config);
                assert!(!args.delete_artifacts);
            }
            _ => panic!("expected service remove"),
        }
    }

    #[test]
    fn test_cli_parses_service_add_rn_cidrs() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "add",
            "--rn-cidrs",
            "10.0.0.0/24",
            "--rn-cidrs",
            "192.168.1.0/24",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert_eq!(args.rn_cidrs, vec!["10.0.0.0/24", "192.168.1.0/24"]);
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_parses_service_add_rn_cidrs_empty_by_default() {
        let cli = Cli::parse_from(["bootroot", "service", "add"]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert!(args.rn_cidrs.is_empty());
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_parses_service_update_rn_cidrs() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--rn-cidrs",
            "10.0.0.0/8",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Update(args)) => {
                assert_eq!(args.rn_cidrs, vec!["10.0.0.0/8"]);
            }
            _ => panic!("expected service update"),
        }
    }

    #[test]
    fn test_cli_parses_service_update_reload_style() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--reload-style",
            "sighup",
            "--reload-target",
            "review",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Update(args)) => {
                assert!(matches!(args.reload_style, Some(ReloadStyle::Sighup)));
                assert_eq!(args.reload_target.as_deref(), Some("review"));
            }
            _ => panic!("expected service update"),
        }
    }

    #[test]
    fn test_cli_parses_service_update_post_renew_low_level() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--post-renew-command",
            "systemctl",
            "--post-renew-arg",
            "reload",
            "--post-renew-arg",
            "nginx",
            "--post-renew-timeout-secs",
            "60",
            "--post-renew-on-failure",
            "stop",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Update(args)) => {
                assert_eq!(args.post_renew_command.as_deref(), Some("systemctl"));
                assert_eq!(args.post_renew_arg, vec!["reload", "nginx"]);
                assert_eq!(args.post_renew_timeout_secs, Some(60));
                assert!(matches!(
                    args.post_renew_on_failure,
                    Some(HookFailurePolicyArg::Stop)
                ));
            }
            _ => panic!("expected service update"),
        }
    }

    #[test]
    fn test_cli_parses_service_update_rn_cidrs_clear() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--rn-cidrs",
            "clear",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Update(args)) => {
                assert_eq!(args.rn_cidrs, vec!["clear"]);
            }
            _ => panic!("expected service update"),
        }
    }

    #[test]
    fn test_cli_parses_service_openbao_sidecar_start() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "openbao-sidecar",
            "start",
            "--service-name",
            "myapp",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::OpenbaoSidecar(
                ServiceOpenbaoSidecarCommand::Start(args),
            )) => {
                assert_eq!(args.service_name, "myapp");
                assert_eq!(
                    args.compose_file.compose_file,
                    PathBuf::from("docker-compose.yml")
                );
                assert!(
                    args.openbao_network.is_none(),
                    "openbao_network must default to None"
                );
            }
            _ => panic!("expected service openbao-sidecar start"),
        }
    }

    #[test]
    fn test_cli_parses_service_openbao_sidecar_start_with_openbao_network() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "openbao-sidecar",
            "start",
            "--service-name",
            "myapp",
            "--openbao-network",
            "external_net",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::OpenbaoSidecar(
                ServiceOpenbaoSidecarCommand::Start(args),
            )) => {
                assert_eq!(args.service_name, "myapp");
                assert_eq!(args.openbao_network.as_deref(), Some("external_net"));
            }
            _ => panic!("expected service openbao-sidecar start"),
        }
    }

    #[test]
    fn test_cli_parses_service_openbao_sidecar_start_custom_compose() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "openbao-sidecar",
            "start",
            "--service-name",
            "myapp",
            "--compose-file",
            "custom.yml",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::OpenbaoSidecar(
                ServiceOpenbaoSidecarCommand::Start(args),
            )) => {
                assert_eq!(args.service_name, "myapp");
                assert_eq!(args.compose_file.compose_file, PathBuf::from("custom.yml"));
            }
            _ => panic!("expected service openbao-sidecar start"),
        }
    }

    #[test]
    fn test_cli_service_openbao_sidecar_start_requires_service_name() {
        let result = Cli::try_parse_from(["bootroot", "service", "openbao-sidecar", "start"]);
        assert!(result.is_err(), "service-name should be required");
    }

    #[test]
    fn test_cli_service_openbao_sidecar_start_rejects_positional() {
        let result =
            Cli::try_parse_from(["bootroot", "service", "openbao-sidecar", "start", "myapp"]);
        assert!(
            result.is_err(),
            "positional service name should be rejected"
        );
    }

    /// Guards the deprecated `service agent start` alias: it must keep
    /// parsing into the same `ServiceOpenbaoSidecarStartArgs` payload so
    /// existing operators on the previous CLI surface keep working for
    /// one release.  Drop in the following release alongside the alias.
    #[test]
    fn test_cli_parses_deprecated_service_agent_start_alias() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "agent",
            "start",
            "--service-name",
            "myapp",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Agent(ServiceOpenbaoSidecarCommand::Start(
                args,
            ))) => {
                assert_eq!(args.service_name, "myapp");
            }
            _ => panic!("expected deprecated service agent start alias"),
        }
    }

    /// `--yes` must work both before and after the rotate subcommand
    /// (issue #587 §1).  Operators and CI scripts expect the flag to
    /// follow the subcommand naturally.
    #[test]
    fn test_cli_rotate_yes_after_subcommand() {
        let cli = Cli::parse_from([
            "bootroot",
            "rotate",
            "force-reissue",
            "--service-name",
            "edge-proxy",
            "--yes",
        ]);
        match cli.command {
            CliCommand::Rotate(args) => {
                assert!(args.yes);
                assert!(matches!(args.command, RotateCommand::ForceReissue(_)));
            }
            _ => panic!("expected Rotate command"),
        }
    }

    #[test]
    fn test_cli_rotate_yes_before_subcommand_still_works() {
        let cli = Cli::parse_from([
            "bootroot",
            "rotate",
            "--yes",
            "force-reissue",
            "--service-name",
            "edge-proxy",
        ]);
        match cli.command {
            CliCommand::Rotate(args) => {
                assert!(args.yes);
                assert!(matches!(args.command, RotateCommand::ForceReissue(_)));
            }
            _ => panic!("expected Rotate command"),
        }
    }

    #[test]
    fn test_cli_rotate_short_y_alias_works() {
        let cli = Cli::parse_from([
            "bootroot",
            "rotate",
            "force-reissue",
            "--service-name",
            "edge-proxy",
            "-y",
        ]);
        match cli.command {
            CliCommand::Rotate(args) => {
                assert!(args.yes);
            }
            _ => panic!("expected Rotate command"),
        }
    }

    #[test]
    fn test_cli_rotate_yes_global_on_db_subcommand() {
        let cli = Cli::parse_from(["bootroot", "rotate", "db", "-y"]);
        match cli.command {
            CliCommand::Rotate(args) => {
                assert!(args.yes);
                assert!(matches!(args.command, RotateCommand::Db(_)));
            }
            _ => panic!("expected Rotate command"),
        }
    }

    /// `--root-token-file` introduced in issue #587 §2.  It must parse
    /// successfully on rotate subcommands and be mutually exclusive with
    /// an explicit `--root-token` CLI flag.
    #[test]
    fn test_cli_rotate_parses_root_token_file() {
        let cli = Cli::parse_from([
            "bootroot",
            "rotate",
            "--root-token-file",
            "/secrets/root.token",
            "trust-sync",
        ]);
        match cli.command {
            CliCommand::Rotate(args) => {
                assert_eq!(
                    args.runtime_auth.root_token_file,
                    Some(PathBuf::from("/secrets/root.token"))
                );
                assert!(args.runtime_auth.root_token.is_none());
            }
            _ => panic!("expected Rotate command"),
        }
    }

    #[test]
    fn test_cli_rotate_rejects_root_token_with_root_token_file() {
        let result = Cli::try_parse_from([
            "bootroot",
            "rotate",
            "--root-token-file",
            "/secrets/root.token",
            "--root-token",
            "explicit-token",
            "trust-sync",
        ]);
        assert!(
            result.is_err(),
            "--root-token-file must conflict with --root-token at parse time"
        );
    }

    /// `--post-renew-arg` accepts hyphen-prefixed values (issue #587 §4):
    /// `-HUP`, `-f`, etc., which previously required `=` to bypass clap's
    /// short-flag parsing.
    #[test]
    fn test_cli_service_add_post_renew_arg_hyphen_value_space_form() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "add",
            "--post-renew-command",
            "pkill",
            "--post-renew-arg",
            "-HUP",
            "--post-renew-arg",
            "-f",
            "--post-renew-arg",
            "review",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert_eq!(args.post_renew_arg, vec!["-HUP", "-f", "review"]);
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_parses_reinit_defaults() {
        let cli = Cli::parse_from(["bootroot", "reinit"]);
        match cli.command {
            CliCommand::Reinit(args) => {
                assert!(!args.yes);
                assert!(args.root_token_output.is_none());
                assert!(!args.no_eab);
                assert!(args.enable.is_empty());
            }
            _ => panic!("expected reinit"),
        }
    }

    #[test]
    fn test_cli_parses_reinit_yes_short() {
        let cli = Cli::parse_from(["bootroot", "reinit", "-y"]);
        match cli.command {
            CliCommand::Reinit(args) => assert!(args.yes),
            _ => panic!("expected reinit"),
        }
    }

    #[test]
    fn test_cli_parses_reinit_full_flags() {
        let cli = Cli::parse_from([
            "bootroot",
            "reinit",
            "--yes",
            "--no-eab",
            "--enable",
            "show-secrets",
            "--root-token-output",
            "/tmp/root.token",
            "--summary-json",
            "out.json",
        ]);
        match cli.command {
            CliCommand::Reinit(args) => {
                assert!(args.yes);
                assert!(args.no_eab);
                assert!(args.enable.contains(&InitFeature::ShowSecrets));
                assert_eq!(
                    args.root_token_output,
                    Some(PathBuf::from("/tmp/root.token"))
                );
                assert_eq!(args.summary_json, Some(PathBuf::from("out.json")));
            }
            _ => panic!("expected reinit"),
        }
    }

    #[test]
    fn test_cli_service_add_post_renew_arg_hyphen_value_eq_form() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "add",
            "--post-renew-command",
            "pkill",
            "--post-renew-arg=-HUP",
            "--post-renew-arg=-f",
            "--post-renew-arg=review",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert_eq!(args.post_renew_arg, vec!["-HUP", "-f", "review"]);
            }
            _ => panic!("expected service add"),
        }
    }
}
