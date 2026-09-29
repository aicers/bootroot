//! The `OpenBao` material one service registration owns, and the three
//! operations both of its callers share: provisioning the derived policy
//! and `AppRole`, seeding the registration's trust material, and tearing
//! that material down again. A fourth operation, finding the
//! registrations the registrar manages, has one caller only — the CLI
//! rotations, which fan control-node material out to them — and lives
//! here because it is defined by the same KV layout.
//!
//! Two callers reach this module and they are deliberately asymmetric:
//!
//! - the CLI's `service add` / `service remove`, which construct an
//!   authenticated client, read `state.json`, prompt, and own local
//!   artifacts; and
//! - the registrar's mint / deregister verbs, which have none of those
//!   and run under a privileged client of their own.
//!
//! What is shared is exactly the part that must not drift: the derived
//! `bootroot-service-<registration_id>` role and policy names, the policy
//! body, the trust material a registration's KV subtree is seeded with
//! (`eab`, `http_responder_hmac`, `trust`, read from the control-node
//! records), and the delete sequence. What is **not** shared is credential
//! issuance. [`provision_service_role`] never creates a `secret_id` and
//! never returns one, and [`write_service_trust_material`] never reads,
//! writes or accepts one, because the two callers deliver it differently
//! — the CLI writes a raw value to a file (and, for a remote service, to
//! KV), the registrar hands a response-wrapping token to a remote caller
//! and must never hold the unwrapped secret at all. Putting issuance here
//! would force one of them onto the other's delivery.
//!
//! [`list_registrar_managed_ids`] is the CLI-only operation. A
//! registrar-minted identity is never in `state.json`, so the rotations
//! that rewrite every service's `trust`, `http_responder_hmac` or `eab`
//! record find those identities by the one durable record they have:
//! the `registrar_binding` under their KV subtree.
//!
//! Nothing here reads `state.json`, prompts, or knows a delivery mode.
//! Every value the operations depend on — the KV mount, the role-level
//! TTLs, the KV suffixes to sweep — arrives as a parameter, so the two
//! callers can keep the different sets they intentionally have.

use anyhow::{Context, Result};
use thiserror::Error;

use crate::openbao::OpenBaoClient;
use crate::registrar_certs::{PATH_AGENT_EAB, PATH_RESPONDER_HMAC};
use crate::secret::HmacSecret;
use crate::trust_bootstrap::{
    CA_BUNDLE_PEM_KEY, CA_TRUST_KV_PATH, EAB_HMAC_KEY, EAB_KID_KEY, HMAC_KEY,
    REGISTRAR_BINDING_KV_SUFFIX, SERVICE_EAB_KV_SUFFIX, SERVICE_KV_BASE, SERVICE_REISSUE_KV_SUFFIX,
    SERVICE_RESPONDER_HMAC_KV_SUFFIX, SERVICE_TRUST_KV_SUFFIX, TRUSTED_CA_KEY,
};

/// Prefix of the derived per-registration role and policy names. The two
/// names are one derivation, so a registration's role and its policy are
/// always spelled alike.
pub const SERVICE_ROLE_PREFIX: &str = "bootroot-service-";

/// Returns the derived `AppRole` name for a registration.
#[must_use]
pub fn service_role_name(registration_id: &str) -> String {
    format!("{SERVICE_ROLE_PREFIX}{registration_id}")
}

/// Returns the derived policy name for a registration, which is the same
/// derivation as [`service_role_name`].
#[must_use]
pub fn service_policy_name(registration_id: &str) -> String {
    format!("{SERVICE_ROLE_PREFIX}{registration_id}")
}

/// Returns the KV v2 path of one of a registration's records.
#[must_use]
pub fn service_kv_path(registration_id: &str, suffix: &str) -> String {
    format!("{SERVICE_KV_BASE}/{registration_id}/{suffix}")
}

/// Builds the service `AppRole` policy body.
///
/// Every path is scoped to the registration's own KV subtree, so two
/// registrations of one component on one host never see each other's
/// material. The subtree is read-only except for the registration's own
/// reissue object: the fast-poll loop must write
/// `completed_at`/`completed_version` back so the control plane's
/// `rotate force-reissue --wait` can observe completion, and that one
/// path — and no other — carries create/update.
#[must_use]
pub fn build_service_policy(kv_mount: &str, registration_id: &str) -> String {
    let base = format!("{SERVICE_KV_BASE}/{registration_id}");
    format!(
        r#"path "{kv_mount}/data/{base}/{SERVICE_REISSUE_KV_SUFFIX}" {{
  capabilities = ["read", "create", "update"]
}}
path "{kv_mount}/data/{base}/*" {{
  capabilities = ["read"]
}}
path "{kv_mount}/metadata/{base}/*" {{
  capabilities = ["list"]
}}
"#
    )
}

/// The role-level `AppRole` lifetimes a caller provisions with.
///
/// These are *role* settings, not per-issuance ones, and they are the
/// caller's to choose: the CLI passes the values its `init` constants
/// fix, and the registrar passes the ones fixed at its construction. The
/// library declares neither, so neither caller can silently inherit the
/// other's.
#[derive(Debug, Clone, Copy)]
pub struct ServiceRoleTtls<'a> {
    /// `token_ttl`, which is also used as `token_max_ttl`.
    pub token_ttl: &'a str,
    /// Role-level `secret_id_ttl`.
    pub secret_id_ttl: &'a str,
}

/// Which step of [`provision_service_role`] failed.
///
/// Carried so a caller can keep the distinct diagnostic it reported
/// before this logic was shared, rather than collapsing three failures
/// onto one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceProvisionStep {
    /// Writing the derived policy.
    Policy,
    /// Creating or converging the derived `AppRole`.
    AppRole,
    /// Reading the role's `role_id` back.
    RoleId,
}

impl ServiceProvisionStep {
    /// Returns a stable lowercase name for the step.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "policy write",
            Self::AppRole => "approle create",
            Self::RoleId => "role id read",
        }
    }
}

/// A failure in one step of [`provision_service_role`].
#[derive(Debug, Error)]
#[error("service role provisioning failed for {registration_id} at the {} step", step.as_str())]
pub struct ServiceProvisionError {
    /// The step that failed.
    pub step: ServiceProvisionStep,
    /// The registration whose material was being provisioned.
    pub registration_id: String,
    /// The underlying `OpenBao` failure.
    #[source]
    pub source: anyhow::Error,
}

/// The derived role and policy a successful provisioning converged on.
///
/// There is deliberately no `secret_id` field: issuance stays at each
/// caller's boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedServiceRole {
    /// The derived `AppRole` name.
    pub role_name: String,
    /// The derived policy name, which equals `role_name`.
    pub policy_name: String,
    /// The role's `role_id`, read back after the role was converged.
    pub role_id: String,
}

/// Creates or converges the derived policy and `AppRole` for a
/// registration and returns its `role_id`.
///
/// Idempotent in both directions: `write_policy` and `create_approle`
/// are upserts, so re-running this against an already-provisioned
/// registration re-applies the current policy body and role settings
/// rather than failing. That is what lets a caller re-drive an
/// interrupted provisioning without a separate repair path.
///
/// **No `secret_id` is created here, and none is returned.** A caller
/// that needs one issues it itself, in the delivery its own boundary
/// requires.
///
/// # Errors
///
/// Returns [`ServiceProvisionError`] naming the step that failed.
pub async fn provision_service_role(
    client: &OpenBaoClient,
    kv_mount: &str,
    registration_id: &str,
    ttls: ServiceRoleTtls<'_>,
) -> Result<ProvisionedServiceRole, ServiceProvisionError> {
    let fail = |step: ServiceProvisionStep| {
        move |source: anyhow::Error| ServiceProvisionError {
            step,
            registration_id: registration_id.to_string(),
            source,
        }
    };

    let policy_name = service_policy_name(registration_id);
    let policy = build_service_policy(kv_mount, registration_id);
    client
        .write_policy(&policy_name, &policy)
        .await
        .map_err(fail(ServiceProvisionStep::Policy))?;

    let role_name = service_role_name(registration_id);
    client
        .create_approle(
            &role_name,
            &[policy_name.as_str()],
            ttls.token_ttl,
            ttls.secret_id_ttl,
            true,
        )
        .await
        .map_err(fail(ServiceProvisionStep::AppRole))?;

    let role_id = client
        .read_role_id(&role_name)
        .await
        .map_err(fail(ServiceProvisionStep::RoleId))?;

    Ok(ProvisionedServiceRole {
        role_name,
        policy_name,
        role_id,
    })
}

/// The key the control-node responder HMAC record carries its value
/// under. The per-service copy is keyed [`HMAC_KEY`] instead.
const CONTROL_RESPONDER_HMAC_VALUE_KEY: &str = "value";

/// Length in hex characters of a SHA-256 fingerprint.
const SHA256_FINGERPRINT_HEX_LEN: usize = 64;

/// A required string key missing from, or not a string in, one of the
/// control-node records [`read_service_trust_material`] reads.
///
/// The rendered forms are the diagnostics `service add` reported before
/// this logic was shared, so the CLI can surface them unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TrustMaterialKey {
    /// `kid` in `bootroot/agent/eab`.
    #[error("OpenBao EAB data missing key: kid")]
    EabKid,
    /// `hmac` in `bootroot/agent/eab`.
    #[error("OpenBao EAB data missing key: hmac")]
    EabHmac,
    /// `value` in `bootroot/responder/hmac`.
    #[error("OpenBao responder HMAC data missing key: value")]
    ResponderHmac,
    /// `ca_bundle_pem` in `bootroot/ca`.
    #[error("OpenBao CA trust data missing key: ca_bundle_pem")]
    CaBundlePem,
}

/// A failure reading, validating or writing a registration's trust
/// material.
///
/// Typed by failure so each caller can keep its own rendering: the CLI
/// maps every variant onto the localized diagnostic it reported before
/// this logic was shared, and the registrar folds it into its one
/// unclassified unavailability.
#[derive(Debug, Error)]
pub enum ServiceTrustError {
    /// Reading a control-node record failed. A clean not-found on the
    /// optional EAB record is not a failure and never lands here.
    #[error("reading KV path {path} failed")]
    Read {
        /// The KV path, spelled without the mount.
        path: &'static str,
        /// The underlying `OpenBao` failure.
        #[source]
        source: anyhow::Error,
    },
    /// Writing one of the registration's records failed. The write may
    /// have reached `OpenBao` before it failed.
    #[error("writing KV path {path} failed")]
    Write {
        /// The KV path, spelled without the mount.
        path: String,
        /// The underlying `OpenBao` failure.
        #[source]
        source: anyhow::Error,
    },
    /// `bootroot/ca` carries no `trusted_ca_sha256` key.
    #[error("CA trust data missing key: {key}")]
    CaTrustMissing {
        /// The missing key.
        key: &'static str,
    },
    /// `trusted_ca_sha256` is an empty list.
    #[error("CA trust list is empty")]
    CaTrustEmpty,
    /// `trusted_ca_sha256` is not a list of 64-hex-character strings.
    #[error("CA trust list is invalid")]
    CaTrustInvalid,
    /// A required string key is missing from a control-node record.
    #[error(transparent)]
    MissingKey(#[from] TrustMaterialKey),
}

/// The trust material a registration's KV subtree is seeded with, as
/// read from the deployment's control-node records.
///
/// There is deliberately no `secret_id` field: credential delivery stays
/// at each caller's boundary.
#[derive(Debug, Clone)]
pub struct ServiceTrustMaterial {
    /// The shared agent EAB key id, or `None` when the deployment has no
    /// EAB record.
    pub eab_kid: Option<String>,
    /// The shared agent EAB HMAC, present exactly when `eab_kid` is.
    pub eab_hmac: Option<HmacSecret>,
    /// The deployment's HTTP-01 responder HMAC.
    pub responder_hmac: HmacSecret,
    /// The pinned CA fingerprints, lowercase or uppercase hex as stored.
    pub trusted_ca_sha256: Vec<String>,
    /// The CA bundle PEM the fingerprints are drawn from.
    pub ca_bundle_pem: String,
}

/// Reads the control-node records a registration's trust material is
/// assembled from: `bootroot/agent/eab`, `bootroot/responder/hmac` and
/// `bootroot/ca`, in that order.
///
/// The EAB record is optional: it exists only when the operator supplied
/// EAB credentials, so a clean not-found reads as "no EAB". Every other
/// failure on it — transport, 5xx, a denied read — propagates, so a
/// transient outage cannot silently strip EAB from a registration. The
/// other two records are required.
///
/// Only the shapes are checked here. The bundle is not checked against
/// its fingerprints: each consumer of the seeded `trust` record re-runs
/// that consistency check on what it reads.
///
/// # Errors
///
/// Returns [`ServiceTrustError::Read`] when a read fails,
/// [`ServiceTrustError::CaTrustMissing`], [`ServiceTrustError::CaTrustInvalid`]
/// or [`ServiceTrustError::CaTrustEmpty`] when `trusted_ca_sha256` is
/// absent, malformed or empty, and [`ServiceTrustError::MissingKey`] when
/// a required string key is absent.
pub async fn read_service_trust_material(
    client: &OpenBaoClient,
    kv_mount: &str,
) -> Result<ServiceTrustMaterial, ServiceTrustError> {
    let read_failed = |path: &'static str| move |source| ServiceTrustError::Read { path, source };
    let eab = client
        .try_read_kv(kv_mount, PATH_AGENT_EAB)
        .await
        .map_err(read_failed(PATH_AGENT_EAB))?;
    let responder_hmac = client
        .read_kv(kv_mount, PATH_RESPONDER_HMAC)
        .await
        .map_err(read_failed(PATH_RESPONDER_HMAC))?;
    let trust = client
        .read_kv(kv_mount, CA_TRUST_KV_PATH)
        .await
        .map_err(read_failed(CA_TRUST_KV_PATH))?;

    let trusted_ca_sha256 = parse_trusted_ca_list(trust.get(TRUSTED_CA_KEY).ok_or(
        ServiceTrustError::CaTrustMissing {
            key: TRUSTED_CA_KEY,
        },
    )?)?;
    if trusted_ca_sha256.is_empty() {
        return Err(ServiceTrustError::CaTrustEmpty);
    }
    let (eab_kid, eab_hmac) = match &eab {
        Some(data) => (
            Some(required_string(
                data,
                EAB_KID_KEY,
                TrustMaterialKey::EabKid,
            )?),
            Some(HmacSecret::new(required_string(
                data,
                EAB_HMAC_KEY,
                TrustMaterialKey::EabHmac,
            )?)),
        ),
        None => (None, None),
    };
    let responder_hmac = HmacSecret::new(required_string(
        &responder_hmac,
        CONTROL_RESPONDER_HMAC_VALUE_KEY,
        TrustMaterialKey::ResponderHmac,
    )?);
    let ca_bundle_pem = required_string(&trust, CA_BUNDLE_PEM_KEY, TrustMaterialKey::CaBundlePem)?;

    Ok(ServiceTrustMaterial {
        eab_kid,
        eab_hmac,
        responder_hmac,
        trusted_ca_sha256,
        ca_bundle_pem,
    })
}

/// Writes a registration's trust material into its KV subtree: `eab`,
/// then `http_responder_hmac`, then `trust`.
///
/// `eab` is written **always**, as `{ "kid": "", "hmac": "" }` when the
/// deployment has no EAB. The agent's fast-poll loop reads that path on
/// every cycle, and the explicit empty shape is the durable "no EAB"
/// representation it applies (removing any stale `eab.json`), whereas a
/// missing path would be ambiguous between "cleared" and "never
/// provisioned".
///
/// Every write is unconditional, so each call bumps the three records'
/// KV versions even when their content is unchanged.
///
/// # Errors
///
/// Returns [`ServiceTrustError::Write`] naming the first write that
/// failed; the writes after it are not attempted.
pub async fn write_service_trust_material(
    client: &OpenBaoClient,
    kv_mount: &str,
    registration_id: &str,
    material: &ServiceTrustMaterial,
) -> Result<(), ServiceTrustError> {
    let eab_kid = material.eab_kid.as_deref().unwrap_or("");
    let eab_hmac = material.eab_hmac.as_ref().map_or("", HmacSecret::expose);
    write_record(
        client,
        kv_mount,
        service_kv_path(registration_id, SERVICE_EAB_KV_SUFFIX),
        serde_json::json!({
            EAB_KID_KEY: eab_kid,
            EAB_HMAC_KEY: eab_hmac,
        }),
    )
    .await?;
    write_record(
        client,
        kv_mount,
        service_kv_path(registration_id, SERVICE_RESPONDER_HMAC_KV_SUFFIX),
        serde_json::json!({ HMAC_KEY: material.responder_hmac.expose() }),
    )
    .await?;
    write_service_trust_record(
        client,
        kv_mount,
        registration_id,
        &material.trusted_ca_sha256,
        &material.ca_bundle_pem,
    )
    .await
}

/// Writes one registration's `trust` record:
/// `{ "trusted_ca_sha256": [...], "ca_bundle_pem": <pem> }`.
///
/// # Errors
///
/// Returns [`ServiceTrustError::Write`] when the write fails.
pub async fn write_service_trust_record(
    client: &OpenBaoClient,
    kv_mount: &str,
    registration_id: &str,
    trusted_ca_sha256: &[String],
    ca_bundle_pem: &str,
) -> Result<(), ServiceTrustError> {
    write_record(
        client,
        kv_mount,
        service_kv_path(registration_id, SERVICE_TRUST_KV_SUFFIX),
        serde_json::json!({
            TRUSTED_CA_KEY: trusted_ca_sha256,
            CA_BUNDLE_PEM_KEY: ca_bundle_pem,
        }),
    )
    .await
}

async fn write_record(
    client: &OpenBaoClient,
    kv_mount: &str,
    path: String,
    data: serde_json::Value,
) -> Result<(), ServiceTrustError> {
    match client.write_kv(kv_mount, &path, data).await {
        Ok(()) => Ok(()),
        Err(source) => Err(ServiceTrustError::Write { path, source }),
    }
}

/// Parses a `trusted_ca_sha256` value: an array of 64-hex-character
/// strings. An empty array parses; whether one is acceptable is the
/// caller's decision.
///
/// # Errors
///
/// Returns [`ServiceTrustError::CaTrustInvalid`] when the value is not an
/// array, or an element is not a 64-hex-character string.
pub fn parse_trusted_ca_list(value: &serde_json::Value) -> Result<Vec<String>, ServiceTrustError> {
    let items = value.as_array().ok_or(ServiceTrustError::CaTrustInvalid)?;
    items
        .iter()
        .map(|item| match item.as_str() {
            Some(fingerprint) if is_valid_sha256_fingerprint(fingerprint) => {
                Ok(fingerprint.to_string())
            }
            _ => Err(ServiceTrustError::CaTrustInvalid),
        })
        .collect()
}

fn is_valid_sha256_fingerprint(value: &str) -> bool {
    value.len() == SHA256_FINGERPRINT_HEX_LEN && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn required_string(
    value: &serde_json::Value,
    key: &str,
    missing: TrustMaterialKey,
) -> Result<String, TrustMaterialKey> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or(missing)
}

/// One `OpenBao` resource a teardown attempted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceResource {
    /// A KV v2 path, spelled without the mount.
    Kv(String),
    /// An `AppRole`, by name.
    AppRole(String),
    /// An ACL policy, by name.
    Policy(String),
}

/// What happened to one resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceOutcome {
    /// The resource existed and was deleted.
    Removed,
    /// The resource was already absent — the idempotent re-run case,
    /// which is a success.
    AlreadyAbsent,
    /// The deletion failed. Carries the rendered failure, because the
    /// teardown keeps going and the `anyhow::Error` cannot be held
    /// alongside a `Clone`/`PartialEq` outcome.
    Failed(String),
}

impl ResourceOutcome {
    /// Returns whether this outcome leaves the resource gone.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        matches!(self, Self::Removed | Self::AlreadyAbsent)
    }
}

/// One resource and what happened to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceTeardown {
    /// The resource the attempt targeted.
    pub resource: ServiceResource,
    /// The result of the attempt.
    pub outcome: ResourceOutcome,
}

/// Every resource a teardown attempted, in attempt order.
///
/// A teardown never short-circuits: one failed deletion must not leave
/// the rest of a registration's material behind, because the caller's
/// durable record of the registration is retained on any failure and the
/// re-run has to make progress.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TeardownReport {
    attempts: Vec<ResourceTeardown>,
}

impl TeardownReport {
    /// Returns every attempt, in the order they were made.
    #[must_use]
    pub fn attempts(&self) -> &[ResourceTeardown] {
        &self.attempts
    }

    /// Returns whether every attempted resource is now gone.
    ///
    /// Already-absent counts as success: a deregistration is idempotent,
    /// and a resource an earlier run removed is not a failure to remove
    /// it again.
    #[must_use]
    pub fn aggregate_success(&self) -> bool {
        self.attempts
            .iter()
            .all(|attempt| attempt.outcome.succeeded())
    }

    fn record(&mut self, resource: ServiceResource, result: Result<bool>) {
        let outcome = match result {
            Ok(true) => ResourceOutcome::Removed,
            Ok(false) => ResourceOutcome::AlreadyAbsent,
            Err(err) => ResourceOutcome::Failed(format!("{err:#}")),
        };
        self.attempts.push(ResourceTeardown { resource, outcome });
    }
}

/// Deletes a registration's `OpenBao` material: every KV path named by
/// `kv_suffixes`, then the derived `AppRole`, then the derived policy.
///
/// Every resource is attempted even when an earlier one failed, and the
/// per-resource outcome is reported rather than raised, so the caller
/// decides what a partial failure means for its own durable record. The
/// role and policy names are derived from `registration_id` here; a
/// caller does not pass them, so the names torn down cannot drift from
/// the names [`provision_service_role`] created.
///
/// `kv_suffixes` is the caller's set on purpose. The CLI passes what its
/// `state.json` entry says it wrote; the registrar passes the full
/// service-material set. Neither includes a registrar binding — a
/// binding outlives the material it covers and is deleted separately,
/// only after this report reports aggregate success.
pub async fn teardown_service_material(
    client: &OpenBaoClient,
    kv_mount: &str,
    registration_id: &str,
    kv_suffixes: &[&str],
) -> TeardownReport {
    let mut report = TeardownReport::default();

    for suffix in kv_suffixes {
        let path = service_kv_path(registration_id, suffix);
        let result = delete_kv_if_present(client, kv_mount, &path).await;
        report.record(ServiceResource::Kv(path), result);
    }

    let role_name = service_role_name(registration_id);
    let result = delete_approle_if_present(client, &role_name).await;
    report.record(ServiceResource::AppRole(role_name), result);

    let policy_name = service_policy_name(registration_id);
    let result = delete_policy_if_present(client, &policy_name).await;
    report.record(ServiceResource::Policy(policy_name), result);

    report
}

/// Returns the registration ids whose KV subtree carries a registrar
/// binding, sorted.
///
/// Lists `bootroot/services/` and keeps each subtree key (one ending in
/// `/`) whose `registrar_binding` record reads back present. A key
/// without the trailing `/` is a leaf record directly under
/// `bootroot/services/`, not a registration subtree, and is skipped
/// without a read. The binding is read for presence only and is not
/// decoded: its state and schema version do not change who owns the id.
/// Presence is checked on the `data/` path, not `metadata/`, because
/// that is what the runtime-rotate policy grants `read` on.
///
/// A subtree with no binding is not reported. Nothing records who owns
/// it, and a caller that writes into what it reports must not guess.
///
/// # Errors
///
/// Returns an error if the listing fails for any reason other than an
/// empty (not-found) tree — a 403 from a token without `list` on
/// `<kv>/metadata/bootroot/services/` included — or if any binding read
/// fails other than as a clean not-found.
pub async fn list_registrar_managed_ids(
    client: &OpenBaoClient,
    kv_mount: &str,
) -> Result<Vec<String>> {
    let base = format!("{SERVICE_KV_BASE}/");
    let keys = client
        .list_kv(kv_mount, &base)
        .await
        .with_context(|| format!("listing KV path {base}"))?;

    let mut ids = Vec::new();
    for registration_id in keys
        .iter()
        .filter_map(|key| key.strip_suffix('/'))
        .filter(|id| !id.is_empty())
    {
        let path = service_kv_path(registration_id, REGISTRAR_BINDING_KV_SUFFIX);
        if client
            .try_read_kv(kv_mount, &path)
            .await
            .with_context(|| format!("reading KV path {path}"))?
            .is_some()
        {
            ids.push(registration_id.to_string());
        }
    }
    ids.sort_unstable();
    Ok(ids)
}

async fn delete_kv_if_present(client: &OpenBaoClient, mount: &str, path: &str) -> Result<bool> {
    if client
        .kv_exists(mount, path)
        .await
        .with_context(|| format!("checking KV path {path}"))?
    {
        client
            .delete_kv(mount, path)
            .await
            .with_context(|| format!("deleting KV path {path}"))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn delete_approle_if_present(client: &OpenBaoClient, role_name: &str) -> Result<bool> {
    if client
        .approle_exists(role_name)
        .await
        .with_context(|| format!("checking AppRole {role_name}"))?
    {
        client
            .delete_approle(role_name)
            .await
            .with_context(|| format!("deleting AppRole {role_name}"))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn delete_policy_if_present(client: &OpenBaoClient, policy_name: &str) -> Result<bool> {
    if client
        .policy_exists(policy_name)
        .await
        .with_context(|| format!("checking policy {policy_name}"))?
    {
        client
            .delete_policy(policy_name)
            .await
            .with_context(|| format!("deleting policy {policy_name}"))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const FINGERPRINT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const BUNDLE: &str = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";

    fn client(server: &MockServer) -> OpenBaoClient {
        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("test-token".to_string());
        client
    }

    async fn mount_read(server: &MockServer, kv_path: &str, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(format!("/v1/secret/data/{kv_path}")))
            .respond_with(response)
            .mount(server)
            .await;
    }

    fn kv(data: &serde_json::Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({ "data": { "data": data } }))
    }

    /// Mounts a well-formed responder HMAC and CA record, and — unless a
    /// test mounted its own first — no EAB record at all.
    async fn mount_control_node(server: &MockServer) {
        mount_read(
            server,
            PATH_RESPONDER_HMAC,
            kv(&json!({ "value": "r-hmac" })),
        )
        .await;
        mount_read(
            server,
            CA_TRUST_KV_PATH,
            kv(&json!({ "trusted_ca_sha256": [FINGERPRINT], "ca_bundle_pem": BUNDLE })),
        )
        .await;
    }

    async fn read_with(
        eab: Option<ResponseTemplate>,
        hmac: Option<serde_json::Value>,
        ca: Option<serde_json::Value>,
    ) -> Result<ServiceTrustMaterial, ServiceTrustError> {
        let server = MockServer::start().await;
        if let Some(eab) = eab {
            mount_read(&server, PATH_AGENT_EAB, eab).await;
        }
        if let Some(hmac) = hmac {
            mount_read(&server, PATH_RESPONDER_HMAC, kv(&hmac)).await;
        }
        if let Some(ca) = ca {
            mount_read(&server, CA_TRUST_KV_PATH, kv(&ca)).await;
        }
        mount_control_node(&server).await;
        read_service_trust_material(&client(&server), "secret").await
    }

    #[tokio::test]
    async fn an_absent_control_node_eab_reads_as_none() {
        let material = read_with(None, None, None).await.expect("reads");
        assert!(material.eab_kid.is_none());
        assert!(material.eab_hmac.is_none());
        assert_eq!(material.responder_hmac.expose(), "r-hmac");
        assert_eq!(material.trusted_ca_sha256, [FINGERPRINT]);
        assert_eq!(material.ca_bundle_pem, BUNDLE);
    }

    #[tokio::test]
    async fn a_failed_control_node_eab_read_is_an_error_not_an_absence() {
        let err = read_with(Some(ResponseTemplate::new(500)), None, None)
            .await
            .expect_err("a 500 must not read as no EAB");
        assert!(
            matches!(err, ServiceTrustError::Read { path, .. } if path == PATH_AGENT_EAB),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn an_eab_with_empty_strings_is_accepted_and_written_through() {
        let server = MockServer::start().await;
        mount_read(
            &server,
            PATH_AGENT_EAB,
            kv(&json!({ "kid": "", "hmac": "" })),
        )
        .await;
        mount_control_node(&server).await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let client = client(&server);

        let material = read_service_trust_material(&client, "secret")
            .await
            .expect("empty strings are accepted");
        assert_eq!(material.eab_kid.as_deref(), Some(""));
        write_service_trust_material(&client, "secret", "h1-roxyd", &material)
            .await
            .expect("writes");

        let requests = server.received_requests().await.expect("recorded");
        let writes: Vec<(String, serde_json::Value)> = requests
            .iter()
            .filter(|request| request.method.as_str() == "POST")
            .map(|request| {
                let body: serde_json::Value =
                    serde_json::from_slice(&request.body).expect("json body");
                (request.url.path().to_string(), body["data"].clone())
            })
            .collect();
        assert_eq!(
            writes,
            [
                (
                    "/v1/secret/data/bootroot/services/h1-roxyd/eab".to_string(),
                    json!({ "kid": "", "hmac": "" })
                ),
                (
                    "/v1/secret/data/bootroot/services/h1-roxyd/http_responder_hmac".to_string(),
                    json!({ "hmac": "r-hmac" })
                ),
                (
                    "/v1/secret/data/bootroot/services/h1-roxyd/trust".to_string(),
                    json!({ "trusted_ca_sha256": [FINGERPRINT], "ca_bundle_pem": BUNDLE })
                ),
            ]
        );
        assert!(
            requests
                .iter()
                .all(|request| !request.url.path().ends_with("/secret_id")),
            "seeding never touches a secret_id"
        );
    }

    #[tokio::test]
    async fn an_eab_missing_a_key_is_an_error() {
        let err = read_with(Some(kv(&json!({ "kid": "k" }))), None, None)
            .await
            .expect_err("a half EAB is malformed");
        assert!(matches!(
            err,
            ServiceTrustError::MissingKey(TrustMaterialKey::EabHmac)
        ));
    }

    #[tokio::test]
    async fn a_responder_hmac_without_its_value_is_an_error() {
        let err = read_with(None, Some(json!({ "hmac": "wrong-key" })), None)
            .await
            .expect_err("the control-node record keys its value as `value`");
        assert!(matches!(
            err,
            ServiceTrustError::MissingKey(TrustMaterialKey::ResponderHmac)
        ));
    }

    #[tokio::test]
    async fn a_malformed_ca_record_is_a_typed_error() {
        let err = read_with(
            None,
            None,
            Some(json!({ "trusted_ca_sha256": [], "ca_bundle_pem": BUNDLE })),
        )
        .await
        .expect_err("an empty list is refused");
        assert!(matches!(err, ServiceTrustError::CaTrustEmpty), "{err:?}");

        let err = read_with(
            None,
            None,
            Some(json!({ "trusted_ca_sha256": ["not-hex"], "ca_bundle_pem": BUNDLE })),
        )
        .await
        .expect_err("a non-hex fingerprint is refused");
        assert!(matches!(err, ServiceTrustError::CaTrustInvalid), "{err:?}");

        let err = read_with(None, None, Some(json!({ "ca_bundle_pem": BUNDLE })))
            .await
            .expect_err("a missing list is refused");
        assert!(
            matches!(err, ServiceTrustError::CaTrustMissing { key } if key == TRUSTED_CA_KEY),
            "{err:?}"
        );

        let err = read_with(
            None,
            None,
            Some(json!({ "trusted_ca_sha256": [FINGERPRINT] })),
        )
        .await
        .expect_err("a missing bundle is refused");
        assert!(matches!(
            err,
            ServiceTrustError::MissingKey(TrustMaterialKey::CaBundlePem)
        ));
    }

    #[tokio::test]
    async fn a_failed_write_stops_the_sequence_and_names_its_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/v1/secret/data/bootroot/services/h1-roxyd/http_responder_hmac",
            ))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let material = ServiceTrustMaterial {
            eab_kid: None,
            eab_hmac: None,
            responder_hmac: HmacSecret::new("r-hmac".to_string()),
            trusted_ca_sha256: vec![FINGERPRINT.to_string()],
            ca_bundle_pem: BUNDLE.to_string(),
        };

        let err = write_service_trust_material(&client(&server), "secret", "h1-roxyd", &material)
            .await
            .expect_err("the responder write fails");
        assert!(
            matches!(&err, ServiceTrustError::Write { path, .. }
                if path == "bootroot/services/h1-roxyd/http_responder_hmac"),
            "{err:?}"
        );
        let requests = server.received_requests().await.expect("recorded");
        assert_eq!(requests.len(), 2, "the trust write is not attempted");
    }

    #[test]
    fn parse_trusted_ca_list_accepts_valid() {
        let value = json!(["a".repeat(64), "B".repeat(64)]);
        let parsed = parse_trusted_ca_list(&value).expect("parse list");
        assert_eq!(parsed, ["a".repeat(64), "B".repeat(64)]);
        assert_eq!(
            parse_trusted_ca_list(&json!([])).expect("empty"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn parse_trusted_ca_list_rejects_non_array() {
        assert!(matches!(
            parse_trusted_ca_list(&json!("not-array")),
            Err(ServiceTrustError::CaTrustInvalid)
        ));
    }

    #[test]
    fn parse_trusted_ca_list_rejects_invalid_fingerprint() {
        for value in [json!(["not-hex"]), json!(["g".repeat(64)]), json!([7])] {
            assert!(matches!(
                parse_trusted_ca_list(&value),
                Err(ServiceTrustError::CaTrustInvalid)
            ));
        }
    }

    #[test]
    fn service_policy_grants_write_only_on_reissue_path() {
        let policy = build_service_policy("secret", "edge-proxy");

        assert!(
            policy.contains(
                "path \"secret/data/bootroot/services/edge-proxy/reissue\" {\n  capabilities = [\"read\", \"create\", \"update\"]"
            ),
            "reissue path must carry create/update, got:\n{policy}"
        );
        assert!(
            policy.contains(
                "path \"secret/data/bootroot/services/edge-proxy/*\" {\n  capabilities = [\"read\"]"
            ),
            "rest of data subtree must stay read-only, got:\n{policy}"
        );
        assert!(
            policy.contains(
                "path \"secret/metadata/bootroot/services/edge-proxy/*\" {\n  capabilities = [\"list\"]"
            ),
            "metadata subtree must stay list-only, got:\n{policy}"
        );
    }

    /// The policy body is keyed on `registration_id`, so two
    /// registrations of one component on one host get disjoint KV
    /// subtrees even though their `service_name` is identical.
    #[test]
    fn service_policy_paths_derive_from_registration_id() {
        let first = build_service_policy("secret", "h1-piglet-001");
        let second = build_service_policy("secret", "h1-piglet-002");

        assert!(first.contains("secret/data/bootroot/services/h1-piglet-001/"));
        assert!(second.contains("secret/data/bootroot/services/h1-piglet-002/"));
        assert!(!first.contains("h1-piglet-002"));
        assert!(!second.contains("h1-piglet-001"));
    }

    #[test]
    fn service_policy_grants_no_broader_write_scope() {
        let policy = build_service_policy("secret", "edge-proxy");

        for block in policy.split("path ").filter(|b| !b.is_empty()) {
            let has_write = block.contains("create") || block.contains("update");
            let is_reissue =
                block.starts_with("\"secret/data/bootroot/services/edge-proxy/reissue\"");
            assert!(
                !has_write || is_reissue,
                "unexpected write capability outside the reissue path:\n{block}"
            );
        }
    }

    /// The role and policy names are one and the same derivation off
    /// `registration_id`, and a one-per-deployment singleton whose key is
    /// still the bare component name keeps the exact names it had before
    /// the split.
    #[test]
    fn role_and_policy_names_derive_from_registration_id() {
        assert_eq!(service_role_name("review"), "bootroot-service-review");
        assert_eq!(service_policy_name("review"), "bootroot-service-review");
        assert_eq!(
            service_role_name("h1-piglet-001"),
            "bootroot-service-h1-piglet-001"
        );
        assert_ne!(
            service_role_name("h1-piglet-001"),
            service_role_name("h1-piglet-002")
        );
    }

    #[test]
    fn kv_path_composes_under_the_service_base() {
        assert_eq!(
            service_kv_path("h1-piglet-001", "registrar_binding"),
            "bootroot/services/h1-piglet-001/registrar_binding"
        );
    }

    #[test]
    fn aggregate_success_treats_already_absent_as_a_success() {
        let mut report = TeardownReport::default();
        report.record(ServiceResource::Kv("a".to_string()), Ok(true));
        report.record(ServiceResource::Kv("b".to_string()), Ok(false));
        assert!(report.aggregate_success());
        assert_eq!(report.attempts().len(), 2);

        report.record(
            ServiceResource::Policy("p".to_string()),
            Err(anyhow::anyhow!("boom")),
        );
        assert!(!report.aggregate_success());
        assert_eq!(
            report.attempts().last().map(|a| &a.outcome),
            Some(&ResourceOutcome::Failed("boom".to_string()))
        );
    }

    const SERVICES_LIST_PATH: &str = "/v1/secret/metadata/bootroot/services/";

    async fn mount_listing(server: &MockServer, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(SERVICES_LIST_PATH))
            .and(query_param("list", "true"))
            .respond_with(response)
            .mount(server)
            .await;
    }

    fn listing(keys: &[&str]) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({ "data": { "keys": keys } }))
    }

    fn binding_path(registration_id: &str) -> String {
        service_kv_path(registration_id, REGISTRAR_BINDING_KV_SUFFIX)
    }

    fn not_found() -> ResponseTemplate {
        ResponseTemplate::new(404).set_body_json(json!({ "errors": [] }))
    }

    #[tokio::test]
    async fn an_empty_services_tree_lists_no_registrar_ids() {
        let server = MockServer::start().await;
        mount_listing(&server, not_found()).await;

        let ids = list_registrar_managed_ids(&client(&server), "secret")
            .await
            .expect("a not-found listing is empty");
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn only_bound_subtrees_are_registrar_managed() {
        let server = MockServer::start().await;
        mount_listing(&server, listing(&["a/", "b/", "leaf"])).await;
        mount_read(
            &server,
            &binding_path("a"),
            kv(&json!({ "state": "active" })),
        )
        .await;
        mount_read(&server, &binding_path("b"), not_found()).await;

        let ids = list_registrar_managed_ids(&client(&server), "secret")
            .await
            .expect("lists");
        assert_eq!(ids, vec!["a".to_string()]);

        let requests = server.received_requests().await.expect("recorded");
        assert!(
            requests.iter().all(|r| !r.url.path().contains("leaf")),
            "a leaf key is not a registration subtree and must not be read"
        );
    }

    #[tokio::test]
    async fn a_failing_binding_read_is_an_error() {
        let server = MockServer::start().await;
        mount_listing(&server, listing(&["a/"])).await;
        mount_read(&server, &binding_path("a"), ResponseTemplate::new(500)).await;

        list_registrar_managed_ids(&client(&server), "secret")
            .await
            .expect_err("a 500 on the binding read must not read as unbound");
    }

    #[tokio::test]
    async fn a_forbidden_listing_is_an_error() {
        let server = MockServer::start().await;
        mount_listing(&server, ResponseTemplate::new(403)).await;

        list_registrar_managed_ids(&client(&server), "secret")
            .await
            .expect_err("a 403 must not read as no registrar identities");
    }

    #[tokio::test]
    async fn registrar_ids_are_returned_sorted() {
        let server = MockServer::start().await;
        mount_listing(&server, listing(&["zeta/", "alpha/", "mid/"])).await;
        for id in ["zeta", "alpha", "mid"] {
            mount_read(&server, &binding_path(id), kv(&json!({}))).await;
        }

        let ids = list_registrar_managed_ids(&client(&server), "secret")
            .await
            .expect("lists");
        assert_eq!(ids, vec!["alpha", "mid", "zeta"]);
    }
}
