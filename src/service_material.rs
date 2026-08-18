//! The `OpenBao` material one service registration owns, and the two
//! operations both of its callers share: provisioning the derived policy
//! and `AppRole`, and tearing that material down again.
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
//! body, and the delete sequence. What is **not** shared is credential
//! issuance. [`provision_service_role`] never creates a `secret_id` and
//! never returns one, because the two callers deliver it differently —
//! the CLI writes a raw value to a file, the registrar hands a
//! response-wrapping token to a remote caller and must never hold the
//! unwrapped secret at all. Putting issuance here would force one of
//! them onto the other's delivery.
//!
//! Nothing here reads `state.json`, prompts, or knows a delivery mode.
//! Every value the operations depend on — the KV mount, the role-level
//! TTLs, the KV suffixes to sweep — arrives as a parameter, so the two
//! callers can keep the different sets they intentionally have.

use anyhow::{Context, Result};
use thiserror::Error;

use crate::openbao::OpenBaoClient;
use crate::trust_bootstrap::{SERVICE_KV_BASE, SERVICE_REISSUE_KV_SUFFIX};

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
    use super::*;

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
}
