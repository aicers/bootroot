//! The bootroot-internal privileged credential: the identity bootroot's
//! own daemon authenticates to `OpenBao` with in order to run the
//! registrar verbs.
//!
//! # The authority boundary
//!
//! The registrar verbs write derived service policies and `AppRole`s and
//! read the deployment's CA, responder-HMAC and agent-EAB material. That
//! authority stays *inside* bootroot: a caller supplies a request and
//! never a credential, never a client, and never anything that selects
//! one. This module is where that promise is kept — it owns the only
//! privileged client the verbs can be built over, and nothing here is
//! reachable from a request.
//!
//! The credential is a **certificate**, not an `AppRole`. It logs in at
//! `auth/cert`, which requires TLS, which is why an endpoint-enabled
//! host transitions its `OpenBao` listener to TLS even on loopback. No
//! path in this module reads a `role_id` or a `secret_id`, and a
//! `http://` `OpenBao` URL is refused outright rather than attempted:
//! a certificate login over plaintext would put the credential on the
//! wire.
//!
//! # The identity
//!
//! One name, fixed: `001.bootroot-registrar-internal.<host>.<domain>`,
//! composed through [`crate::registrar::registrar_internal_identity`] —
//! the same [`crate::registrar::compose_san`] every ordinary service
//! leaf goes through. It falls inside the
//! [`crate::registrar::RESERVED_SERVICE_NAME_PREFIX`] namespace, so no
//! operator-driven `service add` can mint it.
//!
//! # The four fixed credential paths
//!
//! All four live below the state-recorded secrets directory, in the
//! fixed [`INTERNAL_DIR`] subdirectory, and they are an **all-or-none**
//! set: a partial set is a typed failure, never a half-usable
//! credential. [`InternalPaths`] is the one place their names are
//! spelled.
//!
//! Two more files sit beside them and share their all-or-none rule on an
//! endpoint-enabled host: the dedicated agent config
//! ([`InternalPaths::agent_config`]) and the private CA bundle
//! ([`InternalPaths::ca_bundle`]) that config points its trust at. The
//! bundle is this identity's alone — never the shared
//! `secrets/certs/ca-bundle.pem`, and never a KV-rendered service
//! bundle — so a rotation can narrow it without touching anything a
//! service reads.
//!
//! # Renewal
//!
//! There is no registrar-specific scheduler here, and there must not be
//! one. The internal profile is renewed by an ordinary `bootroot-agent`
//! process reading [`InternalPaths::agent_config`], on that config's own
//! `daemon` and `retry` settings, through the same renewal predicate
//! every other profile uses. The operator supervises that process;
//! `init` does not start it.

pub mod agent_config;
pub mod client;
pub mod material;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

pub use agent_config::{
    InternalAgentConfigParams, build_internal_trust_updates, internal_agent_invocation,
    internal_registration_id, internal_signal_pattern, render_internal_agent_config,
    upsert_internal_trust,
};
pub use client::{
    InternalCredential, RootAuthority, is_expired_token_error, require_https,
    require_root_authority,
};
pub use material::{
    AcmeAccountKey, InternalMaterial, MaterialStatus, PrivateKeyPem, load_material,
    material_status, publish_material,
};

/// The fixed subdirectory, below the state-recorded secrets directory,
/// that every bootroot-internal artifact lives in.
///
/// Fixed rather than configurable on purpose: a path an operator could
/// move is a path a rotation, a recovery and a `pkill -HUP` pattern
/// would each have to rediscover, and the three would drift.
pub const INTERNAL_DIR: &str = "registrar-internal";

/// The private key of the internal leaf. Root-owned, `0600`.
pub const KEY_FILE: &str = "key.pem";
/// The internal leaf and the chain it was issued with. Public
/// certificate data.
pub const CHAIN_FILE: &str = "chain.pem";
/// The ACME account signing key the internal profile registers with.
/// Root-owned, `0600`.
pub const ACME_ACCOUNT_FILE: &str = "acme-account.json";
/// The fingerprint of the root the `auth/cert` entry trusts.
pub const ROOT_FINGERPRINT_FILE: &str = "root-fingerprint";
/// The dedicated `bootroot-agent` config for the internal profile.
/// Root-owned, `0600`.
pub const AGENT_CONFIG_FILE: &str = "agent.toml";
/// The internal profile's private CA bundle. Public certificate data.
pub const CA_BUNDLE_FILE: &str = "ca-bundle.pem";

/// The `auth/cert` mount path every login and every entry write goes
/// through.
pub const CERT_AUTH_MOUNT: &str = "cert";

/// The name of the one `auth/cert` entry the deployment trusts.
///
/// The same string as [`crate::registrar::REGISTRAR_INTERNAL_LABEL`],
/// and deliberately so: the entry, the policy and the SAN's reserved
/// label are one name, so an operator reading any of the three finds
/// the other two.
pub const CERT_AUTH_ROLE: &str = crate::registrar::REGISTRAR_INTERNAL_LABEL;

/// The fixed paths of one host's internal credential.
///
/// Constructed from the state-recorded secrets directory and nothing
/// else. Every caller — provisioning, renewal, rotation, recovery and
/// the `SIGHUP` helper — resolves the same six names from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalPaths {
    dir: PathBuf,
}

impl InternalPaths {
    /// Creates the fixed layout below `secrets_dir`.
    #[must_use]
    pub fn new(secrets_dir: &Path) -> Self {
        Self {
            dir: secrets_dir.join(INTERNAL_DIR),
        }
    }

    /// The directory every internal artifact lives in.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The private key of the internal leaf.
    #[must_use]
    pub fn key(&self) -> PathBuf {
        self.dir.join(KEY_FILE)
    }

    /// The internal leaf and its chain.
    #[must_use]
    pub fn chain(&self) -> PathBuf {
        self.dir.join(CHAIN_FILE)
    }

    /// The persistent ACME account signing key.
    #[must_use]
    pub fn acme_account(&self) -> PathBuf {
        self.dir.join(ACME_ACCOUNT_FILE)
    }

    /// The fingerprint of the root the `auth/cert` entry trusts.
    #[must_use]
    pub fn root_fingerprint(&self) -> PathBuf {
        self.dir.join(ROOT_FINGERPRINT_FILE)
    }

    /// The dedicated `bootroot-agent` config for the internal profile.
    #[must_use]
    pub fn agent_config(&self) -> PathBuf {
        self.dir.join(AGENT_CONFIG_FILE)
    }

    /// The internal profile's private CA bundle.
    #[must_use]
    pub fn ca_bundle(&self) -> PathBuf {
        self.dir.join(CA_BUNDLE_FILE)
    }

    /// Every path this layout owns, in a stable order.
    ///
    /// Used by provisioning rollback and by the all-or-none checks, so
    /// a file added to the layout cannot be forgotten by one of them.
    #[must_use]
    pub fn all(&self) -> Vec<PathBuf> {
        vec![
            self.key(),
            self.chain(),
            self.acme_account(),
            self.root_fingerprint(),
            self.agent_config(),
            self.ca_bundle(),
        ]
    }
}

/// Why the bootroot-internal credential could not be used.
///
/// Every variant is a *refusal to act*: none of them is reached after a
/// partial mutation, and none of them carries key material, a login
/// token or an ACME secret.
#[derive(Debug, thiserror::Error)]
pub enum InternalCredentialError {
    /// No internal credential exists below the secrets directory.
    #[error("no bootroot-internal credential exists at {}", .0.display())]
    Absent(PathBuf),
    /// Some of the fixed files exist and others do not. The set is
    /// all-or-none, so this is a failure rather than a partial load.
    #[error(
        "the bootroot-internal credential at {} is incomplete; missing: {}",
        dir.display(),
        missing.join(", ")
    )]
    Partial {
        /// The layout directory.
        dir: PathBuf,
        /// The file names that are absent, in layout order.
        missing: Vec<String>,
    },
    /// A file exists but does not hold what it must.
    #[error("the bootroot-internal credential file {} is invalid: {reason}", path.display())]
    Invalid {
        /// The offending file.
        path: PathBuf,
        /// What was wrong with it. Never quotes the file's bytes.
        reason: String,
    },
    /// The recorded `OpenBao` URL is plaintext. A certificate login is
    /// never attempted over it.
    #[error(
        "the registrar endpoint is enabled but the recorded OpenBao URL is {url}; \
         certificate login requires TLS and is not attempted over plaintext"
    )]
    PlaintextOpenBaoUrl {
        /// The rejected URL, which carries no credential.
        url: String,
    },
    /// The stored root fingerprint disagrees with the active root, so
    /// the credential cannot be trusted and must be repaired.
    #[error(
        "the bootroot-internal credential was issued under root {stored} but the \
         active root is {active}; run `bootroot rotate registrar-internal-credential`"
    )]
    RepairRequired {
        /// The fingerprint recorded beside the credential.
        stored: String,
        /// The fingerprint of the deployment's active root.
        active: String,
    },
    /// A mutation was attempted without explicit root-token authority.
    #[error(
        "repairing the bootroot-internal credential requires an OpenBao token carrying \
         the `root` policy; the supplied token carries [{}]",
        policies.join(", ")
    )]
    RootAuthorityRequired {
        /// The policies the supplied token actually carries.
        policies: Vec<String>,
    },
    /// A file could not be read or written.
    #[error("{operation} {} failed", path.display())]
    Io {
        /// What was being attempted.
        operation: &'static str,
        /// The path it was attempted on.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// An `OpenBao` request failed.
    #[error("{operation} failed")]
    OpenBao {
        /// What was being attempted.
        operation: &'static str,
        /// The underlying failure. Carries no token: the client never
        /// echoes one into an error.
        #[source]
        source: anyhow::Error,
    },
}

/// Builds the ACL policy body the internal credential's token carries.
///
/// This is an **exact allowlist**, and every path in it is one the two
/// verbs actually take:
///
/// - the derived per-registration policy and `AppRole`, both confined to
///   the `bootroot-service-` prefix, which is what stops the credential
///   from authoring a policy under any other name or binding a role to
///   one;
/// - the registration's own KV subtree, for the durable binding and the
///   service material the verbs sweep; and
/// - three read-only paths — the CA trust record, the responder HMAC and
///   the agent EAB — that a minted identity's bootstrap material is
///   assembled from.
///
/// Nothing else. There is no `sys/` grant beyond the derived policy
/// prefix, no `auth/approle/role/*` wildcard, no step-ca password or
/// database path, and no caller-facing identity: the token this policy
/// is attached to is never handed out.
#[must_use]
pub fn build_registrar_internal_policy(kv_mount: &str) -> String {
    use crate::service_material::SERVICE_ROLE_PREFIX;
    use crate::trust_bootstrap::SERVICE_KV_BASE;

    format!(
        r#"# The derived per-registration policy. Confined to the
# `bootroot-service-` prefix: the verbs write a body they derive
# themselves, under a name they derive themselves.
path "sys/policies/acl/{SERVICE_ROLE_PREFIX}*" {{
  capabilities = ["create", "read", "update", "delete"]
}}

# The derived per-registration AppRole, its `role-id` read and its
# `secret-id` issuance. Confined to the same prefix.
path "auth/approle/role/{SERVICE_ROLE_PREFIX}*" {{
  capabilities = ["create", "read", "update", "delete"]
}}

# The registration's own KV subtree: the durable registrar binding and
# every service-material record a deregister sweeps.
path "{kv_mount}/data/{SERVICE_KV_BASE}/*" {{
  capabilities = ["create", "read", "update", "delete"]
}}
path "{kv_mount}/metadata/{SERVICE_KV_BASE}/*" {{
  capabilities = ["read", "delete"]
}}

# Read-only deployment material a minted identity's bootstrap needs.
path "{kv_mount}/data/bootroot/ca" {{
  capabilities = ["read"]
}}
path "{kv_mount}/data/bootroot/responder/hmac" {{
  capabilities = ["read"]
}}
path "{kv_mount}/data/bootroot/agent/eab" {{
  capabilities = ["read"]
}}
"#
    )
}
