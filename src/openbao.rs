use std::fmt::Write as _;

use anyhow::{Context, Result};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const VAULT_TOKEN_HEADER: &str = "X-Vault-Token";
const ROOT_POLICY: &str = "root";

#[derive(Debug, Clone)]
pub struct OpenBaoClient {
    base_url: String,
    client: Client,
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InitStatus {
    initialized: bool,
}

#[derive(Debug, Deserialize)]
pub struct SealStatus {
    pub sealed: bool,
    #[serde(default)]
    pub t: Option<u32>,
    #[serde(default)]
    pub n: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvMountStatus {
    Missing,
    NotKv,
    NotV2,
    Ok,
}

#[derive(Debug, Deserialize, Clone)]
pub struct InitResponse {
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub keys_base64: Vec<String>,
    pub root_token: String,
}

#[derive(Debug, Deserialize)]
struct MountResponse {
    data: MountData,
}

#[derive(Debug, Deserialize)]
struct MountData {
    #[serde(rename = "type")]
    mount_type: String,
    #[serde(default)]
    options: Option<MountOptions>,
}

#[derive(Debug, Deserialize)]
struct MountOptions {
    #[serde(default)]
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthListResponse {
    data: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct RoleIdResponse {
    data: RoleIdData,
}

#[derive(Debug, Deserialize)]
struct RoleIdData {
    role_id: String,
}

#[derive(Debug, Deserialize)]
struct SecretIdResponse {
    data: SecretIdData,
}

#[derive(Debug, Deserialize)]
struct SecretIdData {
    secret_id: String,
}

#[derive(Debug, Deserialize)]
struct AppRoleLoginResponse {
    auth: AppRoleAuth,
}

#[derive(Debug, Deserialize)]
struct AppRoleAuth {
    client_token: String,
}

#[derive(Debug, Deserialize)]
pub struct RekeyInitResponse {
    pub nonce: String,
    #[serde(default)]
    pub progress: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct RekeyUpdateResponse {
    pub complete: bool,
    #[serde(default)]
    pub keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TokenCreateResponse {
    auth: AppRoleAuth,
}

/// Checks whether a response status and body indicate a missing resource.
///
/// `OpenBao` returns 404 for most missing resources but some endpoints
/// (e.g. `sys/mounts`) return 400 with a specific message instead.
fn is_not_found(status: StatusCode, text: &str) -> bool {
    status == StatusCode::NOT_FOUND
        || (status == StatusCode::BAD_REQUEST && text.contains("No secret engine mount"))
}

impl OpenBaoClient {
    /// Creates a new `OpenBao` client targeting the provided base URL.
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be initialized.
    pub fn new(base_url: &str) -> Result<Self> {
        let client = Client::builder()
            .build()
            .context("Failed to build OpenBao HTTP client")?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            token: None,
        })
    }

    pub fn set_token(&mut self, token: String) {
        self.token = Some(token);
    }

    /// Checks the `OpenBao` health endpoint.
    ///
    /// # Errors
    /// Returns an error if the health endpoint cannot be reached or responds
    /// with an unexpected status.
    pub async fn health_check(&self) -> Result<()> {
        let url = self.endpoint("sys/health");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .context("OpenBao health check failed")?;
        let status = response.status();
        // The Vault/OpenBao health endpoint returns non-200 codes for
        // degraded-but-running states:
        //   429 – node is a standby (HA mode)
        //   503 – node is sealed
        //   501 – node is not yet initialized
        // All of these indicate that the server is reachable, so we treat
        // them as a successful health check.
        if status == StatusCode::OK
            || status == StatusCode::TOO_MANY_REQUESTS
            || status == StatusCode::SERVICE_UNAVAILABLE
            || status == StatusCode::NOT_IMPLEMENTED
        {
            return Ok(());
        }
        anyhow::bail!("OpenBao health check failed with status: {status}");
    }

    /// Checks whether the `OpenBao` instance is initialized.
    ///
    /// # Errors
    /// Returns an error if the init status endpoint cannot be queried.
    pub async fn is_initialized(&self) -> Result<bool> {
        let status: InitStatus = self.get_json("sys/init", false).await?;
        Ok(status.initialized)
    }

    /// Initializes `OpenBao` with the provided shares and threshold.
    ///
    /// # Errors
    /// Returns an error if initialization fails or the response is invalid.
    pub async fn init(&self, shares: u8, threshold: u8) -> Result<InitResponse> {
        #[derive(Serialize)]
        struct InitRequest {
            secret_shares: u8,
            secret_threshold: u8,
        }
        let url = self.endpoint("sys/init");
        let response = self
            .client
            .post(url)
            .json(&InitRequest {
                secret_shares: shares,
                secret_threshold: threshold,
            })
            .send()
            .await
            .context("OpenBao init request failed")?;
        Self::parse_response(response).await
    }

    /// Fetches the seal status from `OpenBao`.
    ///
    /// # Errors
    /// Returns an error if the seal status endpoint cannot be queried.
    pub async fn seal_status(&self) -> Result<SealStatus> {
        self.get_json("sys/seal-status", false).await
    }

    /// Submits an unseal key to `OpenBao`.
    ///
    /// # Errors
    /// Returns an error if the unseal request fails or the response is invalid.
    pub async fn unseal(&self, key: &str) -> Result<SealStatus> {
        #[derive(Serialize)]
        struct UnsealRequest<'a> {
            key: &'a str,
        }
        let url = self.endpoint("sys/unseal");
        let response = self
            .client
            .post(url)
            .json(&UnsealRequest { key })
            .send()
            .await
            .context("OpenBao unseal request failed")?;
        Self::parse_response(response).await
    }

    /// Starts unseal key rekey with the given share and threshold values.
    ///
    /// # Errors
    /// Returns an error if the rekey init request fails.
    pub async fn start_rekey(&self, shares: u32, threshold: u32) -> Result<RekeyInitResponse> {
        #[derive(Serialize)]
        struct RekeyInitRequest {
            secret_shares: u32,
            secret_threshold: u32,
        }

        self.put_json(
            "sys/rekey/init",
            &RekeyInitRequest {
                secret_shares: shares,
                secret_threshold: threshold,
            },
        )
        .await
    }

    /// Submits one existing unseal key for an in-progress rekey operation.
    ///
    /// # Errors
    /// Returns an error if the rekey update request fails.
    pub async fn submit_rekey_share(&self, nonce: &str, key: &str) -> Result<RekeyUpdateResponse> {
        #[derive(Serialize)]
        struct RekeyUpdateRequest<'a> {
            nonce: &'a str,
            key: &'a str,
        }

        self.put_json("sys/rekey/update", &RekeyUpdateRequest { nonce, key })
            .await
    }

    /// Creates a new root-policy token.
    ///
    /// # Errors
    /// Returns an error if token creation fails.
    pub async fn create_root_token(&self) -> Result<String> {
        #[derive(Serialize)]
        struct TokenCreateRequest<'a> {
            policies: &'a [&'a str],
            renewable: bool,
            no_parent: bool,
        }

        let response: TokenCreateResponse = self
            .post_json(
                "auth/token/create",
                &TokenCreateRequest {
                    policies: &[ROOT_POLICY],
                    renewable: false,
                    no_parent: true,
                },
            )
            .await?;
        Ok(response.auth.client_token)
    }

    /// Ensures a KV v2 secrets engine is mounted at the given path.
    ///
    /// # Errors
    /// Returns an error if the mount exists with the wrong type/version or if
    /// enabling the mount fails.
    pub async fn ensure_kv_v2(&self, mount: &str) -> Result<()> {
        if let Some(data) = self.get_mount(mount).await? {
            if data.mount_type != "kv" {
                anyhow::bail!("Mount {mount} exists but is not KV");
            }
            let version = data.options.and_then(|opt| opt.version);
            if version.as_deref() != Some("2") {
                anyhow::bail!("Mount {mount} exists but is not KV v2");
            }
        } else {
            #[derive(Serialize)]
            struct MountRequest<'a> {
                #[serde(rename = "type")]
                mount_type: &'a str,
                options: MountOptionsRequest<'a>,
            }
            #[derive(Serialize)]
            struct MountOptionsRequest<'a> {
                version: &'a str,
            }
            self.post_action(
                &format!("sys/mounts/{mount}"),
                &MountRequest {
                    mount_type: "kv",
                    options: MountOptionsRequest { version: "2" },
                },
            )
            .await?;
        }
        Ok(())
    }

    /// Ensures `AppRole` auth is enabled.
    ///
    /// # Errors
    /// Returns an error if auth backends cannot be queried or enabling `AppRole`
    /// fails.
    pub async fn ensure_approle_auth(&self) -> Result<()> {
        let auths: AuthListResponse = self.get_json("sys/auth", true).await?;
        let has_approle = auths
            .data
            .as_object()
            .is_some_and(|map| map.keys().any(|key| key.starts_with("approle/")));
        if !has_approle {
            #[derive(Serialize)]
            struct AuthRequest<'a> {
                #[serde(rename = "type")]
                auth_type: &'a str,
            }
            self.post_action(
                "sys/auth/approle",
                &AuthRequest {
                    auth_type: "approle",
                },
            )
            .await?;
        }
        Ok(())
    }

    /// Writes an ACL policy.
    ///
    /// # Errors
    /// Returns an error if the policy cannot be written.
    pub async fn write_policy(&self, name: &str, policy: &str) -> Result<()> {
        #[derive(Serialize)]
        struct PolicyRequest<'a> {
            policy: &'a str,
        }
        self.post_action(
            &format!("sys/policies/acl/{name}"),
            &PolicyRequest { policy },
        )
        .await
    }

    /// Checks if a policy exists.
    ///
    /// # Errors
    /// Returns an error if the policy lookup fails for unexpected reasons.
    pub async fn policy_exists(&self, name: &str) -> Result<bool> {
        self.resource_exists(&format!("sys/policies/acl/{name}"))
            .await
    }

    /// Deletes an ACL policy.
    ///
    /// # Errors
    /// Returns an error if the delete request fails.
    pub async fn delete_policy(&self, name: &str) -> Result<()> {
        self.delete_action(&format!("sys/policies/acl/{name}"))
            .await
    }

    /// Creates or updates an `AppRole` with the given settings.
    ///
    /// # Errors
    /// Returns an error if the `AppRole` cannot be created or updated.
    pub async fn create_approle(
        &self,
        name: &str,
        policies: &[&str],
        token_ttl: &str,
        secret_id_ttl: &str,
        token_renewable: bool,
    ) -> Result<()> {
        #[derive(Serialize)]
        struct AppRoleRequest<'a> {
            token_policies: &'a [&'a str],
            token_ttl: &'a str,
            token_max_ttl: &'a str,
            token_renewable: bool,
            secret_id_ttl: &'a str,
        }
        self.post_action(
            &format!("auth/approle/role/{name}"),
            &AppRoleRequest {
                token_policies: policies,
                token_ttl,
                token_max_ttl: token_ttl,
                token_renewable,
                secret_id_ttl,
            },
        )
        .await
    }

    /// Checks if an `AppRole` exists.
    ///
    /// # Errors
    /// Returns an error if the `AppRole` lookup fails for unexpected reasons.
    pub async fn approle_exists(&self, name: &str) -> Result<bool> {
        self.resource_exists(&format!("auth/approle/role/{name}"))
            .await
    }

    /// Deletes an `AppRole`.
    ///
    /// # Errors
    /// Returns an error if the delete request fails.
    pub async fn delete_approle(&self, name: &str) -> Result<()> {
        self.delete_action(&format!("auth/approle/role/{name}"))
            .await
    }

    /// Reads the `role_id` for an `AppRole`.
    ///
    /// # Errors
    /// Returns an error if the `role_id` cannot be fetched.
    pub async fn read_role_id(&self, name: &str) -> Result<String> {
        let response: RoleIdResponse = self
            .get_json(&format!("auth/approle/role/{name}/role-id"), true)
            .await?;
        Ok(response.data.role_id)
    }

    /// Creates a new `secret_id` for an `AppRole`.
    ///
    /// # Errors
    /// Returns an error if the `secret_id` cannot be created.
    pub async fn create_secret_id(&self, name: &str) -> Result<String> {
        let response: SecretIdResponse = self
            .post_json(
                &format!("auth/approle/role/{name}/secret-id"),
                &serde_json::json!({}),
            )
            .await?;
        Ok(response.data.secret_id)
    }

    /// Logs in using an `AppRole` `role_id/secret_id` pair.
    ///
    /// # Errors
    /// Returns an error if the login request fails.
    pub async fn login_approle(&self, role_id: &str, secret_id: &str) -> Result<String> {
        let url = self.endpoint("auth/approle/login");
        let response = self
            .client
            .post(url)
            .json(&serde_json::json!({
                "role_id": role_id,
                "secret_id": secret_id
            }))
            .send()
            .await
            .with_context(|| "OpenBao request failed: auth/approle/login")?;
        let parsed: AppRoleLoginResponse = Self::parse_response(response)
            .await
            .context("OpenBao response parse failed: auth/approle/login")?;
        Ok(parsed.auth.client_token)
    }

    /// Writes a KV v2 secret.
    ///
    /// # Errors
    /// Returns an error if the write request fails.
    pub async fn write_kv(&self, mount: &str, path: &str, data: serde_json::Value) -> Result<()> {
        #[derive(Serialize)]
        struct KvRequest {
            data: serde_json::Value,
        }
        self.post_action(&format!("{mount}/data/{path}"), &KvRequest { data })
            .await
    }

    /// Reads a KV v2 secret.
    ///
    /// # Errors
    /// Returns an error if the read request fails.
    pub async fn read_kv(&self, mount: &str, path: &str) -> Result<serde_json::Value> {
        #[derive(Deserialize)]
        struct KvResponse {
            data: KvResponseData,
        }
        #[derive(Deserialize)]
        struct KvResponseData {
            data: serde_json::Value,
        }
        self.get_json::<KvResponse>(&format!("{mount}/data/{path}"), true)
            .await
            .map(|response| response.data.data)
    }

    /// Checks if a KV v2 secret exists.
    ///
    /// # Errors
    /// Returns an error if the lookup fails for unexpected reasons.
    pub async fn kv_exists(&self, mount: &str, path: &str) -> Result<bool> {
        self.resource_exists(&format!("{mount}/metadata/{path}"))
            .await
    }

    /// Checks the status of a KV v2 mount.
    ///
    /// # Errors
    /// Returns an error if the mount lookup fails unexpectedly.
    pub async fn kv_mount_status(&self, mount: &str) -> Result<KvMountStatus> {
        let Some(data) = self.get_mount(mount).await? else {
            return Ok(KvMountStatus::Missing);
        };
        if data.mount_type != "kv" {
            return Ok(KvMountStatus::NotKv);
        }
        let version = data.options.and_then(|opt| opt.version);
        if version.as_deref() != Some("2") {
            return Ok(KvMountStatus::NotV2);
        }
        Ok(KvMountStatus::Ok)
    }

    /// Deletes KV v2 secret metadata and all versions.
    ///
    /// # Errors
    /// Returns an error if the delete request fails.
    pub async fn delete_kv(&self, mount: &str, path: &str) -> Result<()> {
        self.delete_action(&format!("{mount}/metadata/{path}"))
            .await
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}/v1/{path}", self.base_url)
    }

    fn require_token(&self) -> Result<&str> {
        self.token
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("OpenBao token is not set"))
    }

    fn with_auth_header(&self, builder: RequestBuilder) -> Result<RequestBuilder> {
        let token = self.require_token()?;
        Ok(builder.header(VAULT_TOKEN_HEADER, token))
    }

    async fn get_mount(&self, mount: &str) -> Result<Option<MountData>> {
        let url = self.endpoint(&format!("sys/mounts/{mount}"));
        let mut request = self.client.get(url);
        if let Some(token) = &self.token {
            request = request.header(VAULT_TOKEN_HEADER, token);
        }
        let response = request
            .send()
            .await
            .context("Failed to query OpenBao mounts")?;
        let status = response.status();
        let text = response
            .text()
            .await
            .context("Failed to read OpenBao mount response")?;
        if is_not_found(status, &text) {
            return Ok(None);
        }
        if !status.is_success() {
            anyhow::bail!("OpenBao API error ({status}): {text}");
        }
        let parsed: MountResponse =
            serde_json::from_str(&text).context("Failed to parse mount response")?;
        Ok(Some(parsed.data))
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str, use_token: bool) -> Result<T> {
        let url = self.endpoint(path);
        let mut request = self.client.get(url);
        if use_token {
            request = request.header(VAULT_TOKEN_HEADER, self.require_token()?);
        }
        let response = request
            .send()
            .await
            .with_context(|| format!("OpenBao request failed: {path}"))?;
        Self::parse_response(response)
            .await
            .with_context(|| format!("OpenBao response parse failed: {path}"))
    }

    async fn resource_exists(&self, path: &str) -> Result<bool> {
        let url = self.endpoint(path);
        let response = self
            .with_auth_header(self.client.get(url))?
            .send()
            .await
            .with_context(|| format!("OpenBao request failed: {path}"))?;
        let status = response.status();
        let text = response
            .text()
            .await
            .context("Failed to read OpenBao response body")?;
        if is_not_found(status, &text) {
            return Ok(false);
        }
        if !status.is_success() {
            anyhow::bail!("OpenBao API error ({status}): {text}");
        }
        Ok(true)
    }

    async fn post_json<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R> {
        let url = self.endpoint(path);
        let response = self
            .with_auth_header(self.client.post(url))?
            .json(body)
            .send()
            .await
            .with_context(|| format!("OpenBao request failed: {path}"))?;
        Self::parse_response(response)
            .await
            .with_context(|| format!("OpenBao response parse failed: {path}"))
    }

    async fn post_action<T: Serialize>(&self, path: &str, body: &T) -> Result<()> {
        let url = self.endpoint(path);
        let response = self
            .with_auth_header(self.client.post(url))?
            .json(body)
            .send()
            .await
            .with_context(|| format!("OpenBao request failed: {path}"))?;
        Self::ensure_success(response)
            .await
            .with_context(|| format!("OpenBao response failed: {path}"))
    }

    async fn delete_action(&self, path: &str) -> Result<()> {
        let url = self.endpoint(path);
        let response = self
            .with_auth_header(self.client.delete(url))?
            .send()
            .await
            .with_context(|| format!("OpenBao request failed: {path}"))?;
        Self::ensure_success(response)
            .await
            .with_context(|| format!("OpenBao response failed: {path}"))
    }

    async fn put_json<T: Serialize, R: DeserializeOwned>(&self, path: &str, body: &T) -> Result<R> {
        let url = self.endpoint(path);
        let response = self
            .with_auth_header(self.client.put(url))?
            .json(body)
            .send()
            .await
            .with_context(|| format!("OpenBao request failed: {path}"))?;
        Self::parse_response(response)
            .await
            .with_context(|| format!("OpenBao response parse failed: {path}"))
    }

    async fn parse_response<T: DeserializeOwned>(response: reqwest::Response) -> Result<T> {
        let status = response.status();
        let text = response
            .text()
            .await
            .context("Failed to read OpenBao response body")?;
        if !status.is_success() {
            anyhow::bail!("OpenBao API error ({status}): {text}");
        }
        if text.trim().is_empty() {
            return serde_json::from_str("null").context("Failed to parse empty OpenBao response");
        }
        serde_json::from_str(&text).context("Failed to parse OpenBao response")
    }

    async fn ensure_success(response: reqwest::Response) -> Result<()> {
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let text = response
            .text()
            .await
            .context("Failed to read OpenBao response body")?;
        anyhow::bail!("OpenBao API error ({status}): {text}");
    }
}

/// Interval at which the `OpenBao` agent re-renders static secrets.
pub const STATIC_SECRET_RENDER_INTERVAL: &str = "30s";

/// Builds an `OpenBao` agent HCL configuration string.
///
/// # Arguments
///
/// * `openbao_addr` – Vault/`OpenBao` server address.
/// * `role_id_path` – Path to the `AppRole` role-ID file.
/// * `secret_id_path` – Path to the `AppRole` secret-ID file.
/// * `token_path` – Path where the agent writes its token.
/// * `mount_path` – Optional auth mount path (e.g. `"auth/approle"`).
/// * `render_interval` – Value for `static_secret_render_interval`.
/// * `templates` – `(source, destination)` pairs for template blocks.
#[must_use]
pub fn build_agent_config(
    openbao_addr: &str,
    role_id_path: &str,
    secret_id_path: &str,
    token_path: &str,
    mount_path: Option<&str>,
    render_interval: &str,
    templates: &[(&str, &str)],
) -> String {
    let mount_line = match mount_path {
        Some(mp) => format!("\n    mount_path = \"{mp}\""),
        None => String::new(),
    };
    let mut config = format!(
        r#"vault {{
  address = "{openbao_addr}"
}}

auto_auth {{
  method "approle" {{{mount_line}
    config = {{
      role_id_file_path = "{role_id_path}"
      secret_id_file_path = "{secret_id_path}"
      remove_secret_id_file_after_reading = false
    }}
  }}
  sink "file" {{
    config = {{
      path = "{token_path}"
    }}
  }}
}}

template_config {{
  static_secret_render_interval = "{render_interval}"
}}
"#
    );
    for (source_path, destination_path) in templates {
        write!(
            &mut config,
            r#"
template {{
  source = "{source_path}"
  destination = "{destination_path}"
  perms = "0600"
}}
"#
        )
        .expect("write template");
    }
    config
}

#[cfg(test)]
mod agent_config_tests {
    use super::*;

    #[test]
    fn without_mount_path() {
        let hcl = build_agent_config(
            "http://openbao:8200",
            "/role_id",
            "/secret_id",
            "/token",
            None,
            "30s",
            &[("/tpl.ctmpl", "/out.toml")],
        );
        assert!(hcl.contains(r#"address = "http://openbao:8200""#));
        assert!(hcl.contains("role_id_file_path = \"/role_id\""));
        assert!(!hcl.contains("mount_path"));
        assert!(hcl.contains(r#"static_secret_render_interval = "30s""#));
        assert!(hcl.contains(r#"source = "/tpl.ctmpl""#));
    }

    #[test]
    fn with_mount_path() {
        let hcl = build_agent_config(
            "http://openbao:8200",
            "/role_id",
            "/secret_id",
            "/token",
            Some("auth/approle"),
            "30s",
            &[("/tpl.ctmpl", "/out.toml")],
        );
        assert!(hcl.contains(r#"mount_path = "auth/approle""#));
    }

    #[test]
    fn multiple_templates() {
        let hcl = build_agent_config(
            "http://openbao:8200",
            "/role_id",
            "/secret_id",
            "/token",
            None,
            "30s",
            &[("/a.ctmpl", "/a.out"), ("/b.ctmpl", "/b.out")],
        );
        assert!(hcl.contains(r#"source = "/a.ctmpl""#));
        assert!(hcl.contains(r#"source = "/b.ctmpl""#));
    }
}
