use std::fmt::Write as _;

use anyhow::{Context, Result};
use reqwest::{Client, Method, RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const VAULT_TOKEN_HEADER: &str = "X-Vault-Token";
const VAULT_WRAP_TTL_HEADER: &str = "X-Vault-Wrap-TTL";
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

/// Per-issuance options for `create_secret_id`.
///
/// All fields are optional. When every field is `None` (the `Default`
/// value) the resulting API payload is `{}`, which preserves the
/// existing behaviour of deferring to the role-level defaults.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SecretIdOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_uses: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_bound_cidrs: Option<Vec<String>>,
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

/// Response-wrapping metadata returned by `OpenBao` when the
/// `X-Vault-Wrap-TTL` header is set on a request.
#[derive(Debug, Deserialize)]
pub struct WrapInfo {
    pub token: String,
    pub ttl: u64,
    pub creation_time: String,
    pub creation_path: String,
}

#[derive(Debug, Deserialize)]
struct WrappedResponse {
    wrap_info: WrapInfo,
}

#[derive(Debug, Deserialize)]
pub struct RootRotationInitResponse {
    pub nonce: String,
    #[serde(default)]
    pub progress: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct RootRotationUpdateResponse {
    pub complete: bool,
    #[serde(default)]
    pub keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DataEnvelope<T> {
    data: T,
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

    /// Creates a new `OpenBao` client whose TLS verification is anchored
    /// to the given PEM-encoded CA bundle with optional SHA-256 pins.
    ///
    /// This is the primary constructor for RN-side bootstrap: the PEM
    /// content travels inside the bootstrap artifact and `pins` carries
    /// optional SHA-256 fingerprints from `trust.trusted_ca_sha256`.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM content cannot be parsed or the HTTP
    /// client fails to build.
    pub fn with_pem_trust(base_url: &str, ca_pem: &str, pins: &[String]) -> Result<Self> {
        let client = crate::tls::build_http_client_from_pem(ca_pem, pins)?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            token: None,
        })
    }

    /// Creates a new `OpenBao` client with a pre-configured
    /// [`reqwest::Client`].
    #[must_use]
    pub fn with_client(base_url: &str, client: Client) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            token: None,
        }
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
        let status: InitStatus = self.get_json("sys/init", false, None).await?;
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
        self.get_json("sys/seal-status", false, None).await
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

    /// Starts a Shamir root-key rotation with the given share and
    /// threshold values via `POST /sys/rotate/root/init`.
    ///
    /// # Errors
    /// Returns an error if the rotation init request fails.
    pub async fn start_root_rotation(
        &self,
        shares: u32,
        threshold: u32,
    ) -> Result<RootRotationInitResponse> {
        #[derive(Serialize)]
        struct RootRotationInitRequest {
            secret_shares: u32,
            secret_threshold: u32,
        }

        let envelope: DataEnvelope<RootRotationInitResponse> = self
            .post_json(
                "sys/rotate/root/init",
                &RootRotationInitRequest {
                    secret_shares: shares,
                    secret_threshold: threshold,
                },
                None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Submits one existing unseal key for an in-progress root-key
    /// rotation via `POST /sys/rotate/root/update`.
    ///
    /// # Errors
    /// Returns an error if the rotation update request fails.
    pub async fn submit_root_rotation_share(
        &self,
        nonce: &str,
        key: &str,
    ) -> Result<RootRotationUpdateResponse> {
        #[derive(Serialize)]
        struct RootRotationUpdateRequest<'a> {
            nonce: &'a str,
            key: &'a str,
        }

        let envelope: DataEnvelope<RootRotationUpdateResponse> = self
            .post_json(
                "sys/rotate/root/update",
                &RootRotationUpdateRequest { nonce, key },
                None,
            )
            .await?;
        Ok(envelope.data)
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
                None,
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
        let auths: AuthListResponse = self.get_json("sys/auth", true, None).await?;
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

    /// Verifies that a file-based audit backend is enabled.
    ///
    /// Queries `sys/audit` and checks that at least one `file`-type
    /// audit device is present. `OpenBao` >= 2.5 requires audit devices
    /// to be declared in the server configuration file (`openbao.hcl`)
    /// rather than enabled via the API.
    ///
    /// # Errors
    /// Returns an error if the audit state cannot be queried or no
    /// file audit backend is found.
    pub async fn verify_audit_file(&self) -> Result<()> {
        let response = self
            .send_authed(Method::GET, "sys/audit", None)
            .await
            .context("Failed to query audit backends")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("OpenBao audit query failed ({status}): {body}");
        }
        let text = response
            .text()
            .await
            .context("Failed to read audit response")?;
        let has_file = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v.get("data")?.as_object().cloned())
            .is_some_and(|map| {
                map.values().any(|entry| {
                    entry
                        .get("type")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|t| t == "file")
                })
            });
        if has_file {
            return Ok(());
        }
        anyhow::bail!(
            "no file audit backend found; add an audit stanza \
             to openbao.hcl and restart the server"
        );
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
            .get_json(&format!("auth/approle/role/{name}/role-id"), true, None)
            .await?;
        Ok(response.data.role_id)
    }

    /// Creates a new `secret_id` for an `AppRole`.
    ///
    /// # Errors
    /// Returns an error if the `secret_id` cannot be created.
    pub async fn create_secret_id(&self, name: &str, options: &SecretIdOptions) -> Result<String> {
        let response: SecretIdResponse = self
            .post_json(
                &format!("auth/approle/role/{name}/secret-id"),
                options,
                None,
            )
            .await?;
        Ok(response.data.secret_id)
    }

    /// Creates a new `secret_id` with response wrapping, then immediately
    /// unwraps it to obtain the raw value.
    ///
    /// # Errors
    /// Returns an error if wrapping or unwrapping fails.
    pub async fn create_secret_id_wrapped(
        &self,
        name: &str,
        options: &SecretIdOptions,
        wrap_ttl: &str,
    ) -> Result<String> {
        let path = format!("auth/approle/role/{name}/secret-id");
        let wrap_info = self.post_json_wrapped(&path, options, wrap_ttl).await?;
        let response: SecretIdResponse = self.unwrap_secret(&wrap_info.token).await?;
        Ok(response.data.secret_id)
    }

    /// Creates a new `secret_id` with response wrapping and returns the
    /// [`WrapInfo`] without unwrapping.
    ///
    /// The caller is responsible for transporting the wrap token to the
    /// consumer who will call [`Self::unwrap_secret_id`].
    ///
    /// # Errors
    /// Returns an error if the wrapped creation request fails.
    pub async fn create_secret_id_wrap_only(
        &self,
        name: &str,
        options: &SecretIdOptions,
        wrap_ttl: &str,
    ) -> Result<WrapInfo> {
        let path = format!("auth/approle/role/{name}/secret-id");
        self.post_json_wrapped(&path, options, wrap_ttl).await
    }

    /// Unwraps a response-wrapped `secret_id` by consuming the given
    /// wrap token via `sys/wrapping/unwrap`.
    ///
    /// # Errors
    /// Returns an error if the token is expired, already consumed, or
    /// the response cannot be parsed.
    pub async fn unwrap_secret_id(&self, wrap_token: &str) -> Result<String> {
        let response: SecretIdResponse = self.unwrap_secret(wrap_token).await?;
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
        self.get_json::<KvResponse>(&format!("{mount}/data/{path}"), true, None)
            .await
            .map(|response| response.data.data)
    }

    /// Reads a KV v2 secret, treating a missing entry as `Ok(None)`.
    ///
    /// Returns `Ok(None)` when the resource is absent (HTTP 404 or the
    /// equivalent `No secret engine mount` 400 response). Any other
    /// failure — transport errors, 5xx responses, malformed payloads —
    /// is propagated as `Err`, matching the semantics of [`read_kv`].
    ///
    /// # Errors
    /// Returns an error for anything other than a clean not-found.
    pub async fn try_read_kv(
        &self,
        mount: &str,
        path: &str,
    ) -> Result<Option<serde_json::Value>> {
        #[derive(Deserialize)]
        struct KvResponse {
            data: KvResponseData,
        }
        #[derive(Deserialize)]
        struct KvResponseData {
            data: serde_json::Value,
        }
        let full_path = format!("{mount}/data/{path}");
        let response = self.send_authed(Method::GET, &full_path, None).await?;
        let status = response.status();
        let text = response
            .text()
            .await
            .context("Failed to read OpenBao response body")?;
        if is_not_found(status, &text) {
            return Ok(None);
        }
        if !status.is_success() {
            anyhow::bail!("OpenBao API error ({status}): {text}");
        }
        let parsed: KvResponse =
            serde_json::from_str(&text).context("Failed to parse OpenBao response")?;
        Ok(Some(parsed.data.data))
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

    /// Sends an authenticated POST with `X-Vault-Wrap-TTL` and returns
    /// the response-wrapping metadata.
    ///
    /// This is a convenience wrapper around `Self::post_json` that
    /// sets the wrap-TTL header and extracts the `wrap_info` envelope.
    ///
    /// # Errors
    /// Returns an error if the request fails or the wrapped response
    /// cannot be parsed.
    pub async fn post_json_wrapped<T: Serialize>(
        &self,
        path: &str,
        body: &T,
        wrap_ttl: &str,
    ) -> Result<WrapInfo> {
        let wrapped: WrappedResponse = self.post_json(path, body, Some(wrap_ttl)).await?;
        Ok(wrapped.wrap_info)
    }

    /// Unwraps a response-wrapped secret by consuming the given wrap
    /// token via `sys/wrapping/unwrap`.
    ///
    /// # Errors
    /// Returns an error if the unwrap request fails or the response
    /// cannot be parsed.
    pub async fn unwrap_secret<R: DeserializeOwned>(&self, wrap_token: &str) -> Result<R> {
        let path = "sys/wrapping/unwrap";
        let request = self
            .request_builder(Method::POST, path)
            .header(VAULT_TOKEN_HEADER, wrap_token);
        let response = self.send_request(request, path).await?;
        Self::parse_response(response)
            .await
            .with_context(|| format!("OpenBao response parse failed: {path}"))
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

    fn request_builder(&self, method: Method, path: &str) -> RequestBuilder {
        self.client.request(method, self.endpoint(path))
    }

    fn authed_request_builder(&self, method: Method, path: &str) -> Result<RequestBuilder> {
        self.with_auth_header(self.request_builder(method, path))
    }

    async fn send_request(&self, request: RequestBuilder, path: &str) -> Result<Response> {
        request
            .send()
            .await
            .with_context(|| format!("OpenBao request failed: {path}"))
    }

    async fn send_authed(
        &self,
        method: Method,
        path: &str,
        wrap_ttl: Option<&str>,
    ) -> Result<Response> {
        let mut request = self.authed_request_builder(method, path)?;
        if let Some(ttl) = wrap_ttl {
            request = request.header(VAULT_WRAP_TTL_HEADER, ttl);
        }
        self.send_request(request, path).await
    }

    async fn send_authed_json<T: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: &T,
        wrap_ttl: Option<&str>,
    ) -> Result<Response> {
        let mut request = self.authed_request_builder(method, path)?;
        if let Some(ttl) = wrap_ttl {
            request = request.header(VAULT_WRAP_TTL_HEADER, ttl);
        }
        let request = request.json(body);
        self.send_request(request, path).await
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

    async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        use_token: bool,
        wrap_ttl: Option<&str>,
    ) -> Result<T> {
        let mut request = self.request_builder(Method::GET, path);
        if use_token {
            request = request.header(VAULT_TOKEN_HEADER, self.require_token()?);
        }
        if let Some(ttl) = wrap_ttl {
            request = request.header(VAULT_WRAP_TTL_HEADER, ttl);
        }
        let response = self.send_request(request, path).await?;
        Self::parse_response(response)
            .await
            .with_context(|| format!("OpenBao response parse failed: {path}"))
    }

    async fn resource_exists(&self, path: &str) -> Result<bool> {
        let response = self.send_authed(Method::GET, path, None).await?;
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
        wrap_ttl: Option<&str>,
    ) -> Result<R> {
        let response = self
            .send_authed_json(Method::POST, path, body, wrap_ttl)
            .await?;
        Self::parse_response(response)
            .await
            .with_context(|| format!("OpenBao response parse failed: {path}"))
    }

    async fn post_action<T: Serialize>(&self, path: &str, body: &T) -> Result<()> {
        let response = self
            .send_authed_json(Method::POST, path, body, None)
            .await?;
        Self::ensure_success(response)
            .await
            .with_context(|| format!("OpenBao response failed: {path}"))
    }

    async fn delete_action(&self, path: &str) -> Result<()> {
        let response = self.send_authed(Method::DELETE, path, None).await?;
        Self::ensure_success(response)
            .await
            .with_context(|| format!("OpenBao response failed: {path}"))
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

/// Parameters for [`build_agent_config`].
pub struct AgentConfigParams<'a> {
    /// Vault/`OpenBao` server address.
    pub openbao_addr: &'a str,
    /// Path to the `AppRole` role-ID file.
    pub role_id_path: &'a str,
    /// Path to the `AppRole` secret-ID file.
    pub secret_id_path: &'a str,
    /// Path where the agent writes its token.
    pub token_path: &'a str,
    /// Optional auth mount path (e.g. `"auth/approle"`).
    pub mount_path: Option<&'a str>,
    /// Value for `static_secret_render_interval`.
    pub render_interval: &'a str,
    /// `(source, destination)` pairs for template blocks.
    pub templates: &'a [(&'a str, &'a str)],
    /// Optional path to a CA certificate bundle for TLS verification of
    /// the `OpenBao` server.
    pub ca_cert: Option<&'a str>,
}

/// Builds an `OpenBao` agent HCL configuration string.
#[must_use]
pub fn build_agent_config(params: &AgentConfigParams<'_>) -> String {
    let mount_line = match params.mount_path {
        Some(mp) => format!("\n    mount_path = \"{mp}\""),
        None => String::new(),
    };
    let tls_line = match params.ca_cert {
        Some(path) => format!("\n  ca_cert = \"{path}\""),
        None => String::new(),
    };
    let openbao_addr = params.openbao_addr;
    let role_id_path = params.role_id_path;
    let secret_id_path = params.secret_id_path;
    let token_path = params.token_path;
    let render_interval = params.render_interval;
    let mut config = format!(
        r#"vault {{
  address = "{openbao_addr}"{tls_line}
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
    for (source_path, destination_path) in params.templates {
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
mod wrap_tests {
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn client_with_token(server: &MockServer) -> OpenBaoClient {
        let mut client = OpenBaoClient::new(&server.uri()).expect("client init");
        client.set_token("root-token".to_string());
        client
    }

    #[tokio::test]
    async fn get_json_sends_wrap_ttl_header() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/secret/data/test"))
            .and(header("X-Vault-Token", "root-token"))
            .and(header("X-Vault-Wrap-TTL", "90s"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "wrap_info": {
                    "token": "wrap-get-token",
                    "ttl": 90,
                    "creation_time": "2026-04-12T00:00:00Z",
                    "creation_path": "secret/data/test"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_with_token(&server);
        let info: WrappedResponse = client
            .get_json("secret/data/test", true, Some("90s"))
            .await
            .expect("get_json with wrap_ttl should succeed");
        assert_eq!(info.wrap_info.token, "wrap-get-token");
        assert_eq!(info.wrap_info.ttl, 90);
    }

    #[tokio::test]
    async fn create_secret_id_wrapped_sends_header_and_unwraps() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/role/svc-role/secret-id"))
            .and(header("X-Vault-Token", "root-token"))
            .and(header("X-Vault-Wrap-TTL", "30m"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "wrap_info": {
                    "token": "wrap-sid-token",
                    "ttl": 1800,
                    "creation_time": "2026-04-12T00:00:00Z",
                    "creation_path": "auth/approle/role/svc-role/secret-id"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1/sys/wrapping/unwrap"))
            .and(header("X-Vault-Token", "wrap-sid-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "secret_id": "unwrapped-secret-abc",
                    "secret_id_accessor": "acc"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_with_token(&server);
        let opts = SecretIdOptions {
            num_uses: Some(1),
            ..Default::default()
        };
        let secret_id = client
            .create_secret_id_wrapped("svc-role", &opts, "30m")
            .await
            .expect("create_secret_id_wrapped should succeed");
        assert_eq!(secret_id, "unwrapped-secret-abc");
    }
}

#[cfg(test)]
mod secret_id_options_tests {
    use super::*;

    #[test]
    fn default_serializes_to_empty_object() {
        let opts = SecretIdOptions::default();
        let json = serde_json::to_value(&opts).expect("serialize");
        assert_eq!(json, serde_json::json!({}));
    }

    #[test]
    fn serializes_ttl_only() {
        let opts = SecretIdOptions {
            ttl: Some("24h".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_value(&opts).expect("serialize");
        assert_eq!(json, serde_json::json!({"ttl": "24h"}));
    }

    #[test]
    fn serializes_num_uses_only() {
        let opts = SecretIdOptions {
            num_uses: Some(1),
            ..Default::default()
        };
        let json = serde_json::to_value(&opts).expect("serialize");
        assert_eq!(json, serde_json::json!({"num_uses": 1}));
    }

    #[test]
    fn serializes_all_fields() {
        let opts = SecretIdOptions {
            ttl: Some("30m".to_string()),
            num_uses: Some(5),
            metadata: Some(r#"{"source":"rotate"}"#.to_string()),
            token_bound_cidrs: Some(vec!["10.0.0.0/24".to_string()]),
        };
        let json = serde_json::to_value(&opts).expect("serialize");
        assert_eq!(
            json,
            serde_json::json!({
                "ttl": "30m",
                "num_uses": 5,
                "metadata": "{\"source\":\"rotate\"}",
                "token_bound_cidrs": ["10.0.0.0/24"]
            })
        );
    }

    #[test]
    fn omits_none_fields() {
        let opts = SecretIdOptions {
            ttl: Some("1h".to_string()),
            num_uses: None,
            metadata: None,
            token_bound_cidrs: None,
        };
        let json = serde_json::to_value(&opts).expect("serialize");
        let obj = json.as_object().expect("object");
        assert!(obj.contains_key("ttl"));
        assert!(!obj.contains_key("num_uses"));
        assert!(!obj.contains_key("metadata"));
        assert!(!obj.contains_key("token_bound_cidrs"));
    }
}

#[cfg(test)]
mod agent_config_tests {
    use super::*;

    #[test]
    fn without_mount_path() {
        let hcl = build_agent_config(&AgentConfigParams {
            openbao_addr: "http://openbao:8200",
            role_id_path: "/role_id",
            secret_id_path: "/secret_id",
            token_path: "/token",
            mount_path: None,
            render_interval: "30s",
            templates: &[("/tpl.ctmpl", "/out.toml")],
            ca_cert: None,
        });
        assert!(hcl.contains(r#"address = "http://openbao:8200""#));
        assert!(hcl.contains("role_id_file_path = \"/role_id\""));
        assert!(!hcl.contains("mount_path"));
        assert!(!hcl.contains("ca_cert"));
        assert!(hcl.contains(r#"static_secret_render_interval = "30s""#));
        assert!(hcl.contains(r#"source = "/tpl.ctmpl""#));
    }

    #[test]
    fn with_mount_path() {
        let hcl = build_agent_config(&AgentConfigParams {
            openbao_addr: "http://openbao:8200",
            role_id_path: "/role_id",
            secret_id_path: "/secret_id",
            token_path: "/token",
            mount_path: Some("auth/approle"),
            render_interval: "30s",
            templates: &[("/tpl.ctmpl", "/out.toml")],
            ca_cert: None,
        });
        assert!(hcl.contains(r#"mount_path = "auth/approle""#));
    }

    #[test]
    fn multiple_templates() {
        let hcl = build_agent_config(&AgentConfigParams {
            openbao_addr: "http://openbao:8200",
            role_id_path: "/role_id",
            secret_id_path: "/secret_id",
            token_path: "/token",
            mount_path: None,
            render_interval: "30s",
            templates: &[("/a.ctmpl", "/a.out"), ("/b.ctmpl", "/b.out")],
            ca_cert: None,
        });
        assert!(hcl.contains(r#"source = "/a.ctmpl""#));
        assert!(hcl.contains(r#"source = "/b.ctmpl""#));
    }

    #[test]
    fn with_ca_cert() {
        let hcl = build_agent_config(&AgentConfigParams {
            openbao_addr: "https://openbao:8200",
            role_id_path: "/role_id",
            secret_id_path: "/secret_id",
            token_path: "/token",
            mount_path: Some("auth/approle"),
            render_interval: "30s",
            templates: &[("/tpl.ctmpl", "/out.toml")],
            ca_cert: Some("/certs/ca-bundle.pem"),
        });
        assert!(hcl.contains(r#"address = "https://openbao:8200""#));
        assert!(hcl.contains(r#"ca_cert = "/certs/ca-bundle.pem""#));
    }

    #[test]
    fn without_ca_cert() {
        let hcl = build_agent_config(&AgentConfigParams {
            openbao_addr: "http://openbao:8200",
            role_id_path: "/role_id",
            secret_id_path: "/secret_id",
            token_path: "/token",
            mount_path: None,
            render_interval: "30s",
            templates: &[("/tpl.ctmpl", "/out.toml")],
            ca_cert: None,
        });
        assert!(!hcl.contains("ca_cert"));
    }
}

/// End-to-end HTTPS tests proving that [`OpenBaoClient::with_pem_trust`]
/// verifies against the artifact-embedded CA and rejects unknown CAs.
#[cfg(test)]
mod tls_integration_tests {
    use std::sync::Arc;

    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    struct TestCa {
        cert: rcgen::Certificate,
        issuer: Issuer<'static, KeyPair>,
    }

    impl TestCa {
        fn generate() -> Self {
            let key = KeyPair::generate().expect("generate CA key");
            let mut params = CertificateParams::new(Vec::new()).expect("cert params");
            params
                .distinguished_name
                .push(DnType::CommonName, "Test CA");
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let cert = params.self_signed(&key).expect("self-signed CA");
            let issuer = Issuer::new(params, key);
            Self { cert, issuer }
        }

        fn pem(&self) -> String {
            self.cert.pem()
        }

        fn sign_server_cert(&self) -> ServerCert {
            let key = KeyPair::generate().expect("generate server key");
            let mut params =
                CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
            params
                .distinguished_name
                .push(DnType::CommonName, "localhost");
            params.is_ca = IsCa::NoCa;
            let cert = params
                .signed_by(&key, &self.issuer)
                .expect("signed server cert");
            ServerCert {
                cert_der: cert.der().to_vec(),
                key_der: key.serialize_der(),
            }
        }
    }

    struct ServerCert {
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    }

    /// Starts a minimal HTTPS server that returns `200 OK` for every
    /// request. Returns the port on `127.0.0.1`.
    async fn start_tls_server(server: ServerCert) -> u16 {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = CertificateDer::from(server.cert_der);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server.key_der));

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("server TLS config");

        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local addr").port();

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut buf = vec![0u8; 4096];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\n\
                              Content-Length: 0\r\n\
                              Connection: close\r\n\r\n",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });

        port
    }

    #[tokio::test]
    async fn with_pem_trust_validates_against_artifact_ca() {
        let ca = TestCa::generate();
        let server_cert = ca.sign_server_cert();
        let port = start_tls_server(server_cert).await;

        let client =
            OpenBaoClient::with_pem_trust(&format!("https://localhost:{port}"), &ca.pem(), &[])
                .expect("client with correct CA");

        client
            .health_check()
            .await
            .expect("health check should pass with artifact CA");
    }

    #[tokio::test]
    async fn with_pem_trust_rejects_unknown_ca() {
        let ca = TestCa::generate();
        let wrong_ca = TestCa::generate();
        let server_cert = ca.sign_server_cert();
        let port = start_tls_server(server_cert).await;

        let client = OpenBaoClient::with_pem_trust(
            &format!("https://localhost:{port}"),
            &wrong_ca.pem(),
            &[],
        )
        .expect("client with wrong CA");

        client
            .health_check()
            .await
            .expect_err("health check should fail with wrong CA");
    }
}
