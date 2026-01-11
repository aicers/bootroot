use std::any::TypeId;

use anyhow::{Context, Result};
use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const VAULT_TOKEN_HEADER: &str = "X-Vault-Token";

#[derive(Debug, Clone)]
pub struct OpenBaoClient {
    base_url: String,
    client: Client,
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct InitStatus {
    pub initialized: bool,
}

#[derive(Debug, Deserialize)]
pub struct SealStatus {
    pub sealed: bool,
    #[serde(default)]
    pub t: Option<u32>,
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

impl OpenBaoClient {
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

    pub async fn health_check(&self) -> Result<()> {
        let url = self.endpoint("sys/health");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .context("OpenBao health check failed")?;
        let status = response.status();
        if status == StatusCode::OK
            || status == StatusCode::TOO_MANY_REQUESTS
            || status == StatusCode::SERVICE_UNAVAILABLE
            || status == StatusCode::NOT_IMPLEMENTED
        {
            return Ok(());
        }
        anyhow::bail!("OpenBao health check failed with status: {status}");
    }

    pub async fn is_initialized(&self) -> Result<bool> {
        let status: InitStatus = self.get_json("sys/init", false).await?;
        Ok(status.initialized)
    }

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

    pub async fn seal_status(&self) -> Result<SealStatus> {
        self.get_json("sys/seal-status", false).await
    }

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
            let _: serde_json::Value = self
                .post_json(
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
            let _: serde_json::Value = self
                .post_json(
                    "sys/auth/approle",
                    &AuthRequest {
                        auth_type: "approle",
                    },
                )
                .await?;
        }
        Ok(())
    }

    pub async fn write_policy(&self, name: &str, policy: &str) -> Result<()> {
        #[derive(Serialize)]
        struct PolicyRequest<'a> {
            policy: &'a str,
        }
        let _: serde_json::Value = self
            .post_json(
                &format!("sys/policies/acl/{name}"),
                &PolicyRequest { policy },
            )
            .await?;
        Ok(())
    }

    pub async fn create_approle(
        &self,
        name: &str,
        policies: &[String],
        token_ttl: &str,
        secret_id_ttl: &str,
        token_renewable: bool,
    ) -> Result<()> {
        #[derive(Serialize)]
        struct AppRoleRequest<'a> {
            token_policies: &'a [String],
            token_ttl: &'a str,
            token_max_ttl: &'a str,
            token_renewable: bool,
            secret_id_ttl: &'a str,
        }
        let _: serde_json::Value = self
            .post_json(
                &format!("auth/approle/role/{name}"),
                &AppRoleRequest {
                    token_policies: policies,
                    token_ttl,
                    token_max_ttl: token_ttl,
                    token_renewable,
                    secret_id_ttl,
                },
            )
            .await?;
        Ok(())
    }

    pub async fn read_role_id(&self, name: &str) -> Result<String> {
        let response: RoleIdResponse = self
            .get_json(&format!("auth/approle/role/{name}/role-id"), true)
            .await?;
        Ok(response.data.role_id)
    }

    pub async fn create_secret_id(&self, name: &str) -> Result<String> {
        let response: SecretIdResponse = self
            .post_json(
                &format!("auth/approle/role/{name}/secret-id"),
                &serde_json::json!({}),
            )
            .await?;
        Ok(response.data.secret_id)
    }

    pub async fn write_kv(&self, mount: &str, path: &str, data: serde_json::Value) -> Result<()> {
        #[derive(Serialize)]
        struct KvRequest {
            data: serde_json::Value,
        }
        self.post_json(&format!("{mount}/data/{path}"), &KvRequest { data })
            .await
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}/v1/{path}", self.base_url)
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
        if status == StatusCode::NOT_FOUND
            || (status == StatusCode::BAD_REQUEST && text.contains("No secret engine mount"))
        {
            return Ok(None);
        }
        if !status.is_success() {
            anyhow::bail!("OpenBao API error ({status}): {text}");
        }
        let parsed: MountResponse =
            serde_json::from_str(&text).context("Failed to parse mount response")?;
        Ok(Some(parsed.data))
    }

    async fn get_json<T: DeserializeOwned + 'static>(
        &self,
        path: &str,
        use_token: bool,
    ) -> Result<T> {
        let url = self.endpoint(path);
        let mut request = self.client.get(url);
        if use_token {
            let token = self
                .token
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("OpenBao token is not set"))?;
            request = request.header(VAULT_TOKEN_HEADER, token);
        }
        let response = request
            .send()
            .await
            .with_context(|| format!("OpenBao request failed: {path}"))?;
        Self::parse_response(response)
            .await
            .with_context(|| format!("OpenBao response parse failed: {path}"))
    }

    async fn post_json<T: Serialize, R: DeserializeOwned + 'static>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R> {
        let url = self.endpoint(path);
        let token = self
            .token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OpenBao token is not set"))?;
        let response = self
            .client
            .post(url)
            .header(VAULT_TOKEN_HEADER, token)
            .json(body)
            .send()
            .await
            .with_context(|| format!("OpenBao request failed: {path}"))?;
        Self::parse_response(response)
            .await
            .with_context(|| format!("OpenBao response parse failed: {path}"))
    }

    async fn parse_response<T: DeserializeOwned + 'static>(
        response: reqwest::Response,
    ) -> Result<T> {
        let status = response.status();
        let text = response
            .text()
            .await
            .context("Failed to read OpenBao response body")?;
        if !status.is_success() {
            anyhow::bail!("OpenBao API error ({status}): {text}");
        }
        if text.trim().is_empty() {
            let parsed =
                serde_json::from_str("null").context("Failed to parse empty OpenBao response")?;
            return Ok(parsed);
        }
        match serde_json::from_str(&text) {
            Ok(parsed) => Ok(parsed),
            Err(err) => {
                if TypeId::of::<T>() == TypeId::of::<()>() {
                    let parsed = serde_json::from_str("null")
                        .context("Failed to parse OpenBao response as unit")?;
                    Ok(parsed)
                } else {
                    Err(err).context("Failed to parse OpenBao response")
                }
            }
        }
    }
}
