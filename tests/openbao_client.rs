use bootroot::openbao::{KvMountStatus, OpenBaoClient, WrapInfo};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client_with_token(server: &MockServer) -> OpenBaoClient {
    let mut client = OpenBaoClient::new(&server.uri()).expect("client init should succeed");
    client.set_token("root-token".to_string());
    client
}

#[tokio::test]
async fn ensure_approle_auth_enables_when_missing() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/auth"))
        .and(header("X-Vault-Token", "root-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": {} })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/auth/approle"))
        .and(header("X-Vault-Token", "root-token"))
        .and(body_json(json!({ "type": "approle" })))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let client = client_with_token(&server);

    client
        .ensure_approle_auth()
        .await
        .expect("ensure_approle_auth should succeed");
}

#[tokio::test]
async fn write_kv_uses_v2_path() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/stepca/password"))
        .and(header("X-Vault-Token", "root-token"))
        .and(body_json(json!({ "data": { "value": "secret" } })))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let client = client_with_token(&server);

    client
        .write_kv(
            "secret",
            "bootroot/stepca/password",
            json!({ "value": "secret" }),
        )
        .await
        .expect("write_kv should succeed");
}

#[tokio::test]
async fn read_kv_returns_data() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .and(header("X-Vault-Token", "root-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "data": {
                    "trusted_ca_sha256": ["abc123"]
                }
            }
        })))
        .mount(&server)
        .await;

    let client = client_with_token(&server);

    let data = client
        .read_kv("secret", "bootroot/ca")
        .await
        .expect("read_kv should succeed");
    assert_eq!(
        data,
        json!({
            "trusted_ca_sha256": ["abc123"]
        })
    );
}

#[tokio::test]
async fn policy_exists_returns_false_on_404() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/policies/acl/bootroot-agent"))
        .and(header("X-Vault-Token", "root-token"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    let exists = client
        .policy_exists("bootroot-agent")
        .await
        .expect("policy_exists should succeed");
    assert!(!exists);
}

#[tokio::test]
async fn approle_exists_returns_false_on_404() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/approle/role/bootroot-agent-role"))
        .and(header("X-Vault-Token", "root-token"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    let exists = client
        .approle_exists("bootroot-agent-role")
        .await
        .expect("approle_exists should succeed");
    assert!(!exists);
}

#[tokio::test]
async fn approle_login_returns_token() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .and(body_json(json!({
            "role_id": "role-id",
            "secret_id": "secret-id"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": {
                "client_token": "client-token"
            }
        })))
        .mount(&server)
        .await;

    let client = OpenBaoClient::new(&server.uri()).expect("client init should succeed");
    let token = client
        .login_approle("role-id", "secret-id")
        .await
        .expect("login_approle should succeed");
    assert_eq!(token, "client-token");
}

#[tokio::test]
async fn kv_exists_returns_false_on_404() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/bootroot/stepca/password"))
        .and(header("X-Vault-Token", "root-token"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    let exists = client
        .kv_exists("secret", "bootroot/stepca/password")
        .await
        .expect("kv_exists should succeed");
    assert!(!exists);
}

#[tokio::test]
async fn kv_mount_status_returns_missing_on_404() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/mounts/secret"))
        .and(header("X-Vault-Token", "root-token"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    let status = client
        .kv_mount_status("secret")
        .await
        .expect("kv_mount_status should succeed");
    assert_eq!(status, KvMountStatus::Missing);
}

#[tokio::test]
async fn kv_mount_status_returns_ok_for_kv_v2() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/mounts/secret"))
        .and(header("X-Vault-Token", "root-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "kv",
                "options": {
                    "version": "2"
                }
            }
        })))
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    let status = client
        .kv_mount_status("secret")
        .await
        .expect("kv_mount_status should succeed");
    assert_eq!(status, KvMountStatus::Ok);
}

#[tokio::test]
async fn kv_mount_status_returns_not_kv() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/mounts/secret"))
        .and(header("X-Vault-Token", "root-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "transit",
                "options": {}
            }
        })))
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    let status = client
        .kv_mount_status("secret")
        .await
        .expect("kv_mount_status should succeed");
    assert_eq!(status, KvMountStatus::NotKv);
}

#[tokio::test]
async fn kv_mount_status_returns_not_v2() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/mounts/secret"))
        .and(header("X-Vault-Token", "root-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "kv",
                "options": {
                    "version": "1"
                }
            }
        })))
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    let status = client
        .kv_mount_status("secret")
        .await
        .expect("kv_mount_status should succeed");
    assert_eq!(status, KvMountStatus::NotV2);
}

#[tokio::test]
async fn delete_policy_uses_acl_path() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/sys/policies/acl/bootroot-agent"))
        .and(header("X-Vault-Token", "root-token"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    client
        .delete_policy("bootroot-agent")
        .await
        .expect("delete_policy should succeed");
}

#[tokio::test]
async fn delete_approle_uses_role_path() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/auth/approle/role/bootroot-agent-role"))
        .and(header("X-Vault-Token", "root-token"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    client
        .delete_approle("bootroot-agent-role")
        .await
        .expect("delete_approle should succeed");
}

#[tokio::test]
async fn delete_kv_uses_metadata_path() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/secret/metadata/bootroot/responder/hmac"))
        .and(header("X-Vault-Token", "root-token"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    client
        .delete_kv("secret", "bootroot/responder/hmac")
        .await
        .expect("delete_kv should succeed");
}

#[tokio::test]
async fn policy_exists_errors_on_server_failure() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/policies/acl/bootroot-agent"))
        .and(header("X-Vault-Token", "root-token"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    let err = client
        .policy_exists("bootroot-agent")
        .await
        .expect_err("policy_exists should fail on 500");
    assert!(err.to_string().contains("OpenBao API error"));
}

#[tokio::test]
async fn is_initialized_errors_on_malformed_body() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/init"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
        .mount(&server)
        .await;

    let client = OpenBaoClient::new(&server.uri()).expect("client init should succeed");
    let err = client
        .is_initialized()
        .await
        .expect_err("is_initialized should fail on malformed body");
    assert!(err.to_string().contains("OpenBao response parse failed"));
}

#[tokio::test]
async fn start_rekey_uses_sys_rekey_init_path() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/rekey/init"))
        .and(header("X-Vault-Token", "root-token"))
        .and(body_json(json!({
            "secret_shares": 5,
            "secret_threshold": 3
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "nonce": "nonce-1",
            "progress": 0
        })))
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    let response = client
        .start_rekey(5, 3)
        .await
        .expect("start_rekey should succeed");
    assert_eq!(response.nonce, "nonce-1");
}

#[tokio::test]
async fn submit_rekey_share_uses_sys_rekey_update_path() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/rekey/update"))
        .and(header("X-Vault-Token", "root-token"))
        .and(body_json(json!({
            "nonce": "nonce-1",
            "key": "old-unseal-key"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "complete": true,
            "keys": ["new-unseal-1", "new-unseal-2", "new-unseal-3"]
        })))
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    let response = client
        .submit_rekey_share("nonce-1", "old-unseal-key")
        .await
        .expect("submit_rekey_share should succeed");
    assert!(response.complete);
    assert_eq!(
        response.keys,
        vec!["new-unseal-1", "new-unseal-2", "new-unseal-3"]
    );
}

#[tokio::test]
async fn create_root_token_uses_auth_token_create_path() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/token/create"))
        .and(header("X-Vault-Token", "root-token"))
        .and(body_json(json!({
            "policies": ["root"],
            "renewable": false,
            "no_parent": true
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "new-root-token" }
        })))
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    let token = client
        .create_root_token()
        .await
        .expect("create_root_token should succeed");
    assert_eq!(token, "new-root-token");
}

#[tokio::test]
async fn post_json_wrapped_sends_wrap_ttl_via_common_path() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/role/my-role/secret-id"))
        .and(header("X-Vault-Token", "root-token"))
        .and(header("X-Vault-Wrap-TTL", "120s"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "wrap_info": {
                "token": "wrap-token-abc",
                "ttl": 120,
                "creation_time": "2026-04-12T00:00:00Z",
                "creation_path": "auth/approle/role/my-role/secret-id"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    let info: WrapInfo = client
        .post_json_wrapped("auth/approle/role/my-role/secret-id", &json!({}), "120s")
        .await
        .expect("post_json_wrapped should succeed");
    assert_eq!(info.token, "wrap-token-abc");
    assert_eq!(info.ttl, 120);
    assert_eq!(info.creation_path, "auth/approle/role/my-role/secret-id");
}

#[tokio::test]
async fn wrapped_response_envelope_is_parsed() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/data/test"))
        .and(header("X-Vault-Token", "root-token"))
        .and(header("X-Vault-Wrap-TTL", "60s"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "wrap_info": {
                "token": "hvs.wrap-token-xyz",
                "ttl": 60,
                "creation_time": "2026-04-12T12:00:00.000000Z",
                "creation_path": "secret/data/test"
            }
        })))
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    let info: WrapInfo = client
        .post_json_wrapped("secret/data/test", &json!({"data": {"key": "val"}}), "60s")
        .await
        .expect("wrapped response should parse");
    assert_eq!(info.token, "hvs.wrap-token-xyz");
    assert_eq!(info.ttl, 60);
    assert_eq!(info.creation_time, "2026-04-12T12:00:00.000000Z");
    assert_eq!(info.creation_path, "secret/data/test");
}

#[tokio::test]
async fn unwrap_secret_sends_correct_request() {
    #[derive(serde::Deserialize)]
    struct UnwrapResult {
        data: UnwrapData,
    }
    #[derive(serde::Deserialize)]
    struct UnwrapData {
        secret_id: String,
    }

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/unwrap"))
        .and(header("X-Vault-Token", "wrap-token-abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "secret_id": "unwrapped-secret-id"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = OpenBaoClient::new(&server.uri()).expect("client init should succeed");
    let result: UnwrapResult = client
        .unwrap_secret("wrap-token-abc")
        .await
        .expect("unwrap_secret should succeed");
    assert_eq!(result.data.secret_id, "unwrapped-secret-id");
}

#[tokio::test]
async fn verify_audit_file_fails_when_missing() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/audit"))
        .and(header("X-Vault-Token", "root-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": {} })))
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    let err = client
        .verify_audit_file()
        .await
        .expect_err("verify_audit_file should fail when no audit backend exists");
    assert!(
        err.to_string().contains("no file audit backend found"),
        "error should mention missing audit: {err}"
    );
}

#[tokio::test]
async fn verify_audit_file_succeeds_when_present() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/audit"))
        .and(header("X-Vault-Token", "root-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "file/": {
                    "type": "file",
                    "options": { "file_path": "/openbao/audit/audit.log" }
                }
            }
        })))
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    client
        .verify_audit_file()
        .await
        .expect("verify_audit_file should succeed when file backend is present");
}

#[tokio::test]
async fn verify_audit_file_succeeds_at_custom_mount() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/audit"))
        .and(header("X-Vault-Token", "root-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "audit/": {
                    "type": "file",
                    "options": { "file_path": "/var/log/openbao/audit.log" }
                }
            }
        })))
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    client
        .verify_audit_file()
        .await
        .expect("verify_audit_file should detect file backend at custom mount");
}

#[tokio::test]
async fn verify_audit_file_fails_on_empty_response() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/audit"))
        .and(header("X-Vault-Token", "root-token"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    client
        .verify_audit_file()
        .await
        .expect_err("verify_audit_file should fail on empty response body");
}

#[tokio::test]
async fn create_secret_id_with_token_bound_cidrs() {
    use bootroot::openbao::SecretIdOptions;

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/role/svc-role/secret-id"))
        .and(header("X-Vault-Token", "root-token"))
        .and(body_json(json!({
            "num_uses": 0,
            "token_bound_cidrs": ["10.0.0.0/24", "192.168.1.0/24"]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "secret_id": "cidr-bound-secret" }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_with_token(&server);
    let opts = SecretIdOptions {
        num_uses: Some(0),
        token_bound_cidrs: Some(vec![
            "10.0.0.0/24".to_string(),
            "192.168.1.0/24".to_string(),
        ]),
        ..Default::default()
    };
    let secret_id = client
        .create_secret_id("svc-role", &opts)
        .await
        .expect("create_secret_id with CIDRs should succeed");
    assert_eq!(secret_id, "cidr-bound-secret");
}
