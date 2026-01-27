use bootroot::openbao::{KvMountStatus, OpenBaoClient};
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
