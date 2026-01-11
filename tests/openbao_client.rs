use bootroot::openbao::OpenBaoClient;
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

    let mut client = OpenBaoClient::new(&server.uri()).expect("client init should succeed");
    client.set_token("root-token".to_string());

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

    let mut client = OpenBaoClient::new(&server.uri()).expect("client init should succeed");
    client.set_token("root-token".to_string());

    client
        .write_kv(
            "secret",
            "bootroot/stepca/password",
            json!({ "value": "secret" }),
        )
        .await
        .expect("write_kv should succeed");
}
