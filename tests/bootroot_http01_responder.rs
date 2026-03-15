use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bootroot::acme::http01_protocol::{HEADER_SIGNATURE, HEADER_TIMESTAMP, Http01HmacSigner};
use reqwest::StatusCode;
use serde_json::json;
use tempfile::tempdir;
use tokio::time::sleep;

const ADMIN_PATH: &str = "/admin/http01";
const CHALLENGE_PATH_PREFIX: &str = "/.well-known/acme-challenge";
const STARTUP_RETRIES: usize = 50;
const STARTUP_DELAY: Duration = Duration::from_millis(100);
const TEST_TTL_SECS: u64 = 60;

#[tokio::test]
async fn test_http01_responder_serves_registered_token() {
    let temp_dir = tempdir().expect("create temp dir");
    let listen_addr = reserve_socket_addr();
    let admin_addr = reserve_socket_addr();
    let config_path = temp_dir.path().join("responder.toml");
    write_responder_config(&config_path, &listen_addr, &admin_addr, "initial-secret");

    let mut responder = ResponderProcess::spawn(&config_path);
    let challenge_base_url = format!("http://{listen_addr}");
    let admin_base_url = format!("http://{admin_addr}");
    wait_for_ready(&mut responder, &challenge_base_url).await;

    let response = register_token(
        &admin_base_url,
        "initial-secret",
        "token-1",
        "token-1.key",
        TEST_TTL_SECS,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let challenge = fetch_challenge(&challenge_base_url, "token-1").await;
    assert_eq!(challenge.status(), StatusCode::OK);
    assert_eq!(
        challenge.text().await.expect("read challenge response"),
        "token-1.key"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_http01_responder_reloads_hmac_secret_on_sighup() {
    let temp_dir = tempdir().expect("create temp dir");
    let listen_addr = reserve_socket_addr();
    let admin_addr = reserve_socket_addr();
    let config_path = temp_dir.path().join("responder.toml");
    write_responder_config(&config_path, &listen_addr, &admin_addr, "old-secret");

    let mut responder = ResponderProcess::spawn(&config_path);
    let challenge_base_url = format!("http://{listen_addr}");
    let admin_base_url = format!("http://{admin_addr}");
    wait_for_ready(&mut responder, &challenge_base_url).await;

    write_responder_config(&config_path, &listen_addr, &admin_addr, "new-secret");
    send_sighup(responder.pid());

    let accepted_token =
        wait_for_reload(&mut responder, &admin_base_url, "old-secret", "new-secret").await;
    let challenge = fetch_challenge(&challenge_base_url, &accepted_token).await;
    assert_eq!(challenge.status(), StatusCode::OK);
    assert_eq!(
        challenge.text().await.expect("read challenge response"),
        format!("{accepted_token}.key")
    );
}

struct ResponderProcess {
    child: Child,
}

impl ResponderProcess {
    fn spawn(config_path: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_bootroot-http01-responder"))
            .args(["--config", config_path.to_string_lossy().as_ref()])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn bootroot-http01-responder");
        Self { child }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().expect("poll responder process")
    }

    fn take_stderr(&mut self) -> String {
        let Some(mut stderr) = self.child.stderr.take() else {
            return String::new();
        };
        let mut output = String::new();
        stderr
            .read_to_string(&mut output)
            .expect("read responder stderr");
        output
    }
}

impl Drop for ResponderProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn reserve_socket_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener
        .local_addr()
        .expect("read listener address")
        .to_string()
}

fn write_responder_config(config_path: &Path, listen_addr: &str, admin_addr: &str, secret: &str) {
    let contents = format!(
        "listen_addr = \"{listen_addr}\"\n\
admin_addr = \"{admin_addr}\"\n\
hmac_secret = \"{secret}\"\n\
token_ttl_secs = 300\n\
cleanup_interval_secs = 30\n\
max_skew_secs = 60\n"
    );
    fs::write(config_path, contents).expect("write responder config");
}

fn sign_request(
    secret: &str,
    token: &str,
    key_authorization: &str,
    ttl_secs: u64,
) -> (i64, String) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time must be after UNIX_EPOCH")
        .as_secs();
    let timestamp = i64::try_from(timestamp).expect("System time must fit in i64");
    let signer = Http01HmacSigner::new(secret);
    let signature = signer.sign_request(timestamp, token, key_authorization, ttl_secs);
    (timestamp, signature)
}

async fn wait_for_ready(responder: &mut ResponderProcess, challenge_base_url: &str) {
    let url = format!("{challenge_base_url}{CHALLENGE_PATH_PREFIX}/health-check");

    for _ in 0..STARTUP_RETRIES {
        if let Some(status) = responder.try_wait() {
            let stderr = responder.take_stderr();
            panic!("responder exited early with {status}: {stderr}");
        }

        match reqwest::get(&url).await {
            Ok(response) if matches!(response.status(), StatusCode::NOT_FOUND | StatusCode::OK) => {
                return;
            }
            Ok(_) | Err(_) => sleep(STARTUP_DELAY).await,
        }
    }

    panic!("responder did not become ready");
}

async fn register_token(
    admin_base_url: &str,
    secret: &str,
    token: &str,
    key_authorization: &str,
    ttl_secs: u64,
) -> reqwest::Response {
    let (timestamp, signature) = sign_request(secret, token, key_authorization, ttl_secs);

    reqwest::Client::new()
        .post(format!("{admin_base_url}{ADMIN_PATH}"))
        .header(HEADER_TIMESTAMP, timestamp.to_string())
        .header(HEADER_SIGNATURE, signature)
        .json(&json!({
            "token": token,
            "key_authorization": key_authorization,
            "ttl_secs": ttl_secs
        }))
        .send()
        .await
        .expect("send register request")
}

async fn fetch_challenge(challenge_base_url: &str, token: &str) -> reqwest::Response {
    reqwest::get(format!(
        "{challenge_base_url}{CHALLENGE_PATH_PREFIX}/{token}"
    ))
    .await
    .expect("fetch challenge response")
}

#[cfg(unix)]
async fn wait_for_reload(
    responder: &mut ResponderProcess,
    admin_base_url: &str,
    old_secret: &str,
    new_secret: &str,
) -> String {
    for attempt in 0..STARTUP_RETRIES {
        if let Some(status) = responder.try_wait() {
            let stderr = responder.take_stderr();
            panic!("responder exited during reload with {status}: {stderr}");
        }

        let rejected_token = format!("rejected-{attempt}");
        let rejected_key = format!("{rejected_token}.key");
        let rejected = register_token(
            admin_base_url,
            old_secret,
            &rejected_token,
            &rejected_key,
            TEST_TTL_SECS,
        )
        .await;

        if rejected.status() == StatusCode::UNAUTHORIZED {
            let accepted_token = format!("accepted-{attempt}");
            let accepted_key = format!("{accepted_token}.key");
            let accepted = register_token(
                admin_base_url,
                new_secret,
                &accepted_token,
                &accepted_key,
                TEST_TTL_SECS,
            )
            .await;
            if accepted.status() == StatusCode::OK {
                return accepted_token;
            }
        }

        sleep(STARTUP_DELAY).await;
    }

    panic!("responder did not reload the updated HMAC secret");
}

#[cfg(unix)]
fn send_sighup(pid: u32) {
    let pid = i32::try_from(pid).expect("child pid must fit in i32");
    // SAFETY: The pid comes from a live child process spawned by this test.
    let result = unsafe { libc::kill(pid, libc::SIGHUP) };
    assert_eq!(result, 0, "SIGHUP should be delivered");
}
