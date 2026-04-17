pub(crate) const DEFAULT_OPENBAO_URL: &str = "http://localhost:8200";
pub(crate) const DEFAULT_KV_MOUNT: &str = "secret";
pub(crate) const DEFAULT_SECRETS_DIR: &str = "secrets";
pub(crate) const DEFAULT_COMPOSE_FILE: &str = "docker-compose.yml";
pub(crate) const DEFAULT_STEPCA_URL: &str = "https://localhost:9000";
pub(crate) const DEFAULT_STEPCA_PROVISIONER: &str = "acme";

pub(crate) const DEFAULT_CA_NAME: &str = "Bootroot CA";
pub(crate) const DEFAULT_CA_PROVISIONER: &str = "admin";
pub(crate) const DEFAULT_CA_DNS: &str = "localhost,bootroot-ca,stepca.internal";
pub(crate) const DEFAULT_CA_ADDRESS: &str = ":9000";
pub(crate) const SECRET_BYTES: usize = 32;
pub(crate) const DEFAULT_RESPONDER_TOKEN_TTL_SECS: u64 = 60;
// Keep "bootroot-http01" in sync with RESPONDER_SERVICE_NAME.
pub(crate) const DEFAULT_RESPONDER_ADMIN_URL: &str = "http://bootroot-http01:8080";
pub(crate) const RESPONDER_TEMPLATE_DIR: &str = "templates";
pub(crate) const RESPONDER_TEMPLATE_NAME: &str = "responder.toml.ctmpl";
pub(crate) const RESPONDER_CONFIG_DIR: &str = "responder";
pub(crate) const RESPONDER_CONFIG_NAME: &str = "responder.toml";
pub(crate) const RESPONDER_COMPOSE_OVERRIDE_NAME: &str = "docker-compose.responder.override.yml";
pub(crate) const STEPCA_PASSWORD_TEMPLATE_NAME: &str = "password.txt.ctmpl";
pub(crate) const STEPCA_CA_JSON_TEMPLATE_NAME: &str = "ca.json.ctmpl";
pub(crate) const OPENBAO_AGENT_DIR: &str = "openbao";
pub(crate) const OPENBAO_AGENT_STEPCA_DIR: &str = "stepca";
pub(crate) const OPENBAO_AGENT_RESPONDER_DIR: &str = "responder";
pub(crate) const OPENBAO_AGENT_CONFIG_NAME: &str = "agent.hcl";
pub(crate) const OPENBAO_AGENT_ROLE_ID_NAME: &str = "role_id";
pub(crate) const OPENBAO_AGENT_SECRET_ID_NAME: &str = "secret_id";
pub(crate) const OPENBAO_AGENT_COMPOSE_OVERRIDE_NAME: &str =
    "docker-compose.openbao-agent.override.yml";
pub(crate) const OPENBAO_AGENT_STEPCA_SERVICE: &str = "openbao-agent-stepca";
pub(crate) const OPENBAO_AGENT_RESPONDER_SERVICE: &str = "openbao-agent-responder";
pub(crate) const DEFAULT_EAB_ENDPOINT_PATH: &str = "eab";
pub(crate) const DEFAULT_DB_USER: &str = "stepca";
pub(crate) const DEFAULT_DB_NAME: &str = "stepca";
pub(crate) const CA_CERTS_DIR: &str = "certs";
pub(crate) const CA_ROOT_CERT_FILENAME: &str = "root_ca.crt";
pub(crate) const CA_INTERMEDIATE_CERT_FILENAME: &str = "intermediate_ca.crt";

pub(crate) const OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME: &str = "docker-compose.openbao-exposed.yml";
pub(crate) const HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME: &str = "docker-compose.http01-exposed.yml";
#[cfg(test)]
pub(crate) const OPENBAO_TLS_CERT_PATH: &str = "openbao/tls/server.crt";
#[cfg(test)]
pub(crate) const OPENBAO_TLS_KEY_PATH: &str = "openbao/tls/server.key";
pub(crate) const RESPONDER_TLS_CERT_CONTAINER_PATH: &str = "/app/responder/tls/cert.pem";
pub(crate) const RESPONDER_TLS_KEY_CONTAINER_PATH: &str = "/app/responder/tls/key.pem";
pub(crate) const OPENBAO_HCL_PATH: &str = "openbao/openbao.hcl";

pub(crate) mod openbao_constants {
    pub(crate) const INIT_SECRET_SHARES: u8 = 3;
    pub(crate) const INIT_SECRET_THRESHOLD: u8 = 2;
    pub(crate) const TOKEN_TTL: &str = "1h";

    /// Default role-level `secret_id` TTL applied to every `AppRole` created
    /// during `bootroot init`. This is the security-conservative default:
    /// a shorter lifetime limits exposure when a `SecretID` leaks.
    ///
    /// Operators who rotate on a longer cadence should pass
    /// `--secret-id-ttl` with a value that is at least 2× their rotation
    /// interval so that a missed or delayed rotation run does not leave
    /// services unable to re-authenticate.
    pub(crate) const SECRET_ID_TTL: &str = "24h";

    pub(crate) const MAX_SECRET_ID_TTL: &str = "168h";

    /// Warning threshold for `secret_id` TTL. Values above this threshold
    /// trigger a CLI warning but are still accepted (up to
    /// [`MAX_SECRET_ID_TTL`]).
    ///
    /// `24h` is the security-conservative default; use `48h` or longer
    /// when operational slack (surviving missed rotation runs, maintenance
    /// windows, restart recovery) is more important than minimising the
    /// exposure window.
    pub(crate) const RECOMMENDED_SECRET_ID_TTL: &str = "48h";

    pub(crate) const POLICY_BOOTROOT_AGENT: &str = "bootroot-agent";
    pub(crate) const POLICY_BOOTROOT_RESPONDER: &str = "bootroot-responder";
    pub(crate) const POLICY_BOOTROOT_STEPCA: &str = "bootroot-stepca";
    pub(crate) const POLICY_BOOTROOT_RUNTIME_SERVICE_ADD: &str = "bootroot-runtime-service-add";
    pub(crate) const POLICY_BOOTROOT_RUNTIME_ROTATE: &str = "bootroot-runtime-rotate";

    pub(crate) const APPROLE_BOOTROOT_AGENT: &str = "bootroot-agent-role";
    pub(crate) const APPROLE_BOOTROOT_RESPONDER: &str = "bootroot-responder-role";
    pub(crate) const APPROLE_BOOTROOT_STEPCA: &str = "bootroot-stepca-role";
    pub(crate) const APPROLE_BOOTROOT_RUNTIME_SERVICE_ADD: &str =
        "bootroot-runtime-service-add-role";
    pub(crate) const APPROLE_BOOTROOT_RUNTIME_ROTATE: &str = "bootroot-runtime-rotate-role";

    pub(crate) const PATH_STEPCA_PASSWORD: &str = "bootroot/stepca/password";
    pub(crate) const PATH_STEPCA_DB: &str = "bootroot/stepca/db";
    pub(crate) const PATH_RESPONDER_HMAC: &str = "bootroot/responder/hmac";
    pub(crate) const PATH_AGENT_EAB: &str = "bootroot/agent/eab";
    pub(crate) const PATH_CA_TRUST: &str = "bootroot/ca";
}
