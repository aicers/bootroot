mod constants;
mod paths;
mod steps;
mod types;

pub(crate) use constants::openbao_constants::{
    APPROLE_BOOTROOT_AGENT, APPROLE_BOOTROOT_INFRA_ROTATE, APPROLE_BOOTROOT_RESPONDER,
    APPROLE_BOOTROOT_STEPCA, INIT_SECRET_SHARES, INIT_SECRET_THRESHOLD, PATH_AGENT_EAB,
    PATH_CA_TRUST, PATH_RESPONDER_HMAC, PATH_STEPCA_DB, PATH_STEPCA_DB_ADMIN, PATH_STEPCA_PASSWORD,
    POLICY_BOOTROOT_INFRA_ROTATE, SECRET_ID_TTL, TOKEN_TTL,
};
pub(crate) use constants::{
    CA_CERTS_DIR, CA_INTERMEDIATE_CERT_FILENAME, CA_ROOT_CERT_FILENAME, DEFAULT_CERT_DURATION,
    DEFAULT_COMPOSE_FILE, DEFAULT_KV_MOUNT, DEFAULT_OPENBAO_URL, DEFAULT_SECRETS_DIR,
    DEFAULT_STEPCA_PROVISIONER, HTTP01_ADMIN_INFRA_CERT_KEY, HTTP01_ADMIN_TLS_CERT_REL_PATH,
    HTTP01_ADMIN_TLS_DEFAULT_NOT_AFTER, HTTP01_ADMIN_TLS_DEFAULT_RENEW_BEFORE,
    HTTP01_ADMIN_TLS_KEY_REL_PATH, HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME, OPENBAO_AGENT_DIR,
    OPENBAO_AGENT_RESPONDER_DIR, OPENBAO_AGENT_ROLE_ID_NAME, OPENBAO_AGENT_SECRET_ID_NAME,
    OPENBAO_AGENT_STEPCA_DIR, OPENBAO_CONTAINER_NAME, OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME,
    OPENBAO_HCL_PATH, OPENBAO_INFRA_CERT_KEY, OPENBAO_TLS_CERT_PATH,
    OPENBAO_TLS_CONTAINER_CERT_PATH, OPENBAO_TLS_CONTAINER_KEY_PATH, OPENBAO_TLS_DEFAULT_NOT_AFTER,
    OPENBAO_TLS_DEFAULT_RENEW_BEFORE, OPENBAO_TLS_KEY_PATH, RESPONDER_COMPOSE_OVERRIDE_NAME,
    RESPONDER_CONFIG_DIR, RESPONDER_CONFIG_NAME, RESPONDER_TEMPLATE_DIR, SECRET_BYTES,
    STEPCA_CA_JSON_TEMPLATE_NAME, STEPCA_EXPOSED_COMPOSE_OVERRIDE_NAME,
};
pub(crate) use paths::{
    compose_has_openbao, compose_has_responder, compose_has_stepca, resolve_openbao_agent_addr,
    to_container_path,
};
pub(crate) use steps::http01_admin_tls::{
    reissue_http01_admin_tls_cert, strip_responder_tls_config,
};
pub(crate) use steps::openbao_tls::{reissue_openbao_tls_cert, write_openbao_hcl_plaintext};
pub(crate) use steps::stepca_setup::set_acme_cert_duration;
pub(crate) use steps::{
    compute_ca_bundle_pem, compute_ca_fingerprints, infra_rotate_policy, prompt_yes_no,
    read_ca_cert_fingerprint, run_init, validate_secret_id_ttl,
};
pub(crate) use types::{
    AppRoleLabel, DbCheckStatus, InitPlan, InitSummary, ResponderCheck, StepCaInitResult,
};
