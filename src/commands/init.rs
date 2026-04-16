mod constants;
mod paths;
mod steps;
mod types;

pub(crate) use constants::openbao_constants::{
    INIT_SECRET_SHARES, INIT_SECRET_THRESHOLD, PATH_AGENT_EAB, PATH_CA_TRUST, PATH_RESPONDER_HMAC,
    PATH_STEPCA_DB, PATH_STEPCA_PASSWORD, SECRET_ID_TTL, TOKEN_TTL,
};
pub(crate) use constants::{
    CA_CERTS_DIR, CA_INTERMEDIATE_CERT_FILENAME, CA_ROOT_CERT_FILENAME, DEFAULT_COMPOSE_FILE,
    DEFAULT_KV_MOUNT, DEFAULT_OPENBAO_URL, DEFAULT_SECRETS_DIR, DEFAULT_STEPCA_PROVISIONER,
    DEFAULT_STEPCA_URL, OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME, OPENBAO_HCL_PATH, SECRET_BYTES,
};
#[cfg(test)]
pub(crate) use constants::{OPENBAO_TLS_CERT_PATH, OPENBAO_TLS_KEY_PATH};
pub(crate) use paths::{compose_has_responder, to_container_path};
pub(crate) use steps::{
    compute_ca_bundle_pem, compute_ca_fingerprints, prompt_yes_no, read_ca_cert_fingerprint,
    run_init, validate_secret_id_ttl,
};
pub(crate) use types::{DbCheckStatus, InitPlan, InitSummary, ResponderCheck, StepCaInitResult};
