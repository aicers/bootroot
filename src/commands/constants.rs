pub(crate) const RESPONDER_SERVICE_NAME: &str = "bootroot-http01";
pub(crate) const DEFAULT_SECRET_ID_WRAP_TTL: &str = "30m";
pub(crate) use bootroot::trust_bootstrap::{
    EAB_HMAC_KEY as SERVICE_EAB_HMAC_KEY, EAB_KID_KEY as SERVICE_EAB_KID_KEY,
    HMAC_KEY as SERVICE_RESPONDER_HMAC_KEY, SECRET_ID_KEY as SERVICE_SECRET_ID_KEY,
    SERVICE_KV_BASE, TRUSTED_CA_KEY as CA_TRUST_KEY,
};
