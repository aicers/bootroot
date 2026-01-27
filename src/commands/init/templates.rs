use anyhow::{Context, Result};

use super::constants::{PATH_RESPONDER_HMAC, PATH_STEPCA_DB, PATH_STEPCA_PASSWORD};
use crate::i18n::Messages;

pub(crate) fn build_responder_template(kv_mount: &str) -> String {
    format!(
        r#"# HTTP-01 responder config (OpenBao Agent template)

listen_addr = "0.0.0.0:80"
admin_addr = "0.0.0.0:8080"
hmac_secret = "{{{{ with secret "{kv_mount}/data/{PATH_RESPONDER_HMAC}" }}}}{{{{ .Data.data.value }}}}{{{{ end }}}}"
token_ttl_secs = 300
cleanup_interval_secs = 30
max_skew_secs = 60
"#
    )
}

pub(crate) fn build_password_template(kv_mount: &str) -> String {
    format!(
        r#"{{{{ with secret "{kv_mount}/data/{PATH_STEPCA_PASSWORD}" }}}}{{{{ .Data.data.value }}}}{{{{ end }}}}"#
    )
}

pub(crate) fn build_ca_json_template(
    contents: &str,
    kv_mount: &str,
    messages: &Messages,
) -> Result<String> {
    let mut value: serde_json::Value =
        serde_json::from_str(contents).context(messages.error_parse_ca_json_failed())?;
    let db = value
        .get_mut("db")
        .ok_or_else(|| anyhow::anyhow!(messages.error_ca_json_db_missing()))?;
    let data_source = db
        .get_mut("dataSource")
        .ok_or_else(|| anyhow::anyhow!(messages.error_ca_json_db_missing()))?;
    *data_source = serde_json::Value::String(format!(
        "{{{{ with secret \"{kv_mount}/data/{PATH_STEPCA_DB}\" }}}}{{{{ .Data.data.value }}}}{{{{ end }}}}"
    ));
    serde_json::to_string_pretty(&value).context(messages.error_serialize_ca_json_failed())
}

pub(crate) fn build_responder_config(hmac: &str) -> String {
    format!(
        r#"# HTTP-01 responder config (rendered)

listen_addr = "0.0.0.0:80"
admin_addr = "0.0.0.0:8080"
hmac_secret = "{hmac}"
token_ttl_secs = 300
cleanup_interval_secs = 30
max_skew_secs = 60
"#
    )
}
