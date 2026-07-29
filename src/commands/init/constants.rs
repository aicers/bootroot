pub(crate) const DEFAULT_OPENBAO_URL: &str = "http://localhost:8200";
pub(crate) const DEFAULT_KV_MOUNT: &str = "secret";
pub(crate) const DEFAULT_SECRETS_DIR: &str = "secrets";
pub(crate) const DEFAULT_COMPOSE_FILE: &str = "docker-compose.yml";
pub(crate) const DEFAULT_STEPCA_PROVISIONER: &str = "acme";

/// Default `defaultTLSCertDuration` embedded in the ACME provisioner
/// of `ca.json` / `ca.json.ctmpl`. Matches step-ca's own default.
pub(crate) const DEFAULT_CERT_DURATION: &str = "24h";

pub(crate) const DEFAULT_CA_NAME: &str = "Bootroot CA";
/// JWK admin provisioner name passed to `step ca init --provisioner`.
///
/// `step ca init --acme` creates a JWK admin provisioner with this
/// name and an additional ACME provisioner with the hardcoded name
/// `acme` (or `acme-1` if the JWK admin already uses `acme`). Keeping
/// the JWK admin distinct from `DEFAULT_STEPCA_PROVISIONER` ensures
/// the ACME provisioner created by step-ca matches the name the
/// patcher looks up.
pub(crate) const DEFAULT_CA_PROVISIONER: &str = "admin";
/// DNS names step-ca's certificate carries besides its own container
/// name.
///
/// `localhost` and `stepca.internal` are fixed; the third entry is the
/// step-ca container name, which follows the install identity and is
/// spliced in between them by [`default_ca_dns_names`].
const DEFAULT_CA_DNS_FIXED: [&str; 2] = ["localhost", "stepca.internal"];
pub(crate) const DEFAULT_CA_ADDRESS: &str = ":9000";
pub(crate) const SECRET_BYTES: usize = 32;
pub(crate) const DEFAULT_RESPONDER_TOKEN_TTL_SECS: u64 = 60;
/// Port the responder publishes its admin API on inside the network.
const RESPONDER_ADMIN_PORT: u16 = 8080;
/// Port the `OpenBao` container listens on inside the network.
///
/// Fixed, unlike the host-side publish, which `--openbao-host-port` moves
/// so two installs can share a host: the compose port mappings, the
/// `openbao.hcl` listener and the non-loopback bind override all pin the
/// container side to this port. Anything addressing `OpenBao` by
/// container name is on the compose network and must use it rather than
/// whatever host port the URL it was handed carries.
pub(in crate::commands::init) const OPENBAO_CONTAINER_PORT: u16 = 8200;
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
pub(crate) const DEFAULT_DB_USER: &str = "stepca";
pub(crate) const DEFAULT_DB_NAME: &str = "stepca";
pub(crate) const CA_CERTS_DIR: &str = "certs";
pub(crate) const CA_ROOT_CERT_FILENAME: &str = "root_ca.crt";
pub(crate) const CA_INTERMEDIATE_CERT_FILENAME: &str = "intermediate_ca.crt";
pub(crate) const CA_BUNDLE_FILENAME: &str = "ca-bundle.pem";

pub(crate) const OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME: &str = "docker-compose.openbao-exposed.yml";
pub(crate) const HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME: &str = "docker-compose.http01-exposed.yml";
pub(crate) const STEPCA_EXPOSED_COMPOSE_OVERRIDE_NAME: &str = "docker-compose.stepca-exposed.yml";

pub(crate) const OPENBAO_TLS_CERT_PATH: &str = "openbao/tls/server.crt";
pub(crate) const OPENBAO_TLS_KEY_PATH: &str = "openbao/tls/server.key";
pub(crate) const RESPONDER_TLS_CERT_CONTAINER_PATH: &str = "/app/bootroot-http01/tls/server.crt";
pub(crate) const RESPONDER_TLS_KEY_CONTAINER_PATH: &str = "/app/bootroot-http01/tls/server.key";
pub(crate) const OPENBAO_TLS_CONTAINER_CERT_PATH: &str = "/openbao/config/tls/server.crt";
pub(crate) const OPENBAO_TLS_CONTAINER_KEY_PATH: &str = "/openbao/config/tls/server.key";
pub(crate) const OPENBAO_HCL_PATH: &str = "openbao/openbao.hcl";
pub(crate) const OPENBAO_INFRA_CERT_KEY: &str = "openbao";
pub(crate) const OPENBAO_TLS_DEFAULT_NOT_AFTER: &str = "8760h";
pub(crate) const OPENBAO_TLS_DEFAULT_RENEW_BEFORE: &str = "720h";

pub(crate) const HTTP01_ADMIN_INFRA_CERT_KEY: &str = "bootroot-http01";
pub(crate) const HTTP01_ADMIN_TLS_CERT_REL_PATH: &str = "bootroot-http01/tls/server.crt";
pub(crate) const HTTP01_ADMIN_TLS_KEY_REL_PATH: &str = "bootroot-http01/tls/server.key";
pub(crate) const HTTP01_ADMIN_TLS_DEFAULT_NOT_AFTER: &str = "8760h";
pub(crate) const HTTP01_ADMIN_TLS_DEFAULT_RENEW_BEFORE: &str = "720h";

/// Returns step-ca's `dnsNames` list for an install whose step-ca
/// container is `ca_container`.
///
/// `localhost` and `stepca.internal` are not container names and stay
/// fixed; only the middle entry follows the install identity.
pub(crate) fn default_ca_dns_names(ca_container: &str) -> Vec<String> {
    let [localhost, internal] = DEFAULT_CA_DNS_FIXED;
    vec![
        localhost.to_string(),
        ca_container.to_string(),
        internal.to_string(),
    ]
}

/// Returns the in-network admin API URL of `responder_container`.
pub(crate) fn default_responder_admin_url(responder_container: &str) -> String {
    format!("http://{responder_container}:{RESPONDER_ADMIN_PORT}")
}

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
    /// Dedicated policy for rotating the infra `AppRole` `secret_id`s
    /// (stepca/responder). Deliberately NOT folded into
    /// `bootroot-runtime-rotate`: the infra roles read CA core secrets
    /// (CA password, DB DSN), so a credential that can mint their
    /// `secret_id`s can escalate to those secrets. Keeping the grant on
    /// a separate role confines that blast radius.
    pub(crate) const POLICY_BOOTROOT_INFRA_ROTATE: &str = "bootroot-infra-rotate";

    /// Deterministic logins that consume one of a self-minted rotate
    /// credential's uses within a single re-mint cycle. Self-mint is
    /// per-invocation, so a credential's cycle spans exactly one
    /// invocation for both rotate roles: the next invocation's base
    /// login, plus the post-mint verification login of the freshly
    /// minted replacement credential.
    pub(crate) const ROTATE_SELF_MINT_LOGINS_PER_CYCLE: u32 = 2;

    /// `secret_id_num_uses` cap applied to self-minted rotate
    /// credentials: 3× the enumerated logins per cycle, leaving headroom
    /// for transient-error login retries and the crash-recovery login
    /// (a tighter cap risks self-lockout). Bounded uses turn a stolen
    /// snapshot of the credential into a wasting asset without blocking
    /// the legitimate cycle.
    pub(crate) const ROTATE_SELF_MINT_NUM_USES: u32 = 3 * ROTATE_SELF_MINT_LOGINS_PER_CYCLE;

    pub(crate) const APPROLE_BOOTROOT_AGENT: &str = "bootroot-agent-role";
    pub(crate) const APPROLE_BOOTROOT_RESPONDER: &str = "bootroot-responder-role";
    pub(crate) const APPROLE_BOOTROOT_STEPCA: &str = "bootroot-stepca-role";
    pub(crate) const APPROLE_BOOTROOT_RUNTIME_SERVICE_ADD: &str =
        "bootroot-runtime-service-add-role";
    pub(crate) const APPROLE_BOOTROOT_RUNTIME_ROTATE: &str = "bootroot-runtime-rotate-role";
    pub(crate) const APPROLE_BOOTROOT_INFRA_ROTATE: &str = "bootroot-infra-rotate-role";

    pub(crate) const PATH_STEPCA_PASSWORD: &str = "bootroot/stepca/password";
    pub(crate) const PATH_STEPCA_DB: &str = "bootroot/stepca/db";
    /// Stores the admin DSN bootroot used to provision the runtime
    /// role/database. Carries strictly higher privilege than
    /// `PATH_STEPCA_DB` and must NOT be readable by the same `OpenBao`
    /// policy as the runtime DSN — only operator/root tokens
    /// (and any future rotate-only `AppRole`) may read this path.
    pub(crate) const PATH_STEPCA_DB_ADMIN: &str = "bootroot/stepca/db_admin";
    pub(crate) const PATH_RESPONDER_HMAC: &str = "bootroot/responder/hmac";
    pub(crate) const PATH_AGENT_EAB: &str = "bootroot/agent/eab";
    pub(crate) const PATH_CA_TRUST: &str = "bootroot/ca";
}

#[cfg(test)]
mod tests {
    use super::{default_ca_dns_names, default_responder_admin_url};
    use crate::commands::compose_project::{
        DEFAULT_INSTANCE_NAME, DNS_LABEL_LIMIT, LONGEST_CONTAINER_NAME_SUFFIX,
        MAX_INSTANCE_NAME_LEN,
    };
    use crate::commands::container_name::BootrootContainer;

    /// The interpolation prefix every `container_name:` in the shipped
    /// compose files now carries.
    const CONTAINER_NAME_INTERPOLATION: &str = "${BOOTROOT_INSTANCE:-bootroot}";

    /// Reads the `container_name:` suffixes the compose files declare.
    ///
    /// Each value is `${BOOTROOT_INSTANCE:-bootroot}<suffix>`, so the
    /// suffix is what has to agree with [`BootrootContainer`].
    ///
    /// Precedent: `shipped_compose_files_pass_the_localhost_binding_guardrail`
    /// in `commands/guardrails.rs` reaches the checked-in compose files
    /// the same way.
    fn declared_container_name_suffixes() -> Vec<String> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut suffixes = Vec::new();
        for file in ["docker-compose.yml", "docker-compose.deploy.yml"] {
            let contents =
                std::fs::read_to_string(root.join(file)).expect("compose file must be readable");
            for line in contents.lines() {
                if let Some(value) = line.trim().strip_prefix("container_name:") {
                    let value = value.trim();
                    let suffix = value
                        .strip_prefix(CONTAINER_NAME_INTERPOLATION)
                        .unwrap_or_else(|| {
                            panic!(
                                "`container_name: {value}` in {file} must interpolate the \
                                 instance name as `{CONTAINER_NAME_INTERPOLATION}<suffix>`"
                            )
                        });
                    suffixes.push(suffix.to_string());
                }
            }
        }
        suffixes
    }

    /// The compose files and [`BootrootContainer`] are two declarations
    /// of the same names; a container added to one and not the other
    /// would escape the identity derivation (and the length limit below).
    #[test]
    fn compose_container_names_come_from_the_shared_derivation() {
        let declared = declared_container_name_suffixes();
        assert!(
            declared.len() >= 14,
            "expected seven services in each of the two compose files, got {declared:?}"
        );
        let known: Vec<&str> = BootrootContainer::ALL
            .iter()
            .map(|container| container.suffix())
            .collect();
        for suffix in &declared {
            assert!(
                known.contains(&suffix.as_str()),
                "compose declares container suffix `{suffix}`, which \
                 `BootrootContainer` does not know about"
            );
        }
        // The two sidecars are pinned by the generated OpenBao agent
        // override rather than by a checked-in compose file, so they are
        // legitimately absent from `declared`.
        for container in [
            BootrootContainer::OpenBaoAgentStepCa,
            BootrootContainer::OpenBaoAgentResponder,
        ] {
            assert!(
                !declared.contains(&container.suffix().to_string()),
                "{container:?} is pinned by the generated agent override, \
                 not by a checked-in compose file"
            );
        }
    }

    /// The 39-character instance-name limit is derived from the container
    /// names this tree declares: each becomes `<instance><suffix>`, which
    /// serves as a DNS name on the compose network and as a certificate
    /// SAN, so it must fit a 63-octet DNS label.  Adding a longer
    /// container name later must fail here rather than silently making
    /// the limit wrong.
    #[test]
    fn instance_name_limit_leaves_room_for_every_container_name_suffix() {
        let longest = BootrootContainer::ALL
            .iter()
            .map(|container| container.suffix().len())
            .max()
            .expect("the container set is never empty");
        assert_eq!(
            longest,
            LONGEST_CONTAINER_NAME_SUFFIX.len(),
            "the longest declared suffix no longer matches \
             `LONGEST_CONTAINER_NAME_SUFFIX`; update it and the derived limit"
        );
        assert!(
            MAX_INSTANCE_NAME_LEN + longest <= DNS_LABEL_LIMIT,
            "{MAX_INSTANCE_NAME_LEN} + the longest suffix ({longest}) exceeds \
             the {DNS_LABEL_LIMIT}-octet DNS label limit"
        );
    }

    /// Only the container-name element of step-ca's DNS list follows the
    /// identity; `localhost` and `stepca.internal` are not container
    /// names and must survive untouched.
    #[test]
    fn ca_dns_names_scope_only_the_container_name() {
        let default = BootrootContainer::StepCa.name(DEFAULT_INSTANCE_NAME);
        assert_eq!(
            default_ca_dns_names(&default),
            vec!["localhost", "bootroot-ca", "stepca.internal"]
        );
        assert_eq!(
            default_ca_dns_names(&BootrootContainer::StepCa.name("insight")),
            vec!["localhost", "insight-ca", "stepca.internal"]
        );
    }

    #[test]
    fn responder_admin_url_follows_the_container_name() {
        assert_eq!(
            default_responder_admin_url(&BootrootContainer::Http01.name(DEFAULT_INSTANCE_NAME)),
            "http://bootroot-http01:8080"
        );
        assert_eq!(
            default_responder_admin_url(&BootrootContainer::Http01.name("insight")),
            "http://insight-http01:8080"
        );
    }
}
