//! The bootler-rendered registrar config: its on-disk shape, its two
//! integrity gates, and the typed values it yields.
//!
//! The file is rendered by the provisioning tool (`aicers/bootler`) onto
//! both the bootroot/registrar host and the `REView` host at install, at
//! the same absolute path on each. **bootroot only reads it; nothing in
//! this repository writes it in production.** The shape is a
//! cross-repository contract owned by `aicers/bootler` #200; where that
//! issue and this module disagree, that issue wins and this module is
//! corrected. A unilateral change here breaks every enrollment in the
//! deployment, and breaks it at deploy time rather than in either
//! repository's tests.
//!
//! See `docs/reference/registrar-provisioning-config.md` for the
//! documented schema and `docs/reference/provisioning.toml.example` for
//! the example this module's tests load through the production loader.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::Deserialize;

use crate::input_validation::{validate_dns_label, validate_domain_name};
use crate::registrar::error::RegistrarError;
use crate::tls::sha256_hex;

/// Absolute path the provisioning tool renders the registrar config to.
///
/// It is the writer's product-namespaced path, deliberately not under
/// `/etc/bootroot/`: the same file is rendered onto the `REView` host,
/// which has no bootroot and no `/etc/bootroot`. One product-namespaced
/// path is what lets both readers use one constant.
///
/// [`RegistrarConfig::load`] takes the path as a parameter so no test
/// ever reads this one.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/clumit-security/provisioning.toml";

/// File name component of [`DEFAULT_CONFIG_PATH`], for a caller — a
/// test fixture, an installer check — that needs to place or find the
/// file in a directory of its own choosing.
pub const CONFIG_FILE_NAME: &str = "provisioning.toml";

/// The `schema_version` this build implements. A file declaring any
/// other version is refused with
/// [`RegistrarError::UnsupportedSchemaVersion`] rather than
/// best-effort parsed.
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Exact prefix of the fingerprint line, which is the file's first line.
const FINGERPRINT_PREFIX: &str = "fingerprint = \"";
/// Length of a SHA-256 digest rendered as lowercase hex.
const FINGERPRINT_HEX_LEN: usize = 64;

/// How many times a component may be installed, which is what selects
/// the `registration_id` derivation arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Multiplicity {
    /// Installed once across the deployment; the id is `<component>`.
    OnePerDeployment,
    /// Installed once on each host; the id is `<host>-<component>`.
    OnePerHost,
    /// Installed several times on one host; the id is
    /// `<host>-<component>-<instance>`.
    ManyPerHost,
}

impl Multiplicity {
    /// Returns the exact kebab-case string the rendered file spells this
    /// class with.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OnePerDeployment => "one-per-deployment",
            Self::OnePerHost => "one-per-host",
            Self::ManyPerHost => "many-per-host",
        }
    }

    /// Returns whether a registration of a component in this class
    /// carries an `instance`.
    #[must_use]
    pub fn takes_instance(self) -> bool {
        matches!(self, Self::ManyPerHost)
    }
}

impl fmt::Display for Multiplicity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Multiplicity {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "one-per-deployment" => Ok(Self::OnePerDeployment),
            "one-per-host" => Ok(Self::OnePerHost),
            "many-per-host" => Ok(Self::ManyPerHost),
            _ => Err(()),
        }
    }
}

/// The post-renew hook style a component's registration carries.
///
/// These are the four styles of `ReloadStyle` (`src/cli/args.rs`), which
/// is what this repository already applies to a *service* certificate.
/// The infrastructure-certificate `ReloadStrategy` (`src/state.rs`) is a
/// different type with a different vocabulary and is deliberately not
/// this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadKind {
    /// Send `SIGHUP` to a process by name.
    Sighup,
    /// Reload a systemd unit.
    Systemd,
    /// Restart a Docker container.
    DockerRestart,
    /// No post-renew hook. Carries no `target`.
    None,
}

impl ReloadKind {
    /// Returns the exact kebab-case string the rendered file spells this
    /// style with.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sighup => "sighup",
            Self::Systemd => "systemd",
            Self::DockerRestart => "docker-restart",
            Self::None => "none",
        }
    }

    /// Returns whether this style names a target. `none` does not; the
    /// other three require one.
    #[must_use]
    pub fn takes_target(self) -> bool {
        !matches!(self, Self::None)
    }
}

impl fmt::Display for ReloadKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ReloadKind {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "sighup" => Ok(Self::Sighup),
            "systemd" => Ok(Self::Systemd),
            "docker-restart" => Ok(Self::DockerRestart),
            "none" => Ok(Self::None),
            _ => Err(()),
        }
    }
}

/// A `reload` inline table: `{ kind, target }`.
///
/// `target` is compared **literally**. There is no template language,
/// no placeholder and no per-instance parameterisation: a token that
/// looks like `{instance}` is a literal string, and a request whose
/// `reload` carries an expanded form of it is outside the safe-set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadSpec {
    /// The hook style.
    pub kind: ReloadKind,
    /// The process, unit or container the hook acts on. `None` exactly
    /// when `kind` is [`ReloadKind::None`].
    pub target: Option<String>,
}

impl ReloadSpec {
    /// Creates a reload spec naming a target.
    #[must_use]
    pub fn new(kind: ReloadKind, target: &str) -> Self {
        Self {
            kind,
            target: Some(target.to_string()),
        }
    }

    /// Creates the target-free `none` reload spec.
    #[must_use]
    pub fn none() -> Self {
        Self {
            kind: ReloadKind::None,
            target: None,
        }
    }
}

/// The registration spec a component's registrations must present: the
/// two fields that vary per component.
///
/// A component has **exactly one** allowed spec. This is not a per-field
/// allow-list and not a list of allowed pairs — independent per-field
/// sets would admit cross-products no component ever declares, and a
/// list of pairs is ruled out by the spec being host-agnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationSpec {
    /// Numeric gid the issued cert/key files are owned by, or `None`
    /// when the component's registrations carry no cert-group policy.
    pub cert_group: Option<u32>,
    /// The post-renew hook.
    pub reload: ReloadSpec,
}

/// One `[components.<package-id>]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentEntry {
    multiplicity: Multiplicity,
    spec: RegistrationSpec,
}

impl ComponentEntry {
    /// Returns the component's multiplicity class.
    #[must_use]
    pub fn multiplicity(&self) -> Multiplicity {
        self.multiplicity
    }

    /// Returns the component's single rendered spec, which is its
    /// entire safe-set.
    #[must_use]
    pub fn spec(&self) -> &RegistrationSpec {
        &self.spec
    }
}

/// A validated registrar config.
///
/// Constructible only through [`RegistrarConfig::load`], so the declared
/// fingerprint this exposes is reachable only from a load whose digest
/// was checked — no caller can report a digest it did not verify.
#[derive(Debug, Clone)]
pub struct RegistrarConfig {
    path: PathBuf,
    fingerprint: String,
    schema_version: u32,
    domain: String,
    components: BTreeMap<String, ComponentEntry>,
}

/// The envelope and component table, as the body parses before its
/// enum-valued fields are resolved.
///
/// `multiplicity` and `reload.kind` are read here as strings and
/// converted immediately below; neither is *stored* as a string. The
/// conversion happens outside serde because the refusal has to carry the
/// offending value in a typed field, and a serde error can only carry it
/// inside a message.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    schema_version: u32,
    domain: String,
    #[serde(default)]
    components: BTreeMap<String, RawComponent>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawComponent {
    multiplicity: String,
    #[serde(default)]
    cert_group: Option<u32>,
    reload: RawReload,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReload {
    kind: String,
    #[serde(default)]
    target: Option<String>,
}

/// Just enough of the envelope to gate on the version before the rest of
/// the body is parsed against this build's shape.
#[derive(Debug, Deserialize)]
struct SchemaProbe {
    schema_version: u32,
}

impl RegistrarConfig {
    /// Reads, validates and parses the rendered registrar config at
    /// `path`.
    ///
    /// Call this at verb-invocation time rather than caching the result
    /// indefinitely: a re-render must take effect. A missing or
    /// unreadable file is a hard failure, never a default — minting
    /// under a guessed domain would issue a certificate no peer will
    /// ever verify.
    ///
    /// The two integrity gates run in this order:
    ///
    /// 1. The first line must be exactly
    ///    `fingerprint = "<64 lowercase hex>"` followed by one newline,
    ///    and the SHA-256 of the remaining bytes **verbatim as written**
    ///    must equal it. A truncated file can still parse as valid TOML
    ///    with entries missing, and those components would then be
    ///    refused individually — a silent per-component enrollment
    ///    outage indistinguishable from a component that was never
    ///    provisioned. The digest is what turns that into one loud
    ///    failure.
    /// 2. `schema_version` must be [`SUPPORTED_SCHEMA_VERSION`].
    ///
    /// # Errors
    ///
    /// Returns [`RegistrarError::ConfigUnreadable`] when the file is
    /// missing or cannot be read, [`RegistrarError::FingerprintLineMalformed`]
    /// when the first line is not the exact fingerprint form,
    /// [`RegistrarError::FingerprintMismatch`] when the body's digest
    /// disagrees with it, [`RegistrarError::UnsupportedSchemaVersion`]
    /// when the version is not this build's,
    /// [`RegistrarError::ConfigMalformed`] when the body is not UTF-8 or
    /// not the documented TOML shape, and the
    /// `UnknownMultiplicity` / `UnknownReloadKind` /
    /// `InvalidReloadTarget` / `InvalidDomain` / `InvalidComponentKey`
    /// variants when a parsed value is not one this build accepts.
    pub fn load(path: &Path) -> Result<Self, RegistrarError> {
        let bytes = std::fs::read(path).map_err(|source| RegistrarError::ConfigUnreadable {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_bytes(path, &bytes)
    }

    /// Returns the fingerprint the file declared, which this load
    /// verified against the body.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Returns the `schema_version` the file declared.
    #[must_use]
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the deployment-wide domain, the SAN's fourth segment.
    ///
    /// This is read only from the rendered file, never from the wire: a
    /// caller that could supply it could mint certificates under a name
    /// suffix of its choosing.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the path this config was loaded from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the component keys the file declares, in sorted order.
    pub fn component_names(&self) -> impl Iterator<Item = &str> {
        self.components.keys().map(String::as_str)
    }

    /// Returns the entry the wire `service_name` selects.
    ///
    /// A component absent from the file is refused, never defaulted:
    /// fail-open would let a module whose `instance` was wrongly omitted
    /// mint a valid-but-phantom two-part identity that a later correct
    /// request then duplicates.
    ///
    /// # Errors
    ///
    /// Returns [`RegistrarError::ComponentNotConfigured`] when the file
    /// has no entry for `service_name`.
    pub fn component(&self, service_name: &str) -> Result<&ComponentEntry, RegistrarError> {
        self.components
            .get(service_name)
            .ok_or_else(|| RegistrarError::ComponentNotConfigured {
                component: service_name.to_string(),
            })
    }

    /// Resolves the multiplicity class of the component the wire
    /// `service_name` selects.
    ///
    /// This is the class-resolution step, callable without deriving
    /// anything, so a refusal on this arm has no `registration_id` to
    /// report and none is computed as a side effect.
    ///
    /// # Errors
    ///
    /// Returns [`RegistrarError::ComponentNotConfigured`] when the file
    /// has no entry for `service_name`.
    pub fn multiplicity(&self, service_name: &str) -> Result<Multiplicity, RegistrarError> {
        Ok(self.component(service_name)?.multiplicity())
    }

    fn from_bytes(path: &Path, bytes: &[u8]) -> Result<Self, RegistrarError> {
        let declared = read_fingerprint_line(path, bytes)?;
        let body = digested_body(path, bytes)?;
        verify_fingerprint(path, &declared, body)?;

        let text = std::str::from_utf8(body).map_err(|err| RegistrarError::ConfigMalformed {
            path: path.to_path_buf(),
            message: format!("body is not UTF-8: {err}"),
        })?;

        let probe: SchemaProbe = parse_toml(path, text)?;
        if probe.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(RegistrarError::UnsupportedSchemaVersion {
                path: path.to_path_buf(),
                found: probe.schema_version,
                supported: SUPPORTED_SCHEMA_VERSION,
            });
        }

        let raw: RawConfig = parse_toml(path, text)?;
        validate_domain_name(&raw.domain).map_err(|kind| RegistrarError::InvalidDomain {
            domain: raw.domain.clone(),
            kind,
        })?;

        let mut components = BTreeMap::new();
        for (name, entry) in raw.components {
            validate_dns_label(&name).map_err(|kind| RegistrarError::InvalidComponentKey {
                component: name.clone(),
                kind,
            })?;
            let resolved = resolve_component(&name, entry)?;
            components.insert(name, resolved);
        }

        Ok(Self {
            path: path.to_path_buf(),
            fingerprint: declared,
            schema_version: raw.schema_version,
            domain: raw.domain,
            components,
        })
    }
}

/// Reads the declared digest out of the file's first line, which must be
/// exactly `fingerprint = "<64 lowercase hex>"`.
fn read_fingerprint_line(path: &Path, bytes: &[u8]) -> Result<String, RegistrarError> {
    let malformed = || RegistrarError::FingerprintLineMalformed {
        path: path.to_path_buf(),
    };
    let end = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or_else(malformed)?;
    let (line, _) = bytes.split_at_checked(end).ok_or_else(malformed)?;
    let line = std::str::from_utf8(line).map_err(|_| malformed())?;
    let declared = line
        .strip_prefix(FINGERPRINT_PREFIX)
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or_else(malformed)?;
    if declared.len() != FINGERPRINT_HEX_LEN
        || !declared
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(malformed());
    }
    Ok(declared.to_string())
}

/// Returns the digested region: every byte after the newline that ends
/// the fingerprint line, verbatim as written.
fn digested_body<'a>(path: &Path, bytes: &'a [u8]) -> Result<&'a [u8], RegistrarError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or_else(|| RegistrarError::FingerprintLineMalformed {
            path: path.to_path_buf(),
        })?;
    bytes
        .get(end + 1..)
        .ok_or_else(|| RegistrarError::FingerprintLineMalformed {
            path: path.to_path_buf(),
        })
}

fn verify_fingerprint(path: &Path, declared: &str, body: &[u8]) -> Result<(), RegistrarError> {
    let computed = sha256_hex(body);
    // A plain comparison, deliberately. This digest is an integrity
    // check over a local file rather than a MAC over a secret: it is
    // computed from bytes the comparing process just read, and anyone
    // able to write the file can compute the matching digest, so there
    // is nothing a timing side channel could reveal. `ring`'s
    // constant-time helper is deprecated besides.
    if declared != computed {
        return Err(RegistrarError::FingerprintMismatch {
            path: path.to_path_buf(),
            declared: declared.to_string(),
            computed,
        });
    }
    Ok(())
}

/// Parses `text` as TOML through the `config` crate, the same loading
/// idiom the agent's own settings use.
fn parse_toml<T: serde::de::DeserializeOwned>(
    path: &Path,
    text: &str,
) -> Result<T, RegistrarError> {
    config::Config::builder()
        .add_source(config::File::from_str(text, config::FileFormat::Toml))
        .build()
        .and_then(config::Config::try_deserialize)
        .map_err(|err| RegistrarError::ConfigMalformed {
            path: path.to_path_buf(),
            message: err.to_string(),
        })
}

fn resolve_component(name: &str, raw: RawComponent) -> Result<ComponentEntry, RegistrarError> {
    let multiplicity = Multiplicity::from_str(&raw.multiplicity).map_err(|()| {
        RegistrarError::UnknownMultiplicity {
            component: name.to_string(),
            value: raw.multiplicity.clone(),
        }
    })?;
    let kind =
        ReloadKind::from_str(&raw.reload.kind).map_err(|()| RegistrarError::UnknownReloadKind {
            component: name.to_string(),
            value: raw.reload.kind.clone(),
        })?;
    let target = raw.reload.target;
    if kind.takes_target() != target.as_ref().is_some_and(|value| !value.is_empty()) {
        return Err(RegistrarError::InvalidReloadTarget {
            component: name.to_string(),
            kind,
        });
    }
    Ok(ComponentEntry {
        multiplicity,
        spec: RegistrationSpec {
            cert_group: raw.cert_group,
            reload: ReloadSpec { kind, target },
        },
    })
}
