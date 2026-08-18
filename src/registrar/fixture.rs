//! A builder for the rendered registrar config, for tests.
//!
//! Nothing in this repository renders this file in production — it comes
//! from the provisioning tool in another repository — so every test that
//! needs one has to fabricate it. This builder is the canonical
//! fabrication, so the verb, endpoint and acceptance-suite tests consume
//! one shape rather than drifting hand-written approximations of an
//! artifact this repository never produces.
//!
//! It is compiled unconditionally rather than behind `cfg(test)` or a
//! `test-support` feature, because the siblings that must share it are
//! not all in one compilation unit: unit tests in this library, unit
//! tests in the binary crate (which links this library built *without*
//! `cfg(test)`), and integration tests under `tests/` (which cannot see
//! a feature they have no way to enable on a package they are part of).
//! Gating it would leave exactly the callers it exists for writing their
//! own. Nothing here panics or is reachable from a production code path.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::registrar::config::{
    CONFIG_FILE_NAME, Multiplicity, RegistrationSpec, ReloadKind, ReloadSpec,
    SUPPORTED_SCHEMA_VERSION,
};
use crate::tls::sha256_hex;

/// The domain a fixture renders unless a test overrides it.
pub const FIXTURE_DOMAIN: &str = "trusted.domain";

/// One `[components.<key>]` entry as a fixture renders it.
///
/// `multiplicity` and `reload_kind` are held as strings so a test can
/// render a value the loader must refuse. Use the typed builder methods
/// for every other case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentFixture {
    /// The `multiplicity` value to render, verbatim.
    pub multiplicity: String,
    /// The `cert_group` value to render, or `None` to omit the key.
    pub cert_group: Option<u32>,
    /// The `reload.kind` value to render, verbatim.
    pub reload_kind: String,
    /// The `reload.target` value to render, or `None` to omit the key.
    pub reload_target: Option<String>,
}

impl ComponentFixture {
    /// Creates an entry from a multiplicity class and a rendered spec.
    #[must_use]
    pub fn new(multiplicity: Multiplicity, spec: &RegistrationSpec) -> Self {
        Self {
            multiplicity: multiplicity.as_str().to_string(),
            cert_group: spec.cert_group,
            reload_kind: spec.reload.kind.as_str().to_string(),
            reload_target: spec.reload.target.clone(),
        }
    }
}

/// Builds a rendered registrar config a test can write to a directory of
/// its own.
///
/// [`RegistrarConfigFixture::default`] carries the three components of
/// the documented example — `review` (one-per-deployment), `roxyd`
/// (one-per-host, no `cert_group`) and `piglet` (many-per-host) — under
/// [`FIXTURE_DOMAIN`]. Every override returns `Self`, so a test states
/// only what it varies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrarConfigFixture {
    schema_version: u32,
    domain: String,
    components: BTreeMap<String, ComponentFixture>,
    fingerprint: Option<String>,
    header: Option<String>,
}

impl Default for RegistrarConfigFixture {
    fn default() -> Self {
        let mut components = BTreeMap::new();
        components.insert(
            "review".to_string(),
            ComponentFixture::new(
                Multiplicity::OnePerDeployment,
                &RegistrationSpec {
                    cert_group: Some(3000),
                    reload: ReloadSpec::new(ReloadKind::DockerRestart, "review"),
                },
            ),
        );
        components.insert(
            "roxyd".to_string(),
            ComponentFixture::new(
                Multiplicity::OnePerHost,
                &RegistrationSpec {
                    cert_group: None,
                    reload: ReloadSpec::new(ReloadKind::Systemd, "roxyd.service"),
                },
            ),
        );
        components.insert(
            "piglet".to_string(),
            ComponentFixture::new(
                Multiplicity::ManyPerHost,
                &RegistrationSpec {
                    cert_group: Some(3001),
                    reload: ReloadSpec::new(ReloadKind::DockerRestart, "piglet"),
                },
            ),
        );
        Self {
            schema_version: SUPPORTED_SCHEMA_VERSION,
            domain: FIXTURE_DOMAIN.to_string(),
            components,
            fingerprint: None,
            header: None,
        }
    }
}

impl RegistrarConfigFixture {
    /// Creates a fixture carrying the documented example's components.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a fixture with no components at all.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            components: BTreeMap::new(),
            ..Self::default()
        }
    }

    /// Overrides the deployment-wide domain.
    #[must_use]
    pub fn with_domain(mut self, domain: &str) -> Self {
        self.domain = domain.to_string();
        self
    }

    /// Overrides the declared `schema_version`.
    #[must_use]
    pub fn with_schema_version(mut self, version: u32) -> Self {
        self.schema_version = version;
        self
    }

    /// Renders a fingerprint line carrying `fingerprint` instead of the
    /// body's real digest, for a test that needs the digest gate to
    /// fail.
    #[must_use]
    pub fn with_fingerprint(mut self, fingerprint: &str) -> Self {
        self.fingerprint = Some(fingerprint.to_string());
        self
    }

    /// Renders `header` between the fingerprint line and the envelope,
    /// verbatim. Used to ship the documented example's commentary.
    #[must_use]
    pub fn with_header(mut self, header: &str) -> Self {
        self.header = Some(header.to_string());
        self
    }

    /// Adds or replaces a component's whole entry.
    #[must_use]
    pub fn with_component(
        mut self,
        name: &str,
        multiplicity: Multiplicity,
        spec: &RegistrationSpec,
    ) -> Self {
        self.components
            .insert(name.to_string(), ComponentFixture::new(multiplicity, spec));
        self
    }

    /// Adds or replaces a component's entry from raw strings, so a test
    /// can render a `multiplicity` or `reload.kind` the loader refuses.
    #[must_use]
    pub fn with_raw_component(mut self, name: &str, entry: ComponentFixture) -> Self {
        self.components.insert(name.to_string(), entry);
        self
    }

    /// Overrides a component's multiplicity class, adding the component
    /// with the default reload spec when it is not already present.
    #[must_use]
    pub fn with_multiplicity(mut self, name: &str, multiplicity: Multiplicity) -> Self {
        let entry = self
            .components
            .entry(name.to_string())
            .or_insert_with(|| default_entry(multiplicity));
        entry.multiplicity = multiplicity.as_str().to_string();
        self
    }

    /// Overrides a component's safe-set — its single rendered spec —
    /// adding the component as many-per-host when it is not already
    /// present.
    #[must_use]
    pub fn with_spec(mut self, name: &str, spec: &RegistrationSpec) -> Self {
        let entry = self
            .components
            .entry(name.to_string())
            .or_insert_with(|| default_entry(Multiplicity::ManyPerHost));
        entry.cert_group = spec.cert_group;
        entry.reload_kind = spec.reload.kind.as_str().to_string();
        entry.reload_target.clone_from(&spec.reload.target);
        self
    }

    /// Removes a component, so a test can exercise the
    /// component-absent refusal.
    #[must_use]
    pub fn without_component(mut self, name: &str) -> Self {
        self.components.remove(name);
        self
    }

    /// Renders the whole file, fingerprint line first.
    #[must_use]
    pub fn render(&self) -> String {
        let body = self.render_body();
        let fingerprint = self
            .fingerprint
            .clone()
            .unwrap_or_else(|| sha256_hex(body.as_bytes()));
        format!("fingerprint = \"{fingerprint}\"\n{body}")
    }

    /// Renders the digested body: everything after the fingerprint line.
    #[must_use]
    pub fn render_body(&self) -> String {
        let mut out = String::new();
        if let Some(header) = &self.header {
            out.push_str(header);
        }
        let _ = writeln!(out, "schema_version = {}", self.schema_version);
        let _ = writeln!(out, "domain = \"{}\"", self.domain);
        for (name, entry) in &self.components {
            let _ = writeln!(out, "\n[components.{name}]");
            let _ = writeln!(out, "multiplicity = \"{}\"", entry.multiplicity);
            if let Some(gid) = entry.cert_group {
                let _ = writeln!(out, "cert_group = {gid}");
            }
            match &entry.reload_target {
                Some(target) => {
                    let _ = writeln!(
                        out,
                        "reload = {{ kind = \"{}\", target = \"{target}\" }}",
                        entry.reload_kind
                    );
                }
                None => {
                    let _ = writeln!(out, "reload = {{ kind = \"{}\" }}", entry.reload_kind);
                }
            }
        }
        out
    }

    /// Writes the rendered file as `provisioning.toml` inside `dir` and
    /// returns its path.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O failure when the file cannot be
    /// written.
    pub fn write_to(&self, dir: &Path) -> std::io::Result<PathBuf> {
        let path = dir.join(CONFIG_FILE_NAME);
        std::fs::write(&path, self.render())?;
        Ok(path)
    }
}

fn default_entry(multiplicity: Multiplicity) -> ComponentFixture {
    ComponentFixture::new(
        multiplicity,
        &RegistrationSpec {
            cert_group: None,
            reload: ReloadSpec::none(),
        },
    )
}
