//! The registrar endpoint's part in a full CA rotation.
//!
//! On a host that serves the registrar endpoint, the bootroot-internal
//! credential's private trust already moves with the fleet's
//! ([`super::registrar_internal`]). Two further things have to move with
//! it, or the rotation takes the endpoint down:
//!
//! - **The endpoint pin file**, `registrar-endpoint-anchors.sha256`
//!   beside `[registrar_endpoint] client_cert_path`. Both the co-located
//!   registrar client and the daemon's renewal accept a server leaf only
//!   if it chains to an anchor pinned there, so Phase 3 adds the new
//!   generation's counterpart of every old anchor it finds, and Phase 6
//!   removes the old ones once the new ones are proven present.
//! - **The two surface leaves**, the endpoint's server leaf and the
//!   registrar client leaf, which are in no `state.json` entry. Phase 5
//!   removes whichever is still under the old generation, reloads the
//!   daemon so its start-time issuance re-issues them under the new one,
//!   and waits until the files on disk *and* the chain a live handshake
//!   presents have moved. Phase 6 requires both leaves to verify under
//!   the new generation by signature.
//!
//! Phase 6 also proves the narrowed client trust took effect: a
//! registrar client pair from the old generation, preserved by Phase 0
//! before anything could replace it, is accepted before the narrowing
//! and refused after it.
//!
//! Every dial here is [`endpoint_pin::probe_endpoint`], a handshake that
//! sends no request frame and so changes nothing on the endpoint.
//!
//! Nothing here is reached by an intermediate-only rotation or on a host
//! without the internal credential: the caller gates every entry point on
//! [`super::registrar_internal::internal_rotation_applies`].

use std::collections::BTreeSet;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::registrar::endpoint_pin::{
    self, EndpointProbe, EndpointProbeError, ProbeClientPair, ProbeClientPairError, ProbeVerdict,
};
use bootroot::registrar::internal::{InternalPaths, load_internal_config};
use bootroot::registrar::{REGISTRAR_SURFACE_INSTANCE, registrar_endpoint_identity};
use x509_parser::prelude::{ASN1Time, FromDer as _, X509Certificate};

use super::StatePaths;
use crate::commands::trust::RotationState;
use crate::i18n::Messages;

/// How the server certificate key is spelled in a diagnostic.
const SERVER_CERT_SETTING: &str = "[registrar_endpoint] server_cert_path";
/// How the server key key is spelled in a diagnostic.
const SERVER_KEY_SETTING: &str = "[registrar_endpoint] server_key_path";
/// How the client certificate key is spelled in a diagnostic.
const CLIENT_CERT_SETTING: &str = "[registrar_endpoint] client_cert_path";
/// How the client key key is spelled in a diagnostic.
const CLIENT_KEY_SETTING: &str = "[registrar_endpoint] client_key_path";

/// The basename the retired client leaf is preserved under.
const RETIRED_CERT_FILE: &str = "client.crt";
/// The basename the retired client key is preserved under.
const RETIRED_KEY_FILE: &str = "client.key";
/// The retired pair's directory is private to its owner.
const RETIRED_DIR_MODE: u32 = 0o700;
/// Both retired files hold the pair's secret or sit beside it.
const RETIRED_FILE_MODE: u32 = 0o600;

/// How often a wait re-checks the files and re-dials the endpoint.
pub(super) const SURFACE_POLL_INTERVAL: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------
// The endpoint host
// ---------------------------------------------------------------------

/// One of the two surface pairs, as the internal config names it.
#[derive(Debug, Clone)]
pub(super) struct SurfacePair {
    /// The `[registrar_endpoint]` key the certificate path is set by.
    pub(super) setting: &'static str,
    /// The configured certificate path.
    pub(super) cert: PathBuf,
    /// The configured key path.
    pub(super) key: PathBuf,
}

/// What a rotation needs to know about the endpoint on this host, read
/// from the `[registrar_endpoint]` table of `registrar-internal/agent.toml`.
#[derive(Debug, Clone)]
pub(super) struct EndpointHost {
    /// The endpoint pin file, beside the client certificate.
    pub(super) pin_file: PathBuf,
    /// The endpoint's server pair.
    pub(super) server: SurfacePair,
    /// The registrar client pair.
    pub(super) client: SurfacePair,
    /// The exact name the endpoint's server leaf carries.
    pub(super) endpoint_name: String,
}

impl EndpointHost {
    /// Reads the endpoint's paths out of the internal config.
    ///
    /// # Errors
    ///
    /// Returns an error naming the config when it cannot be loaded, and
    /// naming the key when one of the four material paths is unset —
    /// `client_cert_path` first, since the pin file is found beside it.
    pub(super) fn resolve(secrets_dir: &Path, messages: &Messages) -> Result<Self> {
        let paths = InternalPaths::new(secrets_dir);
        let config_path = paths.agent_config();
        let config = config_path.display().to_string();
        let settings = load_internal_config(&paths)
            .with_context(|| messages.error_rotate_endpoint_config_unusable(&config))?;
        let endpoint = &settings.registrar_endpoint;
        let require = |value: Option<&Path>, setting: &str| {
            value.map(Path::to_path_buf).ok_or_else(|| {
                anyhow::anyhow!(messages.error_rotate_endpoint_setting_missing(setting, &config))
            })
        };
        let client_cert = require(endpoint.client_cert_path.as_deref(), CLIENT_CERT_SETTING)?;
        let client_key = require(endpoint.client_key_path.as_deref(), CLIENT_KEY_SETTING)?;
        let server_cert = require(endpoint.server_cert_path.as_deref(), SERVER_CERT_SETTING)?;
        let server_key = require(endpoint.server_key_path.as_deref(), SERVER_KEY_SETTING)?;
        // `load_internal_config` has already held the config to exactly
        // one profile, so this is the host label the surface names are
        // composed on.
        let host = settings
            .profiles
            .first()
            .map(|profile| profile.hostname.clone())
            .unwrap_or_default();
        Ok(Self {
            pin_file: endpoint_pin::anchor_pin_path_for_client_certificate(&client_cert),
            server: SurfacePair {
                setting: SERVER_CERT_SETTING,
                cert: server_cert,
                key: server_key,
            },
            client: SurfacePair {
                setting: CLIENT_CERT_SETTING,
                cert: client_cert,
                key: client_key,
            },
            endpoint_name: registrar_endpoint_identity(
                REGISTRAR_SURFACE_INSTANCE,
                &host,
                &settings.domain,
            ),
        })
    }

    /// Both surface pairs, server first.
    pub(super) fn surface_pairs(&self) -> [&SurfacePair; 2] {
        [&self.server, &self.client]
    }
}

// ---------------------------------------------------------------------
// CA generations and the signature check
// ---------------------------------------------------------------------

/// One CA generation: a root and the intermediate it signed, as DER.
#[derive(Debug, Clone)]
pub(super) struct CaGeneration {
    root: Vec<u8>,
    intermediate: Vec<u8>,
}

impl CaGeneration {
    /// Loads a generation from the root and intermediate PEM files.
    ///
    /// # Errors
    ///
    /// Returns an error naming the file when either cannot be read or
    /// holds no certificate.
    pub(super) fn load(root: &Path, intermediate: &Path, messages: &Messages) -> Result<Self> {
        Ok(Self {
            root: first_certificate_at(root, messages)?,
            intermediate: first_certificate_at(intermediate, messages)?,
        })
    }

    /// Loads a generation and holds it to the fingerprints a rotation
    /// recorded for it, so a backup that was replaced by hand is not
    /// taken for the generation `rotation-state.json` names.
    ///
    /// # Errors
    ///
    /// Returns an error when either file cannot be loaded, or when its
    /// DER SHA-256 is not the recorded fingerprint.
    pub(super) fn load_recorded(
        root: &Path,
        intermediate: &Path,
        root_fp: &str,
        intermediate_fp: &str,
        messages: &Messages,
    ) -> Result<Self> {
        let generation = Self::load(root, intermediate, messages)?;
        for (path, der, expected) in [
            (root, &generation.root, root_fp),
            (intermediate, &generation.intermediate, intermediate_fp),
        ] {
            if !der_sha256_hex(der).eq_ignore_ascii_case(expected) {
                anyhow::bail!(messages.error_rotate_endpoint_generation_mismatch(
                    &path.display().to_string(),
                    expected
                ));
            }
        }
        Ok(generation)
    }

    /// Reports whether `leaf_der` verifies by signature under this
    /// generation: the leaf's signature with the intermediate's public
    /// key, and the intermediate's signature with the root's.
    ///
    /// Deliberately not a comparison of issuer and subject names. A full
    /// rotation generates the new intermediate under the same name as the
    /// old one, so a leaf from the old generation carries exactly the
    /// issuer name a leaf from the new one does.
    pub(super) fn signs(&self, leaf_der: &[u8]) -> bool {
        let (Ok((_, leaf)), Ok((_, intermediate)), Ok((_, root))) = (
            X509Certificate::from_der(leaf_der),
            X509Certificate::from_der(&self.intermediate),
            X509Certificate::from_der(&self.root),
        ) else {
            return false;
        };
        leaf.verify_signature(Some(intermediate.public_key()))
            .is_ok()
            && intermediate
                .verify_signature(Some(root.public_key()))
                .is_ok()
    }
}

/// The lowercase-hex SHA-256 of a certificate's DER — the form every
/// CA fingerprint in a rotation is recorded in.
fn der_sha256_hex(der: &[u8]) -> String {
    use std::fmt::Write as _;
    ring::digest::digest(&ring::digest::SHA256, der)
        .as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// Returns the DER of the first certificate in a PEM file.
fn first_certificate_at(path: &Path, messages: &Messages) -> Result<Vec<u8>> {
    let display = path.display().to_string();
    let pem = std::fs::read(path).with_context(|| messages.error_read_file_failed(&display))?;
    first_certificate(&pem).ok_or_else(|| {
        anyhow::anyhow!(messages.error_parse_cert_failed(&display, "no certificate"))
    })
}

/// Returns the DER of the first certificate in PEM bytes.
fn first_certificate(pem: &[u8]) -> Option<Vec<u8>> {
    rustls_pemfile::certs(&mut std::io::BufReader::new(pem))
        .next()
        .and_then(Result::ok)
        .map(|der| der.as_ref().to_vec())
}

/// Reports whether the leaf at `cert_path` verifies under `generation`.
///
/// An absent or unreadable file is a leaf that has not moved.
pub(super) fn surface_leaf_moved(cert_path: &Path, generation: &CaGeneration) -> bool {
    std::fs::read(cert_path)
        .ok()
        .and_then(|pem| first_certificate(&pem))
        .is_some_and(|der| generation.signs(&der))
}

/// Names, by `[registrar_endpoint]` key, every surface leaf that is absent
/// or does not verify by signature under `new_generation`.
pub(super) fn unmigrated_surface_leaves(
    host: &EndpointHost,
    new_generation: &CaGeneration,
) -> Vec<String> {
    host.surface_pairs()
        .into_iter()
        .filter(|pair| !surface_leaf_moved(&pair.cert, new_generation))
        .map(|pair| pair.setting.to_string())
        .collect()
}

// ---------------------------------------------------------------------
// Phase 0: the pin file
// ---------------------------------------------------------------------

/// The fingerprints Phase 0 accepts as proof the pin file is one the
/// rotation can work from.
///
/// A fresh rotation works from the current root and intermediate. A
/// resumed one works from the generation its recorded phase says the file
/// should name: the old one before Phase 3 is recorded, and the new one —
/// which Phase 3 added — from then on. That is what lets a rotation
/// interrupted inside Phase 6, after the old entries were removed and
/// before the phase was recorded, pass here and finish.
pub(super) fn phase0_accepted_fingerprints(
    resumed: Option<&RotationState>,
    current_root_fp: &str,
    current_intermediate_fp: &str,
) -> [String; 2] {
    match resumed {
        None => [
            current_root_fp.to_string(),
            current_intermediate_fp.to_string(),
        ],
        Some(state) if state.phase < 3 => {
            [state.old_root_fp.clone(), state.old_intermediate_fp.clone()]
        }
        Some(state) => [state.new_root_fp.clone(), state.new_intermediate_fp.clone()],
    }
}

/// Refuses a pin file that is absent, does not parse, or names none of
/// `accepted`.
///
/// # Errors
///
/// Returns an error naming the file for each of the three refusals.
pub(super) fn check_pin_file(
    pin_file: &Path,
    accepted: &[String; 2],
    messages: &Messages,
) -> Result<()> {
    let display = pin_file.display().to_string();
    let contents = match std::fs::read_to_string(pin_file) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!(messages.error_rotate_endpoint_pin_file_missing(&display))
        }
        Err(err) => {
            return Err(anyhow::Error::new(err))
                .with_context(|| messages.error_read_file_failed(&display));
        }
    };
    let pins = endpoint_pin::parse_anchor_pins(&contents).map_err(|err| {
        anyhow::anyhow!(
            messages.error_rotate_endpoint_pin_file_malformed(&display, &err.to_string())
        )
    })?;
    if accepted
        .iter()
        .any(|fingerprint| pins.contains(&fingerprint.to_ascii_lowercase()))
    {
        return Ok(());
    }
    anyhow::bail!(messages.error_rotate_endpoint_pin_file_no_anchor(&display, &accepted.join(", ")))
}

// ---------------------------------------------------------------------
// Phase 0: the retired client pair
// ---------------------------------------------------------------------

/// Why a client pair failed the local checks Phase 0 and a resumed
/// Phase 6 hold it to.
#[derive(Debug)]
pub(super) enum ClientPairCheck {
    /// The pair could not be read, parsed, or its key is not the leaf's.
    Unusable(ProbeClientPairError),
    /// The leaf is outside its validity window.
    OutsideValidity,
    /// The leaf does not verify by signature under the expected
    /// generation.
    NotUnderGeneration,
}

impl ClientPairCheck {
    /// Renders the failed check for an operator.
    pub(super) fn describe(&self, messages: &Messages) -> String {
        match self {
            Self::Unusable(err) => messages.rotate_endpoint_check_key_match(&err.to_string()),
            Self::OutsideValidity => messages.rotate_endpoint_check_validity().to_string(),
            Self::NotUnderGeneration => messages.rotate_endpoint_check_chain().to_string(),
        }
    }
}

/// Holds a client pair to three local checks: the key is the leaf's, the
/// leaf is inside its validity window at `now`, and it verifies by
/// signature under `generation`.
///
/// # Errors
///
/// Returns the first [`ClientPairCheck`] the pair fails.
pub(super) fn check_client_pair(
    cert_pem: &[u8],
    key_pem: &[u8],
    cert_path: &Path,
    key_path: &Path,
    generation: &CaGeneration,
    now: ASN1Time,
) -> Result<ProbeClientPair, ClientPairCheck> {
    let pair = ProbeClientPair::from_pem(cert_pem, key_pem, cert_path, key_path)
        .map_err(ClientPairCheck::Unusable)?;
    let leaf = pair.leaf().as_ref().to_vec();
    let Ok((_, parsed)) = X509Certificate::from_der(&leaf) else {
        return Err(ClientPairCheck::OutsideValidity);
    };
    let validity = parsed.validity();
    if now < validity.not_before || now > validity.not_after {
        return Err(ClientPairCheck::OutsideValidity);
    }
    if !generation.signs(&leaf) {
        return Err(ClientPairCheck::NotUnderGeneration);
    }
    Ok(pair)
}

/// The owner the retired pair's directory and files are given.
#[derive(Debug, Clone, Copy)]
pub(super) struct RetiredOwner {
    uid: u32,
    gid: u32,
}

impl RetiredOwner {
    /// `root:root`, which production always uses: the directory holds a
    /// private key of the identity the endpoint trusts.
    pub(super) fn root() -> Self {
        Self { uid: 0, gid: 0 }
    }

    /// The test process's own ids, so the production create, chown and
    /// rename path runs unchanged in a test that is not root.
    #[cfg(test)]
    pub(super) fn current_process() -> Self {
        // SAFETY: `getegid` takes no argument and always succeeds.
        let gid = unsafe { libc::getegid() };
        Self {
            uid: fs_util::current_process_euid(),
            gid,
        }
    }
}

/// Removes a leftover staging directory, which only an interrupted
/// Phase 0 copy leaves behind and which is never a complete pair.
///
/// # Errors
///
/// Returns an error naming the directory when it exists and cannot be
/// removed.
pub(super) fn sweep_retired_staging(paths: &StatePaths, messages: &Messages) -> Result<()> {
    remove_dir_if_present(&paths.registrar_client_retired_staging(), messages)
}

/// Removes the preserved retired pair, if there is one.
///
/// # Errors
///
/// Returns an error naming the directory when it exists and cannot be
/// removed.
pub(super) fn remove_retired_pair(paths: &StatePaths, messages: &Messages) -> Result<()> {
    remove_dir_if_present(&paths.registrar_client_retired(), messages)
}

fn remove_dir_if_present(dir: &Path, messages: &Messages) -> Result<()> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(anyhow::Error::new(err))
            .with_context(|| messages.error_write_file_failed(&dir.display().to_string())),
    }
}

/// Checks the current registrar client pair and preserves it as the
/// retired pair.
///
/// Held under the publication lock for the pair's destinations — the
/// lock every writer of the pair takes — so the daemon's renewal cannot
/// replace one file of the pair between the two reads. The copy is
/// staged and synced, then renamed into place, so a directory under the
/// final name is always a complete pair; one that already exists is
/// replaced, because on a fresh rotation the current pair is still the
/// old generation.
///
/// # Errors
///
/// Returns an error naming the failed check when the pair is not usable,
/// or naming the path when a read, write, sync or rename fails.
pub(super) async fn preserve_retired_pair(
    client: &SurfacePair,
    paths: &StatePaths,
    current: &CaGeneration,
    owner: RetiredOwner,
    messages: &Messages,
) -> Result<()> {
    let _lock = bootroot::publication_lock::hold(&[&client.cert, &client.key]).await?;
    let cert_pem = std::fs::read(&client.cert)
        .with_context(|| messages.error_read_file_failed(&client.cert.display().to_string()))?;
    let key_pem = std::fs::read(&client.key)
        .with_context(|| messages.error_read_file_failed(&client.key.display().to_string()))?;
    check_client_pair(
        &cert_pem,
        &key_pem,
        &client.cert,
        &client.key,
        current,
        ASN1Time::now(),
    )
    .map_err(|check| {
        anyhow::anyhow!(messages.error_rotate_endpoint_client_pair_check_failed(
            &client.cert.display().to_string(),
            &check.describe(messages),
        ))
    })?;

    let staging = paths.registrar_client_retired_staging();
    let target = paths.registrar_client_retired();
    remove_dir_if_present(&staging, messages)?;
    write_retired_staging(&staging, &cert_pem, &key_pem, owner)
        .with_context(|| messages.error_write_file_failed(&staging.display().to_string()))?;
    remove_dir_if_present(&target, messages)?;
    std::fs::rename(&staging, &target)
        .with_context(|| messages.error_write_file_failed(&target.display().to_string()))?;
    // The rename is what a resumed rotation relies on to find a complete
    // pair, so it has to survive a power loss, not only a clean exit.
    fs_util::sync_parent_dir(&target)?;
    println!(
        "{}",
        messages.rotate_ca_key_endpoint_retired_preserved(&target.display().to_string())
    );
    Ok(())
}

/// Creates the staging directory and both files at their final owner and
/// mode, and syncs all three.
fn write_retired_staging(
    staging: &Path,
    cert_pem: &[u8],
    key_pem: &[u8],
    owner: RetiredOwner,
) -> std::io::Result<()> {
    std::fs::DirBuilder::new()
        .mode(RETIRED_DIR_MODE)
        .create(staging)?;
    std::os::unix::fs::chown(staging, Some(owner.uid), Some(owner.gid))?;
    for (name, bytes) in [(RETIRED_CERT_FILE, cert_pem), (RETIRED_KEY_FILE, key_pem)] {
        let path = staging.join(name);
        // Created at its final mode: the key is never readable wider.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(RETIRED_FILE_MODE)
            .open(&path)?;
        std::os::unix::fs::fchown(&file, Some(owner.uid), Some(owner.gid))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::File::open(staging)?.sync_all()
}

/// What Phase 6 found at the retired pair's directory.
#[derive(Debug)]
pub(super) enum RetiredPair {
    /// The pair passed the local checks and can be dialed with.
    Usable(ProbeClientPair),
    /// The pair cannot prove the old trust is refused, for the reason
    /// given.
    Unusable(String),
}

/// Loads the preserved retired pair and holds it to the local checks:
/// key match, validity window, and a signature chain to the old
/// generation.
pub(super) fn assess_retired_pair(
    paths: &StatePaths,
    old_generation: &CaGeneration,
    messages: &Messages,
) -> RetiredPair {
    let dir = paths.registrar_client_retired();
    let cert_path = dir.join(RETIRED_CERT_FILE);
    let key_path = dir.join(RETIRED_KEY_FILE);
    let (Ok(cert_pem), Ok(key_pem)) = (std::fs::read(&cert_path), std::fs::read(&key_path)) else {
        return RetiredPair::Unusable(
            messages.rotate_endpoint_retired_absent(&dir.display().to_string()),
        );
    };
    match check_client_pair(
        &cert_pem,
        &key_pem,
        &cert_path,
        &key_path,
        old_generation,
        ASN1Time::now(),
    ) {
        Ok(pair) => RetiredPair::Usable(pair),
        Err(check) => RetiredPair::Unusable(check.describe(messages)),
    }
}

/// Holds the preserved retired pair to the local checks against the old
/// generation `state` recorded, read from the Phase-1 backups.
///
/// A backup that is gone, or is no longer the recorded certificate,
/// leaves the chain check impossible. That is a retired pair that cannot
/// be used — which `--force` can waive like any other — rather than a
/// rotation that can never finish.
pub(super) fn assess_recorded_retired_pair(
    paths: &StatePaths,
    state: &RotationState,
    messages: &Messages,
) -> RetiredPair {
    match CaGeneration::load_recorded(
        &paths.root_cert_bak(),
        &paths.intermediate_cert_bak(),
        &state.old_root_fp,
        &state.old_intermediate_fp,
        messages,
    ) {
        Ok(old_generation) => assess_retired_pair(paths, &old_generation, messages),
        Err(err) => RetiredPair::Unusable(format!("{err:#}")),
    }
}

// ---------------------------------------------------------------------
// The pin file edits
// ---------------------------------------------------------------------

/// Each old anchor paired with its new-generation counterpart:
/// `(old root, new root)` and `(old intermediate, new intermediate)`.
pub(super) fn anchor_succession(state: &RotationState) -> [(String, String); 2] {
    [
        (state.old_root_fp.clone(), state.new_root_fp.clone()),
        (
            state.old_intermediate_fp.clone(),
            state.new_intermediate_fp.clone(),
        ),
    ]
}

/// The digest a significant pin-file line carries, or `None` for a blank
/// line or a comment — the parser's own rule for what counts.
fn line_digest(line: &str) -> Option<String> {
    let trimmed = line.trim_matches(|ch: char| ch.is_ascii_whitespace());
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

fn pinned_digests(contents: &str) -> BTreeSet<String> {
    contents.lines().filter_map(line_digest).collect()
}

/// Appends the new counterpart of every pinned old anchor, as lowercase
/// hex, keeping every existing line — comments included — in order.
///
/// Returns `None` when nothing needs adding, so a resumed Phase 3 leaves
/// the file untouched.
pub(super) fn widened_pin_contents(
    contents: &str,
    succession: &[(String, String); 2],
) -> Option<String> {
    let mut pins = pinned_digests(contents);
    let mut widened = contents.to_string();
    let mut changed = false;
    for (old, new) in succession {
        let (old, new) = (old.to_ascii_lowercase(), new.to_ascii_lowercase());
        if old == new || !pins.contains(&old) || pins.contains(&new) {
            continue;
        }
        if !widened.is_empty() && !widened.ends_with('\n') {
            widened.push('\n');
        }
        widened.push_str(&new);
        widened.push('\n');
        pins.insert(new);
        changed = true;
    }
    changed.then_some(widened)
}

/// Removes every pinned old anchor whose new counterpart is pinned,
/// keeping every other line — comments included — in order.
///
/// Returns `Ok(None)` when no old anchor is left, so a resumed Phase 6
/// leaves the file untouched.
///
/// # Errors
///
/// Returns the missing new fingerprint, with nothing removed, when an old
/// anchor is pinned without its counterpart: removing it would leave the
/// file without an anchor for that part of the chain.
pub(super) fn narrowed_pin_contents(
    contents: &str,
    succession: &[(String, String); 2],
) -> Result<Option<String>, String> {
    let pins = pinned_digests(contents);
    let mut removed = BTreeSet::new();
    for (old, new) in succession {
        let (old, new) = (old.to_ascii_lowercase(), new.to_ascii_lowercase());
        if old == new || !pins.contains(&old) {
            continue;
        }
        if !pins.contains(&new) {
            return Err(new);
        }
        removed.insert(old);
    }
    if removed.is_empty() {
        return Ok(None);
    }
    let narrowed: String = contents
        .split_inclusive('\n')
        .filter(|line| line_digest(line).is_none_or(|digest| !removed.contains(&digest)))
        .collect();
    Ok(Some(narrowed))
}

/// Adds the new generation's anchors to the pin file (Phase 3).
///
/// # Errors
///
/// Returns an error naming the file when it cannot be read or written.
pub(super) async fn widen_pin_file(
    pin_file: &Path,
    succession: &[(String, String); 2],
    messages: &Messages,
) -> Result<()> {
    let contents = read_pin_file(pin_file, messages)?;
    match widened_pin_contents(&contents, succession) {
        Some(widened) => {
            write_pin_file(pin_file, &widened, messages).await?;
            println!(
                "{}",
                messages.rotate_ca_key_endpoint_pin_widened(&pin_file.display().to_string())
            );
        }
        None => println!(
            "{}",
            messages.rotate_ca_key_endpoint_pin_unchanged(&pin_file.display().to_string())
        ),
    }
    Ok(())
}

/// Removes the old generation's anchors from the pin file (Phase 6).
///
/// # Errors
///
/// Returns an error naming the file when it cannot be read or written,
/// and naming the file and the missing fingerprint — with nothing
/// removed — when an old anchor's new counterpart is absent.
pub(super) async fn narrow_pin_file(
    pin_file: &Path,
    succession: &[(String, String); 2],
    messages: &Messages,
) -> Result<()> {
    let display = pin_file.display().to_string();
    let contents = read_pin_file(pin_file, messages)?;
    match narrowed_pin_contents(&contents, succession) {
        Ok(Some(narrowed)) => {
            write_pin_file(pin_file, &narrowed, messages).await?;
            println!("{}", messages.rotate_ca_key_endpoint_pin_narrowed(&display));
        }
        Ok(None) => println!(
            "{}",
            messages.rotate_ca_key_endpoint_pin_unchanged(&display)
        ),
        Err(missing) => {
            anyhow::bail!(
                messages.error_rotate_endpoint_pin_counterpart_missing(&display, &missing)
            )
        }
    }
    Ok(())
}

/// Reads the pin file, which must already exist: a rotation never creates
/// it.
fn read_pin_file(pin_file: &Path, messages: &Messages) -> Result<String> {
    let display = pin_file.display().to_string();
    match std::fs::read_to_string(pin_file) {
        Ok(contents) => Ok(contents),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!(messages.error_rotate_endpoint_pin_file_missing(&display))
        }
        Err(err) => {
            Err(anyhow::Error::new(err)).with_context(|| messages.error_read_file_failed(&display))
        }
    }
}

/// Replaces the pin file's contents atomically, keeping its owner, group
/// and mode.
async fn write_pin_file(pin_file: &Path, contents: &str, messages: &Messages) -> Result<()> {
    // Durable, not only atomic: the staged file is `sync_all`ed before the
    // rename and the directory after it. The pin file is what a resumed
    // rotation reads back to decide where it is, and what every caller
    // trusts the endpoint by, so a crash or power loss between this
    // rename and the phase record must not lose it. The staged file takes
    // the existing file's owner, group and mode — the provisioning tool's
    // choice — before it is renamed over it.
    fs_util::atomic_write(
        fs_util::Destination::operator_named(pin_file),
        contents.as_bytes(),
        fs_util::StagedMode::PreserveOrUmask,
    )
    .await
    .with_context(|| messages.error_write_file_failed(&pin_file.display().to_string()))
}

/// Reports whether a run stops once Phase 5 is recorded instead of going
/// on to Phase 7.
///
/// Only on a registrar endpoint host, only while Phase 6 is still ahead,
/// and only when finalization is skipped: there, skipping it defers
/// Phase 6 instead of abandoning it, because Phase 7 would delete the
/// recorded generations and the retired client pair that narrowing the
/// trust and the pin file later needs.
pub(super) fn pauses_before_finalize(
    endpoint_host: bool,
    start_phase: u8,
    skip_finalize: bool,
) -> bool {
    endpoint_host && start_phase < 6 && skip_finalize
}

// ---------------------------------------------------------------------
// Dialing the endpoint
// ---------------------------------------------------------------------

/// Something that can dial the endpoint with a client pair.
///
/// The production one is [`SocketDialer`]; a test substitutes an endpoint
/// whose behaviour it scripts.
pub(super) trait EndpointDialer {
    /// Dials once with `pair` and reports what the endpoint did.
    async fn dial(&self, pair: &ProbeClientPair) -> Result<EndpointProbe, EndpointProbeError>;
}

/// Dials the endpoint's socket through [`endpoint_pin::probe_endpoint`].
pub(super) struct SocketDialer {
    socket_path: PathBuf,
    pin_file: PathBuf,
    endpoint_name: String,
}

impl SocketDialer {
    /// Builds a dialer for the endpoint on `socket_path`, verified by the
    /// host's pin file and endpoint name.
    pub(super) fn new(host: &EndpointHost, socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            pin_file: host.pin_file.clone(),
            endpoint_name: host.endpoint_name.clone(),
        }
    }
}

impl EndpointDialer for SocketDialer {
    async fn dial(&self, pair: &ProbeClientPair) -> Result<EndpointProbe, EndpointProbeError> {
        endpoint_pin::probe_endpoint(&self.socket_path, &self.pin_file, &self.endpoint_name, pair)
            .await
    }
}

/// How long a wait lasts and how often it re-checks.
#[derive(Debug, Clone, Copy)]
pub(super) struct WaitBudget {
    /// The whole wait.
    pub(super) timeout: Duration,
    /// The pause between checks.
    pub(super) poll: Duration,
}

// ---------------------------------------------------------------------
// Phase 5: move both surface leaves
// ---------------------------------------------------------------------

/// Why Phase 5's wait has not been satisfied yet.
#[derive(Debug)]
enum SurfaceMove {
    /// A leaf on disk is absent or not under the new generation.
    NotReissued(Vec<String>),
    /// The endpoint answered with a chain that is not the new one.
    StillOld,
    /// The endpoint presented the new chain but refused the re-issued
    /// client pair.
    ClientRefused,
    /// No endpoint answered.
    Unanswered(String),
}

/// Removes every surface pair not yet under the new generation, reloads
/// the endpoint daemon once, and waits until both leaves on disk and the
/// chain a live handshake presents verify under the new generation, and
/// that handshake accepts the re-issued client pair.
///
/// A pair already moved is left alone, so a resumed Phase 5 does not
/// remove what the previous run moved. Each removal is made under the
/// publication lock every writer of the pair takes, and the lock is
/// released before the signal.
///
/// # Errors
///
/// Returns an error when a lock or a removal fails, when the signal
/// fails, or when the wait times out — naming whether the material was
/// not re-issued, the endpoint still presents the old chain, the endpoint
/// refuses the re-issued client pair, or no endpoint answered.
pub(super) async fn move_surface_leaves<D, S>(
    host: &EndpointHost,
    new_generation: &CaGeneration,
    dialer: &D,
    signal: S,
    budget: WaitBudget,
    messages: &Messages,
) -> Result<()>
where
    D: EndpointDialer,
    S: FnOnce() -> Result<()>,
{
    for pair in host.surface_pairs() {
        if remove_unmoved_pair_under_lock(pair, new_generation, messages).await? {
            println!(
                "{}",
                messages.rotate_ca_key_endpoint_surface_removed(
                    pair.setting,
                    &pair.cert.display().to_string()
                )
            );
        } else {
            println!(
                "{}",
                messages.rotate_ca_key_endpoint_surface_already_moved(pair.setting)
            );
        }
    }
    signal()?;
    println!(
        "{}",
        messages.rotate_ca_key_endpoint_waiting(
            &humantime::format_duration(budget.timeout).to_string()
        )
    );
    wait_for_surface_move(host, new_generation, dialer, budget, messages).await
}

/// Removes one pair's certificate and key unless its leaf already
/// verifies under the new generation, deciding and removing while holding
/// the publication lock for their destinations, and releases it on
/// return. Returns whether the pair was removed.
///
/// The check is made under the lock, not before it: renewal takes the
/// same lock to publish, so a pair it moved while this waited for the
/// lock is seen as moved and kept rather than deleted.
async fn remove_unmoved_pair_under_lock(
    pair: &SurfacePair,
    new_generation: &CaGeneration,
    messages: &Messages,
) -> Result<bool> {
    let _lock = bootroot::publication_lock::hold(&[&pair.cert, &pair.key]).await?;
    if surface_leaf_moved(&pair.cert, new_generation) {
        return Ok(false);
    }
    for path in [&pair.cert, &pair.key] {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(anyhow::Error::new(err)).with_context(|| {
                    messages.error_write_file_failed(&path.display().to_string())
                });
            }
        }
    }
    Ok(true)
}

/// Polls until both conditions of Phase 5 hold, or the budget runs out.
async fn wait_for_surface_move<D: EndpointDialer>(
    host: &EndpointHost,
    new_generation: &CaGeneration,
    dialer: &D,
    budget: WaitBudget,
    messages: &Messages,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + budget.timeout;
    loop {
        let state = surface_move_state(host, new_generation, dialer).await;
        let Some(pending) = state else {
            return Ok(());
        };
        if tokio::time::Instant::now() >= deadline {
            let timeout = humantime::format_duration(budget.timeout).to_string();
            anyhow::bail!(match pending {
                SurfaceMove::NotReissued(settings) => messages
                    .error_rotate_endpoint_surface_not_reissued(&settings.join(", "), &timeout),
                SurfaceMove::StillOld => messages.error_rotate_endpoint_still_old_chain(&timeout),
                SurfaceMove::ClientRefused => {
                    messages.error_rotate_endpoint_reissued_client_refused(&timeout)
                }
                SurfaceMove::Unanswered(detail) => {
                    messages.error_rotate_endpoint_unanswered(&detail, &timeout)
                }
            });
        }
        tokio::time::sleep(budget.poll).await;
    }
}

/// Checks Phase 5's two conditions once. `None` means both hold.
async fn surface_move_state<D: EndpointDialer>(
    host: &EndpointHost,
    new_generation: &CaGeneration,
    dialer: &D,
) -> Option<SurfaceMove> {
    let unmoved = unmigrated_surface_leaves(host, new_generation);
    if !unmoved.is_empty() {
        return Some(SurfaceMove::NotReissued(unmoved));
    }
    // A pair the daemon is part-way through publishing is not a pair yet;
    // the next check reads it again.
    let Ok(pair) = ProbeClientPair::load(&host.client.cert, &host.client.key) else {
        return Some(SurfaceMove::NotReissued(vec![
            host.client.setting.to_string(),
        ]));
    };
    match dialer.dial(&pair).await {
        Ok(probe) => {
            let presented_new = probe
                .presented_chain
                .first()
                .is_some_and(|leaf| new_generation.signs(leaf.as_ref()));
            if !presented_new {
                Some(SurfaceMove::StillOld)
            } else if probe.verdict == ProbeVerdict::Accepted {
                None
            } else {
                // A pause recorded here would leave the re-issued client
                // unable to use the endpoint, and Phase 6 would narrow the
                // trust before its own wait noticed.
                Some(SurfaceMove::ClientRefused)
            }
        }
        Err(err) => Some(SurfaceMove::Unanswered(err.to_string())),
    }
}

// ---------------------------------------------------------------------
// Phase 6: prove the narrowing
// ---------------------------------------------------------------------

/// Reports whether the internal config's pins have already been narrowed,
/// that is, no longer include either old-generation fingerprint.
///
/// # Errors
///
/// Returns an error naming the config when it cannot be loaded.
pub(super) fn internal_trust_narrowed(
    secrets_dir: &Path,
    state: &RotationState,
    messages: &Messages,
) -> Result<bool> {
    let paths = InternalPaths::new(secrets_dir);
    let settings = load_internal_config(&paths).with_context(|| {
        messages.error_rotate_endpoint_config_unusable(&paths.agent_config().display().to_string())
    })?;
    let pins = &settings.trust.trusted_ca_sha256;
    let pinned = |fingerprint: &str| pins.iter().any(|pin| pin.eq_ignore_ascii_case(fingerprint));
    Ok(!pinned(&state.old_root_fp) && !pinned(&state.old_intermediate_fp))
}

/// What Phase 6 will require of the retired pair once the trust is
/// narrowed.
#[derive(Debug)]
pub(super) enum RefusalProof {
    /// The retired pair must be refused.
    Required(ProbeClientPair),
    /// `--force` waived the refusal because the retired pair cannot be
    /// used.
    Waived,
}

/// Runs everything Phase 6 decides before the trust is narrowed.
///
/// With a usable retired pair and trust not yet narrowed, dials with it
/// and requires it accepted: that shows the pair itself is good and the
/// transitional trust still accepts it, so a later refusal can only come
/// from the narrowing. A resumed Phase 6 whose trust is already narrowed
/// relies on the local checks the pair has already passed instead. A
/// retired pair that cannot be used fails Phase 6 unless `force` waives
/// the refusal, with a warning that it was not proven.
///
/// # Errors
///
/// Returns an error when the before-dial does not report the pair
/// accepted, or when the retired pair cannot be used and `force` is not
/// set.
pub(super) async fn prepare_refusal_proof<D: EndpointDialer>(
    dialer: &D,
    retired: RetiredPair,
    trust_narrowed: bool,
    force: bool,
    messages: &Messages,
) -> Result<RefusalProof> {
    match retired {
        RetiredPair::Usable(pair) => {
            if !trust_narrowed {
                match dialer.dial(&pair).await {
                    Ok(probe) if probe.verdict == ProbeVerdict::Accepted => {}
                    Ok(_) => anyhow::bail!(messages.error_rotate_endpoint_before_dial_refused()),
                    Err(err) => anyhow::bail!(
                        messages.error_rotate_endpoint_before_dial_failed(&err.to_string())
                    ),
                }
            }
            Ok(RefusalProof::Required(pair))
        }
        RetiredPair::Unusable(reason) => {
            if !force {
                anyhow::bail!(messages.error_rotate_endpoint_retired_unusable(&reason));
            }
            eprintln!(
                "{}",
                messages.warning_rotate_endpoint_refusal_unproven(&reason)
            );
            Ok(RefusalProof::Waived)
        }
    }
}

/// Finishes Phase 6 on the endpoint once the trust has been narrowed:
/// waits for the narrowing to be proven on live connections, and only
/// then removes the old anchors from the pin file.
///
/// # Errors
///
/// Returns the wait's error with the pin file untouched, or the pin
/// file's own error.
pub(super) async fn finish_narrowing<D: EndpointDialer>(
    host: &EndpointHost,
    dialer: &D,
    proof: &RefusalProof,
    succession: &[(String, String); 2],
    budget: WaitBudget,
    messages: &Messages,
) -> Result<()> {
    wait_for_narrowing(host, dialer, proof, budget, messages).await?;
    narrow_pin_file(&host.pin_file, succession, messages).await
}

/// Why Phase 6's wait has not been satisfied yet.
#[derive(Debug)]
enum NarrowingState {
    /// The current pair was not accepted, with what the dial reported.
    CurrentNotAccepted(String),
    /// The retired pair is still accepted.
    RetiredStillAccepted,
    /// The retired pair's dial gave no verdict.
    RetiredUnanswered(String),
}

/// Waits until a dial with the current client pair is accepted and — unless
/// the refusal was waived — a dial with the retired pair is refused.
///
/// # Errors
///
/// Returns an error naming the failed condition when the budget runs out.
async fn wait_for_narrowing<D: EndpointDialer>(
    host: &EndpointHost,
    dialer: &D,
    proof: &RefusalProof,
    budget: WaitBudget,
    messages: &Messages,
) -> Result<()> {
    println!(
        "{}",
        messages.rotate_ca_key_endpoint_waiting(
            &humantime::format_duration(budget.timeout).to_string()
        )
    );
    let deadline = tokio::time::Instant::now() + budget.timeout;
    loop {
        let Some(pending) = narrowing_state(host, dialer, proof, messages).await else {
            return Ok(());
        };
        if tokio::time::Instant::now() >= deadline {
            let timeout = humantime::format_duration(budget.timeout).to_string();
            anyhow::bail!(match pending {
                NarrowingState::CurrentNotAccepted(detail) => {
                    messages.error_rotate_endpoint_current_not_accepted(&detail, &timeout)
                }
                NarrowingState::RetiredStillAccepted => {
                    messages.error_rotate_endpoint_retired_still_accepted(&timeout)
                }
                NarrowingState::RetiredUnanswered(detail) => {
                    messages.error_rotate_endpoint_unanswered(&detail, &timeout)
                }
            });
        }
        tokio::time::sleep(budget.poll).await;
    }
}

/// Checks Phase 6's two conditions once. `None` means both hold.
async fn narrowing_state<D: EndpointDialer>(
    host: &EndpointHost,
    dialer: &D,
    proof: &RefusalProof,
    messages: &Messages,
) -> Option<NarrowingState> {
    let current = match ProbeClientPair::load(&host.client.cert, &host.client.key) {
        Ok(pair) => pair,
        Err(err) => return Some(NarrowingState::CurrentNotAccepted(err.to_string())),
    };
    match dialer.dial(&current).await {
        Ok(probe) if probe.verdict == ProbeVerdict::Accepted => {}
        Ok(_) => {
            return Some(NarrowingState::CurrentNotAccepted(
                messages.rotate_endpoint_pair_refused().to_string(),
            ));
        }
        Err(err) => return Some(NarrowingState::CurrentNotAccepted(err.to_string())),
    }
    let RefusalProof::Required(retired) = proof else {
        return None;
    };
    match dialer.dial(retired).await {
        Ok(probe) if probe.verdict == ProbeVerdict::Refused => None,
        Ok(_) => Some(NarrowingState::RetiredStillAccepted),
        Err(err) => Some(NarrowingState::RetiredUnanswered(err.to_string())),
    }
}

#[cfg(test)]
mod tests;
