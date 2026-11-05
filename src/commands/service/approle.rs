use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::fs_util::{RootedOwner, SecretsTree};
use bootroot::openbao::{OpenBaoClient, SecretIdOptions};
use bootroot::service_material::{
    ProvisionedServiceRole, ServiceProvisionError, ServiceProvisionStep, ServiceRoleTtls,
    build_service_policy, provision_service_role, service_policy_name,
};

use super::ServiceAppRoleMaterialized;
use crate::commands::init::{SECRET_ID_TTL, TOKEN_TTL, parse_ttl_to_secs};
use crate::i18n::Messages;
use crate::state::StateFile;

/// Renders the step-specific diagnostic the CLI reported for each of the
/// three provisioning calls before that sequence was shared with the
/// registrar.
fn provision_message(err: &ServiceProvisionError, messages: &Messages) -> &'static str {
    match err.step {
        ServiceProvisionStep::Policy => messages.error_openbao_policy_write_failed(),
        ServiceProvisionStep::AppRole => messages.error_openbao_approle_create_failed(),
        ServiceProvisionStep::RoleId => messages.error_openbao_role_id_failed(),
    }
}

/// Returns the role-level `secret_id_ttl` a service role is created with:
/// the value `init --secret-id-ttl` recorded, when it parses to a positive
/// duration, and [`SECRET_ID_TTL`] otherwise.
///
/// A zero is replaced rather than passed on because `OpenBao` reads a role
/// `secret_id_ttl` of 0 as "never expires", and `init` accepts and records
/// one. An absent value is a `state.json` written before `init` recorded
/// it, and an unparseable one was edited by hand; both keep the constant
/// service roles have always had.
fn service_role_secret_id_ttl(state: &StateFile) -> &str {
    state
        .rotate_secret_id_ttl
        .as_deref()
        .filter(|ttl| parse_ttl_to_secs(ttl).is_some_and(|secs| secs > 0))
        .unwrap_or(SECRET_ID_TTL)
}

pub(super) async fn ensure_service_approle(
    client: &OpenBaoClient,
    state: &StateFile,
    registration_id: &str,
    secret_id_options: &SecretIdOptions,
    wrap_ttl: Option<&str>,
    messages: &Messages,
) -> Result<ServiceAppRoleMaterialized> {
    // The role's `secret_id_ttl` follows the one `init` recorded, so a
    // deployment initialised for a longer outage window gives its service
    // credentials the same lifetime as its rotate and infra ones. The
    // shared helper declares no TTLs; choosing them stays this caller's.
    let provisioned = provision_service_role(
        client,
        &state.kv_mount,
        registration_id,
        ServiceRoleTtls {
            token_ttl: TOKEN_TTL,
            secret_id_ttl: service_role_secret_id_ttl(state),
        },
    )
    .await
    .map_err(|err| {
        let message = provision_message(&err, messages);
        anyhow::Error::new(err).context(message)
    })?;
    let ProvisionedServiceRole {
        role_name,
        policy_name,
        role_id,
    } = provisioned;
    // Issuance stays here, not in the shared helper: `service add`
    // delivers the raw `secret_id` to a local file, wrapping only as a
    // transport hop it immediately unwraps.
    let secret_id = match wrap_ttl {
        Some(ttl) => {
            client
                .create_secret_id_wrapped(&role_name, secret_id_options, ttl)
                .await
        }
        None => client.create_secret_id(&role_name, secret_id_options).await,
    }
    .with_context(|| messages.error_openbao_secret_id_failed())?;
    Ok(ServiceAppRoleMaterialized {
        role_name,
        role_id,
        secret_id,
        policy_name,
    })
}

/// Re-applies the service `AppRole` policy for an already-provisioned service.
///
/// `write_policy` is idempotent, so this is safe to run repeatedly. It exists
/// so that services provisioned before the reissue-path write grant was added
/// pick up the updated policy on the idempotent remote `service add` re-run,
/// instead of keeping the old read-only policy indefinitely.
pub(super) async fn reapply_service_policy(
    client: &OpenBaoClient,
    state: &StateFile,
    registration_id: &str,
    messages: &Messages,
) -> Result<()> {
    let policy_name = service_policy_name(registration_id);
    let policy = build_service_policy(&state.kv_mount, registration_id);
    client
        .write_policy(&policy_name, &policy)
        .await
        .with_context(|| messages.error_openbao_policy_write_failed())?;
    Ok(())
}

pub(super) async fn write_secret_id_file(
    tree: &Arc<SecretsTree>,
    secret_id_path: &Path,
    secret_id: &str,
    is_override: bool,
    messages: &Messages,
) -> Result<()> {
    write_service_credential_file(tree, secret_id_path, secret_id, is_override, messages).await
}

pub(super) async fn write_role_id_file(
    tree: &Arc<SecretsTree>,
    role_id_path: &Path,
    role_id: &str,
    is_override: bool,
    messages: &Messages,
) -> Result<()> {
    write_service_credential_file(tree, role_id_path, role_id, is_override, messages).await
}

/// Writes a freshly-minted service credential (`secret_id` or its
/// sibling `role_id`) to `path`.
///
/// For the default secrets-tree location bootroot owns the directory:
/// it is created `0700`, and the file is published by rename at `0600`,
/// replacing any stale file left by a previously removed service. For an
/// operator `--secret-id-path` override the directory is agent-owned and
/// sits outside the secrets tree, so the write goes through the hardened
/// path in [`fs_util::create_owned_credential_noclobber`]: the parent
/// must already exist, the fresh file is chowned to the agent-owning
/// parent, mode `0600`, created no-clobber, and never follows a
/// final-component symlink.
///
/// On a rooted `tree` the default location is written through the
/// handle, following no name: each missing directory level is created at
/// `0700` under the owner of the level it is created in, and the file is
/// published at `0600` under the owner of the file it replaces or, when
/// fresh, of its directory.
async fn write_service_credential_file(
    tree: &Arc<SecretsTree>,
    path: &Path,
    contents: &str,
    is_override: bool,
    messages: &Messages,
) -> Result<()> {
    if !is_override && tree.is_rooted() {
        return publish_below_secrets(tree, path, contents.as_bytes(), messages).await;
    }
    if is_override {
        fs_util::create_owned_credential_noclobber(path, contents.as_bytes())
            .await
            .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    } else {
        // Inside the root-owned secrets tree, published by rename at the
        // policy's `0600` — the same mode the `write` +
        // `set_key_permissions` pair this replaced ended at, now applied
        // to the staged temporary so it holds from the moment the
        // credential appears at its path.
        //
        // It takes the directory flush, for the reason
        // `fs_util::create_owned_credential_noclobber` states for the
        // override path beside it: `OpenBao` has already issued this
        // `secret_id` by the time it is written, and losing the
        // directory entry locks the agent out until an operator
        // intervenes rather than costing a rewrite.
        let parent = path.parent().unwrap_or(Path::new("."));
        fs_util::ensure_secrets_dir(parent).await?;
        fs_util::atomic_write(
            fs_util::Destination::bootroot_owned(path),
            contents.as_bytes(),
            fs_util::StagedMode::Policy(fs_util::KEY_FILE_MODE),
        )
        .await
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    }
    Ok(())
}

/// Publishes `contents` at `path` below the secrets directory through a
/// rooted `tree`, as `ensure_secrets_dir` and `atomic_write` do by path,
/// except for owners: each directory level it creates is `0700` under the
/// owner of the level it is created in, the file is `0600` under the
/// owner of the file it replaces or, when fresh, of the directory it
/// lands in, and the directory is flushed.
pub(super) async fn publish_below_secrets(
    tree: &Arc<SecretsTree>,
    path: &Path,
    contents: &[u8],
    messages: &Messages,
) -> Result<()> {
    let target = path.to_path_buf();
    let payload = contents.to_vec();
    let failed = messages.error_write_file_failed(&path.display().to_string());
    tree.run(move |tree| {
        if let Some(parent) = target.parent() {
            tree.ensure_dir(parent)?;
        }
        tree.publish(
            fs_util::Destination::bootroot_owned(&target),
            &payload,
            fs_util::StagedMode::Policy(fs_util::KEY_FILE_MODE),
            RootedOwner::DestinationOrContainingDir,
            fs_util::StagedDurability::FlushDirectory,
        )
        .context(failed)
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::*;

    fn state_with_ttl(ttl: Option<&str>) -> StateFile {
        let mut value = serde_json::json!({
            "openbao_url": "http://localhost:8200",
            "kv_mount": "secret",
            "secrets_dir": "secrets",
            "policies": {},
            "approles": {},
            "services": {}
        });
        if let Some(ttl) = ttl {
            value["rotate_secret_id_ttl"] = serde_json::json!(ttl);
        }
        serde_json::from_value(value).unwrap()
    }

    /// The recorded TTL reaches the service role only when it parses to a
    /// positive duration; absent, zero, empty and unreadable values all
    /// fall back to the constant.
    #[test]
    fn service_role_secret_id_ttl_follows_positive_recorded_value() {
        assert_eq!(service_role_secret_id_ttl(&state_with_ttl(None)), "24h");
        for recorded in ["168h", "12h"] {
            assert_eq!(
                service_role_secret_id_ttl(&state_with_ttl(Some(recorded))),
                recorded
            );
        }
        for recorded in ["0", "0h", "", "abc"] {
            assert_eq!(
                service_role_secret_id_ttl(&state_with_ttl(Some(recorded))),
                SECRET_ID_TTL,
                "recorded {recorded:?} must fall back to the constant"
            );
        }
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// The default (no-override) write creates the secrets-tree directory
    /// `0700`, writes the file `0600`, and — unlike the override path —
    /// overwrites a stale file left by a previously removed service.
    #[tokio::test]
    async fn write_secret_id_file_default_creates_dir_and_overwrites() {
        let dir = tempdir().unwrap();
        let tree = Arc::new(SecretsTree::open(&dir.path().join("secrets")).unwrap());
        let secret_id_path = dir
            .path()
            .join("secrets")
            .join("services")
            .join("svc")
            .join("secret_id");
        let messages = crate::i18n::test_messages();

        write_secret_id_file(&tree, &secret_id_path, "sid-1", false, &messages)
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&secret_id_path).unwrap(), "sid-1");
        assert_eq!(mode_of(&secret_id_path), fs_util::KEY_FILE_MODE);
        assert_eq!(mode_of(secret_id_path.parent().unwrap()), 0o700);

        // The default path overwrites a stale file, as before.
        write_secret_id_file(&tree, &secret_id_path, "sid-2", false, &messages)
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&secret_id_path).unwrap(), "sid-2");
    }

    /// The override write requires an existing parent, produces a `0600`
    /// file, and refuses to clobber a pre-existing regular file.
    #[tokio::test]
    async fn write_role_id_file_override_is_0600_and_noclobber() {
        let dir = tempdir().unwrap();
        let tree = Arc::new(SecretsTree::open(dir.path()).unwrap());
        let agent_dir = dir.path().join("agent").join("svc");
        std::fs::create_dir_all(&agent_dir).unwrap();
        let role_id_path = agent_dir.join("role_id");
        let messages = crate::i18n::test_messages();

        write_role_id_file(&tree, &role_id_path, "rid", true, &messages)
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&role_id_path).unwrap(), "rid");
        assert_eq!(mode_of(&role_id_path), fs_util::KEY_FILE_MODE);

        let err = write_role_id_file(&tree, &role_id_path, "rid-2", true, &messages)
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("Refusing to overwrite"),
            "override role_id write must be no-clobber, got: {err:#}"
        );
    }

    #[tokio::test]
    async fn rooted_credential_writes_refuse_a_swapped_services_dir() {
        let root = crate::test_support::SwapRoot::new();
        root.write("services/svc/secret_id", "old");
        let tree = Arc::new(root.rooted());
        let messages = crate::i18n::test_messages();
        let before = root.outside_snapshot();
        let link = root.swap("services", &root.outside);
        let path = root.secrets.join("services").join("svc").join("secret_id");

        let err = write_secret_id_file(&tree, &path, "sid", false, &messages)
            .await
            .unwrap_err();
        crate::test_support::assert_error_names(&err, &link);
        let err = write_role_id_file(
            &tree,
            &root.secrets.join("services").join("svc").join("role_id"),
            "rid",
            false,
            &messages,
        )
        .await
        .unwrap_err();
        crate::test_support::assert_error_names(&err, &link);
        assert_eq!(root.outside_snapshot(), before);
    }

    #[tokio::test]
    async fn rooted_credential_writes_match_the_path_based_writes() {
        use std::os::unix::fs::MetadataExt;

        let messages = crate::i18n::test_messages();
        let mut results = Vec::new();
        for rooted in [false, true] {
            let root = crate::test_support::SwapRoot::new();
            let tree = Arc::new(if rooted {
                root.rooted()
            } else {
                SecretsTree::open(&root.secrets).unwrap()
            });
            let service_dir = root.secrets.join("services").join("svc");
            let secret_id = service_dir.join("secret_id");
            write_secret_id_file(&tree, &secret_id, "sid", false, &messages)
                .await
                .unwrap();
            results.push((
                std::fs::read(&secret_id).unwrap(),
                mode_of(&secret_id),
                std::fs::metadata(&secret_id).unwrap().uid(),
                mode_of(&service_dir),
            ));
            if rooted {
                // `services/` is an intermediate level the rooted write
                // created at `0700`.
                assert_eq!(mode_of(&root.secrets.join("services")), 0o700);
            }
        }
        assert_eq!(results[0], results[1]);
    }

    /// The directories and files a rooted `publish_below_secrets` creates
    /// for a remote-bootstrap `service add`, below a `secrets/` with no
    /// `services/` or `remote-bootstrap/` yet.
    fn remote_bootstrap_entries(secrets: &Path) -> (Vec<(PathBuf, &'static str)>, [PathBuf; 3]) {
        let services = secrets.join("services");
        let service_dir = services.join("svc");
        let bootstrap = secrets.join("remote-bootstrap");
        let bootstrap_services = bootstrap.join("services");
        let bootstrap_dir = bootstrap_services.join("svc");
        let files = [
            service_dir.join("role_id"),
            service_dir.join("secret_id"),
            bootstrap_dir.join("bootstrap.json"),
        ];
        let dirs = vec![
            (services, "services/"),
            (service_dir, "services/svc/"),
            (bootstrap, "remote-bootstrap/"),
            (bootstrap_services, "remote-bootstrap/services/"),
            (bootstrap_dir, "remote-bootstrap/services/svc/"),
        ];
        (dirs, files)
    }

    async fn publish_remote_bootstrap_entries(tree: &Arc<SecretsTree>, files: &[PathBuf; 3]) {
        let messages = crate::i18n::test_messages();
        for file in files {
            publish_below_secrets(tree, file, b"payload", &messages)
                .await
                .expect("publish below secrets");
        }
    }

    /// On a rooted handle every level `publish_below_secrets` creates
    /// takes the owner of the level it is created in, and every fresh
    /// file its directory's. `secrets/` takes a supplementary gid so the
    /// directory's group and the writer's differ on Linux, where a fresh
    /// entry takes the writer's primary gid; on macOS a fresh entry
    /// inherits its directory's group anyway. A replaced file keeps the
    /// writer's egid. Single-gid runners skip.
    #[tokio::test]
    async fn rooted_publish_below_secrets_gives_created_entries_the_directory_group() {
        let Some(gid) = bootroot::cert_group::one_supplementary_test_gid() else {
            return;
        };
        let root = crate::test_support::SwapRoot::new();
        std::os::unix::fs::chown(&root.secrets, None, Some(gid))
            .expect("test process must be able to chgrp to a supplementary gid");
        let owner = (fs_util::current_process_euid(), gid);
        let tree = Arc::new(root.rooted());
        let (dirs, files) = remote_bootstrap_entries(&root.secrets);

        publish_remote_bootstrap_entries(&tree, &files).await;

        for (dir, label) in &dirs {
            crate::test_support::assert_owner_and_mode(dir, owner, 0o700, label);
        }
        for file in &files {
            crate::test_support::assert_owner_and_mode(file, owner, 0o600, "a published file");
        }

        let egid = bootroot::cert_group::current_process_egid();
        let [_, secret_id, _] = &files;
        std::os::unix::fs::chown(secret_id, None, Some(egid)).expect("chgrp secret_id");
        publish_below_secrets(&tree, secret_id, b"replaced", &crate::i18n::test_messages())
            .await
            .expect("republish secret_id");
        crate::test_support::assert_owner_and_mode(
            secret_id,
            (owner.0, egid),
            0o600,
            "the replaced secret_id",
        );
    }

    /// As root over a `secrets/` another account owns, with no
    /// `services/` or `remote-bootstrap/` yet, the credentials and the
    /// bootstrap artifact a remote-bootstrap `service add` publishes,
    /// and every directory level above them, are owned by the uid and
    /// gid of `secrets/`: directories `0700`, files `0600`.
    #[tokio::test]
    async fn publish_below_secrets_gives_created_entries_the_secrets_owner_as_root_only() {
        use crate::test_support::{FOREIGN_OWNER, assert_owner_and_mode};

        if !crate::test_support::running_as_root_or_required() {
            return;
        }
        let foreign = (FOREIGN_OWNER, FOREIGN_OWNER);
        let dir = tempdir().unwrap();
        let secrets = crate::test_support::foreign_owned_secrets(dir.path());
        let tree = Arc::new(SecretsTree::open(&secrets).unwrap());
        assert!(tree.is_rooted(), "root over a foreign-owned tree is rooted");
        let (dirs, files) = remote_bootstrap_entries(&secrets);

        publish_remote_bootstrap_entries(&tree, &files).await;

        for (dir, label) in &dirs {
            assert_owner_and_mode(dir, foreign, 0o700, label);
        }
        for file in &files {
            assert_owner_and_mode(file, foreign, 0o600, "a published file");
        }
    }
}
