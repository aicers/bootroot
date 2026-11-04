use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use tempfile::tempdir;

use super::*;
use crate::fs_util::{FixedOwner, current_process_euid};

const PAYLOAD: &[u8] = b"published\n";

/// A `secrets/` directory inside a fresh `tempdir`, at `0700`.
fn secrets_in(root: &Path) -> PathBuf {
    let secrets = root.join("secrets");
    std::fs::create_dir(&secrets).expect("mkdir secrets");
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700))
        .expect("chmod secrets");
    secrets
}

fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .expect("stat")
        .permissions()
        .mode()
        & 0o7777
}

fn owner_of_path(path: &Path) -> (u32, u32) {
    let meta = std::fs::symlink_metadata(path).expect("stat");
    (meta.uid(), meta.gid())
}

fn writer() -> (u32, u32) {
    (
        current_process_euid(),
        crate::cert_group::current_process_egid(),
    )
}

/// Every entry below `root`, by relative path: its kind, mode, and the
/// contents of a file or the target of a link. What the swap tests
/// compare before and after to show nothing outside `secrets/` moved.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, (String, u32, Vec<u8>)> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, (String, u32, Vec<u8>)>) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let path = entry.expect("entry").path();
            let meta = std::fs::symlink_metadata(&path).expect("stat");
            let rel = path.strip_prefix(root).expect("below root").to_path_buf();
            let mode = meta.permissions().mode() & 0o7777;
            if meta.file_type().is_symlink() {
                let target = std::fs::read_link(&path).expect("readlink");
                out.insert(
                    rel,
                    (
                        "link".into(),
                        0,
                        target.as_os_str().as_encoded_bytes().to_vec(),
                    ),
                );
            } else if meta.is_dir() {
                out.insert(rel, ("dir".into(), mode, Vec::new()));
                walk(root, &path, out);
            } else {
                let contents = std::fs::read(&path).expect("read");
                out.insert(rel, ("file".into(), mode, contents));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// Every name below `root` that a staged temporary could carry.
fn stray_temporaries(root: &Path) -> Vec<PathBuf> {
    snapshot(root)
        .into_keys()
        .filter(|rel| {
            rel.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".tmp"))
        })
        .collect()
}

#[test]
fn rooted_mode_is_root_over_a_foreign_owned_tree_only() {
    assert!(rooted_mode(0, 1000));
    assert!(rooted_mode(0, 65_534));
    assert!(!rooted_mode(0, 0), "a root-owned tree has no other owner");
    assert!(!rooted_mode(1000, 1000), "the tree's own owner");
    assert!(!rooted_mode(1000, 2000), "a non-root writer");
    assert!(!rooted_mode(1000, 0), "a non-root writer over root's tree");
}

#[test]
fn open_gives_a_path_based_handle_for_a_missing_anchor_and_for_its_own_owner() {
    let root = tempdir().expect("tempdir");
    let missing = SecretsTree::open(&root.path().join("secrets")).expect("open missing");
    assert!(!missing.is_rooted());

    let secrets = secrets_in(root.path());
    let tree = SecretsTree::open(&secrets).expect("open");
    // The test process owns the tree it just made, root or not.
    assert!(!tree.is_rooted());
    assert!(
        SecretsTree::open_rooted_for_tests(&root.path().join("absent")).is_err(),
        "a forced rooted handle needs an anchor to walk from"
    );
}

#[test]
fn ensure_dir_creates_every_missing_level_at_0700_and_keeps_an_existing_parent() {
    for rooted in [false, true] {
        let root = tempdir().expect("tempdir");
        let secrets = secrets_in(root.path());
        let parent = secrets.join("parent");
        std::fs::create_dir(&parent).expect("mkdir parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let tree = if rooted {
            SecretsTree::open_rooted_for_tests(&secrets)
        } else {
            SecretsTree::open(&secrets)
        }
        .expect("open");

        let leaf = parent.join("a").join("b");
        tree.ensure_dir(&leaf).expect("ensure_dir");

        assert_eq!(mode_of(&parent.join("a")), 0o700, "rooted={rooted}");
        assert_eq!(mode_of(&leaf), 0o700, "rooted={rooted}");
        assert_eq!(mode_of(&parent), 0o755, "rooted={rooted}");
        // As non-root the nearest existing ancestor is the writer's own,
        // so no chown is attempted — one would fail — and both created
        // levels stay the writer's.
        assert_eq!(owner_of_path(&parent.join("a")), writer());
        assert_eq!(owner_of_path(&leaf), writer());
    }
}

#[test]
fn ensure_shared_secrets_dir_sets_two_missing_levels_0700() {
    let root = tempdir().expect("tempdir");
    let parent = root.path().join("existing");
    std::fs::create_dir(&parent).expect("mkdir");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o751)).expect("chmod");

    crate::fs_util::ensure_shared_secrets_dir_blocking(&parent.join("one").join("two"))
        .expect("ensure");

    assert_eq!(mode_of(&parent.join("one")), 0o700);
    assert_eq!(mode_of(&parent.join("one").join("two")), 0o700);
    assert_eq!(mode_of(&parent), 0o751);
}

#[test]
fn ensure_dir_ends_an_existing_last_level_0700_and_keeps_its_owner() {
    for rooted in [false, true] {
        let root = tempdir().expect("tempdir");
        let secrets = secrets_in(root.path());
        let existing = secrets.join("existing");
        std::fs::create_dir(&existing).expect("mkdir");
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let before = owner_of_path(&existing);
        let tree = if rooted {
            SecretsTree::open_rooted_for_tests(&secrets)
        } else {
            SecretsTree::open(&secrets)
        }
        .expect("open");

        tree.ensure_dir(&existing).expect("ensure_dir");

        assert_eq!(mode_of(&existing), 0o700, "rooted={rooted}");
        assert_eq!(owner_of_path(&existing), before, "rooted={rooted}");
    }
}

#[test]
fn rooted_ensure_dir_of_the_anchor_sets_its_mode() {
    let root = tempdir().expect("tempdir");
    let secrets = secrets_in(root.path());
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let tree = SecretsTree::open_rooted_for_tests(&secrets).expect("open");

    tree.ensure_dir(&secrets).expect("ensure anchor");

    assert_eq!(mode_of(&secrets), 0o700);
}

/// The swap: a level of the walk is replaced by a link to a directory
/// outside `secrets/` after the handle was opened.
#[test]
fn rooted_walk_refuses_a_level_swapped_for_a_symlink_after_open() {
    let root = tempdir().expect("tempdir");
    let secrets = secrets_in(root.path());
    let mid = secrets.join("mid");
    std::fs::create_dir_all(mid.join("sub")).expect("mkdir mid/sub");
    let outside = root.path().join("outside");
    std::fs::create_dir(&outside).expect("mkdir outside");
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    std::fs::write(outside.join("keep"), "outside\n").expect("seed outside");
    std::fs::set_permissions(outside.join("keep"), std::fs::Permissions::from_mode(0o644))
        .expect("chmod keep");
    let outside_before = snapshot(&outside);
    let outside_mode = mode_of(&outside);

    let tree = SecretsTree::open_rooted_for_tests(&secrets).expect("open");
    std::fs::rename(&mid, secrets.join("mid-aside")).expect("move mid aside");
    symlink(&outside, &mid).expect("plant link");

    let published = tree.publish(
        Destination::bootroot_owned(&mid.join("sub").join("file")),
        PAYLOAD,
        StagedMode::Policy(0o600),
        RootedOwner::ContainingDir,
        StagedDurability::RenameOnly,
    );
    let err = format!(
        "{:#}",
        published.expect_err("publish through a swapped level")
    );
    assert!(err.contains(&mid.display().to_string()), "{err}");

    let ensured = tree.ensure_dir(&mid.join("new"));
    let err = format!(
        "{:#}",
        ensured.expect_err("ensure_dir through a swapped level")
    );
    assert!(err.contains(&mid.display().to_string()), "{err}");

    assert_eq!(snapshot(&outside), outside_before);
    assert_eq!(mode_of(&outside), outside_mode);
    assert!(!outside.join("sub").exists());
    assert!(!outside.join("new").exists());
    assert_eq!(stray_temporaries(&secrets), Vec::<PathBuf>::new());
}

#[test]
fn rooted_ensure_dir_refuses_a_symlink_at_the_last_level() {
    let root = tempdir().expect("tempdir");
    let secrets = secrets_in(root.path());
    let outside = root.path().join("outside");
    std::fs::create_dir(&outside).expect("mkdir outside");
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let link = secrets.join("link");
    symlink(&outside, &link).expect("plant link");
    let tree = SecretsTree::open_rooted_for_tests(&secrets).expect("open");

    let err = format!("{:#}", tree.ensure_dir(&link).expect_err("refused"));

    assert!(err.contains(&link.display().to_string()), "{err}");
    assert_eq!(mode_of(&outside), 0o755);
}

#[test]
fn rooted_publish_refuses_an_operator_named_symlink_leaf() {
    let root = tempdir().expect("tempdir");
    let secrets = secrets_in(root.path());
    let target = root.path().join("target.yml");
    std::fs::write(&target, "operator\n").expect("seed target");
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).expect("chmod");
    let leaf = secrets.join("override.yml");
    symlink(&target, &leaf).expect("plant link");
    let tree = SecretsTree::open_rooted_for_tests(&secrets).expect("open");

    let err = tree
        .publish(
            Destination::operator_named(&leaf),
            PAYLOAD,
            StagedMode::PreserveOrUmask,
            RootedOwner::ContainingDir,
            StagedDurability::RenameOnly,
        )
        .expect_err("refused");

    assert!(format!("{err:#}").contains(&leaf.display().to_string()));
    assert_eq!(std::fs::read(&target).expect("read target"), b"operator\n");
    assert_eq!(mode_of(&target), 0o640);
    assert!(
        std::fs::symlink_metadata(&leaf)
            .expect("stat")
            .file_type()
            .is_symlink()
    );
    assert_eq!(stray_temporaries(&secrets), Vec::<PathBuf>::new());
}

#[test]
fn rooted_publish_replaces_a_bootroot_owned_symlink_leaf_at_the_stated_mode() {
    for mode in [
        StagedMode::Policy(0o640),
        StagedMode::PreserveOrCreate(0o600),
    ] {
        let root = tempdir().expect("tempdir");
        let secrets = secrets_in(root.path());
        let target = root.path().join("former-target");
        std::fs::write(&target, "old\n").expect("seed target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let leaf = secrets.join("keys.txt");
        symlink(&target, &leaf).expect("plant link");
        let tree = SecretsTree::open_rooted_for_tests(&secrets).expect("open");

        tree.publish(
            Destination::bootroot_owned(&leaf),
            PAYLOAD,
            mode,
            RootedOwner::ContainingDir,
            StagedDurability::FlushDirectory,
        )
        .expect("publish");

        let meta = std::fs::symlink_metadata(&leaf).expect("stat");
        assert!(meta.is_file(), "the link is replaced by the file");
        let expected = match mode {
            StagedMode::Policy(bits) | StagedMode::PreserveOrCreate(bits) => bits,
            StagedMode::PreserveOrUmask => unreachable!("not exercised here"),
        };
        assert_eq!(meta.permissions().mode() & 0o7777, expected);
        assert_eq!(std::fs::read(&leaf).expect("read"), PAYLOAD);
        assert_eq!(std::fs::read(&target).expect("read target"), b"old\n");
        assert_eq!(mode_of(&target), 0o644);
    }
}

#[test]
fn rooted_publish_that_fails_after_staging_leaves_no_temporary() {
    let root = tempdir().expect("tempdir");
    let secrets = secrets_in(root.path());
    let leaf = secrets.join("occupied");
    std::fs::create_dir(&leaf).expect("mkdir leaf");
    std::fs::write(leaf.join("inside"), "kept\n").expect("seed");
    let before = snapshot(&secrets);
    let tree = SecretsTree::open_rooted_for_tests(&secrets).expect("open");

    tree.publish(
        Destination::bootroot_owned(&leaf),
        PAYLOAD,
        StagedMode::Policy(0o600),
        RootedOwner::ContainingDir,
        StagedDurability::RenameOnly,
    )
    .expect_err("a file cannot be renamed over a directory");

    assert_eq!(stray_temporaries(&secrets), Vec::<PathBuf>::new());
    assert_eq!(snapshot(&secrets), before);
}

/// The rooted publish against the path-based one, under every owner a
/// rooted publish offers and every mode policy, onto an absent and onto
/// an existing destination. Both run in this one process, so the umask
/// that decides `PreserveOrUmask`'s create is the same for both.
#[test]
fn rooted_publish_matches_the_path_based_publish() {
    let modes = [
        StagedMode::Policy(0o640),
        StagedMode::PreserveOrUmask,
        StagedMode::PreserveOrCreate(0o600),
    ];
    for owner in [RootedOwner::ContainingDir, RootedOwner::Destination] {
        for (index, mode) in modes.iter().copied().enumerate() {
            for existing in [false, true] {
                let mut results = Vec::new();
                for rooted in [false, true] {
                    let root = tempdir().expect("tempdir");
                    let secrets = secrets_in(root.path());
                    let dir = secrets.join("dir");
                    std::fs::create_dir(&dir).expect("mkdir");
                    let dest = dir.join("file");
                    if existing {
                        std::fs::write(&dest, "previous\n").expect("seed");
                        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o604))
                            .expect("chmod");
                    }
                    let tree = if rooted {
                        SecretsTree::open_rooted_for_tests(&secrets)
                    } else {
                        SecretsTree::open(&secrets)
                    }
                    .expect("open");
                    assert_eq!(tree.is_rooted(), rooted);
                    tree.publish(
                        Destination::operator_named(&dest),
                        PAYLOAD,
                        mode,
                        owner,
                        StagedDurability::FlushDirectory,
                    )
                    .expect("publish");
                    assert_eq!(stray_temporaries(&secrets), Vec::<PathBuf>::new());
                    results.push((
                        std::fs::read(&dest).expect("read"),
                        mode_of(&dest),
                        owner_of_path(&dest),
                    ));
                }
                assert_eq!(
                    results[0], results[1],
                    "owner={owner:?} mode#{index} existing={existing}"
                );
                assert_eq!(results[1].0, PAYLOAD);
            }
        }
    }
}

/// `publish_staged_blocking` stats and chowns the staged file through
/// its descriptor now; for a writer whose names nobody races, each owner
/// policy still publishes what it did.
#[test]
fn publish_staged_blocking_publishes_the_same_under_each_owner_policy() {
    let owners = [
        StagedOwner::Destination,
        StagedOwner::WritingProcess,
        StagedOwner::PolicyGroup(None),
        StagedOwner::PolicyGroup(Some(crate::cert_group::current_process_egid())),
        StagedOwner::ContainingDir,
        StagedOwner::Fixed(FixedOwner::current_process()),
    ];
    for (index, owner) in owners.into_iter().enumerate() {
        for existing in [false, true] {
            let root = tempdir().expect("tempdir");
            let dest = root.path().join("file");
            if existing {
                std::fs::write(&dest, "previous\n").expect("seed");
                std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o604))
                    .expect("chmod");
            }
            publish_staged_blocking(
                &dest,
                PAYLOAD,
                StagedMode::PreserveOrCreate(0o640),
                owner,
                StagedDurability::RenameOnly,
            )
            .expect("publish");
            assert_eq!(std::fs::read(&dest).expect("read"), PAYLOAD);
            let expected = if existing { 0o604 } else { 0o640 };
            assert_eq!(mode_of(&dest), expected, "owner#{index}");
            assert_eq!(owner_of_path(&dest), writer(), "owner#{index}");
        }
    }
}

#[test]
fn rooted_normalize_modes_skips_a_symlink_and_changes_nothing_outside() {
    let root = tempdir().expect("tempdir");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o751))
        .expect("chmod root");
    let secrets = secrets_in(root.path());
    let inside_dir = secrets.join("dir");
    std::fs::create_dir(&inside_dir).expect("mkdir");
    std::fs::set_permissions(&inside_dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let inside_file = inside_dir.join("file");
    std::fs::write(&inside_file, "inside\n").expect("write");
    std::fs::set_permissions(&inside_file, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let outside = root.path().join("outside");
    std::fs::create_dir(&outside).expect("mkdir outside");
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    std::fs::write(outside.join("file"), "outside\n").expect("write outside");
    std::fs::set_permissions(outside.join("file"), std::fs::Permissions::from_mode(0o644))
        .expect("chmod");
    symlink(&outside, secrets.join("escape")).expect("plant link");
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o750))
        .expect("chmod secrets");

    SecretsTree::open_rooted_for_tests(&secrets)
        .expect("open")
        .normalize_modes()
        .expect("normalize");

    assert_eq!(mode_of(&inside_dir), 0o700);
    assert_eq!(mode_of(&inside_file), 0o600);
    assert_eq!(mode_of(&outside), 0o755);
    assert_eq!(mode_of(&outside.join("file")), 0o644);
    assert_eq!(
        mode_of(root.path()),
        0o751,
        "the directory holding secrets/"
    );
    assert_eq!(
        mode_of(&secrets),
        0o750,
        "the anchor's own mode is left alone"
    );
}

#[test]
fn path_based_normalize_modes_gives_the_modes_init_always_gave() {
    let root = tempdir().expect("tempdir");
    let secrets = secrets_in(root.path());
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o750))
        .expect("chmod secrets");
    let nested = secrets.join("a").join("b");
    std::fs::create_dir_all(&nested).expect("mkdir");
    std::fs::set_permissions(secrets.join("a"), std::fs::Permissions::from_mode(0o755))
        .expect("chmod");
    std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o775)).expect("chmod");
    std::fs::write(secrets.join("top"), "top\n").expect("write");
    std::fs::write(nested.join("deep"), "deep\n").expect("write");
    std::fs::set_permissions(nested.join("deep"), std::fs::Permissions::from_mode(0o644))
        .expect("chmod");

    let tree = SecretsTree::open(&secrets).expect("open");
    assert!(!tree.is_rooted());
    tree.normalize_modes().expect("normalize");

    assert_eq!(mode_of(&secrets.join("a")), 0o700);
    assert_eq!(mode_of(&nested), 0o700);
    assert_eq!(mode_of(&secrets.join("top")), 0o600);
    assert_eq!(mode_of(&nested.join("deep")), 0o600);
    assert_eq!(mode_of(&secrets), 0o750);
}

#[test]
fn rooted_set_file_mode_refuses_a_symlinked_leaf() {
    let root = tempdir().expect("tempdir");
    let secrets = secrets_in(root.path());
    let tls = secrets.join("tls");
    std::fs::create_dir(&tls).expect("mkdir");
    let target = root.path().join("elsewhere.key");
    std::fs::write(&target, "key\n").expect("write");
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let leaf = tls.join("server.key");
    symlink(&target, &leaf).expect("plant link");
    let tree = SecretsTree::open_rooted_for_tests(&secrets).expect("open");

    let err = format!(
        "{:#}",
        tree.set_file_mode(&leaf, 0o600).expect_err("refused")
    );

    assert!(err.contains(&leaf.display().to_string()), "{err}");
    assert_eq!(mode_of(&target), 0o644);
}

#[test]
fn set_file_mode_sets_the_mode_of_a_regular_file() {
    for rooted in [false, true] {
        let root = tempdir().expect("tempdir");
        let secrets = secrets_in(root.path());
        let file = secrets.join("server.crt");
        std::fs::write(&file, "crt\n").expect("write");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let tree = if rooted {
            SecretsTree::open_rooted_for_tests(&secrets)
        } else {
            SecretsTree::open(&secrets)
        }
        .expect("open");

        tree.set_file_mode(&file, 0o600).expect("chmod");

        assert_eq!(mode_of(&file), 0o600, "rooted={rooted}");
    }
}

#[test]
fn every_method_rejects_a_path_outside_the_anchor_or_holding_parent_components() {
    let root = tempdir().expect("tempdir");
    let secrets = secrets_in(root.path());
    let sibling = root.path().join("sibling");
    std::fs::create_dir(&sibling).expect("mkdir sibling");
    std::fs::write(sibling.join("file"), "kept\n").expect("write");
    std::fs::set_permissions(sibling.join("file"), std::fs::Permissions::from_mode(0o644))
        .expect("chmod");
    let before = snapshot(root.path());
    let bad = [
        sibling.join("file"),
        secrets.join("..").join("sibling").join("file"),
        secrets.join("dir").join("..").join("..").join("sibling"),
    ];

    for rooted in [false, true] {
        let tree = if rooted {
            SecretsTree::open_rooted_for_tests(&secrets)
        } else {
            SecretsTree::open(&secrets)
        }
        .expect("open");
        for path in &bad {
            let shown = path.display().to_string();
            let errors = [
                tree.ensure_dir(path).expect_err("ensure_dir"),
                tree.publish(
                    Destination::bootroot_owned(path),
                    PAYLOAD,
                    StagedMode::Policy(0o600),
                    RootedOwner::ContainingDir,
                    StagedDurability::RenameOnly,
                )
                .expect_err("publish"),
                tree.set_file_mode(path, 0o600).expect_err("set_file_mode"),
            ];
            for err in errors {
                assert!(
                    format!("{err:#}").contains(&shown),
                    "rooted={rooted}: {err:#}"
                );
            }
        }
    }
    assert_eq!(snapshot(root.path()), before);
}

#[tokio::test]
async fn async_wrappers_run_the_blocking_methods() {
    let root = tempdir().expect("tempdir");
    let secrets = secrets_in(root.path());
    let tree = SecretsTree::open_shared(&secrets).await.expect("open");
    let dir = secrets.join("x").join("y");
    tree.ensure_dir_async(&dir).await.expect("ensure");
    let dest = dir.join("file");
    tree.publish_async(
        Destination::bootroot_owned(&dest),
        PAYLOAD,
        StagedMode::Policy(0o600),
        RootedOwner::ContainingDir,
        StagedDurability::FlushDirectory,
    )
    .await
    .expect("publish");
    assert_eq!(std::fs::read(&dest).expect("read"), PAYLOAD);
    assert_eq!(mode_of(&secrets.join("x")), 0o700);
}
