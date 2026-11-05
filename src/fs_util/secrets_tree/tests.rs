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

/// One recorded entry: its kind, mode, uid, gid, and the contents of a
/// file or the target of a link.
type Entry = (String, u32, u32, u32, Vec<u8>);

/// `root` itself, under the empty relative path, and every entry below
/// it, by relative path, read without following a link. What the swap
/// tests compare before and after to show nothing outside `secrets/`
/// moved or changed owner.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn record(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Entry>) {
        let meta = std::fs::symlink_metadata(path).expect("stat");
        let rel = path.strip_prefix(root).expect("below root").to_path_buf();
        let mode = meta.permissions().mode() & 0o7777;
        let (uid, gid) = (meta.uid(), meta.gid());
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(path).expect("readlink");
            out.insert(
                rel,
                (
                    "link".into(),
                    0,
                    uid,
                    gid,
                    target.as_os_str().as_encoded_bytes().to_vec(),
                ),
            );
        } else if meta.is_dir() {
            out.insert(rel, ("dir".into(), mode, uid, gid, Vec::new()));
            for entry in std::fs::read_dir(path).expect("read_dir") {
                record(root, &entry.expect("entry").path(), out);
            }
        } else {
            let contents = std::fs::read(path).expect("read");
            out.insert(rel, ("file".into(), mode, uid, gid, contents));
        }
    }
    let mut out = BTreeMap::new();
    record(root, root, &mut out);
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

/// `DestinationOrContainingDir` gives a fresh file and one replacing a
/// leaf link the directory's owner, keeps the owner of a regular file it
/// replaces, and maps to `StagedOwner::Destination` by path. The
/// directory takes a supplementary gid and the replaced file the
/// writer's egid, so the two owners differ on every platform; a fresh
/// file discriminates only on Linux, where it takes the writer's primary
/// gid rather than inheriting its directory's. Single-gid runners skip.
#[test]
fn rooted_publish_destination_or_containing_dir_keeps_only_a_replaced_file_owner() {
    assert!(matches!(
        StagedOwner::from(RootedOwner::DestinationOrContainingDir),
        StagedOwner::Destination
    ));
    let Some(gid) = crate::cert_group::one_supplementary_test_gid() else {
        return;
    };
    let egid = crate::cert_group::current_process_egid();
    let dir_owner = (current_process_euid(), gid);
    for case in ["fresh", "regular", "link"] {
        let root = tempdir().expect("tempdir");
        let secrets = secrets_in(root.path());
        let dir = secrets.join("dir");
        std::fs::create_dir(&dir).expect("mkdir");
        std::os::unix::fs::chown(&dir, None, Some(gid))
            .expect("test process must be able to chgrp to a supplementary gid");
        let dest = dir.join("file");
        let target = root.path().join("target");
        match case {
            "regular" => {
                std::fs::write(&dest, "previous\n").expect("seed");
                std::os::unix::fs::chown(&dest, None, Some(egid)).expect("chgrp");
            }
            "link" => {
                std::fs::write(&target, "outside\n").expect("seed target");
                std::os::unix::fs::chown(&target, None, Some(egid)).expect("chgrp target");
                symlink(&target, &dest).expect("plant link");
            }
            _ => {}
        }
        let tree = SecretsTree::open_rooted_for_tests(&secrets).expect("open");

        tree.publish(
            Destination::bootroot_owned(&dest),
            PAYLOAD,
            StagedMode::Policy(0o600),
            RootedOwner::DestinationOrContainingDir,
            StagedDurability::FlushDirectory,
        )
        .expect("publish");

        let meta = std::fs::symlink_metadata(&dest).expect("stat");
        assert!(meta.is_file(), "{case}");
        assert_eq!(mode_of(&dest), 0o600, "{case}");
        assert_eq!(std::fs::read(&dest).expect("read"), PAYLOAD, "{case}");
        let expected = if case == "regular" {
            (current_process_euid(), egid)
        } else {
            dir_owner
        };
        assert_eq!(owner_of_path(&dest), expected, "{case}");
        if case == "link" {
            assert_eq!(std::fs::read(&target).expect("read target"), b"outside\n");
            assert_eq!(
                owner_of_path(&target).1,
                egid,
                "the former target keeps its group"
            );
        }
        assert_eq!(stray_temporaries(&secrets), Vec::<PathBuf>::new(), "{case}");
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

/// The message [`SecretsTree::relative`] refuses a path's spelling with,
/// which a lookup failure never carries.
const NOT_PLAIN: &str = "by plain names alone";

/// Every entry below `root` with its owner, beside what [`snapshot`]
/// records, for the refusals that must leave owners alone too.
fn owners_below(root: &Path) -> BTreeMap<PathBuf, (u32, u32)> {
    snapshot(root)
        .into_keys()
        .map(|rel| {
            let owner = owner_of_path(&root.join(&rel));
            (rel, owner)
        })
        .collect()
}

/// `path` with `suffix` appended to its bytes as they stand, so a
/// spelling `Path::join` would normalise survives.
fn spelled(path: &Path, suffix: &str) -> PathBuf {
    let mut raw = path.as_os_str().to_os_string();
    raw.push(suffix);
    PathBuf::from(raw)
}

fn open_tree(secrets: &Path, rooted: bool) -> SecretsTree {
    let tree = if rooted {
        SecretsTree::open_rooted_for_tests(secrets)
    } else {
        SecretsTree::open(secrets)
    }
    .expect("open");
    assert_eq!(tree.is_rooted(), rooted);
    tree
}

/// A `secrets/` at `0755` holding `dir/` at `0755` and `dir/file` at
/// `0644`, so a path that reaches an existing entry once its `.` is
/// dropped would succeed — and chmod something — were it not refused.
fn dotted_fixture(root: &Path) -> PathBuf {
    let secrets = secrets_in(root);
    let dir = secrets.join("dir");
    std::fs::create_dir(&dir).expect("mkdir dir");
    std::fs::write(dir.join("file"), "kept\n").expect("write file");
    std::fs::set_permissions(dir.join("file"), std::fs::Permissions::from_mode(0o644))
        .expect("chmod file");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod dir");
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o755))
        .expect("chmod secrets");
    secrets
}

/// Literal `.` components immediately below the anchor, inside the
/// remainder and at its end, each spelled so that dropping the `.` would
/// leave an entry that exists.
fn dotted_paths(secrets: &Path) -> Vec<PathBuf> {
    vec![
        spelled(secrets, "/."),
        spelled(secrets, "/./"),
        spelled(secrets, "/./dir"),
        spelled(secrets, "/./dir/file"),
        spelled(secrets, "/dir/./file"),
        spelled(secrets, "/dir/."),
        spelled(secrets, "/dir/./"),
        spelled(secrets, "/dir/file/."),
        spelled(secrets, "/dir//./file"),
    ]
}

fn assert_refused(err: &anyhow::Error, path: &Path, what: &str) {
    let shown = format!("{err:#}");
    assert!(
        shown.contains(&path.display().to_string()),
        "{what} {}: {shown}",
        path.display()
    );
    assert!(
        shown.contains(NOT_PLAIN),
        "{what} {}: refused for another reason: {shown}",
        path.display()
    );
}

#[test]
fn every_method_rejects_a_literal_dot_below_the_anchor() {
    for rooted in [false, true] {
        let root = tempdir().expect("tempdir");
        let secrets = dotted_fixture(root.path());
        let before = snapshot(root.path());
        let owners = owners_below(root.path());
        let tree = open_tree(&secrets, rooted);

        for path in dotted_paths(&secrets) {
            let what = format!("rooted={rooted}");
            let err = tree.ensure_dir(&path).expect_err("ensure_dir");
            assert_refused(&err, &path, &format!("{what} ensure_dir"));
            for dest in [
                Destination::bootroot_owned(&path),
                Destination::operator_named(&path),
            ] {
                let err = tree
                    .publish(
                        dest,
                        PAYLOAD,
                        StagedMode::Policy(0o600),
                        RootedOwner::ContainingDir,
                        StagedDurability::RenameOnly,
                    )
                    .expect_err("publish");
                assert_refused(&err, &path, &format!("{what} publish"));
            }
            let err = tree.set_file_mode(&path, 0o600).expect_err("set_file_mode");
            assert_refused(&err, &path, &format!("{what} set_file_mode"));
        }

        assert_eq!(snapshot(root.path()), before, "rooted={rooted}");
        assert_eq!(owners_below(root.path()), owners, "rooted={rooted}");
        assert_eq!(mode_of(&secrets), 0o755, "the anchor is not chmodded");
        assert_eq!(stray_temporaries(root.path()), Vec::<PathBuf>::new());
    }
}

#[tokio::test]
async fn async_wrappers_reject_a_literal_dot_below_the_anchor() {
    for rooted in [false, true] {
        let root = tempdir().expect("tempdir");
        let secrets = dotted_fixture(root.path());
        let before = snapshot(root.path());
        let owners = owners_below(root.path());
        let tree = Arc::new(open_tree(&secrets, rooted));

        for path in dotted_paths(&secrets) {
            let what = format!("rooted={rooted}");
            let err = tree.ensure_dir_async(&path).await.expect_err("ensure_dir");
            assert_refused(&err, &path, &format!("{what} ensure_dir_async"));
            let err = tree
                .publish_async(
                    Destination::bootroot_owned(&path),
                    PAYLOAD,
                    StagedMode::Policy(0o600),
                    RootedOwner::ContainingDir,
                    StagedDurability::FlushDirectory,
                )
                .await
                .expect_err("publish");
            assert_refused(&err, &path, &format!("{what} publish_async"));
        }

        assert_eq!(snapshot(root.path()), before, "rooted={rooted}");
        assert_eq!(owners_below(root.path()), owners, "rooted={rooted}");
        assert_eq!(mode_of(&secrets), 0o755, "the anchor is not chmodded");
        assert_eq!(stray_temporaries(root.path()), Vec::<PathBuf>::new());
    }
}

/// A prefix spelled differently from the anchor still matches it by
/// components, and the `.` below it is still found in the remainder.
#[test]
fn a_literal_dot_is_refused_below_a_differently_spelled_anchor_prefix() {
    for rooted in [false, true] {
        let root = tempdir().expect("tempdir");
        let secrets = dotted_fixture(root.path());
        let before = snapshot(root.path());
        let tree = open_tree(&secrets, rooted);
        let respelled = spelled(root.path(), "//./secrets");

        for suffix in ["/./dir/file", "/dir/./file", "/dir/file/."] {
            let path = spelled(&respelled, suffix);
            let err = tree.set_file_mode(&path, 0o600).expect_err("set_file_mode");
            assert_refused(&err, &path, &format!("rooted={rooted} set_file_mode"));
            let err = tree.ensure_dir(&path).expect_err("ensure_dir");
            assert_refused(&err, &path, &format!("rooted={rooted} ensure_dir"));
        }
        assert_eq!(snapshot(root.path()), before, "rooted={rooted}");

        let file = spelled(&respelled, "/dir/file");
        tree.set_file_mode(&file, 0o600)
            .expect("the respelled prefix still matches the anchor");
        assert_eq!(mode_of(&secrets.join("dir").join("file")), 0o600);
    }
}

#[test]
fn dotted_names_separators_and_the_anchor_keep_their_handling() {
    for rooted in [false, true] {
        let root = tempdir().expect("tempdir");
        let secrets = dotted_fixture(root.path());
        let tree = open_tree(&secrets, rooted);

        let hidden = secrets.join(".hidden");
        tree.ensure_dir(&hidden).expect("ensure_dir .hidden");
        assert_eq!(mode_of(&hidden), 0o700, "rooted={rooted}");
        let pem = hidden.join("file.pem");
        tree.publish(
            Destination::bootroot_owned(&pem),
            PAYLOAD,
            StagedMode::Policy(0o640),
            RootedOwner::ContainingDir,
            StagedDurability::FlushDirectory,
        )
        .expect("publish .hidden/file.pem");
        assert_eq!(std::fs::read(&pem).expect("read"), PAYLOAD);
        tree.set_file_mode(&pem, 0o600).expect("set_file_mode");
        assert_eq!(mode_of(&pem), 0o600, "rooted={rooted}");

        let doubled = spelled(&secrets, "//dir//file");
        tree.publish(
            Destination::bootroot_owned(&doubled),
            PAYLOAD,
            StagedMode::Policy(0o640),
            RootedOwner::ContainingDir,
            StagedDurability::RenameOnly,
        )
        .expect("publish through repeated separators");
        assert_eq!(
            std::fs::read(secrets.join("dir").join("file")).expect("read"),
            PAYLOAD
        );
        tree.set_file_mode(&doubled, 0o604)
            .expect("set_file_mode through repeated separators");
        assert_eq!(mode_of(&secrets.join("dir").join("file")), 0o604);

        tree.ensure_dir(&spelled(&secrets, "/dir/"))
            .expect("ensure_dir with a trailing separator");
        assert_eq!(mode_of(&secrets.join("dir")), 0o700, "rooted={rooted}");

        tree.ensure_dir(&spelled(&secrets, "/"))
            .expect("ensure_dir of the anchor with a trailing separator");
        assert_eq!(mode_of(&secrets), 0o700, "rooted={rooted}");

        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o755))
            .expect("chmod secrets");
        tree.ensure_dir(&secrets).expect("ensure_dir of the anchor");
        assert_eq!(mode_of(&secrets), 0o700, "rooted={rooted}");
    }
}

/// An anchor whose own spelling holds a `.` keeps accepting itself and
/// the paths a site builds by joining plain names onto it.
#[test]
fn an_anchor_spelled_with_a_dot_accepts_names_joined_onto_it() {
    for rooted in [false, true] {
        let root = tempdir().expect("tempdir");
        let secrets = dotted_fixture(root.path());
        for anchor in [spelled(&secrets, "/."), spelled(&secrets, "/")] {
            std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o755))
                .expect("chmod secrets");
            let tree = open_tree(&anchor, rooted);

            tree.ensure_dir(&anchor).expect("ensure_dir of the anchor");
            assert_eq!(mode_of(&secrets), 0o700, "{}", anchor.display());

            let file = anchor.join("dir").join("file");
            tree.set_file_mode(&file, 0o640).expect("set_file_mode");
            assert_eq!(mode_of(&secrets.join("dir").join("file")), 0o640);

            let below = spelled(&anchor.join("dir"), "/./file");
            let err = tree.set_file_mode(&below, 0o600).expect_err("refused");
            assert_refused(&err, &below, &anchor.display().to_string());
        }
    }
}

/// The byte walk cuts a path after exactly the components
/// `Path::components` yields for it, whatever separators and `.`s the
/// spelling holds, and reports a path that is too short.
#[test]
fn offset_after_components_counts_as_path_components_does() {
    let spellings = [
        "",
        ".",
        "./",
        "/",
        "//",
        "a",
        "a/",
        "./a",
        "/./a",
        "a//b",
        "a/./b",
        "a/b/.",
        "a/b/./",
        "//./a//./b/./c",
        "./a/./b",
        "/a/.hidden/b",
        "a/../b",
    ];
    for spelling in spellings {
        let total = Path::new(spelling).components().count();
        for count in 0..=total {
            let offset = offset_after_components(spelling.as_bytes(), count)
                .unwrap_or_else(|| panic!("{spelling:?} has {count} components"));
            let (head, tail) = spelling.split_at(offset);
            let components: Vec<_> = Path::new(spelling).components().collect();
            assert_eq!(
                Path::new(head).components().collect::<Vec<_>>(),
                components.get(..count).expect("count is within total"),
                "{spelling:?} cut after {count}"
            );
            if count == 0 {
                assert_eq!(tail, spelling);
                continue;
            }
            // Past the cut every later `.` and empty segment is one
            // `Path::components` skips, so the rest are its names.
            let rest: Vec<_> = tail
                .split('/')
                .filter(|segment| !segment.is_empty() && *segment != ".")
                .map(OsStr::new)
                .collect();
            let expected: Vec<_> = components
                .iter()
                .skip(count)
                .map(|component| component.as_os_str())
                .collect();
            assert_eq!(rest, expected, "{spelling:?} cut after {count}");
        }
        assert_eq!(
            offset_after_components(spelling.as_bytes(), total + 1),
            None,
            "{spelling:?}"
        );
    }
}

/// A `secrets/` holding `a/b/file` and a sibling `outside/` holding a
/// recorded file and a directory, as the swap tests below share.
struct SwapFixture {
    _root: tempfile::TempDir,
    root: PathBuf,
    secrets: PathBuf,
    outside: PathBuf,
}

impl SwapFixture {
    fn new() -> Self {
        let root = tempdir().expect("tempdir");
        let base = root.path().to_path_buf();
        let secrets = secrets_in(&base);
        let leaf_dir = secrets.join("a").join("b");
        std::fs::create_dir_all(&leaf_dir).expect("mkdir a/b");
        std::fs::write(leaf_dir.join("file"), "inside\n").expect("seed inside");
        let outside = base.join("outside");
        std::fs::create_dir_all(outside.join("b")).expect("mkdir outside/b");
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755))
            .expect("chmod outside");
        std::fs::write(outside.join("b").join("file"), "outside secret\n").expect("seed");
        std::fs::write(outside.join("secret"), "outside secret\n").expect("seed");
        Self {
            _root: root,
            root: base,
            secrets,
            outside,
        }
    }

    fn rooted(&self) -> SecretsTree {
        SecretsTree::open_rooted_for_tests(&self.secrets).expect("open rooted")
    }

    /// Replaces `secrets/a` with a link to `outside/`.
    fn swap_intermediate(&self) {
        let a = self.secrets.join("a");
        std::fs::rename(&a, self.root.join("a-aside")).expect("move a aside");
        symlink(&self.outside, &a).expect("plant link");
    }

    /// Replaces `secrets/a/b/file` with a link to `outside/secret`.
    fn swap_leaf(&self) {
        let leaf = self.secrets.join("a").join("b").join("file");
        std::fs::remove_file(&leaf).expect("rm leaf");
        symlink(self.outside.join("secret"), &leaf).expect("plant leaf link");
    }

    fn leaf(&self) -> PathBuf {
        self.secrets.join("a").join("b").join("file")
    }
}

fn assert_names(err: &std::io::Error, path: &Path) {
    let shown = err.to_string();
    assert!(shown.contains(&path.display().to_string()), "{shown}");
}

#[test]
fn rooted_read_reads_a_regular_file_and_refuses_links_at_every_level() {
    let fixture = SwapFixture::new();
    let tree = fixture.rooted();
    assert_eq!(tree.read(&fixture.leaf()).expect("read"), b"inside\n");

    fixture.swap_leaf();
    let err = tree.read(&fixture.leaf()).expect_err("leaf link");
    assert_names(&err, &fixture.leaf());

    let fixture = SwapFixture::new();
    let tree = fixture.rooted();
    let before = snapshot(&fixture.outside);
    fixture.swap_intermediate();
    let err = tree.read(&fixture.leaf()).expect_err("intermediate link");
    assert_names(&err, &fixture.secrets.join("a"));
    assert_ne!(err.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(snapshot(&fixture.outside), before);
}

#[test]
fn rooted_read_reports_a_missing_leaf_or_level_as_not_found() {
    let fixture = SwapFixture::new();
    let tree = fixture.rooted();
    let missing_leaf = tree
        .read(&fixture.secrets.join("a").join("b").join("absent"))
        .expect_err("missing leaf");
    assert_eq!(missing_leaf.kind(), std::io::ErrorKind::NotFound);
    let missing_level = tree
        .read(&fixture.secrets.join("templates").join("ca.json.ctmpl"))
        .expect_err("missing level");
    assert_eq!(missing_level.kind(), std::io::ErrorKind::NotFound);
    assert_names(&missing_level, &fixture.secrets.join("templates"));
}

#[test]
fn rooted_read_refuses_a_fifo_without_blocking_and_a_directory() {
    let fixture = SwapFixture::new();
    let fifo = fixture.secrets.join("fifo");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("run mkfifo");
    assert!(status.success());
    let tree = fixture.rooted();
    let err = tree.read(&fifo).expect_err("fifo refused");
    assert_names(&err, &fifo);
    let err = tree
        .read(&fixture.secrets.join("a"))
        .expect_err("directory refused");
    assert_names(&err, &fixture.secrets.join("a"));
}

#[test]
fn rooted_remove_file_unlinks_a_leaf_link_and_refuses_an_intermediate_one() {
    let fixture = SwapFixture::new();
    let tree = fixture.rooted();
    let before = snapshot(&fixture.outside);
    fixture.swap_leaf();
    tree.remove_file(&fixture.leaf()).expect("unlink leaf link");
    assert!(std::fs::symlink_metadata(fixture.leaf()).is_err());
    assert_eq!(snapshot(&fixture.outside), before);

    let fixture = SwapFixture::new();
    let tree = fixture.rooted();
    let before = snapshot(&fixture.outside);
    fixture.swap_intermediate();
    let err = tree.remove_file(&fixture.leaf()).expect_err("refused");
    assert_names(&err, &fixture.secrets.join("a"));
    assert_eq!(snapshot(&fixture.outside), before);

    let missing = tree
        .remove_file(&fixture.secrets.join("nope").join("file"))
        .expect_err("missing");
    assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn rooted_remove_dir_all_unlinks_inner_links_without_descending() {
    let fixture = SwapFixture::new();
    let tree = fixture.rooted();
    let target = fixture.secrets.join("a");
    symlink(&fixture.outside, target.join("b").join("to-outside")).expect("inner link");
    symlink(fixture.outside.join("secret"), target.join("to-file")).expect("inner link");
    let before = snapshot(&fixture.outside);
    tree.remove_dir_all(&target).expect("remove_dir_all");
    assert!(std::fs::symlink_metadata(&target).is_err());
    assert_eq!(snapshot(&fixture.outside), before);
}

#[test]
fn rooted_remove_dir_all_unlinks_a_target_link_and_refuses_an_intermediate_one() {
    let fixture = SwapFixture::new();
    let tree = fixture.rooted();
    let before = snapshot(&fixture.outside);
    fixture.swap_intermediate();
    // The target itself is a link: unlinked, not followed.
    tree.remove_dir_all(&fixture.secrets.join("a"))
        .expect("unlink target link");
    assert!(std::fs::symlink_metadata(fixture.secrets.join("a")).is_err());
    assert_eq!(snapshot(&fixture.outside), before);

    let fixture = SwapFixture::new();
    let tree = fixture.rooted();
    let before = snapshot(&fixture.outside);
    fixture.swap_intermediate();
    let err = tree
        .remove_dir_all(&fixture.secrets.join("a").join("b"))
        .expect_err("intermediate link");
    assert_names(&err, &fixture.secrets.join("a"));
    assert_eq!(snapshot(&fixture.outside), before);

    let missing = tree
        .remove_dir_all(&fixture.secrets.join("absent"))
        .expect_err("missing");
    assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn rooted_read_dir_and_entry_kind_read_without_following() {
    let fixture = SwapFixture::new();
    let b = fixture.secrets.join("a").join("b");
    symlink(&fixture.outside, b.join("link")).expect("link");
    std::fs::create_dir(b.join("sub")).expect("mkdir sub");
    let tree = fixture.rooted();
    let mut listed = tree.read_dir(&b).expect("read_dir");
    listed.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        listed,
        vec![
            (OsString::from("file"), EntryKind::File),
            (OsString::from("link"), EntryKind::Symlink),
            (OsString::from("sub"), EntryKind::Dir),
        ]
    );
    assert_eq!(
        tree.entry_kind(&b.join("link")).expect("kind"),
        Some(EntryKind::Symlink)
    );
    assert_eq!(
        tree.entry_kind(&b.join("sub")).expect("kind"),
        Some(EntryKind::Dir)
    );
    assert_eq!(tree.entry_kind(&b.join("absent")).expect("kind"), None);
    assert_eq!(
        tree.entry_kind(&fixture.secrets.join("x").join("y").join("z"))
            .expect("kind"),
        None,
        "a missing intermediate level is absent"
    );

    let before = snapshot(&fixture.outside);
    fixture.swap_intermediate();
    let err = tree.read_dir(&b).expect_err("read_dir through a link");
    assert_names(&err, &fixture.secrets.join("a"));
    let err = tree
        .entry_kind(&b.join("file"))
        .expect_err("entry_kind through a link");
    assert_names(&err, &fixture.secrets.join("a"));
    assert_eq!(snapshot(&fixture.outside), before);
}

#[test]
fn rooted_read_dir_refuses_a_link_at_the_listed_directory() {
    let fixture = SwapFixture::new();
    let tree = fixture.rooted();
    let before = snapshot(&fixture.outside);
    let b = fixture.secrets.join("a").join("b");
    std::fs::rename(&b, fixture.root.join("b-aside")).expect("move b aside");
    symlink(&fixture.outside, &b).expect("plant link");
    let err = tree
        .read_dir(&b)
        .expect_err("a link at the listed directory");
    assert_names(&err, &b);
    assert_eq!(snapshot(&fixture.outside), before);
}

#[test]
fn rooted_ensure_dir_fixed_creates_missing_levels_0700_under_the_owner() {
    let fixture = SwapFixture::new();
    let tree = fixture.rooted();
    let first = fixture.secrets.join("new");
    let second = first.join("deeper");
    tree.ensure_dir_fixed(&second, FixedOwner::current_process())
        .expect("ensure_dir_fixed");
    assert_eq!(mode_of(&first), 0o700);
    assert_eq!(mode_of(&second), 0o700);
    assert_eq!(owner_of_path(&first), writer());
    assert_eq!(owner_of_path(&second), writer());

    // An existing last level keeps its owner and ends 0700.
    std::fs::set_permissions(&second, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    tree.ensure_dir_fixed(&second, FixedOwner::current_process())
        .expect("again");
    assert_eq!(mode_of(&second), 0o700);

    let before = snapshot(&fixture.outside);
    let outside_mode = mode_of(&fixture.outside);
    fixture.swap_intermediate();
    let err = tree
        .ensure_dir_fixed(
            &fixture.secrets.join("a").join("c"),
            FixedOwner::current_process(),
        )
        .expect_err("intermediate link");
    assert_names(&err, &fixture.secrets.join("a"));
    let leaf_link = fixture.secrets.join("leaf-link");
    symlink(&fixture.outside, &leaf_link).expect("leaf link");
    let err = tree
        .ensure_dir_fixed(&leaf_link, FixedOwner::current_process())
        .expect_err("leaf link");
    assert_names(&err, &leaf_link);
    assert_eq!(snapshot(&fixture.outside), before);
    assert_eq!(mode_of(&fixture.outside), outside_mode);
}

#[test]
fn rooted_adopt_dir_keeps_an_owned_dir_and_refuses_links() {
    let fixture = SwapFixture::new();
    let tree = fixture.rooted();
    let b = fixture.secrets.join("a").join("b");
    tree.adopt_dir(&b).expect("adopt");
    assert_eq!(owner_of_path(&b), owner_of_path(&fixture.secrets));

    let before = snapshot(&fixture.outside);
    let leaf_link = fixture.secrets.join("leaf-link");
    symlink(&fixture.outside, &leaf_link).expect("leaf link");
    let err = tree.adopt_dir(&leaf_link).expect_err("leaf link");
    assert_names(&err, &leaf_link);
    assert_eq!(snapshot(&fixture.outside), before);
    fixture.swap_intermediate();
    let err = tree.adopt_dir(&b).expect_err("intermediate link");
    assert_names(&err, &fixture.secrets.join("a"));
    assert_eq!(snapshot(&fixture.outside), before);
}

#[test]
fn rooted_publish_with_a_fixed_owner_matches_the_path_based_fixed_publish() {
    let mut results = Vec::new();
    for rooted in [false, true] {
        let root = tempdir().expect("tempdir");
        let secrets = secrets_in(root.path());
        let dest = secrets.join("file");
        let tree = if rooted {
            SecretsTree::open_rooted_for_tests(&secrets)
        } else {
            SecretsTree::open(&secrets)
        }
        .expect("open");
        tree.publish(
            Destination::bootroot_owned(&dest),
            PAYLOAD,
            StagedMode::Policy(0o600),
            RootedOwner::Fixed(FixedOwner::current_process()),
            StagedDurability::FlushDirectory,
        )
        .expect("publish");
        results.push((
            std::fs::read(&dest).expect("read"),
            mode_of(&dest),
            owner_of_path(&dest),
        ));
    }
    assert_eq!(results[0], results[1]);
    assert_eq!(results[1], (PAYLOAD.to_vec(), 0o600, writer()));

    let fixture = SwapFixture::new();
    let tree = fixture.rooted();
    let before = snapshot(&fixture.outside);
    fixture.swap_leaf();
    // A bootroot-owned leaf link is replaced, never followed.
    tree.publish(
        Destination::bootroot_owned(&fixture.leaf()),
        PAYLOAD,
        StagedMode::Policy(0o600),
        RootedOwner::Fixed(FixedOwner::current_process()),
        StagedDurability::RenameOnly,
    )
    .expect("replace leaf link");
    assert_eq!(std::fs::read(fixture.leaf()).expect("read"), PAYLOAD);
    fixture.swap_intermediate();
    let err = tree
        .publish(
            Destination::bootroot_owned(&fixture.leaf()),
            PAYLOAD,
            StagedMode::Policy(0o600),
            RootedOwner::Fixed(FixedOwner::current_process()),
            StagedDurability::RenameOnly,
        )
        .expect_err("intermediate link");
    assert!(format!("{err:#}").contains(&fixture.secrets.join("a").display().to_string()));
    assert_eq!(snapshot(&fixture.outside), before);
}

#[test]
fn rooted_only_methods_are_unsupported_on_a_path_based_handle() {
    let fixture = SwapFixture::new();
    let tree = SecretsTree::open(&fixture.secrets).expect("open");
    assert!(!tree.is_rooted());
    let leaf = fixture.leaf();
    let dir = fixture.secrets.join("a");
    let errors = [
        tree.read(&leaf).expect_err("read"),
        tree.remove_file(&leaf).expect_err("remove_file"),
        tree.remove_dir_all(&dir).expect_err("remove_dir_all"),
        tree.read_dir(&dir).expect_err("read_dir"),
        tree.entry_kind(&leaf).expect_err("entry_kind"),
        tree.ensure_dir_fixed(&dir, FixedOwner::current_process())
            .expect_err("ensure_dir_fixed"),
        tree.adopt_dir(&dir).expect_err("adopt_dir"),
    ];
    for err in errors {
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported, "{err}");
    }
    assert!(leaf.exists(), "nothing was removed");
}

#[test]
fn root_by_policy_dirs_must_be_owned_by_the_recorded_writer() {
    let root = tempdir().expect("tempdir");
    let secrets = secrets_in(root.path());
    let internal = secrets.join("registrar-internal");
    std::fs::create_dir(&internal).expect("mkdir internal");
    std::fs::write(internal.join("agent.toml"), "agent\n").expect("seed");
    let retired = secrets.join("registrar-client-retired");
    std::fs::create_dir(&retired).expect("mkdir retired");

    let tree = SecretsTree::open_rooted_for_tests(&secrets).expect("open");
    assert_eq!(
        tree.read(&internal.join("agent.toml")).expect("owned read"),
        b"agent\n"
    );

    let mut foreign = SecretsTree::open_rooted_for_tests(&secrets).expect("open");
    foreign.set_writer_euid_for_tests(current_process_euid().wrapping_add(1));
    let err = foreign
        .read(&internal.join("agent.toml"))
        .expect_err("foreign registrar-internal");
    assert_names(&err, &internal);
    let err = foreign
        .ensure_dir_fixed(&retired.join("sub"), FixedOwner::current_process())
        .expect_err("foreign retired ensure");
    assert_names(&err, &retired);
    assert!(!retired.join("sub").exists());
    let published = foreign.publish(
        Destination::bootroot_owned(&retired.join("key.pem")),
        PAYLOAD,
        StagedMode::Policy(0o600),
        RootedOwner::Fixed(FixedOwner::current_process()),
        StagedDurability::RenameOnly,
    );
    let err = format!("{:#}", published.expect_err("foreign retired publish"));
    assert!(err.contains(&retired.display().to_string()), "{err}");
    assert!(!retired.join("key.pem").exists());
    assert!(
        std::fs::read_dir(&retired).expect("list").next().is_none(),
        "nothing was staged into the foreign directory"
    );
    // A name below the anchor that is not root-by-policy is unaffected.
    foreign
        .ensure_dir_fixed(&secrets.join("other"), FixedOwner::current_process())
        .expect("ordinary level");
}

#[test]
fn rooted_ensure_dir_as_writer_creates_missing_levels_0700_as_the_writer() {
    let fixture = SwapFixture::new();
    let tree = fixture.rooted();
    let first = fixture.secrets.join("new");
    let second = first.join("deeper");
    tree.ensure_dir_as_writer(&second).expect("ensure");
    assert_eq!(mode_of(&first), 0o700);
    assert_eq!(mode_of(&second), 0o700);
    assert_eq!(owner_of_path(&first), writer());
    assert_eq!(owner_of_path(&second), writer());

    // An existing intermediate level keeps its mode; the last one ends
    // 0700.
    std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o750)).expect("chmod");
    std::fs::set_permissions(&second, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    tree.ensure_dir_as_writer(&second).expect("again");
    assert_eq!(mode_of(&first), 0o750);
    assert_eq!(mode_of(&second), 0o700);

    // The anchor itself is chmodded through its descriptor.
    std::fs::set_permissions(&fixture.secrets, std::fs::Permissions::from_mode(0o750))
        .expect("chmod anchor");
    tree.ensure_dir_as_writer(&fixture.secrets).expect("anchor");
    assert_eq!(mode_of(&fixture.secrets), 0o700);

    let before = snapshot(&fixture.outside);
    let outside_mode = mode_of(&fixture.outside);
    let leaf_link = fixture.secrets.join("leaf-link");
    symlink(&fixture.outside, &leaf_link).expect("leaf link");
    let err = tree
        .ensure_dir_as_writer(&leaf_link)
        .expect_err("leaf link");
    assert_names(&err, &leaf_link);
    fixture.swap_intermediate();
    let err = tree
        .ensure_dir_as_writer(&fixture.secrets.join("a").join("c").join("d"))
        .expect_err("intermediate link");
    assert_names(&err, &fixture.secrets.join("a"));
    assert_eq!(snapshot(&fixture.outside), before);
    assert_eq!(mode_of(&fixture.outside), outside_mode);
}

#[test]
fn rooted_create_new_writes_the_exact_mode_and_refuses_an_existing_entry() {
    let fixture = SwapFixture::new();
    let tree = fixture.rooted();
    let fresh = fixture.secrets.join("a").join("b").join("fresh");
    // 0o666 survives any umask that clears a write bit only because of
    // the fchmod: the test never changes the umask itself.
    tree.create_new(&fresh, PAYLOAD, 0o666, Some(writer()))
        .expect("create_new");
    assert_eq!(std::fs::read(&fresh).expect("read"), PAYLOAD);
    assert_eq!(mode_of(&fresh), 0o666);
    assert_eq!(owner_of_path(&fresh), writer());

    let err = tree
        .create_new(&fresh, b"again", 0o600, None)
        .expect_err("existing file");
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_names(&err, &fresh);
    assert_eq!(std::fs::read(&fresh).expect("read"), PAYLOAD);

    let before = snapshot(&fixture.outside);
    fixture.swap_leaf();
    let err = tree
        .create_new(&fixture.leaf(), PAYLOAD, 0o600, None)
        .expect_err("leaf link");
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_names(&err, &fixture.leaf());
    assert_eq!(snapshot(&fixture.outside), before);

    let fixture = SwapFixture::new();
    let tree = fixture.rooted();
    let before = snapshot(&fixture.outside);
    fixture.swap_intermediate();
    let err = tree
        .create_new(
            &fixture.secrets.join("a").join("b").join("new"),
            PAYLOAD,
            0o600,
            None,
        )
        .expect_err("intermediate link");
    assert_names(&err, &fixture.secrets.join("a"));
    assert_eq!(snapshot(&fixture.outside), before);
}

#[test]
fn rooted_create_dir_exclusive_creates_once_and_refuses_what_it_did_not_create() {
    let fixture = SwapFixture::new();
    let tree = fixture.rooted();
    let dir = fixture.secrets.join("staging");
    tree.create_dir_exclusive(&dir, 0o750, writer())
        .expect("create");
    assert_eq!(mode_of(&dir), 0o750);
    assert_eq!(owner_of_path(&dir), writer());
    let err = tree
        .create_dir_exclusive(&dir, 0o700, writer())
        .expect_err("existing");
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_names(&err, &dir);

    let before = snapshot(&fixture.outside);
    let link = fixture.secrets.join("link");
    symlink(&fixture.outside, &link).expect("leaf link");
    let err = tree
        .create_dir_exclusive(&link, 0o700, writer())
        .expect_err("leaf link");
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_names(&err, &link);
    fixture.swap_intermediate();
    let err = tree
        .create_dir_exclusive(&fixture.secrets.join("a").join("new"), 0o700, writer())
        .expect_err("intermediate link");
    assert_names(&err, &fixture.secrets.join("a"));
    assert_eq!(snapshot(&fixture.outside), before);

    // A directory owned by another uid at the name once it is opened is
    // not the one just created: refused before any mode or owner change.
    let fixture = SwapFixture::new();
    let mut foreign = fixture.rooted();
    foreign.set_writer_euid_for_tests(current_process_euid().wrapping_add(1));
    let planted = fixture.secrets.join("planted");
    let err = foreign
        .create_dir_exclusive(&planted, 0o750, writer())
        .expect_err("foreign owner");
    assert_names(&err, &planted);
    assert_ne!(
        mode_of(&planted),
        0o750,
        "the refused directory was not chmodded"
    );
    assert_eq!(owner_of_path(&planted), writer(), "nor re-owned");
}

#[test]
fn rooted_rename_and_sync_dir_refuse_links_on_the_way() {
    let fixture = SwapFixture::new();
    let tree = fixture.rooted();
    let from = fixture.secrets.join("a").join("b").join("file");
    let to = fixture.secrets.join("moved");
    tree.rename(&from, &to).expect("rename");
    assert_eq!(std::fs::read(&to).expect("read"), b"inside\n");
    assert!(std::fs::symlink_metadata(&from).is_err());
    tree.sync_dir(&fixture.secrets).expect("sync anchor");
    tree.sync_dir(&fixture.secrets.join("a").join("b"))
        .expect("sync level");

    let before = snapshot(&fixture.outside);
    fixture.swap_intermediate();
    let err = tree
        .rename(&to, &fixture.secrets.join("a").join("b").join("back"))
        .expect_err("destination parent link");
    assert_names(&err, &fixture.secrets.join("a"));
    let err = tree
        .rename(&fixture.secrets.join("a").join("b").join("file"), &to)
        .expect_err("source parent link");
    assert_names(&err, &fixture.secrets.join("a"));
    let err = tree
        .sync_dir(&fixture.secrets.join("a").join("b"))
        .expect_err("sync through a link");
    assert_names(&err, &fixture.secrets.join("a"));
    let err = tree
        .sync_dir(&fixture.secrets.join("a"))
        .expect_err("sync a link");
    assert_names(&err, &fixture.secrets.join("a"));
    assert_eq!(snapshot(&fixture.outside), before);
}

/// A link at either name is not followed: one at `from` is moved
/// itself, and one at `to` is replaced; what either points at is kept.
#[test]
fn rooted_rename_moves_or_replaces_a_leaf_link_and_keeps_its_target() {
    let fixture = SwapFixture::new();
    let tree = fixture.rooted();
    let before = snapshot(&fixture.outside);
    fixture.swap_leaf();
    let moved = fixture.secrets.join("moved-link");
    tree.rename(&fixture.leaf(), &moved).expect("rename a link");
    assert!(
        std::fs::symlink_metadata(&moved)
            .expect("stat")
            .file_type()
            .is_symlink()
    );
    assert!(std::fs::symlink_metadata(fixture.leaf()).is_err());

    let staged = fixture.secrets.join("staged");
    std::fs::write(&staged, "staged\n").expect("seed staged");
    tree.rename(&staged, &moved).expect("rename over a link");
    let meta = std::fs::symlink_metadata(&moved).expect("stat");
    assert!(meta.file_type().is_file(), "the link was replaced");
    assert_eq!(std::fs::read(&moved).expect("read"), b"staged\n");
    assert_eq!(snapshot(&fixture.outside), before);
}

#[test]
fn rooted_open_lock_creates_a_regular_file_and_refuses_anything_else() {
    let fixture = SwapFixture::new();
    let tree = fixture.rooted();
    let lock = fixture.secrets.join("a").join("b").join(".lock");
    let file = tree.open_lock(&lock, 0o600).expect("open lock");
    file.try_lock().expect("lock taken");
    drop(file);
    assert_eq!(mode_of(&lock), 0o600);
    tree.open_lock(&lock, 0o600).expect("reopen existing");

    let before = snapshot(&fixture.outside);
    fixture.swap_leaf();
    let err = tree
        .open_lock(&fixture.leaf(), 0o600)
        .expect_err("leaf link");
    assert_names(&err, &fixture.leaf());

    let fifo = fixture.secrets.join("fifo");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("run mkfifo");
    assert!(status.success());
    let err = tree.open_lock(&fifo, 0o600).expect_err("fifo");
    assert_names(&err, &fifo);

    fixture.swap_intermediate();
    let err = tree
        .open_lock(&fixture.secrets.join("a").join("b").join(".lock"), 0o600)
        .expect_err("intermediate link");
    assert_names(&err, &fixture.secrets.join("a"));
    assert_eq!(snapshot(&fixture.outside), before);
}

#[test]
fn rooted_read_with_meta_returns_the_read_descriptor_s_mode_and_owner() {
    let fixture = SwapFixture::new();
    std::fs::set_permissions(fixture.leaf(), std::fs::Permissions::from_mode(0o640))
        .expect("chmod");
    let tree = fixture.rooted();
    let (contents, meta) = tree.read_with_meta(&fixture.leaf()).expect("read");
    assert_eq!(contents, b"inside\n");
    assert_eq!(
        meta,
        FileMeta {
            mode: 0o640,
            uid: writer().0,
            gid: writer().1,
        }
    );

    let before = snapshot(&fixture.outside);
    fixture.swap_leaf();
    let err = tree.read_with_meta(&fixture.leaf()).expect_err("leaf link");
    assert_names(&err, &fixture.leaf());
    assert_eq!(snapshot(&fixture.outside), before);
    fixture.swap_intermediate();
    let err = tree
        .read_with_meta(&fixture.leaf())
        .expect_err("intermediate link");
    assert_names(&err, &fixture.secrets.join("a"));
    assert_eq!(snapshot(&fixture.outside), before);
}

#[test]
fn descriptor_only_writers_are_unsupported_on_a_path_based_handle() {
    let fixture = SwapFixture::new();
    let tree = SecretsTree::open(&fixture.secrets).expect("open");
    let leaf = fixture.leaf();
    let dir = fixture.secrets.join("a");
    let errors = [
        tree.ensure_dir_as_writer(&dir)
            .expect_err("ensure_dir_as_writer"),
        tree.create_new(&dir.join("x"), PAYLOAD, 0o600, None)
            .expect_err("create_new"),
        tree.create_dir_exclusive(&dir.join("y"), 0o700, writer())
            .expect_err("create_dir_exclusive"),
        tree.rename(&leaf, &dir.join("z")).expect_err("rename"),
        tree.sync_dir(&dir).expect_err("sync_dir"),
        tree.open_lock(&dir.join("lock"), 0o600)
            .expect_err("open_lock"),
        tree.read_with_meta(&leaf).expect_err("read_with_meta"),
    ];
    for err in errors {
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported, "{err}");
    }
    assert!(leaf.exists());
    assert!(!dir.join("x").exists() && !dir.join("y").exists() && !dir.join("lock").exists());
}
