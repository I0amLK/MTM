//! Current release installation mechanics in disposable paths only.
#![cfg(unix)]

use std::error::Error;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use sha2::{Digest, Sha256};

fn sha(path: &Path) -> Result<String, Box<dyn Error>> {
    Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
}

fn run(arguments: &[String]) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(env!("CARGO_BIN_EXE_mtm"))
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .output()?)
}

fn fixture(root: &Path) -> Result<(String, Vec<String>), Box<dyn Error>> {
    let binary = root.join("candidate");
    fs::copy(env!("CARGO_BIN_EXE_mtm"), &binary)?;
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))?;
    let digest = sha(&binary)?;
    let state = root.join("state");
    let first = root.join("bin-a/mtm");
    let second = root.join("bin-b/mtm");
    fs::create_dir_all(first.parent().ok_or("first parent")?)?;
    fs::create_dir_all(second.parent().ok_or("second parent")?)?;
    let args = vec![
        "install".into(),
        "--binary".into(),
        binary.to_string_lossy().into_owned(),
        "--sha256".into(),
        digest.clone(),
        "--version".into(),
        "0.6.0-preview.1".into(),
        "--state-root".into(),
        state.to_string_lossy().into_owned(),
        "--selector".into(),
        first.to_string_lossy().into_owned(),
        "--selector".into(),
        second.to_string_lossy().into_owned(),
    ];
    Ok((digest, args))
}

#[test]
fn install_status_and_rollback_preserve_both_previous_selectors() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let old_target = root.path().join("old-mtm");
    fs::write(&old_target, b"old")?;
    fs::set_permissions(&old_target, fs::Permissions::from_mode(0o755))?;
    let first = root.path().join("bin-a/mtm");
    let second = root.path().join("bin-b/mtm");
    fs::create_dir_all(first.parent().ok_or("first parent")?)?;
    fs::create_dir_all(second.parent().ok_or("second parent")?)?;
    symlink(&old_target, &first)?;
    fs::write(&second, b"old regular selector")?;
    fs::set_permissions(&second, fs::Permissions::from_mode(0o751))?;
    let old_second_sha = sha(&second)?;
    let (digest, args) = fixture(root.path())?;

    let installed = run(&args)?;
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let report: Value = serde_json::from_slice(&installed.stdout)?;
    assert_eq!(report["state"], "active");
    assert_eq!(report["sha256"], digest);
    assert_eq!(report["release_qualified"], false);
    assert_eq!(report["installed_selector_checked"], true);
    assert_eq!(first.canonicalize()?, second.canonicalize()?);

    let status_args = vec![
        "status".into(),
        "--state-root".into(),
        root.path().join("state").to_string_lossy().into_owned(),
    ];
    assert!(run(&status_args)?.status.success());

    let rollback_args = vec![
        "rollback".into(),
        "--state-root".into(),
        root.path().join("state").to_string_lossy().into_owned(),
    ];
    let rolled = run(&rollback_args)?;
    assert!(
        rolled.status.success(),
        "{}",
        String::from_utf8_lossy(&rolled.stderr)
    );
    let report: Value = serde_json::from_slice(&rolled.stdout)?;
    assert_eq!(report["state"], "previous_active");
    assert_eq!(fs::read_link(&first)?, old_target);
    assert!(!fs::symlink_metadata(&second)?.file_type().is_symlink());
    assert_eq!(sha(&second)?, old_second_sha);
    assert_eq!(fs::metadata(&second)?.permissions().mode() & 0o777, 0o751);
    Ok(())
}

#[test]
fn wrong_hash_drift_and_symlink_source_fail_closed() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let (_, mut args) = fixture(root.path())?;
    args[4] = "0".repeat(64);
    let rejected = run(&args)?;
    assert_eq!(rejected.status.code(), Some(2));
    assert!(!root.path().join("bin-a/mtm").exists());

    let (_, args) = fixture(root.path())?;
    let installed = run(&args)?;
    assert!(installed.status.success());
    let selector = root.path().join("bin-a/mtm");
    fs::remove_file(&selector)?;
    fs::write(&selector, b"operator changed this entry")?;
    let rollback = run(&[
        "rollback".into(),
        "--state-root".into(),
        root.path().join("state").to_string_lossy().into_owned(),
    ])?;
    assert_eq!(rollback.status.code(), Some(2));
    assert_eq!(fs::read(&selector)?, b"operator changed this entry");

    let linked = root.path().join("linked-candidate");
    symlink(root.path().join("candidate"), &linked)?;
    let mut linked_args = args;
    linked_args[2] = linked.to_string_lossy().into_owned();
    assert_eq!(run(&linked_args)?.status.code(), Some(2));
    Ok(())
}

#[test]
fn repeat_install_preserves_the_original_rollback() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let (_, args) = fixture(root.path())?;
    let first = root.path().join("bin-a/mtm");
    fs::write(&first, b"original command")?;
    assert!(run(&args)?.status.success());
    let manifest = root.path().join("state/deployment/current-v2.json");
    let before = fs::read(&manifest)?;
    assert!(run(&args)?.status.success());
    assert_eq!(fs::read(&manifest)?, before);
    assert!(
        run(&[
            "rollback".into(),
            "--state-root".into(),
            root.path().join("state").to_string_lossy().into_owned(),
        ])?
        .status
        .success()
    );
    assert_eq!(fs::read(&first)?, b"original command");
    assert!(!root.path().join("bin-b/mtm").exists());
    Ok(())
}

#[test]
fn empty_manifest_selector_set_cannot_masquerade_as_success() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let (_, args) = fixture(root.path())?;
    assert!(run(&args)?.status.success());
    let manifest = root.path().join("state/deployment/current-v2.json");
    let mut payload: Value = serde_json::from_slice(&fs::read(&manifest)?)?;
    payload["selectors"] = serde_json::json!([]);
    fs::write(&manifest, serde_json::to_vec(&payload)?)?;
    for operation in ["status", "rollback"] {
        assert_eq!(
            run(&[
                operation.into(),
                "--state-root".into(),
                root.path().join("state").to_string_lossy().into_owned(),
            ])?
            .status
            .code(),
            Some(2)
        );
    }
    Ok(())
}

#[test]
fn ancestor_symlinks_and_selectors_inside_the_release_root_are_rejected()
-> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let (_, mut args) = fixture(root.path())?;
    fs::create_dir(root.path().join("outside"))?;
    symlink(root.path().join("outside"), root.path().join("link"))?;
    args[8] = root
        .path()
        .join("link/state")
        .to_string_lossy()
        .into_owned();
    assert_eq!(run(&args)?.status.code(), Some(2));
    assert_eq!(fs::read_dir(root.path().join("outside"))?.count(), 0);
    args[8] = root.path().join("state").to_string_lossy().into_owned();
    args[10] = root.path().join("state/mtm").to_string_lossy().into_owned();
    assert_eq!(run(&args)?.status.code(), Some(2));
    assert!(!root.path().join("state").exists());
    Ok(())
}

#[test]
fn install_checks_its_own_artifact_and_version_before_writing() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let (_, mut args) = fixture(root.path())?;
    args[6] = "unverified-version".into();
    assert_eq!(run(&args)?.status.code(), Some(2));
    assert!(!root.path().join("state").exists());
    args[6] = env!("CARGO_PKG_VERSION").into();
    fs::write(root.path().join("candidate"), b"not an MTM runtime")?;
    args[4] = sha(&root.path().join("candidate"))?;
    assert_eq!(run(&args)?.status.code(), Some(2));
    assert!(!root.path().join("state").exists());
    Ok(())
}
