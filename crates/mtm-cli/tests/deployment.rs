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
    fs::write(&binary, b"reviewed mtm candidate bytes")?;
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
