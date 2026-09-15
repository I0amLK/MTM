//! Actual distribution staging is byte-bound and never selects an installation.
#![cfg(unix)]

use std::error::Error;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::{Command, Stdio};

use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn dist_cli_copies_exact_bytes_and_rejects_wrong_or_linked_sources() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let binary = root.path().join("candidate");
    fs::write(&binary, b"reviewed distribution bytes")?;
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))?;
    let sha = format!("{:x}", Sha256::digest(fs::read(&binary)?));
    let out = root.path().join("dist");
    let run =
        |source: &std::path::Path, digest: &str| -> Result<std::process::Output, std::io::Error> {
            Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
                .args([
                    "dist",
                    "--binary",
                    &source.to_string_lossy(),
                    "--sha256",
                    digest,
                    "--version",
                    "0.6.0-preview.1",
                    "--out",
                    &out.to_string_lossy(),
                ])
                .env_clear()
                .stdin(Stdio::null())
                .output()
        };
    let accepted = run(&binary, &sha)?;
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let report: Value = serde_json::from_slice(&accepted.stdout)?;
    assert_eq!(report["sha256"], sha);
    assert_eq!(report["installed"], false);
    assert_eq!(report["selector_changed"], false);
    assert_eq!(report["release_qualified"], false);
    let artifact = std::path::PathBuf::from(report["artifact"].as_str().ok_or("artifact")?);
    assert_eq!(fs::read(&artifact)?, fs::read(&binary)?);
    assert!(run(&binary, &sha)?.status.success());
    assert!(!run(&binary, &"0".repeat(64))?.status.success());

    let linked = root.path().join("linked");
    symlink(&binary, &linked)?;
    assert!(!run(&linked, &sha)?.status.success());
    assert_eq!(report["version_label_verified"], false);
    let metadata = artifact.parent().ok_or("bundle")?.join("dist.json");
    fs::remove_file(&metadata)?;
    let outside = root.path().join("outside.json");
    fs::write(&outside, serde_json::to_vec(&report)?)?;
    symlink(&outside, &metadata)?;
    assert!(!run(&binary, &sha)?.status.success());
    fs::remove_file(&metadata)?;
    fs::write(&metadata, serde_json::to_vec(&report)?)?;
    fs::write(&artifact, b"preserve this conflict")?;
    assert!(!run(&binary, &sha)?.status.success());
    assert_eq!(fs::read(&artifact)?, b"preserve this conflict");
    fs::remove_file(&artifact)?;
    symlink(root.path().join("does-not-exist"), &artifact)?;
    assert!(!run(&binary, &sha)?.status.success());
    assert!(fs::symlink_metadata(&artifact)?.file_type().is_symlink());
    Ok(())
}

#[test]
fn dist_rejects_parent_symlinks_and_special_executable_bits() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let binary = root.path().join("candidate");
    fs::write(&binary, b"test data, never launched")?;
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))?;
    let sha = format!("{:x}", Sha256::digest(fs::read(&binary)?));
    fs::create_dir(root.path().join("outside"))?;
    symlink(root.path().join("outside"), root.path().join("link"))?;
    for out in [
        root.path().join("link/dist"),
        root.path().join("regular-dist"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
            .args([
                "dist",
                "--binary",
                &binary.to_string_lossy(),
                "--sha256",
                &sha,
                "--version",
                "fixture",
                "--out",
                &out.to_string_lossy(),
            ])
            .env_clear()
            .stdin(Stdio::null())
            .output()?;
        assert!(!output.status.success());
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o4755))?;
    }
    assert_eq!(fs::read_dir(root.path().join("outside"))?.count(), 0);
    assert!(!root.path().join("regular-dist").exists());
    Ok(())
}
