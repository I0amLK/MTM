//! Current release installation mechanics in disposable paths only.
#![cfg(unix)]

use std::env;
use std::error::Error;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::Value;
use sha2::{Digest, Sha256};

const DEPLOYMENT_CANDIDATE_ENV: &str = "MTM_TEST_DEPLOYMENT_CANDIDATE";
const DEPLOYMENT_CANDIDATE_SHA_ENV: &str = "MTM_TEST_DEPLOYMENT_CANDIDATE_SHA256";
const SIGKILL_PROFILE_ENV: &str = "MTM_TEST_INSTALL_SIGKILL_PROFILE";
type PreviousSelector = (PathBuf, String, u32);
type SigkillFixture = (String, Vec<String>, Vec<PreviousSelector>);

fn selected_binary() -> PathBuf {
    env::var_os(DEPLOYMENT_CANDIDATE_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_mtm")))
}

fn sha(path: &Path) -> Result<String, Box<dyn Error>> {
    Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
}

fn run(arguments: &[String]) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(selected_binary())
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .output()?)
}

fn fixture(root: &Path) -> Result<(String, Vec<String>), Box<dyn Error>> {
    let binary = root.join("candidate");
    fs::copy(selected_binary(), &binary)?;
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
        env!("CARGO_PKG_VERSION").into(),
        "--state-root".into(),
        state.to_string_lossy().into_owned(),
        "--selector".into(),
        first.to_string_lossy().into_owned(),
        "--selector".into(),
        second.to_string_lossy().into_owned(),
    ];
    Ok((digest, args))
}

fn sigkill_fixture(root: &Path, selector_count: usize) -> Result<SigkillFixture, Box<dyn Error>> {
    let binary = root.join("candidate");
    fs::copy(selected_binary(), &binary)?;
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))?;
    let digest = sha(&binary)?;
    let state = root.join("state");
    let mut args = vec![
        "install".into(),
        "--binary".into(),
        binary.to_string_lossy().into_owned(),
        "--sha256".into(),
        digest.clone(),
        "--version".into(),
        env!("CARGO_PKG_VERSION").into(),
        "--state-root".into(),
        state.to_string_lossy().into_owned(),
    ];
    let mut previous = Vec::new();
    for index in 0..selector_count {
        let selector = root.join(format!("bin-{index}/mtm"));
        fs::create_dir_all(selector.parent().ok_or("selector parent")?)?;
        let bytes = vec![u8::try_from(index + 1)?; 16 * 1024 * 1024];
        fs::write(&selector, bytes)?;
        let mode = 0o740 | u32::try_from(index % 8)?;
        fs::set_permissions(&selector, fs::Permissions::from_mode(mode))?;
        previous.push((selector.clone(), sha(&selector)?, mode));
        args.push("--selector".into());
        args.push(selector.to_string_lossy().into_owned());
    }
    Ok((digest, args, previous))
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
    assert_eq!(report["version"], env!("CARGO_PKG_VERSION"));
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
    for version in ["unverified-version", "0.6.0-preview.1"] {
        args[6] = version.into();
        assert_eq!(run(&args)?.status.code(), Some(2));
        assert!(!root.path().join("state").exists());
    }
    args[6] = env!("CARGO_PKG_VERSION").into();
    fs::write(root.path().join("candidate"), b"not an MTM runtime")?;
    args[4] = sha(&root.path().join("candidate"))?;
    assert_eq!(run(&args)?.status.code(), Some(2));
    assert!(!root.path().join("state").exists());
    Ok(())
}

#[test]
fn public_commands_recover_persisted_interrupted_prefixes() -> Result<(), Box<dyn Error>> {
    // Interrupted rollback: one selector has already been restored when the
    // process disappears. `status` must use the durable journal to put the
    // active release back and preserve the exact active manifest.
    let root = tempfile::tempdir()?;
    let (_, args) = fixture(root.path())?;
    assert!(run(&args)?.status.success());
    let state = root.path().join("state");
    let manifest = state.join("deployment/current-v2.json");
    let manifest_bytes = fs::read(&manifest)?;
    let active: Value = serde_json::from_slice(&manifest_bytes)?;
    let backup = state.join("deployment/pending-v2.manifest.backup");
    fs::write(&backup, &manifest_bytes)?;
    fs::set_permissions(&backup, fs::Permissions::from_mode(0o600))?;
    let pending = state.join("deployment/pending-v2.json");
    let journal = serde_json::json!({
        "schema":"mtm-install-recovery-v2","operation":"rollback",
        "active_manifest":active,
        "manifest_before":{"kind":"file","backup":backup,"sha256":sha(&backup)?}
    });
    fs::write(&pending, serde_json::to_vec_pretty(&journal)?)?;
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600))?;
    let first = root.path().join("bin-a/mtm");
    fs::remove_file(&first)?;
    let status = run(&[
        "status".into(),
        "--state-root".into(),
        state.to_string_lossy().into_owned(),
    ])?;
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&status.stdout)?["state"],
        "active"
    );
    assert_eq!(fs::read(&manifest)?, manifest_bytes);
    assert!(!pending.exists());
    assert!(!backup.exists());

    // Interrupted first install: only the first selector points at the staged
    // release and no deployment manifest exists. Retrying the same explicit
    // install must first restore the missing baseline and then install normally.
    let retry = tempfile::tempdir()?;
    let (digest, retry_args) = fixture(retry.path())?;
    let retry_state = retry.path().join("state");
    let deployment = retry_state.join("deployment");
    fs::create_dir_all(&deployment)?;
    let release = retry_state
        .join("releases")
        .join(env!("CARGO_PKG_VERSION"))
        .join(&digest)
        .join("mtm");
    fs::create_dir_all(release.parent().ok_or("release parent")?)?;
    fs::copy(retry.path().join("candidate"), &release)?;
    fs::set_permissions(&release, fs::Permissions::from_mode(0o755))?;
    let first = retry.path().join("bin-a/mtm");
    let second = retry.path().join("bin-b/mtm");
    let active = serde_json::json!({
        "schema":"mtm-install-v2","state":"active","version":env!("CARGO_PKG_VERSION"),
        "sha256":digest,"release_path":release,
        "selectors":[
            {"path":first,"previous":{"kind":"missing"}},
            {"path":second,"previous":{"kind":"missing"}}
        ],
        "release_qualified":false,"python_runtime_required":false
    });
    let pending = retry_state.join("deployment/pending-v2.json");
    fs::write(
        &pending,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema":"mtm-install-recovery-v2","operation":"install",
            "active_manifest":active,"manifest_before":{"kind":"missing"}
        }))?,
    )?;
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600))?;
    symlink(&release, &first)?;
    let installed = run(&retry_args)?;
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let report: Value = serde_json::from_slice(&installed.stdout)?;
    assert_eq!(report["state"], "active");
    assert_eq!(report["sha256"], digest);
    assert_eq!(first.canonicalize()?, second.canonicalize()?);
    assert!(!pending.exists());
    Ok(())
}

#[test]
fn external_sigkill_during_real_rollback_recovers_exact_candidate() -> Result<(), Box<dyn Error>> {
    if env::var_os(SIGKILL_PROFILE_ENV).is_none() {
        return Ok(());
    }
    if env::var(SIGKILL_PROFILE_ENV).ok().as_deref() != Some("1") {
        return Err("SIGKILL profile must be explicitly enabled with value 1".into());
    }
    let selected = selected_binary();
    let expected = env::var(DEPLOYMENT_CANDIDATE_SHA_ENV)
        .map_err(|_| "SIGKILL profile requires exact candidate SHA-256")?;
    if sha(&selected)? != expected {
        return Err("SIGKILL profile candidate identity mismatch".into());
    }

    let root = tempfile::tempdir()?;
    let selector_count = 8_usize;
    let (digest, args, previous) = sigkill_fixture(root.path(), selector_count)?;
    if digest != expected {
        return Err("copied SIGKILL candidate identity mismatch".into());
    }
    let installed = run(&args)?;
    if !installed.status.success() {
        return Err(format!(
            "SIGKILL fixture install failed: {}",
            String::from_utf8_lossy(&installed.stderr)
        )
        .into());
    }
    let installed_report: Value = serde_json::from_slice(&installed.stdout)?;
    if installed_report["state"] != "active" || installed_report["sha256"] != digest {
        return Err("SIGKILL fixture install did not become active".into());
    }
    let release = PathBuf::from(
        installed_report["release_path"]
            .as_str()
            .ok_or("installed release path missing")?,
    );
    let state = root.path().join("state");
    let pending = state.join("deployment/pending-v2.json");
    let rollback_args = [
        "rollback".to_owned(),
        "--state-root".to_owned(),
        state.to_string_lossy().into_owned(),
    ];
    let started = Instant::now();
    let mut child = Command::new(&selected)
        .args(&rollback_args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let partial_restored = loop {
        if let Some(status) = child.try_wait()? {
            return Err(
                format!("rollback completed before external SIGKILL window: {status}").into(),
            );
        }
        if pending.is_file() {
            let restored = previous
                .iter()
                .filter(|(selector, _, _)| {
                    fs::symlink_metadata(selector)
                        .is_ok_and(|metadata| !metadata.file_type().is_symlink())
                })
                .count();
            if (1..selector_count).contains(&restored) {
                break restored;
            }
        }
        if Instant::now() >= deadline {
            let _ = kill(Pid::from_raw(i32::try_from(child.id())?), Signal::SIGKILL);
            let _ = child.wait();
            return Err(
                "external SIGKILL fixture did not observe a partial selector prefix".into(),
            );
        }
        thread::sleep(Duration::from_millis(1));
    };
    kill(Pid::from_raw(i32::try_from(child.id())?), Signal::SIGKILL)?;
    let killed = child.wait()?;
    if killed.signal() != Some(Signal::SIGKILL as i32) || !pending.is_file() {
        return Err(
            "rollback process was not externally SIGKILLed with durable recovery state".into(),
        );
    }

    let recovered = run(&[
        "status".into(),
        "--state-root".into(),
        state.to_string_lossy().into_owned(),
    ])?;
    if !recovered.status.success() {
        return Err(format!(
            "post-SIGKILL status recovery failed: {}",
            String::from_utf8_lossy(&recovered.stderr)
        )
        .into());
    }
    let recovered_report: Value = serde_json::from_slice(&recovered.stdout)?;
    if recovered_report["state"] != "active" || pending.exists() {
        return Err(
            "post-SIGKILL recovery did not restore active deployment and clear journal".into(),
        );
    }
    for (selector, _, _) in &previous {
        if selector.canonicalize()? != release.canonicalize()? {
            return Err("post-SIGKILL recovery left a selector off the active candidate".into());
        }
    }

    let final_rollback = run(&rollback_args)?;
    if !final_rollback.status.success() {
        return Err(format!(
            "final rollback after SIGKILL recovery failed: {}",
            String::from_utf8_lossy(&final_rollback.stderr)
        )
        .into());
    }
    let final_report: Value = serde_json::from_slice(&final_rollback.stdout)?;
    if final_report["state"] != "previous_active" {
        return Err("final rollback did not restore previous_active state".into());
    }
    for (selector, expected_sha, expected_mode) in &previous {
        let metadata = fs::symlink_metadata(selector)?;
        if metadata.file_type().is_symlink()
            || sha(selector)? != *expected_sha
            || metadata.permissions().mode() & 0o777 != *expected_mode
        {
            return Err("final rollback did not restore prior selector bytes and mode".into());
        }
    }
    if sha(&selected)? != expected {
        return Err("selected candidate changed during external SIGKILL drill".into());
    }
    println!(
        "MTM_INSTALL_SIGKILL {}",
        serde_json::json!({
            "schema":"mtm-install-sigkill-v1",
            "ok":true,
            "binary_sha256":expected,
            "selector_count":selector_count,
            "partial_restored_selectors":partial_restored,
            "kill_signal":Signal::SIGKILL as i32,
            "external_process_sigkill":true,
            "pending_journal_observed_before_kill":true,
            "recovered_state":"active",
            "all_candidate_selectors_recovered":true,
            "pending_journal_cleared":true,
            "final_state":"previous_active",
            "previous_selector_bytes_and_modes_restored":true,
            "elapsed_ms":started.elapsed().as_millis(),
            "physical_power_loss_tested":false,
            "shared_filesystem_tested":false,
            "production_state_modified":false,
            "production_selectors_changed":false,
            "release_qualified":false
        })
    );
    Ok(())
}
