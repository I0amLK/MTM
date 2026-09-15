//! Real reviewed old/current runtimes; all installs and state are disposable.
use std::env;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};

use crate::candidate_lifecycle;
use crate::support::candidate;
use crate::support::loopback::{Server, sha256_file};
use crate::support::{Result, require, text};

const ENABLE: &str = "MTM_TEST_UPGRADE_PROFILE";

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(Some(_))) {
            return;
        }
        let _ = self.0.kill();
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && matches!(self.0.try_wait(), Ok(None)) {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

// The reviewed CLI writes only bounded JSON on this fixed command family. Monitor
// its private output file and deadline; never retain stderr or inherited secrets.
fn cli(binary: &str, arguments: &[String]) -> Result<Value> {
    let mut output = tempfile::tempfile().map_err(|_| "upgrade CLI output file")?;
    let mut child = OwnedChild(
        Command::new(binary)
            .args(arguments)
            .env_clear()
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .stdout(Stdio::from(
                output
                    .try_clone()
                    .map_err(|_| "upgrade CLI output handle")?,
            ))
            .spawn()
            .map_err(|_| "upgrade CLI start")?,
    );
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        require(
            output
                .metadata()
                .map_err(|_| "upgrade CLI output size")?
                .len()
                <= 65_536,
            "upgrade CLI output exceeded bound",
        )?;
        if let Some(status) = child.0.try_wait().map_err(|_| "upgrade CLI wait")? {
            require(status.success(), "upgrade CLI rejected its fixed operation")?;
            break;
        }
        require(Instant::now() < deadline, "upgrade CLI deadline exceeded")?;
        thread::sleep(Duration::from_millis(10));
    }
    output
        .seek(SeekFrom::Start(0))
        .map_err(|_| "upgrade CLI output seek")?;
    let mut bytes = Vec::new();
    output
        .take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| "upgrade CLI output read")?;
    require(bytes.len() <= 65_536, "upgrade CLI output exceeded bound")?;
    serde_json::from_slice(&bytes).map_err(|_| "upgrade CLI JSON malformed")
}

fn path(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or("upgrade fixture path is not UTF-8")
}

fn schema(server: &Server) -> Result<u64> {
    let database = Connection::open_with_flags(
        server.private_state_path(),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|_| "upgrade fixture database read")?;
    database
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| "upgrade fixture schema read")
}

#[test]
fn exact_installed_upgrade_and_preupgrade_state_rollback() -> Result {
    if env::var_os(ENABLE).is_none() {
        return Ok(());
    }
    require(
        env::var(ENABLE).ok().as_deref() == Some("1"),
        "upgrade profile flag must be exactly one",
    )?;
    require(
        env::var_os(candidate::BINARY_ENV).is_some(),
        "upgrade candidate must be explicit",
    )?;
    let candidate = candidate::select()?;
    let baseline = candidate::select_baseline()?;
    require(
        candidate.sha256 != baseline.sha256,
        "upgrade requires distinct reviewed artifacts",
    )?;
    let mut server = Server::start(&baseline.path)?;
    let owner = server.login()?;
    let old_info = server.call(&owner, "server_info", json!({}))?;
    require(
        old_info["server"] == "mtm"
            && old_info["version"] == "0.5.0-preview.2"
            && schema(&server)? == 2,
        "upgrade fixture requires preview.2 schema-2 baseline",
    )?;
    let created = server.call(
        &owner,
        "rethlas_start",
        json!({
            "problem_tex":"Disposable upgrade fixture: equality is reflexive.",
            "problem_id":"rust-upgrade-fixture","workflow_mode":"compact","register_result":false
        }),
    )?;
    let run_id = text(&created, "run_id")?.to_owned();
    let task = server.call(&owner, "rethlas_step", json!({"run_id":run_id}))?;
    require(
        task["state"] == "assess",
        "baseline did not create an active old run",
    )?;
    let secret_before = server.secret_fingerprint()?;
    let snapshot = server.snapshot_owned_state()?;
    eprintln!(
        "upgrade legacy private shared-write entry count: {}",
        snapshot.legacy_shared_write_entries
    );
    // Explicit preparation of a stopped, disposable copy, never a relaxation of
    // the current vault's mode checks or a rewrite of the pre-upgrade snapshot.
    let prepared_mode_entries = server.prepare_owned_private_modes()?;

    let root = server.installation_fixture_root();
    let state = root.join("state");
    let selectors = [root.join("bin-a/mtm"), root.join("bin-b/mtm")];
    for selector in &selectors {
        fs::create_dir_all(selector.parent().ok_or("upgrade selector parent")?)
            .map_err(|_| "upgrade selector directory")?;
        symlink(&baseline.path, selector).map_err(|_| "upgrade baseline selector")?;
    }
    let arguments = vec![
        "install".into(),
        "--binary".into(),
        candidate.path.clone(),
        "--sha256".into(),
        candidate.sha256.clone(),
        "--version".into(),
        env!("CARGO_PKG_VERSION").into(),
        "--state-root".into(),
        path(&state)?,
        "--selector".into(),
        path(&selectors[0])?,
        "--selector".into(),
        path(&selectors[1])?,
    ];
    let installed = cli(&candidate.path, &arguments)?;
    require(
        installed["ok"] == true && installed["release_qualified"] == false,
        "upgrade self-install outcome",
    )?;
    let executable = PathBuf::from(text(&installed, "release_path")?);
    for selector in &selectors {
        require(
            selector
                .canonicalize()
                .map_err(|_| "upgrade selector resolution")?
                == executable,
            "upgrade selector pair differs",
        )?;
    }
    require(
        sha256_file(&executable)? == candidate.sha256,
        "installed candidate bytes differ",
    )?;
    let manifest = state.join("deployment/current-v2.json");
    let manifest_before = sha256_file(&manifest)?;
    cli(&candidate.path, &arguments)?;
    require(
        sha256_file(&manifest)? == manifest_before,
        "repeat upgrade lost rollback baseline",
    )?;
    server.switch_test_artifact(&executable, &candidate.sha256)?;
    let info = server.call(&owner, "server_info", json!({}))?;
    let current_schema = u64::from(mtm_contracts::ContractSnapshot::current().state_schema);
    require(
        info["version"] == env!("CARGO_PKG_VERSION") && schema(&server)? == current_schema,
        "installed candidate identity or schema mismatch",
    )?;
    require(
        server.secret_fingerprint()? == secret_before,
        "upgrade rotated owned fixture secret",
    )?;
    let resumed = server.call(&owner, "rethlas_step", json!({"run_id":run_id}))?;
    require(resumed["state"] == "assess", "upgrade lost the old run")?;
    let advanced = server.call(
        &owner,
        "rethlas_step",
        candidate_lifecycle::fixture_submission(&resumed, "compact", false)?,
    )?;
    if advanced["state"] != "assemble" {
        eprintln!(
            "upgrade continuation diagnostic: {}",
            json!({
                "state":advanced["state"],"ok":advanced["ok"],
                "error_code":advanced["error"]["code"],
                "submission_error_code":advanced["submission"]["error"]["code"],
                "writes_applied":advanced["writes_applied"]
            })
        );
    }
    require(
        advanced["state"] == "assemble",
        "old run did not advance on installed candidate",
    )?;
    let new_task = crate::start(&server, &owner, "compact")?;
    let new_result = server.call(
        &owner,
        "rethlas_step",
        candidate_lifecycle::fixture_submission(&new_task, "compact", false)?,
    )?;
    require(
        new_result["state"] == "assemble" && new_task["run_id"] != run_id,
        "new run after installed upgrade failed",
    )?;
    server.restart()?;
    let reconnected = server.call(&owner, "rethlas_step", json!({"run_id":run_id}))?;
    require(
        reconnected["state"] == "assemble" && server.secret_fingerprint()? == secret_before,
        "installed restart lost old run or key",
    )?;
    server.stop()?;
    require(schema(&server)? == current_schema, "candidate schema drift")?;
    snapshot.unchanged()?;

    // Rollback needs both the old executable and the pre-upgrade data image.
    let restored_sha256 = server.restore_owned_state(&snapshot)?;
    require(
        restored_sha256 == snapshot.sha256 && schema(&server)? == 2,
        "preupgrade snapshot restoration failed",
    )?;
    let rolled = cli(
        &candidate.path,
        &["rollback".into(), "--state-root".into(), path(&state)?],
    )?;
    require(
        rolled["state"] == "previous_active",
        "selector rollback did not complete",
    )?;
    for selector in &selectors {
        require(
            fs::read_link(selector).map_err(|_| "rollback selector read")?
                == Path::new(&baseline.path),
            "rollback did not restore baseline selectors",
        )?;
    }
    let old_executable = selectors[0]
        .canonicalize()
        .map_err(|_| "rollback executable resolution")?;
    server.switch_test_artifact(&old_executable, &baseline.sha256)?;
    let restored_info = server.call(&owner, "server_info", json!({}))?;
    let restored_task = server.call(&owner, "rethlas_step", json!({"run_id":run_id}))?;
    require(
        restored_info["version"] == "0.5.0-preview.2"
            && restored_task["state"] == "assess"
            && schema(&server)? == 2
            && server.secret_fingerprint()? == secret_before,
        "baseline runtime did not serve its restored state",
    )?;
    let old_advanced = server.call(
        &owner,
        "rethlas_step",
        candidate_lifecycle::fixture_submission(&restored_task, "compact", false)?,
    )?;
    require(
        old_advanced["state"] == "assemble",
        "restored baseline run cannot advance",
    )?;
    server.stop()?;
    snapshot.unchanged()?;
    baseline.unchanged()?;
    candidate.unchanged()?;
    require(
        sha256_file(&executable)? == candidate.sha256,
        "installed artifact drifted",
    )?;

    println!(
        "MTM_UPGRADE_RUNTIME {}",
        json!({
            "ok":true,"candidate_sha256":candidate.sha256,"baseline_sha256":baseline.sha256,
            "candidate_version":env!("CARGO_PKG_VERSION"),"baseline_version":"0.5.0-preview.2",
            "baseline_schema":2,"candidate_schema":current_schema,"restored_schema":2,
            "snapshot_sha256":snapshot.sha256,"restored_snapshot_sha256":restored_sha256,
            "snapshot_entries":snapshot.entries,"snapshot_bytes":snapshot.bytes,
            "private_modes_prepared":true,"prepared_mode_entries":prepared_mode_entries,
            "legacy_shared_write_entries":snapshot.legacy_shared_write_entries,
            "checks":{"baseline_created_old_run":true,"snapshot_copy_verified":true,
                "self_install_exact":true,"both_selectors_agree":true,"repeat_install_preserves_manifest":true,
                "installed_endpoint_identity":true,"old_run_advances_after_upgrade":true,
                "new_run_advances_after_upgrade":true,"same_key_restart":true,
                "baseline_selectors_restored":true,"snapshot_restored_before_old_launch":true,
                "old_runtime_advances_restored_run":true,"snapshot_immutable":true,
                "artifacts_unchanged":true,"clean_shutdown":true},
            "fixture_state_only":true,"installed_endpoint_tested":true,"selectors_tested":2,
            "native_backend":"disabled","latex_policy":"static_only",
            "native_execution_tested":false,"compiled_latex_tested":false,"web_client_tested":false,
            "production_state_modified":false,"production_selectors_changed":false,
            "release_qualified":false
        })
    );
    Ok(())
}
