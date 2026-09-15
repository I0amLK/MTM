//! Explicit MTM-016 release authority. This is the only xtask path allowed to change selectors.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{Result, release_check};

const MILESTONE: &str = "MTM-016";
const VERSION: &str = "0.6.0-preview.1";
const CANDIDATE_SHA256: &str = "f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034";
const CANDIDATE_SOURCE_COMMIT: &str = "c67484319f12c458cd25c538e35bbb25023915a5";
const BINARY_REL: &str = "target/mtm016-f6-frozen/mtm-0.6.0-preview.1-f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034/mtm";
const MANIFEST_REL: &str = "records/governance/mtm016-release-inputs.json";
const RECEIPT_REL: &str = "records/evidence/MTM-016/preview-release.json";
const STATE_ROOT: &str = "/home/lk/.local/share/mtm";
const SELECTOR: &str = "/home/lk/.local/bin/mtm";
const CARGO_ENTRY: &str = "/home/lk/.cargo/bin/mtm";
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;

pub(crate) struct Options {
    binary: String,
    manifest: String,
    authorize: String,
}

impl Options {
    pub(crate) fn parse(arguments: &[String]) -> Result<Self> {
        let mut binary = None;
        let mut manifest = None;
        let mut authorize = None;
        let mut index = 0;
        while index < arguments.len() {
            let key = arguments[index].as_str();
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| format!("{key} requires a value"))?;
            match key {
                "--binary" if binary.is_none() => binary = Some(value.to_owned()),
                "--manifest" if manifest.is_none() => manifest = Some(value.to_owned()),
                "--authorize" if authorize.is_none() => authorize = Some(value.to_owned()),
                _ => {
                    return Err(
                        format!("unknown or duplicate release-cutover option: {key}").into(),
                    );
                }
            }
            index += 2;
        }
        let options = Self {
            binary: binary.ok_or("release-cutover requires --binary")?,
            manifest: manifest.ok_or("release-cutover requires --manifest")?,
            authorize: authorize.ok_or("release-cutover requires --authorize")?,
        };
        require(
            options.binary == BINARY_REL,
            "release-cutover binary must be the exact frozen MTM-016 candidate",
        )?;
        require(
            options.manifest == MANIFEST_REL,
            "release-cutover manifest must be the governed MTM-016 release input",
        )?;
        require(
            options.authorize == MILESTONE,
            "release-cutover requires explicit --authorize MTM-016",
        )?;
        Ok(options)
    }
}

struct RolloutLock {
    path: PathBuf,
}

impl Drop for RolloutLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        if let Some(parent) = self.path.parent() {
            let _ = File::open(parent).and_then(|file| file.sync_all());
        }
    }
}

fn require(value: bool, message: &str) -> Result<()> {
    if value { Ok(()) } else { Err(message.into()) }
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn digest_regular(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "release file must be a regular non-symlink file",
    )?;
    require(
        metadata.len() <= MAX_FILE_BYTES,
        "release file exceeds fixed size bound",
    )?;
    let mut file = File::open(path)?.take(MAX_FILE_BYTES + 1);
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        require(total <= MAX_FILE_BYTES, "release file grew beyond bound")?;
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn json_file(path: &Path, max_bytes: u64) -> Result<Value> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= max_bytes,
        "release JSON is missing, unsafe or oversized",
    )?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    require(
        bytes.len() as u64 <= max_bytes,
        "release JSON grew beyond bound",
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn ensure_real_directory(path: &Path, mode: u32) -> Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        require(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "release directory must be a real directory",
        )?;
    } else {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

fn write_json_replace(path: &Path, value: &Value, mode: u32) -> Result<()> {
    let parent = path.parent().ok_or("release JSON parent missing")?;
    ensure_real_directory(parent, 0o700)?;
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        require(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "release JSON destination must be a regular file",
        )?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    sync_directory(parent)?;
    Ok(())
}

fn write_json_create(path: &Path, value: &Value, mode: u32) -> Result<()> {
    let parent = path.parent().ok_or("release JSON parent missing")?;
    ensure_real_directory(parent, 0o700)?;
    require(!path.exists(), "release receipt already exists")?;
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    sync_directory(parent)?;
    Ok(())
}

fn ensure_backup(path: &Path, before: &Value) -> Result<()> {
    if path.exists() {
        require(
            json_file(path, 256 * 1024)? == *before,
            "release rollback backup conflicts with current pre-cutover state",
        )?;
        return Ok(());
    }
    write_json_create(path, before, 0o600)
}

fn acquire_lock(path: &Path) -> Result<RolloutLock> {
    let parent = path.parent().ok_or("release lock parent missing")?;
    ensure_real_directory(parent, 0o700)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    writeln!(file, "pid={}", std::process::id())?;
    file.sync_all()?;
    sync_directory(parent)?;
    Ok(RolloutLock {
        path: path.to_owned(),
    })
}

fn atomic_symlink(target: &Path, link: &Path) -> Result<()> {
    let parent = link.parent().ok_or("selector parent missing")?;
    ensure_real_directory(parent, 0o755)?;
    if fs::symlink_metadata(link).is_ok() {
        require(
            fs::symlink_metadata(link)?.file_type().is_symlink(),
            "selector must remain a symlink",
        )?;
    }
    let temporary = parent.join(format!(
        ".{}.{}.{}.tmp",
        link.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("mtm"),
        std::process::id(),
        now()?
    ));
    require(!temporary.exists(), "selector temporary path collision")?;
    symlink(target, &temporary)?;
    let result = fs::rename(&temporary, link);
    if temporary.exists() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    sync_directory(parent)?;
    Ok(())
}

fn command_identity(path: &Path, version: &str) -> Result<()> {
    let output = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .output()?;
    require(output.status.success(), "release binary --version failed")?;
    require(
        String::from_utf8(output.stdout)?.trim() == format!("mtm {version}"),
        "release binary version identity mismatch",
    )
}

fn smoke(path: &Path, version: &str) -> Result<()> {
    command_identity(path, version)?;
    let status = Command::new(path)
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    require(status.success(), "release binary --help smoke failed")
}

fn verify_pair(target: &Path, version: &str, expected_sha256: &str) -> Result<()> {
    require(
        digest_regular(target)? == expected_sha256,
        "selected release target hash mismatch",
    )?;
    for entry in [Path::new(SELECTOR), Path::new(CARGO_ENTRY)] {
        require(
            fs::symlink_metadata(entry)?.file_type().is_symlink(),
            "MTM command entry is not a symlink",
        )?;
        require(
            entry.canonicalize()? == target.canonicalize()?,
            "MTM command entries do not select the expected release",
        )?;
        require(
            digest_regular(&entry.canonicalize()?)? == expected_sha256,
            "MTM command entry hash mismatch",
        )?;
    }
    smoke(target, version)
}

fn switch_pair(target: &Path) -> Result<()> {
    atomic_symlink(target, Path::new(SELECTOR))?;
    atomic_symlink(target, Path::new(CARGO_ENTRY))?;
    Ok(())
}

fn copy_immutable(
    source: &Path,
    target: &Path,
    expected_sha256: &str,
    version: &str,
) -> Result<()> {
    let parent = target.parent().ok_or("release target parent missing")?;
    ensure_real_directory(parent, 0o755)?;
    if target.exists() {
        require(
            digest_regular(target)? == expected_sha256,
            "immutable release target conflicts with candidate",
        )?;
        return command_identity(target, version);
    }
    let mut input = File::open(source)?.take(MAX_FILE_BYTES + 1);
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    let copied = std::io::copy(&mut input, &mut temporary)?;
    require(
        copied <= MAX_FILE_BYTES,
        "release copy exceeded fixed bound",
    )?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o755))?;
    temporary.as_file().sync_all()?;
    require(
        digest_regular(temporary.path())? == expected_sha256,
        "release copy hash mismatch",
    )?;
    temporary
        .persist_noclobber(target)
        .map_err(|error| error.error)?;
    sync_directory(parent)?;
    require(
        digest_regular(target)? == expected_sha256,
        "published release hash mismatch",
    )?;
    command_identity(target, version)
}

fn git_clean(root: &Path) -> Result<()> {
    let output = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(root)
        .stdin(Stdio::null())
        .output()?;
    require(output.status.success(), "git status failed before release")?;
    require(
        output.stdout.is_empty(),
        "release-cutover requires a clean worktree",
    )
}

fn git_head(root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .stdin(Stdio::null())
        .output()?;
    require(output.status.success(), "git HEAD lookup failed")?;
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn append_history(manifest: &mut Value, action: &str, state: &str, timestamp: u64) -> Result<()> {
    manifest["history"]
        .as_array_mut()
        .ok_or("deployment manifest history is not an array")?
        .push(json!({"action":action,"recorded_unix_seconds":timestamp,"state":state}));
    Ok(())
}

fn validate_readiness(report: &Value) -> Result<()> {
    require(
        report["schema"] == "mtm-release-check-v1",
        "release readiness schema mismatch",
    )?;
    require(
        report["milestone"] == MILESTONE,
        "release readiness milestone mismatch",
    )?;
    require(
        report["candidate_sha256"] == CANDIDATE_SHA256,
        "release readiness candidate mismatch",
    )?;
    require(
        report["candidate_source_commit"] == CANDIDATE_SOURCE_COMMIT,
        "release readiness source identity mismatch",
    )?;
    require(report["passed"] == true, "release readiness is not passed")?;
    require(
        report["ready_for_release_review"] == true,
        "release is not ready for review",
    )?;
    require(
        report["validated_gates"] == 17,
        "release readiness does not validate all gates",
    )?;
    require(
        report["blocked_gates"] == 0,
        "release readiness still has blockers",
    )?;
    require(
        report["inputs_unchanged"] == true,
        "release inputs changed during readiness check",
    )?;
    require(
        report["production_changed"] == false,
        "readiness check changed production",
    )?;
    require(
        report["release_authorization_implemented"] == false
            && report["release_qualified"] == false,
        "read-only readiness report unexpectedly claims release authority",
    )
}

fn release_object(path: &Path, sha256: &str, version: &str) -> Result<Value> {
    Ok(json!({
        "path":path,
        "sha256":sha256,
        "size_bytes":fs::metadata(path)?.len(),
        "version":version
    }))
}

pub(crate) fn run(root: &Path, options: &Options) -> Result<Value> {
    require(
        options.authorize == MILESTONE,
        "explicit release authorization missing",
    )?;
    git_clean(root)?;
    let candidate = root.join(&options.binary);
    let release_inputs = root.join(&options.manifest);
    let receipt = root.join(RECEIPT_REL);
    require(!receipt.exists(), "MTM-016 release receipt already exists")?;
    require(
        digest_regular(&candidate)? == CANDIDATE_SHA256,
        "frozen release candidate SHA-256 mismatch",
    )?;
    command_identity(&candidate, VERSION)?;

    let readiness_options = release_check::Options::internal(&options.binary, &options.manifest);
    let readiness = release_check::run(root, &readiness_options)?;
    validate_readiness(&readiness)?;
    let release_inputs_sha256 = digest_regular(&release_inputs)?;

    let state_root = Path::new(STATE_ROOT);
    let deployment = state_root.join("deployment/deployment-v1.json");
    let rollback_backup = state_root.join("rollback/mtm016-before-preview1-deployment.json");
    let lock_path = state_root.join("deployment/mtm016-rollout.lock");
    let installed = state_root.join(format!("releases/{VERSION}/mtm"));
    let release_metadata = installed
        .parent()
        .ok_or("installed release parent missing")?
        .join("release.json");

    let before = json_file(&deployment, 256 * 1024)?;
    require(
        before["schema"] == "mtm-deployment-v1",
        "deployment schema mismatch",
    )?;
    require(
        before["state"] == "rust_active",
        "deployment is not in rust_active state",
    )?;
    let previous_path = PathBuf::from(
        before["release"]["path"]
            .as_str()
            .ok_or("deployment release path missing")?,
    );
    let previous_sha256 = before["release"]["sha256"]
        .as_str()
        .ok_or("deployment release SHA-256 missing")?
        .to_owned();
    let previous_version = before["release"]["version"]
        .as_str()
        .ok_or("deployment release version missing")?
        .to_owned();
    require(
        previous_sha256 != CANDIDATE_SHA256,
        "candidate is already the active deployment",
    )?;
    require(
        digest_regular(&previous_path)? == previous_sha256,
        "active deployment hash does not match manifest",
    )?;
    verify_pair(&previous_path, &previous_version, &previous_sha256)?;
    ensure_backup(&rollback_backup, &before)?;

    let _lock = acquire_lock(&lock_path)?;
    copy_immutable(&candidate, &installed, CANDIDATE_SHA256, VERSION)?;
    let installed_object = release_object(&installed, CANDIDATE_SHA256, VERSION)?;
    let metadata_value = json!({
        "path":installed,
        "sha256":CANDIDATE_SHA256,
        "size_bytes":fs::metadata(&installed)?.len(),
        "version":VERSION,
        "milestone":MILESTONE,
        "installed_unix_seconds":now()?
    });
    if release_metadata.exists() {
        let existing = json_file(&release_metadata, 32 * 1024)?;
        require(
            existing["path"] == metadata_value["path"]
                && existing["sha256"] == CANDIDATE_SHA256
                && existing["version"] == VERSION,
            "installed release metadata conflicts with candidate",
        )?;
    } else {
        write_json_create(&release_metadata, &metadata_value, 0o644)?;
    }

    let result = (|| -> Result<Value> {
        let mut deployed = before.clone();
        deployed["release"] = installed_object.clone();
        deployed["previous"] = json!({
            "kind":"symlink",
            "target":previous_path,
            "resolved_target":previous_path,
            "sha256":previous_sha256,
            "version":previous_version
        });

        let cutover_at = now()?;
        switch_pair(&installed)?;
        verify_pair(&installed, VERSION, CANDIDATE_SHA256)?;
        deployed["state"] = json!("rust_active");
        append_history(
            &mut deployed,
            "mtm016_preview1_cutover",
            "rust_active",
            cutover_at,
        )?;
        write_json_replace(&deployment, &deployed, 0o600)?;

        let rollback_at = now()?;
        switch_pair(&previous_path)?;
        verify_pair(&previous_path, &previous_version, &previous_sha256)?;
        deployed["state"] = json!("previous_active");
        append_history(
            &mut deployed,
            "mtm016_preview2_rollback",
            "previous_active",
            rollback_at,
        )?;
        write_json_replace(&deployment, &deployed, 0o600)?;

        let recutover_at = now()?;
        switch_pair(&installed)?;
        verify_pair(&installed, VERSION, CANDIDATE_SHA256)?;
        deployed["state"] = json!("rust_active");
        deployed["updated_at"] = json!(format!("unix:{recutover_at}"));
        deployed["updated_unix_seconds"] = json!(recutover_at);
        append_history(
            &mut deployed,
            "mtm016_preview1_recutover",
            "rust_active",
            recutover_at,
        )?;
        write_json_replace(&deployment, &deployed, 0o600)?;

        let final_manifest = json_file(&deployment, 256 * 1024)?;
        verify_pair(&installed, VERSION, CANDIDATE_SHA256)?;
        require(
            final_manifest["state"] == "rust_active",
            "final deployment state mismatch",
        )?;
        require(
            final_manifest["release"]["path"] == installed_object["path"]
                && final_manifest["release"]["sha256"] == CANDIDATE_SHA256
                && final_manifest["release"]["version"] == VERSION,
            "final deployment manifest does not select the candidate",
        )?;
        require(
            final_manifest["previous"]["sha256"] == previous_sha256,
            "final deployment rollback identity mismatch",
        )?;

        let report = json!({
            "schema_version":"1.0.0",
            "milestone":MILESTONE,
            "phase":"preview_release",
            "version":VERSION,
            "ok":true,
            "release_qualified":true,
            "release_authorized":true,
            "authorization":{"explicit_cli_authorization":true,"milestone":MILESTONE},
            "recorded_unix_seconds":now()?,
            "release_commit":git_head(root)?,
            "candidate_source_commit":CANDIDATE_SOURCE_COMMIT,
            "candidate_binary_sha256":CANDIDATE_SHA256,
            "release_input_manifest_sha256":release_inputs_sha256,
            "readiness":{"passed":true,"validated_gates":17,"blocked_gates":0,"evidence_reexecuted":false},
            "previous_version":previous_version,
            "previous_sha256":previous_sha256,
            "release_path":installed,
            "checks":{
                "readiness_revalidated":true,
                "exact_candidate_hash":true,
                "immutable_release_installed":true,
                "initial_selector_pair_consistent":true,
                "preview1_cutover_smoke":true,
                "preview2_rollback_smoke":true,
                "preview1_recutover_smoke":true,
                "final_selector_pair_consistent":true,
                "deployment_manifest_consistent":true,
                "rollback_backup_preserved":true
            },
            "check_count":10,
            "rollback":{
                "previous_path":previous_path,
                "previous_version":previous_version,
                "previous_sha256":previous_sha256,
                "real_rollback_and_recutover_passed":true
            },
            "existing_sessions_restarted":false,
            "production_data_rewritten":false,
            "production_selector_changed":true,
            "performance_claim":false,
            "evidence_hygiene":{
                "raw_capability_recorded":false,
                "raw_oauth_token_recorded":false,
                "raw_secret_recorded":false,
                "raw_logs_recorded":false
            }
        });
        write_json_create(&receipt, &report, 0o644)?;
        Ok(report)
    })();

    if result.is_err() {
        let _ = switch_pair(&previous_path);
        let _ = write_json_replace(&deployment, &before, 0o600);
        let _ = verify_pair(&previous_path, &previous_version, &previous_sha256);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_requires_exact_candidate_manifest_and_authorization() -> Result<()> {
        let good = vec![
            "--binary".to_owned(),
            BINARY_REL.to_owned(),
            "--manifest".to_owned(),
            MANIFEST_REL.to_owned(),
            "--authorize".to_owned(),
            MILESTONE.to_owned(),
        ];
        Options::parse(&good)?;
        for (index, value) in [
            (1, "target/other/mtm"),
            (3, "records/governance/other.json"),
            (5, "MTM-015"),
        ] {
            let mut bad = good.clone();
            bad[index] = value.to_owned();
            assert!(Options::parse(&bad).is_err());
        }
        Ok(())
    }

    #[test]
    fn readiness_must_remain_read_only_and_fully_validated() -> Result<()> {
        let good = json!({
            "schema":"mtm-release-check-v1","milestone":MILESTONE,
            "candidate_sha256":CANDIDATE_SHA256,"candidate_source_commit":CANDIDATE_SOURCE_COMMIT,
            "passed":true,"ready_for_release_review":true,"validated_gates":17,"blocked_gates":0,
            "inputs_unchanged":true,"production_changed":false,
            "release_authorization_implemented":false,"release_qualified":false
        });
        validate_readiness(&good)?;
        for (pointer, value) in [
            ("/passed", json!(false)),
            ("/blocked_gates", json!(1)),
            ("/validated_gates", json!(16)),
            ("/production_changed", json!(true)),
            ("/release_qualified", json!(true)),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).ok_or("test pointer missing")? = value;
            assert!(validate_readiness(&bad).is_err(), "mutated {pointer}");
        }
        Ok(())
    }

    #[test]
    fn history_append_is_explicit_and_monotone() -> Result<()> {
        let mut manifest = json!({"history":[]});
        append_history(&mut manifest, "cutover", "rust_active", 10)?;
        append_history(&mut manifest, "rollback", "previous_active", 11)?;
        assert_eq!(
            manifest["history"]
                .as_array()
                .ok_or("test history is not an array")?
                .len(),
            2
        );
        assert_eq!(manifest["history"][0]["recorded_unix_seconds"], 10);
        assert_eq!(manifest["history"][1]["recorded_unix_seconds"], 11);
        Ok(())
    }
}
