//! Explicit local release selection. Qualification remains an independent xtask gate.
#![cfg(unix)]

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const SCHEMA: &str = "mtm-install-v2";
const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

type Result<T> = std::result::Result<T, String>;

#[derive(Debug)]
struct InstallOptions {
    binary: PathBuf,
    sha256: String,
    version: String,
    state_root: PathBuf,
    selectors: Vec<PathBuf>,
}

fn require(value: bool, message: &str) -> Result<()> {
    value.then_some(()).ok_or_else(|| message.to_owned())
}

fn absolute(path: &Path, label: &str) -> Result<()> {
    require(path.is_absolute(), &format!("{label} must be absolute"))
}

fn safe_version(version: &str) -> Result<()> {
    require(
        !version.is_empty()
            && version.len() <= 128
            && version != "."
            && version != ".."
            && version.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_')
            }),
        "version is not a safe release path component",
    )
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "artifact must be a regular non-symlink file",
    )?;
    require(
        metadata.len() <= MAX_BINARY_BYTES,
        "artifact exceeds fixed release size bound",
    )?;
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn ensure_dir(path: &Path, mode: u32) -> Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        require(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "deployment directory must be a real directory",
        )?;
    } else {
        fs::create_dir_all(path).map_err(|error| error.to_string())?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| error.to_string())
}

fn atomic_bytes(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| "output has no parent".to_owned())?;
    ensure_dir(parent, 0o700)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "output filename is not UTF-8".to_owned())?;
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        file.write_all(bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))
            .map_err(|error| error.to_string())?;
        fs::rename(&temporary, path).map_err(|error| error.to_string())?;
        sync_dir(parent)
    })();
    if temporary.exists() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn atomic_json(path: &Path, payload: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(payload).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    atomic_bytes(path, &bytes, 0o600)
}

fn atomic_link(target: &Path, selector: &Path) -> Result<()> {
    absolute(selector, "selector")?;
    let parent = selector
        .parent()
        .ok_or_else(|| "selector has no parent".to_owned())?;
    ensure_dir(parent, 0o755)?;
    let name = selector
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "selector filename is not UTF-8".to_owned())?;
    require(name == "mtm", "selector must be named mtm")?;
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    if fs::symlink_metadata(&temporary).is_ok() {
        return Err("stale selector staging entry exists".to_owned());
    }
    let result = (|| -> Result<()> {
        symlink(target, &temporary).map_err(|error| error.to_string())?;
        fs::rename(&temporary, selector).map_err(|error| error.to_string())?;
        sync_dir(parent)
    })();
    if fs::symlink_metadata(&temporary).is_ok() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn parse_install(arguments: &[String]) -> Result<InstallOptions> {
    let mut binary = None;
    let mut sha256 = None;
    let mut version = None;
    let mut state_root = None;
    let mut selectors = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let key = arguments[index].as_str();
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{key} requires a value"))?;
        match key {
            "--binary" if binary.is_none() => binary = Some(PathBuf::from(value)),
            "--sha256" if sha256.is_none() => sha256 = Some(value.to_owned()),
            "--version" if version.is_none() => version = Some(value.to_owned()),
            "--state-root" if state_root.is_none() => state_root = Some(PathBuf::from(value)),
            "--selector" => selectors.push(PathBuf::from(value)),
            _ => return Err(format!("unknown or duplicate install option: {key}")),
        }
        index += 2;
    }
    let options = InstallOptions {
        binary: binary.ok_or_else(|| "--binary is required".to_owned())?,
        sha256: sha256.ok_or_else(|| "--sha256 is required".to_owned())?,
        version: version.ok_or_else(|| "--version is required".to_owned())?,
        state_root: state_root.ok_or_else(|| "--state-root is required".to_owned())?,
        selectors,
    };
    absolute(&options.binary, "binary")?;
    absolute(&options.state_root, "state root")?;
    require(
        valid_sha256(&options.sha256),
        "--sha256 must be lowercase SHA-256",
    )?;
    safe_version(&options.version)?;
    require(
        (1..=8).contains(&options.selectors.len()),
        "install requires one to eight explicit selectors",
    )?;
    let mut unique = BTreeSet::new();
    for selector in &options.selectors {
        absolute(selector, "selector")?;
        require(unique.insert(selector), "duplicate selector")?;
    }
    Ok(options)
}

fn parse_state_root(arguments: &[String]) -> Result<PathBuf> {
    if let [flag, value] = arguments
        && flag == "--state-root"
    {
        let root = PathBuf::from(value);
        absolute(&root, "state root")?;
        return Ok(root);
    }
    Err("expected exactly --state-root <absolute-path>".to_owned())
}

fn copy_release(source: &Path, destination: &Path, expected: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(source).map_err(|error| error.to_string())?;
    require(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o111 != 0,
        "release source must be an executable regular non-symlink file",
    )?;
    require(
        digest(source)? == expected,
        "release source SHA-256 mismatch",
    )?;
    if destination.exists() {
        return require(
            digest(destination)? == expected,
            "immutable release destination conflicts with selected SHA-256",
        );
    }
    let mut source_file = File::open(source).map_err(|error| error.to_string())?;
    let parent = destination
        .parent()
        .ok_or_else(|| "release destination has no parent".to_owned())?;
    ensure_dir(parent, 0o755)?;
    let temporary = parent.join(format!(".mtm.{}.tmp", std::process::id()));
    let result = (|| -> Result<()> {
        let mut target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        std::io::copy(&mut source_file, &mut target).map_err(|error| error.to_string())?;
        target.sync_all().map_err(|error| error.to_string())?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755))
            .map_err(|error| error.to_string())?;
        require(
            digest(&temporary)? == expected,
            "copied release SHA-256 mismatch",
        )?;
        fs::rename(&temporary, destination).map_err(|error| error.to_string())?;
        sync_dir(parent)
    })();
    if temporary.exists() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn previous(selector: &Path, rollback: &Path, index: usize) -> Result<Value> {
    match fs::symlink_metadata(selector) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(json!({"kind":"missing"})),
        Err(error) => Err(error.to_string()),
        Ok(metadata) if metadata.file_type().is_symlink() => Ok(json!({
            "kind":"symlink",
            "target":fs::read_link(selector).map_err(|error| error.to_string())?
        })),
        Ok(metadata) if metadata.is_file() => {
            ensure_dir(rollback, 0o700)?;
            let backup = rollback.join(format!("selector-{index}.backup"));
            if backup.exists() {
                return Err("rollback selector backup already exists".to_owned());
            }
            fs::copy(selector, &backup).map_err(|error| error.to_string())?;
            let mode = metadata.permissions().mode() & 0o777;
            fs::set_permissions(&backup, fs::Permissions::from_mode(mode))
                .map_err(|error| error.to_string())?;
            Ok(json!({"kind":"file","backup":backup,"sha256":digest(&backup)?,"mode":mode}))
        }
        Ok(_) => Err("selector is neither a symlink nor regular file".to_owned()),
    }
}

fn text_path(value: &Value, key: &str) -> Result<PathBuf> {
    value[key]
        .as_str()
        .map(PathBuf::from)
        .ok_or_else(|| format!("manifest {key} is missing"))
}

fn restore_one(selector: &Path, previous: &Value) -> Result<()> {
    let kind = previous["kind"]
        .as_str()
        .ok_or_else(|| "previous selector kind is missing".to_owned())?;
    match kind {
        "missing" => match fs::symlink_metadata(selector) {
            Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
                fs::remove_file(selector).map_err(|error| error.to_string())?;
                sync_dir(
                    selector
                        .parent()
                        .ok_or_else(|| "selector parent missing".to_owned())?,
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err("selector changed to a non-file during rollback".to_owned()),
            Err(error) => Err(error.to_string()),
        },
        "symlink" => atomic_link(&text_path(previous, "target")?, selector),
        "file" => {
            let backup = text_path(previous, "backup")?;
            let expected = previous["sha256"]
                .as_str()
                .ok_or_else(|| "backup hash missing".to_owned())?;
            require(valid_sha256(expected), "invalid backup SHA-256")?;
            require(
                digest(&backup)? == expected,
                "rollback backup SHA-256 mismatch",
            )?;
            let mode = previous["mode"]
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| "rollback backup mode invalid".to_owned())?;
            let bytes = fs::read(&backup).map_err(|error| error.to_string())?;
            atomic_bytes(selector, &bytes, mode)
        }
        _ => Err("unknown previous selector kind".to_owned()),
    }
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("deployment/current-v2.json")
}

fn load_manifest(root: &Path) -> Result<Value> {
    let path = manifest_path(root);
    let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
    require(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() <= MAX_MANIFEST_BYTES,
        "deployment manifest is unsafe or oversized",
    )?;
    let payload: Value =
        serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    require(
        payload["schema"] == SCHEMA,
        "unsupported deployment manifest schema",
    )?;
    Ok(payload)
}

fn selector_entries(payload: &Value) -> Result<&Vec<Value>> {
    payload["selectors"]
        .as_array()
        .ok_or_else(|| "deployment manifest selectors are missing".to_owned())
}

fn verify_installed(payload: &Value, state_root: &Path) -> Result<()> {
    let release = text_path(payload, "release_path")?;
    absolute(&release, "manifest release path")?;
    let canonical_root = state_root
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let canonical_release = release.canonicalize().map_err(|error| error.to_string())?;
    require(
        canonical_release.starts_with(canonical_root.join("releases")),
        "manifest release escapes state root",
    )?;
    let expected = payload["sha256"]
        .as_str()
        .ok_or_else(|| "manifest release hash missing".to_owned())?;
    require(valid_sha256(expected), "manifest release hash invalid")?;
    require(
        digest(&release)? == expected,
        "installed release SHA-256 drifted",
    )?;
    Ok(())
}

fn selector_is_target(selector: &Path, target: &Path) -> Result<bool> {
    let metadata = match fs::symlink_metadata(selector) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.to_string()),
    };
    if !metadata.file_type().is_symlink() {
        return Ok(false);
    }
    let resolved = selector.canonicalize().map_err(|error| error.to_string())?;
    let target = target.canonicalize().map_err(|error| error.to_string())?;
    Ok(resolved == target)
}

fn restored(previous: &Value, selector: &Path) -> Result<bool> {
    match previous["kind"].as_str() {
        Some("missing") => match fs::symlink_metadata(selector) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error.to_string()),
            Ok(_) => Ok(false),
        },
        Some("symlink") => {
            let metadata = match fs::symlink_metadata(selector) {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error.to_string()),
            };
            Ok(metadata.file_type().is_symlink()
                && fs::read_link(selector).map_err(|error| error.to_string())?
                    == text_path(previous, "target")?)
        }
        Some("file") => Ok(fs::symlink_metadata(selector)
            .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
            && digest(selector)?
                == previous["sha256"]
                    .as_str()
                    .ok_or_else(|| "backup hash missing".to_owned())?),
        _ => Err("unknown previous selector kind".to_owned()),
    }
}

fn status_for_root(root: &Path) -> Result<Value> {
    let payload = load_manifest(root)?;
    verify_installed(&payload, root)?;
    let release = text_path(&payload, "release_path")?;
    let state = payload["state"]
        .as_str()
        .ok_or_else(|| "deployment state missing".to_owned())?;
    let mut selector_checks = Vec::new();
    for entry in selector_entries(&payload)? {
        let selector = text_path(entry, "path")?;
        let correct = match state {
            "active" => selector_is_target(&selector, &release)?,
            "previous_active" => restored(&entry["previous"], &selector)?,
            _ => return Err("unknown deployment state".to_owned()),
        };
        selector_checks.push(json!({"path":selector,"correct":correct}));
    }
    require(
        selector_checks.iter().all(|entry| entry["correct"] == true),
        "one or more installed selectors drifted",
    )?;
    Ok(json!({
        "ok":true,"scope":"explicit_local_installation","schema":SCHEMA,"state":state,
        "version":payload["version"],"sha256":payload["sha256"],"release_path":release,
        "selectors":selector_checks,"installed_selector_checked":true,
        "release_qualification_checked":false,"release_qualified":false,
        "python_runtime_required":false
    }))
}

pub(crate) fn install(arguments: &[String]) -> Result<Value> {
    let options = parse_install(arguments)?;
    ensure_dir(&options.state_root, 0o700)?;
    let release = options
        .state_root
        .join("releases")
        .join(&options.version)
        .join(&options.sha256)
        .join("mtm");
    copy_release(&options.binary, &release, &options.sha256)?;
    let metadata = fs::metadata(&release).map_err(|error| error.to_string())?;
    let release_metadata = json!({
        "schema":"mtm-release-v2","version":options.version,"sha256":options.sha256,
        "size_bytes":metadata.len(),"path":release,"release_qualified":false
    });
    let release_metadata_path = release
        .parent()
        .ok_or_else(|| "release parent missing".to_owned())?
        .join("release.json");
    atomic_json(&release_metadata_path, &release_metadata)?;

    let deployment = options.state_root.join("deployment");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let rollback = deployment
        .join("rollback-v2")
        .join(format!("{}-{nonce}", options.sha256));
    let mut selectors = Vec::new();
    for (index, selector) in options.selectors.iter().enumerate() {
        selectors.push(json!({
            "path":selector,
            "previous":previous(selector, &rollback, index)?
        }));
    }
    let payload = json!({
        "schema":SCHEMA,"state":"active","version":options.version,
        "sha256":options.sha256,"release_path":release,"selectors":selectors,
        "release_qualified":false,"python_runtime_required":false
    });
    let entries = selector_entries(&payload)?.clone();
    for (index, entry) in entries.iter().enumerate() {
        let selector = text_path(entry, "path")?;
        if let Err(error) = atomic_link(&release, &selector) {
            for original in entries[..index].iter().rev() {
                if let Ok(restored_selector) = text_path(original, "path") {
                    let _ = restore_one(&restored_selector, &original["previous"]);
                }
            }
            return Err(format!(
                "selector update failed and was compensated: {error}"
            ));
        }
    }
    if let Err(error) = atomic_json(&manifest_path(&options.state_root), &payload) {
        for entry in entries.iter().rev() {
            if let Ok(selector) = text_path(entry, "path") {
                let _ = restore_one(&selector, &entry["previous"]);
            }
        }
        return Err(format!(
            "manifest commit failed and selectors were compensated: {error}"
        ));
    }
    status_for_root(&options.state_root)
}

pub(crate) fn status(arguments: &[String]) -> Result<Value> {
    status_for_root(&parse_state_root(arguments)?)
}

pub(crate) fn rollback(arguments: &[String]) -> Result<Value> {
    let root = parse_state_root(arguments)?;
    let mut payload = load_manifest(&root)?;
    require(
        payload["state"] == "active",
        "rollback requires an active installation",
    )?;
    verify_installed(&payload, &root)?;
    let release = text_path(&payload, "release_path")?;
    let entries = selector_entries(&payload)?.clone();
    for entry in &entries {
        let selector = text_path(entry, "path")?;
        require(
            selector_is_target(&selector, &release)?,
            "selector drifted before rollback",
        )?;
    }
    for (index, entry) in entries.iter().enumerate() {
        let selector = text_path(entry, "path")?;
        if let Err(error) = restore_one(&selector, &entry["previous"]) {
            for restored_entry in entries[..index].iter().rev() {
                if let Ok(restored_selector) = text_path(restored_entry, "path") {
                    let _ = atomic_link(&release, &restored_selector);
                }
            }
            return Err(format!(
                "rollback failed and active selectors were restored: {error}"
            ));
        }
    }
    payload["state"] = Value::String("previous_active".to_owned());
    if let Err(error) = atomic_json(&manifest_path(&root), &payload) {
        for entry in &entries {
            if let Ok(selector) = text_path(entry, "path") {
                let _ = atomic_link(&release, &selector);
            }
        }
        return Err(format!(
            "rollback manifest failed and active selectors were restored: {error}"
        ));
    }
    status_for_root(&root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_requires_explicit_bounded_absolute_inputs() {
        let base = [
            "--binary",
            "/tmp/candidate",
            "--sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--version",
            "0.6.0-preview.1",
            "--state-root",
            "/tmp/state",
            "--selector",
            "/tmp/bin/mtm",
        ]
        .map(str::to_owned);
        assert!(parse_install(&base).is_ok());
        assert!(parse_install(&base[..8]).is_err());
        let mut relative = base.to_vec();
        relative[7] = "relative".into();
        assert!(parse_install(&relative).is_err());
        let mut bad_hash = base.to_vec();
        bad_hash[3] = "A".repeat(64);
        assert!(parse_install(&bad_hash).is_err());
    }
}
