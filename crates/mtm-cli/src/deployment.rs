//! Explicit local release selection. Qualification remains an independent xtask gate.
#![cfg(unix)]

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink};
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
    let text = path
        .to_str()
        .ok_or_else(|| format!("{label} must be UTF-8"))?;
    require(
        path.is_absolute()
            && text.len() <= 4096
            && (text == "/"
                || text
                    .split('/')
                    .skip(1)
                    .all(|part| !matches!(part, "" | "." | ".."))),
        &format!("{label} must be a normalized absolute path"),
    )
}

// Static path guards and a cooperative installation lock, not a hostile same-UID
// filesystem boundary. Never follow an existing directory symlink, even in-root.
fn directory_chain(path: &Path) -> Result<()> {
    absolute(path, "directory")?;
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => require(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "deployment directory is not a real directory",
            )?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

fn bounded_bytes(path: &Path, limit: u64) -> Result<Vec<u8>> {
    directory_chain(path.parent().ok_or("file parent missing")?)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= limit,
        "file must be bounded, regular and non-symlink",
    )?;
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    require(bytes.len() as u64 <= limit, "file grew beyond its bound")?;
    Ok(bytes)
}

fn installation_lock(root: &Path, create: bool) -> Result<nix::fcntl::Flock<File>> {
    directory_chain(root)?;
    let parent = root.join("deployment");
    if create {
        ensure_dir(&parent, 0o700)?;
    }
    directory_chain(&parent)?;
    let path = parent.join("install-v2.lock");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => require(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "unsafe installation lock",
        )?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {}
        Err(error) => return Err(error.to_string()),
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .map_err(|error| error.to_string())?;
    // The inode stays permanent. Removing it would let later callers bypass a lock.
    nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|_| "installation busy or lock unavailable".to_owned())
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
    directory_chain(path.parent().ok_or("artifact parent missing")?)?;
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
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        total += count as u64;
        require(total <= MAX_BINARY_BYTES, "artifact grew beyond its bound")?;
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn ensure_dir(path: &Path, mode: u32) -> Result<()> {
    directory_chain(path)?;
    if path.exists() {
        let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        require(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "deployment directory must be a real directory",
        )?;
    } else {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(mode)
            .create(path)
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
    require(mode <= 0o777, "special permission bits are forbidden")?;
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|error| error.to_string())?;
    // NamedTempFile starts owner-only before any backup or manifest bytes exist.
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|error| error.to_string())?;
    file.as_file()
        .sync_all()
        .map_err(|error| error.to_string())?;
    file.persist(path)
        .map_err(|error| error.error.to_string())?;
    sync_dir(parent)
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
        require(
            selector.file_name().is_some_and(|name| name == "mtm"),
            "selector must be named mtm",
        )?;
        require(
            !selector.starts_with(&options.state_root)
                && !options.state_root.starts_with(selector)
                && selector != &options.binary
                && !options.binary.starts_with(selector),
            "selector overlaps source or installation state",
        )?;
        directory_chain(selector.parent().ok_or("selector parent missing")?)?;
        require(unique.insert(selector), "duplicate selector")?;
    }
    require(
        options.state_root != Path::new("/"),
        "state root cannot be filesystem root",
    )?;
    directory_chain(&options.state_root)?;
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
            && metadata.permissions().mode() & 0o111 != 0
            && metadata.permissions().mode() & 0o6000 == 0,
        "release source must be an executable regular non-symlink file",
    )?;
    require(
        digest(source)? == expected,
        "release source SHA-256 mismatch",
    )?;
    if fs::symlink_metadata(destination).is_ok() {
        return require(
            digest(destination)? == expected
                && fs::metadata(destination)
                    .map_err(|error| error.to_string())?
                    .permissions()
                    .mode()
                    & 0o7777
                    == 0o755,
            "immutable release destination conflicts with selected SHA-256",
        );
    }
    let mut source_file = File::open(source)
        .map_err(|error| error.to_string())?
        .take(MAX_BINARY_BYTES + 1);
    let parent = destination
        .parent()
        .ok_or_else(|| "release destination has no parent".to_owned())?;
    ensure_dir(parent, 0o755)?;
    let mut target = tempfile::NamedTempFile::new_in(parent).map_err(|error| error.to_string())?;
    let copied = std::io::copy(&mut source_file, &mut target).map_err(|error| error.to_string())?;
    require(copied <= MAX_BINARY_BYTES, "release copy grew beyond bound")?;
    target
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o755))
        .map_err(|error| error.to_string())?;
    target
        .as_file()
        .sync_all()
        .map_err(|error| error.to_string())?;
    require(
        digest(target.path())? == expected && digest(source)? == expected,
        "copied release SHA-256 mismatch",
    )?;
    // Unlike rename, no-clobber publication never overwrites a racing artifact.
    match target.persist_noclobber(destination) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            require(
                digest(destination)? == expected,
                "immutable release race conflict",
            )?;
        }
        Err(error) => return Err(error.error.to_string()),
    }
    sync_dir(parent)
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
            let mode = metadata.permissions().mode() & 0o777;
            let bytes = bounded_bytes(selector, MAX_BINARY_BYTES)?;
            atomic_bytes(&backup, &bytes, 0o600)?;
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
            require(
                mode <= 0o777,
                "rollback mode contains special permission bits",
            )?;
            let bytes = bounded_bytes(&backup, MAX_BINARY_BYTES)?;
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
    let payload: Value = serde_json::from_slice(&bounded_bytes(&path, MAX_MANIFEST_BYTES)?)
        .map_err(|error| error.to_string())?;
    validate_manifest(&payload, root)?;
    Ok(payload)
}

fn exact_keys(value: &Value, expected: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or("manifest object required")?;
    require(
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key)),
        "manifest fields differ from contract",
    )
}

fn validate_manifest(payload: &Value, root: &Path) -> Result<()> {
    exact_keys(
        payload,
        &[
            "schema",
            "state",
            "version",
            "sha256",
            "release_path",
            "selectors",
            "release_qualified",
            "python_runtime_required",
        ],
    )?;
    require(
        payload["schema"] == SCHEMA
            && matches!(
                payload["state"].as_str(),
                Some("active" | "previous_active")
            )
            && payload["release_qualified"] == false
            && payload["python_runtime_required"] == false,
        "unsupported deployment identity or state",
    )?;
    let version = payload["version"]
        .as_str()
        .ok_or("manifest version missing")?;
    safe_version(version)?;
    let hash = payload["sha256"].as_str().ok_or("manifest hash missing")?;
    require(valid_sha256(hash), "invalid manifest SHA-256")?;
    require(
        text_path(payload, "release_path")?
            == root.join("releases").join(version).join(hash).join("mtm"),
        "release path differs from exact content address",
    )?;
    let entries = selector_entries(payload)?;
    require(
        (1..=8).contains(&entries.len()),
        "manifest needs one to eight selectors",
    )?;
    let mut paths = BTreeSet::new();
    for (index, entry) in entries.iter().enumerate() {
        exact_keys(entry, &["path", "previous"])?;
        let path = text_path(entry, "path")?;
        absolute(&path, "manifest selector")?;
        require(
            path.file_name().is_some_and(|name| name == "mtm")
                && !path.starts_with(root)
                && !root.starts_with(&path)
                && paths.insert(path.clone()),
            "invalid, duplicate or overlapping manifest selector",
        )?;
        directory_chain(path.parent().ok_or("selector parent missing")?)?;
        let previous = &entry["previous"];
        match previous["kind"].as_str() {
            Some("missing") => exact_keys(previous, &["kind"])?,
            Some("symlink") => {
                exact_keys(previous, &["kind", "target"])?;
                require(
                    previous["target"]
                        .as_str()
                        .is_some_and(|text| !text.is_empty() && text.len() <= 4096),
                    "invalid previous link target",
                )?;
            }
            Some("file") => {
                exact_keys(previous, &["kind", "backup", "sha256", "mode"])?;
                let backup = text_path(previous, "backup")?;
                absolute(&backup, "rollback backup")?;
                require(
                    backup.parent().and_then(Path::parent)
                        == Some(root.join("deployment/rollback-v2").as_path())
                        && backup.file_name().is_some_and(|name| {
                            name == format!("selector-{index}.backup").as_str()
                        })
                        && previous["sha256"].as_str().is_some_and(valid_sha256)
                        && previous["mode"].as_u64().is_some_and(|mode| mode <= 0o777),
                    "invalid backup location, mode or hash",
                )?;
            }
            _ => return Err("unsupported previous selector kind".into()),
        }
    }
    Ok(())
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
    require(
        fs::metadata(&release)
            .map_err(|error| error.to_string())?
            .permissions()
            .mode()
            & 0o7777
            == 0o755,
        "installed release is not an ordinary executable",
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
        Some("file") => Ok(fs::symlink_metadata(selector).is_ok_and(|metadata| {
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && previous["mode"].as_u64()
                    == Some(u64::from(metadata.permissions().mode() & 0o777))
        }) && digest(selector)?
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
    // The selected candidate installs its own exact bytes. This binds the label
    // without launching an unchecked external program or introducing a runner.
    require(
        options.version == env!("CARGO_PKG_VERSION"),
        "run install through the intended versioned MTM artifact",
    )?;
    let running = std::env::current_exe().map_err(|error| error.to_string())?;
    require(
        digest(&options.binary)? == options.sha256 && digest(&running)? == options.sha256,
        "install must select the running candidate's exact bytes",
    )?;
    ensure_dir(&options.state_root, 0o700)?;
    let _lock = installation_lock(&options.state_root, true)?;
    let manifest = manifest_path(&options.state_root);
    let before = match fs::symlink_metadata(&manifest) {
        Ok(_) => {
            let old = load_manifest(&options.state_root)?;
            status_for_root(&options.state_root)?;
            let old_paths: Vec<_> = selector_entries(&old)?
                .iter()
                .map(|entry| text_path(entry, "path"))
                .collect::<Result<_>>()?;
            require(
                old_paths == options.selectors,
                "existing installation selector set cannot change implicitly",
            )?;
            if old["state"] == "active"
                && old["version"] == options.version
                && old["sha256"] == options.sha256
            {
                return status_for_root(&options.state_root);
            }
            Some(bounded_bytes(&manifest, MAX_MANIFEST_BYTES)?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.to_string()),
    };
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
    if fs::symlink_metadata(&release_metadata_path).is_ok() {
        let existing: Value =
            serde_json::from_slice(&bounded_bytes(&release_metadata_path, MAX_MANIFEST_BYTES)?)
                .map_err(|error| error.to_string())?;
        require(
            existing == release_metadata,
            "immutable release metadata conflicts",
        )?;
    } else {
        atomic_json(&release_metadata_path, &release_metadata)?;
    }

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
    validate_manifest(&payload, &options.state_root)?;
    let entries = selector_entries(&payload)?.clone();
    for (index, entry) in entries.iter().enumerate() {
        let selector = text_path(entry, "path")?;
        if atomic_link(&release, &selector).is_err() {
            // Include the failing entry: rename can succeed before fsync fails.
            let restored = compensate(&entries[..=index], None, &manifest, before.as_deref());
            return Err(compensation_message("selector update", restored));
        }
    }
    if atomic_json(&manifest, &payload).is_err() || status_for_root(&options.state_root).is_err() {
        let restored = compensate(&entries, None, &manifest, before.as_deref());
        return Err(compensation_message(
            "manifest commit or postcheck",
            restored,
        ));
    }
    status_for_root(&options.state_root)
}

pub(crate) fn status(arguments: &[String]) -> Result<Value> {
    let root = parse_state_root(arguments)?;
    let _lock = installation_lock(&root, false)?;
    status_for_root(&root)
}

pub(crate) fn rollback(arguments: &[String]) -> Result<Value> {
    let root = parse_state_root(arguments)?;
    let _lock = installation_lock(&root, false)?;
    let mut payload = load_manifest(&root)?;
    if payload["state"] == "previous_active" {
        return status_for_root(&root);
    }
    let before = bounded_bytes(&manifest_path(&root), MAX_MANIFEST_BYTES)?;
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
        if entry["previous"]["kind"] == "file" {
            require(
                digest(&text_path(&entry["previous"], "backup")?)? == entry["previous"]["sha256"],
                "rollback backup drifted before mutation",
            )?;
        }
    }
    for (index, entry) in entries.iter().enumerate() {
        let selector = text_path(entry, "path")?;
        if restore_one(&selector, &entry["previous"]).is_err() {
            let restored = compensate(
                &entries[..=index],
                Some(&release),
                &manifest_path(&root),
                Some(&before),
            );
            return Err(compensation_message("rollback selector", restored));
        }
    }
    payload["state"] = Value::String("previous_active".to_owned());
    if atomic_json(&manifest_path(&root), &payload).is_err() || status_for_root(&root).is_err() {
        let restored = compensate(
            &entries,
            Some(&release),
            &manifest_path(&root),
            Some(&before),
        );
        return Err(compensation_message(
            "rollback manifest or postcheck",
            restored,
        ));
    }
    status_for_root(&root)
}

fn compensation_message(stage: &str, verified: bool) -> String {
    format!("{stage} failed; compensation_verified={verified}; no release qualification is implied")
}

fn compensate(
    entries: &[Value],
    active: Option<&Path>,
    manifest: &Path,
    before: Option<&[u8]>,
) -> bool {
    let mut verified = true;
    for entry in entries.iter().rev() {
        let result = text_path(entry, "path").and_then(|selector| match active {
            Some(target) => atomic_link(target, &selector),
            None => restore_one(&selector, &entry["previous"]),
        });
        verified &= result.is_ok();
    }
    let restored_manifest = match before {
        Some(bytes) => atomic_bytes(manifest, bytes, 0o600),
        None => match fs::remove_file(manifest) {
            Ok(()) => manifest
                .parent()
                .ok_or("manifest parent missing".into())
                .and_then(sync_dir),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.to_string()),
        },
    };
    verified &= restored_manifest.is_ok();
    verified &= match before {
        Some(bytes) => bounded_bytes(manifest, MAX_MANIFEST_BYTES).is_ok_and(|now| now == bytes),
        None => fs::symlink_metadata(manifest)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
    };
    for entry in entries {
        let checked = text_path(entry, "path").and_then(|selector| match active {
            Some(target) => selector_is_target(&selector, target),
            None => restored(&entry["previous"], &selector),
        });
        verified &= checked == Ok(true);
    }
    verified
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compensation_reports_failure_without_hiding_successful_other_restores() -> Result<()> {
        let temp = tempfile::tempdir().map_err(|error| error.to_string())?;
        let first = temp.path().join("a/mtm");
        let second = temp.path().join("b/mtm");
        let manifest = temp.path().join("deployment/current-v2.json");
        ensure_dir(first.parent().ok_or("parent")?, 0o700)?;
        ensure_dir(second.parent().ok_or("parent")?, 0o700)?;
        let entries = vec![
            json!({"path":first,"previous":{"kind":"missing"}}),
            json!({"path":second,"previous":{"kind":"missing"}}),
        ];
        atomic_link(Path::new("/unused-candidate"), &first)?;
        atomic_link(Path::new("/unused-candidate"), &second)?;
        assert!(compensate(&entries, None, &manifest, None));
        atomic_link(Path::new("/unused-candidate"), &first)?;
        ensure_dir(&second, 0o700)?;
        assert!(!compensate(&entries, None, &manifest, None));
        assert!(fs::symlink_metadata(&first).is_err());
        assert!(second.is_dir());
        assert!(compensation_message("fixture", false).contains("compensation_verified=false"));
        Ok(())
    }

    #[test]
    fn manifest_rejects_unknown_fields_backup_escape_and_special_modes() -> Result<()> {
        let temp = tempfile::tempdir().map_err(|error| error.to_string())?;
        let root = temp.path().join("state");
        let hash = "a".repeat(64);
        let value = json!({"schema":SCHEMA,"state":"active","version":"fixture",
            "sha256":hash,"release_path":root.join("releases/fixture").join(&hash).join("mtm"),
            "selectors":[{"path":temp.path().join("bin/mtm"),"previous":{"kind":"file",
                "backup":root.join("deployment/rollback-v2/session/selector-0.backup"),"sha256":hash,"mode":448}}],
            "release_qualified":false,"python_runtime_required":false});
        validate_manifest(&value, &root)?;
        for (pointer, replacement) in [
            ("/selectors/0/path", json!(root.join("mtm"))),
            (
                "/selectors/0/previous/backup",
                json!(temp.path().join("outside")),
            ),
            ("/selectors/0/previous/mode", json!(0o4755)),
            ("/selectors/0/previous/mode", json!(448.0)),
            ("/release_qualified", json!(true)),
            ("/selectors", json!([])),
            ("/state", json!("future")),
        ] {
            let mut changed = value.clone();
            *changed.pointer_mut(pointer).ok_or("fixture pointer")? = replacement;
            assert!(validate_manifest(&changed, &root).is_err());
        }
        let mut unknown = value.clone();
        unknown["override"] = json!(true);
        assert!(validate_manifest(&unknown, &root).is_err());
        let mut duplicate = value.clone();
        duplicate["selectors"] = json!([value["selectors"][0], value["selectors"][0]]);
        assert!(validate_manifest(&duplicate, &root).is_err());
        Ok(())
    }

    #[test]
    fn release_publication_preserves_conflicts_and_lock_inode_serializes_writers() -> Result<()> {
        let temp = tempfile::tempdir().map_err(|error| error.to_string())?;
        let source = temp.path().join("source");
        let target = temp.path().join("mtm");
        atomic_bytes(&source, b"fixture-only-not-an-installable-runtime", 0o755)?;
        let expected = digest(&source)?;
        copy_release(&source, &target, &expected)?;
        copy_release(&source, &target, &expected)?;
        atomic_bytes(&target, b"conflicting immutable artifact", 0o755)?;
        assert!(copy_release(&source, &target, &expected).is_err());
        assert_eq!(
            bounded_bytes(&target, MAX_BINARY_BYTES)?,
            b"conflicting immutable artifact"
        );
        let root = temp.path().join("state");
        let first = installation_lock(&root, true)?;
        assert!(installation_lock(&root, true).is_err());
        drop(first);
        let _second = installation_lock(&root, false)?;
        assert_eq!(
            fs::metadata(root.join("deployment/install-v2.lock"))
                .map_err(|error| error.to_string())?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        Ok(())
    }

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
