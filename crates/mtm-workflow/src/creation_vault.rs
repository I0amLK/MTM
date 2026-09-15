//! Restartable initialization only. Ordinary proof/memory writes do not use this path.
use super::*;
use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_REFERENCES: usize = 128;

pub(crate) struct PreparedInitialization {
    files: Vec<(PathBuf, Vec<u8>)>,
    pub(crate) problem_sha256: String,
    pub(crate) references: Vec<mtm_storage::CreationReference>,
}

impl PreparedInitialization {
    pub(crate) fn new(problem: &str, references: &[Value]) -> Result<Self, ReCtmError> {
        if problem.trim().is_empty() || references.len() > MAX_REFERENCES {
            return Err(validation(
                "Initialization needs a problem and at most 128 references.",
            ));
        }
        let mut total = problem.len();
        if total > MAX_INPUT_BYTES {
            return Err(too_large());
        }
        let mut names = BTreeSet::new();
        let mut normalized = Vec::new();
        let mut manifest = Vec::new();
        let mut files = vec![(
            PathBuf::from("input/problem.tex"),
            problem.as_bytes().to_vec(),
        )];
        for (index, value) in references.iter().enumerate() {
            let value = value
                .as_object()
                .ok_or_else(|| validation("Reference must be an object."))?;
            let default = format!("reference-{}.txt", index + 1);
            let name = safe_reference_name(
                value
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or(&default),
            )?;
            if name.len() > 255 || !names.insert(name.clone()) {
                return Err(validation_code(
                    "DUPLICATE_OR_LONG_REFERENCE_NAME",
                    "Reference names must be unique and at most 255 bytes.",
                ));
            }
            let content = value
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let source = value
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or("inline");
            total = total
                .saturating_add(name.len())
                .saturating_add(content.len())
                .saturating_add(source.len());
            if total > MAX_INPUT_BYTES {
                return Err(too_large());
            }
            manifest.push(
                serde_json::json!({"name":name,"sha256":sha256_text(content),
                "size":content.len(),"source":source}),
            );
            files.push((
                PathBuf::from("references").join(&name),
                content.as_bytes().to_vec(),
            ));
            normalized.push(mtm_storage::CreationReference {
                name,
                content: content.to_owned(),
                source: source.to_owned(),
            });
        }
        if total > MAX_INPUT_BYTES {
            return Err(too_large());
        }
        files.push((
            PathBuf::from("references/manifest.json"),
            pretty_json(&Value::Array(manifest))?.into_bytes(),
        ));
        Ok(Self {
            files,
            references: normalized,
            problem_sha256: sha256_text(problem),
        })
    }
}

/// An OS lock on a permanent private inode, not an authorization capability.
pub(crate) struct CreationGuard {
    _lock: Flock<File>,
    root: PathBuf,
}

impl PrivateVault {
    pub(crate) fn lock_initialization(&self, run: &str) -> Result<CreationGuard, ReCtmError> {
        let root = self.run_root(run)?;
        ensure_directory(&self.runs_root)?;
        ensure_directory(&root)?;
        let path = root.join(".creation.lock");
        if let Ok(meta) = fs::symlink_metadata(&path) {
            regular_private(&meta)?;
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&path)
            .map_err(io_error)?;
        let opened = lock.metadata().map_err(io_error)?;
        regular_private(&opened)?;
        let named = fs::symlink_metadata(&path).map_err(io_error)?;
        regular_private(&named)?;
        if opened.ino() != named.ino() || opened.dev() != named.dev() || opened.nlink() != 1 {
            return Err(conflict());
        }
        match Flock::lock(lock, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => Ok(CreationGuard { _lock: lock, root }),
            Err((_, Errno::EWOULDBLOCK)) => Err(ReCtmError::new(
                "CREATION_RESULT_UNKNOWN",
                "Another initialization attempt holds the run lock; keep the same creation key.",
            )
            .with_category(ErrorCategory::Conflict)
            .with_retryable(false)),
            Err((_, error)) => Err(io_error(std::io::Error::from_raw_os_error(error as i32))),
        }
    }
}

impl CreationGuard {
    pub(crate) fn publish(
        &self,
        input: &PreparedInitialization,
        metadata: &Value,
    ) -> Result<(), ReCtmError> {
        let metadata = pretty_json(metadata)?.into_bytes();
        if metadata.len() > 16_384 {
            return Err(too_large());
        }
        for relative in [
            "input",
            "references",
            "memory",
            "memory/generation",
            "memory/verifier",
            "branches",
            "snapshots",
            "join",
            "draft",
            "verification",
            "final",
            "debug",
            "debug/state",
            ".initialization-tmp",
        ] {
            ensure_directory(&self.root.join(relative))?;
        }
        let mut files = input
            .files
            .iter()
            .map(|(p, b)| (p.as_path(), b.as_slice()))
            .collect::<Vec<_>>();
        files.push((Path::new("run-metadata.json"), &metadata));
        // Detect all pre-existing conflicting final files before publishing missing ones.
        for (relative, bytes) in &files {
            self.check_existing(relative, bytes)?;
        }
        for (relative, bytes) in files {
            self.publish_one(relative, bytes)?;
        }
        File::open(&self.root)
            .and_then(|f| f.sync_all())
            .map_err(io_error)
    }

    fn temporary(&self, relative: &Path) -> PathBuf {
        self.root
            .join(".initialization-tmp")
            .join(format!("{}.tmp", sha256_text(&relative.to_string_lossy())))
    }

    fn check_existing(&self, relative: &Path, bytes: &[u8]) -> Result<bool, ReCtmError> {
        let path = self.root.join(relative);
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(io_error(e)),
        };
        regular_private(&meta)?;
        if meta.nlink() != 1 {
            let temp = fs::symlink_metadata(self.temporary(relative)).map_err(|_| conflict())?;
            regular_private(&temp)?;
            if meta.nlink() != 2 || temp.ino() != meta.ino() || temp.dev() != meta.dev() {
                return Err(conflict());
            }
        }
        if meta.len() != bytes.len() as u64 {
            return Err(conflict());
        }
        let mut actual = Vec::new();
        File::open(path)
            .map_err(io_error)?
            .take(bytes.len() as u64 + 1)
            .read_to_end(&mut actual)
            .map_err(io_error)?;
        if actual != bytes {
            return Err(conflict());
        }
        Ok(true)
    }

    fn publish_one(&self, relative: &Path, bytes: &[u8]) -> Result<(), ReCtmError> {
        let exists = self.check_existing(relative, bytes)?;
        let temp = self.temporary(relative);
        if let Ok(meta) = fs::symlink_metadata(&temp) {
            regular_private(&meta)?;
            if meta.nlink() != 1 {
                let final_meta =
                    fs::symlink_metadata(self.root.join(relative)).map_err(|_| conflict())?;
                if !exists
                    || meta.nlink() != 2
                    || meta.ino() != final_meta.ino()
                    || meta.dev() != final_meta.dev()
                {
                    return Err(conflict());
                }
            }
            fs::remove_file(&temp).map_err(io_error)?;
        }
        if !exists {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)
                .map_err(io_error)?;
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(io_error)?;
            fs::hard_link(&temp, self.root.join(relative)).map_err(io_error)?;
            fs::remove_file(&temp).map_err(io_error)?;
        }
        let parent = self
            .root
            .join(relative)
            .parent()
            .ok_or_else(conflict)?
            .to_path_buf();
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(io_error)?;
        File::open(self.root.join(".initialization-tmp"))
            .and_then(|f| f.sync_all())
            .map_err(io_error)?;
        Ok(())
    }
}

fn ensure_directory(path: &Path) -> Result<(), ReCtmError> {
    use std::os::unix::fs::DirBuilderExt;
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(io_error(e)),
    }
    let meta = fs::symlink_metadata(path).map_err(io_error)?;
    if !meta.is_dir() || meta.permissions().mode() & 0o7777 != 0o700 {
        return Err(conflict());
    }
    Ok(())
}

fn regular_private(meta: &fs::Metadata) -> Result<(), ReCtmError> {
    if !meta.is_file() || meta.permissions().mode() & 0o7777 != 0o600 {
        return Err(conflict());
    }
    Ok(())
}

fn conflict() -> ReCtmError {
    ReCtmError::new("CREATION_INPUT_CONFLICT", "Existing initialization input, file type, links or permissions do not match; no existing input was overwritten.")
        .with_category(ErrorCategory::Conflict).with_retryable(false)
}

fn too_large() -> ReCtmError {
    validation("Initialization input exceeds its bounded size.")
}

#[cfg(test)]
mod tests {
    use super::*;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn input() -> std::result::Result<PreparedInitialization, ReCtmError> {
        PreparedInitialization::new(
            "private fixture α",
            &[serde_json::json!({"name":"ref.txt","content":"source β","source":"inline"})],
        )
    }

    #[test]
    fn repeated_initialization_preserves_inodes_bytes_and_private_modes() -> Result {
        let root = tempfile::tempdir()?;
        let vault = PrivateVault::new(root.path())?;
        let guard = vault.lock_initialization("run")?;
        let input = input()?;
        guard.publish(&input, &serde_json::json!({"owner_id":"owner"}))?;
        let path = guard.root.join("input/problem.tex");
        let before = fs::metadata(&path)?;
        drop(guard);
        vault
            .lock_initialization("run")?
            .publish(&input, &serde_json::json!({"owner_id":"owner"}))?;
        let after = fs::metadata(&path)?;
        assert_eq!(before.ino(), after.ino());
        assert_eq!(after.permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read_to_string(path)?, "private fixture α");
        Ok(())
    }

    #[test]
    fn incomplete_private_temporary_and_linked_publication_can_resume() -> Result {
        for linked in [false, true] {
            let root = tempfile::tempdir()?;
            let vault = PrivateVault::new(root.path())?;
            let guard = vault.lock_initialization("run")?;
            ensure_directory(&guard.root.join("input"))?;
            ensure_directory(&guard.root.join(".initialization-tmp"))?;
            let relative = Path::new("input/problem.tex");
            let temp = guard.temporary(relative);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            file.write_all(if linked {
                "private fixture α".as_bytes()
            } else {
                b"partial"
            })?;
            file.sync_all()?;
            if linked {
                fs::hard_link(&temp, guard.root.join(relative))?;
            }
            drop(file);
            drop(guard);
            let recovered = vault.lock_initialization("run")?;
            recovered.publish(&input()?, &serde_json::json!({}))?;
            assert_eq!(
                fs::read_to_string(recovered.root.join(relative))?,
                "private fixture α"
            );
            assert!(!temp.exists());
            assert_eq!(fs::metadata(recovered.root.join(relative))?.nlink(), 1);
        }
        Ok(())
    }

    #[test]
    fn conflicting_final_file_symlink_and_permission_drift_are_not_overwritten() -> Result {
        for kind in 0..4 {
            let root = tempfile::tempdir()?;
            let vault = PrivateVault::new(root.path())?;
            let guard = vault.lock_initialization("run")?;
            guard.publish(&input()?, &serde_json::json!({}))?;
            let target = guard.root.join("references/ref.txt");
            match kind {
                0 => fs::write(&target, "conflicting")?,
                1 => fs::set_permissions(&target, fs::Permissions::from_mode(0o644))?,
                2 => {
                    fs::remove_file(&target)?;
                    std::os::unix::fs::symlink("/dev/null", &target)?;
                }
                _ => fs::hard_link(&target, root.path().join("unexpected-link"))?,
            }
            let before = fs::symlink_metadata(&target)?;
            assert_eq!(
                guard
                    .publish(&input()?, &serde_json::json!({}))
                    .err()
                    .ok_or("expected conflict")?
                    .code,
                "CREATION_INPUT_CONFLICT"
            );
            let after = fs::symlink_metadata(&target)?;
            assert_eq!(before.ino(), after.ino());
            assert_eq!(before.permissions(), after.permissions());
            if kind == 0 {
                assert_eq!(fs::read_to_string(&target)?, "conflicting");
            }
        }
        Ok(())
    }

    #[test]
    fn input_validation_rejects_duplicate_escape_and_size_before_publication() {
        let duplicate = [
            serde_json::json!({"name":"a","content":"1"}),
            serde_json::json!({"name":"a","content":"2"}),
        ];
        assert!(PreparedInitialization::new("p", &duplicate).is_err());
        assert!(PreparedInitialization::new("p", &[serde_json::json!({"name":"../x"})]).is_err());
        assert!(PreparedInitialization::new(&"x".repeat(MAX_INPUT_BYTES + 1), &[]).is_err());
        assert!(
            PreparedInitialization::new("p", &vec![serde_json::json!({}); MAX_REFERENCES + 1])
                .is_err()
        );
    }

    #[test]
    fn competing_lock_handles_are_exclusive_and_close_releases_them() -> Result {
        let root = tempfile::tempdir()?;
        let vault = PrivateVault::new(root.path())?;
        let held = vault.lock_initialization("run")?;
        assert!(vault.lock_initialization("run").is_err());
        let path = held.root.join(".creation.lock");
        let before = fs::metadata(&path)?.ino();
        drop(held);
        let _next = vault.lock_initialization("run")?;
        assert_eq!(fs::metadata(&path)?.ino(), before);
        Ok(())
    }
}
