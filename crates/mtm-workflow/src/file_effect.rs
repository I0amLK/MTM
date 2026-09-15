//! Bounded cooperative file effects. Never holds a lock across observers or tools.
use super::*;
use mtm_storage::{FileEffectEvidence, FileImage};
use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

const LIMIT: usize = 64 * 1024 * 1024;

#[cfg(test)]
#[path = "file_effect_tests.rs"]
mod tests;

pub(crate) struct FileEffectGuard {
    _lock: Flock<File>,
    root: PathBuf,
    relative: String,
}

pub(crate) fn image(bytes: &[u8]) -> FileImage {
    FileImage {
        bytes: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
    }
}

fn descriptor(relative: &str) -> FileEffectEvidence {
    FileEffectEvidence {
        relative_path: relative.into(),
        before: None,
        after: image(&[]),
    }
}

impl PrivateVault {
    pub(crate) fn lock_file_effect(
        &self,
        run: &str,
        relative: &str,
    ) -> Result<FileEffectGuard, ReCtmError> {
        descriptor(relative).validate()?;
        let root = self.run_root(run)?;
        directory(&self.private_root)?;
        directory(&self.runs_root)?;
        directory(&root)?;
        let mut parent = root.clone();
        let components = relative.split('/').collect::<Vec<_>>();
        for part in &components[..components.len() - 1] {
            parent.push(part);
            directory(&parent)?;
        }
        let locks = root.join(".write-locks");
        directory(&locks)?;
        let path = locks.join(sha256_text(relative));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&path)
            .map_err(io_error)?;
        let meta = file.metadata().map_err(io_error)?;
        regular(&meta)?;
        let named = fs::symlink_metadata(&path).map_err(io_error)?;
        if meta.ino() != named.ino()
            || meta.dev() != named.dev()
            || meta.permissions().mode() & 0o7777 != 0o600
        {
            return Err(conflict());
        }
        let lock = Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, error)| {
            if error == Errno::EWOULDBLOCK {
                ReCtmError::new(
                    "RESULT_UNKNOWN",
                    "The logical file is in use; no effect was replayed.",
                )
                .with_category(ErrorCategory::Conflict)
                .with_retryable(false)
            } else {
                io_error(std::io::Error::from_raw_os_error(error as i32))
            }
        })?;
        Ok(FileEffectGuard {
            _lock: lock,
            root,
            relative: relative.into(),
        })
    }

    pub(crate) fn file_effect_location(&self, path: &Path) -> Option<(String, String)> {
        let path = path.strip_prefix(&self.runs_root).ok()?;
        let mut parts = path.components();
        let run = parts.next()?.as_os_str().to_str()?.to_owned();
        let relative = parts.as_path().to_str()?.to_owned();
        descriptor(&relative).validate().ok()?;
        Some((run, relative))
    }

    pub(crate) fn file_effect_bytes(content: &Value, append: bool) -> Result<Vec<u8>, ReCtmError> {
        if append {
            if !content.is_object() {
                return Err(validation("memory records must be JSON objects"));
            }
            let mut line = python_json(&sort_json(content))?;
            line.push('\n');
            Ok(line.into_bytes())
        } else {
            Ok(pretty_json(content)?.into_bytes())
        }
    }
}

impl FileEffectGuard {
    fn read_bytes(&self) -> Result<Option<Vec<u8>>, ReCtmError> {
        let path = self.root.join(&self.relative);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_error(e)),
            Ok(meta) => regular(&meta)?,
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)
            .map_err(io_error)?;
        regular(&file.metadata().map_err(io_error)?)?;
        let mut bytes = Vec::new();
        file.take(LIMIT as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if bytes.len() > LIMIT {
            return Err(conflict());
        }
        Ok(Some(bytes))
    }

    pub(crate) fn observe(&self) -> Result<Option<FileImage>, ReCtmError> {
        Ok(self.read_bytes()?.as_deref().map(image))
    }

    pub(crate) fn prepare(
        &self,
        content: &[u8],
        append: bool,
    ) -> Result<(FileEffectEvidence, Vec<u8>), ReCtmError> {
        let prior = self.read_bytes()?;
        let before = prior.as_deref().map(image);
        let mut after = if append {
            prior.unwrap_or_default()
        } else {
            Vec::new()
        };
        if append && !after.is_empty() && !after.ends_with(b"\n") {
            return Err(ReCtmError::new(
                "MEMORY_CORRUPT",
                "Memory has an incomplete trailing record; it was not discarded or appended to.",
            )
            .with_category(ErrorCategory::Conflict));
        }
        if append {
            let text = std::str::from_utf8(&after).map_err(|_| conflict())?;
            parse_jsonl(text)?;
        }
        if after.len().saturating_add(content.len()) > LIMIT {
            return Err(conflict());
        }
        after.extend_from_slice(content);
        Ok((
            FileEffectEvidence {
                relative_path: self.relative.clone(),
                before,
                after: image(&after),
            },
            after,
        ))
    }

    pub(crate) fn publish(
        &self,
        evidence: &FileEffectEvidence,
        bytes: &[u8],
    ) -> Result<(), ReCtmError> {
        evidence.validate()?;
        if evidence.relative_path != self.relative
            || image(bytes) != evidence.after
            || self.observe()? != evidence.before
        {
            return Err(conflict());
        }
        let tmpdir = self.root.join(".write-tmp");
        directory(&tmpdir)?;
        let temp = tmpdir.join(sha256_text(&self.relative));
        match fs::symlink_metadata(&temp) {
            Ok(meta) => {
                regular(&meta)?;
                fs::remove_file(&temp).map_err(io_error)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_error(e)),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(io_error)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(io_error)?;
        drop(file);
        let target = self.root.join(&self.relative);
        fs::rename(&temp, &target).map_err(io_error)?;
        File::open(target.parent().ok_or_else(conflict)?)
            .and_then(|f| f.sync_all())
            .map_err(io_error)?;
        File::open(tmpdir)
            .and_then(|f| f.sync_all())
            .map_err(io_error)?;
        Ok(())
    }
}

fn directory(path: &Path) -> Result<(), ReCtmError> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(io_error(e)),
    }
    let meta = fs::symlink_metadata(path).map_err(io_error)?;
    if !meta.is_dir() || meta.permissions().mode() & 0o022 != 0 {
        return Err(conflict());
    }
    Ok(())
}

fn regular(meta: &fs::Metadata) -> Result<(), ReCtmError> {
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.len() > LIMIT as u64
        || meta.permissions().mode() & 0o7022 != 0
    {
        return Err(conflict());
    }
    Ok(())
}

fn conflict() -> ReCtmError {
    ReCtmError::new(
        "FILE_EFFECT_CONFLICT",
        "Logical file type, size, links or content differs from the recorded effect.",
    )
    .with_category(ErrorCategory::Conflict)
    .with_retryable(false)
}
