//! Descriptor-relative, no-follow reads of explicitly selected bundle files.
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use nix::errno::Errno;
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::Mode;

use crate::Result;

pub(super) struct Directory(File);

impl Directory {
    pub(super) fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute()
            || path == Path::new("/")
            || path.as_os_str().len() > 4096
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err("bundle requires an absolute non-traversing directory".into());
        }
        // Open every directory without following symlinks. Each next component
        // is resolved from the held descriptor, not a re-resolved path string.
        let mut directory = File::open("/").map_err(|_| "bundle root unavailable")?;
        for part in path.components() {
            if let Component::Normal(name) = part {
                directory = File::from(
                    openat(
                        &directory,
                        name,
                        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_| "bundle directory unavailable or linked")?,
                );
            }
        }
        let metadata = directory
            .metadata()
            .map_err(|_| "bundle metadata unavailable")?;
        if metadata.mode() & 0o7777 != 0o700 {
            return Err("bundle directory must have mode 0700".into());
        }
        Ok(Self(directory))
    }

    pub(super) fn read(&self, name: &str, limit: u64) -> Result<Option<Vec<u8>>> {
        // Callers use fixed filenames only; keep this guard as a second boundary.
        if name.is_empty()
            || name.len() > 80
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            || matches!(name, "." | "..")
        {
            return Err("invalid bundle file selector".into());
        }
        let descriptor = match openat(
            &self.0,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(Errno::ENOENT) => return Ok(None),
            Err(_) => return Err("bundle file unavailable or linked".into()),
        };
        let mut file = File::from(descriptor);
        let before = file
            .metadata()
            .map_err(|_| "bundle file metadata unavailable")?;
        let owner = self
            .0
            .metadata()
            .map_err(|_| "bundle metadata unavailable")?
            .uid();
        if !before.is_file()
            || before.nlink() != 1
            || before.uid() != owner
            || before.mode() & 0o7022 != 0
            || before.len() == 0
            || before.len() > limit
        {
            return Err("bundle input must be a bounded, owned, unlinked regular file".into());
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "bundle input read failed")?;
        let after = file
            .metadata()
            .map_err(|_| "bundle file metadata unavailable")?;
        if bytes.len() as u64 != before.len() || !unchanged(&before, &after) {
            return Err("bundle input changed during read".into());
        }
        Ok(Some(bytes))
    }
}

fn unchanged(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.nlink() == after.nlink()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}
