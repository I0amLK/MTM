//! Read-only, descriptor-relative snapshots of the formal readiness inventory.
use crate::Result;
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::Mode;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

pub(super) struct Snapshot {
    pub bytes: Vec<u8>,
    metadata: Metadata,
}

fn unchanged(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.nlink() == b.nlink()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

fn directory(path: &Path) -> Result<File> {
    let text = path
        .to_str()
        .ok_or("formal readiness path encoding invalid")?;
    if !path.is_absolute()
        || path == Path::new("/")
        || text.len() > 4096
        || text
            .split('/')
            .skip(1)
            .any(|p| p.is_empty() || matches!(p, "." | ".."))
    {
        return Err("formal readiness root must be absolute and canonical".into());
    }
    let mut file = File::open("/")?;
    for component in path.components() {
        if let Component::Normal(name) = component {
            file = File::from(
                openat(
                    &file,
                    name,
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| "formal readiness directory unavailable or linked")?,
            );
        }
    }
    Ok(file)
}

pub(super) fn read(root: &Path, relative: &str, limit: u64, executable: bool) -> Result<Snapshot> {
    if relative.is_empty()
        || relative.len() > 512
        || relative
            .split('/')
            .any(|p| p.is_empty() || matches!(p, "." | ".."))
        || !relative
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
    {
        return Err("formal readiness inventory path invalid".into());
    }
    let path = root.join(relative);
    let parent = directory(path.parent().ok_or("formal readiness parent missing")?)?;
    let name = path.file_name().ok_or("formal readiness leaf missing")?;
    let mut file = File::from(
        openat(
            &parent,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "formal readiness input unavailable or linked")?,
    );
    let before = file.metadata()?;
    // Public archived JSON already uses 0664. It is never executed; other-write,
    // special mode bits and hard links remain forbidden. Artifacts cannot be
    // group-writable and must retain owner execute permission.
    let forbidden = if executable { 0o7022 } else { 0o7113 };
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != parent.metadata()?.uid()
        || before.mode() & forbidden != 0
        || (executable && before.mode() & 0o100 == 0)
        || (executable && before.len() == 0)
        || before.len() > limit
    {
        return Err("formal readiness input type, ownership, mode or size invalid".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.len() || !unchanged(&before, &file.metadata()?) {
        return Err("formal readiness input changed during read".into());
    }
    Ok(Snapshot {
        bytes,
        metadata: before,
    })
}

impl Snapshot {
    pub(super) fn recheck(&self, other: &Self) -> Result<()> {
        if self.bytes != other.bytes || !unchanged(&self.metadata, &other.metadata) {
            return Err("formal readiness input changed during evaluation".into());
        }
        Ok(())
    }
}
