//! Descriptor-relative bounded reads. The importer never writes any input.
use crate::Result;
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::Mode;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

pub(super) struct Directory(File);
impl Directory {
    pub(super) fn open(path: &Path, private: bool) -> Result<Self> {
        let text = path.to_str().ok_or("import path encoding invalid")?;
        if !path.is_absolute()
            || path == Path::new("/")
            || text.len() > 4096
            || text
                .split('/')
                .skip(1)
                .any(|p| p.is_empty() || matches!(p, "." | ".."))
        {
            return Err("import directory must be absolute and non-traversing".into());
        }
        let mut file = File::open("/").map_err(|_| "import root unavailable")?;
        for component in path.components() {
            if let Component::Normal(name) = component {
                file = File::from(
                    openat(
                        &file,
                        name,
                        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_| "import directory unavailable or linked")?,
                );
            }
        }
        if private && file.metadata()?.mode() & 0o7777 != 0o700 {
            return Err("private import directory must have mode 0700".into());
        }
        Ok(Self(file))
    }
    pub(super) fn read(&self, name: &str, limit: u64) -> Result<Vec<u8>> {
        self.read_checked(name, limit, 0o7022)
    }

    fn read_checked(&self, name: &str, limit: u64, forbidden_mode: u32) -> Result<Vec<u8>> {
        if name.is_empty()
            || name.len() > 160
            || matches!(name, "." | "..")
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err("invalid import leaf name".into());
        }
        let mut file = File::from(
            openat(
                &self.0,
                name,
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "import file unavailable or linked")?,
        );
        let before = file.metadata()?;
        if !before.is_file()
            || before.nlink() != 1
            || before.uid() != self.0.metadata()?.uid()
            || before.mode() & forbidden_mode != 0
            || before.len() == 0
            || before.len() > limit
        {
            return Err("import input must be bounded, owned and an unlinked regular file".into());
        }
        let mut bytes = Vec::new();
        (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != before.len() || !unchanged(&before, &file.metadata()?) {
            return Err("import input changed during read".into());
        }
        Ok(bytes)
    }
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
pub(super) fn repo(root: &Path, relative: &str) -> Result<Vec<u8>> {
    if relative.len() > 512
        || !relative.starts_with("records/evidence/MTM-017/")
        || relative
            .split('/')
            .any(|p| p.is_empty() || matches!(p, "." | ".."))
        || !relative
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
    {
        return Err("import evidence must be a canonical MTM-017 relative path".into());
    }
    let path = root.join(relative);
    let parent = path.parent().ok_or("import parent missing")?;
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or("import leaf missing")?;
    Directory::open(parent, false)?.read(name, 1024 * 1024)
}
pub(super) fn frozen_driver(root: &Path) -> Result<Vec<u8>> {
    // This one public historical JSON record is already mode 0664. It is data,
    // not an executable candidate or private material. No caller selects its
    // name or namespace, and all other readers retain their strict mode rule.
    Directory::open(&root.join("records/governance"), false)?.read_checked(
        "mtm016-release-inputs.json",
        1048576,
        0o7113,
    )
}

pub(super) fn catalog(path: &Path) -> Result<Vec<u8>> {
    let parent = path.parent().ok_or("catalog parent missing")?;
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or("catalog leaf missing")?;
    Directory::open(parent, true)?.read(name, 65536)
}
