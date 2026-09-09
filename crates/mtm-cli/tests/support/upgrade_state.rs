//! Private test-state copies only. No caller-supplied data roots or live backups.
use super::*;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

const MAX_ENTRIES: usize = 4096;
const MAX_FILE: u64 = 16 * 1024 * 1024;
const MAX_TOTAL: usize = 64 * 1024 * 1024;

struct Image {
    directory: bool,
    mode: u32,
    bytes: Vec<u8>,
}

type Tree = BTreeMap<PathBuf, Image>;

fn collect(root: &Path) -> Result<Tree> {
    fn visit(root: &Path, path: &Path, tree: &mut Tree, total: &mut usize) -> Result {
        require(tree.len() < MAX_ENTRIES, "fixture snapshot entry limit")?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "fixture snapshot escaped")?;
        require(
            relative.components().count() <= 32,
            "fixture snapshot depth limit",
        )?;
        require(
            relative.to_str().is_some(),
            "fixture snapshot name is not UTF-8",
        )?;
        let metadata = fs::symlink_metadata(path).map_err(|_| "fixture snapshot metadata")?;
        require(
            (metadata.is_file() || metadata.is_dir())
                && !metadata.file_type().is_symlink()
                && (!metadata.is_file() || metadata.nlink() == 1)
                && metadata.permissions().mode() & 0o7000 == 0,
            "fixture snapshot refuses links, special files or special modes",
        )?;
        let mut bytes = Vec::new();
        if metadata.is_file() {
            require(metadata.len() <= MAX_FILE, "fixture snapshot file limit")?;
            File::open(path)
                .map_err(|_| "fixture snapshot read")?
                .take(MAX_FILE + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "fixture snapshot read")?;
            *total += bytes.len();
            require(
                bytes.len() as u64 <= MAX_FILE && *total <= MAX_TOTAL,
                "fixture snapshot byte limit",
            )?;
        }
        tree.insert(
            relative.to_owned(),
            Image {
                directory: metadata.is_dir(),
                mode: metadata.permissions().mode() & 0o777,
                bytes,
            },
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path).map_err(|_| "fixture snapshot list")? {
                visit(
                    root,
                    &entry.map_err(|_| "fixture snapshot entry")?.path(),
                    tree,
                    total,
                )?;
            }
        }
        Ok(())
    }
    let mut tree = Tree::new();
    let mut total = 0;
    for name in ["data", "workspace"] {
        visit(root, &root.join(name), &mut tree, &mut total)?;
    }
    Ok(tree)
}

fn fingerprint(tree: &Tree) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"mtm-owned-upgrade-snapshot-v1\0");
    for (path, image) in tree {
        let path = path.to_str().ok_or("fixture snapshot name is not UTF-8")?;
        hash.update((path.len() as u64).to_le_bytes());
        hash.update(path.as_bytes());
        hash.update([u8::from(image.directory)]);
        hash.update(image.mode.to_le_bytes());
        hash.update((image.bytes.len() as u64).to_le_bytes());
        hash.update(Sha256::digest(&image.bytes));
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn materialize(root: &Path, tree: &Tree) -> Result {
    for (path, image) in tree {
        let path = root.join(path);
        if image.directory {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .map_err(|_| "fixture snapshot mkdir")?;
        } else {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|_| "fixture snapshot output")?;
            file.write_all(&image.bytes)
                .map_err(|_| "fixture snapshot copy")?;
            file.sync_all().map_err(|_| "fixture snapshot sync")?;
        }
        fs::set_permissions(path, fs::Permissions::from_mode(image.mode))
            .map_err(|_| "fixture snapshot permissions")?;
    }
    require(
        fingerprint(&collect(root)?)? == fingerprint(tree)?,
        "fixture snapshot copy differs",
    )
}

pub struct OwnedSnapshot {
    directory: tempfile::TempDir,
    owner: PathBuf,
    pub sha256: String,
    pub entries: usize,
    pub bytes: usize,
    pub legacy_shared_write_entries: usize,
}

impl OwnedSnapshot {
    pub fn unchanged(&self) -> Result {
        require(
            fingerprint(&collect(self.directory.path())?)? == self.sha256,
            "fixture snapshot drift",
        )
    }
}

impl Server {
    pub fn snapshot_owned_state(&mut self) -> Result<OwnedSnapshot> {
        self.stop()?;
        let tree = collect(self.directory.path())?;
        let directory = tempfile::tempdir().map_err(|_| "fixture snapshot directory")?;
        materialize(directory.path(), &tree)?;
        let snapshot = OwnedSnapshot {
            directory,
            owner: self.directory.path().to_owned(),
            sha256: fingerprint(&tree)?,
            entries: tree.len(),
            bytes: tree.values().map(|entry| entry.bytes.len()).sum(),
            legacy_shared_write_entries: tree
                .iter()
                .filter(|(name, entry)| name.starts_with("data/private") && entry.mode & 0o022 != 0)
                .count(),
        };
        // A stopped server cannot change its source while the copy is checked.
        require(
            fingerprint(&collect(self.directory.path())?)? == snapshot.sha256,
            "fixture source changed during copy",
        )?;
        Ok(snapshot)
    }

    pub fn restore_owned_state(&mut self, snapshot: &OwnedSnapshot) -> Result<String> {
        require(
            snapshot.owner == self.directory.path(),
            "snapshot belongs to another fixture",
        )?;
        self.stop()?;
        snapshot.unchanged()?;
        let tree = collect(snapshot.directory.path())?;
        // These two paths are fixed children of this Server's owned TempDir.
        // Failed copies never restart a runtime or claim a successful rollback.
        for name in ["data", "workspace"] {
            fs::remove_dir_all(self.directory.path().join(name))
                .map_err(|_| "fixture restore cleanup")?;
        }
        materialize(self.directory.path(), &tree)?;
        fingerprint(&collect(self.directory.path())?)
    }

    pub fn switch_test_artifact(&mut self, binary: &Path, sha256: &str) -> Result {
        self.stop()?;
        let metadata = fs::symlink_metadata(binary).map_err(|_| "fixture artifact metadata")?;
        require(
            metadata.is_file()
                && metadata.permissions().mode() & 0o111 != 0
                && metadata.permissions().mode() & 0o6000 == 0,
            "fixture artifact is not an ordinary executable",
        )?;
        require(
            sha256_file(binary)? == sha256,
            "fixture artifact SHA mismatch",
        )?;
        self.binary = binary.to_str().ok_or("fixture artifact path")?.to_owned();
        self.binary_sha256 = sha256.to_owned();
        self.spawn()
    }

    pub fn installation_fixture_root(&self) -> PathBuf {
        self.directory.path().join("installation-fixture")
    }

    pub fn prepare_owned_private_modes(&mut self) -> Result<usize> {
        require(
            self.child.is_none(),
            "private-mode preparation requires a stopped fixture",
        )?;
        let before = collect(self.directory.path())?;
        let mut changed = 0;
        for (name, entry) in &before {
            if name.starts_with("data/private") {
                let mode = if entry.directory { 0o700 } else { 0o600 };
                changed += usize::from(entry.mode != mode);
                fs::set_permissions(
                    self.directory.path().join(name),
                    fs::Permissions::from_mode(mode),
                )
                .map_err(|_| "owned private-mode preparation failed")?;
            }
        }
        let after = collect(self.directory.path())?;
        require(
            before.len() == after.len(),
            "mode preparation changed the file set",
        )?;
        for (name, entry) in &before {
            let next = after.get(name).ok_or("mode preparation removed an entry")?;
            require(
                next.directory == entry.directory && next.bytes == entry.bytes,
                "mode preparation changed fixture contents",
            )?;
            let expected = if name.starts_with("data/private") {
                if entry.directory { 0o700 } else { 0o600 }
            } else {
                entry.mode
            };
            require(
                next.mode == expected,
                "mode preparation changed an unrelated mode",
            )?;
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_copies_modes_and_detects_drift_without_publishing_contents() -> Result {
        let root = tempfile::tempdir().map_err(|_| "fixture root")?;
        for name in ["data", "workspace"] {
            fs::create_dir(root.path().join(name)).map_err(|_| "fixture mkdir")?;
        }
        let file = root.path().join("data/file");
        fs::write(&file, b"private fixture").map_err(|_| "fixture write")?;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600))
            .map_err(|_| "fixture mode")?;
        let tree = collect(root.path())?;
        let copied = tempfile::tempdir().map_err(|_| "fixture copy root")?;
        materialize(copied.path(), &tree)?;
        require(
            fingerprint(&collect(copied.path())?)? == fingerprint(&tree)?,
            "copy digest",
        )?;
        fs::write(copied.path().join("data/file"), b"changed").map_err(|_| "fixture mutation")?;
        require(
            fingerprint(&collect(copied.path())?)? != fingerprint(&tree)?,
            "drift not detected",
        )?;
        std::os::unix::fs::symlink(&file, root.path().join("workspace/link"))
            .map_err(|_| "fixture link")?;
        require(collect(root.path()).is_err(), "snapshot accepted a link")
    }

    #[test]
    fn snapshot_rejects_oversized_sparse_files() -> Result {
        let root = tempfile::tempdir().map_err(|_| "fixture root")?;
        for name in ["data", "workspace"] {
            fs::create_dir(root.path().join(name)).map_err(|_| "fixture mkdir")?;
        }
        File::create(root.path().join("data/large"))
            .map_err(|_| "fixture file")?
            .set_len(MAX_FILE + 1)
            .map_err(|_| "fixture sparse length")?;
        require(
            collect(root.path()).is_err(),
            "snapshot accepted oversized input",
        )
    }

    #[test]
    fn private_mode_preparation_and_snapshot_ownership_preserve_state() -> Result {
        let mut server = Server::start(env!("CARGO_BIN_EXE_mtm"))?;
        let snapshot = server.snapshot_owned_state()?;
        fs::set_permissions(
            server.private_state_path(),
            fs::Permissions::from_mode(0o664),
        )
        .map_err(|_| "fixture shared-write mode")?;
        require(
            server.prepare_owned_private_modes()? >= 1,
            "private mode was not repaired",
        )?;
        require(
            server.restore_owned_state(&snapshot)? == snapshot.sha256,
            "original modes not restored",
        )?;
        let mut other = Server::start(env!("CARGO_BIN_EXE_mtm"))?;
        require(
            other.restore_owned_state(&snapshot).is_err(),
            "foreign snapshot accepted",
        )?;
        other.stop()?;
        let before = fingerprint(&collect(server.directory.path())?)?;
        fs::write(
            snapshot.directory.path().join("data/private/state.sqlite3"),
            b"corrupt fixture snapshot",
        )
        .map_err(|_| "fixture snapshot mutation")?;
        require(
            server.restore_owned_state(&snapshot).is_err(),
            "changed snapshot accepted",
        )?;
        require(
            fingerprint(&collect(server.directory.path())?)? == before,
            "rejected restore changed current state",
        )
    }
}
