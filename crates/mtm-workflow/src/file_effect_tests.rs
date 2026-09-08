use super::*;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn preparation_is_read_only_and_atomic_publication_preserves_utf8_records() -> Result {
    let root = tempfile::tempdir()?;
    let vault = PrivateVault::new(root.path().join("private"))?;
    let path = "memory/generation/events.jsonl";
    let guard = vault.lock_file_effect("run", path)?;
    let first = PrivateVault::file_effect_bytes(&serde_json::json!({"summary":"α 中文 🐚"}), true)?;
    let (evidence, bytes) = guard.prepare(&first, true)?;
    assert!(guard.observe()?.is_none());
    guard.publish(&evidence, &bytes)?;
    assert_eq!(guard.observe()?, Some(image(&first)));
    let (second_evidence, bytes) = guard.prepare(&first, true)?;
    assert_eq!(guard.observe()?, Some(image(&first)));
    guard.publish(&second_evidence, &bytes)?;
    assert_eq!(vault.read_generation_memory("run", "events")?.len(), 2);
    assert_eq!(
        fs::metadata(guard.root.join(path))?.permissions().mode() & 0o777,
        0o600
    );
    Ok(())
}

#[test]
fn old_writers_and_recovery_use_the_same_permanent_lock() -> Result {
    let root = tempfile::tempdir()?;
    let vault = PrivateVault::new(root.path().join("private"))?;
    let guard = vault.lock_file_effect("run", "draft/proof.tex")?;
    let inode = fs::metadata(
        guard
            .root
            .join(".write-locks")
            .join(sha256_text("draft/proof.tex")),
    )?
    .ino();
    assert!(vault.write_proof("run", "must not run").is_err());
    assert!(guard.observe()?.is_none());
    drop(guard);
    vault.write_proof("run", "now writable")?;
    let guard = vault.lock_file_effect("run", "draft/proof.tex")?;
    assert_eq!(
        fs::metadata(
            guard
                .root
                .join(".write-locks")
                .join(sha256_text("draft/proof.tex"))
        )?
        .ino(),
        inode
    );
    Ok(())
}

#[test]
fn interrupted_temporary_never_replaces_the_live_file_until_publication() -> Result {
    let root = tempfile::tempdir()?;
    let vault = PrivateVault::new(root.path().join("private"))?;
    vault.write_proof("run", "old proof")?;
    let guard = vault.lock_file_effect("run", "draft/proof.tex")?;
    let tmpdir = guard.root.join(".write-tmp");
    directory(&tmpdir)?;
    let temp = tmpdir.join(sha256_text("draft/proof.tex"));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(temp)?;
    file.write_all(b"partial replacement")?;
    file.sync_all()?;
    drop(file);
    assert_eq!(guard.observe()?, Some(image(b"old proof")));
    let (evidence, bytes) = guard.prepare(b"new proof", false)?;
    guard.publish(&evidence, &bytes)?;
    assert_eq!(vault.read_proof("run")?, "new proof");
    Ok(())
}

#[test]
fn conflicting_hardlinks_symlinks_and_content_are_not_overwritten() -> Result {
    for kind in ["hardlink", "symlink", "content"] {
        let root = tempfile::tempdir()?;
        let vault = PrivateVault::new(root.path().join("private"))?;
        vault.write_proof("run", "before")?;
        let guard = vault.lock_file_effect("run", "draft/proof.tex")?;
        let (evidence, bytes) = guard.prepare(b"after", false)?;
        let path = guard.root.join("draft/proof.tex");
        match kind {
            "hardlink" => {
                fs::hard_link(&path, root.path().join("other"))?;
            }
            "symlink" => {
                fs::remove_file(&path)?;
                std::os::unix::fs::symlink("/dev/null", &path)?;
            }
            _ => {
                fs::write(&path, "conflict")?;
            }
        }
        assert!(guard.publish(&evidence, &bytes).is_err());
        if kind == "content" {
            assert_eq!(fs::read_to_string(path)?, "conflict");
        }
    }
    Ok(())
}

#[test]
fn incomplete_memory_is_not_silently_concatenated_or_discarded() -> Result {
    let root = tempfile::tempdir()?;
    let vault = PrivateVault::new(root.path().join("private"))?;
    let guard = vault.lock_file_effect("run", "memory/verifier/events.jsonl")?;
    let path = guard.root.join("memory/verifier/events.jsonl");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(b"{\"partial\":")?;
    drop(file);
    assert!(guard.prepare(b"{}\n", true).is_err());
    assert_eq!(fs::read(&path)?, b"{\"partial\":");
    assert!(vault.read_verifier_memory("run", "events").is_err());
    fs::write(&path, b"{}\nnot-json\n")?;
    assert!(guard.prepare(b"{}\n", true).is_err());
    assert!(vault.read_verifier_memory("run", "events").is_err());
    assert_eq!(fs::read(&path)?, b"{}\nnot-json\n");
    Ok(())
}

#[test]
fn branch_targets_and_size_bounds_keep_recovery_in_the_run() -> Result {
    let root = tempfile::tempdir()?;
    let vault = PrivateVault::new(root.path().join("private"))?;
    for path in [
        "../outside",
        "final/proof_verified.tex",
        "branches/../memory/events.jsonl",
    ] {
        assert!(vault.lock_file_effect("run", path).is_err());
    }
    let guard = vault.lock_file_effect("run", "branches/branch-a/memory/events.jsonl")?;
    let (e, b) = guard.prepare(b"{}\n", true)?;
    guard.publish(&e, &b)?;
    assert_eq!(
        vault.read_branch_memory("run", "branch-a", "events")?.len(),
        1
    );
    let path = guard.root.join("branches/branch-a/memory/events.jsonl");
    OpenOptions::new()
        .write(true)
        .open(&path)?
        .set_len(LIMIT as u64 + 1)?;
    assert!(guard.observe().is_err());
    Ok(())
}
