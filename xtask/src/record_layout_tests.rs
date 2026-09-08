use super::*;

fn write(root: &Path, path: &str, bytes: &[u8]) -> Result<()> {
    let path = root.join(path);
    fs::create_dir_all(path.parent().ok_or("fixture parent missing")?)?;
    fs::write(path, bytes)?;
    Ok(())
}

fn fixture() -> Result<(tempfile::TempDir, Value)> {
    let root = tempfile::tempdir()?;
    for name in REQUIRED_GOVERNANCE {
        write(root.path(), &format!("records/governance/{name}"), b"{}")?;
    }
    write(
        root.path(),
        "records/iterations/ITER-016.json",
        b"{\"receipts\":[]}",
    )?;
    write(
        root.path(),
        "records/validation/local-validation.json",
        b"{}",
    )?;
    write(root.path(), "records/README.md", b"Record namespace guide")?;
    let content = b"{\"passed\":false}\n";
    write(
        root.path(),
        "records/evidence/MTM-016/receipt.json",
        content,
    )?;
    let layout = json!({"schema_version":"1.0.0","layout_version":1,"root_json_allowed":false,
        "canonical_roots":{"governance":"records/governance","iterations":"records/iterations",
            "evidence":"records/evidence/MTM-NNN","validation":"records/validation"},
        "relocations":[{"legacy_path":"old.json","current_path":"records/evidence/MTM-016/receipt.json",
            "kind":"evidence","sha256":format!("{:x}",Sha256::digest(content))}]
    });
    Ok((root, layout))
}

#[test]
fn canonical_layout_validates_without_a_reference_repository_or_installation() -> Result<()> {
    let (root, layout) = fixture()?;
    let summary = validate(root.path(), &layout)?;
    assert_eq!(summary["root_json_count"], 0);
    assert_eq!(summary["evidence_hashes_checked"], 1);
    assert_eq!(summary["sealed_observation_hashes_checked"], 0);
    assert_eq!(summary["observations_reexecuted"], false);
    Ok(())
}

#[test]
fn schema_versions_root_policy_and_namespace_descriptors_are_enforced() -> Result<()> {
    let (root, layout) = fixture()?;
    for (key, value) in [
        ("schema_version", json!("2.0.0")),
        ("layout_version", json!(true)),
        ("layout_version", json!(1.0)),
        ("root_json_allowed", json!(true)),
        ("root_json_allowed", Value::Null),
        ("canonical_roots", json!({})),
    ] {
        let mut changed = layout.clone();
        changed[key] = value;
        assert!(validate(root.path(), &changed).is_err());
    }
    Ok(())
}

#[test]
fn malformed_tree_names_nested_evidence_and_root_records_are_rejected() -> Result<()> {
    for path in [
        "root.json",
        "records/unknown/a.json",
        "records/iterations/ITER-x16.json",
        "records/evidence/MTM-16/a.json",
        "records/evidence/MTM-016/nested/a.json",
        "records/evidence/MTM-016/log.txt",
        "records/validation/nested/a.json",
    ] {
        let (root, layout) = fixture()?;
        write(root.path(), path, b"{}")?;
        assert!(
            validate(root.path(), &layout).is_err(),
            "accepted malformed fixture tree"
        );
    }
    Ok(())
}

#[test]
fn required_records_and_namespaces_cannot_disappear() -> Result<()> {
    for path in [
        "records/governance/source-baseline.json",
        "records/iterations/ITER-016.json",
        "records/validation/local-validation.json",
        "records/evidence/MTM-016/receipt.json",
    ] {
        let (root, layout) = fixture()?;
        fs::remove_file(root.path().join(path))?;
        assert!(validate(root.path(), &layout).is_err());
    }
    Ok(())
}

#[test]
fn relocation_pairs_kinds_and_paths_are_strict() -> Result<()> {
    let (root, layout) = fixture()?;
    for (key, value) in [
        ("legacy_path", json!("../old.json")),
        ("legacy_path", json!("dir\\old.json")),
        ("kind", json!("unknown")),
        ("kind", json!("governance")),
        (
            "current_path",
            json!("records/evidence/MTM-016/../receipt.json"),
        ),
        ("current_path", json!("/tmp/outside.json")),
        (
            "current_path",
            json!("records//evidence/MTM-016/receipt.json"),
        ),
    ] {
        let mut changed = layout.clone();
        changed["relocations"][0][key] = value;
        assert!(validate(root.path(), &changed).is_err());
    }
    for entries in [
        json!([]),
        json!([layout["relocations"][0], layout["relocations"][0]]),
    ] {
        let mut changed = layout.clone();
        changed["relocations"] = entries;
        assert!(validate(root.path(), &changed).is_err());
    }
    Ok(())
}

#[test]
fn evidence_hash_is_required_and_relabelling_a_failure_is_detected() -> Result<()> {
    let (root, layout) = fixture()?;
    for hash in [
        Value::Null,
        json!(true),
        json!("a".repeat(63)),
        json!("A".repeat(64)),
    ] {
        let mut changed = layout.clone();
        changed["relocations"][0]["sha256"] = hash;
        assert!(validate(root.path(), &changed).is_err());
    }
    write(
        root.path(),
        "records/evidence/MTM-016/receipt.json",
        b"{\"passed\":true}\n",
    )?;
    assert!(validate(root.path(), &layout).is_err());
    Ok(())
}

#[test]
fn large_record_rejected_before_unbounded_read() -> Result<()> {
    let (root, layout) = fixture()?;
    fs::OpenOptions::new()
        .write(true)
        .open(root.path().join("records/evidence/MTM-016/receipt.json"))?
        .set_len(64 * 1024 * 1024 + 1)?;
    assert!(validate(root.path(), &layout).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn leaf_and_ancestor_symlinks_are_rejected_even_within_checkout() -> Result<()> {
    let (root, layout) = fixture()?;
    let evidence = root.path().join("records/evidence/MTM-016/receipt.json");
    fs::rename(&evidence, root.path().join("retained-source"))?;
    std::os::unix::fs::symlink(root.path().join("retained-source"), &evidence)?;
    assert!(validate(root.path(), &layout).is_err());
    let (root, _) = fixture()?;
    fs::rename(
        root.path().join("records/iterations"),
        root.path().join("retained-iterations"),
    )?;
    std::os::unix::fs::symlink(
        root.path().join("retained-iterations"),
        root.path().join("records/iterations"),
    )?;
    assert!(safe_path(root.path(), "records/iterations/ITER-016.json").is_err());
    Ok(())
}

fn seal(root: &Path, reports: Value) -> Result<()> {
    write(
        root,
        "records/iterations/ITER-016.json",
        &serde_json::to_vec(&json!({"receipts":[{"id":"review","sealed_reports":reports}]}))?,
    )
}

#[test]
fn new_observations_are_hash_bound_but_not_reexecuted_or_relabelled() -> Result<()> {
    let (root, mut layout) = fixture()?;
    let reports = json!([{"path":layout["relocations"][0]["current_path"],
        "sha256":layout["relocations"][0]["sha256"]}]);
    seal(root.path(), reports)?;
    assert_eq!(
        validate(root.path(), &layout)?["sealed_observation_hashes_checked"],
        1
    );
    let changed = b"{\"passed\":true}";
    write(
        root.path(),
        "records/evidence/MTM-016/receipt.json",
        changed,
    )?;
    layout["relocations"][0]["sha256"] = json!(format!("{:x}", Sha256::digest(changed)));
    // The independent receipt seal must still detect the changed bytes.
    assert!(validate(root.path(), &layout).is_err());
    Ok(())
}

#[test]
fn missing_duplicate_cross_milestone_and_malformed_seals_are_rejected() -> Result<()> {
    let (root, layout) = fixture()?;
    let report = json!({"path":layout["relocations"][0]["current_path"],
        "sha256":layout["relocations"][0]["sha256"]});
    for reports in [
        json!([]),
        json!([report, report]),
        json!("invalid"),
        json!([{"path":"records/evidence/MTM-015/receipt.json","sha256":"a".repeat(64)}]),
        json!([{"path":"records/evidence/MTM-016/missing.json","sha256":"a".repeat(64)}]),
        json!([{"path":"records/evidence/MTM-016/receipt.json"}]),
    ] {
        seal(root.path(), reports)?;
        assert!(validate(root.path(), &layout).is_err());
    }
    Ok(())
}

#[test]
fn historical_summary_preserves_identity_counts_and_verdict_types() -> Result<()> {
    let original =
        json!({"project":"MTM-reboot","milestone":"MTM-003","passed":true,"check_count":14});
    assert_eq!(historical_identity(&original, "MTM-003", 14)?, 14);
    for (key, value) in [
        ("project", json!("wrong")),
        ("milestone", json!("MTM-004")),
        ("passed", json!(1)),
        ("passed", json!(false)),
        ("check_count", json!(14.0)),
        ("check_count", json!(13)),
        ("check_count", Value::Null),
    ] {
        let mut changed = original.clone();
        changed[key] = value;
        assert!(historical_identity(&changed, "MTM-003", 14).is_err());
    }
    let v8 = json!({"project":"MTM-reboot","milestone":"MTM-008","passed":true,"checks":vec![json!({});10]});
    assert_eq!(historical_identity(&v8, "MTM-008", 10)?, 10);
    Ok(())
}
