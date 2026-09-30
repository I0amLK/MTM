//! Parser/reader fixtures only. No call to run(), release verdict or private state.
use super::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use tempfile::TempDir;

fn historical_decisions(bytes: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes)?;
    let key = text.find("\"decisions\"").ok_or("decision array missing")?;
    let start = key + text[key..].find('[').ok_or("decision array missing")?;
    let (mut quoted, mut escaped, mut depth, mut count) = (false, false, 0_u64, 0_u64);
    for (offset, b) in bytes[start + 1..].iter().copied().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quoted = false;
            }
            continue;
        }
        match b {
            b'"' => quoted = true,
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1).ok_or("fixture nesting")?;
                if depth == 0 {
                    count += 1;
                    if count == 3 {
                        let mut out = bytes[..start + offset + 2].to_vec();
                        out.extend_from_slice(b"\n  ]\n}\n");
                        return Ok(out);
                    }
                }
            }
            _ => {}
        }
    }
    Err("historical decision prefix missing".into())
}

fn fixtures(root: &Path) -> Result<Inventory<'_>> {
    let mut inventory = Inventory::new(root);
    for (path, sha) in ANCHORS {
        if path == DECISIONS {
            // This draft's pure validators use their exact historical prefix.
            // The production loader still rejects the appended current ledger.
            let bytes = historical_decisions(&fs::read(root.join(path))?)?;
            require(digest(&bytes) == sha, "historical decision fixture drift")?;
            inventory
                .json
                .insert(path.to_owned(), evidence_json::decode(&bytes)?);
        } else {
            inventory.load(path, sha, false)?;
        }
    }
    let snapshot = inventory.get(SNAPSHOT)?.clone();
    for seal in array(&snapshot["report_seals"])? {
        inventory.referred(seal)?;
    }
    for path in [RESEARCH, CLEAN] {
        let value = inventory.get(path)?.clone();
        inventory.closure(&value, 0)?;
    }
    let active = &inventory.get(CLEAN)?["active_decision"];
    let seal = json!({"path":active["path"],"sha256":active["sha256"]});
    inventory.referred(&seal)?;
    Ok(inventory)
}

#[test]
fn options_cannot_select_new_evidence_or_add_authority() -> Result<()> {
    reject_options(&[])?;
    for option in [
        "--record",
        "--manifest",
        "--force",
        "--accept",
        "--authorize",
        "--binary",
        "--sha256",
        "--help",
    ] {
        assert!(reject_options(&[option.to_owned()]).is_err());
    }
    Ok(())
}

#[test]
fn sealed_unknown_fields_duplicates_and_untrusted_references_are_rejected() -> Result<()> {
    let dir = TempDir::new()?;
    fs::write(dir.path().join("data.json"), b"{\"ok\":true}")?;
    let mut inventory = Inventory::new(dir.path());
    inventory.load("data.json", &digest(b"{\"ok\":true}"), false)?;
    fs::write(
        dir.path().join("data.json"),
        b"{\"ok\":true,\"release_qualified\":true}",
    )?;
    let mut changed = Inventory::new(dir.path());
    assert!(
        changed
            .load("data.json", &digest(b"{\"ok\":true}"), false)
            .is_err()
    );
    assert!(inventory.recheck().is_err());
    assert!(reference(&json!({"path":"a","sha256":"a".repeat(64),"passed":true})).is_err());
    assert!(
        inventory
            .referred(&json!({"path":"records/governance/unreviewed.json","sha256":"a".repeat(64)}))
            .is_err()
    );
    assert!(inventory.load("data.json", &"b".repeat(64), false).is_err());
    for bytes in [
        b"{\"x\":0,\"x\":1}".as_slice(),
        b"{\"nested\":{\"x\":0,\"\\u0078\":1}}",
        b"{}{}",
    ] {
        fs::write(dir.path().join("bad.json"), bytes)?;
        assert!(
            Inventory::new(dir.path())
                .load("bad.json", &digest(bytes), false)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn only_named_historical_source_locator_fields_are_not_current_inputs() -> Result<()> {
    let dir = TempDir::new()?;
    let mut inventory = Inventory::new(dir.path());
    let historical = json!({"schema":"mtm017-research-import-implementation-validation-v1",
        "source_files":[{"path":"xtask/src/main.rs","sha256":"a".repeat(64)}],
        "documentation":{"path":"docs/old.md","sha256":"b".repeat(64)}});
    inventory.closure(&historical, 0)?;
    assert!(inventory.files.is_empty());
    let mut other_schema = historical.clone();
    other_schema["schema"] = json!("unreviewed-source-schema");
    assert!(inventory.closure(&other_schema, 0).is_err());
    let mut unexpected_field = historical;
    unexpected_field["current_source"] =
        json!({"path":"xtask/src/main.rs","sha256":"a".repeat(64)});
    assert!(inventory.closure(&unexpected_field, 0).is_err());
    let report = draft_report(
        "a".repeat(64),
        vec![],
        vec![],
        json!({}),
        vec![json!({}), json!({})],
    );
    assert_eq!(report["release_qualified"], false);
    assert_eq!(
        report["current_maintenance"]["whole_source_gate_verified"],
        false
    );
    Ok(())
}

#[test]
fn bounded_reader_rejects_traversal_symlinks_hardlinks_modes_and_special_files() -> Result<()> {
    let dir = TempDir::new()?;
    fs::write(dir.path().join("ok.json"), b"{}")?;
    for path in [
        "",
        "/ok.json",
        "../ok.json",
        "./ok.json",
        "a//b",
        "a/../b",
        "a/",
        "a\\b",
        "a\n",
    ] {
        assert!(files::read(dir.path(), path, 16, false).is_err());
    }
    assert!(files::read(dir.path(), "ok.json", 1, false).is_err());
    symlink("ok.json", dir.path().join("leaf.json"))?;
    assert!(files::read(dir.path(), "leaf.json", 16, false).is_err());
    fs::create_dir(dir.path().join("real"))?;
    fs::write(dir.path().join("real/data.json"), b"{}")?;
    symlink("real", dir.path().join("linked"))?;
    assert!(files::read(dir.path(), "linked/data.json", 16, false).is_err());
    fs::hard_link(dir.path().join("ok.json"), dir.path().join("hard.json"))?;
    assert!(files::read(dir.path(), "hard.json", 16, false).is_err());
    fs::write(dir.path().join("mode.json"), b"{}")?;
    for mode in [0o666, 0o744, 0o4644] {
        fs::set_permissions(
            dir.path().join("mode.json"),
            fs::Permissions::from_mode(mode),
        )?;
        assert!(files::read(dir.path(), "mode.json", 16, false).is_err());
    }
    fs::set_permissions(
        dir.path().join("mode.json"),
        fs::Permissions::from_mode(0o664),
    )?;
    files::read(dir.path(), "mode.json", 16, false)?;
    assert!(files::read(dir.path(), "mode.json", 16, true).is_err());
    nix::unistd::mkfifo(
        &dir.path().join("pipe.json"),
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )?;
    assert!(files::read(dir.path(), "pipe.json", 16, false).is_err());
    fs::write(dir.path().join("empty.json"), b"")?;
    assert!(files::read(dir.path(), "empty.json", 16, false).is_err());
    Ok(())
}

#[test]
fn recheck_rejects_same_bytes_replaced_inode_and_mode_drift() -> Result<()> {
    let dir = TempDir::new()?;
    let path = dir.path().join("value.json");
    fs::write(&path, b"{}")?;
    let before = files::read(dir.path(), "value.json", 16, false)?;
    fs::write(dir.path().join("new.json"), b"{}")?;
    fs::rename(dir.path().join("new.json"), &path)?;
    assert!(
        before
            .recheck(&files::read(dir.path(), "value.json", 16, false)?)
            .is_err()
    );
    let before = files::read(dir.path(), "value.json", 16, false)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    assert!(
        before
            .recheck(&files::read(dir.path(), "value.json", 16, false)?)
            .is_err()
    );
    Ok(())
}

#[test]
fn snapshot_and_source_checkpoint_bind_schema_version_candidate_and_lineage() -> Result<()> {
    let root = crate::root()?;
    let inventory = fixtures(&root)?;
    let good = inventory.get(SNAPSHOT)?;
    validation::snapshot(good)?;
    for (pointer, value) in [
        ("/candidate/sha256", json!(BASELINE)),
        ("/candidate/state_schema", json!(7)),
        ("/candidate/tool_contract", json!("mtm-tools-v9")),
        ("/baseline/path", json!("target/other/mtm")),
        ("/upgrade/operator_state_copy_tested", json!(true)),
        ("/release_qualified", json!(true)),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).ok_or("test pointer")? = value;
        assert!(validation::snapshot(&bad).is_err());
    }
    let source = inventory.get("records/evidence/MTM-017/preview2-source-gate.json")?;
    validation::source_checkpoint(source)?;
    let mut bad = source.clone();
    bad["source_identity"]["before_sha256"] = json!("a".repeat(64));
    assert!(validation::source_checkpoint(&bad).is_err());
    Ok(())
}

#[test]
fn profile_fixtures_recheck_summaries_candidate_and_exact_harness() -> Result<()> {
    let root = crate::root()?;
    let mut inventory = fixtures(&root)?;
    let snapshot = inventory.get(SNAPSHOT)?.clone();
    assert_eq!(validation::profiles(&inventory, &snapshot)?.len(), 8);
    let path = "records/evidence/MTM-017/preview2-protocol-13d7890.json";
    let good = inventory.get(path)?.clone();
    for (pointer, value) in [
        ("/candidate_sha256", json!(BASELINE)),
        (
            "/harness_source_identity/before_sha256",
            json!("a".repeat(64)),
        ),
        ("/harness_source_identity/commit", json!("a".repeat(40))),
        ("/summaries/capability/normal_roundtrips", json!(499)),
        ("/runner/child_reaped", json!(false)),
        ("/passed", json!(false)),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).ok_or("test pointer")? = value;
        inventory.json.insert(path.to_owned(), bad);
        assert!(validation::profiles(&inventory, &snapshot).is_err());
    }
    inventory.json.insert(path.to_owned(), good);
    let path = "records/evidence/MTM-017/preview2-upgrade-schema8-13d7890.json";
    let mut bad = inventory.get(path)?.clone();
    bad["baseline_sha256"] = json!(CANDIDATE);
    inventory.json.insert(path.to_owned(), bad);
    assert!(validation::profiles(&inventory, &snapshot).is_err());
    Ok(())
}

#[test]
fn research_requires_separate_approval_and_exact_unique_fifteen_rows() -> Result<()> {
    let root = crate::root()?;
    let mut inventory = fixtures(&root)?;
    let observed = validation::research(&mut inventory)?;
    assert_eq!(observed["previously_accepted_subset"], 15);
    assert_eq!(observed["newly_accepted_trials"], 0);
    assert_eq!(observed["private_math_review_reexecuted"], false);
    let path = "records/evidence/MTM-017/corpus-import-result-review-20260930-r3.json";
    let good = inventory.get(path)?.clone();
    for (pointer, value) in [
        ("/decision", json!("self_approved")),
        ("/maintenance_binary_sha256", json!("a".repeat(64))),
        (
            "/checks/independently_rehashed_all_186_bundle_artifacts",
            json!(false),
        ),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).ok_or("test pointer")? = value;
        inventory.json.insert(path.to_owned(), bad);
        assert!(validation::research(&mut inventory).is_err());
    }
    inventory.json.insert(path.to_owned(), good);
    let path = "records/evidence/MTM-017/research-corpus-subset-accepted-20260930.json";
    let mut bad = inventory.get(path)?.clone();
    bad["trials"][1] = bad["trials"][0].clone();
    inventory.json.insert(path.to_owned(), bad);
    assert!(validation::research(&mut inventory).is_err());
    Ok(())
}

#[test]
fn waivers_preserve_failure_and_cannot_change_candidate_or_baseline_scope() -> Result<()> {
    let root = crate::root()?;
    let mut inventory = fixtures(&root)?;
    let good = inventory.get(DECISIONS)?.clone();
    let result = validation::waivers(&mut inventory)?;
    assert_eq!(result[0]["passed"], false);
    assert_eq!(result[0]["exact_candidate_reproduced"], false);
    assert_eq!(
        result[1]["current_schema7_rollback_requirement_waived"],
        false
    );
    for (pointer, value) in [
        ("/decisions/2/passed", json!(true)),
        (
            "/decisions/2/applicability/candidate_sha256",
            json!(BASELINE),
        ),
        ("/decisions/2/gate", json!("operator_state_copy")),
        (
            "/decisions/0/compatible_schema7_baseline_sha256",
            json!(CANDIDATE),
        ),
        ("/decisions/0/disposition", json!("technical_pass")),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).ok_or("test pointer")? = value;
        inventory.json.insert(DECISIONS.to_owned(), bad);
        assert!(validation::waivers(&mut inventory).is_err());
    }
    inventory.json.insert(DECISIONS.to_owned(), good);
    let good = inventory.get(CLEAN)?.clone();
    for key in [
        "passed",
        "exact_candidate_reproduced",
        "release_qualified",
        "deployment_authorized",
    ] {
        let mut bad = good.clone();
        bad[key] = json!(true);
        inventory.json.insert(CLEAN.to_owned(), bad);
        assert!(validation::waivers(&mut inventory).is_err());
    }
    Ok(())
}

#[test]
fn draft_does_not_promote_all_true_observations_or_sum_subset_counts() -> Result<()> {
    let report = draft_report(
        "a".repeat(64),
        vec![],
        PROFILES
            .iter()
            .map(|profile| json!({"profile":profile,"passed":true,"release_qualified":true}))
            .collect(),
        json!({"previously_accepted_subset":15}),
        vec![json!({"passed":false}), json!({"passed":false})],
    );
    assert_eq!(report["status"], "blocked");
    assert_eq!(report["requirements_complete"], false);
    assert_eq!(report["implementation_complete"], "unknown");
    assert_eq!(report["release_qualified"], false);
    assert_eq!(report["deployment_authorized"], false);
    assert_eq!(
        report["current_maintenance"]["whole_source_gate_verified"],
        false
    );
    let gates = array(&report["gates"])?;
    assert_eq!(gates.len(), 18);
    let ids = gates
        .iter()
        .map(|v| v["id"].as_str().ok_or("gate id missing"))
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    assert_eq!(ids.len(), 18);
    for row in gates {
        if row["gate_disposition"] == "waived_by_operator"
            || PROFILES.iter().any(|p| row["id"] == *p)
        {
            assert_eq!(row["technical_pass"], false);
        }
        if row["id"] == "full_current_corpus" {
            assert_eq!(row["observation_validation"]["subset_counts_summed"], false);
            assert_eq!(
                row["observation_validation"]["u27_u28_schema8_mapping_pending"],
                true
            );
        }
    }
    Ok(())
}

#[test]
fn historical_decision_fixture_does_not_reenable_stale_production_anchor() -> Result<()> {
    let root = crate::root()?;
    let bytes = fs::read(root.join(DECISIONS))?;
    let prior = historical_decisions(&bytes)?;
    let expected = ANCHORS
        .iter()
        .find(|(path, _)| *path == DECISIONS)
        .ok_or("anchor")?
        .1;
    assert_eq!(digest(&prior), expected);
    let mut corrupt = prior.clone();
    corrupt[0] = b' ';
    assert_ne!(digest(&corrupt), expected);
    if digest(&bytes) != expected {
        assert!(
            Inventory::new(&root)
                .load(DECISIONS, expected, false)
                .is_err()
        );
    }
    Ok(())
}
