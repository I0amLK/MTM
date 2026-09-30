//! Public parser/reader fixtures only; never execute a candidate or real evaluation.
use super::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use tempfile::TempDir;

fn r(path: &str) -> Result<Reference> {
    Ok(Reference {
        path: path.into(),
        sha256: digest(&fs::read(crate::root()?.join(path))?),
    })
}
fn fixture() -> Result<Inputs> {
    Ok(Inputs {
        schema: "mtm017-release-inputs-v1".into(),
        milestone: "MTM-017".into(),
        criteria_revision: CONTRACT.into(),
        criteria: r(CONTRACT_PATH)?,
        candidate_sha256: CANDIDATE.into(),
        baseline_sha256: BASELINE.into(),
        prepared_by: "formal-readiness-preparer".into(),
        source_gate: r(
            "records/evidence/MTM-017/authority-corpus-whole-source-final-20260930.json",
        )?,
        snapshot: r("records/evidence/MTM-017/preview2-qualification-snapshot.json")?,
        corpus_state: r("records/governance/mtm017-corpus-union.json")?,
        corpus_acceptance: r("records/evidence/MTM-017/corpus-union-accepted-20260930.json")?,
        research_state: r("records/governance/mtm017-research-corpus.json")?,
        decisions: r("records/governance/mtm017-readiness-decisions.json")?,
        clean_build_state: r("records/governance/mtm017-clean-build-status.json")?,
        u26_state: r("records/governance/mtm017-u26-waiver.json")?,
        operator_copy: r(
            "records/evidence/MTM-017/operator-copy-prepared-rehearsal-aggregate-20260930.json",
        )?,
        operator_copy_review: r(
            "records/evidence/MTM-017/operator-copy-prepared-rehearsal-review-20260930.json",
        )?,
        known_failure: r(FAILURE.0)?,
        known_failure_followup: r(
            "records/evidence/MTM-017/authority-corpus-source-regression-followup-20260930.json",
        )?,
        mechanism_diagnostic: r(
            "records/evidence/MTM-017/authority-corpus-domain-collision-diagnostic-20260930.json",
        )?,
        risk_disposition: None,
        risk_disposition_review: None,
        test_only_sources: TEST_PATHS.iter().map(|p| r(p)).collect::<Result<_>>()?,
    })
}

#[test]
fn closed_inputs_roles_and_options_reject_unknown_missing_or_cross_scope_values() -> Result<()> {
    let i = fixture()?;
    input_shape(&i)?;
    let base = serde_json::to_value(&i)?;
    for key in base.as_object().ok_or("input object")?.keys() {
        if ["risk_disposition", "risk_disposition_review"].contains(&key.as_str()) {
            continue;
        }
        let mut bad = base.clone();
        bad.as_object_mut().ok_or("input object")?.remove(key);
        assert!(serde_json::from_value::<Inputs>(bad).is_err());
    }
    let mut extra = base.clone();
    extra["release_qualified"] = json!(true);
    assert!(serde_json::from_value::<Inputs>(extra).is_err());
    for (p, v) in [
        ("/candidate_sha256", json!(BASELINE)),
        ("/criteria_revision", json!("old")),
        ("/snapshot/sha256", json!("a".repeat(64))),
        (
            "/test_only_sources/0/path",
            json!("crates/mtm-runtime/src/lib.rs"),
        ),
    ] {
        let mut bad = base.clone();
        *bad.pointer_mut(p).ok_or("pointer")? = v;
        assert!(input_shape(&serde_json::from_value(bad)?).is_err());
    }
    for bytes in [
        b"{\"x\":0,\"x\":1}".as_slice(),
        b"{\"a\":{\"x\":1,\"\\u0078\":2}}",
        b"{}{}",
    ] {
        assert!(evidence_json::decode(bytes).is_err());
    }
    for args in [
        vec![],
        vec!["--record"],
        vec![
            "--inputs",
            "records/evidence/MTM-017/a.json",
            "--input-review",
            "records/evidence/MTM-017/b.json",
            "--force",
        ],
    ] {
        assert!(Options::parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>()).is_err());
    }
    Ok(())
}

#[test]
fn independent_input_review_binds_bytes_source_binary_and_distinct_reviewer() -> Result<()> {
    let i = fixture()?;
    let good = json!({"schema":"mtm017-release-input-review-v1","milestone":"MTM-017","inputs_sha256":"a".repeat(64),"implementation_source_sha256":"b".repeat(64),"maintenance_binary_sha256":"c".repeat(64),"prepared_by":i.prepared_by,"reviewer_session":"independent-review","decision":"approved_for_read_only_readiness_evaluation","checks":REVIEW_CHECKS,"recorded_unix_seconds":1,"release_qualified":false,"deployment_authorized":false});
    review_shape(
        &serde_json::from_value(good.clone())?,
        &i,
        &"a".repeat(64),
        &"b".repeat(64),
        &"c".repeat(64),
    )?;
    for (key, v) in [
        ("inputs_sha256", json!("d".repeat(64))),
        ("implementation_source_sha256", json!("d".repeat(64))),
        ("maintenance_binary_sha256", json!("d".repeat(64))),
        ("reviewer_session", json!(i.prepared_by)),
        ("release_qualified", json!(true)),
        ("checks", json!([])),
    ] {
        let mut bad = good.clone();
        bad[key] = v;
        assert!(
            review_shape(
                &serde_json::from_value(bad)?,
                &i,
                &"a".repeat(64),
                &"b".repeat(64),
                &"c".repeat(64)
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn reader_rejects_ancestor_leaf_links_replacement_modes_and_budgets() -> Result<()> {
    let t = TempDir::new()?;
    fs::create_dir(t.path().join("real"))?;
    fs::write(t.path().join("real/a.json"), b"{}")?;
    symlink("real", t.path().join("link"))?;
    assert!(files::read(t.path(), "link/a.json", 16, false).is_err());
    symlink("a.json", t.path().join("real/l.json"))?;
    assert!(files::read(t.path(), "real/l.json", 16, false).is_err());
    let before = files::read(t.path(), "real/a.json", 16, false)?;
    fs::write(t.path().join("real/new.json"), b"{}")?;
    fs::rename(t.path().join("real/new.json"), t.path().join("real/a.json"))?;
    assert!(
        before
            .recheck(&files::read(t.path(), "real/a.json", 16, false)?)
            .is_err()
    );
    fs::hard_link(t.path().join("real/a.json"), t.path().join("real/h.json"))?;
    assert!(files::read(t.path(), "real/h.json", 16, false).is_err());
    fs::write(t.path().join("mode.json"), b"{}")?;
    fs::set_permissions(
        t.path().join("mode.json"),
        fs::Permissions::from_mode(0o666),
    )?;
    assert!(files::read(t.path(), "mode.json", 16, false).is_err());
    for p in ["../x", "/x", "real//a.json", "real/../mode.json"] {
        assert!(files::read(t.path(), p, 16, false).is_err());
    }
    fs::set_permissions(
        t.path().join("mode.json"),
        fs::Permissions::from_mode(0o644),
    )?;
    files::read(t.path(), "mode.json", 16, false)?;
    assert!(files::read(t.path(), "mode.json", 1, false).is_err());
    fs::set_permissions(
        t.path().join("mode.json"),
        fs::Permissions::from_mode(0o700),
    )?;
    files::read(t.path(), "mode.json", 16, true)?;
    fs::set_permissions(
        t.path().join("mode.json"),
        fs::Permissions::from_mode(0o720),
    )?;
    assert!(files::read(t.path(), "mode.json", 16, true).is_err());
    let dir = t.path().join(PREFIX);
    fs::create_dir_all(&dir)?;
    fs::write(dir.join("budget.json"), b"{}")?;
    let mut inv = Inventory::new(t.path());
    inv.bytes = 64 * 1024 * 1024;
    assert!(
        inv.json(&Reference {
            path: format!("{PREFIX}budget.json"),
            sha256: digest(b"{}")
        })
        .is_err()
    );
    assert!(
        Inventory::new(t.path())
            .json(&Reference {
                path: "docs/secret.json".into(),
                sha256: digest(b"{}")
            })
            .is_err()
    );
    Ok(())
}

#[test]
fn profile_and_current_source_mutations_fail_semantics() -> Result<()> {
    let root = crate::root()?;
    let i = fixture()?;
    let mut inv = Inventory::new(&root);
    assert_eq!(policy::profiles(&mut inv, &i)?.len(), 8);
    let path = "records/evidence/MTM-017/preview2-protocol-13d7890.json";
    let good = inv.documents.get(path).ok_or("profile fixture")?.clone();
    for (p, v) in [
        ("/candidate_sha256", json!(BASELINE)),
        (
            "/harness_source_identity/before_sha256",
            json!("a".repeat(64)),
        ),
        ("/summaries/capability/normal_roundtrips", json!(499)),
        ("/runner/child_reaped", json!(false)),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(p).ok_or("profile pointer")? = v;
        inv.documents.insert(path.into(), bad);
        assert!(policy::profiles(&mut inv, &i).is_err());
    }
    let source = inv.json(&i.source_gate)?;
    let sha = source["source_identity"]["before_sha256"]
        .as_str()
        .ok_or("source sha")?;
    source_gate(&source, sha)?;
    assert!(source_gate(&source, &"a".repeat(64)).is_err());
    for pointer in ["/extra", "/source_identity/extra", "/checks/0/extra"] {
        let mut unknown = source.clone();
        if pointer == "/extra" {
            unknown["extra"] = json!(true);
        } else if pointer == "/source_identity/extra" {
            unknown["source_identity"]["extra"] = json!(true);
        } else {
            unknown["checks"][0]["extra"] = json!(true);
        }
        assert!(source_gate(&unknown, sha).is_err());
    }
    let mut bad = source.clone();
    bad["checks"][0]["passed"] = json!(false);
    assert!(source_gate(&bad, sha).is_err());
    Ok(())
}

#[test]
fn all_scoped_waivers_preserve_technical_failures_and_cannot_expand() -> Result<()> {
    let root = crate::root()?;
    let i = fixture()?;
    let mut inv = Inventory::new(&root);
    let ledger = inv.json(&i.decisions)?;
    policy::waivers(&mut inv, &i, &ledger)?;
    let u = "records/evidence/MTM-017/u26-human-waiver-20260930.json";
    let good = inv.documents.get(u).ok_or("u26")?.clone();
    for (p, v) in [
        ("/passed", json!(true)),
        ("/human_waived_cells", json!(90)),
        ("/applicability/candidate_sha256", json!(BASELINE)),
        ("/cells/0/task_id", json!("U27")),
        ("/cells/1/repeat", json!(1)),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(p).ok_or("waiver pointer")? = v;
        inv.documents.insert(u.into(), bad.clone());
        let mut d = ledger.clone();
        let values = d["decisions"].as_array_mut().ok_or("decisions")?;
        *values
            .iter_mut()
            .find(|x| x["decision_id"] == "MTM017-READINESS-DECISION-006")
            .ok_or("006")? = bad;
        assert!(policy::waivers(&mut inv, &i, &d).is_err());
    }
    let mut duplicate = ledger.clone();
    let first = duplicate["decisions"][0].clone();
    duplicate["decisions"]
        .as_array_mut()
        .ok_or("decisions")?
        .push(first);
    assert!(policy::decision(&duplicate, "MTM017-READINESS-DECISION-001").is_err());
    Ok(())
}

#[test]
fn real_operator_copy_preserves_exact_restore_before_preparation() -> Result<()> {
    let root = crate::root()?;
    let i = fixture()?;
    let mut inv = Inventory::new(&root);
    let ledger = inv.json(&i.decisions)?;
    let good = operator_copy::validate(&mut inv, &i, &ledger)?;
    assert_eq!(good["real_repetitions"], 3);
    let path = "records/evidence/MTM-017/operator-copy-prepared-repeat-1-20260930.json";
    let original = inv.documents.get(path).ok_or("copy fixture")?.clone();
    for (p, v) in [
        ("/real_sanitized_receipts/0/synthetic_only", json!(true)),
        ("/real_sanitized_receipts/0/schema_restored", json!(8)),
        (
            "/real_sanitized_receipts/0/old_run_advanced_on_candidate",
            json!(false),
        ),
        (
            "/real_sanitized_receipts/0/original_bytes_modes_exact_before_baseline_preparation",
            json!(false),
        ),
    ] {
        let mut bad = original.clone();
        *bad.pointer_mut(p).ok_or("copy pointer")? = v;
        inv.documents.insert(path.into(), bad);
        assert!(operator_copy::validate(&mut inv, &i, &ledger).is_err());
    }
    Ok(())
}

#[test]
fn accepted_union_reconstructs_87_without_waiver_technical_promotion() -> Result<()> {
    let root = crate::root()?;
    let i = fixture()?;
    let mut inv = Inventory::new(&root);
    let ledger = inv.json(&i.decisions)?;
    let copy = operator_copy::validate(&mut inv, &i, &ledger)?;
    let research = release_readiness_schema8::verified_research_subset(&root)?;
    let good = corpus::validate(&mut inv, &i, &research, &copy)?;
    assert_eq!(good["technical_accepted_trials"], 87);
    assert_eq!(good["technical_pending_trials"], 3);
    let original = inv
        .documents
        .get(&i.corpus_acceptance.path)
        .ok_or("union fixture")?
        .clone();
    for (p, v) in [
        ("/accepted_trials", json!(90)),
        ("/pending_trials", json!(0)),
        ("/full_corpus_accepted", json!(true)),
        ("/rows/0/task_id", json!("U26")),
        ("/rows/75/status", json!("accepted")),
    ] {
        let mut bad = original.clone();
        *bad.pointer_mut(p).ok_or("union pointer")? = v;
        inv.documents.insert(i.corpus_acceptance.path.clone(), bad);
        assert!(corpus::validate(&mut inv, &i, &research, &copy).is_err());
    }
    Ok(())
}

#[test]
fn reviewed_scoped_risk_acceptance_does_not_relabel_failure_or_allow_other_waivers() -> Result<()> {
    let actual = crate::root()?;
    let temporary = TempDir::new()?;
    let mut i = fixture()?;
    let risk = r("records/evidence/MTM-017/source-risk-human-disposition-20260930.json")?;
    // Previously sealed public review bytes are parser fixtures, not a new review.
    let review_ref = r("records/evidence/MTM-017/source-risk-disposition-review-20260930.json")?;
    let review_bytes = fs::read(actual.join(&review_ref.path))?;
    fs::create_dir_all(temporary.path().join(PREFIX))?;
    fs::write(temporary.path().join(&review_ref.path), review_bytes)?;
    for seal in [
        &i.known_failure,
        &i.known_failure_followup,
        &i.mechanism_diagnostic,
        &i.decisions,
        &risk,
    ] {
        let destination = temporary.path().join(&seal.path);
        fs::create_dir_all(destination.parent().ok_or("fixture parent")?)?;
        fs::write(destination, fs::read(actual.join(&seal.path))?)?;
    }
    i.risk_disposition = Some(risk.clone());
    i.risk_disposition_review = Some(review_ref.clone());
    input_shape(&i)?;
    let mut inv = Inventory::new(temporary.path());
    let observed = policy::finding(&mut inv, &i)?;
    assert_eq!(observed["blocks_current_evaluation"], false);
    assert_eq!(observed["root_cause_status"], "indeterminate");
    assert_eq!(observed["historical_failure_passed"], false);
    assert_eq!(observed["runtime_fix_claimed"], false);
    let original = inv.documents.get(&risk.path).ok_or("risk fixture")?.clone();
    let ledger = inv
        .documents
        .get(&i.decisions.path)
        .ok_or("ledger fixture")?
        .clone();
    for (pointer, value) in [
        ("/passed", json!(true)),
        ("/runtime_fix_claimed", json!(true)),
        ("/candidate_sha256", json!(BASELINE)),
        ("/finding_id", json!("clean_build")),
        ("/decision_id", json!("MTM017-READINESS-DECISION-003")),
        ("/operator_authorization/answer_verbatim", json!("")),
        ("/operator_authorization/answer_verbatim", json!("拒绝")),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).ok_or("risk pointer")? = value;
        inv.documents.insert(risk.path.clone(), changed.clone());
        let mut adjusted = ledger.clone();
        *adjusted["decisions"]
            .as_array_mut()
            .ok_or("decisions")?
            .iter_mut()
            .find(|d| d["decision_id"] == "MTM017-READINESS-DECISION-007")
            .ok_or("007")? = changed;
        inv.documents.insert(i.decisions.path.clone(), adjusted);
        assert!(policy::finding(&mut inv, &i).is_err());
    }
    inv.documents.insert(risk.path.clone(), original);
    inv.documents.insert(i.decisions.path.clone(), ledger);
    let mut review = inv
        .documents
        .get(&review_ref.path)
        .ok_or("review fixture")?
        .clone();
    review["reviewer_session"] = json!(i.prepared_by);
    inv.documents.insert(review_ref.path.clone(), review);
    assert!(policy::finding(&mut inv, &i).is_err());
    Ok(())
}

#[test]
fn production_drift_allowlist_is_only_three_explicit_reviewed_test_paths() {
    for path in TEST_PATHS {
        assert!(permitted_test_delta(path));
    }
    for path in [
        "crates/mtm-runtime/src/lib.rs",
        "crates/mtm-runtime/build.rs",
        "crates/mtm-cli/assets/template.tex",
        "Cargo.toml",
        "Cargo.lock",
        ".cargo/config.toml",
        ".cargo/extra.toml",
        "crates/mtm-runtime/tests/unreviewed.rs",
    ] {
        assert!(!permitted_test_delta(path));
    }
}

#[test]
fn inventory_count_allows_shared_auxiliary_hashes_but_bounds_total_files() -> Result<()> {
    let temp = TempDir::new()?;
    fs::create_dir_all(temp.path().join(PREFIX))?;
    let mut inv = Inventory::new(temp.path());
    for n in 0..257 {
        let path = format!("{PREFIX}budget-{n}.json");
        fs::write(temp.path().join(&path), b"{}")?;
        let result = inv.json(&Reference {
            path,
            sha256: digest(b"{}"),
        });
        assert_eq!(result.is_ok(), n < 256);
    }
    Ok(())
}

#[test]
fn unresolved_finding_and_positive_evaluation_both_need_separate_result_review() -> Result<()> {
    let root = crate::root()?;
    let i = fixture()?;
    let mut inv = Inventory::new(&root);
    let f = policy::finding(&mut inv, &i)?;
    assert_eq!(f["blocks_current_evaluation"], true);
    let original = inv
        .documents
        .get(&i.mechanism_diagnostic.path)
        .ok_or("diagnostic fixture")?
        .clone();
    for (key, value) in [
        ("domain_primary_key_collision_confirmed", json!(false)),
        ("same_run_next_task_recovered", json!(false)),
        ("receipt_replay_writes", json!(1)),
        ("synthetic_only", json!(false)),
    ] {
        let mut changed = original.clone();
        changed["observed"][key] = value;
        inv.documents
            .insert(i.mechanism_diagnostic.path.clone(), changed);
        assert!(policy::finding(&mut inv, &i).is_err());
    }
    for (blocked, expected) in [(true, false), (false, true)] {
        let report = policy::report(
            &i,
            "s",
            "b",
            "i",
            "r",
            json!({"known_finding":{"blocks_current_evaluation":blocked}}),
        );
        assert_eq!(report["readiness_evaluation_passed"], expected);
        assert_eq!(report["release_qualified"], false);
        assert_eq!(report["deployment_authorized"], false);
        assert_eq!(report["result_review_pending"], true);
        assert_eq!(report["technical_accepted_trials"], 87);
        let rows = array(&report["gates"])?;
        assert_eq!(rows.len(), 18);
        let ids = rows
            .iter()
            .filter_map(|v| v["id"].as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), 18);
        for row in rows {
            if [
                "browser_U26",
                "clean_build",
                "historical_binary",
                "current_corpus_accounting",
            ]
            .iter()
            .any(|id| row["id"] == *id)
            {
                assert_eq!(row["technical_pass"], false);
            }
        }
    }
    Ok(())
}
