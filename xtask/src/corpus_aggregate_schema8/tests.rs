//! Synthetic parser regressions only; no candidate/trial execution or corpus credit.
use super::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use tempfile::tempdir;
fn fixture(name: &str) -> Result<Value> {
    let text = match name {
        "portable" => include_str!(
            "../../../records/evidence/MTM-017/portable-corpus-20260930-13d7890-r1.json"
        ),
        "portable_wrapper" => include_str!(
            "../../../records/evidence/MTM-017/portable-corpus-observation-20260930-13d7890-r1.json"
        ),
        "portable_review" => include_str!(
            "../../../records/evidence/MTM-017/portable-corpus-independent-review-20260930-13d7890-r1.json"
        ),
        "native" => {
            include_str!("../../../records/evidence/MTM-017/preview2-corpus-native-13d7890.json")
        }
        "snapshot" => {
            include_str!("../../../records/evidence/MTM-017/preview2-qualification-snapshot.json")
        }
        "u30_wrapper" => include_str!(
            "../../../records/evidence/MTM-017/u30-install-sigkill-observations-20260930.json"
        ),
        "u30_review" => include_str!(
            "../../../records/evidence/MTM-017/u30-install-sigkill-independent-review-20260930.json"
        ),
        "u30_1" => include_str!(
            "../../../records/evidence/MTM-017/u30-install-sigkill-20260930-13d7890-r1.json"
        ),
        "u30_2" => include_str!(
            "../../../records/evidence/MTM-017/u30-install-sigkill-20260930-13d7890-r2.json"
        ),
        "u30_3" => include_str!(
            "../../../records/evidence/MTM-017/u30-install-sigkill-20260930-13d7890-r3.json"
        ),
        _ => return Err("unknown synthetic fixture".into()),
    };
    Ok(serde_json::from_str(text)?)
}
fn reference(a: (&str, &str)) -> Value {
    json!({"path":format!("{PREFIX}{}",a.0),"sha256":a.1})
}
fn input_value() -> Value {
    json!({"schema":"mtm017-partial-corpus-inputs-v1","milestone":"MTM-017","state_schema_version":8,
 "candidate_sha256":CANDIDATE,"candidate_source_commit":PRODUCT_COMMIT,"corpus_sha256":CORPUS,
 "prepared_by":"synthetic-preparer","portable":{"raw":reference(PORTABLE[0]),"observation":reference(PORTABLE[1]),"review":reference(PORTABLE[2])},
 "native":{"raw":reference(NATIVE[0]),"snapshot":reference(NATIVE[1])},
 "research":{"path":RESEARCH.0,"sha256":RESEARCH.1},
 "u30":{"observation":reference(U30[0]),"review":reference(U30[1]),"trials":[
  {"repeat":1,"raw":reference(U30[2])},{"repeat":2,"raw":reference(U30[3])},{"repeat":3,"raw":reference(U30[4])}]},
 "corpus_count_incremented":false,"production_selector_changed":false,"production_state_modified":false,
 "release_qualified":false,"deployment_authorized":false})
}
fn parsed<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T> {
    decode(&serde_json::to_vec(v)?)
}
fn input() -> Result<Inputs> {
    parsed(&input_value())
}
fn set(v: &Value, p: &str, new: Value) -> Result<Value> {
    let mut v = v.clone();
    *v.pointer_mut(p).ok_or("fixture pointer missing")? = new;
    Ok(v)
}
fn raws(i: &Inputs) -> Result<Vec<(u64, Reference, Value)>> {
    i.u30
        .trials
        .iter()
        .map(|t| {
            Ok((
                t.repeat,
                t.raw.clone(),
                fixture(&format!("u30_{}", t.repeat))?,
            ))
        })
        .collect()
}
#[test]
fn closed_input_rejects_unknown_duplicate_missing_wrong_candidate_and_anchors() -> Result<()> {
    let good = input_value();
    input_shape(&parsed(&good)?)?;
    for (p, v) in [
        ("/milestone", json!("MTM-016")),
        ("/state_schema_version", json!(7)),
        ("/candidate_sha256", json!(BASELINE)),
        ("/candidate_source_commit", json!("a".repeat(40))),
        ("/corpus_sha256", json!("a".repeat(64))),
        ("/portable/raw/sha256", json!("a".repeat(64))),
        (
            "/native/raw/path",
            json!("records/evidence/MTM-016/old.json"),
        ),
        ("/research/sha256", json!("a".repeat(64))),
        ("/u30/trials/1/repeat", json!(1)),
        ("/u30/trials/1/raw", reference(U30[2])),
        ("/corpus_count_incremented", json!(true)),
        ("/release_qualified", json!(true)),
        ("/deployment_authorized", json!(true)),
    ] {
        assert!(input_shape(&parsed(&set(&good, p, v)?)?).is_err(), "{p}");
    }
    let mut v = good.clone();
    v["arbitrary_passed_trials"] = json!(90);
    assert!(parsed::<Inputs>(&v).is_err());
    let mut v = good;
    v["u30"]["trials"]
        .as_array_mut()
        .ok_or("fixture array")?
        .pop();
    assert!(input_shape(&parsed(&v)?).is_err());
    assert!(decode::<Inputs>(br#"{"schema":"a","schema":"b"}"#).is_err());
    assert!(decode::<Inputs>(&vec![b' '; 1048577]).is_err());
    Ok(())
}
#[test]
fn portable_semantics_reject_partial_outer_failure_substitution_and_row_drift() -> Result<()> {
    let i = input()?;
    let raw = fixture("portable")?;
    let wrapper = fixture("portable_wrapper")?;
    let review = fixture("portable_review")?;
    assert_eq!(
        batches::portable(&raw, &wrapper, &review, &i.portable)?.len(),
        45
    );
    for (p, v) in [
        ("/passed", json!(true)),
        ("/failed_stage", json!("runner")),
        ("/failure", json!("anything else")),
        ("/runner/exit_code", json!(1)),
        ("/runner/timed_out", json!(true)),
        ("/runner/child_reaped", json!(false)),
        ("/candidate_sha256", json!(BASELINE)),
        ("/milestone", json!("MTM-017")),
        ("/profile", json!("protocol")),
        (
            "/harness_source_identity/before_sha256",
            json!(PRODUCT_SOURCE),
        ),
        ("/summaries/corpus/passed_trials", json!(46)),
        ("/summaries/corpus/blocked_trials", json!(44)),
        ("/summaries/corpus/rows/0/repeat", json!(2)),
        ("/summaries/corpus/rows/45/status", json!("passed")),
        ("/production_state_modified", json!(true)),
        ("/release_qualified", json!(true)),
    ] {
        assert!(
            batches::portable(&set(&raw, p, v)?, &wrapper, &review, &i.portable).is_err(),
            "{p}"
        );
    }
    let mut unknown = raw;
    unknown["unknown"] = json!(true);
    assert!(batches::portable(&unknown, &wrapper, &review, &i.portable).is_err());
    for (p, v) in [
        ("/execution/qualifier_exit_code", json!(0)),
        ("/execution/runner/exit_code", json!(1)),
        ("/candidate/state_schema", json!(7)),
        ("/raw_report/sha256", json!("a".repeat(64))),
        ("/isolation/fresh_per_task_repeat", json!(false)),
        ("/corpus/accepted_delta", json!(45)),
    ] {
        assert!(
            batches::portable(
                &fixture("portable")?,
                &set(&wrapper, p, v)?,
                &review,
                &i.portable
            )
            .is_err(),
            "{p}"
        );
    }
    Ok(())
}
#[test]
fn native_snapshot_and_dangerous_u20_are_semantic_requirements() -> Result<()> {
    let i = input()?;
    let raw = fixture("native")?;
    let snapshot = fixture("snapshot")?;
    assert_eq!(batches::native(&raw, &snapshot, &i.native)?.len(), 15);
    for (p, v) in [
        ("/candidate/state_schema", json!(7)),
        ("/candidate/sha256", json!(BASELINE)),
        ("/candidate/path", json!("target/wrong/mtm")),
        ("/baseline/state_schema", json!(8)),
        ("/baseline/sha256", json!(CANDIDATE)),
        ("/profiles_passed/5", json!("protocol")),
        ("/implementation_commit", json!(OBS_COMMIT)),
        ("/source_sha256", json!(OBS_SOURCE)),
        ("/report_seals/6/sha256", json!("a".repeat(64))),
        (
            "/report_seals/0/sha256",
            snapshot["report_seals"][1]["sha256"].clone(),
        ),
        ("/release_qualified", json!(true)),
    ] {
        assert!(
            batches::native(&raw, &set(&snapshot, p, v)?, &i.native).is_err(),
            "{p}"
        );
    }
    let legacy = json!([
        "hard_isolation",
        "private_vault_hidden",
        "children_reaped",
        "clean_shutdown",
        "safe_denial",
        "exact_grant_binding",
        "once_consumed",
        "safe_network_isolated",
        "safe_granted_network",
        "trusted_network",
        "dangerous_network"
    ]);
    let mut bad = raw.clone();
    bad["summaries"]["corpus_native"]["rows"][12]["checks"] = legacy;
    // Generic historical validator still accepts a legacy row; this current-candidate adapter must not.
    assert!(qualify::validate_receipt(&bad, CANDIDATE, BASELINE, "corpus_native").is_ok());
    assert!(batches::native(&bad, &snapshot, &i.native).is_err());
    let mut mixed = raw.clone();
    mixed["summaries"]["corpus_native"]["rows"][12]["checks"]
        .as_array_mut()
        .ok_or("checks")?
        .push(json!("safe_denial"));
    assert!(batches::native(&mixed, &snapshot, &i.native).is_err());
    for (p, v) in [
        ("/harness_source_identity/before_sha256", json!(OBS_SOURCE)),
        (
            "/summaries/corpus_native/rows/1/trial_id",
            raw["summaries"]["corpus_native"]["rows"][0]["trial_id"].clone(),
        ),
        ("/runner/exit_code", json!(1)),
        ("/native_preflight/ready_for_native_tests", json!(false)),
    ] {
        assert!(
            batches::native(&set(&raw, p, v)?, &snapshot, &i.native).is_err(),
            "{p}"
        );
    }
    Ok(())
}
#[test]
fn u30_requires_three_actual_distinct_fresh_observations_but_allows_same_command_bytes()
-> Result<()> {
    let i = input()?;
    let w = fixture("u30_wrapper")?;
    let review = fixture("u30_review")?;
    let raw = raws(&i)?;
    assert_eq!(
        w["trials"][0]["command"]["sha256"],
        w["trials"][1]["command"]["sha256"]
    );
    assert_eq!(batches::u30(&w, &review, &raw, &i.u30)?.len(), 3);
    for (p, v) in [
        ("/physical_power_loss_tested", json!(true)),
        ("/accepted_delta", json!(3)),
        ("/trials/0/fresh_test_tempdir", json!(false)),
        ("/trials/0/fresh_qualifier_snapshot", json!(false)),
        ("/trials/0/ctm_terminal/exit_code", json!(1)),
        ("/trials/0/candidate_source_commit", json!(OBS_COMMIT)),
        (
            "/trials/1/observation_id",
            w["trials"][0]["observation_id"].clone(),
        ),
        (
            "/trials/1/ctm_terminal/command_id",
            w["trials"][0]["ctm_terminal"]["command_id"].clone(),
        ),
        (
            "/trials/1/unique_tmpdir",
            w["trials"][0]["unique_tmpdir"].clone(),
        ),
        ("/trials/0/raw_report/sha256", json!("a".repeat(64))),
        (
            "/trials/0/recorded_unix_seconds",
            w["trials"][1]["recorded_unix_seconds"].clone(),
        ),
        ("/trials/0/started_at", json!("2099-01-01T00:00:00Z")),
        ("/trials/0/started_at", json!("2026-09-30T99:00:00Z")),
        ("/trials/0/finished_at", json!("2026-09-30T08:49:22Z")),
    ] {
        assert!(
            batches::u30(&set(&w, p, v)?, &review, &raw, &i.u30).is_err(),
            "{p}"
        );
    }
    let mut bad = raw.clone();
    bad[1] = bad[0].clone();
    let mut empty_maps = w.clone();
    empty_maps["trials"][0]["input_sha256_before"] = json!({});
    empty_maps["trials"][0]["input_sha256_after"] = json!({});
    assert!(batches::u30(&empty_maps, &review, &raw, &i.u30).is_err());
    let mut wrong_map = w.clone();
    wrong_map["trials"][0]["input_sha256_before"][DRIVER.0] = json!("a".repeat(64));
    wrong_map["trials"][0]["input_sha256_after"] =
        wrong_map["trials"][0]["input_sha256_before"].clone();
    assert!(batches::u30(&wrong_map, &review, &raw, &i.u30).is_err());
    assert!(batches::u30(&w, &review, &bad, &i.u30).is_err());
    let mut bad = raw.clone();
    bad[0].2["summaries"]["install_sigkill"]["kill_signal"] = json!(15);
    assert!(batches::u30(&w, &review, &bad, &i.u30).is_err());
    let mut badreview = review;
    badreview["reviewer_session"] = badreview["recorded_by"].clone();
    assert!(batches::u30(&w, &badreview, &raw, &i.u30).is_err());
    Ok(())
}
#[test]
fn review_binds_exact_inputs_source_binary_and_zero_delta() -> Result<()> {
    let i = input()?;
    let good = json!({"schema":"mtm017-partial-corpus-input-review-v1","milestone":"MTM-017",
  "inputs_sha256":"a".repeat(64),"implementation_source_sha256":"b".repeat(64),"maintenance_binary_sha256":"c".repeat(64),
  "prepared_by":"synthetic-preparer","reviewer_session":"independent-reviewer","decision":"approved_for_read_only_proposal",
  "checks":REVIEW_CHECKS,"recorded_unix_seconds":1,"accepted_delta":0,"production_selector_changed":false,
  "production_state_modified":false,"release_qualified":false,"deployment_authorized":false});
    let check = |v: &Value| {
        review_shape(
            &parsed(v)?,
            &i,
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
        )
    };
    check(&good)?;
    for (p, v) in [
        ("/inputs_sha256", json!("d".repeat(64))),
        ("/implementation_source_sha256", json!("d".repeat(64))),
        ("/maintenance_binary_sha256", json!("d".repeat(64))),
        ("/reviewer_session", json!("synthetic-preparer")),
        ("/decision", json!("approved_for_deployment")),
        ("/accepted_delta", json!(63)),
        ("/checks", json!([])),
        ("/release_qualified", json!(true)),
        ("/deployment_authorized", json!(true)),
    ] {
        assert!(check(&set(&good, p, v)?).is_err(), "{p}");
    }
    Ok(())
}
#[test]
fn derived_coverage_is_seventy_eight_and_twelve_pending_without_recounting_research() -> Result<()>
{
    let mut rows = BTreeMap::new();
    let r = Reference {
        path: "synthetic".into(),
        sha256: "a".repeat(64),
    };
    for task in (1..=25).chain(std::iter::once(30)) {
        for repeat in 1..=3 {
            let existing = (21..=25).contains(&task);
            add(
                &mut rows,
                &format!("U{task:02}"),
                repeat,
                if existing { "research" } else { "fixture" },
                if existing {
                    "previously_accepted"
                } else {
                    "observed_pass"
                },
                &r,
                None,
            )?;
        }
    }
    let rows = finish_rows(rows)?;
    assert_eq!(
        rows.iter()
            .filter(|v| v.status == "previously_accepted")
            .count(),
        15
    );
    assert_eq!(
        rows.iter().filter(|v| v.status == "observed_pass").count(),
        63
    );
    assert_eq!(rows.iter().filter(|v| v.status == "pending").count(), 12);
    let mut bad = BTreeMap::new();
    add(&mut bad, "U26", 1, "fixture", "observed_pass", &r, None)?;
    assert!(finish_rows(bad).is_err());
    let mut empty = BTreeMap::new();
    add(&mut empty, "U01", 1, "fixture", "observed_pass", &r, None)?;
    assert!(add(&mut empty, "U01", 1, "fixture", "observed_pass", &r, None).is_err());
    Ok(())
}
#[test]
fn inventory_rejects_links_escape_unknown_namespace_drift_and_oversize() -> Result<()> {
    let root = tempdir()?;
    let p = root.path().join(PREFIX);
    fs::create_dir_all(&p)?;
    let file = p.join("fixture.json");
    fs::write(&file, b"{}")?;
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644))?;
    let r = Reference {
        path: format!("{PREFIX}fixture.json"),
        sha256: digest(b"{}"),
    };
    let mut inv = Inventory::new(root.path());
    inv.json(&r)?;
    fs::write(&file, b"[]")?;
    assert!(inv.recheck().is_err());
    for path in [
        "/etc/passwd",
        "records/evidence/MTM-017/../fixture.json",
        "records/evidence/MTM-016/fixture.json",
    ] {
        let mut v = Inventory::new(root.path());
        assert!(
            v.load(&Reference {
                path: path.into(),
                sha256: digest(b"{}")
            })
            .is_err()
        );
    }
    fs::remove_file(&file)?;
    let target = p.join("target.json");
    fs::write(&target, b"{}")?;
    symlink(&target, &file)?;
    assert!(Inventory::new(root.path()).json(&r).is_err());
    fs::remove_file(&file)?;
    fs::hard_link(&target, &file)?;
    assert!(Inventory::new(root.path()).json(&r).is_err());
    fs::remove_file(&file)?;
    fs::remove_file(&target)?;
    fs::write(&file, b"{}")?;
    fs::set_permissions(&file, fs::Permissions::from_mode(0o666))?;
    assert!(Inventory::new(root.path()).json(&r).is_err());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644))?;
    fs::write(&file, vec![b' '; 1048577])?;
    assert!(Inventory::new(root.path()).json(&r).is_err());
    Ok(())
}
#[test]
fn original_research_anchor_and_descendant_seals_cannot_drift() -> Result<()> {
    let root = tempdir()?;
    let path = root.path().join(RESEARCH.0);
    fs::create_dir_all(path.parent().ok_or("parent")?)?;
    fs::write(&path, b"{}")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    assert!(release_readiness_schema8::verified_research_subset(root.path()).is_err());
    let original = include_bytes!("../../../records/governance/mtm017-research-corpus.json");
    fs::write(&path, original)?;
    let child = root
        .path()
        .join("records/evidence/MTM-017/research-corpus-subset-accepted-20260930.json");
    fs::create_dir_all(child.parent().ok_or("parent")?)?;
    fs::write(&child, b"{}")?;
    fs::set_permissions(&child, fs::Permissions::from_mode(0o644))?;
    assert!(release_readiness_schema8::verified_research_subset(root.path()).is_err());
    Ok(())
}
#[test]
fn cli_has_no_accept_release_record_or_arbitrary_corpus_modes() {
    let good = [
        "--inputs",
        "records/evidence/MTM-017/input.json",
        "--input-review",
        "records/evidence/MTM-017/review.json",
    ]
    .map(str::to_owned);
    assert!(Options::parse(&good).is_ok());
    assert!(Options::parse(&good[..2]).is_err());
    for extra in ["--record", "--accept", "--release", "--base"] {
        let mut v = good.to_vec();
        v.push(extra.into());
        assert!(Options::parse(&v).is_err());
    }
}
