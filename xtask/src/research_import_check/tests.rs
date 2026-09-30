//! Synthetic parser/security tests are never corpus evidence.
use super::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use tempfile::tempdir;

#[test]
fn frozen_json_driver_0664_is_data_and_keeps_exact_mode_and_hash() -> Result<()> {
    let root = tempdir()?;
    let path = root.path().join(DRIVER);
    fs::create_dir_all(path.parent().ok_or("fixture parent")?)?;
    fs::write(&path, b"{\"schema\":\"synthetic-not-release-evidence\"}\n")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o664))?;
    let before = fs::metadata(&path)?.permissions().mode();
    let expected = digest(&fs::read(&path)?);
    assert_eq!(frozen_driver_digest(root.path())?, expected);
    assert_eq!(fs::metadata(&path)?.permissions().mode(), before);
    assert!(qualify::digest(&path).is_err());
    fs::write(&path, b"changed")?;
    assert_ne!(frozen_driver_digest(root.path())?, expected);
    assert_ne!(frozen_driver_digest(root.path())?, DRIVER_SHA);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666))?;
    assert!(frozen_driver_digest(root.path()).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o775))?;
    assert!(frozen_driver_digest(root.path()).is_err());
    fs::remove_file(&path)?;
    fs::write(root.path().join("target.json"), b"{}")?;
    symlink(root.path().join("target.json"), &path)?;
    assert!(frozen_driver_digest(root.path()).is_err());
    Ok(())
}

#[test]
fn driver_mode_exception_does_not_apply_to_any_evidence_or_private_input() -> Result<()> {
    let root = tempdir()?;
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
    let path = root.path().join("catalog.json");
    fs::write(&path, b"{}")?;
    for mode in [0o660, 0o664] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
        assert!(
            files::Directory::open(root.path(), false)?
                .read("catalog.json", 1024)
                .is_err()
        );
        assert!(
            files::Directory::open(root.path(), true)?
                .read("catalog.json", 1024)
                .is_err()
        );
        assert!(files::catalog(&path).is_err());
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    assert_eq!(files::catalog(&path)?, b"{}");
    Ok(())
}

fn trial_value(task: &str, repeat: u64) -> Result<Value> {
    Ok(
        json!({"schema":research_precheck::research_policy_for("MTM-017", task)?.trial_schema,
        "milestone":"MTM-017","task_id":task,"scenario":scenario(task)?,"repeat":repeat,
        "case_id":expected_case(task,repeat)?,"trial_id":"1".repeat(32),
        "candidate_sha256":research_precheck::MTM017_CANDIDATE_SHA,
        "candidate_source_commit":research_precheck::MTM017_CANDIDATE_SOURCE,
        "corpus_sha256":research_precheck::CORPUS_SHA,"case_registry_sha256":research_precheck::REGISTRY_SHA,
        "bundle_sha256":"2".repeat(64),"final_tex_sha256":"3".repeat(64),
        "verification_report_sha256":"4".repeat(64),"review_observation_sha256":"5".repeat(64),
        "owner_fingerprint":"6".repeat(64),"generator_session":"synthetic-generator",
        "reviewer_session":"synthetic-reviewer","required_latex_passed":true,"final_artifact_sealed":true,
        "same_live_connection_observed":true,"independent_review_observed":true,"reviewer_statement_checks":1,
        "route_checks":route(task)?,"precheck_passed":true,"mathematical_review_passed":true,
        "raw_private_state_recorded":false,"production_changed":false,"release_qualified":false,
        "recorded_unix_seconds":1}),
    )
}
fn input_value() -> Value {
    let mut trials = Vec::new();
    for task in 21..=25 {
        for repeat in 1..=3 {
            trials.push(json!({"task_id":format!("U{task}"),"repeat":repeat,
            "receipt":{"path":format!("records/evidence/MTM-017/u{task}-r{repeat}.json"),
                "sha256":format!("{:064x}",task*10+repeat)}}));
        }
    }
    json!({"schema":"mtm017-research-import-inputs-v1","milestone":"MTM-017","state_schema_version":8,
        "candidate_sha256":research_precheck::MTM017_CANDIDATE_SHA,
        "candidate_source_commit":research_precheck::MTM017_CANDIDATE_SOURCE,
        "corpus_sha256":research_precheck::CORPUS_SHA,"case_registry_sha256":research_precheck::REGISTRY_SHA,
        "prepared_by":"synthetic-preparer","bundle_catalog_sha256":"a".repeat(64),
        "audit":{"path":"records/evidence/MTM-017/audit.json","sha256":"b".repeat(64)},
        "prechecks":{"path":"records/evidence/MTM-017/prechecks.json","sha256":"c".repeat(64)},
        "trials":trials,"corpus_count_incremented":false,"production_selector_changed":false,
        "production_state_modified":false,"release_qualified":false})
}
fn from_value<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T> {
    decode(&serde_json::to_vec(value)?)
}

#[test]
fn every_trial_identity_flag_route_and_schema_is_fail_closed() -> Result<()> {
    for task in ["U21", "U22", "U23", "U24", "U25"] {
        let good = trial_value(task, 1)?;
        trial_shape(&from_value(&good)?, task, 1)?;
        for (key, bad) in [
            ("schema", json!("unsupported")),
            ("milestone", json!("MTM-016")),
            ("task_id", json!("U26")),
            ("scenario", json!("wrong")),
            ("repeat", json!(0)),
            ("case_id", json!("wrong-case")),
            ("trial_id", json!("bad")),
            ("candidate_sha256", json!("a".repeat(64))),
            ("candidate_source_commit", json!("a".repeat(40))),
            ("corpus_sha256", json!("a".repeat(64))),
            ("case_registry_sha256", json!("a".repeat(64))),
            ("bundle_sha256", json!("bad")),
            ("final_tex_sha256", json!("bad")),
            ("verification_report_sha256", json!("bad")),
            ("review_observation_sha256", json!("bad")),
            ("owner_fingerprint", json!("bad")),
            ("generator_session", json!("synthetic-reviewer")),
            ("reviewer_session", json!("synthetic-generator")),
            ("reviewer_statement_checks", json!(0)),
            ("reviewer_statement_checks", json!(257)),
            ("route_checks", json!([])),
            ("required_latex_passed", json!(false)),
            ("final_artifact_sealed", json!(false)),
            ("same_live_connection_observed", json!(false)),
            ("independent_review_observed", json!(false)),
            ("precheck_passed", json!(false)),
            ("mathematical_review_passed", json!(false)),
            ("raw_private_state_recorded", json!(true)),
            ("production_changed", json!(true)),
            ("release_qualified", json!(true)),
            ("recorded_unix_seconds", json!(0)),
        ] {
            let mut value = good.clone();
            value[key] = bad;
            assert!(
                trial_shape(&from_value(&value)?, task, 1).is_err(),
                "{task}/{key}"
            );
        }
    }
    let mut legacy = trial_value("U25", 1)?;
    legacy["schema"] = json!("mtm-research-trial-evidence-v1");
    assert!(trial_shape(&from_value(&legacy)?, "U25", 1).is_err());
    legacy = trial_value("U25", 1)?;
    legacy["route_checks"][7] = json!("safe_mode_permission_observed");
    assert!(trial_shape(&from_value(&legacy)?, "U25", 1).is_err());
    Ok(())
}

#[test]
fn exact_fifteen_cells_and_input_identity_are_required() -> Result<()> {
    let good = input_value();
    inputs_shape(&from_value(&good)?)?;
    for (pointer, bad) in [
        ("/schema", json!("mtm-research-corpus-batch-v2")),
        ("/milestone", json!("MTM-016")),
        ("/state_schema_version", json!(7)),
        ("/candidate_sha256", json!("a".repeat(64))),
        ("/candidate_source_commit", json!("a".repeat(40))),
        ("/corpus_sha256", json!("a".repeat(64))),
        ("/case_registry_sha256", json!("a".repeat(64))),
        ("/prepared_by", json!("")),
        ("/bundle_catalog_sha256", json!("bad")),
        ("/corpus_count_incremented", json!(true)),
        ("/production_selector_changed", json!(true)),
        ("/production_state_modified", json!(true)),
        ("/release_qualified", json!(true)),
        ("/trials/1/repeat", json!(1)),
        ("/trials/0/task_id", json!("U26")),
        (
            "/trials/1/receipt/path",
            good["trials"][0]["receipt"]["path"].clone(),
        ),
        (
            "/trials/1/receipt/sha256",
            good["trials"][0]["receipt"]["sha256"].clone(),
        ),
    ] {
        let mut value = good.clone();
        *value.pointer_mut(pointer).ok_or("fixture pointer")? = bad;
        assert!(inputs_shape(&from_value(&value)?).is_err(), "{pointer}");
    }
    let mut missing = good;
    missing["trials"]
        .as_array_mut()
        .ok_or("fixture array")?
        .pop();
    assert!(inputs_shape(&from_value(&missing)?).is_err());
    Ok(())
}

#[test]
fn input_review_binds_exact_bytes_implementation_and_separate_reviewer() -> Result<()> {
    let input: Inputs = from_value(&input_value())?;
    let good = json!({"schema":"mtm017-research-import-input-review-v1","milestone":"MTM-017",
        "inputs_sha256":"d".repeat(64),"bundle_catalog_sha256":"a".repeat(64),
        "implementation_source_sha256":"e".repeat(64),"maintenance_binary_sha256":"f".repeat(64),
        "prepared_by":"synthetic-preparer","reviewer_session":"synthetic-separate-reviewer",
        "decision":"approved_for_read_only_proposal","checks":REVIEW_CHECKS,"recorded_unix_seconds":2,
        "corpus_count_incremented":false,"production_selector_changed":false,
        "production_state_modified":false,"release_qualified":false});
    let validate = |v: &Value| -> Result<()> {
        review_shape(
            &from_value(v)?,
            &input,
            &"d".repeat(64),
            &"e".repeat(64),
            &"f".repeat(64),
        )
    };
    validate(&good)?;
    for (key, bad) in [
        ("inputs_sha256", json!("0".repeat(64))),
        ("bundle_catalog_sha256", json!("0".repeat(64))),
        ("implementation_source_sha256", json!("0".repeat(64))),
        ("maintenance_binary_sha256", json!("0".repeat(64))),
        ("reviewer_session", json!("synthetic-preparer")),
        ("prepared_by", json!("someone-else")),
        ("decision", json!("approved")),
        ("decision", json!("release_approved")),
        ("checks", json!([])),
        ("recorded_unix_seconds", json!(0)),
        ("corpus_count_incremented", json!(true)),
        ("production_selector_changed", json!(true)),
        ("production_state_modified", json!(true)),
        ("release_qualified", json!(true)),
    ] {
        let mut value = good.clone();
        value[key] = bad;
        assert!(validate(&value).is_err(), "{key}");
    }
    Ok(())
}

#[test]
fn exact_bundle_and_review_cross_binding_rejects_hash_or_identity_drift() -> Result<()> {
    let trial: Trial = from_value(&trial_value("U21", 1)?)?;
    let report = json!({"milestone":"MTM-017","task_id":"U21","repeat":1,"case_id":trial.case_id,
        "bundle_sha256":trial.bundle_sha256,"required_material_present":true,"existing_material_consistent":true,
        "accepted_trials_delta":0,"research_trial_passed":false,"production_state_modified":false,
        "release_qualified":false,"artifacts":[
            {"artifact":"final.tex","sha256":trial.final_tex_sha256},
            {"artifact":"reviewed.tex","sha256":trial.final_tex_sha256},
            {"artifact":"verification_report.json","sha256":trial.verification_report_sha256},
            {"artifact":"review.json","sha256":trial.review_observation_sha256}]});
    let bundle = json!({"trial_id":trial.trial_id});
    let session = json!({"trial_id":trial.trial_id,"task_id":"U21","repeat":1,"case_id":trial.case_id,
        "milestone":"MTM-017","native_mode":"dangerous","schema":"mtm-research-session-v2"});
    let review = json!({"trial_id":trial.trial_id,"generator_session":trial.generator_session,
        "reviewer_session":trial.reviewer_session,"generator_owner_fingerprint":trial.owner_fingerprint,
        "reviewer_owner_fingerprint":trial.owner_fingerprint,"reviewed_sha256":trial.final_tex_sha256,
        "verification_report_sha256":trial.verification_report_sha256,"reviewed_before_finalization":true,
        "statement_checks":[{"location":"synthetic","summary":"not real review"}]});
    cross_bind(&trial, &report, &bundle, &session, &review)?;
    for pointer in [
        "/bundle_sha256",
        "/artifacts/0/sha256",
        "/artifacts/1/sha256",
        "/artifacts/2/sha256",
        "/artifacts/3/sha256",
    ] {
        let mut bad = report.clone();
        *bad.pointer_mut(pointer).ok_or("fixture pointer")? = json!("0".repeat(64));
        assert!(cross_bind(&trial, &bad, &bundle, &session, &review).is_err());
    }
    for key in [
        "trial_id",
        "generator_session",
        "reviewer_session",
        "generator_owner_fingerprint",
        "reviewer_owner_fingerprint",
        "reviewed_sha256",
        "verification_report_sha256",
        "reviewed_before_finalization",
        "statement_checks",
    ] {
        let mut bad = review.clone();
        bad[key] = Value::Null;
        assert!(cross_bind(&trial, &report, &bundle, &session, &bad).is_err());
    }
    for (key, badval) in [
        ("native_mode", json!("safe")),
        ("schema", json!("mtm-research-session-v1")),
        ("milestone", json!("MTM-016")),
        ("repeat", json!(2)),
        ("case_id", json!("wrong")),
    ] {
        let mut bad = session.clone();
        bad[key] = badval;
        assert!(cross_bind(&trial, &report, &bundle, &bad, &review).is_err());
    }
    Ok(())
}

#[test]
fn duplicate_keys_unknown_fields_and_unbounded_json_are_rejected() -> Result<()> {
    assert!(decode::<Inputs>(br#"{"schema":"a","schema":"b"}"#).is_err());
    assert!(decode::<Catalog>(br#"{"trials":[{"repeat":1,"repeat":2}]}"#).is_err());
    assert!(decode::<Inputs>(&vec![b' '; 1048577]).is_err());
    let mut input = input_value();
    input["accepted_trials"] = json!(15);
    assert!(from_value::<Inputs>(&input).is_err());
    let mut trial = trial_value("U21", 1)?;
    trial["approval"] = json!(true);
    assert!(from_value::<Trial>(&trial).is_err());
    Ok(())
}

#[test]
fn safe_files_reject_escape_links_hardlinks_writable_and_oversize() -> Result<()> {
    let dir = tempdir()?;
    let parent = dir.path().join("records/evidence/MTM-017");
    fs::create_dir_all(&parent)?;
    let good = parent.join("receipt.json");
    fs::write(&good, b"{}")?;
    fs::set_permissions(&good, fs::Permissions::from_mode(0o600))?;
    let relative = "records/evidence/MTM-017/receipt.json";
    assert_eq!(files::repo(dir.path(), relative)?, b"{}");
    let reference = Reference {
        path: relative.into(),
        sha256: digest(b"{}"),
    };
    checked(dir.path(), &reference)?;
    fs::write(&good, b"[]")?;
    assert!(checked(dir.path(), &reference).is_err());
    for path in [
        "/tmp/receipt.json",
        "records/evidence/MTM-017/../receipt.json",
        "records/evidence/MTM-016/receipt.json",
        "records/evidence/MTM-017//receipt.json",
    ] {
        assert!(files::repo(dir.path(), path).is_err());
    }
    symlink(&good, parent.join("link.json"))?;
    assert!(files::repo(dir.path(), "records/evidence/MTM-017/link.json").is_err());
    fs::hard_link(&good, parent.join("hard.json"))?;
    assert!(files::repo(dir.path(), relative).is_err());
    fs::remove_file(parent.join("hard.json"))?;
    fs::set_permissions(&good, fs::Permissions::from_mode(0o666))?;
    assert!(files::repo(dir.path(), relative).is_err());
    fs::set_permissions(&good, fs::Permissions::from_mode(0o600))?;
    fs::write(&good, vec![b'x'; 1048577])?;
    assert!(files::repo(dir.path(), relative).is_err());
    let other = dir.path().join("linked");
    symlink(&parent, &other)?;
    assert!(files::Directory::open(&other, false).is_err());
    assert!(files::catalog(&good).is_err());
    Ok(())
}

#[test]
fn cli_has_no_record_accept_release_or_missing_review_mode() {
    let good = [
        "--inputs",
        "records/evidence/MTM-017/input.json",
        "--bundle-catalog",
        "/tmp/private/catalog.json",
        "--input-review",
        "records/evidence/MTM-017/review.json",
    ]
    .map(str::to_owned)
    .to_vec();
    assert!(Options::parse(&good).is_ok());
    for option in ["--record", "--accept", "--release"] {
        let mut bad = good.clone();
        bad.push(option.into());
        assert!(Options::parse(&bad).is_err());
    }
    assert!(Options::parse(&good[..4]).is_err());
}

#[test]
fn private_manifest_and_cross_descriptor_byte_drift_fail_closed() -> Result<()> {
    let trial: Trial = from_value(&trial_value("U21", 1)?)?;
    let root = tempdir()?;
    let bundle = root.path().join(format!(
        ".mtm-acceptance/MTM-017/research/U21-r1.Abcdef12/evidence-bundle.{}",
        trial.trial_id
    ));
    fs::create_dir_all(&bundle)?;
    fs::set_permissions(&bundle, fs::Permissions::from_mode(0o700))?;
    fs::write(bundle.join("bundle.json"), b"{}")?;
    fs::set_permissions(
        bundle.join("bundle.json"),
        fs::Permissions::from_mode(0o600),
    )?;
    assert_eq!(
        inspect(root.path(), &bundle, &trial)
            .err()
            .ok_or("expected manifest failure")?
            .to_string(),
        "private bundle manifest changed"
    );
    let report = json!({"artifacts":[{"artifact":"session.json","sha256":digest(b"session")},
        {"artifact":"review.json","sha256":digest(b"review")}]});
    observed_bytes(b"session", b"review", b"bundle", b"bundle", &report)?;
    assert!(observed_bytes(b"changed", b"review", b"bundle", b"bundle", &report).is_err());
    assert!(observed_bytes(b"session", b"changed", b"bundle", b"bundle", &report).is_err());
    assert!(observed_bytes(b"session", b"review", b"bundle", b"changed", &report).is_err());
    assert!(bundle_path(&root.path().join("unrelated"), &trial).is_err());
    Ok(())
}

#[test]
fn all_cross_trial_identity_dimensions_must_be_distinct() -> Result<()> {
    let good = trial_value("U21", 1)?;
    for key in [
        "case_id",
        "trial_id",
        "bundle_sha256",
        "final_tex_sha256",
        "verification_report_sha256",
        "review_observation_sha256",
        "recorded_unix_seconds",
    ] {
        let mut set = BTreeSet::new();
        let trial: Trial = from_value(&good)?;
        trial_uniqueness(&mut set, &trial)?;
        let mut second = trial_value("U22", 2)?;
        second["trial_id"] = json!("a".repeat(32));
        second["bundle_sha256"] = json!("b".repeat(64));
        second["final_tex_sha256"] = json!("c".repeat(64));
        second["verification_report_sha256"] = json!("d".repeat(64));
        second["review_observation_sha256"] = json!("e".repeat(64));
        second["recorded_unix_seconds"] = json!(2);
        second[key] = good[key].clone();
        assert!(
            trial_uniqueness(&mut set, &from_value(&second)?).is_err(),
            "{key}"
        );
    }
    Ok(())
}
