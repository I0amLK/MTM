//! An install pass is not a target, browser or production-data qualification.
use super::*;

const CHECKS: [&str; 15] = [
    "baseline_created_old_run",
    "snapshot_copy_verified",
    "self_install_exact",
    "both_selectors_agree",
    "repeat_install_preserves_manifest",
    "installed_endpoint_identity",
    "old_run_advances_after_upgrade",
    "new_run_advances_after_upgrade",
    "same_key_restart",
    "baseline_selectors_restored",
    "snapshot_restored_before_old_launch",
    "old_runtime_advances_restored_run",
    "snapshot_immutable",
    "artifacts_unchanged",
    "clean_shutdown",
];

const SCHEMA8_CHECKS: [&str; 6] = [
    "legacy_verified_revision_preserved",
    "no_fact_backfill",
    "completed_receipt_replayed_without_writes",
    "new_verified_fact_promoted",
    "schema8_tables_removed_by_restore",
    "legacy_proof_bytes_preserved",
];

const SCHEMA7_BASELINE: &str = "f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034";

#[derive(Clone, Copy)]
enum Transition {
    Legacy,
    Schema8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Upgrade {
    ok: bool,
    candidate_sha256: String,
    baseline_sha256: String,
    candidate_version: String,
    baseline_version: String,
    baseline_schema: u64,
    candidate_schema: u64,
    restored_schema: u64,
    snapshot_sha256: String,
    restored_snapshot_sha256: String,
    snapshot_entries: u64,
    snapshot_bytes: u64,
    private_modes_prepared: bool,
    prepared_mode_entries: u64,
    legacy_shared_write_entries: u64,
    checks: BTreeMap<String, bool>,
    fixture_state_only: bool,
    installed_endpoint_tested: bool,
    selectors_tested: u64,
    native_backend: String,
    latex_policy: String,
    native_execution_tested: bool,
    compiled_latex_tested: bool,
    web_client_tested: bool,
    production_state_modified: bool,
    production_selectors_changed: bool,
    release_qualified: bool,
}

pub(super) fn validate(stdout: &[u8], candidate: &str, baseline: &str) -> Result<Value> {
    validate_transition(stdout, candidate, baseline, Transition::Legacy)
}

pub(super) fn validate_schema8(stdout: &[u8], candidate: &str, baseline: &str) -> Result<Value> {
    validate_transition(stdout, candidate, baseline, Transition::Schema8)
}

fn validate_transition(
    stdout: &[u8],
    candidate: &str,
    baseline: &str,
    transition: Transition,
) -> Result<Value> {
    let (marker, key, old_version, new_version, old_schema, new_schema, checks) = match transition {
        Transition::Legacy => (
            "MTM_UPGRADE_RUNTIME ",
            "upgrade",
            "0.5.0-preview.2",
            "0.6.0-preview.1",
            2,
            7,
            CHECKS.to_vec(),
        ),
        Transition::Schema8 => (
            "MTM_SCHEMA8_UPGRADE_RUNTIME ",
            "upgrade_schema8",
            "0.6.0-preview.1",
            "0.6.0-preview.2",
            7,
            8,
            CHECKS.into_iter().chain(SCHEMA8_CHECKS).collect(),
        ),
    };
    let foreign = match transition {
        Transition::Legacy => "MTM_SCHEMA8_UPGRADE_RUNTIME ",
        Transition::Schema8 => "MTM_UPGRADE_RUNTIME ",
    };
    if std::str::from_utf8(stdout)?.contains("MTM_TARGET_RUNTIME ")
        || std::str::from_utf8(stdout)?.contains("MTM_USABILITY_CORPUS ")
        || std::str::from_utf8(stdout)?.contains("MTM_RESOURCE_RUNTIME ")
        || std::str::from_utf8(stdout)?.contains("MTM_PERMISSION_RUNTIME ")
        || std::str::from_utf8(stdout)?.contains("MTM_RETRIEVAL_RUNTIME ")
        || std::str::from_utf8(stdout)?.contains(foreign)
    {
        return Err("upgrade output contains a foreign qualification profile".into());
    }
    let report: Upgrade = extract(stdout, marker)?;
    if !valid_hash(candidate)
        || !valid_hash(baseline)
        || candidate == baseline
        || report.candidate_sha256 != candidate
        || report.baseline_sha256 != baseline
        || !report.ok
        || (matches!(transition, Transition::Schema8) && baseline != SCHEMA7_BASELINE)
        || report.baseline_version != old_version
        || report.candidate_version != new_version
        || report.baseline_schema != old_schema
        || report.candidate_schema != new_schema
        || report.restored_schema != report.baseline_schema
        || !valid_hash(&report.snapshot_sha256)
        || report.restored_snapshot_sha256 != report.snapshot_sha256
        || !(2..=4096).contains(&report.snapshot_entries)
        || !(1..=64 * 1024 * 1024).contains(&report.snapshot_bytes)
        || !report.private_modes_prepared
        || report.prepared_mode_entries > report.snapshot_entries
        || report.legacy_shared_write_entries > report.prepared_mode_entries
        || report.checks.len() != checks.len()
        || !checks
            .iter()
            .all(|key| report.checks.get(*key) == Some(&true))
        || !report.fixture_state_only
        || !report.installed_endpoint_tested
        || report.selectors_tested != 2
        || report.native_backend != "disabled"
        || report.latex_policy != "static_only"
        || report.native_execution_tested
        || report.compiled_latex_tested
        || report.web_client_tested
        || report.production_state_modified
        || report.production_selectors_changed
        || report.release_qualified
    {
        return Err(
            "upgrade summary has inconsistent artifact, snapshot, coverage or scope".into(),
        );
    }
    Ok(json!({key:extract::<Value>(stdout, marker)?}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema8_requires_its_own_transition_all_checks_and_exact_baseline() -> Result<()> {
        let mut good = fixture();
        good["baseline_sha256"] = json!(SCHEMA7_BASELINE);
        good["baseline_version"] = json!("0.6.0-preview.1");
        good["candidate_version"] = json!("0.6.0-preview.2");
        good["baseline_schema"] = json!(7);
        good["candidate_schema"] = json!(8);
        good["restored_schema"] = json!(7);
        for key in SCHEMA8_CHECKS {
            good["checks"][key] = json!(true);
        }
        let encode = |value: &Value| format!("MTM_SCHEMA8_UPGRADE_RUNTIME {value}\n").into_bytes();
        validate_schema8(&encode(&good), &"a".repeat(64), SCHEMA7_BASELINE)?;
        assert!(validate(&encode(&good), &"a".repeat(64), SCHEMA7_BASELINE).is_err());
        assert!(validate_schema8(&output(&fixture()), &"a".repeat(64), SCHEMA7_BASELINE).is_err());
        for key in CHECKS.into_iter().chain(SCHEMA8_CHECKS) {
            for value in [json!(false), json!(1), Value::Null] {
                let mut bad = good.clone();
                bad["checks"][key] = value;
                assert!(
                    validate_schema8(&encode(&bad), &"a".repeat(64), SCHEMA7_BASELINE).is_err()
                );
            }
        }
        for (key, value) in [
            ("candidate_schema", json!(7)),
            ("candidate_schema", json!(8.0)),
            ("baseline_schema", json!(2)),
            ("restored_schema", json!(8)),
            ("candidate_version", json!("0.6.0-preview.1")),
            ("baseline_version", json!("0.5.0-preview.2")),
            ("snapshot_entries", json!(4097)),
            ("snapshot_bytes", json!(67_108_865)),
            ("restored_snapshot_sha256", json!("d".repeat(64))),
            ("fixture_state_only", json!(false)),
            ("production_state_modified", json!(true)),
            ("production_selectors_changed", json!(true)),
            ("release_qualified", json!(true)),
            ("web_client_tested", json!(true)),
            ("unknown_override", json!(true)),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(validate_schema8(&encode(&bad), &"a".repeat(64), SCHEMA7_BASELINE).is_err());
        }
        for key in good.as_object().ok_or("fixture object")?.keys() {
            let mut bad = good.clone();
            bad.as_object_mut().ok_or("fixture object")?.remove(key);
            assert!(validate_schema8(&encode(&bad), &"a".repeat(64), SCHEMA7_BASELINE).is_err());
        }
        let bytes = encode(&good);
        assert!(
            validate_schema8(
                &[bytes.clone(), bytes].concat(),
                &"a".repeat(64),
                SCHEMA7_BASELINE
            )
            .is_err()
        );
        assert!(validate_schema8(&encode(&good), &"a".repeat(64), &"b".repeat(64)).is_err());
        Ok(())
    }

    fn fixture() -> Value {
        json!({
            "ok":true,"candidate_sha256":"a".repeat(64),"baseline_sha256":"b".repeat(64),
            "candidate_version":"0.6.0-preview.1","baseline_version":"0.5.0-preview.2",
            "baseline_schema":2,"candidate_schema":7,"restored_schema":2,
            "snapshot_sha256":"c".repeat(64),"restored_snapshot_sha256":"c".repeat(64),
            "snapshot_entries":12,"snapshot_bytes":4096,
            "private_modes_prepared":true,"prepared_mode_entries":4,"legacy_shared_write_entries":2,
            "checks":CHECKS.into_iter().map(|key| (key,true)).collect::<BTreeMap<_,_>>(),
            "fixture_state_only":true,"installed_endpoint_tested":true,"selectors_tested":2,
            "native_backend":"disabled","latex_policy":"static_only",
            "native_execution_tested":false,"compiled_latex_tested":false,"web_client_tested":false,
            "production_state_modified":false,"production_selectors_changed":false,"release_qualified":false
        })
    }

    fn output(value: &Value) -> Vec<u8> {
        format!("MTM_UPGRADE_RUNTIME {value}\n").into_bytes()
    }

    #[test]
    fn upgrade_requires_every_check_and_strict_field_types() -> Result<()> {
        let good = fixture();
        validate(&output(&good), &"a".repeat(64), &"b".repeat(64))?;
        for key in CHECKS {
            for value in [json!(false), json!(1), Value::Null] {
                let mut changed = good.clone();
                changed["checks"][key] = value;
                assert!(validate(&output(&changed), &"a".repeat(64), &"b".repeat(64)).is_err());
            }
        }
        for key in good.as_object().ok_or("fixture object")?.keys() {
            let mut changed = good.clone();
            changed.as_object_mut().ok_or("fixture object")?.remove(key);
            assert!(validate(&output(&changed), &"a".repeat(64), &"b".repeat(64)).is_err());
        }
        Ok(())
    }

    #[test]
    fn upgrade_rejects_scope_widening_drift_counts_and_duplicate_reports() {
        let good = fixture();
        for (key, value) in [
            ("candidate_sha256", json!("d".repeat(64))),
            ("baseline_sha256", json!("a".repeat(64))),
            ("candidate_schema", json!(7.0)),
            ("restored_schema", json!(7)),
            ("candidate_version", json!("0.5.0-preview.2")),
            ("snapshot_entries", json!(4097)),
            ("snapshot_bytes", json!(67_108_865)),
            ("snapshot_sha256", json!("not-a-hash")),
            ("restored_snapshot_sha256", json!("d".repeat(64))),
            ("selectors_tested", json!(0)),
            ("private_modes_prepared", json!(false)),
            ("prepared_mode_entries", json!(4097)),
            ("legacy_shared_write_entries", json!(12)),
            ("fixture_state_only", json!(false)),
            ("native_execution_tested", json!(true)),
            ("compiled_latex_tested", json!(true)),
            ("web_client_tested", json!(true)),
            ("production_state_modified", json!(true)),
            ("production_selectors_changed", json!(true)),
            ("release_qualified", json!(true)),
            ("unknown_override", json!(true)),
        ] {
            let mut changed = good.clone();
            changed[key] = value;
            assert!(validate(&output(&changed), &"a".repeat(64), &"b".repeat(64)).is_err());
        }
        assert!(validate(&[], &"a".repeat(64), &"b".repeat(64)).is_err());
        assert!(
            validate(
                &[output(&good), b"MTM_TARGET_RUNTIME {}\n".to_vec()].concat(),
                &"a".repeat(64),
                &"b".repeat(64)
            )
            .is_err()
        );
        assert!(
            validate(
                &[output(&good), output(&good)].concat(),
                &"a".repeat(64),
                &"b".repeat(64)
            )
            .is_err()
        );
        assert!(validate(&output(&good), &"a".repeat(64), &"a".repeat(64)).is_err());
    }
}
