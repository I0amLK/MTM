//! Public genuine-copy evidence under the operator-approved two-stage semantics.
use super::*;

pub(super) fn validate(inv: &mut Inventory<'_>, i: &Inputs, ledger: &Value) -> Result<Value> {
    named(
        &i.operator_copy,
        "records/evidence/MTM-017/operator-copy-prepared-rehearsal-aggregate-20260930.json",
        "95190cfb08f3a5efc71d913a272ba8db2dd2779465e5c2b4c77ece09ae30731f",
    )?;
    named(
        &i.operator_copy_review,
        "records/evidence/MTM-017/operator-copy-prepared-rehearsal-review-20260930.json",
        "31e3129197014901f9824d6a48ac26b52b1db59aa4e158af9f98ceef06a8702c",
    )?;
    let a = inv.json(&i.operator_copy)?;
    let review = inv.json(&i.operator_copy_review)?;
    let auth = inv.linked(&a["operator_decision"])?;
    let clarification = inv.linked(&a["order_clarification"])?;
    policy::record_matches(ledger, &auth)?;
    policy::record_matches(ledger, &clarification)?;
    require(
        auth["decision_id"] == "MTM017-READINESS-DECISION-005"
            && auth["candidate_sha256"] == CANDIDATE
            && auth["compatible_schema7_baseline_sha256"] == BASELINE
            && auth["rollback_semantics"] == "exact_restore_then_prepared_continuation"
            && auth["exact_original_bytes_modes_database_restore_required"] == true
            && auth["baseline_private_mode_preparation_after_exact_restore_only"] == true
            && auth["same_existing_run_continuation_required"] == true
            && auth["original_modes_baseline_continuation"] == false
            && clarification["clarifies"] == a["operator_decision"],
        "operator copy approved contract binding mismatch",
    )?;
    let failed = inv.linked(
        &a["preserved_strict_failure"]
            .as_object()
            .map(|o| json!({"path":o.get("path"),"sha256":o.get("sha256")}))
            .ok_or("strict failure ref")?,
    )?;
    require(
        a["preserved_strict_failure"]["still_failed"] == true
            && a["preserved_strict_failure"]["counts_as_success"] == false
            && failed["validated_real_rehearsal_passed"] != true,
        "strict copy failure promoted",
    )?;
    let capture = inv.json(&Reference {
        path: "records/evidence/MTM-017/operator-state-capture-20260930.json".into(),
        sha256: "404e0205ed7fee18bfe3a15c5999d3be2082fb8dad69bc9b5cb8efc6e0917771".into(),
    })?;
    require(
        capture["source_authorized"] == true
            && capture["user_quiescence_attested"] == true
            && capture["capture_attempts"] == 1
            && capture["exit_code"] == 0
            && capture["proc_visibility_complete"] == false
            && capture["transactional_snapshot_claimed"] == false
            && capture["capture_receipt"]["two_source_streams_identical"] == true
            && capture["capture_receipt"]["synthetic_only"] == false
            && capture["capture_receipt"]["archive_sha256"] == a["archive_sha256"]
            && a["source_capture_attempts_total"] == 1
            && a["source_capture_repeated"] == false
            && a["successful_independent_real_repetitions"] == 3
            && a["synthetic_prerequisites_counted_as_real"] == false
            && a["rollback_validation_mode"] == "exact_restore_then_prepared_continuation"
            && a["original_modes_baseline_continuation"] == false
            && a["original_archive_unchanged"] == true
            && a["production_modified"] == false
            && a["selectors_modified"] == false
            && a["release_qualified"] == false,
        "operator capture or aggregate overstates evidence",
    )?;
    require(
        review["aggregate"] == serde_json::to_value(&i.operator_copy)?
            && review["passed"] == true
            && review["verified_distinct_real_repetitions"] == 3
            && review["distinct_commands_sessions_working_inodes_and_exact_proofs"] == true
            && review["rollback_validation_mode"] == "exact_restore_then_prepared_continuation"
            && review["unprepared_baseline_continuation_claimed"] == false
            && review["strict_failure_still_failed"] == true
            && review["operator_decision_sha256"] == a["operator_decision"]["sha256"]
            && review["order_clarification_sha256"] == a["order_clarification"]["sha256"]
            && review["release_qualified"] == false
            && review["deployment_authorized_by_this_review"] == false,
        "independent operator-copy review scope invalid",
    )?;
    let mut seen = BTreeSet::new();
    let mut repeats = BTreeSet::new();
    let mut windows = Vec::new();
    let mut rows = Vec::new();
    for row in array(&a["repetitions"])? {
        let repeat = row["repetition"].as_u64().ok_or("copy repeat missing")?;
        require(
            (1..=3).contains(&repeat)
                && repeats.insert(repeat)
                && row["passed"] == true
                && row["exit_code"] == 0,
            "operator copy repetitions duplicate or failed",
        )?;
        let seal = Reference {
            path: row["observation_path"]
                .as_str()
                .ok_or("copy observation path")?
                .into(),
            sha256: row["observation_sha256"]
                .as_str()
                .ok_or("copy observation hash")?
                .into(),
        };
        let obs = inv.json(&seal)?;
        let proof_seal = Reference {
            path: row["exact_restore_proof_path"]
                .as_str()
                .ok_or("restore proof path")?
                .into(),
            sha256: row["exact_restore_proof_sha256"]
                .as_str()
                .ok_or("restore proof hash")?
                .into(),
        };
        let proof = inv.json(&proof_seal)?;
        require(
            obs["repetition"] == repeat
                && obs["exit_code"] == 0
                && obs["validated_real_rehearsal_passed"] == true
                && obs["source_capture_repeated"] == false
                && obs["original_archive_unchanged"] == true
                && obs["original_archive_owner_readonly"] == true
                && obs["same_old_run_as_original_strict_attempt"] == true
                && obs["production_modified"] == false
                && obs["selectors_modified"] == false
                && obs["production_source_mounted"] == false
                && obs["release_qualified"] == false
                && obs["baseline_exact_restoration_proof"] == proof
                && obs["baseline_exact_restoration_proof_sha256"] == proof_seal.sha256
                && obs["command_id"] == row["command_id"]
                && obs["working_session_identity_sha256"] == row["working_session_identity_sha256"],
            "real copied-state observation binding invalid",
        )?;
        for key in [
            "command_id",
            "working_session_identity_sha256",
            "exact_restore_proof_sha256",
        ] {
            let value = row[key].as_str().ok_or("copy distinct identity missing")?;
            require(
                seen.insert((key.to_owned(), value.to_owned())),
                "copy repetitions not distinct",
            )?;
        }
        require(
            proof["schema"] == "mtm017-baseline-exact-restoration-v1"
                && proof["archive_sha256"] == a["archive_sha256"]
                && proof["restored_archive_sha256"] == a["archive_sha256"]
                && proof["bytes_and_modes_match"] == true
                && proof["before_baseline_mode_preparation"] == true
                && proof["prepared_modes_used_for_exact_check"] == false
                && proof["synthetic_only"] == false,
            "exact restoration was not checked before permission preparation",
        )?;
        let real = array(&obs["real_sanitized_receipts"])?;
        require(
            real.len() == 1,
            "real copy observation receipt cardinality invalid",
        )?;
        let v = &real[0];
        require(
            v["schema"] == "mtm017-schema8-copy-rehearsal-v2"
                && v["evidence_kind"] == "operator_copy_observation"
                && v["synthetic_only"] == false
                && v["candidate_sha256"] == CANDIDATE
                && v["baseline_sha256"] == BASELINE
                && v["archive_sha256"] == a["archive_sha256"]
                && v["run_id"] == a["run_id"]
                && v["schema_before"] == 7
                && v["schema_candidate"] == 8
                && v["schema_restored"] == 7
                && v["rollback_validation_mode"] == "exact_restore_then_prepared_continuation"
                && v["unprepared_baseline_continuation_claimed"] == false
                && v["operator_decision_sha256"] == a["operator_decision"]["sha256"]
                && v["production_modified"] == false
                && v["selectors_modified"] == false
                && v["production_source_mounted"] == false
                && v["release_qualified"] == false
                && v["mathematical_verification_claimed"] == false,
            "real U29 scope or schema mismatch",
        )?;
        for key in [
            "baseline_disposable_copy_mode_prepared",
            "baseline_mode_preparation_content_unchanged",
            "candidate_restart_resumed",
            "clean_shutdown",
            "exactly_one_transition_per_leg",
            "old_owner_authenticated",
            "old_run_advanced_on_candidate",
            "original_archive_unchanged",
            "original_bytes_modes_exact_before_baseline_preparation",
            "owner_and_client_sets_unchanged_on_baseline",
            "owner_and_client_sets_unchanged_on_candidate",
            "persisted_signing_key_preserved",
            "rehearsal_complete",
            "restored_archive_bytes_and_modes_match",
            "restored_old_runtime_advanced",
        ] {
            require(v[key] == true, "required real U29 observation did not pass")?;
        }
        let start = obs["started_at"]
            .as_str()
            .ok_or("copy start missing")?
            .to_owned();
        let end = obs["finished_at"]
            .as_str()
            .ok_or("copy end missing")?
            .to_owned();
        require(
            start == row["started_at"] && end == row["finished_at"] && start < end,
            "copy time window inconsistent",
        )?;
        windows.push((start, end));
        rows.push(json!({"task_id":"U29","repeat":repeat,"evidence":seal,"observation_id":obs["command_id"],"exact_restore_proof":proof_seal}));
    }
    require(
        repeats.len() == 3,
        "three real operator-copy repeats required",
    )?;
    windows.sort();
    for pair in windows.windows(2) {
        require(pair[0].1 < pair[1].0, "real copy observations overlap")?;
    }
    Ok(
        json!({"rows":rows,"real_repetitions":3,"archive_sha256":a["archive_sha256"],
        "rollback_validation_mode":"exact_restore_then_prepared_continuation","original_modes_baseline_continuation":false,
        "transactional_snapshot_claimed":false,"complete_capture_process_visibility_claimed":false,
        "original_strict_failure_preserved":true,"synthetic_trials_counted":0,"private_copy_reopened_now":false}),
    )
}
