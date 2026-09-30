//! Cross-bind the sealed observations without broadening their acceptance scope.
use super::*;

pub(super) fn snapshot(value: &Value) -> Result<()> {
    require(
        value["milestone"] == "MTM-017"
            && value["implementation_commit"] == PRODUCT_COMMIT
            && value["source_sha256"] == PRODUCT_SOURCE
            && value["candidate"]["sha256"] == CANDIDATE
            && value["candidate"]["version"] == "0.6.0-preview.2"
            && value["candidate"]["state_schema"] == 8
            && value["candidate"]["tool_contract"] == "mtm-tools-v10"
            && value["candidate"]["workflow_protocol"] == 3
            && value["candidate"]["public_tools"] == 24
            && value["candidate"]["path"]
                == format!("target/mtm017-preview2/mtm-0.6.0-preview.2-{CANDIDATE}/mtm")
            && value["baseline"]["sha256"] == BASELINE
            && value["baseline"]["version"] == "0.6.0-preview.1"
            && value["baseline"]["state_schema"] == 7
            && value["baseline"]["path"]
                == format!("target/mtm017-baselines/mtm-0.6.0-preview.1-{BASELINE}/mtm")
            && value["release_qualified"] == false
            && value["production_selectors_changed"] == false
            && value["production_state_modified"] == false
            && value["upgrade"]["operator_state_copy_tested"] == false
            && value["native_corpus"]["complete_corpus"] == false,
        "sealed candidate snapshot identity or scope inconsistent",
    )?;
    let profiles = array(&value["profiles_passed"])?;
    require(
        profiles.len() == 8
            && PROFILES
                .iter()
                .all(|name| profiles.iter().filter(|v| *v == name).count() == 1),
        "snapshot profile set inconsistent",
    )?;
    require(
        array(&value["report_seals"])?.len() == 9,
        "snapshot report set inconsistent",
    )
}

pub(super) fn source_checkpoint(value: &Value) -> Result<()> {
    let source = &value["source_identity"];
    require(
        value["passed"] == true
            && value["release_qualified"] == false
            && value["tests_skipped_by_preflight"] == false
            && source["hash_scope"] == "mtm-rust-source-v1"
            && source["before_sha256"] == PRODUCT_SOURCE
            && source["after_sha256"] == PRODUCT_SOURCE
            && source["commit_before"] == PRODUCT_COMMIT
            && source["commit_after"] == PRODUCT_COMMIT
            && source["unchanged"] == true,
        "frozen source checkpoint identity inconsistent",
    )?;
    let checks = array(&value["checks"])?;
    require(
        checks.len() == 4
            && ["format", "clippy", "rust_tests", "diff"]
                .iter()
                .all(|name| {
                    checks
                        .iter()
                        .filter(|v| {
                            v["name"] == *name && v["passed"] == true && v["exit_code"] == 0
                        })
                        .count()
                        == 1
                }),
        "frozen source checks inconsistent",
    )
}

pub(super) fn profiles(inventory: &Inventory<'_>, snapshot: &Value) -> Result<Vec<Value>> {
    let mut observations = Vec::new();
    for name in PROFILES {
        let mut matches = Vec::new();
        for seal in array(&snapshot["report_seals"])? {
            let seal = reference(seal)?;
            let value = inventory.get(&seal.path)?;
            if value["profile"] == name {
                matches.push((seal, value));
            }
        }
        require(matches.len() == 1, "profile report missing or duplicate")?;
        let (seal, value) = matches.pop().ok_or("profile missing")?;
        qualify::validate_receipt(value, CANDIDATE, BASELINE, name)?;
        let source = &value["harness_source_identity"];
        require(
            source["commit"] == PRODUCT_COMMIT
                && source["before_sha256"] == PRODUCT_SOURCE
                && source["after_sha256"] == PRODUCT_SOURCE
                && source["unchanged"] == true,
            "profile harness lineage inconsistent",
        )?;
        observations.push(json!({"profile":name,"report":seal,
            "sealed_original_scope":value["scope"],"original_runner_milestone":value["milestone"],
            "hash_structure_and_profile_summary_verified":true,"harness_binding_verified":true,
            "candidate_sha256":CANDIDATE,"baseline_sha256":value["baseline_sha256"],
            "recorded_scoped_pass":true,"complete_schema8_gate_adapter":false,
            "profile_reexecuted":false}));
    }
    Ok(observations)
}

pub(super) fn research(inventory: &mut Inventory<'_>) -> Result<Value> {
    let state = inventory.get(RESEARCH)?.clone();
    require(
        state["schema"] == "mtm017-research-corpus-state-v1"
            && state["candidate_sha256"] == CANDIDATE
            && state["candidate_source_commit"] == PRODUCT_COMMIT
            && state["state_schema_version"] == 8
            && state["research_accepted"] == true
            && state["accepted_research_subset_trials"] == 15
            && state["expected_research_subset_trials"] == 15
            && state["complete_for_research_scope"] == true
            && state["complete_for_full_corpus"] == false
            && state["historical_counts_inherited"] == false
            && state["release_qualified"] == false
            && state["deployment_authorized"] == false
            && state["frozen_mtm016_driver_sha256"] == DRIVER_SHA,
        "research state scope inconsistent",
    )?;
    let accepted = inventory.referred(&state["active_acceptance"])?;
    let input = inventory.referred(&state["inputs"])?;
    let input_review = inventory.referred(&state["input_review"])?;
    let proposal = inventory.referred(&state["proposal"])?;
    let review = inventory.referred(&state["result_review"])?;
    for key in ["inputs", "input_review", "proposal", "result_review"] {
        require(
            accepted[key] == state[key],
            "research acceptance pointer mismatch",
        )?;
    }
    for key in ["inputs", "input_review", "proposal"] {
        require(
            review[key] == state[key],
            "research result review pointer mismatch",
        )?;
    }
    for value in [&accepted, &input, &proposal] {
        require(
            value["milestone"] == "MTM-017"
                && value["candidate_sha256"] == CANDIDATE
                && value["candidate_source_commit"] == PRODUCT_COMMIT
                && value["state_schema_version"] == 8
                && value["release_qualified"] == false
                && value["production_selector_changed"] == false
                && value["production_state_modified"] == false,
            "research chain candidate or authority mismatch",
        )?;
    }
    for key in [
        "inputs_sha256",
        "bundle_catalog_sha256",
        "implementation_source_sha256",
        "maintenance_binary_sha256",
    ] {
        require(
            input_review[key] == proposal[key],
            "research input review implementation binding mismatch",
        )?;
    }
    require(
        proposal["inputs_sha256"] == state["inputs"]["sha256"]
            && proposal["input_review_sha256"] == state["input_review"]["sha256"]
            && review["implementation_source_sha256"] == proposal["implementation_source_sha256"]
            && review["maintenance_binary_sha256"] == proposal["maintenance_binary_sha256"]
            && input_review["reviewer_session"] != input_review["prepared_by"]
            && input_review["reviewer_session"] == review["reviewer_session"]
            && input_review["decision"] == "approved_for_read_only_proposal"
            && review["decision"] == "approved_for_research_subset_acceptance"
            && accepted["decision"] == "accepted_after_separate_input_and_result_reviews"
            && accepted["research_accepted"] == true
            && accepted["accepted_research_subset_trials"] == 15
            && accepted["complete_for_full_corpus"] == false
            && accepted["historical_counts_inherited"] == false
            && accepted["deployment_authorized"] == false
            && proposal["accepted_trials_delta"] == 0
            && proposal["research_accepted"] == false
            && review["accepted_trials_delta"] == 0
            && review["research_accepted"] == false
            && review["checks"]["independently_reconstructed_all_fifteen_output_rows"] == true
            && review["checks"]["independently_rehashed_all_186_bundle_artifacts"] == true
            && review["checks"]["independent_rerun_stdout_byte_identical_to_proposal"] == true,
        "research separate review and acceptance chain invalid",
    )?;
    let proposed = array(&proposal["trials"])?;
    let accepted_rows = array(&accepted["trials"])?;
    let inputs = array(&input["trials"])?;
    require(
        proposed.len() == 15 && accepted_rows.len() == 15 && inputs.len() == 15,
        "research fifteen-cell matrix missing",
    )?;
    let mut cells = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for ((proposed, accepted), input) in proposed.iter().zip(accepted_rows).zip(inputs) {
        let task = accepted["task_id"]
            .as_str()
            .ok_or("research task missing")?;
        let repeat = accepted["repeat"]
            .as_u64()
            .ok_or("research repeat missing")?;
        require(
            ["U21", "U22", "U23", "U24", "U25"].contains(&task)
                && (1..=3).contains(&repeat)
                && cells.insert((task, repeat))
                && accepted["research_accepted"] == true
                && proposed["eligible_for_result_review"] == true,
            "research cell identity invalid",
        )?;
        let mut left = proposed.clone();
        let mut right = accepted.clone();
        left.as_object_mut()
            .ok_or("research row malformed")?
            .remove("eligible_for_result_review");
        right
            .as_object_mut()
            .ok_or("research row malformed")?
            .remove("research_accepted");
        require(
            left == right
                && input["task_id"] == task
                && input["repeat"] == repeat
                && input["receipt"] == accepted["receipt"],
            "research proposal or accepted row drift",
        )?;
        let receipt = inventory.referred(&accepted["receipt"])?;
        for key in [
            "task_id",
            "repeat",
            "case_id",
            "trial_id",
            "bundle_sha256",
            "final_tex_sha256",
            "verification_report_sha256",
            "review_observation_sha256",
            "reviewer_statement_checks",
        ] {
            require(
                receipt[key] == accepted[key],
                "research original receipt mismatch",
            )?;
        }
        for key in [
            "case_id",
            "trial_id",
            "bundle_sha256",
            "final_tex_sha256",
            "verification_report_sha256",
            "review_observation_sha256",
        ] {
            let text = accepted[key].as_str().ok_or("research identity missing")?;
            require(
                identities.insert((key, text.to_owned())),
                "research identities duplicate",
            )?;
        }
        require(
            receipt["candidate_sha256"] == CANDIDATE
                && receipt["candidate_source_commit"] == PRODUCT_COMMIT
                && receipt["independent_review_observed"] == true
                && receipt["mathematical_review_passed"] == true
                && receipt["final_artifact_sealed"] == true
                && receipt["release_qualified"] == false,
            "research receipt scope inconsistent",
        )?;
    }
    Ok(
        json!({"previously_accepted_subset":15,"scope":"U21-U25_x3_only",
        "public_chain_verified":true,"private_bundle_artifacts_rehashed_now":false,
        "private_math_review_reexecuted":false,"newly_accepted_trials":0,
        "complete_for_full_corpus":false,"historical_counts_inherited":false,
        "input_review_cryptographically_authenticated":false}),
    )
}

pub(super) fn waivers(inventory: &mut Inventory<'_>) -> Result<Vec<Value>> {
    let state = inventory.get(CLEAN)?.clone();
    let ledger = inventory.get(DECISIONS)?.clone();
    let decisions = array(&ledger["decisions"])?;
    require(
        decisions.len() == 3,
        "reviewed operator decision set changed",
    )?;
    let find = |id: &str| -> Result<Value> {
        let matches = decisions
            .iter()
            .filter(|v| v["decision_id"] == id)
            .collect::<Vec<_>>();
        require(matches.len() == 1, "operator decision missing or duplicate")?;
        Ok(matches[0].clone())
    };
    let clean = find("MTM017-READINESS-DECISION-003")?;
    let old = find("MTM017-READINESS-DECISION-001")?;
    for (decision, gate) in [
        (&clean, "clean_build_provenance"),
        (&old, "historical_0_5_0_preview_2_rollback_artifact"),
    ] {
        require(
            decision["gate"] == gate
                && decision["applicability"]["candidate_sha256"] == CANDIDATE
                && decision["applicability"]["candidate_state_schema"] == 8
                && decision["applicability"]["milestone"] == "MTM-017"
                && decision["passed"] == false
                && decision["release_qualified"] == false
                && decision["deployment_authorized"] == false,
            "operator waiver candidate, gate or authority invalid",
        )?;
    }
    require(
        old["disposition"] == "waived_by_operator"
            && old["decision"] == "not_required"
            && old["compatible_schema7_baseline_sha256"] == BASELINE
            && old["historical_fact_preserved"]["observed_available"] == false
            && old["historical_fact_preserved"]["evidence"] == HISTORICAL,
        "historical binary waiver scope invalid",
    )?;
    let active = &state["active_decision"];
    require(
        active["decision_id"] == clean["decision_id"],
        "active clean waiver decision mismatch",
    )?;
    let record = inventory.referred(&json!({"path":active["path"],"sha256":active["sha256"]}))?;
    require(
        record["decision"] == clean
            && clean["decision"] == "waived_by_operator"
            && clean["applicability"]["candidate_source_commit"] == PRODUCT_COMMIT
            && clean["human_authorized_override"] == true
            && clean["gate_allowed_by_governance"] == true
            && clean["exact_candidate_reproduced"] == false
            && clean["technical_status"] == "not_reproduced"
            && state["candidate_sha256"] == CANDIDATE
            && state["gate"] == "clean_build_provenance"
            && state["status"] == "waived_by_operator"
            && state["passed"] == false
            && state["exact_candidate_reproduced"] == false
            && state["release_qualified"] == false
            && state["deployment_authorized"] == false,
        "clean-build waiver changed technical failure or scope",
    )?;
    inventory.closure(&clean["original_failure"], 0)?;
    let original = inventory.referred(&clean["original_failure"]["summary"])?;
    require(
        state["active_observation"] == clean["original_failure"]["summary"]
            && state["prior_gate"] == clean["original_failure"]["prior_gate"]
            && original["candidate"]["sha256"] == CANDIDATE
            && original["source_commit"] == PRODUCT_COMMIT
            && original["runner"]["exit_code"] == 1
            && original["build_results"]["both_builds_equal"] == true
            && original["build_results"]["both_match_selected_candidate"] == false,
        "original clean-build failure not preserved",
    )?;
    Ok(vec![
        json!({"decision_id":clean["decision_id"],"sealed_decision_and_failure_chain_verified":true,
            "passed":false,"technical_status":"not_reproduced","exact_candidate_reproduced":false,
            "gate_allowed_by_governance":true,"new_test_evidence":false}),
        json!({"decision_id":old["decision_id"],"sealed_scoped_decision_verified":true,
            "passed":false,"historical_binary_recovered":false,"current_schema7_rollback_requirement_waived":false}),
    ])
}
