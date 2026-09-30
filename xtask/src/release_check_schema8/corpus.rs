//! Reconstruct the accepted 87 public rows; overlay U26 governance separately.
use super::*;

fn chain(
    inv: &mut Inventory<'_>,
    accepted: &Value,
    input_decision: &str,
    result_decision: &str,
) -> Result<(Value, Value)> {
    let input = inv.linked(&accepted["inputs"])?;
    let input_review = inv.linked(&accepted["input_review"])?;
    let proposal = inv.linked(&accepted["proposal"])?;
    let result_review = inv.linked(&accepted["result_review"])?;
    for key in ["implementation_validation", "whole_source_gate"] {
        inv.linked(&accepted[key])?;
    }
    require(
        input_review["inputs_sha256"] == accepted["inputs"]["sha256"]
            && input_review["decision"] == input_decision
            && result_review["decision"] == result_decision
            && result_review["proposal"] == accepted["proposal"]
            && result_review["inputs"] == accepted["inputs"]
            && result_review["input_review"] == accepted["input_review"]
            && input_review["reviewer_session"] != input_review["prepared_by"]
            && input_review["reviewer_session"] == result_review["reviewer_session"]
            && input_review["release_qualified"] == false
            && result_review["release_qualified"] == false
            && input_review["accepted_delta"] == 0
            && result_review["accepted_delta"] == 0
            && proposal["accepted_delta"] == 0
            && proposal["release_qualified"] == false,
        "historical corpus review/proposal chain mismatch",
    )?;
    Ok((input, proposal))
}
fn cells(value: &Value) -> Result<BTreeMap<(String, u64), Value>> {
    let mut result = BTreeMap::new();
    for row in array(value)? {
        let task = row["task_id"].as_str().ok_or("corpus task missing")?;
        let repeat = row["repeat"].as_u64().ok_or("corpus repeat missing")?;
        require(
            (1..=3).contains(&repeat)
                && (1..=30).any(|n| task == format!("U{n:02}"))
                && result
                    .insert((task.to_owned(), repeat), row.clone())
                    .is_none(),
            "corpus cell unknown, duplicated or malformed",
        )?;
    }
    require(
        result.len() == 90,
        "corpus requires exactly ninety unique cells",
    )?;
    Ok(result)
}
fn same_core(a: &Value, b: &Value) -> Result<()> {
    for key in ["task_id", "repeat", "batch", "evidence", "observation_id"] {
        require(a[key] == b[key], "corpus cell evidence binding changed")?;
    }
    Ok(())
}
pub(super) fn validate(
    inv: &mut Inventory<'_>,
    i: &Inputs,
    research: &Value,
    copied: &Value,
) -> Result<Value> {
    let union = inv.json(&i.corpus_acceptance)?;
    let state = inv.json(&i.corpus_state)?;
    require(
        state["acceptance"] == serde_json::to_value(&i.corpus_acceptance)?
            && state["candidate_sha256"] == CANDIDATE
            && state["accepted_trials"] == 87
            && state["pending_trials"] == 3
            && state["full_corpus_accepted"] == false
            && union["schema"] == "mtm017-governance-corpus-union-accepted-v1"
            && union["candidate_sha256"] == CANDIDATE
            && union["candidate_source_commit"] == PRODUCT_COMMIT
            && union["candidate_source_sha256"] == PRODUCT_SOURCE
            && union["corpus_sha256"] == CORPUS_SHA
            && union["accepted_trials"] == 87
            && union["pending_trials"] == 3
            && union["failed_trials"] == 0
            && union["newly_accepted_trials"] == 9
            && union["newly_accepted_authority_trials"] == 6
            && union["newly_accepted_operator_copy_trials"] == 3
            && union["newly_accepted_research_trials"] == 0
            && union["full_corpus_accepted"] == false
            && union["release_qualified"] == false
            && union["deployment_authorized"] == false
            && union["known_source_failure_unresolved"] == true
            && union["original_modes_baseline_continuation"] == false
            && union["transactional_capture_snapshot_claimed"] == false
            && union["complete_capture_process_visibility_claimed"] == false,
        "immutable 87-cell acceptance scope/count changed",
    )?;
    let (input, proposal) = chain(
        inv,
        &union,
        "approved_for_read_only_governance_union",
        "approved_for_scoped_corpus_union_activation",
    )?;
    let refs = input["refs"]
        .as_object()
        .ok_or("union role references missing")?;
    require(refs.len() == 25, "union reference roles changed")?;
    for seal in refs.values() {
        inv.linked(seal)?;
    }
    require(
        union["prior_78_acceptance"] == input["refs"]["base"]
            && union["prior_78_pointer"] == input["refs"]["base_pointer"]
            && input["refs"]["u29_aggregate"] == serde_json::to_value(&i.operator_copy)?
            && input["refs"]["u29_review"] == serde_json::to_value(&i.operator_copy_review)?
            && input["refs"]["research_pointer"] == serde_json::to_value(&i.research_state)?,
        "union batch/pointer role mismatch",
    )?;
    let base = inv.linked(&input["refs"]["base"])?;
    let base_pointer = inv.linked(&input["refs"]["base_pointer"])?;
    require(
        base["schema"] == "mtm017-partial-corpus-acceptance-v1"
            && base["candidate_sha256"] == CANDIDATE
            && base["accepted_trials"] == 78
            && base["pending_trials"] == 12
            && base["previously_accepted_research_trials"] == 15
            && base["newly_accepted_research_trials"] == 0
            && base["full_corpus_accepted"] == false
            && base["release_qualified"] == false
            && base_pointer["active_acceptance"] == input["refs"]["base"],
        "prior 78 accepted scope invalid",
    )?;
    let (base_input, base_proposal) = chain(
        inv,
        &base,
        "approved_for_read_only_proposal",
        "approved_for_partial_corpus_activation",
    )?;
    for (group, keys) in [
        ("portable", &["raw", "observation", "review"][..]),
        ("native", &["raw", "snapshot"][..]),
        ("u30", &["observation", "review"][..]),
    ] {
        for key in keys {
            inv.linked(&base_input[group][*key])?;
        }
    }
    for trial in array(&base_input["u30"]["trials"])? {
        inv.linked(&trial["raw"])?;
    }
    let reconstructed =
        corpus_aggregate_schema8::archived_public_rows(&base_input, &inv.documents, research)?;
    let baseline_cells = cells(&base["rows"])?;
    let reconstructed_cells = cells(&reconstructed)?;
    let proposed_base_cells = cells(&base_proposal["rows"])?;
    for (key, row) in &baseline_cells {
        let raw = reconstructed_cells
            .get(key)
            .ok_or("reconstructed base cell missing")?;
        let proposed = proposed_base_cells
            .get(key)
            .ok_or("proposed base cell missing")?;
        same_core(row, raw)?;
        same_core(proposed, raw)?;
        require(
            proposed["status"] == raw["status"]
                && row["source_observation_status"] == raw["status"]
                && row["status"]
                    == if raw["status"] == "pending" {
                        json!("pending")
                    } else {
                        json!("accepted")
                    },
            "prior accepted row promotes a pending observation",
        )?;
    }
    let authority_input = inv.linked(&input["refs"]["authority_inputs"])?;
    inv.linked(&authority_input["authorization"])?;
    for seal in array(&authority_input["trials"])? {
        inv.linked(seal)?;
    }
    let mapping = inv.linked(&input["refs"]["mapping"])?;
    let ledger = inv.json(&i.decisions)?;
    policy::record_matches(&ledger, &mapping)?;
    require(
        mapping["decision_id"] == "MTM017-READINESS-DECISION-004"
            && mapping["candidate_sha256"] == CANDIDATE,
        "U27/U28 mapping scope invalid",
    )?;
    let authority =
        authority_corpus_schema8::archived_public_rows(&authority_input, &inv.documents)?;
    let mut additions = BTreeMap::new();
    for row in authority {
        let key = (
            row["task_id"].as_str().ok_or("authority task")?.to_owned(),
            row["repeat"].as_u64().ok_or("authority repeat")?,
        );
        additions.insert(key,json!({"task_id":row["task_id"],"repeat":row["repeat"],
            "batch":"authority_compatibility_and_boundaries","evidence":row["raw"],"observation_id":row["trial_id"]}));
    }
    for row in array(&copied["rows"])? {
        let key = (
            "U29".to_owned(),
            row["repeat"].as_u64().ok_or("U29 repeat")?,
        );
        require(additions.insert(key,json!({"task_id":"U29","repeat":row["repeat"],
            "batch":"operator_copy_exact_restore_then_prepared_continuation","evidence":row["evidence"],
            "observation_id":row["observation_id"]})).is_none(), "duplicate new union cell")?;
    }
    require(additions.len() == 9, "union new observations incomplete")?;
    let final_cells = cells(&union["rows"])?;
    let proposed_cells = cells(&proposal["rows"])?;
    let mut accepted = 0;
    let mut pending = 0;
    for (key, row) in &final_cells {
        let prior = baseline_cells.get(key).ok_or("prior cell missing")?;
        let proposed = proposed_cells
            .get(key)
            .ok_or("union proposal cell missing")?;
        same_core(row, proposed)?;
        if prior["status"] == "accepted" {
            same_core(row, prior)?;
            require(
                row["status"] == "accepted"
                    && proposed["status"] == "previously_accepted"
                    && row["previously_accepted"] == true
                    && row["newly_eligible"] == false
                    && row["newly_accepted_in_this_aggregate"] == false
                    && row["accepted_before_this_aggregate"] == true,
                "prior union cell recounted",
            )?;
            accepted += 1;
        } else if let Some(new) = additions.get(key) {
            same_core(row, new)?;
            require(
                row["status"] == "accepted"
                    && proposed["status"] == "eligible"
                    && row["previously_accepted"] == false
                    && row["newly_eligible"] == true
                    && row["newly_accepted_in_this_aggregate"] == true
                    && row["accepted_before_this_aggregate"] == false,
                "new union cell is not a separately accepted observation",
            )?;
            accepted += 1;
        } else {
            require(
                key.0 == "U26"
                    && row["status"] == "pending"
                    && proposed["status"] == "pending"
                    && row["evidence"].is_null()
                    && row["observation_id"].is_null()
                    && row["previously_accepted"] == false
                    && row["newly_eligible"] == false,
                "unaccepted corpus cell promoted",
            )?;
            pending += 1;
        }
    }
    require(
        accepted == 87 && pending == 3,
        "corpus union technical accounting invalid",
    )?;
    let archive = inv.json(&Reference {
        path: "records/evidence/MTM-017/corpus-union-source-archive-20260930.json".into(),
        sha256: "910d9004850c3a859112340665d0131d0bb1b536b4fcd583636aad97a5665fba".into(),
    })?;
    require(
        archive["archive_only"] == true
            && archive["complete_evidence_archive_in_git"] == false
            && archive["original_result_review"] == union["result_review"],
        "union source archive scope mismatch",
    )?;
    let fields = [
        ("union-validator.sh", "script_sha256"),
        ("union-validator.sql", "validator_sql_sha256"),
        ("union-shapes.sql", "shape_contract_sha256"),
        ("union-negative-mutations.sql", "negative_tests_sha256"),
    ];
    for (name, key) in fields {
        let path = format!("scripts/mtm017-corpus-union/{name}");
        let matches = array(&archive["mappings"])?
            .iter()
            .filter(|v| v["archived_path"] == path)
            .collect::<Vec<_>>();
        require(
            matches.len() == 1
                && matches[0]["byte_identical"] == true
                && matches[0]["sha256"] == union[key],
            "archived union implementation differs from accepted provenance",
        )?;
        inv.load(
            &Reference {
                path,
                sha256: union[key]
                    .as_str()
                    .ok_or("union implementation seal missing")?
                    .into(),
            },
            Kind::Data,
        )?;
    }
    Ok(
        json!({"unique_cells":90,"technical_accepted_trials":87,"technical_pending_trials":3,
        "human_waived_cells":3,"governance_unaccounted_cells":0,"full_technical_corpus":false,
        "previously_accepted_research_trials":15,"newly_accepted_trials":0,"public_rows_reconstructed":true,
        "private_math_reexecuted":false,"private_copy_reopened":false,"historical_harness_git_reconstructable_claimed":false,
        "historical_target_archives_replayed":false,"accepted_union":i.corpus_acceptance}),
    )
}
