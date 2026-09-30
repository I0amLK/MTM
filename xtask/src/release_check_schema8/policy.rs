//! Scoped historical observations, human waivers, and the unresolved finding.
use super::*;

pub(super) fn decision<'a>(ledger: &'a Value, id: &str) -> Result<&'a Value> {
    let values = array(&ledger["decisions"])?;
    require(values.len() <= 32, "decision ledger exceeds bound")?;
    let mut ids = BTreeSet::new();
    for value in values {
        let key = value["decision_id"].as_str().ok_or("decision ID missing")?;
        require(ids.insert(key), "duplicate operator decision")?;
    }
    values
        .iter()
        .find(|v| v["decision_id"] == id)
        .ok_or_else(|| "required operator decision missing".into())
}
pub(super) fn record_matches(ledger: &Value, record: &Value) -> Result<()> {
    let id = record["decision_id"]
        .as_str()
        .ok_or("decision record ID missing")?;
    let item = decision(ledger, id)?;
    let mut expected = record.clone();
    if !item
        .as_object()
        .ok_or("decision object missing")?
        .contains_key("schema")
    {
        expected
            .as_object_mut()
            .ok_or("decision record malformed")?
            .remove("schema");
        expected
            .as_object_mut()
            .ok_or("decision record malformed")?
            .remove("milestone");
    }
    require(*item == expected, "operator record and ledger differ")
}
pub(super) fn profiles(inv: &mut Inventory<'_>, i: &Inputs) -> Result<Vec<Value>> {
    let s = inv.json(&i.snapshot)?;
    require(
        s["candidate"]["sha256"] == CANDIDATE
            && s["baseline"]["sha256"] == BASELINE
            && s["implementation_commit"] == PRODUCT_COMMIT
            && s["source_sha256"] == PRODUCT_SOURCE
            && s["candidate"]["version"] == "0.6.0-preview.2"
            && s["candidate"]["state_schema"] == 8
            && s["candidate"]["tool_contract"] == "mtm-tools-v10"
            && s["candidate"]["workflow_protocol"] == 3
            && s["candidate"]["public_tools"] == 24
            && s["baseline"]["state_schema"] == 7
            && s["baseline"]["version"] == "0.6.0-preview.1"
            && s["release_qualified"] == false,
        "candidate snapshot contract mismatch",
    )?;
    for key in ["candidate", "baseline"] {
        let v = &s[key];
        inv.load(
            &Reference {
                path: v["path"].as_str().ok_or("artifact path")?.into(),
                sha256: v["sha256"].as_str().ok_or("artifact hash")?.into(),
            },
            Kind::Executable,
        )?;
    }
    let seals = array(&s["report_seals"])?;
    require(
        seals.len() == 9 && array(&s["profiles_passed"])?.len() == 8,
        "profile inventory cardinality invalid",
    )?;
    let mut observed = BTreeMap::new();
    let mut paths = BTreeSet::new();
    for seal in seals {
        let r = reference(seal)?;
        require(
            paths.insert(r.path.clone()),
            "profile report path duplicate",
        )?;
        let v = inv.json(&r)?;
        if let Some(name) = v["profile"].as_str() {
            require(
                PROFILES.contains(&name) && !observed.contains_key(name),
                "unknown or duplicate profile",
            )?;
            qualify::validate_receipt(&v, CANDIDATE, BASELINE, name)?;
            let h = &v["harness_source_identity"];
            require(
                h["commit"] == PRODUCT_COMMIT
                    && h["before_sha256"] == PRODUCT_SOURCE
                    && h["after_sha256"] == PRODUCT_SOURCE
                    && h["unchanged"] == true,
                "committed profile harness binding mismatch",
            )?;
            observed.insert(
                name.to_owned(),
                json!({"profile":name,"report":r,"scope":v["scope"],
                "original_runner_milestone":v["milestone"],"technical_scope_validated":true,
                "harness_source_sha256":PRODUCT_SOURCE,"harness_commit":PRODUCT_COMMIT,
                "historical_harness_git_reconstructable":true,"profile_reexecuted":false}),
            );
        } else {
            require(
                r.path == "records/evidence/MTM-017/preview2-source-gate.json",
                "unexpected snapshot source role",
            )?;
            source_gate(&v, PRODUCT_SOURCE)?;
        }
    }
    require(
        PROFILES.iter().all(|p| {
            observed.contains_key(*p)
                && array(&s["profiles_passed"])
                    .is_ok_and(|a| a.iter().filter(|x| *x == p).count() == 1)
        }),
        "profile inventory incomplete",
    )?;
    Ok(observed.into_values().collect())
}
pub(super) fn waivers(inv: &mut Inventory<'_>, i: &Inputs, ledger: &Value) -> Result<Value> {
    let old = decision(ledger, "MTM017-READINESS-DECISION-001")?;
    require(
        old["gate"] == "historical_0_5_0_preview_2_rollback_artifact"
            && old["applicability"]["candidate_sha256"] == CANDIDATE
            && old["applicability"]["candidate_state_schema"] == 8
            && old["decision"] == "not_required"
            && old["disposition"] == "waived_by_operator"
            && old["passed"] == false
            && old["release_qualified"] == false
            && old["deployment_authorized"] == false
            && old["compatible_schema7_baseline_sha256"] == BASELINE
            && old["historical_fact_preserved"]["observed_available"] == false,
        "historical artifact waiver scope invalid",
    )?;
    inv.json(&Reference {
        path: "records/evidence/MTM-016/lifecycle-reconciliation-20260926.json".into(),
        sha256: "9988d973770cbd5a95c15f4dc4a715d2ed772dcf4be77485c937de9d24401efd".into(),
    })?;
    let state = inv.json(&i.clean_build_state)?;
    let clean = decision(ledger, "MTM017-READINESS-DECISION-003")?;
    let active = &state["active_decision"];
    let original = inv.linked(&json!({"path":active["path"],"sha256":active["sha256"]}))?;
    require(
        original["decision"] == *clean
            && active["decision_id"] == clean["decision_id"]
            && clean["gate"] == "clean_build_provenance"
            && clean["applicability"]["candidate_sha256"] == CANDIDATE
            && clean["applicability"]["candidate_source_commit"] == PRODUCT_COMMIT
            && clean["applicability"]["candidate_state_schema"] == 8
            && clean["decision"] == "waived_by_operator"
            && clean["passed"] == false
            && clean["exact_candidate_reproduced"] == false
            && clean["gate_allowed_by_governance"] == true
            && state["candidate_sha256"] == CANDIDATE
            && state["status"] == "waived_by_operator"
            && state["passed"] == false
            && state["exact_candidate_reproduced"] == false,
        "clean-build override scope or technical result invalid",
    )?;
    for key in ["summary", "prior_gate", "comparison"] {
        inv.linked(&clean["original_failure"][key])?;
    }
    let failed = inv.linked(&clean["original_failure"]["summary"])?;
    require(
        failed["candidate"]["sha256"] == CANDIDATE
            && failed["runner"]["exit_code"] == 1
            && failed["build_results"]["both_builds_equal"] == true
            && failed["build_results"]["both_match_selected_candidate"] == false
            && state["active_observation"] == clean["original_failure"]["summary"]
            && state["prior_gate"] == clean["original_failure"]["prior_gate"],
        "clean-build original failure lost",
    )?;
    for seal in array(&failed["sealed_reports"])? {
        inv.linked(seal)?;
    }
    let ustate = inv.json(&i.u26_state)?;
    let u = inv.linked(&ustate["waiver"])?;
    record_matches(ledger, &u)?;
    require(
        u["decision_id"] == "MTM017-READINESS-DECISION-006"
            && u["scope"] == "this_schema8_candidate_U26_three_cells_only"
            && u["applicability"]["candidate_sha256"] == CANDIDATE
            && u["applicability"]["candidate_source_commit"] == PRODUCT_COMMIT
            && u["applicability"]["candidate_state_schema"] == 8
            && u["applicability"]["task_id"] == "U26"
            && u["applicability"]["repeats"] == json!([1, 2, 3])
            && u["passed"] == false
            && u["gate_allowed_by_governance"] == true
            && u["technical_accepted_trials"] == 87
            && u["technical_pending_trials"] == 3
            && u["human_waived_cells"] == 3
            && u["technical_accepted_delta"] == 0
            && u["full_technical_corpus"] == false
            && u["other_gates_waived_by_this_decision"] == false
            && ustate["candidate_sha256"] == CANDIDATE
            && ustate["U26_technical_passed"] == false
            && ustate["technical_accepted_trials"] == 87
            && ustate["technical_pending_trials"] == 3
            && ustate["human_waived_cells"] == 3
            && u["original_87_acceptance"] == serde_json::to_value(&i.corpus_acceptance)?
            && u["original_87_pointer"] == serde_json::to_value(&i.corpus_state)?,
        "U26 waiver exceeds exact three-cell scope",
    )?;
    let mut cells = BTreeSet::new();
    for cell in array(&u["cells"])? {
        let repeat = cell["repeat"].as_u64().ok_or("waiver repeat missing")?;
        require(
            cell["task_id"] == "U26"
                && (1..=3).contains(&repeat)
                && cells.insert(repeat)
                && cell["technical_status"] == "pending"
                && cell["passed"] == false
                && cell["governance_disposition"] == "waived_by_operator"
                && cell["new_technical_trial_claimed"] == false,
            "waiver cell duplicate or broadened",
        )?;
    }
    require(cells.len() == 3, "U26 waiver cells incomplete")?;
    let partial = inv.linked(&u["original_partial_observation"])?;
    require(
        partial["passed"] == false
            && partial["run"]["successful_normal_assessment_submissions"] == 0,
        "original incomplete browser observation changed",
    )?;
    Ok(
        json!({"historical_binary":{"decision_id":old["decision_id"],"technical_pass":false,"governance_disposition":"waived_by_operator"},
        "clean_build":{"decision_id":clean["decision_id"],"technical_pass":false,"exact_candidate_reproduced":false,"governance_disposition":"waived_by_operator"},
        "U26":{"decision_id":u["decision_id"],"technical_pass":false,"technical_pending_trials":3,"human_waived_cells":3,"governance_disposition":"waived_by_operator"},
        "new_technical_trials":0}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskAuthorization {
    source: String,
    user_message_id: String,
    question_verbatim: String,
    answer_verbatim: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskDisposition {
    schema: String,
    milestone: String,
    decision_id: String,
    finding_id: String,
    failed_evidence: Reference,
    candidate_sha256: String,
    root_cause_status: String,
    release_disposition: String,
    passed: bool,
    runtime_fix_claimed: bool,
    operator_authorization: RiskAuthorization,
    diagnostic: Reference,
    deployment_authorized: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskReview {
    schema: String,
    finding_id: String,
    disposition: Reference,
    decision: String,
    reviewer_session: String,
    original_failure_preserved: bool,
    deployment_authorized: bool,
}
pub(super) fn finding(inv: &mut Inventory<'_>, i: &Inputs) -> Result<Value> {
    let failed = inv.json(&i.known_failure)?;
    let followup = inv.json(&i.known_failure_followup)?;
    let diagnostic = inv.json(&i.mechanism_diagnostic)?;
    require(
        diagnostic["schema"] == "mtm017-test-only-domain-collision-diagnostic-v1"
            && diagnostic["scope"]
                == "deterministic_in_process_runtime_mechanism_test_not_original_failure_attribution_or_release"
            && diagnostic["exact_candidate_executed"] == false
            && diagnostic["external_socket_or_browser_tested"] == false
            && diagnostic["observed"]["synthetic_only"] == true
            && diagnostic["observed"]["domain_primary_key_collision_confirmed"] == true
            && diagnostic["observed"]["committed_receipt_completed"] == true
            && diagnostic["observed"]["next_task_missing"] == true
            && diagnostic["observed"]["state_reopened"] == true
            && diagnostic["observed"]["receipt_replay_writes"] == 0
            && diagnostic["observed"]["same_run_next_task_recovered"] == true
            && diagnostic["observed"]["other_run_domain_unchanged"] == true
            && diagnostic["observed"]["caller_memory_unchanged_on_replay_and_recovery"] == true,
        "sealed diagnostic does not establish the stated synthetic recovery mechanism",
    )?;
    require(
        failed["passed"] == false
            && followup["root_cause"] == "indeterminate"
            && followup["original_failed_gate"] == serde_json::to_value(&i.known_failure)?
            && diagnostic["original_failed_gate"] == serde_json::to_value(&i.known_failure)?
            && diagnostic["original_r3_root_cause"] == "indeterminate"
            && diagnostic["original_r3_cause_proven"] == false
            && diagnostic["runtime_fix_claimed"] == false
            && diagnostic["candidate_sha256_rechecked"] == CANDIDATE
            && diagnostic["operator_risk_waiver_granted"] == false,
        "original known finding or mechanism scope changed",
    )?;
    let mut disposition = "unresolved";
    if let (Some(r), Some(review)) = (&i.risk_disposition, &i.risk_disposition_review) {
        let value = inv.json(r)?;
        let ledger = inv.json(&i.decisions)?;
        record_matches(&ledger, &value)?;
        let d: RiskDisposition = serde_json::from_value(value)?;
        let v: RiskReview = serde_json::from_value(inv.json(review)?)?;
        require(
            d.schema == "mtm017-source-risk-disposition-v1"
                && d.milestone == "MTM-017"
                && d.decision_id == "MTM017-READINESS-DECISION-007"
                && d.finding_id == FINDING
                && d.failed_evidence == i.known_failure
                && d.candidate_sha256 == CANDIDATE
                && d.root_cause_status == "indeterminate"
                && d.release_disposition == "accepted_by_operator"
                && !d.passed
                && !d.runtime_fix_claimed
                && d.diagnostic == i.mechanism_diagnostic
                && !d.deployment_authorized
                && d.operator_authorization.source == "direct_operator_confirmation"
                && d.operator_authorization.user_message_id
                    == "Sentinel_f5253c199dc88191801cda29b306b984"
                && !d.operator_authorization.question_verbatim.is_empty()
                && d.operator_authorization.answer_verbatim == "接受"
                && v.schema == "mtm017-source-risk-disposition-review-v1"
                && v.finding_id == FINDING
                && v.disposition == *r
                && v.decision == "approved_for_scoped_readiness"
                && !v.reviewer_session.is_empty()
                && v.reviewer_session != i.prepared_by
                && v.original_failure_preserved
                && !v.deployment_authorized,
            "source risk disposition is not separately reviewed exact-scope operator acceptance",
        )?;
        disposition = "accepted_by_operator";
    }
    Ok(
        json!({"finding_id":FINDING,"failed_evidence":i.known_failure,"diagnostic":i.mechanism_diagnostic,
        "candidate_sha256":CANDIDATE,"applicability":"same_product_source_observation_not_exact_candidate_failure_claim",
        "root_cause_status":"indeterminate","mechanism_reproduced":true,"original_failure_cause_proven":false,
        "runtime_fix_claimed":false,"historical_failure_passed":false,"release_disposition":disposition,
        "blocks_current_evaluation":disposition == "unresolved","disposition":i.risk_disposition,
        "disposition_review":i.risk_disposition_review}),
    )
}
const GATES: [(&str, &str, &str); 18] = [
    (
        "exact_artifact_identity",
        "Exact selected bytes and approved product/build lineage",
        "docs/MTM-017-PREVIEW2-QUALIFICATION.md",
    ),
    (
        "current_source",
        "Fresh stable complete source checks; not old counts",
        "docs/ACCEPTANCE.md",
    ),
    (
        "protocol",
        "Exact-candidate protocol/capability/lifecycle fixtures",
        "docs/MTM-017-PREVIEW2-QUALIFICATION.md",
    ),
    (
        "upgrade_schema8",
        "Generated-state 7/8/7 fixture only",
        "docs/MTM-017-SCHEMA8-UPGRADE.md",
    ),
    (
        "native_commands",
        "Dangerous isolation, commands, TTY, cleanup and CAS",
        "docs/MTM-017-PREVIEW2-QUALIFICATION.md",
    ),
    (
        "compiled_latex",
        "Required full/compact/repair fixture compilation",
        "docs/MTM-017-PREVIEW2-QUALIFICATION.md",
    ),
    (
        "resource",
        "Paired non-regression thresholds, no performance claim",
        "docs/ACCEPTANCE.md",
    ),
    (
        "corpus_native",
        "Validated U16-U20 subset; counted only within union",
        "docs/MTM-017-PARTIAL-CORPUS-AGGREGATE.md",
    ),
    (
        "install_sigkill",
        "Process-SIGKILL and three U30 trials, not power-loss",
        "docs/MTM-017-PARTIAL-CORPUS-AGGREGATE.md",
    ),
    (
        "retrieval",
        "Exact artifact external retrieval and redirect policy",
        "docs/MTM-017-PREVIEW2-QUALIFICATION.md",
    ),
    (
        "research_subset",
        "Previously accepted fifteen public-chain rows, no new mathematics",
        "docs/MTM-017-RESEARCH-CORPUS-IMPORT.md",
    ),
    (
        "operator_state_copy",
        "005 exact restore then prepared same-old-run continuation",
        "MTM017-READINESS-DECISION-005",
    ),
    (
        "browser_U26",
        "006 waives exactly three U26 governance cells, not technical evidence",
        "MTM017-READINESS-DECISION-006",
    ),
    (
        "current_corpus_accounting",
        "87 technical and 3 waived; no technical promotion",
        "MTM017-READINESS-DECISION-004/005/006",
    ),
    (
        "static_integrity",
        "Record, architecture, retirement and Rust-only provenance",
        "docs/CODE_STANDARD.md",
    ),
    (
        "criteria_and_adapter_integrity",
        "Machine consumption completeness, no extra real-world requirement",
        CONTRACT_PATH,
    ),
    (
        "clean_build",
        "003 exact-candidate provenance waiver; technical not reproduced",
        "MTM017-READINESS-DECISION-003",
    ),
    (
        "historical_binary",
        "001 old missing artifact waiver; current baseline still required",
        "MTM017-READINESS-DECISION-001",
    ),
];
pub(super) fn report(
    i: &Inputs,
    source: &str,
    binary: &str,
    inputs_sha: &str,
    review_sha: &str,
    observations: Value,
) -> Value {
    let gates = GATES.iter().map(|(id,scope,basis)| {
        let waiver = matches!(*id,"browser_U26"|"clean_build"|"historical_binary");
        let corpus = *id == "current_corpus_accounting";
        json!({"id":id,"criterion_source":basis,"evidence_scope":scope,
            "technical_pass":!waiver && !corpus,
            "technical_status":if waiver || corpus {"incomplete_or_failed_preserved"} else {"passed_for_stated_scope"},
            "governance_disposition":if waiver {"waived_by_operator"} else if corpus {"accounted_with_scoped_operator_waiver"} else {"technical_requirement_satisfied"},
            "requirement_accounted":true})
    }).collect::<Vec<_>>();
    let passed = observations["known_finding"]["blocks_current_evaluation"] == false;
    let mut report = json!({"schema":"mtm017-readiness-evaluation-v1","milestone":"MTM-017","criteria_revision":CONTRACT,
        "scope":"read_only_qualification_evaluation_pending_independent_result_review",
        "readiness_evaluation_passed":passed,"status":if passed {"evaluation_satisfied_pending_result_review"} else {"unresolved_finding"},
        "inputs_sha256":inputs_sha,"input_review_sha256":review_sha,
        "candidate_sha256":CANDIDATE,"baseline_sha256":BASELINE,"state_schema_version":8,
        "tool_contract":"mtm-tools-v10","workflow_protocol":3,"product_commit":PRODUCT_COMMIT,
        "product_build_source_sha256":PRODUCT_SOURCE,"maintenance_source_sha256":source,"maintenance_binary_sha256":binary,
        "implementation_complete":"unknown","implementation_scope":"whole_project_not_inferred_from_qualification",
        "adapter_implementation_scope_validated":true,"research_accepted":true,"research_acceptance_scope":"previously_accepted_fifteen_only",
        "newly_accepted_research_trials":0,"technical_accepted_trials":87,"technical_pending_trials":3,
        "human_waived_cells":3,"governance_unaccounted_cells":0,"technical_qualification_complete":false,
        "qualification_basis":"technical_evidence_plus_scoped_operator_waivers",
        "release_qualified":false,"result_review_required":true,"result_review_pending":true,"deployment_authorized":false});
    let details = json!({
        "candidate_executed":false,"private_state_opened":false,"target_archives_replayed":false,
        "raw_historical_archives_rehashed_now":false,"historical_harness_git_reconstructable_claimed_for_uncommitted_observations":false,
        "input_review_cryptographically_authenticated":false,"production_selector_changed":false,"production_state_modified":false,
        "corpus_count_incremented":false,"gates":gates,"observations":observations,"criteria":i.criteria,
        "acceptance_next_step":"A separate independent result review must bind these exact evaluation bytes, inputs, source and binary before append-only accepted readiness governance; this command never publishes that acceptance."});
    if let (Value::Object(target), Value::Object(rest)) = (&mut report, details) {
        target.extend(rest);
    }
    report
}
