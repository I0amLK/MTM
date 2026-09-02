use serde_json::json;

use super::super::ResearchStateProjector;
use super::*;

fn active_plan() -> Value {
    json!([{
        "plan_id": "plan-1",
        "summary": "A constituent route",
        "subgoals": ["First local identity", "Second summation step"],
        "subgoal_ids": ["sg-1", "sg-2"],
        "motivation": [],
        "dependencies": [],
        "risks": []
    }])
}

fn empty_progress() -> Value {
    json!({})
}

fn node_id(value: &str) -> ResearchNodeId {
    ResearchNodeId::parse(value).expect("test node id")
}

#[test]
fn normalizes_active_plans_and_current_screening_status() {
    let normalized = normalize_legacy_research(&LegacyResearchInput::new(
        "Prove the constituent formula.",
        2,
        active_plan(),
        json!({
            "plan-1": {
                "sg-1": {"status": "solved", "summary": "done"},
                "sg-2": {"status": "stuck", "summary": "missing summation lemma"}
            }
        }),
    ))
    .expect("legacy normalization");
    let state = ResearchStateProjector::project(normalized.snapshot()).expect("projection");
    assert_eq!(normalized.summary().normalized_nodes(), 3);
    assert_eq!(normalized.summary().normalized_attempts(), 0);
    assert!(normalized.warnings().is_empty());
    assert_eq!(
        state.nodes()[&node_id("node:plan-1:sg-1")].status(),
        ResearchNodeStatus::RouteSolved
    );
    assert_eq!(
        state.nodes()[&node_id("node:plan-1:sg-2")].status(),
        ResearchNodeStatus::Blocked
    );
    assert_eq!(
        state
            .actionable_frontier()
            .iter()
            .map(ResearchNodeId::as_str)
            .collect::<Vec<_>>(),
        vec!["node:plan-1:sg-2"]
    );
}

#[test]
fn normalizes_direct_screening_attempts_in_stable_order() {
    let input = LegacyResearchInput::new("Target", 3, active_plan(), empty_progress())
        .with_proof_steps(vec![json!({
            "record_type": "direct_screening_round",
            "plans": [{
                "plan_id": "plan-1",
                "subgoal_results": [
                    {"subgoal_id": "sg-2", "status": "stuck", "summary": "blocked"},
                    {"subgoal_id": "sg-1", "status": "partial", "summary": "partial"}
                ]
            }]
        })]);
    let normalized = normalize_legacy_research(&input).expect("legacy normalization");
    let state = ResearchStateProjector::project(normalized.snapshot()).expect("projection");
    assert_eq!(state.attempts().len(), 2);
    assert_eq!(state.attempts()[0].node_id().as_str(), "node:plan-1:sg-2");
    assert_eq!(state.attempts()[0].method, ResearchAttemptMethod::Direct);
    assert_eq!(state.attempts()[0].outcome, ResearchAttemptOutcome::Failed);
    assert_eq!(
        state.attempts()[0].obstruction,
        Some(ResearchObstruction::NoProgress)
    );
    assert_eq!(state.attempts()[1].node_id().as_str(), "node:plan-1:sg-1");
    assert_eq!(
        state.attempts()[1].outcome,
        ResearchAttemptOutcome::Progress
    );
}

#[test]
fn unknown_direct_screening_status_is_inconclusive_not_failed() {
    let input = LegacyResearchInput::new("Target", 3, active_plan(), empty_progress())
        .with_proof_steps(vec![json!({
            "record_type": "direct_screening_round",
            "plans": [{
                "plan_id": "plan-1",
                "subgoal_results": [
                    {"subgoal_id": "sg-1", "status": "future-status", "summary": "unknown"}
                ]
            }]
        })]);
    let normalized = normalize_legacy_research(&input).expect("legacy normalization");
    let state = ResearchStateProjector::project(normalized.snapshot()).expect("projection");
    assert_eq!(
        state.attempts()[0].outcome,
        ResearchAttemptOutcome::Inconclusive
    );
    assert_eq!(
        normalized.warnings()[0].code(),
        "unknown_direct_screening_status"
    );
}

#[test]
fn branch_partial_result_updates_only_matched_subgoals() {
    let input = LegacyResearchInput::new("Target", 4, active_plan(), empty_progress())
        .with_branch_results(vec![json!({
            "branch_id": "branch-4-1",
            "plan_id": "plan-1",
            "status": "partial",
            "summary": "one local piece remains",
            "proved_subgoals": ["sg-1"],
            "unproved_subgoals": ["Second summation step"],
            "failure_evidence": ["missing local lemma"]
        })]);
    let normalized = normalize_legacy_research(&input).expect("legacy normalization");
    let state = ResearchStateProjector::project(normalized.snapshot()).expect("projection");
    assert_eq!(
        state.nodes()[&node_id("node:plan-1:sg-1")].status(),
        ResearchNodeStatus::RouteSolved
    );
    assert_eq!(
        state.nodes()[&node_id("node:plan-1:sg-2")].status(),
        ResearchNodeStatus::Blocked
    );
    assert_eq!(state.attempts().len(), 2);
    assert!(
        state
            .attempts()
            .iter()
            .all(|attempt| attempt.method == ResearchAttemptMethod::Synthesis)
    );
}

#[test]
fn claimed_counterexample_requires_a_witness_before_refuting_a_node() {
    let without_witness = LegacyResearchInput::new("Target", 1, active_plan(), empty_progress())
        .with_counterexamples(vec![json!({
            "node_id": "node:plan-1:sg-2",
            "status": "found",
            "summary": "claimed failure"
        })]);
    let normalized = normalize_legacy_research(&without_witness).expect("normalization");
    let state = ResearchStateProjector::project(normalized.snapshot()).expect("projection");
    assert_eq!(
        state.nodes()[&node_id("node:plan-1:sg-2")].status(),
        ResearchNodeStatus::Open
    );
    assert_eq!(
        state.attempts()[0].outcome,
        ResearchAttemptOutcome::Inconclusive
    );
    assert_eq!(
        normalized.warnings()[0].code(),
        "counterexample_without_witness"
    );

    let with_witness = LegacyResearchInput::new("Target", 1, active_plan(), empty_progress())
        .with_counterexamples(vec![json!({
            "node_id": "node:plan-1:sg-2",
            "status": "found",
            "summary": "smallest case fails",
            "witness": {"q": 2}
        })]);
    let normalized = normalize_legacy_research(&with_witness).expect("normalization");
    let state = ResearchStateProjector::analyze(normalized.snapshot()).expect("analysis");
    assert_eq!(
        state.nodes()[&node_id("node:plan-1:sg-2")].status(),
        ResearchNodeStatus::Refuted
    );
    assert_eq!(state.attempts()[0].outcome, ResearchAttemptOutcome::Refuted);
    assert!(!state.invalid_routes().is_empty());
}

#[test]
fn retrieval_novelty_counts_registered_reference_ids_not_raw_results() {
    let input = LegacyResearchInput::new("Target", 1, active_plan(), empty_progress())
        .with_registered_reference_ids(vec![
            "ref-a".to_owned(),
            "ref-b".to_owned(),
            "ref-c".to_owned(),
        ])
        .with_events(vec![
            json!({
                "event_type": "external_paper_search",
                "operation": "paper_search",
                "query": "private query text",
                "results": [
                    {"reference_id": "ref-a"},
                    {"reference_id": "ref-b"},
                    {"title": "metadata only"}
                ]
            }),
            json!({
                "event_type": "external_paper_lookup",
                "operation": "paper_lookup",
                "query": "another private query",
                "results": [
                    {"reference_id": "ref-a"},
                    {"reference_id": "ref-c"}
                ]
            }),
        ]);
    let normalized = normalize_legacy_research(&input).expect("normalization");
    assert_eq!(normalized.summary.retrieval_events, 2);
    assert_eq!(normalized.summary.novel_reference_ids, 3);
    assert_eq!(normalized.summary.repeated_reference_ids, 1);
    let state = ResearchStateProjector::project(normalized.snapshot()).expect("projection");
    assert_eq!(state.attempts().len(), 2);
    assert!(
        state
            .attempts()
            .iter()
            .all(|attempt| !attempt.summary.contains("private query"))
    );
    assert_eq!(state.attempts()[0].evidence_ids.len(), 2);
    assert_eq!(state.attempts()[1].evidence_ids.len(), 1);
}

#[test]
fn verification_failures_and_replanning_decisions_are_normalized() {
    let focus = "node:plan-1:sg-1";
    let input = LegacyResearchInput::new("Target", 5, active_plan(), empty_progress())
        .with_failed_paths(vec![json!({
            "record_type": "key_failures_summary",
            "obstruction": "paired factors use an incompatible convention",
            "next_step": "separate the paired case"
        })])
        .with_big_decisions(vec![json!({
            "change": "retain the first local identity",
            "reason": "it remains valid",
            "preserved_node_ids": [focus],
            "selected_focus_node_id": focus,
            "new_constraints": ["treat paired factors separately"]
        })])
        .with_verification_reports(vec![
            json!({
                "verification_report":{
                    "summary":"needs repair",
                    "critical_errors": [{"location": "Lemma 2", "issue": "sign error"}],
                    "gaps": []
                },
                "verdict":"wrong",
                "repair_hints": "Correct the sign in the paired case."
            }),
            json!({
                "critical_errors": [],
                "gaps": [{"location":"Lemma 3","issue":"missing case"}],
                "repair_hints": "Add the missing legacy case."
            }),
        ]);
    let normalized = normalize_legacy_research(&input).expect("normalization");
    let state = ResearchStateProjector::project(normalized.snapshot()).expect("projection");
    assert_eq!(normalized.summary().normalized_decisions(), 1);
    assert_eq!(state.attempts().len(), 3);
    assert_eq!(state.attempts()[1].method, ResearchAttemptMethod::Repair);
    assert_eq!(state.attempts()[2].method, ResearchAttemptMethod::Repair);
    assert_eq!(
        state.decisions()[0]
            .selected_focus_node_id
            .as_ref()
            .map(ResearchNodeId::as_str),
        Some(focus)
    );
    assert!(
        state.decisions()[0]
            .preserved_node_ids
            .contains(&node_id(focus))
    );
}

#[test]
fn malformed_or_collision_prone_legacy_ids_fail_closed() {
    let invalid = json!([{
        "plan_id": "plan-1",
        "subgoals": ["A"],
        "subgoal_ids": ["bad/id"]
    }]);
    assert!(
        normalize_legacy_research(&LegacyResearchInput::new(
            "Target",
            1,
            invalid,
            empty_progress(),
        ))
        .is_err()
    );

    let mismatched = json!([{
        "plan_id": "plan-1",
        "subgoals": ["A", "B"],
        "subgoal_ids": ["sg-1"]
    }]);
    assert!(matches!(
        normalize_legacy_research(&LegacyResearchInput::new(
            "Target",
            1,
            mismatched,
            empty_progress(),
        )),
        Err(ResearchStateError::MalformedLegacyRecord { .. })
    ));

    let ambiguous = json!([{
        "plan_id": "plan:one",
        "subgoals": ["A"],
        "subgoal_ids": ["sg-1"]
    }]);
    assert!(matches!(
        normalize_legacy_research(&LegacyResearchInput::new(
            "Target",
            1,
            ambiguous,
            empty_progress(),
        )),
        Err(ResearchStateError::MalformedLegacyRecord { .. })
    ));
}

#[test]
fn inactive_screening_and_branch_data_produce_bounded_warnings() {
    let input = LegacyResearchInput::new(
        "Target",
        1,
        active_plan(),
        json!({"old-plan": {"old-sg": {"status": "solved"}}}),
    )
    .with_branch_results(vec![json!({
        "branch_id": "old-branch",
        "plan_id": "old-plan",
        "status": "failed",
        "summary": "old failure"
    })]);
    let normalized = normalize_legacy_research(&input).expect("normalization");
    assert_eq!(normalized.warnings().len(), 2);
    assert_eq!(normalized.warnings()[0].code(), "inactive_screening_plan");
    assert_eq!(normalized.warnings()[1].code(), "inactive_branch_plan");
}

#[test]
fn normalization_and_projection_are_deterministic() {
    let input = LegacyResearchInput::new("Target", 2, active_plan(), empty_progress())
        .with_registered_reference_ids(vec!["ref-a".to_owned()])
        .with_events(vec![json!({
            "event_type": "external_theorem_search",
            "operation": "theorem_search",
            "results": [{"reference_id": "ref-a"}]
        })])
        .with_join_result(json!({
            "outcome": "solved",
            "selected_plan_id": "plan-1"
        }));
    let left = normalize_legacy_research(&input).expect("left normalization");
    let right = normalize_legacy_research(&input).expect("right normalization");
    assert_eq!(left.warnings(), right.warnings());
    assert_eq!(left.summary(), right.summary());
    assert_eq!(
        ResearchStateProjector::project(left.snapshot())
            .expect("left projection")
            .digest(),
        ResearchStateProjector::project(right.snapshot())
            .expect("right projection")
            .digest()
    );
}

#[test]
fn join_selected_branch_is_resolved_to_its_plan() {
    let input = LegacyResearchInput::new("Target", 2, active_plan(), empty_progress())
        .with_branch_results(vec![json!({
            "branch_id": "branch-2-1",
            "plan_id": "plan-1",
            "status": "solved",
            "summary": "complete route"
        })])
        .with_join_result(json!({
            "outcome": "solved",
            "selected_branch_id": "branch-2-1"
        }));
    let normalized = normalize_legacy_research(&input).expect("normalization");
    let state = ResearchStateProjector::project(normalized.snapshot()).expect("projection");
    assert_eq!(state.decisions().len(), 1);
    assert_eq!(
        state.decisions()[0]
            .selected_focus_node_id
            .as_ref()
            .map(ResearchNodeId::as_str),
        Some("node:plan-1:sg-2")
    );
    assert!(normalized.warnings().is_empty());
}

#[test]
fn failed_join_with_null_selected_branch_does_not_emit_unknown_branch_warning() {
    let input = LegacyResearchInput::new("Target", 2, active_plan(), empty_progress())
        .with_branch_results(vec![json!({
            "branch_id": "branch-2-1",
            "plan_id": "plan-1",
            "status": "failed",
            "summary": "route remains blocked"
        })])
        .with_join_result(json!({
            "outcome": "failed",
            "selected_branch_id": null,
            "common_failures": ["shared obstruction"]
        }));
    let normalized = normalize_legacy_research(&input).expect("normalization");
    assert!(normalized.warnings().is_empty());
}

#[test]
fn unknown_counterexample_node_cannot_refute_the_target() {
    let input = LegacyResearchInput::new("Target", 1, active_plan(), empty_progress())
        .with_counterexamples(vec![json!({
            "node_id": "node:missing",
            "status": "found",
            "summary": "claimed counterexample for an unknown node",
            "witness": {"q": 2}
        })]);
    let normalized = normalize_legacy_research(&input).expect("normalization");
    let state = ResearchStateProjector::project(normalized.snapshot()).expect("projection");
    assert_eq!(
        state.nodes()[&node_id("target")].status(),
        ResearchNodeStatus::Open
    );
    assert_eq!(
        state.attempts()[0].outcome,
        ResearchAttemptOutcome::Inconclusive
    );
    assert_eq!(
        normalized.warnings()[0].code(),
        "unknown_counterexample_node"
    );
}

#[test]
fn empty_counterexample_witnesses_remain_inconclusive() {
    for witness in [json!("  "), json!([]), json!({}), Value::Null] {
        let input = LegacyResearchInput::new("Target", 1, active_plan(), empty_progress())
            .with_counterexamples(vec![json!({
                "node_id": "node:plan-1:sg-1",
                "status": "found",
                "summary": "claimed counterexample",
                "witness": witness
            })]);
        let normalized = normalize_legacy_research(&input).expect("normalization");
        let state = ResearchStateProjector::project(normalized.snapshot()).expect("projection");
        assert_eq!(
            state.nodes()[&node_id("node:plan-1:sg-1")].status(),
            ResearchNodeStatus::Open
        );
        assert_eq!(
            state.attempts()[0].outcome,
            ResearchAttemptOutcome::Inconclusive
        );
    }
}

#[test]
fn retrieval_ids_must_exist_in_the_authoritative_registry_snapshot() {
    let input = LegacyResearchInput::new("Target", 1, active_plan(), empty_progress())
        .with_registered_reference_ids(vec!["ref-known".to_owned()])
        .with_events(vec![json!({
            "event_type": "external_paper_search",
            "operation": "paper_search",
            "results": [
                {"reference_id": "ref-forged"},
                {"reference_id": "ref-known"}
            ]
        })]);
    let normalized = normalize_legacy_research(&input).expect("normalization");
    assert_eq!(normalized.summary.novel_reference_ids, 1);
    assert_eq!(
        normalized.warnings()[0].code(),
        "unregistered_retrieval_reference"
    );
    let state = ResearchStateProjector::project(normalized.snapshot()).expect("projection");
    assert_eq!(state.attempts()[0].evidence_ids.len(), 1);
    assert!(state.attempts()[0].evidence_ids.contains("ref-known"));
    assert!(!state.attempts()[0].evidence_ids.contains("ref-forged"));
}

#[test]
fn nested_legacy_arrays_have_hard_limits() {
    let too_many_plans = Value::Array(
        (0..=MAX_ACTIVE_PLANS)
            .map(|index| {
                json!({
                    "plan_id": format!("plan-{index}"),
                    "subgoals": ["A"],
                    "subgoal_ids": ["sg-1"]
                })
            })
            .collect(),
    );
    assert!(matches!(
        normalize_legacy_research(&LegacyResearchInput::new(
            "Target",
            1,
            too_many_plans,
            empty_progress(),
        )),
        Err(ResearchStateError::LimitExceeded {
            kind: "legacy_active_plans",
            ..
        })
    ));

    let too_many_results = Value::Array(
        (0..=MAX_NODE_DEPENDENCIES)
            .map(|_| json!({"subgoal_id": "sg-1", "status": "partial"}))
            .collect(),
    );
    let input = LegacyResearchInput::new("Target", 1, active_plan(), empty_progress())
        .with_proof_steps(vec![json!({
            "record_type": "direct_screening_round",
            "plans": [{"plan_id": "plan-1", "subgoal_results": too_many_results}]
        })]);
    assert!(matches!(
        normalize_legacy_research(&input),
        Err(ResearchStateError::LimitExceeded {
            kind: "legacy_direct_screening_results",
            ..
        })
    ));

    let retrieval_results = Value::Array(
        (0..=MAX_RETRIEVAL_RESULTS_PER_EVENT)
            .map(|index| json!({"reference_id": format!("ref-{index}")}))
            .collect(),
    );
    let input =
        LegacyResearchInput::new("Target", 1, active_plan(), empty_progress()).with_events(vec![
            json!({
                "event_type": "external_paper_search",
                "results": retrieval_results
            }),
        ]);
    assert!(matches!(
        normalize_legacy_research(&input),
        Err(ResearchStateError::LimitExceeded {
            kind: "legacy_retrieval_results",
            ..
        })
    ));

    let too_many_branch_labels = Value::Array(
        (0..=MAX_NODE_DEPENDENCIES)
            .map(|index| Value::String(format!("sg-{index}")))
            .collect(),
    );
    let input = LegacyResearchInput::new("Target", 1, active_plan(), empty_progress())
        .with_branch_results(vec![json!({
            "branch_id": "branch-1",
            "plan_id": "plan-1",
            "status": "partial",
            "summary": "too many labels",
            "proved_subgoals": too_many_branch_labels
        })]);
    assert!(matches!(
        normalize_legacy_research(&input),
        Err(ResearchStateError::LimitExceeded {
            kind: "legacy_string_array",
            ..
        })
    ));
}

#[test]
fn normalization_warnings_are_bounded_and_utf8_safe() {
    let events = (0..(MAX_NORMALIZATION_WARNINGS + 50))
        .map(|_| json!({"event_type": "external_paper_search"}))
        .collect();
    let normalized = normalize_legacy_research(
        &LegacyResearchInput::new("Target", 1, active_plan(), empty_progress()).with_events(events),
    )
    .expect("normalization");
    assert_eq!(normalized.warnings().len(), MAX_NORMALIZATION_WARNINGS);
    assert_eq!(
        normalized
            .warnings()
            .last()
            .map(ResearchNormalizationWarning::code),
        Some("warnings_truncated")
    );

    let long_label = "界".repeat(1_000);
    let normalized = normalize_legacy_research(
        &LegacyResearchInput::new("Target", 1, active_plan(), empty_progress())
            .with_branch_results(vec![json!({
                "branch_id": "branch-1",
                "plan_id": "plan-1",
                "status": "partial",
                "summary": "partial",
                "proved_subgoals": [long_label]
            })]),
    )
    .expect("normalization");
    assert!(
        normalized
            .warnings()
            .iter()
            .all(
                |warning| warning.location().len() <= MAX_WARNING_LOCATION_BYTES
                    && warning.message().len() <= MAX_WARNING_MESSAGE_BYTES
            )
    );
}

#[test]
fn retrieval_novelty_count_can_exceed_bounded_attempt_evidence() {
    let reference_ids = (0..40)
        .map(|index| format!("ref-{index}"))
        .collect::<Vec<_>>();
    let results = reference_ids
        .iter()
        .map(|reference_id| json!({"reference_id": reference_id}))
        .collect::<Vec<_>>();
    let normalized = normalize_legacy_research(
        &LegacyResearchInput::new("Target", 1, active_plan(), empty_progress())
            .with_registered_reference_ids(reference_ids)
            .with_events(vec![json!({
                "event_type": "external_paper_search",
                "results": results
            })]),
    )
    .expect("normalization");
    assert_eq!(normalized.summary.novel_reference_ids, 40);
    assert_eq!(
        normalized.snapshot.attempts[0].evidence_ids.len(),
        MAX_EVIDENCE_IDS
    );
    assert!(
        normalized
            .warnings()
            .iter()
            .any(|warning| warning.code() == "retrieval_evidence_truncated")
    );
}

#[test]
fn oversized_legacy_channel_is_rejected_before_projection() {
    let records = vec![json!({"event_type": "exploration"}); MAX_LEGACY_RECORDS_PER_CHANNEL + 1];
    let input =
        LegacyResearchInput::new("Target", 1, active_plan(), empty_progress()).with_events(records);
    assert!(matches!(
        normalize_legacy_research(&input),
        Err(ResearchStateError::LimitExceeded {
            kind: "legacy_events",
            ..
        })
    ));
}
