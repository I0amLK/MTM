#![allow(clippy::expect_used)]

use serde_json::{Value, json};

use super::*;

fn plans() -> Value {
    json!([
        {
            "plan_id": "route-a",
            "summary": "First route",
            "subgoals": [
                {
                    "key": "local",
                    "statement": "Establish the local identity.",
                    "depends_on": [],
                    "critical": true,
                    "kind": "lemma"
                },
                {
                    "key": "sum",
                    "statement": "Sum the local identities.",
                    "depends_on": ["local"],
                    "critical": true
                }
            ],
            "motivation": ["Matches the decomposition."],
            "dependencies": [],
            "risks": ["Duality convention."]
        },
        {
            "summary": "Second route",
            "subgoals": [
                {
                    "key": "global",
                    "statement": "Prove the result globally.",
                    "depends_on": [],
                    "critical": true,
                    "kind": "construction"
                }
            ],
            "motivation": [],
            "dependencies": [],
            "risks": []
        }
    ])
}

fn normalized_plans() -> Vec<Value> {
    normalize_protocol3_plans(Some(&plans()), 2).expect("plans normalize")
}

fn scope() -> ProtocolResearchScope {
    ProtocolResearchScope::from_active_plans(
        &Value::Array(normalized_plans()),
        ["ref-1".to_owned(), "ref-2".to_owned()],
    )
    .expect("scope")
}

fn stamp() -> ProtocolRecordStamp<'static> {
    ProtocolRecordStamp {
        record_id: "record-1",
        actor_role: "generator",
        actor_domain_id: "generation-domain",
        round_index: 2,
        created_at: "2026-09-02T00:00:00Z",
    }
}

#[test]
fn structured_plans_receive_canonical_node_dependencies() {
    let plans = normalized_plans();
    assert_eq!(plans[0]["plan_id"], "plan-r2-1");
    assert_eq!(plans[0]["source_plan_id"], "route-a");
    assert_eq!(plans[0]["subgoal_ids"], json!(["sg-1", "sg-2"]));
    assert_eq!(
        plans[0]["research_subgoals"][1]["depends_on"],
        json!(["node:plan-r2-1:sg-1"])
    );
    assert_eq!(plans[1]["research_subgoals"][0]["kind"], "construction");
}

#[test]
fn plan_local_graph_rejects_unknown_self_cycle_duplicate_and_extra_fields() {
    let cases = [
        json!([
            {"summary":"A","subgoals":[{"key":"a","statement":"A","depends_on":["missing"],"critical":true}]},
            {"summary":"B","subgoals":[{"key":"b","statement":"B","depends_on":[],"critical":true}]}
        ]),
        json!([
            {"summary":"A","subgoals":[{"key":"a","statement":"A","depends_on":["a"],"critical":true}]},
            {"summary":"B","subgoals":[{"key":"b","statement":"B","depends_on":[],"critical":true}]}
        ]),
        json!([
            {"summary":"A","subgoals":[
                {"key":"a","statement":"A","depends_on":["b"],"critical":true},
                {"key":"b","statement":"B","depends_on":["a"],"critical":true}
            ]},
            {"summary":"B","subgoals":[{"key":"c","statement":"C","depends_on":[],"critical":true}]}
        ]),
        json!([
            {"summary":"A","subgoals":[
                {"key":"a","statement":"A","depends_on":[],"critical":true},
                {"key":"a","statement":"Again","depends_on":[],"critical":true}
            ]},
            {"summary":"B","subgoals":[{"key":"b","statement":"B","depends_on":[],"critical":true}]}
        ]),
        json!([
            {"summary":"A","unknown":true,"subgoals":[{"key":"a","statement":"A","depends_on":[],"critical":true}]},
            {"summary":"B","subgoals":[{"key":"b","statement":"B","depends_on":[],"critical":true}]}
        ]),
    ];
    for case in cases {
        assert!(matches!(
            normalize_protocol3_plans(Some(&case), 1),
            Err(ResearchStateError::MalformedProtocolRecord { .. })
        ));
    }
}

#[test]
fn local_keys_are_unambiguous_and_plan_counts_are_bounded() {
    let invalid = json!([
        {"summary":"A","subgoals":[{"key":"a:b","statement":"A","depends_on":[],"critical":true}]},
        {"summary":"B","subgoals":[{"key":"b","statement":"B","depends_on":[],"critical":true}]}
    ]);
    assert!(normalize_protocol3_plans(Some(&invalid), 1).is_err());

    let too_many = Value::Array(
        (0..=MAX_ACTIVE_PLANS)
            .map(|index| {
                json!({
                    "summary":format!("Plan {index}"),
                    "subgoals":[{"key":"a","statement":"A","depends_on":[],"critical":true}]
                })
            })
            .collect(),
    );
    assert!(matches!(
        normalize_protocol3_plans(Some(&too_many), 1),
        Err(ResearchStateError::LimitExceeded {
            kind: "protocol3_plans",
            ..
        })
    ));
}

#[test]
fn protocol_scope_rejects_duplicate_or_missing_canonical_nodes() {
    let plans = normalized_plans();
    let scope = ProtocolResearchScope::from_active_plans(
        &Value::Array(plans.clone()),
        ["ref-1".to_owned()],
    )
    .expect("scope");
    assert!(scope.contains_plan(&ResearchPlanId::parse("plan-r2-1").expect("plan")));
    assert!(scope.contains_node(&ResearchNodeId::parse("node:plan-r2-1:sg-2").expect("node")));

    let mut malformed = plans;
    malformed[0]["research_subgoals"][1]["node_id"] =
        malformed[0]["research_subgoals"][0]["node_id"].clone();
    assert!(
        ProtocolResearchScope::from_active_plans(&Value::Array(malformed), std::iter::empty(),)
            .is_err()
    );
}

#[test]
fn screening_fields_are_typed_and_status_consistent() {
    let fields = protocol3_screening_fields(
        json!({
            "status":"stuck",
            "summary":"missing input",
            "method":"reduction",
            "obstruction":"missing_lemma",
            "evidence_ids":["record-1"]
        })
        .as_object()
        .expect("object"),
        "stuck",
        "screening",
    )
    .expect("screening fields");
    assert_eq!(fields.method, ResearchAttemptMethod::Reduction);
    assert_eq!(fields.obstruction, Some(ResearchObstruction::MissingLemma));

    let missing_obstruction = json!({"status":"stuck","summary":"stuck"});
    assert!(
        protocol3_screening_fields(
            missing_obstruction.as_object().expect("object"),
            "stuck",
            "screening"
        )
        .is_err()
    );
    let solved_with_obstruction =
        json!({"status":"solved","summary":"done","obstruction":"no_progress"});
    assert!(
        protocol3_screening_fields(
            solved_with_obstruction.as_object().expect("object"),
            "solved",
            "screening"
        )
        .is_err()
    );
    let unknown = json!({"status":"partial","summary":"x","method":"future"});
    assert!(
        protocol3_screening_fields(unknown.as_object().expect("object"), "partial", "screening")
            .is_err()
    );
}

#[test]
fn counterexample_records_require_known_node_scope_and_witness() {
    let scope = scope();
    let record = normalize_protocol3_generation_record(
        "counterexamples",
        &json!({
            "node_id":"node:plan-r2-1:sg-1",
            "outcome":"found",
            "summary":"fails in the smallest case",
            "probe_scope":"q=2",
            "witness":"explicit matrix",
            "evidence_ids":["calc-1"]
        }),
        &stamp(),
        &scope,
    )
    .expect("counterexample");
    assert_eq!(record["record_type"], "counterexample_probe");
    assert_eq!(record["obstruction_class"], "false_claim");
    assert_eq!(record["record_id"], "record-1");

    let missing_witness = json!({
        "node_id":"node:plan-r2-1:sg-1",
        "outcome":"found",
        "summary":"claimed",
        "probe_scope":"small cases"
    });
    assert!(
        normalize_protocol3_generation_record(
            "counterexamples",
            &missing_witness,
            &stamp(),
            &scope
        )
        .is_err()
    );
    let unknown_node = json!({
        "node_id":"node:missing",
        "outcome":"inconclusive",
        "summary":"none",
        "probe_scope":"small cases"
    });
    assert!(
        normalize_protocol3_generation_record("counterexamples", &unknown_node, &stamp(), &scope)
            .is_err()
    );
}

#[test]
fn retrieval_assessment_requires_registered_references() {
    let scope = scope();
    let record = normalize_protocol3_generation_record(
        "events",
        &json!({
            "event_type":"retrieval_assessment",
            "node_id":"node:plan-r2-1:sg-1",
            "outcome":"new_material",
            "summary":"found the missing theorem",
            "query":"constituent rank identity",
            "reference_ids":["ref-1"]
        }),
        &stamp(),
        &scope,
    )
    .expect("retrieval record");
    assert_eq!(record["reference_ids"], json!(["ref-1"]));

    let forged = json!({
        "event_type":"retrieval_assessment",
        "outcome":"new_material",
        "summary":"claimed source",
        "reference_ids":["ref-forged"]
    });
    assert!(normalize_protocol3_generation_record("events", &forged, &stamp(), &scope).is_err());
}

#[test]
fn candidate_lemma_and_notation_events_are_strictly_bounded() {
    let scope = scope();
    let candidate = normalize_protocol3_generation_record(
        "events",
        &json!({
            "event_type":"new_candidate_lemma",
            "statement":"A reusable local lemma.",
            "summary":"isolates the paired-factor case",
            "depends_on":["node:plan-r2-1:sg-1"],
            "critical":true,
            "kind":"lemma",
            "evidence_ids":[]
        }),
        &stamp(),
        &scope,
    )
    .expect("candidate");
    assert_eq!(candidate["candidate_id"], "record-1");

    let notation = normalize_protocol3_generation_record(
        "events",
        &json!({
            "event_type":"notation_resolution",
            "symbol":"rho",
            "resolution":"rank of the restricted form",
            "summary":"fixed the convention"
        }),
        &stamp(),
        &scope,
    )
    .expect("notation");
    assert_eq!(notation["record_type"], "notation_resolution");
}

#[test]
fn branch_obstructions_cannot_cross_plan_boundaries() {
    let scope = scope();
    let plan = ResearchPlanId::parse("plan-r2-1").expect("plan");
    let normalized = normalize_protocol3_branch_obstructions(
        Some(&json!([{
            "node_id":"node:plan-r2-1:sg-2",
            "class":"missing_lemma",
            "summary":"paired case missing",
            "evidence_ids":[]
        }])),
        &scope,
        &plan,
        "branch.obstructions",
    )
    .expect("obstructions");
    assert_eq!(normalized[0]["class"], "missing_lemma");

    let cross_plan = json!([{
        "node_id":"node:plan-r2-2:sg-1",
        "class":"no_progress",
        "summary":"wrong branch"
    }]);
    assert!(
        normalize_protocol3_branch_obstructions(
            Some(&cross_plan),
            &scope,
            &plan,
            "branch.obstructions"
        )
        .is_err()
    );
}

#[test]
fn failure_and_replan_records_require_canonical_scope() {
    let scope = scope();
    let failure = normalize_protocol3_failure_summary(
        &json!({
            "obstruction":"paired factors remain",
            "next_step":"replace the global route",
            "affected_node_ids":["node:plan-r2-1:sg-2"],
            "obstruction_class":"missing_lemma",
            "excluded_plan_ids":["plan-r2-2"],
            "preserved_node_ids":["node:plan-r2-1:sg-1"],
            "required_hypotheses":[],
            "required_reference_queries":["paired factor duality"],
            "selected_focus_node_id":"node:plan-r2-1:sg-2"
        }),
        &scope,
    )
    .expect("failure");
    assert_eq!(failure["obstruction_class"], "missing_lemma");

    let decision = normalize_protocol3_replan_decision(
        &json!({
            "reason":"preserve the local lemma and replace route two",
            "superseded_plan_ids":["plan-r2-2"],
            "preserved_node_ids":["node:plan-r2-1:sg-1"],
            "new_constraints":["respect paired-factor duality"],
            "selected_focus_node_id":"node:plan-r2-1:sg-2"
        }),
        &scope,
    )
    .expect("decision");
    assert_eq!(decision["superseded_plan_ids"], json!(["plan-r2-2"]));

    let unknown = json!({
        "reason":"bad",
        "selected_focus_node_id":"node:missing"
    });
    assert!(normalize_protocol3_replan_decision(&unknown, &scope).is_err());
}

#[test]
fn server_record_fields_cannot_be_supplied_by_the_client() {
    let stamped = stamp_protocol3_record("failure_summary", &json!({"summary":"x"}), &stamp())
        .expect("stamp");
    assert_eq!(stamped["actor_role"], "generator");
    assert_eq!(stamped["round_index"], 2);

    assert!(
        stamp_protocol3_record("failure_summary", &json!({"record_id":"forged"}), &stamp())
            .is_err()
    );
}
