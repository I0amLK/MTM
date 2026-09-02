use super::*;

fn node_id(value: &str) -> ResearchNodeId {
    ResearchNodeId::parse(value).expect("test node id")
}

fn attempt_id(value: &str) -> ResearchAttemptId {
    ResearchAttemptId::parse(value).expect("test attempt id")
}

fn decision_id(value: &str) -> ResearchDecisionId {
    ResearchDecisionId::parse(value).expect("test decision id")
}

fn domain_id(value: &str) -> ResearchDomainId {
    ResearchDomainId::parse(value).expect("test domain id")
}

fn plan_id(value: &str) -> ResearchPlanId {
    ResearchPlanId::parse(value).expect("test plan id")
}

fn target() -> ResearchNode {
    ResearchNode::new(node_id("target"), "Main claim", ResearchNodeKind::Target)
        .expect("target")
        .with_order(0, 0, 0)
}

fn lemma(value: &str, order: u32) -> ResearchNode {
    plan_lemma(value, "plan-1", 1, order)
}

fn plan_lemma(value: &str, plan: &str, plan_order: u32, node_order: u32) -> ResearchNode {
    ResearchNode::new(
        node_id(value),
        format!("Lemma {value}"),
        ResearchNodeKind::Lemma,
    )
    .expect("lemma")
    .with_plan(plan_id(plan))
    .with_order(1, plan_order, node_order)
}

fn ids(values: &[ResearchNodeId]) -> Vec<&str> {
    values.iter().map(ResearchNodeId::as_str).collect()
}

#[test]
fn enum_wire_values_match_frozen_contract() {
    assert_eq!(ResearchNodeKind::Target.as_str(), "target");
    assert_eq!(ResearchNodeStatus::RouteSolved.as_str(), "route_solved");
    assert_eq!(ResearchAttemptMethod::ToyExample.as_str(), "toy_example");
    assert_eq!(
        ResearchAttemptOutcome::Inconclusive.as_str(),
        "inconclusive"
    );
    assert_eq!(
        ResearchObstruction::IncompatiblePartialResults.as_str(),
        "incompatible_partial_results"
    );
}

#[test]
fn identifiers_fail_closed_on_empty_long_or_unsupported_values() {
    assert!(ResearchNodeId::parse("").is_err());
    assert!(ResearchNodeId::parse("-bad").is_err());
    assert!(ResearchNodeId::parse("bad/path").is_err());
    assert!(ResearchNodeId::parse("x".repeat(MAX_IDENTIFIER_BYTES + 1)).is_err());
    assert_eq!(
        ResearchNodeId::parse("node-1_a.b:c")
            .expect("valid id")
            .as_str(),
        "node-1_a.b:c"
    );
}

#[test]
fn mathematical_text_accepts_utf8_and_rejects_empty_or_nul_content() {
    let unicode = ResearchNode::new(
        node_id("unicode"),
        "证明对所有 $q$ 成立。",
        ResearchNodeKind::Lemma,
    )
    .expect("UTF-8 mathematical statement");
    assert_eq!(unicode.statement(), "证明对所有 $q$ 成立。");
    assert!(ResearchNode::new(node_id("empty"), "  \n", ResearchNodeKind::Lemma).is_err());
    assert!(ResearchNode::new(node_id("nul"), "bad\0statement", ResearchNodeKind::Lemma).is_err());
    assert!(
        ResearchAttempt::new(
            attempt_id("attempt-nul"),
            node_id("unicode"),
            domain_id("generation-domain"),
            ResearchAttemptMethod::Direct,
            ResearchAttemptOutcome::Failed,
            "bad\0summary",
        )
        .is_err()
    );
}

#[test]
fn chain_projection_orders_dependencies_before_target() {
    let first = lemma("a", 1);
    let second = lemma("b", 2).with_dependency(node_id("a"));
    let target = target().with_dependency(node_id("b"));
    let state = ResearchStateProjector::project(
        &ResearchSnapshot::new(node_id("target"))
            .with_node(target)
            .with_node(second)
            .with_node(first)
            .with_active_plan(plan_id("plan-1")),
    )
    .expect("valid projection");
    let golden: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../conformance/golden/mtm009-research-graph-v1.json"
    ))
    .expect("research graph golden fixture");
    let expected = &golden["expected"];
    assert_eq!(state.schema_version(), expected["schema_version"]);
    assert_eq!(
        serde_json::json!(ids(state.graph().topological_order())),
        expected["topological_order"]
    );
    assert_eq!(
        serde_json::json!(ids(state.critical_nodes())),
        expected["critical_nodes"]
    );
    assert_eq!(
        serde_json::json!(ids(state.critical_blockers())),
        expected["critical_blockers"]
    );
    assert_eq!(
        serde_json::json!(ids(state.actionable_frontier())),
        expected["actionable_frontier"]
    );
    let plan_route = &state.plan_routes()[&plan_id("plan-1")];
    let expected_route = &expected["plan_routes"]["plan-1"];
    assert_eq!(
        serde_json::json!(ids(plan_route.goal_node_ids())),
        expected_route["goal_node_ids"]
    );
    assert_eq!(
        serde_json::json!(ids(plan_route.critical_nodes())),
        expected_route["critical_nodes"]
    );
    assert_eq!(
        serde_json::json!(ids(plan_route.blockers())),
        expected_route["blockers"]
    );
    assert_eq!(
        serde_json::json!(ids(plan_route.actionable_frontier())),
        expected_route["actionable_frontier"]
    );
    assert_eq!(
        serde_json::json!(ids(plan_route.invalid_nodes())),
        expected_route["invalid_nodes"]
    );
    assert_eq!(
        plan_route.route_solved(),
        expected_route["route_solved"]
            .as_bool()
            .expect("route_solved")
    );
    assert_eq!(
        state.invalid_routes().len(),
        expected["invalid_route_count"].as_u64().expect("count") as usize
    );
    assert_eq!(state.digest(), expected["digest"].as_str().expect("digest"));
}

#[test]
fn solved_dependency_advances_actionable_frontier() {
    let first = lemma("a", 1).with_status(ResearchNodeStatus::RouteSolved);
    let second = lemma("b", 2).with_dependency(node_id("a"));
    let state = ResearchStateProjector::project(
        &ResearchSnapshot::new(node_id("target"))
            .with_node(target().with_dependency(node_id("b")))
            .with_node(first)
            .with_node(second),
    )
    .expect("valid projection");
    assert_eq!(ids(state.actionable_frontier()), vec!["b"]);
    assert_eq!(ids(state.critical_blockers()), vec!["target", "b"]);
}

#[test]
fn disconnected_nodes_are_not_critical_and_follow_critical_frontier() {
    let state = ResearchStateProjector::project(
        &ResearchSnapshot::new(node_id("target"))
            .with_node(target().with_dependency(node_id("critical")))
            .with_node(lemma("detour", 1))
            .with_node(lemma("critical", 2)),
    )
    .expect("valid projection");
    assert_eq!(ids(state.critical_nodes()), vec!["target", "critical"]);
    assert_eq!(ids(state.actionable_frontier()), vec!["critical", "detour"]);
}

#[test]
fn refuted_dependency_invalidates_all_dependents() {
    let refuted = lemma("a", 1).with_status(ResearchNodeStatus::Refuted);
    let middle = lemma("b", 2).with_dependency(node_id("a"));
    let state = ResearchStateProjector::analyze(
        &ResearchSnapshot::new(node_id("target"))
            .with_node(target().with_dependency(node_id("b")))
            .with_node(refuted)
            .with_node(middle),
    )
    .expect("defensive analysis");
    assert!(state.actionable_frontier().is_empty());
    assert_eq!(
        state
            .invalid_routes()
            .iter()
            .map(|route| route.node_id().as_str())
            .collect::<Vec<_>>(),
        vec!["target", "a", "b"]
    );
    assert!(state.invalid_routes().iter().all(|route| {
        route
            .issues()
            .iter()
            .any(|issue| issue.kind() == RouteIssueKind::RefutedDependency)
    }));
}

#[test]
fn superseded_dependency_is_excluded_and_reported() {
    let old = lemma("old", 1).with_status(ResearchNodeStatus::Superseded);
    let current = lemma("current", 2).with_dependency(node_id("old"));
    let state = ResearchStateProjector::analyze(
        &ResearchSnapshot::new(node_id("target"))
            .with_node(target().with_dependency(node_id("current")))
            .with_node(old)
            .with_node(current),
    )
    .expect("defensive analysis");
    assert!(!state.graph().dependencies().contains_key(&node_id("old")));
    assert_eq!(state.invalid_routes().len(), 2);
    assert!(state.invalid_routes().iter().all(|route| {
        route
            .issues()
            .iter()
            .any(|issue| issue.kind() == RouteIssueKind::SupersededDependency)
    }));
}

#[test]
fn cycle_analysis_is_deterministic_and_strict_projection_rejects_it() {
    let left = lemma("a", 1).with_dependency(node_id("b"));
    let right = lemma("b", 2).with_dependency(node_id("a"));
    let snapshot = ResearchSnapshot::new(node_id("target"))
        .with_node(target().with_dependency(node_id("a")))
        .with_node(right)
        .with_node(left);
    let state = ResearchStateProjector::analyze(&snapshot).expect("cycle analysis");
    assert_eq!(state.graph().cycle_components().len(), 1);
    assert_eq!(ids(&state.graph().cycle_components()[0]), vec!["a", "b"]);
    assert_eq!(ids(state.graph().topological_order()), Vec::<&str>::new());
    assert!(matches!(
        ResearchStateProjector::project(&snapshot),
        Err(ResearchStateError::ActiveDependencyCycle { .. })
    ));
}

#[test]
fn self_loop_is_a_cycle() {
    let loop_node = lemma("loop", 1).with_dependency(node_id("loop"));
    let snapshot = ResearchSnapshot::new(node_id("target"))
        .with_node(target().with_dependency(node_id("loop")))
        .with_node(loop_node);
    let state = ResearchStateProjector::analyze(&snapshot).expect("self-loop analysis");
    assert_eq!(ids(&state.graph().cycle_components()[0]), vec!["loop"]);
    assert!(ResearchStateProjector::project(&snapshot).is_err());
}

#[test]
fn unknown_dependency_fails_closed() {
    let snapshot = ResearchSnapshot::new(node_id("target"))
        .with_node(target().with_dependency(node_id("missing")));
    assert!(matches!(
        ResearchStateProjector::project(&snapshot),
        Err(ResearchStateError::UnknownDependency { .. })
    ));
}

#[test]
fn duplicate_node_attempt_and_decision_ids_fail_closed() {
    let duplicate_nodes = ResearchSnapshot::new(node_id("target"))
        .with_node(target())
        .with_node(target());
    assert!(matches!(
        ResearchStateProjector::project(&duplicate_nodes),
        Err(ResearchStateError::DuplicateIdentifier {
            kind: "research_node_id",
            ..
        })
    ));

    let attempt = ResearchAttempt::new(
        attempt_id("attempt-1"),
        node_id("target"),
        domain_id("generation-domain"),
        ResearchAttemptMethod::Direct,
        ResearchAttemptOutcome::Progress,
        "progress",
    )
    .expect("attempt");
    let duplicate_attempts = ResearchSnapshot::new(node_id("target"))
        .with_node(target())
        .with_attempt(attempt.clone())
        .with_attempt(attempt);
    assert!(matches!(
        ResearchStateProjector::project(&duplicate_attempts),
        Err(ResearchStateError::DuplicateIdentifier {
            kind: "research_attempt_id",
            ..
        })
    ));

    let decision = ResearchDecision::new(decision_id("decision-1"), "replan").expect("decision");
    let duplicate_decisions = ResearchSnapshot::new(node_id("target"))
        .with_node(target())
        .with_decision(decision.clone())
        .with_decision(decision);
    assert!(matches!(
        ResearchStateProjector::project(&duplicate_decisions),
        Err(ResearchStateError::DuplicateIdentifier {
            kind: "research_decision_id",
            ..
        })
    ));
}

#[test]
fn attempt_and_decision_references_are_validated() {
    let attempt = ResearchAttempt::new(
        attempt_id("attempt-1"),
        node_id("missing"),
        domain_id("generation-domain"),
        ResearchAttemptMethod::Direct,
        ResearchAttemptOutcome::Failed,
        "failed",
    )
    .expect("attempt");
    let snapshot = ResearchSnapshot::new(node_id("target"))
        .with_node(target())
        .with_attempt(attempt);
    assert!(matches!(
        ResearchStateProjector::project(&snapshot),
        Err(ResearchStateError::UnknownAttemptNode { .. })
    ));

    let decision = ResearchDecision::new(decision_id("decision-1"), "preserve")
        .expect("decision")
        .preserve_node(node_id("missing"));
    let snapshot = ResearchSnapshot::new(node_id("target"))
        .with_node(target())
        .with_decision(decision);
    assert!(matches!(
        ResearchStateProjector::project(&snapshot),
        Err(ResearchStateError::UnknownDecisionNode { .. })
    ));
}

#[test]
fn target_rules_fail_closed() {
    let no_target = ResearchSnapshot::new(node_id("target")).with_node(lemma("a", 1));
    assert_eq!(
        ResearchStateProjector::project(&no_target),
        Err(ResearchStateError::MissingTarget)
    );

    let multiple = ResearchSnapshot::new(node_id("target"))
        .with_node(target())
        .with_node(
            ResearchNode::new(node_id("target-2"), "Other", ResearchNodeKind::Target)
                .expect("second target"),
        );
    assert_eq!(
        ResearchStateProjector::project(&multiple),
        Err(ResearchStateError::MultipleTargets)
    );

    let wrong_selected_target = ResearchSnapshot::new(node_id("selected-lemma"))
        .with_node(
            ResearchNode::new(
                node_id("real-target"),
                "Real target",
                ResearchNodeKind::Target,
            )
            .expect("real target"),
        )
        .with_node(
            ResearchNode::new(
                node_id("selected-lemma"),
                "Not the target",
                ResearchNodeKind::Lemma,
            )
            .expect("selected lemma"),
        );
    assert_eq!(
        ResearchStateProjector::project(&wrong_selected_target),
        Err(ResearchStateError::TargetKindMismatch)
    );

    let superseded = ResearchSnapshot::new(node_id("target"))
        .with_node(target().with_status(ResearchNodeStatus::Superseded));
    assert_eq!(
        ResearchStateProjector::project(&superseded),
        Err(ResearchStateError::SupersededTarget)
    );
}

#[test]
fn node_and_attempt_limits_fail_closed() {
    let mut snapshot = ResearchSnapshot::new(node_id("target")).with_node(target());
    for index in 0..MAX_RESEARCH_NODES {
        snapshot = snapshot.with_node(lemma(&format!("n-{index}"), index as u32));
    }
    assert!(matches!(
        ResearchStateProjector::project(&snapshot),
        Err(ResearchStateError::LimitExceeded {
            kind: "research_nodes",
            ..
        })
    ));

    let mut attempt = ResearchAttempt::new(
        attempt_id("attempt-evidence"),
        node_id("target"),
        domain_id("generation-domain"),
        ResearchAttemptMethod::Computation,
        ResearchAttemptOutcome::Inconclusive,
        "bounded computation",
    )
    .expect("attempt");
    for index in 0..MAX_EVIDENCE_IDS {
        attempt = attempt
            .with_evidence(format!("evidence-{index}"))
            .expect("bounded evidence");
    }
    assert!(attempt.with_evidence("one-too-many").is_err());
}

#[test]
fn canonical_digest_is_independent_of_input_order() {
    let attempt_a = ResearchAttempt::new(
        attempt_id("attempt-a"),
        node_id("a"),
        domain_id("generation-domain"),
        ResearchAttemptMethod::Direct,
        ResearchAttemptOutcome::Progress,
        "partial route",
    )
    .expect("attempt")
    .with_position(1, 2);
    let attempt_b = ResearchAttempt::new(
        attempt_id("attempt-b"),
        node_id("b"),
        domain_id("generation-domain"),
        ResearchAttemptMethod::Reduction,
        ResearchAttemptOutcome::Failed,
        "blocked",
    )
    .expect("attempt")
    .with_position(1, 1);
    let a = lemma("a", 1);
    let b = lemma("b", 2);
    let target = target().with_dependency(node_id("a"));
    let left = ResearchSnapshot::new(node_id("target"))
        .with_node(target.clone())
        .with_node(a.clone())
        .with_node(b.clone())
        .with_attempt(attempt_a.clone())
        .with_attempt(attempt_b.clone());
    let right = ResearchSnapshot::new(node_id("target"))
        .with_node(b)
        .with_node(a)
        .with_node(target)
        .with_attempt(attempt_b)
        .with_attempt(attempt_a);
    let left = ResearchStateProjector::project(&left).expect("left");
    let right = ResearchStateProjector::project(&right).expect("right");
    assert_eq!(left.digest(), right.digest());
    assert_eq!(left, right);
}

#[test]
fn digest_changes_when_mathematical_status_changes() {
    let open = ResearchSnapshot::new(node_id("target"))
        .with_node(target().with_dependency(node_id("a")))
        .with_node(lemma("a", 1));
    let solved = ResearchSnapshot::new(node_id("target"))
        .with_node(target().with_dependency(node_id("a")))
        .with_node(lemma("a", 1).with_status(ResearchNodeStatus::RouteSolved));
    assert_ne!(
        ResearchStateProjector::project(&open)
            .expect("open")
            .digest(),
        ResearchStateProjector::project(&solved)
            .expect("solved")
            .digest()
    );
}

#[test]
fn decisions_and_attempts_are_canonically_sorted() {
    let attempt_late = ResearchAttempt::new(
        attempt_id("attempt-late"),
        node_id("target"),
        domain_id("generation-domain"),
        ResearchAttemptMethod::Synthesis,
        ResearchAttemptOutcome::Progress,
        "late",
    )
    .expect("attempt")
    .with_position(2, 5);
    let attempt_early = ResearchAttempt::new(
        attempt_id("attempt-early"),
        node_id("target"),
        domain_id("generation-domain"),
        ResearchAttemptMethod::Direct,
        ResearchAttemptOutcome::Failed,
        "early",
    )
    .expect("attempt")
    .with_position(1, 9);
    let decision_late = ResearchDecision::new(decision_id("decision-late"), "late")
        .expect("decision")
        .with_event_seq(10);
    let decision_early = ResearchDecision::new(decision_id("decision-early"), "early")
        .expect("decision")
        .with_event_seq(3);
    let state = ResearchStateProjector::project(
        &ResearchSnapshot::new(node_id("target"))
            .with_node(target())
            .with_attempt(attempt_late)
            .with_attempt(attempt_early)
            .with_decision(decision_late)
            .with_decision(decision_early),
    )
    .expect("projection");
    assert_eq!(
        state
            .attempts()
            .iter()
            .map(|attempt| attempt.attempt_id().as_str())
            .collect::<Vec<_>>(),
        vec!["attempt-early", "attempt-late"]
    );
    assert_eq!(
        state
            .decisions()
            .iter()
            .map(|decision| decision.decision_id.as_str())
            .collect::<Vec<_>>(),
        vec!["decision-early", "decision-late"]
    );
}

#[test]
fn active_and_decision_plan_references_fail_closed() {
    let unknown_active = ResearchSnapshot::new(node_id("target"))
        .with_node(target())
        .with_active_plan(plan_id("missing-plan"));
    assert!(matches!(
        ResearchStateProjector::project(&unknown_active),
        Err(ResearchStateError::UnknownActivePlan { .. })
    ));

    let unknown_decision = ResearchDecision::new(decision_id("decision-plan"), "replace route")
        .expect("decision")
        .supersede_plan(plan_id("missing-plan"));
    let snapshot = ResearchSnapshot::new(node_id("target"))
        .with_node(target())
        .with_node(lemma("a", 1))
        .with_active_plan(plan_id("plan-1"))
        .with_decision(unknown_decision);
    assert!(matches!(
        ResearchStateProjector::project(&snapshot),
        Err(ResearchStateError::UnknownDecisionPlan { .. })
    ));
}

#[test]
fn revision_zero_fails_closed() {
    let mut invalid_target = target();
    invalid_target.revision = 0;
    let snapshot = ResearchSnapshot::new(node_id("target")).with_node(invalid_target);
    assert!(matches!(
        ResearchStateProjector::project(&snapshot),
        Err(ResearchStateError::InvalidRevision { .. })
    ));
}

#[test]
fn canonical_text_trims_outer_whitespace() {
    let plain = ResearchSnapshot::new(node_id("target"))
        .with_node(
            ResearchNode::new(node_id("target"), "Main claim", ResearchNodeKind::Target)
                .expect("plain target"),
        )
        .with_attempt(
            ResearchAttempt::new(
                attempt_id("attempt-1"),
                node_id("target"),
                domain_id("generation-domain"),
                ResearchAttemptMethod::Direct,
                ResearchAttemptOutcome::Progress,
                "usable reduction",
            )
            .expect("plain attempt"),
        )
        .with_decision(
            ResearchDecision::new(decision_id("decision-1"), "retain reduction")
                .expect("plain decision"),
        );
    let padded = ResearchSnapshot::new(node_id("target"))
        .with_node(
            ResearchNode::new(
                node_id("target"),
                "  Main claim\n",
                ResearchNodeKind::Target,
            )
            .expect("padded target"),
        )
        .with_attempt(
            ResearchAttempt::new(
                attempt_id("attempt-1"),
                node_id("target"),
                domain_id("generation-domain"),
                ResearchAttemptMethod::Direct,
                ResearchAttemptOutcome::Progress,
                "  usable reduction  ",
            )
            .expect("padded attempt"),
        )
        .with_decision(
            ResearchDecision::new(decision_id("decision-1"), " retain reduction ")
                .expect("padded decision"),
        );
    assert_eq!(
        ResearchStateProjector::project(&plain)
            .expect("plain state")
            .digest(),
        ResearchStateProjector::project(&padded)
            .expect("padded state")
            .digest()
    );
}

#[test]
fn per_record_and_global_edge_limits_fail_closed() {
    let mut oversized = lemma("oversized", 1);
    for index in 0..=MAX_NODE_DEPENDENCIES {
        oversized = oversized.with_dependency(node_id(&format!("base-{index}")));
    }
    let mut snapshot = ResearchSnapshot::new(node_id("target"))
        .with_node(target())
        .with_node(oversized);
    for index in 0..=MAX_NODE_DEPENDENCIES {
        snapshot = snapshot.with_node(lemma(&format!("base-{index}"), index as u32 + 2));
    }
    assert!(matches!(
        ResearchStateProjector::project(&snapshot),
        Err(ResearchStateError::LimitExceeded {
            kind: "node_dependencies",
            ..
        })
    ));

    let mut global = ResearchSnapshot::new(node_id("target")).with_node(target());
    for index in 0..MAX_NODE_DEPENDENCIES {
        global = global.with_node(lemma(&format!("root-{index}"), index as u32));
    }
    for dependent in 0..17 {
        let mut node = lemma(&format!("dependent-{dependent}"), dependent as u32 + 100);
        for dependency in 0..MAX_NODE_DEPENDENCIES {
            node = node.with_dependency(node_id(&format!("root-{dependency}")));
        }
        global = global.with_node(node);
    }
    assert!(matches!(
        ResearchStateProjector::project(&global),
        Err(ResearchStateError::LimitExceeded {
            kind: "research_edges",
            ..
        })
    ));
}

#[test]
fn alternative_plans_remain_disjunctive() {
    let failed_route =
        plan_lemma("route-a-goal", "plan-a", 1, 1).with_status(ResearchNodeStatus::Refuted);
    let solved_route =
        plan_lemma("route-b-goal", "plan-b", 2, 1).with_status(ResearchNodeStatus::RouteSolved);
    let state = ResearchStateProjector::project(
        &ResearchSnapshot::new(node_id("target"))
            .with_node(target())
            .with_node(failed_route)
            .with_node(solved_route)
            .with_active_plan(plan_id("plan-a"))
            .with_active_plan(plan_id("plan-b")),
    )
    .expect("alternative routes");

    let route_a = &state.plan_routes()[&plan_id("plan-a")];
    let route_b = &state.plan_routes()[&plan_id("plan-b")];
    assert!(!route_a.route_solved());
    assert_eq!(ids(route_a.goal_node_ids()), vec!["route-a-goal"]);
    assert_eq!(ids(route_a.invalid_nodes()), vec!["route-a-goal"]);
    assert!(route_b.route_solved());
    assert_eq!(ids(route_b.goal_node_ids()), vec!["route-b-goal"]);
    assert!(route_b.blockers().is_empty());
    assert!(route_b.invalid_nodes().is_empty());
    assert!(
        state
            .invalid_routes()
            .iter()
            .all(|route| route.node_id().as_str() != "target")
    );
    assert!(state.actionable_frontier().is_empty());
}

#[test]
fn plan_goals_are_terminal_nodes_within_the_plan() {
    let first = plan_lemma("first", "plan-1", 1, 1);
    let middle = plan_lemma("middle", "plan-1", 1, 2).with_dependency(node_id("first"));
    let last = plan_lemma("last", "plan-1", 1, 3).with_dependency(node_id("middle"));
    let side = plan_lemma("side", "plan-1", 1, 4).with_dependency(node_id("first"));
    let state = ResearchStateProjector::project(
        &ResearchSnapshot::new(node_id("target"))
            .with_node(target())
            .with_node(first)
            .with_node(middle)
            .with_node(last)
            .with_node(side)
            .with_active_plan(plan_id("plan-1")),
    )
    .expect("plan route");
    let route = &state.plan_routes()[&plan_id("plan-1")];
    assert_eq!(ids(route.goal_node_ids()), vec!["last", "side"]);
    assert_eq!(ids(route.actionable_frontier()), vec!["first"]);
    assert_eq!(
        ids(route.critical_nodes()),
        vec!["first", "middle", "last", "side"]
    );
}

#[test]
fn a_route_is_not_solved_while_a_required_dependency_is_open() {
    let dependency = plan_lemma("dependency", "plan-1", 1, 1);
    let goal = plan_lemma("goal", "plan-1", 1, 2)
        .with_dependency(node_id("dependency"))
        .with_status(ResearchNodeStatus::RouteSolved);
    let state = ResearchStateProjector::project(
        &ResearchSnapshot::new(node_id("target"))
            .with_node(target())
            .with_node(dependency)
            .with_node(goal)
            .with_active_plan(plan_id("plan-1")),
    )
    .expect("incomplete route");
    let route = &state.plan_routes()[&plan_id("plan-1")];
    assert!(!route.route_solved());
    assert_eq!(ids(route.blockers()), vec!["dependency"]);
}

#[test]
fn disjoint_cycles_are_reported_in_stable_order() {
    let a = plan_lemma("a", "plan-1", 1, 1).with_dependency(node_id("b"));
    let b = plan_lemma("b", "plan-1", 1, 2).with_dependency(node_id("a"));
    let c = plan_lemma("c", "plan-2", 2, 1).with_dependency(node_id("d"));
    let d = plan_lemma("d", "plan-2", 2, 2).with_dependency(node_id("c"));
    let state = ResearchStateProjector::analyze(
        &ResearchSnapshot::new(node_id("target"))
            .with_node(target())
            .with_node(d)
            .with_node(b)
            .with_node(c)
            .with_node(a)
            .with_active_plan(plan_id("plan-2"))
            .with_active_plan(plan_id("plan-1")),
    )
    .expect("cycle analysis");
    assert_eq!(
        state
            .graph()
            .cycle_components()
            .iter()
            .map(|component| ids(component))
            .collect::<Vec<_>>(),
        vec![vec!["a", "b"], vec!["c", "d"]]
    );
}

#[test]
fn all_small_ordered_dags_have_valid_deterministic_topological_orders() {
    const NODE_COUNT: usize = 5;
    let possible_edges = (0..NODE_COUNT)
        .flat_map(|dependency| {
            ((dependency + 1)..NODE_COUNT).map(move |dependent| (dependency, dependent))
        })
        .collect::<Vec<_>>();
    for mask in 0usize..(1usize << possible_edges.len()) {
        let mut nodes = (0..NODE_COUNT)
            .map(|index| {
                let kind = if index + 1 == NODE_COUNT {
                    ResearchNodeKind::Target
                } else {
                    ResearchNodeKind::Lemma
                };
                ResearchNode::new(
                    node_id(&format!("n-{index}")),
                    format!("Node {index}"),
                    kind,
                )
                .expect("small DAG node")
                .with_order(0, 0, index as u32)
            })
            .collect::<Vec<_>>();
        for (bit, (dependency, dependent)) in possible_edges.iter().enumerate() {
            if mask & (1usize << bit) != 0 {
                nodes[*dependent] = nodes[*dependent]
                    .clone()
                    .with_dependency(node_id(&format!("n-{dependency}")));
            }
        }
        let forward = nodes.iter().cloned().fold(
            ResearchSnapshot::new(node_id("n-4")),
            ResearchSnapshot::with_node,
        );
        let reverse = nodes.iter().rev().cloned().fold(
            ResearchSnapshot::new(node_id("n-4")),
            ResearchSnapshot::with_node,
        );
        let forward = ResearchStateProjector::project(&forward).expect("forward DAG");
        let reverse = ResearchStateProjector::project(&reverse).expect("reverse DAG");
        assert_eq!(forward.digest(), reverse.digest(), "mask={mask}");
        assert_eq!(forward.graph().topological_order().len(), NODE_COUNT);
        let positions = forward
            .graph()
            .topological_order()
            .iter()
            .enumerate()
            .map(|(index, node_id)| (node_id.as_str(), index))
            .collect::<std::collections::BTreeMap<_, _>>();
        for (dependent, dependencies) in forward.graph().dependencies() {
            for dependency in dependencies {
                assert!(
                    positions[dependency.as_str()] < positions[dependent.as_str()],
                    "mask={mask}, dependency={dependency}, dependent={dependent}"
                );
            }
        }
    }
}
