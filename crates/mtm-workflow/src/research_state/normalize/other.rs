use super::support::{meaningful_witness, resolve_canonical_node};
use super::*;

#[derive(Default)]
pub(super) struct RetrievalCounts {
    pub(super) events: usize,
    pub(super) novel: usize,
    pub(super) repeated: usize,
}

pub(super) fn normalize_counterexamples(
    input: &LegacyResearchInput,
    nodes: &mut BTreeMap<ResearchNodeId, ResearchNode>,
    target_id: &ResearchNodeId,
    attempts: &mut Vec<ResearchAttempt>,
    sequence: &mut u64,
    warnings: &mut WarningCollector,
) -> Result<(), ResearchStateError> {
    let actor = ResearchDomainId::parse("legacy-generation")?;
    for (index, record) in input.counterexamples.iter().enumerate() {
        let location = format!("counterexamples[{index}]");
        let summary = extract_summary(record).unwrap_or("Counterexample probe was inconclusive.");
        let explicit_node = record.get("node_id").is_some();
        let resolved_node = resolve_canonical_node(record.get("node_id"), nodes);
        let node_reference_valid = !explicit_node || resolved_node.is_some();
        let node_id = resolved_node.unwrap_or_else(|| target_id.clone());
        if !node_reference_valid {
            warnings.push(
                "unknown_counterexample_node",
                &location,
                "counterexample node_id is unknown; the record remains inconclusive in shadow",
            );
        }
        let status = record
            .get("status")
            .or_else(|| record.get("result"))
            .or_else(|| record.get("outcome"))
            .and_then(Value::as_str)
            .unwrap_or("inconclusive");
        let has_witness = meaningful_witness(record.get("witness"));
        let claimed_found = matches!(status, "found" | "refuted" | "counterexample_found");
        let found = claimed_found && has_witness && node_reference_valid;
        if claimed_found && !has_witness {
            warnings.push(
                "counterexample_without_witness",
                &location,
                "a claimed counterexample has no witness and is treated as inconclusive",
            );
        }
        if found && let Some(node) = nodes.get_mut(&node_id) {
            node.status = ResearchNodeStatus::Refuted;
        }
        *sequence = sequence.saturating_add(1);
        let mut attempt = ResearchAttempt::new(
            ResearchAttemptId::parse(format!("attempt:counterexample:{}", index + 1))?,
            node_id,
            actor.clone(),
            ResearchAttemptMethod::Counterexample,
            if found {
                ResearchAttemptOutcome::Refuted
            } else {
                ResearchAttemptOutcome::Inconclusive
            },
            summary,
        )?
        .with_position(input.round_index, *sequence);
        if found {
            attempt = attempt.with_obstruction(ResearchObstruction::FalseClaim);
        }
        attempts.push(attempt);
        enforce_attempt_limit(attempts)?;
    }
    Ok(())
}

pub(super) fn normalize_retrieval_events(
    input: &LegacyResearchInput,
    target_id: &ResearchNodeId,
    attempts: &mut Vec<ResearchAttempt>,
    sequence: &mut u64,
    warnings: &mut WarningCollector,
) -> Result<RetrievalCounts, ResearchStateError> {
    let actor = ResearchDomainId::parse("legacy-generation")?;
    let mut seen = BTreeSet::new();
    let mut counts = RetrievalCounts::default();
    for (index, event) in input.events.iter().enumerate() {
        let event_type = event
            .get("event_type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !event_type.starts_with("external_") {
            continue;
        }
        counts.events = counts.events.saturating_add(1);
        let Some(results) = event.get("results").and_then(Value::as_array) else {
            warnings.push(
                "retrieval_without_results",
                format!("events[{index}]"),
                "external retrieval event has no results array",
            );
            continue;
        };
        enforce_count(
            "legacy_retrieval_results",
            results.len(),
            MAX_RETRIEVAL_RESULTS_PER_EVENT,
        )?;
        let mut novel = Vec::new();
        for result in results {
            let Some(reference_id) = result.get("reference_id").and_then(Value::as_str) else {
                continue;
            };
            if !input.registered_reference_ids.contains(reference_id) {
                warnings.push(
                    "unregistered_retrieval_reference",
                    format!("events[{index}].results"),
                    "retrieval result reference_id is absent from the authoritative registry",
                );
                continue;
            }
            if seen.insert(reference_id.to_owned()) {
                counts.novel = counts.novel.saturating_add(1);
                novel.push(reference_id.to_owned());
            } else {
                counts.repeated = counts.repeated.saturating_add(1);
            }
        }
        *sequence = sequence.saturating_add(1);
        let operation = event
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or("research");
        let mut attempt = ResearchAttempt::new(
            ResearchAttemptId::parse(format!("attempt:retrieval:{}", index + 1))?,
            target_id.clone(),
            actor.clone(),
            ResearchAttemptMethod::Retrieval,
            if novel.is_empty() {
                ResearchAttemptOutcome::Inconclusive
            } else {
                ResearchAttemptOutcome::Progress
            },
            format!(
                "{operation} registered {} previously unseen reference id(s).",
                novel.len()
            ),
        )?
        .with_position(input.round_index, *sequence);
        if novel.is_empty() {
            attempt = attempt.with_obstruction(ResearchObstruction::NoProgress);
        }
        if novel.len() > MAX_EVIDENCE_IDS {
            warnings.push(
                "retrieval_evidence_truncated",
                format!("events[{index}].results"),
                format!(
                    "{} novel reference ids were counted but only {} are attached to the attempt",
                    novel.len(),
                    MAX_EVIDENCE_IDS
                ),
            );
        }
        for reference_id in novel.into_iter().take(MAX_EVIDENCE_IDS) {
            attempt = attempt.with_evidence(reference_id)?;
        }
        attempts.push(attempt);
        enforce_attempt_limit(attempts)?;
    }
    Ok(counts)
}

pub(super) fn normalize_failures(
    input: &LegacyResearchInput,
    target_id: &ResearchNodeId,
    attempts: &mut Vec<ResearchAttempt>,
    sequence: &mut u64,
    warnings: &mut WarningCollector,
) -> Result<usize, ResearchStateError> {
    let actor = ResearchDomainId::parse("legacy-generation")?;
    let mut ignored = 0usize;
    for (index, record) in input.failed_paths.iter().enumerate() {
        let Some(summary) = extract_summary(record) else {
            ignored = ignored.saturating_add(1);
            warnings.push(
                "failure_without_summary",
                format!("failed_paths[{index}]"),
                "failure record has no concise summary",
            );
            continue;
        };
        *sequence = sequence.saturating_add(1);
        attempts.push(
            ResearchAttempt::new(
                ResearchAttemptId::parse(format!("attempt:failure:{}", index + 1))?,
                target_id.clone(),
                actor.clone(),
                ResearchAttemptMethod::Synthesis,
                ResearchAttemptOutcome::Failed,
                summary,
            )?
            .with_obstruction(ResearchObstruction::Unknown)
            .with_position(input.round_index, *sequence),
        );
        enforce_attempt_limit(attempts)?;
    }
    Ok(ignored)
}

pub(super) fn normalize_decisions(
    input: &LegacyResearchInput,
    nodes: &BTreeMap<ResearchNodeId, ResearchNode>,
    active_plan_ids: &BTreeSet<ResearchPlanId>,
    decisions: &mut Vec<ResearchDecision>,
    sequence: &mut u64,
    warnings: &mut WarningCollector,
) -> Result<usize, ResearchStateError> {
    let mut ignored = 0usize;
    for (index, record) in input.big_decisions.iter().enumerate() {
        let Some(reason) = extract_summary(record) else {
            ignored = ignored.saturating_add(1);
            warnings.push(
                "decision_without_reason",
                format!("big_decisions[{index}]"),
                "decision record has no concise reason",
            );
            continue;
        };
        *sequence = sequence.saturating_add(1);
        let mut decision = ResearchDecision::new(
            ResearchDecisionId::parse(format!("decision:legacy:{}", index + 1))?,
            reason,
        )?
        .with_event_seq(*sequence);
        for plan_text in bounded_optional_string_array(
            record.get("superseded_plan_ids"),
            &format!("big_decisions[{index}].superseded_plan_ids"),
            MAX_DECISION_PLAN_IDS,
        )? {
            if let Some(plan_id) = active_plan_ids
                .iter()
                .find(|plan_id| plan_id.as_str() == plan_text)
            {
                decision = decision.supersede_plan(plan_id.clone());
            } else {
                warnings.push(
                    "unknown_decision_plan",
                    format!("big_decisions[{index}]"),
                    format!("decision refers to an unknown active plan: {plan_text}"),
                );
            }
        }
        for node_text in bounded_optional_string_array(
            record.get("preserved_node_ids"),
            &format!("big_decisions[{index}].preserved_node_ids"),
            MAX_DECISION_NODE_IDS,
        )? {
            if let Some(node_id) = nodes.keys().find(|node_id| node_id.as_str() == node_text) {
                decision = decision.preserve_node(node_id.clone());
            } else {
                warnings.push(
                    "unknown_preserved_node",
                    format!("big_decisions[{index}]"),
                    format!("decision refers to an unknown node: {node_text}"),
                );
            }
        }
        if let Some(focus_text) = record.get("selected_focus_node_id").and_then(Value::as_str) {
            if let Some(node_id) = nodes.keys().find(|node_id| node_id.as_str() == focus_text) {
                decision = decision.focus_on(node_id.clone());
            } else {
                warnings.push(
                    "unknown_focus_node",
                    format!("big_decisions[{index}]"),
                    "decision selected_focus_node_id is unknown",
                );
            }
        }
        for constraint in bounded_optional_string_array(
            record.get("new_constraints"),
            &format!("big_decisions[{index}].new_constraints"),
            MAX_DECISION_CONSTRAINTS,
        )? {
            decision = decision.add_constraint(constraint)?;
        }
        decisions.push(decision);
        if decisions.len() > MAX_RESEARCH_DECISIONS {
            return Err(ResearchStateError::LimitExceeded {
                kind: "research_decisions",
                limit: MAX_RESEARCH_DECISIONS,
                actual: decisions.len(),
            });
        }
    }
    Ok(ignored)
}

pub(super) fn normalize_verification_reports(
    input: &LegacyResearchInput,
    target_id: &ResearchNodeId,
    attempts: &mut Vec<ResearchAttempt>,
    sequence: &mut u64,
    warnings: &mut WarningCollector,
) -> Result<usize, ResearchStateError> {
    let actor = ResearchDomainId::parse("legacy-repair")?;
    let mut ignored = 0usize;
    for (index, report) in input.verification_reports.iter().enumerate() {
        let critical = report
            .get("critical_errors")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        let gaps = report
            .get("gaps")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        if critical + gaps == 0 {
            continue;
        }
        let summary = report
            .get("repair_hints")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| {
                format!("Verifier reported {critical} critical error(s) and {gaps} gap(s).")
            });
        if summary.trim().is_empty() {
            ignored = ignored.saturating_add(1);
            warnings.push(
                "verification_without_summary",
                format!("verification_reports[{index}]"),
                "verification findings have no repair summary",
            );
            continue;
        }
        *sequence = sequence.saturating_add(1);
        attempts.push(
            ResearchAttempt::new(
                ResearchAttemptId::parse(format!("attempt:repair:{}", index + 1))?,
                target_id.clone(),
                actor.clone(),
                ResearchAttemptMethod::Repair,
                ResearchAttemptOutcome::Failed,
                summary,
            )?
            .with_obstruction(ResearchObstruction::Unknown)
            .with_position(input.round_index, *sequence),
        );
        enforce_attempt_limit(attempts)?;
    }
    Ok(ignored)
}

pub(super) fn normalize_join_decision(
    input: &LegacyResearchInput,
    nodes: &BTreeMap<ResearchNodeId, ResearchNode>,
    active_plan_ids: &BTreeSet<ResearchPlanId>,
    decisions: &mut Vec<ResearchDecision>,
    sequence: &mut u64,
    warnings: &mut WarningCollector,
) -> Result<(), ResearchStateError> {
    let Some(object) = input
        .join_result
        .as_object()
        .filter(|object| !object.is_empty())
    else {
        return Ok(());
    };
    let outcome = object
        .get("outcome")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    *sequence = sequence.saturating_add(1);
    let mut decision = ResearchDecision::new(
        ResearchDecisionId::parse("decision:legacy:join")?,
        format!("Branch join outcome: {outcome}."),
    )?
    .with_event_seq(*sequence);
    let selected_plan = object
        .get("selected_plan_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            let selected_branch = object.get("selected_branch_id")?.as_str()?;
            input
                .branch_results
                .iter()
                .find(|result| {
                    result.get("branch_id").and_then(Value::as_str) == Some(selected_branch)
                })
                .and_then(|result| result.get("plan_id"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    if object.get("selected_branch_id").is_some() && selected_plan.is_none() {
        warnings.push(
            "unknown_join_branch",
            "join_result.selected_branch_id",
            "join decision refers to a branch without a recognized sealed result",
        );
    }
    if let Some(plan_text) = selected_plan.as_deref() {
        if let Some(plan_id) = active_plan_ids
            .iter()
            .find(|plan_id| plan_id.as_str() == plan_text)
        {
            if let Some(goal) = nodes
                .values()
                .filter(|node| node.plan_id.as_ref() == Some(plan_id))
                .max_by_key(|node| (node.plan_order, node.node_order, node.node_id.clone()))
            {
                decision = decision.focus_on(goal.node_id.clone());
            }
        } else {
            warnings.push(
                "unknown_join_plan",
                "join_result.selected_plan_id",
                "join decision refers to an unknown active plan",
            );
        }
    }
    decisions.push(decision);
    if decisions.len() > MAX_RESEARCH_DECISIONS {
        return Err(ResearchStateError::LimitExceeded {
            kind: "research_decisions",
            limit: MAX_RESEARCH_DECISIONS,
            actual: decisions.len(),
        });
    }
    Ok(())
}

fn enforce_attempt_limit(attempts: &[ResearchAttempt]) -> Result<(), ResearchStateError> {
    if attempts.len() > MAX_RESEARCH_ATTEMPTS {
        return Err(ResearchStateError::LimitExceeded {
            kind: "research_attempts",
            limit: MAX_RESEARCH_ATTEMPTS,
            actual: attempts.len(),
        });
    }
    Ok(())
}
