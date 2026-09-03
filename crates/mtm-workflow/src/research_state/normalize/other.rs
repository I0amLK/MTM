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
    for (index, record) in input.counterexamples.iter().enumerate() {
        let location = format!("counterexamples[{index}]");
        let actor = record
            .get("actor_domain_id")
            .and_then(Value::as_str)
            .map(ResearchDomainId::parse)
            .transpose()?
            .unwrap_or(ResearchDomainId::parse("legacy-generation")?);
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
            record
                .get("record_id")
                .and_then(Value::as_str)
                .map(|record_id| ResearchAttemptId::parse(format!("attempt:{record_id}")))
                .transpose()?
                .unwrap_or(ResearchAttemptId::parse(format!(
                    "attempt:counterexample:{}",
                    index + 1
                ))?),
            node_id,
            actor,
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
        for evidence_id in bounded_optional_string_array(
            record.get("evidence_ids"),
            &format!("{location}.evidence_ids"),
            MAX_EVIDENCE_IDS,
        )? {
            attempt = attempt.with_evidence(evidence_id)?;
        }
        attempts.push(attempt);
        enforce_attempt_limit(attempts)?;
    }
    Ok(())
}

pub(super) fn normalize_retrieval_events(
    input: &LegacyResearchInput,
    nodes: &BTreeMap<ResearchNodeId, ResearchNode>,
    target_id: &ResearchNodeId,
    attempts: &mut Vec<ResearchAttempt>,
    sequence: &mut u64,
    warnings: &mut WarningCollector,
) -> Result<RetrievalCounts, ResearchStateError> {
    // `seen` owns aggregate novelty across every retrieval record, including the
    // server-emitted external_* discovery event and the later typed assessment.
    // `assessed` is deliberately separate: an external discovery must not consume
    // the evidence before the model can record its first typed new_material
    // assessment, while repeated typed assessments of the same evidence must not
    // manufacture fresh progress.
    let mut seen = BTreeSet::new();
    let mut assessed = BTreeSet::new();
    let mut counts = RetrievalCounts::default();
    for (index, event) in input.events.iter().enumerate() {
        let event_type = event
            .get("event_type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if event_type == "retrieval_assessment" {
            counts.events = counts.events.saturating_add(1);
            let reference_ids = bounded_optional_string_array(
                event.get("reference_ids"),
                &format!("events[{index}].reference_ids"),
                MAX_EVIDENCE_IDS,
            )?;
            let mut assessment_evidence = Vec::new();
            for reference_id in reference_ids {
                if !input.registered_reference_ids.contains(&reference_id) {
                    return Err(malformed(
                        format!("events[{index}].reference_ids"),
                        "protocol-3 retrieval record contains an unregistered reference_id",
                    ));
                }
                if seen.insert(reference_id.clone()) {
                    counts.novel = counts.novel.saturating_add(1);
                } else {
                    counts.repeated = counts.repeated.saturating_add(1);
                }
                if assessed.insert(reference_id.clone()) {
                    assessment_evidence.push(reference_id);
                }
            }
            let explicit_node = event.get("node_id").is_some_and(|value| !value.is_null());
            let resolved_node = resolve_canonical_node(event.get("node_id"), nodes);
            if explicit_node && resolved_node.is_none() {
                return Err(malformed(
                    format!("events[{index}].node_id"),
                    "protocol-3 retrieval record refers to an unknown node",
                ));
            }
            let node_id = resolved_node.unwrap_or_else(|| target_id.clone());
            let outcome = event
                .get("outcome")
                .and_then(Value::as_str)
                .unwrap_or("inconclusive");
            let summary = event
                .get("summary")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .unwrap_or("Retrieval assessment was inconclusive.");
            let actor = event
                .get("actor_domain_id")
                .and_then(Value::as_str)
                .map(ResearchDomainId::parse)
                .transpose()?
                .unwrap_or(ResearchDomainId::parse("legacy-generation")?);
            let assessment_made_progress =
                outcome == "new_material" && !assessment_evidence.is_empty();
            *sequence = sequence.saturating_add(1);
            let mut attempt = ResearchAttempt::new(
                event
                    .get("record_id")
                    .and_then(Value::as_str)
                    .map(|record_id| ResearchAttemptId::parse(format!("attempt:{record_id}")))
                    .transpose()?
                    .unwrap_or(ResearchAttemptId::parse(format!(
                        "attempt:retrieval:{}",
                        index + 1
                    ))?),
                node_id,
                actor,
                ResearchAttemptMethod::Retrieval,
                if assessment_made_progress {
                    ResearchAttemptOutcome::Progress
                } else {
                    ResearchAttemptOutcome::Inconclusive
                },
                summary,
            )?
            .with_position(input.round_index, *sequence);
            if !assessment_made_progress {
                attempt = attempt.with_obstruction(ResearchObstruction::NoProgress);
            }
            for reference_id in assessment_evidence {
                attempt = attempt.with_evidence(reference_id)?;
            }
            attempts.push(attempt);
            enforce_attempt_limit(attempts)?;
            continue;
        }
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
        let actor = event
            .get("actor_domain_id")
            .and_then(Value::as_str)
            .map(ResearchDomainId::parse)
            .transpose()?
            .unwrap_or(ResearchDomainId::parse("legacy-generation")?);
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
    nodes: &BTreeMap<ResearchNodeId, ResearchNode>,
    target_id: &ResearchNodeId,
    attempts: &mut Vec<ResearchAttempt>,
    sequence: &mut u64,
    warnings: &mut WarningCollector,
) -> Result<usize, ResearchStateError> {
    let mut ignored = 0usize;
    for (index, record) in input.failed_paths.iter().enumerate() {
        let location = format!("failed_paths[{index}]");
        let Some(summary) = extract_summary(record) else {
            ignored = ignored.saturating_add(1);
            warnings.push(
                "failure_without_summary",
                &location,
                "failure record has no concise summary",
            );
            continue;
        };
        let actor = record
            .get("actor_domain_id")
            .and_then(Value::as_str)
            .map(ResearchDomainId::parse)
            .transpose()?
            .unwrap_or(ResearchDomainId::parse("legacy-generation")?);
        let obstruction = record
            .get("obstruction_class")
            .and_then(Value::as_str)
            .and_then(ResearchObstruction::parse)
            .unwrap_or(ResearchObstruction::Unknown);
        let affected = bounded_optional_string_array(
            record.get("affected_node_ids"),
            &format!("{location}.affected_node_ids"),
            MAX_DECISION_NODE_IDS,
        )?;
        let mut affected_nodes = Vec::new();
        if affected.is_empty() {
            affected_nodes.push(target_id.clone());
        } else {
            for raw_node_id in affected {
                let node_id = ResearchNodeId::parse(raw_node_id)?;
                if !nodes.contains_key(&node_id) {
                    return Err(malformed(
                        &location,
                        "failure record refers to an unknown canonical node",
                    ));
                }
                affected_nodes.push(node_id);
            }
        }
        let record_id = record.get("record_id").and_then(Value::as_str);
        for (node_index, node_id) in affected_nodes.into_iter().enumerate() {
            *sequence = sequence.saturating_add(1);
            let attempt_id = record_id.map_or_else(
                || {
                    ResearchAttemptId::parse(format!(
                        "attempt:failure:{}:{}",
                        index + 1,
                        node_index + 1
                    ))
                },
                |record_id| {
                    ResearchAttemptId::parse(format!("attempt:{record_id}:{}", node_index + 1))
                },
            )?;
            attempts.push(
                ResearchAttempt::new(
                    attempt_id,
                    node_id,
                    actor.clone(),
                    ResearchAttemptMethod::Synthesis,
                    ResearchAttemptOutcome::Failed,
                    summary,
                )?
                .with_obstruction(obstruction)
                .with_position(input.round_index, *sequence),
            );
            enforce_attempt_limit(attempts)?;
        }
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
        let findings = report.get("verification_report").and_then(Value::as_object);
        let critical = findings
            .and_then(|object| object.get("critical_errors"))
            .or_else(|| report.get("critical_errors"))
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        let gaps = findings
            .and_then(|object| object.get("gaps"))
            .or_else(|| report.get("gaps"))
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
    let has_selected_branch = object
        .get("selected_branch_id")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty());
    if has_selected_branch && selected_plan.is_none() {
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
