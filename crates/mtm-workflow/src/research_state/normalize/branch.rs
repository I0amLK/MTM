use super::support::resolve_plan_node;
use super::*;

pub(super) fn normalize_branch_results(
    input: &LegacyResearchInput,
    plans: &BTreeMap<ResearchPlanId, Vec<LegacyPlanNode>>,
    nodes: &mut BTreeMap<ResearchNodeId, ResearchNode>,
    attempts: &mut Vec<ResearchAttempt>,
    sequence: &mut u64,
    warnings: &mut WarningCollector,
) -> Result<usize, ResearchStateError> {
    let mut recognized = 0usize;
    for (branch_index, result) in input.branch_results.iter().enumerate() {
        let location = format!("branch_results[{branch_index}]");
        let Some(plan_text) = result.get("plan_id").and_then(Value::as_str) else {
            warnings.push(
                "missing_branch_plan",
                &location,
                "branch result has no plan_id",
            );
            continue;
        };
        let Some((_plan_id, plan_nodes)) = find_plan(plans, plan_text) else {
            warnings.push(
                "inactive_branch_plan",
                &location,
                "sealed branch result belongs to a plan that is no longer active",
            );
            continue;
        };
        let status = result
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("failed");
        if !matches!(status, "solved" | "partial" | "failed") {
            warnings.push(
                "invalid_branch_status",
                &location,
                "branch status is unknown",
            );
            continue;
        }
        let summary = result
            .get("summary")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("Branch completed without a summary.");
        let proved = bounded_optional_string_array(
            result.get("proved_subgoals"),
            &format!("{location}.proved_subgoals"),
            MAX_NODE_DEPENDENCIES,
        )?;
        let unproved = bounded_optional_string_array(
            result.get("unproved_subgoals"),
            &format!("{location}.unproved_subgoals"),
            MAX_NODE_DEPENDENCIES,
        )?;
        let mut obstruction_map =
            BTreeMap::<ResearchNodeId, (ResearchObstruction, Vec<String>)>::new();
        if let Some(obstructions) = result.get("obstructions") {
            let obstructions = obstructions
                .as_array()
                .ok_or_else(|| malformed(&location, "branch obstructions must be an array"))?;
            enforce_count(
                "protocol3_branch_obstructions",
                obstructions.len(),
                MAX_NODE_DEPENDENCIES,
            )?;
            for (obstruction_index, obstruction) in obstructions.iter().enumerate() {
                let obstruction_location = format!("{location}.obstructions[{obstruction_index}]");
                let obstruction = obstruction.as_object().ok_or_else(|| {
                    malformed(
                        &obstruction_location,
                        "branch obstruction must be an object",
                    )
                })?;
                let node_id = ResearchNodeId::parse(required_text(
                    obstruction.get("node_id"),
                    &format!("{obstruction_location}.node_id"),
                )?)?;
                if !plan_nodes.iter().any(|node| node.node_id == node_id) {
                    return Err(malformed(
                        &obstruction_location,
                        "branch obstruction node is outside the branch plan",
                    ));
                }
                let class = obstruction
                    .get("class")
                    .and_then(Value::as_str)
                    .and_then(ResearchObstruction::parse)
                    .ok_or_else(|| {
                        malformed(&obstruction_location, "branch obstruction class is unknown")
                    })?;
                let evidence = bounded_optional_string_array(
                    obstruction.get("evidence_ids"),
                    &format!("{obstruction_location}.evidence_ids"),
                    MAX_EVIDENCE_IDS,
                )?;
                if obstruction_map.insert(node_id, (class, evidence)).is_some() {
                    return Err(malformed(
                        &obstruction_location,
                        "duplicate branch obstruction node",
                    ));
                }
            }
        }
        let mut touched = BTreeSet::new();
        if status == "solved" {
            touched.extend(plan_nodes.iter().map(|node| node.node_id.clone()));
            for node in plan_nodes {
                if let Some(current) = nodes.get_mut(&node.node_id) {
                    current.status = ResearchNodeStatus::RouteSolved;
                }
            }
        } else {
            update_partial_branch(
                &location,
                status,
                plan_nodes,
                &proved,
                &unproved,
                nodes,
                &mut touched,
                warnings,
            );
            touched.extend(obstruction_map.keys().cloned());
            for node_id in obstruction_map.keys() {
                if let Some(current) = nodes.get_mut(node_id)
                    && current.status != ResearchNodeStatus::RouteSolved
                {
                    current.status = ResearchNodeStatus::Blocked;
                }
            }
        }
        let branch_id = result
            .get("branch_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or("unknown");
        let actor = result
            .get("actor_domain_id")
            .and_then(Value::as_str)
            .map(ResearchDomainId::parse)
            .transpose()?
            .unwrap_or(ResearchDomainId::parse(format!(
                "legacy-branch:{branch_id}"
            ))?);
        for (node_index, node_id) in touched.into_iter().enumerate() {
            *sequence = sequence.saturating_add(1);
            let mut attempt = ResearchAttempt::new(
                ResearchAttemptId::parse(format!(
                    "attempt:branch:{}:{}",
                    branch_index + 1,
                    node_index + 1
                ))?,
                node_id.clone(),
                actor.clone(),
                ResearchAttemptMethod::Synthesis,
                match status {
                    "solved" => ResearchAttemptOutcome::RouteSolved,
                    "partial" => ResearchAttemptOutcome::Progress,
                    _ => ResearchAttemptOutcome::Failed,
                },
                summary,
            )?
            .with_position(input.round_index, *sequence);
            if let Some((obstruction, evidence_ids)) = obstruction_map.get(&node_id) {
                attempt = attempt.with_obstruction(*obstruction);
                for evidence_id in evidence_ids {
                    attempt = attempt.with_evidence(evidence_id.clone())?;
                }
            } else if status == "failed" {
                attempt = attempt.with_obstruction(ResearchObstruction::NoProgress);
            }
            attempts.push(attempt);
            if attempts.len() > MAX_RESEARCH_ATTEMPTS {
                return Err(ResearchStateError::LimitExceeded {
                    kind: "research_attempts",
                    limit: MAX_RESEARCH_ATTEMPTS,
                    actual: attempts.len(),
                });
            }
        }
        recognized = recognized.saturating_add(1);
    }
    Ok(recognized)
}

#[allow(clippy::too_many_arguments)]
fn update_partial_branch(
    location: &str,
    status: &str,
    plan_nodes: &[LegacyPlanNode],
    proved: &[String],
    unproved: &[String],
    nodes: &mut BTreeMap<ResearchNodeId, ResearchNode>,
    touched: &mut BTreeSet<ResearchNodeId>,
    warnings: &mut WarningCollector,
) {
    for label in proved {
        if let Some(node_id) = resolve_plan_node(plan_nodes, label) {
            touched.insert(node_id.clone());
            if let Some(current) = nodes.get_mut(node_id) {
                current.status = ResearchNodeStatus::RouteSolved;
            }
        } else {
            warnings.push(
                "unknown_proved_subgoal",
                location,
                format!("branch proved_subgoals entry does not match the active plan: {label}"),
            );
        }
    }
    for label in unproved {
        if let Some(node_id) = resolve_plan_node(plan_nodes, label) {
            touched.insert(node_id.clone());
            if let Some(current) = nodes.get_mut(node_id)
                && current.status != ResearchNodeStatus::RouteSolved
            {
                current.status = ResearchNodeStatus::Blocked;
            }
        } else {
            warnings.push(
                "unknown_unproved_subgoal",
                location,
                format!("branch unproved_subgoals entry does not match the active plan: {label}"),
            );
        }
    }
    if status == "failed" && touched.is_empty() {
        touched.extend(plan_nodes.iter().map(|node| node.node_id.clone()));
        for node in plan_nodes {
            if let Some(current) = nodes.get_mut(&node.node_id)
                && current.status != ResearchNodeStatus::RouteSolved
            {
                current.status = ResearchNodeStatus::Blocked;
            }
        }
    }
}
