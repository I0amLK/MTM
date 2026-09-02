//! Deterministic normalization of protocol-2 research history into the pure graph
//! model. This module performs no I/O and makes no authority decision.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use super::{
    MAX_ACTIVE_PLANS, MAX_DECISION_CONSTRAINTS, MAX_DECISION_NODE_IDS, MAX_DECISION_PLAN_IDS,
    MAX_EVIDENCE_IDS, MAX_NODE_DEPENDENCIES, MAX_RESEARCH_ATTEMPTS, MAX_RESEARCH_DECISIONS,
    MAX_RESEARCH_NODES, ResearchAttempt, ResearchAttemptId, ResearchAttemptMethod,
    ResearchAttemptOutcome, ResearchDecision, ResearchDecisionId, ResearchDomainId, ResearchNode,
    ResearchNodeId, ResearchNodeKind, ResearchNodeStatus, ResearchObstruction, ResearchPlanId,
    ResearchSnapshot, ResearchStateError,
};

const MAX_LEGACY_RECORDS_PER_CHANNEL: usize = 2_048;
const MAX_NORMALIZATION_WARNINGS: usize = 128;
const MAX_WARNING_LOCATION_BYTES: usize = 512;
const MAX_WARNING_MESSAGE_BYTES: usize = 1_024;
const MAX_RETRIEVAL_RESULTS_PER_EVENT: usize = 64;

mod branch;
mod other;
mod support;
#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;

use branch::normalize_branch_results;
use other::{
    normalize_counterexamples, normalize_decisions, normalize_failures, normalize_join_decision,
    normalize_retrieval_events, normalize_verification_reports,
};
use support::{
    bounded_optional_string_array, combined_node_id, extract_summary, find_plan, malformed,
    normalize_screening_status, required_string_array, required_text, screening_outcome,
};

#[derive(Clone, Debug)]
pub struct LegacyResearchInput {
    target_statement: String,
    round_index: u32,
    active_plans: Value,
    screening_progress: Value,
    proof_steps: Vec<Value>,
    counterexamples: Vec<Value>,
    failed_paths: Vec<Value>,
    big_decisions: Vec<Value>,
    events: Vec<Value>,
    registered_reference_ids: BTreeSet<String>,
    branch_results: Vec<Value>,
    join_result: Value,
    verification_reports: Vec<Value>,
}

impl LegacyResearchInput {
    #[must_use]
    pub fn new(
        target_statement: impl Into<String>,
        round_index: u32,
        active_plans: Value,
        screening_progress: Value,
    ) -> Self {
        Self {
            target_statement: target_statement.into(),
            round_index,
            active_plans,
            screening_progress,
            proof_steps: Vec::new(),
            counterexamples: Vec::new(),
            failed_paths: Vec::new(),
            big_decisions: Vec::new(),
            events: Vec::new(),
            registered_reference_ids: BTreeSet::new(),
            branch_results: Vec::new(),
            join_result: Value::Object(Default::default()),
            verification_reports: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_proof_steps(mut self, records: Vec<Value>) -> Self {
        self.proof_steps = records;
        self
    }

    #[must_use]
    pub fn with_counterexamples(mut self, records: Vec<Value>) -> Self {
        self.counterexamples = records;
        self
    }

    #[must_use]
    pub fn with_failed_paths(mut self, records: Vec<Value>) -> Self {
        self.failed_paths = records;
        self
    }

    #[must_use]
    pub fn with_big_decisions(mut self, records: Vec<Value>) -> Self {
        self.big_decisions = records;
        self
    }

    #[must_use]
    pub fn with_events(mut self, records: Vec<Value>) -> Self {
        self.events = records;
        self
    }

    #[must_use]
    pub fn with_registered_reference_ids(
        mut self,
        reference_ids: impl IntoIterator<Item = String>,
    ) -> Self {
        self.registered_reference_ids.extend(reference_ids);
        self
    }

    #[must_use]
    pub fn with_branch_results(mut self, records: Vec<Value>) -> Self {
        self.branch_results = records;
        self
    }

    #[must_use]
    pub fn with_join_result(mut self, record: Value) -> Self {
        self.join_result = record;
        self
    }

    #[must_use]
    pub fn with_verification_reports(mut self, records: Vec<Value>) -> Self {
        self.verification_reports = records;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResearchNormalizationWarning {
    code: String,
    location: String,
    message: String,
}

impl ResearchNormalizationWarning {
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    #[must_use]
    pub fn location(&self) -> &str {
        &self.location
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LegacyNormalizationSummary {
    source_records: BTreeMap<String, usize>,
    normalized_nodes: usize,
    normalized_attempts: usize,
    normalized_decisions: usize,
    retrieval_events: usize,
    novel_reference_ids: usize,
    repeated_reference_ids: usize,
    recognized_branch_results: usize,
    ignored_records: usize,
    warning_count: usize,
}

impl LegacyNormalizationSummary {
    #[must_use]
    pub fn normalized_nodes(&self) -> usize {
        self.normalized_nodes
    }

    #[must_use]
    pub fn normalized_attempts(&self) -> usize {
        self.normalized_attempts
    }

    #[must_use]
    pub fn normalized_decisions(&self) -> usize {
        self.normalized_decisions
    }

    #[must_use]
    pub fn warning_count(&self) -> usize {
        self.warning_count
    }
}

#[derive(Clone, Debug)]
pub struct LegacyNormalization {
    snapshot: ResearchSnapshot,
    warnings: Vec<ResearchNormalizationWarning>,
    summary: LegacyNormalizationSummary,
}

impl LegacyNormalization {
    #[must_use]
    pub fn snapshot(&self) -> &ResearchSnapshot {
        &self.snapshot
    }

    #[must_use]
    pub fn warnings(&self) -> &[ResearchNormalizationWarning] {
        &self.warnings
    }

    #[must_use]
    pub fn summary(&self) -> &LegacyNormalizationSummary {
        &self.summary
    }

    #[must_use]
    pub fn into_snapshot(self) -> ResearchSnapshot {
        self.snapshot
    }
}

#[derive(Clone)]
struct LegacyPlanNode {
    node_id: ResearchNodeId,
    subgoal_id: String,
    statement: String,
}

#[derive(Default)]
struct WarningCollector {
    items: Vec<ResearchNormalizationWarning>,
    omitted: usize,
}

impl WarningCollector {
    fn push(&mut self, code: &str, location: impl Into<String>, message: impl Into<String>) {
        if self.items.len() < MAX_NORMALIZATION_WARNINGS.saturating_sub(1) {
            self.items.push(ResearchNormalizationWarning {
                code: code.to_owned(),
                location: truncate_utf8(&location.into(), MAX_WARNING_LOCATION_BYTES),
                message: truncate_utf8(&message.into(), MAX_WARNING_MESSAGE_BYTES),
            });
        } else {
            self.omitted = self.omitted.saturating_add(1);
        }
    }

    fn finish(mut self) -> Vec<ResearchNormalizationWarning> {
        if self.omitted > 0 {
            self.items.push(ResearchNormalizationWarning {
                code: "warnings_truncated".to_owned(),
                location: "normalization".to_owned(),
                message: format!(
                    "{} additional normalization warnings were omitted",
                    self.omitted
                ),
            });
        }
        self.items
    }
}

pub fn normalize_legacy_research(
    input: &LegacyResearchInput,
) -> Result<LegacyNormalization, ResearchStateError> {
    validate_channel_limits(input)?;
    let target_id = ResearchNodeId::parse("target")?;
    let target = ResearchNode::new(
        target_id.clone(),
        input.target_statement.clone(),
        ResearchNodeKind::Target,
    )?
    .with_order(0, 0, 0);
    let mut warnings = WarningCollector::default();
    let mut nodes = BTreeMap::from([(target_id.clone(), target)]);
    let mut plans = BTreeMap::<ResearchPlanId, Vec<LegacyPlanNode>>::new();
    let mut active_plan_ids = BTreeSet::new();
    normalize_plans(
        input,
        &mut nodes,
        &mut plans,
        &mut active_plan_ids,
        &mut warnings,
    )?;

    let mut attempts = Vec::new();
    let mut decisions = Vec::new();
    let mut sequence = 0u64;
    normalize_direct_attempts(input, &plans, &mut attempts, &mut sequence, &mut warnings)?;
    let recognized_branch_results = normalize_branch_results(
        input,
        &plans,
        &mut nodes,
        &mut attempts,
        &mut sequence,
        &mut warnings,
    )?;
    normalize_counterexamples(
        input,
        &mut nodes,
        &target_id,
        &mut attempts,
        &mut sequence,
        &mut warnings,
    )?;
    let retrieval = normalize_retrieval_events(
        input,
        &nodes,
        &target_id,
        &mut attempts,
        &mut sequence,
        &mut warnings,
    )?;
    let ignored_failures = normalize_failures(
        input,
        &nodes,
        &target_id,
        &mut attempts,
        &mut sequence,
        &mut warnings,
    )?;
    let ignored_decisions = normalize_decisions(
        input,
        &nodes,
        &active_plan_ids,
        &mut decisions,
        &mut sequence,
        &mut warnings,
    )?;
    let ignored_verification = normalize_verification_reports(
        input,
        &target_id,
        &mut attempts,
        &mut sequence,
        &mut warnings,
    )?;
    normalize_join_decision(
        input,
        &nodes,
        &active_plan_ids,
        &mut decisions,
        &mut sequence,
        &mut warnings,
    )?;

    let mut snapshot = ResearchSnapshot::new(target_id);
    for node in nodes.into_values() {
        snapshot = snapshot.with_node(node);
    }
    for attempt in attempts {
        snapshot = snapshot.with_attempt(attempt);
    }
    for decision in decisions {
        snapshot = snapshot.with_decision(decision);
    }
    for plan_id in active_plan_ids {
        snapshot = snapshot.with_active_plan(plan_id);
    }
    let warnings = warnings.finish();
    let summary = LegacyNormalizationSummary {
        source_records: BTreeMap::from([
            ("proof_steps".to_owned(), input.proof_steps.len()),
            ("counterexamples".to_owned(), input.counterexamples.len()),
            ("failed_paths".to_owned(), input.failed_paths.len()),
            ("big_decisions".to_owned(), input.big_decisions.len()),
            ("events".to_owned(), input.events.len()),
            ("branch_results".to_owned(), input.branch_results.len()),
            (
                "verification_reports".to_owned(),
                input.verification_reports.len(),
            ),
        ]),
        normalized_nodes: snapshot.nodes.len(),
        normalized_attempts: snapshot.attempts.len(),
        normalized_decisions: snapshot.decisions.len(),
        retrieval_events: retrieval.events,
        novel_reference_ids: retrieval.novel,
        repeated_reference_ids: retrieval.repeated,
        recognized_branch_results,
        ignored_records: ignored_failures
            .saturating_add(ignored_decisions)
            .saturating_add(ignored_verification),
        warning_count: warnings.len(),
    };
    Ok(LegacyNormalization {
        snapshot,
        warnings,
        summary,
    })
}

fn validate_channel_limits(input: &LegacyResearchInput) -> Result<(), ResearchStateError> {
    for (name, count) in [
        ("legacy_proof_steps", input.proof_steps.len()),
        ("legacy_counterexamples", input.counterexamples.len()),
        ("legacy_failed_paths", input.failed_paths.len()),
        ("legacy_big_decisions", input.big_decisions.len()),
        ("legacy_events", input.events.len()),
        ("legacy_branch_results", input.branch_results.len()),
        (
            "legacy_verification_reports",
            input.verification_reports.len(),
        ),
    ] {
        if count > MAX_LEGACY_RECORDS_PER_CHANNEL {
            return Err(ResearchStateError::LimitExceeded {
                kind: name,
                limit: MAX_LEGACY_RECORDS_PER_CHANNEL,
                actual: count,
            });
        }
    }
    Ok(())
}

fn normalize_plans(
    input: &LegacyResearchInput,
    nodes: &mut BTreeMap<ResearchNodeId, ResearchNode>,
    plans: &mut BTreeMap<ResearchPlanId, Vec<LegacyPlanNode>>,
    active_plan_ids: &mut BTreeSet<ResearchPlanId>,
    warnings: &mut WarningCollector,
) -> Result<(), ResearchStateError> {
    let raw_plans = input.active_plans.as_array().ok_or_else(|| {
        malformed(
            "active_plans",
            "expected an array of server-normalized plans",
        )
    })?;
    enforce_count("legacy_active_plans", raw_plans.len(), MAX_ACTIVE_PLANS)?;
    let progress = match &input.screening_progress {
        Value::Null => None,
        Value::Object(value) => {
            enforce_count("legacy_screening_plans", value.len(), MAX_ACTIVE_PLANS)?;
            Some(value)
        }
        _ => {
            return Err(malformed(
                "screening_progress",
                "expected an object keyed by plan_id",
            ));
        }
    };
    for (plan_index, raw_plan) in raw_plans.iter().enumerate() {
        let location = format!("active_plans[{plan_index}]");
        let object = raw_plan
            .as_object()
            .ok_or_else(|| malformed(&location, "expected an object"))?;
        let plan_text = required_text(object.get("plan_id"), &format!("{location}.plan_id"))?;
        let plan_id = ResearchPlanId::parse(plan_text)?;
        if !active_plan_ids.insert(plan_id.clone()) {
            return Err(ResearchStateError::DuplicateIdentifier {
                kind: "research_plan_id",
                identifier: plan_id.to_string(),
            });
        }
        if let Some(research_subgoals) = object.get("research_subgoals").and_then(Value::as_array) {
            if research_subgoals.is_empty() {
                return Err(malformed(
                    format!("{location}.research_subgoals"),
                    "non-empty canonical research subgoals are required",
                ));
            }
            enforce_count(
                "protocol3_plan_subgoals",
                research_subgoals.len(),
                MAX_NODE_DEPENDENCIES,
            )?;
            let mut plan_nodes = Vec::with_capacity(research_subgoals.len());
            let mut local_ids = BTreeSet::new();
            for (node_index, raw_node) in research_subgoals.iter().enumerate() {
                let node_location = format!("{location}.research_subgoals[{node_index}]");
                let node_object = raw_node
                    .as_object()
                    .ok_or_else(|| malformed(&node_location, "expected an object"))?;
                let subgoal_id = required_text(
                    node_object.get("subgoal_id"),
                    &format!("{node_location}.subgoal_id"),
                )?;
                if !local_ids.insert(subgoal_id.to_owned()) {
                    return Err(malformed(&node_location, "duplicate subgoal id"));
                }
                let node_id = ResearchNodeId::parse(required_text(
                    node_object.get("node_id"),
                    &format!("{node_location}.node_id"),
                )?)?;
                if node_id != combined_node_id(&plan_id, &subgoal_id)? {
                    return Err(malformed(
                        &node_location,
                        "canonical node_id does not match plan_id and subgoal_id",
                    ));
                }
                let statement = required_text(
                    node_object.get("statement"),
                    &format!("{node_location}.statement"),
                )?
                .to_owned();
                let kind = node_object
                    .get("kind")
                    .and_then(Value::as_str)
                    .and_then(ResearchNodeKind::parse)
                    .filter(|kind| *kind != ResearchNodeKind::Target)
                    .ok_or_else(|| {
                        malformed(
                            format!("{node_location}.kind"),
                            "unknown or invalid research node kind",
                        )
                    })?;
                let critical = node_object
                    .get("critical")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        malformed(format!("{node_location}.critical"), "boolean is required")
                    })?;
                let dependencies = bounded_optional_string_array(
                    node_object.get("depends_on"),
                    &format!("{node_location}.depends_on"),
                    MAX_NODE_DEPENDENCIES,
                )?;
                let mut seen_dependencies = BTreeSet::new();
                let mut node = ResearchNode::new(node_id.clone(), &statement, kind)?
                    .with_plan(plan_id.clone())
                    .with_declared_critical(critical)
                    .with_status(
                        progress
                            .and_then(|items| items.get(plan_id.as_str()))
                            .and_then(Value::as_object)
                            .and_then(|items| items.get(&subgoal_id))
                            .and_then(Value::as_object)
                            .and_then(|item| item.get("status"))
                            .and_then(Value::as_str)
                            .map(|status| {
                                normalize_screening_status(status, &node_location, warnings)
                            })
                            .unwrap_or(ResearchNodeStatus::Open),
                    )
                    .with_order(
                        input.round_index,
                        u32::try_from(plan_index + 1).unwrap_or(u32::MAX),
                        u32::try_from(node_index + 1).unwrap_or(u32::MAX),
                    );
                for dependency in dependencies {
                    let dependency = ResearchNodeId::parse(dependency)?;
                    if !seen_dependencies.insert(dependency.clone()) {
                        return Err(malformed(
                            &node_location,
                            "duplicate canonical dependency node_id",
                        ));
                    }
                    node = node.with_dependency(dependency);
                }
                if nodes.insert(node_id.clone(), node).is_some() {
                    return Err(ResearchStateError::DuplicateIdentifier {
                        kind: "research_node_id",
                        identifier: node_id.to_string(),
                    });
                }
                enforce_count("legacy_research_nodes", nodes.len(), MAX_RESEARCH_NODES)?;
                plan_nodes.push(LegacyPlanNode {
                    node_id,
                    subgoal_id: subgoal_id.to_owned(),
                    statement,
                });
            }
            plans.insert(plan_id, plan_nodes);
            continue;
        }
        let subgoals = required_string_array(
            object.get("subgoals"),
            &format!("{location}.subgoals"),
            MAX_NODE_DEPENDENCIES,
        )?;
        let subgoal_ids = required_string_array(
            object.get("subgoal_ids"),
            &format!("{location}.subgoal_ids"),
            MAX_NODE_DEPENDENCIES,
        )?;
        if subgoals.len() != subgoal_ids.len() {
            return Err(malformed(
                &location,
                "subgoals and subgoal_ids must have equal lengths",
            ));
        }
        let mut plan_nodes = Vec::new();
        let mut local_ids = BTreeSet::new();
        for (node_index, (subgoal_id, statement)) in
            subgoal_ids.into_iter().zip(subgoals).enumerate()
        {
            if !local_ids.insert(subgoal_id.clone()) {
                return Err(malformed(
                    format!("{location}.subgoal_ids[{node_index}]"),
                    "duplicate subgoal id",
                ));
            }
            let node_id = combined_node_id(&plan_id, &subgoal_id)?;
            let status = progress
                .and_then(|items| items.get(plan_id.as_str()))
                .and_then(Value::as_object)
                .and_then(|items| items.get(&subgoal_id))
                .and_then(Value::as_object)
                .and_then(|item| item.get("status"))
                .and_then(Value::as_str)
                .map(|status| normalize_screening_status(status, &location, warnings))
                .unwrap_or(ResearchNodeStatus::Open);
            let node =
                ResearchNode::new(node_id.clone(), statement.clone(), ResearchNodeKind::Lemma)?
                    .with_plan(plan_id.clone())
                    .with_status(status)
                    .with_order(
                        input.round_index,
                        u32::try_from(plan_index + 1).unwrap_or(u32::MAX),
                        u32::try_from(node_index + 1).unwrap_or(u32::MAX),
                    );
            if nodes.insert(node_id.clone(), node).is_some() {
                return Err(ResearchStateError::DuplicateIdentifier {
                    kind: "research_node_id",
                    identifier: node_id.to_string(),
                });
            }
            enforce_count("legacy_research_nodes", nodes.len(), MAX_RESEARCH_NODES)?;
            plan_nodes.push(LegacyPlanNode {
                node_id,
                subgoal_id,
                statement,
            });
        }
        plans.insert(plan_id, plan_nodes);
    }
    if let Some(progress) = progress {
        for plan_id in progress.keys() {
            if !active_plan_ids
                .iter()
                .any(|known| known.as_str() == plan_id)
            {
                warnings.push(
                    "inactive_screening_plan",
                    format!("screening_progress.{plan_id}"),
                    "screening progress refers to a plan that is not active",
                );
            }
        }
    }
    Ok(())
}

fn normalize_direct_attempts(
    input: &LegacyResearchInput,
    plans: &BTreeMap<ResearchPlanId, Vec<LegacyPlanNode>>,
    attempts: &mut Vec<ResearchAttempt>,
    sequence: &mut u64,
    warnings: &mut WarningCollector,
) -> Result<(), ResearchStateError> {
    for (record_index, record) in input.proof_steps.iter().enumerate() {
        if record.get("record_type").and_then(Value::as_str) != Some("direct_screening_round") {
            continue;
        }
        let actor = record
            .get("actor_domain_id")
            .and_then(Value::as_str)
            .map(ResearchDomainId::parse)
            .transpose()?
            .unwrap_or(ResearchDomainId::parse("legacy-generation")?);
        let Some(raw_plans) = record.get("plans").and_then(Value::as_array) else {
            warnings.push(
                "malformed_direct_round",
                format!("proof_steps[{record_index}]"),
                "direct_screening_round has no plans array",
            );
            continue;
        };
        enforce_count(
            "legacy_direct_screening_plans",
            raw_plans.len(),
            MAX_ACTIVE_PLANS,
        )?;
        for (plan_index, raw_plan) in raw_plans.iter().enumerate() {
            let Some(plan_text) = raw_plan.get("plan_id").and_then(Value::as_str) else {
                warnings.push(
                    "missing_plan_id",
                    format!("proof_steps[{record_index}].plans[{plan_index}]"),
                    "direct-screening plan has no plan_id",
                );
                continue;
            };
            let Some((_plan_id, plan_nodes)) = find_plan(plans, plan_text) else {
                warnings.push(
                    "unknown_direct_plan",
                    format!("proof_steps[{record_index}].plans[{plan_index}]"),
                    "direct-screening attempt refers to an unknown plan",
                );
                continue;
            };
            let Some(results) = raw_plan.get("subgoal_results").and_then(Value::as_array) else {
                warnings.push(
                    "missing_subgoal_results",
                    format!("proof_steps[{record_index}].plans[{plan_index}]"),
                    "direct-screening plan has no subgoal_results array",
                );
                continue;
            };
            enforce_count(
                "legacy_direct_screening_results",
                results.len(),
                MAX_NODE_DEPENDENCIES,
            )?;
            for (result_index, result) in results.iter().enumerate() {
                let Some(subgoal_id) = result.get("subgoal_id").and_then(Value::as_str) else {
                    warnings.push(
                        "missing_subgoal_id",
                        format!(
                            "proof_steps[{record_index}].plans[{plan_index}].subgoal_results[{result_index}]"
                        ),
                        "direct-screening result has no subgoal_id",
                    );
                    continue;
                };
                let Some(node) = plan_nodes.iter().find(|node| node.subgoal_id == subgoal_id)
                else {
                    warnings.push(
                        "unknown_direct_subgoal",
                        format!(
                            "proof_steps[{record_index}].plans[{plan_index}].subgoal_results[{result_index}]"
                        ),
                        "direct-screening result refers to an unknown subgoal",
                    );
                    continue;
                };
                let status = result
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let outcome = screening_outcome(status).unwrap_or_else(|| {
                    warnings.push(
                        "unknown_direct_screening_status",
                        format!(
                            "proof_steps[{record_index}].plans[{plan_index}].subgoal_results[{result_index}].status"
                        ),
                        "direct-screening status is absent or unknown and is treated as inconclusive",
                    );
                    ResearchAttemptOutcome::Inconclusive
                });
                let summary = result
                    .get("summary")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or("Direct screening produced no summary.");
                *sequence = sequence.saturating_add(1);
                let method = match result.get("method").and_then(Value::as_str) {
                    Some(value) => ResearchAttemptMethod::parse(value).ok_or_else(|| {
                        malformed(
                            format!(
                                "proof_steps[{record_index}].plans[{plan_index}].subgoal_results[{result_index}].method"
                            ),
                            "unknown protocol-3 attempt method",
                        )
                    })?,
                    None => ResearchAttemptMethod::Direct,
                };
                let obstruction = match result.get("obstruction") {
                    None | Some(Value::Null) => None,
                    Some(value) => Some(
                        value
                            .as_str()
                            .and_then(ResearchObstruction::parse)
                            .ok_or_else(|| {
                                malformed(
                                    format!(
                                        "proof_steps[{record_index}].plans[{plan_index}].subgoal_results[{result_index}].obstruction"
                                    ),
                                    "unknown protocol-3 obstruction class",
                                )
                            })?,
                    ),
                };
                let attempt_id = result
                    .get("attempt_id")
                    .and_then(Value::as_str)
                    .map(ResearchAttemptId::parse)
                    .transpose()?
                    .unwrap_or(ResearchAttemptId::parse(format!(
                        "attempt:direct:{}:{}:{}",
                        record_index + 1,
                        plan_index + 1,
                        result_index + 1
                    ))?);
                let mut attempt = ResearchAttempt::new(
                    attempt_id,
                    node.node_id.clone(),
                    actor.clone(),
                    method,
                    outcome,
                    summary,
                )?
                .with_position(input.round_index, *sequence);
                if let Some(obstruction) = obstruction {
                    attempt = attempt.with_obstruction(obstruction);
                } else if status == "stuck" {
                    attempt = attempt.with_obstruction(ResearchObstruction::NoProgress);
                }
                for evidence_id in bounded_optional_string_array(
                    result.get("evidence_ids"),
                    &format!(
                        "proof_steps[{record_index}].plans[{plan_index}].subgoal_results[{result_index}].evidence_ids"
                    ),
                    MAX_EVIDENCE_IDS,
                )? {
                    attempt = attempt.with_evidence(evidence_id)?;
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
        }
    }
    Ok(())
}

fn enforce_count(
    kind: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), ResearchStateError> {
    if actual > limit {
        return Err(ResearchStateError::LimitExceeded {
            kind,
            limit,
            actual,
        });
    }
    Ok(())
}

fn truncate_utf8(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_owned();
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value[..end].to_owned()
}
