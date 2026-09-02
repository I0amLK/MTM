use serde::Serialize;
use serde_json::Value;

use super::{
    ResearchAdvisory, ResearchAttempt, ResearchAttemptMethod, ResearchAttemptOutcome, ResearchNode,
    ResearchNodeId, ResearchNodeStatus, ResearchNormalizationWarning, ResearchState,
    ResearchStateError,
};

pub const MAX_RESEARCH_TASK_VIEW_BYTES: usize = 16_384;
const MAX_VIEW_FRONTIER: usize = 5;
const MAX_VIEW_ATTEMPTS: usize = 5;
const MAX_VIEW_PARTIAL_RESULTS: usize = 5;
const MAX_VIEW_WARNINGS: usize = 3;
const MAX_VIEW_EVIDENCE_IDS: usize = 3;
const MAX_TARGET_TEXT_BYTES: usize = 2_048;
const MAX_NODE_TEXT_BYTES: usize = 768;
const MAX_ATTEMPT_TEXT_BYTES: usize = 768;
const MAX_WARNING_TEXT_BYTES: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct NodeView {
    node_id: String,
    statement: String,
    status: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct AttemptView {
    attempt_id: String,
    node_id: String,
    method: String,
    outcome: String,
    summary: String,
    obstruction: Option<String>,
    evidence_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct RetrievalView {
    attempts: usize,
    new_material_attempts: usize,
    consecutive_no_new_material: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct WarningView {
    code: String,
    location: String,
    message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ResearchViewCounts {
    nodes: usize,
    attempts: usize,
    decisions: usize,
    critical_blockers: usize,
    actionable_frontier: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResearchTaskView {
    advisory_only: bool,
    target: NodeView,
    current_blocker: Option<NodeView>,
    frontier: Vec<NodeView>,
    recent_attempts: Vec<AttemptView>,
    counterexample_coverage: String,
    retrieval: RetrievalView,
    preserved_partial_results: Vec<NodeView>,
    suggested_next_action: ResearchAdvisory,
    graph_digest: String,
    counts: ResearchViewCounts,
    warnings: Vec<WarningView>,
    truncated: bool,
}

impl ResearchTaskView {
    pub fn build(
        state: &ResearchState,
        normalization_warnings: &[ResearchNormalizationWarning],
    ) -> Result<Self, ResearchStateError> {
        let mut truncated = false;
        let target = state
            .nodes()
            .get(state.target_node_id())
            .ok_or(ResearchStateError::MissingTarget)?;
        let target = node_view(target, MAX_TARGET_TEXT_BYTES, &mut truncated);

        let blocker_id = state.critical_blockers().first();
        let current_blocker = blocker_id
            .and_then(|node_id| state.nodes().get(node_id))
            .map(|node| node_view(node, MAX_NODE_TEXT_BYTES, &mut truncated));

        if state.actionable_frontier().len() > MAX_VIEW_FRONTIER {
            truncated = true;
        }
        let frontier = state
            .actionable_frontier()
            .iter()
            .take(MAX_VIEW_FRONTIER)
            .filter_map(|node_id| state.nodes().get(node_id))
            .map(|node| node_view(node, MAX_NODE_TEXT_BYTES, &mut truncated))
            .collect::<Vec<_>>();

        let relevant_attempts = recent_attempts(state, blocker_id);
        if relevant_attempts.1 {
            truncated = true;
        }
        let recent_attempts = relevant_attempts
            .0
            .into_iter()
            .map(|attempt| attempt_view(attempt, &mut truncated))
            .collect::<Vec<_>>();

        let partial_nodes = state
            .nodes()
            .values()
            .filter(|node| node.status() == ResearchNodeStatus::Partial)
            .collect::<Vec<_>>();
        if partial_nodes.len() > MAX_VIEW_PARTIAL_RESULTS {
            truncated = true;
        }
        let preserved_partial_results = partial_nodes
            .into_iter()
            .take(MAX_VIEW_PARTIAL_RESULTS)
            .map(|node| node_view(node, MAX_NODE_TEXT_BYTES, &mut truncated))
            .collect::<Vec<_>>();

        if normalization_warnings.len() > MAX_VIEW_WARNINGS {
            truncated = true;
        }
        let warnings = normalization_warnings
            .iter()
            .take(MAX_VIEW_WARNINGS)
            .map(|warning| WarningView {
                code: bounded_text(warning.code(), 128, &mut truncated),
                location: bounded_text(warning.location(), MAX_WARNING_TEXT_BYTES, &mut truncated),
                message: bounded_text(warning.message(), MAX_WARNING_TEXT_BYTES, &mut truncated),
            })
            .collect::<Vec<_>>();

        let view = Self {
            advisory_only: true,
            target,
            current_blocker,
            frontier,
            recent_attempts,
            counterexample_coverage: counterexample_coverage(state).to_owned(),
            retrieval: retrieval_view(state),
            preserved_partial_results,
            suggested_next_action: ResearchAdvisory::select(state),
            graph_digest: state.digest().to_owned(),
            counts: ResearchViewCounts {
                nodes: state.nodes().len(),
                attempts: state.attempts().len(),
                decisions: state.decisions().len(),
                critical_blockers: state.critical_blockers().len(),
                actionable_frontier: state.actionable_frontier().len(),
            },
            warnings,
            truncated,
        };
        let bytes = serde_json::to_vec(&view).map_err(|_| ResearchStateError::Serialization)?;
        if bytes.len() > MAX_RESEARCH_TASK_VIEW_BYTES {
            return Err(ResearchStateError::LimitExceeded {
                kind: "research_task_view_bytes",
                limit: MAX_RESEARCH_TASK_VIEW_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(view)
    }

    pub fn to_value(&self) -> Result<Value, ResearchStateError> {
        serde_json::to_value(self).map_err(|_| ResearchStateError::Serialization)
    }

    #[must_use]
    pub fn advisory(&self) -> &ResearchAdvisory {
        &self.suggested_next_action
    }

    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn serialized_len(&self) -> Result<usize, ResearchStateError> {
        serde_json::to_vec(self)
            .map(|bytes| bytes.len())
            .map_err(|_| ResearchStateError::Serialization)
    }
}

fn node_view(node: &ResearchNode, maximum: usize, truncated: &mut bool) -> NodeView {
    NodeView {
        node_id: node.node_id().to_string(),
        statement: bounded_text(node.statement(), maximum, truncated),
        status: node.status().as_str().to_owned(),
    }
}

fn recent_attempts<'a>(
    state: &'a ResearchState,
    focus: Option<&ResearchNodeId>,
) -> (Vec<&'a ResearchAttempt>, bool) {
    let focused = focus
        .map(|node_id| {
            state
                .attempts()
                .iter()
                .filter(|attempt| attempt.node_id() == node_id)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let source = if focused.is_empty() {
        state.attempts().iter().collect::<Vec<_>>()
    } else {
        focused
    };
    let truncated = source.len() > MAX_VIEW_ATTEMPTS;
    (
        source.into_iter().rev().take(MAX_VIEW_ATTEMPTS).collect(),
        truncated,
    )
}

fn attempt_view(attempt: &ResearchAttempt, truncated: &mut bool) -> AttemptView {
    if attempt.evidence_ids().len() > MAX_VIEW_EVIDENCE_IDS {
        *truncated = true;
    }
    AttemptView {
        attempt_id: attempt.attempt_id().to_string(),
        node_id: attempt.node_id().to_string(),
        method: attempt.method().as_str().to_owned(),
        outcome: attempt.outcome().as_str().to_owned(),
        summary: bounded_text(attempt.summary(), MAX_ATTEMPT_TEXT_BYTES, truncated),
        obstruction: attempt
            .obstruction()
            .map(|obstruction| obstruction.as_str().to_owned()),
        evidence_ids: attempt
            .evidence_ids()
            .iter()
            .take(MAX_VIEW_EVIDENCE_IDS)
            .map(|value| bounded_text(value, 256, truncated))
            .collect(),
    }
}

fn counterexample_coverage(state: &ResearchState) -> &'static str {
    let attempts = state
        .attempts()
        .iter()
        .filter(|attempt| attempt.method() == ResearchAttemptMethod::Counterexample)
        .collect::<Vec<_>>();
    if attempts
        .iter()
        .any(|attempt| attempt.outcome() == ResearchAttemptOutcome::Refuted)
    {
        "found"
    } else if attempts.is_empty() {
        "not_attempted"
    } else {
        "attempted"
    }
}

fn retrieval_view(state: &ResearchState) -> RetrievalView {
    let retrievals = state
        .attempts()
        .iter()
        .filter(|attempt| attempt.method() == ResearchAttemptMethod::Retrieval)
        .collect::<Vec<_>>();
    let new_material_attempts = retrievals
        .iter()
        .filter(|attempt| attempt.outcome() == ResearchAttemptOutcome::Progress)
        .count();
    let consecutive_no_new_material = retrievals
        .iter()
        .rev()
        .take_while(|attempt| attempt.outcome() == ResearchAttemptOutcome::Inconclusive)
        .count();
    RetrievalView {
        attempts: retrievals.len(),
        new_material_attempts,
        consecutive_no_new_material,
    }
}

fn bounded_text(value: &str, maximum: usize, truncated: &mut bool) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    *truncated = true;
    let mut end = maximum;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::research_state::{
        ResearchAdviceRule, ResearchAttemptId, ResearchDomainId, ResearchNodeKind, ResearchPlanId,
        ResearchSnapshot, ResearchStateProjector,
    };

    #[test]
    fn compact_view_is_deterministic_bounded_and_contains_no_authority_fields()
    -> Result<(), ResearchStateError> {
        let target = ResearchNodeId::parse("target")?;
        let plan = ResearchPlanId::parse("plan-a")?;
        let mut snapshot = ResearchSnapshot::new(target.clone()).with_node(ResearchNode::new(
            target.clone(),
            "Target",
            ResearchNodeKind::Target,
        )?);
        for index in 0..12 {
            let node_id = ResearchNodeId::parse(format!("lemma-{index:02}"))?;
            snapshot = snapshot.with_node(
                ResearchNode::new(
                    node_id.clone(),
                    format!("Lemma {index}: {}", "x".repeat(1200)),
                    ResearchNodeKind::Lemma,
                )?
                .with_plan(plan.clone())
                .with_declared_critical(true)
                .with_status(ResearchNodeStatus::Partial),
            );
            snapshot = snapshot.with_attempt(
                ResearchAttempt::new(
                    ResearchAttemptId::parse(format!("attempt-{index:02}"))?,
                    node_id,
                    ResearchDomainId::parse("private-branch-domain")?,
                    ResearchAttemptMethod::Direct,
                    ResearchAttemptOutcome::Progress,
                    "progress ".repeat(200),
                )?
                .with_position(1, index + 1),
            );
        }
        snapshot = snapshot.with_active_plan(plan);
        let state = ResearchStateProjector::analyze(&snapshot)?;
        let view_a = ResearchTaskView::build(&state, &[])?;
        let view_b = ResearchTaskView::build(&state, &[])?;
        let a = view_a.to_value()?;
        let b = view_b.to_value()?;
        assert_eq!(a, b);
        assert!(view_a.serialized_len()? <= MAX_RESEARCH_TASK_VIEW_BYTES);
        assert!(view_a.truncated());
        let text = a.to_string();
        assert!(!text.contains("private-branch-domain"));
        assert!(!text.contains("capability"));
        assert!(!text.contains("private_vault"));
        Ok(())
    }

    #[test]
    fn view_reports_counterexample_and_retrieval_coverage() -> Result<(), ResearchStateError> {
        let target = ResearchNodeId::parse("target")?;
        let attempt_node = target.clone();
        let snapshot = ResearchSnapshot::new(target.clone())
            .with_node(
                ResearchNode::new(target, "Target", ResearchNodeKind::Target)?
                    .with_status(ResearchNodeStatus::Blocked),
            )
            .with_attempt(ResearchAttempt::new(
                ResearchAttemptId::parse("counterexample-1")?,
                attempt_node.clone(),
                ResearchDomainId::parse("domain")?,
                ResearchAttemptMethod::Counterexample,
                ResearchAttemptOutcome::Inconclusive,
                "No counterexample within the tested scope.",
            )?)
            .with_attempt(ResearchAttempt::new(
                ResearchAttemptId::parse("retrieval-1")?,
                attempt_node.clone(),
                ResearchDomainId::parse("domain")?,
                ResearchAttemptMethod::Retrieval,
                ResearchAttemptOutcome::Inconclusive,
                "No new source.",
            )?)
            .with_attempt(ResearchAttempt::new(
                ResearchAttemptId::parse("retrieval-2")?,
                attempt_node,
                ResearchDomainId::parse("domain")?,
                ResearchAttemptMethod::Retrieval,
                ResearchAttemptOutcome::Inconclusive,
                "Still no new source.",
            )?);
        let state = ResearchStateProjector::analyze(&snapshot)?;
        let value = ResearchTaskView::build(&state, &[])?.to_value()?;
        assert_eq!(value["counterexample_coverage"], "attempted");
        assert_eq!(value["retrieval"]["attempts"], 2);
        assert_eq!(value["retrieval"]["consecutive_no_new_material"], 2);
        assert_eq!(
            value["suggested_next_action"]["rule_id"],
            ResearchAdviceRule::StopRetrieval.as_str()
        );
        Ok(())
    }
}
