use std::collections::BTreeSet;

use serde::Serialize;

use super::{
    ResearchAttempt, ResearchAttemptMethod, ResearchAttemptOutcome, ResearchNodeId,
    ResearchNodeStatus, ResearchObstruction, ResearchState,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ResearchAdviceRule {
    #[serde(rename = "R08_ASSEMBLE")]
    Assemble,
    #[serde(rename = "R01_REPLAN_REFUTED")]
    ReplanRefuted,
    #[serde(rename = "R02_REPLAN_CYCLE")]
    ReplanCycle,
    #[serde(rename = "R03_TEST_COUNTEREXAMPLE")]
    TestCounterexample,
    #[serde(rename = "R04_RETRIEVE_FOCUSED")]
    RetrieveFocused,
    #[serde(rename = "R05_STOP_RETRIEVAL")]
    StopRetrieval,
    #[serde(rename = "R06_SCREEN_FRONTIER")]
    ScreenFrontier,
    #[serde(rename = "R07_CONSOLIDATE")]
    Consolidate,
    #[serde(rename = "R09_REVIEW_STATE")]
    ReviewState,
}

impl ResearchAdviceRule {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Assemble => "R08_ASSEMBLE",
            Self::ReplanRefuted => "R01_REPLAN_REFUTED",
            Self::ReplanCycle => "R02_REPLAN_CYCLE",
            Self::TestCounterexample => "R03_TEST_COUNTEREXAMPLE",
            Self::RetrieveFocused => "R04_RETRIEVE_FOCUSED",
            Self::StopRetrieval => "R05_STOP_RETRIEVAL",
            Self::ScreenFrontier => "R06_SCREEN_FRONTIER",
            Self::Consolidate => "R07_CONSOLIDATE",
            Self::ReviewState => "R09_REVIEW_STATE",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResearchAdvisory {
    rule_id: ResearchAdviceRule,
    focus_node_id: Option<ResearchNodeId>,
    summary: String,
    evidence_facts: Vec<String>,
}

impl ResearchAdvisory {
    #[must_use]
    pub fn select(state: &ResearchState) -> Self {
        if target_or_route_solved(state) {
            return Self::new(
                ResearchAdviceRule::Assemble,
                Some(state.target_node_id().clone()),
                "A complete route is available; assemble the full LaTeX proof.",
                vec!["at_least_one_active_route=route_solved".to_owned()],
            );
        }

        if let Some(node_id) = refuted_without_viable_alternative(state) {
            return Self::new(
                ResearchAdviceRule::ReplanRefuted,
                Some(node_id.clone()),
                "A proof-critical claim is refuted and no viable alternative route remains; replan around the counterexample.",
                vec![
                    format!("refuted_critical_node={node_id}"),
                    "viable_alternative_routes=0".to_owned(),
                ],
            );
        }

        if let Some((node_id, failures)) = repeated_direct_failure_without_counterexample(state) {
            return Self::new(
                ResearchAdviceRule::TestCounterexample,
                Some(node_id.clone()),
                "Repeated direct proof attempts failed; test the smallest meaningful examples before another proof attempt.",
                vec![
                    format!("direct_failed_attempts={failures}"),
                    "counterexample_attempts=0".to_owned(),
                ],
            );
        }

        if let Some(node_id) = missing_reference_without_retrieval(state) {
            return Self::new(
                ResearchAdviceRule::RetrieveFocused,
                Some(node_id.clone()),
                "The current obstruction is a missing external result; retrieve one focused source for this claim.",
                vec![
                    format!("missing_reference_node={node_id}"),
                    "focused_retrieval_attempts=0".to_owned(),
                ],
            );
        }

        if let Some((node_id, count)) = repeated_retrieval_without_novelty(state) {
            return Self::new(
                ResearchAdviceRule::StopRetrieval,
                Some(node_id.clone()),
                "Recent retrieval attempts added no new material; stop searching and synthesize the sources already collected.",
                vec![format!("consecutive_no_novelty_retrievals={count}")],
            );
        }

        if let Some(node_id) = untouched_actionable_critical_node(state) {
            return Self::new(
                ResearchAdviceRule::ScreenFrontier,
                Some(node_id.clone()),
                "An untouched proof-critical frontier claim is actionable; attempt it directly or test a diagnostic toy example.",
                vec![format!("untouched_actionable_node={node_id}")],
            );
        }

        if let Some((node_id, progress_count)) = compatible_partial_progress(state) {
            return Self::new(
                ResearchAdviceRule::Consolidate,
                Some(node_id.clone()),
                "Several non-retrieval attempts made compatible partial progress; consolidate them into one reusable lemma.",
                vec![format!("partial_progress_attempts={progress_count}")],
            );
        }

        let focus = state
            .critical_blockers()
            .first()
            .or_else(|| state.actionable_frontier().first())
            .cloned();
        Self::new(
            ResearchAdviceRule::ReviewState,
            focus,
            "No more specific research rule applies; review the current declarations and choose the next mathematical action.",
            vec!["specific_advisory_rule_match=none".to_owned()],
        )
    }

    #[must_use]
    pub fn cycle_diagnostic(cycle: &[ResearchNodeId]) -> Self {
        Self::new(
            ResearchAdviceRule::ReplanCycle,
            cycle.first().cloned(),
            "The submitted mathematical dependency graph is circular; remove the circular dependency before persistence.",
            vec![format!(
                "cycle={}",
                cycle
                    .iter()
                    .map(ResearchNodeId::as_str)
                    .collect::<Vec<_>>()
                    .join("->")
            )],
        )
    }

    fn new(
        rule_id: ResearchAdviceRule,
        focus_node_id: Option<ResearchNodeId>,
        summary: impl Into<String>,
        evidence_facts: Vec<String>,
    ) -> Self {
        Self {
            rule_id,
            focus_node_id,
            summary: summary.into(),
            evidence_facts,
        }
    }

    #[must_use]
    pub const fn rule_id(&self) -> ResearchAdviceRule {
        self.rule_id
    }

    #[must_use]
    pub fn focus_node_id(&self) -> Option<&ResearchNodeId> {
        self.focus_node_id.as_ref()
    }

    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    #[must_use]
    pub fn evidence_facts(&self) -> &[String] {
        &self.evidence_facts
    }
}

fn target_or_route_solved(state: &ResearchState) -> bool {
    state
        .nodes()
        .get(state.target_node_id())
        .is_some_and(|node| node.status() == ResearchNodeStatus::RouteSolved)
        || state
            .plan_routes()
            .values()
            .any(|route| route.route_solved())
}

fn refuted_without_viable_alternative(state: &ResearchState) -> Option<&ResearchNodeId> {
    let refuted = state.critical_nodes().iter().find(|node_id| {
        state
            .nodes()
            .get(*node_id)
            .is_some_and(|node| node.status() == ResearchNodeStatus::Refuted)
    })?;
    let viable_alternative = state
        .plan_routes()
        .values()
        .any(|route| route.invalid_nodes().is_empty());
    (!viable_alternative).then_some(refuted)
}

fn attempts_for_node<'a>(
    state: &'a ResearchState,
    node_id: &'a ResearchNodeId,
) -> impl Iterator<Item = &'a ResearchAttempt> {
    state
        .attempts()
        .iter()
        .filter(move |attempt| attempt.node_id() == node_id)
}

fn repeated_direct_failure_without_counterexample(
    state: &ResearchState,
) -> Option<(&ResearchNodeId, usize)> {
    state.critical_blockers().iter().find_map(|node_id| {
        let direct_failures = attempts_for_node(state, node_id)
            .filter(|attempt| {
                attempt.method() == ResearchAttemptMethod::Direct
                    && attempt.outcome() == ResearchAttemptOutcome::Failed
            })
            .count();
        let counterexample_attempted = attempts_for_node(state, node_id)
            .any(|attempt| attempt.method() == ResearchAttemptMethod::Counterexample);
        (direct_failures >= 2 && !counterexample_attempted).then_some((node_id, direct_failures))
    })
}

fn missing_reference_without_retrieval(state: &ResearchState) -> Option<&ResearchNodeId> {
    state.critical_blockers().iter().find(|node_id| {
        let missing_reference = attempts_for_node(state, node_id)
            .any(|attempt| attempt.obstruction() == Some(ResearchObstruction::MissingReference));
        let retrieval_attempted = attempts_for_node(state, node_id)
            .any(|attempt| attempt.method() == ResearchAttemptMethod::Retrieval);
        missing_reference && !retrieval_attempted
    })
}

fn repeated_retrieval_without_novelty(state: &ResearchState) -> Option<(&ResearchNodeId, usize)> {
    let retrievals = state
        .attempts()
        .iter()
        .filter(|attempt| attempt.method() == ResearchAttemptMethod::Retrieval)
        .collect::<Vec<_>>();
    if retrievals.len() < 2 {
        return None;
    }
    let mut consecutive = 0usize;
    let mut focus = None;
    for attempt in retrievals.iter().rev() {
        if attempt.outcome() == ResearchAttemptOutcome::Inconclusive {
            consecutive += 1;
            focus = Some(attempt.node_id());
        } else {
            break;
        }
    }
    if consecutive >= 2 {
        focus.map(|node_id| (node_id, consecutive))
    } else {
        None
    }
}

fn untouched_actionable_critical_node(state: &ResearchState) -> Option<&ResearchNodeId> {
    let critical = state.critical_nodes().iter().collect::<BTreeSet<_>>();
    state.actionable_frontier().iter().find(|node_id| {
        critical.contains(node_id) && attempts_for_node(state, node_id).next().is_none()
    })
}

fn compatible_partial_progress(state: &ResearchState) -> Option<(&ResearchNodeId, usize)> {
    state.critical_blockers().iter().find_map(|node_id| {
        let node = state.nodes().get(node_id)?;
        if node.status() != ResearchNodeStatus::Partial {
            return None;
        }
        let progress = attempts_for_node(state, node_id)
            .filter(|attempt| {
                attempt.method() != ResearchAttemptMethod::Retrieval
                    && attempt.outcome() == ResearchAttemptOutcome::Progress
            })
            .count();
        (progress >= 2).then_some((node_id, progress))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::research_state::{
        ResearchAttemptId, ResearchDomainId, ResearchNode, ResearchNodeKind, ResearchPlanId,
        ResearchSnapshot, ResearchStateError, ResearchStateProjector,
    };

    fn id(value: &str) -> Result<ResearchNodeId, ResearchStateError> {
        ResearchNodeId::parse(value)
    }

    fn plan(value: &str) -> Result<ResearchPlanId, ResearchStateError> {
        ResearchPlanId::parse(value)
    }

    fn domain() -> Result<ResearchDomainId, ResearchStateError> {
        ResearchDomainId::parse("test-domain")
    }

    fn state_with_status(status: ResearchNodeStatus) -> Result<ResearchState, ResearchStateError> {
        let target = id("target")?;
        let lemma = id("lemma-a")?;
        let route = plan("plan-a")?;
        let snapshot = ResearchSnapshot::new(target.clone())
            .with_node(
                ResearchNode::new(target.clone(), "Target", ResearchNodeKind::Target)?
                    .with_dependency(lemma.clone()),
            )
            .with_node(
                ResearchNode::new(lemma, "Lemma A", ResearchNodeKind::Lemma)?
                    .with_plan(route.clone())
                    .with_declared_critical(true)
                    .with_status(status),
            )
            .with_active_plan(route);
        ResearchStateProjector::analyze(&snapshot)
    }

    fn state_with_attempts(
        attempts: Vec<ResearchAttempt>,
        status: ResearchNodeStatus,
    ) -> Result<ResearchState, ResearchStateError> {
        let target = id("target")?;
        let lemma = id("lemma-a")?;
        let route = plan("plan-a")?;
        let mut snapshot = ResearchSnapshot::new(target.clone())
            .with_node(
                ResearchNode::new(target, "Target", ResearchNodeKind::Target)?
                    .with_dependency(lemma.clone()),
            )
            .with_node(
                ResearchNode::new(lemma, "Lemma A", ResearchNodeKind::Lemma)?
                    .with_plan(route.clone())
                    .with_declared_critical(true)
                    .with_status(status),
            )
            .with_active_plan(route);
        for attempt in attempts {
            snapshot = snapshot.with_attempt(attempt);
        }
        ResearchStateProjector::analyze(&snapshot)
    }

    fn attempt(
        suffix: usize,
        method: ResearchAttemptMethod,
        outcome: ResearchAttemptOutcome,
        obstruction: Option<ResearchObstruction>,
    ) -> Result<ResearchAttempt, ResearchStateError> {
        let mut value = ResearchAttempt::new(
            ResearchAttemptId::parse(format!("attempt-{suffix}"))?,
            id("lemma-a")?,
            domain()?,
            method,
            outcome,
            format!("attempt {suffix}"),
        )?
        .with_position(1, suffix as u64);
        if let Some(obstruction) = obstruction {
            value = value.with_obstruction(obstruction);
        }
        Ok(value)
    }

    #[test]
    fn assemble_precedes_refuted_alternative() -> Result<(), ResearchStateError> {
        let target = id("target")?;
        let solved = id("solved")?;
        let refuted = id("refuted")?;
        let solved_plan = plan("plan-solved")?;
        let bad_plan = plan("plan-bad")?;
        let state = ResearchStateProjector::analyze(
            &ResearchSnapshot::new(target.clone())
                .with_node(ResearchNode::new(
                    target,
                    "Target",
                    ResearchNodeKind::Target,
                )?)
                .with_node(
                    ResearchNode::new(solved, "Solved", ResearchNodeKind::Lemma)?
                        .with_plan(solved_plan.clone())
                        .with_declared_critical(true)
                        .with_status(ResearchNodeStatus::RouteSolved),
                )
                .with_node(
                    ResearchNode::new(refuted, "Refuted", ResearchNodeKind::Lemma)?
                        .with_plan(bad_plan.clone())
                        .with_declared_critical(true)
                        .with_status(ResearchNodeStatus::Refuted),
                )
                .with_active_plan(solved_plan)
                .with_active_plan(bad_plan),
        )?;
        assert_eq!(
            ResearchAdvisory::select(&state).rule_id(),
            ResearchAdviceRule::Assemble
        );
        Ok(())
    }

    #[test]
    fn refuted_only_route_suggests_replanning() -> Result<(), ResearchStateError> {
        let target = id("target")?;
        let refuted = id("refuted")?;
        let route = plan("plan-refuted")?;
        let state = ResearchStateProjector::analyze(
            &ResearchSnapshot::new(target.clone())
                .with_node(
                    ResearchNode::new(target, "Target", ResearchNodeKind::Target)?
                        .with_dependency(refuted.clone()),
                )
                .with_node(
                    ResearchNode::new(refuted, "Refuted lemma", ResearchNodeKind::Lemma)?
                        .with_plan(route.clone())
                        .with_declared_critical(true)
                        .with_status(ResearchNodeStatus::Refuted),
                )
                .with_active_plan(route),
        )?;
        assert_eq!(
            ResearchAdvisory::select(&state).rule_id(),
            ResearchAdviceRule::ReplanRefuted
        );
        Ok(())
    }

    #[test]
    fn repeated_direct_failure_suggests_counterexample_before_retrieval()
    -> Result<(), ResearchStateError> {
        let state = state_with_attempts(
            vec![
                attempt(
                    1,
                    ResearchAttemptMethod::Direct,
                    ResearchAttemptOutcome::Failed,
                    Some(ResearchObstruction::MissingReference),
                )?,
                attempt(
                    2,
                    ResearchAttemptMethod::Direct,
                    ResearchAttemptOutcome::Failed,
                    Some(ResearchObstruction::MissingReference),
                )?,
            ],
            ResearchNodeStatus::Blocked,
        )?;
        assert_eq!(
            ResearchAdvisory::select(&state).rule_id(),
            ResearchAdviceRule::TestCounterexample
        );
        Ok(())
    }

    #[test]
    fn missing_reference_without_retrieval_suggests_focused_retrieval()
    -> Result<(), ResearchStateError> {
        let state = state_with_attempts(
            vec![attempt(
                1,
                ResearchAttemptMethod::Direct,
                ResearchAttemptOutcome::Failed,
                Some(ResearchObstruction::MissingReference),
            )?],
            ResearchNodeStatus::Blocked,
        )?;
        assert_eq!(
            ResearchAdvisory::select(&state).rule_id(),
            ResearchAdviceRule::RetrieveFocused
        );
        Ok(())
    }

    #[test]
    fn repeated_no_novelty_retrieval_suggests_stop() -> Result<(), ResearchStateError> {
        let state = state_with_attempts(
            vec![
                attempt(
                    1,
                    ResearchAttemptMethod::Retrieval,
                    ResearchAttemptOutcome::Inconclusive,
                    None,
                )?,
                attempt(
                    2,
                    ResearchAttemptMethod::Retrieval,
                    ResearchAttemptOutcome::Inconclusive,
                    None,
                )?,
            ],
            ResearchNodeStatus::Blocked,
        )?;
        assert_eq!(
            ResearchAdvisory::select(&state).rule_id(),
            ResearchAdviceRule::StopRetrieval
        );
        Ok(())
    }

    #[test]
    fn untouched_frontier_suggests_screening() -> Result<(), ResearchStateError> {
        let state = state_with_status(ResearchNodeStatus::Open)?;
        assert_eq!(
            ResearchAdvisory::select(&state).rule_id(),
            ResearchAdviceRule::ScreenFrontier
        );
        Ok(())
    }

    #[test]
    fn compatible_partial_progress_suggests_consolidation() -> Result<(), ResearchStateError> {
        let state = state_with_attempts(
            vec![
                attempt(
                    1,
                    ResearchAttemptMethod::Direct,
                    ResearchAttemptOutcome::Progress,
                    None,
                )?,
                attempt(
                    2,
                    ResearchAttemptMethod::Reduction,
                    ResearchAttemptOutcome::Progress,
                    None,
                )?,
            ],
            ResearchNodeStatus::Partial,
        )?;
        assert_eq!(
            ResearchAdvisory::select(&state).rule_id(),
            ResearchAdviceRule::Consolidate
        );
        Ok(())
    }

    #[test]
    fn fallback_and_cycle_diagnostic_have_stable_ids() -> Result<(), ResearchStateError> {
        let state = state_with_attempts(
            vec![attempt(
                1,
                ResearchAttemptMethod::Counterexample,
                ResearchAttemptOutcome::Inconclusive,
                None,
            )?],
            ResearchNodeStatus::Blocked,
        )?;
        assert_eq!(
            ResearchAdvisory::select(&state).rule_id(),
            ResearchAdviceRule::ReviewState
        );
        let cycle = ResearchAdvisory::cycle_diagnostic(&[id("a")?, id("b")?, id("a")?]);
        assert_eq!(cycle.rule_id(), ResearchAdviceRule::ReplanCycle);
        assert_eq!(cycle.rule_id().as_str(), "R02_REPLAN_CYCLE");
        Ok(())
    }
}
