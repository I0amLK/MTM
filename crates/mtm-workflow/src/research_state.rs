//! Pure mathematical research-state types and dependency-graph analysis.
//!
//! This module deliberately owns no workflow, storage, capability, clock, network,
//! process, verifier, or finalizer authority. It accepts already-normalized records
//! and deterministically derives a bounded graph projection.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;

use serde::Serialize;
use sha2::{Digest, Sha256};

pub const RESEARCH_STATE_SCHEMA_VERSION: u16 = 1;
pub const MAX_RESEARCH_NODES: usize = 256;
pub const MAX_RESEARCH_EDGES: usize = 1_024;
pub const MAX_RESEARCH_ATTEMPTS: usize = 2_048;
pub const MAX_RESEARCH_DECISIONS: usize = 256;
pub const MAX_ACTIVE_PLANS: usize = 64;
pub const MAX_NODE_DEPENDENCIES: usize = 64;
pub const MAX_EVIDENCE_IDS: usize = 32;
pub const MAX_DECISION_PLAN_IDS: usize = 64;
pub const MAX_DECISION_NODE_IDS: usize = 64;
pub const MAX_DECISION_CONSTRAINTS: usize = 64;
pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_STATEMENT_BYTES: usize = 16_384;
pub const MAX_SUMMARY_BYTES: usize = 8_192;
pub const MAX_REASON_BYTES: usize = 8_192;
pub const MAX_EVIDENCE_ID_BYTES: usize = 1_024;

macro_rules! identifier_type {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, ResearchStateError> {
                let value = value.into();
                validate_identifier($kind, &value)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

identifier_type!(ResearchNodeId, "research_node_id");
identifier_type!(ResearchAttemptId, "research_attempt_id");
identifier_type!(ResearchDecisionId, "research_decision_id");
identifier_type!(ResearchPlanId, "research_plan_id");
identifier_type!(ResearchDomainId, "research_domain_id");

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchNodeKind {
    Target,
    Lemma,
    Construction,
    Definition,
}

impl ResearchNodeKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::Lemma => "lemma",
            Self::Construction => "construction",
            Self::Definition => "definition",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchNodeStatus {
    Open,
    Partial,
    RouteSolved,
    Refuted,
    Blocked,
    Superseded,
}

impl ResearchNodeStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Partial => "partial",
            Self::RouteSolved => "route_solved",
            Self::Refuted => "refuted",
            Self::Blocked => "blocked",
            Self::Superseded => "superseded",
        }
    }

    #[must_use]
    pub const fn is_actionable(self) -> bool {
        matches!(self, Self::Open | Self::Partial | Self::Blocked)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchAttemptMethod {
    Direct,
    Reduction,
    ToyExample,
    Counterexample,
    Retrieval,
    Computation,
    Synthesis,
    Repair,
}

impl ResearchAttemptMethod {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Reduction => "reduction",
            Self::ToyExample => "toy_example",
            Self::Counterexample => "counterexample",
            Self::Retrieval => "retrieval",
            Self::Computation => "computation",
            Self::Synthesis => "synthesis",
            Self::Repair => "repair",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchAttemptOutcome {
    Progress,
    RouteSolved,
    Failed,
    Refuted,
    Inconclusive,
}

impl ResearchAttemptOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Progress => "progress",
            Self::RouteSolved => "route_solved",
            Self::Failed => "failed",
            Self::Refuted => "refuted",
            Self::Inconclusive => "inconclusive",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchObstruction {
    FalseClaim,
    MissingHypothesis,
    MissingLemma,
    MissingReference,
    ComputationalBottleneck,
    NotationMismatch,
    CircularDependency,
    IncompatiblePartialResults,
    NoProgress,
    Unknown,
}

impl ResearchObstruction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FalseClaim => "false_claim",
            Self::MissingHypothesis => "missing_hypothesis",
            Self::MissingLemma => "missing_lemma",
            Self::MissingReference => "missing_reference",
            Self::ComputationalBottleneck => "computational_bottleneck",
            Self::NotationMismatch => "notation_mismatch",
            Self::CircularDependency => "circular_dependency",
            Self::IncompatiblePartialResults => "incompatible_partial_results",
            Self::NoProgress => "no_progress",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResearchNode {
    node_id: ResearchNodeId,
    statement: String,
    kind: ResearchNodeKind,
    plan_id: Option<ResearchPlanId>,
    dependencies: BTreeSet<ResearchNodeId>,
    status: ResearchNodeStatus,
    revision: u32,
    created_round: u32,
    plan_order: u32,
    node_order: u32,
    latest_event_seq: u64,
}

impl ResearchNode {
    pub fn new(
        node_id: ResearchNodeId,
        statement: impl Into<String>,
        kind: ResearchNodeKind,
    ) -> Result<Self, ResearchStateError> {
        let statement = statement.into();
        validate_text("node.statement", &statement, MAX_STATEMENT_BYTES, false)?;
        let statement = statement.trim().to_owned();
        Ok(Self {
            node_id,
            statement,
            kind,
            plan_id: None,
            dependencies: BTreeSet::new(),
            status: ResearchNodeStatus::Open,
            revision: 1,
            created_round: 0,
            plan_order: 0,
            node_order: 0,
            latest_event_seq: 0,
        })
    }

    #[must_use]
    pub fn with_plan(mut self, plan_id: ResearchPlanId) -> Self {
        self.plan_id = Some(plan_id);
        self
    }

    #[must_use]
    pub fn with_dependency(mut self, dependency: ResearchNodeId) -> Self {
        self.dependencies.insert(dependency);
        self
    }

    #[must_use]
    pub fn with_status(mut self, status: ResearchNodeStatus) -> Self {
        self.status = status;
        self
    }

    #[must_use]
    pub fn with_revision(mut self, revision: u32, latest_event_seq: u64) -> Self {
        self.revision = revision;
        self.latest_event_seq = latest_event_seq;
        self
    }

    #[must_use]
    pub fn with_order(mut self, created_round: u32, plan_order: u32, node_order: u32) -> Self {
        self.created_round = created_round;
        self.plan_order = plan_order;
        self.node_order = node_order;
        self
    }

    #[must_use]
    pub fn node_id(&self) -> &ResearchNodeId {
        &self.node_id
    }

    #[must_use]
    pub fn statement(&self) -> &str {
        &self.statement
    }

    #[must_use]
    pub const fn kind(&self) -> ResearchNodeKind {
        self.kind
    }

    #[must_use]
    pub fn plan_id(&self) -> Option<&ResearchPlanId> {
        self.plan_id.as_ref()
    }

    #[must_use]
    pub fn dependencies(&self) -> &BTreeSet<ResearchNodeId> {
        &self.dependencies
    }

    #[must_use]
    pub const fn status(&self) -> ResearchNodeStatus {
        self.status
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResearchAttempt {
    attempt_id: ResearchAttemptId,
    node_id: ResearchNodeId,
    actor_domain_id: ResearchDomainId,
    method: ResearchAttemptMethod,
    outcome: ResearchAttemptOutcome,
    summary: String,
    obstruction: Option<ResearchObstruction>,
    evidence_ids: BTreeSet<String>,
    created_round: u32,
    event_seq: u64,
}

impl ResearchAttempt {
    pub fn new(
        attempt_id: ResearchAttemptId,
        node_id: ResearchNodeId,
        actor_domain_id: ResearchDomainId,
        method: ResearchAttemptMethod,
        outcome: ResearchAttemptOutcome,
        summary: impl Into<String>,
    ) -> Result<Self, ResearchStateError> {
        let summary = summary.into();
        validate_text("attempt.summary", &summary, MAX_SUMMARY_BYTES, false)?;
        let summary = summary.trim().to_owned();
        Ok(Self {
            attempt_id,
            node_id,
            actor_domain_id,
            method,
            outcome,
            summary,
            obstruction: None,
            evidence_ids: BTreeSet::new(),
            created_round: 0,
            event_seq: 0,
        })
    }

    #[must_use]
    pub fn with_obstruction(mut self, obstruction: ResearchObstruction) -> Self {
        self.obstruction = Some(obstruction);
        self
    }

    pub fn with_evidence(
        mut self,
        evidence_id: impl Into<String>,
    ) -> Result<Self, ResearchStateError> {
        let evidence_id = evidence_id.into();
        validate_text(
            "attempt.evidence_id",
            &evidence_id,
            MAX_EVIDENCE_ID_BYTES,
            false,
        )?;
        let evidence_id = evidence_id.trim().to_owned();
        if self.evidence_ids.len() >= MAX_EVIDENCE_IDS && !self.evidence_ids.contains(&evidence_id)
        {
            return Err(ResearchStateError::LimitExceeded {
                kind: "attempt_evidence_ids",
                limit: MAX_EVIDENCE_IDS,
                actual: self.evidence_ids.len() + 1,
            });
        }
        self.evidence_ids.insert(evidence_id);
        Ok(self)
    }

    #[must_use]
    pub fn with_position(mut self, created_round: u32, event_seq: u64) -> Self {
        self.created_round = created_round;
        self.event_seq = event_seq;
        self
    }

    #[must_use]
    pub fn attempt_id(&self) -> &ResearchAttemptId {
        &self.attempt_id
    }

    #[must_use]
    pub fn node_id(&self) -> &ResearchNodeId {
        &self.node_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResearchDecision {
    decision_id: ResearchDecisionId,
    superseded_plan_ids: BTreeSet<ResearchPlanId>,
    preserved_node_ids: BTreeSet<ResearchNodeId>,
    new_constraints: BTreeSet<String>,
    selected_focus_node_id: Option<ResearchNodeId>,
    reason: String,
    event_seq: u64,
}

impl ResearchDecision {
    pub fn new(
        decision_id: ResearchDecisionId,
        reason: impl Into<String>,
    ) -> Result<Self, ResearchStateError> {
        let reason = reason.into();
        validate_text("decision.reason", &reason, MAX_REASON_BYTES, false)?;
        let reason = reason.trim().to_owned();
        Ok(Self {
            decision_id,
            superseded_plan_ids: BTreeSet::new(),
            preserved_node_ids: BTreeSet::new(),
            new_constraints: BTreeSet::new(),
            selected_focus_node_id: None,
            reason,
            event_seq: 0,
        })
    }

    #[must_use]
    pub fn supersede_plan(mut self, plan_id: ResearchPlanId) -> Self {
        self.superseded_plan_ids.insert(plan_id);
        self
    }

    #[must_use]
    pub fn preserve_node(mut self, node_id: ResearchNodeId) -> Self {
        self.preserved_node_ids.insert(node_id);
        self
    }

    pub fn add_constraint(
        mut self,
        constraint: impl Into<String>,
    ) -> Result<Self, ResearchStateError> {
        let constraint = constraint.into();
        validate_text(
            "decision.new_constraint",
            &constraint,
            MAX_SUMMARY_BYTES,
            false,
        )?;
        let constraint = constraint.trim().to_owned();
        self.new_constraints.insert(constraint);
        Ok(self)
    }

    #[must_use]
    pub fn focus_on(mut self, node_id: ResearchNodeId) -> Self {
        self.selected_focus_node_id = Some(node_id);
        self
    }

    #[must_use]
    pub fn with_event_seq(mut self, event_seq: u64) -> Self {
        self.event_seq = event_seq;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResearchSnapshot {
    target_node_id: ResearchNodeId,
    nodes: Vec<ResearchNode>,
    attempts: Vec<ResearchAttempt>,
    decisions: Vec<ResearchDecision>,
    active_plan_ids: BTreeSet<ResearchPlanId>,
}

impl ResearchSnapshot {
    #[must_use]
    pub fn new(target_node_id: ResearchNodeId) -> Self {
        Self {
            target_node_id,
            nodes: Vec::new(),
            attempts: Vec::new(),
            decisions: Vec::new(),
            active_plan_ids: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn with_node(mut self, node: ResearchNode) -> Self {
        self.nodes.push(node);
        self
    }

    #[must_use]
    pub fn with_attempt(mut self, attempt: ResearchAttempt) -> Self {
        self.attempts.push(attempt);
        self
    }

    #[must_use]
    pub fn with_decision(mut self, decision: ResearchDecision) -> Self {
        self.decisions.push(decision);
        self
    }

    #[must_use]
    pub fn with_active_plan(mut self, plan_id: ResearchPlanId) -> Self {
        self.active_plan_ids.insert(plan_id);
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteIssueKind {
    RefutedDependency,
    DependencyCycle,
    SupersededDependency,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RouteIssue {
    kind: RouteIssueKind,
    source_node_id: ResearchNodeId,
}

impl RouteIssue {
    #[must_use]
    pub const fn kind(&self) -> RouteIssueKind {
        self.kind
    }

    #[must_use]
    pub fn source_node_id(&self) -> &ResearchNodeId {
        &self.source_node_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InvalidRoute {
    node_id: ResearchNodeId,
    issues: BTreeSet<RouteIssue>,
}

impl InvalidRoute {
    #[must_use]
    pub fn node_id(&self) -> &ResearchNodeId {
        &self.node_id
    }

    #[must_use]
    pub fn issues(&self) -> &BTreeSet<RouteIssue> {
        &self.issues
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResearchDependencyGraph {
    dependencies: BTreeMap<ResearchNodeId, BTreeSet<ResearchNodeId>>,
    dependents: BTreeMap<ResearchNodeId, BTreeSet<ResearchNodeId>>,
    topological_order: Vec<ResearchNodeId>,
    cycle_components: Vec<Vec<ResearchNodeId>>,
}

impl ResearchDependencyGraph {
    #[must_use]
    pub fn dependencies(&self) -> &BTreeMap<ResearchNodeId, BTreeSet<ResearchNodeId>> {
        &self.dependencies
    }

    #[must_use]
    pub fn dependents(&self) -> &BTreeMap<ResearchNodeId, BTreeSet<ResearchNodeId>> {
        &self.dependents
    }

    #[must_use]
    pub fn topological_order(&self) -> &[ResearchNodeId] {
        &self.topological_order
    }

    #[must_use]
    pub fn cycle_components(&self) -> &[Vec<ResearchNodeId>] {
        &self.cycle_components
    }

    #[must_use]
    pub fn is_acyclic(&self) -> bool {
        self.cycle_components.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResearchPlanRoute {
    plan_id: ResearchPlanId,
    goal_node_ids: Vec<ResearchNodeId>,
    critical_nodes: Vec<ResearchNodeId>,
    blockers: Vec<ResearchNodeId>,
    actionable_frontier: Vec<ResearchNodeId>,
    invalid_nodes: Vec<ResearchNodeId>,
    route_solved: bool,
}

impl ResearchPlanRoute {
    #[must_use]
    pub fn plan_id(&self) -> &ResearchPlanId {
        &self.plan_id
    }

    #[must_use]
    pub fn goal_node_ids(&self) -> &[ResearchNodeId] {
        &self.goal_node_ids
    }

    #[must_use]
    pub fn critical_nodes(&self) -> &[ResearchNodeId] {
        &self.critical_nodes
    }

    #[must_use]
    pub fn blockers(&self) -> &[ResearchNodeId] {
        &self.blockers
    }

    #[must_use]
    pub fn actionable_frontier(&self) -> &[ResearchNodeId] {
        &self.actionable_frontier
    }

    #[must_use]
    pub fn invalid_nodes(&self) -> &[ResearchNodeId] {
        &self.invalid_nodes
    }

    #[must_use]
    pub const fn route_solved(&self) -> bool {
        self.route_solved
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResearchState {
    schema_version: u16,
    target_node_id: ResearchNodeId,
    nodes: BTreeMap<ResearchNodeId, ResearchNode>,
    attempts: Vec<ResearchAttempt>,
    decisions: Vec<ResearchDecision>,
    active_plan_ids: BTreeSet<ResearchPlanId>,
    graph: ResearchDependencyGraph,
    plan_routes: BTreeMap<ResearchPlanId, ResearchPlanRoute>,
    critical_nodes: Vec<ResearchNodeId>,
    critical_blockers: Vec<ResearchNodeId>,
    actionable_frontier: Vec<ResearchNodeId>,
    invalid_routes: Vec<InvalidRoute>,
    digest: String,
}

impl ResearchState {
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub fn target_node_id(&self) -> &ResearchNodeId {
        &self.target_node_id
    }

    #[must_use]
    pub fn nodes(&self) -> &BTreeMap<ResearchNodeId, ResearchNode> {
        &self.nodes
    }

    #[must_use]
    pub fn attempts(&self) -> &[ResearchAttempt] {
        &self.attempts
    }

    #[must_use]
    pub fn decisions(&self) -> &[ResearchDecision] {
        &self.decisions
    }

    #[must_use]
    pub fn graph(&self) -> &ResearchDependencyGraph {
        &self.graph
    }

    #[must_use]
    pub fn active_plan_ids(&self) -> &BTreeSet<ResearchPlanId> {
        &self.active_plan_ids
    }

    #[must_use]
    pub fn plan_routes(&self) -> &BTreeMap<ResearchPlanId, ResearchPlanRoute> {
        &self.plan_routes
    }

    #[must_use]
    pub fn critical_nodes(&self) -> &[ResearchNodeId] {
        &self.critical_nodes
    }

    #[must_use]
    pub fn critical_blockers(&self) -> &[ResearchNodeId] {
        &self.critical_blockers
    }

    #[must_use]
    pub fn actionable_frontier(&self) -> &[ResearchNodeId] {
        &self.actionable_frontier
    }

    #[must_use]
    pub fn invalid_routes(&self) -> &[InvalidRoute] {
        &self.invalid_routes
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResearchStateError {
    InvalidIdentifier {
        kind: &'static str,
        reason: &'static str,
    },
    InvalidText {
        field: &'static str,
        reason: &'static str,
    },
    LimitExceeded {
        kind: &'static str,
        limit: usize,
        actual: usize,
    },
    DuplicateIdentifier {
        kind: &'static str,
        identifier: String,
    },
    MissingTarget,
    MultipleTargets,
    TargetKindMismatch,
    SupersededTarget,
    UnknownDependency {
        node_id: ResearchNodeId,
        dependency_id: ResearchNodeId,
    },
    UnknownAttemptNode {
        attempt_id: ResearchAttemptId,
        node_id: ResearchNodeId,
    },
    UnknownDecisionNode {
        decision_id: ResearchDecisionId,
        node_id: ResearchNodeId,
    },
    UnknownDecisionPlan {
        decision_id: ResearchDecisionId,
        plan_id: ResearchPlanId,
    },
    UnknownActivePlan {
        plan_id: ResearchPlanId,
    },
    InvalidRevision {
        node_id: ResearchNodeId,
    },
    ActiveDependencyCycle {
        cycle: Vec<ResearchNodeId>,
    },
    Serialization,
}

impl fmt::Display for ResearchStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier { kind, reason } => {
                write!(formatter, "invalid {kind}: {reason}")
            }
            Self::InvalidText { field, reason } => write!(formatter, "invalid {field}: {reason}"),
            Self::LimitExceeded {
                kind,
                limit,
                actual,
            } => write!(formatter, "{kind} exceeds limit {limit}: received {actual}"),
            Self::DuplicateIdentifier { kind, identifier } => {
                write!(formatter, "duplicate {kind}: {identifier}")
            }
            Self::MissingTarget => formatter.write_str("research target node is missing"),
            Self::MultipleTargets => {
                formatter.write_str("research state contains multiple targets")
            }
            Self::TargetKindMismatch => {
                formatter.write_str("target_node_id does not identify a target node")
            }
            Self::SupersededTarget => formatter.write_str("research target cannot be superseded"),
            Self::UnknownDependency {
                node_id,
                dependency_id,
            } => write!(
                formatter,
                "node {node_id} references unknown dependency {dependency_id}"
            ),
            Self::UnknownAttemptNode {
                attempt_id,
                node_id,
            } => write!(
                formatter,
                "attempt {attempt_id} references unknown node {node_id}"
            ),
            Self::UnknownDecisionNode {
                decision_id,
                node_id,
            } => write!(
                formatter,
                "decision {decision_id} references unknown node {node_id}"
            ),
            Self::UnknownDecisionPlan {
                decision_id,
                plan_id,
            } => write!(
                formatter,
                "decision {decision_id} references unknown plan {plan_id}"
            ),
            Self::UnknownActivePlan { plan_id } => {
                write!(
                    formatter,
                    "active research plan has no declared node: {plan_id}"
                )
            }
            Self::InvalidRevision { node_id } => {
                write!(formatter, "research node {node_id} has revision zero")
            }
            Self::ActiveDependencyCycle { cycle } => write!(
                formatter,
                "active research dependency cycle: {}",
                cycle
                    .iter()
                    .map(ResearchNodeId::as_str)
                    .collect::<Vec<_>>()
                    .join(" -> ")
            ),
            Self::Serialization => formatter.write_str("research-state serialization failed"),
        }
    }
}

impl Error for ResearchStateError {}

pub struct ResearchStateProjector;

impl ResearchStateProjector {
    /// Analyze a normalized snapshot defensively. Cycles are represented explicitly
    /// in the result so a pre-commit caller can explain and reject them.
    pub fn analyze(snapshot: &ResearchSnapshot) -> Result<ResearchState, ResearchStateError> {
        validate_snapshot_limits(snapshot)?;
        let nodes = canonical_nodes(snapshot)?;
        validate_target(snapshot, &nodes)?;
        validate_active_plans(snapshot, &nodes)?;
        let attempts = canonical_attempts(snapshot, &nodes)?;
        let decisions = canonical_decisions(snapshot, &nodes)?;
        let (dependencies, dependents, superseded_seeds) = build_graph(&nodes)?;
        let stable_ids = stable_node_ids(nodes.values());
        let cycle_components = cycle_components(&dependencies, &dependents, &stable_ids, &nodes);
        let topological_order = topological_order(&dependencies, &dependents, &nodes);
        let graph = ResearchDependencyGraph {
            dependencies,
            dependents,
            topological_order,
            cycle_components,
        };
        let issue_map = route_issues(&nodes, &graph, superseded_seeds);
        let invalid_set = issue_map.keys().cloned().collect::<BTreeSet<_>>();
        let actionable_set = nodes
            .values()
            .filter(|node| node.status.is_actionable())
            .filter(|node| {
                node.kind != ResearchNodeKind::Target || snapshot.active_plan_ids.is_empty()
            })
            .filter(|node| !invalid_set.contains(&node.node_id))
            .filter(|node| {
                graph.dependencies[&node.node_id].iter().all(|dependency| {
                    nodes
                        .get(dependency)
                        .is_some_and(|value| value.status == ResearchNodeStatus::RouteSolved)
                })
            })
            .map(|node| node.node_id.clone())
            .collect::<BTreeSet<_>>();
        let plan_routes = derive_plan_routes(snapshot, &nodes, &graph, &issue_map, &actionable_set);
        let mut critical_set = dependency_closure(snapshot.target_node_id(), graph.dependencies());
        for route in plan_routes.values() {
            critical_set.extend(route.critical_nodes.iter().cloned());
        }
        let critical_nodes = ordered_ids(critical_set.iter(), &nodes, None);
        let critical_blockers = ordered_ids(
            critical_set.iter().filter(|node_id| {
                nodes
                    .get(*node_id)
                    .is_some_and(|node| node.status != ResearchNodeStatus::RouteSolved)
            }),
            &nodes,
            None,
        );
        let actionable_frontier = ordered_ids(actionable_set.iter(), &nodes, Some(&critical_set));
        let invalid_routes = ordered_ids(issue_map.keys(), &nodes, Some(&critical_set))
            .into_iter()
            .filter_map(|node_id| {
                issue_map
                    .get(&node_id)
                    .cloned()
                    .map(|issues| InvalidRoute { node_id, issues })
            })
            .collect::<Vec<_>>();

        let mut state = ResearchState {
            schema_version: RESEARCH_STATE_SCHEMA_VERSION,
            target_node_id: snapshot.target_node_id.clone(),
            nodes,
            attempts,
            decisions,
            active_plan_ids: snapshot.active_plan_ids.clone(),
            graph,
            plan_routes,
            critical_nodes,
            critical_blockers,
            actionable_frontier,
            invalid_routes,
            digest: String::new(),
        };
        state.digest = digest_state(&state)?;
        Ok(state)
    }

    /// Produce an authority-safe projection. Persisted active dependency cycles are
    /// rejected rather than silently interpreted as a usable mathematical route.
    pub fn project(snapshot: &ResearchSnapshot) -> Result<ResearchState, ResearchStateError> {
        let state = Self::analyze(snapshot)?;
        if let Some(cycle) = state.graph.cycle_components.first() {
            return Err(ResearchStateError::ActiveDependencyCycle {
                cycle: cycle.clone(),
            });
        }
        Ok(state)
    }
}

impl ResearchSnapshot {
    #[must_use]
    fn target_node_id(&self) -> &ResearchNodeId {
        &self.target_node_id
    }
}

fn validate_identifier(kind: &'static str, value: &str) -> Result<(), ResearchStateError> {
    if value.is_empty() {
        return Err(ResearchStateError::InvalidIdentifier {
            kind,
            reason: "identifier is empty",
        });
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(ResearchStateError::InvalidIdentifier {
            kind,
            reason: "identifier is too long",
        });
    }
    let mut characters = value.chars();
    if !characters
        .next()
        .is_some_and(|value| value.is_ascii_alphanumeric())
    {
        return Err(ResearchStateError::InvalidIdentifier {
            kind,
            reason: "identifier must start with an ASCII alphanumeric character",
        });
    }
    if !characters
        .all(|value| value.is_ascii_alphanumeric() || matches!(value, '-' | '_' | '.' | ':'))
    {
        return Err(ResearchStateError::InvalidIdentifier {
            kind,
            reason: "identifier contains unsupported characters",
        });
    }
    Ok(())
}

fn validate_text(
    field: &'static str,
    value: &str,
    limit: usize,
    allow_empty: bool,
) -> Result<(), ResearchStateError> {
    if !allow_empty && value.trim().is_empty() {
        return Err(ResearchStateError::InvalidText {
            field,
            reason: "value is empty",
        });
    }
    if value.len() > limit {
        return Err(ResearchStateError::InvalidText {
            field,
            reason: "value is too long",
        });
    }
    if value.contains('\0') {
        return Err(ResearchStateError::InvalidText {
            field,
            reason: "value contains a NUL byte",
        });
    }
    Ok(())
}

fn validate_snapshot_limits(snapshot: &ResearchSnapshot) -> Result<(), ResearchStateError> {
    limit("research_nodes", snapshot.nodes.len(), MAX_RESEARCH_NODES)?;
    limit(
        "research_attempts",
        snapshot.attempts.len(),
        MAX_RESEARCH_ATTEMPTS,
    )?;
    limit(
        "research_decisions",
        snapshot.decisions.len(),
        MAX_RESEARCH_DECISIONS,
    )?;
    limit(
        "active_research_plans",
        snapshot.active_plan_ids.len(),
        MAX_ACTIVE_PLANS,
    )?;
    Ok(())
}

fn limit(kind: &'static str, actual: usize, maximum: usize) -> Result<(), ResearchStateError> {
    if actual > maximum {
        return Err(ResearchStateError::LimitExceeded {
            kind,
            limit: maximum,
            actual,
        });
    }
    Ok(())
}

fn canonical_nodes(
    snapshot: &ResearchSnapshot,
) -> Result<BTreeMap<ResearchNodeId, ResearchNode>, ResearchStateError> {
    let mut nodes = BTreeMap::new();
    let mut edge_count = 0usize;
    for node in &snapshot.nodes {
        if node.revision == 0 {
            return Err(ResearchStateError::InvalidRevision {
                node_id: node.node_id.clone(),
            });
        }
        validate_text(
            "node.statement",
            &node.statement,
            MAX_STATEMENT_BYTES,
            false,
        )?;
        limit(
            "node_dependencies",
            node.dependencies.len(),
            MAX_NODE_DEPENDENCIES,
        )?;
        edge_count = edge_count.saturating_add(node.dependencies.len());
        if nodes.insert(node.node_id.clone(), node.clone()).is_some() {
            return Err(ResearchStateError::DuplicateIdentifier {
                kind: "research_node_id",
                identifier: node.node_id.to_string(),
            });
        }
    }
    limit("research_edges", edge_count, MAX_RESEARCH_EDGES)?;
    for node in nodes.values() {
        for dependency in &node.dependencies {
            if !nodes.contains_key(dependency) {
                return Err(ResearchStateError::UnknownDependency {
                    node_id: node.node_id.clone(),
                    dependency_id: dependency.clone(),
                });
            }
        }
    }
    Ok(nodes)
}

fn validate_target(
    snapshot: &ResearchSnapshot,
    nodes: &BTreeMap<ResearchNodeId, ResearchNode>,
) -> Result<(), ResearchStateError> {
    let target_count = nodes
        .values()
        .filter(|node| node.kind == ResearchNodeKind::Target)
        .count();
    if target_count == 0 {
        return Err(ResearchStateError::MissingTarget);
    }
    if target_count > 1 {
        return Err(ResearchStateError::MultipleTargets);
    }
    let target = nodes
        .get(&snapshot.target_node_id)
        .ok_or(ResearchStateError::MissingTarget)?;
    if target.kind != ResearchNodeKind::Target {
        return Err(ResearchStateError::TargetKindMismatch);
    }
    if target.status == ResearchNodeStatus::Superseded {
        return Err(ResearchStateError::SupersededTarget);
    }
    Ok(())
}

fn validate_active_plans(
    snapshot: &ResearchSnapshot,
    nodes: &BTreeMap<ResearchNodeId, ResearchNode>,
) -> Result<(), ResearchStateError> {
    let declared = nodes
        .values()
        .filter(|node| node.status != ResearchNodeStatus::Superseded)
        .filter_map(|node| node.plan_id.clone())
        .collect::<BTreeSet<_>>();
    for plan_id in &snapshot.active_plan_ids {
        if !declared.contains(plan_id) {
            return Err(ResearchStateError::UnknownActivePlan {
                plan_id: plan_id.clone(),
            });
        }
    }
    Ok(())
}

fn canonical_attempts(
    snapshot: &ResearchSnapshot,
    nodes: &BTreeMap<ResearchNodeId, ResearchNode>,
) -> Result<Vec<ResearchAttempt>, ResearchStateError> {
    let mut identifiers = BTreeSet::new();
    let mut attempts = snapshot.attempts.clone();
    for attempt in &attempts {
        validate_text(
            "attempt.summary",
            &attempt.summary,
            MAX_SUMMARY_BYTES,
            false,
        )?;
        limit(
            "attempt_evidence_ids",
            attempt.evidence_ids.len(),
            MAX_EVIDENCE_IDS,
        )?;
        if !identifiers.insert(attempt.attempt_id.clone()) {
            return Err(ResearchStateError::DuplicateIdentifier {
                kind: "research_attempt_id",
                identifier: attempt.attempt_id.to_string(),
            });
        }
        if !nodes.contains_key(&attempt.node_id) {
            return Err(ResearchStateError::UnknownAttemptNode {
                attempt_id: attempt.attempt_id.clone(),
                node_id: attempt.node_id.clone(),
            });
        }
    }
    attempts.sort_by(|left, right| {
        (left.created_round, left.event_seq, &left.attempt_id).cmp(&(
            right.created_round,
            right.event_seq,
            &right.attempt_id,
        ))
    });
    Ok(attempts)
}

fn canonical_decisions(
    snapshot: &ResearchSnapshot,
    nodes: &BTreeMap<ResearchNodeId, ResearchNode>,
) -> Result<Vec<ResearchDecision>, ResearchStateError> {
    let mut identifiers = BTreeSet::new();
    let mut decisions = snapshot.decisions.clone();
    let known_plans = nodes
        .values()
        .filter_map(|node| node.plan_id.clone())
        .chain(snapshot.active_plan_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    for decision in &decisions {
        validate_text("decision.reason", &decision.reason, MAX_REASON_BYTES, false)?;
        limit(
            "decision_superseded_plan_ids",
            decision.superseded_plan_ids.len(),
            MAX_DECISION_PLAN_IDS,
        )?;
        limit(
            "decision_preserved_node_ids",
            decision.preserved_node_ids.len(),
            MAX_DECISION_NODE_IDS,
        )?;
        limit(
            "decision_new_constraints",
            decision.new_constraints.len(),
            MAX_DECISION_CONSTRAINTS,
        )?;
        if !identifiers.insert(decision.decision_id.clone()) {
            return Err(ResearchStateError::DuplicateIdentifier {
                kind: "research_decision_id",
                identifier: decision.decision_id.to_string(),
            });
        }
        for node_id in decision
            .preserved_node_ids
            .iter()
            .chain(decision.selected_focus_node_id.iter())
        {
            if !nodes.contains_key(node_id) {
                return Err(ResearchStateError::UnknownDecisionNode {
                    decision_id: decision.decision_id.clone(),
                    node_id: node_id.clone(),
                });
            }
        }
        for plan_id in &decision.superseded_plan_ids {
            if !known_plans.contains(plan_id) {
                return Err(ResearchStateError::UnknownDecisionPlan {
                    decision_id: decision.decision_id.clone(),
                    plan_id: plan_id.clone(),
                });
            }
        }
    }
    decisions.sort_by(|left, right| {
        (left.event_seq, &left.decision_id).cmp(&(right.event_seq, &right.decision_id))
    });
    Ok(decisions)
}

type GraphMaps = (
    BTreeMap<ResearchNodeId, BTreeSet<ResearchNodeId>>,
    BTreeMap<ResearchNodeId, BTreeSet<ResearchNodeId>>,
    Vec<(ResearchNodeId, ResearchNodeId)>,
);

fn build_graph(
    nodes: &BTreeMap<ResearchNodeId, ResearchNode>,
) -> Result<GraphMaps, ResearchStateError> {
    let mut dependencies = BTreeMap::new();
    let mut dependents = BTreeMap::new();
    let mut superseded_seeds = Vec::new();
    for node in nodes.values() {
        if node.status != ResearchNodeStatus::Superseded {
            dependencies.insert(node.node_id.clone(), BTreeSet::new());
            dependents.insert(node.node_id.clone(), BTreeSet::new());
        }
    }
    for node in nodes.values() {
        if node.status == ResearchNodeStatus::Superseded {
            continue;
        }
        for dependency_id in &node.dependencies {
            let dependency =
                nodes
                    .get(dependency_id)
                    .ok_or_else(|| ResearchStateError::UnknownDependency {
                        node_id: node.node_id.clone(),
                        dependency_id: dependency_id.clone(),
                    })?;
            if dependency.status == ResearchNodeStatus::Superseded {
                superseded_seeds.push((node.node_id.clone(), dependency_id.clone()));
                continue;
            }
            dependencies
                .get_mut(&node.node_id)
                .ok_or(ResearchStateError::Serialization)?
                .insert(dependency_id.clone());
            dependents
                .get_mut(dependency_id)
                .ok_or(ResearchStateError::Serialization)?
                .insert(node.node_id.clone());
        }
    }
    Ok((dependencies, dependents, superseded_seeds))
}

fn stable_node_ids<'a>(nodes: impl Iterator<Item = &'a ResearchNode>) -> Vec<ResearchNodeId> {
    let mut nodes = nodes.collect::<Vec<_>>();
    nodes.sort_by(|left, right| stable_key(left).cmp(&stable_key(right)));
    nodes.into_iter().map(|node| node.node_id.clone()).collect()
}

fn stable_key(node: &ResearchNode) -> (u32, u32, u32, &ResearchNodeId) {
    (
        node.created_round,
        node.plan_order,
        node.node_order,
        &node.node_id,
    )
}

fn ordered_ids<'a>(
    identifiers: impl Iterator<Item = &'a ResearchNodeId>,
    nodes: &BTreeMap<ResearchNodeId, ResearchNode>,
    critical: Option<&BTreeSet<ResearchNodeId>>,
) -> Vec<ResearchNodeId> {
    let mut identifiers = identifiers.cloned().collect::<Vec<_>>();
    identifiers.sort_by(|left, right| {
        let left_node = &nodes[left];
        let right_node = &nodes[right];
        let left_noncritical = critical.is_some_and(|items| !items.contains(left));
        let right_noncritical = critical.is_some_and(|items| !items.contains(right));
        (
            left_noncritical,
            left_node.created_round,
            left_node.plan_order,
            left_node.node_order,
            left,
        )
            .cmp(&(
                right_noncritical,
                right_node.created_round,
                right_node.plan_order,
                right_node.node_order,
                right,
            ))
    });
    identifiers
}

fn topological_order(
    dependencies: &BTreeMap<ResearchNodeId, BTreeSet<ResearchNodeId>>,
    dependents: &BTreeMap<ResearchNodeId, BTreeSet<ResearchNodeId>>,
    nodes: &BTreeMap<ResearchNodeId, ResearchNode>,
) -> Vec<ResearchNodeId> {
    let mut remaining = dependencies
        .iter()
        .map(|(node_id, items)| (node_id.clone(), items.len()))
        .collect::<BTreeMap<_, _>>();
    let mut ready = BTreeSet::new();
    for (node_id, count) in &remaining {
        if *count == 0 {
            ready.insert(OwnedStableNodeKey::from_node(&nodes[node_id]));
        }
    }
    let mut result = Vec::with_capacity(dependencies.len());
    while let Some(key) = ready.pop_first() {
        let node_id = key.node_id;
        result.push(node_id.clone());
        if let Some(items) = dependents.get(&node_id) {
            for dependent in items {
                if let Some(count) = remaining.get_mut(dependent) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        ready.insert(OwnedStableNodeKey::from_node(&nodes[dependent]));
                    }
                }
            }
        }
    }
    result
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct OwnedStableNodeKey {
    created_round: u32,
    plan_order: u32,
    node_order: u32,
    node_id: ResearchNodeId,
}

impl OwnedStableNodeKey {
    fn from_node(node: &ResearchNode) -> Self {
        Self {
            created_round: node.created_round,
            plan_order: node.plan_order,
            node_order: node.node_order,
            node_id: node.node_id.clone(),
        }
    }
}

fn cycle_components(
    dependencies: &BTreeMap<ResearchNodeId, BTreeSet<ResearchNodeId>>,
    dependents: &BTreeMap<ResearchNodeId, BTreeSet<ResearchNodeId>>,
    stable_ids: &[ResearchNodeId],
    nodes: &BTreeMap<ResearchNodeId, ResearchNode>,
) -> Vec<Vec<ResearchNodeId>> {
    let mut visited = BTreeSet::new();
    let mut finishing = Vec::with_capacity(stable_ids.len());
    for node_id in stable_ids {
        dfs_finish(node_id, dependencies, &mut visited, &mut finishing);
    }
    let mut assigned = BTreeSet::new();
    let mut components = Vec::new();
    for node_id in finishing.into_iter().rev() {
        if assigned.contains(&node_id) {
            continue;
        }
        let mut component = Vec::new();
        dfs_collect(&node_id, dependents, &mut assigned, &mut component);
        let self_loop = component.len() == 1
            && dependencies
                .get(&component[0])
                .is_some_and(|items| items.contains(&component[0]));
        if component.len() > 1 || self_loop {
            component
                .sort_by(|left, right| stable_key(&nodes[left]).cmp(&stable_key(&nodes[right])));
            components.push(component);
        }
    }
    components
        .sort_by(|left, right| stable_key(&nodes[&left[0]]).cmp(&stable_key(&nodes[&right[0]])));
    components
}

fn dfs_finish(
    node_id: &ResearchNodeId,
    adjacency: &BTreeMap<ResearchNodeId, BTreeSet<ResearchNodeId>>,
    visited: &mut BTreeSet<ResearchNodeId>,
    finishing: &mut Vec<ResearchNodeId>,
) {
    if !visited.insert(node_id.clone()) {
        return;
    }
    if let Some(neighbors) = adjacency.get(node_id) {
        for neighbor in neighbors {
            dfs_finish(neighbor, adjacency, visited, finishing);
        }
    }
    finishing.push(node_id.clone());
}

fn dfs_collect(
    node_id: &ResearchNodeId,
    adjacency: &BTreeMap<ResearchNodeId, BTreeSet<ResearchNodeId>>,
    visited: &mut BTreeSet<ResearchNodeId>,
    component: &mut Vec<ResearchNodeId>,
) {
    if !visited.insert(node_id.clone()) {
        return;
    }
    component.push(node_id.clone());
    if let Some(neighbors) = adjacency.get(node_id) {
        for neighbor in neighbors {
            dfs_collect(neighbor, adjacency, visited, component);
        }
    }
}

fn dependency_closure(
    target_node_id: &ResearchNodeId,
    dependencies: &BTreeMap<ResearchNodeId, BTreeSet<ResearchNodeId>>,
) -> BTreeSet<ResearchNodeId> {
    let mut result = BTreeSet::new();
    let mut pending = vec![target_node_id.clone()];
    while let Some(node_id) = pending.pop() {
        if !result.insert(node_id.clone()) {
            continue;
        }
        if let Some(items) = dependencies.get(&node_id) {
            pending.extend(items.iter().cloned());
        }
    }
    result
}

fn derive_plan_routes(
    snapshot: &ResearchSnapshot,
    nodes: &BTreeMap<ResearchNodeId, ResearchNode>,
    graph: &ResearchDependencyGraph,
    issue_map: &BTreeMap<ResearchNodeId, BTreeSet<RouteIssue>>,
    actionable_set: &BTreeSet<ResearchNodeId>,
) -> BTreeMap<ResearchPlanId, ResearchPlanRoute> {
    let mut routes = BTreeMap::new();
    for plan_id in &snapshot.active_plan_ids {
        let plan_nodes = nodes
            .values()
            .filter(|node| node.status != ResearchNodeStatus::Superseded)
            .filter(|node| node.plan_id.as_ref() == Some(plan_id))
            .map(|node| node.node_id.clone())
            .collect::<BTreeSet<_>>();
        let mut goal_set = plan_nodes
            .iter()
            .filter(|node_id| {
                graph.dependents.get(*node_id).is_none_or(|dependents| {
                    dependents
                        .iter()
                        .all(|dependent| !plan_nodes.contains(dependent))
                })
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        if goal_set.is_empty() {
            goal_set = plan_nodes.clone();
        }
        let mut critical_set = BTreeSet::new();
        for goal in &goal_set {
            critical_set.extend(dependency_closure(goal, graph.dependencies()));
        }
        let goal_node_ids = ordered_ids(goal_set.iter(), nodes, None);
        let critical_nodes = ordered_ids(critical_set.iter(), nodes, None);
        let blockers = ordered_ids(
            critical_set.iter().filter(|node_id| {
                nodes
                    .get(*node_id)
                    .is_some_and(|node| node.status != ResearchNodeStatus::RouteSolved)
            }),
            nodes,
            None,
        );
        let actionable_frontier = ordered_ids(
            critical_set
                .iter()
                .filter(|node_id| actionable_set.contains(*node_id)),
            nodes,
            Some(&critical_set),
        );
        let invalid_nodes = ordered_ids(
            critical_set
                .iter()
                .filter(|node_id| issue_map.contains_key(*node_id)),
            nodes,
            Some(&critical_set),
        );
        let route_solved = !goal_node_ids.is_empty()
            && invalid_nodes.is_empty()
            && critical_nodes.iter().all(|node_id| {
                nodes
                    .get(node_id)
                    .is_some_and(|node| node.status == ResearchNodeStatus::RouteSolved)
            });
        routes.insert(
            plan_id.clone(),
            ResearchPlanRoute {
                plan_id: plan_id.clone(),
                goal_node_ids,
                critical_nodes,
                blockers,
                actionable_frontier,
                invalid_nodes,
                route_solved,
            },
        );
    }
    routes
}

fn route_issues(
    nodes: &BTreeMap<ResearchNodeId, ResearchNode>,
    graph: &ResearchDependencyGraph,
    superseded_seeds: Vec<(ResearchNodeId, ResearchNodeId)>,
) -> BTreeMap<ResearchNodeId, BTreeSet<RouteIssue>> {
    let mut issues = BTreeMap::<ResearchNodeId, BTreeSet<RouteIssue>>::new();
    let mut pending = VecDeque::<(ResearchNodeId, RouteIssue)>::new();
    for node in nodes.values() {
        if node.status == ResearchNodeStatus::Refuted {
            pending.push_back((
                node.node_id.clone(),
                RouteIssue {
                    kind: RouteIssueKind::RefutedDependency,
                    source_node_id: node.node_id.clone(),
                },
            ));
        }
    }
    for component in &graph.cycle_components {
        if let Some(source) = component.first() {
            let issue = RouteIssue {
                kind: RouteIssueKind::DependencyCycle,
                source_node_id: source.clone(),
            };
            for node_id in component {
                pending.push_back((node_id.clone(), issue.clone()));
            }
        }
    }
    for (node_id, dependency_id) in superseded_seeds {
        pending.push_back((
            node_id,
            RouteIssue {
                kind: RouteIssueKind::SupersededDependency,
                source_node_id: dependency_id,
            },
        ));
    }
    while let Some((node_id, issue)) = pending.pop_front() {
        if !issues
            .entry(node_id.clone())
            .or_default()
            .insert(issue.clone())
        {
            continue;
        }
        if let Some(dependents) = graph.dependents.get(&node_id) {
            for dependent in dependents {
                pending.push_back((dependent.clone(), issue.clone()));
            }
        }
    }
    issues
}

#[derive(Serialize)]
struct DigestPayload<'a> {
    schema_version: u16,
    target_node_id: &'a ResearchNodeId,
    nodes: &'a BTreeMap<ResearchNodeId, ResearchNode>,
    attempts: &'a [ResearchAttempt],
    decisions: &'a [ResearchDecision],
    active_plan_ids: &'a BTreeSet<ResearchPlanId>,
    graph: &'a ResearchDependencyGraph,
    plan_routes: &'a BTreeMap<ResearchPlanId, ResearchPlanRoute>,
    critical_nodes: &'a [ResearchNodeId],
    critical_blockers: &'a [ResearchNodeId],
    actionable_frontier: &'a [ResearchNodeId],
    invalid_routes: &'a [InvalidRoute],
}

fn digest_state(state: &ResearchState) -> Result<String, ResearchStateError> {
    let payload = DigestPayload {
        schema_version: state.schema_version,
        target_node_id: &state.target_node_id,
        nodes: &state.nodes,
        attempts: &state.attempts,
        decisions: &state.decisions,
        active_plan_ids: &state.active_plan_ids,
        graph: &state.graph,
        plan_routes: &state.plan_routes,
        critical_nodes: &state.critical_nodes,
        critical_blockers: &state.critical_blockers,
        actionable_frontier: &state.actionable_frontier,
        invalid_routes: &state.invalid_routes,
    };
    let bytes = serde_json::to_vec(&payload).map_err(|_| ResearchStateError::Serialization)?;
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{}", encode_hex(&digest)))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;
