use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::{
    MAX_ACTIVE_PLANS, MAX_DECISION_CONSTRAINTS, MAX_DECISION_NODE_IDS, MAX_DECISION_PLAN_IDS,
    MAX_EVIDENCE_ID_BYTES, MAX_EVIDENCE_IDS, MAX_IDENTIFIER_BYTES, MAX_NODE_DEPENDENCIES,
    MAX_STATEMENT_BYTES, MAX_SUMMARY_BYTES, ResearchAttemptMethod, ResearchNodeId,
    ResearchNodeKind, ResearchObstruction, ResearchPlanId, ResearchStateError,
};

const MAX_TEXT_ARRAY: usize = 64;
const MAX_QUERY_BYTES: usize = 4_096;
const MAX_SYMBOL_BYTES: usize = 256;
const RESERVED_RECORD_FIELDS: [&str; 6] = [
    "record_type",
    "record_id",
    "actor_role",
    "actor_domain_id",
    "round_index",
    "created_at",
];

#[derive(Clone, Debug)]
pub(crate) struct ProtocolRecordStamp<'a> {
    pub(crate) record_id: &'a str,
    pub(crate) actor_role: &'a str,
    pub(crate) actor_domain_id: &'a str,
    pub(crate) round_index: u32,
    pub(crate) created_at: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProtocolAttemptFields {
    pub(crate) method: ResearchAttemptMethod,
    pub(crate) obstruction: Option<ResearchObstruction>,
    pub(crate) evidence_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProtocolBranchFields {
    pub(crate) status: String,
    pub(crate) summary: String,
    pub(crate) proof_route: Option<String>,
    pub(crate) proved_node_ids: Vec<String>,
    pub(crate) unproved_node_ids: Vec<String>,
    pub(crate) failure_evidence: Vec<String>,
    pub(crate) obstructions: Vec<Value>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProtocolResearchScope {
    plan_nodes: BTreeMap<ResearchPlanId, BTreeSet<ResearchNodeId>>,
    node_plans: BTreeMap<ResearchNodeId, Option<ResearchPlanId>>,
    registered_reference_ids: BTreeSet<String>,
}

impl ProtocolResearchScope {
    pub(crate) fn from_active_plans(
        active_plans: &Value,
        registered_reference_ids: impl IntoIterator<Item = String>,
    ) -> Result<Self, ResearchStateError> {
        let plans = active_plans
            .as_array()
            .ok_or_else(|| malformed("active_plans", "expected an array"))?;
        bounded_count("protocol3_active_plans", plans.len(), MAX_ACTIVE_PLANS)?;
        let mut scope = Self {
            registered_reference_ids: registered_reference_ids.into_iter().collect(),
            ..Self::default()
        };
        scope
            .node_plans
            .insert(ResearchNodeId::parse("target")?, None);
        for (plan_index, plan) in plans.iter().enumerate() {
            let location = format!("active_plans[{plan_index}]");
            let plan_object = object(plan, &location)?;
            let plan_id = ResearchPlanId::parse(required_text(
                plan_object.get("plan_id"),
                &format!("{location}.plan_id"),
                MAX_IDENTIFIER_BYTES,
            )?)?;
            let subgoals = plan_object
                .get("research_subgoals")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    malformed(
                        format!("{location}.research_subgoals"),
                        "protocol-3 active plan is missing canonical research_subgoals",
                    )
                })?;
            bounded_count(
                "protocol3_plan_subgoals",
                subgoals.len(),
                MAX_NODE_DEPENDENCIES,
            )?;
            let bucket = scope.plan_nodes.entry(plan_id.clone()).or_default();
            for (node_index, node) in subgoals.iter().enumerate() {
                let node_location = format!("{location}.research_subgoals[{node_index}]");
                let node = object(node, &node_location)?;
                let node_id = ResearchNodeId::parse(required_text(
                    node.get("node_id"),
                    &format!("{node_location}.node_id"),
                    MAX_IDENTIFIER_BYTES,
                )?)?;
                if !bucket.insert(node_id.clone()) {
                    return Err(malformed(
                        &node_location,
                        "duplicate canonical node_id in one plan",
                    ));
                }
                if scope
                    .node_plans
                    .insert(node_id.clone(), Some(plan_id.clone()))
                    .is_some()
                {
                    return Err(malformed(
                        &node_location,
                        "canonical node_id is shared by multiple plans",
                    ));
                }
            }
        }
        Ok(scope)
    }

    pub(crate) fn contains_node(&self, node_id: &ResearchNodeId) -> bool {
        self.node_plans.contains_key(node_id)
    }

    pub(crate) fn contains_plan(&self, plan_id: &ResearchPlanId) -> bool {
        self.plan_nodes.contains_key(plan_id)
    }

    pub(crate) fn plan_contains_node(
        &self,
        plan_id: &ResearchPlanId,
        node_id: &ResearchNodeId,
    ) -> bool {
        self.plan_nodes
            .get(plan_id)
            .is_some_and(|nodes| nodes.contains(node_id))
    }

    pub(crate) fn reference_registered(&self, reference_id: &str) -> bool {
        self.registered_reference_ids.contains(reference_id)
    }
}

pub(crate) fn normalize_protocol3_plans(
    value: Option<&Value>,
    plan_round: i64,
) -> Result<Vec<Value>, ResearchStateError> {
    let items = value
        .and_then(Value::as_array)
        .filter(|items| items.len() >= 2)
        .ok_or_else(|| malformed("plans", "at least two plans are required"))?;
    bounded_count("protocol3_plans", items.len(), MAX_ACTIVE_PLANS)?;
    let round = plan_round.max(1);
    let mut normalized = Vec::with_capacity(items.len());
    let mut summaries = BTreeSet::new();
    for (plan_index, item) in items.iter().enumerate() {
        let location = format!("plans[{plan_index}]");
        let plan = object(item, &location)?;
        reject_unknown(
            plan,
            &[
                "plan_id",
                "summary",
                "subgoals",
                "motivation",
                "dependencies",
                "risks",
            ],
            &location,
        )?;
        let source_plan_id = optional_text(
            plan.get("plan_id"),
            &format!("{location}.plan_id"),
            MAX_IDENTIFIER_BYTES,
        )?;
        let summary = required_text(
            plan.get("summary"),
            &format!("{location}.summary"),
            MAX_SUMMARY_BYTES,
        )?;
        if !summaries.insert(summary.to_ascii_lowercase()) {
            return Err(malformed(
                &location,
                "plans must have materially distinct summaries",
            ));
        }
        let plan_id = ResearchPlanId::parse(format!("plan-r{round}-{}", plan_index + 1))?;
        let subgoals = plan
            .get("subgoals")
            .and_then(Value::as_array)
            .filter(|subgoals| !subgoals.is_empty())
            .ok_or_else(|| malformed(format!("{location}.subgoals"), "non-empty array required"))?;
        bounded_count(
            "protocol3_plan_subgoals",
            subgoals.len(),
            MAX_NODE_DEPENDENCIES,
        )?;

        let mut local = BTreeMap::<String, LocalSubgoal>::new();
        let mut ordered_keys = Vec::with_capacity(subgoals.len());
        for (subgoal_index, subgoal) in subgoals.iter().enumerate() {
            let subgoal_location = format!("{location}.subgoals[{subgoal_index}]");
            let subgoal = object(subgoal, &subgoal_location)?;
            reject_unknown(
                subgoal,
                &["key", "statement", "depends_on", "critical", "kind"],
                &subgoal_location,
            )?;
            let key = required_text(
                subgoal.get("key"),
                &format!("{subgoal_location}.key"),
                MAX_IDENTIFIER_BYTES,
            )?;
            validate_local_key(key, &format!("{subgoal_location}.key"))?;
            if local.contains_key(key) {
                return Err(malformed(&subgoal_location, "duplicate local subgoal key"));
            }
            let statement = required_text(
                subgoal.get("statement"),
                &format!("{subgoal_location}.statement"),
                MAX_STATEMENT_BYTES,
            )?;
            let depends_on = unique_string_array(
                subgoal.get("depends_on"),
                &format!("{subgoal_location}.depends_on"),
                MAX_NODE_DEPENDENCIES,
                false,
                MAX_IDENTIFIER_BYTES,
            )?;
            let critical = subgoal
                .get("critical")
                .and_then(Value::as_bool)
                .ok_or_else(|| {
                    malformed(
                        format!("{subgoal_location}.critical"),
                        "boolean is required",
                    )
                })?;
            let kind_text =
                optional_text(subgoal.get("kind"), &format!("{subgoal_location}.kind"), 32)?
                    .unwrap_or("lemma");
            let kind = ResearchNodeKind::parse(kind_text)
                .filter(|kind| *kind != ResearchNodeKind::Target)
                .ok_or_else(|| {
                    malformed(
                        format!("{subgoal_location}.kind"),
                        "kind must be lemma, construction, or definition",
                    )
                })?;
            let subgoal_id = format!("sg-{}", subgoal_index + 1);
            let node_id = protocol_node_id(&plan_id, &subgoal_id)?;
            ordered_keys.push(key.to_owned());
            local.insert(
                key.to_owned(),
                LocalSubgoal {
                    statement: statement.to_owned(),
                    depends_on,
                    critical,
                    kind,
                    subgoal_id,
                    node_id,
                },
            );
        }
        validate_local_dependencies(&local, &location)?;

        let mut research_subgoals = Vec::with_capacity(ordered_keys.len());
        let mut statements = Vec::with_capacity(ordered_keys.len());
        let mut subgoal_ids = Vec::with_capacity(ordered_keys.len());
        for key in ordered_keys {
            let subgoal = &local[&key];
            let dependencies = subgoal
                .depends_on
                .iter()
                .map(|dependency| local[dependency].node_id.as_str())
                .collect::<Vec<_>>();
            statements.push(subgoal.statement.clone());
            subgoal_ids.push(subgoal.subgoal_id.clone());
            research_subgoals.push(serde_json::json!({
                "source_key":key,
                "node_id":subgoal.node_id.as_str(),
                "subgoal_id":subgoal.subgoal_id,
                "statement":subgoal.statement,
                "kind":subgoal.kind.as_str(),
                "depends_on":dependencies,
                "critical":subgoal.critical
            }));
        }
        let motivation = text_array(
            plan.get("motivation"),
            &format!("{location}.motivation"),
            MAX_TEXT_ARRAY,
            false,
            MAX_SUMMARY_BYTES,
        )?;
        let dependencies = text_array(
            plan.get("dependencies"),
            &format!("{location}.dependencies"),
            MAX_TEXT_ARRAY,
            false,
            MAX_SUMMARY_BYTES,
        )?;
        let risks = text_array(
            plan.get("risks"),
            &format!("{location}.risks"),
            MAX_TEXT_ARRAY,
            false,
            MAX_SUMMARY_BYTES,
        )?;
        normalized.push(serde_json::json!({
            "plan_id":plan_id.as_str(),
            "source_plan_id":source_plan_id,
            "summary":summary,
            "subgoals":statements,
            "subgoal_ids":subgoal_ids,
            "research_subgoals":research_subgoals,
            "motivation":motivation,
            "dependencies":dependencies,
            "risks":risks
        }));
    }
    Ok(normalized)
}

pub(crate) fn protocol3_screening_fields(
    result: &Map<String, Value>,
    status: &str,
    location: &str,
) -> Result<ProtocolAttemptFields, ResearchStateError> {
    reject_unknown(
        result,
        &[
            "subgoal_id",
            "subgoal",
            "status",
            "summary",
            "method",
            "obstruction",
            "evidence_ids",
        ],
        location,
    )?;
    let method = optional_text(result.get("method"), &format!("{location}.method"), 32)?
        .map(ResearchAttemptMethod::parse)
        .transpose_option()
        .ok_or_else(|| malformed(format!("{location}.method"), "unknown attempt method"))?
        .unwrap_or(ResearchAttemptMethod::Direct);
    let obstruction = optional_text(
        result.get("obstruction"),
        &format!("{location}.obstruction"),
        64,
    )?
    .map(ResearchObstruction::parse)
    .transpose_option()
    .ok_or_else(|| {
        malformed(
            format!("{location}.obstruction"),
            "unknown obstruction class",
        )
    })?;
    if status == "stuck" && obstruction.is_none() {
        return Err(malformed(
            format!("{location}.obstruction"),
            "stuck screening requires an obstruction class",
        ));
    }
    if status == "solved" && obstruction.is_some() {
        return Err(malformed(
            format!("{location}.obstruction"),
            "solved screening may not declare an obstruction",
        ));
    }
    let evidence_ids = unique_string_array(
        result.get("evidence_ids"),
        &format!("{location}.evidence_ids"),
        MAX_EVIDENCE_IDS,
        false,
        MAX_EVIDENCE_ID_BYTES,
    )?;
    Ok(ProtocolAttemptFields {
        method,
        obstruction,
        evidence_ids,
    })
}

pub(crate) fn normalize_protocol3_generation_record(
    channel: &str,
    content: &Value,
    stamp: &ProtocolRecordStamp<'_>,
    scope: &ProtocolResearchScope,
) -> Result<Value, ResearchStateError> {
    match channel {
        "events" => normalize_event(content, stamp, scope),
        "counterexamples" => normalize_counterexample(content, stamp, scope),
        _ => Ok(content.clone()),
    }
}

pub(crate) fn normalize_protocol3_branch_obstructions(
    value: Option<&Value>,
    scope: &ProtocolResearchScope,
    plan_id: &ResearchPlanId,
    location: &str,
) -> Result<Vec<Value>, ResearchStateError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or_else(|| malformed(location, "expected an array"))?;
    bounded_count(
        "protocol3_branch_obstructions",
        items.len(),
        MAX_NODE_DEPENDENCIES,
    )?;
    let mut normalized = Vec::with_capacity(items.len());
    let mut seen = BTreeSet::new();
    for (index, item) in items.iter().enumerate() {
        let item_location = format!("{location}[{index}]");
        let item = object(item, &item_location)?;
        reject_unknown(
            item,
            &["node_id", "class", "summary", "evidence_ids"],
            &item_location,
        )?;
        let node_id = parse_known_node(
            item.get("node_id"),
            scope,
            &format!("{item_location}.node_id"),
        )?;
        if !scope.plan_contains_node(plan_id, &node_id) {
            return Err(malformed(
                format!("{item_location}.node_id"),
                "node is not assigned to this branch plan",
            ));
        }
        if !seen.insert(node_id.clone()) {
            return Err(malformed(
                &item_location,
                "duplicate branch obstruction node",
            ));
        }
        let class = parse_obstruction(item.get("class"), &format!("{item_location}.class"))?;
        let summary = required_text(
            item.get("summary"),
            &format!("{item_location}.summary"),
            MAX_SUMMARY_BYTES,
        )?;
        let evidence_ids = unique_string_array(
            item.get("evidence_ids"),
            &format!("{item_location}.evidence_ids"),
            MAX_EVIDENCE_IDS,
            false,
            MAX_EVIDENCE_ID_BYTES,
        )?;
        normalized.push(serde_json::json!({
            "node_id":node_id.as_str(),
            "class":class.as_str(),
            "summary":summary,
            "evidence_ids":evidence_ids
        }));
    }
    Ok(normalized)
}

pub(crate) fn normalize_protocol3_branch_payload(
    value: &Value,
    scope: &ProtocolResearchScope,
    plan_id: &ResearchPlanId,
) -> Result<ProtocolBranchFields, ResearchStateError> {
    let location = "branch_complete";
    let object = object(value, location)?;
    reject_unknown(
        object,
        &[
            "status",
            "summary",
            "proof_route",
            "proved_subgoals",
            "unproved_subgoals",
            "failure_evidence",
            "obstructions",
        ],
        location,
    )?;
    let status = required_text(object.get("status"), "branch_complete.status", 32)?;
    if !matches!(status, "solved" | "partial" | "failed") {
        return Err(malformed(
            "branch_complete.status",
            "status must be solved, partial, or failed",
        ));
    }
    let summary = required_text(
        object.get("summary"),
        "branch_complete.summary",
        MAX_SUMMARY_BYTES,
    )?;
    let proof_route = optional_text(
        object.get("proof_route"),
        "branch_complete.proof_route",
        MAX_SUMMARY_BYTES,
    )?
    .map(str::to_owned);
    if status == "solved" && proof_route.is_none() {
        return Err(malformed(
            "branch_complete.proof_route",
            "solved branch requires a proof route",
        ));
    }
    let proved_node_ids = known_node_array(
        object.get("proved_subgoals"),
        scope,
        "branch_complete.proved_subgoals",
        MAX_NODE_DEPENDENCIES,
        false,
    )?;
    let unproved_node_ids = known_node_array(
        object.get("unproved_subgoals"),
        scope,
        "branch_complete.unproved_subgoals",
        MAX_NODE_DEPENDENCIES,
        false,
    )?;
    for node_id in proved_node_ids.iter().chain(&unproved_node_ids) {
        let node_id = ResearchNodeId::parse(node_id)?;
        if !scope.plan_contains_node(plan_id, &node_id) {
            return Err(malformed(
                location,
                "proved and unproved node IDs must belong to the branch plan",
            ));
        }
    }
    if proved_node_ids
        .iter()
        .any(|node_id| unproved_node_ids.contains(node_id))
    {
        return Err(malformed(
            location,
            "a node may not be both proved and unproved",
        ));
    }
    let failure_evidence = text_array(
        object.get("failure_evidence"),
        "branch_complete.failure_evidence",
        MAX_TEXT_ARRAY,
        false,
        MAX_SUMMARY_BYTES,
    )?;
    let obstructions = normalize_protocol3_branch_obstructions(
        object.get("obstructions"),
        scope,
        plan_id,
        "branch_complete.obstructions",
    )?;
    if status == "solved"
        && (!unproved_node_ids.is_empty()
            || !failure_evidence.is_empty()
            || !obstructions.is_empty())
    {
        return Err(malformed(
            location,
            "solved branch may not declare unproved nodes, failure evidence, or obstructions",
        ));
    }
    if matches!(status, "partial" | "failed")
        && unproved_node_ids.is_empty()
        && failure_evidence.is_empty()
        && obstructions.is_empty()
    {
        return Err(malformed(
            location,
            "partial or failed branch requires unproved nodes, failure evidence, or obstructions",
        ));
    }
    Ok(ProtocolBranchFields {
        status: status.to_owned(),
        summary: summary.to_owned(),
        proof_route,
        proved_node_ids,
        unproved_node_ids,
        failure_evidence,
        obstructions,
    })
}

pub(crate) fn normalize_protocol3_failure_summary(
    value: &Value,
    scope: &ProtocolResearchScope,
) -> Result<Value, ResearchStateError> {
    let location = "failures_identified.summary";
    let summary = object(value, location)?;
    reject_unknown(
        summary,
        &[
            "obstruction",
            "next_step",
            "affected_node_ids",
            "obstruction_class",
            "excluded_plan_ids",
            "preserved_node_ids",
            "required_hypotheses",
            "required_reference_queries",
            "selected_focus_node_id",
        ],
        location,
    )?;
    let obstruction = required_text(
        summary.get("obstruction"),
        &format!("{location}.obstruction"),
        MAX_SUMMARY_BYTES,
    )?;
    let next_step = required_text(
        summary.get("next_step"),
        &format!("{location}.next_step"),
        MAX_SUMMARY_BYTES,
    )?;
    let class = parse_obstruction(
        summary.get("obstruction_class"),
        &format!("{location}.obstruction_class"),
    )?;
    let affected = known_node_array(
        summary.get("affected_node_ids"),
        scope,
        &format!("{location}.affected_node_ids"),
        MAX_DECISION_NODE_IDS,
        true,
    )?;
    let excluded = known_plan_array(
        summary.get("excluded_plan_ids"),
        scope,
        &format!("{location}.excluded_plan_ids"),
        MAX_DECISION_PLAN_IDS,
        false,
    )?;
    let preserved = known_node_array(
        summary.get("preserved_node_ids"),
        scope,
        &format!("{location}.preserved_node_ids"),
        MAX_DECISION_NODE_IDS,
        false,
    )?;
    let required_hypotheses = text_array(
        summary.get("required_hypotheses"),
        &format!("{location}.required_hypotheses"),
        MAX_DECISION_CONSTRAINTS,
        false,
        MAX_SUMMARY_BYTES,
    )?;
    let required_reference_queries = text_array(
        summary.get("required_reference_queries"),
        &format!("{location}.required_reference_queries"),
        MAX_DECISION_CONSTRAINTS,
        false,
        MAX_QUERY_BYTES,
    )?;
    let focus = optional_known_node(
        summary.get("selected_focus_node_id"),
        scope,
        &format!("{location}.selected_focus_node_id"),
    )?;
    Ok(serde_json::json!({
        "obstruction":obstruction,
        "next_step":next_step,
        "affected_node_ids":affected,
        "obstruction_class":class.as_str(),
        "excluded_plan_ids":excluded,
        "preserved_node_ids":preserved,
        "required_hypotheses":required_hypotheses,
        "required_reference_queries":required_reference_queries,
        "selected_focus_node_id":focus.map(|node|node.as_str().to_owned())
    }))
}

pub(crate) fn normalize_protocol3_replan_decision(
    value: &Value,
    scope: &ProtocolResearchScope,
) -> Result<Value, ResearchStateError> {
    let location = "replan_complete.decision";
    let decision = object(value, location)?;
    reject_unknown(
        decision,
        &[
            "reason",
            "superseded_plan_ids",
            "preserved_node_ids",
            "new_constraints",
            "selected_focus_node_id",
        ],
        location,
    )?;
    let reason = required_text(
        decision.get("reason"),
        &format!("{location}.reason"),
        MAX_SUMMARY_BYTES,
    )?;
    let superseded = known_plan_array(
        decision.get("superseded_plan_ids"),
        scope,
        &format!("{location}.superseded_plan_ids"),
        MAX_DECISION_PLAN_IDS,
        false,
    )?;
    let preserved = known_node_array(
        decision.get("preserved_node_ids"),
        scope,
        &format!("{location}.preserved_node_ids"),
        MAX_DECISION_NODE_IDS,
        false,
    )?;
    let constraints = text_array(
        decision.get("new_constraints"),
        &format!("{location}.new_constraints"),
        MAX_DECISION_CONSTRAINTS,
        false,
        MAX_SUMMARY_BYTES,
    )?;
    let focus = optional_known_node(
        decision.get("selected_focus_node_id"),
        scope,
        &format!("{location}.selected_focus_node_id"),
    )?;
    if superseded.is_empty() && constraints.is_empty() && focus.is_none() {
        return Err(malformed(
            location,
            "decision must supersede a plan, add a constraint, or select a focus node",
        ));
    }
    Ok(serde_json::json!({
        "reason":reason,
        "superseded_plan_ids":superseded,
        "preserved_node_ids":preserved,
        "new_constraints":constraints,
        "selected_focus_node_id":focus.map(|node|node.as_str().to_owned())
    }))
}

pub(crate) fn stamp_protocol3_record(
    record_type: &str,
    content: &Value,
    stamp: &ProtocolRecordStamp<'_>,
) -> Result<Value, ResearchStateError> {
    let content = object(content, record_type)?;
    for field in RESERVED_RECORD_FIELDS {
        if content.contains_key(field) {
            return Err(malformed(
                record_type,
                format!("client may not supply server-owned field {field}"),
            ));
        }
    }
    let mut normalized = content.clone();
    normalized.insert(
        "record_type".to_owned(),
        Value::String(record_type.to_owned()),
    );
    normalized.insert(
        "record_id".to_owned(),
        Value::String(stamp.record_id.to_owned()),
    );
    normalized.insert(
        "actor_role".to_owned(),
        Value::String(stamp.actor_role.to_owned()),
    );
    normalized.insert(
        "actor_domain_id".to_owned(),
        Value::String(stamp.actor_domain_id.to_owned()),
    );
    normalized.insert("round_index".to_owned(), Value::from(stamp.round_index));
    normalized.insert(
        "created_at".to_owned(),
        Value::String(stamp.created_at.to_owned()),
    );
    Ok(Value::Object(normalized))
}

pub(crate) fn protocol_node_id(
    plan_id: &ResearchPlanId,
    subgoal_id: &str,
) -> Result<ResearchNodeId, ResearchStateError> {
    if plan_id.as_str().contains(':') || subgoal_id.contains(':') {
        return Err(malformed(
            "node_id",
            "plan_id and subgoal_id may not contain ':'",
        ));
    }
    ResearchNodeId::parse(format!("node:{}:{subgoal_id}", plan_id.as_str()))
}

#[derive(Clone, Debug)]
struct LocalSubgoal {
    statement: String,
    depends_on: Vec<String>,
    critical: bool,
    kind: ResearchNodeKind,
    subgoal_id: String,
    node_id: ResearchNodeId,
}

fn normalize_event(
    content: &Value,
    stamp: &ProtocolRecordStamp<'_>,
    scope: &ProtocolResearchScope,
) -> Result<Value, ResearchStateError> {
    let event = object(content, "events")?;
    let event_type = required_text(event.get("event_type"), "events.event_type", 64)?;
    match event_type {
        "counterexample_probe" => normalize_counterexample(content, stamp, scope),
        "toy_example_result" => {
            reject_unknown(
                event,
                &[
                    "event_type",
                    "node_id",
                    "outcome",
                    "summary",
                    "evidence_ids",
                ],
                "events.toy_example_result",
            )?;
            let node_id = parse_known_node(event.get("node_id"), scope, "events.node_id")?;
            let outcome = required_text(event.get("outcome"), "events.outcome", 32)?;
            if !matches!(outcome, "progress" | "refuted" | "inconclusive") {
                return Err(malformed(
                    "events.outcome",
                    "toy example outcome must be progress, refuted, or inconclusive",
                ));
            }
            let summary = required_text(event.get("summary"), "events.summary", MAX_SUMMARY_BYTES)?;
            let evidence = unique_string_array(
                event.get("evidence_ids"),
                "events.evidence_ids",
                MAX_EVIDENCE_IDS,
                false,
                MAX_EVIDENCE_ID_BYTES,
            )?;
            stamp_protocol3_record(
                "toy_example_result",
                &serde_json::json!({
                    "event_type":"toy_example_result",
                    "node_id":node_id.as_str(),
                    "outcome":outcome,
                    "summary":summary,
                    "evidence_ids":evidence
                }),
                stamp,
            )
        }
        "retrieval_assessment" => {
            reject_unknown(
                event,
                &[
                    "event_type",
                    "node_id",
                    "outcome",
                    "summary",
                    "query",
                    "reference_ids",
                ],
                "events.retrieval_assessment",
            )?;
            let node_id = optional_known_node(event.get("node_id"), scope, "events.node_id")?;
            let outcome = required_text(event.get("outcome"), "events.outcome", 32)?;
            if !matches!(outcome, "new_material" | "no_new_material" | "inconclusive") {
                return Err(malformed(
                    "events.outcome",
                    "retrieval outcome must be new_material, no_new_material, or inconclusive",
                ));
            }
            let summary = required_text(event.get("summary"), "events.summary", MAX_SUMMARY_BYTES)?;
            let query = optional_text(event.get("query"), "events.query", MAX_QUERY_BYTES)?;
            let references = registered_reference_array(
                event.get("reference_ids"),
                scope,
                "events.reference_ids",
            )?;
            if outcome == "new_material" && references.is_empty() {
                return Err(malformed(
                    "events.reference_ids",
                    "new_material requires at least one registered reference_id",
                ));
            }
            stamp_protocol3_record(
                "retrieval_assessment",
                &serde_json::json!({
                    "event_type":"retrieval_assessment",
                    "node_id":node_id.map(|node|node.as_str().to_owned()),
                    "outcome":outcome,
                    "summary":summary,
                    "query":query,
                    "reference_ids":references
                }),
                stamp,
            )
        }
        "new_candidate_lemma" => {
            reject_unknown(
                event,
                &[
                    "event_type",
                    "statement",
                    "summary",
                    "depends_on",
                    "critical",
                    "kind",
                    "evidence_ids",
                ],
                "events.new_candidate_lemma",
            )?;
            let statement = required_text(
                event.get("statement"),
                "events.statement",
                MAX_STATEMENT_BYTES,
            )?;
            let summary = required_text(event.get("summary"), "events.summary", MAX_SUMMARY_BYTES)?;
            let dependencies = known_node_array(
                event.get("depends_on"),
                scope,
                "events.depends_on",
                MAX_NODE_DEPENDENCIES,
                false,
            )?;
            let critical = event
                .get("critical")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let kind = optional_text(event.get("kind"), "events.kind", 32)?
                .map(ResearchNodeKind::parse)
                .transpose_option()
                .ok_or_else(|| malformed("events.kind", "unknown node kind"))?
                .unwrap_or(ResearchNodeKind::Lemma);
            if kind == ResearchNodeKind::Target {
                return Err(malformed(
                    "events.kind",
                    "candidate lemma cannot declare target kind",
                ));
            }
            let evidence = unique_string_array(
                event.get("evidence_ids"),
                "events.evidence_ids",
                MAX_EVIDENCE_IDS,
                false,
                MAX_EVIDENCE_ID_BYTES,
            )?;
            stamp_protocol3_record(
                "new_candidate_lemma",
                &serde_json::json!({
                    "event_type":"new_candidate_lemma",
                    "candidate_id":stamp.record_id,
                    "statement":statement,
                    "summary":summary,
                    "depends_on":dependencies,
                    "critical":critical,
                    "kind":kind.as_str(),
                    "evidence_ids":evidence
                }),
                stamp,
            )
        }
        "notation_resolution" => {
            reject_unknown(
                event,
                &[
                    "event_type",
                    "node_id",
                    "symbol",
                    "resolution",
                    "summary",
                    "evidence_ids",
                ],
                "events.notation_resolution",
            )?;
            let node_id = optional_known_node(event.get("node_id"), scope, "events.node_id")?;
            let symbol = required_text(event.get("symbol"), "events.symbol", MAX_SYMBOL_BYTES)?;
            let resolution = required_text(
                event.get("resolution"),
                "events.resolution",
                MAX_SUMMARY_BYTES,
            )?;
            let summary = required_text(event.get("summary"), "events.summary", MAX_SUMMARY_BYTES)?;
            let evidence = unique_string_array(
                event.get("evidence_ids"),
                "events.evidence_ids",
                MAX_EVIDENCE_IDS,
                false,
                MAX_EVIDENCE_ID_BYTES,
            )?;
            stamp_protocol3_record(
                "notation_resolution",
                &serde_json::json!({
                    "event_type":"notation_resolution",
                    "node_id":node_id.map(|node|node.as_str().to_owned()),
                    "symbol":symbol,
                    "resolution":resolution,
                    "summary":summary,
                    "evidence_ids":evidence
                }),
                stamp,
            )
        }
        _ => Err(malformed(
            "events.event_type",
            "unknown protocol-3 exploration event type",
        )),
    }
}

fn normalize_counterexample(
    content: &Value,
    stamp: &ProtocolRecordStamp<'_>,
    scope: &ProtocolResearchScope,
) -> Result<Value, ResearchStateError> {
    let event = object(content, "counterexamples")?;
    reject_unknown(
        event,
        &[
            "event_type",
            "node_id",
            "outcome",
            "summary",
            "probe_scope",
            "witness",
            "evidence_ids",
        ],
        "counterexamples",
    )?;
    if let Some(event_type) = event.get("event_type") {
        if event_type.as_str() != Some("counterexample_probe") {
            return Err(malformed(
                "counterexamples.event_type",
                "counterexample channel accepts only counterexample_probe",
            ));
        }
    }
    let node_id = parse_known_node(event.get("node_id"), scope, "counterexamples.node_id")?;
    let outcome = required_text(event.get("outcome"), "counterexamples.outcome", 32)?;
    if !matches!(outcome, "found" | "not_found_within_scope" | "inconclusive") {
        return Err(malformed(
            "counterexamples.outcome",
            "outcome must be found, not_found_within_scope, or inconclusive",
        ));
    }
    let summary = required_text(
        event.get("summary"),
        "counterexamples.summary",
        MAX_SUMMARY_BYTES,
    )?;
    let probe_scope = required_text(
        event.get("probe_scope"),
        "counterexamples.probe_scope",
        MAX_SUMMARY_BYTES,
    )?;
    let witness = optional_text(
        event.get("witness"),
        "counterexamples.witness",
        MAX_SUMMARY_BYTES,
    )?;
    if outcome == "found" && witness.is_none() {
        return Err(malformed(
            "counterexamples.witness",
            "found counterexample requires a non-empty witness",
        ));
    }
    let evidence = unique_string_array(
        event.get("evidence_ids"),
        "counterexamples.evidence_ids",
        MAX_EVIDENCE_IDS,
        false,
        MAX_EVIDENCE_ID_BYTES,
    )?;
    stamp_protocol3_record(
        "counterexample_probe",
        &serde_json::json!({
            "event_type":"counterexample_probe",
            "node_id":node_id.as_str(),
            "outcome":outcome,
            "summary":summary,
            "probe_scope":probe_scope,
            "witness":witness,
            "evidence_ids":evidence,
            "obstruction_class":if outcome=="found"{Some("false_claim")}else{None}
        }),
        stamp,
    )
}

fn validate_local_dependencies(
    subgoals: &BTreeMap<String, LocalSubgoal>,
    location: &str,
) -> Result<(), ResearchStateError> {
    for (key, subgoal) in subgoals {
        for dependency in &subgoal.depends_on {
            validate_local_key(
                dependency,
                &format!("{location}.subgoals[{key}].depends_on"),
            )?;
            if dependency == key {
                return Err(malformed(location, "subgoal may not depend on itself"));
            }
            if !subgoals.contains_key(dependency) {
                return Err(malformed(
                    location,
                    format!("subgoal {key} references unknown local key {dependency}"),
                ));
            }
        }
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for key in subgoals.keys() {
        visit_local(key, subgoals, &mut visiting, &mut visited, location)?;
    }
    Ok(())
}

fn visit_local(
    key: &str,
    subgoals: &BTreeMap<String, LocalSubgoal>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
    location: &str,
) -> Result<(), ResearchStateError> {
    if visited.contains(key) {
        return Ok(());
    }
    if !visiting.insert(key.to_owned()) {
        return Err(malformed(
            location,
            format!("subgoal dependency cycle contains {key}"),
        ));
    }
    for dependency in &subgoals[key].depends_on {
        visit_local(dependency, subgoals, visiting, visited, location)?;
    }
    visiting.remove(key);
    visited.insert(key.to_owned());
    Ok(())
}

fn validate_local_key(value: &str, location: &str) -> Result<(), ResearchStateError> {
    let mut characters = value.chars();
    if value.contains(':')
        || !characters
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric())
        || !characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(malformed(
            location,
            "local key must be an unambiguous ASCII identifier",
        ));
    }
    Ok(())
}

fn parse_known_node(
    value: Option<&Value>,
    scope: &ProtocolResearchScope,
    location: &str,
) -> Result<ResearchNodeId, ResearchStateError> {
    let node_id = ResearchNodeId::parse(required_text(value, location, MAX_IDENTIFIER_BYTES)?)?;
    if !scope.contains_node(&node_id) {
        return Err(malformed(location, "unknown canonical node_id"));
    }
    Ok(node_id)
}

fn optional_known_node(
    value: Option<&Value>,
    scope: &ProtocolResearchScope,
    location: &str,
) -> Result<Option<ResearchNodeId>, ResearchStateError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => parse_known_node(Some(value), scope, location).map(Some),
    }
}

fn parse_obstruction(
    value: Option<&Value>,
    location: &str,
) -> Result<ResearchObstruction, ResearchStateError> {
    let value = required_text(value, location, 64)?;
    ResearchObstruction::parse(value)
        .ok_or_else(|| malformed(location, "unknown obstruction class"))
}

fn known_node_array(
    value: Option<&Value>,
    scope: &ProtocolResearchScope,
    location: &str,
    limit: usize,
    required: bool,
) -> Result<Vec<String>, ResearchStateError> {
    let values = unique_string_array(value, location, limit, required, MAX_IDENTIFIER_BYTES)?;
    values
        .into_iter()
        .map(|value| {
            let node_id = ResearchNodeId::parse(value)?;
            if !scope.contains_node(&node_id) {
                return Err(malformed(location, "unknown canonical node_id"));
            }
            Ok(node_id.as_str().to_owned())
        })
        .collect()
}

fn known_plan_array(
    value: Option<&Value>,
    scope: &ProtocolResearchScope,
    location: &str,
    limit: usize,
    required: bool,
) -> Result<Vec<String>, ResearchStateError> {
    let values = unique_string_array(value, location, limit, required, MAX_IDENTIFIER_BYTES)?;
    values
        .into_iter()
        .map(|value| {
            let plan_id = ResearchPlanId::parse(value)?;
            if !scope.contains_plan(&plan_id) {
                return Err(malformed(location, "unknown canonical plan_id"));
            }
            Ok(plan_id.as_str().to_owned())
        })
        .collect()
}

fn registered_reference_array(
    value: Option<&Value>,
    scope: &ProtocolResearchScope,
    location: &str,
) -> Result<Vec<String>, ResearchStateError> {
    let values = unique_string_array(
        value,
        location,
        MAX_EVIDENCE_IDS,
        false,
        MAX_EVIDENCE_ID_BYTES,
    )?;
    for value in &values {
        if !scope.reference_registered(value) {
            return Err(malformed(
                location,
                "reference_id is not registered for this run",
            ));
        }
    }
    Ok(values)
}

fn object<'a>(
    value: &'a Value,
    location: &str,
) -> Result<&'a Map<String, Value>, ResearchStateError> {
    value
        .as_object()
        .ok_or_else(|| malformed(location, "expected an object"))
}

fn reject_unknown(
    object: &Map<String, Value>,
    allowed: &[&str],
    location: &str,
) -> Result<(), ResearchStateError> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(malformed(location, format!("unknown field {field}")));
    }
    Ok(())
}

fn required_text<'a>(
    value: Option<&'a Value>,
    location: &str,
    max_bytes: usize,
) -> Result<&'a str, ResearchStateError> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= max_bytes && !value.contains('\0'))
        .ok_or_else(|| malformed(location, "non-empty bounded string required"))
}

fn optional_text<'a>(
    value: Option<&'a Value>,
    location: &str,
    max_bytes: usize,
) -> Result<Option<&'a str>, ResearchStateError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => required_text(Some(value), location, max_bytes).map(Some),
    }
}

fn text_array(
    value: Option<&Value>,
    location: &str,
    limit: usize,
    required: bool,
    max_bytes: usize,
) -> Result<Vec<String>, ResearchStateError> {
    let Some(value) = value else {
        return if required {
            Err(malformed(location, "array is required"))
        } else {
            Ok(Vec::new())
        };
    };
    let items = value
        .as_array()
        .ok_or_else(|| malformed(location, "expected an array"))?;
    if required && items.is_empty() {
        return Err(malformed(location, "non-empty array required"));
    }
    bounded_count("protocol3_text_array", items.len(), limit)?;
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            required_text(Some(item), &format!("{location}[{index}]"), max_bytes).map(str::to_owned)
        })
        .collect()
}

fn unique_string_array(
    value: Option<&Value>,
    location: &str,
    limit: usize,
    required: bool,
    max_bytes: usize,
) -> Result<Vec<String>, ResearchStateError> {
    let values = text_array(value, location, limit, required, max_bytes)?;
    let mut seen = BTreeSet::new();
    for value in &values {
        if !seen.insert(value.clone()) {
            return Err(malformed(location, "array entries must be unique"));
        }
    }
    Ok(values)
}

fn bounded_count(
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

fn malformed(location: impl Into<String>, reason: impl Into<String>) -> ResearchStateError {
    ResearchStateError::MalformedProtocolRecord {
        location: location.into(),
        reason: reason.into(),
    }
}

trait TransposeOption<T> {
    fn transpose_option(self) -> Option<Option<T>>;
}

impl<T> TransposeOption<T> for Option<Option<T>> {
    fn transpose_option(self) -> Option<Option<T>> {
        match self {
            None => Some(None),
            Some(Some(value)) => Some(Some(value)),
            Some(None) => None,
        }
    }
}

#[cfg(test)]
mod tests;
