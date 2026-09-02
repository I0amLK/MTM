use super::*;

pub(super) fn find_plan<'a>(
    plans: &'a BTreeMap<ResearchPlanId, Vec<LegacyPlanNode>>,
    plan_text: &str,
) -> Option<(&'a ResearchPlanId, &'a Vec<LegacyPlanNode>)> {
    plans
        .iter()
        .find(|(plan_id, _)| plan_id.as_str() == plan_text)
}

pub(super) fn resolve_plan_node<'a>(
    plan_nodes: &'a [LegacyPlanNode],
    label: &str,
) -> Option<&'a ResearchNodeId> {
    plan_nodes
        .iter()
        .find(|node| node.subgoal_id == label || node.statement == label)
        .map(|node| &node.node_id)
}

pub(super) fn resolve_canonical_node(
    value: Option<&Value>,
    nodes: &BTreeMap<ResearchNodeId, ResearchNode>,
) -> Option<ResearchNodeId> {
    let text = value.and_then(Value::as_str)?;
    nodes
        .keys()
        .find(|node_id| node_id.as_str() == text)
        .cloned()
}

pub(super) fn combined_node_id(
    plan_id: &ResearchPlanId,
    subgoal_id: &str,
) -> Result<ResearchNodeId, ResearchStateError> {
    if plan_id.as_str().contains(':') || subgoal_id.contains(':') {
        return Err(malformed(
            "active_plans",
            "plan_id and subgoal_id may not contain ':' in legacy normalization",
        ));
    }
    ResearchNodeId::parse(format!("node:{}:{subgoal_id}", plan_id.as_str()))
}

pub(super) fn normalize_screening_status(
    value: &str,
    location: &str,
    warnings: &mut WarningCollector,
) -> ResearchNodeStatus {
    match value {
        "solved" => ResearchNodeStatus::RouteSolved,
        "partial" => ResearchNodeStatus::Partial,
        "stuck" => ResearchNodeStatus::Blocked,
        _ => {
            warnings.push(
                "unknown_screening_status",
                location,
                format!("unknown screening status {value:?}; treated as open in shadow"),
            );
            ResearchNodeStatus::Open
        }
    }
}

pub(super) fn screening_outcome(value: &str) -> Option<ResearchAttemptOutcome> {
    match value {
        "solved" => Some(ResearchAttemptOutcome::RouteSolved),
        "partial" => Some(ResearchAttemptOutcome::Progress),
        "stuck" => Some(ResearchAttemptOutcome::Failed),
        _ => None,
    }
}

pub(super) fn required_text(
    value: Option<&Value>,
    location: &str,
) -> Result<String, ResearchStateError> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| malformed(location, "expected a non-empty string"))
}

pub(super) fn required_string_array(
    value: Option<&Value>,
    location: &str,
    limit: usize,
) -> Result<Vec<String>, ResearchStateError> {
    let values = value
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .ok_or_else(|| malformed(location, "expected a non-empty string array"))?;
    if values.len() > limit {
        return Err(ResearchStateError::LimitExceeded {
            kind: "legacy_string_array",
            limit,
            actual: values.len(),
        });
    }
    values
        .iter()
        .enumerate()
        .map(|(index, value)| required_text(Some(value), &format!("{location}[{index}]")))
        .collect()
}

pub(super) fn bounded_optional_string_array(
    value: Option<&Value>,
    location: &str,
    limit: usize,
) -> Result<Vec<String>, ResearchStateError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| malformed(location, "expected a string array when present"))?;
    if values.len() > limit {
        return Err(ResearchStateError::LimitExceeded {
            kind: "legacy_string_array",
            limit,
            actual: values.len(),
        });
    }
    values
        .iter()
        .enumerate()
        .map(|(index, value)| required_text(Some(value), &format!("{location}[{index}]")))
        .collect()
}

pub(super) fn meaningful_witness(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::String(value)) => !value.trim().is_empty(),
        Some(Value::Array(values)) => !values.is_empty(),
        Some(Value::Object(values)) => !values.is_empty(),
        Some(Value::Bool(_)) | Some(Value::Number(_)) => true,
    }
}

pub(super) fn extract_summary(record: &Value) -> Option<&str> {
    ["summary", "obstruction", "reason", "decision", "next_step"]
        .into_iter()
        .filter_map(|key| record.get(key).and_then(Value::as_str))
        .map(str::trim)
        .find(|value| !value.is_empty())
}

pub(super) fn malformed(
    location: impl Into<String>,
    reason: impl Into<String>,
) -> ResearchStateError {
    ResearchStateError::MalformedLegacyRecord {
        location: location.into(),
        reason: reason.into(),
    }
}
