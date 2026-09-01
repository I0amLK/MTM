use mtm_contracts::{ErrorCategory, ReCtmError, WorkflowState};
use serde_json::{Map, Value};

#[derive(Clone)]
pub struct TaskCatalog {
    source: Value,
}

impl TaskCatalog {
    pub fn from_source_snapshot(source: Value) -> Result<Self, ReCtmError> {
        let tasks = source
            .get("tasks")
            .and_then(Value::as_object)
            .ok_or_else(invalid_catalog)?;
        for (state, task) in tasks {
            let object = task.as_object().ok_or_else(invalid_catalog)?;
            if !object
                .get("commit_action")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
                || !object.get("write_contract").is_some_and(Value::is_array)
                || !object
                    .get("commit_payload_schema")
                    .is_some_and(Value::is_object)
                || ![
                    "minimal_submission",
                    "minimal_submission_template",
                    "submission_examples",
                ]
                .iter()
                .any(|key| object.contains_key(*key))
            {
                return Err(ReCtmError::new(
                    "METHODOLOGY_INVALID",
                    "Embedded methodology task contract is invalid.",
                )
                .with_category(ErrorCategory::Internal)
                .with_details(Map::from_iter([(
                    "state".to_owned(),
                    Value::String(state.clone()),
                )])));
            }
        }
        Ok(Self { source })
    }

    pub fn task_for_run(
        &self,
        state: WorkflowState,
        protocol_version: i64,
        effective_mode: &str,
        proof_manifest: Option<&Value>,
    ) -> Result<Value, ReCtmError> {
        let state_name = state_name(state);
        let mut task = self
            .source
            .get("tasks")
            .and_then(Value::as_object)
            .and_then(|tasks| tasks.get(state_name))
            .cloned()
            .ok_or_else(|| {
                ReCtmError::new(
                    "NO_MODEL_TASK",
                    format!("Workflow state has no model task: {state_name}"),
                )
                .with_category(ErrorCategory::Validation)
            })?;
        let object = task.as_object_mut().ok_or_else(invalid_catalog)?;
        object.insert(
            "step_protocol".to_owned(),
            serde_json::json!({
                "tool": "rethlas_step",
                "use_current_envelope_fields": ["run_id", "capability"],
                "envelope_binding": "Copy run_id and capability verbatim from the same current task envelope. Capability is opaque: never decode, edit, normalize, concatenate, or synthesize it.",
                "writes": "Follow write_contract exactly. Each writes[] entry is one logical record; memory records are JSON objects unless that resource's content_schema says otherwise. Do not batch several memory records into one array-valued content field.",
                "action": "Use commit_action exactly as returned by this task.",
                "payload": "Follow commit_payload_schema exactly. Use {} when the schema has no required fields; do not echo logical-write content into commit payload unless the schema explicitly asks for it.",
                "recoverable_correction": "If submission.recoverable is true, continue with the fresh run_id/capability pair returned in the same response. Successful writes listed as retained must not be replayed unless the current task explicitly requires a new record."
            }),
        );
        object.insert(
            "workflow_protocol_version".to_owned(),
            Value::from(protocol_version),
        );

        if protocol_version >= 2 {
            match state {
                WorkflowState::Assess => overlay_assess(object),
                WorkflowState::Assemble | WorkflowState::Repair => {
                    overlay_proof_manifest(object, state, effective_mode)?;
                }
                WorkflowState::Verify => overlay_verify(object, proof_manifest),
                _ => {}
            }
        }
        Ok(task)
    }
}

fn overlay_assess(task: &mut Map<String, Value>) {
    task.insert(
        "commit_payload_schema".to_owned(),
        serde_json::json!({
            "type":"object",
            "additionalProperties":false,
            "properties":{
                "route":{"type":"string","enum":["compact","full"]},
                "route_reason":{"type":"string"},
                "requires_external_retrieval":{"type":"boolean"},
                "requires_multiple_plans":{"type":"boolean"}
            }
        }),
    );
    if let Some(minimal) = task
        .get_mut("minimal_submission")
        .and_then(Value::as_object_mut)
    {
        minimal.insert(
            "payload".to_owned(),
            serde_json::json!({
                "route":"compact",
                "route_reason":"The target is a local lemma with a direct self-contained proof.",
                "requires_external_retrieval":false,
                "requires_multiple_plans":false
            }),
        );
    }
    task.insert(
        "route_policy".to_owned(),
        Value::String("Recommend compact only for a direct self-contained argument that does not need external retrieval or competing decomposition plans. The server makes the final route decision.".to_owned()),
    );
}

fn overlay_proof_manifest(
    task: &mut Map<String, Value>,
    state: WorkflowState,
    effective_mode: &str,
) -> Result<(), ReCtmError> {
    let contract = serde_json::json!({
        "resource":"proof_manifest",
        "required":true,
        "content_schema":{
            "type":"object",
            "required":["target_statement_tex","dependency_revision_ids","reference_ids","conditional_hypotheses","computational_evidence"],
            "additionalProperties":false,
            "properties":{
                "target_statement_tex":{"type":"string","minLength":1},
                "dependency_revision_ids":{"type":"array","items":{"type":"string","minLength":1}},
                "reference_ids":{"type":"array","items":{"type":"string","minLength":1}},
                "conditional_hypotheses":{"type":"array","items":{"type":"string","minLength":1}},
                "computational_evidence":{"type":"array","items":{"type":"object","additionalProperties":true}}
            }
        },
        "example":{
            "target_statement_tex":"Complete target statement in LaTeX.",
            "dependency_revision_ids":[],"reference_ids":[],"conditional_hypotheses":[],"computational_evidence":[]
        }
    });
    let contracts = task
        .entry("write_contract")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(invalid_catalog)?;
    if !contracts
        .iter()
        .any(|item| item.get("resource") == Some(&Value::String("proof_manifest".to_owned())))
    {
        contracts.push(contract);
    }
    let required = task
        .entry("required_records")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(invalid_catalog)?;
    if !required.iter().any(|item| item == "proof_manifest") {
        required.push(Value::String("proof_manifest".to_owned()));
    }
    if let Some(minimal) = task
        .get_mut("minimal_submission")
        .and_then(Value::as_object_mut)
    {
        let writes = minimal
            .entry("writes")
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(invalid_catalog)?;
        if !writes
            .iter()
            .any(|item| item.get("resource") == Some(&Value::String("proof_manifest".to_owned())))
        {
            writes.push(serde_json::json!({
                "resource":"proof_manifest",
                "content":{
                    "target_statement_tex":"Complete target statement in LaTeX.",
                    "dependency_revision_ids":[],"reference_ids":[],"conditional_hypotheses":[],"computational_evidence":[]
                }
            }));
        }
    }
    if state == WorkflowState::Assemble && effective_mode == "compact" {
        if let Some(contracts) = task.get_mut("write_contract").and_then(Value::as_array_mut) {
            for contract in contracts {
                if matches!(
                    contract.get("resource").and_then(Value::as_str),
                    Some("proof" | "proof_manifest")
                ) {
                    if let Some(object) = contract.as_object_mut() {
                        object.remove("required");
                        object.insert(
                            "required_when".to_owned(),
                            Value::String("Required when payload.outcome=proof; omit when payload.outcome=escalate.".to_owned()),
                        );
                    }
                }
            }
        }
        task.insert("required_records".to_owned(), Value::Array(Vec::new()));
        task.insert(
            "required_records_for_outcome".to_owned(),
            serde_json::json!({"proof":["proof","proof_manifest"],"escalate":[]}),
        );
        task.insert(
            "commit_payload_schema".to_owned(),
            serde_json::json!({
                "type":"object","additionalProperties":false,
                "properties":{"outcome":{"type":"string","enum":["proof","escalate"]},"escalation_reason":{"type":"string"}}
            }),
        );
        if let Some(minimal) = task
            .get_mut("minimal_submission")
            .and_then(Value::as_object_mut)
        {
            minimal.insert("payload".to_owned(), serde_json::json!({"outcome":"proof"}));
        }
        task.insert(
            "commit_payload_contract".to_owned(),
            serde_json::json!({
                "outcome":"Use proof after writing proof and proof_manifest. Use escalate without proof writes when full exploration is required."
            }),
        );
    } else if state == WorkflowState::Assemble {
        task.insert(
            "commit_payload_schema".to_owned(),
            serde_json::json!({"type":"object","additionalProperties":false,"properties":{}}),
        );
        task.insert(
            "commit_payload_contract".to_owned(),
            serde_json::json!({
                "proof":"Full-mode assembly writes proof and proof_manifest, then commits an empty payload."
            }),
        );
    }
    Ok(())
}

fn overlay_verify(task: &mut Map<String, Value>, proof_manifest: Option<&Value>) {
    if let Some(contracts) = task.get_mut("write_contract").and_then(Value::as_array_mut) {
        contracts.retain(|item| {
            item.get("resource")
                != Some(&Value::String(
                    "memory:verifier:reference_checks".to_owned(),
                ))
        });
        contracts.push(serde_json::json!({
            "resource":"reference_audit",
            "required_when":"For every reference_id listed in proof_manifest.reference_ids.",
            "content_schema":{
                "type":"object","required":["reference_id","disposition","evidence_basis","evidence_locator"],"additionalProperties":false,
                "properties":{
                    "reference_id":{"type":"string","minLength":1},
                    "disposition":{"type":"string","enum":["SOURCE_VERIFIED","INDEPENDENTLY_REDERIVED","UNRESOLVED","NOT_MATERIAL"]},
                    "evidence_basis":{"type":"string","enum":["stored_source_snapshot","external_source_inspection","independent_derivation","not_material","unresolved"]},
                    "evidence_locator":{"type":"string"},
                    "material":{"type":"boolean"},"assumptions_checked":{"type":"boolean"},"notation_checked":{"type":"boolean"},"source_checked":{"type":"boolean"},"independently_rederived":{"type":"boolean"},"notes":{"type":"string"}
                }
            },
            "example":{
                "reference_id":"ref-...",
                "disposition":"SOURCE_VERIFIED",
                "evidence_basis":"external_source_inspection",
                "evidence_locator":"DOI/arXiv/source location inspected by the verifier",
                "material":true,
                "assumptions_checked":true,
                "notation_checked":true,
                "source_checked":true,
                "independently_rederived":false,
                "notes":"Assumptions and local notation match the cited statement."
            }
        }));
    }
    let reference_ids = proof_manifest
        .and_then(|value| value.get("reference_ids"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    task.insert(
        "reference_ids_requiring_audit".to_owned(),
        serde_json::json!(reference_ids),
    );
    task.insert(
        "reference_audit_policy".to_owned(),
        Value::String("Every material reference listed by proof_manifest must receive a disposition plus evidence_basis/evidence_locator. Missing or UNRESOLVED material references are converted into server-side verification gaps even if the submitted report omits them.".to_owned()),
    );
    task.insert(
        "commit_payload_contract".to_owned(),
        serde_json::json!({
            "memory_preconditions":"At least one memory:verifier:statement_checks record and one memory:verifier:events audit-complete record.",
            "reference_preconditions":"Every proof_manifest.reference_id is covered by structured reference_audit. SOURCE_VERIFIED must identify the stored source snapshot or an external source location actually inspected; INDEPENDENTLY_REDERIVED must identify the independent derivation. Missing or UNRESOLVED material coverage becomes a server-derived verification gap.",
            "server_reads_report_from":"the verification_report logical write; do not echo the report in commit payload"
        }),
    );
    let rules = task
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|rule| {
            !rule
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .contains("reference checks")
        })
        .chain(std::iter::once(Value::String(
            "For protocol 2, use structured reference_audit writes rather than legacy memory:verifier:reference_checks records.".to_owned(),
        )))
        .collect::<Vec<_>>();
    task.insert("rules".to_owned(), Value::Array(rules));
}

fn invalid_catalog() -> ReCtmError {
    ReCtmError::new(
        "METHODOLOGY_INVALID",
        "Embedded methodology resource is invalid.",
    )
    .with_category(ErrorCategory::Internal)
}

pub fn state_name(state: WorkflowState) -> &'static str {
    match state {
        WorkflowState::Created => "created",
        WorkflowState::Assess => "assess",
        WorkflowState::Explore => "explore",
        WorkflowState::ProposePlans => "propose_plans",
        WorkflowState::DirectProving => "direct_proving",
        WorkflowState::BranchPrepare => "branch_prepare",
        WorkflowState::BranchRun => "branch_run",
        WorkflowState::BranchJoin => "branch_join",
        WorkflowState::IdentifyFailures => "identify_failures",
        WorkflowState::Replan => "replan",
        WorkflowState::Assemble => "assemble",
        WorkflowState::LatexValidate => "latex_validate",
        WorkflowState::Verify => "verify",
        WorkflowState::Repair => "repair",
        WorkflowState::Finalize => "finalize",
        WorkflowState::Done => "done",
        WorkflowState::Cancelled => "cancelled",
        WorkflowState::Failed => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_catalog_fails_closed() {
        assert!(
            TaskCatalog::from_source_snapshot(serde_json::json!({"tasks":{"assess":{}}})).is_err()
        );
    }
}
