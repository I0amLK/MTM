use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use mtm_contracts::{ErrorCategory, ReCtmError, WorkflowRole, WorkflowState};
use mtm_storage::{
    CapabilityAuthority, CapabilityClaims, StateStore, TransitionRun, default_permissions,
    role_for_state,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::kernel::{TransitionDecision, TransitionRequest};
use crate::methodology::{TaskCatalog, state_name};
use crate::research::{DisabledResearchProvider, ResearchProvider, ResearchRequest};
use crate::vault::{BRANCH_CHANNELS, GENERATION_CHANNELS, PrivateVault, VERIFIER_CHANNELS};
use crate::verifier::{
    FinalizationPermit, VerificationDecision, VerificationFinding, VerificationVerdict,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LatexGateResult {
    pub policy: String,
    pub static_valid: bool,
    pub compile_attempted: bool,
    pub compile_available: bool,
    pub compile_passed: bool,
    pub gate_passed: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub compiler_output: String,
}

impl LatexGateResult {
    #[must_use]
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

pub trait LatexGate: Send + Sync {
    fn validate(
        &self,
        proof: &str,
        workdir: &std::path::Path,
    ) -> Result<LatexGateResult, ReCtmError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkflowEvent {
    pub event_type: String,
    pub trace_id: String,
    pub run_id: Option<String>,
    pub actor_role: Option<String>,
    pub domain_id: Option<String>,
    pub before_state: Option<String>,
    pub after_state: Option<String>,
    pub decision: String,
    pub reason: String,
    pub details: Value,
}

pub type WorkflowObserver = Arc<dyn Fn(WorkflowEvent) + Send + Sync + 'static>;

pub struct WorkflowEngine {
    store: Arc<StateStore>,
    vault: Arc<PrivateVault>,
    capabilities: Arc<CapabilityAuthority>,
    methodology: Arc<TaskCatalog>,
    latex_gate: Arc<dyn LatexGate>,
    research: Arc<dyn ResearchProvider>,
    observer: Option<WorkflowObserver>,
}

impl WorkflowEngine {
    #[must_use]
    pub fn new(
        store: Arc<StateStore>,
        vault: Arc<PrivateVault>,
        capabilities: Arc<CapabilityAuthority>,
        methodology: Arc<TaskCatalog>,
        latex_gate: Arc<dyn LatexGate>,
        observer: Option<WorkflowObserver>,
    ) -> Self {
        Self::new_with_research(
            store,
            vault,
            capabilities,
            methodology,
            latex_gate,
            Arc::new(DisabledResearchProvider),
            observer,
        )
    }

    #[must_use]
    pub fn new_with_research(
        store: Arc<StateStore>,
        vault: Arc<PrivateVault>,
        capabilities: Arc<CapabilityAuthority>,
        methodology: Arc<TaskCatalog>,
        latex_gate: Arc<dyn LatexGate>,
        research: Arc<dyn ResearchProvider>,
        observer: Option<WorkflowObserver>,
    ) -> Self {
        Self {
            store,
            vault,
            capabilities,
            methodology,
            latex_gate,
            research,
            observer,
        }
    }

    pub fn start(&self, request: StartRequest<'_>) -> Result<Value, ReCtmError> {
        if request.owner_id.trim().is_empty() {
            return Err(invalid("owner_id is required"));
        }
        if request.problem_tex.trim().is_empty() {
            return Err(invalid("problem_tex is required"));
        }
        if !matches!(request.workflow_mode, "auto" | "compact" | "full") {
            return Err(invalid("workflow_mode must be auto, compact, or full"));
        }
        if !matches!(request.workflow_protocol_version, 1 | 2) {
            return Err(invalid("workflow_protocol_version must be 1 or 2"));
        }
        if request.target_claim_id.is_some() && request.project_id.is_none() {
            return Err(invalid("target_claim_id requires project_id"));
        }
        if let Some(project_id) = request.project_id {
            self.store.get_project(project_id, Some(request.owner_id))?;
            if let Some(claim_id) = request.target_claim_id {
                let claim = self.store.get_claim(claim_id, Some(request.owner_id))?;
                if text(&claim, "project_id")? != project_id {
                    return Err(invalid("target_claim_id must belong to project_id"));
                }
            }
        }
        let problem_id = safe_component(request.problem_id.unwrap_or("problem"));
        let runtime = self.store.runtime();
        let run_id = format!("run-{problem_id}-{}", runtime.ids.token_hex(6)?);
        let trace = match request.trace_id {
            Some(trace) => trace.to_owned(),
            None => runtime.ids.token_urlsafe(16)?,
        };
        let export_path = request
            .workspace_export_path
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("rethlas-output/{run_id}/proof_verified.tex"));
        let created_at = runtime.clock.now_iso()?;
        let vault_result = self.vault.initialize_run(
            &run_id,
            request.problem_tex,
            request.references,
            &serde_json::json!({
                "problem_id": problem_id,
                "owner_id": request.owner_id,
                "created_at": created_at,
            }),
        )?;

        let mut project_snapshot: Option<Value> = None;
        let mut base_revision_id: Option<String> = None;
        if let Some(project_id) = request.project_id {
            let snapshot = self
                .store
                .create_project_snapshot(project_id, request.owner_id)?;
            if let Some(claim_id) = request.target_claim_id {
                base_revision_id = self
                    .store
                    .current_claim_revision(claim_id, request.owner_id)?
                    .and_then(|value| {
                        value
                            .get("revision_id")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    });
            }
            project_snapshot = Some(snapshot);
        }

        let metadata = serde_json::json!({
            "native_mode_at_creation": request.native_mode,
            "problem_sha256": vault_result["problem_sha256"],
            "reference_count": vault_result["reference_count"],
            "manual_validation_required": true,
            "active_plans": [],
            "branch_requests": [],
            "latex_result": Value::Null,
            "workspace_export_path": export_path,
            "workflow_protocol_version": request.workflow_protocol_version,
            "requested_workflow_mode": request.workflow_mode,
            "effective_workflow_mode": if request.workflow_mode == "full" { "full" } else { "pending" },
            "compact_verifier_failures": 0,
            "project_id": request.project_id,
            "project_snapshot_id": project_snapshot.as_ref().and_then(|value| value.get("snapshot_id")),
            "target_claim_id": request.target_claim_id,
        });
        self.store
            .create_run(&run_id, &problem_id, request.owner_id, "created", &metadata)?;
        if let Some(snapshot) = &project_snapshot {
            self.store.link_run_to_project(
                &run_id,
                request.owner_id,
                request.project_id.unwrap_or_default(),
                text(snapshot, "snapshot_id")?,
                request.target_claim_id,
                base_revision_id.as_deref(),
                request.workflow_mode,
                if request.workflow_mode == "full" {
                    "full"
                } else {
                    "pending"
                },
                request.register_result,
            )?;
        }
        self.register_inline_references(&run_id, request.project_id, request.references)?;
        self.emit(WorkflowEvent {
            event_type: "workflow.run_created".to_owned(),
            trace_id: trace.clone(),
            run_id: Some(run_id.clone()),
            actor_role: None,
            domain_id: None,
            before_state: None,
            after_state: None,
            decision: "allow".to_owned(),
            reason: "valid_problem_input".to_owned(),
            details: serde_json::json!({
                "problem_id": problem_id,
                "problem_sha256": vault_result["problem_sha256"],
                "reference_count": vault_result["reference_count"],
                "native_mode_recorded_only": request.native_mode,
                "workflow_protocol_version": request.workflow_protocol_version,
                "workflow_mode": request.workflow_mode,
                "project_linked": project_snapshot.is_some(),
            }),
        });
        self.transition(TransitionInput {
            run_id: &run_id,
            before: WorkflowState::Created,
            after: WorkflowState::Assess,
            trace_id: &trace,
            actor: "system",
            reason: "run_initialized",
            evidence: &serde_json::json!({}),
            latex_passed: None,
            verdict: None,
            status: None,
            sealed: None,
            round_delta: 0,
        })?;
        Ok(serde_json::json!({
            "ok": true,
            "run_id": run_id,
            "state": "assess",
            "workspace_export_path": export_path,
            "workflow_protocol_version": request.workflow_protocol_version,
            "workflow_mode": request.workflow_mode,
            "project_id": request.project_id,
            "project_snapshot_id": project_snapshot.as_ref().and_then(|value| value.get("snapshot_id")),
            "target_claim_id": request.target_claim_id,
            "manual_validation_required": true,
            "trace_id": trace,
        }))
    }

    pub fn next_task(
        &self,
        owner_id: &str,
        run_id: &str,
        trace_id: Option<&str>,
    ) -> Result<Value, ReCtmError> {
        let runtime = self.store.runtime();
        let trace = match trace_id {
            Some(trace) => trace.to_owned(),
            None => runtime.ids.token_urlsafe(16)?,
        };
        let mut run = self.require_owner(run_id, owner_id)?;
        run = self.advance_mechanical(run, &trace)?;
        let state = workflow_state(text(&run, "state")?)?;
        if state.terminal() {
            return Ok(serde_json::json!({
                "ok": true,
                "run_id": run_id,
                "state": state_name(state),
                "terminal": true,
                "verdict": run.get("verdict"),
                "workspace_export_path": run.get("metadata").and_then(|m| m.get("workspace_export_path")),
                "trace_id": trace,
            }));
        }
        let role = role_for_state(state).ok_or_else(|| {
            ReCtmError::new(
                "NO_ACTIVE_ROLE",
                format!("No model role is active in state {}.", state_name(state)),
            )
            .with_category(ErrorCategory::Runtime)
        })?;
        let domain = self.ensure_domain(&run, role, &trace)?;
        let permissions = default_permissions(role)
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect::<Vec<_>>();
        let capability = self.capabilities.issue(
            run_id,
            text(&domain, "domain_id")?,
            role,
            &permissions,
            &trace,
            None,
        )?;
        let context = self.task_context(&run, state, role, &domain)?;
        let protocol = metadata_i64(&run, "workflow_protocol_version", 1);
        let effective_mode = metadata_text(&run, "effective_workflow_mode");
        let manifest = self.store.read_proof_manifest(run_id).ok();
        let task = self.methodology.task_for_run(
            state,
            protocol,
            effective_mode,
            manifest.as_ref().and_then(|value| value.get("manifest")),
        )?;
        self.emit(WorkflowEvent {
            event_type: "workflow.task_issued".to_owned(),
            trace_id: trace.clone(),
            run_id: Some(run_id.to_owned()),
            actor_role: Some(role_name(role).to_owned()),
            domain_id: Some(text(&domain, "domain_id")?.to_owned()),
            before_state: None,
            after_state: None,
            decision: "allow".to_owned(),
            reason: "active_role_task".to_owned(),
            details: serde_json::json!({"state": state_name(state)}),
        });
        Ok(serde_json::json!({
            "ok": true,
            "run_id": run_id,
            "state": state_name(state),
            "role": role_name(role),
            "domain_id": domain["domain_id"],
            "capability": capability,
            "task": task,
            "context": context,
            "trace_id": trace,
        }))
    }

    pub fn write(
        &self,
        owner_id: &str,
        capability: &str,
        resource: &str,
        content: &Value,
        trace_id: Option<&str>,
    ) -> Result<Value, ReCtmError> {
        let trace = self.trace(trace_id)?;
        let claims = self
            .capabilities
            .validate(capability, owner_id, "write", resource, &trace, None)?;
        let result = self.write_resource(&claims, resource, content)?;
        self.emit(WorkflowEvent {
            event_type: "workflow.resource_written".to_owned(),
            trace_id: trace.clone(),
            run_id: Some(claims.run_id().to_owned()),
            actor_role: Some(role_name(claims.role()).to_owned()),
            domain_id: Some(claims.domain_id().to_owned()),
            before_state: None,
            after_state: None,
            decision: "allow".to_owned(),
            reason: "resource_acl_passed".to_owned(),
            details: serde_json::json!({"resource":resource,"result":result}),
        });
        Ok(serde_json::json!({
            "ok":true,"run_id":claims.run_id(),"resource":resource,"result":result,"trace_id":trace
        }))
    }

    pub fn read(
        &self,
        owner_id: &str,
        capability: &str,
        resource: &str,
        trace_id: Option<&str>,
    ) -> Result<Value, ReCtmError> {
        let trace = self.trace(trace_id)?;
        let claims = self
            .capabilities
            .validate(capability, owner_id, "read", resource, &trace, None)?;
        let content = self.read_resource(&claims, resource)?;
        Ok(serde_json::json!({
            "ok":true,"run_id":claims.run_id(),"resource":resource,"content":content,"trace_id":trace
        }))
    }

    pub fn search(
        &self,
        owner_id: &str,
        capability: &str,
        resource: &str,
        query: &str,
        limit: usize,
        trace_id: Option<&str>,
    ) -> Result<Value, ReCtmError> {
        if query.trim().is_empty() {
            return Err(invalid("query is required"));
        }
        let trace = self.trace(trace_id)?;
        let claims = self
            .capabilities
            .validate(capability, owner_id, "search", resource, &trace, None)?;
        let records = if let Some(channel) = resource.strip_prefix("memory:generation:") {
            self.vault
                .read_generation_memory(claims.run_id(), channel)?
        } else if let Some(channel) = resource.strip_prefix("memory:branch:") {
            let branch_id = self.branch_id_for_domain(claims.domain_id())?;
            self.vault
                .read_branch_memory(claims.run_id(), &branch_id, channel)?
        } else {
            return Err(invalid_details(
                "resource is not searchable",
                serde_json::json!({"resource":resource}),
            ));
        };
        Ok(serde_json::json!({
            "ok":true,"run_id":claims.run_id(),"resource":resource,"query":query,
            "results":self.vault.search_records(&records, query, limit),"trace_id":trace
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn retrieve(
        &self,
        owner_id: &str,
        capability: &str,
        query: &str,
        operation: &str,
        author: &str,
        title: &str,
        keywords: &str,
        search_intent: &str,
        num_results: usize,
        trace_id: Option<&str>,
    ) -> Result<Value, ReCtmError> {
        if !matches!(
            operation,
            "theorem_search" | "paper_search" | "paper_lookup" | "theorem_context"
        ) {
            return Err(invalid_details(
                "unsupported retrieval operation",
                serde_json::json!({"operation": operation}),
            ));
        }
        let trace = self.trace(trace_id)?;
        let resource = if operation == "theorem_search" {
            "external:theorems"
        } else {
            "external:research"
        };
        let claims = self
            .capabilities
            .validate(capability, owner_id, "retrieve", resource, &trace, None)?;

        if operation == "theorem_context" {
            let reference_id = query.trim();
            let reference = self.store.get_reference(reference_id)?;
            if reference.get("run_id").and_then(Value::as_str) != Some(claims.run_id()) {
                return Err(ReCtmError::new(
                    "REFERENCE_RUN_MISMATCH",
                    "The requested theorem context is outside the active run.",
                )
                .with_category(ErrorCategory::Permission));
            }
            let metadata = reference
                .get("metadata")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            return Ok(serde_json::json!({
                "ok":true,
                "run_id":claims.run_id(),
                "operation":operation,
                "reference":reference,
                "content":metadata.get("retrieved_theorem").and_then(Value::as_str).unwrap_or_default(),
                "source_trust":reference.get("source_state").and_then(Value::as_str).unwrap_or("candidate"),
                "usage_rule":"This is stored discovery context, not proof that the source statement was checked in the original paper.",
                "trace_id":trace,
            }));
        }

        let request = ResearchRequest {
            operation: operation.to_owned(),
            query: query.to_owned(),
            author: author.to_owned(),
            title: title.to_owned(),
            keywords: keywords.to_owned(),
            search_intent: search_intent.to_owned(),
            num_results,
        };
        let mut result = self.research.retrieve(&request)?;
        let result_object = result.as_object_mut().ok_or_else(|| {
            ReCtmError::new(
                "RESEARCH_SERVICE_PROTOCOL_ERROR",
                "Research provider result must be a JSON object.",
            )
            .with_category(ErrorCategory::Runtime)
        })?;
        let raw_results = result_object
            .remove("results")
            .and_then(|value| value.as_array().cloned())
            .ok_or_else(|| {
                ReCtmError::new(
                    "RESEARCH_SERVICE_PROTOCOL_ERROR",
                    "Research provider result must contain a results array.",
                )
                .with_category(ErrorCategory::Runtime)
            })?;
        let project_run = self
            .store
            .get_project_run(claims.run_id(), Some(owner_id))?;
        let project_id = project_run
            .as_ref()
            .and_then(|value| value.get("project_id"))
            .and_then(Value::as_str);
        let endpoint = result_object
            .get("endpoint")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let result_query = result_object
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or(query)
            .to_owned();
        let mut registered = Vec::new();
        for item in raw_results {
            let Some(object) = item.as_object() else {
                continue;
            };
            let identity_material = ["paper_id", "arxiv_id", "theorem_id", "title", "theorem"]
                .iter()
                .map(|key| object.get(*key).and_then(Value::as_str).unwrap_or_default())
                .collect::<Vec<_>>()
                .join("|");
            let identity_key = format!("{operation}:{}", sha256_text(&identity_material));
            let metadata = serde_json::json!({
                "retrieved_theorem":object.get("theorem").and_then(Value::as_str).unwrap_or_default(),
                "authors":object.get("authors").cloned().unwrap_or_else(|| serde_json::json!([])),
                "publication_year":object.get("publication_year").cloned().unwrap_or(Value::Null),
                "open_access_url":object.get("open_access_url").and_then(Value::as_str).unwrap_or_default(),
            });
            let source_uri = object
                .get("source_uri")
                .or_else(|| object.get("landing_page_url"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let reference = self.store.register_reference(
                claims.run_id(),
                project_id,
                operation,
                &identity_key,
                object
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                object
                    .get("paper_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                object
                    .get("arxiv_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                object
                    .get("doi")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                object
                    .get("theorem_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                source_uri,
                "candidate",
                "",
                "",
                &metadata,
            )?;
            let snapshot_metadata = serde_json::Map::from_iter([
                ("operation".to_owned(), Value::String(operation.to_owned())),
                ("query".to_owned(), Value::String(result_query.clone())),
            ]);
            let snapshot = self.store.create_source_snapshot(
                text(&reference, "reference_id")?,
                operation,
                if source_uri.is_empty() {
                    &endpoint
                } else {
                    source_uri
                },
                &serde_json::to_string(&item).map_err(|error| {
                    ReCtmError::new("RESEARCH_JSON_ERROR", error.to_string())
                        .with_category(ErrorCategory::Internal)
                })?,
                "application/json",
                &snapshot_metadata,
            )?;
            let mut enriched = object.clone();
            enriched.insert("reference_id".to_owned(), reference["reference_id"].clone());
            enriched.insert(
                "source_snapshot_id".to_owned(),
                snapshot["source_snapshot_id"].clone(),
            );
            enriched.insert(
                "source_snapshot_sha256".to_owned(),
                snapshot["content_sha256"].clone(),
            );
            registered.push(Value::Object(enriched));
        }
        result_object.insert("results".to_owned(), Value::Array(registered.clone()));
        result_object.insert(
            "count".to_owned(),
            Value::from(u64::try_from(registered.len()).unwrap_or(u64::MAX)),
        );
        let source_trust = result_object
            .get("source_trust")
            .and_then(Value::as_str)
            .unwrap_or("external_unverified")
            .to_owned();
        let usage_rule = result_object
            .get("usage_rule")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let record = serde_json::json!({
            "event_type":format!("external_{operation}"),
            "query":result_query,
            "operation":operation,
            "search_intent":search_intent,
            "result_count":registered.len(),
            "results":registered,
            "source_trust":source_trust,
            "usage_rule":usage_rule,
            "created_at":self.store.runtime().clock.now_iso()?,
        });
        match claims.role() {
            WorkflowRole::Generator | WorkflowRole::Repair => {
                self.vault
                    .append_generation_memory(claims.run_id(), "events", &record)?;
            }
            WorkflowRole::Branch => {
                let branch_id = self.branch_id_for_domain(claims.domain_id())?;
                self.vault
                    .append_branch_memory(claims.run_id(), &branch_id, "events", &record)?;
            }
            WorkflowRole::Verifier => {
                self.vault
                    .append_verifier_memory(claims.run_id(), "events", &record)?;
            }
            _ => {
                return Err(ReCtmError::new(
                    "ROLE_ACCESS_DENIED",
                    "The active workflow role cannot perform external theorem retrieval.",
                )
                .with_category(ErrorCategory::Permission));
            }
        }
        self.emit(WorkflowEvent {
            event_type: "research.retrieval_completed".to_owned(),
            trace_id: trace.clone(),
            run_id: Some(claims.run_id().to_owned()),
            actor_role: Some(role_name(claims.role()).to_owned()),
            domain_id: Some(claims.domain_id().to_owned()),
            before_state: None,
            after_state: None,
            decision: "allow".to_owned(),
            reason: "research_capability_passed".to_owned(),
            details: serde_json::json!({
                "operation":operation,"search_intent":search_intent,
                "query_sha256":sha256_text(query),"result_count":result_object["count"]
            }),
        });
        let mut response = serde_json::Map::new();
        response.insert("ok".to_owned(), Value::Bool(true));
        response.insert(
            "run_id".to_owned(),
            Value::String(claims.run_id().to_owned()),
        );
        response.extend(result_object.clone());
        response.insert("trace_id".to_owned(), Value::String(trace));
        Ok(Value::Object(response))
    }

    pub fn commit(
        &self,
        owner_id: &str,
        capability: &str,
        action: &str,
        payload: &Value,
        trace_id: Option<&str>,
    ) -> Result<Value, ReCtmError> {
        let trace = self.trace(trace_id)?;
        let claims = self
            .capabilities
            .validate(capability, owner_id, "commit", "workflow", &trace, None)?;
        let run = self.store.get_run(claims.run_id())?;
        let result = self.commit_action(&run, &claims, action, payload, &trace)?;
        let mut output = result.as_object().cloned().unwrap_or_default();
        output.insert("ok".to_owned(), Value::Bool(true));
        output.insert("trace_id".to_owned(), Value::String(trace));
        Ok(Value::Object(output))
    }

    pub fn status(&self, owner_id: &str, run_id: &str) -> Result<Value, ReCtmError> {
        let run = self.require_owner(run_id, owner_id)?;
        let branches = self.store.list_branches(run_id)?;
        Ok(serde_json::json!({
            "ok":true,
            "run_id":run_id,
            "problem_id":run["problem_id"],
            "state":run["state"],
            "status":run["status"],
            "round_index":run["round_index"],
            "transition_seq":run["transition_seq"],
            "latex_passed":run["latex_passed"],
            "verdict":run["verdict"],
            "sealed":run["sealed"],
            "workspace_export_path":run.get("metadata").and_then(|m|m.get("workspace_export_path")),
            "branches":branches.iter().map(|branch| serde_json::json!({
                "branch_id":branch["branch_id"],"plan_id":branch["plan_id"],"status":branch["status"],"order_index":branch["order_index"]
            })).collect::<Vec<_>>(),
            "manual_validation_required":true
        }))
    }

    pub fn steer(
        &self,
        owner_id: &str,
        run_id: &str,
        message: &str,
        trace_id: Option<&str>,
    ) -> Result<Value, ReCtmError> {
        let run = self.require_owner(run_id, owner_id)?;
        if workflow_state(text(&run, "state")?)?.terminal() {
            return Err(
                ReCtmError::new("RUN_TERMINAL", "Cannot steer a terminal run.")
                    .with_category(ErrorCategory::Conflict),
            );
        }
        if message.trim().is_empty() {
            return Err(invalid("steering message is required"));
        }
        let trace = self.trace(trace_id)?;
        let steering_id = self.store.add_steering(run_id, owner_id, message.trim())?;
        Ok(
            serde_json::json!({"ok":true,"run_id":run_id,"steering_id":steering_id,"trace_id":trace}),
        )
    }

    pub fn cancel(
        &self,
        owner_id: &str,
        run_id: &str,
        reason: &str,
        trace_id: Option<&str>,
    ) -> Result<Value, ReCtmError> {
        let run = self.require_owner(run_id, owner_id)?;
        let state = workflow_state(text(&run, "state")?)?;
        if state.terminal() {
            return self.status(owner_id, run_id);
        }
        let trace = self.trace(trace_id)?;
        let result = self.transition(TransitionInput {
            run_id,
            before: state,
            after: WorkflowState::Cancelled,
            trace_id: &trace,
            actor: owner_id,
            reason,
            evidence: &serde_json::json!({}),
            latex_passed: None,
            verdict: None,
            status: Some("cancelled"),
            sealed: Some(true),
            round_delta: 0,
        })?;
        Ok(serde_json::json!({"ok":true,"run_id":run_id,"state":result["state"],"trace_id":trace}))
    }

    pub fn resume(&self, owner_id: &str, run_id: &str) -> Result<Value, ReCtmError> {
        let run = self.require_owner(run_id, owner_id)?;
        if workflow_state(text(&run, "state")?)?.terminal() {
            return Err(ReCtmError::new(
                "RUN_TERMINAL",
                "Terminal runs cannot be resumed automatically.",
            )
            .with_category(ErrorCategory::Conflict));
        }
        self.next_task(owner_id, run_id, None)
    }

    pub fn get_artifact(
        &self,
        owner_id: &str,
        run_id: &str,
        artifact: &str,
    ) -> Result<Value, ReCtmError> {
        let run = self.require_owner(run_id, owner_id)?;
        let state = workflow_state(text(&run, "state")?)?;
        let content = match artifact {
            "draft_tex" => Value::String(self.vault.read_proof(run_id)?),
            "proof_manifest" => self.store.read_proof_manifest(run_id)?,
            "reference_audit" => serde_json::json!({
                "references": self.store.list_run_references(run_id)?,
                "audits": self.store.list_reference_audits(run_id)?,
            }),
            "verification_report" => self.vault.read_verification_report(run_id)?,
            "final_tex" => {
                if state != WorkflowState::Done || run.get("sealed") != Some(&Value::Bool(true)) {
                    return Err(ReCtmError::new(
                        "ARTIFACT_NOT_FINAL",
                        "Final LaTeX is available only after mechanical finalization.",
                    )
                    .with_category(ErrorCategory::Permission));
                }
                Value::String(self.vault.read_final_proof(run_id)?)
            }
            "transition_log" => Value::Array(self.store.list_transitions(run_id)?),
            "debug_manifest" => {
                if !state.terminal() {
                    return Err(ReCtmError::new(
                        "DEBUG_BUNDLE_NOT_AVAILABLE",
                        "Debug manifests are exposed only for terminal runs.",
                    )
                    .with_category(ErrorCategory::Permission));
                }
                self.manual_validation_manifest(&run)
            }
            _ => {
                return Err(invalid_details(
                    "unknown artifact",
                    serde_json::json!({"artifact":artifact}),
                ));
            }
        };
        Ok(serde_json::json!({
            "ok":true,"run_id":run_id,"artifact":artifact,"content":content,
            "workspace_export_path":run.get("metadata").and_then(|m|m.get("workspace_export_path"))
        }))
    }

    fn trace(&self, trace_id: Option<&str>) -> Result<String, ReCtmError> {
        match trace_id {
            Some(trace) => Ok(trace.to_owned()),
            None => self.store.runtime().ids.token_urlsafe(16),
        }
    }

    fn emit(&self, event: WorkflowEvent) {
        if let Some(observer) = &self.observer {
            observer(event);
        }
    }

    fn require_owner(&self, run_id: &str, owner_id: &str) -> Result<Value, ReCtmError> {
        let run = self.store.get_run(run_id)?;
        if text(&run, "owner_id")? != owner_id {
            return Err(ReCtmError::new(
                "RUN_OWNER_MISMATCH",
                "OAuth identity does not own this run.",
            )
            .with_category(ErrorCategory::Permission));
        }
        Ok(run)
    }

    fn register_inline_references(
        &self,
        run_id: &str,
        project_id: Option<&str>,
        references: &[Value],
    ) -> Result<(), ReCtmError> {
        let manifest = self.vault.read_references_manifest(run_id)?;
        for (index, item) in manifest.iter().enumerate() {
            let original = references.get(index).and_then(Value::as_object);
            let name = item.get("name").and_then(Value::as_str).unwrap_or_default();
            let sha = item
                .get("sha256")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let title = original
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)
                .unwrap_or(name);
            let source = original
                .and_then(|value| value.get("source"))
                .and_then(Value::as_str)
                .unwrap_or("inline");
            let reference = self.store.register_reference(
                run_id,
                project_id,
                "inline",
                &format!("inline:{name}:{sha}"),
                title,
                "",
                "",
                "",
                "",
                source,
                "candidate",
                sha,
                sha,
                &serde_json::json!({"vault_name":name,"size":item.get("size")}),
            )?;
            let content = original
                .and_then(|value| value.get("content"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let snapshot_metadata =
                Map::from_iter([("vault_name".to_owned(), Value::String(name.to_owned()))]);
            self.store.create_source_snapshot(
                text(&reference, "reference_id")?,
                "inline",
                source,
                content,
                "text/plain",
                &snapshot_metadata,
            )?;
        }
        Ok(())
    }

    // Additional state-specific implementation follows below. It is intentionally
    // kept in the single WorkflowEngine authority so no helper can commit a second
    // transition or publish a second final artifact.
}

impl WorkflowEngine {
    fn update_metadata(&self, run_id: &str, updates: Value) -> Result<Value, ReCtmError> {
        let object = updates
            .as_object()
            .ok_or_else(|| internal("workflow metadata update must be an object"))?;
        self.store.update_run_metadata(run_id, object)
    }

    fn require_generation_records(&self, run_id: &str, channel: &str) -> Result<(), ReCtmError> {
        if self
            .vault
            .read_generation_memory(run_id, channel)?
            .is_empty()
        {
            return Err(ReCtmError::new(
                "WORKFLOW_PRECONDITION_FAILED",
                format!("Required generation memory channel is empty: {channel}"),
            )
            .with_category(ErrorCategory::Validation)
            .with_details(Map::from_iter([(
                "channel".to_owned(),
                Value::String(channel.to_owned()),
            )])));
        }
        Ok(())
    }

    fn require_verifier_records(&self, run_id: &str, channel: &str) -> Result<(), ReCtmError> {
        if self.vault.read_verifier_memory(run_id, channel)?.is_empty() {
            return Err(ReCtmError::new(
                "WORKFLOW_PRECONDITION_FAILED",
                format!("Required verifier memory channel is empty: {channel}"),
            )
            .with_category(ErrorCategory::Validation)
            .with_details(Map::from_iter([(
                "channel".to_owned(),
                Value::String(channel.to_owned()),
            )])));
        }
        Ok(())
    }

    fn branch_id_for_domain(&self, domain_id: &str) -> Result<String, ReCtmError> {
        let domain = self.store.get_domain(domain_id)?;
        domain
            .get("metadata")
            .and_then(Value::as_object)
            .and_then(|metadata| metadata.get("branch_id"))
            .and_then(Value::as_str)
            .filter(|branch_id| !branch_id.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| {
                ReCtmError::new("DOMAIN_BRANCH_MISSING", "Branch domain has no branch id.")
                    .with_category(ErrorCategory::Internal)
            })
    }

    fn manual_validation_manifest(&self, run: &Value) -> Value {
        serde_json::json!({
            "run_id":run.get("run_id"),
            "state":run.get("state"),
            "verdict":run.get("verdict"),
            "latex_passed":run.get("latex_passed").and_then(Value::as_bool).unwrap_or(false),
            "transition_count":run.get("transition_seq").and_then(Value::as_i64).unwrap_or_default(),
            "manual_checks_still_required":[
                "real webpage OAuth and MCP compatibility",
                "target-PC hard isolation under native dangerous mode",
                "real external theorem and web retrieval",
                "multi-turn mathematical quality and domain switching",
                "target LaTeX toolchain reproduction"
            ]
        })
    }

    fn seal_and_transition(
        &self,
        run: &Value,
        claims: &CapabilityClaims,
        after: WorkflowState,
        trace_id: &str,
        reason: &str,
        verdict: Option<&str>,
    ) -> Result<Value, ReCtmError> {
        self.store.seal_domain(claims.domain_id())?;
        let empty = serde_json::json!({});
        let updated = self.transition(TransitionInput {
            run_id: claims.run_id(),
            before: workflow_state(text(run, "state")?)?,
            after,
            trace_id,
            actor: role_name(claims.role()),
            reason,
            evidence: &empty,
            latex_passed: None,
            verdict,
            status: None,
            sealed: None,
            round_delta: 0,
        })?;
        Ok(serde_json::json!({
            "run_id":claims.run_id(),
            "state":updated["state"],
            "verdict":updated["verdict"]
        }))
    }

    fn advance_mechanical(&self, mut run: Value, trace_id: &str) -> Result<Value, ReCtmError> {
        loop {
            match workflow_state(text(&run, "state")?)? {
                WorkflowState::BranchPrepare => run = self.prepare_branch_round(&run, trace_id)?,
                WorkflowState::LatexValidate => run = self.run_latex_gate(&run, trace_id)?,
                WorkflowState::Finalize => run = self.finalize(&run, trace_id)?,
                WorkflowState::Done => {
                    run = self.retry_pending_registry_promotion(&run)?;
                    return Ok(run);
                }
                _ => return Ok(run),
            }
        }
    }

    fn ensure_domain(
        &self,
        run: &Value,
        role: WorkflowRole,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        let run_id = text(run, "run_id")?;
        let state = workflow_state(text(run, "state")?)?;
        if role == WorkflowRole::Branch {
            let branches = self.store.list_branches(run_id)?;
            if let Some(active) = branches
                .iter()
                .find(|branch| branch.get("status") == Some(&Value::String("running".to_owned())))
            {
                return self.store.get_domain(text(active, "domain_id")?);
            }
            let pending = branches
                .iter()
                .find(|branch| branch.get("status") == Some(&Value::String("pending".to_owned())))
                .ok_or_else(|| {
                    ReCtmError::new(
                        "BRANCH_BARRIER_INCONSISTENT",
                        "Branch-run state has no pending or running branch.",
                    )
                    .with_category(ErrorCategory::Internal)
                })?;
            let active =
                self.store
                    .update_branch_status(text(pending, "branch_id")?, "running", None)?;
            return self.store.get_domain(text(&active, "domain_id")?);
        }
        let existing = self
            .store
            .list_domains(run_id, Some(role_name(role)), Some("open"))?;
        if let Some(current) = existing.iter().rev().find(|domain| {
            domain
                .get("metadata")
                .and_then(Value::as_object)
                .and_then(|metadata| metadata.get("state"))
                .and_then(Value::as_str)
                == Some(state_name(state))
        }) {
            return Ok(current.clone());
        }
        let epoch = run.get("epoch").and_then(Value::as_i64).unwrap_or_default();
        let domain_id = format!(
            "{}-{}-{epoch}-{}",
            role_name(role),
            state_name(state),
            self.store.runtime().ids.token_hex(3)?
        );
        let domain = self.store.create_domain(
            &domain_id,
            run_id,
            role_name(role),
            None,
            None,
            &serde_json::json!({"state":state_name(state)}),
        )?;
        self.emit(WorkflowEvent {
            event_type: "domain.created".to_owned(),
            trace_id: trace_id.to_owned(),
            run_id: Some(run_id.to_owned()),
            actor_role: Some(role_name(role).to_owned()),
            domain_id: Some(domain_id),
            before_state: None,
            after_state: None,
            decision: "allow".to_owned(),
            reason: "active_state_requires_domain".to_owned(),
            details: serde_json::json!({"state":state_name(state)}),
        });
        Ok(domain)
    }

    fn task_context(
        &self,
        run: &Value,
        state: WorkflowState,
        role: WorkflowRole,
        domain: &Value,
    ) -> Result<Value, ReCtmError> {
        let protocol = metadata_i64(run, "workflow_protocol_version", 1);
        let mut resources = resources_for_role(role)
            .iter()
            .map(|resource| (*resource).to_owned())
            .collect::<Vec<_>>();
        if protocol >= 2 {
            if role == WorkflowRole::Verifier {
                for resource in &mut resources {
                    if resource == "references:approved" {
                        *resource = "references:candidates".to_owned();
                    }
                }
                for resource in ["proof_manifest", "project:verified_dependencies"] {
                    if !resources.iter().any(|item| item == resource) {
                        resources.push(resource.to_owned());
                    }
                }
            } else if matches!(
                role,
                WorkflowRole::Generator
                    | WorkflowRole::Branch
                    | WorkflowRole::Assembler
                    | WorkflowRole::Repair
            ) && !resources
                .iter()
                .any(|item| item == "project:verified_dependencies")
            {
                resources.push("project:verified_dependencies".to_owned());
            }
        }
        let mut context = Map::from_iter([
            ("problem_id".to_owned(), run["problem_id"].clone()),
            ("round_index".to_owned(), run["round_index"].clone()),
            (
                "available_logical_resources".to_owned(),
                serde_json::json!(resources),
            ),
            ("manual_validation_required".to_owned(), Value::Bool(true)),
        ]);
        if let Some(project_run) = self
            .store
            .get_project_run(text(run, "run_id")?, Some(text(run, "owner_id")?))?
        {
            let snapshot = self.store.get_project_snapshot(
                text(&project_run, "project_snapshot_id")?,
                text(run, "owner_id")?,
            )?;
            let mut verified = snapshot
                .get("revisions")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|revision| {
                    matches!(
                        revision.get("evidence_status").and_then(Value::as_str),
                        Some("VERIFIED" | "CONDITIONAL")
                    )
                })
                .collect::<Vec<_>>();
            if role == WorkflowRole::Verifier {
                let dependencies = self
                    .store
                    .read_proof_manifest(text(run, "run_id")?)
                    .ok()
                    .and_then(|record| record.get("manifest").cloned())
                    .and_then(|manifest| manifest.get("dependency_revision_ids").cloned())
                    .and_then(|ids| ids.as_array().cloned())
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|value| value.as_str().map(str::to_owned))
                    .collect::<BTreeSet<_>>();
                verified.retain(|revision| {
                    revision
                        .get("revision_id")
                        .and_then(Value::as_str)
                        .is_some_and(|id| dependencies.contains(id))
                });
                context.insert(
                    "project_context".to_owned(),
                    serde_json::json!({
                        "project_snapshot_id":snapshot["snapshot_id"],
                        "project_snapshot_sha256":snapshot["snapshot_sha256"],
                        "verified_dependencies":verified,
                    }),
                );
            } else {
                context.insert(
                    "project_context".to_owned(),
                    serde_json::json!({
                        "project_id":project_run["project_id"],
                        "project_snapshot_id":snapshot["snapshot_id"],
                        "project_snapshot_sha256":snapshot["snapshot_sha256"],
                        "target_claim_id":project_run.get("target_claim_id"),
                        "base_revision_id":project_run.get("base_revision_id"),
                        "effective_workflow_mode":project_run.get("effective_workflow_mode"),
                        "verified_revisions":verified,
                    }),
                );
            }
        }
        if state == WorkflowState::DirectProving {
            let public_plans = public_active_plans(
                run.get("metadata")
                    .and_then(Value::as_object)
                    .and_then(|metadata| metadata.get("active_plans")),
            );
            context.insert("active_plans".to_owned(), public_plans.clone());
            context.insert(
                "screening_progress".to_owned(),
                run.get("metadata")
                    .and_then(Value::as_object)
                    .and_then(|metadata| metadata.get("direct_screening_progress"))
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({})),
            );
            let preferred_shape = public_plans
                .as_array()
                .and_then(|plans| plans.first())
                .and_then(Value::as_object)
                .and_then(|plan| {
                    let plan_id = plan.get("plan_id")?.as_str()?;
                    let first = plan.get("subgoals")?.as_array()?.first()?.as_object()?;
                    let subgoal_id = first.get("subgoal_id")?.as_str()?;
                    Some(serde_json::json!({
                        plan_id:{subgoal_id:{"status":"solved|partial|stuck","summary":"..."}}
                    }))
                })
                .unwrap_or_else(|| serde_json::json!({}));
            context.insert(
                "screening_contract".to_owned(),
                serde_json::json!({
                    "preferred_shape":preferred_shape,
                    "server_derives":[
                        "plan status",
                        "overall solved-vs-branch outcome",
                        "branch set when no plan is solved",
                        "stuck-point summary"
                    ],
                    "incomplete_submission":"Accepted without transition; response lists missing plan/subgoal ids."
                }),
            );
        }
        match role {
            WorkflowRole::Branch => {
                let branch_id = domain
                    .get("metadata")
                    .and_then(Value::as_object)
                    .and_then(|metadata| metadata.get("branch_id"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let branch = self.store.get_branch(branch_id)?;
                context.insert("branch_id".to_owned(), Value::String(branch_id.to_owned()));
                context.insert("plan_id".to_owned(), branch["plan_id"].clone());
                context.insert("snapshot_id".to_owned(), branch["snapshot_id"].clone());
                context.insert(
                    "information_barrier".to_owned(),
                    Value::String("Other branch results are unavailable until join.".to_owned()),
                );
            }
            WorkflowRole::Join => {
                context.insert(
                    "sealed_branch_ids".to_owned(),
                    serde_json::json!(
                        self.store
                            .list_branches(text(run, "run_id")?)?
                            .iter()
                            .filter_map(|branch| branch.get("branch_id").and_then(Value::as_str))
                            .collect::<Vec<_>>()
                    ),
                );
            }
            WorkflowRole::Verifier => {
                context.insert(
                    "data_firewall".to_owned(),
                    serde_json::json!([
                        "No generation memory",
                        "No branch internals",
                        "No steering history",
                        "No generator confidence"
                    ]),
                );
            }
            WorkflowRole::Repair => {
                if let Some(latex) = run
                    .get("metadata")
                    .and_then(Value::as_object)
                    .and_then(|metadata| metadata.get("latex_result"))
                    .filter(|value| value.is_object())
                {
                    context.insert("latex_result".to_owned(), latex.clone());
                    context.insert(
                        "repair_source".to_owned(),
                        Value::String(
                            if latex.get("gate_passed") == Some(&Value::Bool(false)) {
                                "latex_gate"
                            } else {
                                "verification_report"
                            }
                            .to_owned(),
                        ),
                    );
                }
            }
            _ => {}
        }
        Ok(Value::Object(context))
    }

    fn transition(&self, input: TransitionInput<'_>) -> Result<Value, ReCtmError> {
        let decision = TransitionDecision::validate(TransitionRequest {
            run_id: input.run_id.to_owned(),
            before: input.before,
            after: input.after,
            actor: input.actor.to_owned(),
            reason: input.reason.to_owned(),
            trace_id: input.trace_id.to_owned(),
        })?;
        let request = decision.request();
        let result = self.store.transition_run(TransitionRun {
            run_id: &request.run_id,
            expected_state: state_name(request.before),
            after_state: state_name(request.after),
            trace_id: &request.trace_id,
            actor: &request.actor,
            reason: &request.reason,
            evidence: input.evidence,
            increment_epoch: true,
            status: input.status,
            latex_passed: input.latex_passed,
            verdict: input.verdict,
            sealed: input.sealed,
            round_delta: input.round_delta,
        })?;
        self.emit(WorkflowEvent {
            event_type: "workflow.transition".to_owned(),
            trace_id: input.trace_id.to_owned(),
            run_id: Some(input.run_id.to_owned()),
            actor_role: Some(input.actor.to_owned()),
            domain_id: None,
            before_state: Some(state_name(input.before).to_owned()),
            after_state: Some(state_name(input.after).to_owned()),
            decision: "allow".to_owned(),
            reason: input.reason.to_owned(),
            details: serde_json::json!({"evidence":input.evidence,"epoch":result["epoch"]}),
        });
        Ok(result)
    }
}

impl WorkflowEngine {
    fn read_resource(
        &self,
        claims: &CapabilityClaims,
        resource: &str,
    ) -> Result<Value, ReCtmError> {
        match resource {
            "problem" => Ok(Value::String(self.vault.read_problem(claims.run_id())?)),
            "references" => {
                let manifest = self.vault.read_references_manifest(claims.run_id())?;
                let mut references = Vec::with_capacity(manifest.len());
                for item in &manifest {
                    let name = item.get("name").and_then(Value::as_str).unwrap_or_default();
                    references.push(serde_json::json!({
                        "name":name,
                        "content":self.vault.read_reference(claims.run_id(), name)?
                    }));
                }
                Ok(serde_json::json!({"manifest":manifest,"references":references}))
            }
            "references:candidates" | "references:approved" => {
                let protocol = metadata_i64(
                    &self.store.get_run(claims.run_id())?,
                    "workflow_protocol_version",
                    1,
                );
                if resource == "references:approved" && protocol < 2 {
                    return self.read_resource(claims, "references");
                }
                let audits = self
                    .store
                    .list_reference_audits(claims.run_id())?
                    .into_iter()
                    .filter_map(|audit| {
                        let reference_id = audit
                            .get("reference_id")
                            .and_then(Value::as_str)
                            .map(str::to_owned)?;
                        Some((reference_id, audit))
                    })
                    .collect::<BTreeMap<_, _>>();
                let mut enriched = Vec::new();
                for reference in self.store.list_run_references(claims.run_id())? {
                    let reference_id = text(&reference, "reference_id")?;
                    if resource == "references:approved"
                        && !audits.get(reference_id).is_some_and(|audit| {
                            matches!(
                                audit.get("disposition").and_then(Value::as_str),
                                Some(
                                    "SOURCE_VERIFIED" | "INDEPENDENTLY_REDERIVED" | "NOT_MATERIAL"
                                )
                            )
                        })
                    {
                        continue;
                    }
                    let metadata = reference.get("metadata").and_then(Value::as_object);
                    let content = if let Some(vault_name) = metadata
                        .and_then(|value| value.get("vault_name"))
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                    {
                        self.vault.read_reference(claims.run_id(), vault_name)?
                    } else {
                        metadata
                            .and_then(|value| value.get("retrieved_theorem"))
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned()
                    };
                    let snapshots = self
                        .store
                        .list_source_snapshots(reference_id)?
                        .into_iter()
                        .map(|snapshot| {
                            let content = snapshot
                                .get("metadata")
                                .and_then(Value::as_object)
                                .and_then(|metadata| metadata.get("content"))
                                .and_then(Value::as_str)
                                .unwrap_or_default();
                            serde_json::json!({
                                "source_snapshot_id":snapshot["source_snapshot_id"],
                                "provider":snapshot["provider"],
                                "source_uri":snapshot["source_uri"],
                                "content_sha256":snapshot["content_sha256"],
                                "content_type":snapshot["content_type"],
                                "content":content
                            })
                        })
                        .collect::<Vec<_>>();
                    let mut object = reference
                        .as_object()
                        .cloned()
                        .ok_or_else(|| internal("reference row is invalid"))?;
                    object.insert("content".to_owned(), Value::String(content));
                    object.insert("source_snapshots".to_owned(), Value::Array(snapshots));
                    object.insert(
                        "audit".to_owned(),
                        audits.get(reference_id).cloned().unwrap_or(Value::Null),
                    );
                    enriched.push(Value::Object(object));
                }
                Ok(serde_json::json!({"references":enriched}))
            }
            "steering" => Ok(Value::Array(Vec::new())),
            "snapshot" => {
                let domain = self.store.get_domain(claims.domain_id())?;
                let snapshot_id = domain
                    .get("snapshot_id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .or_else(|| {
                        domain
                            .get("metadata")
                            .and_then(Value::as_object)
                            .and_then(|metadata| metadata.get("snapshot_id"))
                            .and_then(Value::as_str)
                    })
                    .unwrap_or_default();
                self.vault.read_snapshot(claims.run_id(), snapshot_id)
            }
            "branch:self" => {
                let branch_id = self.branch_id_for_domain(claims.domain_id())?;
                let branch = self.store.get_branch(&branch_id)?;
                Ok(serde_json::json!({
                    "assignment":self.vault.read_branch_assignment(claims.run_id(), &branch_id)?,
                    "status":branch["status"]
                }))
            }
            "join_result" => self.vault.read_join_result(claims.run_id()),
            "proof" => Ok(Value::String(self.vault.read_proof(claims.run_id())?)),
            "proof_manifest" => self.store.read_proof_manifest(claims.run_id()),
            "project:verified_dependencies" => self.project_verified_dependencies(claims),
            "verification_report" => self.vault.read_verification_report(claims.run_id()),
            _ if resource.starts_with("branch:sealed:") => {
                let branches = self.store.list_branches(claims.run_id())?;
                if branches.is_empty()
                    || branches.iter().any(|branch| {
                        branch.get("status") != Some(&Value::String("sealed".to_owned()))
                    })
                {
                    return Err(ReCtmError::new(
                        "BRANCH_BARRIER_NOT_COMPLETE",
                        "All branches must be sealed before join reads.",
                    )
                    .with_category(ErrorCategory::Permission));
                }
                let mut results = Map::new();
                for branch in branches {
                    let branch_id = text(&branch, "branch_id")?;
                    results.insert(
                        branch_id.to_owned(),
                        self.vault.read_branch_result(claims.run_id(), branch_id)?,
                    );
                }
                Ok(Value::Object(results))
            }
            _ if resource.starts_with("memory:generation:") => {
                Ok(Value::Array(self.vault.read_generation_memory(
                    claims.run_id(),
                    resource.rsplit(':').next().unwrap_or_default(),
                )?))
            }
            _ if resource.starts_with("memory:verifier:") => {
                Ok(Value::Array(self.vault.read_verifier_memory(
                    claims.run_id(),
                    resource.rsplit(':').next().unwrap_or_default(),
                )?))
            }
            _ if resource.starts_with("memory:branch:") => {
                let branch_id = self.branch_id_for_domain(claims.domain_id())?;
                Ok(Value::Array(self.vault.read_branch_memory(
                    claims.run_id(),
                    &branch_id,
                    resource.rsplit(':').next().unwrap_or_default(),
                )?))
            }
            _ => Err(invalid_details(
                "unknown logical resource",
                serde_json::json!({"resource":resource}),
            )),
        }
    }

    fn write_resource(
        &self,
        claims: &CapabilityClaims,
        resource: &str,
        content: &Value,
    ) -> Result<Value, ReCtmError> {
        if let Some(channel) = resource.strip_prefix("memory:generation:") {
            if !GENERATION_CHANNELS.contains(&channel) || !content.is_object() {
                return Err(invalid(
                    "generation memory writes require a known channel and JSON object",
                ));
            }
            let path = self
                .vault
                .append_generation_memory(claims.run_id(), channel, content)?;
            return Ok(
                serde_json::json!({"path_kind":"generation_memory","channel":channel,"file":file_name(&path)}),
            );
        }
        if let Some(channel) = resource.strip_prefix("memory:verifier:") {
            if !VERIFIER_CHANNELS.contains(&channel) || !content.is_object() {
                return Err(invalid(
                    "verifier memory writes require a known channel and JSON object",
                ));
            }
            let path = self
                .vault
                .append_verifier_memory(claims.run_id(), channel, content)?;
            return Ok(
                serde_json::json!({"path_kind":"verifier_memory","channel":channel,"file":file_name(&path)}),
            );
        }
        if let Some(channel) = resource.strip_prefix("memory:branch:") {
            if !BRANCH_CHANNELS.contains(&channel) || !content.is_object() {
                return Err(invalid(
                    "branch memory writes require a known channel and JSON object",
                ));
            }
            let branch_id = self.branch_id_for_domain(claims.domain_id())?;
            let path =
                self.vault
                    .append_branch_memory(claims.run_id(), &branch_id, channel, content)?;
            return Ok(
                serde_json::json!({"path_kind":"branch_memory","branch_id":branch_id,"channel":channel,"file":file_name(&path)}),
            );
        }
        match resource {
            "join_result" => {
                if !content.is_object() {
                    return Err(invalid("join_result must be a JSON object"));
                }
                let path = self.vault.write_join_result(claims.run_id(), content)?;
                Ok(serde_json::json!({"path_kind":"join_result","file":file_name(&path)}))
            }
            "proof" => {
                let proof = content
                    .as_str()
                    .ok_or_else(|| invalid("proof must be a LaTeX string"))?;
                let path = self.vault.write_proof(claims.run_id(), proof)?;
                Ok(
                    serde_json::json!({"path_kind":"draft_tex","file":file_name(&path),"size":proof.len()}),
                )
            }
            "proof_manifest" => {
                let manifest = self.normalize_proof_manifest(claims, content)?;
                let stored = self
                    .store
                    .write_proof_manifest(claims.run_id(), &manifest)?;
                Ok(serde_json::json!({"path_kind":"proof_manifest","sha256":stored["sha256"]}))
            }
            "verification_report" => {
                let decision = VerificationDecision::from_submitted_report(content)?;
                let normalized = decision.normalized_payload();
                let path = self
                    .vault
                    .write_verification_report(claims.run_id(), &normalized)?;
                Ok(serde_json::json!({"path_kind":"verification_report","file":file_name(&path)}))
            }
            "reference_audit" => self.write_reference_audit(claims, content),
            "branch:self" => Err(ReCtmError::new(
                "BRANCH_RESULT_REQUIRES_COMMIT",
                "Branch results are written and sealed atomically by branch_complete.",
            )
            .with_category(ErrorCategory::Validation)),
            _ => Err(invalid_details(
                "unknown or non-writable logical resource",
                serde_json::json!({"resource":resource}),
            )),
        }
    }

    fn normalize_proof_manifest(
        &self,
        claims: &CapabilityClaims,
        content: &Value,
    ) -> Result<Value, ReCtmError> {
        let object = content
            .as_object()
            .ok_or_else(|| invalid("proof_manifest must be a JSON object"))?;
        let statement = object
            .get("target_statement_tex")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                invalid("proof_manifest.target_statement_tex must be a non-empty string")
            })?;
        let dependencies = string_array(
            object.get("dependency_revision_ids"),
            "proof_manifest dependency_revision_ids",
            false,
        )?;
        let references = string_array(
            object.get("reference_ids"),
            "proof_manifest reference_ids",
            false,
        )?;
        let conditions = string_array(
            object.get("conditional_hypotheses"),
            "proof_manifest conditional_hypotheses",
            false,
        )?;
        let computational = object
            .get("computational_evidence")
            .and_then(Value::as_array)
            .filter(|items| items.iter().all(Value::is_object))
            .cloned()
            .ok_or_else(|| {
                invalid("proof_manifest computational_evidence must be an array of JSON objects")
            })?;
        let project_run = self
            .store
            .get_project_run(claims.run_id(), Some(claims.owner_id()))?;
        let mut snapshot_ids = BTreeSet::new();
        if let Some(project_run) = &project_run {
            let snapshot = self.store.get_project_snapshot(
                text(project_run, "project_snapshot_id")?,
                claims.owner_id(),
            )?;
            for revision in snapshot
                .get("revisions")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
            {
                if matches!(
                    revision.get("evidence_status").and_then(Value::as_str),
                    Some("VERIFIED" | "CONDITIONAL")
                ) && let Some(id) = revision.get("revision_id").and_then(Value::as_str)
                {
                    snapshot_ids.insert(id.to_owned());
                }
            }
        }
        if !dependencies.is_empty() && project_run.is_none() {
            return Err(invalid(
                "Standalone runs cannot declare project dependency revisions",
            ));
        }
        let invalid_dependencies = dependencies
            .iter()
            .filter(|id| !snapshot_ids.contains(*id))
            .cloned()
            .collect::<Vec<_>>();
        if !invalid_dependencies.is_empty() {
            return Err(invalid_details(
                "proof_manifest dependencies must come from the frozen verified project snapshot",
                serde_json::json!({"invalid_revision_ids":invalid_dependencies}),
            ));
        }
        let known = self
            .store
            .list_run_references(claims.run_id())?
            .into_iter()
            .filter_map(|reference| {
                reference
                    .get("reference_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect::<BTreeSet<_>>();
        let invalid_references = references
            .iter()
            .filter(|id| !known.contains(*id))
            .cloned()
            .collect::<Vec<_>>();
        if !invalid_references.is_empty() {
            return Err(invalid_details(
                "proof_manifest reference_ids must identify references registered for this run",
                serde_json::json!({"invalid_reference_ids":invalid_references}),
            ));
        }
        Ok(serde_json::json!({
            "target_statement_tex":statement,
            "dependency_revision_ids":dependencies,
            "reference_ids":references,
            "conditional_hypotheses":conditions,
            "computational_evidence":computational,
            "project_snapshot_id":project_run.as_ref().and_then(|value|value.get("project_snapshot_id")),
            "workflow_protocol_version":metadata_i64(&self.store.get_run(claims.run_id())?, "workflow_protocol_version", 1)
        }))
    }

    fn write_reference_audit(
        &self,
        claims: &CapabilityClaims,
        content: &Value,
    ) -> Result<Value, ReCtmError> {
        if claims.role() != WorkflowRole::Verifier {
            return Err(invalid(
                "reference_audit writes require a verifier JSON object",
            ));
        }
        let object = content
            .as_object()
            .ok_or_else(|| invalid("reference_audit writes require a verifier JSON object"))?;
        let reference_id = required_trimmed(object, "reference_id")?;
        let disposition = required_trimmed(object, "disposition")?;
        let evidence_basis = required_trimmed(object, "evidence_basis")?;
        let evidence_locator = object
            .get("evidence_locator")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned();
        if !matches!(
            evidence_basis.as_str(),
            "stored_source_snapshot"
                | "external_source_inspection"
                | "independent_derivation"
                | "not_material"
                | "unresolved"
        ) {
            return Err(invalid("reference_audit.evidence_basis is unsupported"));
        }
        for field in [
            "material",
            "assumptions_checked",
            "notation_checked",
            "source_checked",
            "independently_rederived",
        ] {
            if object.contains_key(field) && !object[field].is_boolean() {
                return Err(invalid(&format!("reference_audit.{field} must be boolean")));
            }
        }
        let material = object
            .get("material")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let assumptions = object
            .get("assumptions_checked")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let notation = object
            .get("notation_checked")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let source = object
            .get("source_checked")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let rederived = object
            .get("independently_rederived")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let notes = object
            .get("notes")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match disposition.as_str() {
            "SOURCE_VERIFIED" => {
                if !(source && assumptions && notation) {
                    return Err(invalid(
                        "SOURCE_VERIFIED requires source_checked, assumptions_checked, and notation_checked to be true",
                    ));
                }
                if !matches!(
                    evidence_basis.as_str(),
                    "stored_source_snapshot" | "external_source_inspection"
                ) || evidence_locator.is_empty()
                {
                    return Err(invalid(
                        "SOURCE_VERIFIED requires checked source evidence and a non-empty evidence_locator",
                    ));
                }
                if evidence_basis == "stored_source_snapshot" {
                    let snapshots = self.store.list_source_snapshots(&reference_id)?;
                    let snapshot = snapshots
                        .iter()
                        .find(|snapshot| {
                            snapshot.get("source_snapshot_id").and_then(Value::as_str)
                                == Some(evidence_locator.as_str())
                        })
                        .ok_or_else(|| invalid("Stored source evidence_locator must identify a source snapshot for the audited reference"))?;
                    if snapshot.get("provider").and_then(Value::as_str) != Some("inline") {
                        return Err(invalid(
                            "Stored theorem/paper discovery snapshots are unverified metadata, not original-source evidence; use external_source_inspection after checking the actual source",
                        ));
                    }
                }
            }
            "INDEPENDENTLY_REDERIVED" => {
                if !rederived
                    || evidence_basis != "independent_derivation"
                    || evidence_locator.is_empty()
                {
                    return Err(invalid(
                        "INDEPENDENTLY_REDERIVED requires independent_derivation evidence and a non-empty locator",
                    ));
                }
            }
            "NOT_MATERIAL" => {
                if material || evidence_basis != "not_material" {
                    return Err(invalid(
                        "NOT_MATERIAL requires material=false and evidence_basis=not_material",
                    ));
                }
            }
            "UNRESOLVED" => {
                if evidence_basis != "unresolved" {
                    return Err(invalid("UNRESOLVED requires evidence_basis=unresolved"));
                }
            }
            _ => return Err(invalid("reference_audit disposition is unsupported")),
        }
        let proof_hash = sha256_text(&self.vault.read_proof(claims.run_id())?);
        let manifest_hash = self.store.read_proof_manifest(claims.run_id())?["sha256"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let audit = self.store.write_reference_audit(
            claims.run_id(),
            &reference_id,
            &disposition,
            &evidence_basis,
            &evidence_locator,
            claims.domain_id(),
            &proof_hash,
            &manifest_hash,
            material,
            assumptions,
            notation,
            source,
            rederived,
            notes,
        )?;
        Ok(
            serde_json::json!({"path_kind":"reference_audit","reference_id":reference_id,"disposition":audit["disposition"]}),
        )
    }

    fn project_verified_dependencies(
        &self,
        claims: &CapabilityClaims,
    ) -> Result<Value, ReCtmError> {
        let Some(project_run) = self
            .store
            .get_project_run(claims.run_id(), Some(claims.owner_id()))?
        else {
            return Ok(
                serde_json::json!({"project_id":Value::Null,"snapshot_id":Value::Null,"revisions":[]}),
            );
        };
        let snapshot = self.store.get_project_snapshot(
            text(&project_run, "project_snapshot_id")?,
            claims.owner_id(),
        )?;
        let mut revisions = snapshot
            .get("revisions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|revision| {
                matches!(
                    revision.get("evidence_status").and_then(Value::as_str),
                    Some("VERIFIED" | "CONDITIONAL")
                )
            })
            .collect::<Vec<_>>();
        if claims.role() == WorkflowRole::Verifier {
            let dependencies = self.store.read_proof_manifest(claims.run_id())?["manifest"]
                ["dependency_revision_ids"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect::<BTreeSet<_>>();
            revisions.retain(|revision| {
                revision
                    .get("revision_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| dependencies.contains(id))
            });
        }
        Ok(serde_json::json!({
            "project_id":project_run["project_id"],
            "snapshot_id":snapshot["snapshot_id"],
            "snapshot_sha256":snapshot["snapshot_sha256"],
            "revisions":revisions
        }))
    }
}

impl WorkflowEngine {
    fn commit_action(
        &self,
        run: &Value,
        claims: &CapabilityClaims,
        action: &str,
        payload: &Value,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        let state = workflow_state(text(run, "state")?)?;
        let manifest_record = self.store.read_proof_manifest(claims.run_id()).ok();
        let expected_action = self
            .methodology
            .task_for_run(
                state,
                metadata_i64(run, "workflow_protocol_version", 1),
                metadata_text(run, "effective_workflow_mode"),
                manifest_record
                    .as_ref()
                    .and_then(|value| value.get("manifest")),
            )?
            .get("commit_action")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if action != expected_action {
            return Err(ReCtmError::new(
                "INVALID_COMMIT_ACTION",
                "Commit action does not match the active workflow task.",
            )
            .with_category(ErrorCategory::Validation)
            .with_details(
                serde_json::json!({
                    "expected":expected_action,
                    "received":action,
                    "state":state_name(state)
                })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            ));
        }
        match action {
            "assessment_complete" => {
                let after = self.commit_assessment_complete(run, claims, payload)?;
                self.seal_and_transition(run, claims, after, trace_id, action, None)
            }
            "exploration_complete" => {
                self.require_generation_records(claims.run_id(), "events")?;
                self.seal_and_transition(
                    run,
                    claims,
                    WorkflowState::ProposePlans,
                    trace_id,
                    action,
                    None,
                )
            }
            "plans_proposed" => {
                let after = self.commit_plans_proposed(run, claims, payload)?;
                self.seal_and_transition(run, claims, after, trace_id, action, None)
            }
            "direct_proving_complete" => self.commit_direct_proving(run, claims, payload, trace_id),
            "branch_complete" => self.commit_branch(run, claims, payload, trace_id),
            "join_complete" => {
                let after = self.commit_join(claims, payload)?;
                self.seal_and_transition(run, claims, after, trace_id, action, None)
            }
            "failures_identified" => {
                let summary = payload
                    .get("summary")
                    .filter(|value| value.is_object())
                    .ok_or_else(|| invalid("failures_identified requires summary object"))?;
                let mut record = summary.as_object().cloned().unwrap_or_default();
                record.insert(
                    "record_type".to_owned(),
                    Value::String("key_failures_summary".to_owned()),
                );
                self.vault.append_generation_memory(
                    claims.run_id(),
                    "failed_paths",
                    &Value::Object(record),
                )?;
                self.seal_and_transition(run, claims, WorkflowState::Replan, trace_id, action, None)
            }
            "replan_complete" => {
                let decision = payload
                    .get("decision")
                    .filter(|value| value.is_object())
                    .ok_or_else(|| invalid("replan_complete requires decision object"))?;
                self.vault
                    .append_generation_memory(claims.run_id(), "big_decisions", decision)?;
                self.seal_and_transition(
                    run,
                    claims,
                    WorkflowState::ProposePlans,
                    trace_id,
                    action,
                    None,
                )
            }
            "proof_submitted" => self.commit_proof_submitted(run, claims, payload, trace_id),
            "verification_submitted" => self.commit_verification_submitted(run, claims, trace_id),
            "repair_submitted" => {
                self.commit_repair_submitted(run, claims)?;
                self.seal_and_transition(
                    run,
                    claims,
                    WorkflowState::LatexValidate,
                    trace_id,
                    action,
                    None,
                )
            }
            _ => Err(invalid_details(
                "unsupported commit action",
                serde_json::json!({"action":action}),
            )),
        }
    }

    fn commit_assessment_complete(
        &self,
        run: &Value,
        claims: &CapabilityClaims,
        payload: &Value,
    ) -> Result<WorkflowState, ReCtmError> {
        self.require_generation_records(claims.run_id(), "immediate_conclusions")?;
        if metadata_i64(run, "workflow_protocol_version", 1) < 2 {
            return Ok(WorkflowState::Explore);
        }
        let requested = metadata_text(run, "requested_workflow_mode");
        let route = payload
            .get("route")
            .and_then(Value::as_str)
            .unwrap_or("full");
        let needs_retrieval = payload
            .get("requires_external_retrieval")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let needs_plans = payload
            .get("requires_multiple_plans")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let has_references = !self.store.list_run_references(claims.run_id())?.is_empty();
        let compact_allowed = !needs_retrieval && !needs_plans && !has_references;
        let effective_mode = match requested {
            "full" => "full",
            "compact" if compact_allowed => "compact",
            "compact" => "full",
            _ if route == "compact" && compact_allowed => "compact",
            _ => "full",
        };
        self.update_metadata(
            claims.run_id(),
            serde_json::json!({
                "effective_workflow_mode":effective_mode,
                "workflow_route_reason":payload.get("route_reason").and_then(Value::as_str).unwrap_or_default(),
                "compact_route_allowed":compact_allowed
            }),
        )?;
        if self
            .store
            .get_project_run(claims.run_id(), Some(claims.owner_id()))?
            .is_some()
        {
            self.store
                .set_project_run_mode(claims.run_id(), effective_mode)?;
        }
        Ok(if effective_mode == "compact" {
            WorkflowState::Assemble
        } else {
            WorkflowState::Explore
        })
    }

    fn commit_plans_proposed(
        &self,
        run: &Value,
        claims: &CapabilityClaims,
        payload: &Value,
    ) -> Result<WorkflowState, ReCtmError> {
        let plans = validate_plans(
            payload.get("plans"),
            run.get("round_index")
                .and_then(Value::as_i64)
                .unwrap_or_default()
                + 1,
        )?;
        for plan in &plans {
            let mut record = plan.as_object().cloned().unwrap_or_default();
            record.insert(
                "record_type".to_owned(),
                Value::String("decomposition_plan".to_owned()),
            );
            record.insert("status".to_owned(), Value::String("proposed".to_owned()));
            self.vault.append_generation_memory(
                claims.run_id(),
                "subgoals",
                &Value::Object(record),
            )?;
        }
        self.update_metadata(
            claims.run_id(),
            serde_json::json!({"active_plans":plans,"direct_screening_progress":{}}),
        )?;
        Ok(WorkflowState::DirectProving)
    }

    fn commit_direct_proving(
        &self,
        run: &Value,
        claims: &CapabilityClaims,
        payload: &Value,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        self.require_generation_records(claims.run_id(), "proof_steps")?;
        let active_plans = run
            .get("metadata")
            .and_then(Value::as_object)
            .and_then(|metadata| metadata.get("active_plans"))
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));
        let previous = run
            .get("metadata")
            .and_then(Value::as_object)
            .and_then(|metadata| metadata.get("direct_screening_progress"));
        let (screening, progress, missing) =
            merge_direct_screening(payload.get("screening"), &active_plans, previous)?;
        self.update_metadata(
            claims.run_id(),
            serde_json::json!({"direct_screening_progress":progress}),
        )?;
        if !missing.is_empty() {
            return Ok(serde_json::json!({
                "run_id":claims.run_id(),"state":"direct_proving","complete":false,
                "screening_complete":false,"missing_screening":missing,
                "accepted_progress":screening,"verdict":run.get("verdict")
            }));
        }
        self.vault.append_generation_memory(
            claims.run_id(),
            "proof_steps",
            &serde_json::json!({
                "record_type":"direct_screening_round",
                "plans":screening,
                "created_at":self.store.runtime().clock.now_iso()?
            }),
        )?;
        let solved = screening
            .iter()
            .filter_map(|item| {
                (item.get("status").and_then(Value::as_str) == Some("solved"))
                    .then(|| {
                        item.get("plan_id")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .flatten()
            })
            .collect::<Vec<_>>();
        if !solved.is_empty() {
            let proof_route = payload
                .get("proof_route")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| invalid("solved outcome requires proof_route"))?;
            let mut selected = payload
                .get("selected_plan_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if selected.is_empty() && solved.len() == 1 {
                selected = solved[0].clone();
            }
            if !solved.contains(&selected) {
                return Err(invalid_details(
                    "selected_plan_id must identify a completely solved plan",
                    serde_json::json!({"solved_plan_ids":solved}),
                ));
            }
            self.vault.write_join_result(
                claims.run_id(),
                &serde_json::json!({
                    "source":"direct_proving","status":"solved","selected_plan_id":selected,
                    "proof_route":proof_route,"screening":screening
                }),
            )?;
            return self.seal_and_transition(
                run,
                claims,
                WorkflowState::Assemble,
                trace_id,
                "direct_proving_complete",
                None,
            );
        }
        let branch_plans = active_plans.as_array().cloned().unwrap_or_default();
        self.update_metadata(
            claims.run_id(),
            serde_json::json!({"branch_requests":branch_plans,"last_direct_screening":screening}),
        )?;
        self.seal_and_transition(
            run,
            claims,
            WorkflowState::BranchPrepare,
            trace_id,
            "direct_proving_complete",
            None,
        )
    }

    fn commit_branch(
        &self,
        _run: &Value,
        claims: &CapabilityClaims,
        payload: &Value,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        let branch_id = self.branch_id_for_domain(claims.domain_id())?;
        if self
            .vault
            .read_branch_memory(claims.run_id(), &branch_id, "proof_steps")?
            .is_empty()
        {
            return Err(ReCtmError::new(
                "WORKFLOW_PRECONDITION_FAILED",
                "Branch proof_steps memory must be non-empty before sealing.",
            )
            .with_category(ErrorCategory::Validation)
            .with_details(
                serde_json::json!({"branch_id":branch_id,"channel":"proof_steps"})
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
            ));
        }
        let object = payload
            .as_object()
            .ok_or_else(|| invalid("branch result must be a JSON object"))?;
        let status = object
            .get("status")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or_default();
        if !matches!(status, "solved" | "partial" | "failed") {
            return Err(invalid("branch status must be solved, partial, or failed"));
        }
        let summary = object
            .get("summary")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("branch result requires a non-empty summary"))?;
        if object.contains_key("proof_route") && !object["proof_route"].is_string() {
            return Err(invalid("branch proof_route must be a string when supplied"));
        }
        let proof_route = object
            .get("proof_route")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim();
        let proved_subgoals =
            string_array(object.get("proved_subgoals"), "proved_subgoals", false)?;
        let unproved_subgoals =
            string_array(object.get("unproved_subgoals"), "unproved_subgoals", false)?;
        let failure_evidence =
            string_array(object.get("failure_evidence"), "failure_evidence", false)?;
        if status == "solved" && proof_route.is_empty() {
            return Err(invalid("solved branch result requires proof_route"));
        }
        if matches!(status, "partial" | "failed")
            && unproved_subgoals.is_empty()
            && failure_evidence.is_empty()
        {
            return Err(invalid(
                "partial or failed branch result requires unproved_subgoals or failure_evidence",
            ));
        }
        let branch = self.store.get_branch(&branch_id)?;
        let result_payload = serde_json::json!({
            "branch_id":branch_id,
            "plan_id":branch["plan_id"],
            "status":status,
            "summary":summary,
            "proof_route":if proof_route.is_empty(){Value::Null}else{Value::String(proof_route.to_owned())},
            "proved_subgoals":proved_subgoals,
            "unproved_subgoals":unproved_subgoals,
            "failure_evidence":failure_evidence
        });
        let path = self
            .vault
            .write_branch_result(claims.run_id(), &branch_id, &result_payload)?;
        let path_text = path.to_string_lossy().into_owned();
        self.store
            .update_branch_status(&branch_id, "sealed", Some(&path_text))?;
        self.store.seal_domain(claims.domain_id())?;
        self.vault.append_generation_memory(
            claims.run_id(),
            "branch_states",
            &serde_json::json!({
                "record_type":"branch_sealed","branch_id":branch_id,
                "plan_id":result_payload["plan_id"],"status":status
            }),
        )?;
        let branches = self.store.list_branches(claims.run_id())?;
        let barrier_complete = !branches.is_empty()
            && branches
                .iter()
                .all(|branch| branch.get("status").and_then(Value::as_str) == Some("sealed"));
        let after = if barrier_complete {
            WorkflowState::BranchJoin
        } else {
            WorkflowState::BranchRun
        };
        let evidence = serde_json::json!({
            "branch_id":branch_id,"status":status,"barrier_complete":barrier_complete
        });
        let result = self.transition(TransitionInput {
            run_id: claims.run_id(),
            before: WorkflowState::BranchRun,
            after,
            trace_id,
            actor: role_name(claims.role()),
            reason: if barrier_complete {
                "branch_sealed_barrier_complete"
            } else {
                "branch_sealed_next_pending"
            },
            evidence: &evidence,
            latex_passed: None,
            verdict: None,
            status: None,
            sealed: None,
            round_delta: 0,
        })?;
        Ok(serde_json::json!({
            "run_id":claims.run_id(),"state":result["state"],"branch_id":branch_id,
            "branch_status":"sealed","barrier_complete":barrier_complete
        }))
    }

    fn commit_join(
        &self,
        claims: &CapabilityClaims,
        payload: &Value,
    ) -> Result<WorkflowState, ReCtmError> {
        let object = payload
            .as_object()
            .ok_or_else(|| invalid("join payload must be a JSON object"))?;
        let branches = self.store.list_branches(claims.run_id())?;
        let sealed_ids = branches
            .iter()
            .filter(|branch| branch.get("status").and_then(Value::as_str) == Some("sealed"))
            .filter_map(|branch| {
                branch
                    .get("branch_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect::<BTreeSet<_>>();
        if let Some(considered) = object.get("considered_branch_ids") {
            let considered = string_array(Some(considered), "considered_branch_ids", false)?;
            if considered
                .iter()
                .any(|branch_id| !sealed_ids.contains(branch_id))
            {
                return Err(invalid_details(
                    "considered_branch_ids may contain only sealed branch ids; complete coverage is server-derived",
                    serde_json::json!({"sealed_branch_ids":sealed_ids}),
                ));
            }
        }
        let mut results = BTreeMap::new();
        for branch_id in &sealed_ids {
            results.insert(
                branch_id.clone(),
                self.vault.read_branch_result(claims.run_id(), branch_id)?,
            );
        }
        let solved = results
            .iter()
            .filter(|(_, result)| result.get("status").and_then(Value::as_str) == Some("solved"))
            .map(|(branch_id, _)| branch_id.clone())
            .collect::<Vec<_>>();
        if object.contains_key("selected_branch_id") && !object["selected_branch_id"].is_string() {
            return Err(invalid("selected_branch_id must be a string when supplied"));
        }
        if object.contains_key("synthesis_proof_route")
            && !object["synthesis_proof_route"].is_string()
        {
            return Err(invalid(
                "synthesis_proof_route must be a string when supplied",
            ));
        }
        let mut selected = object
            .get("selected_branch_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned();
        let synthesis = object
            .get("synthesis_proof_route")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned();
        if selected.is_empty() && synthesis.is_empty() && solved.len() == 1 {
            selected = solved[0].clone();
        }
        if !selected.is_empty() && !solved.contains(&selected) {
            return Err(invalid_details(
                "selected_branch_id must identify a solved sealed branch",
                serde_json::json!({"selected_branch_id":selected,"solved_branch_ids":solved}),
            ));
        }
        if selected.is_empty() && synthesis.is_empty() && solved.len() > 1 {
            return Err(invalid_details(
                "multiple solved branches require selected_branch_id or synthesis_proof_route",
                serde_json::json!({"solved_branch_ids":solved}),
            ));
        }
        let outcome = if !selected.is_empty() || !synthesis.is_empty() {
            "solved"
        } else {
            "failed"
        };
        let common_failures = if outcome == "failed" {
            Some(string_array(
                object.get("common_failures"),
                "common_failures",
                true,
            )?)
        } else {
            None
        };
        let mut normalized = object.clone();
        normalized.insert("outcome".to_owned(), Value::String(outcome.to_owned()));
        normalized.insert(
            "selected_branch_id".to_owned(),
            if selected.is_empty() {
                Value::Null
            } else {
                Value::String(selected)
            },
        );
        normalized.insert(
            "considered_branch_ids".to_owned(),
            serde_json::json!(sealed_ids.iter().collect::<Vec<_>>()),
        );
        normalized.insert(
            "joined_at".to_owned(),
            Value::String(self.store.runtime().clock.now_iso()?),
        );
        if let Some(common_failures) = common_failures {
            normalized.insert(
                "common_failures".to_owned(),
                serde_json::json!(common_failures),
            );
        }
        self.vault
            .write_join_result(claims.run_id(), &Value::Object(normalized))?;
        self.vault.append_generation_memory(
            claims.run_id(),
            "branch_states",
            &serde_json::json!({
                "record_type":"branch_join","outcome":outcome,
                "considered_branch_ids":sealed_ids.iter().collect::<Vec<_>>()
            }),
        )?;
        Ok(if outcome == "solved" {
            WorkflowState::Assemble
        } else {
            WorkflowState::IdentifyFailures
        })
    }

    fn commit_proof_submitted(
        &self,
        run: &Value,
        claims: &CapabilityClaims,
        payload: &Value,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        let protocol = metadata_i64(run, "workflow_protocol_version", 1);
        if protocol >= 2
            && payload
                .get("outcome")
                .and_then(Value::as_str)
                .unwrap_or("proof")
                == "escalate"
        {
            if metadata_text(run, "effective_workflow_mode") != "compact" {
                return Err(invalid(
                    "Only a compact assembly may escalate to full exploration",
                ));
            }
            self.update_metadata(
                claims.run_id(),
                serde_json::json!({
                    "effective_workflow_mode":"full",
                    "compact_escalation_reason":payload.get("escalation_reason").and_then(Value::as_str).unwrap_or("assembly requested full exploration")
                }),
            )?;
            if self
                .store
                .get_project_run(claims.run_id(), Some(claims.owner_id()))?
                .is_some()
            {
                self.store.set_project_run_mode(claims.run_id(), "full")?;
            }
            return self.seal_and_transition(
                run,
                claims,
                WorkflowState::Explore,
                trace_id,
                "compact_assembly_escalated_to_full",
                None,
            );
        }
        let proof = self.vault.read_proof(claims.run_id())?;
        if protocol >= 2 {
            self.store.read_proof_manifest(claims.run_id())?;
        }
        self.update_metadata(
            claims.run_id(),
            serde_json::json!({"last_submitted_proof_sha256":sha256_text(&proof)}),
        )?;
        self.seal_and_transition(
            run,
            claims,
            WorkflowState::LatexValidate,
            trace_id,
            "proof_submitted",
            None,
        )
    }

    fn commit_verification_submitted(
        &self,
        run: &Value,
        claims: &CapabilityClaims,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        self.require_verifier_records(claims.run_id(), "statement_checks")?;
        self.require_verifier_records(claims.run_id(), "events")?;
        let proof = self.vault.read_proof(claims.run_id())?;
        let protocol = metadata_i64(run, "workflow_protocol_version", 1);
        if protocol < 2 && proof_declares_external_references(&proof) {
            self.require_verifier_records(claims.run_id(), "reference_checks")?;
        }
        let report = self.vault.read_verification_report(claims.run_id())?;
        let mut decision = VerificationDecision::from_submitted_report(&report)?;
        let mut server_gaps = Vec::new();
        if protocol >= 2 {
            let manifest = self.store.read_proof_manifest(claims.run_id())?["manifest"].clone();
            let audits = self
                .store
                .list_reference_audits(claims.run_id())?
                .into_iter()
                .filter_map(|audit| {
                    let reference_id = audit
                        .get("reference_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)?;
                    Some((reference_id, audit))
                })
                .collect::<BTreeMap<_, _>>();
            for reference_id in manifest
                .get("reference_ids")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                let finding = match audits.get(reference_id) {
                    None => Some(VerificationFinding {
                        location: format!("reference:{reference_id}"),
                        issue: "Material reference has no verifier audit disposition.".to_owned(),
                    }),
                    Some(audit)
                        if !matches!(
                            audit.get("disposition").and_then(Value::as_str),
                            Some("SOURCE_VERIFIED" | "INDEPENDENTLY_REDERIVED" | "NOT_MATERIAL")
                        ) =>
                    {
                        Some(VerificationFinding {
                            location: format!("reference:{reference_id}"),
                            issue: "Material reference remains unresolved after verifier audit."
                                .to_owned(),
                        })
                    }
                    _ => None,
                };
                if let Some(finding) = finding {
                    server_gaps.push(finding.clone());
                    decision = decision.with_server_gap(finding);
                }
            }
        }
        let mut normalized = decision.normalized_payload();
        if decision.verdict() == VerificationVerdict::Wrong
            && normalized
                .get("repair_hints")
                .and_then(Value::as_str)
                .is_some_and(|hints| hints.trim().is_empty())
        {
            if server_gaps.is_empty() {
                return Err(invalid(
                    "wrong verification requires non-empty repair_hints",
                ));
            }
            let hint = format!(
                "Resolve the server-detected reference audit gaps before resubmission: {}",
                server_gaps
                    .iter()
                    .map(|item| format!("{}: {}", item.location, item.issue))
                    .collect::<Vec<_>>()
                    .join("; ")
            );
            normalized["repair_hints"] = Value::String(hint);
        }
        self.vault
            .write_verification_report(claims.run_id(), &normalized)?;
        self.vault
            .append_verifier_memory(claims.run_id(), "verification_reports", &normalized)?;
        self.vault.append_generation_memory(
            claims.run_id(),
            "verification_reports",
            &normalized,
        )?;
        self.update_metadata(
            claims.run_id(),
            serde_json::json!({
                "last_verified_proof_sha256":sha256_text(&proof),
                "last_verifier_audit":{
                    "statement_checks":self.vault.read_verifier_memory(claims.run_id(),"statement_checks")?.len(),
                    "legacy_reference_checks":self.vault.read_verifier_memory(claims.run_id(),"reference_checks")?.len(),
                    "structured_reference_audits":self.store.list_reference_audits(claims.run_id())?.len()
                }
            }),
        )?;
        let verdict = match decision.verdict() {
            VerificationVerdict::Correct => "correct",
            VerificationVerdict::Wrong => "wrong",
        };
        if verdict == "correct" && run.get("latex_passed") != Some(&Value::Bool(true)) {
            return Err(ReCtmError::new(
                "LATEX_GATE_NOT_PASSED",
                "A mathematically correct report cannot finalize before the LaTeX gate passes.",
            )
            .with_category(ErrorCategory::Conflict));
        }
        let after = if verdict == "correct" {
            WorkflowState::Finalize
        } else {
            let compact = metadata_text(run, "effective_workflow_mode") == "compact";
            let failures = metadata_i64(run, "compact_verifier_failures", 0) + i64::from(compact);
            if compact {
                self.update_metadata(
                    claims.run_id(),
                    serde_json::json!({"compact_verifier_failures":failures}),
                )?;
            }
            if compact && failures >= 2 {
                self.update_metadata(
                    claims.run_id(),
                    serde_json::json!({
                        "effective_workflow_mode":"full",
                        "compact_escalated_after_verifier":true
                    }),
                )?;
                if self
                    .store
                    .get_project_run(claims.run_id(), Some(claims.owner_id()))?
                    .is_some()
                {
                    self.store.set_project_run_mode(claims.run_id(), "full")?;
                }
                WorkflowState::Explore
            } else {
                WorkflowState::Repair
            }
        };
        self.seal_and_transition(
            run,
            claims,
            after,
            trace_id,
            if verdict == "wrong" && after == WorkflowState::Explore {
                "compact_verifier_escalated_to_full"
            } else if verdict == "correct" {
                "server_computed_verdict_correct"
            } else {
                "server_computed_verdict_wrong"
            },
            Some(verdict),
        )
    }

    fn commit_repair_submitted(
        &self,
        run: &Value,
        claims: &CapabilityClaims,
    ) -> Result<(), ReCtmError> {
        let proof = self.vault.read_proof(claims.run_id())?;
        if metadata_i64(run, "workflow_protocol_version", 1) >= 2 {
            self.store.read_proof_manifest(claims.run_id())?;
        }
        let proof_sha256 = sha256_text(&proof);
        let prior = metadata_text(run, "last_verified_proof_sha256");
        if !prior.is_empty() && prior == proof_sha256 {
            return Err(ReCtmError::new(
                "REPAIR_DID_NOT_CHANGE_PROOF",
                "A failed verification cannot be resubmitted unchanged.",
            )
            .with_category(ErrorCategory::Validation));
        }
        self.update_metadata(
            claims.run_id(),
            serde_json::json!({"last_submitted_proof_sha256":proof_sha256}),
        )?;
        Ok(())
    }
}

impl WorkflowEngine {
    fn prepare_branch_round(&self, run: &Value, trace_id: &str) -> Result<Value, ReCtmError> {
        let requests = run
            .get("metadata")
            .and_then(Value::as_object)
            .and_then(|metadata| metadata.get("branch_requests"))
            .and_then(Value::as_array)
            .filter(|requests| !requests.is_empty())
            .cloned()
            .ok_or_else(|| {
                ReCtmError::new(
                    "BRANCH_REQUESTS_MISSING",
                    "Branch preparation requires persisted branch requests.",
                )
                .with_category(ErrorCategory::Internal)
            })?;
        let next_round = run
            .get("round_index")
            .and_then(Value::as_i64)
            .unwrap_or_default()
            + 1;
        let snapshot_id = format!(
            "round-{next_round}-{}",
            self.store.runtime().ids.token_hex(4)?
        );
        let mut generation_memory = Map::new();
        for channel in GENERATION_CHANNELS {
            if channel != "events" {
                generation_memory.insert(
                    channel.to_owned(),
                    Value::Array(
                        self.vault
                            .read_generation_memory(text(run, "run_id")?, channel)?,
                    ),
                );
            }
        }
        let snapshot_payload = serde_json::json!({
            "snapshot_id":snapshot_id,
            "created_at":self.store.runtime().clock.now_iso()?,
            "problem":self.vault.read_problem(text(run,"run_id")?)?,
            "references_manifest":self.vault.read_references_manifest(text(run,"run_id")?)?,
            "generation_memory":generation_memory,
            "branch_requests":requests
        });
        let snapshot =
            self.vault
                .create_snapshot(text(run, "run_id")?, &snapshot_id, &snapshot_payload)?;
        for (index, plan) in requests.iter().enumerate() {
            let plan_id = plan
                .get("plan_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| internal("branch request is missing plan_id"))?;
            let branch_id = format!(
                "branch-{next_round}-{}-{}",
                index + 1,
                self.store.runtime().ids.token_hex(3)?
            );
            let domain_id = format!("branch-domain-{branch_id}");
            self.store.create_domain(
                &domain_id,
                text(run, "run_id")?,
                "branch",
                Some(&snapshot_id),
                Some(index as i64),
                &serde_json::json!({
                    "state":"branch_run","branch_id":branch_id,"snapshot_id":snapshot_id
                }),
            )?;
            self.store.create_branch(
                &branch_id,
                text(run, "run_id")?,
                plan_id,
                &domain_id,
                &snapshot_id,
                index as i64,
                &serde_json::json!({"plan":plan}),
            )?;
            self.vault.initialize_branch(
                text(run, "run_id")?,
                &branch_id,
                &serde_json::json!({
                    "branch_id":branch_id,
                    "plan":plan,
                    "snapshot_id":snapshot_id,
                    "snapshot_sha256":snapshot["sha256"]
                }),
            )?;
        }
        self.update_metadata(
            text(run, "run_id")?,
            serde_json::json!({"active_snapshot_id":snapshot_id,"branch_requests":[]}),
        )?;
        let evidence = serde_json::json!({
            "snapshot_id":snapshot_id,"branch_count":requests.len()
        });
        self.transition(TransitionInput {
            run_id: text(run, "run_id")?,
            before: WorkflowState::BranchPrepare,
            after: WorkflowState::BranchRun,
            trace_id,
            actor: "system",
            reason: "frozen_snapshot_and_branch_domains_created",
            evidence: &evidence,
            latex_passed: None,
            verdict: None,
            status: None,
            sealed: None,
            round_delta: 1,
        })
    }

    fn run_latex_gate(&self, run: &Value, trace_id: &str) -> Result<Value, ReCtmError> {
        let run_id = text(run, "run_id")?;
        let proof = self.vault.read_proof(run_id)?;
        let workdir = self.vault.run_root(run_id)?.join("verification/latex");
        let result = self.latex_gate.validate(&proof, &workdir)?;
        self.update_metadata(
            run_id,
            serde_json::json!({"latex_result":result.to_value()}),
        )?;
        self.emit(WorkflowEvent {
            event_type: "latex.gate_result".to_owned(),
            trace_id: trace_id.to_owned(),
            run_id: Some(run_id.to_owned()),
            actor_role: None,
            domain_id: None,
            before_state: Some("latex_validate".to_owned()),
            after_state: None,
            decision: if result.gate_passed { "allow" } else { "deny" }.to_owned(),
            reason: if result.gate_passed {
                "latex_gate_passed"
            } else {
                "latex_gate_failed"
            }
            .to_owned(),
            details: result.to_value(),
        });
        let evidence = result.to_value();
        self.transition(TransitionInput {
            run_id,
            before: WorkflowState::LatexValidate,
            after: if result.gate_passed {
                WorkflowState::Verify
            } else {
                WorkflowState::Repair
            },
            trace_id,
            actor: "latex_gate",
            reason: if result.gate_passed {
                "latex_gate_passed"
            } else {
                "latex_gate_failed"
            },
            evidence: &evidence,
            latex_passed: Some(result.gate_passed),
            verdict: None,
            status: None,
            sealed: None,
            round_delta: 0,
        })
    }

    fn finalize(&self, run: &Value, trace_id: &str) -> Result<Value, ReCtmError> {
        let run_id = text(run, "run_id")?;
        if run.get("latex_passed") != Some(&Value::Bool(true))
            || run.get("verdict").and_then(Value::as_str) != Some("correct")
        {
            return Err(ReCtmError::new(
                "FINALIZATION_GATE_DENIED",
                "Finalization requires a passed LaTeX gate and server-computed correct verdict.",
            )
            .with_category(ErrorCategory::Permission));
        }
        let decision = VerificationDecision::from_submitted_report(
            &self.vault.read_verification_report(run_id)?,
        )?;
        let proof = self.vault.read_proof(run_id)?;
        let proof_sha256 = sha256_text(&proof);
        let verified_hash = metadata_text(run, "last_verified_proof_sha256");
        if verified_hash.is_empty() || verified_hash != proof_sha256 {
            return Err(ReCtmError::new(
                "FINALIZATION_GATE_DENIED",
                "Draft proof bytes do not match the proof approved by the verifier.",
            )
            .with_category(ErrorCategory::Permission));
        }
        let manifest_record = if metadata_i64(run, "workflow_protocol_version", 1) >= 2 {
            Some(self.store.read_proof_manifest(run_id)?)
        } else {
            None
        };
        self.store
            .list_domains(run_id, Some("verifier"), Some("sealed"))?
            .into_iter()
            .last()
            .ok_or_else(|| {
                ReCtmError::new(
                    "FINALIZATION_GATE_DENIED",
                    "Finalization requires a sealed verifier domain.",
                )
                .with_category(ErrorCategory::Permission)
            })?;
        let permit: FinalizationPermit = decision.finalization_permit(
            run_id,
            true,
            &proof_sha256,
            manifest_record
                .as_ref()
                .and_then(|record| record.get("sha256"))
                .and_then(Value::as_str),
        )?;
        let manifest_hash = manifest_record
            .as_ref()
            .and_then(|record| record.get("sha256"))
            .and_then(Value::as_str);
        if permit.proof_manifest_sha256() != manifest_hash {
            return Err(ReCtmError::new(
                "FINALIZATION_PERMIT_MISMATCH",
                "Proof manifest changed after verifier approval.",
            )
            .with_category(ErrorCategory::Conflict));
        }
        let target = self.vault.finalize_proof(run_id, &permit)?;
        let final_proof = self.vault.read_final_proof(run_id)?;
        let evidence = serde_json::json!({
            "artifact":file_name(&target),
            "sha256":sha256_text(&final_proof)
        });
        let result = self.transition(TransitionInput {
            run_id,
            before: WorkflowState::Finalize,
            after: WorkflowState::Done,
            trace_id,
            actor: "finalizer_gate",
            reason: "latex_and_verification_gates_passed",
            evidence: &evidence,
            latex_passed: None,
            verdict: None,
            status: Some("done"),
            sealed: Some(true),
            round_delta: 0,
        })?;
        let result = self.retry_pending_registry_promotion(&result)?;
        self.vault
            .write_manual_validation_manifest(run_id, &self.manual_validation_manifest(&result))?;
        Ok(result)
    }

    fn retry_pending_registry_promotion(&self, run: &Value) -> Result<Value, ReCtmError> {
        if workflow_state(text(run, "state")?)? != WorkflowState::Done
            || metadata_i64(run, "workflow_protocol_version", 1) < 2
        {
            return Ok(run.clone());
        }
        let Some(project_run) = self
            .store
            .get_project_run(text(run, "run_id")?, Some(text(run, "owner_id")?))?
        else {
            return Ok(run.clone());
        };
        if matches!(
            project_run.get("promotion_status").and_then(Value::as_str),
            Some("promoted" | "conflict" | "not_requested")
        ) {
            return Ok(run.clone());
        }
        let run_id = text(run, "run_id")?;
        let owner_id = text(run, "owner_id")?;
        let promotion_result = (|| {
            let manifest_record = self.store.read_proof_manifest(run_id)?;
            let manifest = manifest_record["manifest"].clone();
            let mut conditions = manifest
                .get("conditional_hypotheses")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>();
            for revision_id in manifest
                .get("dependency_revision_ids")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                let revision = self.store.get_claim_revision(revision_id, Some(owner_id))?;
                for condition in revision
                    .get("conditions")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                {
                    conditions.insert(condition.to_owned());
                }
            }
            let final_proof = self.vault.read_final_proof(run_id)?;
            let effective_conditions = conditions.into_iter().collect::<Vec<_>>();
            let promotion = self.store.promote_verified_run(
                run_id,
                owner_id,
                manifest
                    .get("target_statement_tex")
                    .and_then(Value::as_str)
                    .ok_or_else(|| internal("proof manifest target statement is missing"))?,
                &sha256_text(&final_proof),
                &effective_conditions,
                &manifest,
            )?;
            self.update_metadata(
                run_id,
                serde_json::json!({
                    "proof_manifest_sha256":manifest_record["sha256"],
                    "effective_conditions":effective_conditions,
                    "registry_promotion":promotion
                }),
            )?;
            Ok::<(), ReCtmError>(())
        })();
        if let Err(error) = promotion_result {
            let _ = self.update_metadata(
                run_id,
                serde_json::json!({"registry_promotion":{"status":"error","error":error.to_payload()}}),
            );
        }
        self.store.get_run(run_id)
    }
}

pub struct StartRequest<'a> {
    pub owner_id: &'a str,
    pub problem_tex: &'a str,
    pub problem_id: Option<&'a str>,
    pub references: &'a [Value],
    pub native_mode: &'a str,
    pub workspace_export_path: Option<&'a str>,
    pub project_id: Option<&'a str>,
    pub target_claim_id: Option<&'a str>,
    pub workflow_mode: &'a str,
    pub register_result: bool,
    pub workflow_protocol_version: i64,
    pub trace_id: Option<&'a str>,
}

struct TransitionInput<'a> {
    run_id: &'a str,
    before: WorkflowState,
    after: WorkflowState,
    trace_id: &'a str,
    actor: &'a str,
    reason: &'a str,
    evidence: &'a Value,
    latex_passed: Option<bool>,
    verdict: Option<&'a str>,
    status: Option<&'a str>,
    sealed: Option<bool>,
    round_delta: i64,
}

fn resources_for_role(role: WorkflowRole) -> &'static [&'static str] {
    match role {
        WorkflowRole::Generator => &[
            "problem",
            "references",
            "memory:generation:<channel>",
            "steering",
        ],
        WorkflowRole::Branch => &[
            "problem",
            "references",
            "snapshot",
            "branch:self",
            "memory:branch:<channel>",
        ],
        WorkflowRole::Join => &["problem", "snapshot", "branch:sealed:all", "join_result"],
        WorkflowRole::Assembler => &[
            "problem",
            "references",
            "memory:generation:<channel>",
            "join_result",
            "proof",
        ],
        WorkflowRole::Verifier => &[
            "problem",
            "proof",
            "references:approved",
            "memory:verifier:<channel>",
            "verification_report",
        ],
        WorkflowRole::Repair => &[
            "problem",
            "proof",
            "verification_report",
            "memory:generation:<channel>",
        ],
        WorkflowRole::Finalizer => &[],
    }
}

fn validate_plans(value: Option<&Value>, plan_round: i64) -> Result<Vec<Value>, ReCtmError> {
    let items = value
        .and_then(Value::as_array)
        .filter(|items| items.len() >= 2)
        .ok_or_else(|| invalid("plans must contain at least two materially different plans"))?;
    let round = plan_round.max(1);
    let mut plans = Vec::with_capacity(items.len());
    let mut summaries = BTreeSet::new();
    for (index, item) in items.iter().enumerate() {
        let object = item
            .as_object()
            .ok_or_else(|| invalid("each plan must be a JSON object"))?;
        if object.contains_key("plan_id") && !object["plan_id"].is_string() {
            return Err(invalid("plan_id must be a string when supplied"));
        }
        let source_plan_id = object
            .get("plan_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned();
        let plan_id = format!("plan-r{round}-{}", index + 1);
        let summary = object
            .get("summary")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("each plan requires a non-empty string summary"))?
            .to_owned();
        if !summaries.insert(summary.to_ascii_lowercase()) {
            return Err(invalid("plans must have materially distinct summaries"));
        }
        let subgoals = string_array(object.get("subgoals"), "plan subgoals", true)?;
        let motivation = string_array(object.get("motivation"), "plan motivation", false)?;
        let dependencies = string_array(object.get("dependencies"), "plan dependencies", false)?;
        let risks = string_array(object.get("risks"), "plan risks", false)?;
        let subgoal_ids = (1..=subgoals.len())
            .map(|subgoal| format!("sg-{subgoal}"))
            .collect::<Vec<_>>();
        plans.push(serde_json::json!({
            "plan_id":plan_id,
            "source_plan_id":if source_plan_id.is_empty(){Value::Null}else{Value::String(source_plan_id)},
            "summary":summary,
            "subgoals":subgoals,
            "subgoal_ids":subgoal_ids,
            "motivation":motivation,
            "dependencies":dependencies,
            "risks":risks
        }));
    }
    Ok(plans)
}

fn public_active_plans(value: Option<&Value>) -> Value {
    let Some(plans) = value.and_then(Value::as_array) else {
        return Value::Array(Vec::new());
    };
    let public = plans
        .iter()
        .filter_map(Value::as_object)
        .map(|plan| {
            let texts = plan
                .get("subgoals")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let mut ids = plan
                .get("subgoal_ids")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if ids.len() != texts.len() {
                ids = (1..=texts.len())
                    .map(|index| format!("sg-{index}"))
                    .collect();
            }
            serde_json::json!({
                "plan_id":plan.get("plan_id").and_then(Value::as_str).unwrap_or_default(),
                "source_plan_id":plan.get("source_plan_id").cloned().unwrap_or(Value::Null),
                "summary":plan.get("summary").and_then(Value::as_str).unwrap_or_default(),
                "subgoals":ids.into_iter().zip(texts).map(|(subgoal_id,text)|serde_json::json!({"subgoal_id":subgoal_id,"text":text})).collect::<Vec<_>>(),
                "motivation":plan.get("motivation").cloned().unwrap_or_else(||Value::Array(Vec::new())),
                "dependencies":plan.get("dependencies").cloned().unwrap_or_else(||Value::Array(Vec::new())),
                "risks":plan.get("risks").cloned().unwrap_or_else(||Value::Array(Vec::new()))
            })
        })
        .collect::<Vec<_>>();
    Value::Array(public)
}

fn string_array(
    value: Option<&Value>,
    label: &str,
    required: bool,
) -> Result<Vec<String>, ReCtmError> {
    let Some(value) = value else {
        if required {
            return Err(invalid(&format!(
                "{label} must be a non-empty array of non-empty strings"
            )));
        }
        return Ok(Vec::new());
    };
    let items = value.as_array().ok_or_else(|| {
        invalid(&format!(
            "{label} must be {}array of non-empty strings",
            if required { "a non-empty " } else { "an " }
        ))
    })?;
    if required && items.is_empty() {
        return Err(invalid(&format!(
            "{label} must be a non-empty array of non-empty strings"
        )));
    }
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| invalid(&format!("{label} entries must be non-empty strings")))
        })
        .collect()
}

type ScreeningProgress = BTreeMap<String, BTreeMap<String, ScreeningResult>>;

#[derive(Clone)]
struct ScreeningResult {
    status: String,
    summary: String,
}

fn merge_direct_screening(
    value: Option<&Value>,
    active_plans: &Value,
    previous: Option<&Value>,
) -> Result<(Vec<Value>, Value, Vec<Value>), ReCtmError> {
    let plans = active_plans
        .as_array()
        .filter(|plans| !plans.is_empty())
        .ok_or_else(|| invalid("direct screening requires active decomposition plans"))?;
    let mut known = BTreeMap::new();
    let mut source_to_plan = BTreeMap::new();
    for plan in plans {
        let object = plan
            .as_object()
            .ok_or_else(|| internal("active plan is invalid"))?;
        let plan_id = object
            .get("plan_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if !plan_id.is_empty() {
            known.insert(plan_id.clone(), plan.clone());
        }
        if let Some(source) = object
            .get("source_plan_id")
            .and_then(Value::as_str)
            .filter(|source| !source.is_empty())
        {
            source_to_plan.insert(source.to_owned(), plan_id);
        }
    }
    let mut progress = ScreeningProgress::new();
    if let Some(previous) = previous.and_then(Value::as_object) {
        for (plan_id, raw_results) in previous {
            if !known.contains_key(plan_id) {
                continue;
            }
            let Some(raw_results) = raw_results.as_object() else {
                continue;
            };
            let mut bucket = BTreeMap::new();
            for (subgoal_id, result) in raw_results {
                let Some(result) = result.as_object() else {
                    continue;
                };
                if let (Some(status), Some(summary)) = (
                    result.get("status").and_then(Value::as_str),
                    result.get("summary").and_then(Value::as_str),
                ) {
                    bucket.insert(
                        subgoal_id.clone(),
                        ScreeningResult {
                            status: status.to_owned(),
                            summary: summary.to_owned(),
                        },
                    );
                }
            }
            progress.insert(plan_id.clone(), bucket);
        }
    }

    let mut submissions: Vec<(String, Value)> = Vec::new();
    match value {
        None | Some(Value::Null) => {}
        Some(Value::Object(object)) => {
            submissions.extend(
                object
                    .iter()
                    .map(|(plan_id, results)| (plan_id.clone(), results.clone())),
            );
        }
        Some(Value::Array(items)) => {
            for item in items {
                let object = item
                    .as_object()
                    .ok_or_else(|| invalid("each screening report must be an object"))?;
                submissions.push((
                    object
                        .get("plan_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    object
                        .get("subgoal_results")
                        .cloned()
                        .unwrap_or(Value::Null),
                ));
            }
        }
        Some(_) => {
            return Err(invalid(
                "screening must be an object keyed by plan_id or a legacy report array",
            ));
        }
    }

    for (submitted_plan_id, raw_results) in submissions {
        let plan_id = source_to_plan
            .get(&submitted_plan_id)
            .cloned()
            .unwrap_or(submitted_plan_id);
        let plan = known.get(&plan_id).ok_or_else(|| {
            invalid_details(
                "screening plan_id is not active",
                serde_json::json!({"plan_id":plan_id,"active_plan_ids":known.keys().collect::<Vec<_>>() }),
            )
        })?;
        let (ids, texts) = plan_subgoals(plan)?;
        let by_text = ids
            .iter()
            .cloned()
            .zip(texts.iter().cloned())
            .map(|(id, text)| (text, id))
            .collect::<BTreeMap<_, _>>();
        let mut entries = Vec::<(String, Value)>::new();
        match raw_results {
            Value::Object(object) => {
                entries.extend(object);
            }
            Value::Array(items) => {
                for item in items {
                    let object = item
                        .as_object()
                        .ok_or_else(|| invalid("each subgoal result must be an object"))?;
                    let mut subgoal_id = object
                        .get("subgoal_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    if subgoal_id.is_empty() {
                        let text = object
                            .get("subgoal")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        subgoal_id = by_text.get(text).cloned().unwrap_or_default();
                    }
                    entries.push((subgoal_id, item));
                }
            }
            _ => {
                return Err(invalid_details(
                    "plan screening must contain subgoal result objects",
                    serde_json::json!({"plan_id":plan_id}),
                ));
            }
        }
        let bucket = progress.entry(plan_id.clone()).or_default();
        for (subgoal_id, raw_result) in entries {
            if !ids.contains(&subgoal_id) {
                return Err(invalid_details(
                    "screening subgoal_id is not active for the plan",
                    serde_json::json!({"plan_id":plan_id,"subgoal_id":subgoal_id,"active_subgoal_ids":ids}),
                ));
            }
            let object = raw_result
                .as_object()
                .ok_or_else(|| invalid("each subgoal result must be an object"))?;
            let status = object
                .get("status")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or_default();
            let summary = object
                .get("summary")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or_default();
            if !matches!(status, "solved" | "partial" | "stuck") || summary.is_empty() {
                return Err(invalid_details(
                    "subgoal screening requires status solved|partial|stuck and a non-empty summary",
                    serde_json::json!({"plan_id":plan_id,"subgoal_id":subgoal_id}),
                ));
            }
            bucket.insert(
                subgoal_id,
                ScreeningResult {
                    status: status.to_owned(),
                    summary: summary.to_owned(),
                },
            );
        }
    }

    let mut normalized = Vec::new();
    let mut missing = Vec::new();
    for (plan_id, plan) in &known {
        let (ids, texts) = plan_subgoals(plan)?;
        let bucket = progress.get(plan_id);
        let mut results = Vec::new();
        for (id, text) in ids.iter().zip(&texts) {
            let Some(result) = bucket.and_then(|bucket| bucket.get(id)) else {
                missing.push(serde_json::json!({"plan_id":plan_id,"subgoal_id":id,"text":text}));
                continue;
            };
            results.push(serde_json::json!({
                "subgoal_id":id,"subgoal":text,"status":result.status,"summary":result.summary
            }));
        }
        let statuses = results
            .iter()
            .filter_map(|result| result.get("status").and_then(Value::as_str))
            .collect::<Vec<_>>();
        let plan_status = if results.len() == ids.len()
            && !statuses.is_empty()
            && statuses.iter().all(|status| *status == "solved")
        {
            "solved"
        } else if statuses.contains(&"stuck") {
            "stuck"
        } else {
            "partial"
        };
        let stuck = results
            .iter()
            .filter(|result| result.get("status").and_then(Value::as_str) != Some("solved"))
            .filter_map(|result| result.get("summary").and_then(Value::as_str))
            .collect::<Vec<_>>();
        normalized.push(serde_json::json!({
            "plan_id":plan_id,"status":plan_status,"subgoal_results":results,"key_stuck_points":stuck
        }));
    }

    let progress_value = Value::Object(Map::from_iter(progress.into_iter().map(
        |(plan_id, bucket)| {
            (
                plan_id,
                Value::Object(Map::from_iter(bucket.into_iter().map(
                    |(subgoal_id, result)| {
                        (
                            subgoal_id,
                            serde_json::json!({"status":result.status,"summary":result.summary}),
                        )
                    },
                ))),
            )
        },
    )));
    Ok((normalized, progress_value, missing))
}

fn plan_subgoals(plan: &Value) -> Result<(Vec<String>, Vec<String>), ReCtmError> {
    let object = plan
        .as_object()
        .ok_or_else(|| internal("active plan is invalid"))?;
    let texts = object
        .get("subgoals")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut ids = object
        .get("subgoal_ids")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if ids.len() != texts.len() {
        ids = (1..=texts.len())
            .map(|index| format!("sg-{index}"))
            .collect();
    }
    Ok((ids, texts))
}

fn required_trimmed(object: &Map<String, Value>, key: &str) -> Result<String, ReCtmError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid(&format!("reference_audit requires non-empty {key}")))
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned()
}

fn proof_declares_external_references(proof: &str) -> bool {
    Regex::new(
        r"(?i)(?:\\cite\b|arXiv\s*(?:id)?\s*[:=]|paper[_\s-]?id\s*[:=]|theorem[_\s-]?id\s*[:=])",
    )
    .is_ok_and(|pattern| pattern.is_match(proof))
}

fn safe_component(value: &str) -> String {
    let mut output = String::new();
    let mut previous_separator = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
            output.push(character);
            previous_separator = false;
        } else if !previous_separator {
            output.push('-');
            previous_separator = true;
        }
    }
    let cleaned = output
        .trim_matches(['-', '.', '_'])
        .chars()
        .take(80)
        .collect::<String>();
    if cleaned.is_empty() {
        "problem".to_owned()
    } else {
        cleaned
    }
}

fn workflow_state(value: &str) -> Result<WorkflowState, ReCtmError> {
    serde_json::from_value(Value::String(value.to_owned())).map_err(|_| {
        ReCtmError::new("STATE_ROW_INVALID", "Workflow state is invalid.")
            .with_category(ErrorCategory::Internal)
    })
}

fn role_name(role: WorkflowRole) -> &'static str {
    match role {
        WorkflowRole::Generator => "generator",
        WorkflowRole::Branch => "branch",
        WorkflowRole::Join => "join",
        WorkflowRole::Assembler => "assembler",
        WorkflowRole::Verifier => "verifier",
        WorkflowRole::Repair => "repair",
        WorkflowRole::Finalizer => "finalizer",
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, ReCtmError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| internal(&format!("missing string field: {key}")))
}

fn metadata_text<'a>(run: &'a Value, key: &str) -> &'a str {
    run.get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get(key))
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn metadata_i64(run: &Value, key: &str, default: i64) -> i64 {
    run.get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get(key))
        .and_then(Value::as_i64)
        .unwrap_or(default)
}

fn invalid(message: &str) -> ReCtmError {
    ReCtmError::new("INVALID_ARGUMENT", message).with_category(ErrorCategory::Validation)
}

fn invalid_details(message: &str, details: Value) -> ReCtmError {
    ReCtmError::new("INVALID_ARGUMENT", message)
        .with_category(ErrorCategory::Validation)
        .with_details(details.as_object().cloned().unwrap_or_default())
}

fn internal(message: &str) -> ReCtmError {
    ReCtmError::new("WORKFLOW_INTERNAL", message).with_category(ErrorCategory::Internal)
}

fn sha256_text(value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(value.as_bytes());
    format!("{:x}", digest.finalize())
}
