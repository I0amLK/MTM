use std::collections::BTreeMap;
use std::sync::Arc;

use mtm_contracts::{ErrorCategory, ReCtmError};
use mtm_gateway::{
    HIDDEN_TOOL_NAMES, OAuthPrincipal, PUBLIC_TOOL_NAMES, SUPPORTED_PROTOCOL_VERSIONS, ToolBackend,
};
use mtm_storage::{CapabilityAuthority, StateStore};
use mtm_workflow::WorkflowEngine;
use serde_json::{Map, Value};

use crate::latex::static_latex_errors;
use crate::{NativeToolRuntime, NativeWorkspace, RuntimeEventSink};

const INSPECT_OPERATIONS: [&str; 9] = [
    "status",
    "read",
    "search",
    "projects",
    "project_status",
    "claim",
    "dependency_graph",
    "reference_audit",
    "theorem_search",
];
const CONTROL_ACTIONS: [&str; 5] = [
    "steer",
    "cancel",
    "project_create",
    "claim_create",
    "claim_revise",
];
const PROJECT_ARTIFACTS: [&str; 2] = ["project_manifest", "project_summary_tex"];

pub struct RuntimeToolBackend {
    native: Arc<NativeToolRuntime>,
    workspace: Arc<NativeWorkspace>,
    workflow: Arc<WorkflowEngine>,
    store: Arc<StateStore>,
    capabilities: Arc<CapabilityAuthority>,
    workflow_protocol_version: i64,
    observer: Option<RuntimeEventSink>,
}

impl RuntimeToolBackend {
    pub fn new(
        native: Arc<NativeToolRuntime>,
        workspace: Arc<NativeWorkspace>,
        workflow: Arc<WorkflowEngine>,
        store: Arc<StateStore>,
        capabilities: Arc<CapabilityAuthority>,
    ) -> Self {
        Self::new_with_protocol_and_observer(
            native,
            workspace,
            workflow,
            store,
            capabilities,
            2,
            None,
        )
    }

    pub fn new_with_observer(
        native: Arc<NativeToolRuntime>,
        workspace: Arc<NativeWorkspace>,
        workflow: Arc<WorkflowEngine>,
        store: Arc<StateStore>,
        capabilities: Arc<CapabilityAuthority>,
        observer: Option<RuntimeEventSink>,
    ) -> Self {
        Self::new_with_protocol_and_observer(
            native,
            workspace,
            workflow,
            store,
            capabilities,
            2,
            observer,
        )
    }

    pub fn new_with_protocol_and_observer(
        native: Arc<NativeToolRuntime>,
        workspace: Arc<NativeWorkspace>,
        workflow: Arc<WorkflowEngine>,
        store: Arc<StateStore>,
        capabilities: Arc<CapabilityAuthority>,
        workflow_protocol_version: i64,
        observer: Option<RuntimeEventSink>,
    ) -> Self {
        Self {
            native,
            workspace,
            workflow,
            store,
            capabilities,
            workflow_protocol_version,
            observer,
        }
    }

    fn emit(&self, event: Value) {
        if let Some(observer) = &self.observer {
            observer(event);
        }
    }

    fn dispatch(
        &self,
        name: &str,
        arguments: &Map<String, Value>,
        principal: &OAuthPrincipal,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        match name {
            "server_info" => self.server_info(principal, trace_id),
            "check_exec_environment" => Ok(self.native.check_exec_environment()),
            "read_file" => self.workspace.read_file(arguments),
            "list_dir" => self.workspace.list_dir(arguments),
            "list_files" => self.workspace.list_files(arguments),
            "search_text" => self.workspace.search_text(arguments),
            "apply_patch" => self.workspace.apply_patch(
                required_text(arguments, "patch")?,
                arguments
                    .get("dry_run")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            ),
            "exec_command" => self.native.exec_command(arguments),
            "write_stdin" => self.native.write_stdin(arguments),
            "kill_command" => self.native.kill_command(arguments),
            "read_output" => self.native.read_output(arguments),
            "git_status" => self.workspace.git_status(arguments),
            "git_diff" => self.workspace.git_diff(arguments),
            "git_log" => self.workspace.git_log(arguments),
            "git_show" => self.workspace.git_show(arguments),
            "git_blame" => self.workspace.git_blame(arguments),
            "request_permissions" => Ok(self.native.request_permissions(arguments)),
            "view_image" => self.workspace.view_image(arguments),
            "rethlas_start" => self.rethlas_start(principal, arguments, trace_id),
            "rethlas_step" => self.rethlas_step(principal, arguments, trace_id),
            "rethlas_inspect" => self.rethlas_inspect(principal, arguments, trace_id),
            "rethlas_retrieve" => self.rethlas_retrieve(principal, arguments, trace_id),
            "rethlas_control" => self.rethlas_control(principal, arguments, trace_id),
            "rethlas_artifact" => self.rethlas_artifact(principal, arguments, trace_id),
            "rethlas_next" => self.rethlas_next(principal, arguments, trace_id),
            "rethlas_read" => self.rethlas_read(principal, arguments, trace_id),
            "rethlas_write" => self.rethlas_write(principal, arguments, trace_id),
            "rethlas_search" => self.rethlas_search(principal, arguments, trace_id),
            "rethlas_commit" => self.rethlas_commit(principal, arguments, trace_id),
            "rethlas_status" => self
                .workflow
                .status(&principal.client_id, text_or(arguments, "run_id", "")),
            "rethlas_steer" => self.workflow.steer(
                &principal.client_id,
                text_or(arguments, "run_id", ""),
                text_or(arguments, "message", ""),
                Some(trace_id),
            ),
            "rethlas_resume" => self
                .workflow
                .resume(&principal.client_id, text_or(arguments, "run_id", "")),
            "rethlas_cancel" => self.workflow.cancel(
                &principal.client_id,
                text_or(arguments, "run_id", ""),
                text_or(arguments, "reason", "user_cancelled"),
                Some(trace_id),
            ),
            "rethlas_get_artifact" => self.workflow.get_artifact(
                &principal.client_id,
                text_or(arguments, "run_id", ""),
                text_or(arguments, "artifact", ""),
            ),
            "rethlas_export_final" => self.rethlas_export_final(principal, arguments, trace_id),
            other => Err(validation_details(
                "unknown tool",
                serde_json::json!({"tool":other}),
            )),
        }
    }

    fn server_info(&self, principal: &OAuthPrincipal, trace_id: &str) -> Result<Value, ReCtmError> {
        let exec_environment = self.native.check_exec_environment();
        let native_info = self.native.server_info();
        let permission_mode = self.native.mode().as_str();
        let global_tmp = exec_environment
            .get("global_tmp_write")
            .and_then(Value::as_str)
            .unwrap_or("blocked");
        let replacement = (native_info
            .get("native_exec_backend")
            .and_then(Value::as_str)
            == Some("BubblewrapExecBackend"))
        .then_some("bubblewrap");
        let state_schema_version = self.store.schema_version()?;
        let mut payload = serde_json::json!({
            "server":"mtm",
            "title":"MTM",
            "version":env!("CARGO_PKG_VERSION"),
            "supported_protocol_versions":SUPPORTED_PROTOCOL_VERSIONS,
            "workspace":self.workspace.root(),
            "permission_mode":permission_mode,
            "network_allowed":permission_mode != "safe",
            "runtime_dir":"/tmp",
            "home":"/home/re-ctm",
            "tmpdir":"/tmp",
            "cache_dir":"/tmp/cache",
            "auth_enabled":true,
            "dangerously_skip_all_permissions":permission_mode == "dangerous",
            "annotation_override":Value::Null,
            "landlock":{"available":false,"enabled":false,"abi_version":Value::Null,"replacement":replacement},
            "exec_policy":{
                "shell_expansion":if permission_mode == "safe" {"blocked"} else {"allowed"},
                "inline_script":if permission_mode == "safe" {"blocked"} else {"allowed"},
                "global_tmp_write":global_tmp,
                "secret_env_filter":if permission_mode == "dangerous" {"disabled"} else {"enabled"}
            },
            "shell_env_inherit":"none",
            "shell_env_include_only":Vec::<String>::new(),
            "shell_env_exclude":Vec::<String>::new(),
            "output_retention":{"buffer_bytes_per_stream":524288,"head_bytes_per_stream":65536},
            "endpoint_path":"/mcp",
        });
        let Some(object) = payload.as_object_mut() else {
            return Err(ReCtmError::new(
                "INTERNAL_ERROR",
                "server_info payload construction failed",
            )
            .with_category(ErrorCategory::Internal));
        };
        let identity_and_tools = serde_json::json!({
            "project_context":{"root_instruction_files":[],"nested_instruction_files":[],"warnings":[]},
            "oauth_only":true,
            "oauth_client_id":principal.client_id,
            "tool_count":PUBLIC_TOOL_NAMES.len(),
            "tools":PUBLIC_TOOL_NAMES,
            "ctm_native_tool_count":18,
            "rethlas_tool_count":6,
            "ctm_native_tools":&PUBLIC_TOOL_NAMES[..18],
            "rethlas_tools":&PUBLIC_TOOL_NAMES[18..],
            "hidden_legacy_rethlas_aliases":HIDDEN_TOOL_NAMES,
            "tool_catalog_stable":true,
        });
        let Value::Object(identity_and_tools) = identity_and_tools else {
            return Err(ReCtmError::new(
                "INTERNAL_ERROR",
                "server_info tool payload construction failed",
            )
            .with_category(ErrorCategory::Internal));
        };
        object.extend(identity_and_tools);
        let workflow_facts = serde_json::json!({
            "mathematical_task_routing":"Concrete proof, derivation, proof-repair, and rigorous verification tasks should start with rethlas_start unless the user explicitly requests a direct informal answer.",
            "verified_latex_delivery":{"automatic_on_done":true,"default_workspace_path":"rethlas-output/<run_id>/proof_verified.tex","explicit_alternate_export_tool":"rethlas_artifact"},
            "research_workspace":{"state_schema_version":state_schema_version,"workflow_protocol_version":self.workflow_protocol_version,"production_default_workflow_protocol_version":2,"project_registry":true,"compact_verified_lane":true,"proof_manifest":true,"reference_audit":true,"paper_search_provider":"https://api.openalex.org/works","verified_promotion_is_finalizer_only":true},
            "native":native_info,
            "authorization_axioms":{"native":"OAuth identity AND native mode","workflow":"OAuth identity AND signed run capability AND role ACL AND workflow state","non_inheritance":"native dangerous never implies workflow authority"},
            "complete_flow_locally_validated":false,
            "trace_id":trace_id
        });
        let Value::Object(workflow_facts) = workflow_facts else {
            return Err(ReCtmError::new(
                "INTERNAL_ERROR",
                "server_info workflow payload construction failed",
            )
            .with_category(ErrorCategory::Internal));
        };
        object.extend(workflow_facts);
        Ok(payload)
    }

    fn rethlas_start(
        &self,
        principal: &OAuthPrincipal,
        arguments: &Map<String, Value>,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        let references = arguments
            .get("references")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if arguments.contains_key("references") && !arguments["references"].is_array() {
            return Err(validation("references must be an array"));
        }
        let export_path = text_or(arguments, "export_path", "").trim();
        let export = if export_path.is_empty() {
            None
        } else {
            if !export_path.to_ascii_lowercase().ends_with(".tex") {
                return Err(validation_details(
                    "export_path must end in .tex",
                    serde_json::json!({"export_path":export_path}),
                ));
            }
            Some(self.workspace.resolve_for_write(export_path)?.display)
        };
        self.workflow.start(mtm_workflow::StartRequest {
            owner_id: &principal.client_id,
            problem_tex: text_or(arguments, "problem_tex", ""),
            problem_id: Some(text_or(arguments, "problem_id", "problem")),
            references: &references,
            native_mode: self.native.mode().as_str(),
            workspace_export_path: export.as_deref(),
            project_id: optional_nonempty(arguments, "project_id"),
            target_claim_id: optional_nonempty(arguments, "target_claim_id"),
            workflow_mode: text_or(arguments, "workflow_mode", "auto"),
            register_result: arguments
                .get("register_result")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            workflow_protocol_version: self.workflow_protocol_version,
            trace_id: Some(trace_id),
        })
    }

    fn rethlas_next(
        &self,
        principal: &OAuthPrincipal,
        arguments: &Map<String, Value>,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        let result = self.workflow.next_task(
            &principal.client_id,
            text_or(arguments, "run_id", ""),
            Some(trace_id),
        )?;
        self.attach_done_export_if_needed(principal, result, trace_id)
    }

    fn rethlas_read(
        &self,
        principal: &OAuthPrincipal,
        arguments: &Map<String, Value>,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        self.workflow.read(
            &principal.client_id,
            text_or(arguments, "capability", ""),
            text_or(arguments, "resource", ""),
            Some(trace_id),
        )
    }

    fn rethlas_write(
        &self,
        principal: &OAuthPrincipal,
        arguments: &Map<String, Value>,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        self.workflow.write(
            &principal.client_id,
            text_or(arguments, "capability", ""),
            text_or(arguments, "resource", ""),
            arguments.get("content").unwrap_or(&Value::Null),
            Some(trace_id),
        )
    }

    fn rethlas_search(
        &self,
        principal: &OAuthPrincipal,
        arguments: &Map<String, Value>,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        self.workflow.search(
            &principal.client_id,
            text_or(arguments, "capability", ""),
            text_or(arguments, "resource", ""),
            text_or(arguments, "query", ""),
            usize_value(arguments, "limit", 20)?,
            Some(trace_id),
        )
    }

    fn rethlas_retrieve(
        &self,
        principal: &OAuthPrincipal,
        arguments: &Map<String, Value>,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        self.workflow.retrieve(
            &principal.client_id,
            text_or(arguments, "capability", ""),
            text_or(arguments, "query", ""),
            text_or(arguments, "operation", "theorem_search"),
            text_or(arguments, "author", ""),
            text_or(arguments, "title", ""),
            text_or(arguments, "keywords", ""),
            text_or(arguments, "search_intent", "theorem"),
            usize_value(arguments, "num_results", 10)?,
            Some(trace_id),
        )
    }

    fn rethlas_commit(
        &self,
        principal: &OAuthPrincipal,
        arguments: &Map<String, Value>,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        let payload = arguments
            .get("payload")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        if arguments.contains_key("payload") && !arguments["payload"].is_object() {
            return Err(validation("payload must be an object"));
        }
        self.workflow.commit(
            &principal.client_id,
            text_or(arguments, "capability", ""),
            text_or(arguments, "action", ""),
            &Value::Object(payload),
            Some(trace_id),
        )
    }

    fn rethlas_step(
        &self,
        principal: &OAuthPrincipal,
        arguments: &Map<String, Value>,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        let run_id = text_or(arguments, "run_id", "");
        let capability = text_or(arguments, "capability", "");
        let writes = arguments
            .get("writes")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if arguments.contains_key("writes") && !arguments["writes"].is_array() {
            return Err(validation("writes must be an array"));
        }
        let action = text_or(arguments, "action", "");
        let payload = arguments
            .get("payload")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        if !payload.is_object() {
            return Err(validation("payload must be an object"));
        }
        if action.is_empty() && writes.is_empty() && capability.is_empty() {
            let result = self
                .workflow
                .next_task(&principal.client_id, run_id, Some(trace_id))?;
            return self.attach_done_export_if_needed(principal, result, trace_id);
        }
        if capability.is_empty() {
            return Err(validation(
                "capability is required when submitting a Rethlas step",
            ));
        }
        self.capabilities.validate(
            capability,
            &principal.client_id,
            "commit",
            "workflow",
            trace_id,
            Some(run_id),
        )?;
        if !writes.is_empty() && action.is_empty() {
            return Err(validation("action is required when writes are submitted"));
        }
        let mut write_results = Vec::new();
        for (index, item) in writes.iter().enumerate() {
            let result = (|| {
                let object = item
                    .as_object()
                    .ok_or_else(|| validation("each write must be an object"))?;
                self.workflow.write(
                    &principal.client_id,
                    capability,
                    text_or(object, "resource", ""),
                    object.get("content").unwrap_or(&Value::Null),
                    Some(trace_id),
                )
            })();
            match result {
                Ok(value) => write_results.push(value),
                Err(error) if recoverable_error(&error) => {
                    return self.recoverable_step(
                        principal,
                        run_id,
                        capability,
                        error,
                        &write_results,
                        trace_id,
                        Some(serde_json::json!({
                            "index":index,
                            "resource":item.get("resource").and_then(Value::as_str).unwrap_or_default()
                        })),
                    );
                }
                Err(error) => return Err(error),
            }
        }
        if action.is_empty() {
            return Err(validation("action is required to complete a Rethlas step"));
        }
        let submission = match self.workflow.commit(
            &principal.client_id,
            capability,
            action,
            &payload,
            Some(trace_id),
        ) {
            Ok(value) => value,
            Err(error) if recoverable_error(&error) => {
                return self.recoverable_step(
                    principal,
                    run_id,
                    capability,
                    error,
                    &write_results,
                    trace_id,
                    None,
                );
            }
            Err(error) => return Err(error),
        };
        let next = self
            .workflow
            .next_task(&principal.client_id, run_id, Some(trace_id))?;
        let mut result = self.attach_done_export_if_needed(principal, next, trace_id)?;
        self.capabilities
            .revoke(capability, "superseded_by_rethlas_step", trace_id)?;
        let object = result
            .as_object_mut()
            .ok_or_else(|| internal("workflow next_task result must be an object"))?;
        object.insert("submission".to_owned(), submission);
        object.insert(
            "writes_applied".to_owned(),
            Value::from(write_results.len()),
        );
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn recoverable_step(
        &self,
        principal: &OAuthPrincipal,
        run_id: &str,
        capability: &str,
        mut error: ReCtmError,
        writes: &[Value],
        trace_id: &str,
        failed_write: Option<Value>,
    ) -> Result<Value, ReCtmError> {
        let mut current = self
            .workflow
            .next_task(&principal.client_id, run_id, Some(trace_id))?;
        self.capabilities
            .revoke(capability, "superseded_by_recoverable_step", trace_id)?;
        error.retryable = true;
        let mut submission = serde_json::json!({
            "ok":false,"complete":false,"recoverable":true,"retryable":true,"error":error.to_payload(),
            "writes_retained":!writes.is_empty(),
            "correction":"Use the fresh capability in this response and follow the returned task write_contract and commit_payload_schema. Do not replay retained writes unless a genuinely new logical record is needed."
        });
        if let Some(failed) = failed_write {
            submission["failed_write"] = failed;
        }
        let object = current
            .as_object_mut()
            .ok_or_else(|| internal("workflow next_task result must be an object"))?;
        object.insert("submission".to_owned(), submission);
        object.insert("writes_applied".to_owned(), Value::from(writes.len()));
        Ok(current)
    }

    fn rethlas_inspect(
        &self,
        principal: &OAuthPrincipal,
        arguments: &Map<String, Value>,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        let operation = text_or(arguments, "operation", "");
        match operation {
            "status" => self
                .workflow
                .status(&principal.client_id, text_or(arguments, "run_id", "")),
            "read" => self.rethlas_read(principal, arguments, trace_id),
            "search" => self.rethlas_search(principal, arguments, trace_id),
            "projects" => Ok(serde_json::json!({
                "ok":true,"projects":self.store.list_projects(&principal.client_id,i64_value(arguments,"limit",100)?)?
            })),
            "project_status" | "dependency_graph" => {
                let graph = self.store.project_dependency_graph(
                    text_or(arguments, "project_id", ""),
                    &principal.client_id,
                )?;
                merge_ok(graph)
            }
            "claim" => {
                let claim_id = text_or(arguments, "claim_id", "");
                Ok(serde_json::json!({
                    "ok":true,"claim":self.store.get_claim(claim_id,Some(&principal.client_id))?,
                    "revisions":self.store.list_claim_revisions(claim_id,&principal.client_id)?
                }))
            }
            "reference_audit" => {
                let run_id = text_or(arguments, "run_id", "");
                self.workflow.status(&principal.client_id, run_id)?;
                let mut references = Vec::new();
                for reference in self.store.list_run_references(run_id)? {
                    let mut object = reference.as_object().cloned().unwrap_or_default();
                    let id = object
                        .get("reference_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let snapshots = self
                        .store
                        .list_source_snapshots(id)?
                        .into_iter()
                        .map(|snapshot| {
                            serde_json::json!({
                                "source_snapshot_id":snapshot["source_snapshot_id"],"provider":snapshot["provider"],
                                "source_uri":snapshot["source_uri"],"content_sha256":snapshot["content_sha256"],"content_type":snapshot["content_type"]
                            })
                        })
                        .collect::<Vec<_>>();
                    object.insert("source_snapshots".to_owned(), Value::Array(snapshots));
                    references.push(Value::Object(object));
                }
                Ok(
                    serde_json::json!({"ok":true,"run_id":run_id,"references":references,"audits":self.store.list_reference_audits(run_id)?}),
                )
            }
            "theorem_search" => self.inspect_project_theorems(principal, arguments),
            _ => Err(validation(&format!(
                "operation must be one of {}",
                INSPECT_OPERATIONS.join(", ")
            ))),
        }
    }

    fn inspect_project_theorems(
        &self,
        principal: &OAuthPrincipal,
        arguments: &Map<String, Value>,
    ) -> Result<Value, ReCtmError> {
        let project_id = text_or(arguments, "project_id", "");
        let query = text_or(arguments, "query", "").trim().to_ascii_lowercase();
        if query.is_empty() {
            return Err(validation("query is required for theorem_search"));
        }
        let graph = self
            .store
            .project_dependency_graph(project_id, &principal.client_id)?;
        let claims = graph["claims"].as_array().cloned().unwrap_or_default();
        let mut results = Vec::new();
        for revision in graph["revisions"].as_array().into_iter().flatten() {
            let claim_id = revision
                .get("claim_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let claim = claims
                .iter()
                .find(|item| item.get("claim_id").and_then(Value::as_str) == Some(claim_id))
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            let conditions = revision
                .get("conditions")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ");
            let haystack = format!(
                "{} {} {}",
                claim
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                revision
                    .get("statement_tex")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                conditions
            )
            .to_ascii_lowercase();
            if haystack.contains(&query) {
                results.push(serde_json::json!({"claim":claim,"revision":revision}));
            }
        }
        results.truncate(usize_value(arguments, "limit", 20)?);
        Ok(serde_json::json!({"ok":true,"project_id":project_id,"query":query,"results":results}))
    }

    fn rethlas_control(
        &self,
        principal: &OAuthPrincipal,
        arguments: &Map<String, Value>,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        let action = text_or(arguments, "action", "");
        let run_id = text_or(arguments, "run_id", "");
        match action {
            "steer" => self.workflow.steer(
                &principal.client_id,
                run_id,
                text_or(arguments, "message", ""),
                Some(trace_id),
            ),
            "cancel" => self.workflow.cancel(
                &principal.client_id,
                run_id,
                text_or(arguments, "reason", "user_cancelled"),
                Some(trace_id),
            ),
            "project_create" => Ok(serde_json::json!({
                "ok":true,"project":self.store.create_project(
                    &principal.client_id,text_or(arguments,"title",""),optional_nonempty(arguments,"project_id"),
                    arguments.get("metadata").filter(|value|value.is_object()).unwrap_or(&serde_json::json!({}))
                )?
            })),
            "claim_create" => {
                let empty = serde_json::json!({});
                let claim = self.store.create_claim(
                    &principal.client_id,
                    text_or(arguments, "project_id", ""),
                    text_or(arguments, "title", ""),
                    optional_nonempty(arguments, "claim_id"),
                    arguments
                        .get("metadata")
                        .filter(|value| value.is_object())
                        .unwrap_or(&empty),
                )?;
                let statement = text_or(arguments, "statement_tex", "").trim();
                let revision = if statement.is_empty() {
                    Value::Null
                } else {
                    let conditions =
                        required_string_array(arguments.get("conditions"), "conditions")?;
                    self.store.create_open_claim_revision(
                        &principal.client_id,
                        claim["claim_id"].as_str().unwrap_or_default(),
                        statement,
                        &conditions,
                        None,
                    )?
                };
                Ok(serde_json::json!({"ok":true,"claim":claim,"revision":revision}))
            }
            "claim_revise" => {
                let conditions = required_string_array(arguments.get("conditions"), "conditions")?;
                Ok(serde_json::json!({
                    "ok":true,"revision":self.store.create_open_claim_revision(
                        &principal.client_id,text_or(arguments,"claim_id",""),text_or(arguments,"statement_tex",""),
                        &conditions,optional_nonempty(arguments,"expected_base_revision_id")
                    )?
                }))
            }
            _ => Err(validation(&format!(
                "action must be one of {}",
                CONTROL_ACTIONS.join(", ")
            ))),
        }
    }

    fn rethlas_artifact(
        &self,
        principal: &OAuthPrincipal,
        arguments: &Map<String, Value>,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        let action = text_or(arguments, "action", "");
        let artifact = text_or(arguments, "artifact", "");
        if action == "get" {
            if PROJECT_ARTIFACTS.contains(&artifact) {
                return self.project_artifact(
                    principal,
                    text_or(arguments, "project_id", ""),
                    artifact,
                );
            }
            return self.workflow.get_artifact(
                &principal.client_id,
                text_or(arguments, "run_id", ""),
                artifact,
            );
        }
        if action == "export" {
            if PROJECT_ARTIFACTS.contains(&artifact) {
                let project_id = text_or(arguments, "project_id", "");
                let project = self.project_artifact(principal, project_id, artifact)?;
                let path = optional_nonempty(arguments, "path")
                    .map(str::to_owned)
                    .unwrap_or_else(|| {
                        let suffix = if artifact == "project_manifest" {
                            "project_manifest.json"
                        } else {
                            "project_summary.tex"
                        };
                        format!("rethlas-projects/{project_id}/{suffix}")
                    });
                let text = if artifact == "project_manifest" {
                    serde_json::to_string_pretty(&project["content"]).map_err(json_error)? + "\n"
                } else {
                    project["content"].as_str().unwrap_or_default().to_owned()
                };
                let export = self.workspace.export_text(
                    &path,
                    &text,
                    optional_nonempty(arguments, "expected_sha256"),
                )?;
                return Ok(
                    serde_json::json!({"ok":true,"project_id":project_id,"artifact":artifact,"export":export}),
                );
            }
            return self.rethlas_export_final(principal, arguments, trace_id);
        }
        Err(validation("action must be get or export"))
    }

    fn project_artifact(
        &self,
        principal: &OAuthPrincipal,
        project_id: &str,
        artifact: &str,
    ) -> Result<Value, ReCtmError> {
        if project_id.is_empty() {
            return Err(validation("project_id is required for project artifacts"));
        }
        let graph = self
            .store
            .project_dependency_graph(project_id, &principal.client_id)?;
        let mut public_project = graph["project"].as_object().cloned().unwrap_or_default();
        public_project.remove("owner_id");
        let mut provenance = Map::new();
        for revision in graph["revisions"].as_array().into_iter().flatten() {
            let source_run = revision
                .get("source_run_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if source_run.is_empty() {
                continue;
            }
            let manifest = self.store.read_proof_manifest(source_run).ok();
            let audits = self.store.list_reference_audits(source_run)?;
            provenance.insert(
                revision["revision_id"].as_str().unwrap_or_default().to_owned(),
                serde_json::json!({
                    "source_run_id":source_run,
                    "proof_manifest_sha256":manifest.as_ref().map(|value|value["sha256"].clone()).unwrap_or(Value::Null),
                    "dependency_revision_ids":manifest.as_ref().and_then(|value|value["manifest"]["dependency_revision_ids"].as_array()).cloned().unwrap_or_default(),
                    "reference_ids":manifest.as_ref().and_then(|value|value["manifest"]["reference_ids"].as_array()).cloned().unwrap_or_default(),
                    "conditional_hypotheses":manifest.as_ref().and_then(|value|value["manifest"]["conditional_hypotheses"].as_array()).cloned().unwrap_or_default(),
                    "computational_evidence_count":manifest.as_ref().and_then(|value|value["manifest"]["computational_evidence"].as_array()).map_or(0,Vec::len),
                    "reference_audits":audits.into_iter().map(public_audit).collect::<Vec<_>>()
                }),
            );
        }
        let content = match artifact {
            "project_manifest" => serde_json::json!({
                "schema_version":"1.0","project":public_project,"claims":graph["claims"],"revisions":graph["revisions"],"edges":graph["edges"],"revision_provenance":provenance
            }),
            "project_summary_tex" => {
                let claims = graph["claims"].as_array().cloned().unwrap_or_default();
                let by_claim = claims
                    .into_iter()
                    .filter_map(|claim| Some((claim.get("claim_id")?.as_str()?.to_owned(), claim)))
                    .collect::<BTreeMap<_, _>>();
                let mut lines = vec![
                    r"\documentclass{article}".to_owned(),
                    r"\usepackage{amsmath,amsthm}".to_owned(),
                    r"\begin{document}".to_owned(),
                    format!(
                        r"\section*{{{}}}",
                        latex_escape(
                            public_project
                                .get("title")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                        )
                    ),
                ];
                for revision in graph["revisions"].as_array().into_iter().flatten() {
                    if revision.get("lifecycle_status").and_then(Value::as_str) != Some("ACTIVE") {
                        continue;
                    }
                    let claim_id = revision
                        .get("claim_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let title = by_claim
                        .get(claim_id)
                        .and_then(|value| value.get("title"))
                        .and_then(Value::as_str)
                        .unwrap_or(claim_id);
                    lines.push(format!(r"\subsection*{{{}}}", latex_escape(title)));
                    lines.push(format!(
                        r"\textbf{{Status:}} {}.\\",
                        latex_escape(
                            revision
                                .get("evidence_status")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                        )
                    ));
                    let conditions = revision
                        .get("conditions")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>();
                    if !conditions.is_empty() {
                        lines.push(format!(
                            r"\textbf{{Conditions:}} {}.\\",
                            latex_escape(&conditions.join(", "))
                        ));
                    }
                    if let Some(hash) = revision.get("proof_sha256").and_then(Value::as_str) {
                        if !hash.is_empty() {
                            lines.push(format!(
                                r"\textbf{{Proof SHA-256:}} \texttt{{{}}}.\\",
                                latex_escape(hash)
                            ));
                        }
                    }
                    if let Some(item) =
                        provenance.get(revision["revision_id"].as_str().unwrap_or_default())
                    {
                        let count = item["reference_audits"].as_array().map_or(0, Vec::len);
                        lines.push(format!(r"\textbf{{Audited references:}} {count}.\\"));
                    }
                    lines.push(
                        revision
                            .get("statement_tex")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                    );
                    lines.push(String::new());
                }
                lines.push(r"\end{document}".to_owned());
                let text = lines.join("\n") + "\n";
                let errors = static_latex_errors(&text)?;
                if !errors.is_empty() {
                    return Err(ReCtmError::new("PROJECT_SUMMARY_LATEX_UNSAFE","Project summary contains LaTeX operations that are unsafe for a portable artifact.").with_category(ErrorCategory::Validation).with_details(serde_json::json!({"errors":errors})));
                }
                Value::String(text)
            }
            _ => {
                return Err(validation_details(
                    "unknown project artifact",
                    serde_json::json!({"artifact":artifact}),
                ));
            }
        };
        Ok(
            serde_json::json!({"ok":true,"project_id":project_id,"artifact":artifact,"content":content}),
        )
    }

    fn rethlas_export_final(
        &self,
        principal: &OAuthPrincipal,
        arguments: &Map<String, Value>,
        _trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        let run_id = text_or(arguments, "run_id", "");
        let artifact = self
            .workflow
            .get_artifact(&principal.client_id, run_id, "final_tex")?;
        let content = artifact["content"].as_str().unwrap_or_default();
        let requested = optional_nonempty(arguments, "path");
        let export_path = requested
            .map(str::to_owned)
            .or_else(|| {
                artifact
                    .get("workspace_export_path")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| format!("rethlas-output/{run_id}/proof_verified.tex"));
        let export = if requested.is_some() {
            self.workspace.export_text(
                &export_path,
                content,
                optional_nonempty(arguments, "expected_sha256"),
            )?
        } else {
            self.workspace
                .ensure_verified_latex(&export_path, content)?
        };
        Ok(
            serde_json::json!({"ok":true,"run_id":run_id,"artifact":"final_tex","workspace_export_path":export_path,"export":export,"workflow_authority_inherited_by_native":false}),
        )
    }
    fn attach_done_export_if_needed(
        &self,
        principal: &OAuthPrincipal,
        result: Value,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        if result.get("state").and_then(Value::as_str) == Some("done")
            && result.get("terminal").and_then(Value::as_bool) == Some(true)
        {
            return self.attach_automatic_final_export(principal, result, trace_id);
        }
        Ok(result)
    }
    fn attach_automatic_final_export(
        &self,
        principal: &OAuthPrincipal,
        mut result: Value,
        _trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        let run_id = result
            .get("run_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let artifact = self
            .workflow
            .get_artifact(&principal.client_id, &run_id, "final_tex")?;
        let export_path = result
            .get("workspace_export_path")
            .or_else(|| artifact.get("workspace_export_path"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("rethlas-output/{run_id}/proof_verified.tex"));
        let export = self.workspace.ensure_verified_latex(
            &export_path,
            artifact["content"].as_str().unwrap_or_default(),
        );
        let object = result
            .as_object_mut()
            .ok_or_else(|| internal("workflow result must be an object"))?;
        object.insert("workspace_export_path".into(), Value::String(export_path));
        match export {
            Ok(value) => {
                object.insert("workspace_export".into(), value);
                object.insert("final_artifact_available".into(), Value::Bool(true));
                object.insert(
                    "workflow_authority_inherited_by_native".into(),
                    Value::Bool(false),
                );
            }
            Err(error) => {
                object.insert(
                    "workspace_export".into(),
                    serde_json::json!({"ok":false,"error":error.to_payload()}),
                );
                object.insert("final_artifact_available".into(), Value::Bool(true));
            }
        }
        Ok(result)
    }
}

impl ToolBackend for RuntimeToolBackend {
    fn call(
        &self,
        name: &str,
        arguments: &Map<String, Value>,
        principal: &OAuthPrincipal,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        self.emit(serde_json::json!({
            "event_type":"tool.call_started",
            "trace_id":trace_id,
            "decision":"allow",
            "reason":"oauth_principal_and_registered_tool",
            "details":{"tool":name,"argument_keys":arguments.keys().collect::<Vec<_>>()}
        }));
        let (payload, is_error) = match self.dispatch(name, arguments, principal, trace_id) {
            Ok(value) => (ensure_ok(value), false),
            Err(error) => (
                serde_json::json!({"ok":false,"error":error.to_payload(),"trace_id":trace_id}),
                true,
            ),
        };
        self.emit(serde_json::json!({
            "event_type":if is_error {"tool.call_failed"} else {"tool.call_finished"},
            "trace_id":trace_id,
            "decision":if is_error {"error"} else {"allow"},
            "reason":if is_error {"tool_reported_error"} else {"tool_completed"},
            "details":{"tool":name}
        }));
        Ok(tool_result(name, payload, is_error))
    }
}

fn tool_result(name: &str, mut payload: Value, is_error: bool) -> Value {
    if !payload.is_object() {
        payload = serde_json::json!({"ok":!is_error,"result":payload});
    }
    let Some(object) = payload.as_object_mut() else {
        return serde_json::json!({
            "content":[{"type":"text","text":"INTERNAL_ERROR: Tool result normalization failed."}],
            "structuredContent":{"ok":false,"error":{"code":"INTERNAL_ERROR","message":"Tool result normalization failed.","category":"internal","retryable":false,"details":{}}},
            "isError":true
        });
    };
    let image = object.remove("_mcp_image_data");
    let text = if is_error {
        let error = object.get("error").and_then(Value::as_object);
        format!(
            "{}: {}",
            error
                .and_then(|e| e.get("code"))
                .and_then(Value::as_str)
                .unwrap_or("TOOL_ERROR"),
            error
                .and_then(|e| e.get("message"))
                .and_then(Value::as_str)
                .unwrap_or("Tool failed.")
        )
    } else {
        render_summary(name, object)
    };
    let mut content = vec![serde_json::json!({"type":"text","text":text})];
    if name == "view_image" {
        if let Some(data) = image.and_then(|value| value.as_str().map(str::to_owned)) {
            if !data.is_empty() {
                content.push(serde_json::json!({"type":"image","data":data,"mimeType":object.get("mime_type").and_then(Value::as_str).unwrap_or("application/octet-stream")}));
            }
        }
    }
    serde_json::json!({"content":content,"structuredContent":Value::Object(object.clone()),"isError":is_error})
}
fn render_summary(name: &str, payload: &Map<String, Value>) -> String {
    if name == "rethlas_start" {
        return format!(
            "Run {} started; verified LaTeX will be written to {} when the workflow reaches done.",
            json_text(payload, "run_id"),
            json_text(payload, "workspace_export_path")
        );
    }
    if matches!(name, "rethlas_step" | "rethlas_next") {
        if name == "rethlas_step" {
            if let Some(sub) = payload.get("submission").and_then(Value::as_object) {
                if let Some(error) = sub.get("error").and_then(Value::as_object) {
                    let retained =
                        if sub.get("writes_retained").and_then(Value::as_bool) == Some(true) {
                            " Successful logical writes were retained; do not replay them."
                        } else {
                            ""
                        };
                    let recovery = if sub.get("recoverable").and_then(Value::as_bool) == Some(true)
                    {
                        " Continue with the fresh capability and the returned task contract."
                    } else {
                        ""
                    };
                    return format!(
                        "Run {} remains in {}; submission needs correction: {}: {}.{retained}{recovery}",
                        json_text(payload, "run_id"),
                        json_text(payload, "state"),
                        json_text(error, "code"),
                        json_text(error, "message")
                    );
                }
                if sub.get("complete").and_then(Value::as_bool) == Some(false) {
                    let ids = sub
                        .get("missing_screening")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|v| {
                            Some(format!(
                                "{}.{}",
                                v.get("plan_id")?.as_str()?,
                                v.get("subgoal_id")?.as_str()?
                            ))
                        })
                        .collect::<Vec<_>>();
                    return format!(
                        "Run {} remains in direct_proving; accepted screening progress. Still missing: {}.",
                        json_text(payload, "run_id"),
                        if ids.is_empty() {
                            "see structuredContent".to_owned()
                        } else {
                            ids.join(", ")
                        }
                    );
                }
            }
        }
        if payload.get("state").and_then(Value::as_str) == Some("done") {
            if payload
                .get("workspace_export")
                .and_then(Value::as_object)
                .and_then(|v| v.get("ok"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                return format!(
                    "Run {} is done and the verified LaTeX was written to {}.",
                    json_text(payload, "run_id"),
                    json_text(payload, "workspace_export_path")
                );
            }
            return format!(
                "Run {} is done; final LaTeX is available, but automatic workspace export needs attention at {}.",
                json_text(payload, "run_id"),
                json_text(payload, "workspace_export_path")
            );
        }
        return format!(
            "Run {} is in {} for role {}.",
            json_text(payload, "run_id"),
            json_text(payload, "state"),
            payload
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("none")
        );
    }
    if matches!(name, "rethlas_inspect" | "rethlas_status")
        && !json_text(payload, "state").is_empty()
    {
        return format!(
            "Run {}: {} ({}).",
            json_text(payload, "run_id"),
            json_text(payload, "state"),
            json_text(payload, "status")
        );
    }
    if name == "rethlas_get_artifact"
        && payload.get("artifact").and_then(Value::as_str) == Some("final_tex")
    {
        return format!(
            "Final verified LaTeX for run {} is available; workspace path: {}.",
            json_text(payload, "run_id"),
            json_text(payload, "workspace_export_path")
        );
    }
    if name == "server_info" {
        return format!(
            "MTM {} with {} fixed tools.",
            json_text(payload, "version"),
            payload
                .get("tool_count")
                .and_then(Value::as_u64)
                .unwrap_or_default()
        );
    }
    if let Some(summary) = payload
        .get("summary")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
    {
        return summary.to_owned();
    }
    format!("{name} completed.")
}
fn public_audit(value: Value) -> Value {
    let keys = [
        "reference_id",
        "disposition",
        "evidence_basis",
        "evidence_locator",
        "material",
        "assumptions_checked",
        "notation_checked",
        "source_checked",
        "independently_rederived",
        "title",
        "paper_id",
        "arxiv_id",
        "doi",
        "theorem_id",
        "source_uri",
        "source_sha256",
        "content_sha256",
    ];
    let mut result = Map::new();
    for key in keys {
        result.insert(
            key.to_owned(),
            value.get(key).cloned().unwrap_or(Value::Null),
        );
    }
    Value::Object(result)
}
fn latex_escape(value: &str) -> String {
    value
        .replace('\\', r"\textbackslash{}")
        .replace('&', r"\&")
        .replace('%', r"\%")
        .replace('$', r"\$")
        .replace('#', r"\#")
        .replace('_', r"\_")
        .replace('{', r"\{")
        .replace('}', r"\}")
}
fn merge_ok(mut value: Value) -> Result<Value, ReCtmError> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| internal("project graph must be an object"))?;
    object.insert("ok".to_owned(), Value::Bool(true));
    Ok(value)
}
fn ensure_ok(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.entry("ok").or_insert(Value::Bool(true));
        value
    } else {
        serde_json::json!({"ok":true,"result":value})
    }
}
fn recoverable_error(error: &ReCtmError) -> bool {
    matches!(
        error.category,
        ErrorCategory::Validation | ErrorCategory::Conflict
    )
}
fn required_text<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, ReCtmError> {
    map.get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| validation(&format!("{key} is required")))
}
fn text_or<'a>(map: &'a Map<String, Value>, key: &str, default: &'a str) -> &'a str {
    map.get(key).and_then(Value::as_str).unwrap_or(default)
}
fn optional_nonempty<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}
fn usize_value(map: &Map<String, Value>, key: &str, default: usize) -> Result<usize, ReCtmError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(value) => value
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .ok_or_else(|| validation(&format!("{key} must be a non-negative integer"))),
    }
}
fn i64_value(map: &Map<String, Value>, key: &str, default: i64) -> Result<i64, ReCtmError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(value) => value
            .as_i64()
            .ok_or_else(|| validation(&format!("{key} must be an integer"))),
    }
}
fn required_string_array(value: Option<&Value>, label: &str) -> Result<Vec<String>, ReCtmError> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => Ok(items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| validation(&format!("{label} must be an array")))
            })
            .collect::<Result<Vec<_>, _>>()?),
        Some(_) => Err(validation(&format!("{label} must be an array"))),
    }
}
fn json_text<'a>(map: &'a Map<String, Value>, key: &str) -> &'a str {
    map.get(key).and_then(Value::as_str).unwrap_or_default()
}
fn validation(message: &str) -> ReCtmError {
    ReCtmError::new("INVALID_ARGUMENT", message).with_category(ErrorCategory::Validation)
}
fn validation_details(message: &str, details: Value) -> ReCtmError {
    validation(message).with_details(details)
}
fn internal(message: &str) -> ReCtmError {
    ReCtmError::new("INTERNAL_ERROR", message).with_category(ErrorCategory::Internal)
}
fn json_error(error: serde_json::Error) -> ReCtmError {
    ReCtmError::new("JSON_ERROR", error.to_string()).with_category(ErrorCategory::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tool_result_matches_mcp_shape() {
        let result = tool_result(
            "server_info",
            serde_json::json!({"ok":true,"version":"0.3.0","tool_count":24}),
            false,
        );
        assert_eq!(result["isError"], false);
        assert!(result["content"].is_array());
        assert_eq!(result["structuredContent"]["tool_count"], 24);
    }
}
