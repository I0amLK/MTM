//! Resumable keyed initialization; no takeover of legacy pending creations.
use super::*;
use crate::vault::PreparedInitialization;
use mtm_storage::CreationInitialization;

impl WorkflowEngine {
    pub(super) fn start_resumable(
        &self,
        request: StartRequest<'_>,
        identity: CreationIdentity,
    ) -> Result<Value, ReCtmError> {
        // Historical completed receipts are not re-initialized under new input rules.
        if let Some(receipt) = self.store.creation_receipt(request.owner_id, &identity)? {
            if receipt.is_completed() {
                return receipt.response(true);
            }
        }
        // Validate all file inputs before reserving a new key or touching the vault.
        let prepared = PreparedInitialization::new(request.problem_tex, request.references)?;
        let problem_id = safe_component(request.problem_id.unwrap_or("problem"));
        let proposed = format!(
            "run-{problem_id}-{}",
            self.store.runtime().ids.token_hex(6)?
        );
        let (reservation, resumed) =
            match self
                .store
                .reserve_creation(request.owner_id, &identity, &proposed)?
            {
                CreationSlot::Reserved(value) => (value, false),
                CreationSlot::Existing(receipt) if receipt.is_completed() => {
                    return receipt.response(true);
                }
                CreationSlot::Existing(receipt) => (self.store.resume_creation(receipt)?, true),
            };
        let run_id = reservation.run_id();
        let export = request
            .workspace_export_path
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("rethlas-output/{run_id}/proof_verified.tex"));
        let metadata = serde_json::json!({
            "native_mode_at_creation":request.native_mode,"problem_sha256":prepared.problem_sha256,
            "reference_count":prepared.references.len(),"manual_validation_required":true,
            "active_plans":[],"branch_requests":[],"latex_result":Value::Null,
            "workspace_export_path":export,"workflow_protocol_version":request.workflow_protocol_version,
            "requested_workflow_mode":request.workflow_mode,
            "effective_workflow_mode":if request.workflow_mode=="full" {"full"} else {"pending"},
            "compact_verifier_failures":0,"project_id":request.project_id,
            "project_snapshot_id":Value::Null,"target_claim_id":request.target_claim_id,
        });
        let preparation = (|| {
            let guard = self.vault.lock_initialization(run_id)?;
            // Another attempt may have completed between the initial lookup and lock.
            if self.store.observe_creation(&reservation)?.is_completed() {
                return Ok(false);
            }
            guard.publish(
                &prepared,
                &serde_json::json!({"problem_id":problem_id,
                "owner_id":request.owner_id,"created_at":reservation.created_at()}),
            )?;
            self.store.prepare_creation_records(
                &reservation,
                &CreationInitialization {
                    problem_id: &problem_id,
                    metadata: &metadata,
                    project_id: request.project_id,
                    target_claim_id: request.target_claim_id,
                    workflow_mode: request.workflow_mode,
                    register_result: request.register_result,
                    references: &prepared.references,
                },
            )?;
            Ok::<bool, ReCtmError>(true)
        })();
        // Never call observer/transition/next-task/LaTeX while holding the file lock.
        let transitioned = match preparation {
            Ok(true) => self
                .transition(TransitionInput {
                    run_id,
                    before: WorkflowState::Created,
                    after: WorkflowState::Assess,
                    trace_id: reservation.execution_id(),
                    actor: "system",
                    reason: "run_initialized",
                    evidence: &serde_json::json!({}),
                    latex_passed: None,
                    verdict: None,
                    status: None,
                    sealed: None,
                    round_delta: 0,
                })
                .map(|_| true),
            Ok(false) => Ok(false),
            Err(error) => Err(error),
        };
        let observed = self.store.observe_creation(&reservation)?;
        if !observed.is_completed() {
            if let Err(error) = transitioned {
                return Err(error);
            }
            return observed.response(true);
        }
        let won = transitioned.as_ref().is_ok_and(|won| *won);
        let mut response = observed.response(!won)?;
        response["creation_resumed"] = Value::Bool(resumed && won);
        if won {
            response["workspace_export_path"] = Value::from(export);
            response["workflow_protocol_version"] = Value::from(request.workflow_protocol_version);
            response["workflow_mode"] = Value::from(request.workflow_mode);
            response["manual_validation_required"] = Value::Bool(true);
            response["project_id"] = request.project_id.map(Value::from).unwrap_or(Value::Null);
            response["target_claim_id"] = request
                .target_claim_id
                .map(Value::from)
                .unwrap_or(Value::Null);
            let run = self.store.get_run(run_id)?;
            response["project_snapshot_id"] = run["metadata"]["project_snapshot_id"].clone();
        }
        Ok(response)
    }
}
