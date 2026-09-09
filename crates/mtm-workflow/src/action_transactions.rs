//! Bounded database effects for the existing workflow transition authority.
use super::*;

pub(super) struct TaskEffects<'a> {
    pub(super) claims: &'a CapabilityClaims,
    pub(super) expected_metadata: Option<&'a Value>,
    pub(super) metadata_updates: Map<String, Value>,
    pub(super) project_mode: Option<&'a str>,
    pub(super) branch: Option<mtm_storage::BranchSeal<'a>>,
    pub(super) restartable_action: Option<mtm_storage::RestartableActionKind>,
}

impl<'a> TaskEffects<'a> {
    pub(super) fn new(claims: &'a CapabilityClaims) -> Self {
        Self {
            claims,
            expected_metadata: None,
            metadata_updates: Map::new(),
            project_mode: None,
            branch: None,
            restartable_action: None,
        }
    }
}

impl WorkflowEngine {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn seal_atomic_transition(
        &self,
        run: &Value,
        claims: &CapabilityClaims,
        after: WorkflowState,
        trace: &str,
        reason: &str,
        updates: Value,
        project_mode: Option<&str>,
    ) -> Result<Value, ReCtmError> {
        let mut effects = TaskEffects::new(claims);
        effects.expected_metadata = Some(&run["metadata"]);
        effects.metadata_updates = updates
            .as_object()
            .cloned()
            .ok_or_else(|| internal("action metadata must be an object"))?;
        effects.project_mode = project_mode;
        let empty = serde_json::json!({});
        let updated = self.transition_with_task(
            TransitionInput {
                run_id: claims.run_id(),
                before: workflow_state(text(run, "state")?)?,
                after,
                trace_id: trace,
                actor: role_name(claims.role()),
                reason,
                evidence: &empty,
                latex_passed: None,
                verdict: None,
                status: None,
                sealed: None,
                round_delta: 0,
            },
            Some(effects),
        )?;
        Ok(
            serde_json::json!({"run_id":claims.run_id(),"state":updated["state"],"verdict":updated["verdict"]}),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn seal_restartable_transition(
        &self,
        run: &Value,
        claims: &CapabilityClaims,
        after: WorkflowState,
        trace: &str,
        reason: &str,
        updates: Value,
        project_mode: Option<&str>,
        verdict: Option<&str>,
        action: mtm_storage::RestartableActionKind,
    ) -> Result<Value, ReCtmError> {
        let mut effects = TaskEffects::new(claims);
        effects.expected_metadata = Some(&run["metadata"]);
        effects.metadata_updates = updates
            .as_object()
            .cloned()
            .ok_or_else(|| internal("action metadata must be an object"))?;
        effects.project_mode = project_mode;
        effects.restartable_action = Some(action);
        let empty = serde_json::json!({});
        let updated = self.transition_with_task(
            TransitionInput {
                run_id: claims.run_id(),
                before: workflow_state(text(run, "state")?)?,
                after,
                trace_id: trace,
                actor: role_name(claims.role()),
                reason,
                evidence: &empty,
                latex_passed: None,
                verdict,
                status: None,
                sealed: None,
                round_delta: 0,
            },
            Some(effects),
        )?;
        Ok(
            serde_json::json!({"run_id":claims.run_id(),"state":updated["state"],"verdict":updated["verdict"]}),
        )
    }
}
