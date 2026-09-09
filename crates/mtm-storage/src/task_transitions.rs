//! One transaction for task-domain closure, database effects and the transition.
//! WorkflowEngine validates the graph; no file I/O or callback runs here.
use super::*;
use crate::CapabilityClaims;

pub struct BranchSeal<'a> {
    pub branch_id: &'a str,
    pub result_path: &'a str,
}

pub struct TaskTransition<'a> {
    pub transition: TransitionRun<'a>,
    pub expected_metadata: Option<&'a Value>,
    pub metadata_updates: &'a Map<String, Value>,
    pub project_mode: Option<&'a str>,
    pub branch: Option<BranchSeal<'a>>,
}

impl StateStore {
    pub fn transition_task(
        &self,
        claims: &CapabilityClaims,
        task: TaskTransition<'_>,
    ) -> Result<Value, ReCtmError> {
        let request = &task.transition;
        if request.run_id != claims.run_id()
            || request.expected_state != claims.issued_state().as_str()
            || request.actor != claims.role().as_str()
            || !request.increment_epoch
            || task
                .project_mode
                .is_some_and(|mode| !matches!(mode, "compact" | "full"))
            || canonical_json(&Value::Object(task.metadata_updates.clone()))?.len() > 1024 * 1024
        {
            return Err(conflict());
        }
        self.immediate(|tx| {
            step_receipts::recheck_authority(tx, claims, self.runtime.clock.unix_seconds()?)?;
            let _ = step_receipts::check_task(tx, claims, request.trace_id)?;
            let now = self.runtime.clock.now_iso()?;
            let before = run_on(tx, claims.run_id())?;
            if task.expected_metadata.is_some_and(|expected| before["metadata"] != *expected) {
                return Err(conflict());
            }
            if !task.metadata_updates.is_empty() {
                let mut metadata = before["metadata"].as_object().cloned().ok_or_else(conflict)?;
                metadata.extend(task.metadata_updates.clone());
                tx.execute("UPDATE runs SET metadata_json=?,updated_at=? WHERE run_id=?",
                    params![canonical_json(&Value::Object(metadata))?,now,claims.run_id()]).map_err(sql_error)?;
            }
            if let Some(mode) = task.project_mode {
                tx.execute("UPDATE project_runs SET effective_workflow_mode=?,updated_at=? WHERE run_id=?",
                    params![mode,now,claims.run_id()]).map_err(sql_error)?;
            }
            if let Some(branch) = task.branch {
                if claims.role() != mtm_contracts::WorkflowRole::Branch || branch.result_path.len() > 4096 {
                    return Err(conflict());
                }
                let changed = tx.execute("UPDATE branches SET status='sealed',result_path=?,sealed_at=? WHERE branch_id=? AND run_id=? AND domain_id=? AND status<>'sealed'",
                    params![branch.result_path,now,branch.branch_id,claims.run_id(),claims.domain_id()]).map_err(sql_error)?;
                if changed != 1 { return Err(conflict()); }
                let unsealed: i64 = tx.query_row("SELECT COUNT(*) FROM branches WHERE run_id=? AND status<>'sealed'", [claims.run_id()], |r|r.get(0)).map_err(sql_error)?;
                let expected_after = if unsealed == 0 {"branch_join"} else {"branch_run"};
                if request.after_state != expected_after { return Err(conflict()); }
            }
            let changed = tx.execute("UPDATE domains SET status='sealed',sealed_at=? WHERE domain_id=? AND run_id=? AND status='open'",
                params![now,claims.domain_id(),claims.run_id()]).map_err(sql_error)?;
            if changed != 1 { return Err(conflict()); }
            tx.execute("UPDATE capabilities SET revoked=1,revoked_at=?,revoke_reason='domain_sealed' WHERE domain_id=? AND revoked=0",
                params![now,claims.domain_id()]).map_err(sql_error)?;
            transition_on(tx, request, &now)
        })
    }
}

fn run_on(tx: &Connection, run: &str) -> Result<Value, ReCtmError> {
    query_one_on(
        tx,
        "SELECT * FROM runs WHERE run_id=?",
        [run],
        &["metadata_json"],
    )?
    .ok_or_else(|| {
        ReCtmError::new("RUN_NOT_FOUND", "Unknown run.").with_category(ErrorCategory::NotFound)
    })
}

pub(super) fn transition_on(
    tx: &Transaction<'_>,
    request: &TransitionRun<'_>,
    now: &str,
) -> Result<Value, ReCtmError> {
    let row = run_on(tx, request.run_id)?;
    let object = row.as_object().ok_or_else(internal_row_error)?;
    let actual_state = text_value(object, "state")?;
    if actual_state != request.expected_state {
        return Err(ReCtmError::new("STATE_CONFLICT", "The run changed state before this transition was committed.")
            .with_category(ErrorCategory::Conflict).with_retryable(true)
            .with_details(serde_json::json!({"run_id":request.run_id,"expected":request.expected_state,"actual":actual_state})));
    }
    let sequence = integer_value(object, "transition_seq")?
        .checked_add(1)
        .ok_or_else(conflict)?;
    let epoch = integer_value(object, "epoch")?
        .checked_add(i64::from(request.increment_epoch))
        .ok_or_else(conflict)?;
    let round_index = integer_value(object, "round_index")?
        .checked_add(request.round_delta)
        .ok_or_else(conflict)?;
    let status = request.status.unwrap_or(text_value(object, "status")?);
    let latex_passed = request
        .latex_passed
        .map(i64::from)
        .unwrap_or(boolean_storage_value(object, "latex_passed")?);
    let verdict = request
        .verdict
        .map(ToOwned::to_owned)
        .or_else(|| optional_text_value(object, "verdict"));
    let sealed = request
        .sealed
        .map(i64::from)
        .unwrap_or(boolean_storage_value(object, "sealed")?);
    tx.execute("UPDATE runs SET state=?,epoch=?,transition_seq=?,round_index=?,updated_at=?,status=?,latex_passed=?,verdict=?,sealed=? WHERE run_id=?",
        params![request.after_state,epoch,sequence,round_index,now,status,latex_passed,verdict,sealed,request.run_id]).map_err(sql_error)?;
    tx.execute("INSERT INTO transitions(run_id,sequence,trace_id,before_state,after_state,actor,reason,evidence_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        params![request.run_id,sequence,request.trace_id,request.expected_state,request.after_state,request.actor,request.reason,canonical_json(request.evidence)?,now]).map_err(sql_error)?;
    if request.increment_epoch {
        tx.execute("UPDATE capabilities SET revoked=1,revoked_at=?,revoke_reason='run_epoch_advanced' WHERE run_id=? AND revoked=0",
            params![now,request.run_id]).map_err(sql_error)?;
    }
    creation_receipts::record_initialization(tx, request, object, now)?;
    step_receipts::record_transition(tx, request, object, now)?;
    run_on(tx, request.run_id)
}

fn conflict() -> ReCtmError {
    ReCtmError::new(
        "TASK_TRANSITION_CONFLICT",
        "Task transition bindings or database facts changed; no transaction was committed.",
    )
    .with_category(ErrorCategory::Conflict)
    .with_retryable(false)
}
