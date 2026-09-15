//! Mechanical branch preparation commits its database effects as one unit.
//! Snapshot and assignment files are prepared by workflow before this transaction.
use super::*;

pub struct PreparedBranch {
    pub branch_id: String,
    pub plan_id: String,
    pub domain_id: String,
    pub snapshot_id: String,
    pub order_index: i64,
    pub domain_metadata: Value,
    pub branch_metadata: Value,
}

pub struct BranchPreparation<'a> {
    pub transition: TransitionRun<'a>,
    pub expected_branch_requests: &'a Value,
    pub snapshot_id: &'a str,
    pub branches: &'a [PreparedBranch],
}

impl StateStore {
    pub fn complete_latex_gate(
        &self,
        transition: TransitionRun<'_>,
        expected_metadata: &Value,
        latex_result: &Value,
    ) -> Result<Value, ReCtmError> {
        if transition.expected_state != "latex_validate"
            || !matches!(transition.after_state, "verify" | "repair")
            || transition.actor != "latex_gate"
            || !transition.increment_epoch
            || transition.round_delta != 0
            || transition.latex_passed.is_none()
            || !latex_result.is_object()
        {
            return Err(conflict());
        }
        self.immediate(|tx| {
            let run = query_one_on(
                tx,
                "SELECT * FROM runs WHERE run_id=?",
                [transition.run_id],
                &["metadata_json"],
            )?
            .ok_or_else(conflict)?;
            if run["state"] != "latex_validate" || run["metadata"] != *expected_metadata {
                return Err(conflict());
            }
            let mut metadata = run["metadata"].as_object().cloned().ok_or_else(conflict)?;
            metadata.insert("latex_result".to_owned(), latex_result.clone());
            let now = self.runtime.clock.now_iso()?;
            tx.execute(
                "UPDATE runs SET metadata_json=?,updated_at=? WHERE run_id=? AND state='latex_validate'",
                params![canonical_json(&Value::Object(metadata))?, now, transition.run_id],
            )
            .map_err(sql_error)?;
            task_transitions::transition_on(tx, &transition, &now)
        })
    }

    pub fn complete_branch_preparation(
        &self,
        preparation: BranchPreparation<'_>,
    ) -> Result<Value, ReCtmError> {
        let request = &preparation.transition;
        if request.expected_state != "branch_prepare"
            || request.after_state != "branch_run"
            || request.actor != "system"
            || !request.increment_epoch
            || request.round_delta != 1
            || preparation.branches.is_empty()
            || preparation.branches.len() > 64
            || !preparation.expected_branch_requests.is_array()
            || preparation
                .expected_branch_requests
                .as_array()
                .map(Vec::len)
                != Some(preparation.branches.len())
            || preparation.snapshot_id.len() > 128
        {
            return Err(conflict());
        }
        self.immediate(|tx| {
            let run = query_one_on(
                tx,
                "SELECT * FROM runs WHERE run_id=?",
                [request.run_id],
                &["metadata_json"],
            )?
            .ok_or_else(conflict)?;
            if run["state"] != "branch_prepare"
                || run["metadata"]["branch_requests"] != *preparation.expected_branch_requests
            {
                return Err(conflict());
            }
            let round = integer_value(run.as_object().ok_or_else(conflict)?, "round_index")?
                .checked_add(1)
                .ok_or_else(conflict)?;
            let legacy_prefix = format!("round-{round}-%");
            let legacy: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM branches WHERE run_id=? AND snapshot_id LIKE ?",
                    params![request.run_id, legacy_prefix],
                    |row| row.get(0),
                )
                .map_err(sql_error)?;
            if legacy != 0 {
                return Err(ReCtmError::new(
                    "MECHANICAL_LEGACY_PARTIAL_UNKNOWN",
                    "A prior branch-preparation attempt left database rows without a completed transition; automatic adoption is refused.",
                )
                .with_category(ErrorCategory::Conflict)
                .with_retryable(false));
            }
            let now = self.runtime.clock.now_iso()?;
            for branch in preparation.branches {
                if branch.snapshot_id != preparation.snapshot_id
                    || branch.order_index < 0
                    || branch.order_index >= preparation.branches.len() as i64
                {
                    return Err(conflict());
                }
                tx.execute(
                    "INSERT INTO domains(domain_id,run_id,role,status,snapshot_id,order_index,metadata_json,created_at) VALUES(?,?,'branch','open',?,?,?,?)",
                    params![
                        branch.domain_id,
                        request.run_id,
                        branch.snapshot_id,
                        branch.order_index,
                        canonical_json(&branch.domain_metadata)?,
                        now,
                    ],
                )
                .map_err(sql_error)?;
                tx.execute(
                    "INSERT INTO branches(branch_id,run_id,plan_id,domain_id,snapshot_id,order_index,status,metadata_json,created_at) VALUES(?,?,?,?,?,?,'pending',?,?)",
                    params![
                        branch.branch_id,
                        request.run_id,
                        branch.plan_id,
                        branch.domain_id,
                        branch.snapshot_id,
                        branch.order_index,
                        canonical_json(&branch.branch_metadata)?,
                        now,
                    ],
                )
                .map_err(sql_error)?;
            }
            let mut metadata = run["metadata"].as_object().cloned().ok_or_else(conflict)?;
            metadata.insert(
                "active_snapshot_id".to_owned(),
                Value::String(preparation.snapshot_id.to_owned()),
            );
            metadata.insert("branch_requests".to_owned(), Value::Array(Vec::new()));
            tx.execute(
                "UPDATE runs SET metadata_json=?,updated_at=? WHERE run_id=? AND state='branch_prepare'",
                params![canonical_json(&Value::Object(metadata))?, now, request.run_id],
            )
            .map_err(sql_error)?;
            task_transitions::transition_on(tx, request, &now)
        })
    }
}

fn conflict() -> ReCtmError {
    ReCtmError::new(
        "MECHANICAL_TRANSITION_CONFLICT",
        "Mechanical branch-preparation facts changed; no database effects were committed.",
    )
    .with_category(ErrorCategory::Conflict)
    .with_retryable(false)
}
