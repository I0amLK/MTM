//! Checkpoint evidence is fenced; elapsed time never licenses takeover.
use super::*;

pub struct SubmissionExecution {
    id: String,
    fingerprint: String,
}

impl SubmissionExecution {
    #[must_use]
    pub fn trace_id(&self) -> &str {
        &self.id
    }
}

impl StateStore {
    pub fn activate_submission(
        &self,
        reservation: &SubmissionReservation,
        authorized: &AuthorizedSubmission,
        writes: usize,
    ) -> Result<SubmissionExecution, ReCtmError> {
        if writes > 65_536
            || !reservation.receipt.matches_claims(&authorized.claims)
            || reservation.receipt.row.capability_sha256 != authorized.fingerprint
        {
            return Err(invalid_receipt());
        }
        self.immediate(|tx| {
            let receipt = current(tx, &reservation.receipt)?;
            if receipt.result().is_some() {
                return Err(receipt_error("SUBMISSION_NOT_STARTED", "This unstarted reservation was already resolved; no workflow writes were attempted."));
            }
            recheck_authority(tx, &authorized.claims, self.runtime.clock.unix_seconds()?)?;
            let id: Option<String> = tx.query_row(
                "SELECT execution_id FROM step_checkpoints WHERE capability_sha256=? AND phase='prepared'",
                [&authorized.fingerprint], |r| r.get(0),
            ).optional().map_err(sql_error)?;
            let id = id.ok_or_else(unknown)?;
            let changed = tx.execute(
                "UPDATE step_checkpoints SET phase='running',expected_writes=? WHERE capability_sha256=? AND execution_id=? AND phase='prepared'",
                params![writes as i64,authorized.fingerprint,id],
            ).map_err(sql_error)?;
            if changed != 1 { return Err(unknown()); }
            Ok(SubmissionExecution { id, fingerprint: authorized.fingerprint.clone() })
        })
    }

    pub fn checkpoint_submission_write(
        &self,
        execution: &SubmissionExecution,
        accepted: usize,
    ) -> Result<(), ReCtmError> {
        if accepted == 0 || accepted > 65_536 {
            return Err(invalid_receipt());
        }
        self.immediate(|tx| {
            let changed = tx.execute(
                "UPDATE step_checkpoints SET accepted_writes=? WHERE capability_sha256=? AND execution_id=? AND phase='running' AND accepted_writes=? AND expected_writes>=? AND EXISTS(SELECT 1 FROM step_receipts WHERE capability_sha256=? AND status='pending')",
                params![accepted as i64,execution.fingerprint,execution.id,(accepted-1) as i64,accepted as i64,execution.fingerprint],
            ).map_err(sql_error)?;
            if changed != 1 { return Err(invalid_receipt()); }
            Ok(())
        })
    }

    pub fn arm_submission_commit(&self, execution: &SubmissionExecution) -> Result<(), ReCtmError> {
        self.immediate(|tx| {
            let changed = tx.execute(
                "UPDATE step_checkpoints SET phase='commit_ready' WHERE capability_sha256=? AND execution_id=? AND phase='running' AND accepted_writes=expected_writes AND EXISTS(SELECT 1 FROM step_receipts WHERE capability_sha256=? AND status='pending')",
                params![execution.fingerprint,execution.id,execution.fingerprint],
            ).map_err(sql_error)?;
            if changed != 1 { return Err(invalid_receipt()); }
            Ok(())
        })
    }

    /// Read an owned execution's durable result even when task construction failed.
    pub fn observed_submission(
        &self,
        reservation: &SubmissionReservation,
    ) -> Result<SubmissionReceipt, ReCtmError> {
        let connection = self.lock_connection()?;
        current(&connection, &reservation.receipt)
    }

    /// Explicit reconciliation only: no execution, permission issuance or timeout takeover.
    pub fn reconcile_unstarted_submission(
        &self,
        receipt: SubmissionReceipt,
    ) -> Result<SubmissionReceipt, ReCtmError> {
        self.immediate(|tx| {
            let receipt = current(tx, &receipt)?;
            if receipt.result().is_some() { return Ok(receipt); }
            let prepared: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM step_checkpoints WHERE capability_sha256=? AND phase='prepared')",
                [&receipt.row.capability_sha256], |r| r.get(0),
            ).map_err(sql_error)?;
            if !prepared { return Err(unknown()); }
            let result = SubmissionResult {
                disposition: SubmissionDisposition::CorrectionRequired,
                state: receipt.row.issued_state, writes_applied: 0, complete: false,
                error_code: Some("SUBMISSION_NOT_STARTED".into()),
            };
            finish_on(tx, &receipt, &result, &self.runtime.clock.now_iso()?)
        })
    }

    /// A read-only diagnostic. Accepted count is a lower bound for unresolved work.
    pub fn pending_submission_status(&self, owner: &str, run: &str) -> Result<Value, ReCtmError> {
        let connection = self.lock_connection()?;
        let pending = query_one_on(
            &connection,
            "SELECT c.phase,c.accepted_writes FROM step_receipts r LEFT JOIN step_checkpoints c ON c.capability_sha256=r.capability_sha256 WHERE r.owner_id=? AND r.run_id=? AND r.status='pending'",
            [owner, run],
            &[],
        )?;
        Ok(match pending {
            None => Value::Null,
            Some(value) => serde_json::json!({"status":"pending",
                "phase":value["phase"].as_str().unwrap_or("legacy_unknown"),
                "accepted_caller_writes_lower_bound":value["accepted_writes"],
                "recover_unstarted_available":value["phase"]=="prepared",
                "automatic_retry":false,"grants_authority":false}),
        })
    }
}

pub(in crate::store) fn record_transition(
    tx: &Transaction<'_>,
    request: &TransitionRun<'_>,
    before: &Map<String, Value>,
    now: &str,
) -> Result<(), ReCtmError> {
    let row = query_one_on(
        tx,
        "SELECT r.* FROM step_receipts r JOIN step_checkpoints c ON c.capability_sha256=r.capability_sha256 WHERE c.execution_id=?",
        [request.trace_id],
        &[],
    )?;
    let Some(row) = row else {
        return Ok(());
    };
    let receipt = SubmissionReceipt::decode(row)?;
    let checkpoint = query_one_on(
        tx,
        "SELECT phase,expected_writes,accepted_writes FROM step_checkpoints WHERE execution_id=?",
        [request.trace_id],
        &[],
    )?
    .ok_or_else(invalid_receipt)?;
    if receipt.result().is_some()
        || checkpoint["phase"] != "commit_ready"
        || checkpoint["accepted_writes"] != checkpoint["expected_writes"]
        || receipt.row.run_id != request.run_id
        || receipt.row.role.as_str() != request.actor
        || receipt.row.issued_state.as_str() != request.expected_state
        || before.get("epoch").and_then(Value::as_i64) != Some(receipt.row.epoch)
        || before.get("owner_id").and_then(Value::as_str) != Some(receipt.row.owner_id.as_str())
    {
        return Err(invalid_receipt());
    }
    let result = SubmissionResult {
        disposition: SubmissionDisposition::Applied,
        state: serde_json::from_value(Value::from(request.after_state))
            .map_err(|_| invalid_receipt())?,
        writes_applied: checkpoint["accepted_writes"]
            .as_u64()
            .ok_or_else(invalid_receipt)?,
        complete: true,
        error_code: None,
    };
    finish_on(tx, &receipt, &result, now)?;
    Ok(())
}

fn current(
    connection: &Connection,
    expected: &SubmissionReceipt,
) -> Result<SubmissionReceipt, ReCtmError> {
    let row = &expected.row;
    let actual = read_receipt(
        connection,
        &row.capability_sha256,
        &row.owner_id,
        &row.run_id,
    )?
    .ok_or_else(invalid_receipt)?;
    actual.check_binding(&row.workspace_sha256, &row.request_sha256)?;
    if actual.row.domain_id != row.domain_id
        || actual.row.role != row.role
        || actual.row.epoch != row.epoch
        || actual.row.issued_state != row.issued_state
    {
        return Err(invalid_receipt());
    }
    Ok(actual)
}

fn finish_on(
    tx: &Transaction<'_>,
    receipt: &SubmissionReceipt,
    result: &SubmissionResult,
    now: &str,
) -> Result<SubmissionReceipt, ReCtmError> {
    result.validate()?;
    let summary = serde_json::to_string(result).map_err(|_| invalid_receipt())?;
    let changed = tx.execute(
        "UPDATE step_receipts SET status='completed',result_json=?,completed_at=? WHERE capability_sha256=? AND owner_id=? AND run_id=? AND status='pending'",
        params![summary,now,receipt.row.capability_sha256,receipt.row.owner_id,receipt.row.run_id],
    ).map_err(sql_error)?;
    if changed != 1 {
        return Err(invalid_receipt());
    }
    current(tx, receipt)
}

fn unknown() -> ReCtmError {
    receipt_error(
        "RESULT_UNKNOWN",
        "No safe unstarted or completed checkpoint exists. Do not replay partial work or replace its capability.",
    )
}
