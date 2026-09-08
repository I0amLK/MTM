//! Durable, authority-bound reservations. No transaction spans workflow I/O.
use super::*;
use crate::capability::{AuthorizedSubmission, CapabilityClaims, record_matches_claims};
use mtm_contracts::{WorkflowRole, WorkflowState};
use serde::{Deserialize, Serialize};

const MAX_RECEIPTS_PER_RUN: i64 = 4096;
const MAX_RECEIPTS_TOTAL: i64 = 100_000;

#[path = "step_checkpoints.rs"]
mod checkpoints;
pub use checkpoints::SubmissionExecution;
pub(super) use checkpoints::record_transition;

#[path = "step_write_journal.rs"]
mod write_journal;
pub use write_journal::{FileEffectEvidence, FileImage, SubmissionRecovery};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionDisposition {
    Applied,
    CorrectionRequired,
}

/// Receipt data, never a task envelope or an authorization permit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionResult {
    pub disposition: SubmissionDisposition,
    pub state: WorkflowState,
    pub writes_applied: u64,
    pub complete: bool,
    pub error_code: Option<String>,
}

impl SubmissionResult {
    fn validate(&self) -> Result<(), ReCtmError> {
        let error_valid = self.error_code.as_ref().is_some_and(|code| {
            !code.is_empty()
                && code.len() <= 80
                && code
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        });
        if self.writes_applied > 65_536
            || match self.disposition {
                SubmissionDisposition::Applied => self.error_code.is_some(),
                SubmissionDisposition::CorrectionRequired => !error_valid || self.complete,
            }
        {
            return Err(receipt_error(
                "SUBMISSION_RECEIPT_INVALID",
                "Invalid submission completion summary.",
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptRow {
    capability_sha256: String,
    owner_id: String,
    workspace_sha256: String,
    request_sha256: String,
    run_id: String,
    domain_id: String,
    role: WorkflowRole,
    epoch: i64,
    issued_state: WorkflowState,
    status: String,
    result_json: Option<String>,
    created_at: String,
    completed_at: Option<String>,
}

pub struct SubmissionReceipt {
    row: ReceiptRow,
    result: Option<SubmissionResult>,
}

impl SubmissionReceipt {
    fn decode(raw: Value) -> Result<Self, ReCtmError> {
        let row: ReceiptRow = serde_json::from_value(raw).map_err(|_| invalid_receipt())?;
        let result = match (&*row.status, &row.result_json, &row.completed_at) {
            ("pending", None, None) => None,
            ("completed", Some(text), Some(time)) if text.len() <= 2048 && !time.is_empty() => {
                let value: SubmissionResult =
                    serde_json::from_str(text).map_err(|_| invalid_receipt())?;
                value.validate()?;
                Some(value)
            }
            _ => return Err(invalid_receipt()),
        };
        if row.created_at.is_empty()
            || !valid_digest(&row.capability_sha256)
            || !valid_digest(&row.workspace_sha256)
            || !valid_digest(&row.request_sha256)
        {
            return Err(invalid_receipt());
        }
        Ok(Self { row, result })
    }

    pub(crate) fn matches_claims(&self, claims: &CapabilityClaims) -> bool {
        self.row.owner_id == claims.owner_id()
            && self.row.run_id == claims.run_id()
            && self.row.domain_id == claims.domain_id()
            && self.row.role == claims.role()
            && self.row.epoch == claims.epoch()
            && self.row.issued_state == claims.issued_state()
    }

    pub(crate) fn check_binding(&self, workspace: &str, request: &str) -> Result<(), ReCtmError> {
        if self.row.workspace_sha256 != workspace {
            return Err(receipt_error(
                "SUBMISSION_WORKSPACE_MISMATCH",
                "Submission belongs to a different workspace.",
            ));
        }
        if self.row.request_sha256 != request {
            return Err(receipt_error(
                "IDEMPOTENCY_CONFLICT",
                "This capability already identifies a different submission; do not replay changed writes.",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.row.run_id
    }

    #[must_use]
    pub fn result(&self) -> Option<&SubmissionResult> {
        self.result.as_ref()
    }

    #[must_use]
    pub fn summary(&self) -> Value {
        serde_json::json!({"schema_version":1,"status":self.row.status,
            "run_id":self.row.run_id,"domain_id":self.row.domain_id,"role":self.row.role,
            "epoch":self.row.epoch,"issued_state":self.row.issued_state,
            "result":self.result,"grants_authority":false})
    }
}

/// Only reserve_submission can construct this once-only completion handle.
pub struct SubmissionReservation {
    receipt: SubmissionReceipt,
}

pub enum SubmissionSlot {
    Reserved(SubmissionReservation),
    Existing(SubmissionReceipt),
}

impl StateStore {
    pub(crate) fn find_submission_receipt(
        &self,
        fingerprint: &str,
        owner: &str,
        run: &str,
    ) -> Result<Option<SubmissionReceipt>, ReCtmError> {
        let connection = self.lock_connection()?;
        read_receipt(&connection, fingerprint, owner, run)
    }

    pub fn reserve_submission(
        &self,
        authorized: &AuthorizedSubmission,
        workspace: &str,
        request: &str,
    ) -> Result<SubmissionSlot, ReCtmError> {
        if !valid_digest(workspace) || !valid_digest(request) {
            return Err(invalid_receipt());
        }
        let claims = &authorized.claims;
        let created_at = self.runtime.clock.now_iso()?;
        self.immediate(|tx| {
            if let Some(existing) = read_receipt(tx, &authorized.fingerprint, claims.owner_id(), claims.run_id())? {
                if !existing.matches_claims(claims) { return Err(invalid_receipt()); }
                existing.check_binding(workspace, request)?;
                return Ok(SubmissionSlot::Existing(existing));
            }
            let pending: i64 = tx.query_row(
                "SELECT COUNT(*) FROM step_receipts WHERE run_id=? AND status='pending'",
                [claims.run_id()], |row| row.get(0),
            ).map_err(sql_error)?;
            if pending != 0 {
                return Err(receipt_error("RESULT_UNKNOWN", "Another submission for this run has an unresolved outcome. Do not retry with a fresh capability."));
            }
            // Read the clock after acquiring the transaction, not before a lock wait.
            recheck_authority(tx, claims, self.runtime.clock.unix_seconds()?)?;
            let total: i64 = tx.query_row("SELECT COUNT(*) FROM step_receipts", [], |row| row.get(0)).map_err(sql_error)?;
            let run_total: i64 = tx.query_row("SELECT COUNT(*) FROM step_receipts WHERE run_id=?", [claims.run_id()], |row| row.get(0)).map_err(sql_error)?;
            if total >= MAX_RECEIPTS_TOTAL || run_total >= MAX_RECEIPTS_PER_RUN {
                return Err(receipt_error("SUBMISSION_RECEIPT_CAPACITY", "Submission receipt capacity reached; no safety records were removed."));
            }
            tx.execute(
                "INSERT INTO step_receipts(capability_sha256,owner_id,workspace_sha256,request_sha256,run_id,domain_id,role,epoch,issued_state,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,'pending',?)",
                params![authorized.fingerprint, claims.owner_id(), workspace, request, claims.run_id(),
                    claims.domain_id(), claims.role().as_str(), claims.epoch(), claims.issued_state().as_str(), created_at],
            ).map_err(sql_error)?;
            tx.execute(
                "INSERT INTO step_checkpoints(capability_sha256,execution_id,phase) VALUES(?,?,'prepared')",
                params![authorized.fingerprint,self.runtime.ids.token_hex(16)?],
            ).map_err(sql_error)?;
            let receipt = read_receipt(tx, &authorized.fingerprint, claims.owner_id(), claims.run_id())?.ok_or_else(invalid_receipt)?;
            Ok(SubmissionSlot::Reserved(SubmissionReservation { receipt }))
        })
    }

    pub fn complete_submission(
        &self,
        reservation: SubmissionReservation,
        result: &SubmissionResult,
    ) -> Result<SubmissionReceipt, ReCtmError> {
        self.record_submission_outcome(&reservation, result)
    }

    pub fn record_submission_outcome(
        &self,
        reservation: &SubmissionReservation,
        result: &SubmissionResult,
    ) -> Result<SubmissionReceipt, ReCtmError> {
        result.validate()?;
        let summary = serde_json::to_string(result).map_err(|_| invalid_receipt())?;
        if summary.len() > 2048 {
            return Err(invalid_receipt());
        }
        let binding = &reservation.receipt.row;
        let completed_at = self.runtime.clock.now_iso()?;
        self.immediate(|tx| {
            let existing = read_receipt(tx, &binding.capability_sha256, &binding.owner_id, &binding.run_id)?.ok_or_else(invalid_receipt)?;
            existing.check_binding(&binding.workspace_sha256, &binding.request_sha256)?;
            if let Some(recorded) = existing.result() {
                // A transition certificate describes the immediate commit state;
                // next-task mechanics may since have advanced further.
                if recorded == result || (recorded.disposition == SubmissionDisposition::Applied
                    && result.disposition == SubmissionDisposition::Applied
                    && recorded.writes_applied == result.writes_applied && recorded.complete == result.complete) {
                    return Ok(existing);
                }
                return Err(invalid_receipt());
            }
            let enrolled: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM step_write_journals WHERE capability_sha256=?)",
                [&binding.capability_sha256], |row| row.get(0),
            ).map_err(sql_error)?;
            // An error category is not evidence that an outstanding effect did not happen.
            if enrolled { write_journal::require_between(tx, &binding.capability_sha256)?; }
            let changed = tx.execute(
                "UPDATE step_receipts SET status='completed',result_json=?,completed_at=? WHERE capability_sha256=? AND owner_id=? AND run_id=? AND workspace_sha256=? AND request_sha256=? AND status='pending'",
                params![summary, completed_at, binding.capability_sha256, binding.owner_id,
                    binding.run_id, binding.workspace_sha256, binding.request_sha256],
            ).map_err(sql_error)?;
            if changed != 1 { return Err(invalid_receipt()); }
            read_receipt(tx, &binding.capability_sha256, &binding.owner_id, &binding.run_id)?.ok_or_else(invalid_receipt)
        })
    }
}

fn read_receipt(
    connection: &Connection,
    fingerprint: &str,
    owner: &str,
    run: &str,
) -> Result<Option<SubmissionReceipt>, ReCtmError> {
    query_one_on(
        connection,
        "SELECT * FROM step_receipts WHERE capability_sha256=? AND owner_id=? AND run_id=?",
        [fingerprint, owner, run],
        &[],
    )?
    .map(SubmissionReceipt::decode)
    .transpose()
}

fn recheck_authority(
    tx: &Transaction<'_>,
    claims: &CapabilityClaims,
    now: i64,
) -> Result<(), ReCtmError> {
    let run = query_one_on(
        tx,
        "SELECT * FROM runs WHERE run_id=?",
        [claims.run_id()],
        &["metadata_json"],
    )?;
    let domain = query_one_on(
        tx,
        "SELECT * FROM domains WHERE domain_id=?",
        [claims.domain_id()],
        &["metadata_json"],
    )?;
    let cap = query_one_on(
        tx,
        "SELECT * FROM capabilities WHERE nonce=?",
        [claims.nonce()],
        &["permissions_json"],
    )?;
    let (Some(run), Some(domain), Some(cap)) = (run, domain, cap) else {
        return Err(changed_authority());
    };
    if !record_matches_claims(&cap, claims)
        || cap["revoked"] != false
        || claims.expires_at() < now
        || run["owner_id"] != claims.owner_id()
        || run["epoch"].as_i64() != Some(claims.epoch())
        || run["state"] != claims.issued_state().as_str()
        || domain["status"] != "open"
        || domain["run_id"] != claims.run_id()
        || domain["role"] != claims.role().as_str()
    {
        return Err(changed_authority());
    }
    crate::authorize_role_resource(
        claims.role(),
        claims.issued_state(),
        "commit",
        "workflow",
        &domain,
    )
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn receipt_error(code: &str, message: &str) -> ReCtmError {
    ReCtmError::new(code, message)
        .with_category(ErrorCategory::Conflict)
        .with_retryable(false)
        .with_details(serde_json::json!({"automatic_retry":false,"receipt_grants_authority":false}))
}

fn invalid_receipt() -> ReCtmError {
    receipt_error(
        "SUBMISSION_RECEIPT_INVALID",
        "Submission receipt is missing, inconsistent or malformed.",
    )
}

fn changed_authority() -> ReCtmError {
    receipt_error(
        "SUBMISSION_AUTHORITY_CHANGED",
        "Submission authority changed before reservation; no workflow write was attempted.",
    )
}
