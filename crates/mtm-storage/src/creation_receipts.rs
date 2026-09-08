//! Bounded creation identity. This module never issues workflow authority.
use super::*;
use serde::Deserialize;

#[path = "creation_records.rs"]
mod creation_records;
pub use creation_records::{CreationInitialization, CreationReference};

pub struct CreationIdentity {
    key: String,
    workspace: String,
    request: String,
}

impl CreationIdentity {
    pub fn new(key: String, workspace: String, request: String) -> Result<Self, ReCtmError> {
        if [&key, &workspace, &request].iter().any(|v| !digest(v)) {
            return Err(invalid());
        }
        Ok(Self {
            key,
            workspace,
            request,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RowData {
    owner_id: String,
    key_sha256: String,
    workspace_sha256: String,
    request_sha256: String,
    run_id: String,
    execution_id: String,
    status: String,
    created_at: String,
    completed_at: Option<String>,
}

pub struct CreationReceipt {
    row: RowData,
}

impl CreationReceipt {
    #[must_use]
    pub fn is_completed(&self) -> bool {
        self.row.status == "completed"
    }
    fn decode(value: Value) -> Result<Self, ReCtmError> {
        let row: RowData = serde_json::from_value(value).map_err(|_| invalid())?;
        if !matches!(row.status.as_str(), "pending" | "completed")
            || (row.status == "completed") != row.completed_at.is_some()
            || row.completed_at.as_ref().is_some_and(|v| v.is_empty())
            || row.owner_id.is_empty()
            || row.created_at.is_empty()
            || !validate_registry_id(&row.run_id)
            || row.execution_id.len() != 32
            || !row.execution_id.bytes().all(|b| b.is_ascii_hexdigit())
            || [&row.key_sha256, &row.workspace_sha256, &row.request_sha256]
                .iter()
                .any(|v| !digest(v))
        {
            return Err(invalid());
        }
        Ok(Self { row })
    }

    fn check(&self, identity: &CreationIdentity) -> Result<(), ReCtmError> {
        if self.row.workspace_sha256 != identity.workspace {
            return Err(conflict(
                "CREATION_WORKSPACE_MISMATCH",
                "Creation identity belongs to another workspace.",
            ));
        }
        if self.row.request_sha256 != identity.request {
            return Err(conflict(
                "IDEMPOTENCY_CONFLICT",
                "This creation key already identifies different input. Do not change the key to retry an uncertain operation.",
            ));
        }
        Ok(())
    }

    pub fn response(&self, replayed: bool) -> Result<Value, ReCtmError> {
        if self.row.status != "completed" {
            return Err(conflict("CREATION_RESULT_UNKNOWN", "Creation is running or interrupted before its durable completion. Keep the same key; do not create another run as a retry.")
                .with_details(serde_json::json!({"run_id":self.row.run_id,
                    "runs_created":null,"automatic_retry":false,"grants_authority":false})));
        }
        Ok(
            serde_json::json!({"ok":true,"run_id":self.row.run_id,"state":"assess",
            "state_is_historical":true,"runs_created":u8::from(!replayed),
            "creation_receipt":{"status":"completed","replayed":replayed,"grants_authority":false},
            "next_action":{"tool":"rethlas_step","arguments":{"run_id":self.row.run_id}}}),
        )
    }
}

/// Only a successful durable reservation constructs this execution identity.
pub struct CreationReservation {
    receipt: CreationReceipt,
}

impl CreationReservation {
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.receipt.row.run_id
    }

    #[must_use]
    pub fn created_at(&self) -> &str {
        &self.receipt.row.created_at
    }
    #[must_use]
    pub fn execution_id(&self) -> &str {
        &self.receipt.row.execution_id
    }
}

pub enum CreationSlot {
    Reserved(CreationReservation),
    Existing(CreationReceipt),
}

impl StateStore {
    pub fn creation_receipt(
        &self,
        owner: &str,
        identity: &CreationIdentity,
    ) -> Result<Option<CreationReceipt>, ReCtmError> {
        let connection = self.lock_connection()?;
        let receipt = find(&connection, owner, &identity.key)?;
        if let Some(receipt) = &receipt {
            receipt.check(identity)?;
            if receipt.is_completed() {
                let run = query_one_on(
                    &connection,
                    "SELECT owner_id FROM runs WHERE run_id=?",
                    [&receipt.row.run_id],
                    &[],
                )?;
                if run.as_ref().and_then(|r| r["owner_id"].as_str()) != Some(owner) {
                    return Err(invalid());
                }
            }
        }
        Ok(receipt)
    }

    pub fn reserve_creation(
        &self,
        owner: &str,
        identity: &CreationIdentity,
        proposed_run: &str,
    ) -> Result<CreationSlot, ReCtmError> {
        if owner.is_empty() || owner.len() > 512 || !validate_registry_id(proposed_run) {
            return Err(invalid());
        }
        self.immediate(|tx| {
            if let Some(receipt) = find(tx, owner, &identity.key)? {
                receipt.check(identity)?;
                if receipt.row.status == "completed" {
                    let run = query_one_on(tx, "SELECT owner_id FROM runs WHERE run_id=?", [&receipt.row.run_id], &[])?;
                    if run.as_ref().and_then(|r| r["owner_id"].as_str()) != Some(owner) { return Err(invalid()); }
                }
                return Ok(CreationSlot::Existing(receipt));
            }
            let total: i64 = tx.query_row("SELECT COUNT(*) FROM creation_receipts", [], |r| r.get(0)).map_err(sql_error)?;
            let owned: i64 = tx.query_row("SELECT COUNT(*) FROM creation_receipts WHERE owner_id=?", [owner], |r| r.get(0)).map_err(sql_error)?;
            if total >= 100_000 || owned >= 10_000 {
                return Err(conflict("CREATION_RECEIPT_CAPACITY", "Creation receipt capacity reached. Safety records were not removed."));
            }
            let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM runs WHERE run_id=?)", [proposed_run], |r| r.get(0)).map_err(sql_error)?;
            if exists { return Err(conflict("RUN_ALREADY_EXISTS", "Creation requires a new server-issued run identity.")); }
            let execution = self.runtime.ids.token_hex(16)?;
            let now = self.runtime.clock.now_iso()?;
            tx.execute("INSERT INTO creation_receipts(owner_id,key_sha256,workspace_sha256,request_sha256,run_id,execution_id,status,created_at) VALUES(?,?,?,?,?,?,'pending',?)",
                params![owner,identity.key,identity.workspace,identity.request,proposed_run,execution,now]).map_err(sql_error)?;
            tx.execute("INSERT INTO creation_initializations(run_id) VALUES(?)", [proposed_run]).map_err(sql_error)?;
            let receipt = find(tx, owner, &identity.key)?.ok_or_else(invalid)?;
            Ok(CreationSlot::Reserved(CreationReservation { receipt }))
        })
    }

    pub fn observe_creation(
        &self,
        reservation: &CreationReservation,
    ) -> Result<CreationReceipt, ReCtmError> {
        let row = &reservation.receipt.row;
        let connection = self.lock_connection()?;
        let receipt = find(&connection, &row.owner_id, &row.key_sha256)?.ok_or_else(invalid)?;
        if receipt.row.run_id != row.run_id
            || receipt.row.execution_id != row.execution_id
            || receipt.row.workspace_sha256 != row.workspace_sha256
            || receipt.row.request_sha256 != row.request_sha256
        {
            return Err(invalid());
        }
        Ok(receipt)
    }

    /// Rebind only a creation enrolled in the immutable initialization protocol.
    /// The workflow must additionally hold its private OS file lock before any I/O.
    pub fn resume_creation(
        &self,
        receipt: CreationReceipt,
    ) -> Result<CreationReservation, ReCtmError> {
        let connection = self.lock_connection()?;
        let current = find(&connection, &receipt.row.owner_id, &receipt.row.key_sha256)?
            .ok_or_else(invalid)?;
        current.check(&CreationIdentity::new(
            receipt.row.key_sha256,
            receipt.row.workspace_sha256,
            receipt.row.request_sha256,
        )?)?;
        if current.row.run_id != receipt.row.run_id
            || current.row.execution_id != receipt.row.execution_id
        {
            return Err(invalid());
        }
        let enrolled: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM creation_initializations WHERE run_id=?)",
                [&current.row.run_id],
                |r| r.get(0),
            )
            .map_err(sql_error)?;
        if !enrolled {
            return Err(conflict(
                "CREATION_RESULT_UNKNOWN",
                "Legacy initialization has no resumable evidence; it was not restarted.",
            ));
        }
        Ok(CreationReservation { receipt: current })
    }
}

pub(super) fn record_initialization(
    tx: &Transaction<'_>,
    request: &TransitionRun<'_>,
    before: &Map<String, Value>,
    now: &str,
) -> Result<(), ReCtmError> {
    if request.expected_state != "created" || request.after_state != "assess" {
        return Ok(());
    }
    let row = query_one_on(
        tx,
        "SELECT * FROM creation_receipts WHERE run_id=?",
        [request.run_id],
        &[],
    )?;
    let Some(row) = row else {
        return Ok(());
    };
    let receipt = CreationReceipt::decode(row)?;
    if receipt.row.status != "pending"
        || receipt.row.execution_id != request.trace_id
        || before.get("owner_id").and_then(Value::as_str) != Some(receipt.row.owner_id.as_str())
        || request.actor != "system"
        || request.reason != "run_initialized"
    {
        return Err(invalid());
    }
    let changed = tx.execute("UPDATE creation_receipts SET status='completed',completed_at=? WHERE run_id=? AND execution_id=? AND status='pending'",
        params![now,request.run_id,request.trace_id]).map_err(sql_error)?;
    if changed != 1 {
        return Err(invalid());
    }
    Ok(())
}

fn find(
    connection: &Connection,
    owner: &str,
    key: &str,
) -> Result<Option<CreationReceipt>, ReCtmError> {
    query_one_on(
        connection,
        "SELECT * FROM creation_receipts WHERE owner_id=? AND key_sha256=?",
        [owner, key],
        &[],
    )?
    .map(CreationReceipt::decode)
    .transpose()
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn conflict(code: &str, message: &str) -> ReCtmError {
    ReCtmError::new(code, message)
        .with_category(ErrorCategory::Conflict)
        .with_retryable(false)
}

fn invalid() -> ReCtmError {
    conflict(
        "CREATION_RECEIPT_INVALID",
        "Creation binding or persisted receipt is invalid.",
    )
}
