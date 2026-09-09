//! One bounded outstanding effect per submission; no body or credential storage.
use super::*;

const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileImage {
    pub bytes: u64,
    pub sha256: String,
}

impl FileImage {
    fn validate(&self) -> Result<(), ReCtmError> {
        if self.bytes > MAX_FILE_BYTES || !valid_digest(&self.sha256) {
            return Err(invalid_receipt());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEffectEvidence {
    pub relative_path: String,
    pub before: Option<FileImage>,
    pub after: FileImage,
}

impl FileEffectEvidence {
    pub fn validate(&self) -> Result<(), ReCtmError> {
        let parts = self.relative_path.split('/').collect::<Vec<_>>();
        let safe = |part: &str| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part.len() <= 128
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        };
        let supported = matches!(
            parts.as_slice(),
            ["draft", "proof.tex"]
                | ["join", "result.json"]
                | ["verification", "verification.json"]
        ) || matches!(parts.as_slice(), ["memory", "generation" | "verifier", name] if name.ends_with(".jsonl"))
            || matches!(parts.as_slice(), ["branches", _, "memory", name] if name.ends_with(".jsonl"));
        if !supported || !parts.iter().all(|p| safe(p)) {
            return Err(invalid_receipt());
        }
        if let Some(before) = &self.before {
            before.validate()?;
        }
        self.after.validate()
    }

    fn authorize(&self, tx: &Transaction<'_>, claims: &CapabilityClaims) -> Result<(), ReCtmError> {
        self.validate()?;
        let domain = query_one_on(
            tx,
            "SELECT * FROM domains WHERE domain_id=?",
            [claims.domain_id()],
            &["metadata_json"],
        )?
        .ok_or_else(invalid_receipt)?;
        let parts = self.relative_path.split('/').collect::<Vec<_>>();
        let resource = match parts.as_slice() {
            ["memory", kind @ ("generation" | "verifier"), file] => {
                format!(
                    "memory:{kind}:{}",
                    file.strip_suffix(".jsonl").ok_or_else(invalid_receipt)?
                )
            }
            ["branches", branch, "memory", file] => {
                if domain["metadata"]["branch_id"].as_str() != Some(*branch) {
                    return Err(receipt_error(
                        "CROSS_BRANCH_ACCESS_DENIED",
                        "File evidence belongs to another branch.",
                    ));
                }
                format!(
                    "memory:branch:{}",
                    file.strip_suffix(".jsonl").ok_or_else(invalid_receipt)?
                )
            }
            ["draft", "proof.tex"] => "proof".into(),
            ["join", "result.json"] => "join_result".into(),
            ["verification", "verification.json"] => "verification_report".into(),
            _ => return Err(invalid_receipt()),
        };
        let permission = format!("write:{resource}");
        if !claims
            .permissions()
            .iter()
            .any(|p| crate::capability::wildcard_match(p, &permission))
        {
            return Err(receipt_error(
                "ROLE_ACCESS_DENIED",
                "File evidence is not writable by the reserved task.",
            ));
        }
        crate::authorize_role_resource(
            claims.role(),
            claims.issued_state(),
            "write",
            &resource,
            &domain,
        )
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Marker {
    Between,
    Opaque,
    File { evidence: FileEffectEvidence },
}

#[derive(Clone, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    execution_id: String,
    phase: String,
    expected_writes: Option<u64>,
    accepted_writes: u64,
    marker_json: Option<String>,
    atomic_action: Option<AtomicActionKind>,
}

/// Constructed only from a bound receipt and current durable checkpoint.
pub struct SubmissionRecovery {
    receipt: SubmissionReceipt,
    checkpoint: Option<Checkpoint>,
    marker: Option<Marker>,
}

impl SubmissionRecovery {
    #[must_use]
    pub fn file_evidence(&self) -> Option<&FileEffectEvidence> {
        match self.marker.as_ref() {
            Some(Marker::File { evidence }) => Some(evidence),
            _ => None,
        }
    }
}

fn checkpoint(
    connection: &Connection,
    fingerprint: &str,
) -> Result<Option<Checkpoint>, ReCtmError> {
    query_one_on(connection,
        "SELECT c.execution_id,c.phase,c.expected_writes,c.accepted_writes,j.marker_json,c.atomic_action FROM step_checkpoints c LEFT JOIN step_write_journals j ON j.capability_sha256=c.capability_sha256 WHERE c.capability_sha256=?",
        [fingerprint], &[])?
        .map(|row| serde_json::from_value(row).map_err(|_| invalid_receipt()))
        .transpose()
}

pub(super) fn enroll(tx: &Transaction<'_>, fingerprint: &str) -> Result<(), ReCtmError> {
    tx.execute(
        "INSERT INTO step_write_journals VALUES(?,?)",
        params![fingerprint, encode(&Marker::Between)?],
    )
    .map_err(sql_error)?;
    Ok(())
}

fn encode(marker: &Marker) -> Result<String, ReCtmError> {
    if let Marker::File { evidence } = marker {
        evidence.validate()?;
    }
    let text = serde_json::to_string(marker).map_err(|_| invalid_receipt())?;
    if text.len() > 4096 {
        return Err(invalid_receipt());
    }
    Ok(text)
}

pub(super) fn diagnostic(raw: Option<&str>, phase: &str) -> Result<Value, ReCtmError> {
    let marker: Option<Marker> = raw
        .map(|raw| {
            if raw.len() > 4096 {
                return Err(invalid_receipt());
            }
            let marker: Marker = serde_json::from_str(raw).map_err(|_| invalid_receipt())?;
            encode(&marker)?;
            Ok(marker)
        })
        .transpose()?;
    let kind = match &marker {
        Some(Marker::Between) => "between_writes",
        Some(Marker::File { .. }) => "file_effect",
        Some(Marker::Opaque) => "opaque_effect",
        None => "legacy_unknown",
    };
    Ok(
        serde_json::json!({"kind":kind,"recover_only_may_reconcile":phase=="prepared"
        || (phase=="running" && matches!(marker,Some(Marker::Between | Marker::File { .. }))),
        "automatic_retry":false,"grants_authority":false}),
    )
}

pub(super) fn accept(tx: &Transaction<'_>, fingerprint: &str) -> Result<(), ReCtmError> {
    let raw: String = tx
        .query_row(
            "SELECT marker_json FROM step_write_journals WHERE capability_sha256=?",
            [fingerprint],
            |r| r.get(0),
        )
        .map_err(sql_error)?;
    if raw.len() > 4096 {
        return Err(invalid_receipt());
    }
    let marker: Marker = serde_json::from_str(&raw).map_err(|_| invalid_receipt())?;
    encode(&marker)?;
    if marker == Marker::Between {
        return Err(invalid_receipt());
    }
    let changed = tx.execute("UPDATE step_write_journals SET marker_json=? WHERE capability_sha256=? AND marker_json<>?",
        params![encode(&Marker::Between)?,fingerprint,encode(&Marker::Between)?]).map_err(sql_error)?;
    if changed != 1 {
        return Err(invalid_receipt());
    }
    Ok(())
}

pub(super) fn require_between(tx: &Transaction<'_>, fingerprint: &str) -> Result<(), ReCtmError> {
    let between: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM step_write_journals WHERE capability_sha256=? AND marker_json=?)",
        params![fingerprint,encode(&Marker::Between)?], |r| r.get(0)).map_err(sql_error)?;
    if !between {
        return Err(invalid_receipt());
    }
    Ok(())
}

impl StateStore {
    pub fn begin_submission_write(
        &self,
        execution: &SubmissionExecution,
        index: usize,
        evidence: Option<&FileEffectEvidence>,
    ) -> Result<(), ReCtmError> {
        if index >= 65_536 {
            return Err(invalid_receipt());
        }
        let marker = evidence.map_or(Marker::Opaque, |e| Marker::File {
            evidence: e.clone(),
        });
        let marker = encode(&marker)?;
        self.immediate(|tx| {
            recheck_authority(tx, &execution.claims, self.runtime.clock.unix_seconds()?)?;
            if let Some(evidence) = evidence { evidence.authorize(tx, &execution.claims)?; }
            let changed = tx.execute(
                "UPDATE step_write_journals SET marker_json=? WHERE capability_sha256=? AND marker_json=? AND EXISTS(SELECT 1 FROM step_checkpoints c JOIN step_receipts r USING(capability_sha256) WHERE c.capability_sha256=? AND c.execution_id=? AND c.phase='running' AND c.accepted_writes=? AND c.expected_writes>c.accepted_writes AND r.status='pending')",
                params![marker,execution.fingerprint,encode(&Marker::Between)?,execution.fingerprint,execution.id,index as i64],
            ).map_err(sql_error)?;
            if changed != 1 { return Err(invalid_receipt()); }
            Ok(())
        })
    }

    pub fn submission_recovery(
        &self,
        receipt: SubmissionReceipt,
    ) -> Result<SubmissionRecovery, ReCtmError> {
        let connection = self.lock_connection()?;
        let receipt = checkpoints::current(&connection, &receipt)?;
        let checkpoint = checkpoint(&connection, &receipt.row.capability_sha256)?;
        let marker = checkpoint
            .as_ref()
            .and_then(|c| c.marker_json.as_ref())
            .map(|s| {
                if s.len() > 4096 {
                    return Err(invalid_receipt());
                }
                let marker: Marker = serde_json::from_str(s).map_err(|_| invalid_receipt())?;
                encode(&marker)?;
                Ok(marker)
            })
            .transpose()?;
        Ok(SubmissionRecovery {
            receipt,
            checkpoint,
            marker,
        })
    }

    /// Caller holds the file's OS lock for a file observation. No file write occurs.
    pub fn reconcile_caller_writes(
        &self,
        recovery: SubmissionRecovery,
        observed: Option<Option<FileImage>>,
    ) -> Result<SubmissionReceipt, ReCtmError> {
        if let Some(Some(image)) = &observed {
            image.validate()?;
        }
        self.immediate(|tx| {
            let receipt = checkpoints::current(tx, &recovery.receipt)?;
            if receipt.result().is_some() {
                return Ok(receipt);
            }
            let current = checkpoint(tx, &receipt.row.capability_sha256)?;
            if current != recovery.checkpoint {
                return Err(checkpoints::unknown());
            }
            let current = current.ok_or_else(checkpoints::unknown)?;
            if current.atomic_action.is_some()
                && (current.phase != "commit_ready"
                    || !current
                        .atomic_action
                        .is_some_and(|kind| kind.state() == receipt.row.issued_state)
                    || current.expected_writes != Some(current.accepted_writes)
                    || recovery.marker != Some(Marker::Between)
                    || observed.is_some())
            {
                return Err(checkpoints::unknown());
            }
            if current.phase == "prepared" {
                let result = SubmissionResult {
                    disposition: SubmissionDisposition::CorrectionRequired,
                    state: receipt.row.issued_state,
                    writes_applied: 0,
                    complete: false,
                    error_code: Some("SUBMISSION_NOT_STARTED".into()),
                };
                return checkpoints::finish_on(
                    tx,
                    &receipt,
                    &result,
                    &self.runtime.clock.now_iso()?,
                );
            }
            let atomic = current.phase == "commit_ready"
                && current
                    .atomic_action
                    .is_some_and(|kind| kind.state() == receipt.row.issued_state)
                && current.expected_writes == Some(current.accepted_writes)
                && recovery.marker == Some(Marker::Between)
                && observed.is_none();
            if current.phase != "running" && !atomic {
                return Err(checkpoints::unknown());
            }
            let extra = match (&recovery.marker, observed) {
                (Some(Marker::Between), None) => 0,
                (Some(Marker::File { evidence }), Some(actual)) => {
                    // An equal-byte overwrite has no evidence of whether it ran.
                    if evidence.before.as_ref() == Some(&evidence.after) {
                        return Err(checkpoints::unknown());
                    }
                    if actual.as_ref() == Some(&evidence.after) {
                        1
                    } else if actual == evidence.before {
                        0
                    } else {
                        return Err(checkpoints::unknown());
                    }
                }
                _ => return Err(checkpoints::unknown()),
            };
            let accepted = current
                .accepted_writes
                .checked_add(extra)
                .ok_or_else(invalid_receipt)?;
            if accepted > current.expected_writes.ok_or_else(invalid_receipt)? {
                return Err(invalid_receipt());
            }
            let result = SubmissionResult {
                disposition: SubmissionDisposition::CorrectionRequired,
                state: receipt.row.issued_state,
                writes_applied: accepted,
                complete: false,
                error_code: Some("SUBMISSION_INTERRUPTED".into()),
            };
            checkpoints::finish_on(tx, &receipt, &result, &self.runtime.clock.now_iso()?)
        })
    }
}
