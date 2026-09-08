//! Only the two caller database resources are coupled to accepted-write counts.
//! No caller-provided transaction closure or SQL crosses this boundary.
use super::*;

const MAX_RECORD_BYTES: usize = 1024 * 1024;

impl StateStore {
    pub fn write_submission_proof_manifest(
        &self,
        execution: &SubmissionExecution,
        index: usize,
        manifest: &Value,
    ) -> Result<Value, ReCtmError> {
        let canonical = canonical_json(manifest)?;
        if !manifest.is_object() || canonical.len() > MAX_RECORD_BYTES {
            return Err(invalid_receipt());
        }
        let digest = sha256_text(&canonical);
        let result = serde_json::json!({"run_id":execution.claims.run_id(),"manifest":manifest,"sha256":digest});
        self.database_submission(execution, index, "proof_manifest", |tx, now| {
            research_writes::manifest_on(tx, execution.claims.run_id(), &canonical, &digest, now)?;
            Ok(result)
        })
    }

    pub fn write_submission_reference_audit(
        &self,
        execution: &SubmissionExecution,
        index: usize,
        audit: &ReferenceAuditWrite,
    ) -> Result<Value, ReCtmError> {
        let size = [
            &audit.reference_id,
            &audit.disposition,
            &audit.evidence_basis,
            &audit.evidence_locator,
            &audit.verifier_domain_id,
            &audit.proof_sha256,
            &audit.proof_manifest_sha256,
            &audit.notes,
        ]
        .iter()
        .fold(0usize, |total, field| total.saturating_add(field.len()));
        if size > MAX_RECORD_BYTES
            || audit.verifier_domain_id != execution.claims.domain_id()
            || !valid_digest(&audit.proof_sha256)
            || !valid_digest(&audit.proof_manifest_sha256)
        {
            return Err(invalid_receipt());
        }
        self.database_submission(execution, index, "reference_audit", |tx, now| {
            // Recheck the manifest used by the normalizer under the write transaction.
            let manifest = query_one_on(
                tx,
                "SELECT sha256 FROM proof_manifests WHERE run_id=?",
                [execution.claims.run_id()],
                &[],
            )?
            .ok_or_else(invalid_receipt)?;
            if manifest["sha256"] != audit.proof_manifest_sha256 {
                return Err(invalid_receipt());
            }
            research_writes::audit_on(tx, execution.claims.run_id(), audit, now)
        })
    }

    fn database_submission(
        &self,
        execution: &SubmissionExecution,
        index: usize,
        resource: &str,
        mutation: impl FnOnce(&Transaction<'_>, &str) -> Result<Value, ReCtmError>,
    ) -> Result<Value, ReCtmError> {
        if index >= 65_536 {
            return Err(invalid_receipt());
        }
        self.immediate(|tx| {
            recheck_authority(tx, &execution.claims, self.runtime.clock.unix_seconds()?)?;
            let permission = format!("write:{resource}");
            if !execution.claims.permissions().iter().any(|p| crate::capability::wildcard_match(p, &permission)) {
                return Err(receipt_error("ROLE_ACCESS_DENIED", "Reserved task cannot write this database resource."));
            }
            let domain = query_one_on(tx, "SELECT * FROM domains WHERE domain_id=?", [execution.claims.domain_id()], &["metadata_json"])?
                .ok_or_else(invalid_receipt)?;
            crate::authorize_role_resource(execution.claims.role(), execution.claims.issued_state(), "write", resource, &domain)?;
            write_journal::require_between(tx, &execution.fingerprint)?;
            require_slot(tx, execution, index as i64, (index + 1) as i64)?;
            let result = mutation(tx, &self.runtime.clock.now_iso()?)?;
            let changed = tx.execute(
                "UPDATE step_checkpoints SET accepted_writes=? WHERE capability_sha256=? AND execution_id=? AND phase='running' AND accepted_writes=? AND expected_writes>=? AND EXISTS(SELECT 1 FROM step_receipts WHERE capability_sha256=? AND status='pending')",
                params![(index+1) as i64, execution.fingerprint, execution.id, index as i64, (index+1) as i64, execution.fingerprint],
            ).map_err(sql_error)?;
            if changed != 1 { return Err(invalid_receipt()); }
            write_journal::require_between(tx, &execution.fingerprint)?;
            require_slot(tx, execution, (index + 1) as i64, (index + 1) as i64)?;
            Ok(result)
        })
    }
}

fn require_slot(
    tx: &Transaction<'_>,
    execution: &SubmissionExecution,
    accepted: i64,
    minimum_expected: i64,
) -> Result<(), ReCtmError> {
    let matches: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM step_checkpoints c JOIN step_receipts r USING(capability_sha256) WHERE c.capability_sha256=? AND c.execution_id=? AND c.phase='running' AND c.accepted_writes=? AND c.expected_writes>=? AND r.status='pending' AND r.run_id=? AND r.owner_id=? AND r.domain_id=? AND r.epoch=? AND r.issued_state=? AND r.role=?)",
        params![execution.fingerprint, execution.id, accepted, minimum_expected, execution.claims.run_id(), execution.claims.owner_id(), execution.claims.domain_id(), execution.claims.epoch(), execution.claims.issued_state().as_str(), execution.claims.role().as_str()],
        |r| r.get(0),
    ).map_err(sql_error)?;
    if !matches {
        return Err(invalid_receipt());
    }
    Ok(())
}
