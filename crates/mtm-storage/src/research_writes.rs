//! SQL for ordinary and checkpointed research records has one implementation.
use super::*;

/// Normalized record data, not an authorization permit or a verifier decision.
/// Workflow validates evidence semantics; checkpointed writes additionally require
/// an active SubmissionExecution and matching resource/domain authority.
pub struct ReferenceAuditWrite {
    pub reference_id: String,
    pub disposition: String,
    pub evidence_basis: String,
    pub evidence_locator: String,
    pub verifier_domain_id: String,
    pub proof_sha256: String,
    pub proof_manifest_sha256: String,
    pub material: bool,
    pub assumptions_checked: bool,
    pub notation_checked: bool,
    pub source_checked: bool,
    pub independently_rederived: bool,
    pub notes: String,
}

pub(super) fn manifest_on(
    tx: &Transaction<'_>,
    run: &str,
    canonical: &str,
    digest: &str,
    now: &str,
) -> Result<(), ReCtmError> {
    tx.execute(
        "INSERT INTO proof_manifests(run_id, manifest_json, sha256, created_at, updated_at) VALUES(?, ?, ?, ?, ?) ON CONFLICT(run_id) DO UPDATE SET manifest_json=excluded.manifest_json, sha256=excluded.sha256, updated_at=excluded.updated_at",
        params![run, canonical, digest, now, now],
    ).map_err(sql_error)?;
    Ok(())
}

pub(super) fn audit_on(
    tx: &Transaction<'_>,
    run: &str,
    audit: &ReferenceAuditWrite,
    now: &str,
) -> Result<Value, ReCtmError> {
    let reference = query_one_on(
        tx,
        "SELECT run_id FROM references_registry WHERE reference_id=?",
        [&audit.reference_id],
        &[],
    )?
    .ok_or_else(|| {
        ReCtmError::new("REFERENCE_NOT_FOUND", "Unknown reference.")
            .with_category(ErrorCategory::NotFound)
    })?;
    if reference["run_id"] != run {
        return Err(ReCtmError::new(
            "REFERENCE_RUN_MISMATCH",
            "Reference does not belong to this run.",
        )
        .with_category(ErrorCategory::Permission));
    }
    if !matches!(
        audit.disposition.as_str(),
        "SOURCE_VERIFIED" | "INDEPENDENTLY_REDERIVED" | "UNRESOLVED" | "NOT_MATERIAL"
    ) {
        return Err(ReCtmError::new(
            "INVALID_REFERENCE_DISPOSITION",
            "Unsupported reference audit disposition.",
        )
        .with_category(ErrorCategory::Validation));
    }
    tx.execute(
        "INSERT INTO reference_audits(run_id, reference_id, disposition, evidence_basis, evidence_locator, verifier_domain_id, proof_sha256, proof_manifest_sha256, material, assumptions_checked, notation_checked, source_checked, independently_rederived, notes, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(run_id, reference_id) DO UPDATE SET disposition=excluded.disposition, evidence_basis=excluded.evidence_basis, evidence_locator=excluded.evidence_locator, verifier_domain_id=excluded.verifier_domain_id, proof_sha256=excluded.proof_sha256, proof_manifest_sha256=excluded.proof_manifest_sha256, material=excluded.material, assumptions_checked=excluded.assumptions_checked, notation_checked=excluded.notation_checked, source_checked=excluded.source_checked, independently_rederived=excluded.independently_rederived, notes=excluded.notes, updated_at=excluded.updated_at",
        params![run, audit.reference_id, audit.disposition, audit.evidence_basis, audit.evidence_locator,
            audit.verifier_domain_id, audit.proof_sha256, audit.proof_manifest_sha256, i64::from(audit.material),
            i64::from(audit.assumptions_checked), i64::from(audit.notation_checked), i64::from(audit.source_checked),
            i64::from(audit.independently_rederived), audit.notes, now, now],
    ).map_err(sql_error)?;
    query_one_on(
        tx,
        "SELECT * FROM reference_audits WHERE run_id=? AND reference_id=?",
        [run, audit.reference_id.as_str()],
        &[],
    )?
    .ok_or_else(internal_row_error)
}
