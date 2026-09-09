//! Enrollment is explicit. State alone never proves an action had no effects.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomicActionKind {
    AssessmentComplete,
    ExplorationComplete,
    ProofSubmitted,
    RepairSubmitted,
}

impl AtomicActionKind {
    #[must_use]
    pub fn parse(action: &str) -> Option<Self> {
        match action {
            "assessment_complete" => Some(Self::AssessmentComplete),
            "exploration_complete" => Some(Self::ExplorationComplete),
            "proof_submitted" => Some(Self::ProofSubmitted),
            "repair_submitted" => Some(Self::RepairSubmitted),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AssessmentComplete => "assessment_complete",
            Self::ExplorationComplete => "exploration_complete",
            Self::ProofSubmitted => "proof_submitted",
            Self::RepairSubmitted => "repair_submitted",
        }
    }

    pub(super) fn state(self) -> WorkflowState {
        match self {
            Self::AssessmentComplete => WorkflowState::Assess,
            Self::ExplorationComplete => WorkflowState::Explore,
            Self::ProofSubmitted => WorkflowState::Assemble,
            Self::RepairSubmitted => WorkflowState::Repair,
        }
    }
}

impl StateStore {
    /// Called after WorkflowEngine has selected one of the four pure-DB actions.
    /// Direct engine calls without a receipt are not enrolled and gain no recovery.
    pub fn enroll_atomic_action(
        &self,
        claims: &CapabilityClaims,
        trace: &str,
        kind: AtomicActionKind,
    ) -> Result<(), ReCtmError> {
        if claims.issued_state() != kind.state() {
            return Err(invalid_receipt());
        }
        self.immediate(|tx| {
            recheck_authority(tx, claims, self.runtime.clock.unix_seconds()?)?;
            let Some(receipt) = check_task(tx, claims, trace)? else { return Ok(()); };
            write_journal::require_between(tx, &receipt.row.capability_sha256)?;
            let changed = tx.execute("UPDATE step_checkpoints SET atomic_action=? WHERE execution_id=? AND phase='commit_ready' AND expected_writes=accepted_writes AND atomic_action IS NULL",
                params![kind.as_str(),trace]).map_err(sql_error)?;
            if changed != 1 { return Err(invalid_receipt()); }
            Ok(())
        })
    }
}

pub(in crate::store) fn check_task(
    tx: &Transaction<'_>,
    claims: &CapabilityClaims,
    trace: &str,
) -> Result<Option<SubmissionReceipt>, ReCtmError> {
    let row = query_one_on(
        tx,
        "SELECT r.* FROM step_receipts r JOIN step_checkpoints c USING(capability_sha256) WHERE c.execution_id=?",
        [trace],
        &[],
    )?;
    if let Some(row) = row {
        let receipt = SubmissionReceipt::decode(row)?;
        if !receipt.matches_claims(claims) || receipt.result().is_some() {
            return Err(invalid_receipt());
        }
        let ready: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM step_checkpoints WHERE execution_id=? AND phase='commit_ready' AND expected_writes=accepted_writes)", [trace], |r|r.get(0)).map_err(sql_error)?;
        if !ready {
            return Err(invalid_receipt());
        }
        write_journal::require_between(tx, &receipt.row.capability_sha256)?;
        Ok(Some(receipt))
    } else {
        let pending: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM step_receipts WHERE run_id=? AND status='pending')",
                [claims.run_id()],
                |r| r.get(0),
            )
            .map_err(sql_error)?;
        if pending {
            return Err(invalid_receipt());
        }
        Ok(None)
    }
}
