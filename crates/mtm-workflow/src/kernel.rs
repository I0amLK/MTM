use mtm_contracts::{ErrorCategory, ReCtmError, WorkflowState};

pub const ALLOWED_TRANSITIONS: [(WorkflowState, WorkflowState); 24] = [
    (WorkflowState::Created, WorkflowState::Assess),
    (WorkflowState::Assess, WorkflowState::Explore),
    (WorkflowState::Assess, WorkflowState::Assemble),
    (WorkflowState::Explore, WorkflowState::ProposePlans),
    (WorkflowState::ProposePlans, WorkflowState::DirectProving),
    (WorkflowState::DirectProving, WorkflowState::Assemble),
    (WorkflowState::DirectProving, WorkflowState::BranchPrepare),
    (WorkflowState::BranchPrepare, WorkflowState::BranchRun),
    (WorkflowState::BranchRun, WorkflowState::BranchRun),
    (WorkflowState::BranchRun, WorkflowState::BranchJoin),
    (WorkflowState::BranchJoin, WorkflowState::Assemble),
    (WorkflowState::BranchJoin, WorkflowState::IdentifyFailures),
    (WorkflowState::IdentifyFailures, WorkflowState::Replan),
    (WorkflowState::Replan, WorkflowState::ProposePlans),
    (WorkflowState::Assemble, WorkflowState::LatexValidate),
    (WorkflowState::Assemble, WorkflowState::Explore),
    (WorkflowState::LatexValidate, WorkflowState::Verify),
    (WorkflowState::LatexValidate, WorkflowState::Repair),
    (WorkflowState::Verify, WorkflowState::Finalize),
    (WorkflowState::Verify, WorkflowState::Repair),
    (WorkflowState::Verify, WorkflowState::Explore),
    (WorkflowState::Repair, WorkflowState::LatexValidate),
    (WorkflowState::Finalize, WorkflowState::Done),
    (WorkflowState::BranchRun, WorkflowState::Cancelled),
];

#[must_use]
pub fn allowed_transition(before: WorkflowState, after: WorkflowState) -> bool {
    matches!(after, WorkflowState::Cancelled | WorkflowState::Failed)
        || ALLOWED_TRANSITIONS.contains(&(before, after))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionRequest {
    pub run_id: String,
    pub before: WorkflowState,
    pub after: WorkflowState,
    pub actor: String,
    pub reason: String,
    pub trace_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionDecision {
    request: TransitionRequest,
}

impl TransitionDecision {
    pub fn validate(request: TransitionRequest) -> Result<Self, ReCtmError> {
        if !allowed_transition(request.before, request.after) {
            return Err(ReCtmError::new(
                "INVALID_STATE_TRANSITION",
                format!(
                    "Transition is not allowed: {} -> {}",
                    state_name(request.before),
                    state_name(request.after)
                ),
            )
            .with_category(ErrorCategory::Internal));
        }
        Ok(Self { request })
    }

    #[must_use]
    pub fn request(&self) -> &TransitionRequest {
        &self.request
    }
}

/// An authority-bearing value proving that all mechanical finalization gates were
/// checked for one exact proof. Its fields are private and there is no public
/// constructor; only the verifier module can issue it after validation.
#[derive(Debug)]
pub struct FinalizationPermit {
    run_id: String,
    proof_sha256: String,
    proof_manifest_sha256: Option<String>,
    verifier_domain_id: String,
}

impl FinalizationPermit {
    pub(crate) fn issue(
        run_id: String,
        proof_sha256: String,
        proof_manifest_sha256: Option<String>,
        verifier_domain_id: String,
    ) -> Self {
        Self {
            run_id,
            proof_sha256,
            proof_manifest_sha256,
            verifier_domain_id,
        }
    }

    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    #[must_use]
    pub fn proof_sha256(&self) -> &str {
        &self.proof_sha256
    }

    #[must_use]
    pub fn proof_manifest_sha256(&self) -> Option<&str> {
        self.proof_manifest_sha256.as_deref()
    }

    #[must_use]
    pub fn verifier_domain_id(&self) -> &str {
        &self.verifier_domain_id
    }
}

fn state_name(state: WorkflowState) -> &'static str {
    match state {
        WorkflowState::Created => "created",
        WorkflowState::Assess => "assess",
        WorkflowState::Explore => "explore",
        WorkflowState::ProposePlans => "propose_plans",
        WorkflowState::DirectProving => "direct_proving",
        WorkflowState::BranchPrepare => "branch_prepare",
        WorkflowState::BranchRun => "branch_run",
        WorkflowState::BranchJoin => "branch_join",
        WorkflowState::IdentifyFailures => "identify_failures",
        WorkflowState::Replan => "replan",
        WorkflowState::Assemble => "assemble",
        WorkflowState::LatexValidate => "latex_validate",
        WorkflowState::Verify => "verify",
        WorkflowState::Repair => "repair",
        WorkflowState::Finalize => "finalize",
        WorkflowState::Done => "done",
        WorkflowState::Cancelled => "cancelled",
        WorkflowState::Failed => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_transition_graph_is_fail_closed() {
        assert!(allowed_transition(
            WorkflowState::Assess,
            WorkflowState::Explore
        ));
        assert!(allowed_transition(
            WorkflowState::Verify,
            WorkflowState::Finalize
        ));
        assert!(!allowed_transition(
            WorkflowState::Assess,
            WorkflowState::Done
        ));
        assert!(!allowed_transition(
            WorkflowState::Finalize,
            WorkflowState::Verify
        ));
    }
}
