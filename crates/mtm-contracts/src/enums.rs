use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeMode {
    Safe,
    Trusted,
    Dangerous,
}

impl NativeMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Trusted => "trusted",
            Self::Dangerous => "dangerous",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowRole {
    Generator,
    Branch,
    Join,
    Assembler,
    Verifier,
    Repair,
    Finalizer,
}

impl WorkflowRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Generator => "generator",
            Self::Branch => "branch",
            Self::Join => "join",
            Self::Assembler => "assembler",
            Self::Verifier => "verifier",
            Self::Repair => "repair",
            Self::Finalizer => "finalizer",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowState {
    Created,
    Assess,
    Explore,
    ProposePlans,
    DirectProving,
    BranchPrepare,
    BranchRun,
    BranchJoin,
    IdentifyFailures,
    Replan,
    Assemble,
    LatexValidate,
    Verify,
    Repair,
    Finalize,
    Done,
    Cancelled,
    Failed,
}

impl WorkflowState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Assess => "assess",
            Self::Explore => "explore",
            Self::ProposePlans => "propose_plans",
            Self::DirectProving => "direct_proving",
            Self::BranchPrepare => "branch_prepare",
            Self::BranchRun => "branch_run",
            Self::BranchJoin => "branch_join",
            Self::IdentifyFailures => "identify_failures",
            Self::Replan => "replan",
            Self::Assemble => "assemble",
            Self::LatexValidate => "latex_validate",
            Self::Verify => "verify",
            Self::Repair => "repair",
            Self::Finalize => "finalize",
            Self::Done => "done",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }

    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Done | Self::Cancelled | Self::Failed)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStatus {
    Open,
    Sealed,
    Cancelled,
}

impl DomainStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatexPolicy {
    StaticOnly,
    IfAvailable,
    Required,
}

impl LatexPolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaticOnly => "static_only",
            Self::IfAvailable => "if_available",
            Self::Required => "required",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_terminal_states_match_source() {
        assert!(WorkflowState::Done.terminal());
        assert!(WorkflowState::Cancelled.terminal());
        assert!(WorkflowState::Failed.terminal());
        assert!(!WorkflowState::Verify.terminal());
    }

    #[test]
    fn enum_wire_values_match_source() -> Result<(), serde_json::Error> {
        assert_eq!(
            serde_json::to_string(&NativeMode::Dangerous)?,
            "\"dangerous\""
        );
        assert_eq!(
            serde_json::to_string(&WorkflowState::DirectProving)?,
            "\"direct_proving\""
        );
        Ok(())
    }
}
