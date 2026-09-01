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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatexPolicy {
    StaticOnly,
    IfAvailable,
    Required,
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
