#![forbid(unsafe_code)]

pub mod engine;
pub mod kernel;
pub mod methodology;
pub mod research;
pub mod research_state;
pub mod vault;
pub mod verifier;

pub use engine::{
    LatexGate, LatexGateResult, StartRequest, WorkflowEngine, WorkflowEvent, WorkflowObserver,
};
pub use kernel::{TransitionDecision, TransitionRequest, allowed_transition};
pub use methodology::TaskCatalog;
pub use research::{DisabledResearchProvider, ResearchProvider, ResearchRequest};
pub use vault::{BRANCH_CHANNELS, GENERATION_CHANNELS, PrivateVault, VERIFIER_CHANNELS};
pub use verifier::{VerificationDecision, VerificationFinding, VerificationReport};
