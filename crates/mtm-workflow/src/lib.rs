#![forbid(unsafe_code)]

pub mod engine;
pub mod kernel;
pub mod methodology;
pub mod vault;
pub mod verifier;

pub use engine::{
    LatexGate, LatexGateResult, StartRequest, WorkflowEngine, WorkflowEvent, WorkflowObserver,
};
pub use kernel::{FinalizationPermit, TransitionDecision, TransitionRequest, allowed_transition};
pub use methodology::TaskCatalog;
pub use vault::{BRANCH_CHANNELS, GENERATION_CHANNELS, PrivateVault, VERIFIER_CHANNELS};
pub use verifier::{VerificationDecision, VerificationFinding, VerificationReport};
