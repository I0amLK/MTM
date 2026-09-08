#![forbid(unsafe_code)]

pub mod capability;
pub mod schema;
pub mod store;

pub use capability::{
    AuthorizedSubmission, CapabilityAuthority, CapabilityClaims, CapabilityEvent,
    CapabilityObserver, authorize_role_resource, default_permissions, role_for_state,
};
pub use store::{
    Clock, IdSource, StateStore, StoreRuntime, SubmissionDisposition, SubmissionReceipt,
    SubmissionReservation, SubmissionResult, SubmissionSlot, SystemClock, SystemIdSource,
    TransitionRun,
};
