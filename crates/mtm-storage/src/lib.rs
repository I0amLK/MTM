#![forbid(unsafe_code)]

pub mod capability;
pub mod schema;
pub mod store;

pub use capability::{
    CapabilityAuthority, CapabilityClaims, CapabilityEvent, CapabilityObserver,
    authorize_role_resource, claims_from_payload, default_permissions, role_for_state,
};
pub use store::{
    Clock, IdSource, StateStore, StoreRuntime, SystemClock, SystemIdSource, TransitionRun,
};
