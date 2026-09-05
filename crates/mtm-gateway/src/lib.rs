#![forbid(unsafe_code)]

pub mod catalog;
pub mod http;
pub mod mcp;
pub mod oauth;
pub mod runtime;

pub use catalog::{
    ALL_TOOL_DEFINITIONS_SHA256, HIDDEN_TOOL_NAMES, PUBLIC_CATALOG_SHA256, PUBLIC_TOOL_NAMES,
    ToolCatalog,
};
pub use http::{GatewayHttpConfig, GatewayState, build_router, serve};
pub use mcp::{
    HEADER_MISMATCH, InputRequiredResult, LEGACY_PROTOCOL_VERSIONS, MCPDispatcher,
    MISSING_REQUIRED_CLIENT_CAPABILITY, MODERN_PROTOCOL_VERSIONS, SUPPORTED_PROTOCOL_VERSIONS,
    ToolBackend, ToolBackendResult, ToolCallContext,
};
pub use oauth::{OAuthPrincipal, OAuthService, OAuthStore};
pub use runtime::{
    EventSink, FixedClock, GatewayClock, GatewayRuntime, IdSource, SequenceIdSource, SystemClock,
    SystemIdSource,
};
