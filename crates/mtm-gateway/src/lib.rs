#![forbid(unsafe_code)]

pub mod catalog;
pub mod http;
pub mod mcp;
pub mod oauth;
pub mod runtime;

pub use catalog::{
    CAPABILITY_LIFECYCLE, NATIVE_TOOL_COUNT, PUBLIC_TOOL_NAMES, TOOL_CONTRACT_VERSION, ToolCatalog,
    ToolId,
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
