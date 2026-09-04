#![forbid(unsafe_code)]

mod command_policy;
mod evaluator;
mod native_permission;
mod patch;
mod path_policy;
mod redaction;
mod schema;
mod url_policy;

pub use command_policy::{
    InlineScript, check_command_policy, classify_current_command_permissions,
    inline_script_command, is_filtered_env_var,
};
pub use evaluator::evaluate_request;
pub use native_permission::{
    CANONICAL_GENERATED_OR_EXCLUDED_COMPONENTS, DEFAULT_EXEC_MAX_OUTPUT_BYTES,
    DEFAULT_EXEC_PREVIEW_BYTES, DEFAULT_EXEC_TIMEOUT_MS, DEFAULT_EXEC_YIELD_TIME_MS,
    DEFAULT_PERMISSION_TTL_SECONDS, EffectiveNativePolicy, ExecInvocation, ExecInvocationForm,
    ExecPermissionFacts, LONG_TIMEOUT_THRESHOLD_MS_EXCLUSIVE, MAX_EXEC_MAX_OUTPUT_BYTES,
    MAX_EXEC_PREVIEW_BYTES, MAX_EXEC_TIMEOUT_MS, MAX_EXEC_YIELD_TIME_MS,
    MAX_PERMISSION_TTL_SECONDS, NativeEffectivePolicy, NativeInvocation, NativePermissionRequest,
    PatchInvocation, PatchPathFact, ResolvedExecutableFact, canonical_arguments_sha256,
    classify_exec_permissions, classify_patch_permissions, exec_permission_order,
    generated_or_excluded_components, has_canonical_generated_component,
    native_mode_implicitly_grants,
};
pub use patch::{PatchOperation, apply_update_hunks, parse_patch};
pub use path_policy::validate_workspace_path;
pub use redaction::{redact_bytes, redact_json, token_fingerprint};
pub use schema::validate_schema_value;
pub use url_policy::{
    extract_quick_tunnel_origin, validate_oauth_server_url, validate_redirect_uris,
};
