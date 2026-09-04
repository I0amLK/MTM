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
    DEFAULT_PERMISSION_TTL_SECONDS, MAX_PERMISSION_TTL_SECONDS, NativePermissionRequest,
    canonical_arguments_sha256, native_mode_implicitly_grants,
};
pub use patch::{PatchOperation, apply_update_hunks, parse_patch};
pub use path_policy::validate_workspace_path;
pub use redaction::{redact_bytes, redact_json, token_fingerprint};
pub use schema::validate_schema_value;
pub use url_policy::{
    extract_quick_tunnel_origin, validate_oauth_server_url, validate_redirect_uris,
};
