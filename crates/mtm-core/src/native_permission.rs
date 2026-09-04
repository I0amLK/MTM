use std::collections::BTreeMap;

use mtm_contracts::{
    NativeMode, NativePermissionKind, NativePermissionScope, NativePermissionTool, ReCtmError,
    invalid_argument,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const DEFAULT_PERMISSION_TTL_SECONDS: u64 = 300;
pub const MAX_PERMISSION_TTL_SECONDS: u64 = 3_600;

/// Validated, non-authority-bearing form of the public `request_permissions` input.
///
/// The raw nested `arguments` object is deliberately not retained. Later grant records
/// bind this canonical digest together with authenticated owner/workspace facts and the
/// validated tool/kind/scope. Parsing a request never grants permission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativePermissionRequest {
    tool: NativePermissionTool,
    kind: NativePermissionKind,
    reason: String,
    arguments_sha256: String,
    scope: NativePermissionScope,
    ttl_seconds: u64,
}

impl NativePermissionRequest {
    pub fn parse(input: &Map<String, Value>) -> Result<Self, ReCtmError> {
        let tool = input
            .get("tool_name")
            .and_then(Value::as_str)
            .and_then(NativePermissionTool::from_wire)
            .ok_or_else(|| invalid_argument("tool_name must be exec_command or apply_patch"))?;
        let kind = input
            .get("permission")
            .and_then(Value::as_str)
            .and_then(NativePermissionKind::from_wire)
            .ok_or_else(|| {
                invalid_argument("permission is not a supported Native permission kind")
            })?;
        let reason = input
            .get("reason")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid_argument("reason must be a non-empty string"))?
            .to_owned();
        let arguments = input
            .get("arguments")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid_argument("arguments must be an object"))?;
        let scope = match input.get("scope") {
            None => NativePermissionScope::Once,
            Some(Value::String(value)) => NativePermissionScope::from_wire(value)
                .ok_or_else(|| invalid_argument("scope must be once or session"))?,
            Some(_) => return Err(invalid_argument("scope must be once or session")),
        };
        let ttl_seconds = match input.get("ttl_seconds") {
            None => DEFAULT_PERMISSION_TTL_SECONDS,
            Some(Value::Number(number)) => number
                .as_u64()
                .filter(|value| (1..=MAX_PERMISSION_TTL_SECONDS).contains(value))
                .ok_or_else(|| {
                    invalid_argument("ttl_seconds must be an integer between 1 and 3600")
                })?,
            Some(_) => {
                return Err(invalid_argument(
                    "ttl_seconds must be an integer between 1 and 3600",
                ));
            }
        };
        Ok(Self {
            tool,
            kind,
            reason,
            arguments_sha256: canonical_arguments_sha256(arguments)?,
            scope,
            ttl_seconds,
        })
    }

    #[must_use]
    pub const fn tool(&self) -> NativePermissionTool {
        self.tool
    }

    #[must_use]
    pub const fn kind(&self) -> NativePermissionKind {
        self.kind
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    #[must_use]
    pub fn arguments_sha256(&self) -> &str {
        &self.arguments_sha256
    }

    #[must_use]
    pub const fn scope(&self) -> NativePermissionScope {
        self.scope
    }

    #[must_use]
    pub const fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }
}

/// Return permissions implicitly present in the accepted Native mode profile.
///
/// This is profile data, not an explicit user grant, and it carries no workflow,
/// project, verifier, or finalizer authority.
#[must_use]
pub fn native_mode_implicitly_grants(mode: NativeMode, kind: NativePermissionKind) -> bool {
    match mode {
        NativeMode::Safe => false,
        NativeMode::Trusted => matches!(
            kind,
            NativePermissionKind::Network
                | NativePermissionKind::ShellExpansion
                | NativePermissionKind::InlineScript
        ),
        NativeMode::Dangerous => true,
    }
}

pub fn canonical_arguments_sha256(arguments: &Map<String, Value>) -> Result<String, ReCtmError> {
    let sorted = sort_json(&Value::Object(arguments.clone()));
    let bytes = serde_json::to_vec(&sorted)
        .map_err(|error| invalid_argument(format!("arguments are not serializable: {error}")))?;
    let digest = Sha256::digest(bytes);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn sort_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let sorted = object
                .iter()
                .map(|(key, value)| (key.clone(), sort_json(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_json).collect()),
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(arguments: Value) -> Map<String, Value> {
        serde_json::json!({
            "tool_name": "exec_command",
            "permission": "network",
            "reason": "fetch dependency metadata",
            "arguments": arguments,
        })
        .as_object()
        .cloned()
        .unwrap_or_default()
    }

    #[test]
    fn request_defaults_are_typed_and_digest_is_canonical() -> Result<(), ReCtmError> {
        let left = NativePermissionRequest::parse(&request(serde_json::json!({
            "cmd":"curl https://example.com",
            "env":{"B":"2","A":"1"}
        })))?;
        let right = NativePermissionRequest::parse(&request(serde_json::json!({
            "env":{"A":"1","B":"2"},
            "cmd":"curl https://example.com"
        })))?;
        assert_eq!(left.tool(), NativePermissionTool::ExecCommand);
        assert_eq!(left.kind(), NativePermissionKind::Network);
        assert_eq!(left.scope(), NativePermissionScope::Once);
        assert_eq!(left.ttl_seconds(), DEFAULT_PERMISSION_TTL_SECONDS);
        assert_eq!(left.reason(), "fetch dependency metadata");
        assert_eq!(left.arguments_sha256(), right.arguments_sha256());
        assert_eq!(left.arguments_sha256().len(), 64);
        Ok(())
    }

    #[test]
    fn request_binding_changes_when_arguments_change() -> Result<(), ReCtmError> {
        let left = NativePermissionRequest::parse(&request(serde_json::json!({
            "cmd":"curl https://a.example"
        })))?;
        let right = NativePermissionRequest::parse(&request(serde_json::json!({
            "cmd":"curl https://b.example"
        })))?;
        assert_ne!(left.arguments_sha256(), right.arguments_sha256());
        Ok(())
    }

    #[test]
    fn request_rejects_unknown_or_malformed_authority_fields() {
        for (key, value) in [
            ("tool_name", Value::String("rethlas_step".to_owned())),
            ("permission", Value::String("filesystem_escape".to_owned())),
            ("scope", Value::String("forever".to_owned())),
            ("ttl_seconds", Value::from(0)),
            ("ttl_seconds", Value::from(3_601)),
        ] {
            let mut input = request(serde_json::json!({"cmd":"true"}));
            input.insert(key.to_owned(), value);
            assert!(NativePermissionRequest::parse(&input).is_err());
        }
        let mut empty_reason = request(serde_json::json!({"cmd":"true"}));
        empty_reason.insert("reason".to_owned(), Value::String("   ".to_owned()));
        assert!(NativePermissionRequest::parse(&empty_reason).is_err());
        let mut non_object = request(serde_json::json!({"cmd":"true"}));
        non_object.insert("arguments".to_owned(), Value::String("true".to_owned()));
        assert!(NativePermissionRequest::parse(&non_object).is_err());
    }

    #[test]
    fn mode_profiles_are_explicit_data_not_workflow_authority() {
        for kind in NativePermissionKind::ALL {
            assert!(!native_mode_implicitly_grants(NativeMode::Safe, kind));
            assert!(native_mode_implicitly_grants(NativeMode::Dangerous, kind));
        }
        assert!(native_mode_implicitly_grants(
            NativeMode::Trusted,
            NativePermissionKind::Network
        ));
        assert!(native_mode_implicitly_grants(
            NativeMode::Trusted,
            NativePermissionKind::ShellExpansion
        ));
        assert!(native_mode_implicitly_grants(
            NativeMode::Trusted,
            NativePermissionKind::InlineScript
        ));
        for kind in [
            NativePermissionKind::DestructiveCommand,
            NativePermissionKind::LongTimeout,
            NativePermissionKind::SensitiveEnv,
            NativePermissionKind::PrivilegedExecutable,
            NativePermissionKind::WriteGeneratedOrIgnored,
        ] {
            assert!(!native_mode_implicitly_grants(NativeMode::Trusted, kind));
        }
    }
}
