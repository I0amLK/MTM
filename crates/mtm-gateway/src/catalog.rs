use std::collections::{BTreeMap, BTreeSet};

use mtm_contracts::{ErrorCategory, ReCtmError};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const PUBLIC_TOOL_NAMES: [&str; 24] = [
    "server_info",
    "check_exec_environment",
    "read_file",
    "list_dir",
    "list_files",
    "search_text",
    "apply_patch",
    "exec_command",
    "write_stdin",
    "kill_command",
    "read_output",
    "git_status",
    "git_diff",
    "git_log",
    "git_show",
    "git_blame",
    "request_permissions",
    "view_image",
    "rethlas_start",
    "rethlas_step",
    "rethlas_inspect",
    "rethlas_retrieve",
    "rethlas_control",
    "rethlas_artifact",
];

pub const HIDDEN_TOOL_NAMES: [&str; 11] = [
    "rethlas_next",
    "rethlas_read",
    "rethlas_write",
    "rethlas_search",
    "rethlas_commit",
    "rethlas_status",
    "rethlas_steer",
    "rethlas_resume",
    "rethlas_cancel",
    "rethlas_get_artifact",
    "rethlas_export_final",
];

pub const PUBLIC_CATALOG_SHA256: &str =
    "86c8ee7d53a0678d0aaaba47ce2f2f72f5c03747fcb443d78011e005dedaa343";
pub const ALL_TOOL_DEFINITIONS_SHA256: &str =
    "e89c5d2f8bec198fb4a90e7166aadb04b757e4b3ff0c8f459e5fdd468c59f87e";

#[derive(Clone, Debug)]
pub struct ToolCatalog {
    definitions: BTreeMap<String, Value>,
}

impl ToolCatalog {
    pub fn from_source_snapshot(snapshot: &Value) -> Result<Self, ReCtmError> {
        let object = snapshot.as_object().ok_or_else(catalog_error)?;
        let public_names = string_array(object.get("public_names"))?;
        let hidden_names = string_array(object.get("hidden_names"))?;
        if public_names != PUBLIC_TOOL_NAMES.map(str::to_owned) {
            return Err(catalog_error());
        }
        if hidden_names != HIDDEN_TOOL_NAMES.map(str::to_owned) {
            return Err(catalog_error());
        }
        let raw_definitions = object
            .get("definitions")
            .and_then(Value::as_object)
            .ok_or_else(catalog_error)?;
        let expected_names = PUBLIC_TOOL_NAMES
            .iter()
            .chain(HIDDEN_TOOL_NAMES.iter())
            .copied()
            .collect::<BTreeSet<_>>();
        let actual_names = raw_definitions
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if actual_names != expected_names {
            return Err(catalog_error());
        }
        let definitions = raw_definitions
            .iter()
            .map(|(name, definition)| {
                if definition.get("name").and_then(Value::as_str) != Some(name) {
                    return Err(catalog_error());
                }
                Ok((name.clone(), definition.clone()))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let all_value = Value::Object(
            definitions
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        );
        if sha256_canonical(&all_value)? != ALL_TOOL_DEFINITIONS_SHA256 {
            return Err(catalog_error());
        }
        let public = Value::Array(
            PUBLIC_TOOL_NAMES
                .iter()
                .map(|name| definitions.get(*name).cloned().ok_or_else(catalog_error))
                .collect::<Result<Vec<_>, _>>()?,
        );
        if sha256_canonical(&public)? != PUBLIC_CATALOG_SHA256 {
            return Err(catalog_error());
        }
        Ok(Self { definitions })
    }

    #[must_use]
    pub fn list_public(&self) -> Vec<Value> {
        PUBLIC_TOOL_NAMES
            .iter()
            .filter_map(|name| self.definitions.get(*name).cloned())
            .collect()
    }

    #[must_use]
    pub fn definition(&self, name: &str) -> Option<&Value> {
        self.definitions.get(name)
    }

    #[must_use]
    pub fn input_schema(&self, name: &str) -> Option<&Value> {
        self.definition(name)?.get("inputSchema")
    }

    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.definitions.contains_key(name)
    }
}

fn string_array(value: Option<&Value>) -> Result<Vec<String>, ReCtmError> {
    value
        .and_then(Value::as_array)
        .ok_or_else(catalog_error)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned).ok_or_else(catalog_error))
        .collect()
}

fn sha256_canonical(value: &Value) -> Result<String, ReCtmError> {
    let canonical = serde_json::to_vec(&sort_json(value)).map_err(|error| {
        ReCtmError::new("TOOL_CATALOG_SERIALIZATION_ERROR", error.to_string())
            .with_category(ErrorCategory::Internal)
    })?;
    let mut digest = Sha256::new();
    digest.update(canonical);
    Ok(format!("{:x}", digest.finalize()))
}

fn sort_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, item)| (key.clone(), sort_json(item)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect::<Map<_, _>>(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(sort_json).collect()),
        _ => value.clone(),
    }
}

fn catalog_error() -> ReCtmError {
    ReCtmError::new(
        "TOOL_CATALOG_MISMATCH",
        "Tool catalog does not match the frozen Re-CTM 0.3.0 contract.",
    )
    .with_category(ErrorCategory::Security)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_catalog_is_rejected() {
        let snapshot = serde_json::json!({
            "public_names": PUBLIC_TOOL_NAMES,
            "hidden_names": HIDDEN_TOOL_NAMES,
            "definitions": {},
        });
        let code = match ToolCatalog::from_source_snapshot(&snapshot) {
            Ok(_) => String::new(),
            Err(error) => error.code,
        };
        assert_eq!(code, "TOOL_CATALOG_MISMATCH");
    }
}
