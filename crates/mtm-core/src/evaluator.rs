use std::collections::BTreeMap;

use mtm_contracts::{ErrorCategory, NativeMode, ReCtmError, WorkflowState, invalid_argument};
use serde_json::{Map, Value};

use crate::{
    apply_update_hunks, check_command_policy, extract_quick_tunnel_origin, inline_script_command,
    is_filtered_env_var, parse_patch, redact_bytes, redact_json, token_fingerprint,
    validate_oauth_server_url, validate_redirect_uris, validate_schema_value,
    validate_workspace_path,
};

pub fn evaluate_request(request: &Value) -> Result<Value, ReCtmError> {
    let object = request
        .as_object()
        .ok_or_else(|| invalid_argument("request must be an object"))?;
    let operation = required_string(object, "operation")?;
    match operation {
        "schema_validate" => {
            let value = required_value(object, "value")?;
            let schema = required_value(object, "schema")?;
            let path = optional_string(object, "path").unwrap_or("arguments");
            validate_schema_value(value, schema, path)?;
            Ok(serde_json::json!({"valid": true}))
        }
        "redact" => redact_json(required_value(object, "value")?),
        "fingerprint" => {
            let value = required_string(object, "value")?;
            Ok(Value::String(token_fingerprint(value.as_bytes())))
        }
        "redact_bytes" => {
            let value = required_string(object, "value")?;
            Ok(Value::String(redact_bytes(value.as_bytes())))
        }
        "oauth_server_url" => {
            validate_oauth_server_url(required_string(object, "value")?)?;
            Ok(serde_json::json!({"valid": true}))
        }
        "redirect_uris" => Ok(Value::Array(
            validate_redirect_uris(required_value(object, "value")?)?
                .into_iter()
                .map(Value::String)
                .collect(),
        )),
        "quick_tunnel_origin" => Ok(extract_quick_tunnel_origin(required_string(
            object, "value",
        )?)?
        .map_or(Value::Null, Value::String)),
        "workspace_path" => Ok(Value::String(validate_workspace_path(required_string(
            object, "value",
        )?)?)),
        "filtered_env" => Ok(Value::Bool(is_filtered_env_var(
            required_string(object, "name")?,
            required_string(object, "value")?,
        )?)),
        "inline_script" => to_value(inline_script_command(required_string(object, "value")?)),
        "command_policy" => evaluate_command_policy(object),
        "parse_patch" => to_value(parse_patch(required_string(object, "value")?)?),
        "apply_hunks" => evaluate_apply_hunks(object),
        "workflow_terminal" => {
            let state: WorkflowState =
                serde_json::from_value(Value::String(required_string(object, "value")?.to_owned()))
                    .map_err(|_| invalid_argument("value must be a recognized workflow state"))?;
            Ok(Value::Bool(state.terminal()))
        }
        _ => Err(invalid_argument(format!(
            "unknown pure policy operation: {operation}"
        ))),
    }
}

fn evaluate_command_policy(object: &Map<String, Value>) -> Result<Value, ReCtmError> {
    let mode: NativeMode =
        serde_json::from_value(Value::String(required_string(object, "mode")?.to_owned()))
            .map_err(|_| invalid_argument("mode must be safe, trusted, or dangerous"))?;
    let command = required_string(object, "command")?;
    let empty_environment = Value::Object(Map::new());
    let environment_value = object.get("env").unwrap_or(&empty_environment);
    let environment_object = environment_value
        .as_object()
        .ok_or_else(|| invalid_argument("env must be an object of string values"))?;
    let mut environment = BTreeMap::new();
    for (key, value) in environment_object {
        let text = value
            .as_str()
            .ok_or_else(|| invalid_argument("env must be an object of string values"))?;
        environment.insert(key.clone(), text.to_owned());
    }
    check_command_policy(mode, command, &environment)?;
    Ok(serde_json::json!({"allowed": true}))
}

fn evaluate_apply_hunks(object: &Map<String, Value>) -> Result<Value, ReCtmError> {
    let content = required_string(object, "content")?;
    let path = required_string(object, "path")?;
    let hunk_values = required_value(object, "hunks")?
        .as_array()
        .ok_or_else(|| invalid_argument("hunks must be an array of string arrays"))?;
    let mut hunks = Vec::with_capacity(hunk_values.len());
    for hunk in hunk_values {
        let lines = hunk
            .as_array()
            .ok_or_else(|| invalid_argument("hunks must be an array of string arrays"))?;
        let mut parsed = Vec::with_capacity(lines.len());
        for line in lines {
            parsed.push(
                line.as_str()
                    .ok_or_else(|| invalid_argument("hunk lines must be strings"))?
                    .to_owned(),
            );
        }
        hunks.push(parsed);
    }
    Ok(Value::String(apply_update_hunks(content, &hunks, path)?))
}

fn required_value<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Value, ReCtmError> {
    object
        .get(key)
        .ok_or_else(|| invalid_argument(format!("{key} is required")))
}

fn required_string<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, ReCtmError> {
    required_value(object, key)?
        .as_str()
        .ok_or_else(|| invalid_argument(format!("{key} must be a string")))
}

fn optional_string<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

fn to_value<T: serde::Serialize>(value: T) -> Result<Value, ReCtmError> {
    serde_json::to_value(value).map_err(|error| {
        ReCtmError::new(
            "INTERNAL_SERIALIZATION_ERROR",
            format!("Failed to serialize pure policy result: {error}"),
        )
        .with_category(ErrorCategory::Internal)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluator_wraps_pure_operations() -> Result<(), ReCtmError> {
        assert_eq!(
            evaluate_request(&serde_json::json!({
                "operation": "workspace_path",
                "value": "./a//b"
            }))?,
            Value::String("a/b".to_owned())
        );
        assert_eq!(
            evaluate_request(&serde_json::json!({
                "operation": "workflow_terminal",
                "value": "done"
            }))?,
            Value::Bool(true)
        );
        Ok(())
    }
}
