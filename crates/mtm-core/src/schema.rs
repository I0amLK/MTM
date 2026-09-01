use mtm_contracts::{ErrorCategory, ReCtmError, invalid_argument};
use regex::Regex;
use serde_json::{Map, Number, Value};

pub fn validate_schema_value(value: &Value, schema: &Value, path: &str) -> Result<(), ReCtmError> {
    let schema_object = schema.as_object().ok_or_else(|| {
        ReCtmError::new("SCHEMA_INVALID", "Schema must be an object.")
            .with_category(ErrorCategory::Internal)
    })?;

    if let Some(expected) = schema_object.get("const")
        && value != expected
    {
        return Err(invalid_argument(format!(
            "{path} must equal {}",
            python_repr(expected)
        )));
    }

    if let Some(one_of) = schema_object.get("oneOf").and_then(Value::as_array) {
        let matches = one_of
            .iter()
            .filter(|candidate| candidate.is_object())
            .filter(|candidate| validate_schema_value(value, candidate, path).is_ok())
            .count();
        if matches != 1 {
            return Err(invalid_argument(format!(
                "{path} must match exactly one oneOf schema"
            )));
        }
    }

    if let Some(any_of) = schema_object.get("anyOf").and_then(Value::as_array)
        && !any_of
            .iter()
            .filter(|candidate| candidate.is_object())
            .any(|candidate| validate_schema_value(value, candidate, path).is_ok())
    {
        return Err(invalid_argument(format!(
            "{path} must match at least one anyOf schema"
        )));
    }

    if let Some(expected_type) = schema_object.get("type")
        && !schema_type_matches(value, expected_type)
    {
        return Err(invalid_argument(format!(
            "{path} must be {}",
            schema_type_name(expected_type)
        )));
    }

    match value {
        Value::String(text) => validate_string(text, schema_object, path)?,
        Value::Number(number) if number.is_i64() || number.is_u64() => {
            validate_integer(number, schema_object, path)?;
        }
        Value::Array(items) => validate_array(items, schema_object, path)?,
        Value::Object(object) => validate_object(object, schema_object, path)?,
        _ => {}
    }
    Ok(())
}

fn validate_string(text: &str, schema: &Map<String, Value>, path: &str) -> Result<(), ReCtmError> {
    let length = text.chars().count();
    if let Some(minimum) = schema.get("minLength").and_then(Value::as_u64)
        && length < usize_from_u64(minimum)
    {
        return Err(invalid_argument(format!(
            "{path} is shorter than {minimum}"
        )));
    }
    if let Some(maximum) = schema.get("maxLength").and_then(Value::as_u64)
        && length > usize_from_u64(maximum)
    {
        return Err(invalid_argument(format!("{path} is longer than {maximum}")));
    }
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
        let full_pattern = format!(r"\A(?:{pattern})\z");
        let regex = Regex::new(&full_pattern).map_err(|error| {
            ReCtmError::new(
                "SCHEMA_PATTERN_INVALID",
                format!("Schema pattern is invalid: {error}"),
            )
            .with_category(ErrorCategory::Internal)
        })?;
        if !regex.is_match(text) {
            return Err(invalid_argument(format!(
                "{path} does not match the required pattern"
            )));
        }
    }
    if let Some(options) = schema.get("enum").and_then(Value::as_array)
        && !options.iter().any(|candidate| candidate == text)
    {
        return Err(invalid_argument(format!(
            "{path} must be one of {}",
            python_repr(&Value::Array(options.clone()))
        )));
    }
    Ok(())
}

fn validate_integer(
    number: &Number,
    schema: &Map<String, Value>,
    path: &str,
) -> Result<(), ReCtmError> {
    let value = number_as_f64(number);
    if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64)
        && value < minimum
    {
        return Err(invalid_argument(format!(
            "{path} must be >= {}",
            number_text(schema.get("minimum"), minimum)
        )));
    }
    if let Some(maximum) = schema.get("maximum").and_then(Value::as_f64)
        && value > maximum
    {
        return Err(invalid_argument(format!(
            "{path} must be <= {}",
            number_text(schema.get("maximum"), maximum)
        )));
    }
    Ok(())
}

fn validate_array(
    items: &[Value],
    schema: &Map<String, Value>,
    path: &str,
) -> Result<(), ReCtmError> {
    if let Some(minimum) = schema.get("minItems").and_then(Value::as_u64)
        && items.len() < usize_from_u64(minimum)
    {
        return Err(invalid_argument(format!(
            "{path} must contain at least {minimum} items"
        )));
    }
    if let Some(item_schema) = schema.get("items").filter(|value| value.is_object()) {
        for (index, item) in items.iter().enumerate() {
            validate_schema_value(item, item_schema, &format!("{path}[{index}]"))?;
        }
    }
    Ok(())
}

fn validate_object(
    object: &Map<String, Value>,
    schema: &Map<String, Value>,
    path: &str,
) -> Result<(), ReCtmError> {
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for key in required.iter().filter_map(Value::as_str) {
            if !object.contains_key(key) {
                return Err(invalid_argument(format!("{path}.{key} is required")));
            }
        }
    }
    let properties = schema.get("properties").and_then(Value::as_object);
    let additional = schema.get("additionalProperties");
    for (key, item) in object {
        let child_path = format!("{path}.{key}");
        if let Some(child_schema) = properties.and_then(|items| items.get(key))
            && child_schema.is_object()
        {
            validate_schema_value(item, child_schema, &child_path)?;
        } else if additional == Some(&Value::Bool(false)) {
            return Err(invalid_argument(format!(
                "{child_path} is not a recognized argument"
            )));
        } else if let Some(additional_schema) = additional.filter(|value| value.is_object()) {
            validate_schema_value(item, additional_schema, &child_path)?;
        }
    }
    Ok(())
}

fn schema_type_matches(value: &Value, expected: &Value) -> bool {
    if let Some(types) = expected.as_array() {
        return types.iter().any(|item| schema_type_matches(value, item));
    }
    match expected.as_str() {
        Some("array") => value.is_array(),
        Some("boolean") => value.is_boolean(),
        Some("integer") => value.as_i64().is_some() || value.as_u64().is_some(),
        Some("null") => value.is_null(),
        Some("number") => value.is_number(),
        Some("object") => value.is_object(),
        Some("string") => value.is_string(),
        _ => false,
    }
}

fn schema_type_name(expected: &Value) -> String {
    if let Some(types) = expected.as_array() {
        return types
            .iter()
            .map(|item| {
                item.as_str()
                    .map_or_else(|| item.to_string(), str::to_owned)
            })
            .collect::<Vec<_>>()
            .join(" or ");
    }
    expected
        .as_str()
        .map_or_else(|| expected.to_string(), str::to_owned)
}

fn python_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => format!("'{}'", escape_python_string(text)),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(python_repr).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(items) => format!(
            "{{{}}}",
            items
                .iter()
                .map(|(key, item)| format!(
                    "'{}': {}",
                    escape_python_string(key),
                    python_repr(item)
                ))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn escape_python_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn number_as_f64(number: &Number) -> f64 {
    number
        .as_i64()
        .map(|value| value as f64)
        .or_else(|| number.as_u64().map(|value| value as f64))
        .unwrap_or(0.0)
}

fn number_text(original: Option<&Value>, fallback: f64) -> String {
    original.map_or_else(|| fallback.to_string(), Value::to_string)
}

fn usize_from_u64(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_nested_object_and_rejects_extra_field() -> Result<(), &'static str> {
        let schema = serde_json::json!({
            "type": "object",
            "required": ["name"],
            "additionalProperties": false,
            "properties": {
                "name": {"type": "string", "minLength": 1},
                "count": {"type": "integer", "minimum": 1}
            }
        });
        assert!(
            validate_schema_value(
                &serde_json::json!({"name": "x", "count": 2}),
                &schema,
                "arguments"
            )
            .is_ok()
        );
        let result = validate_schema_value(
            &serde_json::json!({"name": "x", "extra": true}),
            &schema,
            "arguments",
        );
        let error = match result {
            Ok(()) => return Err("extra field unexpectedly passed"),
            Err(error) => error,
        };
        assert_eq!(error.code, "INVALID_ARGUMENT");
        assert_eq!(
            error.message,
            "arguments.extra is not a recognized argument"
        );
        Ok(())
    }

    #[test]
    fn one_of_requires_exactly_one_match() -> Result<(), &'static str> {
        let schema = serde_json::json!({
            "oneOf": [
                {"type": "object", "required": ["a"]},
                {"type": "object", "required": ["b"]}
            ]
        });
        let result =
            validate_schema_value(&serde_json::json!({"a": 1, "b": 2}), &schema, "arguments");
        let error = match result {
            Ok(()) => return Err("two oneOf branches unexpectedly passed"),
            Err(error) => error,
        };
        assert_eq!(
            error.message,
            "arguments must match exactly one oneOf schema"
        );
        Ok(())
    }
}
