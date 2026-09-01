use mtm_contracts::{ErrorCategory, ReCtmError};
use regex::{Regex, RegexBuilder};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const SENSITIVE_KEY_PATTERN: &str =
    r"(token|secret|password|authorization|credential|api[_-]?key|code_verifier|code_challenge)";
const SENSITIVE_VALUE_PATTERN: &str =
    r"(Bearer\s+[A-Za-z0-9._~+/=-]+|sk-[A-Za-z0-9_-]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)";

#[must_use]
pub fn token_fingerprint(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    let encoded = format!("{digest:x}");
    encoded.chars().take(12).collect()
}

pub fn redact_json(value: &Value) -> Result<Value, ReCtmError> {
    let key_regex = case_insensitive_regex(SENSITIVE_KEY_PATTERN)?;
    let value_regex = case_insensitive_regex(SENSITIVE_VALUE_PATTERN)?;
    Ok(redact_value(value, &key_regex, &value_regex))
}

#[must_use]
pub fn redact_bytes(value: &[u8]) -> String {
    format!("<bytes:{}:{}>", value.len(), token_fingerprint(value))
}

fn redact_value(value: &Value, key_regex: &Regex, value_regex: &Regex) -> Value {
    match value {
        Value::Object(items) => {
            let mut result = Map::new();
            for (key, item) in items {
                let safe = if key_regex.is_match(key) {
                    Value::String("<redacted>".to_owned())
                } else {
                    redact_value(item, key_regex, value_regex)
                };
                result.insert(key.clone(), safe);
            }
            Value::Object(result)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| redact_value(item, key_regex, value_regex))
                .collect(),
        ),
        Value::String(text) => {
            Value::String(value_regex.replace_all(text, "<redacted>").into_owned())
        }
        _ => value.clone(),
    }
}

fn case_insensitive_regex(pattern: &str) -> Result<Regex, ReCtmError> {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .map_err(|error| {
            ReCtmError::new(
                "INTERNAL_REGEX_ERROR",
                format!("Internal redaction pattern is invalid: {error}"),
            )
            .with_category(ErrorCategory::Internal)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_match_sha256_prefix() {
        assert_eq!(token_fingerprint(b"abc"), "ba7816bf8f01");
        assert_eq!(redact_bytes(b"abc"), "<bytes:3:ba7816bf8f01>");
    }

    #[test]
    fn redacts_keys_and_embedded_values() -> Result<(), ReCtmError> {
        let input = serde_json::json!({
            "password": "plain",
            "safe": "Bearer abc.def-123",
            "nested": [{"api_key": "value"}]
        });
        assert_eq!(
            redact_json(&input)?,
            serde_json::json!({
                "password": "<redacted>",
                "safe": "<redacted>",
                "nested": [{"api_key": "<redacted>"}]
            })
        );
        Ok(())
    }
}
