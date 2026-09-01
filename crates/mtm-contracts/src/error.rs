use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub trait IntoDetailsMap {
    fn into_details_map(self) -> Map<String, Value>;
}

impl IntoDetailsMap for Map<String, Value> {
    fn into_details_map(self) -> Map<String, Value> {
        self
    }
}

impl IntoDetailsMap for Value {
    fn into_details_map(self) -> Map<String, Value> {
        match self {
            Value::Object(map) => map,
            value => Map::from_iter([("value".to_owned(), value)]),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    Validation,
    Permission,
    Security,
    Conflict,
    Runtime,
    NotFound,
    Internal,
}

impl ErrorCategory {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Validation => "validation",
            Self::Permission => "permission",
            Self::Security => "security",
            Self::Conflict => "conflict",
            Self::Runtime => "runtime",
            Self::NotFound => "not_found",
            Self::Internal => "internal",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReCtmError {
    pub code: String,
    pub message: String,
    pub category: ErrorCategory,
    pub retryable: bool,
    pub details: Map<String, Value>,
}

impl ReCtmError {
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            category: ErrorCategory::Runtime,
            retryable: false,
            details: Map::new(),
        }
    }

    #[must_use]
    pub const fn with_category(mut self, category: ErrorCategory) -> Self {
        self.category = category;
        self
    }

    #[must_use]
    pub const fn with_retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    #[must_use]
    pub fn with_details(mut self, details: impl IntoDetailsMap) -> Self {
        self.details = details.into_details_map();
        self
    }

    #[must_use]
    pub fn to_payload(&self) -> Value {
        serde_json::json!({
            "code": self.code,
            "message": self.message,
            "category": self.category,
            "retryable": self.retryable,
            "details": self.details,
        })
    }
}

impl fmt::Display for ReCtmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ReCtmError {}

#[must_use]
pub fn invalid_argument(message: impl Into<String>) -> ReCtmError {
    ReCtmError::new("INVALID_ARGUMENT", message).with_category(ErrorCategory::Validation)
}

#[must_use]
pub fn permission_denied(message: impl Into<String>) -> ReCtmError {
    ReCtmError::new("PERMISSION_DENIED", message).with_category(ErrorCategory::Permission)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_matches_source_shape() {
        let error = invalid_argument("bad input");
        assert_eq!(
            error.to_payload(),
            serde_json::json!({
                "code": "INVALID_ARGUMENT",
                "message": "bad input",
                "category": "validation",
                "retryable": false,
                "details": {},
            })
        );
        assert_eq!(error.to_string(), "INVALID_ARGUMENT: bad input");
    }
}
