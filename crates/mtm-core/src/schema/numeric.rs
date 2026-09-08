//! Inclusive numeric bounds on serde_json's i64/u64/f64 representation.
//! Integer comparisons never round through f64. This is not arbitrary-precision
//! decimal validation and does not implement other JSON Schema numeric keywords.
use std::cmp::Ordering;

use mtm_contracts::{ErrorCategory, ReCtmError, invalid_argument};
use serde_json::{Map, Number, Value};

pub(super) fn validate(
    value: &Number,
    schema: &Map<String, Value>,
    path: &str,
) -> Result<(), ReCtmError> {
    for (keyword, forbidden, symbol) in [
        ("minimum", Ordering::Less, ">="),
        ("maximum", Ordering::Greater, "<="),
    ] {
        let Some(bound) = schema.get(keyword) else {
            continue;
        };
        let bound = bound.as_number().ok_or_else(|| {
            ReCtmError::new("SCHEMA_INVALID", "Numeric bounds must be JSON numbers.")
                .with_category(ErrorCategory::Internal)
        })?;
        if compare(value, bound)? == forbidden {
            return Err(invalid_argument(format!("{path} must be {symbol} {bound}")));
        }
    }
    Ok(())
}

fn integer(number: &Number) -> Option<i128> {
    number
        .as_i64()
        .map(i128::from)
        .or_else(|| number.as_u64().map(i128::from))
}

fn finite(number: &Number) -> Result<f64, ReCtmError> {
    number.as_f64().filter(|n| n.is_finite()).ok_or_else(|| {
        ReCtmError::new(
            "SCHEMA_INVALID",
            "Numeric comparison requires finite numbers.",
        )
        .with_category(ErrorCategory::Internal)
    })
}

fn compare(left: &Number, right: &Number) -> Result<Ordering, ReCtmError> {
    match (integer(left), integer(right)) {
        (Some(left), Some(right)) => Ok(left.cmp(&right)),
        (Some(left), None) => Ok(integer_float(left, finite(right)?)),
        (None, Some(right)) => Ok(integer_float(right, finite(left)?).reverse()),
        (None, None) => finite(left)?.partial_cmp(&finite(right)?).ok_or_else(|| {
            ReCtmError::new("SCHEMA_INVALID", "Numeric comparison was unordered.")
                .with_category(ErrorCategory::Internal)
        }),
    }
}

fn integer_float(integer: i128, float: f64) -> Ordering {
    // These powers of two are exact. The only integers handled here come from
    // i64/u64, so a float outside this interval has a known ordering immediately.
    if float >= 18_446_744_073_709_551_616.0 {
        return Ordering::Less;
    }
    if float < -9_223_372_036_854_775_808.0 {
        return Ordering::Greater;
    }
    let truncated = float.trunc();
    match integer.cmp(&(truncated as i128)) {
        Ordering::Equal if float > truncated => Ordering::Less,
        Ordering::Equal if float < truncated => Ordering::Greater,
        ordering => ordering,
    }
}
