//! Test-only clients. No product authority or Python/runtime fallback lives here.
pub mod candidate;
pub mod loopback;
pub mod recovery;

use serde_json::Value;

// Fixed messages prevent a failed test from printing capabilities or problem text.
pub type Result<T = ()> = std::result::Result<T, &'static str>;

pub fn require(condition: bool, message: &'static str) -> Result {
    if condition { Ok(()) } else { Err(message) }
}

pub fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("missing nonempty protocol field")
}

pub fn submission(task: &Value) -> Result<Value> {
    let minimal = task
        .get("task")
        .and_then(|t| t.get("minimal_submission"))
        .filter(|v| v.is_object())
        .ok_or("task has no minimal submission")?;
    Ok(serde_json::json!({
        "run_id":text(task,"run_id")?, "capability":text(task,"capability")?,
        "action":text(minimal,"action")?,
        "payload":minimal.get("payload").cloned().unwrap_or_else(|| serde_json::json!({})),
        "writes":minimal.get("writes").cloned().unwrap_or_else(|| serde_json::json!([]))
    }))
}
