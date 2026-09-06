//! Operator outcomes are distinct from MCP transport success. Returning a fresh
//! task is not a successful logical submission. No event may grant authority.
use serde_json::Value;

pub(crate) fn completion_event(tool: &str, trace: &str, payload: &Value) -> Value {
    if payload.get("ok").and_then(Value::as_bool) == Some(false)
        && payload.get("error").is_some_and(Value::is_object)
    {
        return serde_json::json!({
            "event_type": "tool.call_failed", "trace_id": trace,
            "decision": "error", "reason": "tool_reported_error",
            "details": {"tool": tool, "error_code": payload["error"]["code"]}
        });
    }
    if let Some(submission) = payload.get("submission").filter(|value| value.is_object()) {
        if submission.get("ok").and_then(Value::as_bool) == Some(false)
            && submission.get("error").is_some_and(Value::is_object)
        {
            // Do not announce a fresh token unless one was actually returned.
            let fresh = submission
                .get("capability_refreshed")
                .and_then(Value::as_bool)
                == Some(true)
                && payload
                    .get("capability")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty())
                && payload.get("writes_applied").and_then(Value::as_u64) == Some(0)
                && submission.get("writes_retained").and_then(Value::as_bool) == Some(false);
            return serde_json::json!({
                "event_type": "tool.call_submission_rejected", "trace_id": trace,
                "decision": "defer", "reason": "submission_not_applied",
                "details": {
                    "tool": tool, "error_code": submission["error"]["code"],
                    "fresh_task_available": fresh, "writes_applied": payload["writes_applied"],
                    "writes_retained": submission["writes_retained"]
                }
            });
        }
    }
    serde_json::json!({
        "event_type": "tool.call_finished", "trace_id": trace,
        "decision": "allow", "reason": "tool_completed", "details": {"tool": tool}
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refresh_payload() -> Value {
        serde_json::json!({
            "ok":true, "capability":"test-token-not-for-logs", "writes_applied":0,
            "submission":{"ok":false,"capability_refreshed":true,"writes_retained":false,
                "recoverable":true,"error":{"code":"CAPABILITY_INVALID"}}
        })
    }

    #[test]
    fn refresh_is_not_reported_as_success_and_copies_no_token() {
        let event = completion_event("rethlas_step", "trace-A", &refresh_payload());
        assert_eq!(event["event_type"], "tool.call_submission_rejected");
        assert_eq!(event["details"]["fresh_task_available"], true);
        assert_eq!(event["trace_id"], "trace-A");
        assert!(!event.to_string().contains("test-token-not-for-logs"));
    }

    #[test]
    fn terminal_or_partial_write_envelope_is_not_falsely_refreshable() {
        let mut terminal = refresh_payload();
        terminal["capability"] = Value::Null;
        assert_eq!(
            completion_event("rethlas_step", "t", &terminal)["details"]["fresh_task_available"],
            false
        );
        let mut partial = refresh_payload();
        partial["writes_applied"] = Value::from(1);
        partial["submission"]["writes_retained"] = Value::from(true);
        assert_eq!(
            completion_event("rethlas_step", "t", &partial)["details"]["fresh_task_available"],
            false
        );
    }

    #[test]
    fn normal_completion_and_explicit_denial_have_distinct_events() {
        let ok = completion_event("rethlas_start", "trace-B", &serde_json::json!({"ok":true}));
        assert_eq!(ok["event_type"], "tool.call_finished");
        let denied = completion_event(
            "request_permissions",
            "trace-C",
            &serde_json::json!({
                "ok":false,"error":{"code":"ELICITATION_DENIED"}
            }),
        );
        assert_eq!(denied["event_type"], "tool.call_failed");
        assert_eq!(denied["details"]["error_code"], "ELICITATION_DENIED");
    }
}
