use super::format_event_line;
use crate::submission_events::completion_event;
use serde_json::json;

#[test]
fn denied_check_is_not_a_runtime_crash_or_a_claim_of_recovery() {
    let event = json!({"event_type":"capability.denied","decision":"deny",
        "reason":"CAPABILITY_INVALID","trace_id":"trace-A"});
    let line = format_event_line(&event, false).unwrap_or_default();
    assert!(line.contains("authorization check denied"));
    assert!(line.contains("trace-A"));
    assert!(!line.contains("runtime error"));
    assert!(!line.contains("recovered"));
}

#[test]
fn interleaved_start_cannot_steal_step_recovery_attribution() {
    let denied = json!({"event_type":"capability.denied","decision":"deny",
        "reason":"CAPABILITY_INVALID","trace_id":"trace-A"});
    let start_done = completion_event("rethlas_start", "trace-B", &json!({"ok":true}));
    let retry = completion_event(
        "rethlas_step",
        "trace-A",
        &json!({
            "ok":true,"capability":"do-not-print","writes_applied":0,
            "submission":{"ok":false,"capability_refreshed":true,"writes_retained":false,
                "error":{"code":"CAPABILITY_INVALID"}}
        }),
    );
    assert_eq!(format_event_line(&start_done, false), None);
    let lines = [denied, retry]
        .iter()
        .filter_map(|event| format_event_line(event, false))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(lines.contains("rethlas_step"));
    assert!(lines.contains("trace-A"));
    assert!(!lines.contains("rethlas_start"));
    assert!(!lines.contains("do-not-print"));
    assert!(!lines.contains("runtime error"));
}

#[test]
fn genuine_failures_and_unrelated_denials_remain_visible() {
    let fail = json!({"event_type":"tool.call_failed","decision":"error",
        "trace_id":"trace-C","details":{"tool":"rethlas_step","error_code":"CAPABILITY_REVOKED"}});
    let line = format_event_line(&fail, false).unwrap_or_default();
    assert!(line.contains("tool failed: rethlas_step (CAPABILITY_REVOKED)"));
    let other = json!({"event_type":"storage.denied","decision":"deny","reason":"ACCESS_DENIED"});
    assert!(format_event_line(&other, false).is_some());
}

#[test]
fn diagnostic_output_is_opt_in_and_does_not_dump_event_payloads() {
    let event = json!({"event_type":"capability.diagnostic","decision":"observe",
    "reason":"submitted","trace_id":"trace-D","details":{
        "token_sha256":"a".repeat(64),"token_bytes":400,"signer_id":"b".repeat(64),
        "instance_id":"c".repeat(32),"validation_stage":"signature_mismatch",
        "capability":"secret-token","raw_arguments":"private-proof-text"
    }});
    assert_eq!(format_event_line(&event, false), None);
    let line = format_event_line(&event, true).unwrap_or_default();
    assert!(line.contains("signature_mismatch"));
    assert!(line.contains(&"a".repeat(64)));
    assert!(!line.contains("secret-token"));
    assert!(!line.contains("private-proof-text"));
}
