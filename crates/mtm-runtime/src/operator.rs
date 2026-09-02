use std::sync::Arc;

use mtm_native::TunnelEvent;
use serde_json::Value;

pub type RuntimeEventSink = Arc<dyn Fn(Value) + Send + Sync + 'static>;

#[derive(Clone, Default)]
pub struct OperatorSession;

impl OperatorSession {
    #[must_use]
    pub fn event_sink(&self) -> RuntimeEventSink {
        Arc::new(|event| {
            eprintln!("{}", format_event_line(&event));
        })
    }

    #[must_use]
    pub fn tunnel_sink(&self) -> Arc<dyn Fn(TunnelEvent) + Send + Sync + 'static> {
        Arc::new(|event| {
            if let Some(url) = event.public_mcp_url {
                eprintln!("Quick Tunnel: {url}");
            } else {
                eprintln!("Quick Tunnel: {:?} ({})", event.state, event.message);
            }
        })
    }
}

fn format_event_line(event: &Value) -> String {
    let event_type = event
        .get("event_type")
        .and_then(Value::as_str)
        .unwrap_or("runtime.event");
    let decision = event
        .get("decision")
        .and_then(Value::as_str)
        .unwrap_or("observe");
    let reason = event
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let trace = event
        .get("trace_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let tool = event
        .get("details")
        .and_then(Value::as_object)
        .and_then(|details| details.get("tool"))
        .and_then(Value::as_str);

    match (event_type, tool) {
        ("tool.call_started", Some(tool)) => {
            let argument_keys = event
                .get("details")
                .and_then(Value::as_object)
                .and_then(|details| details.get("argument_keys"))
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            if argument_keys.is_empty() {
                format!("[tool:start] {tool} trace={trace}")
            } else {
                format!("[tool:start] {tool} args=[{argument_keys}] trace={trace}")
            }
        }
        ("tool.call_finished", Some(tool)) => format!("[tool:done] {tool} trace={trace}"),
        ("tool.call_failed", Some(tool)) => format!("[tool:error] {tool} trace={trace}"),
        _ => format!("[{decision}] {event_type} {reason} trace={trace}"),
    }
}

#[cfg(test)]
mod tests {
    use super::format_event_line;

    #[test]
    fn operator_lines_show_tool_names_without_argument_values() {
        let started = serde_json::json!({
            "event_type": "tool.call_started",
            "trace_id": "trace-1",
            "decision": "allow",
            "details": {
                "tool": "rethlas_step",
                "argument_keys": ["run_id", "capability"]
            }
        });
        let line = format_event_line(&started);
        assert_eq!(
            line,
            "[tool:start] rethlas_step args=[run_id,capability] trace=trace-1"
        );
        assert!(!line.contains("secret-capability-value"));

        let finished = serde_json::json!({
            "event_type": "tool.call_finished",
            "trace_id": "trace-2",
            "decision": "allow",
            "details": {"tool": "search_text"}
        });
        assert_eq!(
            format_event_line(&finished),
            "[tool:done] search_text trace=trace-2"
        );
    }
}
