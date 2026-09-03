use std::sync::Arc;

use mtm_native::{TunnelEvent, TunnelState};
use serde_json::Value;

pub type RuntimeEventSink = Arc<dyn Fn(Value) + Send + Sync + 'static>;

#[derive(Clone, Default)]
pub struct OperatorSession {
    verbose: bool,
}

impl OperatorSession {
    #[must_use]
    pub const fn compact() -> Self {
        Self { verbose: false }
    }

    #[must_use]
    pub const fn verbose() -> Self {
        Self { verbose: true }
    }

    #[must_use]
    pub fn event_sink(&self) -> RuntimeEventSink {
        let verbose = self.verbose;
        Arc::new(move |event| {
            if let Some(line) = format_event_line(&event, verbose) {
                eprintln!("{line}");
            }
        })
    }

    #[must_use]
    pub fn tunnel_sink(&self) -> Arc<dyn Fn(TunnelEvent) + Send + Sync + 'static> {
        let verbose = self.verbose;
        Arc::new(move |event| {
            if let Some(line) = format_tunnel_line(&event, verbose) {
                eprintln!("{line}");
            }
        })
    }
}

fn format_event_line(event: &Value, verbose: bool) -> Option<String> {
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

    if !verbose {
        return match (event_type, tool) {
            ("tool.call_started", Some(tool)) => Some(format!("tool: {tool}")),
            ("tool.call_finished", Some(_)) => None,
            ("tool.call_failed", Some(tool)) => Some(format!("tool failed: {tool}")),
            _ if matches!(decision, "deny" | "error") => {
                if reason.is_empty() {
                    Some(format!("runtime error: {event_type}"))
                } else {
                    Some(format!("runtime error: {event_type} ({reason})"))
                }
            }
            _ => None,
        };
    }

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
                Some(format!("[tool:start] {tool} trace={trace}"))
            } else {
                Some(format!(
                    "[tool:start] {tool} args=[{argument_keys}] trace={trace}"
                ))
            }
        }
        ("tool.call_finished", Some(tool)) => Some(format!("[tool:done] {tool} trace={trace}")),
        ("tool.call_failed", Some(tool)) => Some(format!("[tool:error] {tool} trace={trace}")),
        _ => Some(format!("[{decision}] {event_type} {reason} trace={trace}")),
    }
}

fn format_tunnel_line(event: &TunnelEvent, verbose: bool) -> Option<String> {
    if verbose {
        return if let Some(url) = &event.public_mcp_url {
            Some(format!("Quick Tunnel: {url}"))
        } else {
            Some(format!(
                "Quick Tunnel: {:?} ({})",
                event.state, event.message
            ))
        };
    }
    if let Some(url) = &event.public_mcp_url {
        return Some(format!("Tunnel: {url}"));
    }
    match event.state {
        TunnelState::Unavailable => Some(format!("Tunnel unavailable: {}", event.message)),
        TunnelState::Disconnected => Some(format!("Tunnel disconnected: {}", event.message)),
        TunnelState::Starting | TunnelState::Connected | TunnelState::Closed => None,
    }
}

#[cfg(test)]
mod tests {
    use mtm_native::{TunnelEvent, TunnelState};

    use super::{format_event_line, format_tunnel_line};

    #[test]
    fn compact_operator_lines_show_tool_identity_without_routine_diagnostics() {
        let started = serde_json::json!({
            "event_type": "tool.call_started",
            "trace_id": "trace-1",
            "decision": "allow",
            "details": {
                "tool": "rethlas_step",
                "argument_keys": ["run_id", "capability"]
            }
        });
        let line = format_event_line(&started, false).unwrap_or_default();
        assert_eq!(line, "tool: rethlas_step");
        assert!(!line.contains("trace-1"));
        assert!(!line.contains("capability"));

        let finished = serde_json::json!({
            "event_type": "tool.call_finished",
            "trace_id": "trace-2",
            "decision": "allow",
            "details": {"tool": "search_text"}
        });
        assert_eq!(format_event_line(&finished, false), None);

        let failed = serde_json::json!({
            "event_type": "tool.call_failed",
            "trace_id": "trace-3",
            "decision": "error",
            "details": {"tool": "rethlas_step"}
        });
        assert_eq!(
            format_event_line(&failed, false),
            Some("tool failed: rethlas_step".to_owned())
        );
    }

    #[test]
    fn verbose_operator_lines_preserve_redacted_lifecycle_diagnostics() {
        let started = serde_json::json!({
            "event_type": "tool.call_started",
            "trace_id": "trace-1",
            "decision": "allow",
            "details": {
                "tool": "rethlas_step",
                "argument_keys": ["run_id", "capability"]
            }
        });
        let line = format_event_line(&started, true).unwrap_or_default();
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
            format_event_line(&finished, true),
            Some("[tool:done] search_text trace=trace-2".to_owned())
        );
    }

    #[test]
    fn compact_tunnel_lines_hide_routine_lifecycle_noise() {
        let starting = TunnelEvent {
            state: TunnelState::Starting,
            message: "starting".to_owned(),
            public_mcp_url: None,
            exit_code: None,
        };
        assert_eq!(format_tunnel_line(&starting, false), None);

        let connected = TunnelEvent {
            state: TunnelState::Connected,
            message: "connected".to_owned(),
            public_mcp_url: Some("https://example.trycloudflare.com/mcp".to_owned()),
            exit_code: None,
        };
        assert_eq!(
            format_tunnel_line(&connected, false),
            Some("Tunnel: https://example.trycloudflare.com/mcp".to_owned())
        );

        let unavailable = TunnelEvent {
            state: TunnelState::Unavailable,
            message: "local MCP remains available".to_owned(),
            public_mcp_url: None,
            exit_code: Some(1),
        };
        assert_eq!(
            format_tunnel_line(&unavailable, false),
            Some("Tunnel unavailable: local MCP remains available".to_owned())
        );
    }
}
