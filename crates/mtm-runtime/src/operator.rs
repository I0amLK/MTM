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
            eprintln!("[{decision}] {event_type} {reason} trace={trace}");
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
