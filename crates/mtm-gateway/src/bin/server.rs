#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use mtm_contracts::{ErrorCategory, ReCtmError};
use mtm_gateway::{
    GatewayHttpConfig, GatewayRuntime, GatewayState, MCPDispatcher, OAuthPrincipal, OAuthService,
    OAuthStore, ToolBackend, ToolCatalog, build_router,
};
use serde_json::{Map, Value};

struct EchoBackend {
    calls: Mutex<u64>,
}

impl ToolBackend for EchoBackend {
    fn call(
        &self,
        name: &str,
        arguments: &Map<String, Value>,
        principal: &OAuthPrincipal,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        let mut calls = self.calls.lock().map_err(|_| {
            ReCtmError::new("BACKEND_LOCK_ERROR", "Gateway backend lock was poisoned.")
                .with_category(ErrorCategory::Internal)
        })?;
        *calls += 1;
        Ok(serde_json::json!({
            "content": [{"type": "text", "text": format!("tool {name} completed")}],
            "structuredContent": {
                "ok": true,
                "tool": name,
                "arguments": arguments,
                "client_id": principal.client_id,
                "trace_id": trace_id,
                "gateway_backend": "echo_validation_only",
                "call_index": *calls,
            },
            "isError": false,
        }))
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{}", error.to_payload());
        std::process::exit(1);
    }
}

async fn run() -> Result<(), ReCtmError> {
    let bind: SocketAddr = variable("MTM_GATEWAY_BIND")?
        .parse()
        .map_err(|_| validation("MTM_GATEWAY_BIND must be a socket address"))?;
    let catalog_path = PathBuf::from(variable("MTM_GATEWAY_CATALOG")?);
    let oauth_path = PathBuf::from(variable("MTM_GATEWAY_OAUTH_DB")?);
    let password = variable("MTM_GATEWAY_OAUTH_PASSWORD")?;
    let token_secret = STANDARD
        .decode(variable("MTM_GATEWAY_TOKEN_SECRET_B64")?)
        .map_err(|_| validation("MTM_GATEWAY_TOKEN_SECRET_B64 is invalid"))?;
    let fixed_origin = env::var("MTM_GATEWAY_SERVER_URL").unwrap_or_default();
    let allowed_origins = env::var("MTM_GATEWAY_ALLOWED_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.trim_end_matches('/').to_owned())
        .collect::<BTreeSet<_>>();
    let catalog_value: Value =
        serde_json::from_slice(&fs::read(&catalog_path).map_err(io_error)?).map_err(json_error)?;
    let catalog = Arc::new(ToolCatalog::from_source_snapshot(&catalog_value)?);
    let runtime = GatewayRuntime::default();
    let store = Arc::new(OAuthStore::open(&oauth_path, runtime.clone())?);
    let oauth = Arc::new(OAuthService::new(
        &fixed_origin,
        &password,
        &token_secret,
        store,
        runtime.clone(),
        86_400,
    )?);
    let backend = Arc::new(EchoBackend {
        calls: Mutex::new(0),
    });
    let dispatcher = Arc::new(MCPDispatcher::new(
        Arc::clone(&catalog),
        backend,
        runtime.clone(),
    ));
    let config = GatewayHttpConfig {
        bind_host: bind.ip().to_string(),
        bind_port: bind.port(),
        fixed_oauth_origin: fixed_origin,
        allowed_origins,
        complete_flow_locally_validated: true,
    };
    let state = Arc::new(GatewayState::new(
        oauth, dispatcher, catalog, runtime, config,
    )?);
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(io_error)?;
    let local = listener.local_addr().map_err(io_error)?;
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "service": "mtm-gateway",
            "address": local.to_string(),
            "oauth_only": true,
            "tool_count": 24,
        })
    );
    axum::serve(
        listener,
        build_router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(io_error)
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn variable(name: &str) -> Result<String, ReCtmError> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| validation(&format!("{name} is required")))
}

fn validation(message: &str) -> ReCtmError {
    ReCtmError::new("INVALID_GATEWAY_CONFIGURATION", message)
        .with_category(ErrorCategory::Validation)
}

fn io_error(error: std::io::Error) -> ReCtmError {
    ReCtmError::new("GATEWAY_IO_ERROR", error.to_string()).with_category(ErrorCategory::Runtime)
}

fn json_error(error: serde_json::Error) -> ReCtmError {
    ReCtmError::new("GATEWAY_JSON_ERROR", error.to_string()).with_category(ErrorCategory::Internal)
}
