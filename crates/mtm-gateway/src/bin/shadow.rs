#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use mtm_contracts::{ErrorCategory, ReCtmError};
use mtm_gateway::mcp::{decode_mirror_header, modern_http_status, validate_http_mirror_headers};
use mtm_gateway::{
    FixedClock, GatewayRuntime, MCPDispatcher, OAuthPrincipal, OAuthService, OAuthStore,
    SequenceIdSource, ToolBackend, ToolCatalog,
};
use rusqlite::Connection;
use serde_json::{Map, Value};

struct EchoBackend {
    calls: Arc<Mutex<Vec<Value>>>,
}

impl ToolBackend for EchoBackend {
    fn call(
        &self,
        name: &str,
        arguments: &Map<String, Value>,
        principal: &OAuthPrincipal,
        trace_id: &str,
    ) -> Result<Value, ReCtmError> {
        let call = serde_json::json!({
            "tool": name,
            "arguments": arguments,
            "principal": principal,
            "trace_id": trace_id,
        });
        self.calls
            .lock()
            .map_err(|_| internal("echo backend lock was poisoned"))?
            .push(call.clone());
        Ok(serde_json::json!({
            "content": [{"type": "text", "text": format!("tool {name} completed")}],
            "structuredContent": {
                "ok": true,
                "tool": name,
                "arguments": arguments,
                "client_id": principal.client_id,
            },
            "isError": false,
        }))
    }
}

struct Context {
    database: PathBuf,
    oauth: Arc<OAuthService>,
    dispatcher: MCPDispatcher,
    catalog: Arc<ToolCatalog>,
    events: Arc<Mutex<Vec<Value>>>,
    calls: Arc<Mutex<Vec<Value>>>,
    last_token: Option<String>,
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut context: Option<Context> = None;
    for line in stdin.lock().lines() {
        let response = match line {
            Ok(line) if !line.trim().is_empty() => evaluate(&mut context, &line),
            Ok(_) => continue,
            Err(error) => Err(ReCtmError::new("INPUT_READ_ERROR", error.to_string())
                .with_category(ErrorCategory::Runtime)),
        };
        let payload = match response {
            Ok(result) => serde_json::json!({"ok": true, "result": result}),
            Err(error) => serde_json::json!({"ok": false, "error": error.to_payload()}),
        };
        let output = serde_json::to_string(&payload).unwrap_or_else(|_| {
            "{\"ok\":false,\"error\":{\"code\":\"INTERNAL_SERIALIZATION_ERROR\"}}".to_owned()
        });
        if writeln!(stdout, "{output}")
            .and_then(|_| stdout.flush())
            .is_err()
        {
            break;
        }
    }
}

fn evaluate(context: &mut Option<Context>, line: &str) -> Result<Value, ReCtmError> {
    let request: Value = serde_json::from_str(line).map_err(|error| {
        ReCtmError::new("INVALID_JSON", error.to_string()).with_category(ErrorCategory::Validation)
    })?;
    let operation = request
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| validation("operation is required"))?;
    let payload = request
        .get("payload")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if operation == "init" {
        *context = Some(initialize(&payload)?);
        return Ok(serde_json::json!({"initialized": true}));
    }
    let current = context
        .as_mut()
        .ok_or_else(|| validation("shadow must be initialized first"))?;
    match operation {
        "authorization_server_metadata" => current
            .oauth
            .authorization_server_metadata(optional_text(&payload, "base_url")),
        "protected_resource_metadata" => current
            .oauth
            .protected_resource_metadata(optional_text(&payload, "base_url")),
        "register" => current.oauth.register(
            payload.get("metadata").unwrap_or(&Value::Null),
            text(&payload, "trace_id")?,
        ),
        "validate_authorization_request" => {
            serde_json::to_value(current.oauth.validate_authorization_request(
                &string_map(&payload, "params")?,
                optional_text(&payload, "base_url"),
            )?)
            .map_err(json_error)
        }
        "authorize" => current
            .oauth
            .authorize(
                &string_map(&payload, "params")?,
                text(&payload, "password")?,
                text(&payload, "trace_id")?,
                optional_text(&payload, "base_url"),
            )
            .map(Value::String),
        "exchange_code" => {
            let result = current.oauth.exchange_code(
                &string_map(&payload, "params")?,
                optional_text(&payload, "basic_client_id").unwrap_or_default(),
                optional_text(&payload, "basic_client_secret").unwrap_or_default(),
                text(&payload, "trace_id")?,
                optional_text(&payload, "base_url"),
            )?;
            current.last_token = result
                .get("access_token")
                .and_then(Value::as_str)
                .map(str::to_owned);
            Ok(result)
        }
        "validate_last_token" => {
            serde_json::to_value(current.oauth.validate_authorization_header(
                &format!(
                "Bearer {}",
                current
                    .last_token
                    .as_deref()
                    .ok_or_else(|| validation("last token is unavailable"))?
            ),
                text(&payload, "trace_id")?,
                optional_text(&payload, "base_url"),
            )?)
            .map_err(json_error)
        }
        "decode_last_token" => current.oauth.decode_signed_token(
            current
                .last_token
                .as_deref()
                .ok_or_else(|| validation("last token is unavailable"))?,
        ),
        "last_token" => Ok(current
            .last_token
            .as_ref()
            .map_or(Value::Null, |token| Value::String(token.clone()))),
        "set_last_token" => {
            current.last_token = Some(text(&payload, "token")?.to_owned());
            Ok(serde_json::json!({"updated": true}))
        }
        "oauth_snapshot" => oauth_snapshot(&current.database),
        "mcp_dispatch" => {
            let principal_data = payload
                .get("principal")
                .and_then(Value::as_object)
                .ok_or_else(|| validation("principal is required"))?;
            let principal = OAuthPrincipal::shadow_fixture(
                text(principal_data, "client_id")?.to_owned(),
                text(principal_data, "subject")?.to_owned(),
                text(principal_data, "scope")?.to_owned(),
            );
            current
                .dispatcher
                .dispatch(
                    payload.get("request").unwrap_or(&Value::Null),
                    &principal,
                    optional_text(&payload, "trace_id"),
                    optional_text(&payload, "transport_protocol_version"),
                )
                .map(|value| value.unwrap_or(Value::Null))
        }
        "mirror_validate" => {
            validate_http_mirror_headers(
                payload.get("request").unwrap_or(&Value::Null),
                optional_text(&payload, "version_header"),
                optional_text(&payload, "method_header"),
                optional_text(&payload, "name_header"),
            )
            .map_err(json_rpc_error)?;
            Ok(serde_json::json!({"valid": true}))
        }
        "mirror_decode" => decode_mirror_header(text(&payload, "value")?)
            .map(Value::String)
            .map_err(json_rpc_error),
        "modern_http_status" => Ok(Value::from(modern_http_status(
            payload.get("request").unwrap_or(&Value::Null),
            payload.get("response").unwrap_or(&Value::Null),
        ))),
        "catalog_public" => Ok(Value::Array(current.dispatcher_catalog())),
        "events" => current
            .events
            .lock()
            .map(|events| Value::Array(events.clone()))
            .map_err(|_| internal("event lock was poisoned")),
        "calls" => current
            .calls
            .lock()
            .map(|calls| Value::Array(calls.clone()))
            .map_err(|_| internal("call lock was poisoned")),
        _ => Err(validation("unsupported shadow operation")),
    }
}

impl Context {
    fn dispatcher_catalog(&self) -> Vec<Value> {
        self.catalog.list_public()
    }
}

fn initialize(payload: &Map<String, Value>) -> Result<Context, ReCtmError> {
    let database = PathBuf::from(text(payload, "database")?);
    let secret = STANDARD
        .decode(text(payload, "token_secret_b64")?)
        .map_err(|_| validation("token_secret_b64 is invalid"))?;
    let ids = string_array(payload, "ids")?;
    let events = Arc::new(Mutex::new(Vec::new()));
    let event_sink = {
        let events = Arc::clone(&events);
        Arc::new(move |event: Value| {
            if let Ok(mut target) = events.lock() {
                target.push(event);
            }
        })
    };
    let runtime = GatewayRuntime {
        clock: Arc::new(FixedClock::new(
            integer(payload, "now_unix")?,
            text(payload, "now_iso")?,
        )),
        ids: Arc::new(SequenceIdSource::new(ids)),
        events: event_sink,
    };
    let catalog = Arc::new(ToolCatalog::from_source_snapshot(
        payload
            .get("catalog")
            .ok_or_else(|| validation("catalog is required"))?,
    )?);
    let store = Arc::new(OAuthStore::open(&database, runtime.clone())?);
    let oauth = Arc::new(OAuthService::new(
        text(payload, "server_url")?,
        text(payload, "password")?,
        &secret,
        store,
        runtime.clone(),
        integer(payload, "token_ttl")?,
    )?);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backend = Arc::new(EchoBackend {
        calls: Arc::clone(&calls),
    });
    let dispatcher = MCPDispatcher::new(Arc::clone(&catalog), backend, runtime);
    Ok(Context {
        database,
        oauth,
        dispatcher,
        catalog,
        events,
        calls,
        last_token: None,
    })
}

fn oauth_snapshot(database: &PathBuf) -> Result<Value, ReCtmError> {
    let connection = Connection::open(database).map_err(sqlite_error)?;
    let clients = query_rows(
        &connection,
        "SELECT client_id, redirect_uris_json, token_endpoint_auth_method, client_name, secret_digest, issued_at FROM oauth_clients ORDER BY client_id",
        6,
    )?;
    let codes = query_rows(
        &connection,
        "SELECT code_digest, client_id, redirect_uri, code_challenge, resource, expires_at, created_at FROM oauth_codes ORDER BY code_digest",
        7,
    )?;
    Ok(serde_json::json!({
        "clients": clients,
        "codes": codes,
    }))
}

fn query_rows(
    connection: &Connection,
    query: &str,
    columns: usize,
) -> Result<Vec<Value>, ReCtmError> {
    let mut statement = connection.prepare(query).map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            let mut values = Vec::with_capacity(columns);
            for index in 0..columns {
                let value = match row.get_ref(index)? {
                    rusqlite::types::ValueRef::Null => Value::Null,
                    rusqlite::types::ValueRef::Integer(value) => Value::from(value),
                    rusqlite::types::ValueRef::Real(value) => Value::from(value),
                    rusqlite::types::ValueRef::Text(value) => {
                        Value::String(String::from_utf8_lossy(value).into_owned())
                    }
                    rusqlite::types::ValueRef::Blob(value) => Value::String(STANDARD.encode(value)),
                };
                values.push(value);
            }
            Ok(Value::Array(values))
        })
        .map_err(sqlite_error)?;
    rows.map(|row| row.map_err(sqlite_error)).collect()
}

fn text<'a>(payload: &'a Map<String, Value>, key: &str) -> Result<&'a str, ReCtmError> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| validation(&format!("{key} is required")))
}

fn optional_text<'a>(payload: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    payload.get(key).and_then(Value::as_str)
}

fn integer(payload: &Map<String, Value>, key: &str) -> Result<i64, ReCtmError> {
    payload
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| validation(&format!("{key} must be an integer")))
}

fn string_array(payload: &Map<String, Value>, key: &str) -> Result<Vec<String>, ReCtmError> {
    payload
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| validation(&format!("{key} must be an array")))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| validation(&format!("{key} must contain strings")))
        })
        .collect()
}

fn string_map(
    payload: &Map<String, Value>,
    key: &str,
) -> Result<BTreeMap<String, String>, ReCtmError> {
    payload
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| validation(&format!("{key} must be an object")))?
        .iter()
        .map(|(name, value)| {
            value
                .as_str()
                .map(|value| (name.clone(), value.to_owned()))
                .ok_or_else(|| validation(&format!("{key} values must be strings")))
        })
        .collect()
}

fn json_rpc_error(error: mtm_gateway::mcp::JSONRPCError) -> ReCtmError {
    let mut details = Map::new();
    details.insert("jsonrpc_code".to_owned(), Value::from(error.code));
    if let Some(data) = error.data {
        details.insert("data".to_owned(), data);
    }
    ReCtmError::new("JSONRPC_ERROR", error.message)
        .with_category(ErrorCategory::Validation)
        .with_details(details)
}

fn validation(message: &str) -> ReCtmError {
    ReCtmError::new("INVALID_ARGUMENT", message).with_category(ErrorCategory::Validation)
}

fn internal(message: &str) -> ReCtmError {
    ReCtmError::new("INTERNAL_ERROR", message).with_category(ErrorCategory::Internal)
}

fn json_error(error: serde_json::Error) -> ReCtmError {
    ReCtmError::new("JSON_ERROR", error.to_string()).with_category(ErrorCategory::Internal)
}

fn sqlite_error(error: rusqlite::Error) -> ReCtmError {
    ReCtmError::new("SQLITE_ERROR", error.to_string()).with_category(ErrorCategory::Internal)
}
