use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use mtm_contracts::{ErrorCategory, ReCtmError};
use mtm_core::validate_schema_value;
use serde_json::{Map, Value};

use crate::catalog::ToolCatalog;
use crate::oauth::OAuthPrincipal;
use crate::runtime::GatewayRuntime;

pub const LEGACY_PROTOCOL_VERSIONS: [&str; 2] = ["2025-11-25", "2025-06-18"];
pub const MODERN_PROTOCOL_VERSIONS: [&str; 1] = ["2026-07-28"];
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 3] = ["2026-07-28", "2025-11-25", "2025-06-18"];
pub const LATEST_LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";
pub const HEADER_MISMATCH: i64 = -32020;
pub const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;
pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
pub const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
pub const META_CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
pub const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

const LEGACY_ERA: &str = "legacy";
const MODERN_ERA: &str = "modern";
const MODERN_RESULT_TYPE: &str = "complete";
const BASE64_SENTINEL_PREFIX: &str = "=?base64?";
const BASE64_SENTINEL_SUFFIX: &str = "?=";
const BASE64_SENTINEL_MAX_PAYLOAD: usize = 8192;

pub trait ToolBackend: Send + Sync {
    fn call(
        &self,
        name: &str,
        arguments: &Map<String, Value>,
        principal: &OAuthPrincipal,
        trace_id: &str,
    ) -> Result<Value, ReCtmError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestContext {
    era: String,
    protocol_version: String,
    client_info: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JSONRPCError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

impl JSONRPCError {
    #[must_use]
    pub fn new(code: i64, message: impl Into<String>, data: Option<Value>) -> Self {
        Self {
            code,
            message: message.into(),
            data,
        }
    }
}

pub struct MCPDispatcher {
    catalog: Arc<ToolCatalog>,
    backend: Arc<dyn ToolBackend>,
    runtime: GatewayRuntime,
}

impl MCPDispatcher {
    #[must_use]
    pub fn new(
        catalog: Arc<ToolCatalog>,
        backend: Arc<dyn ToolBackend>,
        runtime: GatewayRuntime,
    ) -> Self {
        Self {
            catalog,
            backend,
            runtime,
        }
    }

    pub fn dispatch(
        &self,
        request: &Value,
        principal: &OAuthPrincipal,
        trace_id: Option<&str>,
        transport_protocol_version: Option<&str>,
    ) -> Result<Option<Value>, ReCtmError> {
        let trace = match trace_id {
            Some(value) => value.to_owned(),
            None => self.runtime.ids.token_urlsafe(16)?,
        };
        let object = request.as_object().ok_or_else(|| {
            ReCtmError::new(
                "INVALID_RPC_ENVELOPE",
                "JSON-RPC request must be an object.",
            )
            .with_category(ErrorCategory::Validation)
        })?;
        let request_id = response_id(object);
        let notification = !object.contains_key("id");
        let dispatched: Result<(RequestContext, Option<Value>), JSONRPCError> = (|| {
            validate_rpc_envelope(object)?;
            let method = object
                .get("method")
                .and_then(Value::as_str)
                .ok_or_else(|| rpc(-32600, "Invalid Request: method must be a non-empty string"))?;
            let params = rpc_params(object)?;
            let era = request_era(method, &params);
            if era == MODERN_ERA {
                let context = modern_request_context(&params)?;
                let result = self.dispatch_modern(method, &params, principal, &trace)?;
                Ok((context, result))
            } else {
                let context = RequestContext {
                    era: LEGACY_ERA.to_owned(),
                    protocol_version: transport_protocol_version
                        .filter(|version| LEGACY_PROTOCOL_VERSIONS.contains(version))
                        .unwrap_or(LATEST_LEGACY_PROTOCOL_VERSION)
                        .to_owned(),
                    client_info: None,
                };
                let result = self.dispatch_legacy(method, &params, principal, &trace)?;
                Ok((context, result))
            }
        })();

        match dispatched {
            Ok((_context, None)) if notification => Ok(None),
            Ok((_context, None)) => Ok(None),
            Ok((context, Some(result))) if notification => {
                let _ = (context, result);
                Ok(None)
            }
            Ok((context, Some(result))) => Ok(Some(serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": shape_result(&context, object["method"].as_str().unwrap_or_default(), result),
            }))),
            Err(_error) if notification => Ok(None),
            Err(error) => Ok(Some(jsonrpc_error(
                request_id,
                error.code,
                &error.message,
                error.data,
            ))),
        }
    }

    fn dispatch_modern(
        &self,
        method: &str,
        params: &Map<String, Value>,
        principal: &OAuthPrincipal,
        trace_id: &str,
    ) -> Result<Option<Value>, JSONRPCError> {
        if !matches!(
            method,
            "server/discover" | "notifications/cancelled" | "ping" | "tools/list" | "tools/call"
        ) {
            return Err(rpc(-32601, &format!("Method not found: {method}")));
        }
        match method {
            "notifications/cancelled" => Ok(None),
            "ping" => Ok(Some(serde_json::json!({}))),
            "server/discover" => Ok(Some(discover_payload())),
            "tools/list" => Ok(Some(serde_json::json!({
                "tools": self.catalog.list_public(),
            }))),
            "tools/call" => self.call_tool(params, principal, trace_id).map(Some),
            _ => Err(rpc(-32601, &format!("Method not found: {method}"))),
        }
    }

    fn dispatch_legacy(
        &self,
        method: &str,
        params: &Map<String, Value>,
        principal: &OAuthPrincipal,
        trace_id: &str,
    ) -> Result<Option<Value>, JSONRPCError> {
        match method {
            "initialize" => {
                let requested = params.get("protocolVersion").and_then(Value::as_str);
                let negotiated = requested
                    .filter(|version| LEGACY_PROTOCOL_VERSIONS.contains(version))
                    .unwrap_or(LATEST_LEGACY_PROTOCOL_VERSION);
                Ok(Some(serde_json::json!({
                    "protocolVersion": negotiated,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": server_identity(),
                    "instructions": server_instructions(),
                })))
            }
            "notifications/initialized" | "notifications/cancelled" => Ok(None),
            "ping" => Ok(Some(serde_json::json!({}))),
            "tools/list" => Ok(Some(serde_json::json!({
                "tools": self.catalog.list_public(),
            }))),
            "tools/call" => self.call_tool(params, principal, trace_id).map(Some),
            _ => Err(rpc(-32601, &format!("Method not found: {method}"))),
        }
    }

    fn call_tool(
        &self,
        params: &Map<String, Value>,
        principal: &OAuthPrincipal,
        trace_id: &str,
    ) -> Result<Value, JSONRPCError> {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| rpc(-32602, "tools/call requires a tool name"))?;
        let arguments = match params.get("arguments") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(arguments)) => arguments.clone(),
            Some(_) => return Err(rpc(-32602, "tools/call arguments must be an object")),
        };
        if !self.catalog.contains(name) {
            return Err(JSONRPCError::new(
                -32602,
                format!("Unknown tool: {name}"),
                Some(serde_json::json!({"reason": "unknown_tool"})),
            ));
        }
        let schema = self.catalog.input_schema(name).ok_or_else(|| {
            JSONRPCError::new(-32603, "Tool catalog is missing an input schema.", None)
        })?;
        if let Err(error) =
            validate_schema_value(&Value::Object(arguments.clone()), schema, "arguments")
        {
            return Err(JSONRPCError::new(
                -32602,
                error.message,
                Some(serde_json::json!({
                    "reason": "invalid_arguments",
                    "code": error.code,
                })),
            ));
        }
        self.backend
            .call(name, &arguments, principal, trace_id)
            .map_err(|error| {
                JSONRPCError::new(
                    -32603,
                    error.message.clone(),
                    Some(serde_json::json!({
                        "re_ctm_error": error.to_payload(),
                        "trace_id": trace_id,
                    })),
                )
            })
    }
}

#[must_use]
pub fn server_identity() -> Value {
    serde_json::json!({"name": "re-ctm", "title": "Re-CTM", "version": "0.3.0"})
}

#[must_use]
pub fn server_instructions() -> &'static str {
    "Use native tools for ordinary workspace and computer operations under the configured native authority. For every concrete mathematical proof, derivation, proof repair, or rigorous verification task, start with rethlas_start and continue with rethlas_step until the run reaches done, unless the user explicitly requests a direct informal answer. Use rethlas_inspect for status/private logical reads, rethlas_retrieve for external mathematical retrieval, rethlas_control for steering/cancellation, and rethlas_artifact for artifact reads or explicit exports. Do not replace a required Rethlas branch, join, LaTeX, verifier, repair, or finalization stage with an unverified answer in chat. When rethlas_step reports done, report the workspace_export_path where proof_verified.tex was automatically written. The rethlas_* workflow is a separate capability-gated authority; native dangerous mode never grants workflow authority."
}

pub fn validate_rpc_envelope(request: &Map<String, Value>) -> Result<(), JSONRPCError> {
    if request.get("jsonrpc") != Some(&Value::String("2.0".to_owned())) {
        return Err(rpc(-32600, "Invalid Request: jsonrpc must be 2.0"));
    }
    if !request
        .get("method")
        .and_then(Value::as_str)
        .is_some_and(|method| !method.is_empty())
    {
        return Err(rpc(
            -32600,
            "Invalid Request: method must be a non-empty string",
        ));
    }
    if let Some(id) = request.get("id") {
        let valid = match id {
            Value::Null | Value::String(_) => true,
            Value::Number(number) => number.is_i64() || number.is_u64(),
            _ => false,
        };
        if !valid {
            return Err(rpc(
                -32600,
                "Invalid Request: id must be string, integer, or null",
            ));
        }
    }
    Ok(())
}

pub fn rpc_params(request: &Map<String, Value>) -> Result<Map<String, Value>, JSONRPCError> {
    match request.get("params") {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(Value::Object(params)) => Ok(params.clone()),
        Some(_) => Err(rpc(-32602, "MCP method params must be an object")),
    }
}

#[must_use]
pub fn request_era(method: &str, params: &Map<String, Value>) -> &'static str {
    if method == "initialize" {
        return LEGACY_ERA;
    }
    if params
        .get("_meta")
        .and_then(Value::as_object)
        .is_some_and(|meta| meta.contains_key(META_PROTOCOL_VERSION))
    {
        MODERN_ERA
    } else {
        LEGACY_ERA
    }
}

pub fn request_era_from_envelope(request: &Value) -> &'static str {
    let Some(object) = request.as_object() else {
        return LEGACY_ERA;
    };
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let params = object
        .get("params")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    request_era(method, &params)
}

pub fn modern_request_context(params: &Map<String, Value>) -> Result<RequestContext, JSONRPCError> {
    let meta = params
        .get("_meta")
        .and_then(Value::as_object)
        .ok_or_else(|| rpc(-32602, "Modern request _meta must be an object"))?;
    let version = meta
        .get(META_PROTOCOL_VERSION)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            JSONRPCError::new(
                -32602,
                format!("{META_PROTOCOL_VERSION} must be a string"),
                Some(serde_json::json!({"reason": "protocol_version"})),
            )
        })?;
    if !MODERN_PROTOCOL_VERSIONS.contains(&version) {
        return Err(JSONRPCError::new(
            UNSUPPORTED_PROTOCOL_VERSION,
            format!("Unsupported MCP protocol version in _meta: {version}"),
            Some(serde_json::json!({
                "supported": MODERN_PROTOCOL_VERSIONS,
                "received": version,
            })),
        ));
    }
    if !meta
        .get(META_CLIENT_CAPABILITIES)
        .is_some_and(Value::is_object)
    {
        return Err(JSONRPCError::new(
            -32602,
            format!("{META_CLIENT_CAPABILITIES} is required and must be an object"),
            Some(serde_json::json!({"reason": "client_capabilities"})),
        ));
    }
    let declared = meta.get(META_CLIENT_INFO);
    if declared.is_some_and(|value| !value.is_object()) {
        return Err(JSONRPCError::new(
            -32602,
            format!("{META_CLIENT_INFO} must be an object when present"),
            Some(serde_json::json!({"reason": "client_info"})),
        ));
    }
    let client_info = declared.and_then(Value::as_object).map(|object| {
        ["name", "version"]
            .into_iter()
            .filter_map(|key| {
                object
                    .get(key)
                    .and_then(Value::as_str)
                    .map(|value| (key.to_owned(), value.chars().take(200).collect::<String>()))
            })
            .collect()
    });
    Ok(RequestContext {
        era: MODERN_ERA.to_owned(),
        protocol_version: version.to_owned(),
        client_info,
    })
}

#[must_use]
pub fn shape_result(context: &RequestContext, method: &str, result: Value) -> Value {
    if context.era != MODERN_ERA {
        return result;
    }
    let mut shaped = result.as_object().cloned().unwrap_or_default();
    shaped.insert(
        "resultType".to_owned(),
        Value::String(MODERN_RESULT_TYPE.to_owned()),
    );
    let mut meta = shaped
        .get("_meta")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    meta.insert(META_SERVER_INFO.to_owned(), server_identity());
    shaped.insert("_meta".to_owned(), Value::Object(meta));
    if matches!(method, "server/discover" | "tools/list") {
        shaped.insert("ttlMs".to_owned(), Value::from(0));
        shaped.insert("cacheScope".to_owned(), Value::String("private".to_owned()));
    }
    Value::Object(shaped)
}

pub fn validate_http_mirror_headers(
    request: &Value,
    version_header: Option<&str>,
    method_header: Option<&str>,
    name_header: Option<&str>,
) -> Result<(), JSONRPCError> {
    let object = request
        .as_object()
        .ok_or_else(|| rpc(-32600, "Invalid Request: jsonrpc must be 2.0"))?;
    validate_rpc_envelope(object)?;
    let method = object["method"].as_str().unwrap_or_default();
    let params = rpc_params(object)?;
    if request_era(method, &params) != MODERN_ERA {
        if version_header.is_some_and(|version| MODERN_PROTOCOL_VERSIONS.contains(&version)) {
            return Err(mirror_error(
                "MCP-Protocol-Version",
                "MCP-Protocol-Version names the modern era but params._meta does not",
                "body_is_not_modern",
            ));
        }
        if version_header.is_some_and(|version| !SUPPORTED_PROTOCOL_VERSIONS.contains(&version)) {
            return Err(JSONRPCError::new(
                -32600,
                "Unsupported MCP protocol version",
                Some(serde_json::json!({
                    "supported": SUPPORTED_PROTOCOL_VERSIONS,
                    "received": version_header,
                })),
            ));
        }
        return Ok(());
    }
    modern_request_context(&params)?;
    let meta = params["_meta"]
        .as_object()
        .ok_or_else(|| rpc(-32602, "Modern request _meta must be an object"))?;
    let meta_version = meta[META_PROTOCOL_VERSION].as_str().unwrap_or_default();
    let Some(version_header) = version_header else {
        return Err(mirror_error(
            "MCP-Protocol-Version",
            "MCP-Protocol-Version is required for a modern request",
            "missing",
        ));
    };
    if version_header != meta_version {
        return Err(mirror_error(
            "MCP-Protocol-Version",
            "MCP-Protocol-Version does not match params._meta",
            "mismatch",
        ));
    }
    let Some(method_header) = method_header else {
        return Err(mirror_error(
            "Mcp-Method",
            "Mcp-Method is required",
            "missing",
        ));
    };
    if method_header != method {
        return Err(mirror_error(
            "Mcp-Method",
            "Mcp-Method does not match request method",
            "mismatch",
        ));
    }
    if method != "tools/call" {
        return Ok(());
    }
    let Some(name_header) = name_header else {
        return Err(mirror_error(
            "Mcp-Name",
            "Mcp-Name is required for tools/call",
            "missing",
        ));
    };
    if decode_mirror_header(name_header)?
        != params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
    {
        return Err(mirror_error(
            "Mcp-Name",
            "Mcp-Name does not match params.name",
            "mismatch",
        ));
    }
    Ok(())
}

pub fn decode_mirror_header(value: &str) -> Result<String, JSONRPCError> {
    if !(value.starts_with(BASE64_SENTINEL_PREFIX) && value.ends_with(BASE64_SENTINEL_SUFFIX)) {
        return Ok(value.to_owned());
    }
    let payload = &value[BASE64_SENTINEL_PREFIX.len()..value.len() - BASE64_SENTINEL_SUFFIX.len()];
    if payload.len() > BASE64_SENTINEL_MAX_PAYLOAD {
        return Err(mirror_error(
            "Mcp-Name",
            "Base64 mirror value is too long",
            "oversized",
        ));
    }
    let decoded = STANDARD.decode(payload).map_err(|_| {
        mirror_error(
            "Mcp-Name",
            "Base64 mirror value is not valid UTF-8",
            "invalid_base64",
        )
    })?;
    String::from_utf8(decoded).map_err(|_| {
        mirror_error(
            "Mcp-Name",
            "Base64 mirror value is not valid UTF-8",
            "invalid_base64",
        )
    })
}

#[must_use]
pub fn modern_http_status(request: &Value, response: &Value) -> u16 {
    if request_era_from_envelope(request) != MODERN_ERA {
        return 200;
    }
    let code = response
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Value::as_i64);
    match code {
        Some(-32601) => 404,
        Some(-32602 | HEADER_MISMATCH | UNSUPPORTED_PROTOCOL_VERSION) => 400,
        _ => 200,
    }
}

#[must_use]
pub fn jsonrpc_error(id: Value, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut error = Map::from_iter([
        ("code".to_owned(), Value::from(code)),
        ("message".to_owned(), Value::String(message.to_owned())),
    ]);
    if let Some(data) = data {
        error.insert("data".to_owned(), data);
    }
    serde_json::json!({"jsonrpc": "2.0", "id": id, "error": error})
}

fn response_id(request: &Map<String, Value>) -> Value {
    match request.get("id") {
        Some(Value::String(value)) => Value::String(value.clone()),
        Some(Value::Number(value)) if value.is_i64() || value.is_u64() => {
            Value::Number(value.clone())
        }
        _ => Value::Null,
    }
}

fn discover_payload() -> Value {
    serde_json::json!({
        "supportedVersions": MODERN_PROTOCOL_VERSIONS,
        "capabilities": {"tools": {"listChanged": false}},
        "oauthOnly": true,
        "instructions": server_instructions(),
    })
}

fn mirror_error(header: &str, message: &str, reason: &str) -> JSONRPCError {
    JSONRPCError::new(
        HEADER_MISMATCH,
        message,
        Some(serde_json::json!({"header": header, "reason": reason})),
    )
}

fn rpc(code: i64, message: &str) -> JSONRPCError {
    JSONRPCError::new(code, message, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modern_meta() -> Value {
        serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        })
    }

    #[test]
    fn envelope_and_modern_mirror_rules_are_fail_closed() {
        let invalid = serde_json::json!({"jsonrpc": "2.0", "id": true, "method": "ping"});
        let invalid_object = invalid.as_object();
        assert!(invalid_object.is_some());
        let result = invalid_object
            .map(validate_rpc_envelope)
            .unwrap_or_else(|| Err(rpc(-32600, "invalid test object")));
        assert_eq!(result.map_err(|error| error.code), Err(-32600));

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "list",
            "method": "tools/list",
            "params": {"_meta": modern_meta()},
        });
        assert!(
            validate_http_mirror_headers(&request, Some("2026-07-28"), Some("tools/list"), None,)
                .is_ok()
        );
        assert_eq!(
            validate_http_mirror_headers(&request, None, Some("tools/list"), None)
                .map_err(|error| error.code),
            Err(HEADER_MISMATCH)
        );
    }

    #[test]
    fn modern_status_and_base64_mirror_match_contract() -> Result<(), JSONRPCError> {
        assert_eq!(
            decode_mirror_header("=?base64?c2VydmVyX2luZm8=?=")?,
            "server_info"
        );
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "future/method",
            "params": {"_meta": modern_meta()},
        });
        let response = jsonrpc_error(Value::from(1), -32601, "missing", None);
        assert_eq!(modern_http_status(&request, &response), 404);
        Ok(())
    }
}
