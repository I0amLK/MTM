use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_MAX_AGE, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, LOCATION,
    VARY, WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, options, post};
use mtm_contracts::{ErrorCategory, ReCtmError};
use serde_json::Value;
use url::Url;
use url::form_urlencoded;

use crate::catalog::ToolCatalog;
use crate::mcp::{
    HEADER_MISMATCH, MCPDispatcher, jsonrpc_error, modern_http_status, request_era_from_envelope,
    validate_http_mirror_headers,
};
use crate::oauth::{OAuthService, parse_basic_authorization};
use crate::runtime::GatewayRuntime;

pub const MAX_REQUEST_BYTES: usize = 1_048_576;
pub const MCP_PATH: &str = "/mcp";

#[derive(Clone, Debug)]
pub struct GatewayHttpConfig {
    pub bind_host: String,
    pub bind_port: u16,
    pub fixed_oauth_origin: String,
    pub allowed_origins: BTreeSet<String>,
    pub complete_flow_locally_validated: bool,
}

impl GatewayHttpConfig {
    pub fn validate(&self) -> Result<(), ReCtmError> {
        if self.fixed_oauth_origin.is_empty() && !is_loopback_host(&self.bind_host) {
            return Err(ReCtmError::new(
                "OAUTH_DYNAMIC_ISSUER_REQUIRES_LOOPBACK",
                "Without a fixed OAuth server URL, the gateway must bind to a loopback host.",
            )
            .with_category(ErrorCategory::Security));
        }
        Ok(())
    }
}

pub struct GatewayState {
    pub oauth: Arc<OAuthService>,
    pub mcp: Arc<MCPDispatcher>,
    pub catalog: Arc<ToolCatalog>,
    pub runtime: GatewayRuntime,
    pub config: GatewayHttpConfig,
}

impl GatewayState {
    pub fn new(
        oauth: Arc<OAuthService>,
        mcp: Arc<MCPDispatcher>,
        catalog: Arc<ToolCatalog>,
        runtime: GatewayRuntime,
        config: GatewayHttpConfig,
    ) -> Result<Self, ReCtmError> {
        config.validate()?;
        Ok(Self {
            oauth,
            mcp,
            catalog,
            runtime,
            config,
        })
    }
}

pub fn build_router(state: Arc<GatewayState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_metadata),
        )
        .route("/.well-known/mcp.json", get(mcp_card))
        .route(
            "/oauth/authorize",
            get(authorize_page).post(authorize_submit),
        )
        .route("/oauth/register", post(register))
        .route("/oauth/token", post(token))
        .route(MCP_PATH, post(mcp).options(preflight))
        .route("/{*path}", options(preflight).fallback(not_found))
        .with_state(state)
}

pub async fn serve(
    listener: tokio::net::TcpListener,
    state: Arc<GatewayState>,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        build_router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

async fn health(State(state): State<Arc<GatewayState>>, request: Request) -> Response {
    let trace = trace_id(&state);
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "service": "re-ctm",
            "oauth_only": true,
            "complete_flow_locally_validated": state.config.complete_flow_locally_validated,
            "trace_id": trace,
        }),
        request.headers(),
        &state,
    )
}

async fn authorization_metadata(
    State(state): State<Arc<GatewayState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let trace = trace_id(&state);
    let result = resolve_base_url(&state, request.headers(), Some(peer))
        .and_then(|base| state.oauth.authorization_server_metadata(Some(&base)));
    value_or_error(result, trace, request.headers(), &state, None)
}

async fn protected_metadata(
    State(state): State<Arc<GatewayState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let trace = trace_id(&state);
    let result = resolve_base_url(&state, request.headers(), Some(peer))
        .and_then(|base| state.oauth.protected_resource_metadata(Some(&base)));
    value_or_error(result, trace, request.headers(), &state, None)
}

async fn mcp_card(
    State(state): State<Arc<GatewayState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let trace = trace_id(&state);
    let result = resolve_base_url(&state, request.headers(), Some(peer)).and_then(|base| {
        Ok(serde_json::json!({
            "name": "re-ctm",
            "title": "Re-CTM",
            "endpoint": format!("{base}{MCP_PATH}"),
            "oauth": state.oauth.protected_resource_metadata(Some(&base))?,
            "tool_count": state.catalog.list_public().len(),
            "tool_catalog_stable": true,
            "manual_validation_required": true,
        }))
    });
    value_or_error(result, trace, request.headers(), &state, None)
}

async fn authorize_page(
    State(state): State<Arc<GatewayState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let trace = trace_id(&state);
    let result = (|| {
        let base = resolve_base_url(&state, request.headers(), Some(peer))?;
        let params = query_params(request.uri().query().unwrap_or_default());
        state
            .oauth
            .validate_authorization_request(&params, Some(&base))
    })();
    match result {
        Ok(validated) => {
            let hidden = BTreeMap::from([
                (
                    "client_id",
                    validated.get("client_id").cloned().unwrap_or_default(),
                ),
                (
                    "redirect_uri",
                    validated.get("redirect_uri").cloned().unwrap_or_default(),
                ),
                ("response_type", "code".to_owned()),
                (
                    "code_challenge",
                    validated.get("code_challenge").cloned().unwrap_or_default(),
                ),
                ("code_challenge_method", "S256".to_owned()),
                (
                    "resource",
                    validated.get("resource").cloned().unwrap_or_default(),
                ),
                ("state", validated.get("state").cloned().unwrap_or_default()),
            ]);
            let hidden_html = hidden
                .iter()
                .map(|(name, value)| {
                    format!(
                        "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                        html_escape(name),
                        html_escape(value)
                    )
                })
                .collect::<String>();
            let body = format!(
                "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Authorize Re-CTM</title>\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<style>body{{font-family:sans-serif;max-width:32rem;margin:4rem auto;padding:1rem}}input,button{{width:100%;padding:.7rem;margin:.4rem 0;box-sizing:border-box}}code{{overflow-wrap:anywhere}}</style>\n</head><body><h1>Authorize Re-CTM</h1>\n<p>Client: <code>{}</code></p>\n<p>Redirect: <code>{}</code></p>\n<form method=\"post\" action=\"/oauth/authorize\">{}\n<label>Operator password<input type=\"password\" name=\"password\" autocomplete=\"current-password\" required></label>\n<button type=\"submit\">Authorize</button></form>\n<p>Trace: <code>{}</code></p></body></html>",
                html_escape(&validated["client_id"]),
                html_escape(&validated["redirect_uri"]),
                hidden_html,
                html_escape(&trace),
            );
            let mut response = Html(body).into_response();
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(error) => error_response(error, &trace, request.headers(), &state, None),
    }
}

async fn register(State(state): State<Arc<GatewayState>>, request: Request) -> Response {
    let trace = trace_id(&state);
    let headers = request.headers().clone();
    let result = read_json_object(request)
        .await
        .and_then(|payload| state.oauth.register(&payload, &trace));
    value_or_error(result, trace, &headers, &state, Some(StatusCode::CREATED))
}

async fn authorize_submit(
    State(state): State<Arc<GatewayState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let trace = trace_id(&state);
    let headers = request.headers().clone();
    let base = resolve_base_url(&state, &headers, Some(peer));
    let result = match base {
        Ok(base) => read_form(request).await.and_then(|mut params| {
            let password = params.remove("password").unwrap_or_default();
            state
                .oauth
                .authorize(&params, &password, &trace, Some(&base))
        }),
        Err(error) => Err(error),
    };
    match result {
        Ok(location) => {
            let mut response = StatusCode::FOUND.into_response();
            if let Ok(value) = HeaderValue::from_str(&location) {
                response.headers_mut().insert(LOCATION, value);
            }
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(error) => error_response(error, &trace, &headers, &state, None),
    }
}

async fn token(
    State(state): State<Arc<GatewayState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let trace = trace_id(&state);
    let headers = request.headers().clone();
    let basic = parse_basic_authorization(
        headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default(),
    );
    let base = resolve_base_url(&state, &headers, Some(peer));
    let result = match base {
        Ok(base) => read_form(request).await.and_then(|params| {
            state
                .oauth
                .exchange_code(&params, &basic.0, &basic.1, &trace, Some(&base))
        }),
        Err(error) => Err(error),
    };
    value_or_error(result, trace, &headers, &state, None)
}

async fn mcp(
    State(state): State<Arc<GatewayState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let trace = trace_id(&state);
    let headers = request.headers().clone();
    if !origin_allowed(&headers, &state.config.allowed_origins) {
        return plain_http_error(
            StatusCode::FORBIDDEN,
            "ORIGIN_DENIED",
            "Browser Origin is not allowed.",
            &trace,
            &headers,
            &state,
        );
    }
    let base = match resolve_base_url(&state, &headers, Some(peer)) {
        Ok(base) => base,
        Err(error) => return error_response(error, &trace, &headers, &state, None),
    };
    let principal = match state.oauth.validate_authorization_header(
        headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default(),
        &trace,
        Some(&base),
    ) {
        Ok(principal) => principal,
        Err(error) => return error_response(error, &trace, &headers, &state, Some(&base)),
    };
    let request_value = match read_json_object(request).await {
        Ok(value) => value,
        Err(error) => return error_response(error, &trace, &headers, &state, None),
    };
    if request_era_from_envelope(&request_value) == "modern" {
        if let Some(duplicate) = duplicate_mirror_header(&headers) {
            let response = jsonrpc_error(
                request_value.get("id").cloned().unwrap_or(Value::Null),
                HEADER_MISMATCH,
                &format!("{duplicate} must appear exactly once"),
                Some(serde_json::json!({"header": duplicate, "reason": "duplicate"})),
            );
            return json_response(StatusCode::BAD_REQUEST, response, &headers, &state);
        }
    }
    if let Err(error) = validate_http_mirror_headers(
        &request_value,
        header_text(&headers, "MCP-Protocol-Version"),
        header_text(&headers, "Mcp-Method"),
        header_text(&headers, "Mcp-Name"),
    ) {
        let response = jsonrpc_error(
            request_value.get("id").cloned().unwrap_or(Value::Null),
            error.code,
            &error.message,
            error.data,
        );
        let status = status_code(modern_http_status(&request_value, &response));
        return json_response(status, response, &headers, &state);
    }
    match state.mcp.dispatch(
        &request_value,
        &principal,
        Some(&trace),
        header_text(&headers, "MCP-Protocol-Version"),
    ) {
        Ok(None) => empty_response(StatusCode::ACCEPTED, &headers, &state),
        Ok(Some(response)) => {
            let status = status_code(modern_http_status(&request_value, &response));
            json_response(status, response, &headers, &state)
        }
        Err(error) => error_response(error, &trace, &headers, &state, None),
    }
}

async fn preflight(State(state): State<Arc<GatewayState>>, request: Request) -> Response {
    let trace = trace_id(&state);
    if !origin_allowed(request.headers(), &state.config.allowed_origins) {
        return plain_http_error(
            StatusCode::FORBIDDEN,
            "ORIGIN_DENIED",
            "Browser Origin is not allowed.",
            &trace,
            request.headers(),
            &state,
        );
    }
    let mut response = empty_response(StatusCode::NO_CONTENT, request.headers(), &state);
    let headers = response.headers_mut();
    headers.insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(
            "Authorization, Content-Type, MCP-Protocol-Version, Mcp-Method, Mcp-Name",
        ),
    );
    headers.insert(ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("600"));
    response
}

async fn not_found(State(state): State<Arc<GatewayState>>, request: Request) -> Response {
    let trace = trace_id(&state);
    plain_http_error(
        StatusCode::NOT_FOUND,
        "NOT_FOUND",
        "Unknown endpoint.",
        &trace,
        request.headers(),
        &state,
    )
}

async fn read_json_object(request: Request) -> Result<Value, ReCtmError> {
    require_content_type(request.headers(), "application/json")?;
    let bytes = read_body(request).await?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        ReCtmError::new("INVALID_BODY", error.to_string()).with_category(ErrorCategory::Validation)
    })?;
    if !value.is_object() {
        return Err(
            ReCtmError::new("INVALID_BODY", "JSON request body must be an object.")
                .with_category(ErrorCategory::Validation),
        );
    }
    Ok(value)
}

async fn read_form(request: Request) -> Result<BTreeMap<String, String>, ReCtmError> {
    require_content_type(request.headers(), "application/x-www-form-urlencoded")?;
    let bytes = read_body(request).await?;
    let text = String::from_utf8(bytes.to_vec()).map_err(|error| {
        ReCtmError::new("INVALID_BODY", error.to_string()).with_category(ErrorCategory::Validation)
    })?;
    Ok(query_params(&text))
}

async fn read_body(request: Request) -> Result<axum::body::Bytes, ReCtmError> {
    let raw_length = request.headers().get(CONTENT_LENGTH).ok_or_else(|| {
        ReCtmError::new("CONTENT_LENGTH_REQUIRED", "Content-Length is required.")
            .with_category(ErrorCategory::Validation)
    })?;
    let length = raw_length
        .to_str()
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| {
            ReCtmError::new(
                "CONTENT_LENGTH_INVALID",
                "Content-Length must be an integer.",
            )
            .with_category(ErrorCategory::Validation)
        })?;
    if length > MAX_REQUEST_BYTES {
        return Err(
            ReCtmError::new("REQUEST_TOO_LARGE", "Request body exceeds the 1 MiB limit.")
                .with_category(ErrorCategory::Validation),
        );
    }
    to_bytes(request.into_body(), MAX_REQUEST_BYTES)
        .await
        .map_err(|error| {
            ReCtmError::new("INVALID_BODY", error.to_string())
                .with_category(ErrorCategory::Validation)
        })
}

fn require_content_type(headers: &HeaderMap, expected: &str) -> Result<(), ReCtmError> {
    let actual = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if actual != expected {
        return Err(ReCtmError::new(
            "CONTENT_TYPE_INVALID",
            if expected == "application/json" {
                "Content-Type must be application/json."
            } else {
                "Content-Type must be application/x-www-form-urlencoded."
            },
        )
        .with_category(ErrorCategory::Validation));
    }
    Ok(())
}

fn resolve_base_url(
    state: &GatewayState,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> Result<String, ReCtmError> {
    if !state.config.fixed_oauth_origin.is_empty() {
        return Ok(state
            .config
            .fixed_oauth_origin
            .trim_end_matches('/')
            .to_owned());
    }
    if !is_loopback_host(&state.config.bind_host) {
        return Err(ReCtmError::new(
            "OAUTH_DYNAMIC_ISSUER_REQUIRES_LOOPBACK",
            "Dynamic OAuth issuer discovery is allowed only on a loopback-bound gateway.",
        )
        .with_category(ErrorCategory::Security));
    }
    let trust_proxy = peer.is_none_or(|address| address.ip().is_loopback());
    let mut protocol = String::new();
    let mut host = String::new();
    if trust_proxy {
        protocol = first_header(headers, "X-Forwarded-Proto");
        if protocol.is_empty() {
            protocol = forwarded_parameter(headers, "proto");
        }
        host = safe_external_host(&first_header(headers, "X-Forwarded-Host"));
        if host.is_empty() {
            host = safe_external_host(&forwarded_parameter(headers, "host"));
        }
    }
    let raw_host = first_header(headers, "Host");
    if host.is_empty() {
        host = safe_external_host(&raw_host);
        if !raw_host.is_empty() && host.is_empty() {
            return Err(ReCtmError::new(
                "OAUTH_EXTERNAL_URL_INVALID",
                "Request Host header is not a valid OAuth origin host.",
            )
            .with_category(ErrorCategory::Validation));
        }
    }
    if host.is_empty() {
        host = host_with_port(&state.config.bind_host, state.config.bind_port);
    }
    if !matches!(protocol.as_str(), "http" | "https") {
        protocol = if is_loopback_host(&host_name(&host)) {
            "http".to_owned()
        } else {
            "https".to_owned()
        };
    }
    Ok(format!("{protocol}://{host}"))
}

fn origin_allowed(headers: &HeaderMap, allowed: &BTreeSet<String>) -> bool {
    let Some(origin) = header_text(headers, "Origin") else {
        return true;
    };
    let Ok(parsed) = Url::parse(origin) else {
        return false;
    };
    if has_userinfo(origin)
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return false;
    }
    let hostname = parsed.host_str().unwrap_or_default();
    if matches!(parsed.scheme(), "http" | "https") && is_loopback_host(hostname) {
        return true;
    }
    allowed.contains(origin.trim_end_matches('/'))
}

fn error_response(
    error: ReCtmError,
    trace: &str,
    headers: &HeaderMap,
    state: &GatewayState,
    resolved_base: Option<&str>,
) -> Response {
    if error.code == "OAUTH_UNAUTHORIZED" {
        let base = resolved_base
            .map(str::to_owned)
            .or_else(|| resolve_base_url(state, headers, None).ok())
            .unwrap_or_default();
        let mut response = json_response(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"error": error.to_payload(), "trace_id": trace}),
            headers,
            state,
        );
        if let Ok(value) = HeaderValue::from_str(&format!(
            "Bearer realm=\"re-ctm\", resource_metadata=\"{base}/.well-known/oauth-protected-resource\""
        )) {
            response.headers_mut().insert(WWW_AUTHENTICATE, value);
        }
        return response;
    }
    let status = match error.category {
        ErrorCategory::Permission | ErrorCategory::Security => StatusCode::FORBIDDEN,
        ErrorCategory::NotFound => StatusCode::NOT_FOUND,
        ErrorCategory::Validation => StatusCode::BAD_REQUEST,
        ErrorCategory::Conflict => StatusCode::CONFLICT,
        ErrorCategory::Runtime | ErrorCategory::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    };
    json_response(
        status,
        serde_json::json!({"error": error.to_payload(), "trace_id": trace}),
        headers,
        state,
    )
}

fn plain_http_error(
    status: StatusCode,
    code: &str,
    message: &str,
    trace: &str,
    headers: &HeaderMap,
    state: &GatewayState,
) -> Response {
    json_response(
        status,
        serde_json::json!({
            "error": {
                "code": code,
                "message": message,
                "category": "http",
                "retryable": false,
                "details": {},
            },
            "trace_id": trace,
        }),
        headers,
        state,
    )
}

fn value_or_error(
    result: Result<Value, ReCtmError>,
    trace: String,
    headers: &HeaderMap,
    state: &GatewayState,
    success_status: Option<StatusCode>,
) -> Response {
    match result {
        Ok(value) => json_response(
            success_status.unwrap_or(StatusCode::OK),
            value,
            headers,
            state,
        ),
        Err(error) => error_response(error, &trace, headers, state, None),
    }
}

fn json_response(
    status: StatusCode,
    value: Value,
    request_headers: &HeaderMap,
    state: &GatewayState,
) -> Response {
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    add_cors(response.headers_mut(), request_headers, state);
    response
}

fn empty_response(
    status: StatusCode,
    request_headers: &HeaderMap,
    state: &GatewayState,
) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    add_cors(response.headers_mut(), request_headers, state);
    response
}

fn add_cors(response: &mut HeaderMap, request: &HeaderMap, state: &GatewayState) {
    if origin_allowed(request, &state.config.allowed_origins)
        && let Some(origin) = request.get("Origin").cloned()
    {
        response.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        response.insert(VARY, HeaderValue::from_static("Origin"));
    }
}

fn query_params(query: &str) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        result
            .entry(key.into_owned())
            .or_insert_with(|| value.into_owned());
    }
    result
}

fn duplicate_mirror_header(headers: &HeaderMap) -> Option<&'static str> {
    ["MCP-Protocol-Version", "Mcp-Method", "Mcp-Name"]
        .into_iter()
        .find(|name| headers.get_all(*name).iter().count() > 1)
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

fn first_header(headers: &HeaderMap, name: &str) -> String {
    header_text(headers, name)
        .unwrap_or_default()
        .split(',')
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn forwarded_parameter(headers: &HeaderMap, name: &str) -> String {
    let first = first_header(headers, "Forwarded");
    for part in first.split(';') {
        let Some((key, value)) = part.trim().split_once('=') else {
            continue;
        };
        if key.eq_ignore_ascii_case(name) {
            return value.trim().trim_matches('"').to_owned();
        }
    }
    String::new()
}

fn safe_external_host(host: &str) -> String {
    let host = host.trim();
    if host.is_empty()
        || host
            .chars()
            .any(|character| character.is_whitespace() || "/\\@?#".contains(character))
    {
        return String::new();
    }
    let Ok(parsed) = Url::parse(&format!("http://{host}")) else {
        return String::new();
    };
    if parsed.host_str().is_none() || has_userinfo(&format!("http://{host}")) {
        return String::new();
    }
    host.to_owned()
}

fn host_name(host: &str) -> String {
    Url::parse(&format!("http://{host}"))
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_default()
}

fn host_with_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn has_userinfo(value: &str) -> bool {
    value
        .split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
        .is_some_and(|authority| authority.contains('@'))
}

fn is_loopback_host(host: &str) -> bool {
    let normalized = host.trim_matches(['[', ']']).to_ascii_lowercase();
    matches!(normalized.as_str(), "localhost" | "127.0.0.1" | "::1")
        || normalized
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn trace_id(state: &GatewayState) -> String {
    state
        .runtime
        .ids
        .token_urlsafe(16)
        .unwrap_or_else(|_| "trace-unavailable".to_owned())
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn status_code(value: u16) -> StatusCode {
    StatusCode::from_u16(value).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_policy_allows_loopback_and_rejects_attacker() {
        let allowed = BTreeSet::from(["https://allowed.example".to_owned()]);
        let mut loopback = HeaderMap::new();
        loopback.insert("Origin", HeaderValue::from_static("http://127.0.0.1:3000"));
        assert!(origin_allowed(&loopback, &allowed));
        let mut approved = HeaderMap::new();
        approved.insert(
            "Origin",
            HeaderValue::from_static("https://allowed.example"),
        );
        assert!(origin_allowed(&approved, &allowed));
        let mut denied = HeaderMap::new();
        denied.insert(
            "Origin",
            HeaderValue::from_static("https://attacker.example"),
        );
        assert!(!origin_allowed(&denied, &allowed));
    }

    #[test]
    fn external_host_parser_rejects_userinfo_and_paths() {
        assert_eq!(
            safe_external_host("gateway.example:443"),
            "gateway.example:443"
        );
        assert!(safe_external_host("user@gateway.example").is_empty());
        assert!(safe_external_host("gateway.example/path").is_empty());
    }

    #[test]
    fn dynamic_issuer_requires_loopback_bind() {
        let config = GatewayHttpConfig {
            bind_host: "0.0.0.0".to_owned(),
            bind_port: 8765,
            fixed_oauth_origin: String::new(),
            allowed_origins: BTreeSet::new(),
            complete_flow_locally_validated: false,
        };
        assert_eq!(
            config.validate().map_err(|error| error.code),
            Err("OAUTH_DYNAMIC_ISSUER_REQUIRES_LOOPBACK".to_owned())
        );
    }
}
