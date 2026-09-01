use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use mtm_contracts::{ErrorCategory, ReCtmError, invalid_argument};
use mtm_core::{token_fingerprint, validate_oauth_server_url, validate_redirect_uris};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use url::form_urlencoded;

use crate::runtime::GatewayRuntime;

pub const AUTH_CODE_TTL_SECONDS: i64 = 300;
pub const ACCESS_TOKEN_TTL_SECONDS: i64 = 24 * 60 * 60;
pub const MAX_CLIENTS: i64 = 1024;
pub const SUPPORTED_AUTH_METHODS: [&str; 3] = ["client_secret_basic", "client_secret_post", "none"];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OAuthPrincipal {
    pub client_id: String,
    pub subject: String,
    pub scope: String,
}

pub struct OAuthStore {
    connection: Mutex<Connection>,
    runtime: GatewayRuntime,
}

impl OAuthStore {
    pub fn open(path: &Path, runtime: GatewayRuntime) -> Result<Self, ReCtmError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(io_error)?;
        }
        let connection = Connection::open(path).map_err(sql_error)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(sql_error)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(sql_error)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS oauth_clients (
                    client_id TEXT PRIMARY KEY,
                    redirect_uris_json TEXT NOT NULL,
                    token_endpoint_auth_method TEXT NOT NULL,
                    client_name TEXT,
                    secret_digest TEXT,
                    issued_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS oauth_codes (
                    code_digest TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
                    redirect_uri TEXT NOT NULL,
                    code_challenge TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );",
            )
            .map_err(sql_error)?;
        Ok(Self {
            connection: Mutex::new(connection),
            runtime,
        })
    }

    pub fn register_client(
        &self,
        redirect_uris: &[String],
        auth_method: &str,
        client_name: Option<&str>,
    ) -> Result<Value, ReCtmError> {
        let connection = self.lock()?;
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM oauth_clients", [], |row| row.get(0))
            .map_err(sql_error)?;
        if count >= MAX_CLIENTS {
            return Err(ReCtmError::new(
                "OAUTH_CLIENT_LIMIT",
                "Dynamic client registration limit reached.",
            )
            .with_category(ErrorCategory::Runtime));
        }
        let client_id = self.runtime.ids.token_urlsafe(24)?;
        let client_secret = if auth_method == "none" {
            None
        } else {
            Some(self.runtime.ids.token_urlsafe(32)?)
        };
        let issued_at = self.runtime.clock.now_unix();
        connection
            .execute(
                "INSERT INTO oauth_clients (
                    client_id, redirect_uris_json, token_endpoint_auth_method,
                    client_name, secret_digest, issued_at
                ) VALUES (?, ?, ?, ?, ?, ?)",
                params![
                    client_id,
                    serde_json::to_string(redirect_uris).map_err(json_error)?,
                    auth_method,
                    client_name,
                    client_secret.as_deref().map(secret_digest),
                    issued_at,
                ],
            )
            .map_err(sql_error)?;
        let mut result = Map::from_iter([
            ("client_id".to_owned(), Value::String(client_id)),
            ("client_id_issued_at".to_owned(), Value::from(issued_at)),
            (
                "redirect_uris".to_owned(),
                Value::Array(redirect_uris.iter().cloned().map(Value::String).collect()),
            ),
            (
                "grant_types".to_owned(),
                serde_json::json!(["authorization_code"]),
            ),
            ("response_types".to_owned(), serde_json::json!(["code"])),
            (
                "token_endpoint_auth_method".to_owned(),
                Value::String(auth_method.to_owned()),
            ),
        ]);
        if let Some(name) = client_name {
            result.insert("client_name".to_owned(), Value::String(name.to_owned()));
        }
        if let Some(secret) = client_secret {
            result.insert("client_secret".to_owned(), Value::String(secret));
            result.insert("client_secret_expires_at".to_owned(), Value::from(0));
        }
        Ok(Value::Object(result))
    }

    pub fn get_client(&self, client_id: &str) -> Result<Option<Value>, ReCtmError> {
        let connection = self.lock()?;
        let row = connection
            .query_row(
                "SELECT client_id, redirect_uris_json, token_endpoint_auth_method,
                        client_name, secret_digest, issued_at
                 FROM oauth_clients WHERE client_id=?",
                [client_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(sql_error)?;
        let Some((client_id, redirects, method, name, digest, issued_at)) = row else {
            return Ok(None);
        };
        let mut result = Map::from_iter([
            ("client_id".to_owned(), Value::String(client_id)),
            (
                "redirect_uris".to_owned(),
                serde_json::from_str(&redirects).map_err(json_error)?,
            ),
            (
                "token_endpoint_auth_method".to_owned(),
                Value::String(method),
            ),
            ("issued_at".to_owned(), Value::from(issued_at)),
        ]);
        result.insert(
            "client_name".to_owned(),
            name.map_or(Value::Null, Value::String),
        );
        result.insert(
            "secret_digest".to_owned(),
            digest.map_or(Value::Null, Value::String),
        );
        Ok(Some(Value::Object(result)))
    }

    pub fn save_code(
        &self,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
        code_challenge: &str,
        resource: &str,
        expires_at: i64,
    ) -> Result<(), ReCtmError> {
        let connection = self.lock()?;
        connection
            .execute(
                "DELETE FROM oauth_codes WHERE expires_at < ?",
                [self.runtime.clock.now_unix()],
            )
            .map_err(sql_error)?;
        connection
            .execute(
                "INSERT INTO oauth_codes (
                    code_digest, client_id, redirect_uri, code_challenge,
                    resource, expires_at, created_at
                 ) VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    secret_digest(code),
                    client_id,
                    redirect_uri,
                    code_challenge,
                    resource,
                    expires_at,
                    self.runtime.clock.now_iso()?,
                ],
            )
            .map_err(sql_error)?;
        Ok(())
    }

    pub fn consume_code(&self, code: &str) -> Result<Option<Value>, ReCtmError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let digest = secret_digest(code);
        let row = transaction
            .query_row(
                "SELECT code_digest, client_id, redirect_uri, code_challenge,
                        resource, expires_at, created_at
                 FROM oauth_codes WHERE code_digest=?",
                [&digest],
                |row| {
                    Ok(serde_json::json!({
                        "code_digest": row.get::<_, String>(0)?,
                        "client_id": row.get::<_, String>(1)?,
                        "redirect_uri": row.get::<_, String>(2)?,
                        "code_challenge": row.get::<_, String>(3)?,
                        "resource": row.get::<_, String>(4)?,
                        "expires_at": row.get::<_, i64>(5)?,
                        "created_at": row.get::<_, String>(6)?,
                    }))
                },
            )
            .optional()
            .map_err(sql_error)?;
        if row.is_some() {
            transaction
                .execute("DELETE FROM oauth_codes WHERE code_digest=?", [&digest])
                .map_err(sql_error)?;
        }
        transaction.commit().map_err(sql_error)?;
        Ok(row)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, ReCtmError> {
        self.connection.lock().map_err(|_| {
            ReCtmError::new("OAUTH_STORE_LOCK_ERROR", "OAuth store lock was poisoned.")
                .with_category(ErrorCategory::Internal)
        })
    }
}

pub struct OAuthService {
    server_url: String,
    password: String,
    token_secret: Vec<u8>,
    store: Arc<OAuthStore>,
    runtime: GatewayRuntime,
    token_ttl: i64,
}

impl OAuthService {
    pub fn new(
        server_url: &str,
        password: &str,
        token_secret: &[u8],
        store: Arc<OAuthStore>,
        runtime: GatewayRuntime,
        token_ttl: i64,
    ) -> Result<Self, ReCtmError> {
        if !server_url.is_empty() {
            validate_oauth_server_url(server_url)?;
        }
        if password.is_empty() {
            return Err(ReCtmError::new(
                "OAUTH_PASSWORD_REQUIRED",
                "RE_CTM_OAUTH_PASSWORD is required.",
            )
            .with_category(ErrorCategory::Security));
        }
        if token_secret.len() < 32 {
            return Err(ReCtmError::new(
                "OAUTH_TOKEN_SECRET_REQUIRED",
                "OAuth signing requires at least 32 secret bytes.",
            )
            .with_category(ErrorCategory::Security));
        }
        Ok(Self {
            server_url: server_url.trim_end_matches('/').to_owned(),
            password: password.to_owned(),
            token_secret: token_secret.to_vec(),
            store,
            runtime,
            token_ttl,
        })
    }

    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn authorization_server_metadata(
        &self,
        base_url: Option<&str>,
    ) -> Result<Value, ReCtmError> {
        let base = self.base_url(base_url)?;
        Ok(serde_json::json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/oauth/authorize"),
            "token_endpoint": format!("{base}/oauth/token"),
            "registration_endpoint": format!("{base}/oauth/register"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": SUPPORTED_AUTH_METHODS,
        }))
    }

    pub fn protected_resource_metadata(&self, base_url: Option<&str>) -> Result<Value, ReCtmError> {
        let base = self.base_url(base_url)?;
        Ok(serde_json::json!({
            "resource": base,
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"],
        }))
    }

    pub fn register(&self, metadata: &Value, trace_id: &str) -> Result<Value, ReCtmError> {
        let object = metadata
            .as_object()
            .ok_or_else(|| invalid_argument("Registration metadata must be an object"))?;
        let redirects =
            validate_redirect_uris(object.get("redirect_uris").unwrap_or(&Value::Null))?;
        let grant_types = object
            .get("grant_types")
            .cloned()
            .unwrap_or_else(|| serde_json::json!(["authorization_code"]));
        if !grant_types
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "authorization_code"))
        {
            return Err(invalid_argument(
                "grant_types must include authorization_code",
            ));
        }
        let response_types = object
            .get("response_types")
            .cloned()
            .unwrap_or_else(|| serde_json::json!(["code"]));
        if !response_types
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "code"))
        {
            return Err(invalid_argument("response_types must include code"));
        }
        let auth_method = object
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            .unwrap_or("none");
        if !SUPPORTED_AUTH_METHODS.contains(&auth_method) {
            return Err(invalid_argument("unsupported token_endpoint_auth_method"));
        }
        let client_name = optional_text(object.get("client_name"), 200);
        let result = self
            .store
            .register_client(&redirects, auth_method, client_name.as_deref())?;
        self.emit(
            "oauth.client_registered",
            trace_id,
            "valid_dynamic_client_registration",
            serde_json::json!({
                "client_id_fingerprint": result.get("client_id").and_then(Value::as_str).map(|value| token_fingerprint(value.as_bytes())),
                "redirect_count": redirects.len(),
                "auth_method": auth_method,
            }),
        );
        Ok(result)
    }

    pub fn validate_authorization_request(
        &self,
        params: &BTreeMap<String, String>,
        base_url: Option<&str>,
    ) -> Result<BTreeMap<String, String>, ReCtmError> {
        let base = self.base_url(base_url)?;
        let client_id = value(params, "client_id");
        let redirect_uri = value(params, "redirect_uri");
        let response_type = value(params, "response_type");
        let code_challenge = value(params, "code_challenge");
        let method = value(params, "code_challenge_method");
        let resource = value(params, "resource").trim_end_matches('/').to_owned();
        let state = value(params, "state");
        let client = self
            .store
            .get_client(&client_id)?
            .ok_or_else(|| permission("OAUTH_INVALID_CLIENT", "Unknown client_id."))?;
        let redirects = client
            .get("redirect_uris")
            .and_then(Value::as_array)
            .ok_or_else(internal_client_error)?;
        if !redirects.iter().any(|item| item == &redirect_uri) {
            return Err(permission(
                "OAUTH_INVALID_REDIRECT",
                "redirect_uri is not registered.",
            ));
        }
        if response_type != "code" {
            return Err(invalid_argument("response_type must be code"));
        }
        if method != "S256" || !valid_pkce_challenge(&code_challenge) {
            return Err(invalid_argument(
                "code_challenge_method must be S256 with a valid challenge",
            ));
        }
        if resource != base {
            return Err(permission(
                "OAUTH_INVALID_TARGET",
                "resource must identify this server.",
            ));
        }
        Ok(BTreeMap::from([
            ("client_id".to_owned(), client_id),
            ("redirect_uri".to_owned(), redirect_uri),
            ("code_challenge".to_owned(), code_challenge),
            ("resource".to_owned(), resource),
            ("state".to_owned(), state),
        ]))
    }

    pub fn authorize(
        &self,
        params: &BTreeMap<String, String>,
        password: &str,
        trace_id: &str,
        base_url: Option<&str>,
    ) -> Result<String, ReCtmError> {
        let validated = self.validate_authorization_request(params, base_url)?;
        if !constant_time_equal(password.as_bytes(), self.password.as_bytes()) {
            self.emit(
                "oauth.authorization_denied",
                trace_id,
                "invalid_authorization_password",
                serde_json::json!({
                    "client_id_fingerprint": token_fingerprint(validated["client_id"].as_bytes()),
                }),
            );
            return Err(permission(
                "OAUTH_ACCESS_DENIED",
                "Invalid authorization password.",
            ));
        }
        let code = self.runtime.ids.token_urlsafe(32)?;
        self.store.save_code(
            &code,
            &validated["client_id"],
            &validated["redirect_uri"],
            &validated["code_challenge"],
            &validated["resource"],
            self.runtime.clock.now_unix() + AUTH_CODE_TTL_SECONDS,
        )?;
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        serializer.append_pair("code", &code);
        if !validated["state"].is_empty() {
            serializer.append_pair("state", &validated["state"]);
        }
        let separator = if validated["redirect_uri"].contains('?') {
            '&'
        } else {
            '?'
        };
        let redirect = format!(
            "{}{}{}",
            validated["redirect_uri"],
            separator,
            serializer.finish()
        );
        self.emit(
            "oauth.authorization_code_issued",
            trace_id,
            "authorization_password_and_pkce_request_valid",
            serde_json::json!({
                "client_id_fingerprint": token_fingerprint(validated["client_id"].as_bytes()),
                "code_fingerprint": token_fingerprint(code.as_bytes()),
            }),
        );
        Ok(redirect)
    }

    pub fn exchange_code(
        &self,
        params: &BTreeMap<String, String>,
        basic_client_id: &str,
        basic_client_secret: &str,
        trace_id: &str,
        base_url: Option<&str>,
    ) -> Result<Value, ReCtmError> {
        let base = self.base_url(base_url)?;
        if value(params, "grant_type") != "authorization_code" {
            return Err(invalid_argument("Only authorization_code is supported."));
        }
        let code = value(params, "code");
        let redirect_uri = value(params, "redirect_uri");
        let verifier = value(params, "code_verifier");
        let resource = value(params, "resource").trim_end_matches('/').to_owned();
        let client_id = first_nonempty(&[value(params, "client_id"), basic_client_id.to_owned()]);
        let client_secret = first_nonempty(&[
            value(params, "client_secret"),
            basic_client_secret.to_owned(),
        ]);
        let presented_method = if !basic_client_id.is_empty() {
            "client_secret_basic"
        } else if !client_secret.is_empty() {
            "client_secret_post"
        } else {
            "none"
        };
        let client = self.store.get_client(&client_id)?;
        if client
            .as_ref()
            .is_none_or(|item| !authenticate_client(item, &client_secret, presented_method))
        {
            return Err(permission(
                "OAUTH_INVALID_CLIENT",
                "Client authentication failed.",
            ));
        }
        if code.is_empty() || !valid_pkce_verifier(&verifier) {
            return Err(permission(
                "OAUTH_INVALID_GRANT",
                "Invalid code or code_verifier.",
            ));
        }
        let record = self.store.consume_code(&code)?.ok_or_else(|| {
            permission(
                "OAUTH_INVALID_GRANT",
                "Authorization code is unknown or already used.",
            )
        })?;
        if record
            .get("expires_at")
            .and_then(Value::as_i64)
            .is_none_or(|expires| expires < self.runtime.clock.now_unix())
        {
            return Err(permission(
                "OAUTH_INVALID_GRANT",
                "Authorization code expired.",
            ));
        }
        let facts = [
            text(&record, "client_id")
                .is_some_and(|value| constant_time_equal(value.as_bytes(), client_id.as_bytes())),
            text(&record, "redirect_uri").is_some_and(|value| {
                constant_time_equal(value.as_bytes(), redirect_uri.as_bytes())
            }),
            text(&record, "resource")
                .is_some_and(|value| constant_time_equal(value.as_bytes(), resource.as_bytes())),
            constant_time_equal(resource.as_bytes(), base.as_bytes()),
            text(&record, "code_challenge")
                .is_some_and(|challenge| verify_pkce(&verifier, challenge)),
        ];
        if !facts.into_iter().all(|value| value) {
            return Err(permission(
                "OAUTH_INVALID_GRANT",
                "Authorization code binding or PKCE verification failed.",
            ));
        }
        let token = self.create_access_token(&client_id, Some(&base))?;
        self.emit(
            "oauth.access_token_issued",
            trace_id,
            "authorization_code_and_pkce_valid",
            serde_json::json!({
                "client_id_fingerprint": token_fingerprint(client_id.as_bytes()),
                "token_fingerprint": token_fingerprint(token.as_bytes()),
            }),
        );
        Ok(serde_json::json!({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": self.token_ttl,
        }))
    }

    pub fn validate_authorization_header(
        &self,
        header: &str,
        trace_id: &str,
        base_url: Option<&str>,
    ) -> Result<OAuthPrincipal, ReCtmError> {
        let base = self.base_url(base_url)?;
        let token = header
            .strip_prefix("Bearer ")
            .map(str::trim)
            .ok_or_else(|| permission("OAUTH_UNAUTHORIZED", "OAuth Bearer token is required."))?;
        let payload = self.decode_signed_token(token).and_then(|payload| {
            let now = self.runtime.clock.now_unix();
            if text(&payload, "iss") != Some(base.as_str())
                || text(&payload, "aud") != Some(base.as_str())
                || payload
                    .get("exp")
                    .and_then(Value::as_i64)
                    .is_none_or(|exp| exp < now)
            {
                return Err(permission(
                    "OAUTH_UNAUTHORIZED",
                    "OAuth access token is invalid or expired.",
                ));
            }
            let client_id = text(&payload, "client_id").unwrap_or_default();
            if client_id.is_empty() || self.store.get_client(client_id)?.is_none() {
                return Err(permission(
                    "OAUTH_UNAUTHORIZED",
                    "OAuth access token is invalid or expired.",
                ));
            }
            Ok(OAuthPrincipal {
                client_id: client_id.to_owned(),
                subject: text(&payload, "sub").unwrap_or(client_id).to_owned(),
                scope: text(&payload, "scope").unwrap_or_default().to_owned(),
            })
        });
        match payload {
            Ok(principal) => {
                self.emit(
                    "oauth.access_token_accepted",
                    trace_id,
                    "signed_access_token_valid",
                    serde_json::json!({
                        "client_id_fingerprint": token_fingerprint(principal.client_id.as_bytes()),
                    }),
                );
                Ok(principal)
            }
            Err(_) => {
                self.emit(
                    "oauth.access_token_denied",
                    trace_id,
                    "invalid_access_token",
                    serde_json::json!({"token_fingerprint": token_fingerprint(token.as_bytes())}),
                );
                Err(permission(
                    "OAUTH_UNAUTHORIZED",
                    "OAuth access token is invalid or expired.",
                ))
            }
        }
    }

    pub fn create_access_token(
        &self,
        client_id: &str,
        base_url: Option<&str>,
    ) -> Result<String, ReCtmError> {
        let base = self.base_url(base_url)?;
        let now = self.runtime.clock.now_unix();
        self.encode_signed_token(&serde_json::json!({
            "v": 1,
            "iss": base,
            "aud": base,
            "sub": client_id,
            "client_id": client_id,
            "iat": now,
            "exp": now + self.token_ttl,
            "scope": "mcp",
        }))
    }

    pub fn encode_signed_token(&self, payload: &Value) -> Result<String, ReCtmError> {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let body = URL_SAFE_NO_PAD.encode(canonical_json(payload)?);
        let signing_input = format!("{header}.{body}");
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.token_secret).map_err(|_| {
            ReCtmError::new(
                "OAUTH_TOKEN_SECRET_INVALID",
                "OAuth signing secret is invalid.",
            )
            .with_category(ErrorCategory::Internal)
        })?;
        mac.update(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        Ok(format!("{signing_input}.{signature}"))
    }

    pub fn decode_signed_token(&self, token: &str) -> Result<Value, ReCtmError> {
        let mut parts = token.splitn(3, '.');
        let header = parts.next().unwrap_or_default();
        let body = parts.next().unwrap_or_default();
        let signature = parts.next().unwrap_or_default();
        if header.is_empty() || body.is_empty() || signature.is_empty() {
            return Err(permission(
                "OAUTH_UNAUTHORIZED",
                "OAuth access token is invalid or expired.",
            ));
        }
        let signing_input = format!("{header}.{body}");
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.token_secret).map_err(|_| {
            ReCtmError::new(
                "OAUTH_TOKEN_SECRET_INVALID",
                "OAuth signing secret is invalid.",
            )
            .with_category(ErrorCategory::Internal)
        })?;
        mac.update(signing_input.as_bytes());
        let expected = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        if !constant_time_equal(signature.as_bytes(), expected.as_bytes()) {
            return Err(permission(
                "OAUTH_UNAUTHORIZED",
                "OAuth access token is invalid or expired.",
            ));
        }
        let decoded_header: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(header)
                .map_err(|_| invalid_token())?,
        )
        .map_err(|_| invalid_token())?;
        if decoded_header.get("alg") != Some(&Value::String("HS256".to_owned())) {
            return Err(invalid_token());
        }
        let payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body).map_err(|_| invalid_token())?)
                .map_err(|_| invalid_token())?;
        if !payload.is_object() {
            return Err(invalid_token());
        }
        Ok(payload)
    }

    pub fn base_url(&self, override_url: Option<&str>) -> Result<String, ReCtmError> {
        let base = if self.server_url.is_empty() {
            override_url.unwrap_or_default()
        } else {
            &self.server_url
        }
        .trim_end_matches('/');
        if base.is_empty() {
            return Err(ReCtmError::new(
                "OAUTH_SERVER_URL_REQUIRED",
                "OAuth request base URL is unavailable.",
            )
            .with_category(ErrorCategory::Validation));
        }
        validate_oauth_server_url(base)?;
        Ok(base.to_owned())
    }

    fn emit(&self, event_type: &str, trace_id: &str, reason: &str, details: Value) {
        (self.runtime.events)(serde_json::json!({
            "event_type": event_type,
            "component": "oauth_authority",
            "trace_id": trace_id,
            "reason": reason,
            "details": details,
        }));
    }
}

pub fn valid_pkce_challenge(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub fn valid_pkce_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

pub fn verify_pkce(verifier: &str, challenge: &str) -> bool {
    if !valid_pkce_verifier(verifier) {
        return false;
    }
    let mut digest = Sha256::new();
    digest.update(verifier.as_bytes());
    constant_time_equal(
        URL_SAFE_NO_PAD.encode(digest.finalize()).as_bytes(),
        challenge.as_bytes(),
    )
}

pub fn parse_basic_authorization(header: &str) -> (String, String) {
    let Some(encoded) = header.strip_prefix("Basic ") else {
        return (String::new(), String::new());
    };
    let Ok(decoded) = STANDARD.decode(encoded) else {
        return (String::new(), String::new());
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
        return (String::new(), String::new());
    };
    let Some((client_id, client_secret)) = decoded.split_once(':') else {
        return (String::new(), String::new());
    };
    (percent_decode(client_id), percent_decode(client_secret))
}

fn authenticate_client(client: &Value, secret: &str, presented_method: &str) -> bool {
    let required = text(client, "token_endpoint_auth_method").unwrap_or_default();
    if required != presented_method {
        return false;
    }
    if required == "none" {
        return secret.is_empty();
    }
    let digest = text(client, "secret_digest").unwrap_or_default();
    !secret.is_empty()
        && !digest.is_empty()
        && constant_time_equal(digest.as_bytes(), secret_digest(secret).as_bytes())
}

fn canonical_json(value: &Value) -> Result<Vec<u8>, ReCtmError> {
    serde_json::to_vec(&sort_json(value)).map_err(json_error)
}

fn sort_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| (key.clone(), sort_json(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(sort_json).collect()),
        _ => value.clone(),
    }
}

fn percent_decode(value: &str) -> String {
    form_urlencoded::parse(format!("v={value}").as_bytes())
        .find_map(|(key, value)| (key == "v").then(|| value.into_owned()))
        .unwrap_or_default()
}

fn optional_text(value: Option<&Value>, maximum: usize) -> Option<String> {
    let value = value?.as_str()?.trim();
    (!value.is_empty()).then(|| value.chars().take(maximum).collect())
}

fn value(params: &BTreeMap<String, String>, key: &str) -> String {
    params.get(key).cloned().unwrap_or_default()
}

fn first_nonempty(values: &[String]) -> String {
    values
        .iter()
        .find(|value| !value.is_empty())
        .cloned()
        .unwrap_or_default()
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn secret_digest(value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(value.as_bytes());
    format!("{:x}", digest.finalize())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn permission(code: &str, message: &str) -> ReCtmError {
    ReCtmError::new(code, message).with_category(ErrorCategory::Permission)
}

fn invalid_token() -> ReCtmError {
    permission(
        "OAUTH_UNAUTHORIZED",
        "OAuth access token is invalid or expired.",
    )
}

fn internal_client_error() -> ReCtmError {
    ReCtmError::new(
        "OAUTH_CLIENT_RECORD_INVALID",
        "OAuth client record has an invalid shape.",
    )
    .with_category(ErrorCategory::Internal)
}

fn sql_error(error: rusqlite::Error) -> ReCtmError {
    ReCtmError::new("OAUTH_SQLITE_ERROR", error.to_string()).with_category(ErrorCategory::Internal)
}

fn json_error(error: serde_json::Error) -> ReCtmError {
    ReCtmError::new("OAUTH_JSON_ERROR", error.to_string()).with_category(ErrorCategory::Internal)
}

fn io_error(error: std::io::Error) -> ReCtmError {
    ReCtmError::new("OAUTH_IO_ERROR", error.to_string()).with_category(ErrorCategory::Runtime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{FixedClock, SequenceIdSource};
    use tempfile::TempDir;
    use url::Url;

    fn service(ids: &[&str]) -> Result<(TempDir, Arc<OAuthService>), ReCtmError> {
        let temp = TempDir::new().map_err(io_error)?;
        let runtime = GatewayRuntime {
            clock: Arc::new(FixedClock::new(1_788_270_000, "2026-09-01T03:00:00Z")),
            ids: Arc::new(SequenceIdSource::new(
                ids.iter().map(|value| (*value).to_owned()),
            )),
            events: Arc::new(|_| {}),
        };
        let store = Arc::new(OAuthStore::open(
            &temp.path().join("oauth.sqlite3"),
            runtime.clone(),
        )?);
        let service = Arc::new(OAuthService::new(
            "https://re-ctm.example.test",
            "operator-password",
            b"oooooooooooooooooooooooooooooooo",
            store,
            runtime,
            86_400,
        )?);
        Ok((temp, service))
    }

    #[test]
    fn public_pkce_code_is_single_use() -> Result<(), ReCtmError> {
        let (_temp, service) = service(&["client-public-fixed", "authorization-code-fixed"])?;
        let registered = service.register(
            &serde_json::json!({
                "redirect_uris": ["http://127.0.0.1/callback"],
                "token_endpoint_auth_method": "none",
            }),
            "trace-register",
        )?;
        let client_id = registered["client_id"]
            .as_str()
            .ok_or_else(internal_client_error)?;
        let verifier = "A".repeat(43);
        let mut digest = Sha256::new();
        digest.update(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(digest.finalize());
        let params = BTreeMap::from([
            ("client_id".to_owned(), client_id.to_owned()),
            (
                "redirect_uri".to_owned(),
                "http://127.0.0.1/callback".to_owned(),
            ),
            ("response_type".to_owned(), "code".to_owned()),
            ("code_challenge".to_owned(), challenge),
            ("code_challenge_method".to_owned(), "S256".to_owned()),
            (
                "resource".to_owned(),
                "https://re-ctm.example.test".to_owned(),
            ),
            ("state".to_owned(), "state".to_owned()),
        ]);
        let redirect = service.authorize(&params, "operator-password", "trace-authorize", None)?;
        let code = Url::parse(&redirect)
            .map_err(|_| invalid_argument("redirect URL invalid"))?
            .query_pairs()
            .find_map(|(key, value)| (key == "code").then(|| value.into_owned()))
            .ok_or_else(|| invalid_argument("authorization code missing"))?;
        let exchange = BTreeMap::from([
            ("grant_type".to_owned(), "authorization_code".to_owned()),
            ("code".to_owned(), code),
            (
                "redirect_uri".to_owned(),
                "http://127.0.0.1/callback".to_owned(),
            ),
            ("code_verifier".to_owned(), verifier),
            ("client_id".to_owned(), client_id.to_owned()),
            (
                "resource".to_owned(),
                "https://re-ctm.example.test".to_owned(),
            ),
        ]);
        let token = service.exchange_code(&exchange, "", "", "trace-token", None)?;
        assert_eq!(token["token_type"], "Bearer");
        let repeated = service.exchange_code(&exchange, "", "", "trace-token-reuse", None);
        assert_eq!(
            repeated.map_err(|error| error.code),
            Err("OAUTH_INVALID_GRANT".to_owned())
        );
        Ok(())
    }

    #[test]
    fn secret_methods_and_pkce_shape_fail_closed() -> Result<(), ReCtmError> {
        let (_temp, service) = service(&["client-secret-fixed", "client-secret-value-fixed"])?;
        let registered = service.register(
            &serde_json::json!({
                "redirect_uris": ["http://localhost/callback"],
                "token_endpoint_auth_method": "client_secret_basic",
            }),
            "trace-register",
        )?;
        assert!(registered.get("client_secret").is_some());
        assert!(!valid_pkce_challenge("short"));
        assert!(!valid_pkce_verifier("short"));
        assert!(!verify_pkce(&"A".repeat(43), &"B".repeat(43)));
        Ok(())
    }
}
