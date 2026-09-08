//! In-process HTTP integration through the real router, DCR/PKCE and dispatcher.
//! No live endpoint, browser, Native execution or workflow acceptance is implied.
//! Credentials are created for disposable stores and are never printed.
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mtm_contracts::ReCtmError;
use mtm_gateway::{
    GatewayHttpConfig, GatewayRuntime, GatewayState, MCPDispatcher, OAuthPrincipal, OAuthService,
    OAuthStore, PUBLIC_TOOL_NAMES, ToolBackend, ToolBackendResult, ToolCallContext, ToolCatalog,
    build_router,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use url::{Url, form_urlencoded};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
const BASE: &str = "http://127.0.0.1:8917";
const RESOURCE: &str = "http://127.0.0.1:8917/mcp";
const REDIRECT: &str = "http://127.0.0.1:8918/callback";
const RETIRED: [&str; 11] = [
    "rethlas_next",
    "rethlas_read",
    "rethlas_write",
    "rethlas_search",
    "rethlas_commit",
    "rethlas_status",
    "rethlas_steer",
    "rethlas_resume",
    "rethlas_cancel",
    "rethlas_get_artifact",
    "rethlas_export_final",
];

#[derive(Default)]
struct CountingBackend(AtomicUsize);

impl ToolBackend for CountingBackend {
    fn call(
        &self,
        name: &str,
        _arguments: &Map<String, Value>,
        _principal: &OAuthPrincipal,
        _trace_id: &str,
        _context: &ToolCallContext,
    ) -> std::result::Result<ToolBackendResult, ReCtmError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(ToolBackendResult::Complete(json!({
            "content":[],"structuredContent":{"ok":true,"tool":name},"isError":false
        })))
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    bytes: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Result<Value> {
        Ok(serde_json::from_slice(&self.bytes)?)
    }
}

struct Fixture {
    router: Router,
    backend: Arc<CountingBackend>,
    password: String,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new(fixed_origin: &str) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let runtime = GatewayRuntime::default();
        let mut key = [0_u8; 32];
        getrandom::fill(&mut key)?;
        let password = runtime.ids.token_urlsafe(32)?;
        let store = Arc::new(OAuthStore::open(
            &directory.path().join("oauth.sqlite3"),
            runtime.clone(),
        )?);
        let oauth = Arc::new(OAuthService::new(
            fixed_origin,
            &password,
            &key,
            store,
            runtime.clone(),
            3600,
        )?);
        let catalog = Arc::new(ToolCatalog::new());
        let backend = Arc::new(CountingBackend::default());
        let mcp = Arc::new(MCPDispatcher::new(
            catalog.clone(),
            backend.clone(),
            runtime.clone(),
        ));
        let config = GatewayHttpConfig {
            bind_host: "127.0.0.1".to_owned(),
            bind_port: 8917,
            fixed_oauth_origin: fixed_origin.to_owned(),
            allowed_origins: BTreeSet::from(["https://allowed.example".to_owned()]),
            complete_flow_locally_validated: false,
        };
        let router = build_router(Arc::new(GatewayState::new(
            oauth, mcp, catalog, runtime, config,
        )?));
        Ok(Self {
            router,
            backend,
            password,
            _directory: directory,
        })
    }

    async fn send(&self, mut request: Request<Body>, peer: &str) -> Result<Reply> {
        request
            .extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>()?));
        let response =
            tokio::time::timeout(Duration::from_secs(5), self.router.clone().oneshot(request))
                .await??;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await?
            .to_vec();
        Ok(Reply {
            status,
            headers,
            bytes,
        })
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: String,
        content_type: &str,
        headers: &[(&str, &str)],
    ) -> Result<Reply> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("Host", "127.0.0.1:8917")
            .header("Content-Type", content_type)
            .header("Content-Length", body.len());
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        self.send(request.body(Body::from(body))?, "127.0.0.1:12345")
            .await
    }

    async fn json(&self, path: &str, value: Value, headers: &[(&str, &str)]) -> Result<Reply> {
        self.request(
            "POST",
            path,
            serde_json::to_string(&value)?,
            "application/json",
            headers,
        )
        .await
    }

    async fn form(&self, path: &str, fields: &BTreeMap<String, String>) -> Result<Reply> {
        self.request(
            "POST",
            path,
            form_urlencoded::Serializer::new(String::new())
                .extend_pairs(fields)
                .finish(),
            "application/x-www-form-urlencoded",
            &[],
        )
        .await
    }

    async fn call(&self, auth: &str, name: &str, arguments: Value) -> Result<Reply> {
        self.json(
            "/mcp",
            rpc("tools/call", json!({"name":name,"arguments":arguments})),
            &[("Authorization", auth)],
        )
        .await
    }

    async fn authorize(&self) -> Result<(String, BTreeMap<String, String>)> {
        let registered = self.json("/oauth/register", json!({
            "redirect_uris":[REDIRECT],"token_endpoint_auth_method":"none","client_name":"Rust HTTP fixture"
        }), &[("Origin", "https://not-an-mcp-origin.example")]).await?;
        assert_eq!(registered.status, StatusCode::CREATED);
        let registration = registered.json()?;
        let client = registration["client_id"]
            .as_str()
            .ok_or("missing client id")?;
        let verifier = "a".repeat(64);
        let mut fields = BTreeMap::from([
            ("client_id".to_owned(), client.to_owned()),
            ("redirect_uri".to_owned(), REDIRECT.to_owned()),
            ("response_type".to_owned(), "code".to_owned()),
            (
                "code_challenge".to_owned(),
                URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
            ),
            ("code_challenge_method".to_owned(), "S256".to_owned()),
            ("resource".to_owned(), RESOURCE.to_owned()),
            ("state".to_owned(), "fixture<&>state".to_owned()),
        ]);
        let query = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&fields)
            .finish();
        let page = self
            .request(
                "GET",
                &format!("/oauth/authorize?{query}"),
                String::new(),
                "text/plain",
                &[],
            )
            .await?;
        assert_eq!(page.status, StatusCode::OK);
        assert_eq!(page.headers["cache-control"], "no-store");
        let html = std::str::from_utf8(&page.bytes)?;
        assert!(html.contains("fixture&lt;&amp;&gt;state"));
        assert!(!html.contains(&self.password));
        fields.insert("password".to_owned(), "incorrect-test-password".to_owned());
        let denied = self.form("/oauth/authorize", &fields).await?;
        assert_eq!(denied.status, StatusCode::FORBIDDEN);
        assert_eq!(denied.json()?["error"]["code"], "OAUTH_ACCESS_DENIED");
        fields.insert("password".to_owned(), self.password.clone());
        let authorized = self.form("/oauth/authorize", &fields).await?;
        assert_eq!(authorized.status, StatusCode::FOUND);
        let location = Url::parse(authorized.headers["location"].to_str()?)?;
        let callback: BTreeMap<String, String> = location.query_pairs().into_owned().collect();
        assert_eq!(
            callback.get("state").map(String::as_str),
            Some("fixture<&>state")
        );
        let code = callback.get("code").ok_or("missing authorization code")?;
        let exchange = BTreeMap::from([
            ("client_id".to_owned(), client.to_owned()),
            ("redirect_uri".to_owned(), REDIRECT.to_owned()),
            ("grant_type".to_owned(), "authorization_code".to_owned()),
            ("code".to_owned(), code.clone()),
            ("code_verifier".to_owned(), verifier),
            ("resource".to_owned(), RESOURCE.to_owned()),
        ]);
        let reply = self.form("/oauth/token", &exchange).await?;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.headers["cache-control"], "no-store");
        let data = reply.json()?;
        assert_eq!(data["token_type"], "Bearer");
        let token = data["access_token"]
            .as_str()
            .ok_or("missing access token")?;
        Ok((format!("Bearer {token}"), exchange))
    }
}

fn rpc(method: &str, params: Value) -> Value {
    json!({"jsonrpc":"2.0","id":"fixture","method":method,"params":params})
}

#[tokio::test]
async fn oauth_http_roundtrip_code_reuse_and_authenticated_dispatch() -> Result {
    let fixture = Fixture::new("")?;
    let (auth, exchange) = fixture.authorize().await?;
    let reuse = fixture.form("/oauth/token", &exchange).await?;
    assert_eq!(reuse.status, StatusCode::FORBIDDEN);
    assert_eq!(reuse.json()?["error"]["code"], "OAUTH_INVALID_GRANT");
    let call = fixture.call(&auth, "server_info", json!({})).await?;
    assert_eq!(call.status, StatusCode::OK);
    assert_eq!(
        call.json()?["result"]["structuredContent"]["tool"],
        "server_info"
    );
    assert_eq!(fixture.backend.0.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn missing_or_invalid_bearer_never_reaches_backend() -> Result {
    let fixture = Fixture::new("")?;
    for auth in ["", "Bearer not-a-valid-token"] {
        let reply = fixture.call(auth, "server_info", json!({})).await?;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.json()?["error"]["code"], "OAUTH_UNAUTHORIZED");
        assert!(
            reply.headers["www-authenticate"]
                .to_str()?
                .contains("/.well-known/oauth-protected-resource/mcp")
        );
    }
    assert_eq!(fixture.backend.0.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn every_retired_alias_and_invalid_request_is_rejected_before_backend() -> Result {
    let fixture = Fixture::new("")?;
    let (auth, _) = fixture.authorize().await?;
    for alias in RETIRED {
        let reply = fixture.call(&auth, alias, json!({})).await?;
        assert_eq!(reply.json()?["error"]["code"], -32602);
        assert_eq!(reply.json()?["error"]["data"]["reason"], "unknown_tool");
    }
    for args in [
        json!({}),
        json!({"cmd":"true","argv":["true"]}),
        json!({"argv":[""]}),
        json!({"cmd":"true","unexpected":1}),
    ] {
        let reply = fixture.call(&auth, "exec_command", args).await?;
        assert_eq!(reply.json()?["error"]["code"], -32602);
    }
    assert_eq!(fixture.backend.0.load(Ordering::SeqCst), 0);
    for args in [
        json!({"cmd":"pwd; pwd"}),
        json!({"argv":["printf","%s",""]}),
    ] {
        let reply = fixture.call(&auth, "exec_command", args).await?;
        assert_eq!(reply.json()?["result"]["isError"], false);
    }
    assert_eq!(fixture.backend.0.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn public_catalog_and_modern_mirrors_share_the_current_contract() -> Result {
    let fixture = Fixture::new("")?;
    let (auth, _) = fixture.authorize().await?;
    let listed = fixture
        .json(
            "/mcp",
            rpc("tools/list", json!({})),
            &[("Authorization", &auth)],
        )
        .await?;
    let value = listed.json()?;
    let names = value["result"]["tools"]
        .as_array()
        .ok_or("missing tools")?
        .iter()
        .map(|tool| tool["name"].as_str().ok_or("missing tool name"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    assert_eq!(names, PUBLIC_TOOL_NAMES);
    let modern = rpc(
        "tools/list",
        json!({"_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":{}
        }}),
    );
    let headers = [
        ("Authorization", auth.as_str()),
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", "tools/list"),
    ];
    let reply = fixture.json("/mcp", modern.clone(), &headers).await?;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()?["result"]["resultType"], "complete");
    assert_eq!(reply.json()?["result"]["ttlMs"], 0);
    let mut duplicate = headers.to_vec();
    duplicate.push(("MCP-Protocol-Version", "2026-07-28"));
    let reply = fixture.json("/mcp", modern.clone(), &duplicate).await?;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()?["error"]["code"], -32020);
    let mismatch = [
        ("Authorization", auth.as_str()),
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", "ping"),
    ];
    let reply = fixture.json("/mcp", modern, &mismatch).await?;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()?["error"]["code"], -32020);
    assert_eq!(fixture.backend.0.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn origin_and_body_guards_stop_calls_before_dispatch() -> Result {
    let fixture = Fixture::new("")?;
    let (auth, _) = fixture.authorize().await?;
    let ping = rpc("ping", json!({}));
    let denied = fixture
        .json(
            "/mcp",
            ping.clone(),
            &[
                ("Authorization", &auth),
                ("Origin", "https://attacker.example"),
            ],
        )
        .await?;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert_eq!(denied.json()?["error"]["code"], "ORIGIN_DENIED");
    let allowed = fixture
        .json(
            "/mcp",
            ping,
            &[
                ("Authorization", &auth),
                ("Origin", "https://allowed.example"),
            ],
        )
        .await?;
    assert_eq!(allowed.status, StatusCode::OK);
    assert_eq!(
        allowed.headers["access-control-allow-origin"],
        "https://allowed.example"
    );
    for body in ["[]".to_owned(), "{".to_owned()] {
        let reply = fixture
            .request(
                "POST",
                "/mcp",
                body,
                "application/json",
                &[("Authorization", &auth)],
            )
            .await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(reply.json()?["error"]["code"], "INVALID_BODY");
    }
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body(Body::from("{}"))?;
    let reply = fixture.send(request, "127.0.0.1:12345").await?;
    assert_eq!(reply.json()?["error"]["code"], "CONTENT_LENGTH_REQUIRED");
    let reply = fixture
        .request(
            "POST",
            "/mcp",
            "x".repeat(1_048_577),
            "application/json",
            &[("Authorization", &auth)],
        )
        .await?;
    assert_eq!(reply.json()?["error"]["code"], "REQUEST_TOO_LARGE");
    assert_eq!(fixture.backend.0.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn resource_discovery_and_forwarding_respect_peer_and_fixed_authority() -> Result {
    let dynamic = Fixture::new("")?;
    let metadata = dynamic
        .request(
            "GET",
            "/.well-known/oauth-protected-resource/mcp",
            String::new(),
            "text/plain",
            &[],
        )
        .await?;
    assert_eq!(metadata.status, StatusCode::OK);
    assert_eq!(metadata.json()?["resource"], RESOURCE);
    for (peer, expected) in [
        ("127.0.0.1:12345", "https://fixture.trycloudflare.com"),
        ("192.0.2.1:12345", BASE),
    ] {
        let request = Request::builder()
            .uri("/.well-known/oauth-authorization-server")
            .header("Host", "127.0.0.1:8917")
            .header("X-Forwarded-Proto", "https")
            .header("X-Forwarded-Host", "fixture.trycloudflare.com")
            .body(Body::empty())?;
        let reply = dynamic.send(request, peer).await?;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.json()?["issuer"], expected);
    }
    let fixed = Fixture::new("https://fixed.example")?;
    let reply = fixed
        .request(
            "GET",
            "/.well-known/oauth-authorization-server",
            String::new(),
            "text/plain",
            &[("X-Forwarded-Host", "attacker.example")],
        )
        .await?;
    assert_eq!(reply.json()?["issuer"], "https://fixed.example");
    Ok(())
}
