//! Test-only deterministic diagnosis, not attribution of the historical r3 failure.
//! All state and authentication are synthetic and confined to one temporary root.

use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mtm_contracts::{LatexPolicy, NativeMode, ReCtmError};
use mtm_gateway::{
    GatewayRuntime, MCPDispatcher, OAuthPrincipal, OAuthService, OAuthStore, ToolCatalog,
};
use mtm_runtime::{
    NativeToolRuntime, NativeWorkspace, RuntimeBackendFacts, RuntimeLatexGate, RuntimeToolBackend,
};
use mtm_storage::{CapabilityAuthority, IdSource, StateStore, StoreRuntime, SystemClock};
use mtm_workflow::{PrivateVault, TaskCatalog, WorkflowEngine};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

// Fixed errors prevent failure output from exposing synthetic tokens or task bodies.
type Result<T = ()> = std::result::Result<T, &'static str>;

fn require(condition: bool, message: &'static str) -> Result {
    if condition { Ok(()) } else { Err(message) }
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or("missing fixture field")
}

struct CollisionIds {
    domains: Mutex<VecDeque<&'static str>>,
    other: AtomicU64,
}

impl CollisionIds {
    fn new() -> Self {
        Self {
            // assess A, assemble A, assess B, assemble B collision, repeated
            // collision for the explicit diagnostic, then a fresh recovery ID.
            domains: Mutex::new(VecDeque::from([
                "010101", "abcdef", "020202", "abcdef", "abcdef", "030303",
            ])),
            other: AtomicU64::new(1),
        }
    }
}

impl IdSource for CollisionIds {
    fn token_hex(&self, bytes: usize) -> std::result::Result<String, ReCtmError> {
        if bytes == 3 {
            return self
                .domains
                .lock()
                .map_err(|_| ReCtmError::new("TEST_IDS", "fixture ID lock failed"))?
                .pop_front()
                .map(str::to_owned)
                .ok_or_else(|| ReCtmError::new("TEST_IDS", "fixture domain IDs exhausted"));
        }
        Ok(format!(
            "{:0width$x}",
            self.other.fetch_add(1, Ordering::SeqCst),
            width = bytes * 2
        ))
    }

    fn token_urlsafe(&self, bytes: usize) -> std::result::Result<String, ReCtmError> {
        self.token_hex(bytes)
    }
}

fn authenticate(root: &Path) -> Result<OAuthPrincipal> {
    let runtime = GatewayRuntime::default();
    let store = Arc::new(
        OAuthStore::open(&root.join("fixture-oauth.sqlite3"), runtime.clone())
            .map_err(|_| "fixture OAuth store")?,
    );
    let service = OAuthService::new(
        "https://fixture.example.test",
        "fixture-password",
        b"oooooooooooooooooooooooooooooooo",
        store,
        runtime,
        86_400,
    )
    .map_err(|_| "fixture OAuth service")?;
    let registered = service
        .register(
            &json!({"redirect_uris":["http://127.0.0.1/callback"],
        "token_endpoint_auth_method":"none"}),
            "fixture-register",
        )
        .map_err(|_| "fixture registration")?;
    let client = text(&registered, "client_id")?;
    let verifier = "A".repeat(43);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let params = BTreeMap::from([
        ("client_id".to_owned(), client.to_owned()),
        (
            "redirect_uri".to_owned(),
            "http://127.0.0.1/callback".to_owned(),
        ),
        ("response_type".to_owned(), "code".to_owned()),
        ("code_challenge".to_owned(), challenge),
        ("code_challenge_method".to_owned(), "S256".to_owned()),
        (
            "resource".to_owned(),
            "https://fixture.example.test".to_owned(),
        ),
    ]);
    let redirect = service
        .authorize(&params, "fixture-password", "fixture-authorize", None)
        .map_err(|_| "fixture authorization")?;
    let code = url::Url::parse(&redirect)
        .map_err(|_| "fixture redirect")?
        .query_pairs()
        .find_map(|(key, value)| (key == "code").then(|| value.into_owned()))
        .ok_or("fixture code")?;
    let exchange = BTreeMap::from([
        ("grant_type".to_owned(), "authorization_code".to_owned()),
        ("code".to_owned(), code),
        (
            "redirect_uri".to_owned(),
            "http://127.0.0.1/callback".to_owned(),
        ),
        ("code_verifier".to_owned(), verifier),
        ("client_id".to_owned(), client.to_owned()),
        (
            "resource".to_owned(),
            "https://fixture.example.test".to_owned(),
        ),
    ]);
    let token = service
        .exchange_code(&exchange, "", "", "fixture-token", None)
        .map_err(|_| "fixture token exchange")?;
    service
        .validate_authorization_header(
            &format!("Bearer {}", text(&token, "access_token")?),
            "fixture-principal",
            None,
        )
        .map_err(|_| "fixture token validation")
}

struct Fixture {
    store: Arc<StateStore>,
    vault: Arc<PrivateVault>,
    workflow: Arc<WorkflowEngine>,
    native: Arc<NativeToolRuntime>,
    mcp: MCPDispatcher,
}

impl Fixture {
    fn open(root: &Path, ids: Arc<CollisionIds>) -> Result<Self> {
        let private = root.join("private");
        let workspace_path = root.join("workspace");
        std::fs::create_dir_all(&workspace_path).map_err(|_| "fixture workspace")?;
        let vault = Arc::new(PrivateVault::new(&private).map_err(|_| "fixture vault")?);
        let store = Arc::new(
            StateStore::open_with_runtime(
                private.join("state.sqlite3"),
                StoreRuntime {
                    clock: Arc::new(SystemClock),
                    ids,
                },
            )
            .map_err(|_| "fixture state")?,
        );
        let capabilities = Arc::new(
            CapabilityAuthority::new(
                b"cccccccccccccccccccccccccccccccc",
                Arc::clone(&store),
                600,
                None,
            )
            .map_err(|_| "fixture capabilities")?,
        );
        let workspace = Arc::new(
            NativeWorkspace::new(&workspace_path, &private)
                .map_err(|_| "fixture workspace policy")?,
        );
        let native = Arc::new(
            NativeToolRuntime::new(
                Arc::clone(&workspace),
                NativeMode::Dangerous,
                "disabled",
                &[],
                &[private],
            )
            .map_err(|_| "fixture Native disabled")?,
        );
        let source = serde_json::from_str(include_str!("../../mtm-cli/assets/methodology-v2.json"))
            .map_err(|_| "fixture methodology JSON")?;
        let catalog =
            Arc::new(TaskCatalog::from_source_snapshot(source).map_err(|_| "fixture methodology")?);
        let workflow = Arc::new(WorkflowEngine::new(
            Arc::clone(&store),
            Arc::clone(&vault),
            Arc::clone(&capabilities),
            catalog,
            Arc::new(RuntimeLatexGate::new(
                LatexPolicy::StaticOnly,
                Arc::clone(&native),
            )),
            None,
        ));
        let backend = Arc::new(RuntimeToolBackend::new_with_protocol_and_observer(
            Arc::clone(&native),
            workspace,
            Arc::clone(&workflow),
            Arc::clone(&store),
            capabilities,
            RuntimeBackendFacts {
                workflow_protocol_version: 3,
                complete_flow_locally_validated: false,
            },
            None,
        ));
        let mcp = MCPDispatcher::new(
            Arc::new(ToolCatalog::new()),
            backend,
            GatewayRuntime::default(),
        );
        Ok(Self {
            store,
            vault,
            workflow,
            native,
            mcp,
        })
    }

    fn call(&self, principal: &OAuthPrincipal, name: &str, arguments: Value) -> Result<Value> {
        let envelope = self
            .mcp
            .dispatch(
                &json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":name,"arguments":arguments}}),
                principal,
                Some("fixture-call"),
                None,
            )
            .map_err(|_| "fixture dispatch")?
            .ok_or("fixture response")?;
        require(
            envelope.get("error").is_none(),
            "fixture JSON-RPC rejection",
        )?;
        require(
            envelope["result"]["isError"] == false,
            "fixture tool rejection",
        )?;
        Ok(envelope["result"]["structuredContent"].clone())
    }

    fn start(&self, principal: &OAuthPrincipal) -> Result<Value> {
        let started = self.call(
            principal,
            "rethlas_start",
            json!({
            "problem_tex":"Synthetic fixture: prove 1=1.","problem_id":"collision-fixture",
            "workflow_mode":"compact","register_result":false}),
        )?;
        self.call(
            principal,
            "rethlas_step",
            json!({"run_id":text(&started,"run_id")?}),
        )
    }

    fn memory(&self, run: &str) -> Result<Value> {
        Ok(json!([
            self.vault
                .read_generation_memory(run, "immediate_conclusions")
                .map_err(|_| "fixture conclusions")?,
            self.vault
                .read_generation_memory(run, "events")
                .map_err(|_| "fixture events")?,
        ]))
    }
}

fn submission(task: &Value) -> Result<Value> {
    let minimal = task
        .pointer("/task/minimal_submission")
        .filter(|value| value.is_object())
        .ok_or("fixture task has no minimal submission")?;
    Ok(
        json!({"run_id":text(task,"run_id")?,"capability":text(task,"capability")?,
        "action":text(minimal,"action")?,"payload":minimal["payload"],"writes":minimal["writes"]}),
    )
}

#[test]
fn deterministic_domain_collision_preserves_committed_receipt_and_recovers() -> Result {
    let root = tempfile::tempdir().map_err(|_| "fixture temporary root")?;
    let principal = authenticate(root.path())?;
    let ids = Arc::new(CollisionIds::new());
    let fixture = Fixture::open(root.path(), Arc::clone(&ids))?;
    let first = fixture.start(&principal)?;
    let first_next = fixture.call(&principal, "rethlas_step", submission(&first)?)?;
    require(
        first_next["state"] == "assemble",
        "fixture positive control did not advance",
    )?;
    submission(&first_next)?;
    let first_domain = text(&first_next, "domain_id")?.to_owned();
    let domain_before = fixture
        .store
        .get_domain(&first_domain)
        .map_err(|_| "fixture first domain")?;

    let second = fixture.start(&principal)?;
    require(
        second["run_id"] != first["run_id"],
        "fixture runs not distinct",
    )?;
    let run = text(&second, "run_id")?.to_owned();
    let request = submission(&second)?;
    let writes = request["writes"].as_array().ok_or("fixture writes")?.len();
    require(writes > 0, "fixture must exercise caller writes")?;
    let response = fixture.call(&principal, "rethlas_step", request.clone())?;
    require(
        response["ok"] == true
            && response["submission"]["ok"] == true
            && response["state"] == "assemble"
            && response["run_id"] == second["run_id"]
            && response["writes_applied"] == writes
            && response["task_required"] == true
            && response["state_is_historical"] == true
            && response["submission_receipt"]["status"] == "completed"
            && response["submission_receipt"]["replayed"] == false
            && response.get("capability").is_none()
            && response.get("task").is_none(),
        "collision did not yield the expected committed receipt without next task",
    )?;
    require(
        fixture
            .store
            .pending_submission_status(&principal.client_id, &run)
            .map_err(|_| "fixture pending status")?
            .is_null(),
        "collision left a pending submission",
    )?;
    require(
        fixture
            .store
            .list_domains(&run, Some("assembler"), None)
            .map_err(|_| "fixture second domains")?
            .is_empty(),
        "collision created an assembler domain",
    )?;
    require(
        fixture
            .store
            .get_domain(&first_domain)
            .map_err(|_| "fixture collision owner")?
            == domain_before,
        "collision changed the other run domain",
    )?;
    let memory = fixture.memory(&run)?;
    let state = fixture
        .store
        .get_run(&run)
        .map_err(|_| "fixture committed state")?;
    let error = fixture
        .workflow
        .next_task(&principal.client_id, &run, Some("fixture-collision-check"))
        .err()
        .ok_or("forced duplicate ID unexpectedly succeeded")?;
    require(
        error.code == "SQLITE_ERROR"
            && error
                .message
                .contains("UNIQUE constraint failed: domains.domain_id"),
        "forced duplicate did not produce the expected domain constraint error",
    )?;
    require(
        fixture.memory(&run)? == memory,
        "failed next task rewrote caller memory",
    )?;
    fixture.native.close().map_err(|_| "fixture close")?;
    drop(fixture);

    // A fresh composition reopens only this disposable database, with no model
    // action replay. The exact original request returns its durable receipt.
    let reopened = Fixture::open(root.path(), Arc::clone(&ids))?;
    let replay = reopened.call(&principal, "rethlas_step", request)?;
    require(
        replay["submission_receipt"]["replayed"] == true
            && replay["writes_applied"] == 0
            && replay["submission_receipt"]["status"] == "completed"
            && replay["task_required"] == true,
        "reopened exact request did not replay its completed zero-write receipt",
    )?;
    require(
        reopened.memory(&run)? == memory
            && reopened
                .store
                .get_run(&run)
                .map_err(|_| "fixture reopened state")?
                == state,
        "receipt replay repeated writes or transitioned state",
    )?;
    let recovered = reopened.call(&principal, "rethlas_step", json!({"run_id":run}))?;
    require(
        recovered["state"] == "assemble"
            && recovered["role"] == "assembler"
            && recovered["domain_id"] != first_domain
            && recovered["run_id"] == second["run_id"],
        "fresh ID did not recover a same-run assembler task",
    )?;
    submission(&recovered)?;
    require(
        reopened.memory(&run)? == memory,
        "task recovery repeated caller writes",
    )?;
    require(
        reopened
            .store
            .get_domain(&first_domain)
            .map_err(|_| "fixture preserved first domain")?
            == domain_before,
        "recovery changed the other run domain",
    )?;
    require(
        ids.domains
            .lock()
            .map_err(|_| "fixture ID accounting")?
            .is_empty(),
        "fixture did not consume the exact domain-ID sequence",
    )?;
    reopened
        .native
        .close()
        .map_err(|_| "fixture reopened close")?;
    println!(
        "MTM_DOMAIN_COLLISION_DIAGNOSTIC {}",
        json!({
        "schema":"mtm017-deterministic-domain-collision-observation-v1",
        "passed":true,"synthetic_only":true,"forced_domain_collisions":2,
        "distinct_runs":2,"committed_receipt_completed":true,"next_task_missing":true,
        "collision_error_code":"SQLITE_ERROR","domain_primary_key_collision_confirmed":true,
        "other_run_domain_unchanged":true,"pending_submission_absent":true,
        "state_reopened":true,"receipt_replay_writes":0,"same_run_next_task_recovered":true,
        "caller_memory_unchanged_on_replay_and_recovery":true,
        "original_r3_cause_proven":false,"runtime_fix_claimed":false,
        "raw_oauth_or_capability_recorded":false,"production_state_modified":false,
        "release_qualified":false,"deployment_authorized":false})
    );
    Ok(())
}
