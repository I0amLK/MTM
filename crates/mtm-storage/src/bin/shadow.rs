#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use mtm_contracts::{ErrorCategory, ReCtmError, WorkflowRole};
use mtm_storage::{CapabilityAuthority, Clock, IdSource, StateStore, StoreRuntime, TransitionRun};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{Map, Value};

const MAX_INPUT_BYTES: u64 = 4 * 1024 * 1024;
static EMPTY_OBJECT: LazyLock<Map<String, Value>> = LazyLock::new(Map::new);

#[derive(Deserialize)]
struct ShadowRequest {
    database: PathBuf,
    now_iso: String,
    unix_seconds: i64,
    #[serde(default)]
    hex_ids: Vec<String>,
    #[serde(default)]
    urlsafe_ids: Vec<String>,
    secret_base64: String,
    #[serde(default)]
    initial_token: Option<String>,
    operations: Vec<Operation>,
}

#[derive(Deserialize)]
struct Operation {
    op: String,
    #[serde(default)]
    args: Map<String, Value>,
}

#[derive(Clone)]
struct FixedClock {
    now_iso: String,
    unix_seconds: i64,
}

impl Clock for FixedClock {
    fn now_iso(&self) -> Result<String, ReCtmError> {
        Ok(self.now_iso.clone())
    }

    fn unix_seconds(&self) -> Result<i64, ReCtmError> {
        Ok(self.unix_seconds)
    }
}

struct QueueIds {
    hex: Mutex<VecDeque<String>>,
    urlsafe: Mutex<VecDeque<String>>,
}

impl QueueIds {
    fn pop(queue: &Mutex<VecDeque<String>>, kind: &str) -> Result<String, ReCtmError> {
        queue
            .lock()
            .map_err(|_| internal("deterministic ID queue is poisoned"))?
            .pop_front()
            .ok_or_else(|| internal(&format!("deterministic {kind} ID queue is empty")))
    }
}

impl IdSource for QueueIds {
    fn token_hex(&self, _bytes: usize) -> Result<String, ReCtmError> {
        Self::pop(&self.hex, "hex")
    }

    fn token_urlsafe(&self, _bytes: usize) -> Result<String, ReCtmError> {
        Self::pop(&self.urlsafe, "urlsafe")
    }
}

fn main() {
    let result = read_request().and_then(run_request);
    let payload = match result {
        Ok(value) => serde_json::json!({"ok": true, "result": value}),
        Err(error) => serde_json::json!({"ok": false, "error": error.to_payload()}),
    };
    match serde_json::to_string(&payload) {
        Ok(output) => println!("{output}"),
        Err(_) => {
            eprintln!("storage shadow serialization failed");
            std::process::exit(2);
        }
    }
}

fn read_request() -> Result<ShadowRequest, ReCtmError> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| runtime("INPUT_READ_ERROR", &error.to_string()))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(validation(
            "INPUT_TOO_LARGE",
            "Storage shadow input exceeds 4 MiB.",
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| validation("INVALID_JSON", &format!("Invalid JSON input: {error}")))
}

fn run_request(request: ShadowRequest) -> Result<Value, ReCtmError> {
    let secret = STANDARD
        .decode(&request.secret_base64)
        .map_err(|_| validation("INVALID_ARGUMENT", "secret_base64 is invalid"))?;
    let runtime = StoreRuntime {
        clock: Arc::new(FixedClock {
            now_iso: request.now_iso,
            unix_seconds: request.unix_seconds,
        }),
        ids: Arc::new(QueueIds {
            hex: Mutex::new(request.hex_ids.into()),
            urlsafe: Mutex::new(request.urlsafe_ids.into()),
        }),
    };
    let store = Arc::new(StateStore::open_with_runtime(&request.database, runtime)?);
    let authority = CapabilityAuthority::new(&secret, Arc::clone(&store), 3600, None)?;
    let mut last_token = request.initial_token;
    let mut results = Vec::with_capacity(request.operations.len());
    for operation in request.operations {
        let result = dispatch(
            &store,
            &authority,
            &request.database,
            &operation,
            &mut last_token,
        );
        results.push(match result {
            Ok(value) => serde_json::json!({"ok": true, "result": value}),
            Err(error) => serde_json::json!({"ok": false, "error": error.to_payload()}),
        });
    }
    let snapshot = store.database_snapshot()?;
    store.checkpoint()?;
    Ok(serde_json::json!({
        "results": results,
        "snapshot": snapshot,
        "last_token": last_token,
    }))
}

fn dispatch(
    store: &Arc<StateStore>,
    authority: &CapabilityAuthority,
    database: &PathBuf,
    operation: &Operation,
    last_token: &mut Option<String>,
) -> Result<Value, ReCtmError> {
    let args = &operation.args;
    match operation.op.as_str() {
        "schema_version" => Ok(Value::from(store.schema_version()?)),
        "database_snapshot" => store.database_snapshot(),
        "database_digest" => store.database_digest(),
        "create_run" => store.create_run(
            text(args, "run_id")?,
            text(args, "problem_id")?,
            text(args, "owner_id")?,
            text(args, "state")?,
            args.get("metadata").unwrap_or(&Value::Object(Map::new())),
        ),
        "get_run" => store.get_run(text(args, "run_id")?),
        "list_runs" => Ok(Value::Array(
            store.list_runs(text(args, "owner_id")?, integer(args, "limit", 100)?)?,
        )),
        "update_run_metadata" => {
            store.update_run_metadata(text(args, "run_id")?, object(args, "updates")?)
        }
        "transition_run" => store.transition_run(TransitionRun {
            run_id: text(args, "run_id")?,
            expected_state: text(args, "expected_state")?,
            after_state: text(args, "after_state")?,
            trace_id: text(args, "trace_id")?,
            actor: text(args, "actor")?,
            reason: text(args, "reason")?,
            evidence: args.get("evidence").unwrap_or(&Value::Object(Map::new())),
            increment_epoch: boolean(args, "increment_epoch", true)?,
            status: optional_text(args, "status")?,
            latex_passed: optional_bool(args, "latex_passed")?,
            verdict: optional_text(args, "verdict")?,
            sealed: optional_bool(args, "sealed")?,
            round_delta: integer(args, "round_delta", 0)?,
        }),
        "create_domain" => store.create_domain(
            text(args, "domain_id")?,
            text(args, "run_id")?,
            text(args, "role")?,
            optional_text(args, "snapshot_id")?,
            optional_integer(args, "order_index")?,
            args.get("metadata").unwrap_or(&Value::Object(Map::new())),
        ),
        "get_domain" => store.get_domain(text(args, "domain_id")?),
        "list_domains" => Ok(Value::Array(store.list_domains(
            text(args, "run_id")?,
            optional_text(args, "role")?,
            optional_text(args, "status")?,
        )?)),
        "seal_domain" => store.seal_domain(text(args, "domain_id")?),
        "create_branch" => store.create_branch(
            text(args, "branch_id")?,
            text(args, "run_id")?,
            text(args, "plan_id")?,
            text(args, "domain_id")?,
            text(args, "snapshot_id")?,
            integer(args, "order_index", 0)?,
            args.get("metadata").unwrap_or(&Value::Object(Map::new())),
        ),
        "get_branch" => store.get_branch(text(args, "branch_id")?),
        "list_branches" => Ok(Value::Array(store.list_branches(text(args, "run_id")?)?)),
        "update_branch_status" => store.update_branch_status(
            text(args, "branch_id")?,
            text(args, "status")?,
            optional_text(args, "result_path")?,
        ),
        "add_steering" => Ok(Value::from(store.add_steering(
            text(args, "run_id")?,
            text(args, "owner_id")?,
            text(args, "message")?,
        )?)),
        "consume_steering" => Ok(Value::Array(
            store.consume_steering(text(args, "run_id")?, integer(args, "limit", 20)?)?,
        )),
        "list_transitions" => Ok(Value::Array(store.list_transitions(text(args, "run_id")?)?)),
        "create_project" => store.create_project(
            text(args, "owner_id")?,
            text(args, "title")?,
            optional_text(args, "project_id")?,
            args.get("metadata").unwrap_or(&Value::Object(Map::new())),
        ),
        "get_project" => {
            store.get_project(text(args, "project_id")?, optional_text(args, "owner_id")?)
        }
        "list_projects" => Ok(Value::Array(
            store.list_projects(text(args, "owner_id")?, integer(args, "limit", 100)?)?,
        )),
        "create_claim" => store.create_claim(
            text(args, "owner_id")?,
            text(args, "project_id")?,
            text(args, "title")?,
            optional_text(args, "claim_id")?,
            args.get("metadata").unwrap_or(&Value::Object(Map::new())),
        ),
        "get_claim" => store.get_claim(text(args, "claim_id")?, optional_text(args, "owner_id")?),
        "list_claims" => Ok(Value::Array(
            store.list_claims(text(args, "project_id")?, text(args, "owner_id")?)?,
        )),
        "list_claim_revisions" => Ok(Value::Array(
            store.list_claim_revisions(text(args, "claim_id")?, text(args, "owner_id")?)?,
        )),
        "get_claim_revision" => {
            store.get_claim_revision(text(args, "revision_id")?, optional_text(args, "owner_id")?)
        }
        "current_claim_revision" => Ok(store
            .current_claim_revision(text(args, "claim_id")?, text(args, "owner_id")?)?
            .unwrap_or(Value::Null)),
        "create_open_claim_revision" => {
            let conditions = strings(args, "conditions")?;
            store.create_open_claim_revision(
                text(args, "owner_id")?,
                text(args, "claim_id")?,
                text(args, "statement_tex")?,
                &conditions,
                optional_text(args, "expected_base_revision_id")?,
            )
        }
        "create_project_snapshot" => {
            store.create_project_snapshot(text(args, "project_id")?, text(args, "owner_id")?)
        }
        "get_project_snapshot" => {
            store.get_project_snapshot(text(args, "snapshot_id")?, text(args, "owner_id")?)
        }
        "link_run_to_project" => store.link_run_to_project(
            text(args, "run_id")?,
            text(args, "owner_id")?,
            text(args, "project_id")?,
            text(args, "project_snapshot_id")?,
            optional_text(args, "target_claim_id")?,
            optional_text(args, "base_revision_id")?,
            text(args, "requested_workflow_mode")?,
            text(args, "effective_workflow_mode")?,
            boolean(args, "register_result", true)?,
        ),
        "get_project_run" => Ok(store
            .get_project_run(text(args, "run_id")?, optional_text(args, "owner_id")?)?
            .unwrap_or(Value::Null)),
        "set_project_run_mode" => {
            store.set_project_run_mode(text(args, "run_id")?, text(args, "mode")?)?;
            Ok(serde_json::json!({"updated": true}))
        }
        "write_proof_manifest" => store.write_proof_manifest(
            text(args, "run_id")?,
            args.get("manifest").ok_or_else(|| missing("manifest"))?,
        ),
        "read_proof_manifest" => store.read_proof_manifest(text(args, "run_id")?),
        "register_reference" => store.register_reference(
            text(args, "run_id")?,
            optional_text(args, "project_id")?,
            text(args, "provider")?,
            text(args, "identity_key")?,
            optional_text(args, "title")?.unwrap_or(""),
            optional_text(args, "paper_id")?.unwrap_or(""),
            optional_text(args, "arxiv_id")?.unwrap_or(""),
            optional_text(args, "doi")?.unwrap_or(""),
            optional_text(args, "theorem_id")?.unwrap_or(""),
            optional_text(args, "source_uri")?.unwrap_or(""),
            optional_text(args, "source_state")?.unwrap_or("candidate"),
            optional_text(args, "source_sha256")?.unwrap_or(""),
            optional_text(args, "content_sha256")?.unwrap_or(""),
            args.get("metadata").unwrap_or(&Value::Object(Map::new())),
        ),
        "get_reference" => store.get_reference(text(args, "reference_id")?),
        "create_source_snapshot" => store.create_source_snapshot(
            text(args, "reference_id")?,
            text(args, "provider")?,
            text(args, "source_uri")?,
            text(args, "content")?,
            optional_text(args, "content_type")?.unwrap_or("application/json"),
            object_or_empty(args, "metadata")?,
        ),
        "list_source_snapshots" => Ok(Value::Array(
            store.list_source_snapshots(text(args, "reference_id")?)?,
        )),
        "list_run_references" => Ok(Value::Array(
            store.list_run_references(text(args, "run_id")?)?,
        )),
        "write_reference_audit" => store.write_reference_audit(
            text(args, "run_id")?,
            text(args, "reference_id")?,
            text(args, "disposition")?,
            optional_text(args, "evidence_basis")?.unwrap_or("unresolved"),
            optional_text(args, "evidence_locator")?.unwrap_or(""),
            optional_text(args, "verifier_domain_id")?.unwrap_or(""),
            optional_text(args, "proof_sha256")?.unwrap_or(""),
            optional_text(args, "proof_manifest_sha256")?.unwrap_or(""),
            boolean(args, "material", true)?,
            boolean(args, "assumptions_checked", false)?,
            boolean(args, "notation_checked", false)?,
            boolean(args, "source_checked", false)?,
            boolean(args, "independently_rederived", false)?,
            optional_text(args, "notes")?.unwrap_or(""),
        ),
        "get_reference_audit" => {
            store.get_reference_audit(text(args, "run_id")?, text(args, "reference_id")?)
        }
        "list_reference_audits" => Ok(Value::Array(
            store.list_reference_audits(text(args, "run_id")?)?,
        )),
        "promote_verified_run" => {
            let conditions = strings(args, "effective_conditions")?;
            store.promote_verified_run(
                text(args, "run_id")?,
                text(args, "owner_id")?,
                text(args, "statement_tex")?,
                text(args, "proof_sha256")?,
                &conditions,
                args.get("manifest").ok_or_else(|| missing("manifest"))?,
            )
        }
        "project_dependency_graph" => {
            store.project_dependency_graph(text(args, "project_id")?, text(args, "owner_id")?)
        }
        "capability_issue" => {
            let role: WorkflowRole =
                serde_json::from_value(Value::String(text(args, "role")?.to_owned()))
                    .map_err(|_| validation("INVALID_ARGUMENT", "role is invalid"))?;
            let token = authority.issue(
                text(args, "run_id")?,
                text(args, "domain_id")?,
                role,
                &strings(args, "permissions")?,
                text(args, "trace_id")?,
                optional_integer(args, "ttl_seconds")?,
            )?;
            *last_token = Some(token.clone());
            Ok(Value::String(token))
        }
        "capability_validate_last" => {
            let token = last_token.as_deref().ok_or_else(|| missing("last_token"))?;
            Ok(authority
                .validate(
                    token,
                    text(args, "owner_id")?,
                    text(args, "action")?,
                    text(args, "resource")?,
                    text(args, "trace_id")?,
                    optional_text(args, "expected_run_id")?,
                )?
                .to_payload())
        }
        "capability_revoke_last" => {
            let token = last_token.as_deref().ok_or_else(|| missing("last_token"))?;
            authority.revoke(token, text(args, "reason")?, text(args, "trace_id")?)?;
            Ok(serde_json::json!({"revoked": true}))
        }
        "capability_encode" => {
            let token = authority.encode(args.get("payload").ok_or_else(|| missing("payload"))?)?;
            *last_token = Some(token.clone());
            Ok(Value::String(token))
        }
        "capability_decode_last" => {
            authority.decode(last_token.as_deref().ok_or_else(|| missing("last_token"))?)
        }
        "tamper_capability_permissions" => {
            let nonce = text(args, "nonce")?;
            let permissions = strings(args, "permissions")?;
            let connection = Connection::open(database).map_err(sqlite_error)?;
            connection
                .execute(
                    "UPDATE capabilities SET permissions_json=? WHERE nonce=?",
                    rusqlite::params![
                        serde_json::to_string(&permissions)
                            .map_err(|error| internal(&error.to_string()))?,
                        nonce
                    ],
                )
                .map_err(sqlite_error)?;
            Ok(serde_json::json!({"tampered": true}))
        }
        "checkpoint" => {
            store.checkpoint()?;
            Ok(serde_json::json!({"checkpointed": true}))
        }
        _ => Err(validation(
            "INVALID_ARGUMENT",
            "unsupported storage shadow operation",
        )),
    }
}

fn text<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a str, ReCtmError> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| missing(key))
}

fn optional_text<'a>(
    args: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, ReCtmError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_str().map(Some).ok_or_else(|| missing(key)),
    }
}

fn object<'a>(
    args: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>, ReCtmError> {
    args.get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| missing(key))
}

fn object_or_empty<'a>(
    args: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>, ReCtmError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(&EMPTY_OBJECT),
        Some(value) => value.as_object().ok_or_else(|| missing(key)),
    }
}

fn strings(args: &Map<String, Value>, key: &str) -> Result<Vec<String>, ReCtmError> {
    args.get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| missing(key))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| missing(key))
        })
        .collect()
}

fn integer(args: &Map<String, Value>, key: &str, default: i64) -> Result<i64, ReCtmError> {
    match args.get(key) {
        None => Ok(default),
        Some(value) => value.as_i64().ok_or_else(|| missing(key)),
    }
}

fn optional_integer(args: &Map<String, Value>, key: &str) -> Result<Option<i64>, ReCtmError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_i64().map(Some).ok_or_else(|| missing(key)),
    }
}

fn boolean(args: &Map<String, Value>, key: &str, default: bool) -> Result<bool, ReCtmError> {
    match args.get(key) {
        None => Ok(default),
        Some(value) => value.as_bool().ok_or_else(|| missing(key)),
    }
}

fn optional_bool(args: &Map<String, Value>, key: &str) -> Result<Option<bool>, ReCtmError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_bool().map(Some).ok_or_else(|| missing(key)),
    }
}

fn missing(key: &str) -> ReCtmError {
    validation(
        "INVALID_ARGUMENT",
        &format!("{key} is required or has the wrong type"),
    )
}

fn validation(code: &str, message: &str) -> ReCtmError {
    ReCtmError::new(code, message).with_category(ErrorCategory::Validation)
}

fn runtime(code: &str, message: &str) -> ReCtmError {
    ReCtmError::new(code, message).with_category(ErrorCategory::Runtime)
}

fn internal(message: &str) -> ReCtmError {
    ReCtmError::new("INTERNAL_ERROR", message).with_category(ErrorCategory::Internal)
}

fn sqlite_error(error: rusqlite::Error) -> ReCtmError {
    ReCtmError::new("SQLITE_ERROR", error.to_string()).with_category(ErrorCategory::Internal)
}
