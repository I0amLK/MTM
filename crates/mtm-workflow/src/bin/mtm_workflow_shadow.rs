#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mtm_contracts::{ErrorCategory, ReCtmError};
use mtm_storage::{CapabilityAuthority, Clock, IdSource, StateStore, StoreRuntime};
use mtm_workflow::{
    LatexGate, LatexGateResult, PrivateVault, StartRequest, TaskCatalog, WorkflowEngine,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

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

struct SequenceIds {
    hex: Mutex<VecDeque<String>>,
    urlsafe: Mutex<VecDeque<String>>,
}

impl SequenceIds {
    fn new(hex: Vec<String>, urlsafe: Vec<String>) -> Self {
        Self {
            hex: Mutex::new(hex.into()),
            urlsafe: Mutex::new(urlsafe.into()),
        }
    }
}

impl IdSource for SequenceIds {
    fn token_hex(&self, _bytes: usize) -> Result<String, ReCtmError> {
        self.hex
            .lock()
            .map_err(|_| internal("hex id queue lock poisoned"))?
            .pop_front()
            .ok_or_else(|| internal("hex id queue exhausted"))
    }

    fn token_urlsafe(&self, _bytes: usize) -> Result<String, ReCtmError> {
        self.urlsafe
            .lock()
            .map_err(|_| internal("urlsafe id queue lock poisoned"))?
            .pop_front()
            .ok_or_else(|| internal("urlsafe id queue exhausted"))
    }
}

struct SequenceLatexGate {
    results: Mutex<VecDeque<LatexGateResult>>,
}

impl LatexGate for SequenceLatexGate {
    fn validate(&self, _proof: &str, _workdir: &Path) -> Result<LatexGateResult, ReCtmError> {
        self.results
            .lock()
            .map_err(|_| internal("latex result queue lock poisoned"))?
            .pop_front()
            .ok_or_else(|| internal("latex result queue exhausted"))
    }
}

struct Context {
    engine: WorkflowEngine,
    store: Arc<StateStore>,
    vault_root: PathBuf,
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
            Ok(result) => serde_json::json!({"ok":true,"result":result}),
            Err(error) => serde_json::json!({"ok":false,"error":error.to_payload()}),
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
    let request: Value = serde_json::from_str(line).map_err(json_error)?;
    let object = request
        .as_object()
        .ok_or_else(|| validation("request must be a JSON object"))?;
    let operation = text(object, "operation")?;
    let payload = object
        .get("payload")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if operation == "init" {
        *context = Some(initialize(&payload)?);
        return Ok(serde_json::json!({"initialized":true}));
    }
    let current = context
        .as_ref()
        .ok_or_else(|| validation("shadow must be initialized first"))?;
    match operation {
        "start" => current.engine.start(StartRequest {
            owner_id: text(&payload, "owner_id")?,
            problem_tex: text(&payload, "problem_tex")?,
            problem_id: optional_text(&payload, "problem_id"),
            references: payload
                .get("references")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
            native_mode: text(&payload, "native_mode")?,
            workspace_export_path: optional_text(&payload, "workspace_export_path"),
            project_id: optional_text(&payload, "project_id"),
            target_claim_id: optional_text(&payload, "target_claim_id"),
            workflow_mode: text(&payload, "workflow_mode")?,
            register_result: boolean(&payload, "register_result", true),
            workflow_protocol_version: integer(&payload, "workflow_protocol_version", 2),
            trace_id: optional_text(&payload, "trace_id"),
        }),
        "next" => current.engine.next_task(
            text(&payload, "owner_id")?,
            text(&payload, "run_id")?,
            optional_text(&payload, "trace_id"),
        ),
        "write" => current.engine.write(
            text(&payload, "owner_id")?,
            text(&payload, "capability")?,
            text(&payload, "resource")?,
            payload.get("content").unwrap_or(&Value::Null),
            optional_text(&payload, "trace_id"),
        ),
        "read" => current.engine.read(
            text(&payload, "owner_id")?,
            text(&payload, "capability")?,
            text(&payload, "resource")?,
            optional_text(&payload, "trace_id"),
        ),
        "search" => current.engine.search(
            text(&payload, "owner_id")?,
            text(&payload, "capability")?,
            text(&payload, "resource")?,
            text(&payload, "query")?,
            usize::try_from(integer(&payload, "limit", 20))
                .map_err(|_| validation("limit is out of range"))?,
            optional_text(&payload, "trace_id"),
        ),
        "commit" => current.engine.commit(
            text(&payload, "owner_id")?,
            text(&payload, "capability")?,
            text(&payload, "action")?,
            payload.get("payload").unwrap_or(&Value::Null),
            optional_text(&payload, "trace_id"),
        ),
        "status" => current
            .engine
            .status(text(&payload, "owner_id")?, text(&payload, "run_id")?),
        "steer" => current.engine.steer(
            text(&payload, "owner_id")?,
            text(&payload, "run_id")?,
            text(&payload, "message")?,
            optional_text(&payload, "trace_id"),
        ),
        "cancel" => current.engine.cancel(
            text(&payload, "owner_id")?,
            text(&payload, "run_id")?,
            text(&payload, "reason")?,
            optional_text(&payload, "trace_id"),
        ),
        "resume" => current
            .engine
            .resume(text(&payload, "owner_id")?, text(&payload, "run_id")?),
        "artifact" => current.engine.get_artifact(
            text(&payload, "owner_id")?,
            text(&payload, "run_id")?,
            text(&payload, "artifact")?,
        ),
        "database_snapshot" => current.store.database_snapshot(),
        "vault_snapshot" => vault_snapshot(&current.vault_root),
        _ => Err(validation("unsupported shadow operation")),
    }
}

fn initialize(payload: &Map<String, Value>) -> Result<Context, ReCtmError> {
    let database = PathBuf::from(text(payload, "database")?);
    let private_root = PathBuf::from(text(payload, "private_root")?);
    let hex_ids = string_array(payload, "hex_ids")?;
    let urlsafe_ids = string_array(payload, "urlsafe_ids")?;
    let clock: Arc<dyn Clock> = Arc::new(FixedClock {
        now_iso: text(payload, "now_iso")?.to_owned(),
        unix_seconds: integer(payload, "unix_seconds", 0),
    });
    let ids: Arc<dyn IdSource> = Arc::new(SequenceIds::new(hex_ids, urlsafe_ids));
    let store = Arc::new(StateStore::open_with_runtime(
        database,
        StoreRuntime {
            clock: Arc::clone(&clock),
            ids: Arc::clone(&ids),
        },
    )?);
    let secret = decode_hex(text(payload, "capability_secret_hex")?)?;
    let capabilities = Arc::new(CapabilityAuthority::new(
        &secret,
        Arc::clone(&store),
        600,
        None,
    )?);
    let methodology = Arc::new(TaskCatalog::from_source_snapshot(
        payload
            .get("methodology")
            .cloned()
            .ok_or_else(|| validation("methodology is required"))?,
    )?);
    let latex_results = payload
        .get("latex_results")
        .and_then(Value::as_array)
        .ok_or_else(|| validation("latex_results must be an array"))?
        .iter()
        .cloned()
        .map(|value| serde_json::from_value(value).map_err(json_error))
        .collect::<Result<VecDeque<_>, ReCtmError>>()?;
    let vault = Arc::new(PrivateVault::new(&private_root)?);
    let engine = WorkflowEngine::new(
        Arc::clone(&store),
        vault,
        capabilities,
        methodology,
        Arc::new(SequenceLatexGate {
            results: Mutex::new(latex_results),
        }),
        None,
    );
    Ok(Context {
        engine,
        store,
        vault_root: private_root,
    })
}

fn vault_snapshot(root: &Path) -> Result<Value, ReCtmError> {
    let mut files = Vec::new();
    walk(root, root, &mut files)?;
    files.sort_by(|left, right| {
        left.get("path")
            .and_then(Value::as_str)
            .cmp(&right.get("path").and_then(Value::as_str))
    });
    Ok(Value::Array(files))
}

fn walk(root: &Path, path: &Path, output: &mut Vec<Value>) -> Result<(), ReCtmError> {
    if !path.exists() {
        return Ok(());
    }
    let entries = fs::read_dir(path).map_err(io_error)?;
    for entry in entries {
        let entry = entry.map_err(io_error)?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| internal("vault snapshot path escaped root"))?
            .to_string_lossy()
            .replace('\\', "/");
        let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
        if metadata.is_dir() {
            walk(root, &path, output)?;
        } else if metadata.is_file() {
            let bytes = fs::read(&path).map_err(io_error)?;
            let mut digest = Sha256::new();
            digest.update(&bytes);
            output.push(serde_json::json!({
                "path":relative,
                "sha256":format!("{:x}",digest.finalize()),
                "bytes":bytes.len()
            }));
        }
    }
    Ok(())
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

fn integer(payload: &Map<String, Value>, key: &str, default: i64) -> i64 {
    payload.get(key).and_then(Value::as_i64).unwrap_or(default)
}

fn boolean(payload: &Map<String, Value>, key: &str, default: bool) -> bool {
    payload.get(key).and_then(Value::as_bool).unwrap_or(default)
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

fn decode_hex(value: &str) -> Result<Vec<u8>, ReCtmError> {
    if value.len() % 2 != 0 {
        return Err(validation("capability_secret_hex is invalid"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)
                .map_err(|_| validation("capability_secret_hex is invalid"))?;
            u8::from_str_radix(text, 16).map_err(|_| validation("capability_secret_hex is invalid"))
        })
        .collect()
}

fn validation(message: &str) -> ReCtmError {
    ReCtmError::new("INVALID_ARGUMENT", message).with_category(ErrorCategory::Validation)
}

fn internal(message: &str) -> ReCtmError {
    ReCtmError::new("INTERNAL_ERROR", message).with_category(ErrorCategory::Internal)
}

fn io_error(error: std::io::Error) -> ReCtmError {
    ReCtmError::new("IO_ERROR", error.to_string()).with_category(ErrorCategory::Runtime)
}

fn json_error(error: serde_json::Error) -> ReCtmError {
    ReCtmError::new("JSON_ERROR", error.to_string()).with_category(ErrorCategory::Internal)
}
