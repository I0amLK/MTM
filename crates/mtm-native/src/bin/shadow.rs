#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use mtm_contracts::{ErrorCategory, NativeMode, ReCtmError};
use mtm_native::{
    BubblewrapCommandSpec, CommandManager, CommandManagerConfig, QuickTunnel, TunnelEvent,
    build_bubblewrap_command, build_toolchain_exposure_plan,
};
use serde_json::Value;

fn main() {
    let mut runtime = ShadowRuntime::new();
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let response = match line {
            Ok(line) if !line.trim().is_empty() => runtime.evaluate(&line),
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
    let _ = runtime.close();
}

struct ShadowRuntime {
    manager: CommandManager,
    tunnel: Option<QuickTunnel>,
    tunnel_events: Arc<Mutex<Vec<TunnelEvent>>>,
}

impl ShadowRuntime {
    fn new() -> Self {
        Self {
            manager: CommandManager::new(CommandManagerConfig::default()),
            tunnel: None,
            tunnel_events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn evaluate(&mut self, line: &str) -> Result<Value, ReCtmError> {
        let request: Value = serde_json::from_str(line).map_err(|error| {
            ReCtmError::new("INVALID_JSON", error.to_string())
                .with_category(ErrorCategory::Validation)
        })?;
        let operation = request
            .get("operation")
            .and_then(Value::as_str)
            .ok_or_else(|| validation("operation is required"))?;
        let payload = request
            .get("payload")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        match operation {
            "process_start" => self.manager.start(from_value(payload)?),
            "process_poll" => self.manager.poll(from_value(payload)?),
            "process_kill" => self.manager.kill(from_value(payload)?),
            "process_read" => {
                let output_ref = text_field(&payload, "output_ref")?;
                let stream = payload.get("stream").and_then(Value::as_str);
                let offset = usize_field(&payload, "offset", 0)?;
                let limit = usize_field(&payload, "limit", 4096)?;
                self.manager.read_output(output_ref, stream, offset, limit)
            }
            "process_close" => {
                self.manager.close()?;
                Ok(serde_json::json!({"closed": true}))
            }
            "toolchain_plan" => toolchain_plan(&payload),
            "bubblewrap_command" => bubblewrap_command(&payload),
            "tunnel_start" => self.tunnel_start(&payload),
            "tunnel_events" => self.tunnel_events(),
            "tunnel_close" => self.tunnel_close(),
            _ => Err(validation("unsupported shadow operation")),
        }
    }

    fn tunnel_start(&mut self, payload: &Value) -> Result<Value, ReCtmError> {
        if let Some(mut tunnel) = self.tunnel.take() {
            tunnel.close()?;
        }
        self.tunnel_events.lock().map_err(|_| lock_error())?.clear();
        let events = Arc::clone(&self.tunnel_events);
        let sink = Arc::new(move |event: TunnelEvent| {
            if let Ok(mut target) = events.lock() {
                target.push(event);
            }
        });
        let executable = payload
            .get("executable")
            .and_then(Value::as_str)
            .map(PathBuf::from);
        let local_origin = text_field(payload, "local_origin")?;
        let wait_ms = usize_field(payload, "wait_ms", 0)?.min(30_000);
        let mut tunnel = QuickTunnel::new(executable, sink);
        let started = tunnel.start(local_origin)?;
        self.tunnel = Some(tunnel);
        if wait_ms > 0 {
            thread::sleep(Duration::from_millis(wait_ms as u64));
        }
        Ok(serde_json::json!({
            "started": started,
            "events": self.event_snapshot()?,
        }))
    }

    fn tunnel_events(&self) -> Result<Value, ReCtmError> {
        Ok(serde_json::json!({"events": self.event_snapshot()?}))
    }

    fn tunnel_close(&mut self) -> Result<Value, ReCtmError> {
        if let Some(mut tunnel) = self.tunnel.take() {
            tunnel.close()?;
        }
        Ok(serde_json::json!({
            "closed": true,
            "events": self.event_snapshot()?,
        }))
    }

    fn event_snapshot(&self) -> Result<Vec<TunnelEvent>, ReCtmError> {
        self.tunnel_events
            .lock()
            .map(|events| events.clone())
            .map_err(|_| lock_error())
    }

    fn close(&mut self) -> Result<(), ReCtmError> {
        if let Some(mut tunnel) = self.tunnel.take() {
            tunnel.close()?;
        }
        self.manager.close()
    }
}

fn toolchain_plan(payload: &Value) -> Result<Value, ReCtmError> {
    let mode: NativeMode = serde_json::from_value(
        payload
            .get("mode")
            .cloned()
            .ok_or_else(|| validation("mode is required"))?,
    )
    .map_err(|error| validation(&error.to_string()))?;
    let workspace = PathBuf::from(text_field(payload, "workspace")?);
    let forbidden_paths = path_array(payload, "forbidden_paths")?;
    let explicit_roots = path_array(payload, "explicit_roots")?;
    let host_path = payload.get("host_path").and_then(Value::as_str);
    let plan = build_toolchain_exposure_plan(
        mode,
        &workspace,
        &forbidden_paths,
        &explicit_roots,
        host_path,
    )?;
    serde_json::to_value(plan).map_err(|error| {
        ReCtmError::new("INTERNAL_SERIALIZATION_ERROR", error.to_string())
            .with_category(ErrorCategory::Internal)
    })
}

fn bubblewrap_command(payload: &Value) -> Result<Value, ReCtmError> {
    let mode: NativeMode = serde_json::from_value(
        payload
            .get("mode")
            .cloned()
            .ok_or_else(|| validation("mode is required"))?,
    )
    .map_err(|error| validation(&error.to_string()))?;
    let workspace = PathBuf::from(text_field(payload, "workspace")?);
    let workdir = payload
        .get("workdir")
        .and_then(Value::as_str)
        .unwrap_or(".");
    let argv = string_array(payload, "argv")?;
    let extra_env = string_map(payload, "extra_env")?;
    let host_path = payload.get("host_path").and_then(Value::as_str);
    let extra_read_roots = path_array(payload, "extra_read_roots")?;
    let forbidden_paths = path_array(payload, "forbidden_paths")?;
    let command = build_bubblewrap_command(&BubblewrapCommandSpec {
        workspace: &workspace,
        workdir,
        mode,
        argv: &argv,
        extra_env: &extra_env,
        host_path,
        extra_read_roots: &extra_read_roots,
        forbidden_paths: &forbidden_paths,
        probe_executable: None,
    })?;
    Ok(serde_json::json!({"command": command}))
}

fn path_array(payload: &Value, key: &str) -> Result<Vec<PathBuf>, ReCtmError> {
    let values = payload
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(PathBuf::from)
                .ok_or_else(|| validation(&format!("{key} must contain strings")))
        })
        .collect()
}

fn string_array(payload: &Value, key: &str) -> Result<Vec<String>, ReCtmError> {
    let values = payload
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| validation(&format!("{key} must be an array")))?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| validation(&format!("{key} must contain strings")))
        })
        .collect()
}

fn string_map(payload: &Value, key: &str) -> Result<BTreeMap<String, String>, ReCtmError> {
    let Some(object) = payload.get(key).and_then(Value::as_object) else {
        return Ok(BTreeMap::new());
    };
    object
        .iter()
        .map(|(name, value)| {
            value
                .as_str()
                .map(|text| (name.clone(), text.to_owned()))
                .ok_or_else(|| validation(&format!("{key} values must be strings")))
        })
        .collect()
}

fn text_field<'a>(payload: &'a Value, key: &str) -> Result<&'a str, ReCtmError> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| validation(&format!("{key} is required")))
}

fn usize_field(payload: &Value, key: &str, default: usize) -> Result<usize, ReCtmError> {
    match payload.get(key) {
        None => Ok(default),
        Some(value) => value
            .as_u64()
            .and_then(|number| usize::try_from(number).ok())
            .ok_or_else(|| validation(&format!("{key} must be a non-negative integer"))),
    }
}

fn from_value<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, ReCtmError> {
    serde_json::from_value(value).map_err(|error| validation(&error.to_string()))
}

fn validation(message: &str) -> ReCtmError {
    ReCtmError::new("INVALID_ARGUMENT", message).with_category(ErrorCategory::Validation)
}

fn lock_error() -> ReCtmError {
    ReCtmError::new("INTERNAL_LOCK_POISONED", "Native shadow lock was poisoned.")
        .with_category(ErrorCategory::Internal)
}
