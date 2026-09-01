use std::collections::BTreeMap;
use std::io::{self, Read};
use std::process::{Command, Stdio};

use mtm_contracts::{ErrorCategory, ReCtmError};
use mtm_native::{
    MAX_REQUEST_BYTES, NATIVE_HELPER_PROTOCOL, NativeHelperRequest, NativeHelperResponse,
    invoke_helper_request,
};

pub fn invoke_runtime_helper(
    request: &NativeHelperRequest,
) -> Result<NativeHelperResponse, ReCtmError> {
    let executable = std::env::current_exe().map_err(io_error)?;
    let request_bytes = serde_json::to_vec(request).map_err(json_error)?;
    if request_bytes.len() > MAX_REQUEST_BYTES {
        return Err(ReCtmError::new(
            "NATIVE_HELPER_REQUEST_TOO_LARGE",
            "helper request exceeded the maximum size",
        )
        .with_category(ErrorCategory::Validation));
    }
    let mut child = Command::new(executable)
        .arg("__native-helper")
        .env_clear()
        .env("PATH", mtm_native::DEFAULT_SANDBOX_PATH)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(io_error)?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin.write_all(&request_bytes).map_err(io_error)?;
    }
    let output = child.wait_with_output().map_err(io_error)?;
    if output.stdout.len() > MAX_REQUEST_BYTES {
        return Err(ReCtmError::new(
            "NATIVE_HELPER_PROTOCOL_ERROR",
            "helper response exceeded the maximum size",
        )
        .with_category(ErrorCategory::Runtime));
    }
    serde_json::from_slice(&output.stdout).map_err(|_| {
        ReCtmError::new(
            "NATIVE_HELPER_PROTOCOL_ERROR",
            "helper process returned invalid JSON",
        )
        .with_category(ErrorCategory::Runtime)
        .with_details(serde_json::json!({"exit_code": output.status.code()}))
    })
}

pub fn native_helper_main() -> i32 {
    let raw = match read_request() {
        Ok(raw) => raw,
        Err(error) => {
            write_error(None, None, error);
            return 1;
        }
    };
    let request: NativeHelperRequest = match serde_json::from_slice(&raw) {
        Ok(request) => request,
        Err(_) => {
            write_error(
                None,
                None,
                ReCtmError::new(
                    "NATIVE_HELPER_PROTOCOL_ERROR",
                    "helper request must be one UTF-8 JSON object",
                )
                .with_category(ErrorCategory::Validation),
            );
            return 1;
        }
    };
    match invoke_helper_request(&request) {
        Ok(response) => match serde_json::to_string(&response) {
            Ok(output) => {
                println!("{output}");
                0
            }
            Err(error) => {
                eprintln!("{error}");
                1
            }
        },
        Err(error) => {
            write_error(Some(&request.operation), Some(&request.request_id), error);
            1
        }
    }
}

pub fn native_sandbox_probe_main(forbidden: &str, probe_name: &str, roots: &str) -> i32 {
    match mtm_native::bubblewrap::run_sandbox_probe(forbidden, probe_name, roots) {
        Ok(probe) => match serde_json::to_string(&probe) {
            Ok(output) => {
                println!("{output}");
                0
            }
            Err(error) => {
                eprintln!("{error}");
                1
            }
        },
        Err(error) => {
            eprintln!("{}: {}", error.code, error.message);
            1
        }
    }
}

fn read_request() -> Result<Vec<u8>, ReCtmError> {
    let mut bytes = Vec::new();
    io::stdin()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(ReCtmError::new(
            "NATIVE_HELPER_REQUEST_TOO_LARGE",
            "helper request exceeded the maximum size",
        )
        .with_category(ErrorCategory::Validation));
    }
    Ok(bytes)
}

fn write_error(operation: Option<&str>, request_id: Option<&str>, error: ReCtmError) {
    let mut fields = BTreeMap::new();
    fields.insert("error".to_owned(), Value::from_error(&error));
    let response = NativeHelperResponse {
        protocol: NATIVE_HELPER_PROTOCOL.to_owned(),
        operation: operation.unwrap_or_default().to_owned(),
        request_id: request_id.unwrap_or_default().to_owned(),
        ok: false,
        fields,
    };
    if let Ok(output) = serde_json::to_string(&response) {
        println!("{output}");
    }
}

struct Value;

impl Value {
    fn from_error(error: &ReCtmError) -> serde_json::Value {
        serde_json::json!({
            "code":error.code,
            "message":error.message,
            "category":error.category.as_str(),
            "retryable":error.retryable,
            "details":error.details,
        })
    }
}

fn io_error(error: std::io::Error) -> ReCtmError {
    ReCtmError::new("NATIVE_HELPER_PROCESS_ERROR", error.to_string())
        .with_category(ErrorCategory::Runtime)
}

fn json_error(error: serde_json::Error) -> ReCtmError {
    ReCtmError::new("NATIVE_HELPER_PROTOCOL_ERROR", error.to_string())
        .with_category(ErrorCategory::Internal)
}
