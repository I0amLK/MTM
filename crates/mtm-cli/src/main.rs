#![forbid(unsafe_code)]

use std::env;
use std::io::{self, Read};

use mtm_contracts::{ContractSnapshot, ErrorCategory, ReCtmError};
use mtm_core::evaluate_request;
use serde_json::Value;

const MAX_EVALUATION_INPUT_BYTES: u64 = 1_048_576;

fn main() {
    let command = env::args().nth(1);
    match command.as_deref() {
        Some("--version" | "-V") => {
            println!("mtm-reboot {}", env!("CARGO_PKG_VERSION"));
        }
        Some("contract") => {
            println!("{}", ContractSnapshot::source_baseline().to_json());
        }
        Some("status") => {
            const STATUS_JSON: &str = concat!(
                "{\"project\":\"MTM-reboot\",",
                "\"milestone\":\"MTM-006\",",
                "\"production_authority\":\"python\",",
                "\"rust_production_components\":0,",
                "\"rust_authoritative_pure_components\":1,",
                "\"rust_authoritative_native_components\":1,",
                "\"rust_authoritative_storage_components\":1,",
                "\"rust_authoritative_gateway_components\":1,",
                "\"completed_milestones\":5}"
            );
            println!("{STATUS_JSON}");
        }
        Some("evaluate") => evaluate_from_stdin(false),
        Some("evaluate-batch") => evaluate_from_stdin(true),
        Some("help" | "--help" | "-h") | None => print_help(),
        Some(other) => {
            eprintln!("unknown command: {other}");
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_help() {
    const HELP: &str = concat!(
        "MTM-reboot bootstrap\n\n",
        "Usage:\n",
        "  mtm-reboot --version\n",
        "  mtm-reboot contract\n",
        "  mtm-reboot status\n",
        "  printf '%s' '<json>' | mtm-reboot evaluate\n",
        "  printf '%s' '<json-array>' | mtm-reboot evaluate-batch\n"
    );
    println!("{HELP}");
}

fn evaluate_from_stdin(batch: bool) {
    let result = read_evaluation_request().and_then(|request| {
        let response = if batch {
            let requests = request.as_array().ok_or_else(|| {
                ReCtmError::new("INVALID_ARGUMENT", "Batch input must be an array.")
                    .with_category(ErrorCategory::Validation)
            })?;
            if requests.len() > 1_000 {
                return Err(ReCtmError::new(
                    "INPUT_TOO_LARGE",
                    "Batch input contains more than 1000 requests.",
                )
                .with_category(ErrorCategory::Validation));
            }
            Value::Array(requests.iter().map(evaluation_response).collect())
        } else {
            evaluation_response(&request)
        };
        serde_json::to_string(&response).map_err(|error| {
            ReCtmError::new(
                "INTERNAL_SERIALIZATION_ERROR",
                format!("Failed to serialize evaluation response: {error}"),
            )
            .with_category(ErrorCategory::Internal)
        })
    });
    match result {
        Ok(output) => println!("{output}"),
        Err(error) => {
            let fallback = serde_json::json!({"ok": false, "error": error.to_payload()});
            match serde_json::to_string(&fallback) {
                Ok(output) => println!("{output}"),
                Err(_) => eprintln!("evaluation failed"),
            }
            std::process::exit(2);
        }
    }
}

fn evaluation_response(request: &Value) -> Value {
    match evaluate_request(request) {
        Ok(value) => serde_json::json!({"ok": true, "result": value}),
        Err(error) => serde_json::json!({"ok": false, "error": error.to_payload()}),
    }
}

fn read_evaluation_request() -> Result<Value, ReCtmError> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_EVALUATION_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ReCtmError::new("INPUT_READ_ERROR", error.to_string()))?;
    if bytes.len() as u64 > MAX_EVALUATION_INPUT_BYTES {
        return Err(
            ReCtmError::new("INPUT_TOO_LARGE", "Evaluation input exceeds 1 MiB.")
                .with_category(ErrorCategory::Validation),
        );
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        ReCtmError::new("INVALID_JSON", format!("Invalid JSON input: {error}"))
            .with_category(ErrorCategory::Validation)
    })
}
