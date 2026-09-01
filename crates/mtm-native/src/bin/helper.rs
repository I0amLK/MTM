#![forbid(unsafe_code)]

use std::env;
use std::io::{self, Read};

use mtm_contracts::{ErrorCategory, ReCtmError};
use mtm_native::{
    MAX_REQUEST_BYTES, NATIVE_HELPER_PROTOCOL, NativeHelperRequest, NativeHelperResponse,
    invoke_helper_request,
};

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let code = match args.as_slice() {
        [flag] if flag == "--version" => {
            println!(
                "{}",
                serde_json::json!({
                    "protocol": NATIVE_HELPER_PROTOCOL,
                    "backend": "bubblewrap",
                    "version": "1",
                })
            );
            0
        }
        [flag, forbidden, probe_name, roots] if flag == "--sandbox-probe" => {
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
        [] => run_protocol(),
        _ => {
            eprintln!("usage: mtm-native-helper [--version]");
            2
        }
    };
    std::process::exit(code);
}

fn run_protocol() -> i32 {
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
        Ok(response) => write_response(&response),
        Err(error) => {
            write_error(Some(&request.operation), Some(&request.request_id), error);
            return 1;
        }
    }
    0
}

fn read_request() -> Result<Vec<u8>, ReCtmError> {
    let mut bytes = Vec::new();
    io::stdin()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| ReCtmError::new("NATIVE_HELPER_PROTOCOL_ERROR", error.to_string()))?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(ReCtmError::new(
            "NATIVE_HELPER_REQUEST_TOO_LARGE",
            "helper request exceeded the maximum size",
        )
        .with_category(ErrorCategory::Validation));
    }
    Ok(bytes)
}

fn write_response(response: &NativeHelperResponse) {
    match serde_json::to_string(response) {
        Ok(output) => println!("{output}"),
        Err(error) => eprintln!("{error}"),
    }
}

fn write_error(operation: Option<&str>, request_id: Option<&str>, error: ReCtmError) {
    let mut fields = BTreeMap::new();
    fields.insert(
        "error".to_owned(),
        serde_json::json!({
            "code": error.code,
            "message": error.message,
            "category": error.category.as_str(),
            "details": error.details,
        }),
    );
    let response = NativeHelperResponse {
        protocol: NATIVE_HELPER_PROTOCOL.to_owned(),
        operation: operation.unwrap_or_default().to_owned(),
        request_id: request_id.unwrap_or_default().to_owned(),
        ok: false,
        fields,
    };
    write_response(&response);
}

use std::collections::BTreeMap;
