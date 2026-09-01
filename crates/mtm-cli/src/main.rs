#![forbid(unsafe_code)]

use std::env;
use std::io::{self, Read};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;

use mtm_contracts::{ContractSnapshot, ErrorCategory, LatexPolicy, NativeMode, ReCtmError};
use mtm_runtime::{
    OperatorSession, QuickTunnel, RuntimeApplication, RuntimeAssets, RuntimeSettings,
    attest_native, evaluate_request, generate_operator_password, materialize_secrets, serve_bound,
};
use serde_json::Value;

const MAX_EVALUATION_INPUT_BYTES: u64 = 1_048_576;

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let command = args.first().map(String::as_str);
    if command == Some("__native-helper") {
        std::process::exit(mtm_runtime::native_helper_main());
    }
    if let [flag, forbidden, probe_name, roots] = args.as_slice()
        && flag == "--sandbox-probe"
    {
        std::process::exit(mtm_runtime::native_sandbox_probe_main(
            forbidden, probe_name, roots,
        ));
    }
    match command {
        Some("--version" | "-V") => {
            println!("re-ctm {}", env!("CARGO_PKG_VERSION"));
        }
        Some("contract") => {
            println!("{}", ContractSnapshot::source_baseline().to_json());
        }
        Some("release-info") => {
            println!(
                "{}",
                serde_json::json!({
                    "name": "re-ctm",
                    "version": env!("CARGO_PKG_VERSION"),
                    "implementation": "rust",
                    "python_runtime_required": false,
                    "public_tool_count": 24,
                    "hidden_alias_count": 11,
                    "state_schema_version": 2,
                    "workflow_protocol_version": 2,
                    "target_os": env::consts::OS,
                    "target_arch": env::consts::ARCH,
                })
            );
        }
        Some("status") => {
            const STATUS_JSON: &str = concat!(
                "{\"project\":\"MTM-reboot\",",
                "\"milestone\":\"MTM-008\",",
                "\"production_authority\":\"python\",",
                "\"rust_production_components\":0,",
                "\"rust_authoritative_pure_components\":1,",
                "\"rust_authoritative_native_components\":1,",
                "\"rust_authoritative_storage_components\":1,",
                "\"rust_authoritative_gateway_components\":1,",
                "\"rust_authoritative_workflow_components\":1,",
                "\"rust_authoritative_runtime_components\":1,",
                "\"completed_milestones\":7}"
            );
            println!("{STATUS_JSON}");
        }
        Some("evaluate") => evaluate_from_stdin(false),
        Some("evaluate-batch") => evaluate_from_stdin(true),
        Some("check-config") => exit_on_error(check_config(&args[1..])),
        Some("attest-native") => exit_on_error(attest_native_command(&args[1..])),
        Some("serve") => exit_on_error(serve(&args[1..], false)),
        Some("tui") => exit_on_error(serve(&args[1..], true)),
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
        "Re-CTM Rust runtime\n\n",
        "Usage:\n",
        "  re-ctm --version\n",
        "  re-ctm release-info\n",
        "  re-ctm contract\n",
        "  re-ctm status\n",
        "  re-ctm check-config [--workspace PATH] [--native-mode MODE]\n",
        "  re-ctm attest-native [--workspace PATH] [--native-mode MODE]\n",
        "  re-ctm serve [--host HOST] [--port PORT] [--workspace PATH] [--native-mode MODE]\n",
        "  re-ctm tui [--quick-tunnel] [--host HOST] [--port PORT] [--workspace PATH] [--native-mode MODE]\n",
        "  printf '%s' '<json>' | re-ctm evaluate\n",
        "  printf '%s' '<json-array>' | re-ctm evaluate-batch\n"
    );
    println!("{HELP}");
}

fn embedded_assets() -> Result<RuntimeAssets, ReCtmError> {
    RuntimeAssets::from_base64_catalog(
        include_str!("../assets/tool-catalog-v1.b64"),
        include_str!("../assets/methodology-v2.json"),
    )
}

fn settings_with_overrides(
    arguments: &[String],
) -> Result<(RuntimeSettings, String, u16), ReCtmError> {
    let mut settings = RuntimeSettings::from_env()?;
    let mut host = "127.0.0.1".to_owned();
    let mut port = 8765_u16;
    let mut index = 0;
    while index < arguments.len() {
        let key = arguments[index].as_str();
        let value = arguments.get(index + 1).ok_or_else(|| {
            ReCtmError::new("INVALID_ARGUMENT", format!("{key} requires a value"))
                .with_category(ErrorCategory::Validation)
        })?;
        match key {
            "--host" => host = value.clone(),
            "--port" => {
                port = value.parse::<u16>().map_err(|_| {
                    ReCtmError::new("INVALID_ARGUMENT", "--port must be an integer")
                        .with_category(ErrorCategory::Validation)
                })?;
            }
            "--workspace" => {
                settings.workspace = PathBuf::from(value).canonicalize().map_err(|error| {
                    ReCtmError::new("INVALID_WORKSPACE", error.to_string())
                        .with_category(ErrorCategory::Validation)
                })?;
            }
            "--native-mode" => {
                settings.native_mode = match value.as_str() {
                    "safe" => NativeMode::Safe,
                    "trusted" => NativeMode::Trusted,
                    "dangerous" => NativeMode::Dangerous,
                    _ => {
                        return Err(ReCtmError::new(
                            "INVALID_ARGUMENT",
                            "--native-mode must be safe, trusted, or dangerous",
                        )
                        .with_category(ErrorCategory::Validation));
                    }
                };
            }
            "--latex-policy" => {
                settings.latex_policy = match value.as_str() {
                    "static_only" => LatexPolicy::StaticOnly,
                    "if_available" => LatexPolicy::IfAvailable,
                    "required" => LatexPolicy::Required,
                    _ => {
                        return Err(ReCtmError::new(
                            "INVALID_ARGUMENT",
                            "--latex-policy must be static_only, if_available, or required",
                        )
                        .with_category(ErrorCategory::Validation));
                    }
                };
            }
            _ => {
                return Err(
                    ReCtmError::new("INVALID_ARGUMENT", format!("unknown option: {key}"))
                        .with_category(ErrorCategory::Validation),
                );
            }
        }
        index += 2;
    }
    settings.validate()?;
    Ok((settings, host, port))
}

fn check_config(arguments: &[String]) -> Result<(), ReCtmError> {
    let (settings, host, port) = settings_with_overrides(arguments)?;
    let assets = embedded_assets()?;
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "workspace": settings.workspace,
            "data_root": settings.data_root,
            "private_root": settings.private_root,
            "native_mode": settings.native_mode.as_str(),
            "native_exec_backend": settings.native_exec_backend,
            "latex_policy": settings.latex_policy.as_str(),
            "oauth_server_url": settings.oauth_server_url,
            "bind_host": host,
            "bind_port": port,
            "tool_count": assets.tool_catalog()["public_names"].as_array().map_or(0, Vec::len),
            "workflow_protocol_version": 2,
            "secrets_materialized": settings.token_secret.len() >= 32 && settings.capability_secret.len() >= 32,
        })
    );
    Ok(())
}

fn attest_native_command(arguments: &[String]) -> Result<(), ReCtmError> {
    let (settings, _, _) = settings_with_overrides(arguments)?;
    println!("{}", attest_native(&settings)?);
    Ok(())
}

fn exit_on_error(result: Result<(), ReCtmError>) {
    if let Err(error) = result {
        eprintln!(
            "{}",
            serde_json::json!({"ok": false, "error": error.to_payload()})
        );
        std::process::exit(2);
    }
}

fn serve(arguments: &[String], tui: bool) -> Result<(), ReCtmError> {
    let quick_tunnel_requested = tui && arguments.iter().any(|item| item == "--quick-tunnel");
    if !tui && arguments.iter().any(|item| item == "--quick-tunnel") {
        return Err(ReCtmError::new(
            "INVALID_ARGUMENT",
            "--quick-tunnel is available only with the tui command",
        )
        .with_category(ErrorCategory::Validation));
    }
    let port_explicit = arguments.iter().any(|item| item == "--port");
    let filtered_arguments = arguments
        .iter()
        .filter(|item| item.as_str() != "--quick-tunnel")
        .cloned()
        .collect::<Vec<_>>();
    let (mut settings, host, mut port) = settings_with_overrides(&filtered_arguments)?;
    if quick_tunnel_requested {
        settings.oauth_server_url.clear();
        if !port_explicit {
            port = 0;
        }
    }
    let mut settings = materialize_secrets(settings)?;
    let generated_password = settings.oauth_password.is_empty();
    if generated_password {
        settings.oauth_password = generate_operator_password()?;
    }

    // Bind before revealing a generated operator key. A bind failure therefore
    // cannot reveal a key for a server that never became locally reachable.
    let listener = TcpListener::bind((host.as_str(), port)).map_err(|error| {
        ReCtmError::new("SERVER_BIND_FAILED", error.to_string())
            .with_category(ErrorCategory::Runtime)
    })?;
    let bound = listener.local_addr().map_err(|error| {
        ReCtmError::new("SERVER_BIND_FAILED", error.to_string())
            .with_category(ErrorCategory::Runtime)
    })?;

    let assets = embedded_assets()?;
    let operator = tui.then(OperatorSession::default);
    let observer = operator.as_ref().map(OperatorSession::event_sink);
    let application = Arc::new(RuntimeApplication::build_with_observer(
        settings.clone(),
        &assets,
        &host,
        bound.port(),
        false,
        observer,
    )?);
    eprintln!("Re-CTM {} (Rust)", env!("CARGO_PKG_VERSION"));
    eprintln!("local MCP: http://{host}:{}/mcp", bound.port());
    eprintln!("mode: {}", settings.native_mode.as_str());
    if generated_password {
        eprintln!("OAuth operator key: {}", settings.oauth_password);
    } else {
        eprintln!("OAuth operator key: configured externally");
    }
    if tui {
        eprintln!("TUI: minimal operator session monitor active");
    }
    let mut quick_tunnel = if quick_tunnel_requested {
        let sink = operator
            .as_ref()
            .map(OperatorSession::tunnel_sink)
            .ok_or_else(|| {
                ReCtmError::new("INTERNAL_ERROR", "TUI operator session is unavailable")
                    .with_category(ErrorCategory::Internal)
            })?;
        let mut tunnel = QuickTunnel::new(None, sink);
        let address = if host.contains(':') {
            format!("http://[{host}]:{}", bound.port())
        } else {
            format!("http://{host}:{}", bound.port())
        };
        match tunnel.start(&address) {
            Ok(_) => Some(tunnel),
            Err(error) => {
                eprintln!("Quick Tunnel unavailable: {}", error.code);
                let _ = tunnel.close();
                None
            }
        }
    } else {
        None
    };

    let result = serve_bound(listener, application);
    if let Some(tunnel) = quick_tunnel.as_mut() {
        let _ = tunnel.close();
    }
    result
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
