//! Explicit A5-style bounded comparison for reviewed MTM artifacts.
//! Inert during ordinary source/protocol tests; no selector or installation use.
use std::env;
use std::time::Instant;

use serde_json::{Value, json};

use crate::support::candidate;
use crate::support::loopback::Server;
use crate::support::{Result, require};

const ENABLE: &str = "MTM_TEST_RESOURCE_PROFILE";

fn native_arguments() -> Value {
    // The reviewed preview.2 public schema requires cmd and rejects argv.
    // Use the identical fixed shell request on BOTH artifacts, not a retry or
    // a baseline-only translation that would compare different execution paths.
    json!({"cmd":"/usr/bin/printf resource-ok","yield_time_ms":30_000})
}

fn stage<T>(role: &'static str, step: &'static str, result: Result<T>) -> Result<T> {
    result.inspect_err(|_| eprintln!("MTM_RESOURCE_DIAGNOSTIC role={role} stage={step}"))
}

fn u64_field(value: &Value, key: &str) -> Result<u64> {
    value[key].as_u64().ok_or("resource process fact missing")
}

fn p95(values: &mut [f64]) -> Result<f64> {
    require(!values.is_empty(), "resource percentile sample is empty")?;
    values.sort_by(f64::total_cmp);
    let index = ((values.len() * 95).div_ceil(100)).saturating_sub(1);
    Ok(values[index])
}

fn measure(binary: &str, role: &'static str) -> Result<Value> {
    let mut starts = Vec::new();
    let mut requests = Vec::new();
    let mut max_rss = 0_u64;
    let mut max_threads = 0_u64;
    let mut max_fds = 0_u64;
    let mut max_shutdown = 0_f64;
    for index in 0..3 {
        let started = Instant::now();
        let mut server = stage(role, "start", Server::start_resource(binary))?;
        starts.push(started.elapsed().as_secs_f64() * 1000.0);
        let owner = stage(role, "login", server.login())?;
        for request_index in 0..70 {
            let request_started = Instant::now();
            let response = if request_index % 2 == 0 {
                stage(
                    role,
                    "exec_request",
                    server.call(&owner, "exec_command", native_arguments()),
                )?
            } else {
                stage(
                    role,
                    "server_info",
                    server.call(&owner, "server_info", json!({})),
                )?
            };
            if request_index % 2 == 0 {
                stage(
                    role,
                    "exec_result",
                    require(
                        response["ok"] == true
                            && response["status"] == "exited"
                            && response["exit_code"] == 0
                            && response["stdout"].as_str() == Some("resource-ok"),
                        "resource Native request failed",
                    ),
                )?;
            } else {
                stage(
                    role,
                    "server_info_result",
                    require(response["server"] == "mtm", "resource server_info failed"),
                )?;
            }
            if request_index >= 10 {
                requests.push(request_started.elapsed().as_secs_f64() * 1000.0);
                let facts = stage(role, "process_facts", server.process_facts())?;
                max_rss = max_rss.max(u64_field(&facts, "rss_kib")?);
                max_threads = max_threads.max(u64_field(&facts, "threads")?);
                max_fds = max_fds.max(u64_field(&facts, "fds")?);
                stage(
                    role,
                    "children",
                    require(
                        u64_field(&facts, "children")? == 0,
                        "completed resource request retained a child process",
                    ),
                )?;
            }
        }
        let shutdown = Instant::now();
        stage(role, "shutdown", server.stop())?;
        max_shutdown = max_shutdown.max(shutdown.elapsed().as_secs_f64() * 1000.0);
        require(index < 3, "resource startup sample overflow")?;
    }
    let startup_p50 = {
        let mut ordered = starts.clone();
        ordered.sort_by(f64::total_cmp);
        ordered[ordered.len() / 2]
    };
    Ok(json!({
        "startup_samples":starts.len(),
        "request_samples":requests.len(),
        "startup_p50_ms":startup_p50,
        "startup_p95_ms":p95(&mut starts)?,
        "request_p95_ms":p95(&mut requests)?,
        "max_rss_kib":max_rss,
        "max_threads":max_threads,
        "max_fds":max_fds,
        "max_shutdown_ms":max_shutdown
    }))
}

fn within(candidate: &Value, baseline: &Value) -> Result<bool> {
    let number =
        |value: &Value, key: &str| value[key].as_f64().ok_or("resource metric must be numeric");
    let count = |value: &Value, key: &str| {
        value[key]
            .as_u64()
            .ok_or("resource count must be an integer")
    };
    Ok(count(candidate, "startup_samples")? == 3
        && count(baseline, "startup_samples")? == 3
        && count(candidate, "request_samples")? == 180
        && count(baseline, "request_samples")? == 180
        && number(candidate, "startup_p95_ms")?
            <= (2.0 * number(baseline, "startup_p95_ms")?)
                .max(number(baseline, "startup_p95_ms")? + 250.0)
        && number(candidate, "request_p95_ms")?
            <= (2.0 * number(baseline, "request_p95_ms")?)
                .max(number(baseline, "request_p95_ms")? + 10.0)
        && count(candidate, "max_rss_kib")?
            <= 262_144_u64.min(count(baseline, "max_rss_kib")? + 32_768)
        && count(candidate, "max_threads")? <= count(baseline, "max_threads")? + 2
        && count(candidate, "max_fds")? <= count(baseline, "max_fds")? + 8
        && number(candidate, "max_shutdown_ms")? <= 8_000.0)
}

#[test]
fn explicit_baseline_and_candidate_resource_non_regression() -> Result {
    if env::var_os(ENABLE).is_none() {
        return Ok(());
    }
    require(
        env::var(ENABLE).ok().as_deref() == Some("1"),
        "resource profile flag must be exactly one",
    )?;
    let candidate = candidate::select()?;
    let baseline = candidate::select_baseline()?;
    require(
        candidate.sha256 != baseline.sha256,
        "resource comparison requires distinct reviewed artifacts",
    )?;
    let baseline_metrics = measure(&baseline.path, "baseline")?;
    baseline.unchanged()?;
    let candidate_metrics = measure(&candidate.path, "candidate")?;
    candidate.unchanged()?;
    stage(
        "comparison",
        "bounds",
        require(
            within(&candidate_metrics, &baseline_metrics)?,
            "candidate exceeded declared resource non-regression bounds",
        ),
    )?;
    let report = json!({
        "ok":true,
        "candidate_sha256":candidate.sha256,
        "baseline_sha256":baseline.sha256,
        "baseline":baseline_metrics,
        "candidate":candidate_metrics,
        "resource_non_regression_tested":true,
        "native_execution_tested":true,
        "native_mode":"dangerous",
        "native_backend":"bubblewrap",
        "request_workload":"server_info_and_public_exec_command",
        "permission_grant_soak_tested":false,
        "web_client_tested":false,
        "install_or_selector_changed":false,
        "performance_claim":false,
        "release_qualified":false
    });
    println!("MTM_RESOURCE_RUNTIME {report}");
    Ok(())
}

#[test]
fn resource_request_uses_one_shared_shell_contract() -> Result {
    require(
        native_arguments() == json!({"cmd":"/usr/bin/printf resource-ok","yield_time_ms":30_000}),
        "resource workload must use the same fixed public cmd request for both versions",
    )
}

// Ordinary source tests use the current binary. An explicitly selected baseline
// additionally checks its real public schema. Native is deliberately disabled:
// this proves request compatibility, not execution or resource non-regression.
#[test]
fn resource_request_reaches_disabled_native_authority() -> Result {
    let mut binaries = vec![("candidate", candidate::select()?)];
    if env::var_os(candidate::BASELINE_ENV).is_some()
        || env::var_os(candidate::BASELINE_HASH_ENV).is_some()
    {
        binaries.insert(0, ("baseline", candidate::select_baseline()?));
    }
    for (role, binary) in binaries {
        let mut server = Server::start(&binary.path)?;
        let owner = server.login()?;
        let catalog = server.request(
            "POST",
            "/mcp",
            "application/json",
            br#"{"jsonrpc":"2.0","id":"resource-catalog","method":"tools/list","params":{}}"#,
            Some(&owner),
        )?;
        require(
            catalog.status == 200,
            "resource contract catalog HTTP failure",
        )?;
        let catalog = catalog.json()?;
        let schema = &catalog["result"]["tools"]
            .as_array()
            .ok_or("resource contract catalog missing")?
            .iter()
            .find(|tool| tool["name"] == "exec_command")
            .ok_or("resource contract exec definition missing")?["inputSchema"];
        let requires_cmd = schema["required"]
            .as_array()
            .is_some_and(|keys| keys.iter().any(|key| key == "cmd"));
        let advertises_argv = schema["properties"].get("argv").is_some();
        let body = serde_json::to_vec(&json!({
            "jsonrpc":"2.0","id":"resource-contract","method":"tools/call",
            "params":{"name":"exec_command","arguments":native_arguments()}
        }))
        .map_err(|_| "resource contract request serialization failed")?;
        let reply = server.request("POST", "/mcp", "application/json", &body, Some(&owner))?;
        require(reply.status == 200, "resource contract HTTP failure")?;
        let reply = reply.json()?;
        let invalid_arguments = reply["error"]["code"] == -32602
            && reply["error"]["data"]["reason"] == "invalid_arguments";
        let disabled = reply.get("error").is_none()
            && reply["result"]["isError"] == true
            && reply["result"]["structuredContent"]["ok"] == false
            && reply["result"]["structuredContent"]["error"]["code"] == "NATIVE_ISOLATION_REQUIRED";
        eprintln!(
            "MTM_RESOURCE_CONTRACT role={role} requires_cmd={requires_cmd} advertises_argv={advertises_argv} rpc_code={} invalid_arguments={invalid_arguments} disabled_authority_reached={disabled}",
            reply["error"]["code"]
                .as_i64()
                .map_or("none".to_owned(), |code| code.to_string())
        );
        for arguments in [
            json!({"yield_time_ms":30_000}),
            json!({"cmd":"","yield_time_ms":30_000}),
            json!({"cmd":"/usr/bin/printf resource-ok","argv":["/usr/bin/printf","resource-ok"]}),
            json!({"cmd":"/usr/bin/printf resource-ok","unknown":true}),
        ] {
            let body = serde_json::to_vec(&json!({
                "jsonrpc":"2.0","id":"resource-invalid","method":"tools/call",
                "params":{"name":"exec_command","arguments":arguments}
            }))
            .map_err(|_| "resource negative request serialization failed")?;
            let reply = server.request("POST", "/mcp", "application/json", &body, Some(&owner))?;
            require(
                reply.status == 200,
                "resource negative contract HTTP failure",
            )?;
            let reply = reply.json()?;
            require(
                reply["error"]["code"] == -32602
                    && reply["error"]["data"]["reason"] == "invalid_arguments"
                    && reply.get("result").is_none(),
                "resource invalid request was not rejected by the public schema",
            )?;
        }
        eprintln!("MTM_RESOURCE_CONTRACT role={role} negative_schema_rejections=4");
        server.stop()?;
        binary.unchanged()?;
        require(
            disabled,
            "resource request did not reach disabled Native authority",
        )?;
    }
    Ok(())
}
