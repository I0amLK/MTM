//! Explicit A5-style bounded comparison for reviewed MTM artifacts.
//! Inert during ordinary source/protocol tests; no selector or installation use.
use std::env;
use std::time::Instant;

use serde_json::{Value, json};

use crate::support::candidate;
use crate::support::loopback::Server;
use crate::support::{Result, require, text};

const ENABLE: &str = "MTM_TEST_RESOURCE_PROFILE";

fn u64_field(value: &Value, key: &str) -> Result<u64> {
    value[key].as_u64().ok_or("resource process fact missing")
}

fn p95(values: &mut [f64]) -> Result<f64> {
    require(!values.is_empty(), "resource percentile sample is empty")?;
    values.sort_by(f64::total_cmp);
    let index = ((values.len() * 95).div_ceil(100)).saturating_sub(1);
    Ok(values[index])
}

fn measure(binary: &str) -> Result<Value> {
    let mut starts = Vec::new();
    let mut requests = Vec::new();
    let mut max_rss = 0_u64;
    let mut max_threads = 0_u64;
    let mut max_fds = 0_u64;
    let mut max_shutdown = 0_f64;
    for index in 0..3 {
        let started = Instant::now();
        let mut server = Server::start_resource(binary)?;
        starts.push(started.elapsed().as_secs_f64() * 1000.0);
        let owner = server.login()?;
        for request_index in 0..70 {
            let request_started = Instant::now();
            let response = if request_index % 2 == 0 {
                server.call(
                    &owner,
                    "exec_command",
                    json!({"argv":["/usr/bin/printf","resource-ok"],"yield_time_ms":30_000}),
                )?
            } else {
                server.call(&owner, "server_info", json!({}))?
            };
            if request_index % 2 == 0 {
                require(
                    response["ok"] == true
                        && response["exit_code"] == 0
                        && text(&response, "stdout")? == "resource-ok",
                    "resource Native request failed",
                )?;
            } else {
                require(response["server"] == "mtm", "resource server_info failed")?;
            }
            if request_index >= 10 {
                requests.push(request_started.elapsed().as_secs_f64() * 1000.0);
                let facts = server.process_facts()?;
                max_rss = max_rss.max(u64_field(&facts, "rss_kib")?);
                max_threads = max_threads.max(u64_field(&facts, "threads")?);
                max_fds = max_fds.max(u64_field(&facts, "fds")?);
                require(
                    u64_field(&facts, "children")? == 0,
                    "completed resource request retained a child process",
                )?;
            }
        }
        let shutdown = Instant::now();
        server.stop()?;
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
    let baseline_metrics = measure(&baseline.path)?;
    baseline.unchanged()?;
    let candidate_metrics = measure(&candidate.path)?;
    candidate.unchanged()?;
    require(
        within(&candidate_metrics, &baseline_metrics)?,
        "candidate exceeded declared resource non-regression bounds",
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
