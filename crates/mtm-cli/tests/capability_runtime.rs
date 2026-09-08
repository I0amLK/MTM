//! Current built binary, disposable socket service and real OAuth/workflow store.
//! No browser, external retrieval, Native sandbox or compiled LaTeX qualification.
#![cfg(unix)]

mod support;

#[path = "support/workspace_smoke.rs"]
mod workspace_smoke;

#[path = "support/target_runtime.rs"]
mod target_runtime;

#[path = "support/resource_runtime.rs"]
mod resource_runtime;

#[path = "support/candidate_lifecycle.rs"]
mod candidate_lifecycle;

#[path = "support/submission_receipts.rs"]
mod submission_receipts;

#[path = "support/e2_recovery.rs"]
mod e2_recovery;

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Value, json};
use support::loopback::{Client, Server, sha256_file};
use support::recovery::{adopt_refresh, error_code, submit_with_one_refresh};
use support::{Result, require, submission, text};

fn start(server: &Server, client: &Client, mode: &str) -> Result<Value> {
    let started = server.call(
        client,
        "rethlas_start",
        json!({
            "problem_tex":"Test fixture: prove that 1=1.","problem_id":"rust-capability-gate",
            "workflow_mode":mode,"register_result":false
        }),
    )?;
    require(started["ok"] == true, "disposable run creation failed")?;
    let task = server.call(
        client,
        "rethlas_step",
        json!({"run_id":text(&started,"run_id")?}),
    )?;
    require(
        task["state"] == "assess",
        "new run did not issue assessment",
    )?;
    submission(&task)?;
    Ok(task)
}

fn cancel(server: &Server, client: &Client, task: &Value) -> Result {
    let response = server.call(client, "rethlas_control", json!({
        "action":"cancel","run_id":text(task,"run_id")?,"reason":"disposable Rust regression complete"
    }))?;
    require(response["ok"] == true, "disposable run cleanup failed")
}

fn advances(before: &Value, after: &Value) -> Result {
    let args = submission(before)?;
    let count = args["writes"]
        .as_array()
        .ok_or("invalid minimal writes")?
        .len() as u64;
    require(
        after["ok"] == true && after["submission"]["ok"] == true && error_code(after).is_empty(),
        "normal step did not succeed",
    )?;
    require(
        after["run_id"] == before["run_id"] && after["state"] != before["state"],
        "normal step did not advance its run",
    )?;
    text(after, "state")?;
    submission(after)?;
    require(
        after["writes_applied"].as_u64() == Some(count),
        "logical write count mismatch",
    )
}

fn mutate(token: &str, truncate: bool) -> Result<String> {
    let (body, signature) = token
        .split_once('.')
        .ok_or("test capability shape changed")?;
    require(
        signature.is_ascii() && signature.len() > 16,
        "test signature is too short",
    )?;
    let signature = if truncate {
        signature[..signature.len() / 2].to_owned()
    } else {
        format!(
            "{}{}",
            if signature.starts_with('A') { 'B' } else { 'A' },
            &signature[1..]
        )
    };
    Ok(format!("{body}.{signature}"))
}

fn adversarial(server: &Server, owner: &Client, report: &mut Value) -> Result {
    let other = server.login()?;
    for truncated in [false, true] {
        let current = start(server, owner, "compact")?;
        let before = submission(&current)?;
        let resource = before["writes"]
            .as_array()
            .and_then(|w| w.first())
            .and_then(|w| w["resource"].as_str())
            .ok_or("assessment fixture omitted memory write")?
            .to_owned();
        let read = |task: &Value| {
            server.call(
                owner,
                "rethlas_inspect",
                json!({
                    "operation":"read","capability":text(task,"capability")?,"resource":resource
                }),
            )
        };
        let memory_before = read(&current)?;
        require(
            memory_before["ok"] == true && memory_before.get("content").is_some(),
            "pre-mutation memory read failed",
        )?;
        let mut invalid = before;
        invalid["capability"] = json!(mutate(text(&current, "capability")?, truncated)?);
        for (name, args) in [
            (
                "rethlas_inspect",
                json!({"operation":"read","resource":resource,"capability":invalid["capability"]}),
            ),
            (
                "rethlas_retrieve",
                json!({"query":"unused fixture","capability":invalid["capability"]}),
            ),
        ] {
            let rejected = server.call(owner, name, args)?;
            require(
                rejected["ok"] == false
                    && error_code(&rejected) == "CAPABILITY_INVALID"
                    && rejected.get("capability").is_none(),
                "invalid read or retrieval obtained authority",
            )?;
        }
        let refreshed = server.call(owner, "rethlas_step", invalid)?;
        adopt_refresh(&current, &refreshed)?;
        let memory_after = read(&refreshed)?;
        require(
            memory_after["ok"] == true
                && memory_after.get("content").is_some()
                && memory_before["content"] == memory_after["content"],
            "invalid capability changed logical memory",
        )?;
        let completed = submit_with_one_refresh(&refreshed, submission, |args| {
            server.call(owner, "rethlas_step", args)
        })?;
        advances(&refreshed, &completed)?;
        let replayed = server.call(owner, "rethlas_step", submission(&refreshed)?)?;
        require(
            replayed["ok"] == true
                && replayed["writes_applied"] == 0
                && replayed["submission_receipt"]["replayed"] == true
                && replayed.get("capability").is_none()
                && replayed.get("context").is_none(),
            "identical replay did not return a non-authorizing zero-write receipt",
        )?;
        for (name, args) in [
            (
                "rethlas_inspect",
                json!({"operation":"read","resource":resource,"capability":refreshed["capability"]}),
            ),
            (
                "rethlas_retrieve",
                json!({"query":"unused fixture","capability":refreshed["capability"]}),
            ),
        ] {
            let rejected = server.call(owner, name, args)?;
            require(
                rejected["ok"] == false && error_code(&rejected) == "CAPABILITY_REVOKED",
                "read or retrieval accepted a revoked capability",
            )?;
        }
        let separate = start(server, owner, "compact")?;
        let mut mismatch = submission(&separate)?;
        mismatch["capability"] = completed["capability"].clone();
        let mismatch = server.call(owner, "rethlas_step", mismatch)?;
        require(
            error_code(&mismatch) == "CAPABILITY_RUN_MISMATCH" && mismatch["ok"] == false,
            "cross-run capability was not rejected",
        )?;
        let mut foreign = submission(&completed)?;
        foreign["capability"] = json!(mutate(text(&completed, "capability")?, false)?);
        let foreign = server.call(&other, "rethlas_step", foreign)?;
        require(
            error_code(&foreign) == "RUN_OWNER_MISMATCH"
                && foreign["ok"] == false
                && foreign.get("capability").is_none(),
            "foreign owner received a refresh",
        )?;
        cancel(server, owner, &completed)?;
        cancel(server, owner, &separate)?;
    }
    report["adversarial_checks"] = json!({
        "mutated_and_truncated_signature":true,"invalid_submission_zero_memory_changes":true,
        "fresh_submission_advances":true,"used_capability_revoked":true,
        "invalid_inspect_and_retrieve_denied":true,
        "revoked_inspect_and_retrieve_denied":true,"cross_run_denied":true,"cross_owner_refresh_denied":true
    });
    Ok(())
}

fn run_gate(report: &mut Value) -> Result {
    let candidate = support::candidate::select()?;
    let binary = candidate.path.as_str();
    let hash = sha256_file(Path::new(binary))?;
    report["binary_sha256"] = json!(hash);
    let mut server = Server::start(binary)?;
    let owner = server.login()?;
    let info = server.call(&owner, "server_info", json!({}))?;
    require(
        info["version"] == env!("CARGO_PKG_VERSION")
            && info["hidden_alias_count"] == 0
            && info["research_workspace"]["workflow_protocol_version"] == 3,
        "wrong binary or protocol identity",
    )?;
    report["version"] = info["version"].clone();
    adversarial(&server, &owner, report)?;

    // A lost outcome is simulated AFTER the real server committed, not by replaying a 502.
    let current = start(&server, &owner, "compact")?;
    let mut calls = 0;
    let lost = submit_with_one_refresh(&current, submission, |args| {
        calls += 1;
        server.call(&owner, "rethlas_step", args)?;
        Err("simulated lost tool outcome; do not replay")
    });
    require(
        lost.is_err() && calls == 1,
        "uncertain outcome was automatically replayed",
    )?;
    let status = server.call(
        &owner,
        "rethlas_inspect",
        json!({"operation":"status","run_id":current["run_id"]}),
    )?;
    require(
        status["state"] == "assemble",
        "status did not reveal the completed submission",
    )?;
    cancel(&server, &owner, &current)?;
    report["lost_outcome_no_automatic_replay"] = json!(true);

    let persistent = start(&server, &owner, "compact")?;
    server.restart()?;
    let resumed = server.call(&owner, "rethlas_step", submission(&persistent)?)?;
    advances(&persistent, &resumed)?;
    cancel(&server, &owner, &resumed)?;
    report["same_identity_and_capability_survive_restart"] = json!(true);

    let mut runs = BTreeSet::new();
    for index in 0..500_u64 {
        let current = start(
            &server,
            &owner,
            if index % 2 == 0 { "compact" } else { "full" },
        )?;
        require(
            runs.insert(text(&current, "run_id")?.to_owned()),
            "duplicate run id in normal corpus",
        )?;
        let next = server.call(&owner, "rethlas_step", submission(&current)?)?;
        if error_code(&next) == "CAPABILITY_INVALID"
            || next.pointer("/submission/capability_refreshed") == Some(&Value::Bool(true))
        {
            report["normal_invalid"] = json!(1);
            return Err("verbatim current-envelope submission required capability refresh");
        }
        if let Err(error) = advances(&current, &next) {
            report["normal_rejections"] = json!(1);
            return Err(error);
        }
        cancel(&server, &owner, &next)?;
        report["normal_roundtrips"] = json!(index + 1);
        report["independent_normal_runs"] = json!(runs.len());
        report["normal_modes"][if index % 2 == 0 { "compact" } else { "full" }] =
            json!(index / 2 + 1);
    }
    server.stop()?;
    report["bounded_clean_shutdown"] = json!(true);
    require(
        sha256_file(Path::new(binary))? == hash,
        "binary changed during qualification",
    )?;
    report["binary_unchanged"] = json!(true);
    candidate.unchanged()?;
    Ok(())
}

#[test]
fn current_binary_capability_regression() -> Result {
    let mut report = json!({
        "schema_version":"1.0.0","kind":"rust_current_binary_loopback_capability_regression",
        "ok":false,"samples_requested":500,"normal_roundtrips":0,"independent_normal_runs":0,
        "normal_invalid":0,"normal_rejections":0,"normal_modes":{"compact":0,"full":0},
        "native_backend":"disabled","latex_policy":"static_only",
        "child_path_policy":"curl_only_no_python","web_client_tested":false,"external_retrieval_tested":false,
        "production_state_modified":false,"raw_capability_recorded":false,"raw_oauth_token_recorded":false,
        "release_qualified":false
    });
    let outcome = run_gate(&mut report);
    report["ok"] = json!(outcome.is_ok());
    if let Err(message) = outcome {
        report["failure"] = json!(message);
    }
    println!("MTM_CAPABILITY_GATE {report}");
    outcome
}
