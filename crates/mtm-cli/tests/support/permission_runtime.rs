//! Scripted consent through real OAuth/MCP and protected workspace writes.
//! Native commands, browser UI and independent human consent are not exercised.
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use mtm_contracts::NativeMode;
use serde_json::{Value, json};

use crate::support::candidate;
use crate::support::loopback::{Client, Server};
use crate::support::{Result, require, text};

const ENABLE: &str = "MTM_TEST_PERMISSION_PROFILE";
const FORM: &str = "native_permission_consent";

fn patch(file: &str, before: &str, after: &str) -> Value {
    json!({"patch":format!("*** Begin Patch\n*** Update File: {file}\n@@\n-{before}\n+{after}\n*** End Patch\n")})
}

fn request(arguments: &Value, scope: &str) -> Value {
    json!({"tool_name":"apply_patch","permission":"write_generated_or_ignored",
        "reason":"Scripted disposable permission fixture, not human acceptance",
        "arguments":arguments,"scope":scope,"ttl_seconds":300})
}

fn data(result: &Value) -> Result<&Value> {
    require(
        result["resultType"] == "complete",
        "permission completion missing",
    )?;
    let data = result
        .get("structuredContent")
        .filter(|v| v.is_object())
        .ok_or("permission structured result missing")?;
    require(
        result["isError"].is_boolean() && (result["isError"] != true || data["ok"] == false),
        "permission result flags inconsistent",
    )?;
    Ok(data)
}

fn message(
    server: &Server,
    owner: &Client,
    req: &Value,
    retry: Option<(&str, Value)>,
) -> Result<Value> {
    server.permission_message(owner, req, json!({"elicitation":{"form":{}}}), retry)
}

fn challenge(server: &Server, owner: &Client, req: &Value) -> Result<String> {
    let result = message(server, owner, req, None)?;
    require(
        result["resultType"] == "input_required",
        "permission challenge missing",
    )?;
    let form = &result["inputRequests"][FORM];
    require(
        form["method"] == "elicitation/create"
            && form["params"]["mode"] == "form"
            && form["params"]["requestedSchema"]["properties"]["approved"]["type"] == "boolean",
        "permission challenge form invalid",
    )?;
    // The fixture body is never copied into a permission prompt.
    let serialized = serde_json::to_string(&result).map_err(|_| "permission prompt encoding")?;
    let body = text(&req["arguments"], "patch")?;
    require(
        !serialized.contains(body) && !serialized.contains("*** Begin Patch"),
        "permission prompt exposed fixture patch",
    )?;
    Ok(text(&result, "requestState")?.to_owned())
}

fn response(action: &str, approved: bool) -> Value {
    let value = if action == "accept" {
        json!({"action":action,"content":{"approved":approved}})
    } else {
        json!({"action":action})
    };
    json!({FORM:value})
}

fn granted(result: &Value) -> Result {
    let value = data(result)?;
    require(
        value["ok"] == true
            && value["status"] == "granted"
            && value["constraints"]["workflow_authority_inherited"] == false,
        "scripted grant was not exact or inherited authority",
    )?;
    text(value, "grant_id")?;
    Ok(())
}

fn grant(server: &Server, owner: &Client, req: &Value) -> Result {
    let state = challenge(server, owner, req)?;
    granted(&message(
        server,
        owner,
        req,
        Some((&state, response("accept", true))),
    )?)
}

fn denied(server: &Server, owner: &Client, args: &Value) -> Result {
    let value = server.call(owner, "apply_patch", args.clone())?;
    require(
        value["ok"] == false && value["error"]["code"] == "PERMISSION_REQUIRED",
        "unapproved protected patch was not denied",
    )
}

fn seed(server: &Server) -> Result {
    fs::create_dir(server.workspace_path().join("target"))
        .map_err(|_| "permission fixture directory")?;
    for name in ["target/guard.txt", "target/pending.txt", "ordinary.txt"] {
        fs::write(server.workspace_path().join(name), b"stable\n")
            .map_err(|_| "permission fixture seed")?;
    }
    Ok(())
}

fn unchanged(server: &Server) -> Result {
    require(
        fs::read(server.workspace_path().join("target/guard.txt"))
            .map_err(|_| "permission fixture read")?
            == b"stable\n",
        "denial changed protected bytes",
    )
}

fn boundary(binary: &str) -> Result<BTreeMap<&'static str, bool>> {
    let mut server = Server::start_permissions(binary, NativeMode::Safe)?;
    seed(&server)?;
    let owner = server.login()?;
    let other = server.login()?;
    let args = patch("target/guard.txt", "stable", "stable");
    let req = request(&args, "once");
    let mut checks = BTreeMap::new();
    let environment = server.call(&owner, "check_exec_environment", json!({}))?;
    require(
        environment["native_mode"] == "safe"
            && environment["native_exec_backend"] == "DisabledExecBackend"
            && environment["hard_isolation_attested"] == false,
        "permission fixture profile drift",
    )?;
    checks.insert("explicit_safe_disabled_profile", true);
    denied(&server, &owner, &args)?;
    unchanged(&server)?;
    checks.insert("unapproved_patch_zero_write", true);

    let legacy = server.call(&owner, "request_permissions", req.clone())?;
    require(
        legacy["status"] == "unsupported" && legacy["grant_id"].is_null(),
        "legacy request minted grant",
    )?;
    for capabilities in [json!({}), json!({"elicitation":{"url":{}}})] {
        let reply = server.permission_message(&owner, &req, capabilities, None)?;
        require(
            data(&reply)?["status"] == "unsupported",
            "unsupported client minted grant",
        )?;
    }
    checks.insert("legacy_and_nonform_clients_no_grant", true);

    for (label, action, approved) in [
        ("decline_zero_write", "decline", false),
        ("cancel_zero_write", "cancel", false),
        ("false_approval_zero_write", "accept", false),
    ] {
        let state = challenge(&server, &owner, &req)?;
        let reply = message(
            &server,
            &owner,
            &req,
            Some((&state, response(action, approved))),
        )?;
        require(
            data(&reply)?["error"]["code"] == "ELICITATION_DENIED"
                && data(&reply)?["grant_id"].is_null(),
            "negative consent minted grant",
        )?;
        denied(&server, &owner, &args)?;
        unchanged(&server)?;
        checks.insert(label, true);
    }

    let state = challenge(&server, &owner, &req)?;
    let approval = response("accept", true);
    let foreign = message(&server, &other, &req, Some((&state, approval.clone())))?;
    require(
        data(&foreign)?["error"]["code"] == "ELICITATION_OWNER_MISMATCH",
        "foreign challenge accepted",
    )?;
    checks.insert("challenge_owner_binding", true);
    let mut changed = req.clone();
    changed["arguments"] = patch("target/guard.txt", "stable", "changed");
    let mutation = message(&server, &owner, &changed, Some((&state, approval.clone())))?;
    require(
        data(&mutation)?["error"]["code"] == "ELICITATION_REQUEST_MISMATCH",
        "mutated challenge accepted",
    )?;
    checks.insert("challenge_argument_binding", true);
    let mut extra = approval.clone();
    extra["unexpected"] = json!({"action":"accept"});
    let malformed = message(&server, &owner, &req, Some((&state, extra)))?;
    require(
        data(&malformed)?["error"]["code"] == "ELICITATION_RESPONSE_INVALID",
        "extra response accepted",
    )?;
    granted(&message(
        &server,
        &owner,
        &req,
        Some((&state, approval.clone())),
    )?)?;
    checks.insert("invalid_responses_preserve_original_challenge", true);
    let duplicate = message(&server, &owner, &req, None)?;
    require(
        data(&duplicate)?["status"] == "already_granted" && data(&duplicate)?["grant_id"].is_null(),
        "duplicate grant not suppressed",
    )?;
    checks.insert("active_exact_grant_suppresses_prompt", true);
    let replay = message(&server, &owner, &req, Some((&state, approval)))?;
    require(
        data(&replay)?["error"]["code"] == "ELICITATION_STATE_INVALID",
        "consumed challenge accepted",
    )?;
    checks.insert("challenge_single_use", true);
    denied(&server, &other, &args)?;
    denied(&server, &owner, &changed["arguments"])?;
    unchanged(&server)?;
    checks.insert("grant_owner_and_argument_binding", true);
    let mut dry = args.clone();
    dry["dry_run"] = json!(true);
    require(
        server.call(&owner, "apply_patch", dry)?["ok"] == true,
        "dry run failed",
    )?;
    require(
        server.call(&owner, "apply_patch", args.clone())?["ok"] == true,
        "dry run consumed grant",
    )?;
    checks.insert("dry_run_does_not_consume_grant", true);
    denied(&server, &owner, &args)?;
    checks.insert("once_grant_cannot_be_reused", true);

    grant(&server, &owner, &req)?;
    let barrier = Arc::new(Barrier::new(2));
    let jobs: Vec<_> = (0..2)
        .map(|_| {
            let client = owner.clone();
            let args = args.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                client.call("apply_patch", args)
            })
        })
        .collect();
    let mut winners = 0;
    // Reap both client threads even when the first one reports an error.
    let results: Vec<_> = jobs.into_iter().map(|job| job.join()).collect();
    for result in results {
        let value = result.map_err(|_| "permission race worker failed")??;
        if value["ok"] == true {
            winners += 1;
        } else {
            require(
                matches!(
                    value["error"]["code"].as_str(),
                    Some("PERMISSION_REQUIRED" | "NATIVE_PATCH_AUTHORITY_FACTS_CHANGED")
                ),
                "permission race unexpected rejection",
            )?;
        }
    }
    require(winners == 1, "once grant race must have exactly one winner")?;
    denied(&server, &owner, &args)?;
    unchanged(&server)?;
    checks.insert("concurrent_once_grant_one_winner", true);

    let session = request(&args, "session");
    grant(&server, &owner, &session)?;
    for _ in 0..2 {
        require(
            server.call(&owner, "apply_patch", args.clone())?["ok"] == true,
            "session grant not reusable",
        )?;
    }
    checks.insert("session_grant_reusable_in_process", true);
    let pending = request(&patch("target/pending.txt", "stable", "stable"), "once");
    let pending_state = challenge(&server, &owner, &pending)?;
    server.restart()?;
    denied(&server, &owner, &args)?;
    let lost = message(
        &server,
        &owner,
        &pending,
        Some((&pending_state, response("accept", true))),
    )?;
    require(
        data(&lost)?["error"]["code"] == "ELICITATION_STATE_INVALID",
        "restart preserved consent state",
    )?;
    checks.insert("restart_invalidates_grants_and_challenges", true);
    let mut expiring = req.clone();
    expiring["ttl_seconds"] = json!(1);
    grant(&server, &owner, &expiring)?;
    thread::sleep(Duration::from_millis(1200));
    denied(&server, &owner, &args)?;
    unchanged(&server)?;
    checks.insert("expired_grant_zero_write", true);
    let ordinary = request(&patch("ordinary.txt", "stable", "stable"), "once");
    let result = message(&server, &owner, &ordinary, None)?;
    require(
        data(&result)?["status"] == "not_required",
        "ordinary path unexpectedly requires grant",
    )?;
    checks.insert("ordinary_path_not_required", true);
    server.stop()?;
    for mode in [NativeMode::Trusted, NativeMode::Dangerous] {
        let mut server = Server::start_permissions(binary, mode)?;
        seed(&server)?;
        let owner = server.login()?;
        if mode == NativeMode::Trusted {
            denied(&server, &owner, &args)?;
            grant(&server, &owner, &req)?;
        }
        require(
            server.call(&owner, "apply_patch", args.clone())?["ok"] == true,
            "trusted or dangerous patch mode did not work",
        )?;
        server.stop()?;
    }
    checks.insert("trusted_and_dangerous_patch_profiles", true);
    checks.insert("clean_shutdown", true);
    Ok(checks)
}

#[test]
fn scripted_permission_boundary_regression() -> Result {
    let candidate = candidate::select()?;
    boundary(&candidate.path)?;
    candidate.unchanged()
}

fn count(value: &Value, key: &str) -> Result<u64> {
    value[key]
        .as_u64()
        .ok_or("permission resource fact missing")
}

#[test]
fn exact_candidate_permission_patch_soak() -> Result {
    if env::var_os(ENABLE).is_none() {
        return Ok(());
    }
    require(
        env::var(ENABLE).ok().as_deref() == Some("1")
            && env::var_os(candidate::BINARY_ENV).is_some(),
        "permission soak requires explicit artifact and exact flag",
    )?;
    let candidate = candidate::select()?;
    let checks = boundary(&candidate.path)?;
    let mut server = Server::start_permissions(&candidate.path, NativeMode::Safe)?;
    seed(&server)?;
    let owner = server.login()?;
    let warmup = patch("target/guard.txt", "stable", "stable");
    for _ in 0..5 {
        grant(&server, &owner, &request(&warmup, "once"))?;
        require(
            server.call(&owner, "apply_patch", warmup.clone())?["ok"] == true,
            "permission warmup failed",
        )?;
    }
    let initial = server.process_facts()?;
    let mut max_rss = count(&initial, "rss_kib")?;
    let mut max_threads = count(&initial, "threads")?;
    let mut max_fds = count(&initial, "fds")?;
    let start = Instant::now();
    let mut before = "stable\n".to_owned();
    let mut cycles = 0_u64;
    for index in 0..100 {
        let after = format!(
            "stable\ncycle-{index}\n{}",
            before
                .strip_prefix("stable\n")
                .ok_or("soak anchor missing")?
        );
        // Inserting after a permanent unique anchor keeps the SAME request valid
        // after success; its next challenge proves grant consumption, not a hunk error.
        let args = json!({"patch":format!("*** Begin Patch\n*** Update File: target/guard.txt\n@@\n stable\n+cycle-{index}\n*** End Patch\n")});
        let req = request(&args, "once");
        denied(&server, &owner, &args)?;
        require(
            fs::read_to_string(server.workspace_path().join("target/guard.txt"))
                .map_err(|_| "soak denied file read")?
                == before,
            "soak denial wrote bytes",
        )?;
        grant(&server, &owner, &req)?;
        let duplicate = message(&server, &owner, &req, None)?;
        require(
            data(&duplicate)?["status"] == "already_granted",
            "soak duplicate minted another grant",
        )?;
        require(
            server.call(&owner, "apply_patch", args)?["ok"] == true,
            "soak granted patch failed",
        )?;
        require(
            fs::read_to_string(server.workspace_path().join("target/guard.txt"))
                .map_err(|_| "soak changed file read")?
                == after,
            "soak actual bytes differ",
        )?;
        let consumed = challenge(&server, &owner, &req)?;
        let cancelled = message(
            &server,
            &owner,
            &req,
            Some((&consumed, response("cancel", false))),
        )?;
        require(
            data(&cancelled)?["error"]["code"] == "ELICITATION_DENIED",
            "soak challenge cleanup failed",
        )?;
        cycles += 1;
        before = after;
        let facts = server.process_facts()?;
        max_rss = max_rss.max(count(&facts, "rss_kib")?);
        max_threads = max_threads.max(count(&facts, "threads")?);
        max_fds = max_fds.max(count(&facts, "fds")?);
        require(
            count(&facts, "children")? == 0,
            "soak retained child process",
        )?;
        require(
            start.elapsed() <= Duration::from_secs(90),
            "permission soak exceeded maximum duration",
        )?;
        thread::sleep((Duration::from_millis((index + 1) * 600)).saturating_sub(start.elapsed()));
    }
    let elapsed = start.elapsed().as_millis();
    let facts = server.process_facts()?;
    max_rss = max_rss.max(count(&facts, "rss_kib")?);
    max_threads = max_threads.max(count(&facts, "threads")?);
    max_fds = max_fds.max(count(&facts, "fds")?);
    require(
        (60_000..=90_000).contains(&elapsed) && count(&facts, "children")? == 0,
        "soak timing or children invalid",
    )?;
    require(
        max_rss <= count(&initial, "rss_kib")?.saturating_add(8192)
            && max_threads <= count(&initial, "threads")?
            && max_fds <= count(&initial, "fds")?,
        "permission patch soak exceeded fixed local growth bounds",
    )?;
    let shutdown = Instant::now();
    server.stop()?;
    let shutdown_ms = shutdown.elapsed().as_millis();
    require(shutdown_ms <= 8000, "permission shutdown exceeded bound")?;
    candidate.unchanged()?;
    println!(
        "MTM_PERMISSION_RUNTIME {}",
        json!({
            "ok":true,"binary_sha256":candidate.sha256,"checks":checks,
            "iterations":cycles,"duration_ms":elapsed,"warmup_iterations":5,
            "initial_denials":cycles,"grants_issued":cycles,"duplicate_prompts_suppressed":cycles,
            "protected_patches_committed":cycles,"consumed_grants_rechallenged":cycles,
            "initial_rss_kib":count(&initial,"rss_kib")?,"max_rss_kib":max_rss,
            "initial_threads":count(&initial,"threads")?,"max_threads":max_threads,
            "initial_fds":count(&initial,"fds")?,"max_fds":max_fds,"retained_children":0,
            "shutdown_ms":shutdown_ms,"native_mode":"safe","native_backend":"disabled",
            "latex_policy":"static_only","consent":"scripted_form_responses",
            "protected_patch_execution_tested":true,"native_command_execution_tested":false,
            "compiled_latex_tested":false,"web_client_tested":false,"human_consent_tested":false,
            "baseline_resource_comparison":false,"production_state_modified":false,
            "selector_changed":false,"release_qualified":false
        })
    );
    Ok(())
}
