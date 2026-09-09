//! Action faults affect disposable SQLite only; no product fault switches.
use std::fs;

use crate::support::candidate;
use crate::support::loopback::{Client, Server};
use crate::support::recovery::error_code;
use crate::support::{Result, require, submission, text};
use rusqlite::Connection;
use serde_json::{Value, json};

fn projection(db: &Connection, run: &str) -> Result<(String, String)> {
    let metadata = db
        .query_row(
            "SELECT metadata_json FROM runs WHERE run_id=?",
            [run],
            |r| r.get(0),
        )
        .map_err(|_| "fixture run metadata")?;
    let domains = db.query_row("SELECT json_group_array(json_object('id',domain_id,'status',status,'sealed_at',sealed_at)) FROM domains WHERE run_id=?", [run], |r| r.get(0))
        .map_err(|_| "fixture domain projection")?;
    Ok((metadata, domains))
}

fn status(server: &Server, owner: &Client, task: &Value) -> Result<Value> {
    server.call(
        owner,
        "rethlas_inspect",
        json!({"operation":"status","run_id":task["run_id"]}),
    )
}

fn run_root(server: &Server, task: &Value) -> Result<std::path::PathBuf> {
    Ok(server
        .private_state_path()
        .parent()
        .ok_or("fixture private root")?
        .join("runs")
        .join(text(task, "run_id")?))
}

fn bytes(path: &std::path::Path) -> Result<Vec<u8>> {
    let value = fs::read(path).map_err(|_| "fixture private effect missing")?;
    require(
        value.len() <= 4 * 1024 * 1024,
        "fixture effect exceeded bound",
    )?;
    Ok(value)
}

#[test]
fn assessment_transition_failure_does_not_seal_domain_or_leave_action_metadata() -> Result {
    let selected = candidate::select()?;
    let mut server = Server::start(&selected.path)?;
    let owner = server.login()?;
    let task = super::start(&server, &owner, "compact")?;
    let mut request = submission(&task)?;
    let retained = request["writes"].as_array().ok_or("fixture writes")?.len() as u64;
    let db = Connection::open(server.private_state_path()).map_err(|_| "fixture DB")?;
    let before = projection(&db, text(&task, "run_id")?)?;
    db.execute_batch("CREATE TRIGGER block_action BEFORE INSERT ON transitions WHEN NEW.before_state='assess' BEGIN SELECT RAISE(ABORT,'action fixture'); END;")
        .map_err(|_| "fixture action trigger")?;
    let failed = server.call(&owner, "rethlas_step", request.clone())?;
    require(
        error_code(&failed) == "RESULT_UNKNOWN",
        "failed action lost uncertainty",
    )?;
    require(
        projection(&db, text(&task, "run_id")?)? == before,
        "failed transition left a sealed domain or action metadata",
    )?;
    db.execute_batch("DROP TRIGGER block_action")
        .map_err(|_| "fixture trigger cleanup")?;
    drop(db);
    server.force_restart()?;
    request["recover_only"] = json!(true);
    let recovery = server.call(&owner, "rethlas_step", request)?;
    require(
        recovery["submission_receipt"]["result"]["error_code"] == "SUBMISSION_INTERRUPTED"
            && recovery["submission_receipt"]["result"]["writes_applied"] == retained
            && recovery["writes_applied"] == 0
            && recovery.get("capability").is_none(),
        "atomic action recovery did not preserve caller-write prefix",
    )?;
    let state = status(&server, &owner, &task)?;
    require(
        state["state"] == "assess" && state["pending_submission"].is_null(),
        "recovery ran the action",
    )?;
    let next = server.call(&owner, "rethlas_step", json!({"run_id":task["run_id"]}))?;
    let mut corrected = submission(&next)?;
    corrected["writes"] = json!([]);
    require(
        server.call(&owner, "rethlas_step", corrected)?["state"] == "assemble",
        "corrected action did not continue",
    )?;
    super::cancel(&server, &owner, &task)?;
    server.stop()?;
    selected.unchanged()
}

fn retained_result(value: &Value, count: u64) -> Result {
    require(
        value["ok"] == true
            && value["writes_applied"] == 0
            && value["submission"]["ok"] == false
            && value["submission"]["complete"] == false
            && value["submission_receipt"]["result"]["writes_applied"] == count
            && value["submission_receipt"]["result"]["error_code"] == "SUBMISSION_INTERRUPTED"
            && value.get("capability").is_none()
            && value.get("context").is_none(),
        "atomic recovery did not return a non-authorizing retained-prefix correction",
    )
}

fn advance_to(server: &Server, owner: &Client, mode: &str, target: &str) -> Result<Value> {
    let mut task = super::start(server, owner, mode)?;
    for _ in 0..8 {
        if task["state"] == target {
            return Ok(task);
        }
        let request =
            super::candidate_lifecycle::fixture_submission(&task, mode, task["state"] == "verify")?;
        task = server.call(owner, "rethlas_step", request)?;
        require(
            task["submission"]["ok"] == true,
            "action fixture setup failed",
        )?;
    }
    Err("action fixture did not reach the requested state")
}

#[test]
fn exploration_proof_escalation_and_repair_recover_without_reexecuting_action() -> Result {
    let selected = candidate::select()?;
    for (mode, state_name, escalate, after_state) in [
        ("full", "explore", false, "propose_plans"),
        ("compact", "assemble", false, "verify"),
        ("compact", "assemble", true, "explore"),
        ("compact", "repair", false, "verify"),
    ] {
        let mut server = Server::start(&selected.path)?;
        let owner = server.login()?;
        let task = advance_to(&server, &owner, mode, state_name)?;
        let mut request = super::candidate_lifecycle::fixture_submission(&task, mode, false)?;
        if escalate {
            request["payload"] =
                json!({"outcome":"escalate","escalation_reason":"fixture full route"});
            request["writes"] = json!([]);
        }
        let count = request["writes"].as_array().ok_or("fixture writes")?.len() as u64;
        let db = Connection::open(server.private_state_path()).map_err(|_| "fixture DB")?;
        let before = projection(&db, text(&task, "run_id")?)?;
        db.execute_batch(&format!("CREATE TRIGGER block_action BEFORE INSERT ON transitions WHEN NEW.before_state='{state_name}' BEGIN SELECT RAISE(ABORT,'fixture action'); END;"))
            .map_err(|_| "fixture trigger")?;
        require(
            error_code(&server.call(&owner, "rethlas_step", request.clone())?) == "RESULT_UNKNOWN",
            "action failure was not unknown",
        )?;
        require(
            projection(&db, text(&task, "run_id")?)? == before,
            "failed action committed database effects",
        )?;
        let interrupted = status(&server, &owner, &task)?;
        require(
            interrupted["pending_submission"]["atomic_action"] == request["action"],
            "atomic action was not explicitly enrolled",
        )?;
        require(
            error_code(&server.call(&owner, "rethlas_step", json!({"run_id":task["run_id"]}))?)
                == "RESULT_UNKNOWN",
            "pending action allowed mechanical refresh",
        )?;
        db.execute_batch("DROP TRIGGER block_action")
            .map_err(|_| "trigger cleanup")?;
        drop(db);
        server.force_restart()?;
        request["recover_only"] = json!(true);
        let other = server.login()?;
        require(
            server.call(&other, "rethlas_step", request.clone())?["ok"] == false,
            "foreign owner reconciled action",
        )?;
        let mut conflict = request.clone();
        conflict["payload"]["changed"] = json!(true);
        require(
            error_code(&server.call(&owner, "rethlas_step", conflict)?) == "IDEMPOTENCY_CONFLICT",
            "changed action request reconciled",
        )?;
        retained_result(
            &server.call(&owner, "rethlas_step", request.clone())?,
            count,
        )?;
        let restored = status(&server, &owner, &task)?;
        require(
            restored["state"] == state_name
                && restored["transition_seq"] == interrupted["transition_seq"],
            "recovery executed action",
        )?;
        let next = server.call(&owner, "rethlas_step", json!({"run_id":task["run_id"]}))?;
        request
            .as_object_mut()
            .ok_or("request")?
            .remove("recover_only");
        request["capability"] = next["capability"].clone();
        request["writes"] = json!([]);
        require(
            server.call(&owner, "rethlas_step", request)?["state"] == after_state,
            "corrected action failed to continue",
        )?;
        super::cancel(&server, &owner, &task)?;
        server.stop()?;
    }
    selected.unchanged()
}

#[test]
fn branch_seal_failure_rolls_back_database_but_does_not_certify_file_effects() -> Result {
    let selected = candidate::select()?;
    let mut server = Server::start(&selected.path)?;
    let owner = server.login()?;
    let direct = advance_to(&server, &owner, "full", "direct_proving")?;
    let mut request = super::candidate_lifecycle::fixture_submission(&direct, "full", false)?;
    let mut screening = serde_json::Map::new();
    for plan in direct["context"]["active_plans"]
        .as_array()
        .ok_or("plans")?
    {
        let mut goals = serde_json::Map::new();
        for goal in plan["subgoals"].as_array().ok_or("goals")? {
            goals.insert(text(goal,"subgoal_id")?.into(),json!({"status":"stuck","summary":"fixture branch needed","method":"direct","obstruction":"no_progress","evidence_ids":[]}));
        }
        screening.insert(text(plan, "plan_id")?.into(), Value::Object(goals));
    }
    request["payload"] = json!({"screening":screening});
    let branch = server.call(&owner, "rethlas_step", request)?;
    require(branch["state"] == "branch_run", "branch fixture failed")?;
    let before = status(&server, &owner, &branch)?;
    let db = Connection::open(server.private_state_path()).map_err(|_| "fixture DB")?;
    let domains = projection(&db, text(&branch, "run_id")?)?.1;
    db.execute_batch("CREATE TRIGGER block_branch BEFORE INSERT ON transitions WHEN NEW.before_state='branch_run' BEGIN SELECT RAISE(ABORT,'fixture branch'); END;").map_err(|_|"branch trigger")?;
    let mut request = json!({"run_id":branch["run_id"],"capability":branch["capability"],"action":"branch_complete",
        "writes":[{"resource":"memory:branch:proof_steps","content":{"summary":"fixture failed attempt"}}],
        "payload":{"status":"failed","summary":"fixture obstruction","proved_subgoals":[],"unproved_subgoals":[],"failure_evidence":["no progress"],"obstructions":[]}});
    require(
        error_code(&server.call(&owner, "rethlas_step", request.clone())?) == "RESULT_UNKNOWN",
        "branch transition fault did not remain unknown",
    )?;
    let after = status(&server, &owner, &branch)?;
    require(
        before["branches"] == after["branches"]
            && before["transition_seq"] == after["transition_seq"],
        "branch/barrier database state partially changed",
    )?;
    require(
        projection(&db, text(&branch, "run_id")?)?.1 == domains,
        "branch domain sealed despite transition failure",
    )?;
    let root = run_root(&server, &branch)?;
    let branch_id = text(&branch["context"], "branch_id")?;
    let branch_result = root.join("branches").join(branch_id).join("result.json");
    let branch_states = root.join("memory/generation/branch_states.jsonl");
    let result_before = bytes(&branch_result)?;
    let states_before = bytes(&branch_states)?;
    db.execute_batch("DROP TRIGGER block_branch")
        .map_err(|_| "branch cleanup")?;
    drop(db);
    server.force_restart()?;
    request["recover_only"] = json!(true);
    retained_result(&server.call(&owner, "rethlas_step", request.clone())?, 1)?;
    let current = server.call(&owner, "rethlas_step", json!({"run_id":branch["run_id"]}))?;
    request
        .as_object_mut()
        .ok_or("request")?
        .remove("recover_only");
    request["capability"] = current["capability"].clone();
    request["writes"] = json!([]);
    let continued = server.call(&owner, "rethlas_step", request)?;
    require(
        continued["state"] == "branch_run" || continued["state"] == "branch_join",
        "branch correction did not continue the barrier",
    )?;
    require(
        bytes(&branch_result)? == result_before && bytes(&branch_states)? == states_before,
        "branch correction rewrote or duplicated internal effects",
    )?;
    super::cancel(&server, &owner, &continued)?;
    server.stop()?;
    selected.unchanged()
}

#[test]
fn plans_direct_and_verification_actions_resume_exact_internal_files_after_restart() -> Result {
    let selected = candidate::select()?;

    {
        let mut server = Server::start(&selected.path)?;
        let owner = server.login()?;
        let task = advance_to(&server, &owner, "full", "propose_plans")?;
        let mut request = super::candidate_lifecycle::fixture_submission(&task, "full", false)?;
        let db = Connection::open(server.private_state_path()).map_err(|_| "fixture DB")?;
        db.execute_batch("CREATE TRIGGER block_plan_action BEFORE INSERT ON transitions WHEN NEW.before_state='propose_plans' BEGIN SELECT RAISE(ABORT,'fixture plan action'); END;")
            .map_err(|_| "fixture plan trigger")?;
        require(
            error_code(&server.call(&owner, "rethlas_step", request.clone())?) == "RESULT_UNKNOWN",
            "planning action fault did not remain unknown",
        )?;
        let root = run_root(&server, &task)?;
        let record_path = root.join("memory/generation/subgoals.jsonl");
        let recorded = bytes(&record_path)?;
        require(
            status(&server, &owner, &task)?["pending_submission"]["caller_write_recovery"]["kind"]
                == "restartable_action",
            "planning action did not expose restartable pending evidence",
        )?;
        db.execute_batch("DROP TRIGGER block_plan_action")
            .map_err(|_| "fixture plan cleanup")?;
        drop(db);
        server.force_restart()?;
        request["recover_only"] = json!(true);
        retained_result(&server.call(&owner, "rethlas_step", request.clone())?, 0)?;
        let current = server.call(&owner, "rethlas_step", json!({"run_id":task["run_id"]}))?;
        request
            .as_object_mut()
            .ok_or("request")?
            .remove("recover_only");
        request["capability"] = current["capability"].clone();
        request["writes"] = json!([]);
        let corrected = server.call(&owner, "rethlas_step", request)?;
        require(
            corrected["state"] == "direct_proving",
            "planning correction did not continue",
        )?;
        require(
            bytes(&record_path)? == recorded,
            "planning action duplicated internal records",
        )?;
        server.stop()?;
    }

    {
        let mut server = Server::start(&selected.path)?;
        let owner = server.login()?;
        let task = advance_to(&server, &owner, "full", "direct_proving")?;
        let mut request = super::candidate_lifecycle::fixture_submission(&task, "full", false)?;
        let db = Connection::open(server.private_state_path()).map_err(|_| "fixture DB")?;
        db.execute_batch("CREATE TRIGGER block_direct_action BEFORE INSERT ON transitions WHEN NEW.before_state='direct_proving' BEGIN SELECT RAISE(ABORT,'fixture direct action'); END;")
            .map_err(|_| "fixture direct trigger")?;
        require(
            error_code(&server.call(&owner, "rethlas_step", request.clone())?) == "RESULT_UNKNOWN",
            "direct action fault did not remain unknown",
        )?;
        let root = run_root(&server, &task)?;
        let proof_steps = root.join("memory/generation/proof_steps.jsonl");
        let join = root.join("join/result.json");
        let proof_steps_before = bytes(&proof_steps)?;
        let join_before = bytes(&join)?;
        db.execute_batch("DROP TRIGGER block_direct_action")
            .map_err(|_| "fixture direct cleanup")?;
        drop(db);
        server.force_restart()?;
        request["recover_only"] = json!(true);
        retained_result(&server.call(&owner, "rethlas_step", request.clone())?, 1)?;
        let current = server.call(&owner, "rethlas_step", json!({"run_id":task["run_id"]}))?;
        request
            .as_object_mut()
            .ok_or("request")?
            .remove("recover_only");
        request["capability"] = current["capability"].clone();
        request["writes"] = json!([]);
        require(
            server.call(&owner, "rethlas_step", request)?["state"] == "assemble",
            "direct correction did not continue",
        )?;
        require(
            bytes(&proof_steps)? == proof_steps_before && bytes(&join)? == join_before,
            "direct action rewrote or duplicated internal effects",
        )?;
        server.stop()?;
    }

    {
        let mut server = Server::start(&selected.path)?;
        let owner = server.login()?;
        let task = advance_to(&server, &owner, "compact", "verify")?;
        let mut request = super::candidate_lifecycle::fixture_submission(&task, "compact", false)?;
        let db = Connection::open(server.private_state_path()).map_err(|_| "fixture DB")?;
        db.execute_batch("CREATE TRIGGER block_verify_action BEFORE INSERT ON transitions WHEN NEW.before_state='verify' BEGIN SELECT RAISE(ABORT,'fixture verify action'); END;")
            .map_err(|_| "fixture verify trigger")?;
        require(
            error_code(&server.call(&owner, "rethlas_step", request.clone())?) == "RESULT_UNKNOWN",
            "verification action fault did not remain unknown",
        )?;
        let root = run_root(&server, &task)?;
        let report = root.join("verification/verification.json");
        let verifier_memory = root.join("memory/verifier/verification_reports.jsonl");
        let generation_memory = root.join("memory/generation/verification_reports.jsonl");
        let report_before = bytes(&report)?;
        let verifier_before = bytes(&verifier_memory)?;
        let generation_before = bytes(&generation_memory)?;
        db.execute_batch("DROP TRIGGER block_verify_action")
            .map_err(|_| "fixture verify cleanup")?;
        drop(db);
        server.force_restart()?;
        request["recover_only"] = json!(true);
        retained_result(&server.call(&owner, "rethlas_step", request.clone())?, 3)?;
        let current = server.call(&owner, "rethlas_step", json!({"run_id":task["run_id"]}))?;
        request
            .as_object_mut()
            .ok_or("request")?
            .remove("recover_only");
        request["capability"] = current["capability"].clone();
        request["writes"] = json!([]);
        require(
            server.call(&owner, "rethlas_step", request)?["state"] == "done",
            "verification correction did not reach finalization",
        )?;
        require(
            bytes(&report)? == report_before
                && bytes(&verifier_memory)? == verifier_before
                && bytes(&generation_memory)? == generation_before,
            "verification action rewrote or duplicated internal effects",
        )?;
        server.stop()?;
    }

    selected.unchanged()
}

#[test]
fn join_failure_and_replan_actions_resume_without_duplicate_internal_records() -> Result {
    let selected = candidate::select()?;
    let mut server = Server::start(&selected.path)?;
    let owner = server.login()?;
    let direct = advance_to(&server, &owner, "full", "direct_proving")?;
    let mut direct_request =
        super::candidate_lifecycle::fixture_submission(&direct, "full", false)?;
    let plan_id = text(&direct["context"]["active_plans"][0], "plan_id")?.to_owned();
    let node_id = text(
        &direct["context"]["active_plans"][0]["subgoals"][0],
        "node_id",
    )?
    .to_owned();
    let mut screening = serde_json::Map::new();
    for plan in direct["context"]["active_plans"]
        .as_array()
        .ok_or("plans")?
    {
        let mut goals = serde_json::Map::new();
        for goal in plan["subgoals"].as_array().ok_or("goals")? {
            goals.insert(
                text(goal, "subgoal_id")?.into(),
                json!({"status":"stuck","summary":"fixture branch needed","method":"direct","obstruction":"no_progress","evidence_ids":[]}),
            );
        }
        screening.insert(text(plan, "plan_id")?.into(), Value::Object(goals));
    }
    direct_request["payload"] = json!({"screening":screening});
    let mut current = server.call(&owner, "rethlas_step", direct_request)?;
    require(
        current["state"] == "branch_run",
        "branch setup did not start",
    )?;
    for _ in 0..8 {
        if current["state"] != "branch_run" {
            break;
        }
        current = server.call(
            &owner,
            "rethlas_step",
            json!({
                "run_id":current["run_id"],"capability":current["capability"],
                "action":"branch_complete",
                "writes":[{"resource":"memory:branch:proof_steps","content":{"summary":"fixture failed branch"}}],
                "payload":{"status":"failed","summary":"fixture obstruction","proved_subgoals":[],"unproved_subgoals":[],"failure_evidence":["no progress"],"obstructions":[]}
            }),
        )?;
    }
    require(
        current["state"] == "branch_join",
        "branch barrier did not reach join",
    )?;

    let root = run_root(&server, &current)?;
    let mut join_request = json!({
        "run_id":current["run_id"],"capability":current["capability"],
        "action":"join_complete","writes":[],"payload":{"common_failures":["fixture obstruction"]}
    });
    let db = Connection::open(server.private_state_path()).map_err(|_| "join fixture DB")?;
    db.execute_batch("CREATE TRIGGER block_join_action BEFORE INSERT ON transitions WHEN NEW.before_state='branch_join' BEGIN SELECT RAISE(ABORT,'fixture join action'); END;")
        .map_err(|_| "join trigger")?;
    require(
        error_code(&server.call(&owner, "rethlas_step", join_request.clone())?) == "RESULT_UNKNOWN",
        "join fault did not remain unknown",
    )?;
    let join_path = root.join("join/result.json");
    let branch_states = root.join("memory/generation/branch_states.jsonl");
    let join_before = bytes(&join_path)?;
    let states_before = bytes(&branch_states)?;
    db.execute_batch("DROP TRIGGER block_join_action")
        .map_err(|_| "join trigger cleanup")?;
    drop(db);
    server.force_restart()?;
    join_request["recover_only"] = json!(true);
    retained_result(
        &server.call(&owner, "rethlas_step", join_request.clone())?,
        0,
    )?;
    let join_task = server.call(&owner, "rethlas_step", json!({"run_id":current["run_id"]}))?;
    join_request
        .as_object_mut()
        .ok_or("join request")?
        .remove("recover_only");
    join_request["capability"] = join_task["capability"].clone();
    let mut failures = server.call(&owner, "rethlas_step", join_request)?;
    require(
        failures["state"] == "identify_failures",
        "join correction did not continue",
    )?;
    require(
        bytes(&join_path)? == join_before && bytes(&branch_states)? == states_before,
        "join correction duplicated internal files",
    )?;

    let mut failure_request = json!({
        "run_id":failures["run_id"],"capability":failures["capability"],
        "action":"failures_identified","writes":[],
        "payload":{"summary":{
            "obstruction":"fixture route stalled","next_step":"replan",
            "affected_node_ids":[node_id],"obstruction_class":"no_progress",
            "excluded_plan_ids":[],"preserved_node_ids":[],"required_hypotheses":[],
            "required_reference_queries":[],"selected_focus_node_id":node_id
        }}
    });
    let db = Connection::open(server.private_state_path()).map_err(|_| "failure fixture DB")?;
    db.execute_batch("CREATE TRIGGER block_failure_action BEFORE INSERT ON transitions WHEN NEW.before_state='identify_failures' BEGIN SELECT RAISE(ABORT,'fixture failure action'); END;")
        .map_err(|_| "failure trigger")?;
    let failure_fault = server.call(&owner, "rethlas_step", failure_request.clone())?;
    require(
        error_code(&failure_fault) == "RESULT_UNKNOWN",
        "failure-summary fault did not remain unknown",
    )?;
    let failed_paths = root.join("memory/generation/failed_paths.jsonl");
    let failed_before = bytes(&failed_paths)?;
    db.execute_batch("DROP TRIGGER block_failure_action")
        .map_err(|_| "failure cleanup")?;
    drop(db);
    server.force_restart()?;
    failure_request["recover_only"] = json!(true);
    retained_result(
        &server.call(&owner, "rethlas_step", failure_request.clone())?,
        0,
    )?;
    let task = server.call(&owner, "rethlas_step", json!({"run_id":failures["run_id"]}))?;
    failure_request
        .as_object_mut()
        .ok_or("failure request")?
        .remove("recover_only");
    failure_request["capability"] = task["capability"].clone();
    failures = server.call(&owner, "rethlas_step", failure_request)?;
    require(
        failures["state"] == "replan",
        "failure correction did not continue",
    )?;
    require(
        bytes(&failed_paths)? == failed_before,
        "failure correction duplicated record",
    )?;

    let mut replan_request = json!({
        "run_id":failures["run_id"],"capability":failures["capability"],
        "action":"replan_complete","writes":[],
        "payload":{"decision":{"reason":"fixture replaces failed route","superseded_plan_ids":[plan_id],"preserved_node_ids":[],"new_constraints":[]}}
    });
    let db = Connection::open(server.private_state_path()).map_err(|_| "replan fixture DB")?;
    db.execute_batch("CREATE TRIGGER block_replan_action BEFORE INSERT ON transitions WHEN NEW.before_state='replan' BEGIN SELECT RAISE(ABORT,'fixture replan action'); END;")
        .map_err(|_| "replan trigger")?;
    require(
        error_code(&server.call(&owner, "rethlas_step", replan_request.clone())?)
            == "RESULT_UNKNOWN",
        "replan fault did not remain unknown",
    )?;
    let decisions = root.join("memory/generation/big_decisions.jsonl");
    let decisions_before = bytes(&decisions)?;
    db.execute_batch("DROP TRIGGER block_replan_action")
        .map_err(|_| "replan cleanup")?;
    drop(db);
    server.force_restart()?;
    replan_request["recover_only"] = json!(true);
    retained_result(
        &server.call(&owner, "rethlas_step", replan_request.clone())?,
        0,
    )?;
    let task = server.call(&owner, "rethlas_step", json!({"run_id":failures["run_id"]}))?;
    replan_request
        .as_object_mut()
        .ok_or("replan request")?
        .remove("recover_only");
    replan_request["capability"] = task["capability"].clone();
    let next = server.call(&owner, "rethlas_step", replan_request)?;
    require(
        next["state"] == "propose_plans",
        "replan correction did not continue",
    )?;
    require(
        bytes(&decisions)? == decisions_before,
        "replan correction duplicated record",
    )?;

    super::cancel(&server, &owner, &next)?;
    server.stop()?;
    selected.unchanged()
}
