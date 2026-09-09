//! Action faults affect disposable SQLite only; no product fault switches.
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
    db.execute_batch("DROP TRIGGER block_branch")
        .map_err(|_| "branch cleanup")?;
    drop(db);
    server.force_restart()?;
    request["recover_only"] = json!(true);
    require(
        error_code(&server.call(&owner, "rethlas_step", request)?) == "RESULT_UNKNOWN",
        "non-atomic branch action was adopted",
    )?;
    super::cancel(&server, &owner, &branch)?;
    server.stop()?;
    selected.unchanged()
}
