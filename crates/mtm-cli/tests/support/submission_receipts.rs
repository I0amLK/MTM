//! Real OAuth/MCP submissions; only disposable fixture state is inspected.
use crate::support::candidate;
use crate::support::loopback::{Client, Server};
use crate::support::recovery::error_code;
use crate::support::{Result, require, submission, text};
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};

#[path = "submission_denials.rs"]
mod submission_denials;

fn status(server: &Server, owner: &Client, task: &Value) -> Result<Value> {
    server.call(
        owner,
        "rethlas_inspect",
        json!({"operation":"status","run_id":task["run_id"]}),
    )
}

fn memory(server: &Server, owner: &Client, task: &Value, resource: &str) -> Result<Value> {
    let result = server.call(
        owner,
        "rethlas_inspect",
        json!({"operation":"read",
        "capability":text(task,"capability")?,"resource":resource}),
    )?;
    require(result["ok"] == true, "fixture memory read rejected")?;
    Ok(result["content"].clone())
}

fn assert_receipt(value: &Value, writes: u64) -> Result {
    require(
        value["ok"] == true
            && value["writes_applied"] == 0
            && value["state_is_historical"] == true
            && value["task_required"] == true
            && value["submission_receipt"]["status"] == "completed"
            && value["submission_receipt"]["result"]["writes_applied"] == writes
            && value["submission_receipt"]["replayed"] == true
            && value["submission_receipt"]["grants_authority"] == false,
        "replay did not return its zero-write historical receipt",
    )?;
    for key in ["capability", "context", "task", "proof", "payload"] {
        require(
            value.get(key).is_none(),
            "receipt leaked authority or private content",
        )?;
    }
    Ok(())
}

#[test]
fn completed_step_replays_across_restart_without_duplicate_memory_or_transitions() -> Result {
    let candidate = candidate::select()?;
    let mut server = Server::start(&candidate.path)?;
    let owner = server.login()?;
    let other = server.login()?;
    let task = super::start(&server, &owner, "compact")?;
    let original = submission(&task)?;
    let count = original["writes"]
        .as_array()
        .ok_or("fixture writes missing")?
        .len() as u64;
    let result = server.call(&owner, "rethlas_step", original.clone())?;
    super::advances(&task, &result)?;
    require(
        result["submission_receipt"]["replayed"] == false,
        "first submission marked replay",
    )?;
    let before = status(&server, &owner, &task)?;
    let resource = text(&original["writes"][0], "resource")?;
    let content = memory(&server, &owner, &result, resource)?;
    for restart in [false, true] {
        if restart {
            server.restart()?;
        }
        let replay = server.call(&owner, "rethlas_step", original.clone())?;
        assert_receipt(&replay, count)?;
        require(
            status(&server, &owner, &task)? == before,
            "replay changed status or transition count",
        )?;
        require(
            memory(&server, &owner, &result, resource)? == content,
            "replay appended duplicate memory",
        )?;
    }
    let mut changed = original.clone();
    changed["payload"]["route_reason"] = json!("changed content on same identity");
    require(
        error_code(&server.call(&owner, "rethlas_step", changed)?) == "IDEMPOTENCY_CONFLICT",
        "changed replay was accepted",
    )?;
    let foreign = server.call(&other, "rethlas_step", original.clone())?;
    require(
        foreign["ok"] == false && foreign.get("submission_receipt").is_none(),
        "foreign owner accessed receipt",
    )?;
    let separate = super::start(&server, &owner, "compact")?;
    let mut wrong_run = original.clone();
    wrong_run["run_id"] = separate["run_id"].clone();
    require(
        error_code(&server.call(&owner, "rethlas_step", wrong_run)?) == "CAPABILITY_RUN_MISMATCH",
        "cross-run receipt accepted",
    )?;
    let connection = Connection::open_with_flags(
        server.private_state_path(),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|_| "fixture receipt DB read")?;
    let rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM step_receipts WHERE run_id=?",
            [text(&task, "run_id")?],
            |r| r.get(0),
        )
        .map_err(|_| "receipt count")?;
    require(rows == 1, "duplicate receipt was inserted")?;
    let persisted: String = connection
        .query_row(
            "SELECT result_json FROM step_receipts WHERE run_id=?",
            [text(&task, "run_id")?],
            |r| r.get(0),
        )
        .map_err(|_| "receipt summary")?;
    require(
        !persisted.contains(text(&original, "capability")?) && !persisted.contains("capability"),
        "raw token stored in receipt",
    )?;
    drop(connection);
    super::cancel(&server, &owner, &task)?;
    super::cancel(&server, &owner, &separate)?;
    // A historical receipt does not resume a now-cancelled run.
    assert_receipt(&server.call(&owner, "rethlas_step", original)?, count)?;
    require(
        status(&server, &owner, &task)?["state"] == "cancelled",
        "receipt replay resumed cancelled run",
    )?;
    server.stop()?;
    candidate.unchanged()
}

#[test]
fn partial_correction_receipt_is_not_replayed_as_success_or_reapplied() -> Result {
    let candidate = candidate::select()?;
    let mut server = Server::start(&candidate.path)?;
    let owner = server.login()?;
    let task = super::start(&server, &owner, "compact")?;
    let mut request = submission(&task)?;
    request["action"] = json!("not_the_current_action");
    let result = server.call(&owner, "rethlas_step", request.clone())?;
    require(
        result["submission"]["ok"] == false
            && result["writes_applied"].as_u64().is_some_and(|n| n > 0),
        "fixture did not exercise retained writes",
    )?;
    let resource = text(&request["writes"][0], "resource")?;
    let before = memory(&server, &owner, &result, resource)?;
    let replay = server.call(&owner, "rethlas_step", request.clone())?;
    assert_receipt(
        &replay,
        result["writes_applied"].as_u64().ok_or("writes count")?,
    )?;
    require(
        replay["submission"]["ok"] == false,
        "correction replay became success",
    )?;
    require(
        memory(&server, &owner, &result, resource)? == before,
        "correction replay duplicated memory",
    )?;
    let mut correction = submission(&result)?;
    correction["writes"] = json!([]);
    let advanced = server.call(&owner, "rethlas_step", correction)?;
    require(
        advanced["state"] == "assemble" && advanced["submission"]["ok"] == true,
        "fresh correction without retained writes failed",
    )?;
    super::cancel(&server, &owner, &task)?;
    server.stop()?;
    candidate.unchanged()
}

#[test]
fn concurrent_public_submissions_apply_once_and_recover_the_same_receipt() -> Result {
    let candidate = candidate::select()?;
    let mut server = Server::start(&candidate.path)?;
    let owner = server.login()?;
    let task = super::start(&server, &owner, "compact")?;
    let before = status(&server, &owner, &task)?;
    let request = submission(&task)?;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let mut threads = Vec::new();
    for _ in 0..4 {
        let client = owner.clone();
        let request = request.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            client.call("rethlas_step", request)
        }));
    }
    let mut applied = Vec::new();
    for thread in threads {
        let value = thread.join().map_err(|_| "concurrent client panicked")??;
        if value["submission_receipt"]["replayed"] == false {
            super::advances(&task, &value)?;
            applied.push(value);
        } else if value["submission_receipt"]["replayed"] == true {
            require(
                value["writes_applied"] == 0,
                "concurrent replay applied writes",
            )?;
        } else {
            require(
                error_code(&value) == "RESULT_UNKNOWN",
                "unexpected concurrency result",
            )?;
        }
    }
    require(
        applied.len() == 1,
        "multiple public requests executed the same submission",
    )?;
    let next = applied.first().ok_or("missing winning submission")?;
    let after = status(&server, &owner, &task)?;
    require(
        after["transition_seq"].as_u64() == before["transition_seq"].as_u64().map(|n| n + 1),
        "concurrent duplicates changed the run more than once",
    )?;
    let resource = text(&request["writes"][0], "resource")?;
    let memory_before = memory(&server, &owner, next, resource)?;
    let replay = owner.call("rethlas_step", request.clone())?;
    assert_receipt(
        &replay,
        next["writes_applied"].as_u64().ok_or("write count")?,
    )?;
    require(
        memory(&server, &owner, next, resource)? == memory_before,
        "post-race replay appended memory",
    )?;
    super::cancel(&server, &owner, &task)?;
    server.stop()?;
    candidate.unchanged()
}

#[test]
fn partial_nonrecoverable_failure_stays_unknown_across_restart_and_fresh_tokens() -> Result {
    let candidate = candidate::select()?;
    let mut server = Server::start(&candidate.path)?;
    let owner = server.login()?;
    let task = super::start(&server, &owner, "compact")?;
    let alternate = server.call(&owner, "rethlas_step", json!({"run_id":task["run_id"]}))?;
    let request = submission(&task)?;
    // A published-file/failed-checkpoint ambiguity must remain unknown. A role
    // denial between writes is no longer a proxy for such uncertainty.
    let db = Connection::open(server.private_state_path()).map_err(|_| "fixture DB")?;
    db.execute_batch("CREATE TRIGGER block_write_ack BEFORE UPDATE ON step_checkpoints WHEN NEW.accepted_writes=1 AND OLD.accepted_writes<>NEW.accepted_writes BEGIN SELECT RAISE(ABORT,'fixture checkpoint failure'); END;")
        .map_err(|_| "fixture checkpoint trigger")?;
    drop(db);
    let unknown = server.call(&owner, "rethlas_step", request.clone())?;
    require(
        error_code(&unknown) == "RESULT_UNKNOWN" && unknown["ok"] == false,
        "unclassified partial failure did not stay unknown",
    )?;
    let resource = text(&request["writes"][0], "resource")?;
    let content = memory(&server, &owner, &task, resource)?;
    server.restart()?;
    let again = server.call(&owner, "rethlas_step", request.clone())?;
    require(
        error_code(&again) == "RESULT_UNKNOWN",
        "pending receipt disappeared after restart",
    )?;
    let fresh = server.call(&owner, "rethlas_step", json!({"run_id":task["run_id"]}))?;
    require(
        error_code(&fresh) == "RESULT_UNKNOWN" && fresh.get("capability").is_none(),
        "pending task refresh ran mechanical work or issued authority",
    )?;
    require(
        error_code(&server.call(&owner, "rethlas_step", submission(&alternate)?)?)
            == "RESULT_UNKNOWN",
        "fresh token bypassed pending-run guard",
    )?;
    require(
        memory(&server, &owner, &task, resource)? == content,
        "pending replay wrote memory",
    )?;
    super::cancel(&server, &owner, &task)?;
    server.stop()?;
    candidate.unchanged()
}
