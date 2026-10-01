//! Real OAuth/MCP on owned disposable state; no production fault switches.
use crate::support::candidate;
use crate::support::loopback::Server;
use crate::support::recovery::error_code;
use crate::support::{Result, require, submission, text};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::sync::{Arc, Barrier};

fn creation(key: &str) -> Value {
    json!({"problem_id":"e2-fixture","problem_tex":"Fixture: 1=1",
        "workflow_mode":"compact","register_result":false,"creation_key":key})
}

#[test]
fn keyed_creation_races_restart_and_independent_intent_are_distinct() -> Result {
    let candidate = candidate::select()?;
    let mut server = Server::start(&candidate.path)?;
    let owner = server.login()?;
    let key = "mtm016-e2-unique-creation-01";
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let owner = owner.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            owner.call("rethlas_start", creation(key))
        }));
    }
    let mut created = Vec::new();
    for handle in handles {
        let value = handle.join().map_err(|_| "creation client panicked")??;
        if value["runs_created"] == 1 {
            created.push(value);
        } else {
            require(
                value["creation_receipt"]["replayed"] == true
                    || error_code(&value) == "CREATION_RESULT_UNKNOWN",
                "unexpected concurrent creation outcome",
            )?;
        }
    }
    require(created.len() == 1, "creation key produced multiple runs")?;
    let first = created.first().ok_or("missing first creation")?;
    // Deliberately discard the result at the caller boundary, then actually restart.
    server.restart()?;
    let replay = server.call(&owner, "rethlas_start", creation(key))?;
    require(
        replay["run_id"] == first["run_id"]
            && replay["runs_created"] == 0
            && replay["state_is_historical"] == true
            && replay.get("capability").is_none(),
        "restart lost creation identity",
    )?;
    let mut changed = creation(key);
    changed["problem_tex"] = json!("different fixture input");
    require(
        error_code(&server.call(&owner, "rethlas_start", changed)?) == "IDEMPOTENCY_CONFLICT",
        "changed creation input accepted",
    )?;
    let independent = server.call(
        &owner,
        "rethlas_start",
        creation("mtm016-e2-unique-creation-02"),
    )?;
    require(
        independent["run_id"] != first["run_id"] && independent["runs_created"] == 1,
        "different intent collapsed into old run",
    )?;
    let mut unkeyed = creation(key);
    unkeyed
        .as_object_mut()
        .ok_or("fixture object")?
        .remove("creation_key");
    let a = server.call(&owner, "rethlas_start", unkeyed.clone())?;
    let b = server.call(&owner, "rethlas_start", unkeyed)?;
    require(
        a["run_id"] != b["run_id"],
        "unkeyed intentional starts were deduplicated",
    )?;
    let other = server.login()?;
    let foreign = server.call(&other, "rethlas_start", creation(key))?;
    require(
        foreign["run_id"] != first["run_id"],
        "another owner recovered a foreign run",
    )?;
    let db = Connection::open(server.private_state_path()).map_err(|_| "fixture database")?;
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM creation_receipts", [], |r| r.get(0))
        .map_err(|_| "creation count")?;
    require(count == 3, "wrong number of durable creation identities")?;
    let persisted: String = db
        .query_row(
            "SELECT group_concat(key_sha256 || request_sha256) FROM creation_receipts",
            [],
            |r| r.get(0),
        )
        .map_err(|_| "creation digests")?;
    require(
        !persisted.contains(key) && !persisted.contains("Fixture"),
        "raw creation key or problem persisted in receipt",
    )?;
    drop(db);
    for run in [first, &independent, &a, &b] {
        super::cancel(&server, &owner, run)?;
    }
    super::cancel(&server, &other, &foreign)?;
    let after_cancel = server.call(&owner, "rethlas_start", creation(key))?;
    require(
        after_cancel["run_id"] == first["run_id"] && after_cancel["runs_created"] == 0,
        "replay recreated a cancelled run",
    )?;
    server.stop()?;
    candidate.unchanged()
}

#[test]
fn recovery_only_never_executes_missing_work_and_reconciles_completed_prefix() -> Result {
    let candidate = candidate::select()?;
    let mut server = Server::start(&candidate.path)?;
    let owner = server.login()?;
    let task = super::start(&server, &owner, "compact")?;
    let mut request = submission(&task)?;
    request["recover_only"] = json!(true);
    let absent = server.call(&owner, "rethlas_step", request.clone())?;
    require(
        error_code(&absent) == "SUBMISSION_RECEIPT_NOT_FOUND",
        "recovery executed a new submission",
    )?;
    let state = server.call(
        &owner,
        "rethlas_inspect",
        json!({"operation":"status","run_id":task["run_id"]}),
    )?;
    require(
        state["state"] == "assess" && state["pending_submission"].is_null(),
        "missing recovery reserved or advanced",
    )?;
    let initial_sequence = state["transition_seq"].clone();
    request
        .as_object_mut()
        .ok_or("fixture request")?
        .remove("recover_only");
    // Pick one valid server-issued record; the default template may include
    // multiple independent records and is not this interruption fixture's size.
    let first = request["writes"]
        .as_array()
        .ok_or("fixture writes")?
        .iter()
        .find(|write| write["resource"] == "memory:generation:immediate_conclusions")
        .cloned()
        .ok_or("fixture first record")?;
    request["writes"] = json!([first]);
    let retained = request["writes"].as_array().ok_or("fixture writes")?.len();
    require(retained == 1, "fixture must retain exactly its first write")?;
    request["writes"].as_array_mut().ok_or("fixture writes")?.push(json!({
        "resource":"memory:generation:immediate_conclusions","content":{"summary":"second record must remain unexecuted"}}));
    // Interrupt the next legal write before its file effect is enrolled. The
    // transaction rolls back to Between with the earlier prefix acknowledged.
    // A role denial is now a completed correction, not an interruption fixture.
    let db = Connection::open(server.private_state_path()).map_err(|_| "fixture database")?;
    db.execute_batch(&format!("CREATE TRIGGER e2_block_write_begin BEFORE UPDATE ON step_write_journals WHEN json_extract(NEW.marker_json,'$.kind')='file' AND (SELECT accepted_writes FROM step_checkpoints WHERE capability_sha256=NEW.capability_sha256)={retained} BEGIN SELECT RAISE(ABORT,'fixture next write interruption'); END;"))
        .map_err(|_| "fixture write interruption")?;
    let unknown = server.call(&owner, "rethlas_step", request.clone())?;
    require(
        error_code(&unknown) == "RESULT_UNKNOWN",
        "partial failure lost uncertainty",
    )?;
    let before_memory = server.call(&owner, "rethlas_inspect", json!({"operation":"read","capability":task["capability"],"resource":"memory:generation:immediate_conclusions"}))?;
    require(
        before_memory["ok"] == true,
        "fixture prefix observation failed",
    )?;
    db.execute_batch("DROP TRIGGER e2_block_write_begin")
        .map_err(|_| "fixture trigger cleanup")?;
    drop(db);
    request["recover_only"] = json!(true);
    let recovered = server.call(&owner, "rethlas_step", request)?;
    require(
        recovered["writes_applied"] == 0
            && recovered["submission"]["ok"] == false
            && recovered["submission_receipt"]["result"]["error_code"] == "SUBMISSION_INTERRUPTED"
            && recovered["submission_receipt"]["result"]["writes_applied"] == retained,
        "recovery did not preserve the exact accepted prefix as a correction",
    )?;
    let state = server.call(
        &owner,
        "rethlas_inspect",
        json!({"operation":"status","run_id":task["run_id"]}),
    )?;
    require(
        state["pending_submission"].is_null()
            && state["state"] == "assess"
            && state["transition_seq"] == initial_sequence,
        "prefix recovery advanced workflow or retained a false pending blocker",
    )?;
    let memory = server.call(&owner, "rethlas_inspect", json!({"operation":"read","capability":task["capability"],"resource":"memory:generation:immediate_conclusions"}))?;
    require(
        memory["ok"] == true
            && memory["content"] == before_memory["content"]
            && !memory["content"]
                .to_string()
                .contains("second record must remain unexecuted"),
        "recovery executed the missing caller write",
    )?;
    super::cancel(&server, &owner, &task)?;
    server.stop()?;
    candidate.unchanged()
}

#[test]
fn committed_step_is_recoverable_when_next_task_construction_fails() -> Result {
    let candidate = candidate::select()?;
    let mut server = Server::start(&candidate.path)?;
    let owner = server.login()?;
    let task = super::start(&server, &owner, "compact")?;
    let request = submission(&task)?;
    let db = Connection::open(server.private_state_path()).map_err(|_| "fixture database")?;
    // Inject only into this fixture's private database. Product has no fault flag.
    db.execute_batch("CREATE TRIGGER e2_block_next_task BEFORE INSERT ON domains WHEN NEW.role='assembler' BEGIN SELECT RAISE(ABORT,'fixture next task unavailable'); END;")
        .map_err(|_| "fixture trigger")?;
    let result = server.call(&owner, "rethlas_step", request.clone())?;
    let expected = request["writes"].as_array().ok_or("fixture writes")?.len() as u64;
    require(
        result["ok"] == true
            && result["writes_applied"] == expected
            && result["submission_receipt"]["replayed"] == false
            && result["task_required"] == true
            && result.get("capability").is_none(),
        "post-commit task error was mislabelled unknown or zero-write",
    )?;
    let pending: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM step_receipts WHERE status='pending'",
            [],
            |r| r.get(0),
        )
        .map_err(|_| "pending count")?;
    require(pending == 0, "committed transition left a pending blocker")?;
    db.execute_batch("DROP TRIGGER e2_block_next_task;")
        .map_err(|_| "fixture trigger cleanup")?;
    drop(db);
    server.restart()?;
    let replay = server.call(&owner, "rethlas_step", request)?;
    require(
        replay["writes_applied"] == 0 && replay["submission_receipt"]["replayed"] == true,
        "restart repeated committed writes",
    )?;
    let next = server.call(&owner, "rethlas_step", json!({"run_id":task["run_id"]}))?;
    require(
        next["state"] == "assemble" && text(&next, "capability").is_ok(),
        "next task could not resume from certified transition",
    )?;
    super::cancel(&server, &owner, &task)?;
    server.stop()?;
    candidate.unchanged()
}
