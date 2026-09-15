//! Faults affect disposable candidate state only. No product fault flags exist.
use crate::support::candidate;
use crate::support::loopback::{Client, Server};
use crate::support::recovery::error_code;
use crate::support::{Result, require, submission, text};
use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};

fn state(server: &Server, owner: &Client, run: &Value) -> Result<Value> {
    server.call(
        owner,
        "rethlas_inspect",
        json!({"operation":"status","run_id":run["run_id"]}),
    )
}

fn block_ack(db: &Connection, count: usize) -> Result {
    db.execute_batch(&format!("CREATE TRIGGER block_write_ack BEFORE UPDATE ON step_checkpoints WHEN NEW.accepted_writes={count} AND OLD.accepted_writes<>NEW.accepted_writes BEGIN SELECT RAISE(ABORT,'fixture checkpoint failure'); END;"))
        .map_err(|_| "fixture trigger failed")
}

fn path(server: &Server, task: &Value, relative: &str) -> Result<std::path::PathBuf> {
    Ok(server
        .private_state_path()
        .parent()
        .ok_or("private fixture path")?
        .join("runs")
        .join(text(task, "run_id")?)
        .join(relative))
}

fn recovered(value: &Value, count: u64) -> Result {
    require(
        value["ok"] == true
            && value["writes_applied"] == 0
            && value["submission"]["ok"] == false
            && value["submission"]["complete"] == false
            && value["submission_receipt"]["result"]["writes_applied"] == count
            && value["submission_receipt"]["result"]["error_code"] == "SUBMISSION_INTERRUPTED"
            && value.get("capability").is_none()
            && value.get("context").is_none(),
        "recovery was not a non-authorizing exact-prefix correction",
    )
}

#[test]
fn published_normalized_memory_survives_ack_failure_restart_and_concurrent_recovery() -> Result {
    let candidate = candidate::select()?;
    let mut server = Server::start(&candidate.path)?;
    let owner = server.login()?;
    let assess = super::start(&server, &owner, "full")?;
    let task = server.call(&owner, "rethlas_step", submission(&assess)?)?;
    require(task["state"] == "explore", "fixture did not enter explore")?;
    let before = state(&server, &owner, &task)?;
    let mut request = submission(&task)?;
    request["writes"] = json!([
        {"resource":"memory:generation:events","content":{"event_type":"notation_resolution","symbol":"=","resolution":"equality α","summary":"first typed record","evidence_ids":[]}},
        {"resource":"memory:generation:events","content":{"event_type":"notation_resolution","symbol":"n","resolution":"integer β","summary":"second typed record","evidence_ids":[]}}
    ]);
    let db = Connection::open(server.private_state_path()).map_err(|_| "fixture DB")?;
    block_ack(&db, 2)?;
    require(
        error_code(&server.call(&owner, "rethlas_step", request.clone())?) == "RESULT_UNKNOWN",
        "checkpoint failure not retained",
    )?;
    let file = path(&server, &task, "memory/generation/events.jsonl")?;
    let bytes = fs::read(&file).map_err(|_| "published fixture memory missing")?;
    let records = String::from_utf8(bytes.clone()).map_err(|_| "fixture UTF8")?;
    let records = records
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| "fixture JSONL")?;
    let last = records.iter().rev().take(2).collect::<Vec<_>>();
    require(
        last.len() == 2
            && last[0].get("record_id").is_some()
            && last[1].get("record_id").is_some()
            && last[0]["record_id"] != last[1]["record_id"],
        "normalized record IDs missing or duplicated",
    )?;
    let marker: String = db.query_row("SELECT j.marker_json FROM step_write_journals j JOIN step_receipts r USING(capability_sha256) WHERE r.run_id=? AND r.status='pending'", [text(&task,"run_id")?], |r| r.get(0)).map_err(|_| "write marker missing")?;
    require(
        !marker.contains("second typed record") && !marker.contains(text(&task, "capability")?),
        "journal leaked body or token",
    )?;
    db.execute_batch("DROP TRIGGER block_write_ack")
        .map_err(|_| "trigger cleanup")?;
    drop(db);
    server.force_restart()?;
    let other = server.login()?;
    request["recover_only"] = json!(true);
    require(
        server.call(&other, "rethlas_step", request.clone())?["ok"] == false,
        "cross-owner recovery accepted",
    )?;
    let mut changed = request.clone();
    changed["payload"]["changed"] = json!(true);
    require(
        error_code(&server.call(&owner, "rethlas_step", changed)?) == "IDEMPOTENCY_CONFLICT",
        "changed recovery accepted",
    )?;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let mut joins = Vec::new();
    // New authenticated clients after restart carry its current socket endpoint.
    let owner = server.relogin(&owner)?;
    for _ in 0..4 {
        let client = owner.clone();
        let args = request.clone();
        let barrier = barrier.clone();
        joins.push(std::thread::spawn(move || {
            barrier.wait();
            client.call("rethlas_step", args)
        }));
    }
    for join in joins {
        let value = join.join().map_err(|_| "recovery worker panicked")??;
        if error_code(&value) != "RESULT_UNKNOWN" {
            recovered(&value, 2)?;
        }
    }
    recovered(&server.call(&owner, "rethlas_step", request)?, 2)?;
    require(
        fs::read(&file).map_err(|_| "memory after recovery")? == bytes,
        "recovery duplicated or renormalized records",
    )?;
    let after = state(&server, &owner, &task)?;
    require(
        after["state"] == before["state"]
            && after["transition_seq"] == before["transition_seq"]
            && after["pending_submission"].is_null(),
        "recovery executed the action or left pending",
    )?;
    let current = server.call(&owner, "rethlas_step", json!({"run_id":task["run_id"]}))?;
    let mut correction = submission(&current)?;
    correction["writes"] = json!([]);
    require(
        server.call(&owner, "rethlas_step", correction)?["state"] == "propose_plans",
        "correction could not use retained records",
    )?;
    super::cancel(&server, &owner, &task)?;
    server.stop()?;
    candidate.unchanged()
}

#[test]
fn live_file_lock_and_conflicting_effect_bytes_never_clear_pending() -> Result {
    let candidate = candidate::select()?;
    let mut server = Server::start(&candidate.path)?;
    let owner = server.login()?;
    let task = super::start(&server, &owner, "compact")?;
    let mut request = submission(&task)?;
    let db = Connection::open(server.private_state_path()).map_err(|_| "fixture DB")?;
    block_ack(&db, 1)?;
    require(
        error_code(&server.call(&owner, "rethlas_step", request.clone())?) == "RESULT_UNKNOWN",
        "fault did not reach file checkpoint",
    )?;
    let relative: String = db.query_row("SELECT json_extract(marker_json,'$.evidence.relative_path') FROM step_write_journals j JOIN step_receipts r USING(capability_sha256) WHERE r.run_id=?",[text(&task,"run_id")?],|r|r.get(0)).map_err(|_|"file evidence absent")?;
    let lockpath = path(
        &server,
        &task,
        &format!(".write-locks/{:x}", Sha256::digest(relative.as_bytes())),
    )?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(lockpath)
        .map_err(|_| "fixture lock file")?;
    let held = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|_| "fixture file lock")?;
    request["recover_only"] = json!(true);
    require(
        error_code(&server.call(&owner, "rethlas_step", request.clone())?) == "RESULT_UNKNOWN",
        "live writer lock bypassed",
    )?;
    drop(held);
    fs::write(path(&server, &task, &relative)?, b"unrelated bytes\n")
        .map_err(|_| "fixture tamper")?;
    require(
        server.call(&owner, "rethlas_step", request.clone())?["ok"] == false,
        "conflicting memory adopted",
    )?;
    require(
        !state(&server, &owner, &task)?["pending_submission"].is_null(),
        "conflict cleared receipt",
    )?;
    super::cancel(&server, &owner, &task)?;
    require(
        server.call(&owner, "rethlas_step", request)?["ok"] == false,
        "cancellation manufactured successful recovery",
    )?;
    server.stop()?;
    candidate.unchanged()
}

#[test]
fn branch_write_recovery_preserves_domain_and_join_barrier() -> Result {
    let candidate = candidate::select()?;
    let mut server = Server::start(&candidate.path)?;
    let owner = server.login()?;
    let mut task = super::start(&server, &owner, "full")?;
    for _ in 0..3 {
        let request = super::candidate_lifecycle::fixture_submission(&task, "full", false)?;
        task = server.call(&owner, "rethlas_step", request)?;
        require(
            task["submission"]["ok"] == true,
            "branch setup submission failed",
        )?;
    }
    require(
        task["state"] == "direct_proving",
        "branch setup missed screening",
    )?;
    let mut direct = super::candidate_lifecycle::fixture_submission(&task, "full", false)?;
    let mut screening = serde_json::Map::new();
    for plan in task["context"]["active_plans"]
        .as_array()
        .ok_or("fixture plans")?
    {
        let mut results = serde_json::Map::new();
        for goal in plan["subgoals"].as_array().ok_or("fixture goals")? {
            results.insert(text(goal, "subgoal_id")?.into(), json!({"status":"stuck",
                "summary":"Controlled branch fixture","method":"direct","obstruction":"no_progress","evidence_ids":[]}));
        }
        screening.insert(text(plan, "plan_id")?.into(), Value::Object(results));
    }
    direct["payload"] = json!({"screening":screening});
    task = server.call(&owner, "rethlas_step", direct)?;
    require(
        task["state"] == "branch_run" && task["role"] == "branch",
        "branch fixture did not enter a branch",
    )?;
    let before = state(&server, &owner, &task)?;
    let branch = text(&task["context"], "branch_id")?;
    let branches = before["branches"].as_array().ok_or("branch list")?;
    require(branches.len() == 2, "fixture must keep two branch domains")?;
    let sibling = branches
        .iter()
        .find(|b| b["branch_id"] != branch)
        .ok_or("sibling absent")?;
    let sibling_id = text(sibling, "branch_id")?;
    let sibling_file = path(
        &server,
        &task,
        &format!("branches/{sibling_id}/memory/events.jsonl"),
    )?;
    require(
        !sibling_file.exists(),
        "sibling fixture memory unexpectedly exists",
    )?;
    let denied = server.call(
        &owner,
        "rethlas_inspect",
        json!({"operation":"read",
        "capability":task["capability"],"resource":format!("branch:{sibling_id}")}),
    )?;
    require(
        denied["ok"] == false && denied.get("content").is_none(),
        "sibling context crossed the branch firewall",
    )?;
    let mut request = json!({"run_id":task["run_id"],"capability":task["capability"],
        "action":"branch_complete","payload":{},"writes":[{"resource":"memory:branch:events",
        "content":{"summary":"Retained branch event, not a solved proof"}}]});
    let db = Connection::open(server.private_state_path()).map_err(|_| "fixture DB")?;
    block_ack(&db, 1)?;
    require(
        error_code(&server.call(&owner, "rethlas_step", request.clone())?) == "RESULT_UNKNOWN",
        "branch checkpoint fault missing",
    )?;
    let file = path(
        &server,
        &task,
        &format!("branches/{branch}/memory/events.jsonl"),
    )?;
    let bytes = fs::read(&file).map_err(|_| "branch event missing")?;
    db.execute_batch("DROP TRIGGER block_write_ack")
        .map_err(|_| "branch trigger cleanup")?;
    drop(db);
    server.force_restart()?;
    request["recover_only"] = json!(true);
    recovered(&server.call(&owner, "rethlas_step", request)?, 1)?;
    let after = state(&server, &owner, &task)?;
    require(
        after["state"] == "branch_run"
            && after["branches"] == before["branches"]
            && after["transition_seq"] == before["transition_seq"],
        "recovery sealed a branch or advanced join",
    )?;
    require(
        !sibling_file.exists() && fs::read(&file).map_err(|_| "branch bytes after")? == bytes,
        "recovery modified either branch memory",
    )?;
    let next = server.call(&owner, "rethlas_step", json!({"run_id":task["run_id"]}))?;
    require(
        next["context"]["branch_id"] == branch && next["role"] == "branch",
        "recovery selected a different domain",
    )?;
    super::cancel(&server, &owner, &task)?;
    server.stop()?;
    candidate.unchanged()
}

#[test]
fn proof_file_and_atomic_database_failure_preserve_the_exact_prefix() -> Result {
    let candidate = candidate::select()?;
    for (ack, corrupt_marker) in [(1, false), (2, false), (1, true)] {
        let mut server = Server::start(&candidate.path)?;
        let owner = server.login()?;
        let assess = super::start(&server, &owner, "compact")?;
        let task = server.call(&owner, "rethlas_step", submission(&assess)?)?;
        let mut request = super::candidate_lifecycle::fixture_submission(&task, "compact", false)?;
        let db = Connection::open(server.private_state_path()).map_err(|_| "fixture DB")?;
        if corrupt_marker {
            db.execute_batch("CREATE TRIGGER block_write_ack BEFORE UPDATE ON step_checkpoints WHEN NEW.accepted_writes=1 AND OLD.accepted_writes=0 BEGIN UPDATE step_write_journals SET marker_json='{}'; END;")
                .map_err(|_| "fixture corrupt acknowledgement trigger")?;
        } else {
            block_ack(&db, ack)?;
        }
        require(
            error_code(&server.call(&owner, "rethlas_step", request.clone())?) == "RESULT_UNKNOWN",
            "proof fault absent",
        )?;
        let file = path(&server, &task, "draft/proof.tex")?;
        let before = fs::read(&file).map_err(|_| "proof missing")?;
        db.execute_batch("DROP TRIGGER block_write_ack")
            .map_err(|_| "trigger removal")?;
        drop(db);
        server.force_restart()?;
        request["recover_only"] = json!(true);
        let result = server.call(&owner, "rethlas_step", request)?;
        // New manifest writes and their acknowledgements roll back together.
        // Legacy opaque journals remain covered separately by storage regressions.
        recovered(&result, 1)?;
        let db = Connection::open(server.private_state_path()).map_err(|_| "fixture DB")?;
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM proof_manifests WHERE run_id=?",
                [text(&task, "run_id")?],
                |r| r.get(0),
            )
            .map_err(|_| "manifest rollback count")?;
        require(count == 0, "unacknowledged manifest remained in database")?;
        require(
            fs::read(&file).map_err(|_| "proof after")? == before,
            "recovery changed proof",
        )?;
        require(
            state(&server, &owner, &task)?["state"] == "assemble",
            "recovery executed proof submission",
        )?;
        super::cancel(&server, &owner, &task)?;
        server.stop()?;
    }
    candidate.unchanged()
}
