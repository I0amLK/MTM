//! Actual candidate transactions in disposable state; no product fault switches.
use crate::support::candidate;
use crate::support::loopback::Server;
use crate::support::recovery::error_code;
use crate::support::{Result, require, submission, text};
use rusqlite::Connection;
use serde_json::{Value, json};

#[test]
fn manifest_and_acknowledgement_fail_as_one_transaction() -> Result {
    let candidate = candidate::select()?;
    let mut server = Server::start(&candidate.path)?;
    let owner = server.login()?;
    let assessment = super::start(&server, &owner, "compact")?;
    let task = server.call(&owner, "rethlas_step", submission(&assessment)?)?;
    require(
        task["state"] == "assemble",
        "fixture did not reach assembly",
    )?;
    let mut request = super::candidate_lifecycle::fixture_submission(&task, "compact", false)?;
    let db = Connection::open(server.private_state_path()).map_err(|_| "fixture database")?;
    db.execute_batch("CREATE TRIGGER db_ack_failure BEFORE UPDATE ON step_checkpoints WHEN NEW.accepted_writes=2 AND OLD.accepted_writes<>2 BEGIN SELECT RAISE(ABORT,'fixture ack'); END;")
        .map_err(|_| "fixture trigger")?;
    let failed = server.call(&owner, "rethlas_step", request.clone())?;
    require(
        error_code(&failed) == "RESULT_UNKNOWN",
        "fixture did not interrupt confirmation",
    )?;
    let manifest_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM proof_manifests WHERE run_id=?",
            [text(&task, "run_id")?],
            |r| r.get(0),
        )
        .map_err(|_| "fixture manifest count")?;
    require(
        manifest_count == 0,
        "database write survived its failed acknowledgement",
    )?;
    db.execute_batch("DROP TRIGGER db_ack_failure")
        .map_err(|_| "fixture cleanup")?;
    drop(db);
    server.force_restart()?;
    request["recover_only"] = json!(true);
    let recovered = server.call(&owner, "rethlas_step", request)?;
    require(
        recovered["submission_receipt"]["result"]["writes_applied"] == 1
            && recovered["writes_applied"] == 0
            && recovered.get("capability").is_none(),
        "recovery did not preserve only the proof write",
    )?;
    let current = server.call(&owner, "rethlas_step", json!({"run_id":task["run_id"]}))?;
    let mut correction =
        super::candidate_lifecycle::fixture_submission(&current, "compact", false)?;
    correction["writes"]
        .as_array_mut()
        .ok_or("fixture writes")?
        .remove(0);
    let next = server.call(&owner, "rethlas_step", correction)?;
    require(
        next["state"] == "verify",
        "retained proof could not be used by correction",
    )?;
    super::cancel(&server, &owner, &task)?;
    server.stop()?;
    candidate.unchanged()
}

fn retained(value: &Value, count: u64) -> Result {
    require(
        value["ok"] == true
            && value["writes_applied"] == 0
            && value["submission"]["ok"] == false
            && value["submission"]["complete"] == false
            && value["submission_receipt"]["result"]["writes_applied"] == count
            && value["submission_receipt"]["result"]["error_code"] == "SUBMISSION_INTERRUPTED"
            && value.get("capability").is_none()
            && value.get("context").is_none(),
        "recovery did not return a non-authorizing exact retained prefix",
    )
}

#[test]
fn audit_rollback_and_committed_audit_recover_without_rewriting_or_finalizing() -> Result {
    let candidate = candidate::select()?;
    for committed in [false, true] {
        let mut server = Server::start(&candidate.path)?;
        let owner = server.login()?;
        let start = server.call(&owner,"rethlas_start",json!({
            "problem_tex":"Fixed protocol fixture: equality is reflexive.","workflow_mode":"full",
            "register_result":false,"references":[{"name":"fixture.txt","content":"Fixed inline source fixture."}]
        }))?;
        require(start["ok"] == true, "reference fixture creation failed")?;
        let mut assembly =
            server.call(&owner, "rethlas_step", json!({"run_id":start["run_id"]}))?;
        // Registered references require the existing full route; do not bypass it.
        for _ in 0..4 {
            let request = super::candidate_lifecycle::fixture_submission(&assembly, "full", false)?;
            assembly = server.call(&owner, "rethlas_step", request)?;
            require(
                assembly["submission"]["ok"] == true,
                "full-route setup failed",
            )?;
        }
        require(
            assembly["state"] == "assemble",
            "full route did not reach assembly",
        )?;
        let db = Connection::open(server.private_state_path()).map_err(|_| "fixture DB")?;
        let reference: String = db
            .query_row(
                "SELECT reference_id FROM references_registry WHERE run_id=?",
                [text(&start, "run_id")?],
                |r| r.get(0),
            )
            .map_err(|_| "reference absent")?;
        let snapshot: String = db
            .query_row(
                "SELECT source_snapshot_id FROM source_snapshots WHERE reference_id=?",
                [&reference],
                |r| r.get(0),
            )
            .map_err(|_| "source snapshot absent")?;
        let mut assembly_request =
            super::candidate_lifecycle::fixture_submission(&assembly, "full", false)?;
        let manifest = assembly_request["writes"]
            .as_array_mut()
            .ok_or("fixture writes")?
            .iter_mut()
            .find(|w| w["resource"] == "proof_manifest")
            .ok_or("fixture manifest missing")?;
        manifest["content"]["reference_ids"] = json!([reference]);
        let task = server.call(&owner, "rethlas_step", assembly_request)?;
        require(task["state"] == "verify", "fixture did not enter verifier")?;
        let mut request = super::candidate_lifecycle::fixture_submission(&task, "full", false)?;
        request["writes"].as_array_mut().ok_or("fixture writes")?.push(json!({
            "resource":"reference_audit","content":{"reference_id":reference,"disposition":"SOURCE_VERIFIED",
            "evidence_basis":"stored_source_snapshot","evidence_locator":snapshot,"material":true,
            "assumptions_checked":true,"notation_checked":true,"source_checked":true,
            "notes":"Scripted fixture check, not independent mathematical verification"}
        }));
        // Neither fault is a product switch: only this temporary database is altered.
        db.execute_batch(if committed {
            "CREATE TRIGGER interrupt_database_step BEFORE UPDATE ON step_checkpoints WHEN NEW.phase='commit_ready' AND OLD.phase='running' BEGIN SELECT RAISE(ABORT,'fixture before action'); END;"
        } else {
            "CREATE TRIGGER interrupt_database_step BEFORE UPDATE ON step_checkpoints WHEN NEW.accepted_writes=4 AND OLD.accepted_writes<>4 BEGIN SELECT RAISE(ABORT,'fixture audit ack'); END;"
        }).map_err(|_| "fixture trigger")?;
        let failed = server.call(&owner, "rethlas_step", request.clone())?;
        require(
            error_code(&failed) == "RESULT_UNKNOWN",
            "fault did not preserve pending outcome",
        )?;
        let row: Option<String> = db.query_row("SELECT json_group_array(json_object('id',audit_id,'notes',notes,'created',created_at,'updated',updated_at,'proof',proof_sha256,'manifest',proof_manifest_sha256)) FROM reference_audits WHERE run_id=?",
            [text(&start,"run_id")?],|r|r.get(0)).map_err(|_| "audit projection")?;
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM reference_audits WHERE run_id=?",
                [text(&start, "run_id")?],
                |r| r.get(0),
            )
            .map_err(|_| "audit count")?;
        require(
            count == i64::from(committed),
            "audit and acknowledgement did not commit together",
        )?;
        let before = server.call(
            &owner,
            "rethlas_inspect",
            json!({"operation":"status","run_id":start["run_id"]}),
        )?;
        db.execute_batch("DROP TRIGGER interrupt_database_step")
            .map_err(|_| "fixture trigger cleanup")?;
        drop(db);
        server.force_restart()?;
        request["recover_only"] = json!(true);
        let prefix = if committed { 4 } else { 3 };
        let recovered = server.call(&owner, "rethlas_step", request.clone())?;
        retained(&recovered, prefix)?;
        let db =
            Connection::open(server.private_state_path()).map_err(|_| "reopened fixture DB")?;
        let after_row: Option<String> = db.query_row("SELECT json_group_array(json_object('id',audit_id,'notes',notes,'created',created_at,'updated',updated_at,'proof',proof_sha256,'manifest',proof_manifest_sha256)) FROM reference_audits WHERE run_id=?",
            [text(&start,"run_id")?],|r|r.get(0)).map_err(|_| "audit after recovery")?;
        require(row == after_row, "recovery rewrote the audit")?;
        let after = server.call(
            &owner,
            "rethlas_inspect",
            json!({"operation":"status","run_id":start["run_id"]}),
        )?;
        require(
            after["state"] == "verify"
                && after["transition_seq"] == before["transition_seq"]
                && after["pending_submission"].is_null(),
            "recovery executed the verification action",
        )?;
        let current = server.call(&owner, "rethlas_step", json!({"run_id":start["run_id"]}))?;
        let mut correction = request;
        correction
            .as_object_mut()
            .ok_or("request object")?
            .remove("recover_only");
        correction["capability"] = current["capability"].clone();
        correction["writes"] = Value::Array(
            correction["writes"]
                .as_array()
                .ok_or("writes")?
                .iter()
                .skip(prefix as usize)
                .cloned()
                .collect(),
        );
        let done = server.call(&owner, "rethlas_step", correction)?;
        require(
            done["state"] == "done" && done["submission"]["ok"] == true,
            "retained evidence did not allow ordinary verifier/finalizer completion",
        )?;
        server.stop()?;
    }
    candidate.unchanged()
}
