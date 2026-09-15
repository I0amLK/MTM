//! Fault injection affects only owned temporary fixture databases and input files.
use crate::support::candidate;
use crate::support::loopback::{Client, Server};
use crate::support::recovery::error_code;
use crate::support::{Result, require, submission};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::MetadataExt;

fn request() -> Value {
    json!({"problem_tex":"Initialization fixture α","problem_id":"creation-resume",
        "creation_key":"initialization-resume-fixture-01","workflow_mode":"full","register_result":false,
        "project_id":"project-fixture","target_claim_id":"claim-fixture",
        "references":[{"name":"reference.txt","content":"Private inline fixture β","source":"inline"}]})
}

fn project(server: &Server, owner: &Client) -> Result {
    let project = server.call(
        owner,
        "rethlas_control",
        json!({"action":"project_create","project_id":"project-fixture","title":"Fixture"}),
    )?;
    require(project["ok"] == true, "fixture project creation failed")?;
    let claim = server.call(owner, "rethlas_control", json!({"action":"claim_create","project_id":"project-fixture","claim_id":"claim-fixture","title":"Fixture claim","statement_tex":"Fixture revision"}))?;
    require(claim["ok"] == true, "fixture claim creation failed")
}

fn count(db: &Connection, table: &str) -> Result<i64> {
    require(
        [
            "runs",
            "project_snapshots",
            "project_runs",
            "references_registry",
            "source_snapshots",
            "transitions",
        ]
        .contains(&table),
        "invalid fixture table",
    )?;
    db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .map_err(|_| "fixture count failed")
}

fn run_id(db: &Connection) -> Result<String> {
    db.query_row("SELECT run_id FROM creation_receipts", [], |r| r.get(0))
        .map_err(|_| "creation identity not durable")
}

const BLOCK_TRANSITION: &str = "CREATE TRIGGER block_initial_transition BEFORE INSERT ON transitions WHEN NEW.before_state='created' BEGIN SELECT RAISE(ABORT,'fixture boundary'); END;";

#[test]
fn interrupted_creation_reuses_files_project_snapshot_and_references_after_forced_restart() -> Result
{
    let candidate = candidate::select()?;
    for after_database in [false, true] {
        let mut server = Server::start(&candidate.path)?;
        let owner = server.login()?;
        project(&server, &owner)?;
        let db = Connection::open(server.private_state_path()).map_err(|_| "fixture database")?;
        db.execute_batch(if after_database {BLOCK_TRANSITION} else {
            "CREATE TRIGGER block_sources BEFORE INSERT ON source_snapshots BEGIN SELECT RAISE(ABORT,'fixture sources'); END;"
        }).map_err(|_| "fixture trigger")?;
        require(
            server.call(&owner, "rethlas_start", request())?["ok"] == false,
            "injected initialization failure was hidden",
        )?;
        let run = run_id(&db)?;
        for table in [
            "runs",
            "project_snapshots",
            "project_runs",
            "references_registry",
            "source_snapshots",
        ] {
            require(
                count(&db, table)? == i64::from(after_database),
                "initialization DB transaction was partial",
            )?;
        }
        require(
            count(&db, "transitions")? == 0,
            "failed initialization advanced state",
        )?;
        let private = server
            .private_state_path()
            .parent()
            .ok_or("fixture path")?
            .join("runs")
            .join(&run);
        let problem = private.join("input/problem.tex");
        let inode = fs::metadata(&problem)
            .map_err(|_| "published problem missing")?
            .ino();
        let snapshot_before: Option<String> = db
            .query_row(
                "SELECT group_concat(snapshot_id || revisions_json) FROM project_snapshots",
                [],
                |r| r.get(0),
            )
            .map_err(|_| "snapshot read")?;
        // A separate process owns this lock while the actual server receives the retry.
        let held = OpenOptions::new()
            .read(true)
            .write(true)
            .open(private.join(".creation.lock"))
            .map_err(|_| "fixture lock")?;
        let held = nix::fcntl::Flock::lock(held, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .map_err(|_| "fixture lock acquisition")?;
        require(
            error_code(&server.call(&owner, "rethlas_start", request())?)
                == "CREATION_RESULT_UNKNOWN",
            "server ignored live initialization lock",
        )?;
        drop(held);
        db.execute_batch(if after_database {
            "DROP TRIGGER block_initial_transition"
        } else {
            "DROP TRIGGER block_sources"
        })
        .map_err(|_| "fixture trigger removal")?;
        // Change project state after the selected snapshot: a retry must keep its old snapshot.
        if after_database {
            db.execute(
                "UPDATE claim_revisions SET statement_tex='later independent project edit'",
                [],
            )
            .map_err(|_| "fixture project edit")?;
        }
        drop(db);
        server.force_restart()?;
        let recovered = server.call(&owner, "rethlas_start", request())?;
        require(
            recovered["ok"] == true
                && recovered["run_id"] == run
                && recovered["creation_resumed"] == true,
            "same creation identity did not resume",
        )?;
        require(
            fs::metadata(&problem)
                .map_err(|_| "problem metadata")?
                .ino()
                == inode
                && fs::read_to_string(&problem).map_err(|_| "problem bytes")?
                    == "Initialization fixture α",
            "recovery replaced existing input",
        )?;
        let db = Connection::open(server.private_state_path())
            .map_err(|_| "fixture reopened database")?;
        for table in [
            "runs",
            "project_snapshots",
            "project_runs",
            "references_registry",
            "source_snapshots",
            "transitions",
        ] {
            require(
                count(&db, table)? == 1,
                "recovery duplicated initialization rows",
            )?;
        }
        if let Some(before) = snapshot_before {
            let after: String = db
                .query_row(
                    "SELECT snapshot_id || revisions_json FROM project_snapshots",
                    [],
                    |r| r.get(0),
                )
                .map_err(|_| "snapshot after")?;
            require(
                before == after,
                "retry selected a different project snapshot",
            )?;
        }
        drop(db);
        let again = server.call(&owner, "rethlas_start", request())?;
        require(
            again["run_id"] == run
                && again["runs_created"] == 0
                && again.get("capability").is_none(),
            "completed creation did not remain a read-only replay",
        )?;
        let task = server.call(&owner, "rethlas_step", json!({"run_id":run}))?;
        let advanced = server.call(&owner, "rethlas_step", submission(&task)?)?;
        super::advances(&task, &advanced)?;
        super::cancel(&server, &owner, &task)?;
        server.stop()?;
    }
    candidate.unchanged()
}

#[test]
fn conflicting_initialization_is_not_rewritten_and_legacy_pending_is_not_adopted() -> Result {
    let candidate = candidate::select()?;
    for tamper in ["input", "database", "legacy"] {
        let mut server = Server::start(&candidate.path)?;
        let owner = server.login()?;
        project(&server, &owner)?;
        let db = Connection::open(server.private_state_path()).map_err(|_| "fixture database")?;
        db.execute_batch(BLOCK_TRANSITION)
            .map_err(|_| "fixture trigger")?;
        require(
            server.call(&owner, "rethlas_start", request())?["ok"] == false,
            "fixture boundary not reached",
        )?;
        let run = run_id(&db)?;
        let input = server
            .private_state_path()
            .parent()
            .ok_or("fixture path")?
            .join("runs")
            .join(&run)
            .join("input/problem.tex");
        match tamper {
            "input" => {
                fs::write(&input, "unrelated private bytes").map_err(|_| "fixture input edit")?
            }
            "database" => {
                db.execute("UPDATE runs SET metadata_json='{}'", [])
                    .map_err(|_| "fixture database edit")?;
            }
            _ => {
                db.execute("DELETE FROM creation_initializations", [])
                    .map_err(|_| "fixture legacy marker")?;
            }
        }
        db.execute_batch("DROP TRIGGER block_initial_transition")
            .map_err(|_| "fixture trigger removal")?;
        drop(db);
        server.force_restart()?;
        let rejected = server.call(&owner, "rethlas_start", request())?;
        require(
            rejected["ok"] == false && rejected.get("capability").is_none(),
            "conflicting initialization was adopted",
        )?;
        if tamper == "input" {
            require(
                fs::read_to_string(input).map_err(|_| "fixture input read")?
                    == "unrelated private bytes",
                "conflicting bytes overwritten",
            )?;
        }
        let db = Connection::open(server.private_state_path())
            .map_err(|_| "fixture reopened database")?;
        require(
            count(&db, "runs")? == 1 && count(&db, "transitions")? == 0,
            "failed recovery duplicated or advanced run",
        )?;
        drop(db);
        server.stop()?;
    }
    candidate.unchanged()
}
