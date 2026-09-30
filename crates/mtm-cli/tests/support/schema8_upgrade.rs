//! Extra schema-7/8 assertions on state created by real disposable runtimes.
use crate::candidate_lifecycle::{PROBLEM, fixture_submission};
use crate::support::loopback::{Client, Server, sha256_file};
use crate::support::{Result, require, text};
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};
use std::path::PathBuf;

pub(super) const BASELINE_SHA256: &str =
    "f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034";

fn database(server: &Server) -> Result<Connection> {
    Connection::open_with_flags(
        server.private_state_path(),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|_| "schema-8 fixture read-only database")
}

fn revisions(server: &Server) -> Result<Vec<String>> {
    let db = database(server)?;
    let mut statement = db.prepare(
        "SELECT json_array(revision_id,claim_id,revision_number,statement_tex,evidence_status,lifecycle_status,source_run_id,proof_sha256,conditions_json,metadata_json,created_at) FROM claim_revisions WHERE claim_id='upgrade-legacy-claim' ORDER BY revision_number"
    ).map_err(|_| "legacy revision query")?;
    statement
        .query_map([], |row| row.get(0))
        .map_err(|_| "legacy revisions")?
        .collect::<std::result::Result<Vec<String>, _>>()
        .map_err(|_| "legacy revision image")
}

fn counts(server: &Server, run: &str) -> Result<(i64, i64)> {
    database(server)?.query_row(
        "SELECT (SELECT count(*) FROM transitions WHERE run_id=?1),(SELECT count(*) FROM step_receipts WHERE run_id=?1)",
        [run], |row| Ok((row.get(0)?, row.get(1)?))
    ).map_err(|_| "durable upgrade receipt counts")
}

fn registered_proof(server: &Server, owner: &Client, claim: &str, export: &str) -> Result<String> {
    let result = server.call(
        owner,
        "rethlas_control",
        json!({
            "action":"claim_create","project_id":"upgrade-project","claim_id":claim,
            "title":"Disposable upgrade claim","statement_tex":PROBLEM
        }),
    )?;
    require(result["ok"] == true, "upgrade claim creation failed")?;
    let started = server.call(
        owner,
        "rethlas_start",
        json!({
            "problem_tex":PROBLEM,"problem_id":claim,"workflow_mode":"compact",
            "register_result":true,"project_id":"upgrade-project","target_claim_id":claim,
            "export_path":export
        }),
    )?;
    require(started["ok"] == true, "upgrade project run creation failed")?;
    let run = text(&started, "run_id")?.to_owned();
    let mut task = server.call(owner, "rethlas_step", json!({"run_id":run}))?;
    // Scripted verification tests persistence, not independent mathematics.
    for _ in 0..6 {
        if task["state"] == "done" {
            return Ok(run);
        }
        task = server.call(
            owner,
            "rethlas_step",
            fixture_submission(&task, "compact", false)?,
        )?;
        require(task["ok"] == true, "upgrade proof fixture rejected")?;
    }
    Err("upgrade registered proof did not finish")
}

pub(super) struct Fixture {
    legacy_image: Vec<String>,
    proof: PathBuf,
    proof_hash: String,
    replay: Value,
    replay_run: String,
    receipt_counts: (i64, i64),
    memory: Value,
    memory_capability: String,
}

impl Fixture {
    pub(super) fn seed(server: &Server, owner: &Client) -> Result<Self> {
        let result = server.call(
            owner,
            "rethlas_control",
            json!({
                "action":"project_create","project_id":"upgrade-project","title":"Upgrade fixture"
            }),
        )?;
        require(result["ok"] == true, "upgrade project creation failed")?;
        let run = registered_proof(server, owner, "upgrade-legacy-claim", "upgrade/legacy.tex")?;
        let verified: i64 = database(server)?.query_row(
            "SELECT count(*) FROM claim_revisions WHERE source_run_id=? AND evidence_status='VERIFIED'",
            [&run], |row| row.get(0)
        ).map_err(|_| "legacy verified revision")?;
        require(verified == 1, "baseline did not promote verified revision")?;
        let proof = server.workspace_path().join("upgrade/legacy.tex");
        let proof_hash = sha256_file(&proof)?;
        let task = crate::start(server, owner, "compact")?;
        let replay_run = text(&task, "run_id")?.to_owned();
        let replay = fixture_submission(&task, "compact", false)?;
        let advanced = server.call(owner, "rethlas_step", replay.clone())?;
        require(
            advanced["state"] == "assemble",
            "baseline receipt run did not advance",
        )?;
        let memory_capability = text(&advanced, "capability")?.to_owned();
        let memory = server.call(
            owner,
            "rethlas_inspect",
            json!({
                "operation":"read","capability":memory_capability,
                "resource":"memory:generation:immediate_conclusions"
            }),
        )?;
        require(memory["ok"] == true, "baseline memory unreadable")?;
        Ok(Self {
            legacy_image: revisions(server)?,
            proof,
            proof_hash,
            receipt_counts: counts(server, &replay_run)?,
            replay,
            replay_run,
            memory: memory["content"].clone(),
            memory_capability,
        })
    }

    pub(super) fn check_migration(&self, server: &Server, owner: &Client) -> Result {
        require(
            revisions(server)? == self.legacy_image,
            "upgrade changed legacy revisions",
        )?;
        let db = database(server)?;
        for table in [
            "facts",
            "fact_edges",
            "fact_revocations",
            "memory_findings",
            "memory_finding_status",
        ] {
            let count: i64 = db
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .map_err(|_| "schema-8 table missing after migration")?;
            require(count == 0, "migration invented facts or finding status")?;
        }
        let backfilled: i64 = db
            .query_row(
                "SELECT count(*) FROM claim_revisions WHERE fact_id IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .map_err(|_| "migrated revision linkage")?;
        require(backfilled == 0, "legacy revision was backfilled")?;
        drop(db);
        let replayed = server.call(owner, "rethlas_step", self.replay.clone())?;
        require(
            replayed["ok"] == true
                && replayed["writes_applied"] == 0
                && replayed["submission_receipt"]["replayed"] == true
                && replayed["submission_receipt"]["grants_authority"] == false,
            "schema-7 completed submission not replayed as non-authorizing receipt",
        )?;
        require(
            counts(server, &self.replay_run)? == self.receipt_counts,
            "upgrade replay duplicated durable rows",
        )?;
        let memory = server.call(
            owner,
            "rethlas_inspect",
            json!({
                "operation":"read","capability":self.memory_capability,
                "resource":"memory:generation:immediate_conclusions"
            }),
        )?;
        require(
            memory["ok"] == true && memory["content"] == self.memory,
            "upgrade replay changed memory",
        )?;
        require(
            sha256_file(&self.proof)? == self.proof_hash,
            "upgrade changed verified proof",
        )
    }

    pub(super) fn exercise_new_fact(&self, server: &Server, owner: &Client) -> Result {
        let run = registered_proof(server, owner, "upgrade-new-claim", "upgrade/new.tex")?;
        let promoted: i64 = database(server)?.query_row(
            "SELECT count(*) FROM claim_revisions r JOIN facts f ON f.fact_id=r.fact_id WHERE r.source_run_id=? AND r.evidence_status='VERIFIED'",
            [&run], |row| row.get(0)
        ).map_err(|_| "new schema-8 fact promotion")?;
        require(promoted == 1, "upgraded runtime failed to promote new fact")?;
        require(
            revisions(server)? == self.legacy_image,
            "new fact modified legacy revision",
        )?;
        require(
            sha256_file(&self.proof)? == self.proof_hash,
            "new fact changed legacy proof",
        )
    }

    pub(super) fn check_restored(&self, server: &Server) -> Result {
        let tables: i64 = database(server)?.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('facts','fact_edges','fact_revocations','memory_findings','memory_finding_status')",
            [], |row| row.get(0)
        ).map_err(|_| "restored schema inventory")?;
        require(tables == 0, "restoration retained schema-8 tables")?;
        require(
            revisions(server)? == self.legacy_image,
            "restore changed original revisions",
        )?;
        require(
            counts(server, &self.replay_run)? == self.receipt_counts,
            "restore changed original receipts",
        )?;
        require(
            sha256_file(&self.proof)? == self.proof_hash,
            "restore changed legacy proof bytes",
        )?;
        require(
            !server.workspace_path().join("upgrade/new.tex").exists(),
            "restore retained new-only artifact",
        )
    }
}
