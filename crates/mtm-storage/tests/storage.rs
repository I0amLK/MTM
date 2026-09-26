use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex};

use mtm_contracts::{ReCtmError, WorkflowRole};
use mtm_storage::schema::{
    SCHEMA_MIGRATIONS_TABLE_SQL, V1_WORKFLOW_SCHEMA_SQL, V2_RESEARCH_SCHEMA_SQL,
    V3_SUBMISSION_RECEIPTS_SQL, V4_RECOVERY_SQL, V5_CREATION_INITIALIZATION_SQL,
    V6_CALLER_WRITE_JOURNAL_SQL, V7_ATOMIC_ACTION_SQL,
};
use mtm_storage::{
    CapabilityAuthority, Clock, FactForPromotion, FindingForStorage, IdSource, StateStore,
    StoreRuntime, TransitionRun, default_permissions,
};
use rusqlite::Connection;
use serde_json::Value;
use tempfile::TempDir;

#[derive(Clone)]
struct FixedClock;

impl Clock for FixedClock {
    fn now_iso(&self) -> Result<String, ReCtmError> {
        Ok("2026-09-01T02:40:00.000Z".to_owned())
    }

    fn unix_seconds(&self) -> Result<i64, ReCtmError> {
        Ok(1_788_252_800)
    }
}

struct FixedIds {
    hex: Mutex<VecDeque<String>>,
    urlsafe: Mutex<VecDeque<String>>,
}

impl FixedIds {
    fn new(hex: &[&str], urlsafe: &[&str]) -> Self {
        Self {
            hex: Mutex::new(hex.iter().map(|value| (*value).to_owned()).collect()),
            urlsafe: Mutex::new(urlsafe.iter().map(|value| (*value).to_owned()).collect()),
        }
    }

    fn next(queue: &Mutex<VecDeque<String>>) -> Result<String, ReCtmError> {
        queue
            .lock()
            .map_err(|_| ReCtmError::new("TEST", "ID queue lock"))?
            .pop_front()
            .ok_or_else(|| ReCtmError::new("TEST", "ID queue empty"))
    }
}

impl IdSource for FixedIds {
    fn token_hex(&self, _bytes: usize) -> Result<String, ReCtmError> {
        Self::next(&self.hex)
    }

    fn token_urlsafe(&self, _bytes: usize) -> Result<String, ReCtmError> {
        Self::next(&self.urlsafe)
    }
}

fn runtime(hex: &[&str], urlsafe: &[&str]) -> StoreRuntime {
    StoreRuntime {
        clock: Arc::new(FixedClock),
        ids: Arc::new(FixedIds::new(hex, urlsafe)),
    }
}

fn value_text<'a>(value: &'a Value, key: &str) -> Result<&'a str, ReCtmError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| ReCtmError::new("TEST", format!("missing {key}")))
}

#[test]
fn historical_v1_migration_preserves_rows_and_rejects_newer_schema() -> Result<(), ReCtmError> {
    let temp = TempDir::new().map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    let path = temp.path().join("v1.sqlite3");
    let connection =
        Connection::open(&path).map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    connection
        .execute_batch(V1_WORKFLOW_SCHEMA_SQL)
        .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    connection
        .execute(
            "INSERT INTO runs(run_id, problem_id, owner_id, state, status, created_at, updated_at) VALUES('legacy-run','legacy-problem','owner','assess','active','old','old')",
            [],
        )
        .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    connection
        .execute_batch("PRAGMA user_version=1;")
        .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    drop(connection);

    let store = StateStore::open_with_runtime(&path, runtime(&[], &[]))?;
    assert_eq!(store.schema_version()?, 8);
    assert_eq!(
        value_text(&store.get_run("legacy-run")?, "problem_id")?,
        "legacy-problem"
    );
    drop(store);

    let newer = temp.path().join("newer.sqlite3");
    let connection =
        Connection::open(&newer).map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    connection
        .execute_batch("PRAGMA user_version=9;")
        .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    drop(connection);
    let newer_error = match StateStore::open_with_runtime(&newer, runtime(&[], &[])) {
        Ok(_) => return Err(ReCtmError::new("TEST", "newer schema was accepted")),
        Err(error) => error,
    };
    assert_eq!(newer_error.code, "STATE_SCHEMA_NEWER_THAN_RUNTIME");
    Ok(())
}

#[test]
fn failed_v2_migration_rolls_back_schema_and_version() -> Result<(), ReCtmError> {
    let temp = TempDir::new().map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    let path = temp.path().join("failed.sqlite3");
    let connection =
        Connection::open(&path).map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    connection
        .execute_batch("CREATE TABLE projects(x TEXT); PRAGMA user_version=1;")
        .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    drop(connection);
    assert!(StateStore::open_with_runtime(&path, runtime(&[], &[])).is_err());
    let inspection =
        Connection::open(&path).map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    let version: i64 = inspection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    let tables = inspection
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()
        })
        .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    assert_eq!(version, 1);
    assert_eq!(tables, vec!["projects".to_owned()]);
    Ok(())
}

fn linked_project_run(store: &StateStore, run_id: &str) -> Result<(String, String), ReCtmError> {
    store.create_project(
        "owner",
        "Project",
        Some("project-main"),
        &serde_json::json!({}),
    )?;
    store.create_claim(
        "owner",
        "project-main",
        "Claim",
        Some("claim-main"),
        &serde_json::json!({}),
    )?;
    let base = store.create_open_claim_revision("owner", "claim-main", "$1=1$.", &[], None)?;
    let snapshot = store.create_project_snapshot("project-main", "owner")?;
    store.create_run(
        run_id,
        "promotion",
        "owner",
        "done",
        &serde_json::json!({"workflow_protocol_version": 2}),
    )?;
    let base_revision = value_text(&base, "revision_id")?.to_owned();
    let snapshot_id = value_text(&snapshot, "snapshot_id")?.to_owned();
    store.link_run_to_project(
        run_id,
        "owner",
        "project-main",
        &snapshot_id,
        Some("claim-main"),
        Some(&base_revision),
        "compact",
        "compact",
        true,
    )?;
    Ok((base_revision, snapshot_id))
}

#[test]
fn promotion_failure_rolls_back_and_repeated_success_is_idempotent() -> Result<(), ReCtmError> {
    let temp = TempDir::new().map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    let store = StateStore::open_with_runtime(
        temp.path().join("state.sqlite3"),
        runtime(&["1111111111111111"], &[]),
    )?;
    let (base_revision, _) = linked_project_run(&store, "run-promote")?;
    assert_eq!(
        store
            .promote_verified_run(
                "run-promote",
                "owner",
                "$1=1$.",
                &"a".repeat(64),
                &[],
                &serde_json::json!({"dependency_revision_ids": ["missing"]}),
            )
            .map_err(|error| error.code),
        Err("DEPENDENCY_NOT_IN_PROJECT".to_owned())
    );
    let current = store
        .current_claim_revision("claim-main", "owner")?
        .ok_or_else(|| ReCtmError::new("TEST", "missing active revision"))?;
    assert_eq!(value_text(&current, "revision_id")?, base_revision);
    assert_eq!(
        store
            .get_project_run("run-promote", Some("owner"))?
            .and_then(|value| value.get("promotion_status").cloned()),
        Some(Value::String("pending".to_owned()))
    );
    let first = store.promote_verified_run(
        "run-promote",
        "owner",
        "$1=1$.",
        &"b".repeat(64),
        &[],
        &serde_json::json!({"dependency_revision_ids": []}),
    )?;
    let second = store.promote_verified_run(
        "run-promote",
        "owner",
        "$1=1$.",
        &"b".repeat(64),
        &[],
        &serde_json::json!({"dependency_revision_ids": []}),
    )?;
    assert_eq!(value_text(&first, "status")?, "promoted");
    assert_eq!(value_text(&second, "status")?, "already_promoted");
    assert_eq!(store.list_claim_revisions("claim-main", "owner")?.len(), 2);
    Ok(())
}

#[test]
fn capability_registry_epoch_owner_and_revocation_are_enforced() -> Result<(), ReCtmError> {
    let temp = TempDir::new().map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    let path = temp.path().join("capability.sqlite3");
    let store = Arc::new(StateStore::open_with_runtime(
        &path,
        runtime(
            &[],
            &["nonce-fixed-000000000001", "nonce-fixed-000000000002"],
        ),
    )?);
    store.create_run(
        "run-cap",
        "problem",
        "owner",
        "assess",
        &serde_json::json!({}),
    )?;
    store.create_domain(
        "domain-cap",
        "run-cap",
        "generator",
        None,
        None,
        &serde_json::json!({}),
    )?;
    let authority = CapabilityAuthority::new(&[b'c'; 32], Arc::clone(&store), 600, None)?;
    let permissions = default_permissions(WorkflowRole::Generator)
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    let token = authority.issue(
        "run-cap",
        "domain-cap",
        WorkflowRole::Generator,
        &permissions,
        "trace-issue",
        Some(600),
    )?;
    assert_eq!(
        authority
            .validate(
                &token,
                "other-owner",
                "read",
                "problem",
                "trace-owner",
                Some("run-cap"),
            )
            .map_err(|error| error.code),
        Err("CAPABILITY_OWNER_MISMATCH".to_owned())
    );
    let connection =
        Connection::open(&path).map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    connection
        .execute(
            "UPDATE capabilities SET permissions_json='[\"read:problem\"]' WHERE nonce='nonce-fixed-000000000001'",
            [],
        )
        .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    drop(connection);
    assert_eq!(
        authority
            .validate(
                &token,
                "owner",
                "read",
                "problem",
                "trace-registry",
                Some("run-cap"),
            )
            .map_err(|error| error.code),
        Err("CAPABILITY_REGISTRY_MISMATCH".to_owned())
    );
    let token = authority.issue(
        "run-cap",
        "domain-cap",
        WorkflowRole::Generator,
        &permissions,
        "trace-issue-2",
        Some(600),
    )?;
    authority.revoke(&token, "test", "trace-revoke")?;
    assert_eq!(
        authority
            .validate(
                &token,
                "owner",
                "read",
                "problem",
                "trace-revoked",
                Some("run-cap"),
            )
            .map_err(|error| error.code),
        Err("CAPABILITY_REVOKED".to_owned())
    );
    store.transition_run(TransitionRun {
        run_id: "run-cap",
        expected_state: "assess",
        after_state: "explore",
        trace_id: "trace-transition",
        actor: "generator",
        reason: "complete",
        evidence: &serde_json::json!({}),
        increment_epoch: true,
        status: None,
        latex_passed: None,
        verdict: None,
        sealed: None,
        round_delta: 0,
    })?;
    Ok(())
}

#[test]
fn database_snapshot_is_deterministic() -> Result<(), ReCtmError> {
    let temp = TempDir::new().map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    let store =
        StateStore::open_with_runtime(temp.path().join("snapshot.sqlite3"), runtime(&[], &[]))?;
    store.create_run(
        "run",
        "problem",
        "owner",
        "assess",
        &serde_json::json!({"b": 2, "a": 1}),
    )?;
    assert_eq!(store.database_snapshot()?, store.database_snapshot()?);
    Ok(())
}

#[test]
fn rollback_copy_remains_a_version_one_database() -> Result<(), ReCtmError> {
    let temp = TempDir::new().map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    let baseline = temp.path().join("baseline.sqlite3");
    make_v1(&baseline)?;
    let migrated = temp.path().join("migrated.sqlite3");
    let rollback = temp.path().join("rollback.sqlite3");
    std::fs::copy(&baseline, &migrated)
        .and_then(|_| std::fs::copy(&baseline, &rollback))
        .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    assert_eq!(
        StateStore::open_with_runtime(&migrated, runtime(&[], &[]))?.schema_version()?,
        8
    );
    let connection =
        Connection::open(&rollback).map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    assert_eq!(version, 1);
    Ok(())
}

#[test]
fn schema_seven_upgrades_without_backfilling_old_revisions() -> Result<(), ReCtmError> {
    let temp = TempDir::new().map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    let path = temp.path().join("v7.sqlite3");
    let connection =
        Connection::open(&path).map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    for sql in [
        V1_WORKFLOW_SCHEMA_SQL,
        SCHEMA_MIGRATIONS_TABLE_SQL,
        V2_RESEARCH_SCHEMA_SQL,
        V3_SUBMISSION_RECEIPTS_SQL,
        V4_RECOVERY_SQL,
        V5_CREATION_INITIALIZATION_SQL,
        V6_CALLER_WRITE_JOURNAL_SQL,
        V7_ATOMIC_ACTION_SQL,
    ] {
        connection
            .execute_batch(sql)
            .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    }
    connection
        .execute_batch("PRAGMA user_version=7;")
        .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    drop(connection);
    let store = StateStore::open_with_runtime(&path, runtime(&[], &[]))?;
    assert_eq!(store.schema_version()?, 8);
    assert!(store.project_fact_graph_operator("missing").is_err());
    drop(store);
    let read_only = StateStore::open_read_only(&path)?;
    assert_eq!(read_only.schema_version()?, 8);
    Ok(())
}

#[test]
fn verified_facts_are_atomic_idempotent_revocable_and_export_stably() -> Result<(), ReCtmError> {
    let temp = TempDir::new().map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    let path = temp.path().join("facts.sqlite3");
    let store = StateStore::open_with_runtime(
        &path,
        runtime(&["1111111111111111", "2222222222222222"], &[]),
    )?;
    let (base_revision, _) = linked_project_run(&store, "run-facts")?;
    let finding = FindingForStorage {
        finding_id: "a".repeat(64),
        kind: "conclusion".to_owned(),
        claim: "Target".to_owned(),
        evidence: "normalized research observation".to_owned(),
        verifiable: true,
        links_json: "{}".to_owned(),
    };
    store.insert_project_findings(
        "project-main",
        "run-facts",
        "owner",
        std::slice::from_ref(&finding),
    )?;
    store.insert_project_findings("project-main", "run-facts", "owner", &[finding])?;
    assert_eq!(
        store.list_project_findings("project-main", "owner")?.len(),
        1
    );
    let lemma = FactForPromotion {
        fact_id: "b".repeat(16),
        statement_tex: "Lemma".to_owned(),
        proof_tex: "lemma proof".to_owned(),
        intuition: String::new(),
        glossary_json: "{}".to_owned(),
        predecessors: vec![],
    };
    let target = FactForPromotion {
        fact_id: "c".repeat(16),
        statement_tex: "Target".to_owned(),
        proof_tex: "target proof".to_owned(),
        intuition: String::new(),
        glossary_json: "{}".to_owned(),
        predecessors: vec![lemma.fact_id.clone()],
    };
    let bad = FactForPromotion {
        predecessors: vec!["d".repeat(16)],
        ..target.clone()
    };
    assert_eq!(
        store
            .promote_verified_run_with_facts(
                "run-facts",
                "owner",
                "Target",
                &"f".repeat(64),
                &[],
                &serde_json::json!({"dependency_revision_ids":[]}),
                &[lemma.clone(), bad]
            )
            .map_err(|error| error.code),
        Err("FACT_GRAPH_CONFLICT".to_owned())
    );
    assert!(
        store
            .list_project_facts("project-main", "owner")?
            .is_empty()
    );
    assert_eq!(
        value_text(
            &store
                .current_claim_revision("claim-main", "owner")?
                .ok_or_else(|| ReCtmError::new("TEST", "missing revision"))?,
            "revision_id"
        )?,
        base_revision
    );
    let injection =
        Connection::open(&path).map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    injection.execute_batch("CREATE TRIGGER reject_fact_revision BEFORE INSERT ON claim_revisions WHEN NEW.fact_id IS NOT NULL BEGIN SELECT RAISE(ABORT, 'injected revision failure'); END;")
        .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    assert!(
        store
            .promote_verified_run_with_facts(
                "run-facts",
                "owner",
                "Target",
                &"f".repeat(64),
                &[],
                &serde_json::json!({"dependency_revision_ids":[]}),
                &[lemma.clone(), target.clone()],
            )
            .is_err()
    );
    assert!(
        store
            .list_project_facts("project-main", "owner")?
            .is_empty()
    );
    assert_eq!(
        store.list_project_findings("project-main", "owner")?[0]["status"],
        "active"
    );
    assert_eq!(
        store
            .current_claim_revision("claim-main", "owner")?
            .ok_or_else(|| ReCtmError::new("TEST", "missing revision after rollback"))?["revision_id"],
        base_revision
    );
    injection
        .execute_batch("DROP TRIGGER reject_fact_revision;")
        .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    let promoted = store.promote_verified_run_with_facts(
        "run-facts",
        "owner",
        "Target",
        &"f".repeat(64),
        &[],
        &serde_json::json!({"dependency_revision_ids":[]}),
        &[lemma.clone(), target.clone()],
    )?;
    assert_eq!(promoted["revision"]["fact_id"], target.fact_id);
    assert_eq!(
        store.list_project_findings("project-main", "owner")?[0]["status"],
        "verified"
    );
    let graph = store.project_fact_graph_operator("project-main")?;
    assert_eq!(
        serde_json::to_vec(&graph).ok(),
        serde_json::to_vec(&store.project_fact_graph_operator("project-main")?).ok()
    );
    assert_eq!(graph["graph"]["edges"].as_array().map(Vec::len), Some(1));
    injection.execute_batch("CREATE TRIGGER reject_fact_revocation BEFORE INSERT ON memory_finding_status WHEN NEW.status='superseded' BEGIN SELECT RAISE(ABORT, 'injected revocation failure'); END;")
        .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    assert!(
        store
            .revoke_project_fact(&lemma.fact_id, "operator", "invalid premise")
            .is_err()
    );
    assert_eq!(store.project_fact_graph_operator("project-main")?, graph);
    assert_eq!(
        store.list_project_findings("project-main", "owner")?[0]["status"],
        "verified"
    );
    injection
        .execute_batch("DROP TRIGGER reject_fact_revocation;")
        .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    let revoked = store.revoke_project_fact(&lemma.fact_id, "operator", "invalid premise")?;
    assert_eq!(
        revoked["revoked_fact_ids"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(
        store.revoke_project_fact(&lemma.fact_id, "operator", "repeat")?["revoked_fact_ids"],
        serde_json::json!([])
    );
    assert_eq!(
        store.list_project_findings("project-main", "owner")?[0]["status"],
        "superseded"
    );
    assert!(
        store
            .active_project_fact_ids("project-main", "owner")?
            .is_empty()
    );
    let snapshot = store.create_project_snapshot("project-main", "owner")?;
    store.create_run("run-again", "new", "owner", "done", &serde_json::json!({}))?;
    store.link_run_to_project(
        "run-again",
        "owner",
        "project-main",
        value_text(&snapshot, "snapshot_id")?,
        Some("claim-main"),
        promoted["revision"]["revision_id"].as_str(),
        "compact",
        "compact",
        true,
    )?;
    let next = FactForPromotion {
        fact_id: "e".repeat(16),
        statement_tex: "Next".to_owned(),
        proof_tex: "next proof".to_owned(),
        intuition: String::new(),
        glossary_json: "{}".to_owned(),
        predecessors: vec![lemma.fact_id],
    };
    assert_eq!(
        store
            .promote_verified_run_with_facts(
                "run-again",
                "owner",
                "Next",
                &"e".repeat(64),
                &[],
                &serde_json::json!({"dependency_revision_ids":[]}),
                &[next]
            )
            .map_err(|error| error.code),
        Err("FACT_GRAPH_CONFLICT".to_owned())
    );
    Ok(())
}

#[test]
fn fact_export_has_no_dangling_edges_during_concurrent_commits() -> Result<(), ReCtmError> {
    let temp = TempDir::new().map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    let path = temp.path().join("concurrent-facts.sqlite3");
    let store = StateStore::open_with_runtime(
        &path,
        runtime(&["1111111111111111", "2222222222222222"], &[]),
    )?;
    linked_project_run(&store, "run-facts")?;
    let root = FactForPromotion {
        fact_id: "a".repeat(16),
        statement_tex: "Root".to_owned(),
        proof_tex: "Root proof".to_owned(),
        intuition: String::new(),
        glossary_json: "{}".to_owned(),
        predecessors: vec![],
    };
    store.promote_verified_run_with_facts(
        "run-facts",
        "owner",
        "Root",
        &"f".repeat(64),
        &[],
        &serde_json::json!({"dependency_revision_ids":[]}),
        &[root],
    )?;
    let start = std::sync::Barrier::new(2);
    std::thread::scope(|scope| -> Result<(), ReCtmError> {
        let writer = scope.spawn(|| -> Result<(), ReCtmError> {
            let connection = Connection::open(&path)
                .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
            start.wait();
            for index in 1..=96 {
                connection.execute_batch(&format!(
                    "BEGIN IMMEDIATE;
                     INSERT INTO facts(fact_id,project_id,source_run_id,statement_tex,proof_tex,created_at)
                     VALUES('{index:016x}','project-main','run-facts','Child','Proof','2026-09-26');
                     INSERT INTO fact_edges(fact_id,predecessor_id) VALUES('{index:016x}','aaaaaaaaaaaaaaaa');
                     COMMIT;"
                )).map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
                std::thread::yield_now();
            }
            Ok(())
        });
        start.wait();
        for _ in 0..96 {
            let graph = store.project_fact_graph_operator("project-main")?;
            let nodes = graph["graph"]["nodes"]
                .as_object()
                .ok_or_else(|| ReCtmError::new("TEST", "missing graph nodes"))?;
            let edges = graph["graph"]["edges"]
                .as_array()
                .ok_or_else(|| ReCtmError::new("TEST", "missing graph edges"))?;
            assert_eq!(nodes.len(), edges.len() + 1);
            for edge in edges {
                assert!(nodes.contains_key(value_text(edge, "source")?));
                assert!(nodes.contains_key(value_text(edge, "target")?));
            }
        }
        writer
            .join()
            .map_err(|_| ReCtmError::new("TEST", "fact writer panicked"))??;
        Ok(())
    })?;
    let read_only = StateStore::open_read_only(&path)?;
    assert_eq!(
        store.project_fact_graph_operator("project-main")?,
        read_only.project_fact_graph_operator("project-main")?
    );
    Ok(())
}

fn make_v1(path: &Path) -> Result<(), ReCtmError> {
    let connection =
        Connection::open(path).map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    connection
        .execute_batch(V1_WORKFLOW_SCHEMA_SQL)
        .and_then(|_| connection.execute_batch("PRAGMA user_version=1;"))
        .map_err(|error| ReCtmError::new("TEST", error.to_string()))
}
