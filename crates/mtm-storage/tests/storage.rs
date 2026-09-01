use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex};

use mtm_contracts::{ReCtmError, WorkflowRole};
use mtm_storage::schema::V1_WORKFLOW_SCHEMA_SQL;
use mtm_storage::{
    CapabilityAuthority, Clock, IdSource, StateStore, StoreRuntime, TransitionRun,
    default_permissions,
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
    assert_eq!(store.schema_version()?, 2);
    assert_eq!(
        value_text(&store.get_run("legacy-run")?, "problem_id")?,
        "legacy-problem"
    );
    drop(store);

    let newer = temp.path().join("newer.sqlite3");
    let connection =
        Connection::open(&newer).map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    connection
        .execute_batch("PRAGMA user_version=3;")
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
        2
    );
    let connection =
        Connection::open(&rollback).map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    assert_eq!(version, 1);
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
