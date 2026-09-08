use std::error::Error;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Barrier};

use mtm_contracts::{ReCtmError, WorkflowRole, WorkflowState};
use mtm_storage::schema::{
    SCHEMA_MIGRATIONS_TABLE_SQL, V1_WORKFLOW_SCHEMA_SQL, V2_RESEARCH_SCHEMA_SQL,
};
use mtm_storage::{
    CapabilityAuthority, Clock, StateStore, StoreRuntime, SubmissionDisposition,
    SubmissionReservation, SubmissionResult, SubmissionSlot, default_permissions,
};
use rusqlite::Connection;
use serde_json::json;

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

struct TestClock(AtomicI64);
impl Clock for TestClock {
    fn now_iso(&self) -> std::result::Result<String, ReCtmError> {
        Ok("2026-09-08T12:00:00Z".into())
    }
    fn unix_seconds(&self) -> std::result::Result<i64, ReCtmError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    store: Arc<StateStore>,
    authority: CapabilityAuthority,
    clock: Arc<TestClock>,
}

impl Fixture {
    fn new() -> Result<Self> {
        let root = tempfile::tempdir()?;
        let clock = Arc::new(TestClock(AtomicI64::new(1000)));
        let store = Arc::new(StateStore::open_with_runtime(
            root.path().join("state.sqlite3"),
            StoreRuntime {
                clock: clock.clone(),
                ..StoreRuntime::default()
            },
        )?);
        store.create_run("run-a", "problem", "owner-a", "assess", &json!({}))?;
        store.create_domain("domain-a", "run-a", "generator", None, None, &json!({}))?;
        let authority = CapabilityAuthority::new(&[7; 32], store.clone(), 600, None)?;
        Ok(Self {
            _root: root,
            store,
            authority,
            clock,
        })
    }

    fn token(&self) -> Result<String> {
        Ok(self.authority.issue(
            "run-a",
            "domain-a",
            WorkflowRole::Generator,
            &default_permissions(WorkflowRole::Generator)
                .iter()
                .map(|s| (*s).to_owned())
                .collect::<Vec<_>>(),
            "issue",
            None,
        )?)
    }

    fn reserve(&self, token: &str) -> Result<SubmissionReservation> {
        let authorized = self
            .authority
            .authorize_submission(token, "owner-a", "run-a", "submit")?;
        match self
            .store
            .reserve_submission(&authorized, &"a".repeat(64), &"b".repeat(64))?
        {
            SubmissionSlot::Reserved(reservation) => Ok(reservation),
            SubmissionSlot::Existing(_) => Err("unexpected existing receipt".into()),
        }
    }
}

fn completion() -> SubmissionResult {
    SubmissionResult {
        disposition: SubmissionDisposition::Applied,
        state: WorkflowState::Assemble,
        writes_applied: 2,
        complete: true,
        error_code: None,
    }
}

#[test]
fn completed_receipt_survives_reopen_without_storing_credentials_or_body() -> Result {
    let fixture = Fixture::new()?;
    let token = fixture.token()?;
    let reserved = fixture.reserve(&token)?;
    let receipt = fixture.store.complete_submission(reserved, &completion())?;
    assert_eq!(receipt.result(), Some(&completion()));
    fixture.authority.revoke(&token, "test", "revoked")?;
    fixture.clock.0.store(5000, Ordering::SeqCst);
    assert!(
        fixture
            .authority
            .authorize_submission(&token, "owner-a", "run-a", "new-write")
            .is_err()
    );
    let reopened = Arc::new(StateStore::open_with_runtime(
        fixture.store.path(),
        fixture.store.runtime(),
    )?);
    let authority = CapabilityAuthority::new(&[7; 32], reopened.clone(), 600, None)?;
    let receipt = authority
        .submission_receipt(&token, "owner-a", "run-a", &"a".repeat(64), &"b".repeat(64))?
        .ok_or("receipt missing")?;
    assert_eq!(receipt.result(), Some(&completion()));
    let snapshot = reopened.database_snapshot()?;
    let text = snapshot["tables"]["step_receipts"].to_string();
    assert!(!text.contains(&token));
    for secret_field in [
        "capability\"",
        "proof",
        "context",
        "payload",
        "permissions",
        "nonce",
    ] {
        assert!(!text.contains(secret_field));
    }
    assert_eq!(
        snapshot["tables"]["step_receipts"]
            .as_array()
            .ok_or("table")?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn lookup_is_bound_to_owner_run_workspace_request_and_current_signer() -> Result {
    let fixture = Fixture::new()?;
    let token = fixture.token()?;
    fixture
        .store
        .complete_submission(fixture.reserve(&token)?, &completion())?;
    for (owner, run) in [("other", "run-a"), ("owner-a", "other-run")] {
        assert!(
            fixture
                .authority
                .submission_receipt(&token, owner, run, &"a".repeat(64), &"b".repeat(64))?
                .is_none()
        );
    }
    for (workspace, request, code) in [
        (
            "c".repeat(64),
            "b".repeat(64),
            "SUBMISSION_WORKSPACE_MISMATCH",
        ),
        ("a".repeat(64), "c".repeat(64), "IDEMPOTENCY_CONFLICT"),
    ] {
        let result = fixture
            .authority
            .submission_receipt(&token, "owner-a", "run-a", &workspace, &request);
        assert_eq!(result.err().ok_or("expected conflict")?.code, code);
    }
    let other_signer = CapabilityAuthority::new(&[8; 32], fixture.store.clone(), 600, None)?;
    assert!(
        other_signer
            .submission_receipt(&token, "owner-a", "run-a", &"a".repeat(64), &"b".repeat(64))?
            .is_none()
    );
    let mut changed = token.clone();
    changed.pop();
    assert!(
        fixture
            .authority
            .submission_receipt(
                &changed,
                "owner-a",
                "run-a",
                &"a".repeat(64),
                &"b".repeat(64)
            )?
            .is_none()
    );
    Connection::open(fixture.store.path())?.execute(
        "UPDATE capabilities SET permissions_json='[\"read:problem\"]'",
        [],
    )?;
    assert!(
        fixture
            .authority
            .submission_receipt(&token, "owner-a", "run-a", &"a".repeat(64), &"b".repeat(64))?
            .is_none()
    );
    Ok(())
}

#[test]
fn pending_survives_restart_and_a_fresh_token_cannot_bypass_it() -> Result {
    let fixture = Fixture::new()?;
    let token = fixture.token()?;
    drop(fixture.reserve(&token)?); // Simulated loss of the executing process.
    let reopened = Arc::new(StateStore::open_with_runtime(
        fixture.store.path(),
        fixture.store.runtime(),
    )?);
    let authority = CapabilityAuthority::new(&[7; 32], reopened.clone(), 600, None)?;
    let receipt = authority
        .submission_receipt(&token, "owner-a", "run-a", &"a".repeat(64), &"b".repeat(64))?
        .ok_or("pending missing")?;
    assert!(receipt.result().is_none());
    let fresh = fixture.token()?;
    let authorized = authority.authorize_submission(&fresh, "owner-a", "run-a", "fresh")?;
    assert_eq!(
        reopened
            .reserve_submission(&authorized, &"a".repeat(64), &"b".repeat(64))
            .err()
            .ok_or("expected blocking")?
            .code,
        "RESULT_UNKNOWN"
    );
    assert_eq!(reopened.list_transitions("run-a")?.len(), 0);
    Ok(())
}

#[test]
fn concurrent_reservations_have_one_winner_across_independent_connections() -> Result {
    let fixture = Fixture::new()?;
    let token = fixture.token()?;
    let authorized = Arc::new(
        fixture
            .authority
            .authorize_submission(&token, "owner-a", "run-a", "once")?,
    );
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let store = StateStore::open_with_runtime(fixture.store.path(), fixture.store.runtime())?;
        let authorized = authorized.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            store
                .reserve_submission(&authorized, &"a".repeat(64), &"b".repeat(64))
                .map(|value| matches!(value, SubmissionSlot::Reserved(_)))
        }));
    }
    let mut winners = 0;
    for handle in handles {
        winners += usize::from(handle.join().map_err(|_| "thread panicked")??);
    }
    assert_eq!(winners, 1);
    Ok(())
}

#[test]
fn reservation_rechecks_authority_and_rejects_malformed_bindings() -> Result {
    let fixture = Fixture::new()?;
    let token = fixture.token()?;
    let authorized = fixture
        .authority
        .authorize_submission(&token, "owner-a", "run-a", "check")?;
    assert!(!format!("{authorized:?}").contains(&token));
    assert!(
        fixture
            .store
            .reserve_submission(&authorized, "bad-hash", &"b".repeat(64))
            .is_err()
    );
    fixture
        .authority
        .revoke(&token, "revoked before reservation", "revoke")?;
    assert_eq!(
        fixture
            .store
            .reserve_submission(&authorized, &"a".repeat(64), &"b".repeat(64))
            .err()
            .ok_or("expected refusal")?
            .code,
        "SUBMISSION_AUTHORITY_CHANGED"
    );
    assert!(
        fixture
            .authority
            .submission_receipt(&token, "owner-a", "run-a", &"a".repeat(64), &"b".repeat(64))?
            .is_none()
    );
    Ok(())
}

#[test]
fn invalid_completion_retains_pending_and_correction_is_distinct_from_success() -> Result {
    let fixture = Fixture::new()?;
    let token = fixture.token()?;
    let mut invalid = completion();
    invalid.error_code = Some("secret proof text must not persist".into());
    assert!(
        fixture
            .store
            .complete_submission(fixture.reserve(&token)?, &invalid)
            .is_err()
    );
    let receipt = fixture
        .authority
        .submission_receipt(&token, "owner-a", "run-a", &"a".repeat(64), &"b".repeat(64))?
        .ok_or("missing")?;
    assert!(receipt.result().is_none());
    let second = Fixture::new()?;
    let token = second.token()?;
    let result = SubmissionResult {
        disposition: SubmissionDisposition::CorrectionRequired,
        state: WorkflowState::Assess,
        writes_applied: 1,
        complete: false,
        error_code: Some("INVALID_ARGUMENT".into()),
    };
    let receipt = second
        .store
        .complete_submission(second.reserve(&token)?, &result)?;
    assert_eq!(receipt.result(), Some(&result));
    Ok(())
}

#[test]
fn per_run_capacity_refuses_new_work_without_removing_receipts() -> Result {
    let fixture = Fixture::new()?;
    let token = fixture.token()?;
    let connection = Connection::open(fixture.store.path())?;
    connection.execute(
        "WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM seq WHERE x<4096)
         INSERT INTO step_receipts(capability_sha256,owner_id,workspace_sha256,request_sha256,run_id,domain_id,role,epoch,issued_state,status,result_json,created_at,completed_at)
         SELECT printf('%064x',x),'owner-a',?,?, 'run-a','domain-a','generator',1,'assess','completed',?,'test','test' FROM seq",
        rusqlite::params!["a".repeat(64), "b".repeat(64), serde_json::to_string(&completion())?],
    )?;
    assert!(
        fixture
            .reserve(&token)
            .err()
            .ok_or("capacity accepted")?
            .to_string()
            .contains("capacity")
    );
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM step_receipts", [], |row| row.get(0))?;
    assert_eq!(count, 4096);
    Ok(())
}

fn create_v2(path: &std::path::Path) -> Result {
    let connection = Connection::open(path)?;
    connection.execute_batch(V1_WORKFLOW_SCHEMA_SQL)?;
    connection.execute_batch(V2_RESEARCH_SCHEMA_SQL)?;
    connection.execute_batch(SCHEMA_MIGRATIONS_TABLE_SQL)?;
    connection.execute_batch("INSERT INTO runs(run_id,problem_id,owner_id,state,status,created_at,updated_at) VALUES('old','old-problem','owner','assess','active','old','old'); PRAGMA user_version=2;")?;
    Ok(())
}

#[test]
fn v2_upgrade_preserves_rows_and_preupgrade_copy_and_is_idempotent() -> Result {
    let root = tempfile::tempdir()?;
    let before = root.path().join("before.sqlite3");
    let copy = root.path().join("upgrade.sqlite3");
    create_v2(&before)?;
    let bytes = std::fs::read(&before)?;
    std::fs::copy(&before, &copy)?;
    for _ in 0..2 {
        let store = StateStore::open(&copy)?;
        assert_eq!(store.schema_version()?, 5);
        assert_eq!(store.get_run("old")?["problem_id"], "old-problem");
    }
    assert_eq!(std::fs::read(&before)?, bytes);
    assert_eq!(
        Connection::open(&before)?
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?,
        2
    );
    Ok(())
}

#[test]
fn v3_migration_failure_rolls_back_new_table_and_version() -> Result {
    let root = tempfile::tempdir()?;
    let path = root.path().join("broken.sqlite3");
    create_v2(&path)?;
    Connection::open(&path)?.execute_batch(
        "CREATE TABLE collision(x); CREATE INDEX idx_step_receipts_run ON collision(x);",
    )?;
    assert!(StateStore::open(&path).is_err());
    let connection = Connection::open(&path)?;
    assert_eq!(
        connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?,
        2
    );
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name='step_receipts'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    Ok(())
}

#[test]
fn different_capabilities_for_one_run_still_have_one_pending_winner() -> Result {
    let fixture = Fixture::new()?;
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let token = fixture.token()?;
        let authorized = fixture.authority.authorize_submission(
            &token,
            "owner-a",
            "run-a",
            "different-token",
        )?;
        let store = StateStore::open_with_runtime(fixture.store.path(), fixture.store.runtime())?;
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            match store.reserve_submission(&authorized, &"a".repeat(64), &"b".repeat(64)) {
                Ok(SubmissionSlot::Reserved(_)) => Ok(true),
                Err(error) if error.code == "RESULT_UNKNOWN" => Ok(false),
                _ => Err("unexpected competing reservation outcome"),
            }
        }));
    }
    let mut winners = 0;
    for handle in handles {
        winners += usize::from(handle.join().map_err(|_| "thread panicked")??);
    }
    assert_eq!(winners, 1);
    Ok(())
}

#[test]
fn expired_or_changed_domain_cannot_reserve_after_initial_validation() -> Result {
    for changed_clock in [false, true] {
        let fixture = Fixture::new()?;
        let token = fixture.token()?;
        let authorized = fixture.authority.authorize_submission(
            &token,
            "owner-a",
            "run-a",
            "initial-validation",
        )?;
        if changed_clock {
            fixture.clock.0.store(5000, Ordering::SeqCst);
        } else {
            Connection::open(fixture.store.path())?.execute(
                "UPDATE domains SET status='sealed' WHERE domain_id='domain-a'",
                [],
            )?;
        }
        let error = fixture
            .store
            .reserve_submission(&authorized, &"a".repeat(64), &"b".repeat(64))
            .err()
            .ok_or("stale validation was reused")?;
        assert_eq!(error.code, "SUBMISSION_AUTHORITY_CHANGED");
    }
    Ok(())
}

#[test]
fn corrupt_receipt_never_falls_back_to_new_execution() -> Result {
    let fixture = Fixture::new()?;
    let token = fixture.token()?;
    fixture
        .store
        .complete_submission(fixture.reserve(&token)?, &completion())?;
    let connection = Connection::open(fixture.store.path())?;
    connection.execute("UPDATE step_receipts SET result_json='{}'", [])?;
    let error = fixture
        .authority
        .submission_receipt(&token, "owner-a", "run-a", &"a".repeat(64), &"b".repeat(64))
        .err()
        .ok_or("corrupt receipt was accepted")?;
    assert_eq!(error.code, "SUBMISSION_RECEIPT_INVALID");
    assert!(
        connection
            .execute("UPDATE step_receipts SET result_json=?", ["x".repeat(2049)])
            .is_err()
    );
    Ok(())
}

#[test]
fn global_capacity_is_enforced_even_for_a_run_without_receipts() -> Result {
    let fixture = Fixture::new()?;
    fixture
        .store
        .create_run("other", "problem", "owner-a", "assess", &json!({}))?;
    fixture
        .store
        .create_domain("other-domain", "other", "generator", None, None, &json!({}))?;
    let connection = Connection::open(fixture.store.path())?;
    connection.execute(
        "WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM seq WHERE x<100000)
         INSERT INTO step_receipts(capability_sha256,owner_id,workspace_sha256,request_sha256,run_id,domain_id,role,epoch,issued_state,status,result_json,created_at,completed_at)
         SELECT printf('%064x',x),'owner-a',?,?, 'other','other-domain','generator',1,'assess','completed',?,'test','test' FROM seq",
        rusqlite::params!["a".repeat(64), "b".repeat(64), serde_json::to_string(&completion())?],
    )?;
    let token = fixture.token()?;
    let authorized = fixture
        .authority
        .authorize_submission(&token, "owner-a", "run-a", "capacity")?;
    let error = fixture
        .store
        .reserve_submission(&authorized, &"a".repeat(64), &"b".repeat(64))
        .err()
        .ok_or("global capacity accepted")?;
    assert_eq!(error.code, "SUBMISSION_RECEIPT_CAPACITY");
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM step_receipts", [], |r| r.get(0))?;
    assert_eq!(count, 100_000);
    Ok(())
}
