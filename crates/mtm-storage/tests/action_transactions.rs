use std::sync::{Arc, Barrier};

use mtm_contracts::{WorkflowRole, WorkflowState};
use mtm_storage::{
    AtomicActionKind, CapabilityAuthority, CapabilityClaims, StateStore, SubmissionDisposition,
    SubmissionExecution, SubmissionReceipt, SubmissionSlot, TaskTransition, TransitionRun,
    default_permissions,
};
use rusqlite::Connection;
use serde_json::{Map, Value, json};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Fixture {
    _root: tempfile::TempDir,
    store: Arc<StateStore>,
    authority: CapabilityAuthority,
    token: String,
    claims: CapabilityClaims,
    execution: SubmissionExecution,
}

impl Fixture {
    fn new(enroll: bool) -> Result<Self> {
        let root = tempfile::tempdir()?;
        let store = Arc::new(StateStore::open(root.path().join("state.sqlite3"))?);
        store.create_run("run", "p", "owner", "assess", &json!({"untouched":true}))?;
        store.create_domain("domain", "run", "generator", None, None, &json!({}))?;
        let authority = CapabilityAuthority::new(&[12; 32], store.clone(), 600, None)?;
        let permissions = default_permissions(WorkflowRole::Generator)
            .iter()
            .map(|p| (*p).into())
            .collect::<Vec<_>>();
        let token = authority.issue(
            "run",
            "domain",
            WorkflowRole::Generator,
            &permissions,
            "issue",
            None,
        )?;
        let authorized = authority.authorize_submission(&token, "owner", "run", "reserve")?;
        let claims =
            authority.validate(&token, "owner", "commit", "workflow", "claims", Some("run"))?;
        let reservation =
            match store.reserve_submission(&authorized, &"a".repeat(64), &"b".repeat(64))? {
                SubmissionSlot::Reserved(r) => r,
                _ => return Err("unexpected reservation".into()),
            };
        let execution = store.activate_submission(&reservation, &authorized, 0)?;
        store.arm_submission_commit(&execution)?;
        if enroll {
            store.enroll_atomic_action(
                &claims,
                execution.trace_id(),
                AtomicActionKind::AssessmentComplete,
            )?;
        }
        Ok(Self {
            _root: root,
            store,
            authority,
            token,
            claims,
            execution,
        })
    }

    fn receipt(&self) -> Result<SubmissionReceipt> {
        Ok(self
            .authority
            .submission_receipt(
                &self.token,
                "owner",
                "run",
                &"a".repeat(64),
                &"b".repeat(64),
            )?
            .ok_or("missing receipt")?)
    }

    fn commit(&self) -> std::result::Result<Value, mtm_contracts::ReCtmError> {
        commit(
            &self.store,
            &self.claims,
            self.execution.trace_id(),
            &json!({"untouched":true}),
        )
    }
}

fn commit(
    store: &StateStore,
    claims: &CapabilityClaims,
    trace: &str,
    expected: &Value,
) -> std::result::Result<Value, mtm_contracts::ReCtmError> {
    let updates = Map::from_iter([("effective_workflow_mode".into(), json!("compact"))]);
    store.transition_task(
        claims,
        TaskTransition {
            transition: TransitionRun {
                run_id: "run",
                expected_state: "assess",
                after_state: "assemble",
                trace_id: trace,
                actor: "generator",
                reason: "assessment_complete",
                evidence: &json!({}),
                increment_epoch: true,
                status: None,
                latex_passed: None,
                verdict: None,
                sealed: None,
                round_delta: 0,
            },
            expected_metadata: Some(expected),
            metadata_updates: &updates,
            project_mode: Some("compact"),
            branch: None,
            restartable_action: None,
        },
    )
}

#[test]
fn every_database_boundary_rolls_back_domain_metadata_transition_and_receipt() -> Result {
    for trigger in [
        "BEFORE UPDATE OF metadata_json ON runs",
        "BEFORE UPDATE ON domains",
        "BEFORE UPDATE ON capabilities",
        "BEFORE INSERT ON transitions",
        "BEFORE UPDATE ON step_receipts",
    ] {
        let f = Fixture::new(true)?;
        let before = f.store.database_snapshot()?;
        let db = Connection::open(f.store.path())?;
        db.execute_batch(&format!("CREATE TRIGGER injected {trigger} BEGIN SELECT RAISE(ABORT,'fixture transaction'); END;"))?;
        assert!(f.commit().is_err(), "{trigger}");
        assert_eq!(f.store.database_snapshot()?, before, "{trigger}");
        db.execute_batch("DROP TRIGGER injected")?;
        let recovery = f.store.submission_recovery(f.receipt()?)?;
        let receipt = f.store.reconcile_caller_writes(recovery, None)?;
        assert_eq!(
            receipt.result().ok_or("pending")?.error_code.as_deref(),
            Some("SUBMISSION_INTERRUPTED")
        );
        assert!(f.commit().is_err());
        assert_eq!(f.store.get_run("run")?["state"], "assess");
        assert_eq!(f.store.get_domain("domain")?["status"], "open");
    }
    Ok(())
}

#[test]
fn completed_action_survives_reopen_and_preserves_one_transition() -> Result {
    let f = Fixture::new(true)?;
    let first = f.commit()?;
    assert_eq!(first["state"], "assemble");
    assert_eq!(first["metadata"]["untouched"], true);
    let reopened = StateStore::open(f.store.path())?;
    let receipt =
        reopened.reconcile_caller_writes(reopened.submission_recovery(f.receipt()?)?, None)?;
    assert_eq!(
        receipt.result().ok_or("pending")?.disposition,
        SubmissionDisposition::Applied
    );
    assert_eq!(
        receipt.result().ok_or("pending")?.state,
        WorkflowState::Assemble
    );
    assert!(f.commit().is_err());
    assert_eq!(reopened.list_transitions("run")?.len(), 1);
    assert_eq!(reopened.get_domain("domain")?["status"], "sealed");
    Ok(())
}

#[test]
fn project_mode_and_action_metadata_cannot_commit_separately() -> Result {
    let f = Fixture::new(true)?;
    let db = Connection::open(f.store.path())?;
    db.execute_batch("INSERT INTO projects(project_id,owner_id,title,created_at,updated_at) VALUES('project','owner','fixture','old','old'); INSERT INTO project_snapshots(snapshot_id,project_id,owner_id,snapshot_sha256,created_at) VALUES('snapshot','project','owner','fixture','old'); INSERT INTO project_runs(run_id,project_id,project_snapshot_id,effective_workflow_mode,created_at,updated_at) VALUES('run','project','snapshot','full','old','old');")?;
    let before = f.store.database_snapshot()?;
    db.execute_batch("CREATE TRIGGER fail_mode AFTER UPDATE ON project_runs BEGIN SELECT RAISE(ABORT,'fixture project mode'); END;")?;
    assert!(f.commit().is_err());
    assert_eq!(f.store.database_snapshot()?, before);
    db.execute_batch("DROP TRIGGER fail_mode")?;
    f.commit()?;
    let mode: String = db.query_row(
        "SELECT effective_workflow_mode FROM project_runs WHERE run_id='run'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(mode, "compact");
    assert_eq!(
        f.store.get_run("run")?["metadata"]["effective_workflow_mode"],
        "compact"
    );
    Ok(())
}

#[test]
fn explicit_enrollment_never_adopts_legacy_or_wrong_kind_or_trace() -> Result {
    let f = Fixture::new(false)?;
    assert!(
        f.store
            .reconcile_caller_writes(f.store.submission_recovery(f.receipt()?)?, None)
            .is_err()
    );
    assert!(
        f.store
            .enroll_atomic_action(
                &f.claims,
                f.execution.trace_id(),
                AtomicActionKind::ProofSubmitted,
            )
            .is_err()
    );
    assert!(
        f.store
            .enroll_atomic_action(&f.claims, "wrong", AtomicActionKind::AssessmentComplete)
            .is_err()
    );
    assert!(commit(&f.store, &f.claims, "wrong", &json!({"untouched":true})).is_err());
    f.store.enroll_atomic_action(
        &f.claims,
        f.execution.trace_id(),
        AtomicActionKind::AssessmentComplete,
    )?;
    assert!(
        f.store
            .enroll_atomic_action(
                &f.claims,
                f.execution.trace_id(),
                AtomicActionKind::AssessmentComplete,
            )
            .is_err()
    );
    for action in [
        "verification_submitted",
        "plans_proposed",
        "branch_complete",
        "join_complete",
        "finalize",
    ] {
        assert!(AtomicActionKind::parse(action).is_none());
    }
    Ok(())
}

#[test]
fn recovery_and_original_action_have_only_one_transactional_outcome() -> Result {
    for _ in 0..16 {
        let f = Fixture::new(true)?;
        let recovery = f.store.submission_recovery(f.receipt()?)?;
        let other = StateStore::open(f.store.path())?;
        let barrier = Arc::new(Barrier::new(2));
        let peer = barrier.clone();
        let handle = std::thread::spawn(move || {
            peer.wait();
            other.reconcile_caller_writes(recovery, None)
        });
        barrier.wait();
        let committed = f.commit().is_ok();
        let recovered = handle.join().map_err(|_| "recovery thread")??;
        assert_eq!(
            recovered.result().ok_or("pending")?.disposition == SubmissionDisposition::Applied,
            committed
        );
        assert_eq!(
            f.store.list_transitions("run")?.len(),
            usize::from(committed)
        );
        assert_eq!(
            f.store.get_domain("domain")?["status"],
            if committed { "sealed" } else { "open" }
        );
    }
    Ok(())
}

#[test]
fn changed_authority_metadata_and_overflow_cannot_commit_partial_effects() -> Result {
    for mutation in ["revoke", "owner", "epoch", "metadata", "domain", "overflow"] {
        let f = Fixture::new(true)?;
        let db = Connection::open(f.store.path())?;
        match mutation {
            "revoke" => f.authority.revoke(&f.token, "fixture", "revoke")?,
            "owner" => {
                db.execute("UPDATE runs SET owner_id='other'", [])?;
            }
            "epoch" => {
                db.execute("UPDATE runs SET epoch=epoch+1", [])?;
            }
            "metadata" => {
                db.execute("UPDATE runs SET metadata_json='{}'", [])?;
            }
            "domain" => {
                db.execute("UPDATE domains SET status='sealed'", [])?;
            }
            _ => {
                db.execute("UPDATE runs SET transition_seq=9223372036854775807", [])?;
            }
        }
        let before = f.store.database_snapshot()?;
        assert!(f.commit().is_err(), "{mutation}");
        assert_eq!(f.store.database_snapshot()?, before);
    }
    Ok(())
}

#[test]
fn inconsistent_enrollment_cannot_certify_an_unstarted_or_completed_action() -> Result {
    for statement in [
        "UPDATE step_checkpoints SET phase='prepared',expected_writes=NULL",
        "UPDATE step_checkpoints SET phase='running'",
        "UPDATE step_checkpoints SET atomic_action='repair_submitted'",
        "UPDATE step_write_journals SET marker_json='{\"kind\":\"opaque\"}'",
    ] {
        let f = Fixture::new(true)?;
        Connection::open(f.store.path())?.execute_batch(statement)?;
        let recovery = f.store.submission_recovery(f.receipt()?)?;
        assert!(f.store.reconcile_caller_writes(recovery, None).is_err());
        assert!(f.receipt()?.result().is_none());
        assert!(f.store.list_transitions("run")?.is_empty());
    }
    Ok(())
}

#[test]
fn checkpoint_count_constraint_rejects_false_atomic_completion() -> Result {
    let f = Fixture::new(true)?;
    let before = f.store.database_snapshot()?;
    let db = Connection::open(f.store.path())?;
    assert!(
        db.execute("UPDATE step_checkpoints SET expected_writes=1", [])
            .is_err()
    );
    assert_eq!(f.store.database_snapshot()?, before);
    assert!(f.receipt()?.result().is_none());
    Ok(())
}

#[test]
fn schema7_migration_preserves_unenrolled_work_and_failed_migration_rolls_back() -> Result {
    use mtm_storage::schema::*;
    for collision in [false, true] {
        let root = tempfile::tempdir()?;
        let path = root.path().join("legacy.sqlite3");
        let db = Connection::open(&path)?;
        for sql in [
            SCHEMA_MIGRATIONS_TABLE_SQL,
            V1_WORKFLOW_SCHEMA_SQL,
            V2_RESEARCH_SCHEMA_SQL,
            V3_SUBMISSION_RECEIPTS_SQL,
            V4_RECOVERY_SQL,
            V5_CREATION_INITIALIZATION_SQL,
            V6_CALLER_WRITE_JOURNAL_SQL,
        ] {
            db.execute_batch(sql)?;
        }
        db.execute_batch("INSERT INTO runs(run_id,problem_id,owner_id,state,status,created_at,updated_at) VALUES('run','p','owner','assess','active','old','old'); INSERT INTO domains(domain_id,run_id,role,status,created_at) VALUES('domain','run','generator','open','old'); PRAGMA user_version=6;")?;
        for version in 1..=6 {
            db.execute(
                "INSERT INTO schema_migrations VALUES(?,'old','fixture')",
                [version],
            )?;
        }
        db.execute("INSERT INTO step_receipts VALUES(?,'owner',?,?,'run','domain','generator',1,'assess','pending',NULL,'old',NULL)", rusqlite::params!["a".repeat(64),"b".repeat(64),"c".repeat(64)])?;
        db.execute(
            "INSERT INTO step_checkpoints VALUES(?,?,'commit_ready',0,0)",
            rusqlite::params!["a".repeat(64), "d".repeat(32)],
        )?;
        db.execute(
            "INSERT INTO step_write_journals VALUES(?,?)",
            rusqlite::params!["a".repeat(64), "{\"kind\":\"between\"}"],
        )?;
        if collision {
            db.execute_batch("ALTER TABLE step_checkpoints ADD COLUMN atomic_action TEXT")?;
        }
        let backup = std::fs::read(&path)?;
        let copy = root.path().join("preupgrade.sqlite3");
        std::fs::write(&copy, &backup)?;
        let store = StateStore::open(&path);
        assert_eq!(store.is_ok(), !collision);
        assert_eq!(
            db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?,
            if collision { 6 } else { 7 }
        );
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version=7",
                [],
                |r| r.get::<_, i64>(0)
            )?,
            i64::from(!collision)
        );
        let enrolled: Option<String> =
            db.query_row("SELECT atomic_action FROM step_checkpoints", [], |r| {
                r.get(0)
            })?;
        assert!(enrolled.is_none());
        assert_eq!(std::fs::read(&copy)?, backup);
        if let Ok(store) = store {
            assert!(store.pending_submission_status("owner", "run")?["atomic_action"].is_null());
        }
    }
    Ok(())
}
