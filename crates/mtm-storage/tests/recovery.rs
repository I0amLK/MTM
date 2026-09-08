use std::sync::{Arc, Barrier};

use mtm_contracts::WorkflowRole;
use mtm_storage::{
    AuthorizedSubmission, CapabilityAuthority, CreationIdentity, CreationSlot, StateStore,
    SubmissionReservation, SubmissionSlot, TransitionRun, default_permissions,
};
use rusqlite::Connection;
use serde_json::{Value, json};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn schema5_preserves_legacy_creation_and_does_not_enroll_unknown_work() -> Result {
    let root = tempfile::tempdir()?;
    let path = root.path().join("v4.sqlite3");
    schema3(&path)?;
    let db = Connection::open(&path)?;
    db.execute_batch(mtm_storage::schema::V4_RECOVERY_SQL)?;
    db.execute_batch("PRAGMA user_version=4;")?;
    db.execute(
        "INSERT INTO creation_receipts VALUES('owner',?,?,?,'old-run',?,'pending','old',NULL)",
        rusqlite::params![
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "1".repeat(32)
        ],
    )?;
    drop(db);
    let bytes = std::fs::read(&path)?;
    let backup = root.path().join("preupgrade");
    std::fs::write(&backup, &bytes)?;
    let store = StateStore::open(&path)?;
    let old = match store.reserve_creation("owner", &identity('b', 'c')?, "different-proposed")? {
        CreationSlot::Existing(receipt) => receipt,
        _ => return Err("old identity was replaced".into()),
    };
    assert!(store.resume_creation(old).is_err());
    assert_eq!(store.schema_version()?, 6);
    let db = Connection::open(&path)?;
    let enrolled: i64 = db.query_row("SELECT COUNT(*) FROM creation_initializations", [], |r| {
        r.get(0)
    })?;
    assert_eq!(enrolled, 0);
    assert_eq!(std::fs::read(backup)?, bytes);
    Ok(())
}

#[test]
fn schema5_failed_migration_preserves_version_and_existing_rows() -> Result {
    let root = tempfile::tempdir()?;
    let path = root.path().join("blocked-v4.sqlite3");
    schema3(&path)?;
    let db = Connection::open(&path)?;
    db.execute_batch(mtm_storage::schema::V4_RECOVERY_SQL)?;
    db.execute_batch("CREATE TABLE creation_initializations(collision); PRAGMA user_version=4;")?;
    assert!(StateStore::open(&path).is_err());
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?,
        4
    );
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version=5",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    Ok(())
}

#[test]
fn creation_records_are_one_transaction_and_replay_checks_material_and_rows() -> Result {
    let root = tempfile::tempdir()?;
    let path = root.path().join("state.sqlite3");
    let store = StateStore::open(&path)?;
    let reservation = match store.reserve_creation("owner", &identity('b', 'c')?, "run-new")? {
        CreationSlot::Reserved(value) => value,
        _ => return Err("expected reservation".into()),
    };
    let references = [mtm_storage::CreationReference {
        name: "source.txt".into(),
        content: "private source".into(),
        source: "inline".into(),
    }];
    let metadata = json!({"workspace_export_path":"out/proof.tex"});
    let material = mtm_storage::CreationInitialization {
        problem_id: "problem",
        metadata: &metadata,
        project_id: None,
        target_claim_id: None,
        workflow_mode: "full",
        register_result: false,
        references: &references,
    };
    let db = Connection::open(&path)?;
    db.execute_batch("CREATE TRIGGER block_source BEFORE INSERT ON source_snapshots BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;
    assert!(
        store
            .prepare_creation_records(&reservation, &material)
            .is_err()
    );
    assert!(store.list_runs("owner", 10)?.is_empty());
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM references_registry", [], |r| r
            .get::<_, i64>(0))?,
        0
    );
    db.execute_batch("DROP TRIGGER block_source")?;
    let first = store.prepare_creation_records(&reservation, &material)?;
    let again = store.prepare_creation_records(&reservation, &material)?;
    assert_eq!(first, again);
    let changed = mtm_storage::CreationInitialization {
        workflow_mode: "compact",
        ..material
    };
    assert!(
        store
            .prepare_creation_records(&reservation, &changed)
            .is_err()
    );
    let original = mtm_storage::CreationInitialization {
        workflow_mode: "full",
        ..changed
    };
    db.execute("UPDATE source_snapshots SET metadata_json='{}'", [])?;
    assert!(
        store
            .prepare_creation_records(&reservation, &original)
            .is_err()
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM runs", [], |r| r.get::<_, i64>(0))?,
        1
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM source_snapshots", [], |r| r
            .get::<_, i64>(0))?,
        1
    );
    Ok(())
}

#[test]
fn upgrading_legacy_receipts_preserves_payload_and_does_not_invent_checkpoints() -> Result {
    let root = tempfile::tempdir()?;
    let path = root.path().join("legacy.sqlite3");
    schema3(&path)?;
    let db = Connection::open(&path)?;
    db.execute_batch("INSERT INTO runs(run_id,problem_id,owner_id,state,status,created_at,updated_at) VALUES('run-old','old','owner','assess','active','old','old'); INSERT INTO domains(domain_id,run_id,role,status,created_at) VALUES('domain-old','run-old','generator','open','old');")?;
    let result = r#"{"disposition":"correction_required","state":"assess","writes_applied":1,"complete":false,"error_code":"INVALID_ARGUMENT"}"#;
    for (fingerprint, status, result, completed) in [
        ("a".repeat(64), "pending", None, None),
        ("b".repeat(64), "completed", Some(result), Some("old")),
    ] {
        db.execute("INSERT INTO step_receipts VALUES(?,'owner',?,?,'run-old','domain-old','generator',1,'assess',? ,?,'old',?)",
            rusqlite::params![fingerprint,"c".repeat(64),"d".repeat(64),status,result,completed])?;
    }
    let before: String = db.query_row("SELECT group_concat(capability_sha256 || status || COALESCE(result_json,'NULL')) FROM step_receipts ORDER BY capability_sha256", [], |r| r.get(0))?;
    drop(db);
    let store = StateStore::open(&path)?;
    let db = Connection::open(&path)?;
    let after: String = db.query_row("SELECT group_concat(capability_sha256 || status || COALESCE(result_json,'NULL')) FROM step_receipts ORDER BY capability_sha256", [], |r| r.get(0))?;
    assert_eq!(before, after);
    assert_eq!(
        store.pending_submission_status("owner", "run-old")?["phase"],
        "legacy_unknown"
    );
    let checkpoints: i64 =
        db.query_row("SELECT COUNT(*) FROM step_checkpoints", [], |r| r.get(0))?;
    assert_eq!(checkpoints, 0);
    Ok(())
}

#[test]
fn invalid_creation_and_capacity_never_remove_safety_records() -> Result {
    assert!(CreationIdentity::new("bad".into(), "b".repeat(64), "c".repeat(64)).is_err());
    let root = tempfile::tempdir()?;
    let path = root.path().join("capacity.sqlite3");
    let store = StateStore::open(&path)?;
    assert!(
        store
            .reserve_creation("", &identity('b', 'c')?, "run-new")
            .is_err()
    );
    assert!(
        store
            .reserve_creation("owner", &identity('b', 'c')?, "../escape")
            .is_err()
    );
    let db = Connection::open(&path)?;
    db.execute_batch("WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM seq WHERE x<10000) INSERT INTO creation_receipts SELECT 'owner',printf('%064x',x),printf('%064x',1),printf('%064x',2),'run-' || x,printf('%032x',x),'pending','old',NULL FROM seq;")?;
    let error = match store.reserve_creation("owner", &identity('b', 'c')?, "not-started") {
        Err(error) => error,
        Ok(_) => return Err("capacity did not refuse creation".into()),
    };
    assert_eq!(error.code, "CREATION_RECEIPT_CAPACITY");
    let count: i64 = db.query_row("SELECT COUNT(*) FROM creation_receipts", [], |r| r.get(0))?;
    assert_eq!(count, 10_000);
    assert!(store.list_runs("owner", 10)?.is_empty());
    Ok(())
}

#[test]
fn changed_epoch_cannot_be_certified_by_a_matching_execution_trace() -> Result {
    let f = Fixture::new()?;
    let (authorized, reservation) = f.reserve()?;
    let execution = f.store.activate_submission(&reservation, &authorized, 0)?;
    f.store.arm_submission_commit(&execution)?;
    Connection::open(f.store.path())?.execute("UPDATE runs SET epoch=epoch+1", [])?;
    let attempt = f.store.transition_run(transition(
        "run-a",
        execution.trace_id(),
        "assess",
        "assemble",
        "generator",
    ));
    assert!(attempt.is_err());
    assert_eq!(f.store.get_run("run-a")?["state"], "assess");
    assert!(f.receipt()?.result().is_none());
    assert!(f.store.list_transitions("run-a")?.is_empty());
    Ok(())
}

fn identity(workspace: char, request: char) -> Result<CreationIdentity> {
    Ok(CreationIdentity::new(
        "a".repeat(64),
        workspace.to_string().repeat(64),
        request.to_string().repeat(64),
    )?)
}

fn transition<'a>(
    run: &'a str,
    trace: &'a str,
    before: &'a str,
    after: &'a str,
    actor: &'a str,
) -> TransitionRun<'a> {
    TransitionRun {
        run_id: run,
        trace_id: trace,
        expected_state: before,
        after_state: after,
        actor,
        reason: if before == "created" {
            "run_initialized"
        } else {
            "fixture_commit"
        },
        evidence: &Value::Null,
        increment_epoch: true,
        status: None,
        latex_passed: None,
        verdict: None,
        sealed: None,
        round_delta: 0,
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    store: Arc<StateStore>,
    authority: CapabilityAuthority,
    token: String,
}

impl Fixture {
    fn new() -> Result<Self> {
        let root = tempfile::tempdir()?;
        let store = Arc::new(StateStore::open(root.path().join("state.sqlite3"))?);
        store.create_run("run-a", "problem", "owner", "assess", &json!({}))?;
        store.create_domain("domain-a", "run-a", "generator", None, None, &json!({}))?;
        let authority = CapabilityAuthority::new(&[4; 32], store.clone(), 600, None)?;
        let permissions = default_permissions(WorkflowRole::Generator)
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>();
        let token = authority.issue(
            "run-a",
            "domain-a",
            WorkflowRole::Generator,
            &permissions,
            "issued",
            None,
        )?;
        Ok(Self {
            _root: root,
            store,
            authority,
            token,
        })
    }

    fn reserve(&self) -> Result<(AuthorizedSubmission, SubmissionReservation)> {
        let authorized =
            self.authority
                .authorize_submission(&self.token, "owner", "run-a", "outer")?;
        match self
            .store
            .reserve_submission(&authorized, &"a".repeat(64), &"b".repeat(64))?
        {
            SubmissionSlot::Reserved(reservation) => Ok((authorized, reservation)),
            SubmissionSlot::Existing(_) => Err("unexpected existing submission".into()),
        }
    }

    fn receipt(&self) -> Result<mtm_storage::SubmissionReceipt> {
        Ok(self
            .authority
            .submission_receipt(
                &self.token,
                "owner",
                "run-a",
                &"a".repeat(64),
                &"b".repeat(64),
            )?
            .ok_or("missing receipt")?)
    }
}

#[test]
fn creation_completion_is_atomic_bound_and_survives_reopen() -> Result {
    let root = tempfile::tempdir()?;
    let path = root.path().join("state.sqlite3");
    let store = StateStore::open(&path)?;
    let binding = identity('b', 'c')?;
    let reserved = match store.reserve_creation("owner", &binding, "run-new")? {
        CreationSlot::Reserved(value) => value,
        _ => return Err("missing reservation".into()),
    };
    assert_eq!(
        store
            .observe_creation(&reserved)?
            .response(true)
            .err()
            .ok_or("expected unknown")?
            .code,
        "CREATION_RESULT_UNKNOWN"
    );
    store.create_run("run-new", "problem", "owner", "created", &json!({}))?;
    assert!(
        store
            .transition_run(transition(
                "run-new",
                "wrong-trace",
                "created",
                "assess",
                "system"
            ))
            .is_err()
    );
    assert_eq!(store.get_run("run-new")?["state"], "created");
    store.transition_run(transition(
        "run-new",
        reserved.execution_id(),
        "created",
        "assess",
        "system",
    ))?;
    assert_eq!(
        store.observe_creation(&reserved)?.response(false)?["runs_created"],
        1
    );
    drop(store);
    let reopened = StateStore::open(&path)?;
    let replay = match reopened.reserve_creation("owner", &binding, "unused-new-id")? {
        CreationSlot::Existing(value) => value.response(true)?,
        _ => return Err("creation was repeated".into()),
    };
    assert_eq!(replay["run_id"], "run-new");
    assert_eq!(replay["runs_created"], 0);
    assert!(replay.get("capability").is_none());
    assert_eq!(reopened.list_runs("owner", 100)?.len(), 1);
    assert_eq!(
        reopened
            .reserve_creation("owner", &identity('d', 'c')?, "unused")
            .err()
            .ok_or("workspace mismatch")?
            .code,
        "CREATION_WORKSPACE_MISMATCH"
    );
    assert_eq!(
        reopened
            .reserve_creation("owner", &identity('b', 'd')?, "unused")
            .err()
            .ok_or("request mismatch")?
            .code,
        "IDEMPOTENCY_CONFLICT"
    );
    assert!(matches!(
        reopened.reserve_creation("another-owner", &binding, "independent")?,
        CreationSlot::Reserved(_)
    ));
    Ok(())
}

#[test]
fn concurrent_creation_keys_choose_one_server_run_identity() -> Result {
    let root = tempfile::tempdir()?;
    let path = root.path().join("state.sqlite3");
    StateStore::open(&path)?;
    let barrier = Arc::new(Barrier::new(8));
    let mut joins = Vec::new();
    for index in 0..8 {
        let store = StateStore::open(&path)?;
        let barrier = barrier.clone();
        joins.push(std::thread::spawn(move || -> Result<bool> {
            barrier.wait();
            Ok(matches!(
                store.reserve_creation("owner", &identity('b', 'c')?, &format!("run-{index}"))?,
                CreationSlot::Reserved(_)
            ))
        }));
    }
    let mut winners = 0;
    for join in joins {
        winners += usize::from(join.join().map_err(|_| "thread failure")??);
    }
    assert_eq!(winners, 1);
    let connection = Connection::open(path)?;
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM creation_receipts", [], |r| r
            .get::<_, i64>(0))?,
        1
    );
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM runs", [], |r| r.get::<_, i64>(0))?,
        0
    );
    Ok(())
}

#[test]
fn prepared_recovery_fences_the_original_worker_without_writing() -> Result {
    let f = Fixture::new()?;
    let (authorized, reservation) = f.reserve()?;
    let recovered = f.store.reconcile_unstarted_submission(f.receipt()?)?;
    let result = recovered.result().ok_or("missing outcome")?;
    assert_eq!(result.writes_applied, 0);
    assert_eq!(result.error_code.as_deref(), Some("SUBMISSION_NOT_STARTED"));
    assert!(
        f.store
            .activate_submission(&reservation, &authorized, 2)
            .is_err()
    );
    assert!(f.store.list_transitions("run-a")?.is_empty());
    assert_eq!(f.store.get_run("run-a")?["state"], "assess");
    assert!(
        f.store
            .pending_submission_status("owner", "run-a")?
            .is_null()
    );
    Ok(())
}

#[test]
fn activation_and_explicit_recovery_have_one_transactional_winner() -> Result {
    let f = Fixture::new()?;
    let (authorized, reservation) = f.reserve()?;
    let store = StateStore::open(f.store.path())?;
    let receipt = f.receipt()?;
    let barrier = Arc::new(Barrier::new(2));
    let other = barrier.clone();
    let join = std::thread::spawn(move || {
        other.wait();
        store.reconcile_unstarted_submission(receipt).is_ok()
    });
    barrier.wait();
    let activated = f
        .store
        .activate_submission(&reservation, &authorized, 0)
        .is_ok();
    let recovered = join.join().map_err(|_| "thread failure")?;
    assert_ne!(activated, recovered);
    Ok(())
}

#[test]
fn transition_certificate_survives_loss_of_runtime_continuation() -> Result {
    let f = Fixture::new()?;
    let (authorized, reservation) = f.reserve()?;
    let execution = f.store.activate_submission(&reservation, &authorized, 2)?;
    f.store.begin_submission_write(&execution, 0, None)?;
    f.store.checkpoint_submission_write(&execution, 1)?;
    assert!(f.store.arm_submission_commit(&execution).is_err());
    f.store.begin_submission_write(&execution, 1, None)?;
    f.store.checkpoint_submission_write(&execution, 2)?;
    f.store.arm_submission_commit(&execution)?;
    f.store.transition_run(transition(
        "run-a",
        execution.trace_id(),
        "assess",
        "assemble",
        "generator",
    ))?;
    drop(reservation); // No runtime finish call: the transaction is the evidence.
    let reopened = Arc::new(StateStore::open(f.store.path())?);
    let authority = CapabilityAuthority::new(&[4; 32], reopened.clone(), 600, None)?;
    let receipt = authority
        .submission_receipt(&f.token, "owner", "run-a", &"a".repeat(64), &"b".repeat(64))?
        .ok_or("missing committed receipt")?;
    assert_eq!(
        receipt
            .result()
            .ok_or("pending despite commit")?
            .writes_applied,
        2
    );
    assert!(
        reopened
            .pending_submission_status("owner", "run-a")?
            .is_null()
    );
    assert!(
        authority
            .authorize_submission(&f.token, "owner", "run-a", "again")
            .is_err()
    );
    assert_eq!(reopened.list_transitions("run-a")?.len(), 1);
    Ok(())
}

#[test]
fn premature_or_failed_transition_cannot_certify_a_result() -> Result {
    let f = Fixture::new()?;
    let (authorized, reservation) = f.reserve()?;
    let execution = f.store.activate_submission(&reservation, &authorized, 0)?;
    assert!(
        f.store
            .transition_run(transition(
                "run-a",
                execution.trace_id(),
                "assess",
                "assemble",
                "generator"
            ))
            .is_err()
    );
    assert_eq!(f.store.get_run("run-a")?["state"], "assess");
    assert!(f.store.list_transitions("run-a")?.is_empty());
    assert!(f.receipt()?.result().is_none());
    f.store.arm_submission_commit(&execution)?;
    Connection::open(f.store.path())?.execute_batch("CREATE TRIGGER reject_receipt BEFORE UPDATE ON step_receipts BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;
    assert!(
        f.store
            .transition_run(transition(
                "run-a",
                execution.trace_id(),
                "assess",
                "assemble",
                "generator"
            ))
            .is_err()
    );
    assert_eq!(f.store.get_run("run-a")?["state"], "assess");
    assert!(f.store.list_transitions("run-a")?.is_empty());
    assert!(
        f.authority
            .authorize_submission(&f.token, "owner", "run-a", "still-active")
            .is_ok()
    );
    Ok(())
}

#[test]
fn running_and_legacy_unknown_work_are_never_reclassified_by_status() -> Result {
    for legacy in [false, true] {
        let f = Fixture::new()?;
        let (authorized, reservation) = f.reserve()?;
        if legacy {
            Connection::open(f.store.path())?.execute("DELETE FROM step_checkpoints", [])?;
        } else {
            f.store.activate_submission(&reservation, &authorized, 1)?;
        }
        assert_eq!(
            f.store
                .reconcile_unstarted_submission(f.receipt()?)
                .err()
                .ok_or("unsafe recovery")?
                .code,
            "RESULT_UNKNOWN"
        );
        assert_eq!(
            f.store.pending_submission_status("owner", "run-a")?["phase"],
            if legacy { "legacy_unknown" } else { "running" }
        );
        f.store.transition_run(transition(
            "run-a",
            "owner-cancel",
            "assess",
            "cancelled",
            "owner",
        ))?;
        assert!(f.receipt()?.result().is_none());
    }
    Ok(())
}

fn schema3(path: &std::path::Path) -> Result {
    use mtm_storage::schema::{
        SCHEMA_MIGRATIONS_TABLE_SQL, V1_WORKFLOW_SCHEMA_SQL, V2_RESEARCH_SCHEMA_SQL,
        V3_SUBMISSION_RECEIPTS_SQL,
    };
    let db = Connection::open(path)?;
    for sql in [
        SCHEMA_MIGRATIONS_TABLE_SQL,
        V1_WORKFLOW_SCHEMA_SQL,
        V2_RESEARCH_SCHEMA_SQL,
        V3_SUBMISSION_RECEIPTS_SQL,
    ] {
        db.execute_batch(sql)?;
    }
    db.execute_batch("INSERT INTO schema_migrations VALUES(1,'old','v1'),(2,'old','v2'),(3,'old','v3'); PRAGMA user_version=3;")?;
    Ok(())
}

#[test]
fn schema4_migration_preserves_schema3_and_rolls_back_on_failure() -> Result {
    let root = tempfile::tempdir()?;
    for broken in [false, true] {
        let path = root.path().join(if broken {
            "broken.sqlite3"
        } else {
            "valid.sqlite3"
        });
        schema3(&path)?;
        if broken {
            Connection::open(&path)?.execute_batch("CREATE TABLE step_checkpoints(collision);")?;
        }
        let old = std::fs::read(&path)?;
        let backup = path.with_extension("backup");
        std::fs::write(&backup, &old)?;
        let result = StateStore::open(&path);
        assert_eq!(result.is_ok(), !broken);
        let db = Connection::open(&path)?;
        assert_eq!(
            db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?,
            if broken { 3 } else { 6 }
        );
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name='creation_receipts'",
                [],
                |r| r.get::<_, i64>(0)
            )?,
            i64::from(!broken)
        );
        assert_eq!(std::fs::read(backup)?, old);
    }
    Ok(())
}
