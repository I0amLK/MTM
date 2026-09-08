use mtm_contracts::WorkflowRole;
use mtm_storage::{
    CapabilityAuthority, FileEffectEvidence, FileImage, StateStore, SubmissionExecution,
    SubmissionReceipt, SubmissionSlot, default_permissions,
};
use rusqlite::Connection;
use serde_json::json;
use std::sync::{Arc, Barrier};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Fixture {
    _root: tempfile::TempDir,
    store: Arc<StateStore>,
    authority: CapabilityAuthority,
    token: String,
    execution: SubmissionExecution,
    reservation: mtm_storage::SubmissionReservation,
}

impl Fixture {
    fn new(writes: usize) -> Result<Self> {
        let root = tempfile::tempdir()?;
        let store = Arc::new(StateStore::open(root.path().join("state.sqlite3"))?);
        store.create_run("run", "problem", "owner", "assess", &json!({}))?;
        store.create_domain("domain", "run", "generator", None, None, &json!({}))?;
        let authority = CapabilityAuthority::new(&[5; 32], store.clone(), 600, None)?;
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
        let reservation =
            match store.reserve_submission(&authorized, &"a".repeat(64), &"b".repeat(64))? {
                SubmissionSlot::Reserved(r) => r,
                _ => return Err("unexpected existing receipt".into()),
            };
        let execution = store.activate_submission(&reservation, &authorized, writes)?;
        Ok(Self {
            _root: root,
            store,
            authority,
            token,
            execution,
            reservation,
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
}

fn image(letter: char) -> FileImage {
    FileImage {
        bytes: 10,
        sha256: letter.to_string().repeat(64),
    }
}

fn effect() -> FileEffectEvidence {
    FileEffectEvidence {
        relative_path: "memory/generation/events.jsonl".into(),
        before: Some(image('c')),
        after: image('d'),
    }
}

#[test]
fn file_evidence_cannot_borrow_another_role_and_corrupt_ack_rolls_back() -> Result {
    let f = Fixture::new(1)?;
    for relative in [
        "memory/verifier/events.jsonl",
        "draft/proof.tex",
        "branches/foreign/memory/events.jsonl",
    ] {
        let mut evidence = effect();
        evidence.relative_path = relative.into();
        assert!(
            f.store
                .begin_submission_write(&f.execution, 0, Some(&evidence))
                .is_err()
        );
    }
    f.store
        .begin_submission_write(&f.execution, 0, Some(&effect()))?;
    let db = Connection::open(f.store.path())?;
    db.execute("UPDATE step_write_journals SET marker_json='{}'", [])?;
    let fake_correction = mtm_storage::SubmissionResult {
        disposition: mtm_storage::SubmissionDisposition::CorrectionRequired,
        state: mtm_contracts::WorkflowState::Assess,
        writes_applied: 0,
        complete: false,
        error_code: Some("INVALID_ARGUMENT".into()),
    };
    assert!(
        f.store
            .record_submission_outcome(&f.reservation, &fake_correction)
            .is_err()
    );
    assert!(
        f.store
            .checkpoint_submission_write(&f.execution, 1)
            .is_err()
    );
    let count: i64 = db.query_row("SELECT accepted_writes FROM step_checkpoints", [], |r| {
        r.get(0)
    })?;
    assert_eq!(count, 0);
    assert!(f.receipt()?.result().is_none());
    Ok(())
}

#[test]
fn before_after_and_conflict_images_resolve_only_proven_effects() -> Result {
    for (actual, expected) in [
        (Some(image('c')), Some(0)),
        (Some(image('d')), Some(1)),
        (Some(image('e')), None),
        (None, None),
    ] {
        let f = Fixture::new(1)?;
        f.store
            .begin_submission_write(&f.execution, 0, Some(&effect()))?;
        let observed = f.store.submission_recovery(f.receipt()?)?;
        let recovered = f.store.reconcile_caller_writes(observed, Some(actual));
        if let Some(expected) = expected {
            let result = recovered?;
            let result = result.result().ok_or("missing result")?;
            assert_eq!(result.writes_applied, expected);
            assert_eq!(result.error_code.as_deref(), Some("SUBMISSION_INTERRUPTED"));
            assert!(!result.complete);
            assert!(
                f.store
                    .begin_submission_write(&f.execution, 0, None)
                    .is_err()
            );
        } else {
            assert!(recovered.is_err());
            assert!(f.receipt()?.result().is_none());
        }
        assert!(f.store.list_transitions("run")?.is_empty());
    }
    Ok(())
}

#[test]
fn between_writes_recovers_prefix_without_accepting_missing_writes() -> Result {
    let f = Fixture::new(3)?;
    f.store.begin_submission_write(&f.execution, 0, None)?;
    f.store.checkpoint_submission_write(&f.execution, 1)?;
    let snapshot = f.store.submission_recovery(f.receipt()?)?;
    let recovered = f.store.reconcile_caller_writes(snapshot, None)?;
    assert_eq!(recovered.result().ok_or("pending")?.writes_applied, 1);
    assert!(
        f.store
            .begin_submission_write(&f.execution, 1, None)
            .is_err()
    );
    assert!(f.store.arm_submission_commit(&f.execution).is_err());
    Ok(())
}

#[test]
fn write_activation_and_reconciliation_have_one_winner() -> Result {
    for _ in 0..8 {
        let f = Fixture::new(1)?;
        let snapshot = f.store.submission_recovery(f.receipt()?)?;
        let store = StateStore::open(f.store.path())?;
        let barrier = Arc::new(Barrier::new(2));
        let peer = barrier.clone();
        let recovery = std::thread::spawn(move || {
            peer.wait();
            store.reconcile_caller_writes(snapshot, None).is_ok()
        });
        barrier.wait();
        let started = f
            .store
            .begin_submission_write(&f.execution, 0, None)
            .is_ok();
        assert_ne!(started, recovery.join().map_err(|_| "thread failure")?);
    }
    Ok(())
}

#[test]
fn failed_checkpoint_keeps_the_file_journal_and_exact_prefix() -> Result {
    let f = Fixture::new(2)?;
    f.store
        .begin_submission_write(&f.execution, 0, Some(&effect()))?;
    let db = Connection::open(f.store.path())?;
    db.execute_batch("CREATE TRIGGER block_ack BEFORE UPDATE ON step_checkpoints BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;
    assert!(
        f.store
            .checkpoint_submission_write(&f.execution, 1)
            .is_err()
    );
    db.execute_batch("DROP TRIGGER block_ack")?;
    let reopened = StateStore::open(f.store.path())?;
    let observed = reopened.submission_recovery(f.receipt()?)?;
    assert_eq!(observed.file_evidence(), Some(&effect()));
    let recovered = reopened.reconcile_caller_writes(observed, Some(Some(image('d'))))?;
    assert_eq!(recovered.result().ok_or("pending")?.writes_applied, 1);
    Ok(())
}

#[test]
fn opaque_commit_ready_legacy_and_ambiguous_writes_stay_unknown() -> Result {
    for kind in ["opaque", "commit", "legacy", "ambiguous", "corrupt"] {
        let f = Fixture::new(1)?;
        match kind {
            "legacy" => {
                Connection::open(f.store.path())?.execute("DELETE FROM step_write_journals", [])?;
            }
            "corrupt" => {
                Connection::open(f.store.path())?
                    .execute("UPDATE step_write_journals SET marker_json='{}'", [])?;
            }
            "ambiguous" => {
                let mut e = effect();
                e.after = image('c');
                f.store.begin_submission_write(&f.execution, 0, Some(&e))?;
            }
            _ => {
                f.store.begin_submission_write(&f.execution, 0, None)?;
            }
        }
        if kind == "commit" {
            f.store.checkpoint_submission_write(&f.execution, 1)?;
            f.store.arm_submission_commit(&f.execution)?;
        }
        let recovered = f
            .store
            .submission_recovery(f.receipt()?)
            .and_then(|s| f.store.reconcile_caller_writes(s, Some(Some(image('c')))));
        assert!(recovered.is_err(), "{kind}");
        assert!(f.receipt()?.result().is_none());
    }
    Ok(())
}

#[test]
fn invalid_locators_and_changed_authority_fail_before_installing_evidence() -> Result {
    let f = Fixture::new(1)?;
    for path in [
        "../outside",
        "final/proof_verified.tex",
        "memory/generation/../events.jsonl",
        "/absolute",
        "branches/../memory/events.jsonl",
    ] {
        let mut e = effect();
        e.relative_path = path.into();
        assert!(
            f.store
                .begin_submission_write(&f.execution, 0, Some(&e))
                .is_err()
        );
    }
    let mut e = effect();
    e.after.bytes = 64 * 1024 * 1024 + 1;
    assert!(
        f.store
            .begin_submission_write(&f.execution, 0, Some(&e))
            .is_err()
    );
    assert!(
        f.store
            .begin_submission_write(&f.execution, 1, None)
            .is_err()
    );
    Connection::open(f.store.path())?.execute("UPDATE runs SET epoch=epoch+1", [])?;
    assert!(
        f.store
            .begin_submission_write(&f.execution, 0, Some(&effect()))
            .is_err()
    );
    Ok(())
}

#[test]
fn schema6_preserves_legacy_journals_and_migration_rollback() -> Result {
    use mtm_storage::schema::{
        SCHEMA_MIGRATIONS_TABLE_SQL, V1_WORKFLOW_SCHEMA_SQL, V2_RESEARCH_SCHEMA_SQL,
        V3_SUBMISSION_RECEIPTS_SQL, V4_RECOVERY_SQL, V5_CREATION_INITIALIZATION_SQL,
    };
    for collision in [false, true] {
        let root = tempfile::tempdir()?;
        let path = root.path().join("old.sqlite3");
        let db = Connection::open(&path)?;
        for sql in [
            SCHEMA_MIGRATIONS_TABLE_SQL,
            V1_WORKFLOW_SCHEMA_SQL,
            V2_RESEARCH_SCHEMA_SQL,
            V3_SUBMISSION_RECEIPTS_SQL,
            V4_RECOVERY_SQL,
            V5_CREATION_INITIALIZATION_SQL,
        ] {
            db.execute_batch(sql)?;
        }
        db.execute_batch("INSERT INTO runs(run_id,problem_id,owner_id,state,status,created_at,updated_at) VALUES('legacy','p','owner','assess','active','old','old'); INSERT INTO domains(domain_id,run_id,role,status,created_at) VALUES('legacy-domain','legacy','generator','open','old'); PRAGMA user_version=5;")?;
        for version in 1..=5 {
            db.execute(
                "INSERT INTO schema_migrations VALUES(?,'old','historical fixture')",
                [version],
            )?;
        }
        db.execute("INSERT INTO step_receipts VALUES(?,'owner',?,?,'legacy','legacy-domain','generator',1,'assess','pending',NULL,'old',NULL)",
            rusqlite::params!["a".repeat(64),"b".repeat(64),"c".repeat(64)])?;
        db.execute(
            "INSERT INTO step_checkpoints VALUES(?,?,'running',1,0)",
            rusqlite::params!["a".repeat(64), "d".repeat(32)],
        )?;
        if collision {
            db.execute_batch("CREATE TABLE step_write_journals(collision)")?;
        }
        drop(db);
        let old_bytes = std::fs::read(&path)?;
        let copy = root.path().join("rollback.sqlite3");
        std::fs::write(&copy, &old_bytes)?;
        let opened = StateStore::open(&path);
        assert_eq!(opened.is_ok(), !collision);
        let db = Connection::open(&path)?;
        let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        assert_eq!(version, if collision { 5 } else { 6 });
        let count: i64 =
            db.query_row("SELECT COUNT(*) FROM step_write_journals", [], |r| r.get(0))?;
        assert_eq!(count, 0);
        let status: String = db.query_row("SELECT status FROM step_receipts", [], |r| r.get(0))?;
        assert_eq!(status, "pending");
        assert_eq!(std::fs::read(copy)?, old_bytes);
        if let Ok(store) = opened {
            let pending = store.pending_submission_status("owner", "legacy")?;
            assert_eq!(pending["caller_write_recovery"]["kind"], "legacy_unknown");
            assert_eq!(
                pending["caller_write_recovery"]["recover_only_may_reconcile"],
                false
            );
        }
    }
    Ok(())
}
