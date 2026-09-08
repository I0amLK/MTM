use mtm_contracts::{ReCtmError, WorkflowRole, WorkflowState};
use mtm_storage::{
    CapabilityAuthority, Clock, ReferenceAuditWrite, StateStore, StoreRuntime,
    SubmissionDisposition, SubmissionExecution, SubmissionReceipt, SubmissionReservation,
    SubmissionResult, SubmissionSlot, default_permissions,
};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Barrier};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct TestClock(AtomicI64);
impl Clock for TestClock {
    fn now_iso(&self) -> std::result::Result<String, ReCtmError> {
        Ok("2026-09-08T20:00:00Z".into())
    }
    fn unix_seconds(&self) -> std::result::Result<i64, ReCtmError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    store: Arc<StateStore>,
    authority: CapabilityAuthority,
    token: String,
    reservation: SubmissionReservation,
    execution: SubmissionExecution,
    clock: Arc<TestClock>,
}

impl Fixture {
    fn new(role: WorkflowRole) -> Result<Self> {
        let root = tempfile::tempdir()?;
        let clock = Arc::new(TestClock(AtomicI64::new(1000)));
        let store = Arc::new(StateStore::open_with_runtime(
            root.path().join("state.sqlite3"),
            StoreRuntime {
                clock: clock.clone(),
                ..StoreRuntime::default()
            },
        )?);
        let state = match role {
            WorkflowRole::Verifier => "verify",
            WorkflowRole::Assembler => "assemble",
            _ => "assess",
        };
        store.create_run("run", "problem", "owner", state, &json!({}))?;
        store.create_domain("domain", "run", role.as_str(), None, None, &json!({}))?;
        let authority = CapabilityAuthority::new(&[9; 32], store.clone(), 600, None)?;
        let permissions = default_permissions(role)
            .iter()
            .map(|s| (*s).into())
            .collect::<Vec<_>>();
        let token = authority.issue("run", "domain", role, &permissions, "issue", None)?;
        let authorized = authority.authorize_submission(&token, "owner", "run", "submit")?;
        let reservation =
            match store.reserve_submission(&authorized, &"a".repeat(64), &"b".repeat(64))? {
                SubmissionSlot::Reserved(r) => r,
                _ => return Err("unexpected receipt".into()),
            };
        let execution = store.activate_submission(&reservation, &authorized, 1)?;
        Ok(Self {
            _root: root,
            store,
            authority,
            token,
            reservation,
            execution,
            clock,
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
            .ok_or("receipt missing")?)
    }

    fn accepted(&self) -> Result<i64> {
        Ok(Connection::open(self.store.path())?.query_row(
            "SELECT accepted_writes FROM step_checkpoints",
            [],
            |r| r.get(0),
        )?)
    }

    fn audit(&self) -> Result<ReferenceAuditWrite> {
        let manifest = self
            .store
            .write_proof_manifest("run", &json!({"target_statement_tex":"fixture"}))?;
        Connection::open(self.store.path())?.execute_batch("INSERT INTO references_registry(reference_id,run_id,identity_key,provider,created_at,updated_at) VALUES('ref','run','inline','inline','old','old')")?;
        Ok(ReferenceAuditWrite {
            reference_id: "ref".into(),
            disposition: "UNRESOLVED".into(),
            evidence_basis: "unresolved".into(),
            evidence_locator: String::new(),
            verifier_domain_id: "domain".into(),
            proof_sha256: "c".repeat(64),
            proof_manifest_sha256: manifest["sha256"].as_str().ok_or("digest")?.into(),
            material: true,
            assumptions_checked: false,
            notation_checked: false,
            source_checked: false,
            independently_rederived: false,
            notes: "private audit fixture".into(),
        })
    }
}

const BLOCK_ACK: &str = "CREATE TRIGGER block_ack BEFORE UPDATE ON step_checkpoints WHEN NEW.accepted_writes=1 BEGIN SELECT RAISE(ABORT,'fixture ack'); END;";

#[test]
fn a_changed_confirmation_count_cannot_commit_a_database_effect() -> Result {
    let f = Fixture::new(WorkflowRole::Assembler)?;
    let db = Connection::open(f.store.path())?;
    db.execute_batch("CREATE TRIGGER drift_ack AFTER UPDATE ON step_checkpoints WHEN NEW.accepted_writes=1 BEGIN UPDATE step_checkpoints SET accepted_writes=0; END;")?;
    assert!(
        f.store
            .write_submission_proof_manifest(&f.execution, 0, &json!({"fixture":true}))
            .is_err()
    );
    assert_eq!(f.accepted()?, 0);
    assert!(f.store.read_proof_manifest("run").is_err());
    assert!(f.receipt()?.result().is_none());
    Ok(())
}

#[test]
fn failed_manifest_insert_or_replace_rolls_back_with_the_ack() -> Result {
    for replace in [false, true] {
        let f = Fixture::new(WorkflowRole::Assembler)?;
        let old = if replace {
            Some(
                f.store
                    .write_proof_manifest("run", &json!({"old":"must remain"}))?,
            )
        } else {
            None
        };
        let db = Connection::open(f.store.path())?;
        db.execute_batch(BLOCK_ACK)?;
        assert!(
            f.store
                .write_submission_proof_manifest(&f.execution, 0, &json!({"new":"not committed"}))
                .is_err()
        );
        assert_eq!(f.store.read_proof_manifest("run").ok(), old);
        assert_eq!(f.accepted()?, 0);
        db.execute_batch("DROP TRIGGER block_ack")?;
        let recovery = f.store.submission_recovery(f.receipt()?)?;
        assert_eq!(
            f.store
                .reconcile_caller_writes(recovery, None)?
                .result()
                .ok_or("pending")?
                .writes_applied,
            0
        );
        assert!(
            f.store
                .write_submission_proof_manifest(&f.execution, 0, &json!({}))
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn failed_audit_insert_or_replace_preserves_old_row_and_counter() -> Result {
    for replace in [false, true] {
        let f = Fixture::new(WorkflowRole::Verifier)?;
        let mut audit = f.audit()?;
        let old = if replace {
            Some(f.store.write_reference_audit(
                "run",
                "ref",
                "UNRESOLVED",
                "unresolved",
                "",
                "domain",
                &audit.proof_sha256,
                &audit.proof_manifest_sha256,
                true,
                false,
                false,
                false,
                false,
                "old notes",
            )?)
        } else {
            None
        };
        audit.notes = "replacement that must roll back".into();
        let db = Connection::open(f.store.path())?;
        db.execute_batch(BLOCK_ACK)?;
        assert!(
            f.store
                .write_submission_reference_audit(&f.execution, 0, &audit)
                .is_err()
        );
        assert_eq!(f.store.get_reference_audit("run", "ref").ok(), old);
        assert_eq!(f.accepted()?, 0);
        assert!(f.receipt()?.result().is_none());
    }
    Ok(())
}

#[test]
fn committed_database_record_and_count_survive_reopen_and_cannot_be_applied_twice() -> Result {
    let f = Fixture::new(WorkflowRole::Assembler)?;
    let value = json!({"target_statement_tex":"private retained fixture"});
    let stored = f
        .store
        .write_submission_proof_manifest(&f.execution, 0, &value)?;
    let reopened = StateStore::open_with_runtime(f.store.path(), f.store.runtime())?;
    assert_eq!(reopened.read_proof_manifest("run")?, stored);
    assert_eq!(f.accepted()?, 1);
    assert!(
        reopened
            .write_submission_proof_manifest(&f.execution, 0, &value)
            .is_err()
    );
    let recovery = reopened.submission_recovery(f.receipt()?)?;
    let recovered = reopened.reconcile_caller_writes(recovery, None)?;
    assert_eq!(recovered.result().ok_or("pending")?.writes_applied, 1);
    assert!(!recovered.result().ok_or("pending")?.complete);
    assert!(reopened.list_transitions("run")?.is_empty());
    let rows = reopened.database_snapshot()?["tables"]["step_write_journals"].to_string();
    assert!(!rows.contains(&f.token) && !rows.contains("private retained fixture"));
    Ok(())
}

#[test]
fn database_write_and_recovery_have_one_winner_across_connections() -> Result {
    for _ in 0..8 {
        let f = Fixture::new(WorkflowRole::Assembler)?;
        let recovery = f.store.submission_recovery(f.receipt()?)?;
        let other = StateStore::open(f.store.path())?;
        let barrier = Arc::new(Barrier::new(2));
        let peer = barrier.clone();
        let handle = std::thread::spawn(move || {
            peer.wait();
            other.reconcile_caller_writes(recovery, None).is_ok()
        });
        barrier.wait();
        let wrote = f
            .store
            .write_submission_proof_manifest(&f.execution, 0, &json!({"n":1}))
            .is_ok();
        assert_ne!(wrote, handle.join().map_err(|_| "recovery thread failed")?);
        assert_eq!(f.accepted()?, i64::from(wrote));
        assert_eq!(f.store.read_proof_manifest("run").is_ok(), wrote);
    }
    Ok(())
}

#[test]
fn revoked_expired_or_rebound_execution_never_writes() -> Result {
    for mutation in [
        "revoked",
        "expired",
        "epoch",
        "owner",
        "domain",
        "permissions",
    ] {
        let f = Fixture::new(WorkflowRole::Assembler)?;
        let db = Connection::open(f.store.path())?;
        match mutation {
            "revoked" => {
                f.authority.revoke(&f.token, "fixture", "revoke")?;
            }
            "expired" => {
                f.clock.0.store(2000, Ordering::SeqCst);
            }
            "epoch" => {
                db.execute("UPDATE runs SET epoch=epoch+1", [])?;
            }
            "owner" => {
                db.execute("UPDATE runs SET owner_id='other'", [])?;
            }
            "domain" => {
                db.execute("UPDATE domains SET status='sealed'", [])?;
            }
            _ => {
                db.execute(
                    "UPDATE capabilities SET permissions_json='[\"commit:workflow\"]'",
                    [],
                )?;
            }
        }
        assert!(
            f.store
                .write_submission_proof_manifest(&f.execution, 0, &json!({}))
                .is_err(),
            "{mutation}"
        );
        assert_eq!(f.accepted()?, 0);
        assert!(f.store.read_proof_manifest("run").is_err());
    }
    Ok(())
}

#[test]
fn resource_domain_reference_and_manifest_bindings_are_rechecked() -> Result {
    let generator = Fixture::new(WorkflowRole::Generator)?;
    assert!(
        generator
            .store
            .write_submission_proof_manifest(&generator.execution, 0, &json!({}))
            .is_err()
    );
    for mutation in ["domain", "manifest", "foreign_reference", "disposition"] {
        let f = Fixture::new(WorkflowRole::Verifier)?;
        let mut audit = f.audit()?;
        match mutation {
            "domain" => {
                audit.verifier_domain_id = "another-domain".into();
            }
            "manifest" => {
                f.store
                    .write_proof_manifest("run", &json!({"changed":true}))?;
            }
            "foreign_reference" => {
                f.store
                    .create_run("other", "p", "other", "assess", &json!({}))?;
                Connection::open(f.store.path())?
                    .execute("UPDATE references_registry SET run_id='other'", [])?;
            }
            _ => {
                audit.disposition = "UNSUPPORTED".into();
            }
        }
        assert!(
            f.store
                .write_submission_reference_audit(&f.execution, 0, &audit)
                .is_err(),
            "{mutation}"
        );
        assert_eq!(f.accepted()?, 0);
        assert!(f.store.get_reference_audit("run", "ref").is_err());
    }
    Ok(())
}

#[test]
fn wrong_summary_counts_and_legacy_opaque_journals_never_clear_pending() -> Result {
    let f = Fixture::new(WorkflowRole::Assembler)?;
    f.store
        .write_submission_proof_manifest(&f.execution, 0, &json!({}))?;
    let summary = SubmissionResult {
        disposition: SubmissionDisposition::CorrectionRequired,
        state: WorkflowState::Assemble,
        writes_applied: 0,
        complete: false,
        error_code: Some("INVALID_ARGUMENT".into()),
    };
    assert!(
        f.store
            .record_submission_outcome(&f.reservation, &summary)
            .is_err()
    );
    assert!(f.receipt()?.result().is_none());
    let correct = SubmissionResult {
        writes_applied: 1,
        ..summary
    };
    assert!(
        f.store
            .record_submission_outcome(&f.reservation, &correct)
            .is_ok()
    );
    let old = Fixture::new(WorkflowRole::Assembler)?;
    old.store.begin_submission_write(&old.execution, 0, None)?;
    assert!(
        old.store
            .write_submission_proof_manifest(&old.execution, 0, &json!({}))
            .is_err()
    );
    let recovery = old.store.submission_recovery(old.receipt()?)?;
    assert!(old.store.reconcile_caller_writes(recovery, None).is_err());
    Ok(())
}

#[test]
fn bad_indices_oversized_records_and_corrupt_confirmation_roll_back() -> Result {
    let f = Fixture::new(WorkflowRole::Assembler)?;
    for (index, value) in [
        (1, json!({})),
        (65_536, json!({})),
        (0, Value::Null),
        (0, json!({"oversized":"x".repeat(1024*1024)})),
    ] {
        assert!(
            f.store
                .write_submission_proof_manifest(&f.execution, index, &value)
                .is_err()
        );
    }
    let db = Connection::open(f.store.path())?;
    db.execute_batch("CREATE TRIGGER corrupt_ack AFTER UPDATE ON step_checkpoints BEGIN UPDATE step_write_journals SET marker_json='{}'; END;")?;
    assert!(
        f.store
            .write_submission_proof_manifest(&f.execution, 0, &json!({}))
            .is_err()
    );
    assert_eq!(f.accepted()?, 0);
    assert!(f.store.read_proof_manifest("run").is_err());
    db.execute_batch("DROP TRIGGER corrupt_ack")?;
    assert!(
        f.store
            .reconcile_caller_writes(f.store.submission_recovery(f.receipt()?)?, None)
            .is_ok()
    );
    Ok(())
}
