use mtm_storage::{BranchPreparation, PreparedBranch, StateStore, TransitionRun};
use rusqlite::Connection;
use serde_json::{Value, json};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn branches() -> Vec<PreparedBranch> {
    (0..2)
        .map(|index| PreparedBranch {
            branch_id: format!("branch-1-{}-fixed", index + 1),
            plan_id: format!("plan-{}", index + 1),
            domain_id: format!("branch-domain-{}", index + 1),
            snapshot_id: "round-1-fixed".into(),
            order_index: index,
            domain_metadata: json!({"state":"branch_run","branch_id":format!("branch-1-{}-fixed",index+1),"snapshot_id":"round-1-fixed"}),
            branch_metadata: json!({"plan":{"plan_id":format!("plan-{}",index+1)}}),
        })
        .collect()
}

fn requests() -> Value {
    json!([{"plan_id":"plan-1"},{"plan_id":"plan-2"}])
}

fn setup() -> Result<(tempfile::TempDir, StateStore)> {
    let root = tempfile::tempdir()?;
    let store = StateStore::open(root.path().join("state.sqlite3"))?;
    store.create_run(
        "run",
        "p",
        "owner",
        "branch_prepare",
        &json!({"branch_requests":requests(),"untouched":true}),
    )?;
    Ok((root, store))
}

fn complete(store: &StateStore) -> std::result::Result<Value, mtm_contracts::ReCtmError> {
    let branch_rows = branches();
    let expected = requests();
    let evidence = json!({"snapshot_id":"round-1-fixed","branch_count":2});
    store.complete_branch_preparation(BranchPreparation {
        transition: TransitionRun {
            run_id: "run",
            expected_state: "branch_prepare",
            after_state: "branch_run",
            trace_id: "mechanical",
            actor: "system",
            reason: "frozen_snapshot_and_branch_domains_created",
            evidence: &evidence,
            increment_epoch: true,
            status: None,
            latex_passed: None,
            verdict: None,
            sealed: None,
            round_delta: 1,
        },
        expected_branch_requests: &expected,
        snapshot_id: "round-1-fixed",
        branches: &branch_rows,
    })
}

#[test]
fn branch_rows_metadata_and_transition_commit_as_one_transaction() -> Result {
    let (_root, store) = setup()?;
    let result = complete(&store)?;
    assert_eq!(result["state"], "branch_run");
    assert_eq!(result["round_index"], 1);
    assert_eq!(result["metadata"]["active_snapshot_id"], "round-1-fixed");
    assert_eq!(result["metadata"]["branch_requests"], json!([]));
    assert_eq!(store.list_branches("run")?.len(), 2);
    assert_eq!(store.list_domains("run", Some("branch"), None)?.len(), 2);
    assert_eq!(store.list_transitions("run")?.len(), 1);
    Ok(())
}

#[test]
fn any_transition_failure_rolls_back_all_branch_database_effects() -> Result {
    let (_root, store) = setup()?;
    let before = store.database_snapshot()?;
    let db = Connection::open(store.path())?;
    db.execute_batch(
        "CREATE TRIGGER fail_mechanical BEFORE INSERT ON transitions BEGIN SELECT RAISE(ABORT,'fixture'); END;",
    )?;
    assert!(complete(&store).is_err());
    assert_eq!(store.database_snapshot()?, before);
    db.execute_batch("DROP TRIGGER fail_mechanical")?;
    assert_eq!(complete(&store)?["state"], "branch_run");
    assert_eq!(store.list_branches("run")?.len(), 2);
    Ok(())
}

#[test]
fn legacy_partial_current_round_is_refused_instead_of_adopted_or_duplicated() -> Result {
    let (_root, store) = setup()?;
    let db = Connection::open(store.path())?;
    db.execute_batch(
        "INSERT INTO domains(domain_id,run_id,role,status,snapshot_id,order_index,metadata_json,created_at) VALUES('legacy-domain','run','branch','open','round-1-legacy',0,'{}','old');
         INSERT INTO branches(branch_id,run_id,plan_id,domain_id,snapshot_id,order_index,status,metadata_json,created_at) VALUES('legacy-branch','run','legacy-plan','legacy-domain','round-1-legacy',0,'pending','{}','old');",
    )?;
    let before = store.database_snapshot()?;
    let error = complete(&store).err().ok_or("legacy partial was adopted")?;
    assert_eq!(error.code, "MECHANICAL_LEGACY_PARTIAL_UNKNOWN");
    assert_eq!(store.database_snapshot()?, before);
    Ok(())
}

#[test]
fn latex_result_and_transition_commit_or_roll_back_together() -> Result {
    let root = tempfile::tempdir()?;
    let store = StateStore::open(root.path().join("state.sqlite3"))?;
    store.create_run(
        "latex-run",
        "p",
        "owner",
        "latex_validate",
        &json!({"stable":true}),
    )?;
    let expected = json!({"stable":true});
    let result = json!({"gate_passed":true,"compile_attempted":true});
    let evidence = result.clone();
    let transition = || TransitionRun {
        run_id: "latex-run",
        expected_state: "latex_validate",
        after_state: "verify",
        trace_id: "latex-trace",
        actor: "latex_gate",
        reason: "latex_gate_passed",
        evidence: &evidence,
        increment_epoch: true,
        status: None,
        latex_passed: Some(true),
        verdict: None,
        sealed: None,
        round_delta: 0,
    };
    let db = Connection::open(store.path())?;
    let before = store.database_snapshot()?;
    db.execute_batch(
        "CREATE TRIGGER fail_latex BEFORE INSERT ON transitions BEGIN SELECT RAISE(ABORT,'fixture'); END;",
    )?;
    assert!(
        store
            .complete_latex_gate(transition(), &expected, &result)
            .is_err()
    );
    assert_eq!(store.database_snapshot()?, before);
    db.execute_batch("DROP TRIGGER fail_latex")?;
    let updated = store.complete_latex_gate(transition(), &expected, &result)?;
    assert_eq!(updated["state"], "verify");
    assert_eq!(updated["latex_passed"], true);
    assert_eq!(updated["metadata"]["latex_result"], result);
    assert_eq!(store.list_transitions("latex-run")?.len(), 1);
    Ok(())
}
