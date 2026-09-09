use std::sync::Arc;

use mtm_contracts::{WorkflowRole, WorkflowState};
use mtm_storage::{
    CapabilityAuthority, CapabilityClaims, RestartableActionKind, StateStore,
    SubmissionDisposition, SubmissionExecution, SubmissionReceipt, SubmissionSlot, TaskTransition,
    TransitionRun, default_permissions,
};
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
    fn new() -> Result<Self> {
        let root = tempfile::tempdir()?;
        let store = Arc::new(StateStore::open(root.path().join("state.sqlite3"))?);
        store.create_run(
            "run",
            "problem",
            "owner",
            "propose_plans",
            &json!({"workflow_protocol_version":3}),
        )?;
        store.create_domain(
            "domain",
            "run",
            "generator",
            None,
            None,
            &json!({"state":"propose_plans"}),
        )?;
        let authority = CapabilityAuthority::new(&[44; 32], store.clone(), 600, None)?;
        let permissions = default_permissions(WorkflowRole::Generator)
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        let token = authority.issue(
            "run",
            "domain",
            WorkflowRole::Generator,
            &permissions,
            "fixture",
            None,
        )?;
        let authorized = authority.authorize_submission(&token, "owner", "run", "reserve")?;
        let claims =
            authority.validate(&token, "owner", "commit", "workflow", "claims", Some("run"))?;
        let reservation =
            match store.reserve_submission(&authorized, &"a".repeat(64), &"b".repeat(64))? {
                SubmissionSlot::Reserved(value) => value,
                SubmissionSlot::Existing(_) => return Err("unexpected existing receipt".into()),
            };
        let execution = store.activate_submission(&reservation, &authorized, 0)?;
        store.arm_submission_commit(&execution)?;
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

    fn commit(&self) -> Result<Value> {
        let updates = Map::new();
        Ok(self.store.transition_task(
            &self.claims,
            TaskTransition {
                transition: TransitionRun {
                    run_id: "run",
                    expected_state: "propose_plans",
                    after_state: "direct_proving",
                    trace_id: self.execution.trace_id(),
                    actor: "generator",
                    reason: "plans_proposed",
                    evidence: &json!({}),
                    increment_epoch: true,
                    status: None,
                    latex_passed: None,
                    verdict: None,
                    sealed: None,
                    round_delta: 0,
                },
                expected_metadata: None,
                metadata_updates: &updates,
                project_mode: None,
                branch: None,
                restartable_action: Some(RestartableActionKind::PlansProposed),
            },
        )?)
    }
}

#[test]
fn restartable_marker_can_close_unknown_without_executing_action() -> Result {
    let f = Fixture::new()?;
    f.store.enroll_restartable_action(
        &f.claims,
        f.execution.trace_id(),
        RestartableActionKind::PlansProposed,
    )?;
    let recovered = f
        .store
        .reconcile_caller_writes(f.store.submission_recovery(f.receipt()?)?, None)?;
    let result = recovered.result().ok_or("missing recovery result")?;
    assert_eq!(
        result.disposition,
        SubmissionDisposition::CorrectionRequired
    );
    assert_eq!(result.state, WorkflowState::ProposePlans);
    assert_eq!(result.writes_applied, 0);
    assert_eq!(result.error_code.as_deref(), Some("SUBMISSION_INTERRUPTED"));
    assert_eq!(f.store.get_run("run")?["state"], "propose_plans");
    assert_eq!(f.store.get_domain("domain")?["status"], "open");
    assert!(f.store.list_transitions("run")?.is_empty());
    assert!(f.commit().is_err());
    Ok(())
}

#[test]
fn restartable_action_transition_and_receipt_commit_together() -> Result {
    let f = Fixture::new()?;
    f.store.enroll_restartable_action(
        &f.claims,
        f.execution.trace_id(),
        RestartableActionKind::PlansProposed,
    )?;
    let run = f.commit()?;
    assert_eq!(run["state"], "direct_proving");
    assert_eq!(f.store.get_domain("domain")?["status"], "sealed");
    assert_eq!(f.store.list_transitions("run")?.len(), 1);
    let receipt = f.receipt()?;
    let result = receipt.result().ok_or("missing applied receipt")?;
    assert_eq!(result.disposition, SubmissionDisposition::Applied);
    assert_eq!(result.state, WorkflowState::DirectProving);
    assert!(result.complete);
    Ok(())
}

#[test]
fn legacy_unmarked_and_wrong_state_actions_are_never_adopted() -> Result {
    let legacy = Fixture::new()?;
    assert!(
        legacy
            .store
            .reconcile_caller_writes(legacy.store.submission_recovery(legacy.receipt()?)?, None,)
            .is_err()
    );
    assert!(legacy.receipt()?.result().is_none());

    let wrong = Fixture::new()?;
    assert!(
        wrong
            .store
            .enroll_restartable_action(
                &wrong.claims,
                wrong.execution.trace_id(),
                RestartableActionKind::VerificationSubmitted,
            )
            .is_err()
    );
    assert!(wrong.receipt()?.result().is_none());
    Ok(())
}

#[test]
fn recovered_old_receipt_does_not_block_a_fresh_restartable_submission() -> Result {
    let f = Fixture::new()?;
    f.store.enroll_restartable_action(
        &f.claims,
        f.execution.trace_id(),
        RestartableActionKind::PlansProposed,
    )?;
    f.store
        .reconcile_caller_writes(f.store.submission_recovery(f.receipt()?)?, None)?;

    let permissions = default_permissions(WorkflowRole::Generator)
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    let fresh_token = f.authority.issue(
        "run",
        "domain",
        WorkflowRole::Generator,
        &permissions,
        "fresh",
        None,
    )?;
    let authorized =
        f.authority
            .authorize_submission(&fresh_token, "owner", "run", "reserve-fresh")?;
    let claims = f.authority.validate(
        &fresh_token,
        "owner",
        "commit",
        "workflow",
        "claims-fresh",
        Some("run"),
    )?;
    let reservation =
        match f
            .store
            .reserve_submission(&authorized, &"c".repeat(64), &"d".repeat(64))?
        {
            SubmissionSlot::Reserved(value) => value,
            SubmissionSlot::Existing(_) => return Err("fresh receipt unexpectedly existed".into()),
        };
    let execution = f.store.activate_submission(&reservation, &authorized, 0)?;
    f.store.arm_submission_commit(&execution)?;
    f.store.enroll_restartable_action(
        &claims,
        execution.trace_id(),
        RestartableActionKind::PlansProposed,
    )?;
    let before = f.store.get_run("run")?["metadata"].clone();
    let updates = Map::from_iter([
        ("active_plans".to_owned(), json!([{"plan_id":"plan-r1-1"}])),
        ("direct_screening_progress".to_owned(), json!({})),
    ]);
    let run = f.store.transition_task(
        &claims,
        TaskTransition {
            transition: TransitionRun {
                run_id: "run",
                expected_state: "propose_plans",
                after_state: "direct_proving",
                trace_id: execution.trace_id(),
                actor: "generator",
                reason: "plans_proposed",
                evidence: &json!({}),
                increment_epoch: true,
                status: None,
                latex_passed: None,
                verdict: None,
                sealed: None,
                round_delta: 0,
            },
            expected_metadata: Some(&before),
            metadata_updates: &updates,
            project_mode: None,
            branch: None,
            restartable_action: Some(RestartableActionKind::PlansProposed),
        },
    )?;
    assert_eq!(run["state"], "direct_proving");
    Ok(())
}
