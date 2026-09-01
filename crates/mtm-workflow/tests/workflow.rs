use std::path::Path;
use std::sync::Arc;

use mtm_contracts::{ErrorCategory, ReCtmError};
use mtm_storage::{CapabilityAuthority, StateStore};
use mtm_workflow::{
    LatexGate, LatexGateResult, PrivateVault, StartRequest, TaskCatalog, WorkflowEngine,
};
use serde_json::Value;

struct PassingLatex;

impl LatexGate for PassingLatex {
    fn validate(&self, _proof: &str, _workdir: &Path) -> Result<LatexGateResult, ReCtmError> {
        Ok(LatexGateResult {
            policy: "test".to_owned(),
            static_valid: true,
            compile_attempted: true,
            compile_available: true,
            compile_passed: true,
            gate_passed: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            compiler_output: String::new(),
        })
    }
}

struct FailingLatex;

impl LatexGate for FailingLatex {
    fn validate(&self, _proof: &str, _workdir: &Path) -> Result<LatexGateResult, ReCtmError> {
        Ok(LatexGateResult {
            policy: "test".to_owned(),
            static_valid: false,
            compile_attempted: true,
            compile_available: true,
            compile_passed: false,
            gate_passed: false,
            errors: vec!["synthetic failure".to_owned()],
            warnings: Vec::new(),
            compiler_output: "synthetic failure".to_owned(),
        })
    }
}

fn task(action: &str) -> Value {
    serde_json::json!({
        "commit_action":action,
        "write_contract":[],
        "commit_payload_schema":{"type":"object","additionalProperties":true},
        "minimal_submission":{}
    })
}

fn catalog() -> Result<TaskCatalog, ReCtmError> {
    TaskCatalog::from_source_snapshot(serde_json::json!({
        "tasks":{
            "assess":task("assessment_complete"),
            "explore":task("exploration_complete"),
            "propose_plans":task("plans_proposed"),
            "direct_proving":task("direct_proving_complete"),
            "branch_run":task("branch_complete"),
            "branch_join":task("join_complete"),
            "identify_failures":task("failures_identified"),
            "replan":task("replan_complete"),
            "assemble":task("proof_submitted"),
            "verify":task("verification_submitted"),
            "repair":task("repair_submitted")
        }
    }))
}

fn engine(root: &Path, latex: Arc<dyn LatexGate>) -> Result<WorkflowEngine, ReCtmError> {
    let store = Arc::new(StateStore::open(root.join("state.sqlite3"))?);
    let vault = Arc::new(PrivateVault::new(root.join("private"))?);
    let capability = Arc::new(CapabilityAuthority::new(
        b"cccccccccccccccccccccccccccccccc",
        Arc::clone(&store),
        600,
        None,
    )?);
    Ok(WorkflowEngine::new(
        store,
        vault,
        capability,
        Arc::new(catalog()?),
        latex,
        None,
    ))
}

fn start_compact(engine: &WorkflowEngine) -> Result<String, ReCtmError> {
    let started = engine.start(StartRequest {
        owner_id: "owner",
        problem_tex: r"\begin{proposition}Prove $1=1$.\end{proposition}",
        problem_id: Some("one-equals-one"),
        references: &[],
        native_mode: "dangerous",
        workspace_export_path: None,
        project_id: None,
        target_claim_id: None,
        workflow_mode: "compact",
        register_result: true,
        workflow_protocol_version: 2,
        trace_id: Some("trace-start"),
    })?;
    started
        .get("run_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            ReCtmError::new("TEST_FAILURE", "run_id missing").with_category(ErrorCategory::Internal)
        })
}

fn capability(task: &Value) -> Result<&str, ReCtmError> {
    task.get("capability")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ReCtmError::new("TEST_FAILURE", "capability missing")
                .with_category(ErrorCategory::Internal)
        })
}

#[test]
fn compact_correct_flow_reaches_mechanical_finalization() -> Result<(), ReCtmError> {
    let temp = tempfile::tempdir().map_err(|error| {
        ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
    })?;
    let engine = engine(temp.path(), Arc::new(PassingLatex))?;
    let run_id = start_compact(&engine)?;

    let assess = engine.next_task("owner", &run_id, Some("trace-assess"))?;
    engine.write(
        "owner",
        capability(&assess)?,
        "memory:generation:immediate_conclusions",
        &serde_json::json!({"summary":"Reflexivity."}),
        Some("trace-write-assess"),
    )?;
    let assembled = engine.commit(
        "owner",
        capability(&assess)?,
        "assessment_complete",
        &serde_json::json!({
            "route":"compact","route_reason":"direct",
            "requires_external_retrieval":false,"requires_multiple_plans":false
        }),
        Some("trace-commit-assess"),
    )?;
    assert_eq!(assembled["state"], "assemble");

    let assembler = engine.next_task("owner", &run_id, Some("trace-assembler"))?;
    let proof = r"\begin{proof}By reflexivity.\end{proof}";
    engine.write(
        "owner",
        capability(&assembler)?,
        "proof",
        &Value::String(proof.to_owned()),
        Some("trace-proof"),
    )?;
    engine.write(
        "owner",
        capability(&assembler)?,
        "proof_manifest",
        &serde_json::json!({
            "target_statement_tex":"Prove $1=1$.",
            "dependency_revision_ids":[],"reference_ids":[],
            "conditional_hypotheses":[],"computational_evidence":[]
        }),
        Some("trace-manifest"),
    )?;
    let latex = engine.commit(
        "owner",
        capability(&assembler)?,
        "proof_submitted",
        &serde_json::json!({"outcome":"proof"}),
        Some("trace-submit-proof"),
    )?;
    assert_eq!(latex["state"], "latex_validate");

    let verifier = engine.next_task("owner", &run_id, Some("trace-verifier"))?;
    assert_eq!(verifier["state"], "verify");
    engine.write(
        "owner",
        capability(&verifier)?,
        "memory:verifier:statement_checks",
        &serde_json::json!({"location":"proof","status":"checked"}),
        Some("trace-statement"),
    )?;
    engine.write(
        "owner",
        capability(&verifier)?,
        "memory:verifier:events",
        &serde_json::json!({"event_type":"verification_audit_complete"}),
        Some("trace-verifier-event"),
    )?;
    engine.write(
        "owner",
        capability(&verifier)?,
        "verification_report",
        &serde_json::json!({
            "verification_report":{"summary":"Every step is valid.","critical_errors":[],"gaps":[]},
            "verdict":"wrong",
            "repair_hints":"model verdict must be ignored"
        }),
        Some("trace-report"),
    )?;
    let finalized = engine.commit(
        "owner",
        capability(&verifier)?,
        "verification_submitted",
        &serde_json::json!({}),
        Some("trace-submit-verification"),
    )?;
    assert_eq!(finalized["state"], "finalize");
    assert_eq!(finalized["verdict"], "correct");

    let done = engine.next_task("owner", &run_id, Some("trace-finalize"))?;
    assert_eq!(done["state"], "done");
    assert_eq!(done["terminal"], true);
    let artifact = engine.get_artifact("owner", &run_id, "final_tex")?;
    assert_eq!(artifact["content"], proof);
    Ok(())
}

#[test]
fn latex_failure_routes_to_repair_without_final_artifact() -> Result<(), ReCtmError> {
    let temp = tempfile::tempdir().map_err(|error| {
        ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
    })?;
    let engine = engine(temp.path(), Arc::new(FailingLatex))?;
    let run_id = start_compact(&engine)?;
    let assess = engine.next_task("owner", &run_id, None)?;
    engine.write(
        "owner",
        capability(&assess)?,
        "memory:generation:immediate_conclusions",
        &serde_json::json!({"summary":"direct"}),
        None,
    )?;
    engine.commit(
        "owner",
        capability(&assess)?,
        "assessment_complete",
        &serde_json::json!({"route":"compact","requires_external_retrieval":false,"requires_multiple_plans":false}),
        None,
    )?;
    let assembler = engine.next_task("owner", &run_id, None)?;
    engine.write(
        "owner",
        capability(&assembler)?,
        "proof",
        &Value::String("broken proof".to_owned()),
        None,
    )?;
    engine.write(
        "owner",
        capability(&assembler)?,
        "proof_manifest",
        &serde_json::json!({
            "target_statement_tex":"x","dependency_revision_ids":[],"reference_ids":[],
            "conditional_hypotheses":[],"computational_evidence":[]
        }),
        None,
    )?;
    engine.commit(
        "owner",
        capability(&assembler)?,
        "proof_submitted",
        &serde_json::json!({}),
        None,
    )?;
    let repair = engine.next_task("owner", &run_id, None)?;
    assert_eq!(repair["state"], "repair");
    let final_artifact = engine.get_artifact("owner", &run_id, "final_tex");
    assert!(final_artifact.is_err());
    Ok(())
}

#[test]
fn full_mode_branch_barrier_requires_every_branch_to_seal() -> Result<(), ReCtmError> {
    let temp = tempfile::tempdir().map_err(|error| {
        ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
    })?;
    let engine = engine(temp.path(), Arc::new(PassingLatex))?;
    let started = engine.start(StartRequest {
        owner_id: "owner",
        problem_tex: "Prove a two-route statement.",
        problem_id: Some("branch-test"),
        references: &[],
        native_mode: "dangerous",
        workspace_export_path: None,
        project_id: None,
        target_claim_id: None,
        workflow_mode: "full",
        register_result: true,
        workflow_protocol_version: 2,
        trace_id: None,
    })?;
    let run_id = started["run_id"].as_str().unwrap_or_default().to_owned();
    let assess = engine.next_task("owner", &run_id, None)?;
    engine.write(
        "owner",
        capability(&assess)?,
        "memory:generation:immediate_conclusions",
        &serde_json::json!({"summary":"initial"}),
        None,
    )?;
    engine.commit(
        "owner",
        capability(&assess)?,
        "assessment_complete",
        &serde_json::json!({"route":"full"}),
        None,
    )?;
    let explore = engine.next_task("owner", &run_id, None)?;
    engine.write(
        "owner",
        capability(&explore)?,
        "memory:generation:events",
        &serde_json::json!({"event_type":"explore"}),
        None,
    )?;
    engine.commit(
        "owner",
        capability(&explore)?,
        "exploration_complete",
        &serde_json::json!({}),
        None,
    )?;
    let planning = engine.next_task("owner", &run_id, None)?;
    engine.commit(
        "owner",
        capability(&planning)?,
        "plans_proposed",
        &serde_json::json!({
            "plans":[
                {"plan_id":"first","summary":"Split into cases","subgoals":["case A"]},
                {"plan_id":"second","summary":"Use an invariant","subgoals":["invariant B"]}
            ]
        }),
        None,
    )?;
    let direct = engine.next_task("owner", &run_id, None)?;
    engine.write(
        "owner",
        capability(&direct)?,
        "memory:generation:proof_steps",
        &serde_json::json!({"attempt":"screen both"}),
        None,
    )?;
    let branched = engine.commit(
        "owner",
        capability(&direct)?,
        "direct_proving_complete",
        &serde_json::json!({
            "screening":{
                "plan-r1-1":{"sg-1":{"status":"stuck","summary":"needs branch work"}},
                "plan-r1-2":{"sg-1":{"status":"stuck","summary":"needs independent branch"}}
            }
        }),
        None,
    )?;
    assert_eq!(branched["state"], "branch_prepare");

    let branch_a = engine.next_task("owner", &run_id, None)?;
    assert_eq!(branch_a["state"], "branch_run");
    engine.write(
        "owner",
        capability(&branch_a)?,
        "memory:branch:proof_steps",
        &serde_json::json!({"step":"branch a proof"}),
        None,
    )?;
    let sealed_a = engine.commit(
        "owner",
        capability(&branch_a)?,
        "branch_complete",
        &serde_json::json!({
            "status":"solved","summary":"route A works","proof_route":"complete route A",
            "proved_subgoals":["case A"]
        }),
        None,
    )?;
    assert_eq!(sealed_a["barrier_complete"], false);
    assert_eq!(sealed_a["state"], "branch_run");

    let branch_b = engine.next_task("owner", &run_id, None)?;
    assert_ne!(
        branch_a["context"]["branch_id"],
        branch_b["context"]["branch_id"]
    );
    engine.write(
        "owner",
        capability(&branch_b)?,
        "memory:branch:proof_steps",
        &serde_json::json!({"step":"branch b attempt"}),
        None,
    )?;
    let sealed_b = engine.commit(
        "owner",
        capability(&branch_b)?,
        "branch_complete",
        &serde_json::json!({
            "status":"failed","summary":"route B fails",
            "unproved_subgoals":["invariant B"],"failure_evidence":["obstruction"]
        }),
        None,
    )?;
    assert_eq!(sealed_b["barrier_complete"], true);
    assert_eq!(sealed_b["state"], "branch_join");

    let join = engine.next_task("owner", &run_id, None)?;
    let selected = branch_a["context"]["branch_id"]
        .as_str()
        .unwrap_or_default();
    let assembled = engine.commit(
        "owner",
        capability(&join)?,
        "join_complete",
        &serde_json::json!({"selected_branch_id":selected}),
        None,
    )?;
    assert_eq!(assembled["state"], "assemble");
    Ok(())
}

#[test]
fn second_compact_verifier_failure_escalates_to_full_exploration() -> Result<(), ReCtmError> {
    let temp = tempfile::tempdir().map_err(|error| {
        ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
    })?;
    let engine = engine(temp.path(), Arc::new(PassingLatex))?;
    let run_id = start_compact(&engine)?;
    let assess = engine.next_task("owner", &run_id, None)?;
    engine.write(
        "owner",
        capability(&assess)?,
        "memory:generation:immediate_conclusions",
        &serde_json::json!({"summary":"direct"}),
        None,
    )?;
    engine.commit(
        "owner",
        capability(&assess)?,
        "assessment_complete",
        &serde_json::json!({
            "route":"compact","requires_external_retrieval":false,"requires_multiple_plans":false
        }),
        None,
    )?;
    let assembler = engine.next_task("owner", &run_id, None)?;
    engine.write(
        "owner",
        capability(&assembler)?,
        "proof",
        &Value::String("proof version one".to_owned()),
        None,
    )?;
    engine.write(
        "owner",
        capability(&assembler)?,
        "proof_manifest",
        &serde_json::json!({
            "target_statement_tex":"target","dependency_revision_ids":[],"reference_ids":[],
            "conditional_hypotheses":[],"computational_evidence":[]
        }),
        None,
    )?;
    engine.commit(
        "owner",
        capability(&assembler)?,
        "proof_submitted",
        &serde_json::json!({}),
        None,
    )?;

    let verifier = engine.next_task("owner", &run_id, None)?;
    write_wrong_verification(&engine, &verifier, "first gap")?;
    let repair_state = engine.commit(
        "owner",
        capability(&verifier)?,
        "verification_submitted",
        &serde_json::json!({}),
        None,
    )?;
    assert_eq!(repair_state["state"], "repair");

    let repair = engine.next_task("owner", &run_id, None)?;
    engine.write(
        "owner",
        capability(&repair)?,
        "proof",
        &Value::String("proof version two".to_owned()),
        None,
    )?;
    engine.write(
        "owner",
        capability(&repair)?,
        "proof_manifest",
        &serde_json::json!({
            "target_statement_tex":"target","dependency_revision_ids":[],"reference_ids":[],
            "conditional_hypotheses":[],"computational_evidence":[]
        }),
        None,
    )?;
    engine.commit(
        "owner",
        capability(&repair)?,
        "repair_submitted",
        &serde_json::json!({}),
        None,
    )?;

    let verifier_again = engine.next_task("owner", &run_id, None)?;
    assert_eq!(verifier_again["state"], "verify");
    write_wrong_verification(&engine, &verifier_again, "second gap")?;
    let escalated = engine.commit(
        "owner",
        capability(&verifier_again)?,
        "verification_submitted",
        &serde_json::json!({}),
        None,
    )?;
    assert_eq!(escalated["state"], "explore");
    let explore = engine.next_task("owner", &run_id, None)?;
    assert_eq!(explore["state"], "explore");
    assert_eq!(explore["role"], "generator");
    Ok(())
}

fn write_wrong_verification(
    engine: &WorkflowEngine,
    task: &Value,
    issue: &str,
) -> Result<(), ReCtmError> {
    engine.write(
        "owner",
        capability(task)?,
        "memory:verifier:statement_checks",
        &serde_json::json!({"location":"proof","status":"gap","summary":issue}),
        None,
    )?;
    engine.write(
        "owner",
        capability(task)?,
        "memory:verifier:events",
        &serde_json::json!({"event_type":"verification_audit_complete"}),
        None,
    )?;
    engine.write(
        "owner",
        capability(task)?,
        "verification_report",
        &serde_json::json!({
            "verification_report":{
                "summary":"needs repair","critical_errors":[],
                "gaps":[{"location":"proof","issue":issue}]
            },
            "verdict":"correct",
            "repair_hints":"repair the stated gap"
        }),
        None,
    )?;
    Ok(())
}
