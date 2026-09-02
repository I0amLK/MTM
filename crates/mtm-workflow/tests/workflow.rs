use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mtm_contracts::{ErrorCategory, ReCtmError};
use mtm_storage::{CapabilityAuthority, StateStore};
use mtm_workflow::{
    LatexGate, LatexGateResult, PrivateVault, StartRequest, TaskCatalog, WorkflowEngine,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

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
    start_compact_with_protocol(engine, 2)
}

fn start_compact_with_protocol(
    engine: &WorkflowEngine,
    workflow_protocol_version: i64,
) -> Result<String, ReCtmError> {
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
        workflow_protocol_version,
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

fn tree_digest(root: &Path) -> Result<String, ReCtmError> {
    fn collect(root: &Path, current: &Path, paths: &mut Vec<PathBuf>) -> Result<(), ReCtmError> {
        let mut entries = fs::read_dir(current)
            .map_err(|error| {
                ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
            })?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            paths.push(path.strip_prefix(root).unwrap_or(&path).to_path_buf());
            if entry
                .file_type()
                .map_err(|error| {
                    ReCtmError::new("TEST_IO", error.to_string())
                        .with_category(ErrorCategory::Runtime)
                })?
                .is_dir()
            {
                collect(root, &path, paths)?;
            }
        }
        Ok(())
    }

    let mut paths = Vec::new();
    collect(root, root, &mut paths)?;
    let mut digest = Sha256::new();
    for relative in paths {
        digest.update(relative.to_string_lossy().as_bytes());
        digest.update([0]);
        let absolute = root.join(&relative);
        if absolute.is_file() {
            digest.update(fs::read(&absolute).map_err(|error| {
                ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
            })?);
        }
        digest.update([0xff]);
    }
    Ok(format!("{:x}", digest.finalize()))
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
fn protocol_three_branch_context_does_not_receive_global_research_view() -> Result<(), ReCtmError> {
    let temp = tempfile::tempdir().map_err(|error| {
        ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
    })?;
    let engine = engine(temp.path(), Arc::new(PassingLatex))?;
    let started = engine.start(StartRequest {
        owner_id: "owner",
        problem_tex: "Prove a two-route protocol-three statement.",
        problem_id: Some("protocol-three-branch-firewall"),
        references: &[],
        native_mode: "dangerous",
        workspace_export_path: None,
        project_id: None,
        target_claim_id: None,
        workflow_mode: "full",
        register_result: true,
        workflow_protocol_version: 3,
        trace_id: None,
    })?;
    let run_id = started["run_id"].as_str().unwrap_or_default().to_owned();
    let assess = engine.next_task("owner", &run_id, None)?;
    engine.write(
        "owner",
        capability(&assess)?,
        "memory:generation:immediate_conclusions",
        &serde_json::json!({"summary":"branch both routes"}),
        None,
    )?;
    engine.commit(
        "owner",
        capability(&assess)?,
        "assessment_complete",
        &serde_json::json!({"route":"full","requires_multiple_plans":true}),
        None,
    )?;
    let explore = engine.next_task("owner", &run_id, None)?;
    engine.write(
        "owner",
        capability(&explore)?,
        "memory:generation:events",
        &serde_json::json!({
            "event_type":"notation_resolution","symbol":"x","resolution":"fixed",
            "summary":"notation fixed","evidence_ids":[]
        }),
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
                {"summary":"Route A","subgoals":[{"key":"a","statement":"Prove A","depends_on":[],"critical":true}],"motivation":[],"dependencies":[],"risks":[]},
                {"summary":"Route B","subgoals":[{"key":"b","statement":"Prove B","depends_on":[],"critical":true}],"motivation":[],"dependencies":[],"risks":[]}
            ]
        }),
        None,
    )?;
    let direct = engine.next_task("owner", &run_id, None)?;
    let plans = direct["context"]["active_plans"]
        .as_array()
        .ok_or_else(|| {
            ReCtmError::new("TEST_FAILURE", "protocol-three branch plans missing")
                .with_category(ErrorCategory::Internal)
        })?;
    let mut screening = serde_json::Map::new();
    for plan in plans {
        let plan_id = plan["plan_id"].as_str().unwrap_or_default().to_owned();
        let subgoal_id = plan["subgoals"][0]["subgoal_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        screening.insert(
            plan_id,
            serde_json::json!({
                subgoal_id:{"status":"stuck","summary":"needs branch work","method":"direct","obstruction":"no_progress","evidence_ids":[]}
            }),
        );
    }
    engine.write(
        "owner",
        capability(&direct)?,
        "memory:generation:proof_steps",
        &serde_json::json!({"summary":"both routes need branches"}),
        None,
    )?;
    let branched = engine.commit(
        "owner",
        capability(&direct)?,
        "direct_proving_complete",
        &serde_json::json!({"screening":Value::Object(screening)}),
        None,
    )?;
    assert_eq!(branched["state"], "branch_prepare");
    let branch = engine.next_task("owner", &run_id, None)?;
    assert_eq!(branch["role"], "branch");
    assert!(
        branch["context"]
            .get("mathematical_research_state")
            .is_none()
    );
    Ok(())
}

#[test]
fn protocol_three_structured_research_contract_reaches_same_tex_finalizer() -> Result<(), ReCtmError>
{
    let temp = tempfile::tempdir().map_err(|error| {
        ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
    })?;
    let engine = engine(temp.path(), Arc::new(PassingLatex))?;
    let started = engine.start(StartRequest {
        owner_id: "owner",
        problem_tex: r"\begin{proposition}Prove $1=1$.\end{proposition}",
        problem_id: Some("protocol-three-one-equals-one"),
        references: &[],
        native_mode: "dangerous",
        workspace_export_path: None,
        project_id: None,
        target_claim_id: None,
        workflow_mode: "full",
        register_result: true,
        workflow_protocol_version: 3,
        trace_id: Some("trace-p3-start"),
    })?;
    let run_id = started["run_id"]
        .as_str()
        .ok_or_else(|| {
            ReCtmError::new("TEST_FAILURE", "protocol-3 run_id missing")
                .with_category(ErrorCategory::Internal)
        })?
        .to_owned();

    let assess = engine.next_task("owner", &run_id, Some("trace-p3-assess"))?;
    assert_eq!(assess["task"]["workflow_protocol_version"], 3);
    assert_eq!(
        assess["task"]["mathematical_research_contract"]["final_artifact"],
        "proof_verified.tex"
    );
    let assess_research = assess["context"]
        .get("mathematical_research_state")
        .ok_or_else(|| {
            ReCtmError::new("TEST_FAILURE", "protocol-3 generator research view missing")
                .with_category(ErrorCategory::Internal)
        })?;
    assert_eq!(assess_research["advisory_only"], true);
    assert!(assess_research["graph_digest"].as_str().is_some());
    assert!(
        serde_json::to_vec(assess_research)
            .map_err(|error| ReCtmError::new("TEST_JSON", error.to_string()))?
            .len()
            <= mtm_workflow::research_state::MAX_RESEARCH_TASK_VIEW_BYTES
    );
    engine.write(
        "owner",
        capability(&assess)?,
        "memory:generation:immediate_conclusions",
        &serde_json::json!({"summary":"Reflexivity should close the target."}),
        Some("trace-p3-assess-write"),
    )?;
    engine.commit(
        "owner",
        capability(&assess)?,
        "assessment_complete",
        &serde_json::json!({
            "route":"full","route_reason":"exercise structured research contract",
            "requires_external_retrieval":false,"requires_multiple_plans":true
        }),
        Some("trace-p3-assess-commit"),
    )?;

    let explore = engine.next_task("owner", &run_id, Some("trace-p3-explore"))?;
    assert_eq!(explore["state"], "explore");
    let explore_writes = explore["task"]["write_contract"]
        .as_array()
        .ok_or_else(|| {
            ReCtmError::new("TEST_FAILURE", "protocol-3 explore write contract missing")
                .with_category(ErrorCategory::Internal)
        })?;
    assert_eq!(explore_writes[0]["resource"], "memory:generation:events");
    assert_eq!(
        explore_writes[1]["resource"],
        "memory:generation:counterexamples"
    );
    engine.write(
        "owner",
        capability(&explore)?,
        "memory:generation:events",
        &serde_json::json!({
            "event_type":"notation_resolution","symbol":"=",
            "resolution":"Use ordinary equality.","summary":"No notation ambiguity remains.",
            "evidence_ids":[]
        }),
        Some("trace-p3-explore-write"),
    )?;
    engine.commit(
        "owner",
        capability(&explore)?,
        "exploration_complete",
        &serde_json::json!({}),
        Some("trace-p3-explore-commit"),
    )?;

    let planning = engine.next_task("owner", &run_id, Some("trace-p3-planning"))?;
    assert_eq!(planning["state"], "propose_plans");
    assert_eq!(
        planning["task"]["commit_payload_schema"]["properties"]["plans"]["items"]["properties"]["subgoals"]
            ["items"]["type"],
        "object"
    );
    engine.commit(
        "owner",
        capability(&planning)?,
        "plans_proposed",
        &serde_json::json!({
            "plans":[
                {
                    "summary":"Reduce equality to reflexivity in two explicit steps.",
                    "subgoals":[
                        {"key":"base","statement":"Establish reflexivity of 1.","depends_on":[],"critical":true},
                        {"key":"finish","statement":"Use reflexivity to conclude 1=1.","depends_on":["base"],"critical":true}
                    ],
                    "motivation":["Makes the dependency order explicit."],"dependencies":[],"risks":[]
                },
                {
                    "summary":"Use a deliberately distinct algebraic route.",
                    "subgoals":[
                        {"key":"alternate","statement":"Derive 1=1 from an equality axiom.","depends_on":[],"critical":true}
                    ],
                    "motivation":["Independent route for screening."],"dependencies":[],
                    "risks":["More machinery than necessary."]
                }
            ]
        }),
        Some("trace-p3-planning-commit"),
    )?;

    let direct = engine.next_task("owner", &run_id, Some("trace-p3-direct"))?;
    assert_eq!(direct["state"], "direct_proving");
    let direct_research = direct["context"]
        .get("mathematical_research_state")
        .ok_or_else(|| {
            ReCtmError::new("TEST_FAILURE", "protocol-3 direct research view missing")
                .with_category(ErrorCategory::Internal)
        })?;
    assert_eq!(direct_research["advisory_only"], true);
    assert!(direct_research["suggested_next_action"]["rule_id"].is_string());
    let plans = direct["context"]["active_plans"]
        .as_array()
        .ok_or_else(|| {
            ReCtmError::new("TEST_FAILURE", "protocol-3 active plans missing")
                .with_category(ErrorCategory::Internal)
        })?;
    assert_eq!(plans.len(), 2);
    let first_plan_id = plans[0]["plan_id"].as_str().unwrap_or_default().to_owned();
    let second_plan_id = plans[1]["plan_id"].as_str().unwrap_or_default().to_owned();
    let first_subgoals = plans[0]["subgoals"].as_array().ok_or_else(|| {
        ReCtmError::new("TEST_FAILURE", "first protocol-3 subgoals missing")
            .with_category(ErrorCategory::Internal)
    })?;
    let second_subgoals = plans[1]["subgoals"].as_array().ok_or_else(|| {
        ReCtmError::new("TEST_FAILURE", "second protocol-3 subgoals missing")
            .with_category(ErrorCategory::Internal)
    })?;
    let base_id = first_subgoals[0]["subgoal_id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let finish_id = first_subgoals[1]["subgoal_id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let alternate_id = second_subgoals[0]["subgoal_id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let base_node_id = first_subgoals[0]["node_id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        !base_node_id.is_empty(),
        "protocol-3 active plans: {plans:?}"
    );
    assert_eq!(
        first_subgoals[1]["depends_on"],
        Value::Array(vec![Value::String(base_node_id)])
    );
    engine.write(
        "owner",
        capability(&direct)?,
        "memory:generation:proof_steps",
        &serde_json::json!({"summary":"Screened both structured routes."}),
        Some("trace-p3-direct-write"),
    )?;
    let mut first_results = serde_json::Map::new();
    first_results.insert(
        base_id,
        serde_json::json!({"status":"solved","summary":"Reflexivity is immediate.","method":"direct","evidence_ids":[]}),
    );
    first_results.insert(
        finish_id,
        serde_json::json!({"status":"solved","summary":"The target follows.","method":"reduction","evidence_ids":[]}),
    );
    let mut second_results = serde_json::Map::new();
    second_results.insert(
        alternate_id,
        serde_json::json!({"status":"stuck","summary":"This route needs an unnecessary lemma.","method":"direct","obstruction":"missing_lemma","evidence_ids":[]}),
    );
    let mut screening = serde_json::Map::new();
    screening.insert(first_plan_id.clone(), Value::Object(first_results));
    screening.insert(second_plan_id, Value::Object(second_results));
    let assembled = engine.commit(
        "owner",
        capability(&direct)?,
        "direct_proving_complete",
        &serde_json::json!({
            "screening":Value::Object(screening),"selected_plan_id":first_plan_id,
            "proof_route":"Apply reflexivity and conclude the equality."
        }),
        Some("trace-p3-direct-commit"),
    )?;
    assert_eq!(assembled["state"], "assemble");
    let shadow = engine.research_state_shadow("owner", &run_id)?;
    assert_eq!(shadow["workflow_protocol_version"], 3);
    assert!(shadow["research_state"]["plan_routes"].is_object());

    let assembler = engine.next_task("owner", &run_id, Some("trace-p3-assemble"))?;
    let proof = r"\begin{proof}By reflexivity, $1=1$.\end{proof}";
    engine.write(
        "owner",
        capability(&assembler)?,
        "proof",
        &Value::String(proof.to_owned()),
        Some("trace-p3-proof"),
    )?;
    engine.write(
        "owner",
        capability(&assembler)?,
        "proof_manifest",
        &serde_json::json!({
            "target_statement_tex":"Prove $1=1$.","dependency_revision_ids":[],"reference_ids":[],
            "conditional_hypotheses":[],"computational_evidence":[]
        }),
        Some("trace-p3-manifest"),
    )?;
    engine.commit(
        "owner",
        capability(&assembler)?,
        "proof_submitted",
        &serde_json::json!({"outcome":"proof"}),
        Some("trace-p3-proof-commit"),
    )?;

    let verifier = engine.next_task("owner", &run_id, Some("trace-p3-verifier"))?;
    assert_eq!(verifier["state"], "verify");
    assert!(
        verifier["context"]
            .get("mathematical_research_state")
            .is_none()
    );
    engine.write(
        "owner",
        capability(&verifier)?,
        "memory:verifier:statement_checks",
        &serde_json::json!({"location":"proof","status":"checked"}),
        Some("trace-p3-statement-check"),
    )?;
    engine.write(
        "owner",
        capability(&verifier)?,
        "memory:verifier:events",
        &serde_json::json!({"event_type":"verification_audit_complete"}),
        Some("trace-p3-verifier-event"),
    )?;
    engine.write(
        "owner",
        capability(&verifier)?,
        "verification_report",
        &serde_json::json!({
            "verification_report":{"summary":"The proof is valid.","critical_errors":[],"gaps":[]},
            "verdict":"correct","repair_hints":""
        }),
        Some("trace-p3-verification-report"),
    )?;
    let finalized = engine.commit(
        "owner",
        capability(&verifier)?,
        "verification_submitted",
        &serde_json::json!({}),
        Some("trace-p3-verification-commit"),
    )?;
    assert_eq!(finalized["state"], "finalize");
    let done = engine.next_task("owner", &run_id, Some("trace-p3-finalize"))?;
    assert_eq!(done["state"], "done");
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
fn research_state_shadow_is_deterministic_owner_scoped_and_side_effect_free()
-> Result<(), ReCtmError> {
    let temp = tempfile::tempdir().map_err(|error| {
        ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
    })?;
    let engine = engine(temp.path(), Arc::new(PassingLatex))?;
    let started = engine.start(StartRequest {
        owner_id: "owner",
        problem_tex: "Prove a two-route research-state statement.",
        problem_id: Some("research-shadow"),
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
        &serde_json::json!({"summary":"use two independent routes"}),
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
        &serde_json::json!({
            "event_type":"external_theorem_search",
            "operation":"theorem_search",
            "query":"private search wording",
            "results":[{"reference_id":"ref-shadow-a"}]
        }),
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
    assert!(
        direct["context"]
            .get("mathematical_research_state")
            .is_none()
    );
    engine.write(
        "owner",
        capability(&direct)?,
        "memory:generation:proof_steps",
        &serde_json::json!({"attempt":"screen both routes"}),
        None,
    )?;
    let branched = engine.commit(
        "owner",
        capability(&direct)?,
        "direct_proving_complete",
        &serde_json::json!({
            "screening":{
                "plan-r1-1":{"sg-1":{"status":"stuck","summary":"needs branch work"}},
                "plan-r1-2":{"sg-1":{"status":"partial","summary":"invariant is plausible"}}
            }
        }),
        None,
    )?;
    assert_eq!(branched["state"], "branch_prepare");

    let before = tree_digest(temp.path())?;
    let first = engine.research_state_shadow("owner", &run_id)?;
    let second = engine.research_state_shadow("owner", &run_id)?;
    let after = tree_digest(temp.path())?;
    assert_eq!(before, after);
    assert_eq!(first, second);
    let concurrent = std::thread::scope(|scope| {
        let handles = (0..8)
            .map(|_| {
                let engine = &engine;
                let run_id = run_id.as_str();
                scope.spawn(move || engine.research_state_shadow("owner", run_id))
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| {
                handle.join().map_err(|_| {
                    ReCtmError::new("TEST_THREAD_PANIC", "research-state shadow thread panicked")
                        .with_category(ErrorCategory::Internal)
                })?
            })
            .collect::<Result<Vec<_>, ReCtmError>>()
    })?;
    assert!(concurrent.iter().all(|value| value == &first));
    assert_eq!(before, tree_digest(temp.path())?);
    assert_eq!(first["shadow"], true);
    assert_eq!(first["workflow_protocol_version"], 2);
    assert_eq!(first["normalization"]["normalized_nodes"], 3);
    assert_eq!(first["normalization"]["normalized_attempts"], 3);
    assert_eq!(first["normalization"]["retrieval_events"], 1);
    assert_eq!(first["normalization"]["novel_reference_ids"], 0);
    assert_eq!(first["normalization"]["warning_count"], 1);
    assert_eq!(
        first["warnings"][0]["code"],
        "unregistered_retrieval_reference"
    );
    assert!(first["research_state"].get("advisory_action").is_none());
    assert!(!first.to_string().contains("private search wording"));
    assert!(
        engine
            .research_state_shadow("different-owner", &run_id)
            .is_err()
    );
    Ok(())
}

#[test]
fn protocol_three_repair_gets_advisory_context_but_verifier_does_not() -> Result<(), ReCtmError> {
    let temp = tempfile::tempdir().map_err(|error| {
        ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
    })?;
    let engine = engine(temp.path(), Arc::new(PassingLatex))?;
    let run_id = start_compact_with_protocol(&engine, 3)?;
    let assess = engine.next_task("owner", &run_id, None)?;
    assert_eq!(
        assess["context"]["mathematical_research_state"]["advisory_only"],
        true
    );
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
    assert_eq!(assembler["role"], "assembler");
    assert!(
        assembler["context"]
            .get("mathematical_research_state")
            .is_none()
    );
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
    assert_eq!(verifier["role"], "verifier");
    assert!(
        verifier["context"]
            .get("mathematical_research_state")
            .is_none()
    );
    write_wrong_verification(&engine, &verifier, "repair-needed")?;
    let repair_state = engine.commit(
        "owner",
        capability(&verifier)?,
        "verification_submitted",
        &serde_json::json!({}),
        None,
    )?;
    assert_eq!(repair_state["state"], "repair");
    let repair = engine.next_task("owner", &run_id, None)?;
    assert_eq!(repair["role"], "repair");
    assert_eq!(
        repair["context"]["mathematical_research_state"]["advisory_only"],
        true
    );
    assert!(
        repair["context"]["mathematical_research_state"]["graph_digest"]
            .as_str()
            .is_some()
    );
    let repair_view = repair["context"]["mathematical_research_state"].to_string();
    assert!(repair_view.contains("repair the stated gap"));
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
    let verifier_two = engine.next_task("owner", &run_id, None)?;
    write_wrong_verification(&engine, &verifier_two, "second-repair-needed")?;
    let escalated = engine.commit(
        "owner",
        capability(&verifier_two)?,
        "verification_submitted",
        &serde_json::json!({}),
        None,
    )?;
    assert_eq!(escalated["state"], "explore");
    let generator = engine.next_task("owner", &run_id, None)?;
    assert_eq!(generator["role"], "generator");
    let generator_view = generator["context"]["mathematical_research_state"].to_string();
    assert!(!generator_view.contains("repair the stated gap"));
    assert!(!generator_view.contains("legacy-repair"));
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
