#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use mtm_contracts::{ErrorCategory, ReCtmError};
use mtm_storage::{CapabilityAuthority, StateStore};
use mtm_workflow::{
    LatexGate, LatexGateResult, PrivateVault, StartRequest, TaskCatalog, WorkflowEngine,
};
use serde_json::{Map, Value};

struct RealPdfLatexGate {
    executable: PathBuf,
}

impl LatexGate for RealPdfLatexGate {
    fn validate(&self, proof: &str, workdir: &Path) -> Result<LatexGateResult, ReCtmError> {
        fs::create_dir_all(workdir).map_err(io_error)?;
        let input = workdir.join("proof.tex");
        fs::write(&input, proof).map_err(io_error)?;
        let output = Command::new(&self.executable)
            .arg("-interaction=nonstopmode")
            .arg("-halt-on-error")
            .arg("proof.tex")
            .current_dir(workdir)
            .output()
            .map_err(io_error)?;
        let compiler_output = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let passed = output.status.success() && workdir.join("proof.pdf").is_file();
        Ok(LatexGateResult {
            policy: "required".to_owned(),
            static_valid: true,
            compile_attempted: true,
            compile_available: true,
            compile_passed: passed,
            gate_passed: passed,
            errors: if passed {
                Vec::new()
            } else {
                vec!["pdflatex failed".to_owned()]
            },
            warnings: Vec::new(),
            compiler_output: compiler_output
                .chars()
                .rev()
                .take(4000)
                .collect::<String>()
                .chars()
                .rev()
                .collect(),
        })
    }
}

struct Fixture {
    root: tempfile::TempDir,
    store: Arc<StateStore>,
    vault: Arc<PrivateVault>,
    engine: WorkflowEngine,
}

fn main() {
    let result = run();
    let payload = match result {
        Ok(payload) => payload,
        Err(error) => serde_json::json!({"ok":false,"error":error.to_payload()}),
    };
    println!(
        "{}",
        serde_json::to_string(&payload).unwrap_or_else(|_| "{\"ok\":false}".to_owned())
    );
    if payload.get("ok") != Some(&Value::Bool(true)) {
        std::process::exit(1);
    }
}

fn run() -> Result<Value, ReCtmError> {
    let methodology_path = std::env::args()
        .nth(1)
        .ok_or_else(|| validation("methodology path argument is required"))?;
    let pdflatex = std::env::args()
        .nth(2)
        .ok_or_else(|| validation("pdflatex path argument is required"))?;
    let methodology: Value =
        serde_json::from_str(&fs::read_to_string(methodology_path).map_err(io_error)?)
            .map_err(json_error)?;

    let project = project_promotion_case(&methodology, &pdflatex)?;
    let tamper = tamper_case(&methodology, &pdflatex)?;
    let reference = missing_reference_audit_case(&methodology, &pdflatex)?;
    let checks = vec![
        check(
            "real_pdflatex_finalization",
            project["finalized"] == Value::Bool(true),
        ),
        check(
            "verified_project_promotion",
            project["promoted"] == Value::Bool(true),
        ),
        check(
            "final_artifact_read_only",
            project["read_only"] == Value::Bool(true),
        ),
        check(
            "model_verdict_cannot_override_server",
            project["server_verdict"] == "correct",
        ),
        check(
            "post_verifier_proof_tamper_denied",
            tamper["denied"] == Value::Bool(true),
        ),
        check(
            "tamper_does_not_publish_final_artifact",
            tamper["final_absent"] == Value::Bool(true),
        ),
        check(
            "missing_reference_audit_becomes_server_gap",
            reference["server_gap"] == Value::Bool(true),
        ),
        check(
            "reference_gap_routes_to_repair",
            reference["repair"] == Value::Bool(true),
        ),
    ];
    let passed = checks
        .iter()
        .all(|item| item.get("passed") == Some(&Value::Bool(true)));
    Ok(serde_json::json!({
        "ok":passed,
        "check_count":checks.len(),
        "checks":checks,
        "sensitive_content_omitted":true
    }))
}

fn fixture(methodology: &Value, pdflatex: &str) -> Result<Fixture, ReCtmError> {
    let root = tempfile::tempdir().map_err(io_error)?;
    let store = Arc::new(StateStore::open(root.path().join("state.sqlite3"))?);
    let vault = Arc::new(PrivateVault::new(root.path().join("private"))?);
    let capabilities = Arc::new(CapabilityAuthority::new(
        b"cccccccccccccccccccccccccccccccc",
        Arc::clone(&store),
        600,
        None,
    )?);
    let engine = WorkflowEngine::new(
        Arc::clone(&store),
        Arc::clone(&vault),
        capabilities,
        Arc::new(TaskCatalog::from_source_snapshot(methodology.clone())?),
        Arc::new(RealPdfLatexGate {
            executable: PathBuf::from(pdflatex),
        }),
        None,
    );
    Ok(Fixture {
        root,
        store,
        vault,
        engine,
    })
}

fn project_promotion_case(methodology: &Value, pdflatex: &str) -> Result<Value, ReCtmError> {
    let fixture = fixture(methodology, pdflatex)?;
    let project = fixture.store.create_project(
        "owner",
        "Target project",
        Some("project-target"),
        &serde_json::json!({}),
    )?;
    let claim = fixture.store.create_claim(
        "owner",
        text(&project, "project_id")?,
        "Target claim",
        Some("claim-target"),
        &serde_json::json!({}),
    )?;
    fixture.store.create_open_claim_revision(
        "owner",
        text(&claim, "claim_id")?,
        "Prove $1=1$.",
        &[],
        None,
    )?;
    let run_id = start_compact(
        &fixture.engine,
        Some("project-target"),
        Some("claim-target"),
        "promotion",
    )?;
    let verifier =
        compact_to_verifier(&fixture.engine, &run_id, latex_document("By reflexivity."))?;
    write_correct_report(&fixture.engine, &verifier, true)?;
    let commit = fixture.engine.commit(
        "owner",
        capability(&verifier)?,
        "verification_submitted",
        &serde_json::json!({}),
        None,
    )?;
    let next = fixture.engine.next_task("owner", &run_id, None)?;
    let artifact = fixture.engine.get_artifact("owner", &run_id, "final_tex")?;
    let revisions = fixture
        .store
        .list_claim_revisions("claim-target", "owner")?;
    let promoted = revisions.len() == 2
        && revisions[0].get("lifecycle_status").and_then(Value::as_str) == Some("SUPERSEDED")
        && revisions[1].get("lifecycle_status").and_then(Value::as_str) == Some("ACTIVE")
        && revisions[1].get("evidence_status").and_then(Value::as_str) == Some("VERIFIED");
    let final_path = fixture
        .vault
        .run_root(&run_id)?
        .join("final/proof_verified.tex");
    let read_only = read_only_mode(&final_path)?;
    let _keep_root_alive = fixture.root.path();
    Ok(serde_json::json!({
        "finalized":next["state"] == "done" && artifact["content"].is_string(),
        "promoted":promoted,
        "read_only":read_only,
        "server_verdict":commit["verdict"]
    }))
}

fn tamper_case(methodology: &Value, pdflatex: &str) -> Result<Value, ReCtmError> {
    let fixture = fixture(methodology, pdflatex)?;
    let run_id = start_compact(&fixture.engine, None, None, "tamper")?;
    let verifier =
        compact_to_verifier(&fixture.engine, &run_id, latex_document("By reflexivity."))?;
    write_correct_report(&fixture.engine, &verifier, false)?;
    fixture.engine.commit(
        "owner",
        capability(&verifier)?,
        "verification_submitted",
        &serde_json::json!({}),
        None,
    )?;
    let draft = fixture.vault.run_root(&run_id)?.join("draft/proof.tex");
    fs::write(&draft, latex_document("Tampered after verifier approval.")).map_err(io_error)?;
    let denied = fixture.engine.next_task("owner", &run_id, None);
    let final_path = fixture
        .vault
        .run_root(&run_id)?
        .join("final/proof_verified.tex");
    Ok(serde_json::json!({
        "denied":denied.err().is_some_and(|error| error.code == "FINALIZATION_GATE_DENIED" || error.code == "FINALIZATION_PERMIT_MISMATCH"),
        "final_absent":!final_path.exists()
    }))
}

fn missing_reference_audit_case(methodology: &Value, pdflatex: &str) -> Result<Value, ReCtmError> {
    let fixture = fixture(methodology, pdflatex)?;
    let references = [serde_json::json!({
        "name":"reference.txt","content":"An inline reference statement.","source":"inline"
    })];
    let started = fixture.engine.start(StartRequest {
        owner_id: "owner",
        problem_tex: "Prove a statement using the supplied reference.",
        problem_id: Some("reference-gap"),
        references: &references,
        native_mode: "dangerous",
        workspace_export_path: None,
        project_id: None,
        target_claim_id: None,
        workflow_mode: "full",
        register_result: true,
        workflow_protocol_version: 2,
        trace_id: None,
    })?;
    let run_id = text(&started, "run_id")?.to_owned();
    let assess = fixture.engine.next_task("owner", &run_id, None)?;
    fixture.engine.write(
        "owner",
        capability(&assess)?,
        "memory:generation:immediate_conclusions",
        &serde_json::json!({"summary":"reference route"}),
        None,
    )?;
    fixture.engine.commit(
        "owner",
        capability(&assess)?,
        "assessment_complete",
        &serde_json::json!({"route":"full"}),
        None,
    )?;
    let explore = fixture.engine.next_task("owner", &run_id, None)?;
    fixture.engine.write(
        "owner",
        capability(&explore)?,
        "memory:generation:events",
        &serde_json::json!({"event_type":"explore"}),
        None,
    )?;
    fixture.engine.commit(
        "owner",
        capability(&explore)?,
        "exploration_complete",
        &serde_json::json!({}),
        None,
    )?;
    let planning = fixture.engine.next_task("owner", &run_id, None)?;
    fixture.engine.commit(
        "owner",
        capability(&planning)?,
        "plans_proposed",
        &serde_json::json!({
            "plans":[
                {"plan_id":"a","summary":"Direct reference route","subgoals":["derive target"]},
                {"plan_id":"b","summary":"Alternative route","subgoals":["find alternative"]}
            ]
        }),
        None,
    )?;
    let direct = fixture.engine.next_task("owner", &run_id, None)?;
    fixture.engine.write(
        "owner",
        capability(&direct)?,
        "memory:generation:proof_steps",
        &serde_json::json!({"attempt":"direct"}),
        None,
    )?;
    fixture.engine.commit(
        "owner",
        capability(&direct)?,
        "direct_proving_complete",
        &serde_json::json!({
            "screening":{
                "plan-r1-1":{"sg-1":{"status":"solved","summary":"route complete"}},
                "plan-r1-2":{"sg-1":{"status":"stuck","summary":"not needed"}}
            },
            "selected_plan_id":"plan-r1-1",
            "proof_route":"use supplied reference"
        }),
        None,
    )?;
    let assembler = fixture.engine.next_task("owner", &run_id, None)?;
    let reference_id = fixture
        .store
        .list_run_references(&run_id)?
        .into_iter()
        .next()
        .and_then(|value| {
            value
                .get("reference_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .ok_or_else(|| internal("reference id missing"))?;
    fixture.engine.write(
        "owner",
        capability(&assembler)?,
        "proof",
        &Value::String(latex_document("Use the supplied reference.")),
        None,
    )?;
    fixture.engine.write(
        "owner",
        capability(&assembler)?,
        "proof_manifest",
        &serde_json::json!({
            "target_statement_tex":"target","dependency_revision_ids":[],
            "reference_ids":[reference_id],"conditional_hypotheses":[],"computational_evidence":[]
        }),
        None,
    )?;
    fixture.engine.commit(
        "owner",
        capability(&assembler)?,
        "proof_submitted",
        &serde_json::json!({}),
        None,
    )?;
    let verifier = fixture.engine.next_task("owner", &run_id, None)?;
    write_correct_report(&fixture.engine, &verifier, false)?;
    let result = fixture.engine.commit(
        "owner",
        capability(&verifier)?,
        "verification_submitted",
        &serde_json::json!({}),
        None,
    )?;
    let report = fixture
        .engine
        .get_artifact("owner", &run_id, "verification_report")?;
    let gaps = report["content"]["verification_report"]["gaps"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    Ok(serde_json::json!({
        "server_gap":gaps.iter().any(|gap| gap.get("location").and_then(Value::as_str).is_some_and(|location| location.starts_with("reference:"))),
        "repair":result["state"] == "repair" && result["verdict"] == "wrong"
    }))
}

fn start_compact(
    engine: &WorkflowEngine,
    project_id: Option<&str>,
    target_claim_id: Option<&str>,
    problem_id: &str,
) -> Result<String, ReCtmError> {
    let started = engine.start(StartRequest {
        owner_id: "owner",
        problem_tex: "Prove $1=1$.",
        problem_id: Some(problem_id),
        references: &[],
        native_mode: "dangerous",
        workspace_export_path: None,
        project_id,
        target_claim_id,
        workflow_mode: "compact",
        register_result: true,
        workflow_protocol_version: 2,
        trace_id: None,
    })?;
    Ok(text(&started, "run_id")?.to_owned())
}

fn compact_to_verifier(
    engine: &WorkflowEngine,
    run_id: &str,
    proof: String,
) -> Result<Value, ReCtmError> {
    let assess = engine.next_task("owner", run_id, None)?;
    engine.write(
        "owner",
        capability(&assess)?,
        "memory:generation:immediate_conclusions",
        &serde_json::json!({"summary":"reflexivity"}),
        None,
    )?;
    engine.commit(
        "owner",
        capability(&assess)?,
        "assessment_complete",
        &serde_json::json!({
            "route":"compact","route_reason":"direct","requires_external_retrieval":false,"requires_multiple_plans":false
        }),
        None,
    )?;
    let assembler = engine.next_task("owner", run_id, None)?;
    engine.write(
        "owner",
        capability(&assembler)?,
        "proof",
        &Value::String(proof),
        None,
    )?;
    engine.write(
        "owner",
        capability(&assembler)?,
        "proof_manifest",
        &serde_json::json!({
            "target_statement_tex":"Prove $1=1$.","dependency_revision_ids":[],"reference_ids":[],
            "conditional_hypotheses":[],"computational_evidence":[]
        }),
        None,
    )?;
    engine.commit(
        "owner",
        capability(&assembler)?,
        "proof_submitted",
        &serde_json::json!({"outcome":"proof"}),
        None,
    )?;
    engine.next_task("owner", run_id, None)
}

fn write_correct_report(
    engine: &WorkflowEngine,
    verifier: &Value,
    wrong_model_verdict: bool,
) -> Result<(), ReCtmError> {
    let cap = capability(verifier)?;
    engine.write(
        "owner",
        cap,
        "memory:verifier:statement_checks",
        &serde_json::json!({"location":"proof","status":"checked"}),
        None,
    )?;
    engine.write(
        "owner",
        cap,
        "memory:verifier:events",
        &serde_json::json!({"event_type":"verification_audit_complete"}),
        None,
    )?;
    engine.write(
        "owner",
        cap,
        "verification_report",
        &serde_json::json!({
            "verification_report":{"summary":"checked","critical_errors":[],"gaps":[]},
            "verdict":if wrong_model_verdict {"wrong"} else {"correct"},
            "repair_hints":if wrong_model_verdict {"must be ignored"} else {""}
        }),
        None,
    )?;
    Ok(())
}

fn latex_document(body: &str) -> String {
    format!(
        "\\documentclass{{article}}\n\\begin{{document}}\n\\begin{{proof}}{body}\\end{{proof}}\n\\end{{document}}\n"
    )
}

fn capability(task: &Value) -> Result<&str, ReCtmError> {
    task.get("capability")
        .and_then(Value::as_str)
        .ok_or_else(|| internal("task capability missing"))
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, ReCtmError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| internal(&format!("missing string field: {key}")))
}

fn check(name: &str, passed: bool) -> Value {
    serde_json::json!({"name":name,"passed":passed})
}

fn read_only_mode(path: &Path) -> Result<bool, ReCtmError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        return Ok(fs::metadata(path).map_err(io_error)?.permissions().mode() & 0o222 == 0);
    }
    #[cfg(not(unix))]
    {
        Ok(fs::metadata(path)
            .map_err(io_error)?
            .permissions()
            .readonly())
    }
}

fn validation(message: &str) -> ReCtmError {
    ReCtmError::new("INVALID_ARGUMENT", message).with_category(ErrorCategory::Validation)
}

fn internal(message: &str) -> ReCtmError {
    ReCtmError::new("TARGET_VALIDATION_ERROR", message).with_category(ErrorCategory::Internal)
}

fn io_error(error: std::io::Error) -> ReCtmError {
    ReCtmError::new("TARGET_IO_ERROR", error.to_string()).with_category(ErrorCategory::Runtime)
}

fn json_error(error: serde_json::Error) -> ReCtmError {
    ReCtmError::new("TARGET_JSON_ERROR", error.to_string()).with_category(ErrorCategory::Internal)
}
