use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mtm_contracts::{ErrorCategory, ReCtmError};
use mtm_storage::{CapabilityAuthority, FactForPromotion, FindingForStorage, StateStore};
use mtm_workflow::memory::compute_fact_id;
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

fn advance_compact_to_finalize(engine: &WorkflowEngine) -> Result<(String, String), ReCtmError> {
    let run_id = start_compact(engine)?;
    let assess = engine.next_task("owner", &run_id, None)?;
    engine.write(
        "owner",
        capability(&assess)?,
        "memory:generation:immediate_conclusions",
        &serde_json::json!({"summary":"Reflexivity."}),
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
    let proof = "\\begin{proof}Reflexivity gives $1=1$.\\end{proof}".to_owned();
    engine.write(
        "owner",
        capability(&assembler)?,
        "proof",
        &Value::String(proof.clone()),
        None,
    )?;
    engine.write(
        "owner",
        capability(&assembler)?,
        "proof_manifest",
        &serde_json::json!({
            "target_statement_tex":"Prove $1=1$.","dependency_revision_ids":[],
            "reference_ids":[],"conditional_hypotheses":[],"computational_evidence":[]
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
    let verifier = engine.next_task("owner", &run_id, None)?;
    engine.write(
        "owner",
        capability(&verifier)?,
        "memory:verifier:statement_checks",
        &serde_json::json!({"location":"proof","status":"checked"}),
        None,
    )?;
    engine.write(
        "owner",
        capability(&verifier)?,
        "memory:verifier:events",
        &serde_json::json!({"event_type":"verification_audit_complete"}),
        None,
    )?;
    engine.write(
        "owner",
        capability(&verifier)?,
        "verification_report",
        &serde_json::json!({
            "verification_report":{"summary":"Valid.","critical_errors":[],"gaps":[]},
            "verdict":"correct","repair_hints":""
        }),
        None,
    )?;
    let finalized = engine.commit(
        "owner",
        capability(&verifier)?,
        "verification_submitted",
        &serde_json::json!({}),
        None,
    )?;
    assert_eq!(finalized["state"], "finalize");
    Ok((run_id, proof))
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
fn tree_digest_still_detects_database_and_file_writes_after_read_setup() -> Result<(), ReCtmError> {
    let temp = tempfile::tempdir().map_err(|e| ReCtmError::new("TEST_IO", e.to_string()))?;
    let store = StateStore::open(temp.path().join("state.sqlite3"))?;
    store.create_run("run", "p", "owner", "assess", &serde_json::json!({}))?;
    store.get_run("run")?;
    let before = tree_digest(temp.path())?;
    let updates = serde_json::Map::from_iter([("changed".into(), Value::Bool(true))]);
    store.update_run_metadata("run", &updates)?;
    let after_database = tree_digest(temp.path())?;
    assert_ne!(before, after_database);
    fs::write(temp.path().join("fixture.txt"), "changed bytes")
        .map_err(|e| ReCtmError::new("TEST_IO", e.to_string()))?;
    assert_ne!(after_database, tree_digest(temp.path())?);
    Ok(())
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
fn verified_three_fact_manifest_reappears_in_next_run_memory() -> Result<(), ReCtmError> {
    assert_three_fact_memory(false)
}

#[test]
fn verified_revision_dependency_revocation_preserves_independent_lemmas() -> Result<(), ReCtmError>
{
    assert_three_fact_memory(true)
}

fn assert_three_fact_memory(with_dependency: bool) -> Result<(), ReCtmError> {
    let temp =
        tempfile::tempdir().map_err(|error| ReCtmError::new("TEST_IO", error.to_string()))?;
    let store = StateStore::open(temp.path().join("state.sqlite3"))?;
    store.create_project(
        "owner",
        "Memory",
        Some("project-memory"),
        &serde_json::json!({}),
    )?;
    let external_fact_id = compute_fact_id(
        "project-memory",
        &[],
        &BTreeMap::new(),
        "External lemma.",
        "External proof.",
    );
    let dependency_revision_ids = if with_dependency {
        store.create_claim(
            "owner",
            "project-memory",
            "External",
            Some("claim-external"),
            &serde_json::json!({}),
        )?;
        let base = store.create_open_claim_revision(
            "owner",
            "claim-external",
            "External lemma.",
            &[],
            None,
        )?;
        let snapshot = store.create_project_snapshot("project-memory", "owner")?;
        store.create_run(
            "run-external",
            "external",
            "owner",
            "done",
            &serde_json::json!({}),
        )?;
        store.link_run_to_project(
            "run-external",
            "owner",
            "project-memory",
            snapshot["snapshot_id"]
                .as_str()
                .ok_or_else(|| ReCtmError::new("TEST", "snapshot missing"))?,
            Some("claim-external"),
            base["revision_id"].as_str(),
            "compact",
            "compact",
            true,
        )?;
        let promoted = store.promote_verified_run_with_facts(
            "run-external",
            "owner",
            "External lemma.",
            &format!("{:x}", Sha256::digest(b"External proof.")),
            &[],
            &serde_json::json!({"dependency_revision_ids":[]}),
            &[FactForPromotion {
                fact_id: external_fact_id.clone(),
                statement_tex: "External lemma.".to_owned(),
                proof_tex: "External proof.".to_owned(),
                intuition: String::new(),
                glossary_json: "{}".to_owned(),
                predecessors: Vec::new(),
            }],
        )?;
        assert_eq!(promoted["status"], "promoted");
        vec![
            promoted["revision"]["revision_id"]
                .as_str()
                .ok_or_else(|| ReCtmError::new("TEST", "dependency revision missing"))?
                .to_owned(),
        ]
    } else {
        Vec::new()
    };
    store.create_claim(
        "owner",
        "project-memory",
        "Target",
        Some("claim-memory"),
        &serde_json::json!({}),
    )?;
    store.create_open_claim_revision("owner", "claim-memory", "Prove $1=1$.", &[], None)?;
    let engine = engine(temp.path(), Arc::new(PassingLatex))?;
    let started = engine.start(StartRequest {
        owner_id: "owner",
        problem_tex: "Prove $1=1$.",
        problem_id: Some("memory-proof"),
        references: &[],
        native_mode: "dangerous",
        workspace_export_path: None,
        project_id: Some("project-memory"),
        target_claim_id: Some("claim-memory"),
        workflow_mode: "compact",
        register_result: true,
        workflow_protocol_version: 3,
        trace_id: None,
    })?;
    let run_id = started["run_id"]
        .as_str()
        .ok_or_else(|| ReCtmError::new("TEST", "run id missing"))?;
    let assess = engine.next_task("owner", run_id, None)?;
    engine.write(
        "owner",
        capability(&assess)?,
        "memory:generation:immediate_conclusions",
        &serde_json::json!({"summary":"Reflexivity."}),
        None,
    )?;
    engine.commit("owner", capability(&assess)?, "assessment_complete",
        &serde_json::json!({"route":"compact","requires_external_retrieval":false,"requires_multiple_plans":false}), None)?;
    let assembler = engine.next_task("owner", run_id, None)?;
    let proof = r"\begin{proof}Lemma A. Step A. Lemma B. Step B. Prove $1=1$. Step C.\end{proof}";
    engine.write(
        "owner",
        capability(&assembler)?,
        "proof",
        &Value::String(proof.to_owned()),
        None,
    )?;
    engine.write("owner", capability(&assembler)?, "proof_manifest", &serde_json::json!({
        "target_statement_tex":"Prove $1=1$.","dependency_revision_ids":dependency_revision_ids,"reference_ids":[],
        "conditional_hypotheses":[],"computational_evidence":[],
        "facts":[
            {"key":"a","statement_tex":"Lemma A.","proof_tex":"Step A.","predecessors":[],"glossary_introduces":{}},
            {"key":"b","statement_tex":"Lemma B.","proof_tex":"Step B.","predecessors":["a"],"glossary_introduces":{}},
            {"key":"target","statement_tex":"Prove $1=1$.","proof_tex":"Step C.","predecessors":["b"],"glossary_introduces":{}}
        ]
    }), None)?;
    engine.commit(
        "owner",
        capability(&assembler)?,
        "proof_submitted",
        &serde_json::json!({"outcome":"proof"}),
        None,
    )?;
    let verifier = engine.next_task("owner", run_id, None)?;
    assert!(verifier["context"].get("project_memory").is_none());
    engine.write(
        "owner",
        capability(&verifier)?,
        "memory:verifier:statement_checks",
        &serde_json::json!({"location":"proof","status":"checked"}),
        None,
    )?;
    engine.write(
        "owner",
        capability(&verifier)?,
        "memory:verifier:events",
        &serde_json::json!({"event_type":"verification_audit_complete"}),
        None,
    )?;
    engine.write(
        "owner",
        capability(&verifier)?,
        "verification_report",
        &serde_json::json!({
            "verification_report":{"summary":"Valid.","critical_errors":[],"gaps":[]},
            "verdict":"correct","repair_hints":""
        }),
        None,
    )?;
    engine.commit(
        "owner",
        capability(&verifier)?,
        "verification_submitted",
        &serde_json::json!({}),
        None,
    )?;
    let done = engine.next_task("owner", run_id, None)?;
    assert_eq!(done["state"], "done");
    let graph = store.project_fact_graph("project-memory", "owner")?;
    let expected_nodes = if with_dependency { 4 } else { 3 };
    let expected_edges = if with_dependency { 3 } else { 2 };
    assert_eq!(
        graph["graph"]["nodes"]
            .as_object()
            .map(serde_json::Map::len),
        Some(expected_nodes)
    );
    assert_eq!(
        graph["graph"]["edges"].as_array().map(Vec::len),
        Some(expected_edges)
    );
    let a = compute_fact_id(
        "project-memory",
        &[],
        &BTreeMap::new(),
        "Lemma A.",
        "Step A.",
    );
    let b = compute_fact_id(
        "project-memory",
        std::slice::from_ref(&a),
        &BTreeMap::new(),
        "Lemma B.",
        "Step B.",
    );
    let mut target_predecessors = vec![b.clone()];
    if with_dependency {
        target_predecessors.push(external_fact_id.clone());
    }
    target_predecessors.sort();
    let target_id = compute_fact_id(
        "project-memory",
        &target_predecessors,
        &BTreeMap::new(),
        "Prove $1=1$.",
        "Step C.",
    );
    for id in [&a, &b, &target_id] {
        assert!(graph["graph"]["nodes"].get(id).is_some());
    }
    assert!(
        store
            .memory_fact_predecessors("project-memory", &a)?
            .is_empty()
    );
    assert_eq!(
        store.memory_fact_predecessors("project-memory", &b)?,
        vec![a.clone()]
    );
    assert_eq!(
        store.memory_fact_predecessors("project-memory", &target_id)?,
        target_predecessors
    );
    let revision = store
        .current_claim_revision("claim-memory", "owner")?
        .ok_or_else(|| ReCtmError::new("TEST", "promoted target revision missing"))?;
    assert_eq!(revision["fact_id"], target_id);

    let next = engine.start(StartRequest {
        owner_id: "owner",
        problem_tex: "Prove $1=1$.",
        problem_id: Some("memory-next"),
        references: &[],
        native_mode: "dangerous",
        workspace_export_path: None,
        project_id: Some("project-memory"),
        target_claim_id: None,
        workflow_mode: "compact",
        register_result: false,
        workflow_protocol_version: 3,
        trace_id: None,
    })?;
    let next_id = next["run_id"]
        .as_str()
        .ok_or_else(|| ReCtmError::new("TEST", "next run id missing"))?;
    let task = engine.next_task("owner", next_id, None)?;
    let memory = &task["context"]["mathematical_research_state"]["project_memory"];
    assert_eq!(
        memory["fact_graph"]["nodes"].as_array().map(Vec::len),
        Some(expected_nodes)
    );
    assert_eq!(
        memory["fact_graph"]["edges"].as_array().map(Vec::len),
        Some(expected_edges)
    );
    assert_eq!(memory["advisory_only"], true);
    assert_eq!(serde_json::to_vec(memory).ok(), serde_json::to_vec(&engine.next_task("owner", next_id, None)?["context"]["mathematical_research_state"]["project_memory"]).ok());
    if with_dependency {
        let revoked = store.revoke_project_fact(
            &external_fact_id,
            "operator",
            "Regression fixture: invalid external premise",
        )?;
        let mut expected_revoked = vec![external_fact_id, target_id];
        expected_revoked.sort();
        assert_eq!(
            revoked["revoked_fact_ids"],
            serde_json::json!(expected_revoked)
        );
        assert_eq!(
            store.active_project_fact_ids("project-memory", "owner")?,
            BTreeSet::from([a, b])
        );
    }
    Ok(())
}

#[test]
fn project_memory_remains_bounded_with_long_fact_chains_and_many_findings() -> Result<(), ReCtmError>
{
    assert_bounded_project_memory(false)
}

#[test]
fn project_memory_keeps_shared_predecessors_when_truncating() -> Result<(), ReCtmError> {
    assert_bounded_project_memory(true)
}

fn assert_bounded_project_memory(shared_predecessors: bool) -> Result<(), ReCtmError> {
    let temp =
        tempfile::tempdir().map_err(|error| ReCtmError::new("TEST_IO", error.to_string()))?;
    let store = StateStore::open(temp.path().join("state.sqlite3"))?;
    store.create_project(
        "owner",
        "Large",
        Some("project-large"),
        &serde_json::json!({}),
    )?;
    store.create_claim(
        "owner",
        "project-large",
        "Target",
        Some("claim-large"),
        &serde_json::json!({}),
    )?;
    let base = store.create_open_claim_revision("owner", "claim-large", "Target.", &[], None)?;
    let snapshot = store.create_project_snapshot("project-large", "owner")?;
    store.create_run(
        "run-large",
        "prior-proof",
        "owner",
        "done",
        &serde_json::json!({}),
    )?;
    store.link_run_to_project(
        "run-large",
        "owner",
        "project-large",
        snapshot["snapshot_id"]
            .as_str()
            .ok_or_else(|| ReCtmError::new("TEST", "snapshot missing"))?,
        Some("claim-large"),
        base["revision_id"].as_str(),
        "compact",
        "compact",
        true,
    )?;
    let facts = (0..16)
        .map(|index| FactForPromotion {
            fact_id: format!("{:016x}", index + 1),
            statement_tex: if index == 15 {
                "Target.".to_owned()
            } else {
                format!("Lemma {index}: {}", "x".repeat(500))
            },
            proof_tex: format!("Proof step {index}."),
            intuition: String::new(),
            glossary_json: "{}".to_owned(),
            predecessors: if shared_predecessors {
                (1..=index).map(|id| format!("{id:016x}")).collect()
            } else if index == 0 {
                Vec::new()
            } else {
                vec![format!("{index:016x}")]
            },
        })
        .collect::<Vec<_>>();
    store.promote_verified_run_with_facts(
        "run-large",
        "owner",
        "Target.",
        &"a".repeat(64),
        &[],
        &serde_json::json!({"dependency_revision_ids":[]}),
        &facts,
    )?;
    let kinds = ["dead_end", "counterexample", "obstacle", "plan"];
    let findings = (0..80)
        .map(|index| FindingForStorage {
            finding_id: format!("{index:064x}"),
            kind: kinds[index % kinds.len()].to_owned(),
            claim: format!("Finding {index}: {}", "c".repeat(1500)),
            evidence: "e".repeat(1500),
            verifiable: false,
            links_json: "{}".to_owned(),
        })
        .collect::<Vec<_>>();
    store.insert_project_findings("project-large", "run-large", "owner", &findings)?;

    let engine = engine(temp.path(), Arc::new(PassingLatex))?;
    let started = engine.start(StartRequest {
        owner_id: "owner",
        problem_tex: "Target.",
        problem_id: Some("memory-large-next"),
        references: &[],
        native_mode: "dangerous",
        workspace_export_path: None,
        project_id: Some("project-large"),
        target_claim_id: None,
        workflow_mode: "compact",
        register_result: false,
        workflow_protocol_version: 3,
        trace_id: None,
    })?;
    let run_id = started["run_id"]
        .as_str()
        .ok_or_else(|| ReCtmError::new("TEST", "run id missing"))?;
    let task = engine.next_task("owner", run_id, None)?;
    let view = &task["context"]["mathematical_research_state"];
    let memory = &view["project_memory"];
    assert!(
        serde_json::to_vec(view)
            .map_err(|error| ReCtmError::new("TEST", error.to_string()))?
            .len()
            <= mtm_workflow::research_state::MAX_RESEARCH_TASK_VIEW_BYTES
    );
    assert!(
        memory["fact_graph"]["nodes"]
            .as_array()
            .is_some_and(|nodes| !nodes.is_empty() && nodes.len() <= 8)
    );
    assert_eq!(memory["fact_graph"]["truncated"], true);
    let nodes = memory["fact_graph"]["nodes"]
        .as_array()
        .ok_or_else(|| ReCtmError::new("TEST", "missing memory nodes"))?;
    let mut seen = BTreeSet::new();
    let mut expected_edges = BTreeSet::new();
    for node in nodes {
        let id = node["fact_id"]
            .as_str()
            .ok_or_else(|| ReCtmError::new("TEST", "missing memory fact id"))?;
        for predecessor in store.memory_fact_predecessors("project-large", id)? {
            assert!(
                seen.contains(&predecessor),
                "predecessor omitted or out of order"
            );
            expected_edges.insert((id.to_owned(), predecessor));
        }
        assert!(seen.insert(id.to_owned()));
    }
    let edges = memory["fact_graph"]["edges"]
        .as_array()
        .ok_or_else(|| ReCtmError::new("TEST", "missing memory edges"))?;
    let actual_edges = edges
        .iter()
        .map(|edge| {
            Ok((
                edge[0]
                    .as_str()
                    .ok_or_else(|| ReCtmError::new("TEST", "edge source"))?
                    .to_owned(),
                edge[1]
                    .as_str()
                    .ok_or_else(|| ReCtmError::new("TEST", "edge target"))?
                    .to_owned(),
            ))
        })
        .collect::<Result<BTreeSet<_>, ReCtmError>>()?;
    assert_eq!(actual_edges, expected_edges);
    let encoded = serde_json::to_vec(&memory["fact_graph"])
        .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
    assert_eq!(
        memory["graph_digest"],
        format!("sha256:{:x}", Sha256::digest(encoded))
    );
    let again = engine.next_task("owner", run_id, None)?;
    assert_eq!(
        memory,
        &again["context"]["mathematical_research_state"]["project_memory"]
    );
    for group in [
        "prior_dead_ends",
        "prior_counterexamples",
        "obstacles",
        "other_findings",
    ] {
        assert!(memory[group].as_array().is_some_and(|rows| rows.len() <= 5));
    }
    Ok(())
}

#[test]
fn legacy_revision_without_fact_cannot_enter_a_new_fact_proof() -> Result<(), ReCtmError> {
    let temp =
        tempfile::tempdir().map_err(|error| ReCtmError::new("TEST_IO", error.to_string()))?;
    let store = StateStore::open(temp.path().join("state.sqlite3"))?;
    store.create_project(
        "owner",
        "Legacy",
        Some("project-legacy"),
        &serde_json::json!({}),
    )?;
    store.create_claim(
        "owner",
        "project-legacy",
        "Old",
        Some("claim-old"),
        &serde_json::json!({}),
    )?;
    let old_base =
        store.create_open_claim_revision("owner", "claim-old", "Old lemma.", &[], None)?;
    let old_snapshot = store.create_project_snapshot("project-legacy", "owner")?;
    store.create_run(
        "run-legacy",
        "old-proof",
        "owner",
        "done",
        &serde_json::json!({}),
    )?;
    store.link_run_to_project(
        "run-legacy",
        "owner",
        "project-legacy",
        old_snapshot["snapshot_id"]
            .as_str()
            .ok_or_else(|| ReCtmError::new("TEST", "snapshot missing"))?,
        Some("claim-old"),
        old_base["revision_id"].as_str(),
        "compact",
        "compact",
        true,
    )?;
    let old = store.promote_verified_run(
        "run-legacy",
        "owner",
        "Old lemma.",
        &"a".repeat(64),
        &[],
        &serde_json::json!({"dependency_revision_ids":[]}),
    )?;
    assert!(old["revision"]["fact_id"].is_null());
    store.create_claim(
        "owner",
        "project-legacy",
        "Target",
        Some("claim-new"),
        &serde_json::json!({}),
    )?;
    store.create_open_claim_revision("owner", "claim-new", "Target.", &[], None)?;

    let engine = engine(temp.path(), Arc::new(PassingLatex))?;
    let started = engine.start(StartRequest {
        owner_id: "owner",
        problem_tex: "Target.",
        problem_id: Some("legacy-dependency"),
        references: &[],
        native_mode: "dangerous",
        workspace_export_path: None,
        project_id: Some("project-legacy"),
        target_claim_id: Some("claim-new"),
        workflow_mode: "compact",
        register_result: true,
        workflow_protocol_version: 3,
        trace_id: None,
    })?;
    let run_id = started["run_id"]
        .as_str()
        .ok_or_else(|| ReCtmError::new("TEST", "run id missing"))?;
    let assess = engine.next_task("owner", run_id, None)?;
    engine.write(
        "owner",
        capability(&assess)?,
        "memory:generation:immediate_conclusions",
        &serde_json::json!({"summary":"Old lemma is available."}),
        None,
    )?;
    engine.commit("owner", capability(&assess)?, "assessment_complete",
        &serde_json::json!({"route":"compact","requires_external_retrieval":false,"requires_multiple_plans":false}), None)?;
    let assembler = engine.next_task("owner", run_id, None)?;
    engine.write(
        "owner",
        capability(&assembler)?,
        "proof",
        &Value::String("Old lemma. Target.".to_owned()),
        None,
    )?;
    engine.write(
        "owner",
        capability(&assembler)?,
        "proof_manifest",
        &serde_json::json!({
            "target_statement_tex":"Target.",
            "dependency_revision_ids":[old["revision"]["revision_id"]],
            "reference_ids":[],"conditional_hypotheses":[],"computational_evidence":[]
        }),
        None,
    )?;
    let error = engine
        .commit(
            "owner",
            capability(&assembler)?,
            "proof_submitted",
            &serde_json::json!({"outcome":"proof"}),
            None,
        )
        .err()
        .ok_or_else(|| ReCtmError::new("TEST", "legacy revision was accepted"))?;
    assert_eq!(error.code, "INVALID_ARGUMENT");
    assert!(error.message.contains("no verified fact"));
    assert_eq!(engine.status("owner", run_id)?["state"], "assemble");
    assert!(
        store
            .list_project_facts("project-legacy", "owner")?
            .is_empty()
    );
    Ok(())
}

#[test]
fn done_reconnect_repairs_only_the_missing_manual_manifest_without_republishing_proof()
-> Result<(), ReCtmError> {
    let temp = tempfile::tempdir().map_err(|error| {
        ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
    })?;
    let engine = engine(temp.path(), Arc::new(PassingLatex))?;
    let (run_id, proof) = advance_compact_to_finalize(&engine)?;
    let run_root = temp.path().join("private/runs").join(&run_id);
    let manual = run_root.join("debug/manual-validation-manifest.json");
    fs::create_dir(&manual).map_err(|error| {
        ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
    })?;
    assert!(
        engine
            .next_task("owner", &run_id, Some("finalize-post-transition-fault"))
            .is_err()
    );
    assert_eq!(engine.status("owner", &run_id)?["state"], "done");
    let final_path = run_root.join("final/proof_verified.tex");
    let final_bytes = fs::read(&final_path).map_err(|error| {
        ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
    })?;
    assert_eq!(String::from_utf8_lossy(&final_bytes), proof);
    fs::remove_dir(&manual).map_err(|error| {
        ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
    })?;
    let done = engine.next_task("owner", &run_id, Some("done-reconnect"))?;
    assert_eq!(done["state"], "done");
    assert!(manual.is_file());
    assert_eq!(
        fs::read(&final_path).map_err(|error| {
            ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
        })?,
        final_bytes
    );
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
fn interrupted_branch_preparation_leaves_no_partial_database_rows_and_reuses_one_plan()
-> Result<(), ReCtmError> {
    let temp = tempfile::tempdir().map_err(|error| {
        ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
    })?;
    let engine = engine(temp.path(), Arc::new(PassingLatex))?;
    let started = engine.start(StartRequest {
        owner_id: "owner",
        problem_tex: "Prove a two-route branch preparation recovery statement.",
        problem_id: Some("branch-prepare-recovery"),
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
        &serde_json::json!({"summary":"two routes"}),
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
            ReCtmError::new("TEST_FAILURE", "active plans missing")
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
            serde_json::json!({subgoal_id:{
                "status":"stuck","summary":"branch needed","method":"direct",
                "obstruction":"no_progress","evidence_ids":[]
            }}),
        );
    }
    engine.write(
        "owner",
        capability(&direct)?,
        "memory:generation:proof_steps",
        &serde_json::json!({"summary":"branch both plans"}),
        None,
    )?;
    let prepared = engine.commit(
        "owner",
        capability(&direct)?,
        "direct_proving_complete",
        &serde_json::json!({"screening":Value::Object(screening)}),
        None,
    )?;
    assert_eq!(prepared["state"], "branch_prepare");

    let branches_root = temp
        .path()
        .join("private/runs")
        .join(&run_id)
        .join("branches");
    fs::remove_dir(&branches_root).map_err(|error| {
        ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
    })?;
    fs::write(&branches_root, b"fault fixture").map_err(|error| {
        ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
    })?;
    assert!(
        engine
            .next_task("owner", &run_id, Some("branch-prepare-fault"))
            .is_err()
    );
    let independent = StateStore::open(temp.path().join("state.sqlite3"))?;
    assert!(independent.list_branches(&run_id)?.is_empty());
    assert!(
        independent
            .list_domains(&run_id, Some("branch"), None)?
            .is_empty()
    );

    fs::remove_file(&branches_root).map_err(|error| {
        ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
    })?;
    fs::create_dir(&branches_root).map_err(|error| {
        ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
    })?;
    let branch = engine.next_task("owner", &run_id, Some("branch-prepare-retry"))?;
    assert_eq!(branch["state"], "branch_run");
    assert_eq!(independent.list_branches(&run_id)?.len(), 2);
    assert_eq!(
        independent
            .list_domains(&run_id, Some("branch"), None)?
            .len(),
        2
    );
    let snapshots = fs::read_dir(
        temp.path()
            .join("private/runs")
            .join(&run_id)
            .join("snapshots"),
    )
    .map_err(|error| ReCtmError::new("TEST_IO", error.to_string()))?
    .collect::<Result<Vec<_>, _>>()
    .map_err(|error| ReCtmError::new("TEST_IO", error.to_string()))?;
    assert_eq!(snapshots.len(), 1);
    Ok(())
}

#[test]
fn protocol_three_inline_references_expose_registered_ids_for_typed_retrieval()
-> Result<(), ReCtmError> {
    let temp = tempfile::tempdir().map_err(|error| {
        ReCtmError::new("TEST_IO", error.to_string()).with_category(ErrorCategory::Runtime)
    })?;
    let engine = engine(temp.path(), Arc::new(PassingLatex))?;
    let references = vec![serde_json::json!({
        "name":"source-a.txt",
        "content":"A checked source statement.",
        "source":"https://example.invalid/source-a"
    })];
    let started = engine.start(StartRequest {
        owner_id: "owner",
        problem_tex: "Prove a statement using one injected reference.",
        problem_id: Some("protocol-three-inline-reference"),
        references: &references,
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
    let registered = assess["context"]["registered_references"]
        .as_array()
        .ok_or_else(|| {
            ReCtmError::new("TEST_FAILURE", "registered reference locators missing")
                .with_category(ErrorCategory::Internal)
        })?;
    assert_eq!(registered.len(), 1);
    assert_eq!(registered[0]["title"], "source-a.txt");
    let reference_id = registered[0]["reference_id"]
        .as_str()
        .ok_or_else(|| {
            ReCtmError::new("TEST_FAILURE", "registered reference id missing")
                .with_category(ErrorCategory::Internal)
        })?
        .to_owned();
    engine.write(
        "owner",
        capability(&assess)?,
        "memory:generation:immediate_conclusions",
        &serde_json::json!({"summary":"the injected source is relevant"}),
        None,
    )?;
    engine.write(
        "owner",
        capability(&assess)?,
        "memory:generation:events",
        &serde_json::json!({
            "event_type":"assessment",
            "summary":"Use the registered source during exploration."
        }),
        None,
    )?;
    engine.commit(
        "owner",
        capability(&assess)?,
        "assessment_complete",
        &serde_json::json!({"route":"full","requires_external_retrieval":true}),
        None,
    )?;

    let explore = engine.next_task("owner", &run_id, None)?;
    assert_eq!(
        explore["context"]["registered_references"][0]["reference_id"],
        reference_id
    );
    engine.write(
        "owner",
        capability(&explore)?,
        "memory:generation:events",
        &serde_json::json!({
            "event_type":"retrieval_assessment",
            "outcome":"new_material",
            "summary":"The injected source supplies relevant material.",
            "query":"injected source",
            "reference_ids":[reference_id]
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
    let proof_steps = engine.read(
        "owner",
        capability(&assembler)?,
        "memory:generation:proof_steps",
        None,
    )?;
    assert_eq!(
        proof_steps["content"].as_array().map(Vec::len),
        Some(1),
        "protocol-3 direct screening must persist its canonical proof_steps record"
    );
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

    // The transition returns its row inside the write transaction. Establish the
    // post-commit read view before freezing bytes: the first SELECT can update
    // SQLite's transient WAL-index read mark. Do not exclude SHM, WAL, database
    // or private files from the unchanged-byte assertions below.
    assert_eq!(engine.status("owner", &run_id)?["state"], "branch_prepare");
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
