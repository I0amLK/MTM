//! Synthetic integrity regressions. These never count as research trials.
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use nix::sys::stat::Mode;
use nix::unistd::mkfifo;
use tempfile::{TempDir, tempdir};

use super::*;

const REGISTRY: &[u8] = include_bytes!("../../../conformance/mtm016-research-cases.tsv");
const CORPUS: &[u8] = include_bytes!("../../../conformance/mtm016-usability-corpus.json");
const RELEASE_INPUTS: &str = include_str!("../../../records/governance/mtm016-release-inputs.json");

#[test]
fn frozen_research_identity_matches_selected_release_candidate() -> Result<()> {
    let manifest: Value = serde_json::from_str(RELEASE_INPUTS)?;
    assert_eq!(manifest["candidate_sha256"], CANDIDATE_SHA);
    assert_eq!(manifest["candidate_source_commit"], CANDIDATE_SOURCE);
    Ok(())
}

struct Fixture {
    directory: TempDir,
    bundle: Value,
    material: BTreeMap<Kind, Vec<u8>>,
}

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

impl Fixture {
    fn persist(&mut self) -> Result<()> {
        let mut bindings = Vec::new();
        for (kind, bytes) in &self.material {
            write(&self.directory.path().join(kind.filename()), bytes)?;
            bindings.push(json!({"kind":kind,"sha256":hash(bytes)}));
        }
        self.bundle["artifacts"] = json!(bindings);
        self.write_bundle()
    }

    fn write_bundle(&self) -> Result<()> {
        write(
            &self.directory.path().join("bundle.json"),
            &serde_json::to_vec(&self.bundle)?,
        )
    }

    fn inspect(&self) -> Result<Value> {
        inspect(&files::Directory::open(self.directory.path())?, REGISTRY)
    }

    fn change(&mut self, kind: Kind, key: &str, value: Value) -> Result<()> {
        let bytes = self.material.get(&kind).ok_or("fixture material missing")?;
        let mut object: Value = serde_json::from_slice(bytes)?;
        object[key] = value;
        self.material.insert(kind, serde_json::to_vec(&object)?);
        self.persist()
    }
}

fn fixture(task: &str, repeat: u8) -> Result<Fixture> {
    let mut fixture = Fixture {
        directory: tempdir()?,
        bundle: json!({"schema":"mtm-research-bundle-v1","task_id":task,"repeat":repeat,
            "trial_id":"a".repeat(32),"run_id":"run-private-NOT-FOR-REPORT","artifacts":[]}),
        material: BTreeMap::new(),
    };
    fs::set_permissions(fixture.directory.path(), fs::Permissions::from_mode(0o700))?;
    let bundle: Bundle = serde_json::from_value(fixture.bundle.clone())?;
    let case = case(REGISTRY, &bundle)?;
    let final_tex =
        b"\\documentclass{article}\\begin{document}SYNTHETIC-NOT-A-REAL-PROOF\\end{document}";
    let output = b"SYNTHETIC-COMPILER-OUTPUT-NOT-PROOF-OF-COMPILATION\n";
    let final_report = json!({"verification_report":{"summary":"Synthetic checker fixture, not a real mathematical review.","critical_errors":[],"gaps":[]},"repair_hints":""});
    let first_report = json!({"verification_report":{"summary":"Synthetic seeded defect.","critical_errors":[],"gaps":[{"location":"Synthetic draft step 1","issue":"Missing quantifier justification."}]},"repair_hints":"Supply the missing argument."});
    let final_report_bytes = serde_json::to_vec(&final_report)?;
    let first_report_bytes = serde_json::to_vec(&first_report)?;
    let seed = b"\\documentclass{article}\\begin{document}SYNTHETIC-SEEDED-GAP\\end{document}";
    let sage_input = b"SYNTHETIC-NEVER-EXECUTED-SAGE-INPUT\n";
    let sage_output = b"SYNTHETIC-NOT-REAL-SAGE-OUTPUT\n";
    let magma_input = b"SYNTHETIC-NEVER-EXECUTED-MAGMA-INPUT\n";
    let magma_output = b"SYNTHETIC-NOT-REAL-MAGMA-OUTPUT\n";
    let mut after = if task == "U24" {
        vec![
            "assess",
            "explore",
            "propose_plans",
            "branch_prepare",
            "branch_run",
            "branch_join",
            "assemble",
            "latex_validate",
            "verify",
        ]
    } else {
        vec!["assess", "assemble", "latex_validate", "verify"]
    };
    if task == "U23" {
        after.extend(["repair", "latex_validate", "verify"]);
    }
    after.extend(["finalize", "done"]);
    let mut before = "created";
    let transitions: Vec<_> = after.iter().enumerate().map(|(index, state)| {
        let row = json!({"run_id":bundle.run_id,"sequence":index+1,"before_state":before,"after_state":state});
        before = state;
        row
    }).collect();
    for kind in required(task)? {
        let value = match kind {
            Kind::Session => json!({"schema":"mtm-research-session-v1","milestone":"MTM-016",
                "task_id":task,"repeat":repeat,"case_id":case.id,"workflow_mode":case.mode,
                "trial_id":bundle.trial_id,"candidate_sha256":CANDIDATE_SHA,"candidate_source_commit":CANDIDATE_SOURCE,
                "launcher_source_commit":"c".repeat(40),"launcher_sha256":"d".repeat(64),
                "case_registry_sha256":REGISTRY_SHA,"corpus_sha256":CORPUS_SHA,
                "native_mode":"safe","latex_policy":"required","session_prepared":true,
                "runtime_executed":false,"independent_review_recorded":false,"research_trial_passed":false,"release_qualified":false}),
            Kind::Status => json!({"ok":true,"run_id":bundle.run_id,"problem_id":case.id,
                "state":"done","status":"done","sealed":true,"verdict":"correct","latex_passed":true,
                "manual_validation_required":true,"pending_submission":null,"transition_seq":transitions.len()}),
            Kind::Transitions => json!(transitions),
            Kind::VerificationReport => final_report.clone(),
            Kind::FirstFindings => first_report.clone(),
            Kind::ProofManifest => json!({"target_statement_tex":"Synthetic target.",
                "reference_ids":if task == "U22" {vec!["synthetic-reference"]} else {vec![]},
                "dependency_revision_ids":[],"conditional_hypotheses":[],
                "computational_evidence":if task == "U25" {vec!["sage-check","magma-check"]} else {vec![]}}),
            Kind::Compiler => {
                json!({"schema":"mtm-research-compiler-observation-v1","run_id":bundle.run_id,
                "policy":"required","program":"latexmk","exit_code":0,
                "source_sha256":hash(final_tex),"output_sha256":hash(output)})
            }
            Kind::Review => {
                json!({"schema":"mtm-research-review-observation-v1","trial_id":bundle.trial_id,
                "run_id":bundle.run_id,"generator_session":"private-generator-marker","reviewer_session":"private-reviewer-marker",
                "generator_owner_fingerprint":"e".repeat(64),"reviewer_owner_fingerprint":"e".repeat(64),
                "reviewed_sha256":hash(final_tex),"verification_report_sha256":hash(&final_report_bytes),
                "same_live_connection_observed":true,"reviewed_before_finalization":true,
                "statement_checks":[{"location":"Synthetic line 1","summary":"PRIVATE-REVIEW-NOT-AUTHENTICATED"}]})
            }
            Kind::Retrieval => {
                json!({"schema":"mtm-research-retrieval-observation-v1","run_id":bundle.run_id,
                "calls":[{"method":"rethlas_retrieve","reference_ids":["synthetic-reference"],
                    "result_sha256":"1".repeat(64),"external_network_observed":true}],
                "raw_credentials_recorded":false,"raw_response_bodies_recorded":false})
            }
            Kind::ReferenceAudit => json!({"references":[{"reference_id":"synthetic-reference"}],
                "audits":[{"reference_id":"synthetic-reference","disposition":"SOURCE_VERIFIED",
                    "evidence_basis":"external_source_inspection","evidence_locator":"synthetic-source-locator",
                    "material":true,"assumptions_checked":true,"notation_checked":true,"source_checked":true,
                    "proof_sha256":hash(final_tex)}]}),
            Kind::Sources => {
                json!({"schema":"mtm-research-source-observation-v1","run_id":bundle.run_id,
                "sources":[{"reference_id":"synthetic-reference","source_kind":"authoritative",
                    "locator_sha256":"2".repeat(64),"content_sha256":"3".repeat(64),
                    "original_or_authoritative_source_inspected":true}]})
            }
            Kind::RepairHistory => json!({"seeded_challenge":true,"run_id":bundle.run_id,
                "initial_draft_sha256":hash(seed),"first_findings_sha256":hash(&first_report_bytes),
                "final_sha256":hash(final_tex)}),
            Kind::Branches => {
                json!({"schema":"mtm-research-branch-observation-v1","run_id":bundle.run_id,
                "branches":[
                    {"branch_id":"branch-1","domain_id":"domain-1","session_marker":"branch-session-1",
                        "order_index":0,"status":"sealed","result_sha256":"4".repeat(64),"sibling_private_read_denied":true},
                    {"branch_id":"branch-2","domain_id":"domain-2","session_marker":"branch-session-2",
                        "order_index":1,"status":"sealed","result_sha256":"5".repeat(64),"sibling_private_read_denied":true}],
                "join":{"all_required_sealed_before_join":true,"considered_branch_ids":["branch-1","branch-2"],
                    "result_sha256":"6".repeat(64)}})
            }
            Kind::CasObservation => {
                json!({"schema":"mtm-research-cas-observation-v1","run_id":bundle.run_id,
                "native_mode":"safe","general_proof_independent":true,"raw_credentials_recorded":false,
                "tools":[
                    {"name":"sage","version":"synthetic-sage","input_sha256":hash(sage_input),
                        "output_sha256":hash(sage_output),"exit_code":0,
                        "permission_challenge_observed":true,"permission_granted":true},
                    {"name":"magma","version":"synthetic-magma","input_sha256":hash(magma_input),
                        "output_sha256":hash(magma_output),"exit_code":0,
                        "permission_challenge_observed":true,"permission_granted":true}]})
            }
            _ => {
                json!({"synthetic_material":"Presence only. Route semantics are NOT verified by this fixture."})
            }
        };
        let bytes = match kind {
            Kind::FinalTex | Kind::ReviewedTex => final_tex.to_vec(),
            Kind::SeededDraft => seed.to_vec(),
            Kind::CompilerOutput => output.to_vec(),
            Kind::SageInput => sage_input.to_vec(),
            Kind::SageOutput => sage_output.to_vec(),
            Kind::MagmaInput => magma_input.to_vec(),
            Kind::MagmaOutput => magma_output.to_vec(),
            _ => serde_json::to_vec(&value)?,
        };
        fixture.material.insert(kind, bytes);
    }
    fixture.persist()?;
    Ok(fixture)
}

#[test]
fn every_fixed_case_can_inventory_material_but_never_grants_acceptance() -> Result<()> {
    for task in ["U21", "U22", "U23", "U24", "U25"] {
        for repeat in 1..=3 {
            let fixture = fixture(task, repeat)?;
            let report = fixture.inspect()?;
            assert_eq!(report["required_material_present"], true);
            assert_eq!(report["research_trial_passed"], false);
            assert_eq!(report["accepted_trials_delta"], 0);
            assert_eq!(report["release_qualified"], false);
            assert_eq!(report["manual_validation_required"], true);
            assert_eq!(report, fixture.inspect()?);
        }
    }
    Ok(())
}

#[test]
fn every_missing_or_unlisted_material_is_reported_without_acceptance() -> Result<()> {
    for task in ["U21", "U22", "U23", "U24", "U25"] {
        for kind in required(task)? {
            let fixture = fixture(task, 1)?;
            fs::remove_file(fixture.directory.path().join(kind.filename()))?;
            let report = fixture.inspect()?;
            assert_eq!(report["required_material_present"], false);
            assert_eq!(report["missing_material"], json!([kind.filename()]));
        }
    }
    let mut fixture = fixture("U21", 1)?;
    fixture.bundle["artifacts"] = json!([]);
    fixture.write_bundle()?;
    assert_eq!(fixture.inspect()?["artifact_count"], 0);
    Ok(())
}

#[test]
fn unknown_fields_roles_duplicates_versions_and_digest_shapes_fail_closed() -> Result<()> {
    for (key, value) in [
        ("schema", json!("v99")),
        ("task_id", json!("U26")),
        ("repeat", json!(0)),
        ("repeat", json!(4)),
        ("trial_id", json!("wrong")),
        ("run_id", json!("../secret")),
        ("capability", json!("SECRET-NEVER-ECHO")),
        ("release_qualified", json!(true)),
    ] {
        let mut fixture = fixture("U21", 1)?;
        fixture.bundle[key] = value;
        fixture.write_bundle()?;
        assert!(fixture.inspect().is_err());
    }
    let mut fixture = fixture("U21", 1)?;
    let binding = fixture.bundle["artifacts"][0].clone();
    for bindings in [
        json!([binding, binding]),
        json!([{"kind":"operator.log","sha256":"f".repeat(64)}]),
        json!([{"kind":"sources","sha256":"f".repeat(64)}]),
        json!([{"kind":"session","sha256":"NOT-A-DIGEST"}]),
        json!([{"kind":"session","sha256":"f".repeat(64),"path":"/etc/passwd"}]),
    ] {
        fixture.bundle["artifacts"] = bindings;
        fixture.write_bundle()?;
        assert!(fixture.inspect().is_err());
    }
    Ok(())
}

#[test]
fn ambiguous_json_and_hash_tampering_are_not_silently_repaired() -> Result<()> {
    let mut fixture = fixture("U21", 1)?;
    for bytes in [
        br#"{"schema":0,"schema":1}"#.as_slice(),
        br#"{"nested":{"x":1,"\u0078":2}}"#,
        b"{}{}",
    ] {
        write(&fixture.directory.path().join("bundle.json"), bytes)?;
        assert!(fixture.inspect().is_err());
    }
    fixture.persist()?;
    write(
        &fixture.directory.path().join("final.tex"),
        b"modified final",
    )?;
    assert!(fixture.inspect().is_err());
    fixture
        .material
        .insert(Kind::Review, br#"{"x":0,"x":1}"#.to_vec());
    fixture.persist()?;
    assert!(fixture.inspect().is_err());
    Ok(())
}

#[test]
fn preparations_cannot_be_promoted_reassigned_or_downgraded() -> Result<()> {
    for (key, value) in [
        ("research_trial_passed", json!(true)),
        ("runtime_executed", json!(true)),
        ("independent_review_recorded", json!(true)),
        ("release_qualified", json!(true)),
        ("native_mode", json!("dangerous")),
        ("latex_policy", json!("static-only")),
        ("repeat", json!(2)),
        ("case_id", json!("old-problem-id")),
        ("trial_id", json!("b".repeat(32))),
        ("candidate_sha256", json!("b".repeat(64))),
        ("launcher_sha256", json!("")),
        ("extra", json!(true)),
    ] {
        let mut fixture = fixture("U21", 1)?;
        fixture.change(Kind::Session, key, value)?;
        assert!(fixture.inspect().is_err());
    }
    Ok(())
}

#[test]
fn wrong_owner_same_session_blank_findings_and_other_draft_are_rejected() -> Result<()> {
    for (key, value) in [
        ("reviewer_owner_fingerprint", json!("f".repeat(64))),
        ("reviewer_session", json!("private-generator-marker")),
        ("reviewed_sha256", json!("f".repeat(64))),
        ("verification_report_sha256", json!("f".repeat(64))),
        ("same_live_connection_observed", json!(false)),
        ("reviewed_before_finalization", json!(false)),
        ("statement_checks", json!([])),
        (
            "statement_checks",
            json!([{"location":" ","summary":"checked"}]),
        ),
        ("run_id", json!("other-run")),
        ("independent", json!(true)),
    ] {
        let mut fixture = fixture("U21", 1)?;
        fixture.change(Kind::Review, key, value)?;
        assert!(fixture.inspect().is_err());
    }
    let mut fixture = fixture("U21", 1)?;
    fixture
        .material
        .insert(Kind::ReviewedTex, b"different review draft".to_vec());
    fixture.persist()?;
    assert!(fixture.inspect().is_err());
    Ok(())
}

#[test]
fn current_terminal_compiler_and_report_facts_must_agree() -> Result<()> {
    for (key, value) in [
        ("state", json!("verify")),
        ("sealed", json!(false)),
        ("latex_passed", json!(false)),
        ("manual_validation_required", json!(false)),
        ("pending_submission", json!({"pending":true})),
        ("problem_id", json!("wrong-case")),
        ("transition_seq", json!(7)),
    ] {
        let mut fixture = fixture("U21", 1)?;
        fixture.change(Kind::Status, key, value)?;
        assert!(fixture.inspect().is_err());
    }
    for (key, value) in [
        ("policy", json!("disabled")),
        ("exit_code", json!(1)),
        ("source_sha256", json!("f".repeat(64))),
        ("output_sha256", json!("f".repeat(64))),
    ] {
        let mut fixture = fixture("U21", 1)?;
        fixture.change(Kind::Compiler, key, value)?;
        assert!(fixture.inspect().is_err());
    }
    let mut fixture = fixture("U21", 1)?;
    fixture.change(Kind::VerificationReport, "verification_report", json!({"summary":"Unresolved.","critical_errors":[],"gaps":[{"location":"step","issue":"gap"}]}))?;
    assert!(fixture.inspect().is_err());
    Ok(())
}

#[test]
fn unordered_cross_run_incomplete_or_uncompiled_transitions_fail() -> Result<()> {
    for (index, key, value) in [
        (0, "sequence", json!(0)),
        (1, "run_id", json!("other-run")),
        (2, "before_state", json!("wrong")),
        (3, "before_state", json!("assemble")),
        (5, "after_state", json!("verify")),
    ] {
        let mut fixture = fixture("U21", 1)?;
        let mut rows: Value = serde_json::from_slice(
            fixture
                .material
                .get(&Kind::Transitions)
                .ok_or("fixture transitions missing")?,
        )?;
        rows[index][key] = value;
        fixture
            .material
            .insert(Kind::Transitions, serde_json::to_vec(&rows)?);
        fixture.persist()?;
        assert!(fixture.inspect().is_err());
    }
    Ok(())
}

#[test]
fn seeded_findings_and_real_repair_bytes_cannot_be_replaced_with_success_labels() -> Result<()> {
    let mut fixture = self::fixture("U23", 1)?;
    fixture.change(Kind::RepairHistory, "seeded_challenge", json!(false))?;
    assert!(fixture.inspect().is_err());
    let mut fixture = self::fixture("U23", 1)?;
    fixture.change(
        Kind::FirstFindings,
        "verification_report",
        json!({"summary":"correct","critical_errors":[],"gaps":[]}),
    )?;
    assert!(fixture.inspect().is_err());
    let mut fixture = self::fixture("U22", 1)?;
    fixture.change(Kind::ProofManifest, "reference_ids", json!([]))?;
    assert!(fixture.inspect().is_err());
    Ok(())
}

#[test]
fn retrieval_requires_real_call_source_inspection_and_reference_audit_binding() -> Result<()> {
    for (kind, pointer, value) in [
        (Kind::Retrieval, "/raw_credentials_recorded", json!(true)),
        (
            Kind::Retrieval,
            "/calls/0/external_network_observed",
            json!(false),
        ),
        (Kind::Retrieval, "/calls/0/result_sha256", json!("short")),
        (
            Kind::Retrieval,
            "/calls/0/reference_ids",
            json!(["other-reference"]),
        ),
        (
            Kind::Sources,
            "/sources/0/original_or_authoritative_source_inspected",
            json!(false),
        ),
        (Kind::Sources, "/sources/0/source_kind", json!("summary")),
        (
            Kind::ReferenceAudit,
            "/audits/0/disposition",
            json!("UNRESOLVED"),
        ),
        (
            Kind::ReferenceAudit,
            "/audits/0/source_checked",
            json!(false),
        ),
        (
            Kind::ReferenceAudit,
            "/audits/0/proof_sha256",
            json!("f".repeat(64)),
        ),
    ] {
        let mut fixture = fixture("U22", 1)?;
        let mut object: Value =
            serde_json::from_slice(fixture.material.get(&kind).ok_or("route fixture missing")?)?;
        *object.pointer_mut(pointer).ok_or("route fixture pointer")? = value;
        fixture.material.insert(kind, serde_json::to_vec(&object)?);
        fixture.persist()?;
        assert!(fixture.inspect().is_err(), "mutated {pointer}");
    }
    Ok(())
}

#[test]
fn branch_route_requires_distinct_sealed_isolated_branches_and_join_order() -> Result<()> {
    for (pointer, value) in [
        ("/branches/0/status", json!("running")),
        ("/branches/0/sibling_private_read_denied", json!(false)),
        ("/branches/1/session_marker", json!("branch-session-1")),
        ("/branches/1/domain_id", json!("domain-1")),
        ("/branches/1/order_index", json!(0)),
        ("/join/all_required_sealed_before_join", json!(false)),
        ("/join/considered_branch_ids", json!(["branch-1"])),
    ] {
        let mut fixture = fixture("U24", 1)?;
        let mut object: Value = serde_json::from_slice(
            fixture
                .material
                .get(&Kind::Branches)
                .ok_or("branch fixture missing")?,
        )?;
        *object
            .pointer_mut(pointer)
            .ok_or("branch fixture pointer")? = value;
        fixture
            .material
            .insert(Kind::Branches, serde_json::to_vec(&object)?);
        fixture.persist()?;
        assert!(fixture.inspect().is_err(), "mutated {pointer}");
    }
    let mut fixture = fixture("U24", 1)?;
    let mut rows: Value = serde_json::from_slice(
        fixture
            .material
            .get(&Kind::Transitions)
            .ok_or("branch transitions missing")?,
    )?;
    let row = rows
        .as_array_mut()
        .ok_or("branch transitions array missing")?
        .iter_mut()
        .find(|row| row["after_state"] == "branch_join")
        .ok_or("branch join row missing")?;
    row["after_state"] = json!("direct_proving");
    fixture
        .material
        .insert(Kind::Transitions, serde_json::to_vec(&rows)?);
    fixture.persist()?;
    assert!(fixture.inspect().is_err());
    Ok(())
}

#[test]
fn cas_route_requires_safe_permissioned_sage_and_magma_bound_to_exact_io() -> Result<()> {
    for (pointer, value) in [
        ("/native_mode", json!("dangerous")),
        ("/general_proof_independent", json!(false)),
        ("/raw_credentials_recorded", json!(true)),
        ("/tools/0/permission_challenge_observed", json!(false)),
        ("/tools/0/permission_granted", json!(false)),
        ("/tools/0/exit_code", json!(1)),
        ("/tools/0/input_sha256", json!("f".repeat(64))),
        ("/tools/1/name", json!("sage")),
    ] {
        let mut fixture = fixture("U25", 1)?;
        let mut object: Value = serde_json::from_slice(
            fixture
                .material
                .get(&Kind::CasObservation)
                .ok_or("CAS fixture missing")?,
        )?;
        *object.pointer_mut(pointer).ok_or("CAS fixture pointer")? = value;
        fixture
            .material
            .insert(Kind::CasObservation, serde_json::to_vec(&object)?);
        fixture.persist()?;
        assert!(fixture.inspect().is_err(), "mutated {pointer}");
    }
    let mut fixture = fixture("U25", 1)?;
    fixture.change(Kind::ProofManifest, "computational_evidence", json!([]))?;
    assert!(fixture.inspect().is_err());
    Ok(())
}

#[test]
fn symlinks_hardlinks_directories_and_fifos_fail_without_reading_targets() -> Result<()> {
    for mode in ["symlink", "hardlink", "directory", "fifo"] {
        let fixture = fixture("U21", 1)?;
        let path = fixture.directory.path().join("final.tex");
        fs::remove_file(&path)?;
        let target = fixture.directory.path().join("secret.txt");
        write(&target, b"SECRET-NEVER-READ-OR-PRINT")?;
        match mode {
            "symlink" => symlink(&target, &path)?,
            "hardlink" => fs::hard_link(&target, &path)?,
            "directory" => fs::create_dir(&path)?,
            "fifo" => mkfifo(&path, Mode::S_IRUSR | Mode::S_IWUSR)?,
            _ => return Err("invalid test case".into()),
        }
        assert!(fixture.inspect().is_err());
    }
    Ok(())
}

#[test]
fn descriptor_pinning_prevents_ancestor_swap_redirection() -> Result<()> {
    let root = tempdir()?;
    let bundle = root.path().join("bundle");
    let moved = root.path().join("moved");
    let outside = root.path().join("outside");
    for path in [&bundle, &outside] {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    write(&bundle.join("final.tex"), b"original")?;
    write(&outside.join("final.tex"), b"secret")?;
    let descriptor = files::Directory::open(&bundle)?;
    fs::rename(&bundle, &moved)?;
    symlink(&outside, &bundle)?;
    assert_eq!(
        descriptor.read("final.tex", FILE_LIMIT)?,
        Some(b"original".to_vec())
    );
    assert!(files::Directory::open(&bundle).is_err());
    assert!(files::Directory::open(&bundle.join("..")).is_err());
    assert!(descriptor.read("../secret", FILE_LIMIT).is_err());
    Ok(())
}

#[test]
fn empty_oversized_non_utf8_inputs_and_public_bundle_permissions_are_rejected() -> Result<()> {
    for bytes in [
        Vec::new(),
        vec![b'x'; FILE_LIMIT as usize + 1],
        vec![0xff],
        vec![0],
        b" \n".to_vec(),
    ] {
        let mut fixture = fixture("U21", 1)?;
        fixture.material.insert(Kind::FinalTex, bytes);
        fixture.persist()?;
        assert!(fixture.inspect().is_err());
    }
    let fixture = fixture("U21", 1)?;
    fs::set_permissions(fixture.directory.path(), fs::Permissions::from_mode(0o755))?;
    assert!(fixture.inspect().is_err());
    Ok(())
}

#[test]
fn report_and_errors_do_not_echo_private_content_and_reads_do_not_write() -> Result<()> {
    let fixture = fixture("U21", 1)?;
    let before = fs::read(fixture.directory.path().join("bundle.json"))?;
    let entries_before = fs::read_dir(fixture.directory.path())?.count();
    let report = serde_json::to_string(&fixture.inspect()?)?;
    for private in [
        "run-private",
        "private-generator",
        "private-reviewer",
        "PRIVATE-REVIEW",
        "SYNTHETIC-NOT-A-REAL-PROOF",
        "SYNTHETIC-COMPILER",
    ] {
        assert!(!report.contains(private));
    }
    assert_eq!(
        fs::read(fixture.directory.path().join("bundle.json"))?,
        before
    );
    assert_eq!(
        fs::read_dir(fixture.directory.path())?.count(),
        entries_before
    );
    let error = decode::<Bundle>(br#"{"capability":"SECRET-NEVER-ECHO"}"#)
        .err()
        .ok_or("fixture should fail")?;
    assert!(!error.to_string().contains("SECRET"));
    Ok(())
}

#[test]
fn command_options_and_pinned_inputs_cannot_be_overridden() -> Result<()> {
    assert!(Options::parse(&["--bundle".into(), "/tmp/example".into()]).is_ok());
    for args in [
        vec![],
        vec!["--bundle", "relative"],
        vec!["--bundle", "/tmp/x", "--record"],
        vec!["--binary", "/tmp/x"],
        vec!["--accept", "/tmp/x"],
    ] {
        assert!(Options::parse(&args.into_iter().map(String::from).collect::<Vec<_>>()).is_err());
    }
    let fixture = fixture("U21", 1)?;
    assert!(
        inspect(
            &files::Directory::open(fixture.directory.path())?,
            b"changed registry"
        )
        .is_err()
    );
    let root = tempdir()?;
    fs::create_dir(root.path().join("conformance"))?;
    write(
        &root.path().join("conformance/mtm016-research-cases.tsv"),
        REGISTRY,
    )?;
    write(
        &root.path().join("conformance/mtm016-usability-corpus.json"),
        CORPUS,
    )?;
    let binary = root.path().join(format!(
        "target/mtm016-f5-frozen/mtm-0.6.0-preview.1-{CANDIDATE_SHA}/mtm"
    ));
    fs::create_dir_all(binary.parent().ok_or("fixture parent missing")?)?;
    let mut wrong_candidate = vec![0_u8; 128];
    wrong_candidate[..4].copy_from_slice(b"\x7fELF");
    write(&binary, &wrong_candidate)?;
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o500))?;
    let error = run(
        root.path(),
        &Options {
            bundle: fixture.directory.path().into(),
        },
    )
    .err()
    .ok_or("wrong candidate must fail")?;
    assert_eq!(error.to_string(), "selected candidate digest mismatch");
    Ok(())
}
