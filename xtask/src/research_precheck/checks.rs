//! Mechanical consistency only. No observation is authenticated by its hash.
use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;

use super::{
    Bundle, CORPUS_SHA, Case, Kind, REGISTRY_SHA, ResearchIdentity, decode, hash, hex, require,
    research_policy_for,
};
use crate::{Result, evidence_json};

type Material = BTreeMap<Kind, Vec<u8>>;

fn object(material: &Material, kind: Kind) -> Result<Option<Value>> {
    material
        .get(&kind)
        .map(|bytes| evidence_json::decode(bytes))
        .transpose()
}

fn nonempty(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|text| !text.trim().is_empty() && text.len() <= 65536)
}

fn digest_field(value: &Value, key: &str) -> bool {
    value[key].as_str().is_some_and(|text| hex(text, 64))
}

fn matches_file(value: &Value, key: &str, material: &Material, kind: Kind) -> Result<()> {
    require(digest_field(value, key), "invalid observation digest")?;
    if let Some(bytes) = material.get(&kind) {
        require(
            value[key] == hash(bytes),
            "observation and material digest differ",
        )?;
    }
    Ok(())
}

fn session(value: &Value, bundle: &Bundle, case: &Case, identity: ResearchIdentity) -> Result<()> {
    let policy = research_policy_for(identity.milestone, &bundle.task_id)?;
    require(
        value.as_object().is_some_and(|fields| fields.len() == 20),
        "preparation schema mismatch",
    )?;
    require(
        value["schema"] == policy.session_schema
            && value["milestone"] == identity.milestone
            && value["task_id"] == bundle.task_id
            && value["repeat"] == bundle.repeat
            && value["case_id"] == case.id
            && value["workflow_mode"] == case.mode
            && value["trial_id"] == bundle.trial_id
            && value["candidate_sha256"] == identity.candidate_sha256
            && value["candidate_source_commit"] == identity.candidate_source_commit
            && value["case_registry_sha256"] == REGISTRY_SHA
            && value["corpus_sha256"] == CORPUS_SHA
            && value["native_mode"] == policy.native_mode
            && value["latex_policy"] == "required"
            && value["session_prepared"] == true
            && value["runtime_executed"] == false
            && value["independent_review_recorded"] == false
            && value["research_trial_passed"] == false
            && value["release_qualified"] == false
            && value["launcher_source_commit"]
                .as_str()
                .is_some_and(|text| hex(text, 40))
            && digest_field(value, "launcher_sha256"),
        "preparation identity or frozen policy mismatch",
    )
}

fn status(value: &Value, bundle: &Bundle, case: &Case) -> Result<()> {
    require(
        value["ok"] == true
            && value["run_id"] == bundle.run_id
            && value["problem_id"] == case.id
            && value["state"] == "done"
            && value["status"] == "done"
            && value["sealed"] == true
            && value["verdict"] == "correct"
            && value["latex_passed"] == true
            && value["manual_validation_required"] == true
            && value.get("pending_submission") == Some(&Value::Null)
            && value["transition_seq"]
                .as_u64()
                .is_some_and(|seq| (1..=256).contains(&seq)),
        "terminal observation is incomplete or belongs to another trial",
    )
}

fn transitions(value: &Value, bundle: &Bundle, status: Option<&Value>) -> Result<()> {
    let rows = value
        .as_array()
        .ok_or("transition evidence must be an array")?;
    require(
        !rows.is_empty() && rows.len() <= 256,
        "transition evidence count invalid",
    )?;
    let mut previous: Option<&str> = None;
    let mut verified = 0;
    let mut compiled = 0;
    let mut repairs = 0;
    for (index, row) in rows.iter().enumerate() {
        let before = row["before_state"]
            .as_str()
            .ok_or("transition before-state missing")?;
        let after = row["after_state"]
            .as_str()
            .ok_or("transition after-state missing")?;
        require(
            !before.is_empty()
                && !after.is_empty()
                && before.len() <= 64
                && after.len() <= 64
                && row["run_id"] == bundle.run_id
                && row["sequence"] == index + 1
                && previous.is_none_or(|state| state == before)
                && before != "done"
                && (after != "done" || index + 1 == rows.len()),
            "transition order, sequence or run binding mismatch",
        )?;
        if after == "latex_validate" {
            compiled += 1;
        }
        if after == "verify" {
            require(
                before == "latex_validate",
                "verification without preceding compiler gate",
            )?;
            verified += 1;
        }
        if after == "repair" {
            repairs += 1;
        }
        previous = Some(after);
    }
    let final_row = rows.last().ok_or("transition evidence empty")?;
    require(
        previous == Some("done")
            && final_row["before_state"] == "finalize"
            && verified > 0
            && compiled > 0,
        "compiler, verification or finalizer transition evidence missing",
    )?;
    if let Some(status) = status {
        require(
            status["transition_seq"] == rows.len(),
            "terminal transition count mismatch",
        )?;
    }
    if bundle.task_id == "U23" {
        require(
            repairs > 0 && compiled >= 2 && verified >= 2,
            "seeded repair cycle evidence missing",
        )?;
    }
    Ok(())
}

fn findings(value: &Value, expect_correct: bool) -> Result<()> {
    let report = &value["verification_report"];
    let errors = report["critical_errors"]
        .as_array()
        .ok_or("critical error array missing")?;
    let gaps = report["gaps"]
        .as_array()
        .ok_or("verification gap array missing")?;
    require(
        nonempty(&report["summary"]),
        "substantive report summary missing",
    )?;
    require(
        (errors.is_empty() && gaps.is_empty()) == expect_correct,
        "verification findings contradict stage",
    )?;
    if !expect_correct {
        require(
            nonempty(&value["repair_hints"]),
            "seeded findings lack repair guidance",
        )?;
    }
    for issue in errors.iter().chain(gaps) {
        require(
            nonempty(&issue["location"]) && nonempty(&issue["issue"]),
            "finding lacks location or explanation",
        )?;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatementCheck {
    location: String,
    summary: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    schema: String,
    trial_id: String,
    run_id: String,
    generator_session: String,
    reviewer_session: String,
    generator_owner_fingerprint: String,
    reviewer_owner_fingerprint: String,
    reviewed_sha256: String,
    verification_report_sha256: String,
    same_live_connection_observed: bool,
    reviewed_before_finalization: bool,
    statement_checks: Vec<StatementCheck>,
}

fn marker(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

fn review(bytes: &[u8], bundle: &Bundle, material: &Material) -> Result<()> {
    let review: Review = decode(bytes)?;
    require(
        review.schema == "mtm-research-review-observation-v1"
            && review.trial_id == bundle.trial_id
            && review.run_id == bundle.run_id
            && marker(&review.generator_session)
            && marker(&review.reviewer_session)
            && review.generator_session != review.reviewer_session
            && hex(&review.generator_owner_fingerprint, 64)
            && review.generator_owner_fingerprint == review.reviewer_owner_fingerprint
            && hex(&review.reviewed_sha256, 64)
            && hex(&review.verification_report_sha256, 64)
            && review.same_live_connection_observed
            && review.reviewed_before_finalization,
        "review observation identity, owner continuity or session separation mismatch",
    )?;
    require(
        !review.statement_checks.is_empty() && review.statement_checks.len() <= 256,
        "review statement checks missing or oversized",
    )?;
    for check in review.statement_checks {
        require(
            !check.location.trim().is_empty()
                && !check.summary.trim().is_empty()
                && check.location.len() <= 1024
                && check.summary.len() <= 8192,
            "review statement check empty or oversized",
        )?;
    }
    if let Some(bytes) = material.get(&Kind::ReviewedTex) {
        require(
            review.reviewed_sha256 == hash(bytes),
            "review observation refers to different proof bytes",
        )?;
    }
    if let Some(bytes) = material.get(&Kind::VerificationReport) {
        require(
            review.verification_report_sha256 == hash(bytes),
            "review observation refers to a different verification report",
        )?;
    }
    Ok(())
}

fn bounded_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
        })
}

fn string_set(value: &Value, key: &str, allow_empty: bool) -> Result<BTreeSet<String>> {
    let values = value[key]
        .as_array()
        .ok_or("expected bounded string array")?;
    require(values.len() <= 256, "string array exceeds bound")?;
    if !allow_empty {
        require(!values.is_empty(), "required string array is empty")?;
    }
    let mut result = BTreeSet::new();
    for value in values {
        let text = value.as_str().ok_or("string array member must be text")?;
        require(bounded_id(text), "string array member is invalid")?;
        require(
            result.insert(text.to_owned()),
            "duplicate string array member",
        )?;
    }
    Ok(result)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetrievalCall {
    method: String,
    reference_ids: Vec<String>,
    result_sha256: String,
    external_network_observed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetrievalObservation {
    schema: String,
    run_id: String,
    calls: Vec<RetrievalCall>,
    raw_credentials_recorded: bool,
    raw_response_bodies_recorded: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceInspection {
    reference_id: String,
    source_kind: String,
    locator_sha256: String,
    content_sha256: String,
    original_or_authoritative_source_inspected: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceObservation {
    schema: String,
    run_id: String,
    sources: Vec<SourceInspection>,
}

fn retrieval_route(bundle: &Bundle, manifest: &Value, material: &Material) -> Result<()> {
    let reference_ids = string_set(manifest, "reference_ids", false)?;
    let retrieval: RetrievalObservation = decode(
        material
            .get(&Kind::Retrieval)
            .ok_or("retrieval observation missing")?,
    )?;
    require(
        retrieval.schema == "mtm-research-retrieval-observation-v1"
            && retrieval.run_id == bundle.run_id
            && !retrieval.calls.is_empty()
            && retrieval.calls.len() <= 32
            && !retrieval.raw_credentials_recorded
            && !retrieval.raw_response_bodies_recorded,
        "retrieval observation identity or confidentiality scope invalid",
    )?;
    let mut retrieved = BTreeSet::new();
    for call in retrieval.calls {
        require(
            call.method == "rethlas_retrieve"
                && call.external_network_observed
                && hex(&call.result_sha256, 64)
                && !call.reference_ids.is_empty()
                && call.reference_ids.len() <= 64,
            "retrieval call does not prove a bounded external retrieval",
        )?;
        for reference_id in call.reference_ids {
            require(bounded_id(&reference_id), "retrieval reference id invalid")?;
            retrieved.insert(reference_id);
        }
    }
    require(
        reference_ids.is_subset(&retrieved),
        "proof references are not covered by retrieval observations",
    )?;

    let sources: SourceObservation = decode(
        material
            .get(&Kind::Sources)
            .ok_or("source inspection observation missing")?,
    )?;
    require(
        sources.schema == "mtm-research-source-observation-v1"
            && sources.run_id == bundle.run_id
            && !sources.sources.is_empty()
            && sources.sources.len() <= 64,
        "source inspection observation identity or count invalid",
    )?;
    let mut inspected = BTreeSet::new();
    for source in sources.sources {
        require(
            bounded_id(&source.reference_id)
                && matches!(source.source_kind.as_str(), "original" | "authoritative")
                && hex(&source.locator_sha256, 64)
                && hex(&source.content_sha256, 64)
                && source.original_or_authoritative_source_inspected,
            "source inspection does not identify checked original or authoritative material",
        )?;
        require(
            inspected.insert(source.reference_id),
            "duplicate source inspection reference",
        )?;
    }
    require(
        reference_ids.is_subset(&inspected),
        "proof references are not covered by original-source inspection",
    )?;

    let audit =
        object(material, Kind::ReferenceAudit)?.ok_or("reference audit artifact missing")?;
    let references = audit["references"]
        .as_array()
        .ok_or("reference audit references missing")?;
    let audits = audit["audits"]
        .as_array()
        .ok_or("reference audit rows missing")?;
    require(
        references.len() <= 256 && audits.len() <= 256,
        "reference audit exceeds bound",
    )?;
    let registered = references
        .iter()
        .filter_map(|reference| reference["reference_id"].as_str())
        .filter(|reference_id| bounded_id(reference_id))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    require(
        reference_ids.is_subset(&registered),
        "proof references are not present in the run reference registry",
    )?;
    let reviewed_hash = material.get(&Kind::ReviewedTex).map(|bytes| hash(bytes));
    for reference_id in reference_ids {
        let matching = audits
            .iter()
            .filter(|audit| audit["reference_id"].as_str() == Some(reference_id.as_str()))
            .collect::<Vec<_>>();
        require(
            matching.len() == 1,
            "material reference must have exactly one audit row",
        )?;
        let row = matching[0];
        require(
            row["disposition"] == "SOURCE_VERIFIED"
                && row["material"] == true
                && row["source_checked"] == true
                && row["assumptions_checked"] == true
                && row["notation_checked"] == true
                && matches!(
                    row["evidence_basis"].as_str(),
                    Some("stored_source_snapshot" | "external_source_inspection")
                )
                && row["evidence_locator"]
                    .as_str()
                    .is_some_and(|value| !value.trim().is_empty() && value.len() <= 2048),
            "material reference audit is unresolved or insufficiently checked",
        )?;
        if let Some(expected) = &reviewed_hash {
            require(
                row["proof_sha256"] == *expected,
                "reference audit is bound to different proof bytes",
            )?;
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BranchRow {
    branch_id: String,
    domain_id: String,
    session_marker: String,
    order_index: u64,
    status: String,
    result_sha256: String,
    sibling_private_read_denied: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinObservation {
    all_required_sealed_before_join: bool,
    considered_branch_ids: Vec<String>,
    result_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BranchObservation {
    schema: String,
    run_id: String,
    branches: Vec<BranchRow>,
    join: JoinObservation,
}

fn branch_route(bundle: &Bundle, material: &Material) -> Result<()> {
    let observation: BranchObservation = decode(
        material
            .get(&Kind::Branches)
            .ok_or("branch observation missing")?,
    )?;
    require(
        observation.schema == "mtm-research-branch-observation-v1"
            && observation.run_id == bundle.run_id
            && (2..=16).contains(&observation.branches.len())
            && observation.join.all_required_sealed_before_join
            && hex(&observation.join.result_sha256, 64),
        "branch observation identity, count or join state invalid",
    )?;
    let mut branches = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let mut sessions = BTreeSet::new();
    let mut orders = BTreeSet::new();
    for branch in observation.branches {
        require(
            bounded_id(&branch.branch_id)
                && bounded_id(&branch.domain_id)
                && marker(&branch.session_marker)
                && branch.status == "sealed"
                && branch.order_index < 16
                && hex(&branch.result_sha256, 64)
                && branch.sibling_private_read_denied,
            "branch row is not sealed, isolated or bounded",
        )?;
        require(
            branches.insert(branch.branch_id)
                && domains.insert(branch.domain_id)
                && sessions.insert(branch.session_marker)
                && orders.insert(branch.order_index),
            "branch ids, domains, sessions and order indexes must be distinct",
        )?;
    }
    let considered = observation
        .join
        .considered_branch_ids
        .into_iter()
        .collect::<BTreeSet<_>>();
    require(
        considered == branches,
        "join did not consider exactly all sealed branches",
    )?;
    let transitions =
        object(material, Kind::Transitions)?.ok_or("branch transition evidence missing")?;
    let states = transitions
        .as_array()
        .ok_or("branch transitions must be an array")?
        .iter()
        .filter_map(|row| row["after_state"].as_str())
        .collect::<Vec<_>>();
    let branch_prepare = states.iter().position(|state| *state == "branch_prepare");
    let branch_run = states.iter().position(|state| *state == "branch_run");
    let branch_join = states.iter().position(|state| *state == "branch_join");
    require(
        matches!(
            (branch_prepare, branch_run, branch_join),
            (Some(a), Some(b), Some(c)) if a < b && b < c
        ),
        "branch workflow did not reach prepare, run and join in order",
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CasToolObservation {
    name: String,
    version: String,
    input_sha256: String,
    output_sha256: String,
    exit_code: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CasObservation {
    schema: String,
    run_id: String,
    native_mode: String,
    general_proof_independent: bool,
    raw_credentials_recorded: bool,
    tools: Vec<CasToolObservation>,
}

fn cas_route(bundle: &Bundle, material: &Material) -> Result<()> {
    let observation: CasObservation = decode(
        material
            .get(&Kind::CasObservation)
            .ok_or("CAS observation missing")?,
    )?;
    require(
        observation.schema == "mtm-research-cas-observation-v2"
            && observation.run_id == bundle.run_id
            && observation.native_mode == "dangerous"
            && observation.general_proof_independent
            && !observation.raw_credentials_recorded
            && observation.tools.len() == 2,
        "CAS observation identity or scope invalid",
    )?;
    let mut names = BTreeSet::new();
    for tool in observation.tools {
        require(
            matches!(tool.name.as_str(), "sage" | "magma")
                && !tool.version.trim().is_empty()
                && tool.version.len() <= 256
                && hex(&tool.input_sha256, 64)
                && hex(&tool.output_sha256, 64)
                && tool.exit_code == 0,
            "CAS tool execution observation invalid",
        )?;
        require(
            names.insert(tool.name.clone()),
            "duplicate CAS tool observation",
        )?;
        let (input, output) = match tool.name.as_str() {
            "sage" => (Kind::SageInput, Kind::SageOutput),
            "magma" => (Kind::MagmaInput, Kind::MagmaOutput),
            _ => return Err("unsupported CAS tool observation".into()),
        };
        matches_file(
            &serde_json::json!({"digest":tool.input_sha256}),
            "digest",
            material,
            input,
        )?;
        matches_file(
            &serde_json::json!({"digest":tool.output_sha256}),
            "digest",
            material,
            output,
        )?;
    }
    require(
        names == BTreeSet::from(["magma".to_owned(), "sage".to_owned()]),
        "both Sage and Magma observations are required",
    )
}

pub(super) fn validate(
    bundle: &Bundle,
    case: &Case,
    material: &Material,
    identity: ResearchIdentity,
) -> Result<()> {
    if let Some(value) = object(material, Kind::Session)? {
        session(&value, bundle, case, identity)?;
    }
    let status_value = object(material, Kind::Status)?;
    if let Some(value) = &status_value {
        status(value, bundle, case)?;
    }
    if let Some(value) = object(material, Kind::Transitions)? {
        transitions(&value, bundle, status_value.as_ref())?;
    }
    if let Some(value) = object(material, Kind::VerificationReport)? {
        findings(&value, true)?;
    }
    if let Some(value) = object(material, Kind::FirstFindings)? {
        findings(&value, false)?;
    }
    if let Some(value) = object(material, Kind::ProofManifest)? {
        require(
            nonempty(&value["target_statement_tex"]),
            "proof manifest target missing",
        )?;
        for key in [
            "reference_ids",
            "dependency_revision_ids",
            "conditional_hypotheses",
            "computational_evidence",
        ] {
            require(value[key].is_array(), "proof manifest array missing")?;
        }
        require(
            value["conditional_hypotheses"]
                .as_array()
                .is_some_and(Vec::is_empty),
            "conditional proof cannot complete unconditional trial",
        )?;
        if bundle.task_id == "U22" {
            require(
                value["reference_ids"]
                    .as_array()
                    .is_some_and(|ids| !ids.is_empty()),
                "retrieval trial has no material reference",
            )?;
            if [Kind::Retrieval, Kind::ReferenceAudit, Kind::Sources]
                .iter()
                .all(|kind| material.contains_key(kind))
            {
                retrieval_route(bundle, &value, material)?;
            }
        }
        if bundle.task_id == "U25" {
            require(
                value["computational_evidence"]
                    .as_array()
                    .is_some_and(|items| items.len() >= 2 && items.len() <= 64),
                "CAS trial must retain computational evidence separately from the proof",
            )?;
        }
    }
    if let Some(value) = object(material, Kind::Compiler)? {
        require(
            value["schema"] == "mtm-research-compiler-observation-v1"
                && value["run_id"] == bundle.run_id
                && value["policy"] == "required"
                && value["exit_code"] == 0
                && matches!(value["program"].as_str(), Some("latexmk" | "pdflatex")),
            "required compiler observation missing or unsuccessful",
        )?;
        matches_file(&value, "source_sha256", material, Kind::FinalTex)?;
        matches_file(&value, "output_sha256", material, Kind::CompilerOutput)?;
    }
    if let (Some(final_tex), Some(reviewed_tex)) = (
        material.get(&Kind::FinalTex),
        material.get(&Kind::ReviewedTex),
    ) {
        require(
            final_tex == reviewed_tex,
            "final proof differs from the reviewed bytes",
        )?;
    }
    if let Some(bytes) = material.get(&Kind::Review) {
        review(bytes, bundle, material)?;
    }
    if let Some(value) = object(material, Kind::RepairHistory)? {
        require(
            value["seeded_challenge"] == true && value["run_id"] == bundle.run_id,
            "repair provenance is not a declared seeded challenge",
        )?;
        matches_file(&value, "initial_draft_sha256", material, Kind::SeededDraft)?;
        matches_file(
            &value,
            "first_findings_sha256",
            material,
            Kind::FirstFindings,
        )?;
        matches_file(&value, "final_sha256", material, Kind::FinalTex)?;
    }
    if let (Some(seed), Some(final_tex)) = (
        material.get(&Kind::SeededDraft),
        material.get(&Kind::FinalTex),
    ) {
        require(seed != final_tex, "seeded draft was not repaired")?;
    }
    if bundle.task_id == "U24"
        && [Kind::Branches, Kind::Transitions]
            .iter()
            .all(|kind| material.contains_key(kind))
    {
        branch_route(bundle, material)?;
    }
    if bundle.task_id == "U25"
        && [
            Kind::SageInput,
            Kind::SageOutput,
            Kind::MagmaInput,
            Kind::MagmaOutput,
            Kind::CasObservation,
        ]
        .iter()
        .all(|kind| material.contains_key(kind))
    {
        cas_route(bundle, material)?;
    }
    // These checks bind route facts to each other but do not authenticate who
    // created the observations or independently determine mathematical truth.
    // The precheck never interprets arbitrary provider text or executes a command.
    Ok(())
}
