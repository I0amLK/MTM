//! MTM-017-only read-only research import proposal. Never grants acceptance.
use crate::{Result, capability, evidence_json, qualify, research_precheck};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
mod files;
#[cfg(test)]
mod tests;

#[cfg(test)]
const DRIVER: &str = "records/governance/mtm016-release-inputs.json";
const DRIVER_SHA: &str = "e55f2c5624e6f94f4805bed38dd968626808f7df00d95bff9168cf86eb8cda04";
const REVIEW_CHECKS: [&str; 6] = [
    "implementation_and_negative_tests_reviewed",
    "all_fifteen_original_bundles_inspected",
    "receipt_and_exact_artifact_bindings_checked",
    "route_observations_and_review_provenance_inspected",
    "no_historical_base_or_release_authority_inherited",
    "proposal_only_zero_accepted_delta",
];
pub(crate) struct Options {
    inputs: String,
    catalog: PathBuf,
    review: String,
}
impl Options {
    pub(crate) fn parse(args: &[String]) -> Result<Self> {
        if args.len() != 6
            || args[0] != "--inputs"
            || args[2] != "--bundle-catalog"
            || args[4] != "--input-review"
            || !Path::new(&args[3]).is_absolute()
        {
            return Err("use research-import-check --inputs <repo-relative-json> --bundle-catalog <absolute-private-json> --input-review <repo-relative-json> only".into());
        }
        Ok(Self {
            inputs: args[1].clone(),
            catalog: PathBuf::from(&args[3]),
            review: args[5].clone(),
        })
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    path: String,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrialRef {
    task_id: String,
    repeat: u64,
    receipt: Reference,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    schema: String,
    milestone: String,
    state_schema_version: u64,
    candidate_sha256: String,
    candidate_source_commit: String,
    corpus_sha256: String,
    case_registry_sha256: String,
    prepared_by: String,
    bundle_catalog_sha256: String,
    audit: Reference,
    prechecks: Reference,
    trials: Vec<TrialRef>,
    corpus_count_incremented: bool,
    production_selector_changed: bool,
    production_state_modified: bool,
    release_qualified: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    schema: String,
    milestone: String,
    trials: Vec<BundleRef>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleRef {
    task_id: String,
    repeat: u64,
    bundle: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputReview {
    schema: String,
    milestone: String,
    inputs_sha256: String,
    bundle_catalog_sha256: String,
    implementation_source_sha256: String,
    maintenance_binary_sha256: String,
    prepared_by: String,
    reviewer_session: String,
    decision: String,
    checks: Vec<String>,
    recorded_unix_seconds: u64,
    corpus_count_incremented: bool,
    production_selector_changed: bool,
    production_state_modified: bool,
    release_qualified: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Trial {
    schema: String,
    milestone: String,
    task_id: String,
    scenario: String,
    repeat: u64,
    case_id: String,
    trial_id: String,
    candidate_sha256: String,
    candidate_source_commit: String,
    corpus_sha256: String,
    case_registry_sha256: String,
    bundle_sha256: String,
    final_tex_sha256: String,
    verification_report_sha256: String,
    review_observation_sha256: String,
    owner_fingerprint: String,
    generator_session: String,
    reviewer_session: String,
    required_latex_passed: bool,
    final_artifact_sealed: bool,
    same_live_connection_observed: bool,
    independent_review_observed: bool,
    reviewer_statement_checks: u64,
    route_checks: Vec<String>,
    precheck_passed: bool,
    mathematical_review_passed: bool,
    raw_private_state_recorded: bool,
    production_changed: bool,
    release_qualified: bool,
    recorded_unix_seconds: u64,
}
fn require(ok: bool, message: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn marker(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_value(evidence_json::decode(bytes)?)
        .map_err(|_| "import closed schema invalid".into())
}
fn identity(candidate: &str, source: &str, corpus: &str, registry: &str) -> bool {
    candidate == research_precheck::MTM017_CANDIDATE_SHA
        && source == research_precheck::MTM017_CANDIDATE_SOURCE
        && corpus == research_precheck::CORPUS_SHA
        && registry == research_precheck::REGISTRY_SHA
}
fn cell(task: &str, repeat: u64) -> bool {
    matches!(task, "U21" | "U22" | "U23" | "U24" | "U25") && (1..=3).contains(&repeat)
}
fn expected_case(task: &str, repeat: u64) -> Result<&'static str> {
    let repetition = repeat.to_string();
    for line in include_str!("../../../conformance/mtm016-research-cases.tsv")
        .lines()
        .skip(1)
    {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() == 6 && fields[0] == task && fields[1] == repetition {
            return Ok(fields[2]);
        }
    }
    Err("import cell absent from frozen registry".into())
}
fn scenario(task: &str) -> Result<&'static str> {
    match task {
        "U21" => Ok("compact_compiled_proof"),
        "U22" => Ok("full_retrieval_proof"),
        "U23" => Ok("repair_compiled_proof"),
        "U24" => Ok("branch_join_sealing"),
        "U25" => Ok("cas_crosscheck"),
        _ => Err("import task invalid".into()),
    }
}
fn route(task: &str) -> Result<Vec<&'static str>> {
    let mut result = vec![
        "owner_continuity",
        "separate_reviewer_session",
        "required_latex",
        "reviewed_exact_final_bytes",
        "substantive_statement_checks",
    ];
    result.extend(match task {
        "U21" => vec![],
        "U22" => vec![
            "retrieval_used",
            "original_or_authoritative_sources_checked",
            "reference_audits_bound",
        ],
        "U23" => vec![
            "seeded_gap_preserved",
            "specific_gap_found",
            "repair_recompiled",
            "repair_reverified",
        ],
        "U24" => vec![
            "two_or_more_branches",
            "branch_domains_distinct",
            "sibling_private_read_denied",
            "all_branches_sealed_before_join",
        ],
        "U25" => vec![
            "sage_executed",
            "magma_executed",
            "dangerous_native_observed",
            "cas_bound_to_inputs_outputs",
            "general_proof_independent",
        ],
        _ => return Err("import route invalid".into()),
    });
    Ok(result)
}
fn inputs_shape(input: &Inputs) -> Result<()> {
    require(
        input.schema == "mtm017-research-import-inputs-v1"
            && input.milestone == "MTM-017"
            && input.state_schema_version == 8
            && identity(
                &input.candidate_sha256,
                &input.candidate_source_commit,
                &input.corpus_sha256,
                &input.case_registry_sha256,
            )
            && marker(&input.prepared_by)
            && hex(&input.bundle_catalog_sha256, 64)
            && input.trials.len() == 15
            && !input.corpus_count_incremented
            && !input.production_selector_changed
            && !input.production_state_modified
            && !input.release_qualified,
        "MTM-017 import identity, scope or flags invalid",
    )?;
    let mut cells = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    for trial in &input.trials {
        require(
            cell(&trial.task_id, trial.repeat)
                && cells.insert((&trial.task_id, trial.repeat))
                && paths.insert(&trial.receipt.path)
                && hex(&trial.receipt.sha256, 64)
                && hashes.insert(&trial.receipt.sha256),
            "import cells or receipt references duplicate or invalid",
        )?;
    }
    Ok(())
}
fn review_shape(
    review: &InputReview,
    input: &Inputs,
    input_sha: &str,
    source: &str,
    binary: &str,
) -> Result<()> {
    require(
        review.schema == "mtm017-research-import-input-review-v1"
            && review.milestone == "MTM-017"
            && review.inputs_sha256 == input_sha
            && review.bundle_catalog_sha256 == input.bundle_catalog_sha256
            && hex(source, 64)
            && hex(binary, 64)
            && review.implementation_source_sha256 == source
            && review.maintenance_binary_sha256 == binary
            && review.prepared_by == input.prepared_by
            && marker(&review.reviewer_session)
            && review.reviewer_session != review.prepared_by
            && review.decision == "approved_for_read_only_proposal"
            && review.checks.iter().map(String::as_str).collect::<Vec<_>>() == REVIEW_CHECKS
            && review.recorded_unix_seconds > 0
            && !review.corpus_count_incremented
            && !review.production_selector_changed
            && !review.production_state_modified
            && !review.release_qualified,
        "separate input review does not bind this input and implementation",
    )
}
fn trial_shape(trial: &Trial, task: &str, repeat: u64) -> Result<()> {
    let policy = research_precheck::research_policy_for("MTM-017", task)?;
    require(
        trial.schema == policy.trial_schema
            && trial.milestone == "MTM-017"
            && trial.task_id == task
            && trial.repeat == repeat
            && trial.case_id == expected_case(task, repeat)?
            && trial.scenario == scenario(task)?
            && identity(
                &trial.candidate_sha256,
                &trial.candidate_source_commit,
                &trial.corpus_sha256,
                &trial.case_registry_sha256,
            )
            && hex(&trial.trial_id, 32)
            && hex(&trial.bundle_sha256, 64)
            && hex(&trial.final_tex_sha256, 64)
            && hex(&trial.verification_report_sha256, 64)
            && hex(&trial.review_observation_sha256, 64)
            && hex(&trial.owner_fingerprint, 64)
            && marker(&trial.generator_session)
            && marker(&trial.reviewer_session)
            && trial.generator_session != trial.reviewer_session
            && trial.required_latex_passed
            && trial.final_artifact_sealed
            && trial.same_live_connection_observed
            && trial.independent_review_observed
            && (1..=256).contains(&trial.reviewer_statement_checks)
            && trial
                .route_checks
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                == route(task)?
            && trial.precheck_passed
            && trial.mathematical_review_passed
            && !trial.raw_private_state_recorded
            && !trial.production_changed
            && !trial.release_qualified
            && trial.recorded_unix_seconds > 0,
        "MTM-017 trial identity, review, route or flags invalid",
    )
}
fn checked(root: &Path, reference: &Reference) -> Result<Vec<u8>> {
    require(
        hex(&reference.sha256, 64),
        "import reference digest invalid",
    )?;
    let bytes = files::repo(root, &reference.path)?;
    require(
        digest(&bytes) == reference.sha256,
        "import referenced bytes changed",
    )?;
    Ok(bytes)
}
fn bundle_path(path: &Path, trial: &Trial) -> Result<()> {
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or("bundle selector invalid")?;
    let parent = path.parent().ok_or("bundle parent invalid")?;
    let session = parent
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or("session selector invalid")?;
    let prefix = format!("{}-r{}.", trial.task_id, trial.repeat);
    let suffix = session
        .strip_prefix(&prefix)
        .ok_or("bundle cell directory mismatch")?;
    let base = parent.parent().ok_or("bundle acceptance parent missing")?;
    require(
        name == format!("evidence-bundle.{}", trial.trial_id)
            && suffix.len() == 8
            && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
            && base.ends_with(".mtm-acceptance/MTM-017/research"),
        "bundle selector outside explicit trial",
    )
}
fn artifact_hash<'a>(report: &'a Value, name: &str) -> Result<&'a str> {
    report["artifacts"]
        .as_array()
        .and_then(|a| a.iter().find(|v| v["artifact"] == name))
        .and_then(|v| v["sha256"].as_str())
        .ok_or_else(|| "precheck artifact binding missing".into())
}
fn cross_bind(
    trial: &Trial,
    report: &Value,
    bundle: &Value,
    session: &Value,
    review: &Value,
) -> Result<()> {
    require(
        report["milestone"] == "MTM-017"
            && report["task_id"] == trial.task_id
            && report["repeat"] == trial.repeat
            && report["case_id"] == trial.case_id
            && report["bundle_sha256"] == trial.bundle_sha256
            && report["required_material_present"] == true
            && report["existing_material_consistent"] == true
            && report["accepted_trials_delta"] == 0
            && report["research_trial_passed"] == false
            && report["production_state_modified"] == false
            && report["release_qualified"] == false
            && bundle["trial_id"] == trial.trial_id
            && session["trial_id"] == trial.trial_id
            && session["task_id"] == trial.task_id
            && session["repeat"] == trial.repeat
            && session["case_id"] == trial.case_id
            && session["milestone"] == "MTM-017"
            && session["native_mode"] == "dangerous"
            && session["schema"] == "mtm-research-session-v2"
            && review["trial_id"] == trial.trial_id
            && review["generator_session"] == trial.generator_session
            && review["reviewer_session"] == trial.reviewer_session
            && review["generator_owner_fingerprint"] == trial.owner_fingerprint
            && review["reviewer_owner_fingerprint"] == trial.owner_fingerprint
            && review["reviewed_sha256"] == trial.final_tex_sha256
            && review["verification_report_sha256"] == trial.verification_report_sha256
            && review["reviewed_before_finalization"] == true
            && review["statement_checks"]
                .as_array()
                .is_some_and(|a| a.len() as u64 == trial.reviewer_statement_checks)
            && artifact_hash(report, "final.tex")? == trial.final_tex_sha256
            && artifact_hash(report, "reviewed.tex")? == trial.final_tex_sha256
            && artifact_hash(report, "verification_report.json")?
                == trial.verification_report_sha256
            && artifact_hash(report, "review.json")? == trial.review_observation_sha256,
        "receipt does not bind exact private bundle and independent review observations",
    )
}
fn observed_bytes(
    session: &[u8],
    review: &[u8],
    before: &[u8],
    after: &[u8],
    report: &Value,
) -> Result<()> {
    require(
        digest(session) == artifact_hash(report, "session.json")?
            && digest(review) == artifact_hash(report, "review.json")?
            && before == after,
        "bundle changed across private inspection",
    )
}

fn trial_uniqueness(unique: &mut BTreeSet<(&'static str, String)>, trial: &Trial) -> Result<()> {
    for (kind, value) in [
        ("case", trial.case_id.clone()),
        ("trial", trial.trial_id.clone()),
        ("bundle", trial.bundle_sha256.clone()),
        ("final", trial.final_tex_sha256.clone()),
        ("verification", trial.verification_report_sha256.clone()),
        ("review", trial.review_observation_sha256.clone()),
        ("recorded", trial.recorded_unix_seconds.to_string()),
    ] {
        require(
            unique.insert((kind, value)),
            "trial identities, bytes or recording times duplicate",
        )?;
    }
    Ok(())
}

fn inspect(root: &Path, path: &Path, trial: &Trial) -> Result<Value> {
    bundle_path(path, trial)?;
    let directory = files::Directory::open(path, true)?;
    let bundle = directory.read("bundle.json", 1048576)?;
    require(
        digest(&bundle) == trial.bundle_sha256,
        "private bundle manifest changed",
    )?;
    let session = directory.read("session.json", 1048576)?;
    let review = directory.read("review.json", 1048576)?;
    let report = research_precheck::validate_bundle(root, path)?;
    observed_bytes(
        &session,
        &review,
        &bundle,
        &directory.read("bundle.json", 1048576)?,
        &report,
    )?;
    cross_bind(
        trial,
        &report,
        &evidence_json::decode(&bundle)?,
        &evidence_json::decode(&session)?,
        &evidence_json::decode(&review)?,
    )?;
    Ok(report)
}
fn frozen_driver_digest(root: &Path) -> Result<String> {
    Ok(digest(&files::frozen_driver(root)?))
}

pub(crate) fn run(root: &Path, options: &Options) -> Result<Value> {
    let source = capability::source_hash(root)?;
    let binary = qualify::digest(&std::env::current_exe()?)?;
    require(
        frozen_driver_digest(root)? == DRIVER_SHA,
        "frozen MTM-016 driver changed",
    )?;
    let input_bytes = files::repo(root, &options.inputs)?;
    let input: Inputs = decode(&input_bytes)?;
    inputs_shape(&input)?;
    checked(root, &input.audit)?;
    checked(root, &input.prechecks)?;
    let review_bytes = files::repo(root, &options.review)?;
    let review: InputReview = decode(&review_bytes)?;
    review_shape(&review, &input, &digest(&input_bytes), &source, &binary)?;
    let catalog_bytes = files::catalog(&options.catalog)?;
    require(
        digest(&catalog_bytes) == input.bundle_catalog_sha256,
        "private catalog bytes changed",
    )?;
    let catalog: Catalog = decode(&catalog_bytes)?;
    require(
        catalog.schema == "mtm017-research-bundle-catalog-v1"
            && catalog.milestone == "MTM-017"
            && catalog.trials.len() == 15,
        "private catalog scope invalid",
    )?;
    let mut bundle_map = BTreeMap::new();
    let mut bundle_paths = BTreeSet::new();
    for entry in &catalog.trials {
        require(
            cell(&entry.task_id, entry.repeat)
                && bundle_paths.insert(&entry.bundle)
                && bundle_map
                    .insert((entry.task_id.as_str(), entry.repeat), &entry.bundle)
                    .is_none(),
            "private catalog cells or paths duplicate",
        )?;
    }
    let mut unique = BTreeSet::new();
    let mut rows = Vec::new();
    for reference in &input.trials {
        let bytes = checked(root, &reference.receipt)?;
        let trial: Trial = decode(&bytes)?;
        trial_shape(&trial, &reference.task_id, reference.repeat)?;
        trial_uniqueness(&mut unique, &trial)?;
        let path = bundle_map
            .get(&(reference.task_id.as_str(), reference.repeat))
            .ok_or("private catalog missing trial cell")?;
        let report = inspect(root, path, &trial)?;
        rows.push(json!({"task_id":trial.task_id,"repeat":trial.repeat,"case_id":trial.case_id,
            "trial_id":trial.trial_id,"receipt":reference.receipt,"bundle_sha256":trial.bundle_sha256,
            "final_tex_sha256":trial.final_tex_sha256,"verification_report_sha256":trial.verification_report_sha256,
            "review_observation_sha256":trial.review_observation_sha256,"artifact_count":report["artifact_count"],
            "reviewer_statement_checks":trial.reviewer_statement_checks,"eligible_for_result_review":true}));
    }
    require(
        files::repo(root, &options.inputs)? == input_bytes
            && files::repo(root, &options.review)? == review_bytes
            && files::catalog(&options.catalog)? == catalog_bytes
            && capability::source_hash(root)? == source
            && frozen_driver_digest(root)? == DRIVER_SHA,
        "import inputs or source changed during proposal",
    )?;
    checked(root, &input.audit)?;
    checked(root, &input.prechecks)?;
    for reference in &input.trials {
        checked(root, &reference.receipt)?;
    }
    rows.sort_by_key(|v| {
        (
            v["task_id"].as_str().map(str::to_owned),
            v["repeat"].as_u64(),
        )
    });
    Ok(
        json!({"schema":"mtm017-research-import-proposal-v1","milestone":"MTM-017","state_schema_version":8,
        "scope":"U21-U25_fifteen_trial_research_subset_only","inputs_sha256":digest(&input_bytes),
        "input_review_sha256":digest(&review_bytes),"bundle_catalog_sha256":digest(&catalog_bytes),
        "implementation_source_sha256":source,"maintenance_binary_sha256":binary,
        "candidate_sha256":input.candidate_sha256,"candidate_source_commit":input.candidate_source_commit,
        "corpus_sha256":input.corpus_sha256,"case_registry_sha256":input.case_registry_sha256,
        "audit":input.audit,"prechecks":input.prechecks,"trials":rows,"eligible_trials":15,
        "accepted_trials_delta":0,"corpus_count_incremented":false,"result_review_required":true,
        "implementation_complete":"unknown","implementation_scope":"whole_project_requires_separate_evidence",
        "research_accepted":false,"deployment_authorized":false,
        "input_review_cryptographically_authenticated":false,"historical_counts_inherited":false,
        "production_selector_changed":false,"production_state_modified":false,"release_qualified":false,
        "frozen_driver_sha256":DRIVER_SHA,
        "limitations":["Procedural review records and hashes do not authenticate a reviewer or re-prove mathematics.",
            "This command writes no file and grants no corpus count or deployment authority.",
            "A separate result review and explicit governance acceptance are still required."]}),
    )
}
