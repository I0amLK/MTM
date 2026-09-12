//! Closed U21-U25 aggregation. Research receipts are reviewed evidence, not proof certificates.
use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::*;

const CORPUS: &str = include_str!("../../conformance/mtm016-usability-corpus.json");
const CASES: &str = include_str!("../../conformance/mtm016-research-cases.tsv");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchRef {
    profile: String,
    path: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Aggregate {
    schema: String,
    milestone: String,
    candidate_sha256: String,
    candidate_source_commit: String,
    corpus_sha256: String,
    base: CorpusAggregateRef,
    batches: Vec<BatchRef>,
    passed_trials: u64,
    failed_trials: u64,
    blocked_trials: u64,
    complete: bool,
    production_changed: bool,
    release_qualified: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrialRef {
    task_id: String,
    repeat: u64,
    path: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResearchBatch {
    schema: String,
    milestone: String,
    candidate_sha256: String,
    candidate_source_commit: String,
    corpus_sha256: String,
    case_registry_sha256: String,
    trials: Vec<TrialRef>,
    tasks: u64,
    repeats: u64,
    passed_trials: u64,
    failed_trials: u64,
    complete_for_research_scope: bool,
    production_changed: bool,
    release_qualified: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrialEvidence {
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

fn corpus_sha() -> String {
    format!("{:x}", Sha256::digest(CORPUS.as_bytes()))
}

fn cases_sha() -> String {
    format!("{:x}", Sha256::digest(CASES.as_bytes()))
}

fn expected_case(task: &str, repeat: u64) -> Result<String> {
    let repeat = repeat.to_string();
    for line in CASES.lines().skip(1) {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() == 6 && fields[0] == task && fields[1] == repeat {
            return Ok(fields[2].to_owned());
        }
    }
    Err("research corpus cell is absent from the frozen case registry".into())
}

fn scenario(task: &str) -> Result<&'static str> {
    match task {
        "U21" => Ok("compact_compiled_proof"),
        "U22" => Ok("full_retrieval_proof"),
        "U23" => Ok("repair_compiled_proof"),
        "U24" => Ok("branch_join_sealing"),
        "U25" => Ok("cas_crosscheck"),
        _ => Err("unsupported research corpus task".into()),
    }
}

fn common_checks() -> [&'static str; 5] {
    [
        "owner_continuity",
        "separate_reviewer_session",
        "required_latex",
        "reviewed_exact_final_bytes",
        "substantive_statement_checks",
    ]
}

fn expected_route_checks(task: &str) -> Result<Vec<&'static str>> {
    let mut checks = common_checks().to_vec();
    let extra: &[&str] = match task {
        "U21" => &[],
        "U22" => &[
            "retrieval_used",
            "original_or_authoritative_sources_checked",
            "reference_audits_bound",
        ],
        "U23" => &[
            "seeded_gap_preserved",
            "specific_gap_found",
            "repair_recompiled",
            "repair_reverified",
        ],
        "U24" => &[
            "two_or_more_branches",
            "branch_domains_distinct",
            "sibling_private_read_denied",
            "all_branches_sealed_before_join",
        ],
        "U25" => &[
            "sage_executed",
            "magma_executed",
            "safe_mode_permission_observed",
            "cas_bound_to_inputs_outputs",
            "general_proof_independent",
        ],
        _ => return Err("unsupported research corpus task".into()),
    };
    checks.extend(extra);
    Ok(checks)
}

fn marker(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn trial(value: &Value, manifest: &Manifest, task: &str, repeat: u64) -> Result<u64> {
    let evidence: TrialEvidence = serde_json::from_value(value.clone())
        .map_err(|_| "research trial evidence schema invalid")?;
    let expected_checks = expected_route_checks(task)?;
    if evidence.schema != "mtm-research-trial-evidence-v1"
        || evidence.milestone != "MTM-016"
        || evidence.task_id != task
        || evidence.scenario != scenario(task)?
        || evidence.repeat != repeat
        || evidence.case_id != expected_case(task, repeat)?
        || !identity_matches(
            &evidence.candidate_sha256,
            &evidence.candidate_source_commit,
            manifest,
        )
        || evidence.corpus_sha256 != corpus_sha()
        || evidence.case_registry_sha256 != cases_sha()
        || !hash(&evidence.trial_id, 32)
        || !hash(&evidence.bundle_sha256, 64)
        || !hash(&evidence.final_tex_sha256, 64)
        || !hash(&evidence.verification_report_sha256, 64)
        || !hash(&evidence.review_observation_sha256, 64)
        || !hash(&evidence.owner_fingerprint, 64)
        || !marker(&evidence.generator_session)
        || !marker(&evidence.reviewer_session)
        || evidence.generator_session == evidence.reviewer_session
        || !evidence.required_latex_passed
        || !evidence.final_artifact_sealed
        || !evidence.same_live_connection_observed
        || !evidence.independent_review_observed
        || evidence.reviewer_statement_checks == 0
        || evidence.reviewer_statement_checks > 256
        || evidence
            .route_checks
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != expected_checks
        || !evidence.precheck_passed
        || !evidence.mathematical_review_passed
        || evidence.raw_private_state_recorded
        || evidence.production_changed
        || evidence.release_qualified
        || evidence.recorded_unix_seconds == 0
    {
        return Err("research trial identity, review or route evidence invalid".into());
    }
    Ok(evidence.recorded_unix_seconds)
}

fn batch(root: &Path, value: &Value, manifest: &Manifest) -> Result<()> {
    let batch: ResearchBatch = serde_json::from_value(value.clone())
        .map_err(|_| "research corpus batch schema invalid")?;
    if batch.schema != "mtm-research-corpus-batch-v1"
        || batch.milestone != "MTM-016"
        || !identity_matches(
            &batch.candidate_sha256,
            &batch.candidate_source_commit,
            manifest,
        )
        || batch.corpus_sha256 != corpus_sha()
        || batch.case_registry_sha256 != cases_sha()
        || batch.tasks != 5
        || batch.repeats != 3
        || batch.trials.len() != 15
        || batch.passed_trials != 15
        || batch.failed_trials != 0
        || !batch.complete_for_research_scope
        || batch.production_changed
        || batch.release_qualified
    {
        return Err("research corpus batch identity, counts or scope invalid".into());
    }
    let mut cells = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    let mut trial_ids = BTreeSet::new();
    let mut recorded_times = BTreeSet::new();
    for reference in &batch.trials {
        if !(matches!(
            reference.task_id.as_str(),
            "U21" | "U22" | "U23" | "U24" | "U25"
        ) && (1..=3).contains(&reference.repeat)
            && cells.insert((reference.task_id.clone(), reference.repeat))
            && paths.insert(reference.path.clone())
            && hashes.insert(reference.sha256.clone()))
        {
            return Err("research trial references are duplicate or outside U21-U25".into());
        }
        let value = checked_evidence(root, &reference.path, &reference.sha256)?;
        let recorded = trial(&value, manifest, &reference.task_id, reference.repeat)?;
        let trial_id = value["trial_id"]
            .as_str()
            .ok_or("research trial id missing after validation")?;
        if !trial_ids.insert(trial_id.to_owned()) || !recorded_times.insert(recorded) {
            return Err(
                "research trial identities or observation timestamps are not independent".into(),
            );
        }
    }
    for task in ["U21", "U22", "U23", "U24", "U25"] {
        for repeat in 1..=3 {
            if !cells.contains(&(task.to_owned(), repeat)) {
                return Err("research corpus batch is missing a fixed task/repeat cell".into());
            }
        }
    }
    Ok(())
}

fn shape(value: &Value, manifest: &Manifest) -> Result<Aggregate> {
    let aggregate: Aggregate = serde_json::from_value(value.clone())
        .map_err(|_| "research corpus aggregate schema invalid")?;
    if aggregate.schema != "mtm-usability-corpus-aggregate-v3"
        || aggregate.milestone != "MTM-016"
        || !identity_matches(
            &aggregate.candidate_sha256,
            &aggregate.candidate_source_commit,
            manifest,
        )
        || aggregate.corpus_sha256 != corpus_sha()
        || aggregate.batches.len() != 1
        || aggregate.batches[0].profile != "corpus_research"
        || aggregate.base.path == aggregate.batches[0].path
        || aggregate.base.sha256 == aggregate.batches[0].sha256
        || aggregate.passed_trials != 78
        || aggregate.failed_trials != 0
        || aggregate.blocked_trials != 12
        || aggregate.complete
        || aggregate.production_changed
        || aggregate.release_qualified
    {
        return Err("research corpus aggregate identity, counts or scope invalid".into());
    }
    Ok(aggregate)
}

pub(super) fn validate(
    root: &Path,
    value: &Value,
    manifest: &Manifest,
    cache: &mut BTreeMap<String, String>,
) -> Result<bool> {
    let aggregate = shape(value, manifest)?;
    let base = checked_evidence(root, &aggregate.base.path, &aggregate.base.sha256)?;
    if base["schema"] != "mtm-usability-corpus-aggregate-v2"
        || base["passed_trials"] != 63
        || base["failed_trials"] != 0
        || base["blocked_trials"] != 27
        || base["complete"] != false
        || base["corpus_sha256"] != aggregate.corpus_sha256
        || native_corpus_aggregate::validate(root, &base, manifest, cache)?
    {
        return Err("research corpus aggregate requires the exact validated 63/27 base".into());
    }
    let selected = &aggregate.batches[0];
    let research = checked_evidence(root, &selected.path, &selected.sha256)?;
    batch(root, &research, manifest)?;
    // U26-U29 remain absent. Research acceptance cannot authorize the final corpus gate.
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use tempfile::tempdir;

    fn manifest() -> Manifest {
        Manifest {
            schema: "mtm-release-inputs-v1".into(),
            milestone: "MTM-016".into(),
            candidate_sha256: "a".repeat(64),
            candidate_source_commit: "b".repeat(40),
            baseline_sha256: "c".repeat(64),
            evidence: BTreeMap::new(),
        }
    }

    fn trial_fixture(task: &str, repeat: u64) -> Result<Value> {
        Ok(json!({
            "schema":"mtm-research-trial-evidence-v1","milestone":"MTM-016",
            "task_id":task,"scenario":scenario(task)?,"repeat":repeat,"case_id":expected_case(task,repeat)?,
            "trial_id":format!("{:032x}",(task.as_bytes()[2]-b'0') as u64*10+repeat),
            "candidate_sha256":"a".repeat(64),"candidate_source_commit":"b".repeat(40),
            "corpus_sha256":corpus_sha(),"case_registry_sha256":cases_sha(),
            "bundle_sha256":"d".repeat(64),"final_tex_sha256":"e".repeat(64),
            "verification_report_sha256":"f".repeat(64),"review_observation_sha256":"1".repeat(64),
            "owner_fingerprint":"2".repeat(64),"generator_session":"generator-session",
            "reviewer_session":"reviewer-session","required_latex_passed":true,"final_artifact_sealed":true,
            "same_live_connection_observed":true,"independent_review_observed":true,
            "reviewer_statement_checks":2,"route_checks":expected_route_checks(task)?,
            "precheck_passed":true,"mathematical_review_passed":true,"raw_private_state_recorded":false,
            "production_changed":false,"release_qualified":false,"recorded_unix_seconds":1700000000+repeat+(task.as_bytes()[2] as u64)*10
        }))
    }

    #[test]
    fn trial_requires_every_review_route_and_identity_fact() -> Result<()> {
        let manifest = manifest();
        for task in ["U21", "U22", "U23", "U24", "U25"] {
            let good = trial_fixture(task, 1)?;
            trial(&good, &manifest, task, 1)?;
            for (pointer, replacement) in [
                ("/required_latex_passed", json!(false)),
                ("/same_live_connection_observed", json!(false)),
                ("/independent_review_observed", json!(false)),
                ("/mathematical_review_passed", json!(false)),
                ("/precheck_passed", json!(false)),
                ("/raw_private_state_recorded", json!(true)),
                ("/reviewer_session", json!("generator-session")),
                ("/route_checks", json!([])),
                ("/case_id", json!("wrong-case")),
                ("/candidate_sha256", json!("9".repeat(64))),
            ] {
                let mut bad = good.clone();
                *bad.pointer_mut(pointer).ok_or("trial fixture pointer")? = replacement;
                assert!(
                    trial(&bad, &manifest, task, 1).is_err(),
                    "mutated {pointer}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn aggregate_is_exactly_78_12_and_never_a_complete_gate() -> Result<()> {
        let manifest = manifest();
        let good = json!({
            "schema":"mtm-usability-corpus-aggregate-v3","milestone":"MTM-016",
            "candidate_sha256":manifest.candidate_sha256,"candidate_source_commit":manifest.candidate_source_commit,
            "corpus_sha256":corpus_sha(),
            "base":{"path":"records/evidence/MTM-016/base.json","sha256":"3".repeat(64)},
            "batches":[{"profile":"corpus_research","path":"records/evidence/MTM-016/research.json","sha256":"4".repeat(64)}],
            "passed_trials":78,"failed_trials":0,"blocked_trials":12,"complete":false,
            "production_changed":false,"release_qualified":false
        });
        shape(&good, &manifest)?;
        for (pointer, replacement) in [
            ("/passed_trials", json!(77)),
            ("/blocked_trials", json!(11)),
            ("/failed_trials", json!(1)),
            ("/complete", json!(true)),
            ("/release_qualified", json!(true)),
            ("/batches/0/profile", json!("corpus_native")),
            ("/candidate_sha256", json!("9".repeat(64))),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer)
                .ok_or("aggregate fixture pointer")? = replacement;
            assert!(shape(&bad, &manifest).is_err(), "mutated {pointer}");
        }
        Ok(())
    }

    #[test]
    fn batch_requires_exactly_fifteen_distinct_hash_bound_trial_receipts() -> Result<()> {
        let manifest = manifest();
        let root = tempdir()?;
        let evidence = root.path().join("records/evidence/MTM-016");
        fs::create_dir_all(&evidence)?;
        let mut refs = Vec::new();
        for task in ["U21", "U22", "U23", "U24", "U25"] {
            for repeat in 1..=3 {
                let trial = trial_fixture(task, repeat)?;
                let bytes = serde_json::to_vec(&trial)?;
                let name = format!("{}-r{repeat}.json", task.to_ascii_lowercase());
                fs::write(evidence.join(&name), &bytes)?;
                refs.push(json!({
                    "task_id":task,"repeat":repeat,
                    "path":format!("records/evidence/MTM-016/{name}"),
                    "sha256":format!("{:x}",Sha256::digest(&bytes))
                }));
            }
        }
        let good = json!({
            "schema":"mtm-research-corpus-batch-v1","milestone":"MTM-016",
            "candidate_sha256":manifest.candidate_sha256,"candidate_source_commit":manifest.candidate_source_commit,
            "corpus_sha256":corpus_sha(),"case_registry_sha256":cases_sha(),"trials":refs,
            "tasks":5,"repeats":3,"passed_trials":15,"failed_trials":0,
            "complete_for_research_scope":true,"production_changed":false,"release_qualified":false
        });
        batch(root.path(), &good, &manifest)?;
        for (pointer, replacement) in [
            ("/passed_trials", json!(14)),
            ("/complete_for_research_scope", json!(false)),
            ("/trials/1/repeat", json!(1)),
            ("/trials/1/sha256", good["trials"][0]["sha256"].clone()),
            ("/trials/1/path", good["trials"][0]["path"].clone()),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).ok_or("batch fixture pointer")? = replacement;
            assert!(
                batch(root.path(), &bad, &manifest).is_err(),
                "mutated {pointer}"
            );
        }
        let mut missing = good.clone();
        missing["trials"]
            .as_array_mut()
            .ok_or("batch trials")?
            .pop();
        assert!(batch(root.path(), &missing, &manifest).is_err());
        Ok(())
    }
}
