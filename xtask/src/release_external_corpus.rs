//! Closed U26-U29 aggregation. Existing broad gates cannot substitute for repetitions.
use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::*;

const CORPUS: &str = include_str!("../../conformance/mtm016-usability-corpus.json");

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
struct ExternalBatch {
    schema: String,
    milestone: String,
    candidate_sha256: String,
    candidate_source_commit: String,
    corpus_sha256: String,
    trials: Vec<TrialRef>,
    tasks: u64,
    repeats: u64,
    passed_trials: u64,
    failed_trials: u64,
    complete_for_external_scope: bool,
    production_changed: bool,
    release_qualified: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalTrial {
    schema: String,
    milestone: String,
    task_id: String,
    scenario: String,
    repeat: u64,
    trial_id: String,
    candidate_sha256: String,
    candidate_source_commit: String,
    corpus_sha256: String,
    witness_observation_sha256: String,
    candidate_exact_observed: bool,
    real_browser_observed: bool,
    independent_human_observed: bool,
    operator_authorized_copy: bool,
    production_original_read_only: bool,
    original_copy_unchanged: bool,
    normal_invalid_count: u64,
    submission_rejection_count: u64,
    protected_effect_count: u64,
    route_checks: Vec<String>,
    raw_private_state_recorded: bool,
    production_changed: bool,
    release_qualified: bool,
    recorded_unix_seconds: u64,
}

fn corpus_sha() -> String {
    format!("{:x}", Sha256::digest(CORPUS.as_bytes()))
}

fn scenario(task: &str) -> Result<&'static str> {
    match task {
        "U26" => Ok("browser_oauth_reconnect"),
        "U27" => Ok("human_consent_decline"),
        "U28" => Ok("human_consent_scopes"),
        "U29" => Ok("copied_operator_state"),
        _ => Err("unsupported external corpus task".into()),
    }
}

fn route_checks(task: &str) -> Result<Vec<&'static str>> {
    match task {
        "U26" => Ok(vec![
            "real_browser",
            "dcr_pkce",
            "protected_resource",
            "reconnect_exact_candidate",
            "normal_invalid_zero",
            "submission_rejections_zero",
        ]),
        "U27" => Ok(vec![
            "real_browser",
            "independent_human",
            "decline_observed",
            "cancel_observed",
            "zero_protected_effects",
            "exact_candidate",
        ]),
        "U28" => Ok(vec![
            "real_browser",
            "independent_human",
            "once_grant_consumed",
            "session_grant_reused",
            "expiry_observed",
            "restart_invalidation",
            "exact_candidate",
        ]),
        "U29" => Ok(vec![
            "operator_authorized_copy",
            "production_original_read_only",
            "candidate_upgrade_resume",
            "original_copy_restored",
            "old_runtime_resume",
            "exact_candidate",
        ]),
        _ => Err("unsupported external corpus task".into()),
    }
}

fn trial(value: &Value, manifest: &Manifest, task: &str, repeat: u64) -> Result<u64> {
    let evidence: ExternalTrial = serde_json::from_value(value.clone())
        .map_err(|_| "external corpus trial schema invalid")?;
    let expected_checks = route_checks(task)?;
    let common = evidence.schema == "mtm-external-corpus-trial-evidence-v1"
        && evidence.milestone == "MTM-016"
        && evidence.task_id == task
        && evidence.scenario == scenario(task)?
        && evidence.repeat == repeat
        && identity_matches(
            &evidence.candidate_sha256,
            &evidence.candidate_source_commit,
            manifest,
        )
        && evidence.corpus_sha256 == corpus_sha()
        && hash(&evidence.trial_id, 32)
        && hash(&evidence.witness_observation_sha256, 64)
        && evidence.candidate_exact_observed
        && evidence.normal_invalid_count == 0
        && evidence.submission_rejection_count == 0
        && evidence
            .route_checks
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            == expected_checks
        && !evidence.raw_private_state_recorded
        && !evidence.production_changed
        && !evidence.release_qualified
        && evidence.recorded_unix_seconds != 0;
    let task_scope = match task {
        "U26" => {
            evidence.real_browser_observed
                && !evidence.independent_human_observed
                && !evidence.operator_authorized_copy
                && !evidence.production_original_read_only
                && !evidence.original_copy_unchanged
        }
        "U27" => {
            evidence.real_browser_observed
                && evidence.independent_human_observed
                && !evidence.operator_authorized_copy
                && !evidence.production_original_read_only
                && !evidence.original_copy_unchanged
                && evidence.protected_effect_count == 0
        }
        "U28" => {
            evidence.real_browser_observed
                && evidence.independent_human_observed
                && !evidence.operator_authorized_copy
                && !evidence.production_original_read_only
                && !evidence.original_copy_unchanged
        }
        "U29" => {
            !evidence.real_browser_observed
                && !evidence.independent_human_observed
                && evidence.operator_authorized_copy
                && evidence.production_original_read_only
                && evidence.original_copy_unchanged
        }
        _ => false,
    };
    if !common || !task_scope {
        return Err("external corpus trial identity, witness or route evidence invalid".into());
    }
    Ok(evidence.recorded_unix_seconds)
}

fn batch(root: &Path, value: &Value, manifest: &Manifest) -> Result<()> {
    let batch: ExternalBatch = serde_json::from_value(value.clone())
        .map_err(|_| "external corpus batch schema invalid")?;
    if batch.schema != "mtm-external-corpus-batch-v1"
        || batch.milestone != "MTM-016"
        || !identity_matches(
            &batch.candidate_sha256,
            &batch.candidate_source_commit,
            manifest,
        )
        || batch.corpus_sha256 != corpus_sha()
        || batch.tasks != 4
        || batch.repeats != 3
        || batch.trials.len() != 12
        || batch.passed_trials != 12
        || batch.failed_trials != 0
        || !batch.complete_for_external_scope
        || batch.production_changed
        || batch.release_qualified
    {
        return Err("external corpus batch identity, counts or scope invalid".into());
    }
    let mut cells = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    let mut trial_ids = BTreeSet::new();
    let mut times = BTreeSet::new();
    for reference in &batch.trials {
        if !(matches!(reference.task_id.as_str(), "U26" | "U27" | "U28" | "U29")
            && (1..=3).contains(&reference.repeat)
            && cells.insert((reference.task_id.clone(), reference.repeat))
            && paths.insert(reference.path.clone())
            && hashes.insert(reference.sha256.clone()))
        {
            return Err("external trial references are duplicate or outside U26-U29".into());
        }
        let value = checked_evidence(root, &reference.path, &reference.sha256)?;
        let recorded = trial(&value, manifest, &reference.task_id, reference.repeat)?;
        let trial_id = value["trial_id"]
            .as_str()
            .ok_or("external trial id missing after validation")?;
        if !trial_ids.insert(trial_id.to_owned()) || !times.insert(recorded) {
            return Err("external corpus repetitions do not have distinct identities/times".into());
        }
    }
    for task in ["U26", "U27", "U28", "U29"] {
        for repeat in 1..=3 {
            if !cells.contains(&(task.to_owned(), repeat)) {
                return Err("external corpus batch is missing a fixed task/repeat cell".into());
            }
        }
    }
    Ok(())
}

fn shape(value: &Value, manifest: &Manifest) -> Result<Aggregate> {
    let aggregate: Aggregate = serde_json::from_value(value.clone())
        .map_err(|_| "complete corpus aggregate schema invalid")?;
    if aggregate.schema != "mtm-usability-corpus-aggregate-v4"
        || aggregate.milestone != "MTM-016"
        || !identity_matches(
            &aggregate.candidate_sha256,
            &aggregate.candidate_source_commit,
            manifest,
        )
        || aggregate.corpus_sha256 != corpus_sha()
        || aggregate.batches.len() != 1
        || aggregate.batches[0].profile != "corpus_external"
        || aggregate.base.path == aggregate.batches[0].path
        || aggregate.base.sha256 == aggregate.batches[0].sha256
        || aggregate.passed_trials != 90
        || aggregate.failed_trials != 0
        || aggregate.blocked_trials != 0
        || !aggregate.complete
        || aggregate.production_changed
        || aggregate.release_qualified
    {
        return Err("complete corpus aggregate identity, counts or scope invalid".into());
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
    if base["schema"] != "mtm-usability-corpus-aggregate-v3"
        || base["passed_trials"] != 78
        || base["failed_trials"] != 0
        || base["blocked_trials"] != 12
        || base["complete"] != false
        || base["corpus_sha256"] != aggregate.corpus_sha256
        || research_corpus_aggregate::validate(root, &base, manifest, cache)?
    {
        return Err("complete corpus aggregate requires the exact validated 78/12 base".into());
    }
    let selected = &aggregate.batches[0];
    let external = checked_evidence(root, &selected.path, &selected.sha256)?;
    batch(root, &external, manifest)?;
    Ok(true)
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
        let browser = task != "U29";
        let human = matches!(task, "U27" | "U28");
        let copy = task == "U29";
        Ok(json!({
            "schema":"mtm-external-corpus-trial-evidence-v1","milestone":"MTM-016",
            "task_id":task,"scenario":scenario(task)?,"repeat":repeat,
            "trial_id":format!("{:032x}",(task.as_bytes()[2]-b'0') as u64*10+repeat),
            "candidate_sha256":"a".repeat(64),"candidate_source_commit":"b".repeat(40),
            "corpus_sha256":corpus_sha(),"witness_observation_sha256":"d".repeat(64),
            "candidate_exact_observed":true,"real_browser_observed":browser,
            "independent_human_observed":human,"operator_authorized_copy":copy,
            "production_original_read_only":copy,"original_copy_unchanged":copy,
            "normal_invalid_count":0,"submission_rejection_count":0,
            "protected_effect_count":if task=="U27" {0} else {1},"route_checks":route_checks(task)?,
            "raw_private_state_recorded":false,"production_changed":false,"release_qualified":false,
            "recorded_unix_seconds":1800000000+repeat+(task.as_bytes()[2] as u64)*10
        }))
    }

    #[test]
    fn external_trial_scope_cannot_be_widened_or_relabelled() -> Result<()> {
        let manifest = manifest();
        for task in ["U26", "U27", "U28", "U29"] {
            let good = trial_fixture(task, 1)?;
            trial(&good, &manifest, task, 1)?;
            for (pointer, replacement) in [
                ("/candidate_exact_observed", json!(false)),
                ("/normal_invalid_count", json!(1)),
                ("/submission_rejection_count", json!(1)),
                ("/route_checks", json!([])),
                ("/candidate_sha256", json!("9".repeat(64))),
                ("/raw_private_state_recorded", json!(true)),
            ] {
                let mut bad = good.clone();
                *bad.pointer_mut(pointer).ok_or("external trial pointer")? = replacement;
                assert!(
                    trial(&bad, &manifest, task, 1).is_err(),
                    "mutated {pointer}"
                );
            }
        }
        let mut decline = trial_fixture("U27", 1)?;
        decline["protected_effect_count"] = json!(1);
        assert!(trial(&decline, &manifest, "U27", 1).is_err());
        let mut copied = trial_fixture("U29", 1)?;
        copied["production_original_read_only"] = json!(false);
        assert!(trial(&copied, &manifest, "U29", 1).is_err());
        Ok(())
    }

    #[test]
    fn external_batch_requires_twelve_distinct_repetitions() -> Result<()> {
        let manifest = manifest();
        let root = tempdir()?;
        let evidence = root.path().join("records/evidence/MTM-016");
        fs::create_dir_all(&evidence)?;
        let mut refs = Vec::new();
        for task in ["U26", "U27", "U28", "U29"] {
            for repeat in 1..=3 {
                let trial = trial_fixture(task, repeat)?;
                let bytes = serde_json::to_vec(&trial)?;
                let name = format!("{}-r{repeat}.json", task.to_ascii_lowercase());
                fs::write(evidence.join(&name), &bytes)?;
                refs.push(json!({"task_id":task,"repeat":repeat,
                    "path":format!("records/evidence/MTM-016/{name}"),
                    "sha256":format!("{:x}",Sha256::digest(&bytes))}));
            }
        }
        let good = json!({
            "schema":"mtm-external-corpus-batch-v1","milestone":"MTM-016",
            "candidate_sha256":manifest.candidate_sha256,"candidate_source_commit":manifest.candidate_source_commit,
            "corpus_sha256":corpus_sha(),"trials":refs,"tasks":4,"repeats":3,"passed_trials":12,
            "failed_trials":0,"complete_for_external_scope":true,"production_changed":false,"release_qualified":false
        });
        batch(root.path(), &good, &manifest)?;
        let mut missing = good.clone();
        missing["trials"].as_array_mut().ok_or("trials")?.pop();
        assert!(batch(root.path(), &missing, &manifest).is_err());
        let mut duplicate = good.clone();
        duplicate["trials"][1]["repeat"] = json!(1);
        assert!(batch(root.path(), &duplicate, &manifest).is_err());
        Ok(())
    }

    #[test]
    fn v4_is_the_only_complete_90_0_shape() -> Result<()> {
        let manifest = manifest();
        let good = json!({
            "schema":"mtm-usability-corpus-aggregate-v4","milestone":"MTM-016",
            "candidate_sha256":manifest.candidate_sha256,"candidate_source_commit":manifest.candidate_source_commit,
            "corpus_sha256":corpus_sha(),
            "base":{"path":"records/evidence/MTM-016/research-v3.json","sha256":"1".repeat(64)},
            "batches":[{"profile":"corpus_external","path":"records/evidence/MTM-016/external.json","sha256":"2".repeat(64)}],
            "passed_trials":90,"failed_trials":0,"blocked_trials":0,"complete":true,
            "production_changed":false,"release_qualified":false
        });
        shape(&good, &manifest)?;
        for (pointer, replacement) in [
            ("/passed_trials", json!(89)),
            ("/failed_trials", json!(1)),
            ("/blocked_trials", json!(1)),
            ("/complete", json!(false)),
            ("/release_qualified", json!(true)),
            ("/batches/0/profile", json!("browser_human")),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).ok_or("v4 pointer")? = replacement;
            assert!(shape(&bad, &manifest).is_err(), "mutated {pointer}");
        }
        Ok(())
    }
}
