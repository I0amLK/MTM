//! Append native trials to the immutable 48/42 base; unsupported batches fail.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
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
    batches: Vec<Batch>,
    passed_trials: u64,
    failed_trials: u64,
    blocked_trials: u64,
    complete: bool,
    production_changed: bool,
    release_qualified: bool,
}

fn shape(value: &Value, manifest: &Manifest) -> Result<Aggregate> {
    let aggregate: Aggregate = serde_json::from_value(value.clone())
        .map_err(|_| "Native corpus aggregate schema invalid")?;
    if aggregate.schema != "mtm-usability-corpus-aggregate-v2"
        || aggregate.milestone != "MTM-016"
        || !identity_matches(
            &aggregate.candidate_sha256,
            &aggregate.candidate_source_commit,
            manifest,
        )
        || !hash(&aggregate.corpus_sha256, 64)
        || aggregate.batches.len() != 1
        || aggregate.batches[0].profile != "corpus_native"
        || aggregate.base.path == aggregate.batches[0].path
        || aggregate.base.sha256 == aggregate.batches[0].sha256
        || aggregate.failed_trials != 0
        || aggregate.complete
        || aggregate.production_changed
        || aggregate.release_qualified
    {
        return Err("Native corpus aggregate identity, batches or scope invalid".into());
    }
    Ok(aggregate)
}

fn counts(aggregate: &Aggregate, base: &Value, native: &Value) -> Result<()> {
    if base["schema"] != "mtm-usability-corpus-aggregate-v1"
        || base["passed_trials"] != 48
        || base["failed_trials"] != 0
        || base["blocked_trials"] != 42
        || base["complete"] != false
        || base["corpus_sha256"] != aggregate.corpus_sha256
        || native["corpus_definition_sha256"] != aggregate.corpus_sha256
        || native["summaries"]["corpus_native"]["passed_trials"] != 15
        || native["summaries"]["corpus_native"]["failed_trials"] != 0
        || aggregate.passed_trials != 63
        || aggregate.blocked_trials != 27
    {
        return Err(
            "Native corpus aggregate does not preserve its exact 63/27 partial boundary".into(),
        );
    }
    Ok(())
}

pub(super) fn validate(
    root: &Path,
    value: &Value,
    manifest: &Manifest,
    cache: &mut BTreeMap<String, String>,
) -> Result<bool> {
    let aggregate = shape(value, manifest)?;
    let base = checked_evidence(root, &aggregate.base.path, &aggregate.base.sha256)?;
    // Only the historical v1 form is accepted here; no recursive aggregation.
    if validate_corpus_aggregate(root, &base, manifest, cache)? {
        return Err("Native corpus aggregate requires the immutable partial base".into());
    }
    let batch = &aggregate.batches[0];
    let native = checked_evidence(root, &batch.path, &batch.sha256)?;
    qualify::validate_receipt(
        &native,
        &manifest.candidate_sha256,
        &manifest.baseline_sha256,
        "corpus_native",
    )?;
    lineage(root, &native["harness_source_identity"], cache)?;
    counts(&aggregate, &base, &native)?;
    // U21-U29 remain absent; never count this partial aggregate as a full gate.
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_aggregate_is_closed_partial_and_not_a_waiver() -> Result<()> {
        let manifest = decode(include_bytes!(
            "../../records/governance/mtm016-release-inputs.json"
        ))?;
        let base: Value = serde_json::from_str(include_str!(
            "../../records/evidence/MTM-016/corpus-f5-final-u30-aggregate.json"
        ))?;
        let good = json!({"schema":"mtm-usability-corpus-aggregate-v2","milestone":"MTM-016",
            "candidate_sha256":manifest.candidate_sha256,"candidate_source_commit":manifest.candidate_source_commit,
            "corpus_sha256":base["corpus_sha256"],
            "base":{"path":"records/evidence/MTM-016/base.json","sha256":"a".repeat(64)},
            "batches":[{"profile":"corpus_native","path":"records/evidence/MTM-016/native.json","sha256":"b".repeat(64)}],
            "passed_trials":63,"failed_trials":0,"blocked_trials":27,"complete":false,"production_changed":false,"release_qualified":false});
        let native = json!({"corpus_definition_sha256":base["corpus_sha256"],"summaries":{"corpus_native":{"passed_trials":15,"failed_trials":0}}});
        counts(&shape(&good, &manifest)?, &base, &native)?;
        for (pointer, value) in [
            ("/complete", json!(true)),
            ("/release_qualified", json!(true)),
            ("/production_changed", json!(true)),
            ("/batches", json!([])),
            ("/batches", json!([good["batches"][0], good["batches"][0]])),
            ("/batches/0/profile", json!("native_commands")),
            ("/batches/0/path", good["base"]["path"].clone()),
            ("/batches/0/sha256", good["base"]["sha256"].clone()),
            ("/failed_trials", json!(1)),
            ("/candidate_sha256", json!("c".repeat(64))),
            ("/passed_trials", json!(90)),
            ("/blocked_trials", json!(0)),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer)
                .ok_or("aggregate fixture pointer")? = value;
            assert!(
                shape(&bad, &manifest)
                    .and_then(|a| counts(&a, &base, &native))
                    .is_err()
            );
        }
        for key in good.as_object().ok_or("aggregate fixture object")?.keys() {
            let mut bad = good.clone();
            bad.as_object_mut()
                .ok_or("aggregate fixture object")?
                .remove(key);
            assert!(shape(&bad, &manifest).is_err());
        }
        Ok(())
    }
}
