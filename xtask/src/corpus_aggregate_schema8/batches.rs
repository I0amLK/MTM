//! Closed semantic adapters; supporting observations retain their original labels.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    before_sha256: String,
    after_sha256: String,
    commit: String,
    unchanged: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Runner {
    child_reaped: bool,
    elapsed_ms: u64,
    exit_code: i64,
    output_limit_exceeded: bool,
    pipes_closed: bool,
    raw_output_recorded: bool,
    signal: Value,
    stderr_bytes_retained: u64,
    stdout_bytes_retained: u64,
    timed_out: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Portable {
    baseline_launched: Value,
    baseline_sha256: Value,
    candidate_launched: bool,
    candidate_sha256: String,
    corpus_definition_sha256: String,
    delivery: String,
    failed_stage: String,
    failure: String,
    harness_source_identity: Source,
    milestone: String,
    original_and_snapshot_unchanged: bool,
    passed: bool,
    pending: Vec<String>,
    production_selectors_changed: bool,
    production_state_modified: bool,
    profile: String,
    python_invoked: bool,
    raw_test_output_recorded: bool,
    recorded_unix_seconds: u64,
    release_qualified: bool,
    runner: Runner,
    schema_version: String,
    scope: String,
    selector_changed: bool,
    summaries: Value,
    test_stderr_sha256: String,
    test_stdout_sha256: String,
}
fn source(v: &Value, sha: &str, commit: &str) -> Result<()> {
    let s: Source =
        serde_json::from_value(v.clone()).map_err(|_| "corpus source schema invalid")?;
    require(
        s.before_sha256 == sha && s.after_sha256 == sha && s.commit == commit && s.unchanged,
        "corpus harness source lineage invalid",
    )
}
fn reference_matches(v: &Value, r: &Reference) -> bool {
    v["path"] == r.path && v["sha256"] == r.sha256
}
pub(super) fn portable(
    raw: &Value,
    wrapper: &Value,
    review: &Value,
    input: &PortableInput,
) -> Result<Vec<Value>> {
    let p: Portable = serde_json::from_value(raw.clone())
        .map_err(|_| "portable receipt closed schema invalid")?;
    let r = &p.runner;
    let s = &p.harness_source_identity;
    require(
        p.schema_version == "1.0.0"
            && p.milestone == "MTM-016"
            && p.profile == "corpus"
            && p.delivery == "F5"
            && p.scope == "exact_candidate_partial_usability_corpus_not_release"
            && p.candidate_sha256 == CANDIDATE
            && p.candidate_launched
            && p.original_and_snapshot_unchanged
            && p.baseline_launched.is_null()
            && p.baseline_sha256.is_null()
            && !p.passed
            && p.failed_stage == "corpus_coverage"
            && p.failure
                == "Corpus contains blocked or failed trials; completed trials remain recorded"
            && p.corpus_definition_sha256 == CORPUS
            && !p.production_selectors_changed
            && !p.production_state_modified
            && !p.python_invoked
            && !p.raw_test_output_recorded
            && !p.release_qualified
            && !p.selector_changed
            && p.recorded_unix_seconds > 0
            && p.pending
                == [
                    "Native tasks U16-U20",
                    "independent research tasks U21-U25",
                    "external-client/operator tasks U26-U30",
                    "full release gates",
                ]
            && s.before_sha256 == OBS_SOURCE
            && s.after_sha256 == OBS_SOURCE
            && s.commit == OBS_COMMIT
            && s.unchanged
            && r.child_reaped
            && r.pipes_closed
            && r.exit_code == 0
            && !r.output_limit_exceeded
            && !r.raw_output_recorded
            && r.signal.is_null()
            && !r.timed_out
            && r.elapsed_ms > 0
            && r.elapsed_ms <= 610000
            && r.stdout_bytes_retained > 0
            && r.stdout_bytes_retained <= 2097152
            && r.stderr_bytes_retained <= 2097152
            && hash(&p.test_stdout_sha256)
            && hash(&p.test_stderr_sha256),
        "portable partial outer result, runner, scope or identity invalid",
    )?;
    require(
        !qualify::validate_corpus_summary(&p.summaries, CANDIDATE)?,
        "portable observation must retain incomplete corpus result",
    )?;
    let summary = &p.summaries["corpus"];
    require(
        summary["passed_trials"] == 45
            && summary["failed_trials"] == 0
            && summary["blocked_trials"] == 45
            && summary["native_backend"] == "disabled"
            && summary["latex_policy"] == "static_only",
        "portable summary is not exactly forty-five observed rows",
    )?;
    let mut selected = Vec::new();
    for row in array(&summary["rows"])? {
        let task = row["task_id"].as_str().ok_or("portable task missing")?;
        let n = task
            .strip_prefix('U')
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or("portable task invalid")?;
        if n <= 15 {
            require(row["status"] == "passed", "portable row not passed")?;
            selected.push(row.clone());
        } else {
            require(
                row["status"] == "blocked",
                "portable promoted an unexecuted cell",
            )?;
        }
    }
    require(selected.len() == 45, "portable row count invalid")?;
    let candidate = &wrapper["candidate"];
    let execution = &wrapper["execution"];
    let corpus = &wrapper["corpus"];
    require(
        wrapper["schema"] == "mtm017-portable-corpus-observation-v1"
            && wrapper["milestone"] == "MTM-017"
            && candidate["sha256"] == CANDIDATE
            && candidate["version"] == "0.6.0-preview.2"
            && candidate["state_schema"] == 8
            && candidate["product_source_commit"] == PRODUCT_COMMIT
            && candidate["original_build_source_sha256"] == PRODUCT_SOURCE
            && reference_matches(&candidate["source_binding"], &input_snapshot())
            && candidate["product_lineage_check"]["exit_code"] == 0
            && candidate["product_lineage_check"]["diff_bytes"] == 0
            && candidate["product_lineage_check"]["harness_changes_do_not_rebuild_or_relabel_product"]
                == true
            && wrapper["harness_source_identity"] == raw["harness_source_identity"]
            && execution["qualifier_exit_code"] == 1
            && execution["exit_classification"] == "expected_incomplete_corpus_coverage"
            && execution["unexpected_portable_failure"] == false
            && execution["raw_passed_value"] == false
            && execution["runner"] == raw["runner"]
            && execution["qualification_attempts"] == 1
            && execution["record_flag"] == false
            && corpus["total_rows"] == 90
            && corpus["unique_task_repeat_rows"] == 90
            && corpus["passed_trials"] == 45
            && corpus["failed_trials"] == 0
            && corpus["blocked_trials"] == 45
            && corpus["passed"] == false
            && corpus["failed_stage"] == "corpus_coverage"
            && corpus["accepted_delta"] == 0
            && corpus["full_90_trial_acceptance"] == false
            && reference_matches(&wrapper["raw_report"], &input.raw)
            && wrapper["raw_report"]["archived_byte_for_byte"] == true
            && wrapper["raw_report"]["original_runner_milestone"] == "MTM-016"
            && wrapper["raw_report"]["runner_label_unchanged"] == true
            && wrapper["isolation"]["fresh_per_task_repeat"] == true
            && wrapper["isolation"]["production_paths_opened"] == false,
        "portable observation scope or raw binding invalid",
    )?;
    for k in [
        "release_qualified",
        "release_ready",
        "deployment_authorized",
        "production_state_modified",
        "production_selectors_changed",
        "old_release_driver_or_manifest_modified",
        "historical_candidate_validation_overwritten",
    ] {
        require(
            wrapper["boundaries"][k] == false,
            "portable observation expanded authority",
        )?;
    }
    require(
        wrapper["boundaries"]["accepted_delta"] == 0
            && review["schema"] == "mtm017-portable-corpus-independent-review-record-v1"
            && review["milestone"] == "MTM-017"
            && review["reviewer"]["independent_from_executor_and_scribe"] == true
            && review["scribe"]["performed_independent_review"] == false
            && review["conclusion"]["observation_review_passed"] == true
            && review["conclusion"]["accepted_delta"] == 0
            && review["conclusion"]["raw_passed_remains_false"] == true
            && review["conclusion"]["full_90_trial_acceptance"] == false
            && review["conclusion"]["release_qualified"] == false
            && review["conclusion"]["deployment_authorized"] == false,
        "portable independent review scope invalid",
    )?;
    let refs = array(&review["reviewed_artifacts"])?;
    require(
        refs.iter()
            .filter(|v| reference_matches(v, &input.raw))
            .count()
            == 1
            && refs
                .iter()
                .filter(|v| reference_matches(v, &input.observation))
                .count()
                == 1,
        "portable review does not bind selected raw and wrapper",
    )?;
    Ok(selected)
}
fn input_snapshot() -> Reference {
    Reference {
        path: format!("{PREFIX}{}", NATIVE[1].0),
        sha256: NATIVE[1].1.into(),
    }
}
pub(super) fn native(raw: &Value, snapshot: &Value, input: &NativeInput) -> Result<Vec<Value>> {
    qualify::validate_receipt(raw, CANDIDATE, BASELINE, "corpus_native")?;
    source(
        &raw["harness_source_identity"],
        PRODUCT_SOURCE,
        PRODUCT_COMMIT,
    )?;
    require(
        snapshot["milestone"] == "MTM-017"
            && snapshot["implementation_commit"] == PRODUCT_COMMIT
            && snapshot["source_sha256"] == PRODUCT_SOURCE
            && snapshot["candidate"]["sha256"] == CANDIDATE
            && snapshot["candidate"]["path"]
                == format!("target/mtm017-preview2/mtm-0.6.0-preview.2-{CANDIDATE}/mtm")
            && snapshot["baseline"]["sha256"] == BASELINE
            && snapshot["baseline"]["version"] == "0.6.0-preview.1"
            && snapshot["baseline"]["state_schema"] == 7
            && snapshot["baseline"]["path"]
                == format!("target/mtm017-baselines/mtm-0.6.0-preview.1-{BASELINE}/mtm")
            && snapshot["candidate"]["version"] == "0.6.0-preview.2"
            && snapshot["candidate"]["state_schema"] == 8
            && snapshot["candidate"]["tool_contract"] == "mtm-tools-v10"
            && snapshot["candidate"]["workflow_protocol"] == 3
            && snapshot["candidate"]["public_tools"] == 24
            && snapshot["qualification_reports_archived_byte_for_byte"] == true
            && snapshot["production_selectors_changed"] == false
            && snapshot["production_state_modified"] == false
            && snapshot["release_qualified"] == false
            && snapshot["native_corpus"]["passed"] == 15
            && snapshot["native_corpus"]["failed"] == 0
            && snapshot["native_corpus"]["complete_corpus"] == false,
        "Native candidate snapshot identity or scope invalid",
    )?;
    let seals = array(&snapshot["report_seals"])?;
    let mut paths = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    let profiles = array(&snapshot["profiles_passed"])?;
    require(
        profiles.len() == 8
            && [
                "upgrade_schema8",
                "protocol",
                "native_commands",
                "compiled_latex",
                "resource",
                "corpus_native",
                "install_sigkill",
                "retrieval",
            ]
            .iter()
            .all(|name| profiles.iter().filter(|v| *v == name).count() == 1),
        "Native snapshot profile set invalid",
    )?;
    require(
        seals.len() == 9
            && seals
                .iter()
                .filter(|v| reference_matches(v, &input.raw))
                .count()
                == 1,
        "Native snapshot raw seal missing or duplicated",
    )?;
    for seal in seals {
        let r: Reference = serde_json::from_value(seal.clone())
            .map_err(|_| "snapshot seal closed schema invalid")?;
        require(
            paths.insert(r.path) && hash(&r.sha256) && hashes.insert(r.sha256),
            "snapshot seal invalid or duplicate",
        )?;
    }
    let summary = &raw["summaries"]["corpus_native"];
    let rows = array(&summary["rows"])?;
    require(
        rows.len() == 15
            && summary["passed_trials"] == 15
            && summary["failed_trials"] == 0
            && summary["human_consent_tested"] == false,
        "Native subset counts or human scope invalid",
    )?;
    let expected = json!([
        "hard_isolation",
        "private_vault_hidden",
        "children_reaped",
        "clean_shutdown",
        "dangerous_network",
        "repeated_without_grant",
        "network_shared_vault_hidden"
    ]);
    for row in rows {
        require(row["status"] == "passed", "Native row not passed")?;
        if row["task_id"] == "U20" {
            require(
                row["checks"] == expected,
                "MTM-017 U20 requires dangerous-only checks",
            )?;
        }
    }
    Ok(rows.clone())
}
fn observation_time(value: &str) -> Result<u64> {
    // This adapter is deliberately fixed to the reviewed 2026-09-30 batch.
    let b = value.as_bytes();
    require(
        b.len() == 20
            && b.starts_with(b"2026-09-30T")
            && b[13] == b':'
            && b[16] == b':'
            && b[19] == b'Z',
        "U30 UTC date format invalid",
    )?;
    let number = |start: usize| -> Result<u64> {
        let pair = &b[start..start + 2];
        require(
            pair.iter().all(u8::is_ascii_digit),
            "U30 UTC digits invalid",
        )?;
        Ok(u64::from(pair[0] - b'0') * 10 + u64::from(pair[1] - b'0'))
    };
    let (h, m, s) = (number(11)?, number(14)?, number(17)?);
    require(h < 24 && m < 60 && s < 60, "U30 UTC clock out of range")?;
    Ok(1_790_726_400 + h * 3600 + m * 60 + s)
}

pub(super) fn u30(
    wrapper: &Value,
    review: &Value,
    raws: &[(u64, Reference, Value)],
    input: &U30Input,
) -> Result<Vec<(u64, Reference, String)>> {
    require(
        wrapper["schema"] == "mtm017-u30-install-sigkill-observation-v1"
            && wrapper["milestone"] == "MTM-017"
            && wrapper["candidate_sha256"] == CANDIDATE
            && wrapper["state_schema"] == 8
            && wrapper["profile"] == "install_sigkill"
            && wrapper["runner_milestone_label_preserved"] == "MTM-016"
            && wrapper["observation_count"] == 3
            && wrapper["observed_successful_trials"] == 3
            && wrapper["failed_trials"] == 0
            && wrapper["accepted_delta"] == 0
            && wrapper["historical_single_trial_not_reused"] == true
            && wrapper["prior_mtm017_records_unchanged"] == true
            && wrapper["old_driver_and_manifest_unchanged"] == true,
        "U30 observation scope invalid",
    )?;
    for k in [
        "physical_power_loss_tested",
        "shared_filesystem_tested",
        "production_selectors_changed",
        "production_state_modified",
        "live_capture_performed",
        "non_test_processes_signalled",
        "release_qualified",
        "deployment_authorized",
    ] {
        require(wrapper[k] == false, "U30 observation expanded scope")?;
    }
    require(
        review["schema"] == "mtm017-u30-independent-observation-review-v1"
            && review["milestone"] == "MTM-017"
            && review["decision"] == "observations_approved_for_separate_aggregate_review"
            && review["reviewer_session"] != review["recorded_by"]
            && review["recording_role"] == "scribe_only"
            && review["review_received_from_separate_reviewer"] == true
            && review["accepted_delta"] == 0
            && review["physical_power_loss_tested"] == false
            && review["production_selector_changed"] == false
            && review["production_state_modified"] == false
            && review["release_qualified"] == false
            && review["deployment_authorized"] == false,
        "U30 independent review invalid",
    )?;
    let observations = array(&wrapper["trials"])?;
    require(
        observations.len() == 3 && raws.len() == 3,
        "three U30 observations required",
    )?;
    let mut unique = BTreeSet::new();
    let mut selected = Vec::new();
    let mut windows = BTreeMap::new();
    let reviewed = array(&review["reviewed_artifacts"])?;
    require(
        reviewed
            .iter()
            .filter(|v| reference_matches(v, &input.observation))
            .count()
            == 1,
        "U30 review wrapper binding missing",
    )?;
    for (repeat, seal, raw) in raws {
        require((1..=3).contains(repeat), "U30 repeat invalid")?;
        qualify::validate_receipt(raw, CANDIDATE, BASELINE, "install_sigkill")?;
        source(&raw["harness_source_identity"], OBS_SOURCE, OBS_COMMIT)?;
        let matched = observations
            .iter()
            .filter(|v| v["trial"] == *repeat)
            .collect::<Vec<_>>();
        require(
            matched.len() == 1,
            "U30 repeat observation missing or duplicate",
        )?;
        let o = matched[0];
        let id = o["observation_id"]
            .as_str()
            .ok_or("U30 observation id missing")?;
        let command = o["ctm_terminal"]["command_id"]
            .as_str()
            .ok_or("U30 command id missing")?;
        let tmp = o["unique_tmpdir"].as_str().ok_or("U30 TMPDIR missing")?;
        let time = o["recorded_unix_seconds"]
            .as_u64()
            .ok_or("U30 recording time missing")?;
        require(
            o["task_id"] == "U30"
                && marker(id)
                && marker(command)
                && time > 0
                && o["recorded_unix_seconds"] == raw["recorded_unix_seconds"]
                && reference_matches(&o["raw_report"], seal)
                && o["raw_report_source"]["sha256"] == seal.sha256
                && o["candidate_source_commit"] == PRODUCT_COMMIT
                && o["harness_source_identity"] == raw["harness_source_identity"]
                && o["input_hashes_unchanged"] == true
                && o["input_sha256_before"] == o["input_sha256_after"]
                && o["input_sha256_before"].as_object().is_some_and(|m| {
                    m.len() == 9 && m.values().all(|v| v.as_str().is_some_and(hash))
                })
                && o["input_sha256_before"]
                    [format!("target/mtm017-preview2/mtm-0.6.0-preview.2-{CANDIDATE}/mtm")]
                    == CANDIDATE
                && o["input_sha256_before"]
                    [format!("target/mtm017-baselines/mtm-0.6.0-preview.1-{BASELINE}/mtm")]
                    == BASELINE
                && o["input_sha256_before"][DRIVER.0] == DRIVER.1
                && o["product_source_lineage_exact"] == true
                && o["product_source_lineage_diff"]["sha256"] == digest(b"")
                && o["fresh_qualifier_snapshot"] == true
                && o["fresh_test_tempdir"] == true
                && o["baseline_not_launched"] == true
                && o["accepted_delta"] == 0
                && o["ctm_terminal"]["trial"] == *repeat
                && o["ctm_terminal"]["status"] == "exited"
                && o["ctm_terminal"]["exit_code"] == 0
                && o["ctm_terminal"]["timed_out"] == false
                && o["ctm_terminal"]["signal"].is_null()
                && Path::new(tmp).is_absolute()
                && tmp.ends_with(&format!("/trial-{repeat}/tmp"))
                && reviewed
                    .iter()
                    .filter(|v| reference_matches(v, seal))
                    .count()
                    == 1,
            "U30 original observation, freshness or review binding invalid",
        )?;
        let started = observation_time(o["started_at"].as_str().ok_or("U30 start missing")?)?;
        let finished = observation_time(o["finished_at"].as_str().ok_or("U30 finish missing")?)?;
        require(
            started < finished
                && finished == time
                && finished - started <= 610
                && raw["runner"]["elapsed_ms"]
                    .as_u64()
                    .is_some_and(|ms| ms > 0 && ms <= (finished - started) * 1000),
            "U30 time window invalid",
        )?;
        for (kind, value) in [
            ("repeat", repeat.to_string()),
            ("path", seal.path.clone()),
            ("sha", seal.sha256.clone()),
            ("observation", id.into()),
            ("time", time.to_string()),
            ("command", command.into()),
            ("tmpdir", tmp.into()),
        ] {
            require(
                unique.insert((kind, value)),
                "U30 independent trials duplicated",
            )?;
        }
        windows.insert(*repeat, (started, finished));
        selected.push((*repeat, seal.clone(), id.into()));
    }
    let ordered = windows.values().collect::<Vec<_>>();
    require(
        ordered.windows(2).all(|w| w[0].1 <= w[1].0),
        "U30 trials were not serial",
    )?;
    Ok(selected)
}
