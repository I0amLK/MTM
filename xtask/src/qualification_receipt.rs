//! Revalidate sealed qualification data with the SAME summary validators.
use super::*;
use serde::Deserialize;

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
struct Source {
    before_sha256: String,
    after_sha256: String,
    commit: String,
    unchanged: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    baseline_launched: Value,
    baseline_sha256: Value,
    candidate_launched: bool,
    candidate_sha256: String,
    delivery: String,
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
    selector_scope: Option<String>,
    summaries: Value,
    test_stderr_sha256: String,
    test_stdout_sha256: String,
    native_preflight: Option<Value>,
}

pub(crate) fn validate(value: &Value, hash: &str, baseline: &str, name: &str) -> Result<()> {
    let report: Receipt = serde_json::from_value(value.clone())
        .map_err(|_| "qualification receipt schema invalid")?;
    let profile = Profile::parse(name)?;
    let paired = matches!(profile, Profile::Upgrade | Profile::Resource);
    let scope = match profile {
        Profile::Protocol => "exact_candidate_protocol_not_release",
        Profile::Target => "exact_candidate_target_not_release",
        Profile::Resource => "exact_candidate_resource_not_release",
        Profile::Upgrade => "exact_candidate_installed_upgrade_fixture_not_release",
        Profile::Permissions => "exact_candidate_scripted_patch_permissions_not_release",
        Profile::Corpus => return Err("partial corpus is not a completed release gate".into()),
    };
    let runner = &report.runner;
    let source = &report.harness_source_identity;
    if !valid_hash(hash)
        || !valid_hash(baseline)
        || report.schema_version != "1.0.0"
        || report.milestone != "MTM-016"
        || report.profile != name
        || report.scope != scope
        || report.delivery != profile.delivery()
        || report.candidate_sha256 != hash
        || !report.candidate_launched
        || !report.passed
        || !report.original_and_snapshot_unchanged
        || report.release_qualified
        || report.production_selectors_changed
        || report.production_state_modified
        || report.python_invoked
        || report.raw_test_output_recorded
        || report.recorded_unix_seconds == 0
        || report.pending.len() > 32
        || report.pending.iter().any(|v| v.len() > 512)
        || !runner.child_reaped
        || !runner.pipes_closed
        || runner.exit_code != 0
        || runner.timed_out
        || runner.output_limit_exceeded
        || runner.raw_output_recorded
        || !runner.signal.is_null()
        || runner.elapsed_ms > 610_000
        || runner.stdout_bytes_retained > 2 * 1024 * 1024
        || runner.stderr_bytes_retained > 2 * 1024 * 1024
        || !valid_hash(&report.test_stdout_sha256)
        || !valid_hash(&report.test_stderr_sha256)
        || !source.unchanged
        || !valid_hash(&source.before_sha256)
        || source.before_sha256 != source.after_sha256
        || source.commit.len() != 40
        || !source.commit.bytes().all(|b| b.is_ascii_hexdigit())
        || (paired
            && (report.baseline_sha256 != baseline
                || report.baseline_launched != true
                || hash == baseline))
        || (!paired && (!report.baseline_sha256.is_null() || !report.baseline_launched.is_null()))
        || report.selector_changed != (profile == Profile::Upgrade)
        || report.selector_scope.as_deref()
            != if profile == Profile::Upgrade {
                Some("owned_disposable_fixture_only")
            } else {
                None
            }
    {
        return Err("qualification receipt identity, result or scope inconsistent".into());
    }
    if matches!(profile, Profile::Target | Profile::Resource) {
        let native = report
            .native_preflight
            .as_ref()
            .ok_or("Native preflight missing")?;
        if native["passed"] != true || native["ready_for_native_tests"] != true {
            return Err("Native preflight did not pass".into());
        }
    } else if report.native_preflight.is_some() {
        return Err("unexpected Native preflight claim".into());
    }
    let summaries = &report.summaries;
    let mut bytes = Vec::new();
    let mut line = |key: &str, marker: &str| -> Result<()> {
        let value = summaries.get(key).ok_or("qualification summary missing")?;
        bytes.extend_from_slice(format!("{marker} {value}\n").as_bytes());
        Ok(())
    };
    let checked = match profile {
        Profile::Permissions => {
            line("permissions", "MTM_PERMISSION_RUNTIME")?;
            summary::validate_permissions(&bytes, hash)?
        }
        Profile::Upgrade => {
            line("upgrade", "MTM_UPGRADE_RUNTIME")?;
            summary::validate_upgrade(&bytes, hash, baseline)?
        }
        Profile::Resource => {
            line("resource", "MTM_RESOURCE_RUNTIME")?;
            summary::validate_resource(&bytes, hash, baseline)?
        }
        Profile::Protocol | Profile::Target => {
            line("capability", "MTM_CAPABILITY_GATE")?;
            line("workspace", "MTM_WORKSPACE_SMOKE")?;
            line("lifecycle", "MTM_CANDIDATE_LIFECYCLE")?;
            if profile == Profile::Target {
                line("target", "MTM_TARGET_RUNTIME")?;
            }
            summary::validate(&bytes, hash, profile)?
        }
        Profile::Corpus => return Err("partial corpus is not a completed release gate".into()),
    };
    if &checked != summaries {
        return Err("qualification summary has extra or inconsistent fields".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_protocol_rechecks_nested_counts_and_runner_not_just_passed() -> Result<()> {
        let good: Value = serde_json::from_str(include_str!(
            "../../records/evidence/MTM-016/candidate-protocol-f3-cc17b16.json"
        ))?;
        let hash = good["candidate_sha256"].as_str().ok_or("fixture hash")?;
        validate(&good, hash, &"b".repeat(64), "protocol")?;
        for (pointer, value) in [
            ("/summaries/capability/normal_roundtrips", json!(499)),
            ("/summaries/capability/normal_roundtrips", json!(500.0)),
            ("/summaries/target", json!({"ok":true})),
            ("/runner/exit_code", json!(101)),
            ("/runner/child_reaped", json!(false)),
            ("/harness_source_identity/unchanged", json!(false)),
            ("/release_qualified", json!(true)),
            ("/candidate_sha256", json!("b".repeat(64))),
        ] {
            let mut changed = good.clone();
            *changed.pointer_mut(pointer).ok_or("fixture pointer")? = value;
            assert!(validate(&changed, hash, &"b".repeat(64), "protocol").is_err());
        }
        assert!(validate(&good, hash, &"b".repeat(64), "target").is_err());
        Ok(())
    }
}
