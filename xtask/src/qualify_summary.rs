//! All three independent fixture summaries must bind the selected artifact.
use super::*;
use serde::Deserialize;

#[path = "corpus_summary.rs"]
mod corpus;
pub(super) use corpus::validate as validate_corpus;

#[path = "install_sigkill_summary.rs"]
mod install_sigkill;
pub(super) use install_sigkill::validate as validate_install_sigkill;

#[path = "retrieval_summary.rs"]
mod retrieval;
pub(super) use retrieval::validate as validate_retrieval;

#[path = "permission_summary.rs"]
mod permissions;
pub(super) use permissions::validate as validate_permissions;

#[path = "native_command_summary.rs"]
mod native_commands;
pub(super) use native_commands::validate as validate_native_commands;

#[path = "compiled_latex_summary.rs"]
mod compiled_latex;
pub(super) use compiled_latex::validate as validate_compiled_latex;

#[path = "upgrade_summary.rs"]
mod upgrade;

pub(super) fn validate_upgrade(stdout: &[u8], candidate: &str, baseline: &str) -> Result<Value> {
    upgrade::validate(stdout, candidate, baseline)
}

pub(super) fn validate_schema8_upgrade(
    stdout: &[u8],
    candidate: &str,
    baseline: &str,
) -> Result<Value> {
    upgrade::validate_schema8(stdout, candidate, baseline)
}

fn extract<T: serde::de::DeserializeOwned>(stdout: &[u8], marker: &str) -> Result<T> {
    let text = std::str::from_utf8(stdout).map_err(|_| "qualification output is not UTF-8")?;
    let mut lines = text.lines().filter_map(|line| line.split_once(marker));
    let (_, value) = lines
        .next()
        .ok_or("required qualification summary missing")?;
    if lines.next().is_some() || value.len() > 32_768 {
        return Err("duplicate or oversized qualification summary".into());
    }
    serde_json::from_str(value).map_err(|_| "qualification summary schema invalid".into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Workspace {
    ok: bool,
    binary_sha256: String,
    git_tools_checked: u64,
    utf8_continuation_lossless: bool,
    changed_file_denied: bool,
    blame_continuation_preserved: bool,
    child_path: String,
    native_execution_tested: bool,
    web_client_tested: bool,
    release_qualified: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Flow {
    states: Vec<String>,
    sealed: bool,
    artifact_matches: bool,
    restart_resumed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lifecycle {
    ok: bool,
    binary_sha256: String,
    flows: BTreeMap<String, Flow>,
    persisted_secret_owner_only: bool,
    same_key_restart: bool,
    changed_key_old_bearer_denied: bool,
    changed_key_old_capability_zero_writes: bool,
    same_owner_fresh_recovery: bool,
    copied_v1_state_migrated: bool,
    legacy_row_preserved: bool,
    new_run_after_migration: bool,
    verifier_firewall: bool,
    no_premature_artifact: bool,
    clean_shutdown: bool,
    native_execution_tested: bool,
    latex_policy: String,
    web_client_tested: bool,
    independent_mathematical_verification: bool,
    release_qualified: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetRuntime {
    ok: bool,
    binary_sha256: String,
    native_execution_tested: bool,
    native_mode: String,
    native_backend: String,
    hard_isolation_attested: bool,
    private_vault_visible: bool,
    compiled_latex_tested: bool,
    latex_policy: String,
    flow: Flow,
    web_client_tested: bool,
    independent_mathematical_verification: bool,
    resource_non_regression_tested: bool,
    install_or_selector_changed: bool,
    release_qualified: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceMetrics {
    startup_samples: u64,
    request_samples: u64,
    startup_p50_ms: f64,
    startup_p95_ms: f64,
    request_p95_ms: f64,
    max_rss_kib: u64,
    max_threads: u64,
    max_fds: u64,
    max_shutdown_ms: f64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceRuntime {
    ok: bool,
    candidate_sha256: String,
    baseline_sha256: String,
    baseline: ResourceMetrics,
    candidate: ResourceMetrics,
    resource_non_regression_tested: bool,
    native_execution_tested: bool,
    native_mode: String,
    native_backend: String,
    request_workload: String,
    permission_grant_soak_tested: bool,
    web_client_tested: bool,
    install_or_selector_changed: bool,
    performance_claim: bool,
    release_qualified: bool,
}

fn metric_shape(value: &ResourceMetrics) -> bool {
    value.startup_samples == 3
        && value.request_samples == 180
        && [
            value.startup_p50_ms,
            value.startup_p95_ms,
            value.request_p95_ms,
            value.max_shutdown_ms,
        ]
        .into_iter()
        .all(|number| number.is_finite() && number >= 0.0)
        && value.startup_p95_ms >= value.startup_p50_ms
        && value.max_rss_kib > 0
        && value.max_threads > 0
        && value.max_fds > 0
}

fn resource_bounds(candidate: &ResourceMetrics, baseline: &ResourceMetrics) -> bool {
    metric_shape(candidate)
        && metric_shape(baseline)
        && candidate.startup_p95_ms
            <= (2.0 * baseline.startup_p95_ms).max(baseline.startup_p95_ms + 250.0)
        && candidate.request_p95_ms
            <= (2.0 * baseline.request_p95_ms).max(baseline.request_p95_ms + 10.0)
        && candidate.max_rss_kib <= 262_144_u64.min(baseline.max_rss_kib.saturating_add(32_768))
        && candidate.max_threads <= baseline.max_threads.saturating_add(2)
        && candidate.max_fds <= baseline.max_fds.saturating_add(8)
        && candidate.max_shutdown_ms <= 8_000.0
}

pub(super) fn validate_resource(
    stdout: &[u8],
    candidate_hash: &str,
    baseline_hash: &str,
) -> Result<Value> {
    if [
        "MTM_UPGRADE_RUNTIME ",
        "MTM_SCHEMA8_UPGRADE_RUNTIME ",
        "MTM_PERMISSION_RUNTIME ",
        "MTM_USABILITY_CORPUS ",
        "MTM_RETRIEVAL_RUNTIME ",
    ]
    .iter()
    .any(|marker| std::str::from_utf8(stdout).is_ok_and(|text| text.contains(marker)))
    {
        return Err("resource output contains foreign profile evidence".into());
    }
    let resource: ResourceRuntime = extract(stdout, "MTM_RESOURCE_RUNTIME ")?;
    if !valid_hash(candidate_hash)
        || !valid_hash(baseline_hash)
        || candidate_hash == baseline_hash
        || resource.candidate_sha256 != candidate_hash
        || resource.baseline_sha256 != baseline_hash
        || !resource.ok
        || !resource.resource_non_regression_tested
        || !resource.native_execution_tested
        || resource.native_mode != "dangerous"
        || resource.native_backend != "bubblewrap"
        || resource.request_workload != "server_info_and_public_exec_command"
        || resource.permission_grant_soak_tested
        || resource.web_client_tested
        || resource.install_or_selector_changed
        || resource.performance_claim
        || resource.release_qualified
        || !resource_bounds(&resource.candidate, &resource.baseline)
    {
        return Err("resource summary has inconsistent identity, scope or bounds".into());
    }
    Ok(json!({"resource":extract::<Value>(stdout,"MTM_RESOURCE_RUNTIME ")?}))
}

pub(super) fn validate(stdout: &[u8], hash: &str, profile: Profile) -> Result<Value> {
    if [
        "MTM_UPGRADE_RUNTIME ",
        "MTM_SCHEMA8_UPGRADE_RUNTIME ",
        "MTM_PERMISSION_RUNTIME ",
        "MTM_USABILITY_CORPUS ",
        "MTM_RETRIEVAL_RUNTIME ",
    ]
    .iter()
    .any(|marker| std::str::from_utf8(stdout).is_ok_and(|text| text.contains(marker)))
    {
        return Err("protocol/target output contains foreign profile evidence".into());
    }
    if !matches!(profile, Profile::Protocol | Profile::Target) {
        return Err("selected profile requires its own explicit summary validation".into());
    }
    let capability = capability::checked_summary(stdout)?;
    let workspace: Workspace = extract(stdout, "MTM_WORKSPACE_SMOKE ")?;
    let lifecycle: Lifecycle = extract(stdout, "MTM_CANDIDATE_LIFECYCLE ")?;
    if !valid_hash(hash)
        || capability["binary_sha256"] != hash
        || workspace.binary_sha256 != hash
        || lifecycle.binary_sha256 != hash
        || !workspace.ok
        || workspace.git_tools_checked != 5
        || !workspace.utf8_continuation_lossless
        || !workspace.changed_file_denied
        || !workspace.blame_continuation_preserved
        || workspace.child_path != "curl_and_git_only"
        || workspace.native_execution_tested
        || workspace.web_client_tested
        || workspace.release_qualified
        || !lifecycle.ok
        || !lifecycle.persisted_secret_owner_only
        || !lifecycle.same_key_restart
        || !lifecycle.changed_key_old_bearer_denied
        || !lifecycle.changed_key_old_capability_zero_writes
        || !lifecycle.same_owner_fresh_recovery
        || !lifecycle.copied_v1_state_migrated
        || !lifecycle.legacy_row_preserved
        || !lifecycle.new_run_after_migration
        || !lifecycle.verifier_firewall
        || !lifecycle.no_premature_artifact
        || !lifecycle.clean_shutdown
        || lifecycle.native_execution_tested
        || lifecycle.latex_policy != "static_only"
        || lifecycle.web_client_tested
        || lifecycle.independent_mathematical_verification
        || lifecycle.release_qualified
    {
        return Err("candidate summaries have inconsistent identity, scope or checks".into());
    }
    let expected = BTreeMap::from([
        ("compact", vec!["assess", "assemble", "verify", "done"]),
        (
            "full",
            vec![
                "assess",
                "explore",
                "propose_plans",
                "direct_proving",
                "assemble",
                "verify",
                "done",
            ],
        ),
        (
            "repair",
            vec!["assess", "assemble", "verify", "repair", "verify", "done"],
        ),
    ]);
    if lifecycle.flows.len() != expected.len() {
        return Err("candidate flow coverage incomplete".into());
    }
    for (name, states) in expected {
        let flow = lifecycle.flows.get(name).ok_or("candidate flow missing")?;
        if flow.states != states || !flow.sealed || !flow.artifact_matches || !flow.restart_resumed
        {
            return Err("candidate flow did not complete its exact expected route".into());
        }
    }
    let target = if profile == Profile::Target {
        let target: TargetRuntime = extract(stdout, "MTM_TARGET_RUNTIME ")?;
        if !target.ok
            || target.binary_sha256 != hash
            || !target.native_execution_tested
            || target.native_mode != "dangerous"
            || target.native_backend != "bubblewrap"
            || !target.hard_isolation_attested
            || target.private_vault_visible
            || !target.compiled_latex_tested
            || target.latex_policy != "required"
            || target.flow.states != vec!["assess", "assemble", "verify", "done"]
            || !target.flow.sealed
            || !target.flow.artifact_matches
            || !target.flow.restart_resumed
            || target.web_client_tested
            || target.independent_mathematical_verification
            || target.resource_non_regression_tested
            || target.install_or_selector_changed
            || target.release_qualified
        {
            return Err(
                "target candidate summary has inconsistent identity, scope or checks".into(),
            );
        }
        Some(extract::<Value>(stdout, "MTM_TARGET_RUNTIME ")?)
    } else {
        // Protocol qualification must not accidentally consume target-only claims.
        if std::str::from_utf8(stdout)
            .map_err(|_| "qualification output is not UTF-8")?
            .contains("MTM_TARGET_RUNTIME ")
        {
            return Err(
                "protocol profile unexpectedly emitted target qualification evidence".into(),
            );
        }
        None
    };
    Ok(json!({"capability":capability,
        "workspace":extract::<Value>(stdout,"MTM_WORKSPACE_SMOKE ")?,
        "lifecycle":extract::<Value>(stdout,"MTM_CANDIDATE_LIFECYCLE ")?,
        "target":target}))
}
