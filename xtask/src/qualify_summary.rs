//! All three independent fixture summaries must bind the selected artifact.
use super::*;
use serde::Deserialize;

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

pub(super) fn validate(stdout: &[u8], hash: &str, profile: Profile) -> Result<Value> {
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
