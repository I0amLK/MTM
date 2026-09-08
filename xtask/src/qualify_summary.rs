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

pub(super) fn validate(stdout: &[u8], hash: &str) -> Result<Value> {
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
    Ok(json!({"capability":capability,
        "workspace":extract::<Value>(stdout,"MTM_WORKSPACE_SMOKE ")?,
        "lifecycle":extract::<Value>(stdout,"MTM_CANDIDATE_LIFECYCLE ")?}))
}
