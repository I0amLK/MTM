//! MTM-017 closed U27/U28 observations. Read-only, zero accepted delta.
use crate::{Result, capability, evidence_json};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path};
mod files;
#[cfg(test)]
mod tests;
const CANDIDATE: &str = "13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4";
const AUTH: (&str, &str) = (
    "records/evidence/MTM-017/u27-u28-operator-mapping-authorization-20260930.json",
    "3fded16a067a77f6935aca556593e2c955563562c1ec8bf02a76d138ba24fcbc",
);
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    path: String,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    schema: String,
    milestone: String,
    candidate_sha256: String,
    harness_source_sha256: String,
    authorization: Reference,
    trials: Vec<Reference>,
}
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    database_sha256: String,
    workspace_sha256: String,
    private_files_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    pid: u64,
    root_sha256: String,
    owner_sha256: String,
    session_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Permission {
    calls: u64,
    before: Snapshot,
    after: Snapshot,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Boundary {
    before: Snapshot,
    after: Snapshot,
    hard_isolation_attested: bool,
    native_positive: bool,
    workspace_api_positive: bool,
    native_private_read_denied: bool,
    native_private_write_denied: bool,
    workspace_escape_denied: bool,
    invalid_workflow_read_denied: bool,
    foreign_owner_step_denied: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Phase {
    phase: String,
    identity: Identity,
    permission: Permission,
    boundary: Option<Boundary>,
    compatibility_marker_fixed: bool,
    expiry_null: bool,
    elicitation_seen: bool,
    business_effects_from_requests: bool,
    grant_or_consent_ledger_present: bool,
    before: Snapshot,
    after: Snapshot,
    boundaries_checked: String,
    positive_control_passed: bool,
    negative_effects: bool,
    children_reaped: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    schema: String,
    milestone: String,
    task_id: String,
    repeat: u64,
    trial_id: String,
    candidate_sha256: String,
    harness_source_sha256: String,
    version: String,
    state_schema: u64,
    workflow_protocol: u64,
    tool_contract: String,
    started_unix_ms: u64,
    finished_unix_ms: u64,
    phases: Vec<Phase>,
    passed: bool,
    clean_shutdown: bool,
    synthetic_state_only: bool,
    human_consent_tested: bool,
    accepted_delta: u64,
    production_selector_changed: bool,
    production_state_modified: bool,
    release_qualified: bool,
    deployment_authorized: bool,
}
fn check(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err("schema8 authority observation contract mismatch; no acceptance".into())
    }
}
fn hash(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn snapshot(v: &Snapshot) -> bool {
    [
        &v.database_sha256,
        &v.workspace_sha256,
        &v.private_files_sha256,
    ]
    .iter()
    .all(|s| hash(s))
}
fn validate(v: &Observation, source: &str) -> Result<()> {
    check(
        v.schema == "mtm017-authority-observation-v1"
            && v.milestone == "MTM-017"
            && ["U27", "U28"].contains(&v.task_id.as_str())
            && (1..=3).contains(&v.repeat)
            && (16..=96).contains(&v.trial_id.len())
            && v.trial_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
    )?;
    check(
        v.candidate_sha256 == CANDIDATE
            && v.harness_source_sha256 == source
            && hash(source)
            && v.version == "0.6.0-preview.2"
            && v.state_schema == 8
            && v.workflow_protocol == 3
            && v.tool_contract == "mtm-tools-v10",
    )?;
    check(
        v.passed
            && v.clean_shutdown
            && v.synthetic_state_only
            && !v.human_consent_tested
            && v.accepted_delta == 0
            && !v.production_selector_changed
            && !v.production_state_modified
            && !v.release_qualified
            && !v.deployment_authorized,
    )?;
    let current_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    check(
        v.started_unix_ms >= 1790726400000
            && v.finished_unix_ms < 1790812800000
            && u128::from(v.finished_unix_ms) <= current_ms
            && v.finished_unix_ms > v.started_unix_ms
            && v.finished_unix_ms - v.started_unix_ms <= 300000
            && v.phases.len() == 3,
    )?;
    let first = &v.phases[0].identity;
    let mut sessions = BTreeSet::new();
    for (p, label) in v.phases.iter().zip(["initial", "reconnect", "restart"]) {
        check(
            p.phase == label
                && p.identity.pid > 0
                && p.identity.root_sha256 == first.root_sha256
                && p.identity.owner_sha256 == first.owner_sha256
                && hash(&p.identity.root_sha256)
                && hash(&p.identity.owner_sha256)
                && hash(&p.identity.session_sha256)
                && sessions.insert(&p.identity.session_sha256),
        )?;
        check(if label == "restart" {
            p.identity.pid != first.pid
        } else {
            p.identity.pid == first.pid
        })?;
        check(
            p.compatibility_marker_fixed
                && p.expiry_null
                && !p.elicitation_seen
                && !p.business_effects_from_requests
                && !p.grant_or_consent_ledger_present
                && !p.negative_effects
                && p.children_reaped
                && p.permission.calls == 8
                && p.permission.before == p.permission.after
                && p.permission.before == p.before
                && snapshot(&p.before)
                && snapshot(&p.after),
        )?;
        if v.task_id == "U27" {
            check(
                p.before == p.after
                    && p.boundary.is_none()
                    && !p.positive_control_passed
                    && p.boundaries_checked == "disabled_exec",
            )?;
        } else {
            let b = p.boundary.as_ref().ok_or("native boundary missing")?;
            check(
                p.positive_control_passed
                    && p.boundaries_checked == "native_private_workspace_workflow"
                    && b.before == b.after
                    && b.after == p.after
                    && b.before.database_sha256 == p.before.database_sha256
                    && b.before.private_files_sha256 == p.before.private_files_sha256
                    && b.before.workspace_sha256 != p.before.workspace_sha256
                    && b.hard_isolation_attested
                    && b.native_positive
                    && b.workspace_api_positive
                    && b.native_private_read_denied
                    && b.native_private_write_denied
                    && b.workspace_escape_denied
                    && b.invalid_workflow_read_denied
                    && b.foreign_owner_step_denied,
            )?;
        }
    }
    for pair in v.phases.windows(2) {
        check(pair[0].after == pair[1].before)?;
    }
    Ok(())
}
fn path(path: &str) -> bool {
    path.strip_prefix("records/evidence/MTM-017/")
        .is_some_and(|v| {
            !v.contains('/')
                && v.ends_with(".json")
                && v.len() < 180
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn collection(items: &[(&Reference, Observation)], source: &str) -> Result<()> {
    check(items.len() == 6)?;
    let mut cells = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut roots = BTreeSet::new();
    let mut owners = BTreeSet::new();
    let mut pids = BTreeSet::new();
    let mut sessions = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut windows = Vec::new();
    for (r, o) in items {
        validate(o, source)?;
        check(
            path(&r.path)
                && hash(&r.sha256)
                && hashes.insert(&r.sha256)
                && paths.insert(&r.path)
                && cells.insert((&o.task_id, o.repeat))
                && ids.insert(&o.trial_id)
                && roots.insert(&o.phases[0].identity.root_sha256)
                && owners.insert(&o.phases[0].identity.owner_sha256),
        )?;
        for p in [&o.phases[0], &o.phases[2]] {
            check(pids.insert(p.identity.pid))?;
        }
        for p in &o.phases {
            check(sessions.insert(&p.identity.session_sha256))?;
        }
        windows.push((o.started_unix_ms, o.finished_unix_ms));
    }
    windows.sort();
    for pair in windows.windows(2) {
        check(pair[0].1 < pair[1].0)?;
    }
    Ok(())
}
/// Historical public receipt validation only. The source in the sealed inputs
/// is an observed harness identity, not the current source or a Git-tree claim.
pub(crate) fn archived_public_rows(
    value: &Value,
    documents: &std::collections::BTreeMap<String, Value>,
) -> Result<Vec<Value>> {
    let inputs: Inputs = serde_json::from_value(value.clone())?;
    check(
        inputs.schema == "mtm017-authority-inputs-v1"
            && inputs.milestone == "MTM-017"
            && inputs.candidate_sha256 == CANDIDATE
            && inputs.authorization.path == AUTH.0
            && inputs.authorization.sha256 == AUTH.1
            && hash(&inputs.harness_source_sha256)
            && inputs.trials.len() == 6,
    )?;
    let mut observations = Vec::new();
    let mut rows = Vec::new();
    for r in &inputs.trials {
        check(path(&r.path) && hash(&r.sha256))?;
        let value = documents
            .get(&r.path)
            .ok_or("archived authority receipt missing")?;
        let o: Observation = serde_json::from_value(value.clone())?;
        validate(&o, &inputs.harness_source_sha256)?;
        rows.push(json!({"task_id":o.task_id,"repeat":o.repeat,"trial_id":o.trial_id,"raw":{"path":r.path,"sha256":r.sha256}}));
        observations.push((r, o));
    }
    collection(&observations, &inputs.harness_source_sha256)?;
    Ok(rows)
}

pub(crate) fn run(root: &Path, args: &[String]) -> Result<Value> {
    check(args.len() == 2 && args[0] == "--inputs" && path(&args[1]))?;
    let input = files::read(root, &args[1], 1024 * 1024, false)?;
    let value = evidence_json::decode(&input.bytes)?;
    let inputs: Inputs =
        serde_json::from_value(value).map_err(|_| "closed authority input invalid")?;
    let source = capability::source_hash(root)?;
    check(
        inputs.schema == "mtm017-authority-inputs-v1"
            && inputs.milestone == "MTM-017"
            && inputs.candidate_sha256 == CANDIDATE
            && inputs.harness_source_sha256 == source
            && inputs.authorization.path == AUTH.0
            && inputs.authorization.sha256 == AUTH.1
            && inputs.trials.len() == 6,
    )?;
    let auth = files::read(root, AUTH.0, 1024 * 1024, false)?;
    check(digest(&auth.bytes) == AUTH.1)?;
    let mut observations = Vec::new();
    let mut rows = Vec::new();
    let mut seals = Vec::new();
    for r in &inputs.trials {
        check(path(&r.path) && hash(&r.sha256))?;
        let bytes = files::read(root, &r.path, 1024 * 1024, false)?;
        check(digest(&bytes.bytes) == r.sha256)?;
        let o: Observation = serde_json::from_value(evidence_json::decode(&bytes.bytes)?)
            .map_err(|_| "closed authority observation invalid")?;
        validate(&o, &source)?;
        rows.push(json!({"task_id":o.task_id,"repeat":o.repeat,"trial_id":o.trial_id,"raw":{"path":r.path,"sha256":r.sha256},"state":"observed_pass","accepted":false}));
        observations.push((r, o));
        seals.push((r, bytes));
    }
    collection(&observations, &source)?;
    for (r, s) in seals {
        s.recheck(&files::read(root, &r.path, 1024 * 1024, false)?)?;
    }
    input.recheck(&files::read(root, &args[1], 1024 * 1024, false)?)?;
    auth.recheck(&files::read(root, AUTH.0, 1024 * 1024, false)?)?;
    check(source == capability::source_hash(root)?)?;
    Ok(
        json!({"schema":"mtm017-authority-observation-collection-v1","milestone":"MTM-017","candidate_sha256":CANDIDATE,"harness_source_sha256":source,"inputs":{"path":args[1],"sha256":digest(&input.bytes)},"observed_trials":6,"rows":rows,"accepted_delta":0,"corpus_count_incremented":false,"implementation_complete":"unknown","research_accepted":false,"human_consent_tested":false,"full_corpus_accepted":false,"production_selector_changed":false,"production_state_modified":false,"release_qualified":false,"deployment_authorized":false}),
    )
}
