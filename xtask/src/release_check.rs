//! Read-only release blockers. No deployment or human-review authority.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    Result, capability, check_report, evidence_json, git, inventory, qualify, records, retirement,
};

const GATES: [&str; 14] = [
    "source",
    "protocol",
    "permissions",
    "upgrade",
    "target",
    "resource",
    "clean_build",
    "native_commands",
    "compiled_latex",
    "retrieval",
    "browser_human",
    "copied_operator_state",
    "install_sigkill",
    "corpus",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRef {
    path: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    milestone: String,
    candidate_sha256: String,
    candidate_source_commit: String,
    baseline_sha256: String,
    evidence: BTreeMap<String, EvidenceRef>,
}

pub(crate) struct Options {
    binary: String,
    manifest: String,
    pub record: bool,
}

impl Options {
    pub(crate) fn parse(args: &[String]) -> Result<Self> {
        let mut values = BTreeMap::new();
        let mut record = false;
        let mut input = args.iter();
        while let Some(key) = input.next() {
            if key == "--record" && !record {
                record = true;
                continue;
            }
            if !["--binary", "--manifest"].contains(&key.as_str()) || values.contains_key(key) {
                return Err("unknown or duplicate release-check option".into());
            }
            let value = input
                .next()
                .filter(|v| !v.is_empty() && !v.starts_with("--"))
                .ok_or("release-check option requires a value")?;
            values.insert(key.clone(), value.clone());
        }
        Ok(Self {
            binary: values
                .remove("--binary")
                .ok_or("explicit binary required")?,
            manifest: values
                .remove("--manifest")
                .ok_or("explicit evidence manifest required")?,
            record,
        })
    }
}

fn hash(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn decode(bytes: &[u8]) -> Result<Manifest> {
    let manifest: Manifest = serde_json::from_value(evidence_json::decode(bytes)?)
        .map_err(|_| "release input schema invalid")?;
    if manifest.schema != "mtm-release-inputs-v1"
        || manifest.milestone != "MTM-016"
        || !hash(&manifest.candidate_sha256, 64)
        || !hash(&manifest.baseline_sha256, 64)
        || manifest.candidate_sha256 == manifest.baseline_sha256
        || !hash(&manifest.candidate_source_commit, 40)
        || manifest.evidence.len() > GATES.len()
    {
        return Err("release input identity invalid".into());
    }
    let mut paths = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    for (gate, evidence) in &manifest.evidence {
        if !GATES.contains(&gate.as_str())
            || !hash(&evidence.sha256, 64)
            || !evidence.path.starts_with("records/evidence/MTM-016/")
            || !paths.insert(&evidence.path)
            || !hashes.insert(&evidence.sha256)
        {
            return Err("unknown, duplicated or historical release evidence".into());
        }
    }
    Ok(manifest)
}

fn product_path(path: &str) -> bool {
    [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        ".cargo/config.toml",
    ]
    .contains(&path)
        || (path.starts_with("crates/") && !path.contains("/tests/"))
}

fn same_product(root: &Path, commit: &str) -> Result<bool> {
    git(root, &["merge-base", "--is-ancestor", commit, "HEAD"])?;
    // Include uncommitted product changes and untracked product files as blockers.
    let changed = git(root, &["diff", "--name-only", "-z", commit, "--"])?;
    let untracked = git(root, &["ls-files", "-z", "--others", "--exclude-standard"])?;
    for bytes in [&changed, &untracked] {
        for name in bytes.split(|b| *b == 0).filter(|v| !v.is_empty()) {
            if product_path(std::str::from_utf8(name)?) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn lineage(root: &Path, identity: &Value, cache: &mut BTreeMap<String, String>) -> Result<()> {
    let commit = identity["commit"]
        .as_str()
        .ok_or("missing evidence source commit")?;
    let before = identity["before_sha256"]
        .as_str()
        .ok_or("missing evidence source hash")?;
    if !hash(commit, 40)
        || !hash(before, 64)
        || identity["after_sha256"] != before
        || identity["unchanged"] != true
        || !same_product(root, commit)?
    {
        return Err("evidence source lineage mismatch".into());
    }
    if !cache.contains_key(commit) {
        cache.insert(commit.to_owned(), capability::source_hash_at(root, commit)?);
    }
    if cache.get(commit).map(String::as_str) != Some(before) {
        return Err("evidence harness hash differs from committed source".into());
    }
    Ok(())
}

fn supported(name: &str) -> bool {
    matches!(
        name,
        "source"
            | "protocol"
            | "permissions"
            | "upgrade"
            | "target"
            | "resource"
            | "clean_build"
            | "native_commands"
            | "compiled_latex"
            | "retrieval"
            | "browser_human"
            | "copied_operator_state"
            | "install_sigkill"
            | "corpus"
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeCommandEvidence {
    schema: String,
    milestone: String,
    candidate_sha256: String,
    candidate_source_commit: String,
    scope: String,
    native_backend: String,
    hard_isolation_attested: bool,
    safe_mode_passed: bool,
    trusted_mode_passed: bool,
    dangerous_mode_passed: bool,
    tty_stdin_passed: bool,
    timeout_kill_passed: bool,
    descendant_cleanup_passed: bool,
    sage_functional_passed: bool,
    magma_functional_passed: bool,
    permission_grant_soak_passed: bool,
    production_changed: bool,
    release_qualified: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompiledLatexEvidence {
    schema: String,
    milestone: String,
    candidate_sha256: String,
    candidate_source_commit: String,
    scope: String,
    native_backend: String,
    hard_isolation_attested: bool,
    latex_policy: String,
    latexmk_used: bool,
    pdflatex_used: bool,
    shell_escape_disabled: bool,
    full_flow_compiled: bool,
    compact_flow_compiled: bool,
    repair_flow_compiled: bool,
    final_artifacts_verified: bool,
    production_changed: bool,
    release_qualified: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetrievalEvidence {
    schema: String,
    milestone: String,
    candidate_sha256: String,
    candidate_source_commit: String,
    scope: String,
    actual_external_retrieval: bool,
    https_only: bool,
    redirect_policy_checked: bool,
    request_count: u64,
    independent_source_count: u64,
    raw_credentials_recorded: bool,
    production_changed: bool,
    release_qualified: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserHumanEvidence {
    schema: String,
    milestone: String,
    candidate_sha256: String,
    candidate_source_commit: String,
    scope: String,
    actual_web_client: bool,
    oauth_dcr_pkce_passed: bool,
    protected_resource_metadata_passed: bool,
    human_consent_observed: bool,
    independent_observer: bool,
    paired_roundtrips: u64,
    capability_invalid_count: u64,
    submission_rejection_count: u64,
    raw_token_recorded: bool,
    raw_secret_recorded: bool,
    production_changed: bool,
    release_qualified: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CopiedOperatorStateEvidence {
    schema: String,
    milestone: String,
    candidate_sha256: String,
    candidate_source_commit: String,
    scope: String,
    operator_authorized: bool,
    source_was_copy: bool,
    production_read_only: bool,
    production_modified: bool,
    preupgrade_copy_preserved: bool,
    schema_before: u64,
    schema_candidate: u64,
    schema_restored: u64,
    migration_passed: bool,
    old_run_resumed_on_candidate: bool,
    rollback_passed: bool,
    restored_old_runtime_resumed: bool,
    raw_private_state_recorded: bool,
    release_qualified: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusAggregateRef {
    path: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusSupplementRef {
    task_id: String,
    repeat: u64,
    path: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusAggregate {
    schema: String,
    milestone: String,
    candidate_sha256: String,
    candidate_source_commit: String,
    corpus_sha256: String,
    base: CorpusAggregateRef,
    supplements: Vec<CorpusSupplementRef>,
    passed_trials: u64,
    failed_trials: u64,
    blocked_trials: u64,
    complete: bool,
    production_changed: bool,
    release_qualified: bool,
}

fn identity_matches(
    candidate_sha256: &str,
    candidate_source_commit: &str,
    manifest: &Manifest,
) -> bool {
    candidate_sha256 == manifest.candidate_sha256
        && candidate_source_commit == manifest.candidate_source_commit
}

fn validate_native_commands(value: &Value, manifest: &Manifest) -> Result<bool> {
    let evidence: NativeCommandEvidence = serde_json::from_value(value.clone())
        .map_err(|_| "Native command evidence schema invalid")?;
    if evidence.schema != "mtm-native-command-evidence-v1"
        || evidence.milestone != "MTM-016"
        || !identity_matches(
            &evidence.candidate_sha256,
            &evidence.candidate_source_commit,
            manifest,
        )
        || evidence.scope != "capable_host_native_command_and_permission_soak"
        || evidence.native_backend != "bubblewrap"
        || !evidence.hard_isolation_attested
        || !evidence.safe_mode_passed
        || !evidence.trusted_mode_passed
        || !evidence.dangerous_mode_passed
        || !evidence.tty_stdin_passed
        || !evidence.timeout_kill_passed
        || !evidence.descendant_cleanup_passed
        || !evidence.sage_functional_passed
        || !evidence.magma_functional_passed
        || !evidence.permission_grant_soak_passed
        || evidence.production_changed
        || evidence.release_qualified
    {
        return Err("Native command evidence identity or required behavior invalid".into());
    }
    Ok(true)
}

fn validate_compiled_latex(value: &Value, manifest: &Manifest) -> Result<bool> {
    let evidence: CompiledLatexEvidence = serde_json::from_value(value.clone())
        .map_err(|_| "compiled LaTeX evidence schema invalid")?;
    if evidence.schema != "mtm-compiled-latex-evidence-v1"
        || evidence.milestone != "MTM-016"
        || !identity_matches(
            &evidence.candidate_sha256,
            &evidence.candidate_source_commit,
            manifest,
        )
        || evidence.scope != "required_latex_full_compact_repair"
        || evidence.native_backend != "bubblewrap"
        || !evidence.hard_isolation_attested
        || evidence.latex_policy != "required"
        || !evidence.latexmk_used
        || !evidence.pdflatex_used
        || !evidence.shell_escape_disabled
        || !evidence.full_flow_compiled
        || !evidence.compact_flow_compiled
        || !evidence.repair_flow_compiled
        || !evidence.final_artifacts_verified
        || evidence.production_changed
        || evidence.release_qualified
    {
        return Err("compiled LaTeX evidence identity or required flow invalid".into());
    }
    Ok(true)
}

fn validate_retrieval(value: &Value, manifest: &Manifest) -> Result<bool> {
    let evidence: RetrievalEvidence =
        serde_json::from_value(value.clone()).map_err(|_| "retrieval evidence schema invalid")?;
    if evidence.schema != "mtm-retrieval-evidence-v1"
        || evidence.milestone != "MTM-016"
        || !identity_matches(
            &evidence.candidate_sha256,
            &evidence.candidate_source_commit,
            manifest,
        )
        || evidence.scope != "real_external_retrieval_and_redirect_policy"
        || !evidence.actual_external_retrieval
        || !evidence.https_only
        || !evidence.redirect_policy_checked
        || !(3..=100).contains(&evidence.request_count)
        || !(2..=100).contains(&evidence.independent_source_count)
        || evidence.independent_source_count > evidence.request_count
        || evidence.raw_credentials_recorded
        || evidence.production_changed
        || evidence.release_qualified
    {
        return Err("retrieval evidence identity, count or policy invalid".into());
    }
    Ok(true)
}

fn validate_browser_human(value: &Value, manifest: &Manifest) -> Result<bool> {
    let evidence: BrowserHumanEvidence = serde_json::from_value(value.clone())
        .map_err(|_| "browser/human evidence schema invalid")?;
    if evidence.schema != "mtm-browser-human-evidence-v1"
        || evidence.milestone != "MTM-016"
        || !identity_matches(
            &evidence.candidate_sha256,
            &evidence.candidate_source_commit,
            manifest,
        )
        || evidence.scope != "real_web_client_and_independent_human_consent"
        || !evidence.actual_web_client
        || !evidence.oauth_dcr_pkce_passed
        || !evidence.protected_resource_metadata_passed
        || !evidence.human_consent_observed
        || !evidence.independent_observer
        || !(5..=100).contains(&evidence.paired_roundtrips)
        || evidence.capability_invalid_count != 0
        || evidence.submission_rejection_count != 0
        || evidence.raw_token_recorded
        || evidence.raw_secret_recorded
        || evidence.production_changed
        || evidence.release_qualified
    {
        return Err("browser/human evidence identity or acceptance invalid".into());
    }
    Ok(true)
}

fn validate_copied_operator_state(value: &Value, manifest: &Manifest) -> Result<bool> {
    let evidence: CopiedOperatorStateEvidence = serde_json::from_value(value.clone())
        .map_err(|_| "copied operator-state evidence schema invalid")?;
    if evidence.schema != "mtm-copied-operator-state-evidence-v1"
        || evidence.milestone != "MTM-016"
        || !identity_matches(
            &evidence.candidate_sha256,
            &evidence.candidate_source_commit,
            manifest,
        )
        || evidence.scope != "operator_authorized_copied_state_upgrade_and_rollback"
        || !evidence.operator_authorized
        || !evidence.source_was_copy
        || !evidence.production_read_only
        || evidence.production_modified
        || !evidence.preupgrade_copy_preserved
        || !(1..=6).contains(&evidence.schema_before)
        || evidence.schema_candidate != 7
        || evidence.schema_restored != evidence.schema_before
        || !evidence.migration_passed
        || !evidence.old_run_resumed_on_candidate
        || !evidence.rollback_passed
        || !evidence.restored_old_runtime_resumed
        || evidence.raw_private_state_recorded
        || evidence.release_qualified
    {
        return Err("copied operator-state evidence identity or rollback invalid".into());
    }
    Ok(true)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanBuildEvidence {
    schema: String,
    milestone: String,
    source_commit: String,
    selected_candidate_sha256: String,
    clean_build_sha256: String,
    build_locked: bool,
    build_offline: bool,
    detached_clean_worktree: bool,
    build_exit_code: i64,
    exact_candidate_bytes_reproduced: bool,
    python_free_path_proven: bool,
    production_changed: bool,
    release_qualified: bool,
}

fn validate_clean_build(value: &Value, manifest: &Manifest) -> Result<bool> {
    let evidence: CleanBuildEvidence =
        serde_json::from_value(value.clone()).map_err(|_| "clean build evidence schema invalid")?;
    if evidence.schema != "mtm-clean-build-evidence-v1"
        || evidence.milestone != "MTM-016"
        || evidence.source_commit != manifest.candidate_source_commit
        || evidence.selected_candidate_sha256 != manifest.candidate_sha256
        || !hash(&evidence.clean_build_sha256, 64)
        || !evidence.build_locked
        || !evidence.build_offline
        || !evidence.detached_clean_worktree
        || evidence.build_exit_code != 0
        || evidence.production_changed
        || evidence.release_qualified
        || evidence.exact_candidate_bytes_reproduced
            != (evidence.clean_build_sha256 == evidence.selected_candidate_sha256)
    {
        return Err("clean build evidence identity, build result or scope invalid".into());
    }
    Ok(evidence.exact_candidate_bytes_reproduced && evidence.python_free_path_proven)
}

fn validate_corpus(value: &Value, manifest: &Manifest) -> Result<bool> {
    if value["schema_version"] != "1.0.0"
        || value["milestone"] != "MTM-016"
        || value["profile"] != "corpus"
        || value["delivery"] != "F5"
        || value["scope"] != "exact_candidate_partial_usability_corpus_not_release"
        || value["candidate_sha256"] != manifest.candidate_sha256
        || value["candidate_launched"] != true
        || !value["baseline_sha256"].is_null()
        || !value["baseline_launched"].is_null()
        || value["original_and_snapshot_unchanged"] != true
        || value["production_selectors_changed"] != false
        || value["production_state_modified"] != false
        || value["python_invoked"] != false
        || value["raw_test_output_recorded"] != false
        || value["release_qualified"] != false
        || value["selector_changed"] != false
        || value["runner"]["exit_code"] != 0
        || value["runner"]["child_reaped"] != true
        || value["runner"]["pipes_closed"] != true
        || value["runner"]["timed_out"] != false
        || value["runner"]["output_limit_exceeded"] != false
        || value["runner"]["raw_output_recorded"] != false
        || !value["runner"]["signal"].is_null()
    {
        return Err("corpus receipt identity, runner or scope invalid".into());
    }
    let complete =
        qualify::validate_corpus_summary(&value["summaries"], &manifest.candidate_sha256)?;
    if value["corpus_definition_sha256"] != value["summaries"]["corpus"]["corpus_sha256"]
        || value["passed"] != complete
        || (!complete
            && (value["failed_stage"] != "corpus_coverage"
                || value["failure"]
                    != "Corpus contains blocked or failed trials; completed trials remain recorded"))
    {
        return Err("corpus receipt completion state inconsistent".into());
    }
    Ok(complete)
}

fn checked_evidence(root: &Path, path: &str, expected: &str) -> Result<Value> {
    if !path.starts_with("records/evidence/MTM-016/") || !hash(expected, 64) {
        return Err("aggregate evidence reference is outside current milestone".into());
    }
    let bytes = records::read_bytes(root, path, 1024 * 1024)?;
    use sha2::{Digest, Sha256};
    if format!("{:x}", Sha256::digest(&bytes)) != expected {
        return Err("aggregate evidence hash mismatch".into());
    }
    evidence_json::decode(&bytes)
}

fn validate_corpus_aggregate(
    root: &Path,
    value: &Value,
    manifest: &Manifest,
    cache: &mut BTreeMap<String, String>,
) -> Result<bool> {
    let aggregate: CorpusAggregate =
        serde_json::from_value(value.clone()).map_err(|_| "corpus aggregate schema invalid")?;
    if aggregate.schema != "mtm-usability-corpus-aggregate-v1"
        || aggregate.milestone != "MTM-016"
        || aggregate.candidate_sha256 != manifest.candidate_sha256
        || aggregate.candidate_source_commit != manifest.candidate_source_commit
        || !hash(&aggregate.corpus_sha256, 64)
        || aggregate.supplements.len() != 3
        || aggregate.failed_trials != 0
        || aggregate.passed_trials + aggregate.failed_trials + aggregate.blocked_trials != 90
        || aggregate.production_changed
        || aggregate.release_qualified
    {
        return Err("corpus aggregate identity or counts invalid".into());
    }
    let base = checked_evidence(root, &aggregate.base.path, &aggregate.base.sha256)?;
    let base_complete = validate_corpus(&base, manifest)?;
    if base_complete
        || base["summaries"]["corpus"]["passed_trials"] != 45
        || base["summaries"]["corpus"]["failed_trials"] != 0
        || base["summaries"]["corpus"]["blocked_trials"] != 45
        || base["summaries"]["corpus"]["corpus_sha256"] != aggregate.corpus_sha256
    {
        return Err("corpus aggregate base is not the exact 45/45 partial matrix".into());
    }
    lineage(root, &base["harness_source_identity"], cache)?;

    let mut repeats = BTreeSet::new();
    let mut receipt_times = BTreeSet::new();
    let mut receipt_hashes = BTreeSet::new();
    for supplement in &aggregate.supplements {
        if supplement.task_id != "U30"
            || !(1..=3).contains(&supplement.repeat)
            || !repeats.insert(supplement.repeat)
            || !receipt_hashes.insert(&supplement.sha256)
        {
            return Err("corpus U30 supplements are duplicate or misidentified".into());
        }
        let receipt = checked_evidence(root, &supplement.path, &supplement.sha256)?;
        qualify::validate_receipt(
            &receipt,
            &manifest.candidate_sha256,
            &manifest.baseline_sha256,
            "install_sigkill",
        )?;
        lineage(root, &receipt["harness_source_identity"], cache)?;
        let recorded = receipt["recorded_unix_seconds"]
            .as_u64()
            .ok_or("U30 receipt timestamp missing")?;
        if !receipt_times.insert(recorded) {
            return Err("U30 repeats do not have distinct receipt timestamps".into());
        }
    }
    if aggregate.passed_trials != 48 || aggregate.blocked_trials != 42 || aggregate.complete {
        return Err(
            "corpus aggregate did not preserve the exact partial completion boundary".into(),
        );
    }
    Ok(false)
}

fn validate_evidence(
    root: &Path,
    name: &str,
    value: &Value,
    manifest: &Manifest,
    cache: &mut BTreeMap<String, String>,
) -> Result<bool> {
    if name == "source" {
        let identity = &value["source_identity"];
        let current = capability::source_hash(root)?;
        let checks = value["checks"].as_array().ok_or("source checks missing")?;
        let evaluated = check_report::summarize(
            checks,
            &value["native_environment"],
            identity["unchanged"] == true,
        );
        if value["schema_version"] != "1.0.0"
            || value["milestone"] != "MTM-016"
            || value["scope"] != "rust_source_with_inherited_host_tests"
            || value["passed"] != true
            || evaluated["passed"] != true
            || identity["before_sha256"] != current
            || identity["after_sha256"] != current
            || value["tests_skipped_by_preflight"] != false
            || value["release_qualified"] != false
            || value["production_state_modified"] != false
            || value["production_selector_changed"] != false
        {
            return Err("current complete source gate has not passed".into());
        }
        return Ok(true);
    }
    if name == "corpus" {
        if value["schema"] == "mtm-usability-corpus-aggregate-v1" {
            return validate_corpus_aggregate(root, value, manifest, cache);
        }
        let complete = validate_corpus(value, manifest)?;
        lineage(root, &value["harness_source_identity"], cache)?;
        return Ok(complete);
    }
    if name == "clean_build" {
        return validate_clean_build(value, manifest);
    }
    if name == "native_commands" {
        if value["schema_version"] == "1.0.0" && value["profile"] == "native_commands" {
            qualify::validate_receipt(
                value,
                &manifest.candidate_sha256,
                &manifest.baseline_sha256,
                "native_commands",
            )?;
            lineage(root, &value["harness_source_identity"], cache)?;
            return Ok(true);
        }
        return validate_native_commands(value, manifest);
    }
    if name == "compiled_latex" {
        if value["schema_version"] == "1.0.0" && value["profile"] == "compiled_latex" {
            qualify::validate_receipt(
                value,
                &manifest.candidate_sha256,
                &manifest.baseline_sha256,
                "compiled_latex",
            )?;
            lineage(root, &value["harness_source_identity"], cache)?;
            return Ok(true);
        }
        return validate_compiled_latex(value, manifest);
    }
    if name == "retrieval" {
        if value["schema_version"] == "1.0.0" && value["profile"] == "retrieval" {
            qualify::validate_receipt(
                value,
                &manifest.candidate_sha256,
                &manifest.baseline_sha256,
                name,
            )?;
            lineage(root, &value["harness_source_identity"], cache)?;
            return Ok(true);
        }
        return validate_retrieval(value, manifest);
    }
    if name == "browser_human" {
        return validate_browser_human(value, manifest);
    }
    if name == "copied_operator_state" {
        return validate_copied_operator_state(value, manifest);
    }
    if name == "install_sigkill" {
        qualify::validate_receipt(
            value,
            &manifest.candidate_sha256,
            &manifest.baseline_sha256,
            name,
        )?;
        lineage(root, &value["harness_source_identity"], cache)?;
        return Ok(true);
    }
    qualify::validate_receipt(
        value,
        &manifest.candidate_sha256,
        &manifest.baseline_sha256,
        name,
    )?;
    lineage(root, &value["harness_source_identity"], cache)?;
    Ok(true)
}

fn item(name: &str, status: &str, reason: &str) -> Value {
    json!({"gate":name,"status":status,"reason":reason})
}

pub(crate) fn run(root: &Path, options: &Options) -> Result<Value> {
    let bytes = records::read_bytes(root, &options.manifest, 64 * 1024)
        .map_err(|_| "release input manifest is missing or unsafe")?;
    let manifest = decode(&bytes)?;
    let binary = root.join(&options.binary);
    let actual = qualify::digest(&binary).map_err(|_| "release candidate is missing or unsafe")?;
    if actual != manifest.candidate_sha256
        || !same_product(root, &manifest.candidate_source_commit)?
    {
        return Err(
            "release candidate or current product source differs from selected identity".into(),
        );
    }
    let mut gates = Vec::new();
    let mut cache = BTreeMap::new();
    for name in GATES {
        let Some(reference) = manifest.evidence.get(name) else {
            gates.push(item(name, "blocked", "required_evidence_missing"));
            continue;
        };
        if !supported(name) {
            gates.push(item(
                name,
                "blocked",
                "reviewed_evidence_adapter_not_implemented",
            ));
            continue;
        }
        let result = (|| -> Result<bool> {
            let bytes = records::read_bytes(root, &reference.path, 1024 * 1024)?;
            use sha2::{Digest, Sha256};
            if format!("{:x}", Sha256::digest(&bytes)) != reference.sha256 {
                return Err("evidence hash mismatch".into());
            }
            validate_evidence(
                root,
                name,
                &evidence_json::decode(&bytes)?,
                &manifest,
                &mut cache,
            )
        })();
        let complete = result.as_ref().is_ok_and(|value| *value);
        let partial = result.as_ref().is_ok_and(|value| !*value);
        gates.push(item(
            name,
            if complete { "validated" } else { "blocked" },
            if complete {
                "sealed_scope_revalidated_not_reexecuted"
            } else if partial {
                "validated_partial_scope_not_required_real_world_acceptance"
            } else {
                "evidence_failed_identity_integrity_or_scope"
            },
        ));
    }
    for (name, result) in [
        ("record_integrity", records::validate(root)),
        ("retirement_provenance", retirement::validate(root)),
    ] {
        gates.push(item(
            name,
            if result.is_ok() {
                "validated"
            } else {
                "blocked"
            },
            if result.is_ok() {
                "current_static_checks_passed"
            } else {
                "current_static_checks_failed"
            },
        ));
    }
    let audit = inventory::audit(root)?;
    gates.push(item(
        "rust_only",
        if audit["rust_only_ready"] == true {
            "validated"
        } else {
            "blocked"
        },
        if audit["rust_only_ready"] == true {
            "no_first_party_python_source_or_runtime_launcher"
        } else {
            "first_party_python_source_or_runtime_launcher_remains"
        },
    ));
    let unchanged = qualify::digest(&binary)? == actual
        && records::read_bytes(root, &options.manifest, 64 * 1024)? == bytes;
    let validated = gates.iter().filter(|v| v["status"] == "validated").count();
    let complete = unchanged && validated == gates.len();
    Ok(
        json!({"schema":"mtm-release-check-v1","milestone":"MTM-016",
        "scope":"read_only_release_readiness_not_authorization","candidate_sha256":actual,
        "candidate_source_commit":manifest.candidate_source_commit,"inputs_unchanged":unchanged,
        "passed":complete,"ready_for_release_review":complete,"release_qualified":false,
        "release_authorization_implemented":false,"production_changed":false,"evidence_reexecuted":false,
        "round4_complete":false,"round5_complete":false,"gates":gates,
        "validated_gates":validated,"blocked_gates":gates.len()-validated,
        "remaining_python_files":audit["python_file_count"],
        "legacy_rust_reference_files":audit["legacy_rust_reference_file_count"],
        "compatibility_rust_reference_files":audit["compatibility_rust_reference_file_count"],
        "legacy_shadow_binary_files":audit["legacy_shadow_binary_file_count"]}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Value {
        json!({"schema":"mtm-release-inputs-v1","milestone":"MTM-016",
            "candidate_sha256":"a".repeat(64),"candidate_source_commit":"c".repeat(40),
            "baseline_sha256":"b".repeat(64),"evidence":{}})
    }

    #[test]
    fn no_cli_override_or_manifest_pass_flag_can_remove_release_blockers() -> Result<()> {
        decode(&serde_json::to_vec(&manifest())?)?;
        for key in [
            "passed",
            "release_qualified",
            "skip",
            "human_consent",
            "native_disabled_ok",
        ] {
            let mut value = manifest();
            value[key] = json!(true);
            assert!(decode(&serde_json::to_vec(&value)?).is_err());
            assert!(Options::parse(&[format!("--{key}")]).is_err());
        }
        assert!(GATES.iter().all(|name| supported(name)));
        Ok(())
    }

    #[test]
    fn all_real_world_adapters_require_exact_identity_and_positive_evidence() -> Result<()> {
        let selected: Manifest = serde_json::from_value(manifest())?;
        let native = json!({
            "schema":"mtm-native-command-evidence-v1","milestone":"MTM-016",
            "candidate_sha256":selected.candidate_sha256,"candidate_source_commit":selected.candidate_source_commit,
            "scope":"capable_host_native_command_and_permission_soak","native_backend":"bubblewrap",
            "hard_isolation_attested":true,"safe_mode_passed":true,"trusted_mode_passed":true,
            "dangerous_mode_passed":true,"tty_stdin_passed":true,"timeout_kill_passed":true,
            "descendant_cleanup_passed":true,"sage_functional_passed":true,"magma_functional_passed":true,
            "permission_grant_soak_passed":true,"production_changed":false,"release_qualified":false
        });
        assert!(validate_native_commands(&native, &selected)?);
        let mut bad = native.clone();
        bad["magma_functional_passed"] = json!(false);
        assert!(validate_native_commands(&bad, &selected).is_err());

        let latex = json!({
            "schema":"mtm-compiled-latex-evidence-v1","milestone":"MTM-016",
            "candidate_sha256":selected.candidate_sha256,"candidate_source_commit":selected.candidate_source_commit,
            "scope":"required_latex_full_compact_repair","native_backend":"bubblewrap",
            "hard_isolation_attested":true,"latex_policy":"required","latexmk_used":true,"pdflatex_used":true,
            "shell_escape_disabled":true,"full_flow_compiled":true,"compact_flow_compiled":true,
            "repair_flow_compiled":true,"final_artifacts_verified":true,"production_changed":false,
            "release_qualified":false
        });
        assert!(validate_compiled_latex(&latex, &selected)?);
        let mut bad = latex.clone();
        bad["repair_flow_compiled"] = json!(false);
        assert!(validate_compiled_latex(&bad, &selected).is_err());

        let retrieval = json!({
            "schema":"mtm-retrieval-evidence-v1","milestone":"MTM-016",
            "candidate_sha256":selected.candidate_sha256,"candidate_source_commit":selected.candidate_source_commit,
            "scope":"real_external_retrieval_and_redirect_policy","actual_external_retrieval":true,
            "https_only":true,"redirect_policy_checked":true,"request_count":5,"independent_source_count":2,
            "raw_credentials_recorded":false,"production_changed":false,"release_qualified":false
        });
        assert!(validate_retrieval(&retrieval, &selected)?);
        let mut bad = retrieval.clone();
        bad["request_count"] = json!(2);
        assert!(validate_retrieval(&bad, &selected).is_err());

        let browser = json!({
            "schema":"mtm-browser-human-evidence-v1","milestone":"MTM-016",
            "candidate_sha256":selected.candidate_sha256,"candidate_source_commit":selected.candidate_source_commit,
            "scope":"real_web_client_and_independent_human_consent","actual_web_client":true,
            "oauth_dcr_pkce_passed":true,"protected_resource_metadata_passed":true,
            "human_consent_observed":true,"independent_observer":true,"paired_roundtrips":5,
            "capability_invalid_count":0,"submission_rejection_count":0,"raw_token_recorded":false,
            "raw_secret_recorded":false,"production_changed":false,"release_qualified":false
        });
        assert!(validate_browser_human(&browser, &selected)?);
        let mut bad = browser.clone();
        bad["human_consent_observed"] = json!(false);
        assert!(validate_browser_human(&bad, &selected).is_err());

        let copied = json!({
            "schema":"mtm-copied-operator-state-evidence-v1","milestone":"MTM-016",
            "candidate_sha256":selected.candidate_sha256,"candidate_source_commit":selected.candidate_source_commit,
            "scope":"operator_authorized_copied_state_upgrade_and_rollback","operator_authorized":true,
            "source_was_copy":true,"production_read_only":true,"production_modified":false,
            "preupgrade_copy_preserved":true,"schema_before":2,"schema_candidate":7,"schema_restored":2,
            "migration_passed":true,"old_run_resumed_on_candidate":true,"rollback_passed":true,
            "restored_old_runtime_resumed":true,"raw_private_state_recorded":false,"release_qualified":false
        });
        assert!(validate_copied_operator_state(&copied, &selected)?);
        let mut bad = copied.clone();
        bad["operator_authorized"] = json!(false);
        assert!(validate_copied_operator_state(&bad, &selected).is_err());
        Ok(())
    }

    #[test]
    fn incomplete_clean_build_evidence_is_valid_but_never_a_release_pass() -> Result<()> {
        let selected: Manifest = serde_json::from_value(manifest())?;
        let build = json!({
            "schema":"mtm-clean-build-evidence-v1","milestone":"MTM-016",
            "source_commit":selected.candidate_source_commit,
            "selected_candidate_sha256":selected.candidate_sha256,
            "clean_build_sha256":"e".repeat(64),"build_locked":true,"build_offline":true,
            "detached_clean_worktree":true,"build_exit_code":0,
            "exact_candidate_bytes_reproduced":false,"python_free_path_proven":false,
            "production_changed":false,"release_qualified":false
        });
        assert!(!validate_clean_build(&build, &selected)?);
        let mut lie = build.clone();
        lie["exact_candidate_bytes_reproduced"] = json!(true);
        assert!(validate_clean_build(&lie, &selected).is_err());
        Ok(())
    }

    #[test]
    fn duplicate_unknown_and_historical_evidence_cannot_be_reused_as_current() -> Result<()> {
        let reference =
            json!({"path":"records/evidence/MTM-016/test.json","sha256":"d".repeat(64)});
        let mut value = manifest();
        value["evidence"] = json!({"protocol":reference,"target":reference});
        assert!(decode(&serde_json::to_vec(&value)?).is_err());
        value["evidence"] = json!({"unknown":reference});
        assert!(decode(&serde_json::to_vec(&value)?).is_err());
        value["evidence"] = json!({"target":{"path":"records/evidence/MTM-015/target.json","sha256":"d".repeat(64)}});
        assert!(decode(&serde_json::to_vec(&value)?).is_err());
        Ok(())
    }
}
