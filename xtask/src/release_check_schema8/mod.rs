//! MTM-017 read-only formal evaluation. Acceptance remains a separate review.
use crate::{
    Result, architecture, authority_corpus_schema8, capability, check_report,
    corpus_aggregate_schema8, evidence_json, inventory, qualify, records,
    release_readiness_schema8, retirement,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
mod corpus;
mod files;
mod operator_copy;
mod policy;
#[cfg(test)]
mod tests;

const CANDIDATE: &str = "13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4";
const BASELINE: &str = "f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034";
const PRODUCT_COMMIT: &str = "7b4afe2359e688263557f62154e4bc1e640c12c0";
const PRODUCT_SOURCE: &str = "0adec4b02a8b54fd20fb30c796c9959ccc346cc0f9336517fc47eafcb6951e02";
const DRIVER: (&str, &str) = (
    "records/governance/mtm016-release-inputs.json",
    "e55f2c5624e6f94f4805bed38dd968626808f7df00d95bff9168cf86eb8cda04",
);
const CORPUS_SHA: &str = "9227aa6e199887860d88091467aa53fe45eee55cd337eac0587059f8ec434861";
const FAILURE: (&str, &str) = (
    "records/evidence/MTM-017/authority-corpus-whole-source-r3-failed-20260930.json",
    "5214ea3ec16b5277e950ca110a94af554d335c94c9c2a8328cc97bab0e615fb7",
);
const FINDING: &str = "MTM017-SOURCE-R3-NORMAL-ASSESSMENT";
const CONTRACT: &str = "mtm017-release-readiness-contract-v1";
const CONTRACT_PATH: &str = "docs/MTM-017-FORMAL-READINESS.md";
const PREFIX: &str = "records/evidence/MTM-017/";
const TEST_PATHS: [&str; 3] = [
    "crates/mtm-cli/tests/support/loopback.rs",
    "crates/mtm-cli/tests/schema8_authority_corpus.rs",
    "crates/mtm-runtime/tests/domain_collision.rs",
];
const PROFILES: [&str; 8] = [
    "protocol",
    "upgrade_schema8",
    "native_commands",
    "compiled_latex",
    "resource",
    "corpus_native",
    "install_sigkill",
    "retrieval",
];
const REVIEW_CHECKS: [&str; 6] = [
    "eighteen_mapping_scopes_reviewed",
    "public_chain_refs_and_scoped_waivers_reviewed",
    "known_failure_disposition_scope_reviewed",
    "current_source_and_binary_bound",
    "negative_tests_and_no_action_boundary_reviewed",
    "separate_result_review_required",
];
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Reference {
    path: String,
    sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    schema: String,
    milestone: String,
    criteria_revision: String,
    criteria: Reference,
    candidate_sha256: String,
    baseline_sha256: String,
    prepared_by: String,
    source_gate: Reference,
    snapshot: Reference,
    corpus_state: Reference,
    corpus_acceptance: Reference,
    research_state: Reference,
    decisions: Reference,
    clean_build_state: Reference,
    u26_state: Reference,
    operator_copy: Reference,
    operator_copy_review: Reference,
    known_failure: Reference,
    known_failure_followup: Reference,
    mechanism_diagnostic: Reference,
    risk_disposition: Option<Reference>,
    risk_disposition_review: Option<Reference>,
    test_only_sources: Vec<Reference>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputReview {
    schema: String,
    milestone: String,
    inputs_sha256: String,
    implementation_source_sha256: String,
    maintenance_binary_sha256: String,
    prepared_by: String,
    reviewer_session: String,
    decision: String,
    checks: Vec<String>,
    recorded_unix_seconds: u64,
    release_qualified: bool,
    deployment_authorized: bool,
}
pub(crate) struct Options {
    inputs: String,
    review: String,
}
impl Options {
    pub(crate) fn parse(args: &[String]) -> Result<Self> {
        require(
            args.len() == 4 && args[0] == "--inputs" && args[2] == "--input-review",
            "use release-check-schema8 --inputs <flat-MTM017-JSON> --input-review <flat-MTM017-JSON> only",
        )?;
        require(
            evidence_path(&args[1]) && evidence_path(&args[3]) && args[1] != args[3],
            "formal readiness input selectors invalid",
        )?;
        Ok(Self {
            inputs: args[1].clone(),
            review: args[3].clone(),
        })
    }
}
fn require(ok: bool, message: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hash(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn array(v: &Value) -> Result<&Vec<Value>> {
    v.as_array()
        .ok_or_else(|| "formal readiness array missing".into())
}
fn reference(v: &Value) -> Result<Reference> {
    serde_json::from_value(v.clone())
        .map_err(|_| "formal readiness reference schema invalid".into())
}
fn evidence_path(path: &str) -> bool {
    path.strip_prefix(PREFIX)
        .is_some_and(|name| !name.is_empty() && !name.contains('/') && name.ends_with(".json"))
}
fn named(r: &Reference, path: &str, sha: &str) -> Result<()> {
    require(
        r.path == path && r.sha256 == sha,
        "formal readiness fixed evidence identity mismatch",
    )
}
fn input_shape(i: &Inputs) -> Result<()> {
    require(
        i.schema == "mtm017-release-inputs-v1"
            && i.milestone == "MTM-017"
            && i.criteria_revision == CONTRACT
            && i.criteria.path == CONTRACT_PATH
            && i.candidate_sha256 == CANDIDATE
            && i.baseline_sha256 == BASELINE
            && !i.prepared_by.is_empty()
            && i.prepared_by.len() <= 128
            && i.risk_disposition.is_some() == i.risk_disposition_review.is_some(),
        "formal readiness input scope invalid",
    )?;
    named(
        &i.snapshot,
        "records/evidence/MTM-017/preview2-qualification-snapshot.json",
        "5018c5b1050cefe6e0ef6c7db0bb0aeb15b03ed492ee8e75d6737097b535d55c",
    )?;
    named(
        &i.corpus_acceptance,
        "records/evidence/MTM-017/corpus-union-accepted-20260930.json",
        "1afff81a1ce804eb4fa88ef23012c37f2289f0f54d02fe73b0092e5cceba7523",
    )?;
    named(
        &i.corpus_state,
        "records/governance/mtm017-corpus-union.json",
        "9e2d9de518a3ab1225134164828f1f83ddcb83d0f72c55399301ea53452c1393",
    )?;
    named(
        &i.research_state,
        "records/governance/mtm017-research-corpus.json",
        "27aff327aba433e907e3ee639bad5ce0cee1512ba61359bfc2f988c42626eb24",
    )?;
    named(
        &i.u26_state,
        "records/governance/mtm017-u26-waiver.json",
        "4bcf208c6e68d490b835fd895b6879a4dd694f5cbb698a6fc3fcf6248ee5219c",
    )?;
    named(
        &i.clean_build_state,
        "records/governance/mtm017-clean-build-status.json",
        "3d40b58e1c55222960644aed8703e8afe058ee5f1899cff9307906c7785e9769",
    )?;
    named(&i.known_failure, FAILURE.0, FAILURE.1)?;
    named(
        &i.known_failure_followup,
        "records/evidence/MTM-017/authority-corpus-source-regression-followup-20260930.json",
        "e5d4d5a4374f75abb113b0dd995f9a8a2e9118788d9ccba5a922232f5611fa45",
    )?;
    named(
        &i.mechanism_diagnostic,
        "records/evidence/MTM-017/authority-corpus-domain-collision-diagnostic-20260930.json",
        "8995c3db3585b43b984b9c234dbb7f6613ef135e16991540184a3a7db8a395fc",
    )?;
    if let (Some(risk), Some(review)) = (&i.risk_disposition, &i.risk_disposition_review) {
        named(
            risk,
            "records/evidence/MTM-017/source-risk-human-disposition-20260930.json",
            "a6132158e02e45dee166a214e0b8eadd7c72d55715e17b680aff9d7838496014",
        )?;
        named(
            review,
            "records/evidence/MTM-017/source-risk-disposition-review-20260930.json",
            "6a57d1a1792fd9078f9a057209ae936326d547d750ab9b2de691d1960c7f913c",
        )?;
    }
    require(
        i.decisions.path == "records/governance/mtm017-readiness-decisions.json"
            && i.test_only_sources.len() == TEST_PATHS.len(),
        "formal readiness ledger or test delta invalid",
    )?;
    let names = i
        .test_only_sources
        .iter()
        .map(|r| r.path.as_str())
        .collect::<BTreeSet<_>>();
    require(
        names.len() == TEST_PATHS.len() && TEST_PATHS.iter().all(|p| names.contains(p)),
        "formal readiness unreviewed test-only delta",
    )?;
    Ok(())
}
fn review_shape(
    r: &InputReview,
    i: &Inputs,
    input: &str,
    source: &str,
    binary: &str,
) -> Result<()> {
    require(
        r.schema == "mtm017-release-input-review-v1"
            && r.milestone == "MTM-017"
            && r.inputs_sha256 == input
            && r.implementation_source_sha256 == source
            && r.maintenance_binary_sha256 == binary
            && r.prepared_by == i.prepared_by
            && !r.reviewer_session.is_empty()
            && r.reviewer_session.len() <= 128
            && r.reviewer_session != r.prepared_by
            && r.decision == "approved_for_read_only_readiness_evaluation"
            && r.checks == REVIEW_CHECKS
            && r.recorded_unix_seconds > 0
            && !r.release_qualified
            && !r.deployment_authorized,
        "formal readiness independent input review does not bind current inputs/source/binary",
    )
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Json,
    Data,
    Executable,
}
struct Inventory<'a> {
    root: &'a Path,
    entries: BTreeMap<String, (Reference, files::Snapshot, Kind)>,
    documents: BTreeMap<String, Value>,
    bytes: usize,
}
impl<'a> Inventory<'a> {
    fn new(root: &'a Path) -> Self {
        Self {
            root,
            entries: BTreeMap::new(),
            documents: BTreeMap::new(),
            bytes: 0,
        }
    }
    fn load(&mut self, r: &Reference, kind: Kind) -> Result<()> {
        require(hash(&r.sha256), "formal readiness digest invalid")?;
        let allowed = match kind {
            Kind::Json => {
                evidence_path(&r.path)
                    || [
                        DRIVER.0,
                        "records/evidence/MTM-016/lifecycle-reconciliation-20260926.json",
                        "records/governance/mtm017-readiness-decisions.json",
                        "records/governance/mtm017-research-corpus.json",
                        "records/governance/mtm017-clean-build-status.json",
                        "records/governance/mtm017-u26-waiver.json",
                        "records/governance/mtm017-corpus-union.json",
                        "records/governance/mtm017-partial-corpus.json",
                    ]
                    .contains(&r.path.as_str())
            }
            Kind::Data => {
                r.path == CONTRACT_PATH
                    || r.path == "conformance/mtm016-usability-corpus.json"
                    || TEST_PATHS.contains(&r.path.as_str())
                    || [
                        "scripts/mtm017-corpus-union/union-validator.sh",
                        "scripts/mtm017-corpus-union/union-validator.sql",
                        "scripts/mtm017-corpus-union/union-shapes.sql",
                        "scripts/mtm017-corpus-union/union-negative-mutations.sql",
                    ]
                    .contains(&r.path.as_str())
            }
            Kind::Executable => {
                r.path == format!("target/mtm017-preview2/mtm-0.6.0-preview.2-{CANDIDATE}/mtm")
                    || r.path
                        == format!("target/mtm017-baselines/mtm-0.6.0-preview.1-{BASELINE}/mtm")
            }
        };
        require(allowed, "formal readiness role/path is not permitted")?;
        if let Some((old, _, old_kind)) = self.entries.get(&r.path) {
            return require(
                old == r && *old_kind == kind,
                "formal readiness conflicting shared seal",
            );
        }
        require(
            self.entries.len() < 256,
            "formal readiness file count exceeded",
        )?;
        let read = files::read(
            self.root,
            &r.path,
            if kind == Kind::Executable {
                32 * 1024 * 1024
            } else {
                1024 * 1024
            },
            kind == Kind::Executable,
        )?;
        require(
            digest(&read.bytes) == r.sha256,
            "formal readiness sealed bytes changed",
        )?;
        self.bytes = self
            .bytes
            .checked_add(read.bytes.len())
            .ok_or("formal readiness size overflow")?;
        require(
            self.bytes <= 64 * 1024 * 1024,
            "formal readiness total byte budget exceeded",
        )?;
        if kind == Kind::Json {
            self.documents
                .insert(r.path.clone(), evidence_json::decode(&read.bytes)?);
        }
        self.entries.insert(r.path.clone(), (r.clone(), read, kind));
        Ok(())
    }
    fn json(&mut self, r: &Reference) -> Result<Value> {
        self.load(r, Kind::Json)?;
        self.documents
            .get(&r.path)
            .cloned()
            .ok_or_else(|| "formal readiness JSON missing".into())
    }
    fn linked(&mut self, v: &Value) -> Result<Value> {
        self.json(&reference(v)?)
    }
    fn recheck(&self) -> Result<()> {
        for (r, before, kind) in self.entries.values() {
            before.recheck(&files::read(
                self.root,
                &r.path,
                if *kind == Kind::Executable {
                    32 * 1024 * 1024
                } else {
                    1024 * 1024
                },
                *kind == Kind::Executable,
            )?)?;
        }
        Ok(())
    }
}
fn source_gate(v: &Value, current: &str) -> Result<()> {
    let closed = |value: &Value, keys: &[&str]| -> Result<()> {
        let object = value.as_object().ok_or("source gate object missing")?;
        require(
            object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)),
            "source gate has unknown or missing fields",
        )
    };
    closed(
        v,
        &[
            "architecture",
            "checks",
            "commit_hook_executable_checked",
            "milestone",
            "native_environment",
            "passed",
            "pending",
            "product_test_evaluation",
            "production_selector_changed",
            "production_state_modified",
            "record_integrity",
            "recorded_unix_seconds",
            "release_qualified",
            "retirement",
            "schema_version",
            "scope",
            "source_identity",
            "test_failure_attribution",
            "tests_skipped_by_preflight",
        ],
    )?;
    let identity = &v["source_identity"];
    closed(
        identity,
        &[
            "after_sha256",
            "before_sha256",
            "commit_after",
            "commit_before",
            "hash_scope",
            "unchanged",
        ],
    )?;
    let checks = array(&v["checks"])?;
    for check in checks {
        closed(check, &["exit_code", "name", "passed"])?;
    }
    let evaluated = check_report::summarize(
        checks,
        &v["native_environment"],
        identity["unchanged"] == true,
    );
    require(
        v["schema_version"] == "1.0.0"
            && v["milestone"] == "MTM-016"
            && v["scope"] == "rust_source_with_inherited_host_tests"
            && v["passed"] == true
            && evaluated["passed"] == true
            && v["product_test_evaluation"] == evaluated
            && identity["hash_scope"] == "mtm-rust-source-v1"
            && identity["commit_before"] == identity["commit_after"]
            && identity["commit_before"].as_str().is_some_and(|commit| {
                commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit())
            })
            && v["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|time| time > 0)
            && v["record_integrity"]["ok"] == true
            && v["architecture"]["ok"] == true
            && v["retirement"]["ok"] == true
            && v["commit_hook_executable_checked"] == true
            && identity["before_sha256"] == current
            && identity["after_sha256"] == current
            && v["tests_skipped_by_preflight"] == false
            && v["release_qualified"] == false
            && v["production_selector_changed"] == false
            && v["production_state_modified"] == false,
        "fresh complete source gate does not cover current source",
    )
}
fn permitted_test_delta(path: &str) -> bool {
    TEST_PATHS.contains(&path)
}
fn product_identity(root: &Path, i: &Inputs, inv: &mut Inventory<'_>) -> Result<()> {
    require(
        capability::source_hash_at(root, PRODUCT_COMMIT)? == PRODUCT_SOURCE,
        "selected candidate historical committed source mismatch",
    )?;
    require(
        crate::git(root, &["merge-base", PRODUCT_COMMIT, "HEAD"])?
            == format!("{PRODUCT_COMMIT}\n").as_bytes(),
        "selected product checkpoint is not an ancestor",
    )?;
    for seal in &i.test_only_sources {
        inv.load(seal, Kind::Data)?;
    }
    // All crate files (including build.rs and embedded resources) and root build
    // configuration are covered. Only these reviewed integration-test paths differ.
    for args in [
        vec![
            "diff",
            "--name-only",
            PRODUCT_COMMIT,
            "--",
            "crates",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            ".cargo",
        ],
        vec![
            "ls-files",
            "--others",
            "--exclude-standard",
            "--",
            "crates",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            ".cargo",
        ],
    ] {
        let output = crate::git(root, &args)?;
        for path in std::str::from_utf8(&output)?.lines() {
            require(
                permitted_test_delta(path),
                "unreviewed production/build-input drift",
            )?;
        }
    }
    Ok(())
}
pub(crate) fn run(root: &Path, options: &Options) -> Result<Value> {
    let before = capability::source_hash(root)?;
    let binary = qualify::digest(&std::env::current_exe()?)?;
    let ib = files::read(root, &options.inputs, 1024 * 1024, false)?;
    let rb = files::read(root, &options.review, 1024 * 1024, false)?;
    let inputs: Inputs = serde_json::from_value(evidence_json::decode(&ib.bytes)?)?;
    let review: InputReview = serde_json::from_value(evidence_json::decode(&rb.bytes)?)?;
    input_shape(&inputs)?;
    review_shape(&review, &inputs, &digest(&ib.bytes), &before, &binary)?;
    let mut inv = Inventory::new(root);
    inv.load(&inputs.criteria, Kind::Data)?;
    inv.load(
        &Reference {
            path: DRIVER.0.into(),
            sha256: DRIVER.1.into(),
        },
        Kind::Json,
    )?;
    inv.load(
        &Reference {
            path: "conformance/mtm016-usability-corpus.json".into(),
            sha256: CORPUS_SHA.into(),
        },
        Kind::Data,
    )?;
    source_gate(&inv.json(&inputs.source_gate)?, &before)?;
    product_identity(root, &inputs, &mut inv)?;
    let profiles = policy::profiles(&mut inv, &inputs)?;
    let research = release_readiness_schema8::verified_research_subset(root)?;
    for seal in array(&research["sealed_inputs"])? {
        inv.load(&reference(seal)?, Kind::Json)?;
    }
    let decisions = inv.json(&inputs.decisions)?;
    let waivers = policy::waivers(&mut inv, &inputs, &decisions)?;
    let copied = operator_copy::validate(&mut inv, &inputs, &decisions)?;
    let corpus = corpus::validate(&mut inv, &inputs, &research, &copied)?;
    let finding = policy::finding(&mut inv, &inputs)?;
    require(
        records::validate(root)?["ok"] == true
            && architecture::validate(root)?["ok"] == true
            && retirement::validate(root)?["ok"] == true
            && inventory::audit(root)?["rust_only_ready"] == true,
        "formal readiness current static integrity failed",
    )?;
    require(
        crate::git(root, &["diff", "--check"])?.is_empty(),
        "formal readiness diff check failed",
    )?;
    inv.recheck()?;
    ib.recheck(&files::read(root, &options.inputs, 1024 * 1024, false)?)?;
    rb.recheck(&files::read(root, &options.review, 1024 * 1024, false)?)?;
    require(
        capability::source_hash(root)? == before
            && qualify::digest(&std::env::current_exe()?)? == binary,
        "formal readiness source or executable changed during evaluation",
    )?;
    let seals = inv
        .entries
        .values()
        .map(|(r, _, _)| r.clone())
        .collect::<Vec<_>>();
    Ok(policy::report(
        &inputs,
        &before,
        &binary,
        &digest(&ib.bytes),
        &digest(&rb.bytes),
        json!({"profiles":profiles,"research":research["verification"],"operator_copy":copied,
            "corpus":corpus,"waivers":waivers,"known_finding":finding,"verified_inventory":seals}),
    ))
}
