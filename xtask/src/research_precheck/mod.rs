//! Read-only evidence preparation. Consistent observations are not acceptance.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{Result, evidence_json, qualify, records};

mod checks;
mod files;
#[cfg(test)]
mod tests;

pub(crate) const CANDIDATE_SHA: &str =
    "f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034";
pub(crate) const CANDIDATE_SOURCE: &str = "c67484319f12c458cd25c538e35bbb25023915a5";
const CANDIDATE_STAGE: &str = "mtm016-f6-frozen";
pub(crate) const CORPUS_SHA: &str =
    "9227aa6e199887860d88091467aa53fe45eee55cd337eac0587059f8ec434861";
pub(crate) const REGISTRY_SHA: &str =
    "cd6d6a758e667fca21d2a04d2eba9a015c1d156350b34438660dd8bd16ae1bb9";
const JSON_LIMIT: u64 = 1024 * 1024;
const FILE_LIMIT: u64 = 4 * 1024 * 1024;
const TOTAL_LIMIT: usize = 32 * 1024 * 1024;

/// Acceptance metadata only: this type grants no Native or workflow authority.
pub(crate) struct ResearchPolicy {
    pub(crate) session_schema: &'static str,
    pub(crate) native_mode: &'static str,
    pub(crate) trial_schema: &'static str,
}

pub(crate) fn research_policy(task: &str) -> Result<ResearchPolicy> {
    match task {
        "U21" | "U22" | "U23" | "U24" => Ok(ResearchPolicy {
            session_schema: "mtm-research-session-v1",
            native_mode: "safe",
            trial_schema: "mtm-research-trial-evidence-v1",
        }),
        "U25" => Ok(ResearchPolicy {
            session_schema: "mtm-research-session-v2",
            native_mode: "dangerous",
            trial_schema: "mtm-research-trial-evidence-v2",
        }),
        _ => Err("unsupported research acceptance policy".into()),
    }
}

pub(crate) struct Options {
    bundle: PathBuf,
}

impl Options {
    pub(crate) fn parse(args: &[String]) -> Result<Self> {
        if args.len() != 2 || args[0] != "--bundle" || !Path::new(&args[1]).is_absolute() {
            return Err("use research-precheck --bundle <absolute-private-directory> only".into());
        }
        Ok(Self {
            bundle: PathBuf::from(&args[1]),
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Session,
    Status,
    Transitions,
    ProofManifest,
    VerificationReport,
    Compiler,
    CompilerOutput,
    FinalTex,
    ReviewedTex,
    Review,
    Retrieval,
    ReferenceAudit,
    Sources,
    SeededDraft,
    FirstFindings,
    RepairHistory,
    Branches,
    SageInput,
    SageOutput,
    MagmaInput,
    MagmaOutput,
    CasObservation,
}

impl Kind {
    fn filename(self) -> &'static str {
        match self {
            Self::Session => "session.json",
            Self::Status => "status.json",
            Self::Transitions => "transitions.json",
            Self::ProofManifest => "proof_manifest.json",
            Self::VerificationReport => "verification_report.json",
            Self::Compiler => "compiler.json",
            Self::CompilerOutput => "compiler_output.txt",
            Self::FinalTex => "final.tex",
            Self::ReviewedTex => "reviewed.tex",
            Self::Review => "review.json",
            Self::Retrieval => "retrieval.json",
            Self::ReferenceAudit => "reference_audit.json",
            Self::Sources => "sources.json",
            Self::SeededDraft => "seeded_draft.tex",
            Self::FirstFindings => "first_findings.json",
            Self::RepairHistory => "repair_history.json",
            Self::Branches => "branches.json",
            Self::SageInput => "sage_input.txt",
            Self::SageOutput => "sage_output.txt",
            Self::MagmaInput => "magma_input.txt",
            Self::MagmaOutput => "magma_output.txt",
            Self::CasObservation => "cas_observation.json",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    kind: Kind,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    schema: String,
    task_id: String,
    repeat: u8,
    trial_id: String,
    run_id: String,
    artifacts: Vec<Binding>,
}

struct Case {
    id: String,
    mode: String,
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn require(condition: bool, message: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_value(evidence_json::decode(bytes)?)
        .map_err(|_| "research evidence schema mismatch".into())
}

fn required(task: &str) -> Result<BTreeSet<Kind>> {
    use Kind::*;
    let mut kinds = BTreeSet::from([
        Session,
        Status,
        Transitions,
        ProofManifest,
        VerificationReport,
        Compiler,
        CompilerOutput,
        FinalTex,
        ReviewedTex,
        Review,
    ]);
    let extra: &[Kind] = match task {
        "U21" => &[],
        "U22" => &[Retrieval, ReferenceAudit, Sources],
        "U23" => &[SeededDraft, FirstFindings, RepairHistory],
        "U24" => &[Branches],
        "U25" => &[
            SageInput,
            SageOutput,
            MagmaInput,
            MagmaOutput,
            CasObservation,
        ],
        _ => return Err("task is not in the frozen research corpus".into()),
    };
    kinds.extend(extra);
    Ok(kinds)
}

fn case(registry: &[u8], bundle: &Bundle) -> Result<Case> {
    require(
        hash(registry) == REGISTRY_SHA,
        "research registry hash mismatch",
    )?;
    require(
        (1..=3).contains(&bundle.repeat),
        "research repeat must be one to three",
    )?;
    let registry =
        std::str::from_utf8(registry).map_err(|_| "research registry encoding mismatch")?;
    let repetition = bundle.repeat.to_string();
    for line in registry.lines().skip(1) {
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() == 6 && fields[0] == bundle.task_id && fields[1] == repetition {
            return Ok(Case {
                id: fields[2].into(),
                mode: fields[3].into(),
            });
        }
    }
    Err("research case absent from frozen registry".into())
}

fn inspect(directory: &files::Directory, registry: &[u8]) -> Result<Value> {
    let bytes = directory
        .read("bundle.json", JSON_LIMIT)?
        .ok_or("bundle manifest missing")?;
    let bundle: Bundle = decode(&bytes)?;
    require(
        bundle.schema == "mtm-research-bundle-v1",
        "unsupported research bundle version",
    )?;
    require(hex(&bundle.trial_id, 32), "invalid research trial identity")?;
    require(
        !bundle.run_id.is_empty()
            && bundle.run_id.len() <= 256
            && bundle
                .run_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)),
        "invalid research run identity",
    )?;
    let case = case(registry, &bundle)?;
    let required = required(&bundle.task_id)?;
    require(
        bundle.artifacts.len() <= 22,
        "research artifact count exceeds bound",
    )?;
    let mut seen = BTreeSet::new();
    // Validate all selectors before opening any artifact. No paths, commands,
    // secret-file selectors, extra authority fields or duplicate roles accepted.
    for binding in &bundle.artifacts {
        require(
            required.contains(&binding.kind),
            "artifact does not belong to this task",
        )?;
        require(
            seen.insert(binding.kind),
            "duplicate research artifact role",
        )?;
        require(hex(&binding.sha256, 64), "invalid research artifact digest")?;
    }
    let mut material = BTreeMap::new();
    let mut observed = Vec::new();
    let mut total = bytes.len();
    for binding in &bundle.artifacts {
        let filename = binding.kind.filename();
        let limit = if filename.ends_with(".json") {
            JSON_LIMIT
        } else {
            FILE_LIMIT
        };
        let Some(content) = directory.read(filename, limit)? else {
            continue;
        };
        require(
            hash(&content) == binding.sha256,
            "research artifact digest mismatch",
        )?;
        total += content.len();
        require(
            total <= TOTAL_LIMIT,
            "research bundle exceeds aggregate byte bound",
        )?;
        if filename.ends_with(".json") {
            let value = evidence_json::decode(&content)?;
            require(
                value.as_object().is_some_and(|value| !value.is_empty())
                    || value.as_array().is_some_and(|value| !value.is_empty()),
                "research JSON artifact must contain structured material",
            )?;
        } else {
            let text =
                std::str::from_utf8(&content).map_err(|_| "research material must be UTF-8")?;
            require(
                !text.trim().is_empty() && !text.contains('\0'),
                "empty or NUL research material",
            )?;
        }
        observed.push(json!({"artifact":filename,"bytes":content.len(),"sha256":binding.sha256}));
        material.insert(binding.kind, content);
    }
    checks::validate(&bundle, &case, &material)?;
    let missing: Vec<_> = required
        .iter()
        .filter(|kind| !material.contains_key(kind))
        .map(|kind| kind.filename())
        .collect();
    Ok(json!({
        "schema":"mtm-research-precheck-v1","milestone":"MTM-016",
        "scope":"read_only_bundle_integrity_and_common_fact_consistency",
        "task_id":bundle.task_id,"repeat":bundle.repeat,"case_id":case.id,
        "bundle_sha256":hash(&bytes),"artifact_count":material.len(),
        "bytes_read":total,"artifacts":observed,"missing_material":missing,
        "required_material_present":missing.is_empty(),"existing_material_consistent":true,
        "research_trial_passed":false,"accepted_trials_delta":0,"release_qualified":false,
        "manual_validation_required":true,"production_state_modified":false,
        "workflow_mutations":0,"runtime_started":false,"corpus_modified":false,
        "manual_pending":[
            "authenticate source observations and exact running candidate",
            "independently confirm the separate reviewer/session boundary",
            "audit mathematical correctness and route-specific evidence semantics",
            "collect remaining repeats and use a separately reviewed corpus importer"
        ]
    }))
}

pub(crate) fn run(root: &Path, options: &Options) -> Result<Value> {
    validate_bundle(root, &options.bundle)
}

pub(crate) fn validate_bundle(root: &Path, bundle: &Path) -> Result<Value> {
    let registry = records::read_bytes(root, "conformance/mtm016-research-cases.tsv", 32768)
        .map_err(|_| "frozen research registry unavailable")?;
    let corpus = records::read_bytes(root, "conformance/mtm016-usability-corpus.json", 65536)
        .map_err(|_| "frozen research corpus unavailable")?;
    require(hash(&corpus) == CORPUS_SHA, "research corpus hash mismatch")?;
    let candidate = root.join(format!(
        "target/{CANDIDATE_STAGE}/mtm-0.6.0-preview.1-{CANDIDATE_SHA}/mtm"
    ));
    require(
        qualify::digest(&candidate)? == CANDIDATE_SHA,
        "selected candidate digest mismatch",
    )?;
    let mut report = inspect(&files::Directory::open(bundle)?, &registry)?;
    report["selected_candidate_bytes_checked"] = json!(true);
    report["candidate_sha256"] = json!(CANDIDATE_SHA);
    // This is not an attestation that a running process used those bytes.
    report["running_candidate_attested_by_precheck"] = json!(false);
    Ok(report)
}
