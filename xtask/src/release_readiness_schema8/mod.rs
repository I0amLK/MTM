//! Fixed-inventory MTM-017 readiness draft, not a release qualification adapter.
use crate::{Result, capability, evidence_json, inventory, qualify, records, retirement};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

mod files;
#[cfg(test)]
mod tests;
mod validation;

const CANDIDATE: &str = "13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4";
const BASELINE: &str = "f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034";
const PRODUCT_COMMIT: &str = "7b4afe2359e688263557f62154e4bc1e640c12c0";
const PRODUCT_SOURCE: &str = "0adec4b02a8b54fd20fb30c796c9959ccc346cc0f9336517fc47eafcb6951e02";
const DRIVER_SHA: &str = "e55f2c5624e6f94f4805bed38dd968626808f7df00d95bff9168cf86eb8cda04";
const SNAPSHOT: &str = "records/evidence/MTM-017/preview2-qualification-snapshot.json";
const RESEARCH: &str = "records/governance/mtm017-research-corpus.json";
const CLEAN: &str = "records/governance/mtm017-clean-build-status.json";
const DECISIONS: &str = "records/governance/mtm017-readiness-decisions.json";
const DRIVER: &str = "records/governance/mtm016-release-inputs.json";
const HISTORICAL: &str = "records/evidence/MTM-016/lifecycle-reconciliation-20260926.json";
const ANCHORS: [(&str, &str); 6] = [
    (
        SNAPSHOT,
        "5018c5b1050cefe6e0ef6c7db0bb0aeb15b03ed492ee8e75d6737097b535d55c",
    ),
    (
        RESEARCH,
        "27aff327aba433e907e3ee639bad5ce0cee1512ba61359bfc2f988c42626eb24",
    ),
    (
        CLEAN,
        "3d40b58e1c55222960644aed8703e8afe058ee5f1899cff9307906c7785e9769",
    ),
    (
        DECISIONS,
        "e785e2dd9e4ab1d1e9c3857f9b9de3d0b8d4a21f8ad305bc08d7fa48497e102b",
    ),
    (DRIVER, DRIVER_SHA),
    (
        HISTORICAL,
        "9988d973770cbd5a95c15f4dc4a715d2ed772dcf4be77485c937de9d24401efd",
    ),
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

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    path: String,
    sha256: String,
}

fn require(ok: bool, message: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn array(value: &Value) -> Result<&Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| "readiness evidence array missing".into())
}
fn reference(value: &Value) -> Result<Reference> {
    serde_json::from_value(value.clone()).map_err(|_| "readiness reference schema invalid".into())
}

struct Inventory<'a> {
    root: &'a Path,
    files: BTreeMap<String, (Reference, files::Snapshot, bool)>,
    json: BTreeMap<String, Value>,
}
impl<'a> Inventory<'a> {
    fn new(root: &'a Path) -> Self {
        Self {
            root,
            files: BTreeMap::new(),
            json: BTreeMap::new(),
        }
    }
    fn load(&mut self, path: &str, sha256: &str, executable: bool) -> Result<()> {
        require(hash(sha256), "readiness digest invalid")?;
        if let Some((existing, _, kind)) = self.files.get(path) {
            return require(
                existing.sha256 == sha256 && *kind == executable,
                "conflicting readiness seal",
            );
        }
        require(
            self.files.len() < 128,
            "readiness inventory exceeds fixed bound",
        )?;
        let snapshot = files::read(
            self.root,
            path,
            if executable {
                32 * 1024 * 1024
            } else {
                1024 * 1024
            },
            executable,
        )?;
        require(
            digest(&snapshot.bytes) == sha256,
            "readiness sealed input bytes changed",
        )?;
        if !executable {
            self.json
                .insert(path.to_owned(), evidence_json::decode(&snapshot.bytes)?);
        }
        self.files.insert(
            path.to_owned(),
            (
                Reference {
                    path: path.to_owned(),
                    sha256: sha256.to_owned(),
                },
                snapshot,
                executable,
            ),
        );
        Ok(())
    }
    fn get(&self, path: &str) -> Result<&Value> {
        self.json
            .get(path)
            .ok_or_else(|| "readiness evidence not loaded".into())
    }
    fn referred(&mut self, value: &Value) -> Result<Value> {
        let seal = reference(value)?;
        require(
            seal.path.starts_with("records/evidence/MTM-017/")
                || ANCHORS
                    .iter()
                    .any(|(path, sha)| *path == seal.path && *sha == seal.sha256),
            "readiness reference outside reviewed evidence namespace",
        )?;
        self.load(&seal.path, &seal.sha256, false)?;
        Ok(self.get(&seal.path)?.clone())
    }
    fn closure(&mut self, value: &Value, depth: usize) -> Result<()> {
        require(depth <= 16, "readiness reference depth exceeded")?;
        match value {
            Value::Object(object)
                if object.len() == 2
                    && object.contains_key("path")
                    && object.contains_key("sha256") =>
            {
                let seal = reference(value)?;
                let already = self.files.contains_key(&seal.path);
                let child = self.referred(value)?;
                if !already {
                    self.closure(&child, depth + 1)?;
                }
            }
            Value::Object(object) => {
                for (key, child) in object {
                    // These seals describe the old import implementation, not
                    // current mutable source inputs. Keep its containing sealed
                    // report, but never relabel the old source as current.
                    if value["schema"] == "mtm017-research-import-implementation-validation-v1"
                        && matches!(key.as_str(), "source_files" | "documentation")
                    {
                        continue;
                    }
                    self.closure(child, depth + 1)?;
                }
            }
            Value::Array(values) => {
                for child in values {
                    self.closure(child, depth + 1)?;
                }
            }
            _ => (),
        }
        Ok(())
    }
    fn recheck(&self) -> Result<()> {
        for (seal, before, executable) in self.files.values() {
            let after = files::read(
                self.root,
                &seal.path,
                if *executable {
                    32 * 1024 * 1024
                } else {
                    1024 * 1024
                },
                *executable,
            )?;
            before.recheck(&after)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Disposition {
    TechnicalPass,
    WaivedByOperator,
    MissingEvidence,
    CriteriaNotImplemented,
}

#[derive(Serialize)]
struct Gate {
    id: &'static str,
    scope: &'static str,
    gate_disposition: Disposition,
    technical_pass: bool,
    governance_disposition: Option<&'static str>,
    observation_validation: Value,
    remaining: &'static str,
}
fn gate(
    id: &'static str,
    scope: &'static str,
    disposition: Disposition,
    observed: Value,
    remaining: &'static str,
) -> Gate {
    Gate {
        id,
        scope,
        gate_disposition: disposition,
        technical_pass: disposition == Disposition::TechnicalPass,
        governance_disposition: None,
        observation_validation: observed,
        remaining,
    }
}

/// Reopen only the previously accepted research chain. No new count, private
/// trial execution, waiver or unrelated readiness gate is supplied by this view.
pub(crate) fn verified_research_subset(root: &Path) -> Result<Value> {
    let mut inventory = Inventory::new(root);
    let (_, sha) = ANCHORS
        .iter()
        .find(|(path, _)| *path == RESEARCH)
        .ok_or("research anchor missing")?;
    inventory.load(RESEARCH, sha, false)?;
    let state = inventory.get(RESEARCH)?.clone();
    inventory.closure(&state, 0)?;
    let verification = validation::research(&mut inventory)?;
    let accepted = inventory.referred(&state["active_acceptance"])?;
    inventory.recheck()?;
    let seals = inventory
        .files
        .values()
        .map(|(seal, _, _)| seal.clone())
        .collect::<Vec<_>>();
    Ok(json!({"state":state,"accepted":accepted,"verification":verification,"sealed_inputs":seals}))
}

pub(crate) fn reject_options(args: &[String]) -> Result<()> {
    require(
        args.is_empty(),
        "release-readiness-schema8 takes no options; fixed read-only draft only",
    )
}

pub(crate) fn run(root: &Path) -> Result<Value> {
    let current_source = capability::source_hash(root)?;
    let mut inventory = Inventory::new(root);
    for (path, sha256) in ANCHORS {
        inventory.load(path, sha256, false)?;
    }
    let snapshot = inventory.get(SNAPSHOT)?.clone();
    validation::snapshot(&snapshot)?;
    for key in ["candidate", "baseline"] {
        let artifact = &snapshot[key];
        inventory.load(
            artifact["path"].as_str().ok_or("artifact path missing")?,
            artifact["sha256"]
                .as_str()
                .ok_or("artifact digest missing")?,
            true,
        )?;
    }
    for seal in array(&snapshot["report_seals"])? {
        inventory.referred(seal)?;
    }
    for path in [RESEARCH, CLEAN] {
        let value = inventory.get(path)?.clone();
        inventory.closure(&value, 0)?;
    }
    let profiles = validation::profiles(&inventory, &snapshot)?;
    let research = validation::research(&mut inventory)?;
    let waivers = validation::waivers(&mut inventory)?;
    let source_gate = inventory.get("records/evidence/MTM-017/preview2-source-gate.json")?;
    validation::source_checkpoint(source_gate)?;
    require(
        capability::source_hash_at(root, PRODUCT_COMMIT)? == PRODUCT_SOURCE,
        "historical source lineage mismatch",
    )?;
    require(
        crate::git(root, &["merge-base", PRODUCT_COMMIT, "HEAD"])?
            == format!("{PRODUCT_COMMIT}\n").as_bytes(),
        "product checkpoint is not an ancestor",
    )?;
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
            ".cargo/config.toml",
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
            ".cargo/config.toml",
        ],
    ] {
        require(
            crate::git(root, &args)?.is_empty(),
            "product files diverge from selected checkpoint",
        )?;
    }
    let integrity = records::validate(root)?;
    let retired = retirement::validate(root)?;
    let audit = inventory::audit(root)?;
    require(
        integrity["ok"] == true && retired["ok"] == true && audit["rust_only_ready"] == true,
        "current static integrity check blocked",
    )?;
    inventory.recheck()?;
    require(
        capability::source_hash(root)? == current_source,
        "maintenance source changed during draft",
    )?;
    let observed = inventory.files.values().map(|(seal, _, executable)| json!({"path":seal.path,"sha256":seal.sha256,"kind":if *executable {"artifact_bytes_only"} else {"sealed_json"}})).collect::<Vec<_>>();
    Ok(draft_report(
        current_source,
        observed,
        profiles,
        research,
        waivers,
    ))
}

fn draft_report(
    current_source: String,
    observed: Vec<Value>,
    profiles: Vec<Value>,
    research: Value,
    waivers: Vec<Value>,
) -> Value {
    let gates = gates(profiles, research.clone(), waivers);
    json!({
        "schema":"mtm017-readiness-draft-v1","milestone":"MTM-017",
        "scope":"fixed_reviewed_inventory_and_proposed_gate_gaps_not_final_release_inputs",
        "status":"blocked","proposed_gate_registry":true,"requirements_complete":false,
        "candidate_sha256":CANDIDATE,"baseline_sha256":BASELINE,"state_schema_version":8,
        "tool_contract":"mtm-tools-v10","workflow_protocol":3,
        "implementation_complete":"unknown","implementation_scope":"whole_current_tree_requires_separate_evidence",
        "product_checkpoint":{"commit":PRODUCT_COMMIT,"source_sha256":PRODUCT_SOURCE,"source_checkpoint_verified":true,"git_source_recomputed":true,"product_files_unchanged":true},
        "current_maintenance":{"source_sha256":current_source,"whole_source_gate_verified":false,"scope":"static_integrity_only_not_fresh_workspace_tests"},
        "research_accepted":true,"research_acceptance_scope":"previously_accepted_U21_U25_fifteen_trials_only",
        "research":research,"release_qualified":false,"deployment_authorized":false,
        "production_selector_changed":false,"production_state_modified":false,
        "candidate_executed":false,"operator_state_opened":false,"final_release_inputs_created":false,
        "current_static_integrity":{"records_ok":true,"retirement_ok":true,"rust_only_ready":true},
        "gates":gates,"verified_inventory":observed,
        "limitations":["The eighteen rows are proposed gap accounting, not approved complete schema-8 release criteria.",
            "Profile validators recheck their sealed original scopes; no full schema-8 release adapter is inferred.",
            "Procedural acceptance and waiver records are not cryptographic authentication or fresh mathematical review.",
            "Retired F2 consent/grant authority is not required; explicit U27/U28 schema-8 mapping remains pending.",
            "This version cannot qualify a release; completing criteria and evidence requires a separately reviewed implementation."]
    })
}

fn gates(profiles: Vec<Value>, research: Value, waivers: Vec<Value>) -> Vec<Gate> {
    use Disposition::*;
    let mut gates = vec![
        gate(
            "exact_artifact_identity",
            "fixed candidate and schema-7 baseline byte identity only",
            TechnicalPass,
            json!({"artifact_bytes_verified":true,"candidate_executed":false}),
            "Version/schema are sealed provenance, not a newly executed binary assertion.",
        ),
        gate(
            "source_checkpoint_and_current_maintenance",
            "frozen product versus changed maintenance source",
            MissingEvidence,
            json!({"frozen_product_source_and_lineage_verified":true,"current_maintenance_whole_source_gate_verified":false}),
            "Fresh complete maintenance/source acceptance remains separate; old 633/0/1 counts are not current.",
        ),
    ];
    for (profile, scope) in PROFILES.into_iter().zip([
        "loopback protocol/capability fixtures",
        "generated disposable schema 7/8/7 fixture only",
        "dangerous-only capable-host Native fixture scope",
        "compiled-LaTeX fixed mathematical fixtures",
        "paired baseline/candidate resource workload",
        "U16-U20 fifteen Native fixture rows only",
        "disposable process-SIGKILL recovery only",
        "external retrieval and redirect checks only",
    ]) {
        let observation = profiles
            .iter()
            .find(|v| v["profile"] == profile)
            .cloned()
            .unwrap_or(Value::Null);
        gates.push(gate(
            profile,
            scope,
            CriteriaNotImplemented,
            observation,
            "Original scoped receipt validation is not a complete current release gate adapter.",
        ));
    }
    gates.push(gate(
        "research_subset",
        "previously accepted U21-U25 x3 public acceptance chain only",
        TechnicalPass,
        research,
        "No new mathematical review, new rows, full corpus or browser gate is inferred.",
    ));
    gates.push(gate("operator_state_copy", "genuine schema-7 operator-copy migration, existing-run continuation and exact rollback", MissingEvidence, json!({"operator_copy_evidence_in_fixed_inventory":false}), "Need separately authorized consistent copy, provenance, 7/8/7, old-run resume and exact bytes/modes/database restoration."));
    gates.push(gate(
        "real_browser",
        "current OAuth/PKCE reconnect in a real client",
        CriteriaNotImplemented,
        json!({"raw_observations_not_promoted":true}),
        "Closed schema-8 adapter and reviewed required observation set are not implemented.",
    ));
    gates.push(gate("full_current_corpus", "complete current-artifact corpus with explicit schema-8 mapping", MissingEvidence, json!({"historical_counts_inherited":false,"subset_counts_summed":false,"u27_u28_schema8_mapping_pending":true}), "No full current aggregate; Native15 and research15 are not automatically 30/90, and SIGKILL is not U30 x3."));
    gates.push(gate(
        "current_static_integrity",
        "record layout, deletion provenance and Rust-only inventory",
        TechnicalPass,
        json!({"records_ok":true,"retirement_ok":true,"rust_only_ready":true}),
        "No runtime parity, fresh workspace source gate or obsolete consent requirement inherited.",
    ));
    gates.push(gate("schema8_criteria_and_adapters", "complete explicitly reviewed schema-8 release criteria", CriteriaNotImplemented, json!({"requirements_complete":false,"proposed_gate_registry":true}), "Approve current contract mapping and implement missing closed adapters before final release-input assembly."));
    for (id, scope, waiver) in [
        (
            "clean_build_provenance",
            "DECISION-003 exact-candidate single-gate human override",
            &waivers[0],
        ),
        (
            "historical_0_5_0_preview_2_rollback_artifact",
            "DECISION-001 old missing binary excluded from this candidate scope",
            &waivers[1],
        ),
    ] {
        let mut row = gate(
            id,
            scope,
            WaivedByOperator,
            waiver.clone(),
            "Waiver does not establish technical success or authorize any other gate/deployment.",
        );
        row.governance_disposition = Some("waived_by_operator");
        gates.push(row);
    }
    gates
}
