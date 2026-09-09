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
        "source" | "protocol" | "permissions" | "upgrade" | "target" | "resource"
    )
}

fn validate_evidence(
    root: &Path,
    name: &str,
    value: &Value,
    manifest: &Manifest,
    cache: &mut BTreeMap<String, String>,
) -> Result<()> {
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
        return Ok(());
    }
    qualify::validate_receipt(
        value,
        &manifest.candidate_sha256,
        &manifest.baseline_sha256,
        name,
    )?;
    lineage(root, &value["harness_source_identity"], cache)
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
        let result = (|| -> Result<()> {
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
        gates.push(item(
            name,
            if result.is_ok() {
                "validated"
            } else {
                "blocked"
            },
            if result.is_ok() {
                "sealed_scope_revalidated_not_reexecuted"
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
            "current_inventory_empty"
        } else {
            "first_party_python_or_legacy_references_remain"
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
        "legacy_rust_reference_files":audit["legacy_rust_reference_file_count"]}),
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
        for name in [
            "browser_human",
            "native_commands",
            "copied_operator_state",
            "install_sigkill",
        ] {
            assert!(!supported(name));
            assert!(GATES.contains(&name));
        }
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
