//! A deletion ledger is evidence of reviewed scope, not proof of runtime parity.
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{Result, git};

const BASELINE: &str = "b3ab147b72d72aa546c9c41bdbe71924aa5ebb97";
const MANIFEST: &str = "records/governance/python-retirement.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema_version: String,
    milestone: String,
    baseline_commit: String,
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    baseline_sha256: String,
    disposition: Disposition,
    rationale: String,
    replacements: Vec<String>,
    verification: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Disposition {
    ReplacedByRust,
    HistoricalComparisonRetired,
}

fn relative(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 512
        || !Path::new(path)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err("retirement locator must remain repository-relative".into());
    }
    Ok(())
}

fn check_plan(plan: &Plan) -> Result<BTreeSet<String>> {
    if plan.schema_version != "1.0.0"
        || plan.milestone != "MTM-016"
        || plan.baseline_commit != BASELINE
        || plan.entries.len() > 512
    {
        return Err("unsupported retirement plan or baseline".into());
    }
    let mut paths = BTreeSet::new();
    for entry in &plan.entries {
        relative(&entry.path)?;
        if !entry.path.ends_with(".py")
            || !["scripts/", "tests/", "conformance/"]
                .iter()
                .any(|prefix| entry.path.starts_with(prefix))
            || !paths.insert(entry.path.clone())
        {
            return Err("duplicate or out-of-scope Python retirement".into());
        }
        if entry.baseline_sha256.len() != 64
            || !entry
                .baseline_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || entry.rationale.trim().is_empty()
            || entry.rationale.len() > 2000
            || entry.replacements.is_empty()
            || entry.replacements.len() > 32
            || entry.verification.is_empty()
            || entry.verification.len() > 32
            || entry
                .verification
                .iter()
                .any(|text| text.is_empty() || text.len() > 1000)
        {
            return Err("retirement lacks bounded provenance or replacement coverage".into());
        }
        for replacement in &entry.replacements {
            relative(replacement)?;
            if !replacement.ends_with(".rs") {
                return Err("retirement replacement must name Rust source or tests".into());
            }
        }
    }
    Ok(paths)
}

fn match_deleted(plan: &Plan, observed: &BTreeSet<String>) -> Result<()> {
    if check_plan(plan)? != *observed {
        return Err("Python deletions differ from the reviewed retirement ledger".into());
    }
    Ok(())
}

pub(crate) fn validate(root: &Path) -> Result<Value> {
    let manifest = root.join(MANIFEST);
    if fs::symlink_metadata(&manifest)?.file_type().is_symlink()
        || !manifest.canonicalize()?.starts_with(root)
        || fs::metadata(&manifest)?.len() > 1024 * 1024
    {
        return Err("unsafe or oversized retirement ledger".into());
    }
    let plan: Plan = serde_json::from_slice(&fs::read(manifest)?)?;
    check_plan(&plan)?;
    let removed = git(
        root,
        &[
            "diff",
            "--name-only",
            "-z",
            "--diff-filter=D",
            BASELINE,
            "--",
            "scripts",
            "conformance",
            "tests",
        ],
    )?;
    let mut observed = BTreeSet::new();
    for bytes in removed.split(|b| *b == 0).filter(|name| !name.is_empty()) {
        let path = std::str::from_utf8(bytes)?;
        if path.ends_with(".py") {
            observed.insert(path.to_owned());
        }
    }
    match_deleted(&plan, &observed)?;
    let mut replaced = 0;
    let mut comparisons = 0;
    for entry in &plan.entries {
        match fs::symlink_metadata(root.join(&entry.path)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("retired Python source remains present or unreadable".into()),
        }
        let baseline = git(root, &["show", &format!("{BASELINE}:{}", entry.path)])?;
        if format!("{:x}", Sha256::digest(&baseline)) != entry.baseline_sha256 {
            return Err("retired Python baseline digest mismatch".into());
        }
        for replacement in &entry.replacements {
            let path = root.join(replacement);
            if !path.is_file()
                || fs::symlink_metadata(&path)?.file_type().is_symlink()
                || !path.canonicalize()?.starts_with(root)
            {
                return Err("Rust retirement replacement is missing or escapes checkout".into());
            }
        }
        match entry.disposition {
            Disposition::ReplacedByRust => replaced += 1,
            Disposition::HistoricalComparisonRetired => comparisons += 1,
        }
    }
    Ok(json!({
        "ok":true,"scope":"reviewed_python_deletion_provenance",
        "retired_python_files":plan.entries.len(),"replaced_by_rust":replaced,
        "historical_comparisons_retired":comparisons,
        "baseline_hashes_checked":plan.entries.len(),
        "runtime_parity_proven":false,"release_qualified":false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        json!({"schema_version":"1.0.0","milestone":"MTM-016","baseline_commit":BASELINE,
            "entries":[{"path":"scripts/old.py","baseline_sha256":"a".repeat(64),
                "disposition":"replaced_by_rust","rationale":"covered by Rust",
                "replacements":["xtask/src/commit_message.rs"],"verification":["cargo test -p mtm-xtask"]}]})
    }

    #[test]
    fn undeclared_or_fictitious_deletions_are_rejected() -> Result<()> {
        let plan: Plan = serde_json::from_value(fixture())?;
        assert!(match_deleted(&plan, &BTreeSet::new()).is_err());
        let observed = BTreeSet::from(["scripts/old.py".to_owned()]);
        match_deleted(&plan, &observed)?;
        assert!(
            match_deleted(
                &plan,
                &BTreeSet::from([
                    "scripts/old.py".to_owned(),
                    "tests/unreviewed.py".to_owned(),
                ])
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn missing_coverage_unknown_schema_and_escape_fail_closed() -> Result<()> {
        for path in ["../old.py", "/old.py", "other/old.py", "scripts/old.rs"] {
            let mut value = fixture();
            value["entries"][0]["path"] = json!(path);
            assert!(check_plan(&serde_json::from_value(value)?).is_err());
        }
        for (field, replacement) in [
            ("baseline_sha256", json!("bad")),
            ("replacements", json!([])),
            ("verification", json!([])),
            ("rationale", json!("")),
        ] {
            let mut value = fixture();
            value["entries"][0][field] = replacement;
            assert!(check_plan(&serde_json::from_value(value)?).is_err());
        }
        let mut future = fixture();
        future["schema_version"] = json!("2.0.0");
        assert!(check_plan(&serde_json::from_value(future)?).is_err());
        let mut unknown = fixture();
        unknown["override"] = json!(true);
        assert!(serde_json::from_value::<Plan>(unknown).is_err());
        Ok(())
    }
}
