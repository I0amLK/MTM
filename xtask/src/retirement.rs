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
    #[serde(default)]
    families: Vec<Family>,
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
#[serde(deny_unknown_fields)]
struct Family {
    name: String,
    disposition: Disposition,
    rationale: String,
    replacements: Vec<String>,
    verification: Vec<String>,
    members: Vec<Member>,
    #[serde(default)]
    pending_acceptance: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    path: String,
    baseline_sha256: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Disposition {
    ReplacedByRust,
    HistoricalComparisonRetired,
    ConsolidatedWithPendingAcceptance,
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

fn check_coverage(
    path: &str,
    baseline_sha256: &str,
    rationale: &str,
    replacements: &[String],
    verification: &[String],
    paths: &mut BTreeSet<String>,
) -> Result<()> {
    relative(path)?;
    if !path.ends_with(".py")
        || !["scripts/", "tests/", "conformance/"]
            .iter()
            .any(|prefix| path.starts_with(prefix))
        || !paths.insert(path.to_owned())
    {
        return Err("duplicate or out-of-scope Python retirement".into());
    }
    if baseline_sha256.len() != 64
        || !baseline_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || rationale.trim().is_empty()
        || rationale.len() > 2000
        || replacements.is_empty()
        || replacements.len() > 32
        || verification.is_empty()
        || verification.len() > 32
        || verification
            .iter()
            .any(|text| text.is_empty() || text.len() > 1000)
    {
        return Err("retirement lacks bounded provenance or replacement coverage".into());
    }
    for replacement in replacements {
        relative(replacement)?;
        if !replacement.ends_with(".rs") {
            return Err("retirement replacement must name Rust source or tests".into());
        }
    }
    Ok(())
}

fn check_plan(plan: &Plan) -> Result<BTreeSet<String>> {
    let family_member_count = plan
        .families
        .iter()
        .try_fold(0_usize, |total, family| {
            total.checked_add(family.members.len())
        })
        .ok_or("retirement member count overflow")?;
    if plan.schema_version != "1.0.0"
        || plan.milestone != "MTM-016"
        || plan.baseline_commit != BASELINE
        || plan.entries.len() + family_member_count > 512
        || plan.families.len() > 64
    {
        return Err("unsupported retirement plan or baseline".into());
    }
    let mut paths = BTreeSet::new();
    for entry in &plan.entries {
        if matches!(
            entry.disposition,
            Disposition::ConsolidatedWithPendingAcceptance
        ) {
            return Err("pending consolidation must name a family and its acceptance gaps".into());
        }
        check_coverage(
            &entry.path,
            &entry.baseline_sha256,
            &entry.rationale,
            &entry.replacements,
            &entry.verification,
            &mut paths,
        )?;
    }
    let mut family_names = BTreeSet::new();
    for family in &plan.families {
        let pending = &family.pending_acceptance;
        if pending.len() > 32
            || pending
                .iter()
                .any(|item| item.trim().is_empty() || item.len() > 1000)
            || matches!(
                family.disposition,
                Disposition::ConsolidatedWithPendingAcceptance
            ) == pending.is_empty()
        {
            return Err("family disposition must preserve explicit pending acceptance".into());
        }
        if family.name.trim().is_empty()
            || family.name.len() > 128
            || !family_names.insert(family.name.as_str())
            || family.members.is_empty()
        {
            return Err("invalid or duplicate retirement family".into());
        }
        for member in &family.members {
            check_coverage(
                &member.path,
                &member.baseline_sha256,
                &family.rationale,
                &family.replacements,
                &family.verification,
                &mut paths,
            )?;
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

fn validate_retired_source(
    root: &Path,
    path: &str,
    baseline_sha256: &str,
    replacements: &[String],
) -> Result<()> {
    match fs::symlink_metadata(root.join(path)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err("retired Python source remains present or unreadable".into()),
    }
    let baseline = git(root, &["show", &format!("{BASELINE}:{path}")])?;
    if format!("{:x}", Sha256::digest(&baseline)) != baseline_sha256 {
        return Err("retired Python baseline digest mismatch".into());
    }
    for replacement in replacements {
        let path = root.join(replacement);
        if !path.is_file()
            || fs::symlink_metadata(&path)?.file_type().is_symlink()
            || !path.canonicalize()?.starts_with(root)
        {
            return Err("Rust retirement replacement is missing or escapes checkout".into());
        }
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
    let mut consolidated = 0;
    for entry in &plan.entries {
        validate_retired_source(
            root,
            &entry.path,
            &entry.baseline_sha256,
            &entry.replacements,
        )?;
        match entry.disposition {
            Disposition::ReplacedByRust => replaced += 1,
            Disposition::HistoricalComparisonRetired => comparisons += 1,
            Disposition::ConsolidatedWithPendingAcceptance => {
                return Err("unexpected standalone consolidation".into());
            }
        }
    }
    for family in &plan.families {
        for member in &family.members {
            validate_retired_source(
                root,
                &member.path,
                &member.baseline_sha256,
                &family.replacements,
            )?;
            match family.disposition {
                Disposition::ReplacedByRust => replaced += 1,
                Disposition::HistoricalComparisonRetired => comparisons += 1,
                Disposition::ConsolidatedWithPendingAcceptance => consolidated += 1,
            }
        }
    }
    let retired = plan.entries.len()
        + plan
            .families
            .iter()
            .map(|family| family.members.len())
            .sum::<usize>();
    Ok(json!({
        "ok":true,"scope":"reviewed_python_deletion_provenance",
        "retired_python_files":retired,"retirement_families":plan.families.len(),
        "replaced_by_rust":replaced,
        "consolidated_with_pending_acceptance":consolidated,
        "pending_family_acceptance":plan.families.iter().filter(|family| !family.pending_acceptance.is_empty())
            .map(|family| json!({"family":family.name,"pending":family.pending_acceptance})).collect::<Vec<_>>(),
        "historical_comparisons_retired":comparisons,
        "baseline_hashes_checked":retired,
        "runtime_parity_proven":false,"release_qualified":false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consolidation_cannot_hide_unfinished_acceptance() -> Result<()> {
        let mut value = fixture();
        value["families"] = json!([{
            "name":"target-family","disposition":"consolidated_with_pending_acceptance",
            "rationale":"historical runner retired; forward target qualification remains separate",
            "replacements":["xtask/src/qualify.rs"],"verification":["cargo xtask retirement"],
            "members":[{"path":"scripts/target.py","baseline_sha256":"b".repeat(64)}]
        }]);
        assert!(check_plan(&serde_json::from_value(value.clone())?).is_err());
        value["families"][0]["pending_acceptance"] = json!(["Exact candidate host qualification"]);
        assert!(check_plan(&serde_json::from_value(value.clone())?).is_ok());
        value["families"][0]["disposition"] = json!("replaced_by_rust");
        assert!(check_plan(&serde_json::from_value(value)?).is_err());
        Ok(())
    }

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
    fn family_members_expand_into_the_exact_deletion_set() -> Result<()> {
        let mut value = fixture();
        value["families"] = json!([{
            "name":"release_family",
            "disposition":"replaced_by_rust",
            "rationale":"grouped release replacement",
            "replacements":["xtask/src/commit_message.rs"],
            "verification":["cargo test -p mtm-xtask"],
            "members":[{"path":"tests/family.py","baseline_sha256":"b".repeat(64)}]
        }]);
        let plan: Plan = serde_json::from_value(value)?;
        let observed = BTreeSet::from(["scripts/old.py".to_owned(), "tests/family.py".to_owned()]);
        match_deleted(&plan, &observed)?;
        assert!(match_deleted(&plan, &BTreeSet::from(["scripts/old.py".to_owned()])).is_err());

        let mut duplicate = fixture();
        duplicate["families"] = json!([{
            "name":"duplicate_family",
            "disposition":"replaced_by_rust",
            "rationale":"must reject duplicate member",
            "replacements":["xtask/src/commit_message.rs"],
            "verification":["cargo test -p mtm-xtask"],
            "members":[{"path":"scripts/old.py","baseline_sha256":"b".repeat(64)}]
        }]);
        assert!(check_plan(&serde_json::from_value(duplicate)?).is_err());
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
