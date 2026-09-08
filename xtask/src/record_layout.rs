//! Canonical record namespaces and sealed observations, independent of deployment.
use super::*;

const REQUIRED_GOVERNANCE: [&str; 6] = [
    "authority-inventory.json",
    "engineering-graph.json",
    "migration-graph.json",
    "project-progress.json",
    "record-layout.json",
    "source-baseline.json",
];
const MAX_ENTRIES: usize = 10_000;

fn numbered(name: &str, prefix: &str, suffix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|s| s.strip_suffix(suffix))
        .is_some_and(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()))
}

fn children(root: &Path, relative: &str, budget: &mut usize) -> Result<Vec<String>> {
    let path = safe_path(root, relative)?;
    require(path.is_dir(), "record namespace must be a directory")?;
    let mut names = Vec::new();
    for entry in fs::read_dir(path)? {
        require(*budget > 0, "record tree exceeds entry bound")?;
        *budget -= 1;
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "record name must be UTF-8")?;
        safe_path(root, &format!("{relative}/{name}"))?;
        names.push(name);
    }
    names.sort();
    Ok(names)
}

fn json_file(root: &Path, relative: &str) -> Result<()> {
    require(
        relative.ends_with(".json") && safe_path(root, relative)?.is_file(),
        "record namespace may contain only regular JSON files",
    )
}

fn digest_matches(root: &Path, path: &str, expected: &str) -> Result<()> {
    require(
        expected.len() == 64
            && expected
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "record digest must be lowercase SHA-256",
    )?;
    let bytes = read_bytes(root, path, 64 * 1024 * 1024)?;
    require(
        format!("{:x}", Sha256::digest(bytes)) == expected,
        "sealed record digest changed",
    )
}

fn relocation_path(path: &str, kind: &str) -> bool {
    let parts: Vec<_> = path.split('/').collect();
    match parts.as_slice() {
        ["records", "governance", file] if kind == "governance" => file.ends_with(".json"),
        ["records", "validation", file] if kind == "validation" => file.ends_with(".json"),
        ["records", "evidence", milestone, file] if kind == "evidence" => {
            numbered(milestone, "MTM-", "") && file.ends_with(".json")
        }
        _ => false,
    }
}

fn sealed_observations(root: &Path, iterations: &[String]) -> Result<usize> {
    let mut seen = BTreeSet::new();
    for filename in iterations {
        let iteration = load(root, &format!("records/iterations/{filename}"))?;
        let Some(receipts) = iteration.get("receipts") else {
            continue;
        };
        let receipts = receipts
            .as_array()
            .ok_or("iteration receipts must be an array")?;
        require(receipts.len() <= 1024, "too many iteration receipts")?;
        let milestone = format!("MTM-{}", &filename[5..8]);
        for receipt in receipts {
            let Some(seals) = receipt.get("sealed_reports") else {
                continue;
            };
            let seals = seals.as_array().ok_or("sealed_reports must be an array")?;
            require(
                !seals.is_empty() && seals.len() <= 128,
                "invalid sealed report count",
            )?;
            for seal in seals {
                let path = text(seal, "path")?;
                require(
                    path.starts_with(&format!("records/evidence/{milestone}/"))
                        && relocation_path(path, "evidence")
                        && seen.insert(path.to_owned())
                        && seen.len() <= 512,
                    "duplicate or cross-milestone sealed observation",
                )?;
                digest_matches(root, path, text(seal, "sha256")?)?;
            }
        }
    }
    Ok(seen.len())
}

pub(super) fn validate(root: &Path, payload: &Value) -> Result<Value> {
    require(
        payload["schema_version"] == "1.0.0"
            && payload["layout_version"].as_u64() == Some(1)
            && payload["root_json_allowed"] == false,
        "unsupported record layout or root-record policy",
    )?;
    require(
        payload["canonical_roots"]
            == json!({
                "governance":"records/governance", "iterations":"records/iterations",
                "evidence":"records/evidence/MTM-NNN", "validation":"records/validation"
            }),
        "record namespace declarations changed",
    )?;
    for (index, entry) in fs::read_dir(root)?.enumerate() {
        require(index < MAX_ENTRIES, "repository root exceeds entry bound")?;
        require(
            entry?.path().extension().is_none_or(|ext| ext != "json"),
            "repository-root JSON records are forbidden",
        )?;
    }
    let mut budget = MAX_ENTRIES;
    let mut roots = children(root, "records", &mut budget)?;
    // The existing record-tree guide is documentation, not a fifth namespace.
    if roots.iter().any(|name| name == "README.md") {
        require(
            safe_path(root, "records/README.md")?.is_file(),
            "record guide must be a file",
        )?;
        roots.retain(|name| name != "README.md");
    }
    require(
        roots == ["evidence", "governance", "iterations", "validation"],
        "unknown record namespace",
    )?;
    let governance = children(root, "records/governance", &mut budget)?;
    for required in REQUIRED_GOVERNANCE {
        require(
            governance.iter().any(|name| name == required),
            "required governance record missing",
        )?;
    }
    for name in &governance {
        json_file(root, &format!("records/governance/{name}"))?;
    }
    let iterations = children(root, "records/iterations", &mut budget)?;
    require(!iterations.is_empty(), "iteration records missing")?;
    for name in &iterations {
        require(
            numbered(name, "ITER-", ".json"),
            "invalid iteration record name",
        )?;
        json_file(root, &format!("records/iterations/{name}"))?;
    }
    let milestones = children(root, "records/evidence", &mut budget)?;
    require(!milestones.is_empty(), "evidence namespaces missing")?;
    for name in &milestones {
        require(
            numbered(name, "MTM-", ""),
            "invalid evidence milestone name",
        )?;
        let directory = format!("records/evidence/{name}");
        for name in children(root, &directory, &mut budget)? {
            json_file(root, &format!("{directory}/{name}"))?;
        }
    }
    let validation = children(root, "records/validation", &mut budget)?;
    require(
        validation
            .iter()
            .any(|name| name == "local-validation.json"),
        "historical local validation record missing",
    )?;
    for name in validation {
        json_file(root, &format!("records/validation/{name}"))?;
    }

    let relocations = array(payload, "relocations")?;
    require(
        !relocations.is_empty() && relocations.len() <= 1024,
        "invalid relocation count",
    )?;
    let mut legacy_seen = BTreeSet::new();
    let mut current_seen = BTreeSet::new();
    let mut hashes = 0;
    for item in relocations {
        let legacy = text(item, "legacy_path")?;
        let current = text(item, "current_path")?;
        let kind = text(item, "kind")?;
        require(
            !legacy.contains(['/', '\\']) && legacy.ends_with(".json"),
            "legacy locator must be a root JSON filename",
        )?;
        require(
            legacy_seen.insert(legacy) && current_seen.insert(current),
            "relocations must be one-to-one",
        )?;
        require(
            relocation_path(current, kind),
            "unsupported relocation kind or namespace",
        )?;
        json_file(root, current)?;
        if kind == "evidence" || item.get("sha256").is_some() {
            digest_matches(root, current, text(item, "sha256")?)?;
            hashes += 1;
        }
    }
    let seals = sealed_observations(root, &iterations)?;
    Ok(
        json!({"root_json_count":0,"governance_record_count":governance.len(),
        "iteration_record_count":iterations.len(),"evidence_milestone_count":milestones.len(),
        "relocation_count":relocations.len(),"evidence_hashes_checked":hashes,
        "sealed_observation_hashes_checked":seals,"observations_reexecuted":false}),
    )
}

fn historical_identity(payload: &Value, milestone: &str, expected_count: u64) -> Result<u64> {
    require(
        payload["project"] == "MTM-reboot"
            && payload["milestone"] == milestone
            && payload["passed"] == true,
        "historical receipt identity or verdict changed",
    )?;
    let count = if milestone == "MTM-008" {
        payload["checks"].as_array().map(|items| items.len() as u64)
    } else {
        payload["check_count"].as_u64()
    };
    require(
        count == Some(expected_count),
        "historical receipt check count changed",
    )?;
    Ok(expected_count)
}

pub(super) fn historical_releases(root: &Path) -> Result<Value> {
    let mut evidence = BTreeMap::new();
    for (milestone, expected) in [
        ("MTM-003", 14),
        ("MTM-004", 10),
        ("MTM-005", 15),
        ("MTM-006", 8),
        ("MTM-007", 12),
        ("MTM-008", 10),
    ] {
        let filename = if milestone == "MTM-008" {
            "candidate-validation.json"
        } else {
            "target-validation.json"
        };
        let path = format!("records/evidence/{milestone}/{filename}");
        // Called only after the baseline-bound layout hashes have been verified.
        let bytes = read_bytes(root, &path, 8 * 1024 * 1024)?;
        let count = historical_identity(&serde_json::from_slice(&bytes)?, milestone, expected)?;
        evidence.insert(
            milestone,
            json!({"path":path,"sha256":format!("{:x}",Sha256::digest(bytes)),"check_count":count}),
        );
    }
    Ok(
        json!({"historical_milestones":evidence.len(),"evidence":evidence,
        "scope":"immutable_historical_receipts_only","current_release_qualified":false}),
    )
}

#[cfg(test)]
#[path = "record_layout_tests.rs"]
mod tests;
