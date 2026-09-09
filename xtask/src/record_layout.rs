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

fn historical_release_identity(
    payload: &Value,
    milestone: &str,
    phase: &str,
    version: &str,
    binary_field: &str,
    binary_sha256: &str,
) -> Result<()> {
    require(
        payload["schema_version"] == "1.0.0"
            && payload["milestone"] == milestone
            && payload["phase"] == phase
            && payload["version"] == version,
        "historical release identity changed",
    )?;
    let accepted = payload.get("passed").or_else(|| payload.get("ok"));
    require(
        accepted == Some(&Value::Bool(true)),
        "historical release verdict changed",
    )?;
    require(
        payload[binary_field] == binary_sha256,
        "historical release binary identity changed",
    )?;
    let rollback_recutover = payload["rollback"]["real_rollback_and_recutover_passed"] == true
        || (payload["checks"]["stable_rollback_smoke"] == true
            && payload["checks"]["candidate_recutover_smoke"] == true);
    require(
        rollback_recutover,
        "historical release rollback receipt changed",
    )?;
    if let Some(project) = payload.get("project") {
        require(
            project == "MTM-reboot",
            "historical release project changed",
        )?;
    }
    if let Some(info) = payload.get("release_info") {
        require(
            info["implementation"] == "rust"
                && info["python_runtime_required"] == false
                && info["version"] == version,
            "historical release runtime identity changed",
        )?;
    }
    Ok(())
}

fn historical_mtm015_lifecycle(root: &Path) -> Result<BTreeMap<&'static str, Value>> {
    let mut evidence = BTreeMap::new();
    for (name, filename, phase, expected_sha256, expected_count) in [
        (
            "target_qualification",
            "target-qualification.json",
            "target_qualification",
            "6155b14f9e5c365b0049dd2436b5f6888f403ab4d2685eb45e5e5e8079e05da5",
            Some(15_u64),
        ),
        (
            "candidate_stage",
            "candidate-stage.json",
            "candidate_stage",
            "5787fd9d54cb8eb918833ecc8fc8cba417adde9de0baa612577042abb506aed4",
            Some(9_u64),
        ),
        (
            "web_client",
            "web-client.json",
            "web_client",
            "345d9bdb3bd7da994b7406038ca739a18140c9e581c0ba6761f4e9328ee0040f",
            None,
        ),
    ] {
        let path = format!("records/evidence/MTM-015/{filename}");
        let bytes = read_bytes(root, &path, 8 * 1024 * 1024)?;
        let actual_sha256 = format!("{:x}", Sha256::digest(&bytes));
        require(
            actual_sha256 == expected_sha256,
            "MTM-015 lifecycle receipt digest changed",
        )?;
        let payload: Value = serde_json::from_slice(&bytes)?;
        let candidate_sha256 = payload["candidate_binary_sha256"]
            .as_str()
            .or_else(|| payload["binary_sha256"].as_str());
        require(
            payload["schema_version"] == "1.0.0"
                && payload["milestone"] == "MTM-015"
                && payload["phase"] == phase
                && payload["ok"] == true
                && candidate_sha256
                    == Some("2164c84701b191b06a66a5d28ba595697d355f9a3bdc78ca31ea455d49793d6a")
                && payload["selector_changed"] == false
                && payload["production_state_rewritten"] == false,
            "MTM-015 lifecycle receipt identity changed",
        )?;
        if let Some(expected_count) = expected_count {
            require(
                payload["check_count"].as_u64() == Some(expected_count),
                "MTM-015 lifecycle check count changed",
            )?;
        }
        evidence.insert(
            name,
            json!({"path":path,"sha256":actual_sha256,"phase":phase,
                "candidate_binary_sha256":"2164c84701b191b06a66a5d28ba595697d355f9a3bdc78ca31ea455d49793d6a"}),
        );
    }
    Ok(evidence)
}

pub(super) fn historical_releases(root: &Path) -> Result<Value> {
    let mut target_evidence = BTreeMap::new();
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
        target_evidence.insert(
            milestone,
            json!({"path":path,"sha256":format!("{:x}",Sha256::digest(bytes)),"check_count":count}),
        );
    }
    let mut release_evidence = BTreeMap::new();
    for (milestone, phase, version, binary_field, binary_sha256) in [
        (
            "MTM-009",
            "mtm009_preview_release",
            "0.4.0-preview.1",
            "binary_sha256",
            "e76c2124cddb73370d902394df3c143124870abf8f05240f1a72ca835a8e2477",
        ),
        (
            "MTM-011",
            "mtm011_preview_release",
            "0.4.0-preview.2",
            "binary_sha256",
            "5ed668d5bf765be2efd1b50933e941cf60dbbd414e3b6daab77745624d5cfa81",
        ),
        (
            "MTM-012",
            "mtm012_preview_release",
            "0.4.0-preview.3",
            "binary_sha256",
            "545ab9ef8cc01edf804581cb52c2b1a4158d03bd8a25ea00c7785039167f3659",
        ),
        (
            "MTM-013",
            "stable_0_4_0_release",
            "0.4.0",
            "binary_sha256",
            "3312ca75a1de8707e740963cc0add4b09430dccc9dc63a3145e4456ff2b0cdf3",
        ),
        (
            "MTM-014",
            "preview_release",
            "0.5.0-preview.1",
            "binary_sha256",
            "2b2cd48bea965fd21c5c54d3be3ead6917eaf40870e9aa801c48bb9484209036",
        ),
        (
            "MTM-015",
            "preview_release",
            "0.5.0-preview.2",
            "candidate_binary_sha256",
            "2164c84701b191b06a66a5d28ba595697d355f9a3bdc78ca31ea455d49793d6a",
        ),
    ] {
        let path = format!("records/evidence/{milestone}/preview-release.json");
        let path = if milestone == "MTM-013" {
            "records/evidence/MTM-013/stable-release.json".to_owned()
        } else {
            path
        };
        let bytes = read_bytes(root, &path, 8 * 1024 * 1024)?;
        historical_release_identity(
            &serde_json::from_slice(&bytes)?,
            milestone,
            phase,
            version,
            binary_field,
            binary_sha256,
        )?;
        release_evidence.insert(
            milestone,
            json!({"path":path,"sha256":format!("{:x}",Sha256::digest(bytes)),
                "version":version,"binary_sha256":binary_sha256}),
        );
    }
    let mtm015_lifecycle = historical_mtm015_lifecycle(root)?;
    Ok(
        json!({"historical_milestones":target_evidence.len()+release_evidence.len(),
        "historical_target_milestones":target_evidence.len(),
        "historical_release_milestones":release_evidence.len(),
        "target_evidence":target_evidence,"release_evidence":release_evidence,
        "mtm015_lifecycle_evidence":mtm015_lifecycle,
        "scope":"immutable_historical_receipts_only","live_selectors_checked":false,
        "current_release_qualified":false}),
    )
}

#[cfg(test)]
#[path = "record_layout_tests.rs"]
mod tests;
