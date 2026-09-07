//! Static integrity checks; never reads a live selector or author-specific home.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{Result, git};

const RETIREMENT_BASELINE: &str = "b3ab147b72d72aa546c9c41bdbe71924aa5ebb97";

fn valid_status(status: &str) -> bool {
    matches!(
        status,
        "proposed"
            | "approved"
            | "in_progress"
            | "shadow"
            | "authoritative"
            | "blocked"
            | "completed"
            | "rejected"
            | "superseded"
    )
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn load(root: &Path, path: &str) -> Result<Value> {
    let path = safe_path(root, path)?;
    require(
        fs::metadata(&path)?.len() <= 8 * 1024 * 1024,
        "record exceeds fixed size bound",
    )?;
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn safe_path(root: &Path, relative: &str) -> Result<std::path::PathBuf> {
    let path = Path::new(relative);
    require(
        !relative.is_empty()
            && path
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
        "record path must be repository relative",
    )?;
    let joined = root.join(path);
    require(
        !fs::symlink_metadata(&joined)?.file_type().is_symlink(),
        "record cannot be a symlink",
    )?;
    require(
        joined.canonicalize()?.starts_with(root),
        "record escaped repository",
    )?;
    Ok(joined)
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value[key]
        .as_array()
        .ok_or_else(|| format!("missing array: {key}").into())
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing text: {key}").into())
}

fn validate_graph(graph: &Value) -> Result<usize> {
    require(
        graph["schema_version"] == "1.0.0",
        "unsupported migration graph schema",
    )?;
    let mut nodes = BTreeMap::new();
    for milestone in array(graph, "milestones")? {
        let id = text(milestone, "id")?;
        require(
            valid_status(text(milestone, "status")?),
            "unknown milestone status",
        )?;
        require(nodes.insert(id, milestone).is_none(), "duplicate milestone")?;
    }
    let mut dependencies = BTreeSet::new();
    for (id, milestone) in &nodes {
        for dependency in array(milestone, "dependencies")? {
            let dependency = dependency.as_str().ok_or("dependency must be text")?;
            require(
                nodes.contains_key(dependency) && dependency != *id,
                "invalid dependency",
            )?;
            require(
                dependencies.insert((*id, dependency)),
                "duplicate dependency",
            )?;
        }
        if matches!(
            text(milestone, "status")?,
            "completed" | "authoritative" | "rejected" | "superseded"
        ) {
            require(
                array(graph, "receipts")?.iter().any(|receipt| {
                    receipt["milestone_id"] == *id && receipt["status_after"] == milestone["status"]
                }),
                "terminal milestone lacks receipt",
            )?;
        }
    }
    let mut edges = BTreeSet::new();
    for edge in array(graph, "edges")? {
        require(
            edges.insert((text(edge, "source")?, text(edge, "target")?)),
            "duplicate edge",
        )?;
    }
    require(
        edges == dependencies,
        "edges differ from declared dependencies",
    )?;
    let mut visited = BTreeSet::new();
    loop {
        let before = visited.len();
        for id in nodes.keys() {
            if dependencies
                .iter()
                .filter(|(source, _)| source == id)
                .all(|(_, target)| visited.contains(target))
            {
                visited.insert(*id);
            }
        }
        if visited.len() == before {
            break;
        }
    }
    require(visited.len() == nodes.len(), "milestone dependency cycle")?;
    let mut event_ids = BTreeSet::new();
    let mut latest = BTreeMap::new();
    for event in array(graph, "events")? {
        require(
            event_ids.insert(text(event, "event_id")?),
            "duplicate event",
        )?;
        let id = text(event, "milestone_id")?;
        require(nodes.contains_key(id), "event for unknown milestone")?;
        require(
            valid_status(text(event, "status_before")?)
                && valid_status(text(event, "status_after")?),
            "unknown event status",
        )?;
        if let Some(previous) = latest.get(id) {
            require(
                *previous == text(event, "status_before")?,
                "event status chain drift",
            )?;
        }
        latest.insert(id, text(event, "status_after")?);
    }
    for (id, milestone) in nodes {
        require(
            latest.get(id).copied() == Some(text(milestone, "status")?),
            "milestone lacks current status event",
        )?;
    }
    Ok(visited.len())
}

fn validate_append_only(previous: &Value, current: &Value) -> Result<()> {
    for key in ["events", "receipts"] {
        require(
            array(current, key)?.starts_with(array(previous, key)?),
            "historical record prefix changed",
        )?;
    }
    Ok(())
}

fn preserve_history(root: &Path, graph: &Value) -> Result<()> {
    git(
        root,
        &["merge-base", "--is-ancestor", RETIREMENT_BASELINE, "HEAD"],
    )?;
    let baseline_graph: Value = serde_json::from_slice(&git(
        root,
        &[
            "show",
            &format!("{RETIREMENT_BASELINE}:records/governance/migration-graph.json"),
        ],
    )?)?;
    validate_append_only(&baseline_graph, graph)?;
    let changed = git(
        root,
        &[
            "diff",
            "--name-only",
            RETIREMENT_BASELINE,
            "--",
            "LICENSE",
            "NOTICE",
            "records/governance/record-layout.json",
            "records/governance/source-baseline.json",
            "records/evidence/MTM-00*",
            "records/evidence/MTM-01[0-5]/*",
        ],
    )?;
    require(
        changed.is_empty(),
        "historical evidence or legal notice changed during retirement",
    )
}

pub(crate) fn validate(root: &Path) -> Result<Value> {
    let graph = load(root, "records/governance/migration-graph.json")?;
    let count = validate_graph(&graph)?;
    preserve_history(root, &graph)?;
    let layout = load(root, "records/governance/record-layout.json")?;
    let mut hashes = 0;
    let mut locators = BTreeSet::new();
    for relocation in array(&layout, "relocations")? {
        let locator = text(relocation, "current_path")?;
        require(locators.insert(locator), "duplicate record locator")?;
        let path = safe_path(root, locator)?;
        if relocation["kind"] == "evidence" {
            require(
                relocation["sha256"].is_string(),
                "evidence digest is mandatory",
            )?;
        }
        if let Some(hash) = relocation["sha256"].as_str() {
            require(
                hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "invalid evidence digest",
            )?;
            require(
                fs::metadata(&path)?.len() <= 64 * 1024 * 1024,
                "evidence exceeds fixed size bound",
            )?;
            require(
                format!("{:x}", Sha256::digest(fs::read(path)?)) == hash,
                "historical evidence digest changed",
            )?;
            hashes += 1;
        }
    }
    for entry in fs::read_dir(root)? {
        require(
            entry?.path().extension().is_none_or(|ext| ext != "json"),
            "repository-root JSON records are forbidden",
        )?;
    }
    Ok(
        json!({"ok":true,"scope":"static_record_integrity_only","milestones":count,"historical_hashes_checked":hashes,"live_deployment_checked":false,"baseline_history_and_notices_unchanged":true}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph() -> Value {
        json!({"schema_version":"1.0.0","milestones":[{"id":"MTM-A","status":"in_progress","dependencies":[]}],
            "edges":[],"receipts":[],"events":[{"event_id":"1","milestone_id":"MTM-A","status_before":"approved","status_after":"in_progress"}]})
    }

    #[test]
    fn graph_rejects_unknown_dependencies_and_missing_receipts() {
        let mut unknown = graph();
        unknown["milestones"][0]["dependencies"] = json!(["missing"]);
        assert!(validate_graph(&unknown).is_err());
        let mut terminal = graph();
        terminal["milestones"][0]["status"] = json!("completed");
        assert!(validate_graph(&terminal).is_err());
    }

    #[test]
    fn graph_rejects_event_drift_and_cycles() {
        let mut stale = graph();
        stale["events"][0]["status_after"] = json!("approved");
        assert!(validate_graph(&stale).is_err());
        let mut cycle = graph();
        cycle["milestones"] = json!([
            {"id":"A","status":"in_progress","dependencies":["B"]},
            {"id":"B","status":"in_progress","dependencies":["A"]}
        ]);
        cycle["edges"] = json!([{"source":"A","target":"B"},{"source":"B","target":"A"}]);
        assert!(validate_graph(&cycle).is_err());
    }

    #[test]
    fn valid_graph_is_independent_of_deployment() -> Result<()> {
        assert_eq!(validate_graph(&graph())?, 1);
        assert!(safe_path(Path::new("/"), "../etc/passwd").is_err());
        assert!(safe_path(Path::new("/"), "/etc/passwd").is_err());
        Ok(())
    }

    #[test]
    fn unknown_schema_and_status_cannot_masquerade_as_valid_records() {
        let mut unknown = graph();
        unknown["schema_version"] = json!("99.0.0");
        assert!(validate_graph(&unknown).is_err());
        let mut unknown = graph();
        unknown["milestones"][0]["status"] = json!("unchecked");
        unknown["events"][0]["status_after"] = json!("unchecked");
        assert!(validate_graph(&unknown).is_err());
    }

    #[test]
    fn rejected_history_cannot_be_deleted_or_relabelled() -> Result<()> {
        let previous = json!({"events":[{"status":"rejected"}],"receipts":[{"ok":false}]});
        let appended = json!({"events":[{"status":"rejected"},{"status":"accepted"}],"receipts":[{"ok":false},{"ok":true}]});
        validate_append_only(&previous, &appended)?;
        let removed = json!({"events":[],"receipts":[]});
        assert!(validate_append_only(&previous, &removed).is_err());
        let relabelled = json!({"events":[{"status":"accepted"}],"receipts":[{"ok":true}]});
        assert!(validate_append_only(&previous, &relabelled).is_err());
        Ok(())
    }
}
