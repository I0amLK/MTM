//! Static integrity checks; never reads a live selector or author-specific home.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Component, Path};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{Result, git};

#[path = "record_layout.rs"]
mod layout;

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
    Ok(serde_json::from_slice(&read_bytes(
        root,
        path,
        8 * 1024 * 1024,
    )?)?)
}

pub(crate) fn read_bytes(root: &Path, path: &str, limit: u64) -> Result<Vec<u8>> {
    let path = safe_path(root, path)?;
    let metadata = fs::metadata(&path)?;
    require(
        metadata.is_file() && metadata.len() <= limit,
        "record must be a bounded regular file",
    )?;
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    require(bytes.len() as u64 <= limit, "record grew beyond its bound")?;
    Ok(bytes)
}

fn safe_path(root: &Path, relative: &str) -> Result<std::path::PathBuf> {
    let path = Path::new(relative);
    require(
        !relative.is_empty()
            && relative.len() <= 512
            && !relative.contains('\\')
            && relative
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && path
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
        "record path must be repository relative",
    )?;
    let joined = root.join(path);
    let mut component_path = root.to_path_buf();
    for component in path.components() {
        component_path.push(component);
        require(
            !fs::symlink_metadata(&component_path)?
                .file_type()
                .is_symlink(),
            "record path cannot contain a symlink",
        )?;
    }
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

fn preserve_receipt_prefix(previous: &Value, current: &Value) -> Result<()> {
    if previous.get("receipts").is_some() {
        require(
            array(current, "receipts")?.starts_with(array(previous, "receipts")?),
            "committed iteration receipts cannot be deleted or rewritten",
        )?;
    }
    Ok(())
}

fn preserve_iteration_receipts(root: &Path) -> Result<()> {
    let paths = git(
        root,
        &[
            "ls-tree",
            "-rz",
            "--name-only",
            "HEAD",
            "--",
            "records/iterations",
        ],
    )?;
    let mut count = 0;
    for path in paths
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        count += 1;
        require(count <= 512, "iteration history exceeds fixed bound")?;
        let path = std::str::from_utf8(path)?;
        let current = load(root, path)?;
        let previous: Value =
            serde_json::from_slice(&git(root, &["show", &format!("HEAD:{path}")])?)?;
        preserve_receipt_prefix(&previous, &current)?;
    }
    Ok(())
}

pub(crate) fn validate(root: &Path) -> Result<Value> {
    let graph = load(root, "records/governance/migration-graph.json")?;
    let count = validate_graph(&graph)?;
    preserve_history(root, &graph)?;
    preserve_iteration_receipts(root)?;
    let layout = load(root, "records/governance/record-layout.json")?;
    let layout_summary = layout::validate(root, &layout)?;
    let historical_releases = layout::historical_releases(root)?;
    let hashes = layout_summary["evidence_hashes_checked"].clone();
    Ok(
        json!({"ok":true,"scope":"static_record_integrity_only","milestones":count,
            "historical_hashes_checked":hashes,"layout":layout_summary,
            "historical_releases":historical_releases,"live_deployment_checked":false,
            "baseline_history_and_notices_unchanged":true,"release_qualified":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_receipt_seals_cannot_disappear_or_change_with_the_expected_hash() -> Result<()> {
        let previous = json!({"receipts":[{"id":"review","sealed_reports":[
            {"path":"records/evidence/MTM-016/report.json","sha256":"a".repeat(64)}]}]});
        let mut appended = previous.clone();
        appended["receipts"]
            .as_array_mut()
            .ok_or("missing fixture receipts")?
            .push(json!({"id":"next"}));
        preserve_receipt_prefix(&previous, &appended)?;
        assert!(preserve_receipt_prefix(&previous, &json!({"receipts":[]})).is_err());
        assert!(preserve_receipt_prefix(&previous, &json!({})).is_err());
        let mut edited = previous.clone();
        edited["receipts"][0]["sealed_reports"][0]["sha256"] = json!("b".repeat(64));
        assert!(preserve_receipt_prefix(&previous, &edited).is_err());
        Ok(())
    }

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
