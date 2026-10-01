//! Revision-bound structured editing. The existing patch transaction is the only
//! writer; this module parses, transforms and prepares without filesystem writes.
use super::*;
use serde::Deserialize;
use serde_json::json;

const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Action {
    Create,
    Write,
    Edit,
    Delete,
    Move,
    Copy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    action: Action,
    path: String,
    revision: Option<String>,
    content: Option<String>,
    destination: Option<String>,
    edits: Option<Vec<LineEdit>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LineEdit {
    op: EditOp,
    start_line: Option<usize>,
    end_line: Option<usize>,
    line: Option<usize>,
    content: Option<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EditOp {
    Replace,
    Delete,
    InsertAfter,
    InsertBefore,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    changes: Vec<Change>,
    #[serde(default)]
    dry_run: bool,
    idempotency_key: Option<String>,
}

impl Request {
    fn parse(arguments: &Map<String, Value>) -> Result<Self, ReCtmError> {
        let bytes =
            serde_json::to_vec(arguments).map_err(|_| validation("Invalid change request"))?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(validation("apply_changes request exceeds 1 MiB"));
        }
        let request: Self = serde_json::from_slice(&bytes)
            .map_err(|_| validation("Malformed structured change, field type or unknown field"))?;
        if request.changes.is_empty() || request.changes.len() > 100 {
            return Err(validation("changes must contain 1..100 entries"));
        }
        if request
            .idempotency_key
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 128 || s.contains('\0'))
        {
            return Err(validation(
                "idempotency_key must contain 1..128 bytes without NUL",
            ));
        }
        for change in &request.changes {
            if change.path.is_empty() {
                return Err(validation("path is required"));
            }
            if change
                .revision
                .as_ref()
                .is_some_and(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return Err(validation("revision must be a SHA-256 hex digest"));
            }
            match change.action {
                Action::Create | Action::Write => {
                    if change.content.is_none()
                        || change.destination.is_some()
                        || change.edits.is_some()
                        || (change.action == Action::Create && change.revision.is_some())
                    {
                        return Err(validation(
                            "create/write require content; create rejects revision; edits/destination are not accepted",
                        ));
                    }
                }
                Action::Edit => {
                    if change.content.is_some()
                        || change.destination.is_some()
                        || change
                            .edits
                            .as_ref()
                            .is_none_or(|e| e.is_empty() || e.len() > 200)
                    {
                        return Err(validation(
                            "edit requires 1..200 edits and rejects content/destination",
                        ));
                    }
                }
                Action::Delete => {
                    if change.content.is_some()
                        || change.destination.is_some()
                        || change.edits.is_some()
                    {
                        return Err(validation("delete accepts only path and revision"));
                    }
                }
                Action::Move | Action::Copy => {
                    if change.destination.as_ref().is_none_or(String::is_empty)
                        || change.content.is_some()
                        || change.edits.is_some()
                    {
                        return Err(validation(
                            "move/copy require destination and reject content/edits",
                        ));
                    }
                }
            }
        }
        Ok(request)
    }
}

pub(super) fn prepare(
    workspace: &NativeWorkspace,
    arguments: &Map<String, Value>,
) -> Result<(PreparedPatch, PatchInvocation), ReCtmError> {
    let request = Request::parse(arguments)?;
    let identity = stable_directory_identity(&workspace.root)?;
    let mut paths = BTreeSet::new();
    let mut resolutions = BTreeMap::new();
    // Resolve every source and destination before any reads or staging. Aliases
    // such as a and ./a name one slot; no chained writes exist in this tool.
    for change in &request.changes {
        for path in std::iter::once(&change.path).chain(change.destination.as_ref()) {
            workspace.deny_patch_symlink_components(path)?;
            let resolved = workspace.resolve_for_write(path)?;
            resolutions.insert(path.clone(), resolved.clone());
            if !paths.insert(resolved.display) {
                return Err(validation(
                    "A resolved path may appear only once in changes",
                ));
            }
        }
    }
    let invocation = PatchInvocation::structured_scope(
        &paths.iter().cloned().collect::<Vec<_>>(),
        request.dry_run,
        mtm_core::canonical_arguments_sha256(arguments)?,
    )?;
    let mut prepared = PreparedPatch {
        workspace_root: workspace.root.clone(),
        workspace_identity: identity,
        arguments_sha256: invocation.arguments_sha256().to_owned(),
        dry_run: request.dry_run,
        changes: Vec::new(),
        dependencies: Vec::new(),
        strict_dependency_links: true,
        #[cfg(test)]
        legacy_result: false,
        evidence: BTreeMap::new(),
        authority: {
            let (path_facts, git_metadata) = workspace.collect_patch_authority_facts(&paths)?;
            PatchAuthoritySnapshot::Classified {
                path_facts,
                git_metadata,
            }
        },
        summary: Vec::new(),
        additions: 0,
        removals: 0,
        affected_files: Vec::new(),
    };
    let mut source_bytes = 0usize;
    for change in request.changes {
        let source = bound_resolution(workspace, &change.path, &resolutions)?;
        let (baseline, original, mode) = if source.existed {
            if change.action == Action::Create {
                return Err(validation_code(
                    "PATH_EXISTS",
                    "create requires an absent path",
                ));
            }
            let metadata = fs::symlink_metadata(&source.path).map_err(io_error)?;
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(ReCtmError::new(
                    "UNSAFE_CHANGE_SOURCE",
                    "Structured changes require a regular, non-hardlinked source",
                )
                .with_category(ErrorCategory::Security));
            }
            if source_bytes.saturating_add(usize::try_from(metadata.len()).unwrap_or(usize::MAX))
                > MAX_BYTES
            {
                return Err(validation("Structured source bytes exceed 64 MiB"));
            }
            let (captured, baseline, text) = workspace
                .capture_existing_patch_file(&change.path, PatchPreparationSemantics::Authority)?;
            if captured.path != source.path || captured.display != source.display {
                return Err(patch_authority_facts_changed(
                    "Structured source resolution changed during capture",
                ));
            }
            bound_resolution(workspace, &change.path, &resolutions)?;
            if fs::symlink_metadata(&source.path)
                .map_err(io_error)?
                .nlink()
                != 1
            {
                return Err(patch_authority_facts_changed(
                    "Structured source gained a hardlink during capture",
                ));
            }
            source_bytes = source_bytes.saturating_add(text.len());
            if source_bytes > MAX_BYTES {
                return Err(validation("Captured structured source bytes exceed 64 MiB"));
            }
            let PatchBaseline::File { fingerprint } = &baseline else {
                return Err(internal("Missing source fingerprint"));
            };
            if change.revision.as_deref().is_none() {
                return Err(ReCtmError::new(
                    "REVISION_REQUIRED",
                    "Read the file and supply its revision",
                )
                .with_category(ErrorCategory::Validation));
            }
            if change.revision.as_deref() != Some(fingerprint.sha256.as_str()) {
                return Err(ReCtmError::new(
                    "REVISION_MISMATCH",
                    "File revision changed; read it again before editing",
                )
                .with_category(ErrorCategory::Conflict)
                .with_retryable(true));
            }
            let mode = Some(fingerprint.identity.mode & 0o777);
            (baseline, Some(text), mode)
        } else {
            if !matches!(change.action, Action::Create | Action::Write) {
                return Err(ReCtmError::new("NOT_FOUND", "Change source does not exist")
                    .with_category(ErrorCategory::NotFound));
            }
            if change.revision.is_some() {
                return Err(
                    ReCtmError::new("REVISION_MISMATCH", "Missing path has no revision")
                        .with_category(ErrorCategory::Conflict),
                );
            }
            (PatchBaseline::Missing, None, None)
        };
        let old = original.as_deref().unwrap_or("");
        match change.action {
            Action::Create | Action::Write | Action::Edit => {
                let (content, edit_evidence) = if change.action == Action::Edit {
                    let result = edit_outcome(old, change.edits.as_deref().unwrap_or_default())?;
                    (result.0, Some((result.1, result.2, result.3)))
                } else {
                    (change.content.unwrap_or_default(), None)
                };
                if content.len() > MAX_BYTES {
                    return Err(validation("Changed file exceeds 64 MiB"));
                }
                let unchanged = original.as_deref() == Some(content.as_str());
                let operation = if unchanged {
                    "unchanged"
                } else if source.existed {
                    "write"
                } else {
                    "create"
                };
                let mut detail = evidence(&content, old, unchanged);
                if let Some((ranges, _, _)) = &edit_evidence {
                    detail["changed_ranges"] = json!(ranges);
                }
                prepared.evidence.insert(source.display.clone(), detail);
                prepared.affected_files.push(PreparedAffectedFile {
                    operation: operation.into(),
                    path: source.display.clone(),
                });
                prepared.summary.push(format!(
                    "{} {}",
                    if unchanged { "=" } else { "M" },
                    source.display
                ));
                if !unchanged {
                    let (added, removed) = edit_evidence
                        .as_ref()
                        .map_or((count_lines(&content), count_lines(old)), |(_, a, r)| {
                            (*a, *r)
                        });
                    prepared.additions += added;
                    prepared.removals += removed;
                }
                let path = PreparedPathChange {
                    relative_path: source.display.clone(),
                    resolution: PatchPathResolution::ForWrite,
                    resolved: source,
                    baseline,
                    final_content: if unchanged {
                        None
                    } else {
                        Some(content.into_bytes())
                    },
                    final_mode: mode,
                };
                if unchanged {
                    prepared.dependencies.push(path);
                } else {
                    prepared.changes.push(path);
                }
            }
            Action::Delete => {
                prepared.removals += count_lines(old);
                prepared.summary.push(format!("D {}", source.display));
                prepared.affected_files.push(PreparedAffectedFile {
                    operation: "delete".into(),
                    path: source.display.clone(),
                });
                prepared.evidence.insert(
                    source.display.clone(),
                    json!({"total_lines":0,"changed_ranges":[]}),
                );
                prepared.changes.push(PreparedPathChange {
                    relative_path: source.display.clone(),
                    resolution: PatchPathResolution::ForWrite,
                    resolved: source,
                    baseline,
                    final_content: None,
                    final_mode: None,
                });
            }
            Action::Move | Action::Copy => {
                let destination = change
                    .destination
                    .as_deref()
                    .ok_or_else(|| validation("Missing destination"))?;
                let target = bound_resolution(workspace, destination, &resolutions)?;
                if target.existed {
                    return Err(validation_code(
                        "PATH_EXISTS",
                        "move/copy destination must not exist",
                    ));
                }
                let operation = if change.action == Action::Move {
                    "move"
                } else {
                    "copy"
                };
                let mut detail = evidence(old, "", false);
                detail["old_path"] = json!(source.display);
                prepared.evidence.insert(target.display.clone(), detail);
                prepared.additions += count_lines(old);
                prepared.summary.push(format!(
                    "{operation} {} -> {}",
                    source.display, target.display
                ));
                prepared.affected_files.push(PreparedAffectedFile {
                    operation: operation.into(),
                    path: target.display.clone(),
                });
                prepared.changes.push(PreparedPathChange {
                    relative_path: target.display.clone(),
                    resolution: PatchPathResolution::ForWrite,
                    resolved: target,
                    baseline: PatchBaseline::Missing,
                    final_content: Some(old.as_bytes().to_vec()),
                    final_mode: mode,
                });
                let source_path = PreparedPathChange {
                    relative_path: source.display.clone(),
                    resolution: PatchPathResolution::ForWrite,
                    resolved: source,
                    baseline,
                    final_content: None,
                    final_mode: None,
                };
                if change.action == Action::Move {
                    prepared.removals += count_lines(old);
                    prepared.affected_files.push(PreparedAffectedFile {
                        operation: "delete".into(),
                        path: source_path.resolved.display.clone(),
                    });
                    prepared.changes.push(source_path);
                } else {
                    prepared.dependencies.push(source_path);
                }
            }
        }
    }
    workspace.revalidate_prepared_patch(&prepared)?;
    Ok((prepared, invocation))
}

fn bound_resolution(
    workspace: &NativeWorkspace,
    path: &str,
    initial: &BTreeMap<String, ResolvedPath>,
) -> Result<ResolvedPath, ReCtmError> {
    workspace.deny_patch_symlink_components(path)?;
    let current = workspace.resolve_for_write(path)?;
    let previous = initial
        .get(path)
        .ok_or_else(|| internal("Missing structured path binding"))?;
    if current.path != previous.path
        || current.display != previous.display
        || current.existed != previous.existed
    {
        return Err(patch_authority_facts_changed(
            "Structured path resolution changed after classification",
        ));
    }
    Ok(current)
}

fn count_lines(text: &str) -> usize {
    text.split_inclusive('\n').count()
}

fn evidence(content: &str, original: &str, unchanged: bool) -> Value {
    json!({"revision":sha256_bytes(content.as_bytes()),"total_lines":count_lines(content),
    "match_quality":"exact","changed_ranges":if unchanged { json!([]) } else {
        json!([{"start_line":1,"end_line":count_lines(content),"added_lines":count_lines(content),"removed_lines":count_lines(original)}])
    }})
}

#[cfg(test)]
fn edit_lines(original: &str, edits: &[LineEdit]) -> Result<String, ReCtmError> {
    edit_outcome(original, edits).map(|result| result.0)
}

fn edit_outcome(
    original: &str,
    edits: &[LineEdit],
) -> Result<(String, Vec<Value>, usize, usize), ReCtmError> {
    // Number exactly the LF-delimited lines returned by MTM read_file. A bare
    // CR is content, not a hidden extra line. CRLF files retain CRLF endings.
    let (bom, text) = original
        .strip_prefix('\u{feff}')
        .map_or(("", original), |t| ("\u{feff}", t));
    let crlf = text
        .find('\n')
        .is_some_and(|i| i > 0 && text.as_bytes()[i - 1] == b'\r');
    let trailing = text.ends_with('\n');
    let mut raw_lines: Vec<String> = text.split_inclusive('\n').map(str::to_owned).collect();
    if raw_lines.is_empty() && !bom.is_empty() {
        raw_lines.push(String::new());
    }
    let lines: Vec<String> = raw_lines
        .iter()
        .map(|s| match s.strip_suffix('\n') {
            Some(body) => body.strip_suffix('\r').unwrap_or(body).to_owned(),
            None => s.clone(),
        })
        .collect();
    let total = lines.len();
    let mut replacements = Vec::new();
    for edit in edits {
        let (start, end) = match edit.op {
            EditOp::Replace | EditOp::Delete => {
                let start = edit
                    .start_line
                    .filter(|n| *n > 0)
                    .ok_or_else(|| validation("start_line must be positive"))?;
                let end = edit.end_line.unwrap_or(start);
                if end < start || edit.line.is_some() {
                    return Err(validation("Invalid line range"));
                }
                (start - 1, end)
            }
            EditOp::InsertAfter | EditOp::InsertBefore => {
                if edit.start_line.is_some() || edit.end_line.is_some() {
                    return Err(validation("Insertion uses line only"));
                }
                let line = edit
                    .line
                    .ok_or_else(|| validation("Insertion requires line"))?;
                let offset = if matches!(edit.op, EditOp::InsertBefore) {
                    line.checked_sub(1)
                        .ok_or_else(|| validation("insert_before starts at 1"))?
                } else {
                    line
                };
                (offset, offset)
            }
        };
        if end > total || start > total {
            return Err(validation("Edit addresses past the last line"));
        }
        let new = if matches!(edit.op, EditOp::Delete) {
            if edit.content.is_some() {
                return Err(validation("delete edit rejects content"));
            }
            Vec::new()
        } else {
            let content = edit
                .content
                .as_deref()
                .ok_or_else(|| validation("Edit content is required"))?;
            if content.is_empty() {
                Vec::new()
            } else {
                content
                    .replace("\r\n", "\n")
                    .replace('\r', "\n")
                    .split('\n')
                    .map(str::to_owned)
                    .collect()
            }
        };
        replacements.push((start, end, new));
    }
    replacements.sort_by_key(|(start, end, _)| (*start, *end));
    for pair in replacements.windows(2) {
        if pair[1].0 < pair[0].1
            || (pair[0].0 == pair[0].1 && pair[1].0 == pair[1].1 && pair[0].0 == pair[1].0)
        {
            return Err(validation("Line edits overlap"));
        }
    }
    let mut ranges = Vec::new();
    let mut added = 0usize;
    let mut removed = 0usize;
    for (start, end, new) in &replacements {
        if lines[*start..*end] != *new {
            let first = start + added + 1 - removed;
            ranges.push(json!({"start_line":first,"end_line":first+new.len()-1,"added_lines":new.len(),"removed_lines":end-start}));
            added += new.len();
            removed += end - start;
        }
    }
    let ending = if crlf { "\r\n" } else { "\n" };
    for (start, end, new) in replacements.into_iter().rev() {
        if lines[start..end] != new {
            raw_lines.splice(
                start..end,
                new.into_iter().map(|line| format!("{line}{ending}")),
            );
        }
    }
    let last = raw_lines.len().saturating_sub(1);
    for (i, line) in raw_lines.iter_mut().enumerate() {
        if i < last && !line.ends_with('\n') {
            line.push_str(ending);
        }
        if i == last && !trailing && total != 0 && line.ends_with('\n') && line != ending {
            line.truncate(line.len() - if line.ends_with("\r\n") { 2 } else { 1 });
        }
    }
    let content = if raw_lines.is_empty() {
        String::new()
    } else {
        format!("{bom}{}", raw_lines.concat())
    };
    Ok((content, ranges, added, removed))
}

#[cfg(test)]
#[path = "workspace_changes_tests.rs"]
mod tests;
