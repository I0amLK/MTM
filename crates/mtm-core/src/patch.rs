use mtm_contracts::{ErrorCategory, ReCtmError};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PatchOperation {
    pub kind: String,
    pub path: String,
    pub add_content: Option<String>,
    pub hunks: Vec<Vec<String>>,
    pub move_to: Option<String>,
}

impl PatchOperation {
    fn add(path: String, content: String) -> Self {
        Self {
            kind: "add".to_owned(),
            path,
            add_content: Some(content),
            hunks: Vec::new(),
            move_to: None,
        }
    }

    fn delete(path: String) -> Self {
        Self {
            kind: "delete".to_owned(),
            path,
            add_content: None,
            hunks: Vec::new(),
            move_to: None,
        }
    }

    fn update(path: String, hunks: Vec<Vec<String>>, move_to: Option<String>) -> Self {
        Self {
            kind: "update".to_owned(),
            path,
            add_content: None,
            hunks,
            move_to,
        }
    }
}

pub fn parse_patch(patch: &str) -> Result<Vec<PatchOperation>, ReCtmError> {
    let normalized = patch.replace("\r\n", "\n").replace('\r', "\n");
    let mut lines = normalized
        .split('\n')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    if lines
        .first()
        .is_none_or(|line| line.trim() != "*** Begin Patch")
        || lines
            .last()
            .is_none_or(|line| line.trim() != "*** End Patch")
    {
        return Err(patch_failed(
            "Patch must use *** Begin Patch / *** End Patch envelope.",
        ));
    }

    let mut operations = Vec::new();
    let mut index = 1;
    while index < lines.len().saturating_sub(1) {
        let line = &lines[index];
        if line.is_empty() {
            index += 1;
            continue;
        }
        if let Some(path) = line.strip_prefix("*** Add File: ") {
            index += 1;
            let mut content = Vec::new();
            while index < lines.len().saturating_sub(1) && !lines[index].starts_with("*** ") {
                let Some(value) = lines[index].strip_prefix('+') else {
                    return Err(patch_failed("Add file lines must start with '+'."));
                };
                content.push(value.to_owned());
                index += 1;
            }
            operations.push(PatchOperation::add(
                path.trim().to_owned(),
                format!("{}\n", content.join("\n")),
            ));
            continue;
        }
        if let Some(path) = line.strip_prefix("*** Delete File: ") {
            operations.push(PatchOperation::delete(path.trim().to_owned()));
            index += 1;
            continue;
        }
        if let Some(path) = line.strip_prefix("*** Update File: ") {
            let path = path.trim().to_owned();
            index += 1;
            let mut move_to = None;
            if index < lines.len().saturating_sub(1)
                && let Some(target) = lines[index].strip_prefix("*** Move to: ")
            {
                move_to = Some(target.trim().to_owned());
                index += 1;
            }
            let mut hunks = Vec::new();
            let mut current = Vec::new();
            while index < lines.len().saturating_sub(1) && !lines[index].starts_with("*** ") {
                if lines[index].starts_with("@@") {
                    if !current.is_empty() {
                        hunks.push(current);
                    }
                    current = Vec::new();
                } else {
                    current.push(lines[index].clone());
                }
                index += 1;
            }
            if !current.is_empty() {
                hunks.push(current);
            }
            operations.push(PatchOperation::update(path, hunks, move_to));
            continue;
        }
        return Err(patch_failed(&format!("Unrecognized patch line: {line}")));
    }
    Ok(operations)
}

pub fn apply_update_hunks(
    content: &str,
    hunks: &[Vec<String>],
    path: &str,
) -> Result<String, ReCtmError> {
    if hunks.is_empty() {
        return Ok(content.to_owned());
    }
    let normalized = content.replace("\r\n", "\n").replace('\r', "\n");
    let lines = normalized
        .split('\n')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let parsed = hunks
        .iter()
        .map(|hunk| parse_hunk(hunk))
        .collect::<Result<Vec<_>, _>>()?;
    let mut replacements = Vec::new();
    for (index, (old, new)) in parsed.into_iter().enumerate() {
        let matches = if old.is_empty() {
            vec![0]
        } else {
            find_all(&lines, &old)
        };
        if matches.is_empty() {
            let mut details = Map::new();
            details.insert("hunk_index".to_owned(), Value::from(index));
            return Err(ReCtmError::new(
                "PATCH_CONTEXT_NOT_FOUND",
                format!("Patch context did not match in {path}."),
            )
            .with_category(ErrorCategory::Validation)
            .with_retryable(true)
            .with_details(details));
        }
        if matches.len() > 1 {
            let mut details = Map::new();
            details.insert("hunk_index".to_owned(), Value::from(index));
            details.insert("match_count".to_owned(), Value::from(matches.len()));
            return Err(ReCtmError::new(
                "PATCH_CONTEXT_AMBIGUOUS",
                format!(
                    "Patch context matched {} locations in {path}.",
                    matches.len()
                ),
            )
            .with_category(ErrorCategory::Validation)
            .with_retryable(true)
            .with_details(details));
        }
        let start = matches[0];
        replacements.push((start, start + old.len(), new));
    }
    replacements.sort();
    for pair in replacements.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(
                ReCtmError::new("PATCH_HUNKS_OVERLAP", "Patch hunks overlap.")
                    .with_category(ErrorCategory::Validation),
            );
        }
    }
    let mut updated = lines;
    for (start, end, new) in replacements.into_iter().rev() {
        updated.splice(start..end, new);
    }
    let mut result = updated.join("\n");
    if content.contains("\r\n") {
        result = result.replace('\n', "\r\n");
    }
    Ok(result)
}

fn parse_hunk(hunk: &[String]) -> Result<(Vec<String>, Vec<String>), ReCtmError> {
    let mut old = Vec::new();
    let mut new = Vec::new();
    for raw in hunk {
        if raw == "*** End of File" {
            continue;
        }
        if raw.is_empty() {
            old.push(String::new());
            new.push(String::new());
            continue;
        }
        let mut characters = raw.chars();
        let marker = characters.next().unwrap_or_default();
        let value = if matches!(marker, ' ' | '-' | '+') {
            characters.collect::<String>()
        } else {
            raw.clone()
        };
        match marker {
            ' ' => {
                old.push(value.clone());
                new.push(value);
            }
            '-' => old.push(value),
            '+' => new.push(value),
            _ => {
                return Err(patch_failed(
                    "Update lines must start with space, '-' or '+'.",
                ));
            }
        }
    }
    Ok((old, new))
}

fn find_all(lines: &[String], needle: &[String]) -> Vec<usize> {
    if needle.len() > lines.len() {
        return Vec::new();
    }
    (0..=lines.len() - needle.len())
        .filter(|index| lines[*index..*index + needle.len()] == *needle)
        .collect()
}

fn patch_failed(message: &str) -> ReCtmError {
    ReCtmError::new("PATCH_FAILED", message).with_category(ErrorCategory::Validation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_add_delete_update_and_move() -> Result<(), ReCtmError> {
        let patch = concat!(
            "*** Begin Patch\n",
            "*** Add File: a.txt\n",
            "+hello\n",
            "*** Delete File: old.txt\n",
            "*** Update File: src.txt\n",
            "*** Move to: dst.txt\n",
            "@@\n",
            "-old\n",
            "+new\n",
            "*** End Patch\n"
        );
        let operations = parse_patch(patch)?;
        assert_eq!(operations.len(), 3);
        assert_eq!(operations[0].add_content.as_deref(), Some("hello\n"));
        assert_eq!(operations[2].move_to.as_deref(), Some("dst.txt"));
        Ok(())
    }

    #[test]
    fn applies_unique_hunk_and_preserves_crlf() -> Result<(), ReCtmError> {
        let hunks = vec![vec![
            " line1".to_owned(),
            "-line2".to_owned(),
            "+changed".to_owned(),
        ]];
        assert_eq!(
            apply_update_hunks("line1\r\nline2\r\n", &hunks, "a.txt")?,
            "line1\r\nchanged\r\n"
        );
        Ok(())
    }
}
