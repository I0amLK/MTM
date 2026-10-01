use std::fmt;

use mtm_contracts::{ErrorCategory, ReCtmError};
use serde::{Deserialize, Serialize};

#[path = "patch_legacy.rs"]
mod legacy;
pub use legacy::{apply_update_hunks, parse_patch};

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PatchOperation {
    pub kind: String,
    pub path: String,
    pub add_content: Option<String>,
    pub hunks: Vec<Vec<String>>,
    pub move_to: Option<String>,
}

impl fmt::Debug for PatchOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PatchOperation")
            .field("kind", &self.kind)
            .field("path", &self.path)
            .field(
                "add_content",
                &self.add_content.as_ref().map(|_| "[REDACTED]"),
            )
            .field("hunk_count", &self.hunks.len())
            .field("move_to", &self.move_to)
            .finish()
    }
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

pub fn parse_patch_current(patch: &str) -> Result<Vec<PatchOperation>, ReCtmError> {
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
            while index < lines.len().saturating_sub(1)
                && (!lines[index].starts_with("*** ") || lines[index] == "*** End of File")
            {
                if lines[index].starts_with("@@") {
                    if !current.is_empty() {
                        hunks.push(current);
                    }
                    current = vec![lines[index].clone()];
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

    #[test]
    fn operation_debug_redacts_patch_content() -> Result<(), ReCtmError> {
        let operations = parse_patch(
            "*** Begin Patch\n*** Add File: out.txt\n+SECRET_PATCH_BODY\n*** End Patch\n",
        )?;
        let debug = format!("{:?}", operations[0]);
        assert!(!debug.contains("SECRET_PATCH_BODY"));
        Ok(())
    }
}
