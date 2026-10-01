//! Bounded untracked additions from stable bytes, never Git external diff helpers.
use super::*;
pub(super) fn diff(
    workspace: &NativeWorkspace,
    repo: &git_scope::Repository,
    filters: &[String],
    max_bytes: usize,
) -> Result<(String, bool, Vec<String>), ReCtmError> {
    let mut command = repo.command("ls-files");
    command.extend(["-z".into(), "--others".into(), "--exclude-standard".into()]);
    if !filters.is_empty() {
        command.push("--".into());
        command.extend_from_slice(filters);
    }
    let listed = workspace.run_sync(command, 5000, 262144)?;
    ensure_exit_ok(&listed, "git untracked enumeration failed")?;
    git_scope::complete_output(&listed)?;
    let mut truncated = false;
    let raw = listed["stdout"].as_str().unwrap_or_default();
    if (!raw.is_empty() && !raw.ends_with('\0')) || raw.contains('\u{fffd}') {
        return Err(validation(
            "Untracked path listing is not complete UTF-8 NUL records; narrow the filter",
        ));
    }
    let mut output = String::new();
    let mut files = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    for (index, path) in raw.split_terminator('\0').enumerate() {
        if index >= 128 || output.len() >= max_bytes || std::time::Instant::now() >= deadline {
            truncated = true;
            break;
        }
        let absolute = repo.root.join(path);
        let relative = absolute
            .strip_prefix(&workspace.root)
            .map_err(|_| validation("Untracked path outside workspace"))?;
        let relative = relative
            .to_str()
            .ok_or_else(|| validation("Untracked path is not UTF-8"))?;
        workspace.deny_patch_symlink_components(relative)?;
        let resolved = workspace.resolve_for_write(relative)?;
        let metadata = fs::symlink_metadata(&resolved.path).map_err(io_error)?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(ReCtmError::new(
                "UNSAFE_UNTRACKED_FILE",
                "Untracked diff refuses linked/nonregular files",
            )
            .with_category(ErrorCategory::Security));
        }
        if metadata.len() > 8 * 1024 * 1024 {
            truncated = true;
            continue;
        }
        let (bytes, _) = read_stable_regular_file(&resolved.path)?;
        if fs::symlink_metadata(&resolved.path)
            .map_err(io_error)?
            .nlink()
            != 1
        {
            return Err(patch_authority_facts_changed(
                "Untracked source gained a hardlink",
            ));
        }
        let quoted = |prefix: &str| {
            let name = format!("{prefix}/{path}");
            if name
                .chars()
                .any(|c| c.is_whitespace() || c == '"' || c == '\\')
            {
                serde_json::to_string(&name).unwrap_or_default()
            } else {
                name
            }
        };
        let a = quoted("a");
        let b = quoted("b");
        let mode = if metadata.mode() & 0o111 != 0 {
            0o100755
        } else {
            0o100644
        };
        let mut section =
            format!("diff --git {a} {b}\nnew file mode {mode:06o}\n--- /dev/null\n+++ {b}\n");
        if let Ok(text) = std::str::from_utf8(&bytes)
            && !text.contains('\0')
        {
            let count = text.split_inclusive('\n').count();
            if count > 0 {
                section.push_str(&format!("@@ -0,0 +1,{count} @@\n"));
            }
            for line in text.split_inclusive('\n') {
                let budget = max_bytes.saturating_sub(output.len());
                if section.len() >= budget {
                    truncated = true;
                    break;
                }
                section.push('+');
                let available = budget.saturating_sub(section.len());
                let part = truncate_utf8_bytes(line, available);
                if part.len() < line.len() {
                    truncated = true;
                }
                section.push_str(&part);
                if section.len() >= budget {
                    truncated = true;
                    break;
                }
            }
            if !text.is_empty() && !text.ends_with('\n') {
                section.push_str("\n\\ No newline at end of file\n");
            }
        } else {
            section.push_str(&format!("Binary files /dev/null and {b} differ\n"));
        }
        let budget = max_bytes.saturating_sub(output.len());
        let bounded = truncate_utf8_bytes(&section, budget);
        if bounded.len() < section.len() {
            truncated = true;
        }
        output.push_str(&bounded);
        files.push(path.to_owned());
    }
    Ok((output, truncated, files))
}
