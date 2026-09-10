use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};

use serde_json::{Value, json};

use crate::{Result, git};

fn disposition(path: &str) -> &'static str {
    if path.starts_with("conformance/") {
        "extract independent static fixtures, then retire shadow execution"
    } else if path.starts_with("tests/") {
        "port behavior and negative tests to the responsible Rust crate"
    } else if path.contains("release") || path.contains("deployment") || path.contains("cutover") {
        "consolidate release/install/rollback in Rust CLI and xtask"
    } else if path.contains("validate") || path.contains("record") || path.contains("evidence") {
        "consolidate Rust evidence validation; keep historical records immutable"
    } else {
        "review and port reusable qualification behavior before retirement"
    }
}

const COMPATIBILITY_MARKERS: [&str; 4] = ["ReCtm", "re_ctm", "re-ctm", "Re-CTM"];

fn repository_python_path(text: &str) -> bool {
    ["scripts/", "conformance/", "tests/"].iter().any(|prefix| {
        text.match_indices(prefix).any(|(start, _)| {
            text[start..]
                .split(|character: char| {
                    character.is_whitespace()
                        || matches!(character, '"' | '\'' | ')' | ']' | '}' | ',' | ';')
                })
                .next()
                .is_some_and(|path| path.ends_with(".py"))
        })
    })
}

fn first_party_python_launcher(text: &str) -> bool {
    let command_new = ["Command", "::new("].concat();
    let direct = ["python", "python3"]
        .iter()
        .any(|name| text.contains(&format!("{command_new}\"{name}\")")));
    let python_space = ["python", " "].concat();
    let python3_space = ["python", "3 "].concat();
    let shell_or_wrapper = text.contains(&command_new)
        && (text.contains(&python_space) || text.contains(&python3_space))
        && repository_python_path(text);
    direct || shell_or_wrapper
}

fn legacy_shadow_binary(path: &str) -> bool {
    matches!(
        path,
        "crates/mtm-native/src/bin/shadow.rs"
            | "crates/mtm-storage/src/bin/shadow.rs"
            | "crates/mtm-workflow/src/bin/mtm_workflow_shadow.rs"
            | "crates/mtm-workflow/src/bin/target_validation.rs"
    )
}

fn git_paths(bytes: &[u8]) -> Result<BTreeSet<String>> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| {
            let name = std::str::from_utf8(name)?;
            if !Path::new(name)
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
            {
                return Err("inventory path must remain repository-relative".into());
            }
            Ok(name.to_owned())
        })
        .collect()
}

pub(crate) fn current_paths(
    list: &[u8],
    deleted: &[u8],
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let mut paths = git_paths(list)?;
    let deleted = git_paths(deleted)?;
    if !deleted.is_subset(&paths) {
        return Err("Git index changed during inventory".into());
    }
    paths.retain(|path| !deleted.contains(path));
    Ok((paths, deleted))
}

pub(crate) fn audit(root: &Path) -> Result<Value> {
    let list = git(
        root,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
    )?;
    let deleted = git(root, &["ls-files", "--deleted", "-z"])?;
    let (paths, deleted) = current_paths(&list, &deleted)?;
    for path in &deleted {
        match fs::symlink_metadata(root.join(path)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("deleted inventory entry changed during audit".into()),
        }
    }
    let mut python = Vec::new();
    let mut compatibility = Vec::new();
    let mut python_launchers = Vec::new();
    let mut legacy_shadows = Vec::new();
    let mut unread = Vec::new();
    for path in &paths {
        let file = root.join(path);
        let rust_source =
            (path.starts_with("crates/") || path.starts_with("xtask/")) && path.ends_with(".rs");
        let relevant = path.ends_with(".py") || rust_source;
        if !relevant {
            continue;
        }
        let metadata = fs::symlink_metadata(&file)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > 8 * 1024 * 1024
        {
            unread.push(path.clone());
            continue;
        }
        let text = fs::read_to_string(&file)?;
        if path.ends_with(".py") {
            python.push(json!({"path":path,"bytes":metadata.len(),"lines":text.lines().count(),"disposition":disposition(path)}));
        }
        if rust_source {
            if path.starts_with("crates/")
                && COMPATIBILITY_MARKERS
                    .iter()
                    .any(|marker| text.contains(marker))
            {
                compatibility.push(path.clone());
            }
            if first_party_python_launcher(&text) {
                python_launchers.push(path.clone());
            }
            if legacy_shadow_binary(path) {
                legacy_shadows.push(path.clone());
            }
        }
    }
    let head = String::from_utf8(git(root, &["rev-parse", "HEAD"])?)?;
    Ok(json!({
        "schema_version":"1.0.0", "milestone":"MTM-016", "audit_completed":true,
        "base_head":head.trim(), "tracked_and_unignored_file_count":paths.len(),
        "pending_deleted_file_count":deleted.len(), "pending_deleted_files":deleted,
        "python_file_count":python.len(), "python_files":python,
        "legacy_rust_reference_file_count":python_launchers.len(),
        "legacy_rust_reference_files":python_launchers,
        "legacy_rust_reference_definition":"Rust sources that can launch a first-party repository Python entrypoint; compatibility names are reported separately.",
        "compatibility_rust_reference_file_count":compatibility.len(),
        "compatibility_rust_reference_files":compatibility,
        "legacy_shadow_binary_file_count":legacy_shadows.len(),
        "legacy_shadow_binary_files":legacy_shadows,
        "legacy_shadow_binary_cleanup":"informational; these Rust-only development binaries are not first-party Python authority and changing them belongs to a future candidate source cleanup",
        "uninspected_source_files":unread,
        "rust_only_ready":python.is_empty() && python_launchers.is_empty() && unread.is_empty(),
        "interpretation":"Rust-only readiness means no first-party Python source and no Rust launcher for a first-party repository Python entrypoint. Historical/wire-compatible Re-CTM spellings and user-requested Python commands are not runtime-authority dependencies and remain visible in separate diagnostics."
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_understands_unstaged_deletions_without_hiding_other_files() -> Result<()> {
        let (current, deleted) = current_paths(
            b"scripts/retired.py\0crates/a.rs\0crates/a.rs\0",
            b"scripts/retired.py\0",
        )?;
        assert_eq!(current, BTreeSet::from(["crates/a.rs".to_owned()]));
        assert_eq!(deleted, BTreeSet::from(["scripts/retired.py".to_owned()]));
        assert!(current_paths(b"crates/a.rs\0", b"unknown.rs\0").is_err());
        Ok(())
    }

    #[test]
    fn inventory_rejects_escaped_and_non_utf8_paths() {
        for bytes in [
            &b"../outside.rs\0"[..],
            &b"/outside.rs\0"[..],
            &b"bad\xff.rs\0"[..],
        ] {
            assert!(git_paths(bytes).is_err());
        }
    }

    #[test]
    fn every_python_category_has_an_explicit_retirement_owner() {
        assert!(disposition("conformance/python_shadow.py").contains("fixtures"));
        assert!(disposition("tests/test_security.py").contains("negative"));
        assert!(disposition("scripts/release_mtm.py").contains("rollback"));
        assert!(disposition("scripts/validate_records.py").contains("immutable"));
        assert!(disposition("scripts/other.py").contains("review"));
    }

    #[test]
    fn compatibility_names_do_not_masquerade_as_python_runtime_authority() {
        for text in [
            "use mtm_contracts::ReCtmError;",
            "const PROTOCOL: &str = \"re-ctm-native-helper-v1\";",
            "let payload = json!({\"re_ctm_error\": value});",
            "let command = \"python3 -c 'print(1)'\";",
            "let command = \"python3 script.py\";",
        ] {
            assert!(!first_party_python_launcher(text));
        }
    }

    #[test]
    fn first_party_python_launchers_fail_the_semantic_runtime_check() {
        let command = [
            "Command",
            "::new(\"python3\").arg(\"",
            "scripts/run_",
            "checks.py\")",
        ]
        .concat();
        assert!(first_party_python_launcher(&command));

        let shell = [
            "Command",
            "::new(\"sh\").arg(\"-c\").arg(\"python",
            "3 ",
            "conformance/python_",
            "shadow.py\")",
        ]
        .concat();
        assert!(first_party_python_launcher(&shell));
    }

    #[test]
    fn legacy_shadow_binaries_are_reported_without_becoming_python_authority() {
        assert!(legacy_shadow_binary("crates/mtm-native/src/bin/shadow.rs"));
        assert!(legacy_shadow_binary(
            "crates/mtm-workflow/src/bin/target_validation.rs"
        ));
        assert!(!legacy_shadow_binary("crates/mtm-native/src/bin/helper.rs"));
    }
}
