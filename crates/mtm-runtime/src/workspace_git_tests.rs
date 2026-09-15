use super::*;
use serde_json::json;

fn args(value: Value) -> Result<Map<String, Value>, ReCtmError> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| internal("test arguments"))
}

fn git(root: &Path, args: &[&str]) -> Result<(), ReCtmError> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_AUTHOR_NAME", "MTM fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "MTM fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .output()
        .map_err(io_error)?;
    if !output.status.success() {
        return Err(internal("Git fixture setup failed"));
    }
    Ok(())
}

fn init(root: &Path, label: &str) -> Result<(), ReCtmError> {
    fs::create_dir_all(root).map_err(io_error)?;
    git(root, &["init", "--quiet"])?;
    fs::write(root.join("a.txt"), format!("{label}\nsecond\n")).map_err(io_error)?;
    git(root, &["add", "--", "a.txt"])?;
    git(
        root,
        &[
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "--quiet",
            "-m",
            label,
        ],
    )
}

fn fixture() -> Result<(tempfile::TempDir, tempfile::TempDir, NativeWorkspace), ReCtmError> {
    let root = tempfile::tempdir().map_err(io_error)?;
    let private = tempfile::tempdir().map_err(io_error)?;
    init(root.path(), "parent-fixture")?;
    init(&root.path().join("nested"), "child-fixture")?;
    let workspace = NativeWorkspace::new(root.path(), private.path())?;
    Ok((root, private, workspace))
}

#[test]
fn log_accepts_regular_file_filter_in_the_selected_repository() -> Result<(), ReCtmError> {
    let (_root, _private, workspace) = fixture()?;
    let result = workspace.git_log(&args(json!({"path":"a.txt"}))?)?;
    assert_eq!(result["is_repo"], true);
    assert_eq!(result["commits"][0]["subject"], "parent-fixture");
    Ok(())
}

#[test]
fn log_selects_child_repository_instead_of_parent_history() -> Result<(), ReCtmError> {
    let (_root, _private, workspace) = fixture()?;
    let result = workspace.git_log(&args(json!({"repo_path":"nested","path":"a.txt"}))?)?;
    assert_eq!(result["commits"][0]["subject"], "child-fixture");
    assert_eq!(result["repo_path"], "nested");
    Ok(())
}

#[test]
fn diff_and_show_use_the_selected_repo_and_relative_literal_filters() -> Result<(), ReCtmError> {
    let (root, _private, workspace) = fixture()?;
    fs::write(root.path().join("nested/a.txt"), "changed-child\n").map_err(io_error)?;
    fs::write(root.path().join("a.txt"), "changed-parent\n").map_err(io_error)?;
    let diff = workspace.git_diff(&args(json!({"repo_path":"nested","path":"a.txt"}))?)?;
    let text = diff["diff"]
        .as_str()
        .ok_or_else(|| internal("missing diff"))?;
    assert!(text.contains("changed-child"));
    assert!(!text.contains("changed-parent"));
    let show = workspace.git_show(&args(json!({"repo_path":"nested","include_diff":false}))?)?;
    assert!(
        show["content"]
            .as_str()
            .is_some_and(|s| s.contains("child-fixture"))
    );
    Ok(())
}

#[test]
fn blame_clamps_short_files_and_keeps_revision_in_continuation() -> Result<(), ReCtmError> {
    let (_root, _private, workspace) = fixture()?;
    let result = workspace.git_blame(&args(
        json!({"repo_path":"nested","path":"a.txt","rev":"HEAD","max_lines":1}),
    )?)?;
    assert_eq!(result["lines"][0]["content"], "child-fixture");
    assert_eq!(result["next_action"]["arguments"]["repo_path"], "nested");
    assert_eq!(result["next_action"]["arguments"]["rev"], "HEAD");
    let next = workspace.git_blame(&args(result["next_action"]["arguments"].clone())?)?;
    assert_eq!(next["lines"][0]["content"], "second");
    let all = workspace.git_blame(&args(json!({"repo_path":"nested","path":"a.txt"}))?)?;
    assert_eq!(all["lines"].as_array().map(Vec::len), Some(2));
    Ok(())
}

#[test]
fn repository_discovery_never_climbs_outside_workspace() -> Result<(), ReCtmError> {
    let root = tempfile::tempdir().map_err(io_error)?;
    let private = tempfile::tempdir().map_err(io_error)?;
    init(root.path(), "outside-workspace")?;
    fs::create_dir(root.path().join("workspace")).map_err(io_error)?;
    let workspace = NativeWorkspace::new(&root.path().join("workspace"), private.path())?;
    assert_eq!(workspace.git_status(&Map::new())?["is_repo"], false);
    assert_eq!(workspace.git_log(&Map::new())?["is_repo"], false);
    Ok(())
}

#[test]
fn status_exact_limit_is_not_truncated_and_odd_names_are_not_split() -> Result<(), ReCtmError> {
    let root = tempfile::tempdir().map_err(io_error)?;
    let private = tempfile::tempdir().map_err(io_error)?;
    init(root.path(), "fixture")?;
    let name = "中文 -> actual\nfile.txt";
    fs::write(root.path().join(name), "data").map_err(io_error)?;
    let workspace = NativeWorkspace::new(root.path(), private.path())?;
    let result = workspace.git_status(&args(json!({"max_entries":1}))?)?;
    assert_eq!(result["entries"][0]["path"], name);
    assert!(result["entries"][0]["original_path"].is_null());
    assert_eq!(result["truncated"], false);
    Ok(())
}

#[test]
fn git_filters_and_metadata_cannot_escape_workspace() -> Result<(), ReCtmError> {
    let (root, private, workspace) = fixture()?;
    for request in [
        json!({"repo_path":"../escape"}),
        json!({"path":"../escape"}),
    ] {
        assert!(workspace.git_diff(&args(request)?).is_err());
    }
    fs::create_dir(root.path().join("foreign")).map_err(io_error)?;
    init(private.path(), "private-fixture")?;
    fs::write(
        root.path().join("foreign/.git"),
        format!("gitdir: {}\n", private.path().join(".git").display()),
    )
    .map_err(io_error)?;
    assert!(
        workspace
            .git_status(&args(json!({"repo_path":"foreign"}))?)
            .is_err()
    );
    Ok(())
}

#[test]
fn legitimate_workspace_worktree_is_supported() -> Result<(), ReCtmError> {
    let (root, _private, workspace) = fixture()?;
    git(
        root.path(),
        &["worktree", "add", "--quiet", "--detach", "linked", "HEAD"],
    )?;
    let result = workspace.git_log(&args(json!({"repo_path":"linked"}))?)?;
    assert_eq!(result["repo_path"], "linked");
    assert_eq!(result["commits"][0]["subject"], "parent-fixture");
    Ok(())
}

#[test]
fn deleted_file_history_does_not_require_a_current_file() -> Result<(), ReCtmError> {
    let (root, _private, workspace) = fixture()?;
    git(&root.path().join("nested"), &["rm", "--quiet", "a.txt"])?;
    git(
        &root.path().join("nested"),
        &[
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "--quiet",
            "-m",
            "delete-child-file",
        ],
    )?;
    let result = workspace.git_log(&args(json!({"repo_path":"nested","path":"a.txt"}))?)?;
    assert_eq!(result["commits"][0]["subject"], "delete-child-file");
    assert_eq!(result["commits"][1]["subject"], "child-fixture");
    Ok(())
}

#[test]
fn literal_glob_filename_does_not_select_siblings() -> Result<(), ReCtmError> {
    let (root, _private, workspace) = fixture()?;
    let nested = root.path().join("nested");
    fs::write(nested.join("*.txt"), "literal-before\n").map_err(io_error)?;
    git(&nested, &["--literal-pathspecs", "add", "--", "*.txt"])?;
    git(
        &nested,
        &[
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "--quiet",
            "-m",
            "literal-name",
        ],
    )?;
    fs::write(nested.join("*.txt"), "literal-after\n").map_err(io_error)?;
    fs::write(nested.join("a.txt"), "sibling-not-selected\n").map_err(io_error)?;
    let result = workspace.git_diff(&args(json!({"repo_path":"nested","path":"*.txt"}))?)?;
    let diff = result["diff"]
        .as_str()
        .ok_or_else(|| internal("missing diff"))?;
    assert!(diff.contains("literal-after"));
    assert!(!diff.contains("sibling-not-selected"));
    Ok(())
}
