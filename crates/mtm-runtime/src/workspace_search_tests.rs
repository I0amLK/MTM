use super::*;

fn arguments(value: Value) -> Result<Map<String, Value>, ReCtmError> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| internal("search test requires object arguments"))
}

#[test]
fn search_regular_file_does_not_search_its_siblings() -> Result<(), ReCtmError> {
    let root = tempfile::tempdir().map_err(io_error)?;
    let private = tempfile::tempdir().map_err(io_error)?;
    fs::create_dir(root.path().join("nested")).map_err(io_error)?;
    fs::write(
        root.path().join("nested/a.txt"),
        "before\n数学 needle\nafter\n",
    )
    .map_err(io_error)?;
    fs::write(root.path().join("nested/b.txt"), "needle in sibling\n").map_err(io_error)?;
    let workspace = NativeWorkspace::new(root.path(), private.path())?;
    let result = workspace.search_text(&arguments(serde_json::json!({
        "path": "nested/a.txt", "query": "needle", "context_lines": 1
    }))?)?;
    assert_eq!(result["total_matches"], 1);
    assert_eq!(result["matches"][0]["path"], "nested/a.txt");
    assert_eq!(result["matches"][0]["line"], 2);
    assert_eq!(
        result["matches"][0]["before"],
        serde_json::json!(["before"])
    );
    assert_eq!(result["matches"][0]["after"], serde_json::json!(["after"]));
    Ok(())
}

#[test]
fn file_search_respects_include_and_exclude_filters() -> Result<(), ReCtmError> {
    let root = tempfile::tempdir().map_err(io_error)?;
    let private = tempfile::tempdir().map_err(io_error)?;
    fs::create_dir(root.path().join("nested")).map_err(io_error)?;
    fs::write(root.path().join("nested/a.txt"), "needle\n").map_err(io_error)?;
    let workspace = NativeWorkspace::new(root.path(), private.path())?;
    for (filters, expected) in [
        (serde_json::json!({"glob":"*.txt"}), 1),
        (serde_json::json!({"include_globs":["nested/*.txt"]}), 1),
        (serde_json::json!({"glob":"*.rs"}), 0),
        (serde_json::json!({"exclude_globs":["*.txt"]}), 0),
        (serde_json::json!({"exclude_globs":["nested/*.txt"]}), 0),
    ] {
        let mut args = arguments(serde_json::json!({"path":"nested/a.txt","query":"needle"}))?;
        args.extend(arguments(filters)?);
        assert_eq!(workspace.search_text(&args)?["total_matches"], expected);
    }
    Ok(())
}

#[test]
fn file_search_preserves_workspace_and_vault_boundaries() -> Result<(), ReCtmError> {
    let root = tempfile::tempdir().map_err(io_error)?;
    let private = tempfile::tempdir().map_err(io_error)?;
    fs::write(private.path().join("private.txt"), "secret needle\n").map_err(io_error)?;
    std::os::unix::fs::symlink(
        private.path().join("private.txt"),
        root.path().join("escape"),
    )
    .map_err(io_error)?;
    let workspace = NativeWorkspace::new(root.path(), private.path())?;
    for path in ["escape", "../private.txt", "missing.txt"] {
        assert!(
            workspace
                .search_text(&arguments(serde_json::json!({
                    "path":path,"query":"needle"
                }))?)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn search_bounds_are_enforced_before_reading() -> Result<(), ReCtmError> {
    let root = tempfile::tempdir().map_err(io_error)?;
    let private = tempfile::tempdir().map_err(io_error)?;
    fs::write(root.path().join("a.txt"), "needle\n").map_err(io_error)?;
    let workspace = NativeWorkspace::new(root.path(), private.path())?;
    for (field, value) in [
        ("max_results", 0),
        ("max_results", 10_001),
        ("context_lines", 6),
        ("max_preview_bytes", 79),
        ("max_preview_bytes", 4_097),
    ] {
        let mut args = arguments(serde_json::json!({"path":"a.txt","query":"needle"}))?;
        args.insert(field.to_owned(), value.into());
        let result = workspace.search_text(&args);
        assert_eq!(
            result.map_err(|error| error.code),
            Err("INVALID_ARGUMENT".to_owned())
        );
    }
    Ok(())
}

#[test]
fn directory_search_keeps_existing_hidden_and_filter_behavior() -> Result<(), ReCtmError> {
    let root = tempfile::tempdir().map_err(io_error)?;
    let private = tempfile::tempdir().map_err(io_error)?;
    fs::write(root.path().join("a.txt"), "needle\n").map_err(io_error)?;
    fs::write(root.path().join(".hidden.txt"), "needle\n").map_err(io_error)?;
    fs::write(root.path().join("b.rs"), "needle\n").map_err(io_error)?;
    let workspace = NativeWorkspace::new(root.path(), private.path())?;
    let result = workspace.search_text(&arguments(serde_json::json!({
        "path":".","glob":"*.txt","query":"needle"
    }))?)?;
    assert_eq!(result["total_matches"], 1);
    assert_eq!(result["matches"][0]["path"], "a.txt");
    Ok(())
}
