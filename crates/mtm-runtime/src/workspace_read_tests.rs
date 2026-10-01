use super::*;
use serde_json::json;

fn args(value: Value) -> Result<Map<String, Value>, ReCtmError> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| internal("test arguments"))
}

fn fixture(
    content: &[u8],
) -> Result<(tempfile::TempDir, tempfile::TempDir, NativeWorkspace), ReCtmError> {
    let root = tempfile::tempdir().map_err(io_error)?;
    let private = tempfile::tempdir().map_err(io_error)?;
    fs::write(root.path().join("text"), content).map_err(io_error)?;
    let workspace = NativeWorkspace::new(root.path(), private.path())?;
    Ok((root, private, workspace))
}

#[test]
fn long_utf8_line_continuations_are_lossless_and_byte_bounded() -> Result<(), ReCtmError> {
    let input = "中文🙂abcdef\r\nlast line without newline";
    let (_root, _private, workspace) = fixture(input.as_bytes())?;
    let mut request = args(json!({"path":"text","max_bytes":7,"max_lines":1}))?;
    let mut joined = String::new();
    for _ in 0..32 {
        let result = workspace.read_file(&request)?;
        assert_eq!(result["revision"], result["sha256"]);
        assert_eq!(result["revision"], sha256_bytes(input.as_bytes()));
        assert_eq!(result["revision_algorithm"], "sha256");
        let content = result["content"]
            .as_str()
            .ok_or_else(|| internal("missing content"))?;
        assert!(content.len() <= 7);
        assert!(!content.is_empty());
        joined.push_str(content);
        if result["next_action"].is_null() {
            assert_eq!(result["truncated"], false);
            break;
        }
        assert_eq!(result["truncated"], true);
        let next = args(result["next_action"]["arguments"].clone())?;
        assert_ne!(request, next);
        request = next;
    }
    assert_eq!(joined, input);
    Ok(())
}

#[test]
fn last_partial_line_is_not_reported_as_complete() -> Result<(), ReCtmError> {
    let (_root, _private, workspace) = fixture(b"abcdef")?;
    let result = workspace.read_file(&args(json!({"path":"text","max_bytes":3}))?)?;
    assert_eq!(result["content"], "abc");
    assert_eq!(result["truncated"], true);
    assert_eq!(result["next_start_line"], 1);
    assert_eq!(result["next_line_byte_offset"], 3);
    Ok(())
}

#[test]
fn explicit_range_and_page_size_combine_without_skipping_lines() -> Result<(), ReCtmError> {
    let (_root, _private, workspace) = fixture(b"one\ntwo\nthree\nfour\n")?;
    let first = workspace.read_file(&args(
        json!({"path":"text","start_line":2,"end_line":3,"max_lines":1}),
    )?)?;
    assert_eq!(first["content"], "two\n");
    let second = workspace.read_file(&args(first["next_action"]["arguments"].clone())?)?;
    assert_eq!(second["content"], "three\n");
    assert_eq!(second["truncated"], false);
    assert!(second["next_action"].is_null());
    Ok(())
}

#[test]
fn invalid_ranges_and_byte_offsets_fail_before_reading() -> Result<(), ReCtmError> {
    let (_root, _private, workspace) = fixture("中x".as_bytes())?;
    for extra in [
        json!({"start_line":0}),
        json!({"start_line":2,"end_line":1}),
        json!({"max_lines":0}),
        json!({"max_bytes":0}),
        json!({"max_bytes":1_048_577}),
        json!({"line_byte_offset":1}),
        json!({"line_byte_offset":5}),
        json!({"line_byte_offset":-1}),
    ] {
        let mut request = args(json!({"path":"text"}))?;
        request.extend(args(extra)?);
        assert!(workspace.read_file(&request).is_err());
    }
    let too_small = workspace.read_file(&args(json!({"path":"text","max_bytes":1}))?);
    assert_eq!(
        too_small.map_err(|e| e.code),
        Err("READ_PAGE_TOO_SMALL".to_owned())
    );
    Ok(())
}

#[test]
fn empty_and_beyond_eof_ranges_do_not_overflow_or_invent_content() -> Result<(), ReCtmError> {
    let (_root, _private, workspace) = fixture(b"")?;
    for start in [1_i64, i64::MAX] {
        let result = workspace.read_file(&args(
            json!({"path":"text","start_line":start,"max_lines":i64::MAX}),
        )?)?;
        assert_eq!(result["content"], "");
        assert_eq!(result["truncated"], false);
        assert!(result["next_action"].is_null());
    }
    Ok(())
}

#[test]
fn large_files_are_rejected_before_unbounded_allocation() -> Result<(), ReCtmError> {
    let (root, _private, workspace) = fixture(b"")?;
    fs::OpenOptions::new()
        .write(true)
        .open(root.path().join("text"))
        .map_err(io_error)?
        .set_len(64 * 1024 * 1024 + 1)
        .map_err(io_error)?;
    let result = workspace.read_file(&args(json!({"path":"text"}))?);
    assert_eq!(
        result.map(|_| ()).map_err(|e| e.code),
        Err("FILE_TOO_LARGE".to_owned())
    );
    Ok(())
}

#[test]
fn read_paging_preserves_binary_and_private_path_denials() -> Result<(), ReCtmError> {
    let (root, private, workspace) = fixture(b"\xff")?;
    assert_eq!(
        workspace
            .read_file(&args(json!({"path":"text"}))?)
            .map_err(|e| e.code),
        Err("BINARY_FILE".to_owned())
    );
    fs::write(private.path().join("private"), "private").map_err(io_error)?;
    std::os::unix::fs::symlink(private.path().join("private"), root.path().join("escape"))
        .map_err(io_error)?;
    assert!(
        workspace
            .read_file(&args(json!({"path":"escape"}))?)
            .is_err()
    );
    Ok(())
}

#[test]
fn continuation_rejects_changed_file_before_returning_content() -> Result<(), ReCtmError> {
    let (root, _private, workspace) = fixture(b"old\nmore\n")?;
    let first = workspace.read_file(&args(json!({"path":"text","max_lines":1}))?)?;
    fs::write(root.path().join("text"), b"new\nmore\n").map_err(io_error)?;
    let result = workspace.read_file(&args(first["next_action"]["arguments"].clone())?);
    assert_eq!(
        result.map(|_| ()).map_err(|e| e.code),
        Err("READ_FILE_CHANGED".to_owned())
    );
    Ok(())
}
