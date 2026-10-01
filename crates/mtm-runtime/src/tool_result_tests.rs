use super::tool_result;
use serde_json::{Value, json};

#[test]
fn read_banner_preserves_lossless_content_and_partial_continuation() {
    let content = "中文\r\nlast";
    let payload = json!({"ok":true,"content":content,"start_line":1,"end_line":2,
        "total_lines":2,"revision":"a".repeat(64),"line_byte_offset":3,
        "truncated":true,"next_action":{"tool":"read_file","arguments":{"path":"text","start_line":2,"line_byte_offset":4,"expected_sha256":"a".repeat(64)}}});
    let result = tool_result("read_file", payload.clone(), false);
    assert_eq!(result["structuredContent"], payload);
    let rendered = result["content"][0]["text"].as_str().unwrap_or_default();
    assert!(rendered.starts_with("[Showing lines 1-2 of 2 revision="));
    assert!(rendered.contains("line_byte_offset=3"));
    assert!(rendered.contains(content));
    assert!(rendered.contains("continue with next_action verbatim"));
    assert!(rendered.contains("expected_sha256"));
}

#[test]
fn moved_nested_payload_preserves_structured_content_and_error_flag() {
    let payload = json!({"ok":true,"large":{"rows":[{"text":"x".repeat(65536)}]}});
    let expected = payload.clone();
    let result = tool_result("server_info", payload, false);
    assert_eq!(result["structuredContent"], expected);
    assert_eq!(result["isError"], false);
    assert!(result["content"].is_array());
}

#[test]
fn moving_payload_keeps_image_extraction_private() {
    let result = tool_result(
        "view_image",
        json!({
            "ok":true,"_mcp_image_data":"aW1hZ2U=","mime_type":"image/png"
        }),
        false,
    );
    assert!(result["structuredContent"].get("_mcp_image_data").is_none());
    assert_eq!(result["content"][1]["data"], "aW1hZ2U=");
    assert_eq!(result["content"][1]["mimeType"], "image/png");
}

#[test]
fn moving_payload_preserves_error_and_nonobject_normalization() {
    let error = json!({"ok":false,"error":{"code":"TEST_ERROR","message":"test"}});
    let result = tool_result("rethlas_step", error.clone(), true);
    assert_eq!(result["structuredContent"], error);
    assert_eq!(result["isError"], true);
    let result = tool_result("server_info", Value::from(42), false);
    assert_eq!(result["structuredContent"], json!({"ok":true,"result":42}));
}

#[test]
fn actual_native_payloads_match_their_declared_output_schemas()
-> Result<(), mtm_contracts::ReCtmError> {
    use mtm_contracts::ReCtmError;
    fn validate(name: &str, payload: Value) -> Result<(), ReCtmError> {
        let wire = tool_result(name, payload, false);
        let catalog = mtm_gateway::ToolCatalog::new();
        let schema = &catalog
            .definition(name)
            .ok_or_else(|| ReCtmError::new("TEST", "tool"))?["outputSchema"];
        mtm_core::validate_schema_value(&wire["structuredContent"], schema, "result")?;
        assert!(
            wire["structuredContent"]
                .get("_native_first_terminal")
                .is_none()
        );
        Ok(())
    }
    let root = tempfile::tempdir().map_err(|_| ReCtmError::new("TEST", "temp"))?;
    let private = tempfile::tempdir().map_err(|_| ReCtmError::new("TEST", "temp"))?;
    std::fs::write(root.path().join("a"), "content\n")
        .map_err(|_| ReCtmError::new("TEST", "write"))?;
    let workspace = crate::NativeWorkspace::new(root.path(), private.path())?;
    let arguments = json!({"path":"a"}).as_object().cloned().unwrap_or_default();
    let mut read = workspace.read_file(&arguments)?;
    read["ok"] = json!(true);
    validate("read_file", read)?;
    let arguments = json!({"changes":[{"action":"create","path":"b","content":"new"}]})
        .as_object()
        .cloned()
        .unwrap_or_default();
    let (prepared, _) = workspace.prepare_changes(&arguments)?;
    let mut changed = workspace.commit_prepared_patch_with_authorization(prepared, || Ok(()))?;
    changed["ok"] = json!(true);
    validate("apply_changes", changed)?;
    let manager = mtm_native::CommandManager::new(mtm_native::CommandManagerConfig::default());
    let request = serde_json::from_value::<mtm_native::CommandRequest>(
        json!({"argv":["/bin/false"],"yield_time_ms":3000,"timeout_ms":2000}),
    )
    .map_err(|_| ReCtmError::new("TEST", "request"))?;
    let started = manager.start(request)?;
    let id = started["command_id"]
        .as_str()
        .ok_or_else(|| ReCtmError::new("TEST", "id"))?
        .to_owned();
    validate("exec_command", started)?;
    validate(
        "read_output",
        manager.read_output(&format!("command:{id}:stdout"), None, 0, 4096)?,
    )?;
    let poll = serde_json::from_value::<mtm_native::PollRequest>(
        json!({"command_id":id,"yield_time_ms":0}),
    )
    .map_err(|_| ReCtmError::new("TEST", "poll"))?;
    validate("write_stdin", manager.poll(poll)?)?;
    let kill = serde_json::from_value::<mtm_native::KillRequest>(json!({"command_id":id}))
        .map_err(|_| ReCtmError::new("TEST", "kill"))?;
    validate("kill_command", manager.kill(kill)?)?;
    manager.close()
}
