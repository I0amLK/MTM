use super::tool_result;
use serde_json::{Value, json};

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
