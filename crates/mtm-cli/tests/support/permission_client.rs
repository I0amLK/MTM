//! Real loopback MRTR messages with scripted responses. No human-UI claim.
use super::*;

impl Server {
    pub fn permission_message(
        &self,
        owner: &Client,
        arguments: &Value,
        capabilities: Value,
        continuation: Option<(&str, Value)>,
    ) -> Result<Value> {
        let mut params = json!({
            "name":"request_permissions", "arguments":arguments,
            "_meta":{
                "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                "io.modelcontextprotocol/clientCapabilities":capabilities,
                "io.modelcontextprotocol/clientInfo":{"name":"Rust scripted permission fixture","version":"1"}
            }
        });
        if let Some((state, responses)) = continuation {
            params["requestState"] = json!(state);
            params["inputResponses"] = responses;
        }
        let bytes = serde_json::to_vec(&json!({
            "jsonrpc":"2.0", "id":"permission-fixture", "method":"tools/call", "params":params
        }))
        .map_err(|_| "permission request encoding")?;
        let reply = Self::request_at(
            self.endpoint,
            self.deadline,
            "POST",
            "/mcp",
            HttpPayload {
                content_type: "application/json",
                body: &bytes,
                extra_headers: "MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: request_permissions\r\n",
            },
            Some(owner),
        )?;
        require(
            reply.status == 200,
            "permission fixture HTTP failure; no replay",
        )?;
        let reply = reply.json()?;
        require(
            reply.get("error").is_none(),
            "permission fixture protocol rejected",
        )?;
        reply
            .get("result")
            .filter(|v| v.is_object())
            .cloned()
            .ok_or("permission fixture result missing")
    }
}
