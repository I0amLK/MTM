from __future__ import annotations

import dataclasses
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = (ROOT / "../Re-CTM/src").resolve()
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from re_ctm.ctm_compat import (  # noqa: E402
    apply_update_hunks,
    check_command_policy,
    inline_script_command,
    is_filtered_env_var,
    parse_patch,
)
from re_ctm.debug import redact, token_fingerprint  # noqa: E402
from re_ctm.enums import WorkflowState  # noqa: E402
from re_ctm.errors import ReCTMError  # noqa: E402
from re_ctm.native import NativeWorkspace  # noqa: E402
from re_ctm.oauth import _validate_server_url, validate_redirect_uris  # noqa: E402
from re_ctm.quick_tunnel import extract_quick_tunnel_origin  # noqa: E402
from re_ctm.tools import _validate_schema_value  # noqa: E402


def evaluate_request(request: dict[str, Any]) -> dict[str, Any]:
    try:
        operation = request["operation"]
        if operation == "schema_validate":
            _validate_schema_value(
                request["value"],
                request["schema"],
                path=request.get("path", "arguments"),
            )
            result: Any = {"valid": True}
        elif operation == "redact":
            result = redact(request["value"])
        elif operation == "fingerprint":
            result = token_fingerprint(request["value"])
        elif operation == "redact_bytes":
            result = redact(request["value"].encode("utf-8"))
        elif operation == "oauth_server_url":
            _validate_server_url(request["value"])
            result = {"valid": True}
        elif operation == "redirect_uris":
            result = list(validate_redirect_uris(request["value"]))
        elif operation == "quick_tunnel_origin":
            result = extract_quick_tunnel_origin(request["value"])
        elif operation == "workspace_path":
            workspace = object.__new__(NativeWorkspace)
            result = str(workspace._validate_text(request["value"]))
        elif operation == "filtered_env":
            result = is_filtered_env_var(request["name"], request["value"])
        elif operation == "inline_script":
            result = inline_script_command(request["value"])
        elif operation == "command_policy":
            check_command_policy(request["mode"], request["command"], request.get("env", {}))
            result = {"allowed": True}
        elif operation == "parse_patch":
            result = [dataclasses.asdict(item) for item in parse_patch(request["value"])]
        elif operation == "apply_hunks":
            result = apply_update_hunks(
                request["content"],
                request["hunks"],
                request["path"],
            )
        elif operation == "workflow_terminal":
            result = WorkflowState(request["value"]).terminal
        else:
            raise ValueError(f"unknown reference operation: {operation}")
    except ReCTMError as error:
        return {"ok": False, "error": error.to_payload()}
    return {"ok": True, "result": result}
