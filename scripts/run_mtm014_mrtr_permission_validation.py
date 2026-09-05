#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from mtm008_runtime_harness import free_port, oauth_token, runtime_environment, wait_for_port
from run_mtm007_http_smoke import tool_call
from mtm008_runtime_harness import json_request


ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("MTM014_BINARY", ROOT / "target" / "debug" / "mtm"))
MODERN_VERSION = "2026-07-28"
CONSENT_KEY = "native_permission_consent"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def close(process: subprocess.Popen[str]) -> int:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        return process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        return process.wait(timeout=3)


def launch(root: Path, mode: str) -> tuple[subprocess.Popen[str], int, str]:
    workspace = root / f"workspace-{mode}"
    data_root = root / f"data-{mode}"
    workspace.mkdir(parents=True, exist_ok=True)
    port = free_port()
    environment = runtime_environment(workspace, data_root, "rust")
    environment["MTM_NATIVE_MODE"] = mode
    process = subprocess.Popen(
        [
            str(BINARY),
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--workspace",
            str(workspace),
            "--native-mode",
            mode,
            "--latex-policy",
            "static_only",
        ],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    wait_for_port(port, process)
    return process, port, f"http://127.0.0.1:{port}"


def modern_tool_call(
    port: int,
    token: str,
    name: str,
    arguments: dict[str, Any],
    *,
    capabilities: dict[str, Any],
    input_responses: dict[str, Any] | None = None,
    request_state: str | None = None,
) -> tuple[int, dict[str, Any]]:
    params: dict[str, Any] = {
        "name": name,
        "arguments": arguments,
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": capabilities,
            "io.modelcontextprotocol/clientInfo": {
                "name": "mtm014-validation-client",
                "version": "1",
            },
        },
    }
    if input_responses is not None:
        params["inputResponses"] = input_responses
    if request_state is not None:
        params["requestState"] = request_state
    status, _, payload = json_request(
        port,
        "POST",
        "/mcp",
        {
            "jsonrpc": "2.0",
            "id": f"{name}-validation",
            "method": "tools/call",
            "params": params,
        },
        headers={
            "Authorization": f"Bearer {token}",
            "MCP-Protocol-Version": MODERN_VERSION,
            "Mcp-Method": "tools/call",
            "Mcp-Name": name,
        },
    )
    return status, payload


def permission_request(
    *,
    permission: str = "inline_script",
    command: str = "sh -c 'true'",
    scope: str = "once",
    ttl_seconds: int = 300,
) -> dict[str, Any]:
    return {
        "tool_name": "exec_command",
        "permission": permission,
        "reason": "validate explicit Native permission consent",
        "arguments": {"cmd": command},
        "scope": scope,
        "ttl_seconds": ttl_seconds,
    }


def result(payload: dict[str, Any]) -> dict[str, Any]:
    value = payload.get("result")
    if not isinstance(value, dict):
        raise RuntimeError(f"MCP response has no object result: {payload}")
    return value


def structured(payload: dict[str, Any]) -> dict[str, Any]:
    value = result(payload).get("structuredContent")
    if not isinstance(value, dict):
        raise RuntimeError(f"MCP response has no structuredContent: {payload}")
    return value


def tool_error_code(payload: dict[str, Any]) -> str:
    return str(structured(payload).get("error", {}).get("code") or "")


def input_required(payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    value = result(payload)
    if value.get("resultType") != "input_required":
        raise RuntimeError(f"expected input_required result: {payload}")
    state = value.get("requestState")
    requests = value.get("inputRequests")
    if not isinstance(state, str) or not state:
        raise RuntimeError("input_required response omitted requestState")
    if not isinstance(requests, dict) or not isinstance(requests.get(CONSENT_KEY), dict):
        raise RuntimeError("input_required response omitted Native consent request")
    return state, requests[CONSENT_KEY]


def consent_response(approved: bool = True) -> dict[str, Any]:
    return {
        CONSENT_KEY: {
            "action": "accept",
            "content": {"approved": approved},
        }
    }


def run_safe(root: Path) -> tuple[dict[str, bool], dict[str, Any]]:
    checks: dict[str, bool] = {}
    facts: dict[str, Any] = {}
    process, port, base = launch(root, "safe")
    try:
        token = oauth_token(port, base, "MTM-014 MRTR safe")
        request = permission_request()

        legacy = tool_call(port, token, "request_permissions", request)
        checks["legacy_remains_unsupported"] = structured(legacy).get("status") == "unsupported"

        no_cap_status, no_cap = modern_tool_call(
            port,
            token,
            "request_permissions",
            request,
            capabilities={},
        )
        checks["modern_without_elicitation_remains_unsupported"] = (
            no_cap_status == 200 and structured(no_cap).get("status") == "unsupported"
        )

        first_status, first = modern_tool_call(
            port,
            token,
            "request_permissions",
            request,
            capabilities={"elicitation": {"form": {}}},
        )
        state, input_request = input_required(first)
        serialized_first = json.dumps(first, sort_keys=True)
        checks["safe_intrinsic_permission_requires_input"] = first_status == 200
        checks["input_request_is_form_elicitation"] = (
            input_request.get("method") == "elicitation/create"
            and input_request.get("params", {}).get("mode") == "form"
        )
        checks["input_prompt_omits_raw_command"] = request["arguments"]["cmd"] not in serialized_first
        checks["input_prompt_contains_boolean_schema"] = (
            input_request.get("params", {})
            .get("requestedSchema", {})
            .get("properties", {})
            .get("approved", {})
            .get("type")
            == "boolean"
        )

        accepted_status, accepted = modern_tool_call(
            port,
            token,
            "request_permissions",
            request,
            capabilities={"elicitation": {"form": {}}},
            input_responses=consent_response(True),
            request_state=state,
        )
        accepted_payload = structured(accepted)
        checks["accept_mints_exact_grant"] = (
            accepted_status == 200
            and accepted_payload.get("status") == "granted"
            and isinstance(accepted_payload.get("grant_id"), str)
            and bool(accepted_payload.get("grant_id"))
        )
        checks["grant_response_omits_raw_command"] = request["arguments"]["cmd"] not in json.dumps(
            accepted, sort_keys=True
        )
        checks["grant_never_inherits_workflow_authority"] = (
            accepted_payload.get("constraints", {}).get("workflow_authority_inherited") is False
        )

        duplicate_status, duplicate = modern_tool_call(
            port,
            token,
            "request_permissions",
            request,
            capabilities={"elicitation": {"form": {}}},
        )
        checks["active_exact_grant_suppresses_duplicate_prompt"] = (
            duplicate_status == 200
            and result(duplicate).get("resultType") == "complete"
            and structured(duplicate).get("status") == "already_granted"
            and structured(duplicate).get("grant_id") is None
        )

        replay_status, replay = modern_tool_call(
            port,
            token,
            "request_permissions",
            request,
            capabilities={"elicitation": {"form": {}}},
            input_responses=consent_response(True),
            request_state=state,
        )
        checks["accepted_state_replay_fails_closed"] = (
            replay_status == 200
            and result(replay).get("isError") is True
            and tool_error_code(replay) == "ELICITATION_STATE_INVALID"
        )

        mutation_request = permission_request(command="sh -c 'printf mutation-base'")
        mutation_first_status, mutation_first = modern_tool_call(
            port,
            token,
            "request_permissions",
            mutation_request,
            capabilities={"elicitation": {}},
        )
        mutation_state, _ = input_required(mutation_first)
        mutated_request = permission_request(command="sh -c 'printf changed'")
        mutation_status, mutation = modern_tool_call(
            port,
            token,
            "request_permissions",
            mutated_request,
            capabilities={"elicitation": {}},
            input_responses=consent_response(True),
            request_state=mutation_state,
        )
        checks["argument_mutation_fails_closed"] = (
            mutation_first_status == 200
            and mutation_status == 200
            and result(mutation).get("isError") is True
            and tool_error_code(mutation) == "ELICITATION_REQUEST_MISMATCH"
        )
        recovery_status, recovery = modern_tool_call(
            port,
            token,
            "request_permissions",
            mutation_request,
            capabilities={"elicitation": {}},
            input_responses=consent_response(True),
            request_state=mutation_state,
        )
        checks["mutation_does_not_consume_original_challenge"] = (
            recovery_status == 200 and structured(recovery).get("status") == "granted"
        )

        extra_request = permission_request(command="sh -c 'printf extra-base'")
        extra_first_status, extra_first = modern_tool_call(
            port,
            token,
            "request_permissions",
            extra_request,
            capabilities={"elicitation": {}},
        )
        extra_state, _ = input_required(extra_first)
        extra_responses = consent_response(True)
        extra_responses["unexpected"] = {"action": "accept", "content": {"approved": True}}
        extra_status, extra = modern_tool_call(
            port,
            token,
            "request_permissions",
            extra_request,
            capabilities={"elicitation": {}},
            input_responses=extra_responses,
            request_state=extra_state,
        )
        checks["extra_input_response_fails_closed"] = (
            extra_first_status == 200
            and extra_status == 200
            and result(extra).get("isError") is True
            and tool_error_code(extra) == "ELICITATION_RESPONSE_INVALID"
        )
        extra_recovery_status, extra_recovery = modern_tool_call(
            port,
            token,
            "request_permissions",
            extra_request,
            capabilities={"elicitation": {}},
            input_responses=consent_response(True),
            request_state=extra_state,
        )
        checks["extra_response_failure_does_not_consume_challenge"] = (
            extra_recovery_status == 200
            and structured(extra_recovery).get("status") == "granted"
        )

        non_intrinsic_status, non_intrinsic = modern_tool_call(
            port,
            token,
            "request_permissions",
            permission_request(permission="network", command="printf local"),
            capabilities={"elicitation": {}},
        )
        checks["non_intrinsic_permission_is_not_required"] = (
            non_intrinsic_status == 200
            and result(non_intrinsic).get("resultType") == "complete"
            and structured(non_intrinsic).get("status") == "not_required"
        )

        decline_request = permission_request(command="sh -c 'printf decline-base'")
        decline_first_status, decline_first = modern_tool_call(
            port,
            token,
            "request_permissions",
            decline_request,
            capabilities={"elicitation": {}},
        )
        decline_state, _ = input_required(decline_first)
        decline_status, decline = modern_tool_call(
            port,
            token,
            "request_permissions",
            decline_request,
            capabilities={"elicitation": {}},
            input_responses={CONSENT_KEY: {"action": "decline"}},
            request_state=decline_state,
        )
        checks["decline_mints_no_grant"] = (
            decline_first_status == 200
            and decline_status == 200
            and structured(decline).get("status") == "denied"
            and structured(decline).get("grant_id") is None
        )

        facts["safe_server_exit_code"] = None
        return checks, facts
    finally:
        facts["safe_server_exit_code"] = close(process)
        checks["safe_server_exits_cleanly"] = facts["safe_server_exit_code"] == 0


def run_profile(root: Path, mode: str) -> tuple[dict[str, bool], dict[str, Any]]:
    checks: dict[str, bool] = {}
    facts: dict[str, Any] = {}
    process, port, base = launch(root, mode)
    try:
        token = oauth_token(port, base, f"MTM-014 MRTR {mode}")
        status, payload = modern_tool_call(
            port,
            token,
            "request_permissions",
            permission_request(),
            capabilities={"elicitation": {}},
        )
        value = structured(payload)
        if mode == "trusted":
            checks["trusted_inline_script_is_implicit"] = (
                status == 200
                and result(payload).get("resultType") == "complete"
                and value.get("status") == "not_required"
                and value.get("constraints", {}).get("source") == "native_mode_profile"
            )
        elif mode == "dangerous":
            checks["dangerous_compatibility_grant_is_preserved"] = (
                status == 200
                and value.get("status") == "granted"
                and value.get("grant_id") == "dangerously-skip-all-permissions"
            )
        return checks, facts
    finally:
        facts[f"{mode}_server_exit_code"] = close(process)
        checks[f"{mode}_server_exits_cleanly"] = facts[f"{mode}_server_exit_code"] == 0


def main() -> int:
    if not BINARY.is_file():
        print(json.dumps({"ok": False, "error": f"MTM binary missing: {BINARY}"}, indent=2))
        return 1
    checks: dict[str, bool] = {}
    facts: dict[str, Any] = {}
    try:
        with tempfile.TemporaryDirectory(prefix="mtm014-mrtr-") as temporary:
            root = Path(temporary)
            for runner in (run_safe,):
                next_checks, next_facts = runner(root)
                checks.update(next_checks)
                facts.update(next_facts)
            for mode in ("trusted", "dangerous"):
                next_checks, next_facts = run_profile(root, mode)
                checks.update(next_checks)
                facts.update(next_facts)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, sort_keys=True))
        return 1

    report = {
        "schema_version": "1.0.0",
        "milestone": "MTM-014",
        "phase": "mrtr_permission_bridge_integration",
        "ok": all(checks.values()),
        "binary_sha256": sha256_file(BINARY),
        "check_count": len(checks),
        "checks": dict(sorted(checks.items())),
        "facts": facts,
        "real_human_consent_evidence": False,
        "raw_oauth_token_recorded": False,
        "raw_request_state_recorded": False,
        "raw_grant_id_recorded": False,
        "raw_tool_arguments_recorded": False,
        "production_exec_or_patch_authority_cutover": False,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
