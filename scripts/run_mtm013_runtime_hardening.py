#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from mtm008_runtime_harness import free_port, oauth_token, runtime_environment, wait_for_port
from run_mtm007_http_smoke import tool_call


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BINARY = ROOT / "target" / "debug" / "mtm"
BINARY = Path(os.environ.get("MTM013_BINARY", DEFAULT_BINARY))
REPORT = Path(os.environ.get("MTM013_HARDENING_REPORT", ROOT / "mtm013-runtime-hardening.json"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def structured(response: dict[str, Any]) -> dict[str, Any]:
    result = response.get("result")
    if not isinstance(result, dict):
        raise RuntimeError(f"MCP response has no result: {response}")
    content = result.get("structuredContent")
    if not isinstance(content, dict):
        raise RuntimeError(f"MCP response has no structuredContent: {response}")
    return content


def is_error(response: dict[str, Any]) -> bool:
    result = response.get("result")
    return isinstance(result, dict) and result.get("isError") is True


def error_code(response: dict[str, Any]) -> str:
    return str(structured(response).get("error", {}).get("code") or "")


def mutate_signature(token: str) -> str:
    body, signature = token.split(".", 1)
    replacement = "A" if signature[0] != "A" else "B"
    return f"{body}.{replacement}{signature[1:]}"


def truncate_signature(token: str) -> str:
    body, signature = token.split(".", 1)
    keep = max(8, len(signature) // 2)
    return f"{body}.{signature[:keep]}"


def task_submission(task: dict[str, Any], capability: str) -> dict[str, Any]:
    minimal = task.get("task", {}).get("minimal_submission")
    if not isinstance(minimal, dict):
        raise RuntimeError("current task has no minimal_submission")
    return {
        "run_id": str(task["run_id"]),
        "capability": capability,
        "action": str(minimal["action"]),
        "payload": minimal.get("payload", {}),
        "writes": minimal.get("writes", []),
    }


def close(process: subprocess.Popen[str]) -> int:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        return process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        return process.wait(timeout=3)


def launch(root: Path) -> tuple[subprocess.Popen[str], int, str]:
    workspace = root / "workspace"
    data_root = root / "data"
    workspace.mkdir(parents=True, exist_ok=True)
    port = free_port()
    environment = runtime_environment(workspace, data_root, "rust")
    environment["MTM_WORKFLOW_PROTOCOL_VERSION"] = "3"
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
            "safe",
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


def start_run(port: int, token: str, problem_id: str) -> dict[str, Any]:
    started = structured(
        tool_call(
            port,
            token,
            "rethlas_start",
            {
                "problem_tex": r"\begin{proposition}Prove that $1=1$.\end{proposition}",
                "problem_id": problem_id,
                "workflow_mode": "full",
                "register_result": False,
            },
        )
    )
    return structured(tool_call(port, token, "rethlas_step", {"run_id": started["run_id"]}))


def main() -> int:
    if not BINARY.is_file():
        raise SystemExit(f"MTM-013 binary is missing: {BINARY}")
    checks: dict[str, bool] = {}
    facts: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="mtm013-hardening-") as temporary:
        root = Path(temporary)
        process, port, base = launch(root)
        try:
            owner_token = oauth_token(port, base, "MTM-013 owner")
            other_token = oauth_token(port, base, "MTM-013 other owner")

            info = structured(tool_call(port, owner_token, "server_info", {}))
            checks["server_info_complete_flow_validated"] = (
                info.get("complete_flow_locally_validated") is True
            )
            checks["server_info_protocol_default_unchanged"] = (
                info.get("research_workspace", {}).get(
                    "production_default_workflow_protocol_version"
                )
                == 3
            )

            current = start_run(port, owner_token, "mtm013-capability-refresh")
            original_capability = str(current["capability"])
            original_state = str(current["state"])

            mutated_response = tool_call(
                port,
                owner_token,
                "rethlas_step",
                task_submission(current, mutate_signature(original_capability)),
            )
            mutated = structured(mutated_response)
            checks["mutated_capability_is_recoverable_not_error"] = not is_error(mutated_response)
            checks["mutated_capability_reports_invalid"] = (
                mutated.get("submission", {}).get("error", {}).get("code")
                == "CAPABILITY_INVALID"
            )
            checks["mutated_capability_refreshes_fresh_envelope"] = (
                mutated.get("submission", {}).get("capability_refreshed") is True
                and isinstance(mutated.get("capability"), str)
                and mutated.get("capability") not in {original_capability, mutate_signature(original_capability)}
            )
            checks["mutated_capability_applies_zero_writes"] = (
                mutated.get("writes_applied") == 0 and mutated.get("state") == original_state
            )

            truncated_response = tool_call(
                port,
                owner_token,
                "rethlas_step",
                task_submission(mutated, truncate_signature(str(mutated["capability"]))),
            )
            truncated = structured(truncated_response)
            checks["truncated_capability_refreshes_without_writes"] = (
                not is_error(truncated_response)
                and truncated.get("submission", {}).get("error", {}).get("code")
                == "CAPABILITY_INVALID"
                and truncated.get("writes_applied") == 0
                and truncated.get("state") == original_state
            )

            fresh_capability = str(truncated["capability"])
            valid_response = tool_call(
                port,
                owner_token,
                "rethlas_step",
                task_submission(truncated, fresh_capability),
            )
            valid = structured(valid_response)
            checks["fresh_capability_resubmission_advances"] = (
                not is_error(valid_response)
                and valid.get("state") != original_state
                and int(valid.get("writes_applied", -1))
                == len(truncated.get("task", {}).get("minimal_submission", {}).get("writes", []))
            )

            revoked_response = tool_call(
                port,
                owner_token,
                "rethlas_step",
                task_submission(valid, fresh_capability),
            )
            checks["revoked_capability_remains_denied"] = (
                is_error(revoked_response) and error_code(revoked_response) == "CAPABILITY_REVOKED"
            )

            second = start_run(port, owner_token, "mtm013-cross-run")
            first_current_capability = str(valid["capability"])
            cross_run_response = tool_call(
                port,
                owner_token,
                "rethlas_step",
                task_submission(second, first_current_capability),
            )
            checks["cross_run_capability_remains_denied"] = (
                is_error(cross_run_response)
                and error_code(cross_run_response) == "CAPABILITY_RUN_MISMATCH"
            )

            cross_owner_response = tool_call(
                port,
                other_token,
                "rethlas_step",
                task_submission(valid, mutate_signature(first_current_capability)),
            )
            checks["invalid_capability_cannot_cross_owner_refresh"] = (
                is_error(cross_owner_response)
                and error_code(cross_owner_response) == "RUN_OWNER_MISMATCH"
            )

            facts = {
                "initial_state": original_state,
                "advanced_state": valid.get("state"),
                "workflow_protocol_version": info.get("research_workspace", {}).get(
                    "workflow_protocol_version"
                ),
                "production_default_workflow_protocol_version": info.get(
                    "research_workspace", {}
                ).get("production_default_workflow_protocol_version"),
            }
        finally:
            exit_code = close(process)
        checks["server_exits_cleanly"] = exit_code == 0

    payload = {
        "schema_version": "1.0.0",
        "milestone": "MTM-013",
        "binary_sha256": sha256_file(BINARY),
        "harness_sha256": sha256_file(Path(__file__)),
        "checks": checks,
        "facts": facts,
        "raw_capability_recorded": False,
        "raw_oauth_token_recorded": False,
        "ok": bool(checks) and all(checks.values()),
    }
    REPORT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
