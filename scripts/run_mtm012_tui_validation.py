#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Any

from mtm008_runtime_harness import (
    CAPABILITY_SECRET,
    OPERATOR_PASSWORD,
    TOKEN_SECRET,
    free_port,
    oauth_token,
    runtime_environment,
    wait_for_port,
)
from run_mtm007_http_smoke import tool_call


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BINARY = ROOT / "target" / "release" / "mtm"
REPORT = Path(os.environ.get("MTM012_TUI_REPORT", ROOT / "mtm012-tui-validation.json"))
BINARY = Path(os.environ.get("MTM012_BINARY", DEFAULT_BINARY))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def workspace_version() -> str:
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    return str(manifest["workspace"]["package"]["version"])


def close(process: subprocess.Popen[str]) -> tuple[int, str]:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        code = process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        code = process.wait(timeout=3)
    stderr = process.stderr.read() if process.stderr is not None else ""
    return code, stderr


def launch(
    root: Path,
    *,
    verbose: bool,
    external_password: bool,
) -> tuple[subprocess.Popen[str], int, str]:
    workspace = root / ("workspace-verbose" if verbose else "workspace-compact")
    data_root = root / ("data-verbose" if verbose else "data-compact")
    workspace.mkdir(parents=True, exist_ok=True)
    port = free_port()
    environment = runtime_environment(workspace, data_root, "rust")
    environment["MTM_WORKFLOW_PROTOCOL_VERSION"] = "3"
    if not external_password:
        environment.pop("MTM_OAUTH_PASSWORD", None)
    command = [
        str(BINARY),
        "tui",
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
    ]
    if verbose:
        command.append("--verbose")
    process = subprocess.Popen(
        command,
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


def exercise_tools(port: int, base: str) -> None:
    token = oauth_token(port, base, "MTM-012 TUI validation")
    tool_call(port, token, "server_info", {})
    tool_call(
        port,
        token,
        "rethlas_start",
        {
            "problem_tex": "Prove that 1=1.",
            "problem_id": "mtm012-tui-smoke",
            "workflow_mode": "compact",
            "register_result": False,
        },
    )
    tool_call(port, token, "rethlas_step", {"run_id": "run-does-not-exist"})


def contains_forbidden_secret(text: str) -> bool:
    forbidden = [
        OPERATOR_PASSWORD,
        TOKEN_SECRET,
        CAPABILITY_SECRET,
        "Bearer ",
    ]
    lowered = text.lower()
    return any(value.lower() in lowered for value in forbidden)


def main() -> int:
    if not BINARY.is_file():
        raise SystemExit(f"MTM-012 binary is missing: {BINARY}")
    version = workspace_version()
    reported_version = subprocess.run(
        [str(BINARY), "--version"],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        check=True,
    ).stdout.strip()
    if reported_version != f"mtm {version}":
        raise SystemExit(f"binary/workspace version mismatch: {reported_version} != mtm {version}")

    with tempfile.TemporaryDirectory(prefix="mtm012-tui-") as raw_root:
        root = Path(raw_root)

        compact, compact_port, compact_base = launch(
            root,
            verbose=False,
            external_password=True,
        )
        try:
            exercise_tools(compact_port, compact_base)
        finally:
            compact_code, compact_log = close(compact)

        verbose, verbose_port, verbose_base = launch(
            root,
            verbose=True,
            external_password=True,
        )
        try:
            exercise_tools(verbose_port, verbose_base)
        finally:
            verbose_code, verbose_log = close(verbose)

        generated, _, _ = launch(root, verbose=False, external_password=False)
        # wait_for_port can observe the bound listener just before the startup
        # lines and SIGINT handler become visible; allow that bounded local
        # initialization to finish before checking the generated-key surface.
        time.sleep(0.2)
        generated_code, generated_log = close(generated)

    generated_keys = re.findall(r"(?m)^OAuth key: (\S+)$", generated_log)
    compact_tool_lines = [line for line in compact_log.splitlines() if line.startswith("tool: ")]
    checks: dict[str, bool] = {
        "compact_process_exits_cleanly": compact_code == 0,
        "verbose_process_exits_cleanly": verbose_code == 0,
        "generated_key_process_exits_cleanly": generated_code == 0,
        "compact_header_is_short": f"MTM {version} | P3 | safe" in compact_log,
        "compact_mcp_endpoint_visible": f"MCP: http://127.0.0.1:{compact_port}/mcp" in compact_log,
        "compact_tool_identity_visible": "tool: server_info" in compact_log
        and "tool: rethlas_start" in compact_log,
        "compact_success_completion_silent": "[tool:done]" not in compact_log
        and "tool.call_finished" not in compact_log,
        "compact_failure_visible": "tool failed: rethlas_step" in compact_log,
        "compact_trace_hidden": "trace=" not in compact_log,
        "compact_argument_keys_hidden": "args=[" not in compact_log,
        "compact_external_password_status_silent": "OAuth key:" not in compact_log
        and "OAuth operator key:" not in compact_log,
        "compact_tool_lines_are_not_duplicated": compact_tool_lines.count("tool: server_info") == 1
        and compact_tool_lines.count("tool: rethlas_start") == 1,
        "verbose_mode_announced": "TUI: verbose operator diagnostics active" in verbose_log,
        "verbose_start_and_done_visible": "[tool:start] server_info" in verbose_log
        and "[tool:done] server_info" in verbose_log,
        "verbose_failure_visible": "[tool:error] rethlas_step" in verbose_log,
        "verbose_trace_visible": "trace=" in verbose_log,
        "verbose_argument_keys_visible": "args=[run_id]" in verbose_log,
        "compact_secrets_redacted": not contains_forbidden_secret(compact_log),
        "verbose_secrets_redacted": not contains_forbidden_secret(verbose_log),
        "generated_operator_key_shown_once": len(generated_keys) == 1 and bool(generated_keys[0]),
    }
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "milestone": "MTM-012",
        "version": version,
        "binary_sha256": sha256_file(BINARY),
        "harness_sha256": sha256_file(Path(__file__)),
        "checks": checks,
        "compact_tool_line_count": len(compact_tool_lines),
        "verbose_diagnostic_markers": {
            "start": verbose_log.count("[tool:start]"),
            "done": verbose_log.count("[tool:done]"),
            "error": verbose_log.count("[tool:error]"),
        },
        "generated_operator_key_recorded": False,
        "raw_tui_log_recorded": False,
        "performance_claim": False,
        "ok": all(checks.values()),
    }
    temporary = REPORT.with_suffix(REPORT.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(REPORT)
    print(json.dumps(payload, indent=2))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
