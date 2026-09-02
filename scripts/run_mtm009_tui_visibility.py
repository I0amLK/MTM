#!/usr/bin/env python3
from __future__ import annotations

import json
import signal
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.mtm008_runtime_harness import free_port, oauth_token, runtime_environment, wait_for_port
from scripts.run_mtm007_http_smoke import tool_call


BINARY = ROOT / "target" / "release" / "mtm"


def main() -> int:
    if not BINARY.is_file():
        raise RuntimeError("build target/release/mtm before running TUI visibility acceptance")

    with tempfile.TemporaryDirectory(prefix="mtm009-tui-") as temporary:
        root = Path(temporary)
        workspace = root / "workspace"
        data_root = root / "data"
        workspace.mkdir()
        marker = "tui-visibility-secret-content"
        target = workspace / "visibility-probe.txt"
        target.write_text(marker + "\n", encoding="utf-8")
        port = free_port()
        environment = runtime_environment(workspace, data_root, "rust")
        process = subprocess.Popen(
            [
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
        token = oauth_token(port, f"http://127.0.0.1:{port}", "MTM-009 TUI visibility")
        response = tool_call(port, token, "read_file", {"path": "visibility-probe.txt"})
        result = response.get("result", {}).get("structuredContent", {})
        if result.get("ok") is False:
            raise RuntimeError(f"read_file failed: {result}")

        process.send_signal(signal.SIGINT)
        exit_code = process.wait(timeout=8)
        stdout = process.stdout.read() if process.stdout is not None else ""
        stderr = process.stderr.read() if process.stderr is not None else ""
        checks = {
            "process_exit_clean": exit_code == 0,
            "tool_start_visible": "[tool:start] read_file args=[path]" in stderr,
            "tool_done_visible": "[tool:done] read_file" in stderr,
            "argument_value_hidden": "visibility-probe.txt" not in stderr,
            "file_content_hidden": marker not in stderr,
            "tui_monitor_announced": "TUI: minimal operator session monitor active" in stderr,
        }
        payload = {
            "ok": all(checks.values()),
            "version": subprocess.run(
                [str(BINARY), "--version"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                check=True,
            ).stdout.strip(),
            "checks": checks,
            "stdout_bytes": len(stdout.encode()),
            "stderr_bytes": len(stderr.encode()),
        }
        print(json.dumps(payload, indent=2))
        return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
