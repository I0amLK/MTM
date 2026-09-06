#!/usr/bin/env python3
"""Launch the exact staged MTM-015 candidate for a real web-client session."""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from mtm008_runtime_harness import free_port, runtime_environment, wait_for_port
from validate_mtm015_candidate_stage import validate as validate_stage


ROOT = Path(__file__).resolve().parents[1]
STATE = Path("/home/lk/.local/share/mtm/candidates/MTM-015/web-client-sessions")
PUBLIC_RE = re.compile(r"Quick Tunnel: (https://[a-z0-9-]+\.trycloudflare\.com/mcp)")


def metadata_ok(public_mcp: str) -> bool:
    origin = public_mcp.removesuffix("/mcp")
    url = origin + "/.well-known/oauth-authorization-server"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                payload = json.loads(response.read())
            if payload.get("issuer") == origin:
                return True
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            pass
        time.sleep(0.5)
    return False


def main() -> int:
    stage = validate_stage()
    candidate = Path(stage["candidate_path"])
    if shutil.which("cloudflared") is None:
        raise SystemExit("cloudflared is required for the web-client candidate session")
    session_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    session = STATE / session_id
    workspace = session / "workspace"
    data_root = session / "data"
    session.mkdir(parents=True, mode=0o700)
    workspace.mkdir(mode=0o700)
    password_file = session / "operator-password"
    password_file.write_text(secrets.token_hex(32) + "\n", encoding="utf-8")
    os.chmod(password_file, 0o600)
    password = password_file.read_text(encoding="utf-8").strip()
    log_path = session / "operator.log"
    descriptor_path = session / "session.json"
    port = free_port()
    local_origin = f"http://127.0.0.1:{port}"
    environment = runtime_environment(workspace, data_root, "rust")
    environment.pop("MTM_TOKEN_SECRET", None)
    environment.pop("MTM_CAPABILITY_SECRET", None)
    environment.update(
        MTM_OAUTH_PASSWORD=password,
        MTM_DEBUG="1",
        MTM_TRACE_PAYLOADS="0",
        MTM_NATIVE_EXEC_BACKEND="disabled",
        MTM_NATIVE_MODE="safe",
        MTM_LATEX_POLICY="static_only",
        MTM_WORKFLOW_PROTOCOL_VERSION="3",
    )
    process = subprocess.Popen(
        [
            str(candidate), "tui", "--quick-tunnel", "--verbose",
            "--host", "127.0.0.1", "--port", str(port),
            "--workspace", str(workspace), "--native-mode", "safe",
            "--latex-policy", "static_only",
        ],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        start_new_session=True,
        bufsize=1,
    )
    public_mcp = ""
    log = log_path.open("w", encoding="utf-8")
    os.chmod(log_path, 0o600)

    def stop(_signum: int, _frame: object) -> None:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    try:
        wait_for_port(port, process)
        deadline = time.monotonic() + 45
        assert process.stderr is not None
        while time.monotonic() < deadline and process.poll() is None:
            line = process.stderr.readline()
            if not line:
                time.sleep(0.05)
                continue
            log.write(line)
            log.flush()
            match = PUBLIC_RE.search(line)
            if match:
                public_mcp = match.group(1)
                break
        if not public_mcp:
            raise RuntimeError("Quick Tunnel URL was not observed")
        if not metadata_ok(public_mcp):
            raise RuntimeError("Quick Tunnel OAuth metadata issuer did not validate")
        descriptor = {
            "schema_version": "1.0.0",
            "milestone": "MTM-015",
            "session_id": session_id,
            "candidate_binary_sha256": stage["candidate_binary_sha256"],
            "candidate_path": str(candidate),
            "public_mcp_url": public_mcp,
            "local_origin": local_origin,
            "operator_password_file": str(password_file),
            "operator_log": str(log_path),
            "started_at": datetime.now(timezone.utc).isoformat(),
            "metadata_issuer_validated": True,
            "web_client_confirmed": False,
        }
        descriptor_path.write_text(json.dumps(descriptor, indent=2, sort_keys=True) + "\n")
        os.chmod(descriptor_path, 0o600)
        print(json.dumps({
            "ok": True,
            "public_mcp_url": public_mcp,
            "operator_password_file": str(password_file),
            "session_descriptor": str(descriptor_path),
            "candidate_binary_sha256": stage["candidate_binary_sha256"],
            "instruction": "Keep this process running while the real web client performs the MTM-015 test.",
        }), flush=True)
        for line in process.stderr:
            log.write(line)
            log.flush()
        code = process.wait()
        descriptor["closed_at"] = datetime.now(timezone.utc).isoformat()
        descriptor["exit_code"] = code
        descriptor_path.write_text(json.dumps(descriptor, indent=2, sort_keys=True) + "\n")
        return 0 if code == 0 else 1
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
        log.close()
        process_list = subprocess.run(
            ["ps", "-eo", "args="], stdout=subprocess.PIPE, text=True, check=True
        ).stdout
        if f"--url {local_origin}" in process_list:
            raise RuntimeError("owned Quick Tunnel child remained after shutdown")


if __name__ == "__main__":
    raise SystemExit(main())
