#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT.parent / "Re-CTM"
RUST_BINARY = ROOT / "target" / "debug" / "mtm"
GOLDEN_HASH = ROOT / "conformance" / "golden" / "mtm007-reference.sha256"
SOURCE_COMMIT = "50d08eb89e3ecc46317fd49709fa4ebcda135b5a"
TOKEN_SECRET = "11" * 32
CAPABILITY_SECRET = "22" * 32
OPERATOR_PASSWORD = "mtm007-conformance-operator"
CAPABILITY_RE = re.compile(r"^[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}$")
RUN_RE = re.compile(r"run-[A-Za-z0-9_.-]+")
TRACE_RE = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_])")


def cargo_environment() -> dict[str, str]:
    environment = os.environ.copy()
    cargo_home = ROOT / ".toolchain" / "cargo"
    rustup_home = ROOT / ".toolchain" / "rustup"
    toolchain_bin = rustup_home / "toolchains" / "1.98.0-x86_64-unknown-linux-gnu" / "bin"
    environment["CARGO_HOME"] = str(cargo_home)
    environment["RUSTUP_HOME"] = str(rustup_home)
    environment["PATH"] = os.pathsep.join(
        [str(toolchain_bin), str(cargo_home / "bin"), environment.get("PATH", "")]
    )
    return environment


def build_rust() -> None:
    cargo = ROOT / ".toolchain" / "rustup" / "toolchains" / "1.98.0-x86_64-unknown-linux-gnu" / "bin" / "cargo"
    subprocess.run(
        [str(cargo), "build", "-q", "-p", "mtm-cli"],
        cwd=ROOT,
        env=cargo_environment(),
        check=True,
    )


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_port(port: int, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stderr = process.stderr.read() if process.stderr is not None else ""
            raise RuntimeError(f"server exited during startup: {stderr[-4000:]}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"server did not listen on port {port}")


class Server:
    def __init__(self, kind: str, workspace: Path, data_root: Path) -> None:
        self.kind = kind
        self.workspace = workspace
        self.data_root = data_root
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        environment = os.environ.copy()
        environment.update(
            {
                "RE_CTM_WORKSPACE": str(workspace),
                "RE_CTM_DATA_ROOT": str(data_root),
                "RE_CTM_PRIVATE_ROOT": str(data_root / "private"),
                "RE_CTM_DEBUG_ROOT": str(data_root / "debug"),
                "RE_CTM_NATIVE_EXEC_BACKEND": "disabled",
                "RE_CTM_NATIVE_MODE": "safe",
                "RE_CTM_LATEX_POLICY": "static_only",
                "RE_CTM_OAUTH_PASSWORD": OPERATOR_PASSWORD,
                "RE_CTM_TOKEN_SECRET": TOKEN_SECRET,
                "RE_CTM_CAPABILITY_SECRET": CAPABILITY_SECRET,
                "RE_CTM_SERVER_URL": "",
                "RE_CTM_DEBUG": "0",
            }
        )
        if kind == "rust":
            command = [
                str(RUST_BINARY),
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--workspace",
                str(workspace),
                "--native-mode",
                "safe",
                "--latex-policy",
                "static_only",
            ]
        elif kind == "python":
            environment["PYTHONPATH"] = str(SOURCE_ROOT / "src")
            command = [
                "python3",
                "-m",
                "re_ctm",
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--workspace",
                str(workspace),
                "--native-mode",
                "safe",
                "--latex-policy",
                "static_only",
            ]
        else:
            raise ValueError(kind)
        self.process = subprocess.Popen(
            command,
            cwd=SOURCE_ROOT if kind == "python" else ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        wait_for_port(self.port, self.process)
        self.token = oauth_token(self)

    def close(self) -> dict[str, Any]:
        if self.process.poll() is None:
            self.process.terminate()
        try:
            code = self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            code = self.process.wait(timeout=2)
        stdout = self.process.stdout.read() if self.process.stdout is not None else ""
        stderr = self.process.stderr.read() if self.process.stderr is not None else ""
        return {
            "exit_code": code,
            "stdout_bytes": len(stdout.encode()),
            "stderr_bytes": len(stderr.encode()),
        }

    def rpc(self, request: dict[str, Any]) -> dict[str, Any]:
        status, _, payload = json_request(
            self.port,
            "POST",
            "/mcp",
            request,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        if status != 200:
            raise RuntimeError(f"{self.kind} MCP status {status}: {payload}")
        return payload

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        response = self.rpc(
            {
                "jsonrpc": "2.0",
                "id": f"call-{name}",
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )
        return dict(response.get("result") or {})


def request(
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    provided = dict(headers or {})
    if body is not None:
        provided.setdefault("Content-Length", str(len(body)))
    connection.request(method, path, body=body, headers=provided)
    response = connection.getresponse()
    data = response.read()
    result_headers = {key.lower(): value for key, value in response.getheaders()}
    status = response.status
    connection.close()
    return status, result_headers, data


def json_request(
    port: int,
    method: str,
    path: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], dict[str, Any]]:
    encoded = json.dumps(payload, separators=(",", ":")).encode()
    provided = {"Content-Type": "application/json", **(headers or {})}
    status, result_headers, data = request(port, method, path, body=encoded, headers=provided)
    return status, result_headers, json.loads(data or b"{}")


def form_request(
    port: int,
    path: str,
    payload: dict[str, str],
) -> tuple[int, dict[str, str], bytes]:
    encoded = urllib.parse.urlencode(payload).encode()
    return request(
        port,
        "POST",
        path,
        body=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )


def oauth_token(server: Server) -> str:
    redirect_uri = "http://127.0.0.1/mtm007-callback"
    status, _, registered = json_request(
        server.port,
        "POST",
        "/oauth/register",
        {
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "none",
            "client_name": "MTM-007 differential",
        },
    )
    if status != 201:
        raise RuntimeError(f"registration failed: {status} {registered}")
    client_id = str(registered["client_id"])
    verifier = "A" * 43
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    authorization = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": server.base,
        "state": "mtm007-state",
        "password": OPERATOR_PASSWORD,
    }
    status, headers, _ = form_request(server.port, "/oauth/authorize", authorization)
    if status not in (302, 303):
        raise RuntimeError(f"authorization failed: {status}")
    location = headers.get("location", "")
    code = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query).get("code", [""])[0]
    if not code:
        raise RuntimeError("authorization did not return a code")
    status, _, raw = form_request(
        server.port,
        "/oauth/token",
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
            "client_id": client_id,
            "resource": server.base,
        },
    )
    token_result = json.loads(raw or b"{}")
    if status != 200 or not token_result.get("access_token"):
        raise RuntimeError(f"token exchange failed: {status} {token_result}")
    return str(token_result["access_token"])


def prepare_workspace(path: Path) -> None:
    path.mkdir(parents=True)
    (path / "README.txt").write_text("alpha\nbeta\ngamma\n", encoding="utf-8")
    (path / "nested").mkdir()
    (path / "nested" / "note.txt").write_text("needle in nested file\n", encoding="utf-8")
    png = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Zl1sAAAAASUVORK5CYII="
    )
    (path / "pixel.png").write_bytes(png)
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "mtm007@example.invalid"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "MTM 007"], cwd=path, check=True)
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    git_environment = os.environ.copy()
    git_environment.update(
        {
            "GIT_AUTHOR_DATE": "2026-09-01T12:00:00+00:00",
            "GIT_COMMITTER_DATE": "2026-09-01T12:00:00+00:00",
        }
    )
    subprocess.run(
        ["git", "commit", "-q", "-m", "fixture"],
        cwd=path,
        env=git_environment,
        check=True,
    )


def structured(result: dict[str, Any]) -> Any:
    return result.get("structuredContent")


def normalize(value: Any, *, server: Server, run_id: str | None = None) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key in sorted(value):
            if key in {
                "trace_id",
                "created_at",
                "updated_at",
                "issued_at",
                "expires_at",
                "timestamp",
                "mtime_ns",
                "modified",
            }:
                continue
            result[key] = normalize(value[key], server=server, run_id=run_id)
        return result
    if isinstance(value, list):
        return [normalize(item, server=server, run_id=run_id) for item in value]
    if isinstance(value, str):
        text = value.replace(server.base, "<BASE>")
        text = text.replace(str(server.workspace), "<WORKSPACE>")
        text = text.replace(str(server.data_root), "<DATA_ROOT>")
        if run_id:
            text = text.replace(run_id, "<RUN>")
        text = RUN_RE.sub("<RUN>", text)
        if CAPABILITY_RE.fullmatch(text):
            return "<CAPABILITY>"
        if len(text) >= 24 and TRACE_RE.fullmatch(text) and "/" not in text:
            return "<OPAQUE>"
        return text
    return value


def record_pair(
    records: list[dict[str, Any]],
    name: str,
    python_value: Any,
    rust_value: Any,
) -> None:
    records.append(
        {
            "name": name,
            "python": python_value,
            "rust": rust_value,
            "match": python_value == rust_value,
        }
    )


def tool_pair(
    records: list[dict[str, Any]],
    name: str,
    arguments: dict[str, Any],
    python: Server,
    rust: Server,
    *,
    normalize_run: tuple[str | None, str | None] = (None, None),
) -> tuple[Any, Any]:
    py = structured(python.call(name, arguments))
    rs = structured(rust.call(name, arguments))
    py_n = normalize(py, server=python, run_id=normalize_run[0])
    rs_n = normalize(rs, server=rust, run_id=normalize_run[1])
    record_pair(records, name, py_n, rs_n)
    return py, rs


def run_scenario(python: Server, rust: Server) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for server in (python, rust):
        status, _, raw = request(server.port, "GET", "/.well-known/oauth-authorization-server")
        if status != 200:
            raise RuntimeError(f"metadata failed for {server.kind}")
        metadata = json.loads(raw)
        selected = {
            key: metadata.get(key)
            for key in (
                "issuer",
                "authorization_endpoint",
                "token_endpoint",
                "registration_endpoint",
                "code_challenge_methods_supported",
            )
        }
        selected = normalize(selected, server=server)
        if server.kind == "python":
            py_metadata = selected
        else:
            rs_metadata = selected
    record_pair(records, "oauth_metadata", py_metadata, rs_metadata)

    list_request = {"jsonrpc": "2.0", "id": "list", "method": "tools/list", "params": {}}
    py_list = python.rpc(list_request).get("result")
    rs_list = rust.rpc(list_request).get("result")
    record_pair(
        records,
        "tools_list",
        normalize(py_list, server=python),
        normalize(rs_list, server=rust),
    )

    tool_pair(records, "server_info", {}, python, rust)
    tool_pair(records, "check_exec_environment", {}, python, rust)
    tool_pair(records, "read_file", {"path": "README.txt"}, python, rust)
    tool_pair(records, "list_dir", {"path": ".", "sort": "name"}, python, rust)
    tool_pair(records, "list_files", {"glob": "**/*.txt", "sort": "path"}, python, rust)
    tool_pair(records, "search_text", {"query": "needle", "path": "."}, python, rust)
    tool_pair(records, "git_status", {}, python, rust)
    tool_pair(records, "git_log", {"max_count": 1}, python, rust)
    tool_pair(records, "git_show", {"rev": "HEAD", "include_diff": False}, python, rust)
    tool_pair(records, "git_blame", {"path": "README.txt", "start_line": 1, "end_line": 1}, python, rust)
    tool_pair(
        records,
        "view_image",
        {"path": "pixel.png", "auto_resize": False, "max_bytes": 1_000_000},
        python,
        rust,
    )
    tool_pair(
        records,
        "request_permissions",
        {
            "tool_name": "exec_command",
            "permission": "network",
            "reason": "MTM-007 conformance",
            "arguments": {"cmd": "true"},
        },
        python,
        rust,
    )
    patch = "*** Begin Patch\n*** Update File: README.txt\n@@\n-alpha\n+alpha changed\n*** End Patch"
    tool_pair(records, "apply_patch", {"patch": patch, "dry_run": True}, python, rust)

    py_start = structured(
        python.call(
            "rethlas_start",
            {"problem_tex": "Prove that 1+1=2.", "workflow_mode": "compact"},
        )
    )
    rs_start = structured(
        rust.call(
            "rethlas_start",
            {"problem_tex": "Prove that 1+1=2.", "workflow_mode": "compact"},
        )
    )
    py_run = str((py_start or {}).get("run_id") or "")
    rs_run = str((rs_start or {}).get("run_id") or "")
    if not py_run or not rs_run:
        raise RuntimeError("rethlas_start did not return run ids")
    record_pair(
        records,
        "rethlas_start",
        normalize(py_start, server=python, run_id=py_run),
        normalize(rs_start, server=rust, run_id=rs_run),
    )
    py_step = structured(python.call("rethlas_step", {"run_id": py_run}))
    rs_step = structured(rust.call("rethlas_step", {"run_id": rs_run}))
    record_pair(
        records,
        "rethlas_step_initial",
        normalize(py_step, server=python, run_id=py_run),
        normalize(rs_step, server=rust, run_id=rs_run),
    )
    py_status = structured(
        python.call("rethlas_inspect", {"operation": "status", "run_id": py_run})
    )
    rs_status = structured(
        rust.call("rethlas_inspect", {"operation": "status", "run_id": rs_run})
    )
    record_pair(
        records,
        "rethlas_status",
        normalize(py_status, server=python, run_id=py_run),
        normalize(rs_status, server=rust, run_id=rs_run),
    )
    return records


def source_state() -> dict[str, Any]:
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=SOURCE_ROOT,
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout.strip()
    tracked = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=SOURCE_ROOT,
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout.strip()
    runtime_tracked = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no", "--", "src/re_ctm"],
        cwd=SOURCE_ROOT,
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout.strip()
    return {
        "head": head,
        "repo_tracked_clean": not tracked,
        "runtime_tracked_clean": not runtime_tracked,
    }


def main() -> int:
    build_rust()
    source = source_state()
    if source["head"] != SOURCE_COMMIT or not source["runtime_tracked_clean"]:
        print(json.dumps({"ok": False, "error": "source commit changed", "source": source}, indent=2))
        return 1
    records: list[dict[str, Any]] = []
    shutdown: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="mtm007-conformance-") as directory:
        root = Path(directory)
        py_workspace = root / "python-workspace"
        rs_workspace = root / "rust-workspace"
        prepare_workspace(py_workspace)
        shutil.copytree(py_workspace, rs_workspace, symlinks=True)
        python = Server("python", py_workspace, root / "python-data")
        rust = Server("rust", rs_workspace, root / "rust-data")
        try:
            records = run_scenario(python, rust)
        finally:
            shutdown["python"] = python.close()
            shutdown["rust"] = rust.close()

    mismatches = [record for record in records if not record["match"]]
    comparable = [{"name": item["name"], "python": item["python"], "rust": item["rust"]} for item in records]
    digest = hashlib.sha256(
        json.dumps(comparable, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    recorded = GOLDEN_HASH.read_text(encoding="utf-8").strip()
    golden_match = digest == recorded
    report = {
        "ok": not mismatches and golden_match,
        "project": "MTM-reboot",
        "milestone": "MTM-007",
        "source_commit": source["head"],
        "source_runtime_tracked_clean": source["runtime_tracked_clean"],
        "source_repo_tracked_clean": source["repo_tracked_clean"],
        "record_count": len(records),
        "mismatch_count": len(mismatches),
        "sha256": digest,
        "recorded_sha256": recorded,
        "golden_match": golden_match,
        "mismatches": mismatches,
        "shutdown": shutdown,
        "authority": {
            "python": "source reference on disposable state",
            "rust": "MTM-007 full composition on disposable state",
            "deployed_production": "python",
        },
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
