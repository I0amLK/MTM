#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import sys
import tomllib
import urllib.parse
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"][
    "package"
]["version"]


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
    body = json.dumps(payload, separators=(",", ":")).encode()
    status, response_headers, data = request(
        port,
        method,
        path,
        body=body,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    return status, response_headers, json.loads(data or b"{}")


def form_request(
    port: int,
    path: str,
    payload: dict[str, str],
) -> tuple[int, dict[str, str], dict[str, Any]]:
    body = urllib.parse.urlencode(payload).encode()
    status, response_headers, data = request(
        port,
        "POST",
        path,
        body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    parsed = json.loads(data) if data else {}
    return status, response_headers, parsed


def pkce(verifier: str) -> str:
    return (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )


def tool_call(port: int, token: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    status, _, payload = json_request(
        port,
        "POST",
        "/mcp",
        {
            "jsonrpc": "2.0",
            "id": name,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    if status != 200:
        raise RuntimeError(f"{name} HTTP status {status}: {payload}")
    return payload


def main() -> int:
    if len(sys.argv) not in {2, 3}:
        raise SystemExit("usage: run_mtm007_http_smoke.py PORT [--expect-bubblewrap]")
    port = int(sys.argv[1])
    expect_bubblewrap = len(sys.argv) == 3 and sys.argv[2] == "--expect-bubblewrap"
    base = f"http://127.0.0.1:{port}"
    redirect_uri = "http://127.0.0.1/callback"
    verifier = "A" * 43

    status, _, registered = json_request(
        port,
        "POST",
        "/oauth/register",
        {
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "none",
            "client_name": "MTM-007 full Rust smoke",
        },
    )
    if status != 201:
        raise RuntimeError(f"registration failed: {status} {registered}")
    client_id = str(registered["client_id"])

    authorize = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "code_challenge": pkce(verifier),
        "code_challenge_method": "S256",
        "resource": base,
        "state": "mtm007-state",
        "password": "operator-password",
    }
    body = urllib.parse.urlencode(authorize).encode()
    status, headers, _ = request(
        port,
        "POST",
        "/oauth/authorize",
        body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if status not in {302, 303}:
        raise RuntimeError(f"authorize failed: {status}")
    location = headers.get("location", "")
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
    code = query.get("code", [""])[0]
    if not code or query.get("state", [""])[0] != "mtm007-state":
        raise RuntimeError("authorization redirect did not contain code/state")

    status, _, token_result = form_request(
        port,
        "/oauth/token",
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
            "client_id": client_id,
            "resource": base,
        },
    )
    if status != 200 or not token_result.get("access_token"):
        raise RuntimeError(f"token exchange failed: {status} {token_result}")
    token = str(token_result["access_token"])

    status, _, listed = json_request(
        port,
        "POST",
        "/mcp",
        {"jsonrpc": "2.0", "id": "list", "method": "tools/list", "params": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    names = [item.get("name") for item in listed.get("result", {}).get("tools", [])]
    if status != 200 or len(names) != 24 or "rethlas_status" in names:
        raise RuntimeError(f"tool catalog mismatch: {status} {names}")

    server_info = tool_call(port, token, "server_info", {})
    server_structured = server_info.get("result", {}).get("structuredContent", {})
    if (
        server_structured.get("tool_count") != 24
        or server_structured.get("version") != EXPECTED_VERSION
    ):
        raise RuntimeError(f"server_info did not reach RuntimeToolBackend: {server_structured}")

    read_file = tool_call(port, token, "read_file", {"path": "hello.txt"})
    read_structured = read_file.get("result", {}).get("structuredContent", {})
    if read_structured.get("content") != "hello from rust runtime\n":
        raise RuntimeError(f"read_file did not reach Rust workspace backend: {read_structured}")

    started = tool_call(
        port,
        token,
        "rethlas_start",
        {"problem_tex": "Prove $1=1$.", "workflow_mode": "compact"},
    )
    started_structured = started.get("result", {}).get("structuredContent", {})
    if not started_structured.get("run_id") or started_structured.get("state") != "assess":
        raise RuntimeError(f"rethlas_start did not reach Rust workflow: {started_structured}")

    bubblewrap_checked = False
    if expect_bubblewrap:
        environment = tool_call(port, token, "check_exec_environment", {})
        env_structured = environment.get("result", {}).get("structuredContent", {})
        if (
            env_structured.get("native_exec_backend") != "BubblewrapExecBackend"
            or env_structured.get("hard_isolation_attested") is not True
        ):
            raise RuntimeError(f"Bubblewrap attestation missing: {env_structured}")
        executed = tool_call(
            port,
            token,
            "exec_command",
            {
                "cmd": "printf 'isolated-native-ok\\n'",
                "workdir": ".",
                "yield_time_ms": 30000,
                "timeout_ms": 30000,
            },
        )
        exec_structured = executed.get("result", {}).get("structuredContent", {})
        if exec_structured.get("exit_code") != 0 or "isolated-native-ok" not in str(
            exec_structured.get("stdout", "")
        ):
            raise RuntimeError(f"Bubblewrap exec did not complete: {exec_structured}")
        bubblewrap_checked = True

    print(
        json.dumps(
            {
                "ok": True,
                "tool_count": len(names),
                "hidden_alias_not_listed": "rethlas_status" not in names,
                "server_info_runtime_backend": True,
                "read_file_runtime_backend": True,
                "rethlas_start_runtime_backend": True,
                "run_id_present": True,
                "bubblewrap_checked": bubblewrap_checked,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
