#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import html
import http.client
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-005/target-validation.json"
CARGO_HOME = ROOT / ".toolchain" / "cargo"
RUSTUP_HOME = ROOT / ".toolchain" / "rustup"
SERVER = ROOT / "target" / "debug" / "mtm-gateway-server"
SOURCE = (ROOT / "../Re-CTM").resolve()
PUBLIC_NAMES = [
    "server_info",
    "check_exec_environment",
    "read_file",
    "list_dir",
    "list_files",
    "search_text",
    "apply_patch",
    "exec_command",
    "write_stdin",
    "kill_command",
    "read_output",
    "git_status",
    "git_diff",
    "git_log",
    "git_show",
    "git_blame",
    "request_permissions",
    "view_image",
    "rethlas_start",
    "rethlas_step",
    "rethlas_inspect",
    "rethlas_retrieve",
    "rethlas_control",
    "rethlas_artifact",
]


def implementation_sha256() -> str:
    digest = hashlib.sha256()
    roots = [
        ROOT / "Cargo.toml",
        ROOT / "Cargo.lock",
        ROOT / "rust-toolchain.toml",
        ROOT / "crates" / "mtm-contracts",
        ROOT / "crates" / "mtm-core",
        ROOT / "crates" / "mtm-gateway",
    ]
    files: list[Path] = []
    for root in roots:
        if root.is_file():
            files.append(root)
        elif root.is_dir():
            files.extend(path for path in root.rglob("*") if path.is_file())
    for path in sorted(files):
        relative = path.relative_to(ROOT).as_posix().encode()
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def cargo_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["CARGO_HOME"] = str(CARGO_HOME)
    environment["RUSTUP_HOME"] = str(RUSTUP_HOME)
    environment["PATH"] = str(CARGO_HOME / "bin") + os.pathsep + environment.get("PATH", "")
    return environment


def build_server() -> None:
    subprocess.run(
        [
            str(CARGO_HOME / "bin" / "cargo"),
            "build",
            "-q",
            "-p",
            "mtm-gateway",
            "--bin",
            "mtm-gateway-server",
        ],
        cwd=ROOT,
        env=cargo_environment(),
        check=True,
    )


def source_catalog(path: Path) -> None:
    script = """
import json
from re_ctm.tools import PUBLIC_TOOL_NAMES, TOOL_SPECS
from re_ctm.rethlas_contracts import HIDDEN_LEGACY_ALIAS_SEMANTICS
payload = {
  'schema_version': '1.0.0',
  'public_names': list(PUBLIC_TOOL_NAMES),
  'hidden_names': [name for name in TOOL_SPECS if name not in PUBLIC_TOOL_NAMES],
  'definitions': {name: TOOL_SPECS[name].definition(name) for name in TOOL_SPECS},
  'alias_semantics': {name: list(value) for name, value in HIDDEN_LEGACY_ALIAS_SEMANTICS.items()},
}
print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':')))
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(SOURCE / "src")
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=environment,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    path.write_text(completed.stdout, encoding="utf-8")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class GatewayProcess:
    def __init__(
        self,
        *,
        root: Path,
        catalog: Path,
        port: int,
        server_url: str = "",
    ) -> None:
        environment = os.environ.copy()
        environment.update(
            {
                "MTM_GATEWAY_BIND": f"127.0.0.1:{port}",
                "MTM_GATEWAY_CATALOG": str(catalog),
                "MTM_GATEWAY_OAUTH_DB": str(root / f"oauth-{port}.sqlite3"),
                "MTM_GATEWAY_OAUTH_PASSWORD": "operator-password",
                "MTM_GATEWAY_TOKEN_SECRET_B64": base64.b64encode(b"o" * 32).decode(),
                "MTM_GATEWAY_ALLOWED_ORIGINS": "https://allowed.example",
                "MTM_GATEWAY_SERVER_URL": server_url,
            }
        )
        self.process = subprocess.Popen(
            [str(SERVER)],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if self.process.stdout is None:
            raise RuntimeError("gateway stdout unavailable")
        line = self.process.stdout.readline()
        if not line:
            stderr = self.process.stderr.read() if self.process.stderr is not None else ""
            raise RuntimeError(f"gateway failed to start: {stderr}")
        startup = json.loads(line)
        if startup.get("ok") is not True:
            raise RuntimeError(f"gateway startup failed: {startup}")
        self.port = port
        self.base = f"http://127.0.0.1:{port}"

    def close(self) -> dict[str, Any]:
        self.process.terminate()
        try:
            code = self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            code = self.process.wait(timeout=2)
        stderr = self.process.stderr.read() if self.process.stderr is not None else ""
        return {"exit_code": code, "stderr_empty": not stderr.strip()}


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
    status, response_headers, data = request(
        port, method, path, body=encoded, headers=provided
    )
    return status, response_headers, json.loads(data or b"{}")


def form_request(
    port: int,
    path: str,
    payload: dict[str, str],
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], dict[str, Any]]:
    encoded = urllib.parse.urlencode(payload).encode()
    provided = {
        "Content-Type": "application/x-www-form-urlencoded",
        **(headers or {}),
    }
    status, response_headers, data = request(
        port, "POST", path, body=encoded, headers=provided
    )
    return status, response_headers, json.loads(data or b"{}")


def pkce(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


class CallbackHandler(http.server.BaseHTTPRequestHandler):
    result: dict[str, str] = {}
    event = threading.Event()

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        type(self).result = {key: values[0] for key, values in query.items() if values}
        type(self).event.set()
        body = b"<!doctype html><title>OAuth complete</title><p>complete</p>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def firefox_binary() -> str | None:
    return shutil.which("firefox")


def browser_oauth(
    firefox: str,
    root: Path,
    gateway: GatewayProcess,
    client_id: str,
    redirect_uri: str,
    verifier: str,
) -> dict[str, Any]:
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "code_challenge": pkce(verifier),
        "code_challenge_method": "S256",
        "resource": gateway.base,
        "state": "browser-state",
    }
    authorize_url = gateway.base + "/oauth/authorize?" + urllib.parse.urlencode(params)
    profile = root / "firefox-profile"
    profile.mkdir()
    page_image = root / "authorize.png"
    page = subprocess.run(
        [
            firefox,
            "--headless",
            "--no-remote",
            "-profile",
            str(profile),
            "--screenshot",
            str(page_image),
            authorize_url,
        ],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=40,
        check=False,
    )
    fields = {**params, "password": "operator-password"}
    inputs = "".join(
        f'<input type="hidden" name="{html.escape(key)}" value="{html.escape(value)}">'
        for key, value in fields.items()
    )
    driver_page = root / "browser-submit.html"
    driver_page.write_text(
        "<!doctype html><form id='f' method='post' action='"
        + html.escape(gateway.base + "/oauth/authorize")
        + "'>"
        + inputs
        + "</form><script>document.getElementById('f').submit()</script>",
        encoding="utf-8",
    )
    CallbackHandler.result = {}
    CallbackHandler.event.clear()
    callback_image = root / "callback.png"
    submit = subprocess.Popen(
        [
            firefox,
            "--headless",
            "--no-remote",
            "-profile",
            str(profile),
            "--screenshot",
            str(callback_image),
            driver_page.as_uri(),
        ],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    received = CallbackHandler.event.wait(timeout=30)
    try:
        submit_stdout, submit_stderr = submit.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        submit.terminate()
        submit_stdout, submit_stderr = submit.communicate(timeout=5)
    return {
        "auth_page_loaded": page.returncode == 0 and page_image.is_file(),
        "browser_submit_received": received,
        "browser_exit_code": submit.returncode,
        "code": CallbackHandler.result.get("code", ""),
        "state": CallbackHandler.result.get("state", ""),
        "diagnostic_empty": not (page.stderr + submit_stderr + submit_stdout).strip(),
    }


def duplicate_header_request(
    port: int,
    token: str,
    payload: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    body = json.dumps(payload, separators=(",", ":")).encode()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    connection.putrequest("POST", "/mcp")
    connection.putheader("Content-Type", "application/json")
    connection.putheader("Content-Length", str(len(body)))
    connection.putheader("Authorization", f"Bearer {token}")
    connection.putheader("MCP-Protocol-Version", "2026-07-28")
    connection.putheader("MCP-Protocol-Version", "2026-07-28")
    connection.putheader("Mcp-Method", "tools/list")
    connection.endheaders(body)
    response = connection.getresponse()
    data = json.loads(response.read() or b"{}")
    status = response.status
    connection.close()
    return status, data


def main() -> int:
    build_server()
    firefox = firefox_binary()
    checks: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="mtm005-target-") as directory:
        root = Path(directory)
        catalog = root / "catalog.json"
        source_catalog(catalog)
        callback_server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), CallbackHandler
        )
        callback_thread = threading.Thread(
            target=callback_server.serve_forever, daemon=True
        )
        callback_thread.start()
        callback_port = int(callback_server.server_address[1])
        redirect_uri = f"http://127.0.0.1:{callback_port}/callback"
        gateway = GatewayProcess(
            root=root, catalog=catalog, port=free_port(), server_url=""
        )
        try:
            status, _, metadata_raw = request(
                gateway.port, "GET", "/.well-known/oauth-authorization-server"
            )
            metadata = json.loads(metadata_raw)
            checks.append(
                {
                    "name": "dynamic_loopback_metadata",
                    "passed": status == 200 and metadata.get("issuer") == gateway.base,
                    "status": status,
                }
            )
            status, _, forwarded_raw = request(
                gateway.port,
                "GET",
                "/.well-known/oauth-authorization-server",
                headers={
                    "X-Forwarded-Proto": "https",
                    "X-Forwarded-Host": "unit-test.trycloudflare.com",
                },
            )
            forwarded = json.loads(forwarded_raw)
            checks.append(
                {
                    "name": "trusted_loopback_forwarded_origin",
                    "passed": status == 200
                    and forwarded.get("issuer")
                    == "https://unit-test.trycloudflare.com",
                    "status": status,
                }
            )
            registration_payload = {
                "redirect_uris": [redirect_uri],
                "token_endpoint_auth_method": "none",
                "client_name": "Browser Target Client",
            }
            status, _, registered = json_request(
                gateway.port,
                "POST",
                "/oauth/register",
                registration_payload,
                headers={"Origin": "https://attacker.example"},
            )
            checks.append(
                {
                    "name": "oauth_registration_not_blocked_by_mcp_origin_gate",
                    "passed": status == 201 and bool(registered.get("client_id")),
                    "status": status,
                }
            )
            verifier = "A" * 43
            if firefox is None:
                browser_result = {
                    "auth_page_loaded": False,
                    "browser_submit_received": False,
                    "browser_exit_code": None,
                    "code": "",
                    "state": "",
                    "diagnostic_empty": False,
                }
            else:
                browser_result = browser_oauth(
                    firefox,
                    root,
                    gateway,
                    str(registered.get("client_id") or ""),
                    redirect_uri,
                    verifier,
                )
            code = str(browser_result.pop("code"))
            checks.append(
                {
                    "name": "real_firefox_authorization_page_and_form",
                    "passed": browser_result["auth_page_loaded"]
                    and browser_result["browser_submit_received"]
                    and bool(code)
                    and browser_result["state"] == "browser-state",
                    **browser_result,
                }
            )
            token_payload = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
                "client_id": str(registered.get("client_id") or ""),
                "resource": gateway.base,
            }
            status, _, token_result = form_request(
                gateway.port, "/oauth/token", token_payload
            )
            token = str(token_result.get("access_token") or "")
            checks.append(
                {
                    "name": "browser_code_pkce_exchange",
                    "passed": status == 200
                    and token_result.get("token_type") == "Bearer"
                    and bool(token),
                    "status": status,
                }
            )
            reuse_status, _, reuse = form_request(
                gateway.port, "/oauth/token", token_payload
            )
            checks.append(
                {
                    "name": "authorization_code_single_use",
                    "passed": reuse_status == 403
                    and reuse.get("error", {}).get("code") == "OAUTH_INVALID_GRANT",
                    "status": reuse_status,
                }
            )
            ping = {"jsonrpc": "2.0", "id": "ping", "method": "ping", "params": {}}
            unauthorized_status, unauthorized_headers, unauthorized = json_request(
                gateway.port, "POST", "/mcp", ping
            )
            checks.append(
                {
                    "name": "mcp_requires_bearer_and_advertises_resource_metadata",
                    "passed": unauthorized_status == 401
                    and unauthorized.get("error", {}).get("code") == "OAUTH_UNAUTHORIZED"
                    and "resource_metadata="
                    in unauthorized_headers.get("www-authenticate", ""),
                    "status": unauthorized_status,
                }
            )
            auth = {"Authorization": f"Bearer {token}"}
            list_request = {
                "jsonrpc": "2.0",
                "id": "legacy-list",
                "method": "tools/list",
                "params": {},
            }
            status, _, listed = json_request(
                gateway.port, "POST", "/mcp", list_request, headers=auth
            )
            names = [item.get("name") for item in listed.get("result", {}).get("tools", [])]
            checks.append(
                {
                    "name": "legacy_exact_public_catalog",
                    "passed": status == 200 and names == PUBLIC_NAMES,
                    "status": status,
                    "tool_count": len(names),
                }
            )
            modern_meta = {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            }
            modern_list = {
                "jsonrpc": "2.0",
                "id": "modern-list",
                "method": "tools/list",
                "params": {"_meta": modern_meta},
            }
            modern_headers = {
                **auth,
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/list",
            }
            status, _, modern = json_request(
                gateway.port,
                "POST",
                "/mcp",
                modern_list,
                headers=modern_headers,
            )
            checks.append(
                {
                    "name": "modern_mcp_shape_and_mirror_headers",
                    "passed": status == 200
                    and modern.get("result", {}).get("resultType") == "complete"
                    and modern.get("result", {}).get("ttlMs") == 0
                    and len(modern.get("result", {}).get("tools", [])) == 24,
                    "status": status,
                }
            )
            public_call = {
                "jsonrpc": "2.0",
                "id": "public-call",
                "method": "tools/call",
                "params": {"name": "server_info", "arguments": {}},
            }
            status, _, public = json_request(
                gateway.port, "POST", "/mcp", public_call, headers=auth
            )
            hidden_call = {
                "jsonrpc": "2.0",
                "id": "hidden-call",
                "method": "tools/call",
                "params": {
                    "name": "rethlas_status",
                    "arguments": {"run_id": "run-target"},
                },
            }
            hidden_status, _, hidden = json_request(
                gateway.port, "POST", "/mcp", hidden_call, headers=auth
            )
            checks.append(
                {
                    "name": "public_and_hidden_dispatch_boundary",
                    "passed": status == 200
                    and hidden_status == 200
                    and public.get("result", {})
                    .get("structuredContent", {})
                    .get("tool")
                    == "server_info"
                    and hidden.get("result", {})
                    .get("structuredContent", {})
                    .get("tool")
                    == "rethlas_status"
                    and "rethlas_status" not in names,
                }
            )
            denied_status, _, denied = json_request(
                gateway.port,
                "POST",
                "/mcp",
                ping,
                headers={**auth, "Origin": "https://attacker.example"},
            )
            allowed_status, allowed_headers, _ = json_request(
                gateway.port,
                "POST",
                "/mcp",
                ping,
                headers={**auth, "Origin": "https://allowed.example"},
            )
            checks.append(
                {
                    "name": "mcp_origin_gate_and_cors",
                    "passed": denied_status == 403
                    and denied.get("error", {}).get("code") == "ORIGIN_DENIED"
                    and allowed_status == 200
                    and allowed_headers.get("access-control-allow-origin")
                    == "https://allowed.example",
                }
            )
            unknown = {
                "jsonrpc": "2.0",
                "id": "unknown",
                "method": "future/method",
                "params": {"_meta": modern_meta},
            }
            unknown_status, _, unknown_result = json_request(
                gateway.port,
                "POST",
                "/mcp",
                unknown,
                headers={
                    **auth,
                    "MCP-Protocol-Version": "2026-07-28",
                    "Mcp-Method": "future/method",
                },
            )
            mismatch_status, _, mismatch = json_request(
                gateway.port,
                "POST",
                "/mcp",
                modern_list,
                headers={
                    **auth,
                    "MCP-Protocol-Version": "2026-07-28",
                    "Mcp-Method": "ping",
                },
            )
            duplicate_status, duplicate = duplicate_header_request(
                gateway.port, token, modern_list
            )
            checks.append(
                {
                    "name": "modern_http_error_statuses_and_duplicate_headers",
                    "passed": unknown_status == 404
                    and unknown_result.get("error", {}).get("code") == -32601
                    and mismatch_status == 400
                    and mismatch.get("error", {}).get("code") == -32020
                    and duplicate_status == 400
                    and duplicate.get("error", {}).get("code") == -32020,
                }
            )
        finally:
            callback_server.shutdown()
            callback_server.server_close()
            callback_thread.join(timeout=2)
            primary_close = gateway.close()
        checks.append(
            {
                "name": "gateway_owned_process_shutdown",
                "passed": primary_close["exit_code"] in {-15, 0}
                and primary_close["stderr_empty"],
                "exit_code": primary_close["exit_code"],
            }
        )

        fixed = GatewayProcess(
            root=root,
            catalog=catalog,
            port=free_port(),
            server_url="https://fixed.example",
        )
        try:
            fixed_status, _, fixed_raw = request(
                fixed.port,
                "GET",
                "/.well-known/oauth-authorization-server",
                headers={
                    "X-Forwarded-Proto": "https",
                    "X-Forwarded-Host": "attacker.example",
                },
            )
            fixed_metadata = json.loads(fixed_raw)
            checks.append(
                {
                    "name": "fixed_origin_ignores_forwarded_attacker",
                    "passed": fixed_status == 200
                    and fixed_metadata.get("issuer") == "https://fixed.example",
                    "status": fixed_status,
                }
            )
        finally:
            fixed_close = fixed.close()
        checks.append(
            {
                "name": "fixed_gateway_shutdown",
                "passed": fixed_close["exit_code"] in {-15, 0}
                and fixed_close["stderr_empty"],
                "exit_code": fixed_close["exit_code"],
            }
        )

    passed = all(check.get("passed") is True for check in checks)
    payload = {
        "schema_version": "1.0.0",
        "project": "MTM-reboot",
        "milestone": "MTM-005",
        "implementation_sha256": implementation_sha256(),
        "environment": {
            "platform": os.uname().sysname,
            "release": os.uname().release,
            "machine": os.uname().machine,
            "browser": Path(firefox).name if firefox else None,
        },
        "passed": passed,
        "check_count": len(checks),
        "checks": checks,
        "sensitive_content_omitted": True,
        "claim": (
            "This report validates the current Linux target's real Rust HTTP gateway, "
            "Firefox-rendered authorization page and browser form submission, DCR/PKCE/code "
            "exchange, single-use codes, OAuth challenge metadata, exact 24-tool catalog, "
            "hidden alias dispatch, legacy/modern MCP, mirror headers, CORS/origin gates, "
            "dynamic/fixed issuer behavior and owned-process shutdown. It omits passwords, "
            "client identifiers, client secrets, authorization codes, access tokens, tool "
            "arguments/results and OAuth database rows. Workflow and finalizer semantics remain "
            "MTM-006."
        ),
    }
    temporary = REPORT.with_name(REPORT.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(REPORT)
    print(json.dumps({"ok": passed, "report": str(REPORT)}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
