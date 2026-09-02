#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import resource
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE_BASELINE = ROOT / "source-baseline.json"
GOLDEN_HASH = ROOT / "conformance" / "golden" / "mtm005-reference.sha256"
CARGO_HOME = ROOT / ".toolchain" / "cargo"
RUSTUP_HOME = ROOT / ".toolchain" / "rustup"
RUST_SHADOW = ROOT / "target" / "debug" / "mtm-gateway-shadow"
MAX_ELAPSED_SECONDS = 30.0
MAX_RSS_KIB = 131_072
SAMPLES = 7
BASE_URL = "https://re-ctm.example.test"
NOW_UNIX = 1_788_270_000
NOW_ISO = "2026-09-01T03:00:00Z"
TOKEN_SECRET = b"o" * 32


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def normalize_release_branding(value: Any) -> Any:
    """Canonicalize intentional product identity/version divergence across releases."""
    if isinstance(value, list):
        return [normalize_release_branding(item) for item in value]
    if isinstance(value, dict):
        name = value.get("name")
        server = value.get("server")
        title = value.get("title")
        product_identity = (
            (isinstance(name, str) and name in {"re-ctm", "mtm"})
            or (isinstance(server, str) and server in {"re-ctm", "mtm"})
        ) and isinstance(title, str) and title in {"Re-CTM", "MTM"}
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if key in {"name", "service", "server"} and item == "re-ctm":
                normalized[key] = "mtm"
            elif key == "title" and item == "Re-CTM":
                normalized[key] = "MTM"
            elif key == "version" and product_identity:
                normalized[key] = "<PRODUCT_VERSION>"
            else:
                normalized[key] = normalize_release_branding(item)
        return normalized
    return value


def source_facts() -> tuple[Path, str, list[str]]:
    baseline = json.loads(SOURCE_BASELINE.read_text(encoding="utf-8"))
    source = (ROOT / baseline["source_path"]).resolve()
    commit = str(baseline["source_commit"])
    files = [str(item) for item in baseline["reference_files"]]
    actual = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    if actual != commit:
        raise RuntimeError(f"source baseline commit drift: expected {commit}, got {actual}")
    for mode in ([], ["--cached"]):
        completed = subprocess.run(
            ["git", "diff", "--quiet", *mode, commit, "--", *files],
            cwd=source,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("source reference files are dirty relative to the frozen commit")
    return source, commit, files


def cargo_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["CARGO_HOME"] = str(CARGO_HOME)
    environment["RUSTUP_HOME"] = str(RUSTUP_HOME)
    environment["PATH"] = str(CARGO_HOME / "bin") + os.pathsep + environment.get("PATH", "")
    return environment


def build_binary() -> None:
    subprocess.run(
        [
            str(CARGO_HOME / "bin" / "cargo"),
            "build",
            "-q",
            "-p",
            "mtm-gateway",
            "--features",
            "shadow-fixture",
            "--bin",
            "mtm-gateway-shadow",
        ],
        cwd=ROOT,
        env=cargo_environment(),
        check=True,
    )


def source_catalog(source: Path) -> dict[str, Any]:
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
    environment["PYTHONPATH"] = str(source / "src")
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=environment,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return json.loads(completed.stdout)


class Driver:
    def __init__(self, command: list[str], environment: dict[str, str]) -> None:
        self.process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )

    def request(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError("shadow process pipes are unavailable")
        encoded = canonical({"operation": operation, "payload": payload})
        self.process.stdin.write(encoded + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            stderr = self.process.stderr.read() if self.process.stderr is not None else ""
            raise RuntimeError(f"shadow process exited early: {stderr[-4000:]}")
        return json.loads(line)

    def max_rss_kib(self) -> int:
        status = Path(f"/proc/{self.process.pid}/status")
        if not status.is_file():
            return 0
        values: dict[str, int] = {}
        for line in status.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith(("VmRSS:", "VmHWM:")):
                key, raw = line.split(":", 1)
                values[key] = int(raw.strip().split()[0])
        return values.get("VmHWM", values.get("VmRSS", 0))

    def close(self) -> tuple[int, str]:
        if self.process.stdin is not None:
            self.process.stdin.close()
        try:
            code = self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                code = self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                code = self.process.wait(timeout=2)
        stderr = self.process.stderr.read() if self.process.stderr is not None else ""
        return code, stderr[-4000:]


def deterministic_ids() -> list[str]:
    return [
        "client-public-fixed-000000000001",
        "code-public-fixed-000000000000000000000001",
        "client-basic-fixed-000000000002",
        "secret-basic-fixed-000000000000000000000002",
        "code-basic-fixed-000000000000000000000002",
        "client-post-fixed-0000000000003",
        "secret-post-fixed-0000000000000000000000003",
        "code-post-fixed-0000000000000000000000003",
    ]


def challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def auth_params(client_id: str, redirect_uri: str, verifier: str, state: str) -> dict[str, str]:
    return {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "code_challenge": challenge(verifier),
        "code_challenge_method": "S256",
        "resource": BASE_URL,
        "state": state,
    }


def extract_code(redirect: str) -> str:
    return urllib.parse.parse_qs(urllib.parse.urlsplit(redirect).query)["code"][0]


def run_scenario(
    command: list[str],
    environment: dict[str, str],
    database: Path,
    catalog: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    driver = Driver(command, environment)
    started = time.perf_counter()
    records: list[dict[str, Any]] = []

    def step(name: str, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = driver.request(operation, payload)
        records.append({"name": name, "operation": operation, "response": response})
        return response

    init = step(
        "init",
        "init",
        {
            "database": str(database),
            "server_url": BASE_URL,
            "password": "operator-password",
            "token_secret_b64": base64.b64encode(TOKEN_SECRET).decode(),
            "now_unix": NOW_UNIX,
            "now_iso": NOW_ISO,
            "token_ttl": 86_400,
            "ids": deterministic_ids(),
            "catalog": catalog,
        },
    )
    if init.get("ok") is not True:
        raise RuntimeError(f"shadow initialization failed: {init}")
    step("authorization_metadata", "authorization_server_metadata", {})
    step("protected_metadata", "protected_resource_metadata", {})
    step(
        "registration_invalid_redirect",
        "register",
        {
            "metadata": {"redirect_uris": ["http://example.com/callback"]},
            "trace_id": "trace-register-invalid",
        },
    )
    redirect_public = "http://127.0.0.1/callback"
    public_registration = step(
        "registration_public_none",
        "register",
        {
            "metadata": {
                "redirect_uris": [redirect_public, "http://localhost/callback"],
                "token_endpoint_auth_method": "none",
                "client_name": "Public Client",
            },
            "trace_id": "trace-register-public",
        },
    )["result"]
    public_params = auth_params(
        public_registration["client_id"], redirect_public, "A" * 43, "public-state"
    )
    step(
        "validate_public_authorization",
        "validate_authorization_request",
        {"params": public_params},
    )
    step(
        "wrong_operator_password",
        "authorize",
        {
            "params": public_params,
            "password": "wrong",
            "trace_id": "trace-auth-denied",
        },
    )
    public_redirect = step(
        "authorize_public",
        "authorize",
        {
            "params": public_params,
            "password": "operator-password",
            "trace_id": "trace-auth-public",
        },
    )["result"]
    public_code = extract_code(public_redirect)
    public_exchange = {
        "grant_type": "authorization_code",
        "code": public_code,
        "redirect_uri": redirect_public,
        "code_verifier": "A" * 43,
        "client_id": public_registration["client_id"],
        "resource": BASE_URL,
    }
    public_token = step(
        "exchange_public",
        "exchange_code",
        {"params": public_exchange, "trace_id": "trace-token-public"},
    )["result"]["access_token"]
    step(
        "validate_public_token",
        "validate_last_token",
        {"trace_id": "trace-validate-public"},
    )
    step("decode_public_token", "decode_last_token", {})
    step(
        "reuse_public_code",
        "exchange_code",
        {"params": public_exchange, "trace_id": "trace-token-reuse"},
    )
    step(
        "set_tampered_token",
        "set_last_token",
        {"token": public_token[:-1] + ("A" if public_token[-1] != "A" else "B")},
    )
    step(
        "reject_tampered_token",
        "validate_last_token",
        {"trace_id": "trace-validate-tampered"},
    )
    step("restore_public_token", "set_last_token", {"token": public_token})

    redirect_basic = "http://127.0.0.1/basic"
    basic_registration = step(
        "registration_basic",
        "register",
        {
            "metadata": {
                "redirect_uris": [redirect_basic],
                "token_endpoint_auth_method": "client_secret_basic",
                "client_name": "Basic Client",
            },
            "trace_id": "trace-register-basic",
        },
    )["result"]
    basic_params = auth_params(
        basic_registration["client_id"], redirect_basic, "B" * 43, "basic-state"
    )
    basic_code = extract_code(
        step(
            "authorize_basic",
            "authorize",
            {
                "params": basic_params,
                "password": "operator-password",
                "trace_id": "trace-auth-basic",
            },
        )["result"]
    )
    step(
        "exchange_basic",
        "exchange_code",
        {
            "params": {
                "grant_type": "authorization_code",
                "code": basic_code,
                "redirect_uri": redirect_basic,
                "code_verifier": "B" * 43,
                "resource": BASE_URL,
            },
            "basic_client_id": basic_registration["client_id"],
            "basic_client_secret": basic_registration["client_secret"],
            "trace_id": "trace-token-basic",
        },
    )

    redirect_post = "http://127.0.0.1/post"
    post_registration = step(
        "registration_post",
        "register",
        {
            "metadata": {
                "redirect_uris": [redirect_post],
                "token_endpoint_auth_method": "client_secret_post",
                "client_name": "Post Client",
            },
            "trace_id": "trace-register-post",
        },
    )["result"]
    post_params = auth_params(
        post_registration["client_id"], redirect_post, "C" * 43, "post-state"
    )
    post_code = extract_code(
        step(
            "authorize_post",
            "authorize",
            {
                "params": post_params,
                "password": "operator-password",
                "trace_id": "trace-auth-post",
            },
        )["result"]
    )
    step(
        "exchange_post",
        "exchange_code",
        {
            "params": {
                "grant_type": "authorization_code",
                "code": post_code,
                "redirect_uri": redirect_post,
                "code_verifier": "C" * 43,
                "client_id": post_registration["client_id"],
                "client_secret": post_registration["client_secret"],
                "resource": BASE_URL,
            },
            "trace_id": "trace-token-post",
        },
    )
    step("oauth_physical_snapshot", "oauth_snapshot", {})

    principal = {
        "client_id": public_registration["client_id"],
        "subject": public_registration["client_id"],
        "scope": "mcp",
    }

    def rpc(name: str, request: dict[str, Any], transport: str | None = None) -> None:
        payload: dict[str, Any] = {
            "request": request,
            "principal": principal,
            "trace_id": f"trace-{name}",
        }
        if transport is not None:
            payload["transport_protocol_version"] = transport
        step(name, "mcp_dispatch", payload)

    rpc(
        "legacy_initialize_modern_requested",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2026-07-28"},
        },
    )
    rpc("legacy_ping", {"jsonrpc": "2.0", "id": 2, "method": "ping"})
    rpc(
        "legacy_tools_list",
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
    )
    modern_meta = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "Conformance", "version": "1"},
    }
    modern_list = {
        "jsonrpc": "2.0",
        "id": "modern-list",
        "method": "tools/list",
        "params": {"_meta": modern_meta},
    }
    rpc("modern_tools_list", modern_list, "2026-07-28")
    rpc(
        "modern_discover",
        {
            "jsonrpc": "2.0",
            "id": "discover",
            "method": "server/discover",
            "params": {"_meta": modern_meta},
        },
        "2026-07-28",
    )
    rpc(
        "public_tool_call",
        {
            "jsonrpc": "2.0",
            "id": "call-public",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "example.txt"}},
        },
    )
    rpc(
        "hidden_alias_call",
        {
            "jsonrpc": "2.0",
            "id": "call-hidden",
            "method": "tools/call",
            "params": {"name": "rethlas_status", "arguments": {"run_id": "run-1"}},
        },
    )
    rpc(
        "invalid_tool_arguments",
        {
            "jsonrpc": "2.0",
            "id": "invalid-args",
            "method": "tools/call",
            "params": {"name": "exec_command", "arguments": {}},
        },
    )
    rpc(
        "unknown_tool",
        {
            "jsonrpc": "2.0",
            "id": "unknown-tool",
            "method": "tools/call",
            "params": {"name": "not_a_tool", "arguments": {}},
        },
    )
    rpc(
        "unknown_legacy_method",
        {"jsonrpc": "2.0", "id": "unknown-method", "method": "future/method", "params": {}},
    )
    rpc(
        "unknown_modern_method",
        {
            "jsonrpc": "2.0",
            "id": "unknown-modern",
            "method": "future/method",
            "params": {"_meta": modern_meta},
        },
        "2026-07-28",
    )
    rpc(
        "notification_ping",
        {"jsonrpc": "2.0", "method": "ping", "params": {}},
    )
    rpc(
        "invalid_rpc_id",
        {"jsonrpc": "2.0", "id": True, "method": "ping", "params": {}},
    )

    step(
        "mirror_modern_list_valid",
        "mirror_validate",
        {
            "request": modern_list,
            "version_header": "2026-07-28",
            "method_header": "tools/list",
        },
    )
    step(
        "mirror_modern_list_missing_version",
        "mirror_validate",
        {"request": modern_list, "method_header": "tools/list"},
    )
    modern_call = {
        "jsonrpc": "2.0",
        "id": "modern-call",
        "method": "tools/call",
        "params": {
            "name": "server_info",
            "arguments": {},
            "_meta": modern_meta,
        },
    }
    step(
        "mirror_modern_call_valid",
        "mirror_validate",
        {
            "request": modern_call,
            "version_header": "2026-07-28",
            "method_header": "tools/call",
            "name_header": "server_info",
        },
    )
    encoded_name = "=?base64?" + base64.b64encode(b"server_info").decode() + "?="
    step(
        "mirror_base64_name_valid",
        "mirror_validate",
        {
            "request": modern_call,
            "version_header": "2026-07-28",
            "method_header": "tools/call",
            "name_header": encoded_name,
        },
    )
    step("mirror_decode", "mirror_decode", {"value": encoded_name})
    step(
        "modern_http_status_unknown_method",
        "modern_http_status",
        {
            "request": {"jsonrpc": "2.0", "id": 1, "method": "x", "params": {"_meta": modern_meta}},
            "response": {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "x"}},
        },
    )
    step("catalog_public", "catalog_public", {})
    step("events", "events", {})
    step("calls", "calls", {})

    max_rss = driver.max_rss_kib()
    code, stderr = driver.close()
    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    return records, {
        "elapsed_ms": elapsed_ms,
        "max_rss_kib": max_rss,
        "exit_code": code,
        "stderr_tail": stderr,
        "record_count": len(records),
        "response_bytes": len(canonical(records).encode("utf-8")),
    }


def environment_for_python(source: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(source / "src")
    return environment


def git_status() -> str:
    return subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout


def percentile_95(samples: list[float]) -> float:
    ordered = sorted(samples)
    index = max(0, min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1)))))
    return ordered[index]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--print-golden", action="store_true")
    args = parser.parse_args(argv)

    source, commit, reference_files = source_facts()
    build_binary()
    catalog = source_catalog(source)
    before_status = git_status()
    python_command = [sys.executable, "conformance/python_gateway_shadow.py"]
    rust_command = [str(RUST_SHADOW)]
    python_samples: list[dict[str, Any]] = []
    rust_samples: list[dict[str, Any]] = []
    reference_records: list[dict[str, Any]] | None = None
    rust_records: list[dict[str, Any]] | None = None
    with tempfile.TemporaryDirectory(prefix="mtm005-conformance-") as directory:
        root = Path(directory)
        for index in range(SAMPLES):
            python_run, python_resource = run_scenario(
                python_command,
                environment_for_python(source),
                root / f"python-{index}.sqlite3",
                catalog,
            )
            rust_run, rust_resource = run_scenario(
                rust_command,
                cargo_environment(),
                root / f"rust-{index}.sqlite3",
                catalog,
            )
            python_samples.append(python_resource)
            rust_samples.append(rust_resource)
            if reference_records is None:
                reference_records = python_run
                rust_records = rust_run
            elif python_run != reference_records or rust_run != rust_records:
                raise RuntimeError("MTM-005 conformance scenario is not deterministic")
    after_status = git_status()
    assert reference_records is not None and rust_records is not None
    mismatches = []
    for expected, actual in zip(reference_records, rust_records, strict=True):
        if normalize_release_branding(expected) != normalize_release_branding(actual):
            mismatches.append(
                {
                    "name": expected.get("name"),
                    "python": expected,
                    "rust": actual,
                }
            )
    if len(reference_records) != len(rust_records):
        mismatches.append(
            {
                "name": "record_count",
                "python": len(reference_records),
                "rust": len(rust_records),
            }
        )
    reference_hash = hashlib.sha256(canonical(reference_records).encode("utf-8")).hexdigest()
    recorded_hash = GOLDEN_HASH.read_text(encoding="utf-8").strip() if GOLDEN_HASH.exists() else ""
    golden_match = args.print_golden or reference_hash == recorded_hash

    def resources(samples: list[dict[str, Any]]) -> dict[str, Any]:
        elapsed = [float(item["elapsed_ms"]) for item in samples]
        rss = [int(item["max_rss_kib"]) for item in samples]
        return {
            "samples": len(samples),
            "elapsed_ms_median": round(statistics.median(elapsed), 3),
            "elapsed_ms_p95": round(percentile_95(elapsed), 3),
            "max_rss_kib": max(rss),
            "record_count": samples[0]["record_count"],
            "response_bytes": samples[0]["response_bytes"],
        }

    python_resources = resources(python_samples)
    rust_resources = resources(rust_samples)
    resource_ok = (
        python_resources["elapsed_ms_p95"] <= MAX_ELAPSED_SECONDS * 1000
        and rust_resources["elapsed_ms_p95"] <= MAX_ELAPSED_SECONDS * 1000
        and python_resources["max_rss_kib"] <= MAX_RSS_KIB
        and rust_resources["max_rss_kib"] <= MAX_RSS_KIB
        and rust_resources["elapsed_ms_p95"]
        <= max(float(python_resources["elapsed_ms_p95"]) * 3.0, 3_000.0)
        and rust_resources["max_rss_kib"]
        <= max(int(python_resources["max_rss_kib"]) * 2, 65_536)
    )
    summary = {
        "ok": not mismatches and golden_match and resource_ok and before_status == after_status,
        "source_commit": commit,
        "source_reference_file_count": len(reference_files),
        "source_reference_files_clean": True,
        "record_count": len(reference_records),
        "public_tool_count": len(catalog["public_names"]),
        "hidden_tool_count": len(catalog["hidden_names"]),
        "public_catalog_sha256": hashlib.sha256(
            canonical([catalog["definitions"][name] for name in catalog["public_names"]]).encode("utf-8")
        ).hexdigest(),
        "all_tool_definitions_sha256": hashlib.sha256(
            canonical(catalog["definitions"]).encode("utf-8")
        ).hexdigest(),
        "reference_sha256": reference_hash,
        "recorded_sha256": recorded_hash or None,
        "golden_match": golden_match,
        "release_branding_normalization": "re-ctm/Re-CTM identity plus product release version",
        "differential_mismatch_count": len(mismatches),
        "mismatches": mismatches[:20],
        "resources": {
            "python_reference": python_resources,
            "rust_shadow": rust_resources,
            "limits": {
                "elapsed_seconds": MAX_ELAPSED_SECONDS,
                "max_rss_kib": MAX_RSS_KIB,
            },
        },
        "resource_gate_passed": resource_ok,
        "shadow_side_effect_free": before_status == after_status,
        "authority": {
            "source_reference": "python",
            "rust_mode": "oauth_mcp_gateway_shadow",
            "deployed_traffic_authority": "python",
        },
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
