#!/usr/bin/env python3
from __future__ import annotations

import http.server
import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-003/target-validation.json"
CARGO_HOME = ROOT / ".toolchain" / "cargo"
RUSTUP_HOME = ROOT / ".toolchain" / "rustup"
HELPER = ROOT / "target" / "debug" / "mtm-native-helper"
SHADOW = ROOT / "target" / "debug" / "mtm-native-shadow"
SOURCE_HELPER = (ROOT / "../Re-CTM/src/re_ctm/native_helper_bwrap.py").resolve()


def implementation_sha256() -> str:
    digest = hashlib.sha256()
    roots = [
        ROOT / "Cargo.toml",
        ROOT / "Cargo.lock",
        ROOT / "rust-toolchain.toml",
        ROOT / "crates" / "mtm-contracts",
        ROOT / "crates" / "mtm-core",
        ROOT / "crates" / "mtm-native",
    ]
    files: list[Path] = []
    for root in roots:
        if root.is_file():
            files.append(root)
        elif root.is_dir():
            files.extend(path for path in root.rglob("*") if path.is_file())
    for path in sorted(files):
        relative = path.relative_to(ROOT).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        content = path.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


class ShadowDriver:
    def __init__(self) -> None:
        self.process = subprocess.Popen(
            [str(SHADOW)],
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=minimal_environment(),
        )

    def request(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError("shadow driver pipes unavailable")
        request = json.dumps(
            {"operation": operation, "payload": payload},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        self.process.stdin.write(request + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            stderr = self.process.stderr.read() if self.process.stderr is not None else ""
            raise RuntimeError(f"shadow driver exited early: {stderr}")
        return json.loads(line)

    def result(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self.request(operation, payload)
        if response.get("ok") is not True or not isinstance(response.get("result"), dict):
            raise RuntimeError(f"shadow operation failed: {operation}: {response}")
        return response["result"]

    def close(self) -> None:
        try:
            if self.process.poll() is None:
                try:
                    self.result("tunnel_close", {})
                except Exception:
                    pass
                try:
                    self.result("process_close", {})
                except Exception:
                    pass
            if self.process.stdin is not None:
                self.process.stdin.close()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
        finally:
            if self.process.stderr is not None:
                _ = self.process.stderr.read()


def minimal_environment() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/nonexistent"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "CARGO_HOME": str(CARGO_HOME),
        "RUSTUP_HOME": str(RUSTUP_HOME),
    }


def build_binaries() -> None:
    environment = minimal_environment()
    environment["PATH"] = str(CARGO_HOME / "bin") + os.pathsep + environment["PATH"]
    subprocess.run(
        [str(CARGO_HOME / "bin" / "cargo"), "build", "-q", "-p", "mtm-native", "--bins"],
        cwd=ROOT,
        env=environment,
        check=True,
    )


def helper_request(request: dict[str, Any]) -> tuple[int, dict[str, Any], str]:
    completed = subprocess.run(
        [str(HELPER)],
        cwd=ROOT,
        input=json.dumps(request, ensure_ascii=False),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=minimal_environment(),
        check=False,
        timeout=max(30, int(request.get("timeout_ms", 30_000)) // 1000 + 10),
    )
    payload = json.loads(completed.stdout)
    return completed.returncode, payload, completed.stderr


def python_helper_request(request: dict[str, Any]) -> tuple[int, dict[str, Any], str]:
    completed = subprocess.run(
        ["/usr/bin/python3", str(SOURCE_HELPER)],
        cwd=ROOT,
        input=json.dumps(request, ensure_ascii=False),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=minimal_environment(),
        check=False,
        timeout=max(30, int(request.get("timeout_ms", 30_000)) // 1000 + 10),
    )
    payload = json.loads(completed.stdout)
    return completed.returncode, payload, completed.stderr


def helper_payload(
    operation: str,
    request_id: str,
    workspace: Path,
    data: Path,
    private: Path,
    *,
    mode: str,
    host_path: str,
    read_roots: list[str],
    argv: list[str] | None = None,
    timeout_ms: int = 30_000,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "protocol": "re-ctm-native-helper-v1",
        "operation": operation,
        "request_id": request_id,
        "workspace": str(workspace),
        "forbidden_paths": [str(data), str(private)],
        "mode": mode,
        "host_path": host_path,
        "extra_read_roots": read_roots,
    }
    if argv is not None:
        payload.update({"argv": argv, "workdir": ".", "timeout_ms": timeout_ms})
    return payload


def assert_helper_success(
    checks: list[dict[str, Any]],
    name: str,
    request: dict[str, Any],
    predicate: Any,
) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        exit_code, response, stderr = helper_request(request)
        passed = exit_code == 0 and response.get("ok") is True and bool(predicate(response))
        checks.append(
            {
                "name": name,
                "passed": passed,
                "exit_code": exit_code,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                "response": redact_response(response),
                "stderr_tail": stderr[-2000:],
            }
        )
        return response
    except Exception as exc:  # noqa: BLE001 - target gate records boundary failure
        checks.append(
            {
                "name": name,
                "passed": False,
                "exit_code": 1,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
        return {}


def redact_response(response: dict[str, Any]) -> dict[str, Any]:
    result = dict(response)
    if isinstance(result.get("stdout"), str) and len(result["stdout"]) > 4000:
        result["stdout"] = result["stdout"][-4000:]
    if isinstance(result.get("stderr"), str) and len(result["stderr"]) > 4000:
        result["stderr"] = result["stderr"][-4000:]
    return result


def normalize_helper_response(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: normalize_helper_response(item)
            for key, item in value.items()
            if key != "elapsed_ms"
        }
    if isinstance(value, list):
        return [normalize_helper_response(item) for item in value]
    return value


def target_checks(root: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    workspace = root / "workspace"
    data = root / "data"
    private = data / "private"
    workspace.mkdir()
    private.mkdir(parents=True)
    (workspace / "hello.txt").write_text("workspace-ok\n", encoding="utf-8")
    canary = private / "canary.txt"
    canary.write_text("PRIVATE-CANARY\n", encoding="utf-8")

    driver = ShadowDriver()
    try:
        explicit = root / "explicit-toolchain"
        explicit_exec = explicit / "Executables"
        explicit_exec.mkdir(parents=True)
        symbolic = explicit_exec / "symbolic-kernel"
        symbolic.write_text("#!/bin/sh\nprintf 'generic-ok\\n'\n", encoding="utf-8")
        symbolic.chmod(0o755)

        explicit_plan = driver.result(
            "toolchain_plan",
            {
                "mode": "safe",
                "workspace": str(workspace),
                "forbidden_paths": [str(data), str(private)],
                "explicit_roots": [str(explicit)],
                "host_path": str(root / "not-inherited"),
            },
        )
        explicit_path = str(explicit_plan["sandbox_path"])
        explicit_roots = [str(value) for value in explicit_plan["read_only_roots"]]

        attestation = assert_helper_success(
            checks,
            "bubblewrap_attestation",
            helper_payload(
                "attest",
                "target-attest-001",
                workspace,
                data,
                private,
                mode="safe",
                host_path=explicit_path,
                read_roots=explicit_roots,
            ),
            lambda response: response.get("attestation", {}).get("hard_isolation") is True
            and response.get("attestation", {}).get("forbidden_paths_hidden") is True
            and response.get("attestation", {}).get("private_vault_mounted") is False
            and response.get("attestation", {}).get("network_isolated") is True
            and response.get("attestation", {}).get("toolchain_read_only_root_count") == 1,
        )

        assert_helper_success(
            checks,
            "safe_workspace_read",
            helper_payload(
                "execute",
                "target-safe-cat-001",
                workspace,
                data,
                private,
                mode="safe",
                host_path=explicit_path,
                read_roots=explicit_roots,
                argv=["/bin/cat", "hello.txt"],
            ),
            lambda response: response.get("exit_code") == 0
            and response.get("stdout") == "workspace-ok\n"
            and response.get("attestation", {}).get("network_isolated") is True,
        )

        assert_helper_success(
            checks,
            "private_vault_and_parent_env_denial",
            helper_payload(
                "execute",
                "target-private-denial-001",
                workspace,
                data,
                private,
                mode="dangerous",
                host_path=explicit_path,
                read_roots=explicit_roots,
                argv=[
                    "/usr/bin/python3",
                    "-c",
                    (
                        "import os,sys; "
                        "print(os.path.exists(sys.argv[1])); "
                        "print(os.environ.get('MTM_PARENT_SECRET','missing'))"
                    ),
                    str(canary),
                ],
            ),
            lambda response: response.get("exit_code") == 0
            and str(response.get("stdout", "")).splitlines() == ["False", "missing"]
            and response.get("attestation", {}).get("private_vault_mounted") is False,
        )

        assert_helper_success(
            checks,
            "explicit_generic_toolchain_execution",
            helper_payload(
                "execute",
                "target-explicit-tool-001",
                workspace,
                data,
                private,
                mode="safe",
                host_path=explicit_path,
                read_roots=explicit_roots,
                argv=["symbolic-kernel"],
            ),
            lambda response: response.get("exit_code") == 0
            and response.get("stdout") == "generic-ok\n",
        )

        denied_target = explicit / "must-remain-read-only"
        assert_helper_success(
            checks,
            "toolchain_mount_read_only",
            helper_payload(
                "execute",
                "target-read-only-001",
                workspace,
                data,
                private,
                mode="dangerous",
                host_path=explicit_path,
                read_roots=explicit_roots,
                argv=["/bin/sh", "-c", f"printf no > {denied_target}"],
            ),
            lambda response: response.get("exit_code") not in {None, 0}
            and not denied_target.exists(),
        )

        dangerous_plan = driver.result(
            "toolchain_plan",
            {
                "mode": "dangerous",
                "workspace": str(workspace),
                "forbidden_paths": [str(data), str(private)],
                "explicit_roots": [],
                "host_path": os.environ.get("PATH", ""),
            },
        )
        dangerous_path = str(dangerous_plan["sandbox_path"])
        dangerous_roots = [str(value) for value in dangerous_plan["read_only_roots"]]
        checks.append(
            {
                "name": "toolchain_plan_discovers_target_cas",
                "passed": any("miniconda3" in root for root in dangerous_roots)
                and any("magma" in root.lower() or ".local" in root for root in dangerous_roots),
                "exit_code": 0,
                "read_only_root_count": len(dangerous_roots),
                "root_fingerprints_only": [fingerprint(root) for root in dangerous_roots],
            }
        )

        assert_helper_success(
            checks,
            "dangerous_plan_attestation",
            helper_payload(
                "attest",
                "target-dangerous-plan-attest-001",
                workspace,
                data,
                private,
                mode="safe",
                host_path=dangerous_path,
                read_roots=dangerous_roots,
            ),
            lambda response: response.get("attestation", {}).get(
                "toolchain_read_only_root_count"
            )
            == len(dangerous_roots),
        )

        assert_helper_success(
            checks,
            "sagemath_execution",
            helper_payload(
                "execute",
                "target-sage-001",
                workspace,
                data,
                private,
                mode="dangerous",
                host_path=dangerous_path,
                read_roots=dangerous_roots,
                argv=["sage", "-c", "print(2+3)"],
                timeout_ms=120_000,
            ),
            lambda response: response.get("exit_code") == 0
            and "5" in str(response.get("stdout", "")).split(),
        )

        assert_helper_success(
            checks,
            "magma_execution",
            helper_payload(
                "execute",
                "target-magma-001",
                workspace,
                data,
                private,
                mode="dangerous",
                host_path=dangerous_path,
                read_roots=dangerous_roots,
                argv=["/bin/sh", "-c", "printf '2+3;\\nquit;\\n' | magma -b"],
                timeout_ms=120_000,
            ),
            lambda response: response.get("exit_code") == 0
            and "5" in str(response.get("stdout", "")).split(),
        )

        timeout_response = assert_helper_success(
            checks,
            "helper_timeout_provenance",
            helper_payload(
                "execute",
                "target-timeout-001",
                workspace,
                data,
                private,
                mode="dangerous",
                host_path=dangerous_path,
                read_roots=dangerous_roots,
                argv=["/bin/sh", "-c", "sleep 2"],
                timeout_ms=120,
            ),
            lambda response: response.get("status") == "timeout"
            and response.get("timed_out") is True,
        )

        helper_parity_requests = [
            helper_payload(
                "attest",
                "target-parity-attest-001",
                workspace,
                data,
                private,
                mode="safe",
                host_path=explicit_path,
                read_roots=explicit_roots,
            ),
            helper_payload(
                "execute",
                "target-parity-execute-001",
                workspace,
                data,
                private,
                mode="safe",
                host_path=explicit_path,
                read_roots=explicit_roots,
                argv=["/bin/cat", "hello.txt"],
            ),
            helper_payload(
                "execute",
                "target-parity-timeout-001",
                workspace,
                data,
                private,
                mode="dangerous",
                host_path=explicit_path,
                read_roots=explicit_roots,
                argv=["/bin/sh", "-c", "sleep 2"],
                timeout_ms=120,
            ),
        ]
        parity_mismatches = []
        for request in helper_parity_requests:
            rust_exit, rust_response, rust_stderr = helper_request(request)
            python_exit, python_response, python_stderr = python_helper_request(request)
            normalized_rust = normalize_helper_response(rust_response)
            normalized_python = normalize_helper_response(python_response)
            if rust_exit != python_exit or normalized_rust != normalized_python:
                parity_mismatches.append(
                    {
                        "operation": request["operation"],
                        "request_id": request["request_id"],
                        "python_exit": python_exit,
                        "rust_exit": rust_exit,
                        "python": normalized_python,
                        "rust": normalized_rust,
                        "python_stderr_tail": python_stderr[-1000:],
                        "rust_stderr_tail": rust_stderr[-1000:],
                    }
                )
        checks.append(
            {
                "name": "python_rust_helper_protocol_parity",
                "passed": not parity_mismatches,
                "exit_code": 0 if not parity_mismatches else 1,
                "case_count": len(helper_parity_requests),
                "mismatch_count": len(parity_mismatches),
                "mismatches": parity_mismatches,
            }
        )

        bubblewrap = driver.result(
            "bubblewrap_command",
            {
                "workspace": str(workspace),
                "workdir": ".",
                "mode": "dangerous",
                "argv": [
                    "/bin/sh",
                    "-c",
                    "printf 'ready\\n'; read value; printf 'got:%s\\n' \"$value\"",
                ],
                "extra_env": {},
                "host_path": dangerous_path,
                "extra_read_roots": dangerous_roots,
                "forbidden_paths": [str(data), str(private)],
            },
        )["command"]
        tty = driver.result(
            "process_start",
            {
                "argv": bubblewrap,
                "env": {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                "timeout_ms": 10_000,
                "yield_time_ms": 100,
                "max_output_bytes": 65_536,
                "stdin": "",
                "tty": True,
                "preview_bytes": 4096,
            },
        )
        tty_reply = driver.result(
            "process_poll",
            {
                "command_id": tty["command_id"],
                "chars": "hello-isolated-tty\n",
                "yield_time_ms": 1500,
                "max_output_bytes": 65_536,
                "preview_bytes": 4096,
            },
        )
        tty_text = (str(tty.get("stdout", "")) + str(tty_reply.get("stdout", ""))).replace(
            "\r", ""
        )
        checks.append(
            {
                "name": "isolated_tty_round_trip",
                "passed": "ready" in tty_text and "got:hello-isolated-tty" in tty_text,
                "exit_code": tty_reply.get("exit_code"),
                "status": tty_reply.get("status"),
                "output_tail": tty_text[-1000:],
            }
        )

        long_running = driver.result(
            "process_start",
            {
                "argv": driver.result(
                    "bubblewrap_command",
                    {
                        "workspace": str(workspace),
                        "workdir": ".",
                        "mode": "dangerous",
                        "argv": ["/bin/sh", "-c", "printf 'started\\n'; sleep 20"],
                        "extra_env": {},
                        "host_path": dangerous_path,
                        "extra_read_roots": dangerous_roots,
                        "forbidden_paths": [str(data), str(private)],
                    },
                )["command"],
                "env": {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                "timeout_ms": 30_000,
                "yield_time_ms": 100,
                "max_output_bytes": 65_536,
                "stdin": "",
                "tty": False,
                "preview_bytes": 4096,
            },
        )
        killed = driver.result(
            "process_kill",
            {
                "command_id": long_running["command_id"],
                "signal": "TERM",
                "wait_ms": 2000,
                "kill_wait_ms": 1000,
                "max_output_bytes": 65_536,
                "preview_bytes": 4096,
            },
        )
        checks.append(
            {
                "name": "isolated_process_group_kill",
                "passed": killed.get("status") in {"terminated", "killed", "exited"}
                and killed.get("killed") is True,
                "exit_code": killed.get("exit_code"),
                "signal": killed.get("signal"),
                "termination": killed.get("termination"),
            }
        )

        quick_tunnel_check(driver, checks)
        _ = attestation
        _ = timeout_response
    finally:
        driver.close()
    return checks


def quick_tunnel_check(driver: ShadowDriver, checks: list[dict[str, Any]]) -> None:
    cloudflared = shutil.which("cloudflared")
    if cloudflared is None:
        checks.append(
            {
                "name": "real_quick_tunnel_lifecycle",
                "passed": False,
                "exit_code": 127,
                "error": "cloudflared not found",
            }
        )
        return
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0),
        QuietHandler,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    local_origin = f"http://127.0.0.1:{port}"
    try:
        started = driver.result(
            "tunnel_start",
            {
                "executable": cloudflared,
                "local_origin": local_origin,
                "wait_ms": 500,
            },
        )
        deadline = time.monotonic() + 20
        events = list(started.get("events", []))
        while time.monotonic() < deadline and not any(
            event.get("state") == "connected" for event in events
        ):
            time.sleep(0.25)
            events = driver.result("tunnel_events", {}).get("events", [])
        public_urls = [
            str(event["public_mcp_url"])
            for event in events
            if event.get("state") == "connected" and event.get("public_mcp_url")
        ]
        active_before_close = cloudflared_processes(local_origin)
        closed = driver.result("tunnel_close", {})
        time.sleep(0.3)
        active_after_close = cloudflared_processes(local_origin)
        checks.append(
            {
                "name": "real_quick_tunnel_lifecycle",
                "passed": started.get("started") is True
                and len(public_urls) == 1
                and public_urls[0].startswith("https://")
                and public_urls[0].endswith(".trycloudflare.com/mcp")
                and bool(active_before_close)
                and not active_after_close
                and [event.get("state") for event in closed.get("events", [])].count("closed")
                == 1,
                "exit_code": 0,
                "public_url_fingerprint": fingerprint(public_urls[0]) if public_urls else None,
                "event_states": [event.get("state") for event in events],
                "owned_process_count_before_close": len(active_before_close),
                "owned_process_count_after_close": len(active_after_close),
                "close_event_states": [
                    event.get("state") for event in closed.get("events", [])
                ],
            }
        )
    except Exception as exc:  # noqa: BLE001 - record real network boundary failure
        checks.append(
            {
                "name": "real_quick_tunnel_lifecycle",
                "passed": False,
                "exit_code": 1,
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


class QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def cloudflared_processes(local_origin: str) -> list[int]:
    result = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            command = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(
                "utf-8", errors="replace"
            )
        except OSError:
            continue
        if "cloudflared" in command and local_origin in command:
            result.append(int(entry.name))
    return result


def fingerprint(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def main() -> int:
    build_binaries()
    environment = {
        "platform": os.uname().sysname,
        "release": os.uname().release,
        "machine": os.uname().machine,
        "bwrap": shutil.which("bwrap"),
        "sage": shutil.which("sage"),
        "magma": shutil.which("magma"),
        "cloudflared": shutil.which("cloudflared"),
    }
    with tempfile.TemporaryDirectory(prefix="mtm003-target-") as raw_root:
        checks = target_checks(Path(raw_root))
    payload = {
        "schema_version": "1.0.0",
        "project": "MTM-reboot",
        "milestone": "MTM-003",
        "implementation_sha256": implementation_sha256(),
        "environment": environment,
        "passed": bool(checks) and all(check.get("passed") is True for check in checks),
        "check_count": len(checks),
        "checks": checks,
        "claim": (
            "This report covers the current Linux target's real Rust Bubblewrap/helper, "
            "process/TTY/timeout/kill, SageMath, Magma, read-only toolchain, private-root, "
            "and owned Quick Tunnel boundaries. It does not validate OAuth/MCP, SQLite, "
            "workflow, verifier/finalizer, packaging, or Python retirement."
        ),
    }
    temporary = REPORT.with_name(REPORT.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(REPORT)
    print(json.dumps({"ok": payload["passed"], "report": str(REPORT)}, indent=2))
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
