#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import statistics
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

try:
    from scripts.run_mtm007_conformance import (
        CAPABILITY_SECRET,
        OPERATOR_PASSWORD,
        TOKEN_SECRET,
        free_port,
        json_request,
        oauth_token,
        prepare_workspace,
    )
except ModuleNotFoundError:
    from run_mtm007_conformance import (  # type: ignore[no-redef]
        CAPABILITY_SECRET,
        OPERATOR_PASSWORD,
        TOKEN_SECRET,
        free_port,
        json_request,
        oauth_token,
        prepare_workspace,
    )


ROOT = Path(__file__).resolve().parents[1]
RELEASE_BINARY = ROOT / "target" / "release" / "mtm-reboot"
REPORT = ROOT / "mtm007-target-validation.json"
PUBLIC_TUNNEL_RE = re.compile(r"Quick Tunnel: (https://[a-z0-9-]+\.trycloudflare\.com/mcp)")


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


def cargo() -> Path:
    return ROOT / ".toolchain" / "rustup" / "toolchains" / "1.98.0-x86_64-unknown-linux-gnu" / "bin" / "cargo"


def implementation_files() -> list[Path]:
    files = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "rust-toolchain.toml", Path(__file__)]
    for crate in sorted((ROOT / "crates").iterdir()):
        manifest = crate / "Cargo.toml"
        if manifest.is_file():
            files.append(manifest)
        files.extend(sorted((crate / "src").rglob("*.rs")) if (crate / "src").is_dir() else [])
        files.extend(sorted((crate / "assets").rglob("*")) if (crate / "assets").is_dir() else [])
    return [path for path in files if path.is_file()]


def implementation_sha256() -> str:
    digest = hashlib.sha256()
    for path in implementation_files():
        relative = path.relative_to(ROOT) if path.is_relative_to(ROOT) else Path(path.name)
        digest.update(str(relative).encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def build_release() -> None:
    subprocess.run(
        [str(cargo()), "build", "--release", "-q", "-p", "mtm-cli"],
        cwd=ROOT,
        env=cargo_environment(),
        check=True,
    )


def runtime_environment(workspace: Path, data_root: Path, backend: str, latex_policy: str) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "RE_CTM_WORKSPACE": str(workspace),
            "RE_CTM_DATA_ROOT": str(data_root),
            "RE_CTM_PRIVATE_ROOT": str(data_root / "private"),
            "RE_CTM_DEBUG_ROOT": str(data_root / "debug"),
            "RE_CTM_NATIVE_EXEC_BACKEND": backend,
            "RE_CTM_NATIVE_MODE": "safe",
            "RE_CTM_LATEX_POLICY": latex_policy,
            "RE_CTM_OAUTH_PASSWORD": OPERATOR_PASSWORD,
            "RE_CTM_TOKEN_SECRET": TOKEN_SECRET,
            "RE_CTM_CAPABILITY_SECRET": CAPABILITY_SECRET,
            "RE_CTM_SERVER_URL": "",
            "RE_CTM_DEBUG": "0",
        }
    )
    return environment


class ReleaseServer:
    kind = "rust-release"

    def __init__(
        self,
        workspace: Path,
        data_root: Path,
        *,
        backend: str,
        latex_policy: str,
        quick_tunnel: bool = False,
    ) -> None:
        self.workspace = workspace
        self.data_root = data_root
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        command = [
            str(RELEASE_BINARY),
            "tui",
            "--host",
            "127.0.0.1",
            "--port",
            str(self.port),
            "--workspace",
            str(workspace),
            "--native-mode",
            "safe",
            "--latex-policy",
            latex_policy,
        ]
        if quick_tunnel:
            command.insert(2, "--quick-tunnel")
        self.process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=runtime_environment(workspace, data_root, backend, latex_policy),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.stderr_lines: list[str] = []
        self.stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self.stderr_thread.start()
        wait_for_port(self.port, self.process)
        self.token = oauth_token(self)

    def _read_stderr(self) -> None:
        if self.process.stderr is None:
            return
        for line in self.process.stderr:
            self.stderr_lines.append(line.rstrip("\n"))

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        status, _, payload = json_request(
            self.port,
            "POST",
            "/mcp",
            {
                "jsonrpc": "2.0",
                "id": f"target-{name}",
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            },
            headers={"Authorization": f"Bearer {self.token}"},
        )
        if status != 200:
            raise RuntimeError(f"MCP call {name} returned HTTP {status}: {payload}")
        result = payload.get("result")
        if not isinstance(result, dict):
            raise RuntimeError(f"MCP call {name} returned no result")
        return result

    def close(self) -> int:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
        try:
            code = self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            code = self.process.wait(timeout=3)
        self.stderr_thread.join(timeout=2)
        return code


def wait_for_port(port: int, process: subprocess.Popen[str]) -> None:
    import socket

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("release server exited before listening")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("release server did not become reachable")


def structured(result: dict[str, Any]) -> dict[str, Any]:
    value = result.get("structuredContent")
    if not isinstance(value, dict):
        raise RuntimeError("tool result did not contain structuredContent")
    return value


def drive_compact_workflow(server: ReleaseServer) -> dict[str, Any]:
    start_result = server.call(
        "rethlas_start",
        {"problem_tex": "Prove that $1+1=2$.", "workflow_mode": "compact"},
    )
    start = structured(start_result)
    run_id = str(start.get("run_id") or "")
    if not run_id:
        raise RuntimeError("rethlas_start did not return run_id")
    current = structured(server.call("rethlas_step", {"run_id": run_id}))

    proof = """\\documentclass{article}
\\usepackage{amsmath,amsthm}
\\newtheorem{theorem}{Theorem}
\\begin{document}
\\begin{theorem}One has $1+1=2$.\\end{theorem}
\\begin{proof}This is the standard successor arithmetic identity in the natural numbers.\\end{proof}
\\end{document}
"""
    states: list[str] = []
    for _ in range(10):
        state = str(current.get("state") or "")
        states.append(state)
        if state == "done":
            break
        task = current.get("task")
        if not isinstance(task, dict):
            raise RuntimeError(f"state {state} did not include a task")
        minimal = task.get("minimal_submission")
        if not isinstance(minimal, dict):
            raise RuntimeError(f"state {state} did not include minimal_submission")
        submission = copy.deepcopy(minimal)
        writes = submission.get("writes") or []
        if not isinstance(writes, list):
            raise RuntimeError("minimal writes is not an array")
        for write in writes:
            if not isinstance(write, dict):
                continue
            if write.get("resource") == "proof":
                write["content"] = proof
            elif write.get("resource") == "proof_manifest":
                write["content"] = {
                    "target_statement_tex": "Prove that $1+1=2$.",
                    "dependency_revision_ids": [],
                    "reference_ids": [],
                    "conditional_hypotheses": [],
                    "computational_evidence": [],
                }
        request = {
            "run_id": run_id,
            "capability": str(current.get("capability") or ""),
            "action": str(submission.get("action") or task.get("commit_action") or ""),
            "writes": writes,
            "payload": submission.get("payload") or {},
        }
        next_current = structured(server.call("rethlas_step", request))
        if state == "assemble" and next_current.get("state") == "repair":
            transitions = structured(
                server.call(
                    "rethlas_artifact",
                    {"action": "get", "run_id": run_id, "artifact": "transition_log"},
                )
            ).get("content")
            safe_latex: dict[str, Any] = {}
            if isinstance(transitions, list):
                for transition in reversed(transitions):
                    if not isinstance(transition, dict) or transition.get("reason") != "latex_gate_failed":
                        continue
                    evidence = transition.get("evidence")
                    if isinstance(evidence, dict):
                        safe_latex = {
                            key: evidence.get(key)
                            for key in (
                                "policy",
                                "static_valid",
                                "compile_attempted",
                                "compile_available",
                                "compile_passed",
                                "gate_passed",
                                "errors",
                                "warnings",
                            )
                        }
                    break
            raise RuntimeError(f"real LaTeX gate failed: {safe_latex}")
        current = next_current
    if str(current.get("state") or "") != "done":
        raise RuntimeError(f"compact workflow did not reach done: {states}")
    export_path = str(current.get("workspace_export_path") or start.get("workspace_export_path") or "")
    final_path = server.workspace / export_path
    return {
        "run_id_present": bool(run_id),
        "states": states,
        "final_exists": final_path.is_file(),
        "final_contains_document": final_path.is_file()
        and "\\documentclass{article}" in final_path.read_text(encoding="utf-8"),
        "export_relative": bool(export_path) and not Path(export_path).is_absolute(),
    }


def real_research_check(server: ReleaseServer) -> bool:
    start = structured(
        server.call(
            "rethlas_start",
            {"problem_tex": "Find one useful reference about the Pythagorean theorem.", "workflow_mode": "full"},
        )
    )
    run_id = str(start.get("run_id") or "")
    if not run_id:
        return False
    current = structured(server.call("rethlas_step", {"run_id": run_id}))
    research = server.call(
        "rethlas_retrieve",
        {
            "capability": str(current.get("capability") or ""),
            "operation": "paper_search",
            "query": "Pythagorean theorem",
            "num_results": 1,
        },
    )
    research_payload = structured(research)
    server.call(
        "rethlas_control",
        {"action": "cancel", "run_id": run_id, "reason": "target_validation_complete"},
    )
    return research.get("isError") is not True and research_payload.get("ok") is not False


def release_link_check() -> dict[str, Any]:
    completed = subprocess.run(
        ["ldd", str(RELEASE_BINARY)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=True,
    )
    return {
        "version_ok": subprocess.run(
            [str(RELEASE_BINARY), "--version"],
            stdout=subprocess.PIPE,
            text=True,
            check=True,
        ).stdout.strip()
        == "re-ctm 0.3.0",
        "python_linked": "python" in completed.stdout.lower(),
    }


def install_check(root: Path, workspace: Path, data_root: Path) -> dict[str, Any]:
    install_root = root / "install"
    subprocess.run(
        [
            str(cargo()),
            "install",
            "--path",
            "crates/mtm-cli",
            "--root",
            str(install_root),
            "--locked",
            "--force",
            "--quiet",
        ],
        cwd=ROOT,
        env=cargo_environment(),
        check=True,
    )
    binary = install_root / "bin" / "mtm-reboot"
    environment = runtime_environment(workspace, data_root, "disabled", "static_only")
    version = subprocess.run(
        [str(binary), "--version"], stdout=subprocess.PIPE, text=True, check=True
    ).stdout.strip()
    config = subprocess.run(
        [str(binary), "check-config", "--workspace", str(workspace)],
        env=environment,
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout.strip()
    parsed = json.loads(config)
    dynamic = subprocess.run(
        ["ldd", str(binary)], stdout=subprocess.PIPE, text=True, check=True
    ).stdout
    return {
        "version_ok": version == "re-ctm 0.3.0",
        "tool_count": parsed.get("tool_count"),
        "python_linked": "python" in dynamic.lower(),
    }


def wait_for_public_tunnel(server: ReleaseServer) -> str:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        for line in list(server.stderr_lines):
            match = PUBLIC_TUNNEL_RE.search(line)
            if match:
                return match.group(1)
        if server.process.poll() is not None:
            break
        time.sleep(0.1)
    return ""


def quick_tunnel_check(root: Path) -> dict[str, Any]:
    workspace = root / "tunnel-workspace"
    prepare_workspace(workspace)
    server = ReleaseServer(
        workspace,
        root / "tunnel-data",
        backend="disabled",
        latex_policy="static_only",
        quick_tunnel=True,
    )
    public_mcp = ""
    issuer_ok = False
    try:
        public_mcp = wait_for_public_tunnel(server)
        if public_mcp:
            origin = public_mcp.removesuffix("/mcp")
            metadata_url = origin + "/.well-known/oauth-authorization-server"
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                try:
                    with urllib.request.urlopen(metadata_url, timeout=5) as response:
                        metadata = json.loads(response.read())
                    issuer_ok = metadata.get("issuer") == origin
                    if issuer_ok:
                        break
                except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
                    pass
                time.sleep(0.5)
    finally:
        local_origin = server.base
        code = server.close()
    process_list = subprocess.run(
        ["ps", "-eo", "args="], stdout=subprocess.PIPE, text=True, check=True
    ).stdout
    owned_alive = f"--url {local_origin}" in process_list
    return {
        "public_url_observed": bool(public_mcp),
        "public_metadata_issuer_ok": issuer_ok,
        "shutdown_exit_code": code,
        "owned_child_remaining": owned_alive,
    }


def process_rss_kib(pid: int) -> int:
    status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            fields = line.split()
            if len(fields) >= 2:
                return int(fields[1])
    raise RuntimeError("VmRSS is unavailable for resource sampling")


def percentile95(values: list[float]) -> float:
    if not values:
        raise ValueError("resource sample is empty")
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(0.95 * (len(ordered) - 1)))))
    return ordered[index]


def resource_sample(kind: str, root: Path, sample_index: int) -> dict[str, float]:
    workspace = root / f"{kind}-workspace-{sample_index}"
    prepare_workspace(workspace)
    data_root = root / f"{kind}-data-{sample_index}"
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    environment = runtime_environment(workspace, data_root, "disabled", "static_only")
    if kind == "rust":
        command = [
            str(RELEASE_BINARY),
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
        ]
        cwd = ROOT
    elif kind == "python":
        source_root = ROOT.parent / "Re-CTM"
        environment["PYTHONPATH"] = str(source_root / "src")
        command = [
            "python3",
            "-m",
            "re_ctm",
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
        ]
        cwd = source_root
    else:
        raise ValueError(kind)
    started = time.perf_counter()
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        wait_for_port(port, process)
        client = type("ResourceClient", (), {"port": port, "base": base})()
        token = oauth_token(client)
        auth = {"Authorization": f"Bearer {token}"}
        status, _, listed = json_request(
            port,
            "POST",
            "/mcp",
            {"jsonrpc": "2.0", "id": "list", "method": "tools/list", "params": {}},
            headers=auth,
        )
        if status != 200 or len(listed.get("result", {}).get("tools", [])) != 24:
            raise RuntimeError(f"{kind} resource tools/list failed")
        status, _, info = json_request(
            port,
            "POST",
            "/mcp",
            {
                "jsonrpc": "2.0",
                "id": "info",
                "method": "tools/call",
                "params": {"name": "server_info", "arguments": {}},
            },
            headers=auth,
        )
        if status != 200 or info.get("result", {}).get("structuredContent", {}).get("tool_count") != 24:
            raise RuntimeError(f"{kind} resource server_info failed")
        elapsed_ms = (time.perf_counter() - started) * 1000
        rss_kib = process_rss_kib(process.pid)
        return {"elapsed_ms": round(elapsed_ms, 3), "rss_kib": float(rss_kib)}
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def resource_non_regression(root: Path) -> dict[str, Any]:
    samples = 7
    python_samples = [resource_sample("python", root, index) for index in range(samples)]
    rust_samples = [resource_sample("rust", root, index) for index in range(samples)]
    python_elapsed = [item["elapsed_ms"] for item in python_samples]
    rust_elapsed = [item["elapsed_ms"] for item in rust_samples]
    python_rss = [item["rss_kib"] for item in python_samples]
    rust_rss = [item["rss_kib"] for item in rust_samples]
    python_summary = {
        "elapsed_ms_median": round(statistics.median(python_elapsed), 3),
        "elapsed_ms_p95": round(percentile95(python_elapsed), 3),
        "rss_kib_median": round(statistics.median(python_rss)),
        "rss_kib_max": round(max(python_rss)),
    }
    rust_summary = {
        "elapsed_ms_median": round(statistics.median(rust_elapsed), 3),
        "elapsed_ms_p95": round(percentile95(rust_elapsed), 3),
        "rss_kib_median": round(statistics.median(rust_rss)),
        "rss_kib_max": round(max(rust_rss)),
    }
    elapsed_ratio = rust_summary["elapsed_ms_p95"] / max(1.0, python_summary["elapsed_ms_p95"])
    rss_ratio = rust_summary["rss_kib_median"] / max(1.0, python_summary["rss_kib_median"])
    passed = elapsed_ratio <= 1.25 and rss_ratio <= 1.10 and rust_summary["rss_kib_max"] <= 262144
    return {
        "samples": samples,
        "python": python_summary,
        "rust_release": rust_summary,
        "elapsed_p95_ratio": round(elapsed_ratio, 3),
        "rss_median_ratio": round(rss_ratio, 3),
        "limits": {
            "rust_elapsed_p95_ratio_max": 1.25,
            "rust_rss_median_ratio_max": 1.10,
            "rust_absolute_rss_kib_max": 262144,
        },
        "passed": passed,
    }


def main() -> int:
    build_release()
    checks: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="mtm007-target-") as directory:
        root = Path(directory)
        workspace = root / "workspace"
        prepare_workspace(workspace)
        link = release_link_check()
        checks.append(
            {
                "name": "release_binary_has_no_python_runtime",
                "passed": link["version_ok"] and not link["python_linked"],
            }
        )
        installed = install_check(root, workspace, root / "install-data")
        checks.append(
            {
                "name": "cargo_install_path_distribution",
                "passed": installed["version_ok"]
                and installed["tool_count"] == 24
                and not installed["python_linked"],
            }
        )

        server = ReleaseServer(
            workspace,
            root / "runtime-data",
            backend="bubblewrap",
            latex_policy="required",
        )
        try:
            environment = structured(server.call("check_exec_environment", {}))
            checks.append(
                {
                    "name": "bubblewrap_runtime_attestation",
                    "passed": environment.get("hard_isolation_attested") is True
                    and environment.get("native_exec_backend") == "BubblewrapExecBackend"
                    and environment.get("private_vault_visible") is False,
                }
            )
            native_result = server.call(
                "exec_command",
                {
                    "cmd": "/usr/bin/printf mtm007-native",
                    "workdir": ".",
                    "yield_time_ms": 5000,
                    "timeout_ms": 30000,
                    "verbosity": "full",
                },
            )
            native_payload = structured(native_result)
            checks.append(
                {
                    "name": "native_command_through_public_tool",
                    "passed": native_result.get("isError") is not True
                    and "mtm007-native" in str(native_payload.get("stdout") or ""),
                }
            )
            research_ok = real_research_check(server)
            workflow = drive_compact_workflow(server)
            checks.append(
                {
                    "name": "real_research_provider",
                    "passed": research_ok,
                }
            )
            checks.append(
                {
                    "name": "real_latex_finalization_through_public_tools",
                    "passed": "verify" in workflow["states"]
                    and workflow["final_exists"]
                    and workflow["final_contains_document"],
                }
            )
            checks.append(
                {
                    "name": "verified_workspace_artifact_delivery",
                    "passed": workflow["run_id_present"]
                    and workflow["export_relative"]
                    and workflow["final_exists"],
                }
            )
        finally:
            shutdown_code = server.close()
        log_text = "\n".join(server.stderr_lines)
        checks.append(
            {
                "name": "tui_observer_non_authoritative_and_redacted",
                "passed": "TUI: minimal operator session monitor active" in log_text
                and "tool.call_started" in log_text
                and OPERATOR_PASSWORD not in log_text
                and TOKEN_SECRET not in log_text
                and CAPABILITY_SECRET not in log_text,
            }
        )
        checks.append(
            {
                "name": "graceful_sigint_shutdown",
                "passed": shutdown_code == 0,
                "exit_code": shutdown_code,
            }
        )

        tunnel = quick_tunnel_check(root)
        checks.append(
            {
                "name": "quick_tunnel_public_metadata",
                "passed": tunnel["public_url_observed"]
                and tunnel["public_metadata_issuer_ok"],
            }
        )
        checks.append(
            {
                "name": "quick_tunnel_owned_shutdown",
                "passed": tunnel["shutdown_exit_code"] == 0
                and not tunnel["owned_child_remaining"],
                "exit_code": tunnel["shutdown_exit_code"],
            }
        )
        resources = resource_non_regression(root)
        checks.append(
            {
                "name": "resource_non_regression",
                "passed": resources["passed"],
                "resources": resources,
            }
        )

    required = {item["name"] for item in checks}
    passed = all(item.get("passed") is True for item in checks)
    environment = {
        "platform": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "bwrap": shutil.which("bwrap"),
        "latexmk": shutil.which("latexmk"),
        "pdflatex": shutil.which("pdflatex"),
        "cloudflared": shutil.which("cloudflared"),
        "curl": shutil.which("curl"),
    }
    report = {
        "project": "MTM-reboot",
        "milestone": "MTM-007",
        "passed": passed,
        "implementation_sha256": implementation_sha256(),
        "check_count": len(checks),
        "checks": checks,
        "environment": environment,
        "required_check_names": sorted(required),
        "sensitive_content_recorded": False,
    }
    REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
