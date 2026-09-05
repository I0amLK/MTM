#!/usr/bin/env python3
"""MTM-014 release-test support; no production runtime dependency."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mtm008_runtime_harness import free_port, oauth_token, runtime_environment, wait_for_port
from run_mtm014_mrtr_permission_validation import (
    modern_tool_call, input_required, consent_response, structured,
)
from run_mtm014_public_authority_target import (
    assert_permission_required, assert_tool_success, call_tool, grant_permission,
)

ROOT = Path(__file__).resolve().parents[1]
HOME = Path("/home/lk")
VERSION = "0.5.0-preview.1"
STABLE_SHA = "3312ca75a1de8707e740963cc0add4b09430dccc9dc63a3145e4456ff2b0cdf3"
IMPLEMENTATION = "2f11750c07317d879f1bedfd2198c36786b8ca74"
RUNTIME_REPAIR_FILE = "crates/mtm-native/src/process.rs"
RUNTIME_REPAIR_SHA = "678d147503a9ff60006e63e9b3e671c620bee818fddc6295dcad42ba1a3de36a"
SELECTOR = HOME / ".local/bin/mtm"
CARGO_ENTRY = HOME / ".cargo/bin/mtm"
STATE_ROOT = HOME / ".local/share/mtm"
STABLE = STATE_ROOT / "releases/0.4.0/mtm"
INSTALLED = STATE_ROOT / f"releases/{VERSION}/mtm"
STAGED = ROOT / "target/mtm014-preview-install/bin/mtm"
QUALIFICATION = ROOT / "records/evidence/MTM-014/preview-qualification.json"
RELEASE = ROOT / "records/evidence/MTM-014/preview-release.json"
PREREQUISITES = (
    "records/evidence/MTM-014/elicitation-capability.json",
    "records/evidence/MTM-014/native-permission-target.json",
    "records/evidence/MTM-014/public-authority-target.json",
)
HARNESS_FILES = (
    "scripts/mtm014_release_support.py",
    "scripts/run_mtm014_preview_qualification.py",
    "scripts/release_mtm014_preview.py",
    "scripts/validate_mtm014_preview_release.py",
    "scripts/mtm008_runtime_harness.py",
    "scripts/mtm008_deployment.py",
    "scripts/run_mtm014_public_authority_target.py",
    "scripts/run_mtm014_mrtr_permission_validation.py",
    "scripts/run_mtm007_http_smoke.py",
    "scripts/run_mtm007_target_validation.py",
    "scripts/run_mtm013_exact_stable_semantic_regression.py",
    "scripts/run_mtm013_stable_qualification.py",
    "scripts/run_mtm012_tui_validation.py",
)
QUALIFICATION_CHECKS = {
    "versioned_identity", "clean_git_install", "runtime_source_scope_verified",
    "safe_public_suite", "trusted_public_suite", "dangerous_public_suite",
    "all_mode_attestation", "qc_required_latex", "compact_required_latex",
    "copied_existing_state", "old_run_upgrade_rollback", "tui_display_contract",
    "tui_native_permission_flow", "resource_non_regression", "permission_soak",
    "stable_entries_unchanged", "protocol2_override", "required_tools_present",
}
RELEASE_CHECKS = {
    "qualified_binary_installed", "candidate_selector_smoke", "stable_rollback_smoke",
    "candidate_recutover_smoke", "post_recutover_soak", "stable_artifact_preserved",
    "both_entries_agree", "deployment_manifest_consistent",
}
HYGIENE = {
    "raw_credentials_recorded": False, "raw_grant_or_capability_recorded": False,
    "raw_command_or_proof_recorded": False, "raw_logs_recorded": False,
}
PUBLIC_SUITE_CHECKS = {
    "safe": {"tool_contract", "all_seven_exec_permissions", "once_replay", "argument_mutation",
             "cross_owner", "multi_risk_atomicity", "concurrent_one_winner", "real_dns_https",
             "tty_stdin_kill", "descendant_cleanup", "patch_normal_dry_ignored_mutation",
             "patch_symlink_escape", "session_reuse_restart_invalidation"},
    "trusted": {"implicit_profile", "explicit_boundaries", "generated_patch_gated"},
    "dangerous": {"complete_implicit_profile", "real_network", "privileged_no_grant",
                  "generated_patch_no_grant", "git_latex_sage", "workflow_non_inheritance"},
}
TUI_CHECKS = {
    "compact_process_exits_cleanly", "verbose_process_exits_cleanly", "generated_key_process_exits_cleanly",
    "compact_header_is_short", "compact_mcp_endpoint_visible", "compact_tool_identity_visible",
    "compact_success_completion_silent", "compact_failure_visible", "compact_trace_hidden",
    "compact_argument_keys_hidden", "compact_external_password_status_silent", "compact_tool_lines_are_not_duplicated",
    "verbose_mode_announced", "verbose_start_and_done_visible", "verbose_failure_visible",
    "verbose_trace_visible", "verbose_argument_keys_visible", "compact_secrets_redacted",
    "verbose_secrets_redacted", "generated_operator_key_shown_once",
}


class ReleaseFailure(RuntimeError):
    """Only fixed, non-sensitive stage labels may be used as messages."""


def require(condition: bool, stage: str) -> None:
    if not condition:
        raise ReleaseFailure(stage)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def git(*args: str) -> bytes:
    result = subprocess.run(["git", *args], cwd=ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=30, check=False)
    require(result.returncode == 0, "git_binding")
    return result.stdout


def identity(binary: Path, version: str) -> dict[str, Any]:
    result = subprocess.run([str(binary), "release-info"], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=10, check=True)
    info = json.loads(result.stdout)
    for key, expected in {
        "name": "mtm", "version": version, "implementation": "rust",
        "production_authority": "rust", "python_runtime_required": False,
        "public_tool_count": 24, "hidden_alias_count": 11,
        "state_schema_version": 2, "workflow_protocol_version": 3,
    }.items():
        require(type(info.get(key)) is type(expected) and info[key] == expected,
                "release_identity")
    return info


def stable_pair() -> bool:
    return (SELECTOR.is_symlink() and SELECTOR.resolve() == STABLE
            and all(path.is_file() and digest(path) == STABLE_SHA
                    for path in (SELECTOR, CARGO_ENTRY, STABLE)))


def source_scope_verified(commit: str) -> bool:
    """Allow only version metadata and the explicitly hash-frozen watchdog repair."""
    try:
        git("merge-base", "--is-ancestor", IMPLEMENTATION, commit)
        files = git("ls-tree", "-r", "--name-only", commit, "crates").decode().splitlines()
        old_files = git("ls-tree", "-r", "--name-only", IMPLEMENTATION, "crates").decode().splitlines()
        if set(files) != set(old_files):
            return False
        for name in files:
            if name == RUNTIME_REPAIR_FILE:
                if hashlib.sha256(git("show", f"{commit}:{name}")).hexdigest() != RUNTIME_REPAIR_SHA:
                    return False
                continue
            if name.endswith(".rs") or "/assets/" in name:
                if git("show", f"{commit}:{name}") != git("show", f"{IMPLEMENTATION}:{name}"):
                    return False
        manifests = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]
        manifests += [name for name in files if name.endswith("Cargo.toml")]
        for name in manifests:
            old = git("show", f"{IMPLEMENTATION}:{name}")
            new = git("show", f"{commit}:{name}")
            if new != old.replace(b"0.4.0", VERSION.encode()):
                return False
        return True
    except (ReleaseFailure, subprocess.SubprocessError):
        return False


class Server:
    """Disposable loopback server with private, bounded readback of diagnostics."""
    def __init__(self, binary: Path, root: Path, *, mode: str = "safe",
                 latex: str = "static_only", tui: bool = False,
                 port: int | None = None, protocol: int = 3) -> None:
        self.workspace = root / "workspace"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.port = free_port() if port is None else port
        self.base = f"http://127.0.0.1:{self.port}"
        self.log = tempfile.TemporaryFile()
        self.output = tempfile.TemporaryFile()
        self.log_text = ""
        env = runtime_environment(self.workspace, root / "data", "rust")
        env.update(MTM_NATIVE_EXEC_BACKEND="bubblewrap", MTM_NATIVE_MODE=mode,
                   MTM_LATEX_POLICY=latex, MTM_WORKFLOW_PROTOCOL_VERSION=str(protocol),
                   MTM_TRACE_PAYLOADS="0", MTM_DEBUG="0", MTM_NATIVE_EXEC_ALLOW_ROOTS="")
        self.process = subprocess.Popen(
            [str(binary), "tui" if tui else "serve", "--host", "127.0.0.1",
             "--port", str(self.port), "--workspace", str(self.workspace),
             "--native-mode", mode, "--latex-policy", latex],
            cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=self.output,
            stderr=self.log, start_new_session=True,
        )
        try:
            wait_for_port(self.port, self.process)
            self.token = oauth_token(self.port, self.base, "MTM-014 release validation")
        except BaseException:
            self.close()
            raise

    def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        return call_tool(self.port, self.token, name, args)

    def close(self) -> float:
        started = time.monotonic()
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
        try:
            code = self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=3)
            code = -9
        try:
            self.log.seek(0)
            raw = self.log.read(1_048_577)
            require(len(raw) <= 1_048_576, "bounded_server_diagnostics")
            self.log_text = raw.decode("utf-8", errors="replace")
        finally:
            self.log.close()
            self.output.close()
        require(code == 0, "graceful_server_shutdown")
        return (time.monotonic() - started) * 1000


@contextlib.contextmanager
def server(binary: Path, root: Path, **kwargs: Any) -> Iterator[Server]:
    instance = Server(binary, root, **kwargs)
    try:
        yield instance
    finally:
        instance.close()


def facts(pid: int) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            values["rss_kib"] = int(line.split()[1])
        elif line.startswith("Threads:"):
            values["threads"] = int(line.split()[1])
    values["fds"] = len(list(Path(f"/proc/{pid}/fd").iterdir()))
    children: set[str] = set()
    for task in Path(f"/proc/{pid}/task").iterdir():
        try:
            children.update((task / "children").read_text().split())
        except FileNotFoundError:
            continue
    values["children"] = len(children)
    require(set(values) == {"rss_kib", "threads", "fds", "children"}, "process_facts")
    return values


def p95(values: list[float]) -> float:
    require(bool(values), "resource_samples")
    ordered = sorted(values)
    return ordered[max(0, (len(ordered) * 95 + 99) // 100 - 1)]


def measure(binary: Path, root: Path) -> dict[str, float | int]:
    starts: list[float] = []
    calls: list[float] = []
    samples: list[dict[str, int]] = []
    shutdowns: list[float] = []
    for index in range(3):
        before = time.monotonic()
        instance = Server(binary, root / str(index))
        starts.append((time.monotonic() - before) * 1000)
        try:
            for n in range(70):
                start = time.monotonic()
                name, arguments = ("server_info", {}) if n % 2 else (
                    "exec_command", {"cmd": "printf local", "yield_time_ms": 30_000})
                value = assert_tool_success(instance.call(name, arguments))
                if name == "exec_command":
                    require(value.get("exit_code") == 0, "resource_local_command")
                if n >= 10:
                    calls.append((time.monotonic() - start) * 1000)
                    samples.append(facts(instance.process.pid))
        finally:
            shutdowns.append(instance.close())
    return {
        "startup_samples": len(starts), "request_samples": len(calls),
        "startup_p50_ms": round(statistics.median(starts), 3),
        "startup_p95_ms": round(p95(starts), 3),
        "request_p95_ms": round(p95(calls), 3),
        "max_rss_kib": max(s["rss_kib"] for s in samples),
        "max_threads": max(s["threads"] for s in samples),
        "max_fds": max(s["fds"] for s in samples),
        "max_shutdown_ms": round(max(shutdowns), 3),
    }


def resource_ok(old: dict[str, Any], new: dict[str, Any]) -> bool:
    return (
        new["startup_samples"] == old["startup_samples"] == 3
        and new["request_samples"] == old["request_samples"] == 180
        and new["startup_p95_ms"] <= max(2 * old["startup_p95_ms"], old["startup_p95_ms"] + 250)
        and new["request_p95_ms"] <= max(2 * old["request_p95_ms"], old["request_p95_ms"] + 10)
        and new["max_rss_kib"] <= min(262_144, old["max_rss_kib"] + 32_768)
        and new["max_threads"] <= old["max_threads"] + 2
        and new["max_fds"] <= old["max_fds"] + 8
        and new["max_shutdown_ms"] <= 8_000
    )


def permission_smoke(binary: Path, root: Path, *, legacy: bool = False,
                     tui: bool = False) -> bool:
    instance = Server(binary, root, tui=tui)
    args = {"cmd": 'sh -c "printf release-smoke"'}
    try:
        denied = instance.call("exec_command", args)
        if legacy:
            require(denied.get("result", {}).get("isError") is True, "stable_safe_denial")
            require(assert_tool_success(instance.call("exec_command", {
                "cmd": "printf stable-ok"})).get("stdout") == "stable-ok", "stable_exec")
        else:
            assert_permission_required(denied, tool_name="exec_command", permissions=["inline_script"])
            grant_permission(instance.port, instance.token, tool_name="exec_command",
                             permission="inline_script", arguments=args)
            require(assert_tool_success(instance.call("exec_command", args)).get("stdout")
                    == "release-smoke", "preview_once_exec")
            assert_permission_required(instance.call("exec_command", args),
                                       tool_name="exec_command", permissions=["inline_script"])
        info = assert_tool_success(instance.call("server_info", {}))
        require(info["native"]["workflow_authority_inherited"] is False, "workflow_firewall")
    finally:
        instance.close()
    if tui and not legacy:
        text = instance.log_text
        require("tool: request_permissions" in text and "tool: exec_command" in text,
                "tui_permission_visibility")
        require("release-smoke" not in text and "npg-" not in text
                and "Bearer " not in text and instance.token not in text,
                "tui_redaction")
    return True


def soak(binary: Path, root: Path) -> dict[str, Any]:
    instance = Server(binary, root)
    try:
        assert_tool_success(instance.call("exec_command", {"cmd": "printf warm"}))
        baseline = facts(instance.process.pid)
        peak = baseline.copy()
        started = time.monotonic()
        iterations = 0
        # Grants use a short test TTL; ordinary consumed-grant tombstones expire
        # naturally rather than being removed by the test harness.
        while time.monotonic() - started < 60:
            args = {"cmd": 'sh -c "printf soak"', "timeout_ms": 5_000}
            request = {"tool_name": "exec_command", "permission": "inline_script",
                       "reason": "bounded release soak", "arguments": args,
                       "scope": "once", "ttl_seconds": 5}
            status, first = modern_tool_call(instance.port, instance.token, "request_permissions",
                                            request, capabilities={"elicitation": {}})
            require(status == 200, "soak_challenge")
            state, _ = input_required(first)
            status, accepted = modern_tool_call(
                instance.port, instance.token, "request_permissions", request,
                capabilities={"elicitation": {}}, input_responses=consent_response(True),
                request_state=state,
            )
            require(status == 200 and structured(accepted).get("status") == "granted", "soak_grant")
            require(assert_tool_success(instance.call("exec_command", args)).get("stdout") == "soak",
                    "soak_authorized_exec")
            assert_permission_required(instance.call("exec_command", args),
                                       tool_name="exec_command", permissions=["inline_script"])
            current = facts(instance.process.pid)
            peak = {key: max(peak[key], current[key]) for key in peak}
            iterations += 1
            time.sleep(0.05)
        time.sleep(0.1)
        end = facts(instance.process.pid)
        summary = {"duration_seconds": round(time.monotonic() - started, 3),
                   "iterations": iterations, "before": baseline, "peak": peak, "after": end}
    finally:
        shutdown_ms = instance.close()
    summary["shutdown_ms"] = round(shutdown_ms, 3)
    require(soak_ok(summary), "permission_soak_bounds")
    return summary


def soak_ok(value: dict[str, Any]) -> bool:
    before, peak, after = value["before"], value["peak"], value["after"]
    return (60 <= value["duration_seconds"] <= 90 and value["iterations"] >= 100
            and peak["rss_kib"] <= min(262_144, before["rss_kib"] + 16_384)
            and peak["threads"] <= before["threads"] + 2
            and peak["fds"] <= before["fds"] + 8
            and after["children"] == 0 and value["shutdown_ms"] <= 8_000)
