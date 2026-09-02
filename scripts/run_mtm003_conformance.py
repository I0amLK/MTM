#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "source-baseline.json"
GOLDEN = ROOT / "conformance" / "golden" / "mtm003-reference.sha256"
CARGO_HOME = ROOT / ".toolchain" / "cargo"
RUSTUP_HOME = ROOT / ".toolchain" / "rustup"
RUST_SHADOW = ROOT / "target" / "debug" / "mtm-native-shadow"
MAX_RSS_KIB = 131_072
MAX_SCENARIO_SECONDS = 30.0


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def cargo_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["CARGO_HOME"] = str(CARGO_HOME)
    environment["RUSTUP_HOME"] = str(RUSTUP_HOME)
    environment["PATH"] = str(CARGO_HOME / "bin") + os.pathsep + environment.get("PATH", "")
    return environment


def verify_source_baseline() -> tuple[Path, dict[str, Any]]:
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    source = (ROOT / baseline["source_path"]).resolve()
    expected = str(baseline["source_commit"])
    actual = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    references = [str(value) for value in baseline.get("reference_files", [])]
    dirty = subprocess.run(
        ["git", "status", "--porcelain=v1", "--", *references],
        cwd=source,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    return source, {
        "expected_commit": expected,
        "actual_commit": actual,
        "commit_match": actual == expected,
        "reference_file_count": len(references),
        "reference_files_clean": not dirty,
        "dirty_reference_output": dirty,
    }


def build_binaries() -> None:
    subprocess.run(
        [str(CARGO_HOME / "bin" / "cargo"), "build", "-q", "-p", "mtm-native", "--bins"],
        cwd=ROOT,
        env=cargo_environment(),
        check=True,
    )


@dataclass
class Driver:
    label: str
    command: list[str]
    process: subprocess.Popen[str] = field(init=False)
    started: float = field(init=False)
    max_rss_kib: int = 0
    request_count: int = 0

    def __post_init__(self) -> None:
        self.started = time.perf_counter()
        self.process = subprocess.Popen(
            self.command,
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=minimal_driver_environment(),
        )
        self.sample_rss()

    def request(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError(f"{self.label} driver pipes unavailable")
        self.process.stdin.write(canonical({"operation": operation, "payload": payload}) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        self.sample_rss()
        self.request_count += 1
        if not line:
            stderr = self.process.stderr.read() if self.process.stderr is not None else ""
            raise RuntimeError(f"{self.label} driver exited early: {stderr}")
        response = json.loads(line)
        if not isinstance(response, dict):
            raise TypeError(f"{self.label} driver response must be an object")
        return response

    def sample_rss(self) -> None:
        status = Path(f"/proc/{self.process.pid}/status")
        try:
            for line in status.read_text(encoding="utf-8").splitlines():
                if line.startswith("VmRSS:"):
                    self.max_rss_kib = max(self.max_rss_kib, int(line.split()[1]))
                    break
        except (OSError, ValueError, IndexError):
            pass

    def close(self) -> dict[str, Any]:
        try:
            if self.process.poll() is None:
                try:
                    self.request("process_close", {})
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
            self.sample_rss()
        stderr = self.process.stderr.read() if self.process.stderr is not None else ""
        return {
            "elapsed_ms": round((time.perf_counter() - self.started) * 1000, 3),
            "max_rss_kib": self.max_rss_kib,
            "request_count": self.request_count,
            "exit_code": self.process.returncode,
            "stderr_tail": stderr[-4000:],
        }


def minimal_driver_environment() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONPATH": "",
        "HOME": os.environ.get("HOME", "/nonexistent"),
    }


def require_ok(response: dict[str, Any], label: str) -> dict[str, Any]:
    if response.get("ok") is not True:
        raise RuntimeError(f"{label} failed: {response}")
    result = response.get("result")
    if not isinstance(result, dict):
        raise TypeError(f"{label} result must be an object")
    return result


def response_contract(response: dict[str, Any]) -> dict[str, Any]:
    if response.get("ok") is True:
        return {"ok": True, "result": response.get("result")}
    error = response.get("error") if isinstance(response.get("error"), dict) else {}
    return {
        "ok": False,
        "error": {
            "code": error.get("code"),
            "message": error.get("message"),
            "category": error.get("category"),
            "retryable": error.get("retryable"),
            "details": error.get("details", {}),
        },
    }


def prepare_fixture(root: Path) -> dict[str, str]:
    workspace = root / "workspace"
    data = root / "data"
    private = data / "private"
    environment = root / "science-stack"
    environment_bin = environment / "bin"
    wrapper_bin = root / "wrapper-bin"
    product = root / "vendor-product"
    product_exec = product / "Executables"
    explicit = root / "explicit-toolchain"
    explicit_bin = explicit / "bin"
    for path in (workspace, private, environment_bin, wrapper_bin, product_exec, explicit_bin):
        path.mkdir(parents=True, exist_ok=True)
    (private / "canary.txt").write_text("PRIVATE-CANARY\n", encoding="utf-8")
    (environment_bin / "symbolic-a").write_text("#!/bin/sh\n", encoding="utf-8")
    target = product_exec / "symbolic-b"
    target.write_text("#!/bin/sh\n", encoding="utf-8")
    target.chmod(0o755)
    (wrapper_bin / "symbolic-b").symlink_to(target)
    executable = explicit_bin / "symbolic-c"
    executable.write_text("#!/bin/sh\nprintf 'explicit-ok\\n'\n", encoding="utf-8")
    executable.chmod(0o755)
    return {
        "workspace": str(workspace),
        "data": str(data),
        "private": str(private),
        "environment": str(environment),
        "environment_bin": str(environment_bin),
        "wrapper_bin": str(wrapper_bin),
        "product": str(product),
        "explicit": str(explicit),
        "explicit_bin": str(explicit_bin),
        "host_path": os.pathsep.join(
            [str(environment_bin), str(wrapper_bin), "/usr/bin", "/bin"]
        ),
    }


def static_cases(driver: Driver, fixture: dict[str, str]) -> dict[str, Any]:
    cases: dict[str, Any] = {}
    cases["safe_explicit"] = response_contract(
        driver.request(
            "toolchain_plan",
            {
                "mode": "safe",
                "workspace": fixture["workspace"],
                "forbidden_paths": [fixture["data"], fixture["private"]],
                "explicit_roots": [fixture["explicit"]],
                "host_path": str(Path(fixture["workspace"]) / "not-inherited"),
            },
        )
    )
    cases["dangerous_discovery"] = response_contract(
        driver.request(
            "toolchain_plan",
            {
                "mode": "dangerous",
                "workspace": fixture["workspace"],
                "forbidden_paths": [fixture["data"], fixture["private"]],
                "explicit_roots": [fixture["explicit"]],
                "host_path": fixture["host_path"],
            },
        )
    )
    cases["denied_overlap"] = response_contract(
        driver.request(
            "toolchain_plan",
            {
                "mode": "dangerous",
                "workspace": fixture["workspace"],
                "forbidden_paths": [fixture["data"], fixture["private"]],
                "explicit_roots": [fixture["private"]],
                "host_path": fixture["host_path"],
            },
        )
    )
    command_payload = {
        "workspace": fixture["workspace"],
        "workdir": ".",
        "mode": "safe",
        "argv": ["/bin/echo", "hello-native"],
        "extra_env": {"MTM_VISIBLE": "yes"},
        "host_path": "/usr/bin:/bin",
        "extra_read_roots": [fixture["explicit"]],
        "forbidden_paths": [fixture["data"], fixture["private"]],
    }
    cases["bubblewrap_command"] = response_contract(
        driver.request("bubblewrap_command", command_payload)
    )
    return cases


def process_scenario(driver: Driver) -> dict[str, Any]:
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    result: dict[str, Any] = {}

    sync = require_ok(
        driver.request(
            "process_start",
            {
                "argv": ["/bin/sh", "-c", "printf 'out\\n'; printf 'err\\n' >&2"],
                "env": environment,
                "timeout_ms": 5000,
                "yield_time_ms": 2000,
                "max_output_bytes": 65536,
                "stdin": "",
                "tty": False,
                "preview_bytes": 4096,
            },
        ),
        f"{driver.label} sync",
    )
    result["sync"] = {
        "status": sync.get("status"),
        "exit_code": sync.get("exit_code"),
        "timed_out": sync.get("timed_out"),
        "stdout": normalize_terminal_text(sync.get("stdout")),
        "stderr": normalize_terminal_text(sync.get("stderr")),
    }

    running = require_ok(
        driver.request(
            "process_start",
            {
                "argv": [
                    "/bin/sh",
                    "-c",
                    "printf 'started\\n'; sleep 20",
                ],
                "env": environment,
                "timeout_ms": 30_000,
                "yield_time_ms": 100,
                "max_output_bytes": 65_536,
                "stdin": "",
                "tty": False,
                "preview_bytes": 4096,
            },
        ),
        f"{driver.label} running",
    )
    command_id = str(running["command_id"])
    output = require_ok(
        driver.request(
            "process_read",
            {
                "output_ref": f"command:{command_id}:stdout",
                "offset": 0,
                "limit": 4096,
            },
        ),
        f"{driver.label} read",
    )
    killed = require_ok(
        driver.request(
            "process_kill",
            {
                "command_id": command_id,
                "signal": "TERM",
                "wait_ms": 2000,
                "kill_wait_ms": 1000,
                "max_output_bytes": 65536,
                "preview_bytes": 4096,
            },
        ),
        f"{driver.label} kill",
    )
    result["lifecycle"] = {
        "initial_status": running.get("status"),
        "initial_contains_started": "started" in normalize_terminal_text(running.get("stdout")),
        "read_contains_started": "started" in normalize_terminal_text(output.get("content")),
        "kill_status": killed.get("status"),
        "killed": killed.get("killed"),
        "signal": killed.get("signal"),
        "termination_source": nested(killed, "termination", "source"),
        "term_sent": nested(killed, "termination", "term_sent_by_re_ctm"),
    }

    tty = require_ok(
        driver.request(
            "process_start",
            {
                "argv": [
                    "/bin/sh",
                    "-c",
                    "printf 'ready\\n'; read value; printf 'got:%s\\n' \"$value\"",
                ],
                "env": environment,
                "timeout_ms": 10_000,
                "yield_time_ms": 100,
                "max_output_bytes": 65_536,
                "stdin": "",
                "tty": True,
                "preview_bytes": 4096,
            },
        ),
        f"{driver.label} tty start",
    )
    tty_id = str(tty["command_id"])
    tty_reply = require_ok(
        driver.request(
            "process_poll",
            {
                "command_id": tty_id,
                "chars": "hello-lifecycle\n",
                "yield_time_ms": 1500,
                "max_output_bytes": 65536,
                "preview_bytes": 4096,
            },
        ),
        f"{driver.label} tty poll",
    )
    tty_text = normalize_terminal_text(tty.get("stdout")) + normalize_terminal_text(
        tty_reply.get("stdout")
    )
    result["tty"] = {
        "ready": "ready" in tty_text,
        "round_trip": "got:hello-lifecycle" in tty_text,
        "terminal": tty_reply.get("status") in {"exited", "terminated"},
    }

    timeout = require_ok(
        driver.request(
            "process_start",
            {
                "argv": ["/bin/sh", "-c", "sleep 2"],
                "env": environment,
                "timeout_ms": 120,
                "yield_time_ms": 600,
                "max_output_bytes": 65536,
                "stdin": "",
                "tty": False,
                "preview_bytes": 4096,
            },
        ),
        f"{driver.label} timeout",
    )
    result["timeout"] = {
        "status": timeout.get("status"),
        "timed_out": timeout.get("timed_out"),
        "termination_source": nested(timeout, "termination", "source"),
        "term_sent": nested(timeout, "termination", "term_sent_by_re_ctm"),
        "signal": timeout.get("signal"),
    }

    large = require_ok(
        driver.request(
            "process_start",
            {
                "argv": [
                    "/usr/bin/python3",
                    "-c",
                    "import sys; sys.stdout.write('H'*600000)",
                ],
                "env": environment,
                "timeout_ms": 10_000,
                "yield_time_ms": 5000,
                "max_output_bytes": 1024,
                "stdin": "",
                "tty": False,
                "preview_bytes": 256,
            },
        ),
        f"{driver.label} large",
    )
    large_id = str(large["command_id"])
    page = require_ok(
        driver.request(
            "process_read",
            {
                "output_ref": f"command:{large_id}:stdout",
                "offset": 100_000,
                "limit": 128,
            },
        ),
        f"{driver.label} large page",
    )
    result["retention"] = {
        "total_stream_bytes": page.get("total_stream_bytes"),
        "head_retained_bytes": page.get("head_retained_bytes"),
        "stream_dropped_bytes": page.get("stream_dropped_bytes"),
        "evicted_gap_bytes": page.get("evicted_gap_bytes"),
        "omitted_bytes_positive": int(page.get("omitted_bytes") or 0) > 0,
        "content_length": len(str(page.get("content") or "")),
        "content_is_h": set(str(page.get("content") or "")) <= {"H"},
    }
    return result


def normalize_terminal_text(value: Any) -> str:
    return str(value or "").replace("\r\n", "\n").replace("\r", "\n")


def nested(value: dict[str, Any], *keys: str) -> Any:
    current: Any = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def git_status() -> str:
    return subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--print-golden", action="store_true")
    args = parser.parse_args(argv)
    source, baseline = verify_source_baseline()
    if not baseline["commit_match"] or not baseline["reference_files_clean"]:
        print(json.dumps({"ok": False, "source": str(source), **baseline}, indent=2))
        return 1
    build_binaries()
    before_status = git_status()
    with tempfile.TemporaryDirectory(prefix="mtm003-conformance-") as raw_root:
        fixture_root = str(Path(raw_root))
        fixture = prepare_fixture(Path(raw_root))
        python_driver = Driver(
            "python",
            [sys.executable, "conformance/python_native_shadow.py"],
        )
        try:
            python_static = static_cases(python_driver, fixture)
            python_process = process_scenario(python_driver)
        finally:
            python_resources = python_driver.close()

        rust_driver = Driver("rust", [str(RUST_SHADOW)])
        try:
            rust_static = static_cases(rust_driver, fixture)
            rust_process = process_scenario(rust_driver)
        finally:
            rust_resources = rust_driver.close()

    exact_mismatches = compare_mapping(python_static, rust_static)
    process_mismatches = compare_mapping(python_process, rust_process)
    reference = normalize_paths(
        {
            "static": python_static,
            "process": python_process,
        },
        fixture_root,
    )
    reference_hash = hashlib.sha256(canonical(reference).encode("utf-8")).hexdigest()
    recorded_hash = GOLDEN.read_text(encoding="utf-8").strip() if GOLDEN.exists() else ""
    golden_match = args.print_golden or reference_hash == recorded_hash
    after_status = git_status()
    side_effect_free = before_status == after_status
    resource_ok = (
        python_resources["elapsed_ms"] <= MAX_SCENARIO_SECONDS * 1000
        and rust_resources["elapsed_ms"] <= MAX_SCENARIO_SECONDS * 1000
        and python_resources["max_rss_kib"] <= MAX_RSS_KIB
        and rust_resources["max_rss_kib"] <= MAX_RSS_KIB
        and rust_resources["elapsed_ms"] <= max(python_resources["elapsed_ms"] * 3, 5000)
        and rust_resources["max_rss_kib"] <= max(python_resources["max_rss_kib"] * 2, 65_536)
    )
    summary = {
        "ok": not exact_mismatches
        and not process_mismatches
        and golden_match
        and side_effect_free
        and resource_ok,
        "source_commit": baseline["actual_commit"],
        "source_reference_file_count": baseline["reference_file_count"],
        "source_reference_files_clean": baseline["reference_files_clean"],
        "exact_case_count": len(python_static),
        "process_case_count": len(python_process),
        "reference_sha256": reference_hash,
        "recorded_sha256": recorded_hash or None,
        "golden_match": golden_match,
        "exact_mismatches": exact_mismatches,
        "process_mismatches": process_mismatches,
        "resources": {
            "python_reference": python_resources,
            "rust_shadow": rust_resources,
            "limits": {
                "elapsed_seconds": MAX_SCENARIO_SECONDS,
                "max_rss_kib": MAX_RSS_KIB,
            },
        },
        "resource_gate_passed": resource_ok,
        "shadow_side_effect_free": side_effect_free,
        "authority": {
            "source_reference": "python",
            "rust_mode": "read_only_shadow",
            "production_authority": "python",
        },
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["ok"] else 1


def compare_mapping(expected: dict[str, Any], actual: dict[str, Any]) -> list[dict[str, Any]]:
    mismatches = []
    for key in sorted(set(expected) | set(actual)):
        if normalize_release_branding(expected.get(key)) != normalize_release_branding(
            actual.get(key)
        ):
            mismatches.append(
                {
                    "case": key,
                    "python": expected.get(key),
                    "rust": actual.get(key),
                }
            )
    return mismatches


def normalize_release_branding(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: normalize_release_branding(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize_release_branding(item) for item in value]
    if value == "root overlaps Re-CTM data/private state":
        return "root overlaps MTM data/private state"
    return value


def normalize_paths(value: Any, root: str) -> Any:
    if isinstance(value, dict):
        return {key: normalize_paths(item, root) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize_paths(item, root) for item in value]
    if isinstance(value, str):
        return value.replace(root, "<FIXTURE_ROOT>")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
