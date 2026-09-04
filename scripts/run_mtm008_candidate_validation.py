#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

try:
    from scripts.mtm008_deployment import (
        DeploymentLayout,
        cutover,
        public_summary,
        recutover,
        rollback,
        run_version,
        sha256_file,
        validate_rust_release,
    )
    from scripts.mtm008_runtime_harness import (
        OPERATOR_PASSWORD,
        ROOT,
        RUST_BINARY,
        SOURCE_ROOT,
        build_release,
        free_port,
        prepare_workspace,
        runtime_environment,
        wait_for_port,
    )
except ModuleNotFoundError:
    from mtm008_deployment import (
        DeploymentLayout,
        cutover,
        public_summary,
        recutover,
        rollback,
        run_version,
        sha256_file,
        validate_rust_release,
    )
    from mtm008_runtime_harness import (
        OPERATOR_PASSWORD,
        ROOT,
        RUST_BINARY,
        SOURCE_ROOT,
        build_release,
        free_port,
        prepare_workspace,
        runtime_environment,
        wait_for_port,
    )


REPORT = ROOT / "records/evidence/MTM-008/candidate-validation.json"
PERFORMANCE_REPORT = ROOT / "records/evidence/MTM-008/performance.json"
SOAK_REPORT = ROOT / "records/evidence/MTM-008/soak.json"
VERSION = "0.3.0"
IMPLEMENTATION_PATHS = [
    ROOT / "Cargo.toml",
    ROOT / "Cargo.lock",
    ROOT / "crates",
    ROOT / "scripts" / "mtm008_deployment.py",
    ROOT / "scripts" / "mtm008_runtime_harness.py",
    ROOT / "scripts" / "run_mtm008_performance.py",
    ROOT / "scripts" / "run_mtm008_soak.py",
    ROOT / "scripts" / "run_mtm008_candidate_validation.py",
    ROOT / "scripts" / "validate_mtm008_candidate_evidence.py",
]


def implementation_sha256() -> str:
    digest = hashlib.sha256()
    paths: list[Path] = []
    for candidate in IMPLEMENTATION_PATHS:
        if candidate.is_dir():
            paths.extend(
                path
                for path in candidate.rglob("*")
                if path.is_file() and "target" not in path.parts and "__pycache__" not in path.parts
            )
        elif candidate.is_file():
            paths.append(candidate)
    for path in sorted(set(paths)):
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def build_rollback_wheel(output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    uv = shutil.which("uv")
    if uv is None:
        raise RuntimeError("uv is required to create the immutable Python rollback wheel")
    subprocess.run(
        [uv, "build", "--wheel", "--out-dir", str(output), str(SOURCE_ROOT)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=300,
        check=True,
    )
    wheels = sorted(output.glob("re_ctm-0.3.0-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected one Re-CTM rollback wheel, found {len(wheels)}")
    return wheels[0]


def restore_wheel(wheel: Path, root: Path) -> dict[str, Any]:
    uv = shutil.which("uv")
    if uv is None:
        raise RuntimeError("uv is required for the rollback restore drill")
    tool_dir = root / "tools"
    bin_dir = root / "bin"
    environment = os.environ.copy()
    environment.update({"UV_TOOL_DIR": str(tool_dir), "UV_TOOL_BIN_DIR": str(bin_dir)})
    completed = subprocess.run(
        [uv, "tool", "install", "--force", "--from", str(wheel), "re-ctm"],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=300,
        check=False,
    )
    executable = bin_dir / "re-ctm"
    return {
        "install_exit_code": completed.returncode,
        "command_exists": executable.is_file() or executable.is_symlink(),
        "version": run_version(executable.resolve()) if executable.exists() else "",
    }


def probe_server(executable: Path, root: Path, label: str) -> dict[str, Any]:
    workspace = root / f"{label}-workspace"
    data_root = root / f"{label}-data"
    prepare_workspace(workspace)
    port = free_port()
    kind = "rust" if label.startswith("rust") else "python"
    environment = runtime_environment(workspace, data_root, kind)
    command = [
        str(executable),
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
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        wait_for_port(port, process)
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/.well-known/oauth-authorization-server",
            timeout=10,
        ) as response:
            metadata = json.loads(response.read())
        passed = response.status == 200 and metadata.get("issuer") == f"http://127.0.0.1:{port}"
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            exit_code = process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            exit_code = process.wait(timeout=3)
    return {"passed": passed, "exit_code": exit_code}


def dynamic_dependencies(binary: Path) -> str:
    completed = subprocess.run(
        ["ldd", str(binary)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
        check=False,
    )
    return completed.stdout.lower()


def validate_previous_evidence() -> dict[str, bool]:
    validators = [
        "validate_mtm003_target_evidence.py",
        "validate_mtm004_target_evidence.py",
        "validate_mtm005_target_evidence.py",
        "validate_mtm006_target_evidence.py",
        "validate_mtm007_target_evidence.py",
    ]
    results: dict[str, bool] = {}
    for name in validators:
        completed = subprocess.run(
            ["python3", str(ROOT / "scripts" / name)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            check=False,
        )
        results[name] = completed.returncode == 0
    return results


def main() -> int:
    build_release()
    info = validate_rust_release(RUST_BINARY, VERSION)
    performance = json.loads(PERFORMANCE_REPORT.read_text(encoding="utf-8"))
    soak = json.loads(SOAK_REPORT.read_text(encoding="utf-8"))
    previous_evidence = validate_previous_evidence()
    with tempfile.TemporaryDirectory(prefix="mtm008-candidate-") as directory:
        root = Path(directory)
        wheel = build_rollback_wheel(root / "rollback-wheel")
        wheel_sha256 = sha256_file(wheel)
        wheel_size = wheel.stat().st_size
        restore = restore_wheel(wheel, root / "restore")
        previous = root / "previous" / "mtm"
        previous.parent.mkdir(parents=True)
        shutil.copy2(SOURCE_ROOT / ".venv" / "bin" / "re-ctm", previous)
        os.chmod(previous, 0o755)
        bin_dir = root / "live-bin"
        bin_dir.mkdir()
        link = bin_dir / "mtm"
        link.symlink_to(previous)
        layout = DeploymentLayout(link, root / "deployment")
        deployed = cutover(RUST_BINARY, layout, VERSION, wheel)
        rust_probe = probe_server(link.resolve(), root, "rust-candidate")
        rolled = rollback(layout.manifest)
        python_probe = probe_server(link.resolve(), root, "python-rollback")
        active = recutover(layout.manifest)
        recutover_probe = probe_server(link.resolve(), root, "rust-recutover")

    checks = [
        {
            "name": "release_identity",
            "passed": info.get("implementation") == "rust"
            and info.get("python_runtime_required") is False,
        },
        {
            "name": "release_has_no_python_linkage",
            "passed": "python" not in dynamic_dependencies(RUST_BINARY),
        },
        {
            "name": "previous_target_evidence_fresh",
            "passed": all(previous_evidence.values()),
            "validators": previous_evidence,
        },
        {
            "name": "immutable_python_rollback_wheel",
            "passed": wheel_size > 0,
            "sha256": wheel_sha256,
            "size_bytes": wheel_size,
        },
        {
            "name": "rollback_wheel_restore",
            "passed": restore["install_exit_code"] == 0
            and restore["command_exists"]
            and restore["version"] == "re-ctm 0.3.0",
        },
        {
            "name": "atomic_rust_cutover",
            "passed": deployed["state"] == "rust_active" and rust_probe["passed"],
        },
        {
            "name": "python_rollback_drill",
            "passed": rolled["state"] == "previous_active" and python_probe["passed"],
        },
        {
            "name": "rust_recutover_drill",
            "passed": active["state"] == "rust_active" and recutover_probe["passed"],
        },
        {
            "name": "a6_performance_qualification",
            "passed": performance.get("passed") is True
            and performance.get("claim", {}).get("passed") is True
            and performance.get("environment", {}).get("rust_binary_sha256")
            == sha256_file(RUST_BINARY),
        },
        {
            "name": "release_soak",
            "passed": soak.get("passed") is True
            and soak.get("release_binary", {}).get("sha256") == sha256_file(RUST_BINARY),
        },
    ]
    report = {
        "schema_version": "1.0.0",
        "project": "MTM-reboot",
        "milestone": "MTM-008",
        "phase": "candidate",
        "passed": all(item["passed"] for item in checks),
        "implementation_sha256": implementation_sha256(),
        "release_binary": {
            "version": run_version(RUST_BINARY),
            "sha256": sha256_file(RUST_BINARY),
            "size_bytes": RUST_BINARY.stat().st_size,
        },
        "checks": checks,
        "performance_claim": performance.get("claim"),
        "soak_summary": {
            "duration_seconds": soak.get("duration_seconds"),
            "request_count": soak.get("request_count"),
            "request_errors": soak.get("request_errors"),
            "stateful_start_cancel_cycles": soak.get("stateful_start_cancel_cycles"),
            "resources": soak.get("resources"),
        },
        "deployment_summary": public_summary(active),
        "environment": {
            "platform": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "uv": shutil.which("uv"),
        },
        "production_authority_changed": False,
        "sensitive_content_recorded": False,
    }
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
