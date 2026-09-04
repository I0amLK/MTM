#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import platform
import secrets
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

try:
    from scripts.mtm008_deployment import (
        DeploymentLayout,
        cutover,
        load_manifest,
        processes_using,
        public_summary,
        recutover,
        rollback,
        run_json,
        run_version,
        sha256_file,
        validate_rust_release,
    )
    from scripts.mtm008_runtime_harness import (
        ROOT,
        RUST_BINARY,
        SOURCE_ROOT,
        build_release,
        free_port,
        prepare_workspace,
        runtime_environment,
        wait_for_port,
    )
    from scripts.validate_mtm008_candidate_evidence import validate as validate_candidate
except ModuleNotFoundError:
    from mtm008_deployment import (
        DeploymentLayout,
        cutover,
        load_manifest,
        processes_using,
        public_summary,
        recutover,
        rollback,
        run_json,
        run_version,
        sha256_file,
        validate_rust_release,
    )
    from mtm008_runtime_harness import (
        ROOT,
        RUST_BINARY,
        SOURCE_ROOT,
        build_release,
        free_port,
        prepare_workspace,
        runtime_environment,
        wait_for_port,
    )
    from validate_mtm008_candidate_evidence import validate as validate_candidate


REPORT = ROOT / "records/evidence/MTM-008/live-cutover.json"
HOME = Path("/home/lk")
BIN_LINK = HOME / ".local" / "bin" / "re-ctm"
STATE_ROOT = HOME / ".local" / "share" / "re-ctm-rust"
PYTHON_TOOL_ROOT = HOME / ".local" / "share" / "uv" / "tools" / "re-ctm"
DEV_VENV_ROOT = SOURCE_ROOT / ".venv"
ROLLBACK_WHEEL = STATE_ROOT / "rollback" / "re_ctm-0.3.0-py3-none-any.whl"
VERSION = "0.3.0"
CANDIDATE_COMMIT = "4117734941970e8068cfe49291ff6f13a3123792"
IMPLEMENTATION_FILES = [
    ROOT / "scripts" / "mtm008_deployment.py",
    ROOT / "scripts" / "run_mtm008_live_cutover.py",
    ROOT / "scripts" / "validate_mtm008_live_evidence.py",
]


def implementation_sha256() -> str:
    digest = hashlib.sha256()
    for path in sorted(IMPLEMENTATION_FILES):
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def process_record(pid: int) -> dict[str, Any] | None:
    root = Path("/proc") / str(pid)
    try:
        executable = (root / "exe").resolve()
        cwd = (root / "cwd").resolve()
        argv = [
            item.decode("utf-8", "replace")
            for item in (root / "cmdline").read_bytes().split(b"\0")
            if item
        ]
        environment = {
            key.decode("utf-8", "replace"): value.decode("utf-8", "replace")
            for item in (root / "environ").read_bytes().split(b"\0")
            if b"=" in item
            for key, value in [item.split(b"=", 1)]
        }
    except (FileNotFoundError, PermissionError, OSError):
        return None
    marker_index = next(
        (
            index
            for index, item in enumerate(argv)
            if item.endswith("/re-ctm") or item == "re-ctm"
        ),
        None,
    )
    if marker_index is None or marker_index + 1 >= len(argv):
        return None
    command = argv[marker_index + 1 :]
    if command[0] not in {"serve", "tui"}:
        return None
    selected_environment = {
        key: value
        for key, value in environment.items()
        if key.startswith("RE_CTM_") or key in {"LANG", "LC_ALL", "LC_CTYPE", "TMPDIR"}
    }
    return {
        "pid": pid,
        "executable": str(executable),
        "cwd": str(cwd),
        "command": command,
        "environment": selected_environment,
    }


def discover_python_sessions() -> list[dict[str, Any]]:
    sessions: list[dict[str, Any]] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        record = process_record(int(entry.name))
        if record is None:
            continue
        executable = Path(record["executable"])
        is_python = executable.name.startswith("python")
        from_known_root = any(
            executable == root or root in executable.parents
            for root in (PYTHON_TOOL_ROOT, DEV_VENV_ROOT)
        )
        if not is_python and not from_known_root:
            continue
        if all(existing["pid"] != record["pid"] for existing in sessions):
            sessions.append(record)
    return sorted(sessions, key=lambda item: int(item["pid"]))


def descendants(pids: set[int]) -> set[int]:
    parent_map: dict[int, int] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            suffix = (entry / "stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()
            parent_map[int(entry.name)] = int(suffix[1])
        except (FileNotFoundError, PermissionError, OSError, ValueError, IndexError):
            continue
    result = set(pids)
    changed = True
    while changed:
        changed = False
        for pid, parent in parent_map.items():
            if parent in result and pid not in result:
                result.add(pid)
                changed = True
    return result


def alive(pids: set[int]) -> set[int]:
    return {pid for pid in pids if (Path("/proc") / str(pid)).exists()}


def stop_sessions(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    roots = {int(item["pid"]) for item in sessions}
    owned = descendants(roots)
    for item in sessions:
        try:
            os.kill(int(item["pid"]), signal.SIGINT)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline and alive(owned):
        time.sleep(0.1)
    term = alive(owned)
    for pid in term:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and alive(owned):
        time.sleep(0.1)
    killed = alive(owned)
    for pid in killed:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline and alive(owned):
        time.sleep(0.05)
    remaining = alive(owned)
    if remaining:
        raise RuntimeError(f"Re-CTM session descendants remain after shutdown: {len(remaining)}")
    return {
        "session_count": len(sessions),
        "owned_process_count": len(owned),
        "required_sigterm_count": len(term),
        "required_sigkill_count": len(killed),
        "remaining_count": len(remaining),
    }


def build_permanent_wheel() -> dict[str, Any]:
    ROLLBACK_WHEEL.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(ROLLBACK_WHEEL.parent, 0o700)
    with tempfile.TemporaryDirectory(prefix="mtm008-live-wheel-") as directory:
        output = Path(directory)
        uv = shutil.which("uv")
        if uv is None:
            raise RuntimeError("uv is required to build the rollback wheel")
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
            raise RuntimeError(f"expected one rollback wheel, found {len(wheels)}")
        temporary = ROLLBACK_WHEEL.with_name(f".{ROLLBACK_WHEEL.name}.{os.getpid()}.tmp")
        try:
            shutil.copyfile(wheels[0], temporary)
            os.chmod(temporary, 0o600)
            os.replace(temporary, ROLLBACK_WHEEL)
        finally:
            temporary.unlink(missing_ok=True)
    return {
        "path": str(ROLLBACK_WHEEL),
        "sha256": sha256_file(ROLLBACK_WHEEL),
        "size_bytes": ROLLBACK_WHEEL.stat().st_size,
    }


def probe(executable: Path, root: Path, label: str) -> dict[str, Any]:
    workspace = root / f"{label}-workspace"
    data_root = root / f"{label}-data"
    prepare_workspace(workspace)
    port = free_port()
    environment = runtime_environment(workspace, data_root)
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
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        wait_for_port(port, process)
        info = run_json(executable, "release-info") if label.startswith("rust") else None
        passed = info is not None and info.get("implementation") == "rust" if info else True
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        try:
            exit_code = process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            exit_code = process.wait(timeout=3)
    return {"passed": passed, "exit_code": exit_code}


def restart_sessions(sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    session_root = STATE_ROOT / "sessions"
    session_root.mkdir(parents=True, exist_ok=True)
    os.chmod(session_root, 0o700)
    restarted: list[dict[str, Any]] = []
    for index, session in enumerate(sessions):
        log_path = session_root / f"session-{index + 1}.log"
        log_handle = log_path.open("wb", buffering=0)
        os.chmod(log_path, 0o600)
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("RE_CTM_") and not key.startswith("TUNNEL_")
        }
        environment.update(session["environment"])
        key_source = "preserved_environment"
        key_path: Path | None = None
        if not environment.get("RE_CTM_OAUTH_PASSWORD"):
            key_source = "generated_owner_only_file"
            key_path = session_root / f"session-{index + 1}.operator-key"
            temporary_key = key_path.with_name(f".{key_path.name}.{os.getpid()}.tmp")
            temporary_key.write_text(secrets.token_urlsafe(32) + "\n", encoding="utf-8")
            os.chmod(temporary_key, 0o600)
            os.replace(temporary_key, key_path)
            environment["RE_CTM_OAUTH_PASSWORD"] = key_path.read_text(encoding="utf-8").strip()
        process = subprocess.Popen(
            [str(BIN_LINK), *session["command"]],
            cwd=session["cwd"],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=log_handle,
            start_new_session=True,
        )
        log_handle.close()
        port: int | None = None
        if "--port" in session["command"]:
            position = session["command"].index("--port")
            port = int(session["command"][position + 1])
        try:
            if port is not None and port > 0:
                wait_for_port(port, process, timeout=15)
            else:
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline and process.poll() is None:
                    if log_path.exists() and b"local MCP:" in log_path.read_bytes():
                        break
                    time.sleep(0.1)
                if process.poll() is not None:
                    raise RuntimeError("restarted session exited during startup")
        except Exception:
            if process.poll() is None:
                process.terminate()
            raise
        log_bytes = log_path.read_bytes() if log_path.exists() else b""
        unsafe_key_line = any(
            line.startswith(b"OAuth operator key:")
            and line.strip() != b"OAuth operator key: configured externally"
            for line in log_bytes.splitlines()
        )
        if unsafe_key_line:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
            raise RuntimeError("restarted session wrote an OAuth key into its log")
        restarted.append(
            {
                "pid": process.pid,
                "mode": session["command"][0],
                "port": port,
                "cwd": session["cwd"],
                "log_path": str(log_path),
                "executable": str((Path("/proc") / str(process.pid) / "exe").resolve()),
                "operator_key_source": key_source,
                "operator_key_file": str(key_path) if key_path is not None else None,
                "log_secret_free": True,
            }
        )
    return restarted


def main() -> int:
    validate_candidate()
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout.strip()
    if head != CANDIDATE_COMMIT:
        raise RuntimeError(f"live cutover requires candidate commit {CANDIDATE_COMMIT}, got {head}")
    status_lines = subprocess.run(
        ["git", "status", "--porcelain"], cwd=ROOT, stdout=subprocess.PIPE, text=True, check=True
    ).stdout.splitlines()
    allowed_dirty = {
        "scripts/run_mtm008_live_cutover.py",
        "scripts/validate_mtm008_live_evidence.py",
    }
    unexpected_dirty = []
    for line in status_lines:
        path = line[3:].strip()
        if path not in allowed_dirty:
            unexpected_dirty.append(line)
    if unexpected_dirty:
        raise RuntimeError(f"live cutover has unexpected candidate worktree changes: {unexpected_dirty}")
    if STATE_ROOT.exists():
        raise RuntimeError(f"live deployment root already exists: {STATE_ROOT}")
    build_release()
    validate_rust_release(RUST_BINARY, VERSION)
    wheel = build_permanent_wheel()
    sessions = discover_python_sessions()
    if not sessions:
        raise RuntimeError("no live Python Re-CTM session was found to transfer")
    safe_session_summary = [
        {
            "mode": item["command"][0],
            "port": (
                int(item["command"][item["command"].index("--port") + 1])
                if "--port" in item["command"]
                else None
            ),
            "cwd": item["cwd"],
            "environment_key_count": len(item["environment"]),
        }
        for item in sessions
    ]
    stopped = stop_sessions(sessions)
    layout = DeploymentLayout(BIN_LINK, STATE_ROOT)
    deployment = cutover(RUST_BINARY, layout, VERSION, ROLLBACK_WHEEL)
    with tempfile.TemporaryDirectory(prefix="mtm008-live-probe-") as directory:
        root = Path(directory)
        rust_probe = probe(BIN_LINK.resolve(), root, "rust-live")
        rolled = rollback(layout.manifest)
        python_probe = probe(BIN_LINK.resolve(), root, "python-rollback")
        active = recutover(layout.manifest)
        rust_recutover_probe = probe(BIN_LINK.resolve(), root, "rust-recutover")
    restarted = restart_sessions(sessions)
    time.sleep(1.0)
    restarted_alive = all((Path("/proc") / str(item["pid"])).exists() for item in restarted)
    restarted_rust = all(
        Path(item["executable"]).resolve() == Path(active["release"]["path"]).resolve()
        for item in restarted
    )
    python_remaining = len(discover_python_sessions())
    checks = [
        {"name": "candidate_commit_clean", "passed": True},
        {"name": "rollback_wheel_persisted", "passed": ROLLBACK_WHEEL.is_file()},
        {"name": "python_sessions_stopped", "passed": stopped["remaining_count"] == 0},
        {"name": "live_rust_cutover", "passed": deployment["state"] == "rust_active" and rust_probe["passed"]},
        {"name": "live_python_rollback", "passed": rolled["state"] == "previous_active" and python_probe["passed"]},
        {"name": "live_rust_recutover", "passed": active["state"] == "rust_active" and rust_recutover_probe["passed"]},
        {"name": "sessions_restarted_on_rust", "passed": restarted_alive and restarted_rust and len(restarted) == len(sessions)},
        {"name": "session_logs_secret_free", "passed": all(item["log_secret_free"] for item in restarted)},
        {"name": "no_python_re_ctm_process", "passed": python_remaining == 0},
        {"name": "live_command_release_identity", "passed": run_json(BIN_LINK.resolve(), "release-info").get("implementation") == "rust"},
    ]
    report = {
        "schema_version": "1.0.0",
        "project": "MTM-reboot",
        "milestone": "MTM-008",
        "phase": "live_cutover",
        "passed": all(item["passed"] for item in checks),
        "implementation_sha256": implementation_sha256(),
        "candidate_commit": CANDIDATE_COMMIT,
        "checks": checks,
        "release": active["release"],
        "rollback_wheel": wheel,
        "deployment": public_summary(load_manifest(layout.manifest)),
        "transferred_sessions": safe_session_summary,
        "shutdown": stopped,
        "restarted_sessions": restarted,
        "production_authority_changed": True,
        "production_authority": "rust",
        "python_tool_root_retained": PYTHON_TOOL_ROOT.exists(),
        "environment": {
            "platform": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "sensitive_content_recorded": False,
    }
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
