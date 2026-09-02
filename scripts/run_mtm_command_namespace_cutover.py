#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

try:
    from scripts.mtm008_deployment import DeploymentLayout, cutover, load_manifest, run_json, run_version, sha256_file
    from scripts.mtm008_runtime_harness import ROOT, RUST_BINARY, build_release, prepare_workspace, free_port, wait_for_port
except ModuleNotFoundError:
    from mtm008_deployment import DeploymentLayout, cutover, load_manifest, run_json, run_version, sha256_file
    from mtm008_runtime_harness import ROOT, RUST_BINARY, build_release, prepare_workspace, free_port, wait_for_port


HOME = Path("/home/lk")
REPORT = ROOT / "mtm-command-namespace.json"
MTM_BIN = HOME / ".local" / "bin" / "mtm"
RE_CTM_BIN = HOME / ".local" / "bin" / "re-ctm"
MTM_STATE_ROOT = HOME / ".local" / "share" / "mtm"
OLD_MTM_ROOT = HOME / ".local" / "share" / "re-ctm-rust"
RE_CTM_WHEEL = OLD_MTM_ROOT / "rollback" / "re_ctm-0.3.0-py3-none-any.whl"
RE_CTM_TOOL_ROOT = HOME / ".local" / "share" / "uv" / "tools" / "re-ctm"
VERSION = "0.3.0"
EXPECTED_SESSIONS = 4
IMPLEMENTATION_FILES = [
    ROOT / "crates" / "mtm-cli" / "Cargo.toml",
    ROOT / "crates" / "mtm-cli" / "src" / "main.rs",
    ROOT / "scripts" / "mtm008_deployment.py",
    ROOT / "scripts" / "run_mtm_command_namespace_cutover.py",
    ROOT / "scripts" / "validate_mtm_command_namespace.py",
]


def implementation_sha256() -> str:
    digest = hashlib.sha256()
    for path in sorted(IMPLEMENTATION_FILES):
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def session_record(pid: int) -> dict[str, Any] | None:
    base = Path("/proc") / str(pid)
    try:
        executable = (base / "exe").resolve()
        cwd = (base / "cwd").resolve()
        argv = [item.decode("utf-8", "replace") for item in (base / "cmdline").read_bytes().split(b"\0") if item]
        env_items = [item for item in (base / "environ").read_bytes().split(b"\0") if b"=" in item]
    except (FileNotFoundError, PermissionError, OSError):
        return None
    marker = next(
        (
            index
            for index, item in enumerate(argv)
            if item in {"mtm", "re-ctm"} or item.endswith("/mtm") or item.endswith("/re-ctm")
        ),
        None,
    )
    if marker is None or marker + 1 >= len(argv):
        return None
    command = argv[marker + 1 :]
    if not command or command[0] not in {"serve", "tui"}:
        return None
    environment: dict[str, str] = {}
    for item in env_items:
        key, value = item.split(b"=", 1)
        key_text = key.decode("utf-8", "replace")
        if key_text.startswith("RE_CTM_") or key_text in {"LANG", "LC_ALL", "LC_CTYPE", "TMPDIR"}:
            environment[key_text] = value.decode("utf-8", "replace")
    return {
        "pid": pid,
        "executable": str(executable),
        "cwd": str(cwd),
        "command": command,
        "environment": environment,
    }


def discover_sessions() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for item in Path("/proc").iterdir():
        if not item.name.isdigit():
            continue
        record = session_record(int(item.name))
        if record is not None:
            records.append(record)
    return sorted(records, key=lambda item: int(item["pid"]))


def descendants(roots: set[int]) -> set[int]:
    parent_map: dict[int, int] = {}
    for item in Path("/proc").iterdir():
        if not item.name.isdigit():
            continue
        try:
            fields = (item / "stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()
            parent_map[int(item.name)] = int(fields[1])
        except (FileNotFoundError, PermissionError, OSError, ValueError, IndexError):
            continue
    result = set(roots)
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


def stop_sessions(sessions: list[dict[str, Any]]) -> dict[str, int]:
    owned = descendants({int(item["pid"]) for item in sessions})
    for session in sessions:
        try:
            os.kill(int(session["pid"]), signal.SIGINT)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and alive(owned):
        time.sleep(0.1)
    term = alive(owned)
    for pid in term:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and alive(owned):
        time.sleep(0.1)
    remaining = alive(owned)
    if remaining:
        raise RuntimeError(f"MTM session descendants remain after shutdown: {len(remaining)}")
    return {"owned": len(owned), "sigterm": len(term), "remaining": 0}


def verify_re_ctm_wheel() -> None:
    if not RE_CTM_WHEEL.is_file():
        raise RuntimeError(f"Re-CTM rollback wheel is missing: {RE_CTM_WHEEL}")
    uv = shutil.which("uv")
    if uv is None:
        raise RuntimeError("uv is required to restore Re-CTM")
    with tempfile.TemporaryDirectory(prefix="mtm-namespace-rectm-") as directory:
        root = Path(directory)
        env = os.environ.copy()
        env.update({"UV_TOOL_DIR": str(root / "tools"), "UV_TOOL_BIN_DIR": str(root / "bin")})
        subprocess.run(
            [uv, "tool", "install", "--force", "--from", str(RE_CTM_WHEEL), "re-ctm"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
            check=True,
        )
        restored = root / "bin" / "re-ctm"
        if run_version(restored.resolve()) != "re-ctm 0.3.0":
            raise RuntimeError("restored Re-CTM wheel identity mismatch")


def install_re_ctm() -> None:
    uv = shutil.which("uv")
    if uv is None:
        raise RuntimeError("uv is required to install Re-CTM")
    if RE_CTM_BIN.is_symlink() or RE_CTM_BIN.exists():
        RE_CTM_BIN.unlink()
    environment = os.environ.copy()
    environment.update(
        {
            "UV_TOOL_DIR": str(HOME / ".local" / "share" / "uv" / "tools"),
            "UV_TOOL_BIN_DIR": str(HOME / ".local" / "bin"),
        }
    )
    subprocess.run(
        [uv, "tool", "install", "--force", "--from", str(RE_CTM_WHEEL), "re-ctm"],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=300,
        check=True,
    )
    if run_version(RE_CTM_BIN.resolve()) != "re-ctm 0.3.0":
        raise RuntimeError("installed Re-CTM identity mismatch")


def recovered_session_specs() -> list[dict[str, Any]]:
    old_session_root = OLD_MTM_ROOT / "sessions"
    new_session_root = MTM_STATE_ROOT / "sessions"
    new_session_root.mkdir(parents=True, exist_ok=True)
    os.chmod(new_session_root, 0o700)

    def password_for(index: int) -> str:
        old_key = old_session_root / f"session-{index}.operator-key"
        if old_key.is_file():
            return old_key.read_text(encoding="utf-8").strip()
        key_path = new_session_root / f"session-{index}.operator-key"
        if not key_path.exists():
            temporary = key_path.with_name(f".{key_path.name}.{os.getpid()}.tmp")
            temporary.write_text(secrets.token_urlsafe(32) + "\n", encoding="utf-8")
            os.chmod(temporary, 0o600)
            os.replace(temporary, key_path)
        return key_path.read_text(encoding="utf-8").strip()

    return [
        {
            "pid": 0,
            "cwd": "/home/lk/桌面/re-test",
            "command": ["tui", "--quick-tunnel", "--native-mode", "dangerous"],
            "environment": {"RE_CTM_OAUTH_PASSWORD": password_for(1)},
        },
        {
            "pid": 0,
            "cwd": "/home/lk/桌面/tempcoding/Re-CTM",
            "command": [
                "serve", "--host", "127.0.0.1", "--port", "48991",
                "--workspace", "/home/lk/桌面/tempcoding/Re-CTM",
                "--native-mode", "safe", "--latex-policy", "required",
            ],
            "environment": {"RE_CTM_OAUTH_PASSWORD": password_for(2)},
        },
        {
            "pid": 0,
            "cwd": "/home/lk/桌面/re-test",
            "command": ["serve", "--host", "127.0.0.1", "--port", "44567", "--native-mode", "dangerous"],
            "environment": {"RE_CTM_OAUTH_PASSWORD": password_for(3)},
        },
        {
            "pid": 0,
            "cwd": "/home/lk/桌面/re-test",
            "command": ["serve", "--host", "127.0.0.1", "--port", "34569", "--native-mode", "dangerous"],
            "environment": {"RE_CTM_OAUTH_PASSWORD": password_for(4)},
        },
    ]


def restart_sessions(sessions: list[dict[str, Any]], release: Path) -> list[dict[str, Any]]:
    root = MTM_STATE_ROOT / "sessions"
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    restarted: list[dict[str, Any]] = []
    for index, session in enumerate(sessions, 1):
        env = {key: value for key, value in os.environ.items() if not key.startswith("RE_CTM_")}
        env.update(session["environment"])
        if not env.get("RE_CTM_OAUTH_PASSWORD"):
            raise RuntimeError("captured MTM session lacks an operator key; refusing background restart")
        log_path = root / f"session-{index}.log"
        with log_path.open("wb", buffering=0) as log:
            os.chmod(log_path, 0o600)
            process = subprocess.Popen(
                [str(MTM_BIN), *session["command"]],
                cwd=session["cwd"],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
                start_new_session=True,
            )
        port: int | None = None
        if "--port" in session["command"]:
            pos = session["command"].index("--port")
            port = int(session["command"][pos + 1])
        if port is not None and port > 0:
            wait_for_port(port, process, timeout=15)
        else:
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and process.poll() is None:
                if log_path.exists() and b"local MCP:" in log_path.read_bytes():
                    break
                time.sleep(0.1)
            if process.poll() is not None:
                raise RuntimeError("MTM TUI session exited during restart")
        executable = (Path("/proc") / str(process.pid) / "exe").resolve()
        if executable != release.resolve():
            raise RuntimeError("restarted MTM session is not using the selected release")
        restarted.append({"pid": process.pid, "mode": session["command"][0], "port": port, "cwd": session["cwd"]})
    return restarted


def probe_re_ctm() -> bool:
    with tempfile.TemporaryDirectory(prefix="mtm-namespace-rectm-probe-") as directory:
        root = Path(directory)
        workspace = root / "workspace"
        prepare_workspace(workspace)
        port = free_port()
        env = os.environ.copy()
        env["RE_CTM_OAUTH_PASSWORD"] = "namespace-probe-operator-password-000000000000"
        process = subprocess.Popen(
            [str(RE_CTM_BIN), "serve", "--host", "127.0.0.1", "--port", str(port), "--workspace", str(workspace)],
            cwd=root,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            wait_for_port(port, process, timeout=15)
            return process.poll() is None
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def main() -> int:
    build_release()
    if run_version(RUST_BINARY) != "mtm 0.3.0":
        raise RuntimeError("MTM release binary has the wrong command identity")
    info = run_json(RUST_BINARY, "release-info")
    if info.get("name") != "mtm" or info.get("implementation") != "rust":
        raise RuntimeError("MTM release-info identity mismatch")
    verify_re_ctm_wheel()

    sessions = discover_sessions()
    recovered = False
    if not sessions:
        sessions = recovered_session_specs()
        recovered = True
    if len(sessions) != EXPECTED_SESSIONS:
        raise RuntimeError(f"expected {EXPECTED_SESSIONS} live MTM sessions, found {len(sessions)}")
    stopped = stop_sessions(sessions) if not recovered else {"owned": 0, "sigterm": 0, "remaining": 0}

    if MTM_STATE_ROOT.exists():
        deployment = load_manifest(MTM_STATE_ROOT / "deployment" / "deployment-v1.json")
    else:
        deployment = cutover(RUST_BINARY, DeploymentLayout(MTM_BIN, MTM_STATE_ROOT), VERSION)
    release = Path(str(deployment["release"]["path"]))
    install_re_ctm()
    restarted = restart_sessions(sessions, release)

    checks = [
        {"name": "mtm_command_unique", "passed": MTM_BIN.is_symlink() and MTM_BIN.resolve() == release.resolve()},
        {"name": "re_ctm_command_unique", "passed": RE_CTM_BIN.exists() and RE_CTM_BIN.resolve() != MTM_BIN.resolve()},
        {"name": "mtm_identity", "passed": run_version(MTM_BIN.resolve()) == "mtm 0.3.0"},
        {"name": "re_ctm_identity", "passed": run_version(RE_CTM_BIN.resolve()) == "re-ctm 0.3.0"},
        {"name": "mtm_release_info", "passed": run_json(MTM_BIN.resolve(), "release-info").get("name") == "mtm"},
        {"name": "re_ctm_server_probe", "passed": probe_re_ctm()},
        {"name": "mtm_sessions_restarted", "passed": len(restarted) == EXPECTED_SESSIONS},
        {"name": "old_mtm_selector_released", "passed": RE_CTM_BIN.resolve() != release.resolve()},
        {"name": "distinct_install_roots", "passed": MTM_STATE_ROOT.resolve() != RE_CTM_TOOL_ROOT.resolve()},
    ]
    report = {
        "schema_version": "1.0.0",
        "project": "MTM-reboot",
        "phase": "command_namespace_separation",
        "passed": all(item["passed"] for item in checks),
        "implementation_sha256": implementation_sha256(),
        "checks": checks,
        "mtm": {"command": str(MTM_BIN), "target": str(MTM_BIN.resolve()), "version": run_version(MTM_BIN.resolve()), "release_sha256": sha256_file(release)},
        "re_ctm": {"command": str(RE_CTM_BIN), "target": str(RE_CTM_BIN.resolve()), "version": run_version(RE_CTM_BIN.resolve())},
        "sessions": {"stopped": stopped, "restarted_count": len(restarted)},
        "recovery_after_partial_cutover": recovered,
        "historical_migration_root_retained": OLD_MTM_ROOT.exists(),
        "sensitive_content_recorded": False,
    }
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
