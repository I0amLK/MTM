#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

try:
    from scripts.mtm008_deployment import (
        DeploymentError,
        atomic_write_json,
        fsync_directory,
        install_release,
        load_manifest,
        manifest_layout,
        processes_using,
        public_summary,
        retire_python,
        rollback,
        run_json,
        run_version,
        sha256_file,
        utc_now,
        verify_active_rust,
    )
    from scripts.run_mtm008_candidate_validation import probe_server, restore_wheel
    from scripts.run_mtm008_live_cutover import (
        BIN_LINK,
        PYTHON_TOOL_ROOT,
        ROLLBACK_WHEEL,
        STATE_ROOT,
        VERSION,
        process_record,
        restart_sessions,
        stop_sessions,
    )
    from scripts.mtm008_runtime_harness import ROOT, RUST_BINARY, SOURCE_ROOT, build_release
    from scripts.validate_mtm008_candidate_evidence import validate as validate_candidate
    from scripts.validate_mtm008_live_evidence import validate as validate_live
except ModuleNotFoundError:
    from mtm008_deployment import (
        DeploymentError,
        atomic_write_json,
        fsync_directory,
        install_release,
        load_manifest,
        manifest_layout,
        processes_using,
        public_summary,
        retire_python,
        rollback,
        run_json,
        run_version,
        sha256_file,
        utc_now,
        verify_active_rust,
    )
    from run_mtm008_candidate_validation import probe_server, restore_wheel
    from run_mtm008_live_cutover import (
        BIN_LINK,
        PYTHON_TOOL_ROOT,
        ROLLBACK_WHEEL,
        STATE_ROOT,
        VERSION,
        process_record,
        restart_sessions,
        stop_sessions,
    )
    from mtm008_runtime_harness import ROOT, RUST_BINARY, SOURCE_ROOT, build_release
    from validate_mtm008_candidate_evidence import validate as validate_candidate
    from validate_mtm008_live_evidence import validate as validate_live


REPORT = ROOT / "mtm008-retirement.json"
INVENTORY = ROOT / "authority-inventory.json"
MANIFEST = STATE_ROOT / "deployment" / "deployment-v1.json"
HELPER_LINK = Path("/home/lk/.local/bin/re-ctm-native-helper")
QUALIFICATION_COMMIT = "b1601149d3dd555278bcd26ecda02f39a0600860"
EXPECTED_SESSION_COUNT = 4
IMPLEMENTATION_FILES = [
    ROOT / "scripts" / "mtm008_deployment.py",
    ROOT / "scripts" / "run_mtm008_live_cutover.py",
    ROOT / "scripts" / "run_mtm008_python_retirement.py",
    ROOT / "scripts" / "validate_mtm008_retirement_evidence.py",
]


def implementation_sha256() -> str:
    digest = hashlib.sha256()
    for path in sorted(IMPLEMENTATION_FILES):
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def git_output(*arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=True,
    ).stdout.strip()


def release_inputs_clean() -> bool:
    return not git_output(
        "status",
        "--porcelain",
        "--",
        "Cargo.toml",
        "Cargo.lock",
        "crates",
    )


def discover_rust_sessions(release_path: Path) -> list[dict[str, Any]]:
    release_path = release_path.resolve(strict=True)
    sessions: list[dict[str, Any]] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        record = process_record(int(entry.name))
        if record is None:
            continue
        try:
            executable = Path(record["executable"]).resolve(strict=True)
        except (FileNotFoundError, OSError):
            continue
        if executable == release_path:
            sessions.append(record)
    return sorted(sessions, key=lambda item: int(item["pid"]))


def backup_current_release(release_path: Path) -> dict[str, Any]:
    rollback_root = STATE_ROOT / "rollback"
    rollback_root.mkdir(parents=True, exist_ok=True)
    os.chmod(rollback_root, 0o700)
    backup = rollback_root / "re-ctm-rust-authoritative-before-retirement"
    temporary = backup.with_name(f".{backup.name}.{os.getpid()}.tmp")
    try:
        shutil.copyfile(release_path, temporary)
        os.chmod(temporary, 0o700)
        os.replace(temporary, backup)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "path": str(backup),
        "sha256": sha256_file(backup),
        "size_bytes": backup.stat().st_size,
        "version": run_version(backup),
    }


def update_manifest_release(
    manifest: dict[str, Any],
    release: dict[str, Any],
    rust_rollback: dict[str, Any],
) -> dict[str, Any]:
    manifest["release"] = release
    manifest["rust_rollback_release"] = rust_rollback
    manifest["state"] = "rust_active"
    manifest["updated_at"] = utc_now()
    manifest.setdefault("history", []).append(
        {
            "at": utc_now(),
            "action": "upgrade_release",
            "state": "rust_active",
            "release_sha256": release["sha256"],
        }
    )
    atomic_write_json(MANIFEST, manifest)
    return manifest


def restore_old_rust_after_failed_upgrade(
    sessions: list[dict[str, Any]],
    rollback_release: dict[str, Any],
) -> None:
    try:
        current_manifest = load_manifest(MANIFEST)
        current_release = Path(str(current_manifest.get("release", {}).get("path") or ""))
        if current_release.is_file():
            partial_sessions = discover_rust_sessions(current_release)
            if partial_sessions:
                stop_sessions(partial_sessions)
        layout = manifest_layout(current_manifest)
        restored = install_release(Path(rollback_release["path"]), layout, VERSION)
        current_manifest["release"] = restored
        current_manifest["state"] = "rust_active"
        current_manifest["updated_at"] = utc_now()
        current_manifest.setdefault("history", []).append(
            {"at": utc_now(), "action": "upgrade_rollback", "state": "rust_active"}
        )
        atomic_write_json(MANIFEST, current_manifest)
        verify_active_rust(layout, current_manifest)
        restart_sessions(sessions)
    except Exception as exc:  # pragma: no cover - catastrophic target recovery path
        raise RuntimeError("failed to restore the pre-retirement Rust release") from exc


def restore_wheel_after_retirement() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="mtm008-retired-wheel-") as directory:
        root = Path(directory)
        restored = restore_wheel(ROLLBACK_WHEEL, root)
        executable = root / "bin" / "re-ctm"
        probe = (
            probe_server(executable.resolve(), root, "python-retirement-restore")
            if restored["command_exists"]
            else {"passed": False, "exit_code": None}
        )
        return {
            "install_exit_code": restored["install_exit_code"],
            "command_exists": restored["command_exists"],
            "version": restored["version"],
            "server_probe_passed": probe["passed"]
            and probe["exit_code"] in {0, -15, 130, -2},
            "server_exit_code": probe["exit_code"],
        }


def remove_retired_helper_link() -> dict[str, Any]:
    if not HELPER_LINK.exists() and not HELPER_LINK.is_symlink():
        return {"removed": True, "previously_absent": True}
    if not HELPER_LINK.is_symlink():
        raise RuntimeError("legacy helper entry is not a symlink")
    target = os.readlink(HELPER_LINK)
    resolved = (
        (HELPER_LINK.parent / target).resolve(strict=False)
        if not os.path.isabs(target)
        else Path(target).resolve(strict=False)
    )
    python_root = PYTHON_TOOL_ROOT.resolve(strict=False)
    if resolved != python_root and python_root not in resolved.parents:
        raise RuntimeError("legacy helper symlink does not belong to the retired Python tool root")
    HELPER_LINK.unlink()
    fsync_directory(HELPER_LINK.parent)
    return {"removed": not HELPER_LINK.exists(), "previously_absent": False}


def dynamic_linkage_has_python(binary: Path) -> bool:
    completed = subprocess.run(
        ["ldd", str(binary)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
        check=False,
    )
    return "python" in completed.stdout.lower()


def session_logs_are_secret_free(restarted: list[dict[str, Any]]) -> bool:
    for item in restarted:
        path = Path(str(item["log_path"]))
        if not path.is_file() or (path.stat().st_mode & 0o777) != 0o600:
            return False
        for line in path.read_bytes().splitlines():
            if line.startswith(b"OAuth operator key:") and line.strip() != (
                b"OAuth operator key: configured externally"
            ):
                return False
    return True


def write_report(path: Path, payload: dict[str, Any], mode: int = 0o644) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    candidate = validate_candidate()
    live = validate_live()
    head = git_output("rev-parse", "HEAD")
    if head != QUALIFICATION_COMMIT:
        raise RuntimeError(f"retirement requires qualification commit {QUALIFICATION_COMMIT}")
    if not release_inputs_clean():
        raise RuntimeError("release inputs changed after qualification commit")

    build_release()
    candidate_payload = json.loads((ROOT / "mtm008-candidate-validation.json").read_text())
    expected_release_sha = str(candidate_payload["release_binary"]["sha256"])
    if sha256_file(RUST_BINARY) != expected_release_sha:
        raise RuntimeError("rebuilt release does not match the qualified candidate")

    manifest = load_manifest(MANIFEST)
    layout = manifest_layout(manifest)
    verify_active_rust(layout, manifest)
    old_release = Path(str(manifest["release"]["path"]))
    sessions = discover_rust_sessions(old_release)
    if len(sessions) != EXPECTED_SESSION_COUNT:
        raise RuntimeError(
            f"expected {EXPECTED_SESSION_COUNT} live Rust sessions, found {len(sessions)}"
        )
    rust_rollback = backup_current_release(old_release)
    shutdown = stop_sessions(sessions)

    try:
        final_release = install_release(RUST_BINARY, layout, VERSION)
        manifest = update_manifest_release(manifest, final_release, rust_rollback)
        verify_active_rust(layout, manifest)
        restarted = restart_sessions(sessions)
        if len(restarted) != len(sessions):
            raise RuntimeError("not every live session restarted on the final release")
    except Exception:
        restore_old_rust_after_failed_upgrade(sessions, rust_rollback)
        raise

    status = run_json(BIN_LINK.resolve(), "status")
    release_info = run_json(BIN_LINK.resolve(), "release-info")
    if status.get("production_authority") != "rust":
        raise RuntimeError("final live status does not report Rust authority")
    if status.get("milestone_state") != "authoritative":
        raise RuntimeError("final live status lost the authoritative MTM-008 phase")
    if release_info.get("implementation") != "rust" or release_info.get(
        "python_runtime_required"
    ) is not False:
        raise RuntimeError("final release identity is not the no-Python Rust runtime")

    manifest = retire_python(MANIFEST, PYTHON_TOOL_ROOT)
    helper_retirement = remove_retired_helper_link()
    manifest["retired_python_previous"] = manifest.get("previous")
    manifest["previous"] = {
        "kind": "retired_python_wheel",
        "version": manifest.get("retired_python_previous", {}).get("version"),
        "wheel_sha256": manifest.get("rollback_wheel", {}).get("sha256"),
    }
    manifest["updated_at"] = utc_now()
    atomic_write_json(MANIFEST, manifest)

    wheel_restore = restore_wheel_after_retirement()
    rollback_fail_closed = False
    try:
        rollback(MANIFEST)
    except DeploymentError:
        rollback_fail_closed = True

    final_release_path = Path(str(manifest["release"]["path"])).resolve(strict=True)
    current_sessions = discover_rust_sessions(final_release_path)
    session_exact = len(current_sessions) == EXPECTED_SESSION_COUNT and all(
        Path(item["executable"]).resolve(strict=True) == final_release_path
        for item in current_sessions
    )
    no_python_process = not processes_using(PYTHON_TOOL_ROOT)
    logs_safe = session_logs_are_secret_free(restarted)

    performance = json.loads((ROOT / "mtm008-performance.json").read_text())
    soak = json.loads((ROOT / "mtm008-soak.json").read_text())
    inventory = {
        "schema_version": "1.0.0",
        "project": "MTM-reboot",
        "milestone": "MTM-008",
        "production_authority": "rust",
        "production_command": str(BIN_LINK),
        "production_command_target": str(BIN_LINK.resolve()),
        "release": manifest["release"],
        "release_info": release_info,
        "runtime_authorities": {
            "contracts_policy": "rust",
            "native_process_isolation": "rust_plus_bubblewrap",
            "storage_capability": "rust",
            "oauth_mcp_http": "rust",
            "workflow_vault_verifier_finalizer": "rust",
            "runtime_adapters_operator_ui": "rust",
        },
        "python_production_runtime": {
            "retired": not PYTHON_TOOL_ROOT.exists(),
            "tool_root": str(PYTHON_TOOL_ROOT),
            "active_process_count": len(processes_using(PYTHON_TOOL_ROOT)),
            "legacy_helper_link_removed": helper_retirement["removed"],
            "historical_source_preserved": SOURCE_ROOT.is_dir(),
        },
        "rollback": {
            "wheel": manifest["rollback_wheel"],
            "isolated_restore_verified": wheel_restore,
            "legacy_selector_rollback_fails_closed": rollback_fail_closed,
            "pre_retirement_rust_release": rust_rollback,
        },
        "live_sessions": {
            "count": len(current_sessions),
            "exact_release": session_exact,
            "logs_secret_free": logs_safe,
        },
        "a6_claim": performance["claim"],
        "soak": {
            "duration_seconds": soak["duration_seconds"],
            "request_count": soak["request_count"],
            "request_errors": soak["request_errors"],
            "resources": soak["resources"],
        },
    }
    write_report(INVENTORY, inventory)

    checks = [
        {"name": "qualification_commit_exact", "passed": head == QUALIFICATION_COMMIT},
        {"name": "candidate_evidence_fresh", "passed": bool(candidate)},
        {"name": "live_cutover_evidence_fresh", "passed": bool(live)},
        {
            "name": "final_release_matches_qualified_candidate",
            "passed": final_release["sha256"] == expected_release_sha,
        },
        {
            "name": "live_sessions_stopped_for_upgrade",
            "passed": shutdown["remaining_count"] == 0,
        },
        {"name": "live_sessions_restarted_exact_release", "passed": session_exact},
        {
            "name": "final_status_reports_rust_authority",
            "passed": status.get("production_authority") == "rust"
            and status.get("milestone_state") == "authoritative",
        },
        {
            "name": "rollback_wheel_restored_after_retirement",
            "passed": wheel_restore["install_exit_code"] == 0
            and wheel_restore["command_exists"]
            and wheel_restore["version"] == "re-ctm 0.3.0"
            and wheel_restore["server_probe_passed"],
        },
        {"name": "python_tool_root_removed", "passed": not PYTHON_TOOL_ROOT.exists()},
        {
            "name": "legacy_python_helper_link_removed",
            "passed": helper_retirement["removed"],
        },
        {"name": "no_python_re_ctm_process", "passed": no_python_process},
        {
            "name": "deployment_manifest_retired",
            "passed": manifest.get("state") == "rust_active_python_retired"
            and manifest.get("python_runtime_retired", {}).get("removed") is True,
        },
        {
            "name": "rollback_wheel_retained",
            "passed": ROLLBACK_WHEEL.is_file()
            and sha256_file(ROLLBACK_WHEEL) == manifest["rollback_wheel"]["sha256"],
        },
        {
            "name": "release_has_no_python_linkage",
            "passed": not dynamic_linkage_has_python(final_release_path),
        },
        {"name": "historical_source_preserved", "passed": SOURCE_ROOT.is_dir()},
        {"name": "session_logs_secret_free", "passed": logs_safe},
        {"name": "legacy_selector_rollback_fails_closed", "passed": rollback_fail_closed},
    ]
    passed = all(item["passed"] for item in checks)
    report = {
        "schema_version": "1.0.0",
        "project": "MTM-reboot",
        "milestone": "MTM-008",
        "phase": "python_retirement",
        "passed": passed,
        "implementation_sha256": implementation_sha256(),
        "qualification_commit": QUALIFICATION_COMMIT,
        "checks": checks,
        "release": final_release,
        "deployment": public_summary(manifest),
        "session_upgrade": {
            "captured_count": len(sessions),
            "shutdown": shutdown,
            "restarted_count": len(restarted),
            "exact_release": session_exact,
            "logs_secret_free": logs_safe,
        },
        "wheel_restore": wheel_restore,
        "helper_retirement": helper_retirement,
        "authority_inventory": str(INVENTORY),
        "environment": {
            "platform": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "production_authority": "rust",
        "python_production_runtime_retired": not PYTHON_TOOL_ROOT.exists(),
        "sensitive_content_recorded": False,
    }
    write_report(REPORT, report)
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
