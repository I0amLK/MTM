#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import run_mtm007_target_validation as target_validation
from mtm008_runtime_harness import oauth_token


VERSION = "0.4.0"
SOURCE_COMMIT = "fcdc0cd09bb0852e46bb8cdc37de3b81ccff27e3"
BINARY = ROOT / "target" / "release" / "mtm"
EXPECTED_BINARY_SHA256 = "3312ca75a1de8707e740963cc0add4b09430dccc9dc63a3145e4456ff2b0cdf3"
LIVE_DATA_ROOT = Path("/home/lk/.mtm")
REPORT = ROOT / "records/evidence/MTM-013/stable-qualification.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_json(executable: Path, *args: str, env: dict[str, str] | None = None) -> dict[str, Any]:
    completed = subprocess.run(
        [str(executable), *args],
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=True,
    )
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict):
        raise RuntimeError(f"{executable} {' '.join(args)} returned non-object JSON")
    return payload


def check_config(executable: Path, override: int | None) -> dict[str, Any]:
    environment = os.environ.copy()
    environment["HOME"] = "/home/lk"
    if override is None:
        environment.pop("MTM_WORKFLOW_PROTOCOL_VERSION", None)
    else:
        environment["MTM_WORKFLOW_PROTOCOL_VERSION"] = str(override)
    return run_json(executable, "check-config", env=environment)


def sqlite_backup(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_uri = f"file:{source}?mode=ro"
    with sqlite3.connect(source_uri, uri=True) as source_db, sqlite3.connect(destination) as target_db:
        source_db.backup(target_db)


def clone_existing_state(destination: Path) -> dict[str, int]:
    if not LIVE_DATA_ROOT.is_dir():
        raise RuntimeError(f"live data root is missing: {LIVE_DATA_ROOT}")
    destination.mkdir(parents=True, exist_ok=True)
    private = destination / "private"
    private.mkdir(parents=True, exist_ok=True)
    sqlite_backup(LIVE_DATA_ROOT / "oauth.sqlite3", destination / "oauth.sqlite3")
    sqlite_backup(LIVE_DATA_ROOT / "private" / "state.sqlite3", private / "state.sqlite3")
    return {
        "source_bytes": sum(path.stat().st_size for path in LIVE_DATA_ROOT.rglob("*") if path.is_file()),
        "oauth_backup_bytes": (destination / "oauth.sqlite3").stat().st_size,
        "state_backup_bytes": (private / "state.sqlite3").stat().st_size,
    }


def process_facts(pid: int) -> dict[str, int]:
    status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    facts: dict[str, int] = {}
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            facts["rss_kib"] = int(line.split()[1])
        elif line.startswith("Threads:"):
            facts["threads"] = int(line.split()[1])
    facts["fds"] = len(list(Path(f"/proc/{pid}/fd").iterdir()))
    return facts


def stable_identity(executable: Path) -> bool:
    info = run_json(executable, "release-info")
    expected = {
        "name": "mtm",
        "version": VERSION,
        "implementation": "rust",
        "production_authority": "rust",
        "python_runtime_required": False,
        "public_tool_count": 24,
        "hidden_alias_count": 11,
        "state_schema_version": 2,
        "workflow_protocol_version": 3,
    }
    return all(info.get(key) == value for key, value in expected.items())


def clean_clone_install(root: Path) -> dict[str, Any]:
    clone = root / "clean-clone"
    install_root = root / "clean-install"
    subprocess.run(
        ["git", "clone", "--local", "--no-hardlinks", "--quiet", str(ROOT), str(clone)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
        check=True,
    )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=clone,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        check=True,
    ).stdout.strip()
    if head != SOURCE_COMMIT:
        raise RuntimeError(f"clean clone resolved {head}, expected {SOURCE_COMMIT}")
    cargo = ROOT / ".toolchain" / "rustup" / "toolchains" / "1.98.0-x86_64-unknown-linux-gnu" / "bin" / "cargo"
    rustc = ROOT / ".toolchain" / "rustup" / "toolchains" / "1.98.0-x86_64-unknown-linux-gnu" / "bin" / "rustc"
    toolchain_bin = cargo.parent
    environment = os.environ.copy()
    environment["CARGO_HOME"] = str(ROOT / ".toolchain" / "cargo")
    environment["RUSTUP_HOME"] = str(ROOT / ".toolchain" / "rustup")
    environment["RUSTC"] = str(rustc)
    environment["PATH"] = os.pathsep.join([str(toolchain_bin), environment.get("PATH", "")])
    subprocess.run(
        [
            str(cargo),
            "install",
            "--path",
            str(clone / "crates" / "mtm-cli"),
            "--locked",
            "--root",
            str(install_root),
            "--force",
        ],
        cwd=clone,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=300,
        check=True,
    )
    installed = install_root / "bin" / "mtm"
    return {
        "source_commit": head,
        "version": subprocess.run(
            [str(installed), "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip(),
        "identity_ok": stable_identity(installed),
        "binary_sha256": sha256_file(installed),
    }


def existing_state_upgrade(root: Path) -> dict[str, Any]:
    copied = root / "copied-live-state"
    backup = clone_existing_state(copied)
    workspace = root / "upgrade-workspace"
    workspace.mkdir()
    server = target_validation.ReleaseServer(
        workspace,
        copied,
        backend="disabled",
        latex_policy="static_only",
    )
    try:
        info = target_validation.structured(server.call("server_info", {}))
        status = target_validation.structured(
            server.call("rethlas_inspect", {"operation": "projects", "limit": 5})
        )
        return {
            **backup,
            "server_version": info.get("version"),
            "state_schema_version": info.get("research_workspace", {}).get("state_schema_version"),
            "workflow_protocol_version": info.get("research_workspace", {}).get("workflow_protocol_version"),
            "production_default": info.get("research_workspace", {}).get(
                "production_default_workflow_protocol_version"
            ),
            "complete_flow_locally_validated": info.get("complete_flow_locally_validated"),
            "projects_query_ok": status.get("ok") is not False,
        }
    finally:
        exit_code = server.close()
        if exit_code != 0:
            raise RuntimeError(f"copied-state upgrade server exited {exit_code}")


def proof_finalization(root: Path) -> dict[str, Any]:
    workspace = root / "proof-workspace"
    workspace.mkdir()
    data_root = root / "proof-data"
    server = target_validation.ReleaseServer(
        workspace,
        data_root,
        backend="bubblewrap",
        latex_policy="required",
    )
    try:
        result = target_validation.drive_compact_workflow(server)
        return result
    finally:
        exit_code = server.close()
        if exit_code != 0:
            raise RuntimeError(f"proof finalization server exited {exit_code}")


def bounded_soak(root: Path) -> dict[str, Any]:
    workspace = root / "soak-workspace"
    workspace.mkdir()
    data_root = root / "soak-data"
    server = target_validation.ReleaseServer(
        workspace,
        data_root,
        backend="disabled",
        latex_policy="static_only",
    )
    started = time.monotonic()
    before = process_facts(server.process.pid)
    requests = 0
    try:
        while time.monotonic() - started < 10.0:
            result = server.call("server_info", {})
            if result.get("isError") is True:
                raise RuntimeError("server_info failed during stable soak")
            requests += 1
        after = process_facts(server.process.pid)
        return {
            "duration_seconds": round(time.monotonic() - started, 3),
            "requests": requests,
            "rss_kib_before": before.get("rss_kib", 0),
            "rss_kib_after": after.get("rss_kib", 0),
            "threads_before": before.get("threads", 0),
            "threads_after": after.get("threads", 0),
            "fds_before": before.get("fds", 0),
            "fds_after": after.get("fds", 0),
        }
    finally:
        exit_code = server.close()
        if exit_code != 0:
            raise RuntimeError(f"soak server exited {exit_code}")


def run_sub_evidence(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    hardening_report = root / "stable-hardening.json"
    environment = os.environ.copy()
    environment["MTM013_BINARY"] = str(BINARY)
    environment["MTM013_HARDENING_REPORT"] = str(hardening_report)
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "run_mtm013_runtime_hardening.py")],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
        check=True,
    )
    hardening = json.loads(hardening_report.read_text(encoding="utf-8"))

    tui_report = root / "stable-tui.json"
    environment = os.environ.copy()
    environment["MTM012_BINARY"] = str(BINARY)
    environment["MTM012_TUI_REPORT"] = str(tui_report)
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "run_mtm012_tui_validation.py")],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
        check=True,
    )
    tui = json.loads(tui_report.read_text(encoding="utf-8"))
    return hardening, tui


def main() -> int:
    if not BINARY.is_file() or sha256_file(BINARY) != EXPECTED_BINARY_SHA256:
        raise RuntimeError("stable release binary does not match the frozen MTM-013 artifact")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        check=True,
    ).stdout.strip()
    if head != SOURCE_COMMIT:
        raise RuntimeError(f"stable qualification requires source commit {SOURCE_COMMIT}, got {head}")

    target_validation.RELEASE_BINARY = BINARY
    with tempfile.TemporaryDirectory(prefix="mtm013-stable-") as directory:
        root = Path(directory)
        clean_install = clean_clone_install(root)
        existing_upgrade = existing_state_upgrade(root)
        proof = proof_finalization(root)
        soak = bounded_soak(root)
        hardening, tui = run_sub_evidence(root)

    default_config = check_config(BINARY, None)
    rollback_config = check_config(BINARY, 2)
    checks = {
        "stable_release_identity": stable_identity(BINARY),
        "clean_clone_install": clean_install.get("identity_ok") is True
        and clean_install.get("version") == "mtm 0.4.0",
        "copied_existing_state_opens": existing_upgrade.get("server_version") == VERSION
        and existing_upgrade.get("state_schema_version") == 2
        and existing_upgrade.get("projects_query_ok") is True,
        "copied_state_keeps_protocol3_default": existing_upgrade.get("workflow_protocol_version") == 3
        and existing_upgrade.get("production_default") == 3,
        "copied_state_reports_complete_flow_validated": existing_upgrade.get(
            "complete_flow_locally_validated"
        )
        is True,
        "proof_finalization_reaches_done": proof.get("final_exists") is True
        and proof.get("final_contains_document") is True
        and proof.get("export_relative") is True,
        "stable_default_protocol3": default_config.get("workflow_protocol_version") == 3,
        "stable_explicit_protocol2": rollback_config.get("workflow_protocol_version") == 2,
        "release_capability_hardening": hardening.get("ok") is True
        and len(hardening.get("checks", {})) >= 12
        and all(hardening.get("checks", {}).values()),
        "release_tui_non_regression": tui.get("ok") is True
        and tui.get("version") == VERSION
        and len(tui.get("checks", {})) == 20
        and all(tui.get("checks", {}).values()),
        "bounded_soak_requests": soak.get("duration_seconds", 0) >= 9.5
        and soak.get("requests", 0) >= 100,
        "bounded_soak_threads_stable": soak.get("threads_after", 0)
        <= soak.get("threads_before", 0) + 1,
        "bounded_soak_fds_stable": soak.get("fds_after", 0) <= soak.get("fds_before", 0) + 2,
        "bounded_soak_rss": soak.get("rss_kib_after", 0) <= soak.get("rss_kib_before", 0) + 16_384,
    }
    payload = {
        "schema_version": "1.0.0",
        "milestone": "MTM-013",
        "phase": "stable_0_4_0_qualification",
        "version": VERSION,
        "source_commit": SOURCE_COMMIT,
        "binary_sha256": sha256_file(BINARY),
        "checks": checks,
        "clean_install": clean_install,
        "existing_state_upgrade": existing_upgrade,
        "proof_finalization": {
            "run_id_present": proof.get("run_id_present"),
            "states": proof.get("states"),
            "final_exists": proof.get("final_exists"),
            "final_contains_document": proof.get("final_contains_document"),
            "export_relative": proof.get("export_relative"),
        },
        "soak": soak,
        "hardening_check_count": len(hardening.get("checks", {})),
        "tui_check_count": len(tui.get("checks", {})),
        "public_github_install": {
            "status": "pending_push_credentials",
            "local_clean_clone_exact_commit_passed": clean_install.get("source_commit") == SOURCE_COMMIT,
        },
        "raw_capability_recorded": False,
        "raw_oauth_token_recorded": False,
        "raw_proof_recorded": False,
        "ok": all(checks.values()),
    }
    REPORT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
