#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from mtm008_deployment import (
    MANIFEST_SCHEMA,
    DeploymentError,
    DeploymentLayout,
    atomic_symlink,
    atomic_write_json,
    fsync_directory,
    install_release,
    load_manifest,
    run_json,
    run_version,
    sha256_file,
    utc_now,
    validate_rust_release,
    verify_active_rust,
)
from validate_mtm013_public_install import validate as validate_public_install


ROOT = Path(__file__).resolve().parents[1]
HOME = Path("/home/lk")
VERSION = "0.4.0"
EXPECTED_PROTOCOL = 3
SOURCE_COMMIT = "fcdc0cd09bb0852e46bb8cdc37de3b81ccff27e3"
BINARY = ROOT / "target" / "release" / "mtm"
EXPECTED_BINARY_SHA256 = "3312ca75a1de8707e740963cc0add4b09430dccc9dc63a3145e4456ff2b0cdf3"
ROLLBACK_VERSION = "0.4.0-preview.3"
ROLLBACK_PROTOCOL = 3
ROLLBACK_SHA256 = "545ab9ef8cc01edf804581cb52c2b1a4158d03bd8a25ea00c7785039167f3659"
QUALIFICATION = ROOT / "mtm013-stable-qualification.json"
QUALIFICATION_SHA256 = "94b57b08d10f268d9f13b63c32478a5888ec6034ddeae8ef807d06357fa18412"
RESOURCE = ROOT / "mtm013-stable-resource.json"
RESOURCE_SHA256 = "73629371264f0be12eb8c6cc138d4009483d78ab796487fa56c1596815a8e1d2"
PUBLIC_INSTALL = ROOT / "mtm013-public-install.json"
REPORT = ROOT / "mtm013-stable-release.json"
CARGO_COMMAND = HOME / ".cargo" / "bin" / "mtm"
LAYOUT = DeploymentLayout(
    bin_link=HOME / ".local" / "bin" / "mtm",
    state_root=HOME / ".local" / "share" / "mtm",
)
ROLLBACK_BINARY = LAYOUT.releases_root / ROLLBACK_VERSION / "mtm"
CARGO_ROLLBACK = LAYOUT.rollback_root / "mtm-preview3-cargo"


def check_config(executable: Path, override: int | None) -> dict[str, Any]:
    environment = os.environ.copy()
    environment["HOME"] = str(HOME)
    if override is None:
        environment.pop("MTM_WORKFLOW_PROTOCOL_VERSION", None)
    else:
        environment["MTM_WORKFLOW_PROTOCOL_VERSION"] = str(override)
    completed = subprocess.run(
        [str(executable), "check-config"],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        check=True,
    )
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise DeploymentError("check-config did not return an accepted object")
    return payload


def expected_identity(path: Path, version: str) -> dict[str, Any]:
    info = run_json(path, "release-info")
    expected = {
        "name": "mtm",
        "version": version,
        "implementation": "rust",
        "production_authority": "rust",
        "python_runtime_required": False,
        "public_tool_count": 24,
        "hidden_alias_count": 11,
        "state_schema_version": 2,
        "workflow_protocol_version": 3,
    }
    mismatches = {key: (expected_value, info.get(key)) for key, expected_value in expected.items() if info.get(key) != expected_value}
    if mismatches:
        raise DeploymentError(f"MTM command identity mismatch: {mismatches}")
    return info


def atomic_copy_executable(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    try:
        shutil.copyfile(source, temporary)
        os.chmod(temporary, 0o755)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        fsync_directory(destination.parent)
    finally:
        temporary.unlink(missing_ok=True)


def preserve_cargo_preview3() -> dict[str, Any]:
    if not CARGO_COMMAND.is_file():
        raise DeploymentError("login-shell-preferred ~/.cargo/bin/mtm is missing")
    expected_identity(CARGO_COMMAND, ROLLBACK_VERSION)
    LAYOUT.rollback_root.mkdir(parents=True, exist_ok=True)
    atomic_copy_executable(CARGO_COMMAND, CARGO_ROLLBACK)
    return {
        "path": str(CARGO_ROLLBACK),
        "sha256": sha256_file(CARGO_ROLLBACK),
        "version": run_version(CARGO_ROLLBACK),
    }


def accepted_selector_rollback() -> dict[str, Any]:
    if not ROLLBACK_BINARY.is_file():
        raise DeploymentError(f"preview.3 rollback binary is missing: {ROLLBACK_BINARY}")
    validate_rust_release(ROLLBACK_BINARY, ROLLBACK_VERSION, ROLLBACK_PROTOCOL)
    actual_sha = sha256_file(ROLLBACK_BINARY)
    if actual_sha != ROLLBACK_SHA256:
        raise DeploymentError(f"preview.3 rollback hash mismatch: {actual_sha}")
    return {
        "kind": "symlink",
        "target": str(ROLLBACK_BINARY),
        "resolved_target": str(ROLLBACK_BINARY.resolve(strict=True)),
        "version": run_version(ROLLBACK_BINARY),
        "sha256": actual_sha,
    }


def verify_pair(selector_target: Path, cargo_version: str, default_protocol: int) -> None:
    if not LAYOUT.bin_link.is_symlink() or LAYOUT.bin_link.resolve(strict=True) != selector_target.resolve(strict=True):
        raise DeploymentError("versioned MTM selector does not resolve to the expected release")
    expected_identity(LAYOUT.bin_link.resolve(strict=True), cargo_version)
    expected_identity(CARGO_COMMAND, cargo_version)
    if check_config(CARGO_COMMAND, None).get("workflow_protocol_version") != default_protocol:
        raise DeploymentError("login-shell MTM command selected the wrong default protocol")


def main() -> int:
    if not BINARY.is_file() or sha256_file(BINARY) != EXPECTED_BINARY_SHA256:
        raise DeploymentError("stable release binary is missing or differs from qualification")
    validate_rust_release(BINARY, VERSION, EXPECTED_PROTOCOL)
    if sha256_file(QUALIFICATION) != QUALIFICATION_SHA256:
        raise DeploymentError("stable qualification report drifted")
    if sha256_file(RESOURCE) != RESOURCE_SHA256:
        raise DeploymentError("stable resource report drifted")
    public_payload = json.loads(PUBLIC_INSTALL.read_text(encoding="utf-8"))
    public_summary = validate_public_install(public_payload)
    if public_summary.get("source_commit") != SOURCE_COMMIT:
        raise DeploymentError("public installation is not bound to the frozen source")

    previous = accepted_selector_rollback()
    if not LAYOUT.bin_link.is_symlink() or LAYOUT.bin_link.resolve(strict=True) != ROLLBACK_BINARY.resolve(strict=True):
        raise DeploymentError("pre-stable selector is not the accepted preview.3 rollback release")
    cargo_previous = preserve_cargo_preview3()
    old_manifest = load_manifest(LAYOUT.manifest)
    release = install_release(BINARY, LAYOUT, VERSION, EXPECTED_PROTOCOL)
    now = utc_now()
    history = list(old_manifest.get("history") or [])
    history.append({"at": now, "action": "stable_0_4_0_cutover", "state": "rust_active"})
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "created_at": old_manifest.get("created_at") or now,
        "updated_at": now,
        "state": "rust_active",
        "command_link": str(LAYOUT.bin_link),
        "release": release,
        "previous": previous,
        "rollback_wheel": None,
        "history": history,
    }

    atomic_symlink(release["path"], LAYOUT.bin_link)
    atomic_copy_executable(Path(release["path"]), CARGO_COMMAND)
    verify_active_rust(LAYOUT, manifest, EXPECTED_PROTOCOL)
    verify_pair(Path(release["path"]), VERSION, 3)
    stable_default = check_config(CARGO_COMMAND, None)
    stable_protocol2 = check_config(CARGO_COMMAND, 2)
    if stable_protocol2.get("workflow_protocol_version") != 2:
        raise DeploymentError("stable explicit protocol-2 rollback failed")
    atomic_write_json(LAYOUT.manifest, manifest)

    rollback_at = utc_now()
    atomic_symlink(previous["target"], LAYOUT.bin_link)
    atomic_copy_executable(CARGO_ROLLBACK, CARGO_COMMAND)
    verify_pair(ROLLBACK_BINARY, ROLLBACK_VERSION, 3)
    manifest["state"] = "previous_active"
    manifest["updated_at"] = rollback_at
    manifest["history"].append({"at": rollback_at, "action": "stable_0_4_0_rollback", "state": "previous_active"})
    atomic_write_json(LAYOUT.manifest, manifest)

    recutover_at = utc_now()
    atomic_symlink(release["path"], LAYOUT.bin_link)
    atomic_copy_executable(Path(release["path"]), CARGO_COMMAND)
    manifest["state"] = "rust_active"
    manifest["updated_at"] = recutover_at
    manifest["history"].append({"at": recutover_at, "action": "stable_0_4_0_recutover", "state": "rust_active"})
    verify_active_rust(LAYOUT, manifest, EXPECTED_PROTOCOL)
    verify_pair(Path(release["path"]), VERSION, 3)
    atomic_write_json(LAYOUT.manifest, manifest)

    report = {
        "schema_version": "1.0.0",
        "project": "MTM-reboot",
        "milestone": "MTM-013",
        "phase": "stable_0_4_0_release",
        "passed": True,
        "version": VERSION,
        "source_commit": SOURCE_COMMIT,
        "binary_sha256": release["sha256"],
        "production_command": str(LAYOUT.bin_link),
        "production_command_target": release["path"],
        "shell_command": str(CARGO_COMMAND),
        "shell_command_sha256": sha256_file(CARGO_COMMAND),
        "release_info": expected_identity(CARGO_COMMAND, VERSION),
        "runtime_probes": {
            "stable_default_after_cutover": stable_default["workflow_protocol_version"],
            "stable_explicit_protocol2": stable_protocol2["workflow_protocol_version"],
            "preview3_default_during_rollback": 3,
            "stable_default_after_recutover": check_config(CARGO_COMMAND, None)["workflow_protocol_version"],
        },
        "rollback": {
            "selector_target": previous["target"],
            "selector_sha256": previous["sha256"],
            "cargo_backup": cargo_previous,
            "real_rollback_and_recutover_passed": True,
        },
        "qualification": {
            "local_report_sha256": QUALIFICATION_SHA256,
            "resource_report_sha256": RESOURCE_SHA256,
            "public_install_report_sha256": sha256_file(PUBLIC_INSTALL),
        },
        "existing_runs_rewritten": False,
        "final_artifact": "proof_verified.tex",
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
