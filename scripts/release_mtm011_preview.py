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
    DeploymentLayout,
    DeploymentError,
    atomic_symlink,
    atomic_write_json,
    ensure_directory,
    install_release,
    load_manifest,
    run_json,
    run_version,
    sha256_file,
    utc_now,
    validate_rust_release,
    verify_active_rust,
)


ROOT = Path(__file__).resolve().parents[1]
HOME = Path("/home/lk")
VERSION = "0.4.0-preview.2"
EXPECTED_PROTOCOL = 3
BINARY = ROOT / "target" / "release" / "mtm"
EXPECTED_BINARY_SHA256 = "5ed668d5bf765be2efd1b50933e941cf60dbbd414e3b6daab77745624d5cfa81"
ROLLBACK_VERSION = "0.4.0-preview.1"
ROLLBACK_PROTOCOL = 2
ROLLBACK_SHA256 = "e76c2124cddb73370d902394df3c143124870abf8f05240f1a72ca835a8e2477"
A4_CANDIDATE_SHA256 = "5cebde6458f29012f3da72564ad6a940cc319aae162f9695070474b77d83b036"
ACCEPTED_EVALUATION_SHA256 = "1820027a361604fd77da2e303e1c7c43ab6f25edd7a7401cc6176705c280bd05"
POST_A5 = ROOT / "mtm011-cutover-resource.json"
POST_A5_SHA256 = "fc9ad093e0abb91d4b90fb05f9c2b280d359557938d701da81dcd5789bdf6f8d"
REPORT = ROOT / "mtm011-preview-release.json"
LAYOUT = DeploymentLayout(
    bin_link=HOME / ".local" / "bin" / "mtm",
    state_root=HOME / ".local" / "share" / "mtm",
)
ROLLBACK_BINARY = LAYOUT.releases_root / ROLLBACK_VERSION / "mtm"
CARGO_COMMAND = HOME / ".cargo" / "bin" / "mtm"
A4_CANDIDATE_ARCHIVE = (
    LAYOUT.state_root / "evidence" / f"mtm011-a4-candidate-{A4_CANDIDATE_SHA256[:12]}" / "mtm"
)


def write_report(payload: dict[str, Any]) -> None:
    temporary = REPORT.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(REPORT)


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


def accepted_rollback() -> dict[str, Any]:
    if not ROLLBACK_BINARY.is_file():
        raise DeploymentError(f"preview.1 rollback binary is missing: {ROLLBACK_BINARY}")
    validate_rust_release(ROLLBACK_BINARY, ROLLBACK_VERSION, ROLLBACK_PROTOCOL)
    actual_sha = sha256_file(ROLLBACK_BINARY)
    if actual_sha != ROLLBACK_SHA256:
        raise DeploymentError(
            f"preview.1 rollback hash mismatch: expected {ROLLBACK_SHA256}, got {actual_sha}"
        )
    return {
        "kind": "symlink",
        "target": str(ROLLBACK_BINARY),
        "resolved_target": str(ROLLBACK_BINARY.resolve(strict=True)),
        "version": run_version(ROLLBACK_BINARY),
        "sha256": actual_sha,
        "workflow_protocol_version": ROLLBACK_PROTOCOL,
    }


def bind_shell_command_alias() -> dict[str, Any]:
    ensure_directory(A4_CANDIDATE_ARCHIVE.parent, 0o700)
    if CARGO_COMMAND.is_symlink():
        if CARGO_COMMAND.resolve(strict=True) != LAYOUT.bin_link.resolve(strict=True):
            raise DeploymentError("existing ~/.cargo/bin/mtm symlink does not follow the MTM selector")
    elif CARGO_COMMAND.is_file():
        current_sha = sha256_file(CARGO_COMMAND)
        if current_sha != A4_CANDIDATE_SHA256:
            raise DeploymentError(
                "existing ~/.cargo/bin/mtm is neither the accepted A4 candidate nor the production selector"
            )
        if A4_CANDIDATE_ARCHIVE.exists():
            if sha256_file(A4_CANDIDATE_ARCHIVE) != A4_CANDIDATE_SHA256:
                raise DeploymentError("archived MTM-011 A4 candidate hash drifted")
        else:
            shutil.copyfile(CARGO_COMMAND, A4_CANDIDATE_ARCHIVE)
            os.chmod(A4_CANDIDATE_ARCHIVE, 0o755)
            if sha256_file(A4_CANDIDATE_ARCHIVE) != A4_CANDIDATE_SHA256:
                raise DeploymentError("failed to archive the MTM-011 A4 candidate byte-for-byte")
        atomic_symlink(str(LAYOUT.bin_link), CARGO_COMMAND)
    else:
        raise DeploymentError("~/.cargo/bin/mtm is missing; refusing to create an unproven shell alias")
    if not A4_CANDIDATE_ARCHIVE.is_file() or sha256_file(A4_CANDIDATE_ARCHIVE) != A4_CANDIDATE_SHA256:
        raise DeploymentError("MTM-011 A4 candidate archive is missing after alias binding")
    if CARGO_COMMAND.resolve(strict=True) != LAYOUT.bin_link.resolve(strict=True):
        raise DeploymentError("~/.cargo/bin/mtm does not follow the production MTM selector")
    return {
        "path": str(CARGO_COMMAND),
        "resolved_target": str(CARGO_COMMAND.resolve(strict=True)),
        "a4_candidate_archive": str(A4_CANDIDATE_ARCHIVE),
        "a4_candidate_sha256": A4_CANDIDATE_SHA256,
    }


def main() -> int:
    if sha256_file(BINARY) != EXPECTED_BINARY_SHA256:
        raise DeploymentError("release binary differs from the post-cutover A5-qualified artifact")
    validate_rust_release(BINARY, VERSION, EXPECTED_PROTOCOL)
    if sha256_file(POST_A5) != POST_A5_SHA256:
        raise DeploymentError("post-cutover A5 evidence binding drifted")
    previous = accepted_rollback()
    if not LAYOUT.bin_link.is_symlink():
        raise DeploymentError("production MTM command is not a selector symlink")

    old_manifest = load_manifest(LAYOUT.manifest)
    release = install_release(BINARY, LAYOUT, VERSION, EXPECTED_PROTOCOL)
    now = utc_now()
    history = list(old_manifest.get("history") or [])
    history.append({"at": now, "action": "preview2_cutover", "state": "rust_active"})
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

    current_target = LAYOUT.bin_link.resolve(strict=True)
    if current_target not in {ROLLBACK_BINARY.resolve(strict=True), Path(release["path"]).resolve(strict=True)}:
        raise DeploymentError("production selector is neither preview.1 rollback nor preview.2 release")
    # Initial cutover to preview.2, or revalidate an already-active preview.2.
    atomic_symlink(release["path"], LAYOUT.bin_link)
    verify_active_rust(LAYOUT, manifest, EXPECTED_PROTOCOL)
    shell_alias = bind_shell_command_alias()
    default_after_cutover = check_config(CARGO_COMMAND, None)
    explicit_protocol2 = check_config(CARGO_COMMAND, 2)
    if default_after_cutover.get("workflow_protocol_version") != 3:
        raise DeploymentError("preview.2 no-override runtime did not select protocol 3")
    if explicit_protocol2.get("workflow_protocol_version") != 2:
        raise DeploymentError("preview.2 explicit protocol-2 rollback override failed")
    atomic_write_json(LAYOUT.manifest, manifest)

    # Real selector rollback to preview.1.
    rollback_at = utc_now()
    atomic_symlink(previous["target"], LAYOUT.bin_link)
    validate_rust_release(LAYOUT.bin_link.resolve(strict=True), ROLLBACK_VERSION, ROLLBACK_PROTOCOL)
    rollback_default = check_config(CARGO_COMMAND, None)
    if rollback_default.get("workflow_protocol_version") != 2:
        raise DeploymentError("selector rollback to preview.1 did not restore protocol-2 default")
    manifest["state"] = "previous_active"
    manifest["updated_at"] = rollback_at
    manifest["history"].append({"at": rollback_at, "action": "preview2_rollback", "state": "previous_active"})
    atomic_write_json(LAYOUT.manifest, manifest)

    # Real selector recutover to preview.2.
    recutover_at = utc_now()
    atomic_symlink(release["path"], LAYOUT.bin_link)
    manifest["state"] = "rust_active"
    manifest["updated_at"] = recutover_at
    manifest["history"].append({"at": recutover_at, "action": "preview2_recutover", "state": "rust_active"})
    verify_active_rust(LAYOUT, manifest, EXPECTED_PROTOCOL)
    recutover_default = check_config(CARGO_COMMAND, None)
    if recutover_default.get("workflow_protocol_version") != 3:
        raise DeploymentError("preview.2 recutover did not restore protocol-3 default")
    atomic_write_json(LAYOUT.manifest, manifest)

    info = run_json(LAYOUT.bin_link.resolve(strict=True), "release-info")
    report = {
        "schema_version": "1.0.0",
        "project": "MTM-reboot",
        "phase": "mtm011_preview_release",
        "milestone": "MTM-011",
        "milestone_status": "in_progress",
        "passed": True,
        "version": VERSION,
        "source_commit": "2b763e7130ffdd88707b6c1d97974a0ea29bc0b2",
        "binary_sha256": release["sha256"],
        "production_command": str(LAYOUT.bin_link),
        "production_command_target": release["path"],
        "shell_command_alias": shell_alias,
        "release_info": info,
        "workflow_protocols": {
            "production_default": 3,
            "rollback_override": 2,
            "protocol3_default_cutover_allowed": True,
        },
        "qualification": {
            "accepted_evaluation_sha256": ACCEPTED_EVALUATION_SHA256,
            "post_cutover_a5_sha256": POST_A5_SHA256,
            "post_cutover_a5_binary_sha256": EXPECTED_BINARY_SHA256,
        },
        "runtime_probes": {
            "preview2_default_after_cutover": default_after_cutover["workflow_protocol_version"],
            "preview2_explicit_protocol2": explicit_protocol2["workflow_protocol_version"],
            "preview1_default_during_rollback": rollback_default["workflow_protocol_version"],
            "preview2_default_after_recutover": recutover_default["workflow_protocol_version"],
        },
        "rollback": {
            "target": previous["target"],
            "sha256": previous["sha256"],
            "version": previous["version"],
            "real_rollback_and_recutover_passed": True,
        },
        "existing_runs_rewritten": False,
        "final_artifact": "proof_verified.tex",
    }
    write_report(report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
