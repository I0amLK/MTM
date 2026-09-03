#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from mtm008_deployment import (
    MANIFEST_SCHEMA,
    DeploymentError,
    DeploymentLayout,
    atomic_symlink,
    atomic_write_json,
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
VERSION = "0.4.0-preview.3"
EXPECTED_PROTOCOL = 3
BINARY = ROOT / "target" / "release" / "mtm"
EXPECTED_BINARY_SHA256 = "545ab9ef8cc01edf804581cb52c2b1a4158d03bd8a25ea00c7785039167f3659"
ROLLBACK_VERSION = "0.4.0-preview.2"
ROLLBACK_PROTOCOL = 3
ROLLBACK_SHA256 = "5ed668d5bf765be2efd1b50933e941cf60dbbd414e3b6daab77745624d5cfa81"
TUI_REPORT = ROOT / "mtm012-tui-validation.json"
TUI_REPORT_SHA256 = "be9a9317988afc7a727a7f4bba00f7dcf0119394773c0825b4526a77f9aa868b"
SOURCE_COMMIT = "e9276f2ea0917f4c0ae14146a2407c01d4e425cc"
EVIDENCE_COMMIT = "8a740ce5abdcdc90ff408d04ff41562cf40093d2"
REPORT = ROOT / "mtm012-preview-release.json"
CARGO_ALIAS = HOME / ".cargo" / "bin" / "mtm"
LAYOUT = DeploymentLayout(
    bin_link=HOME / ".local" / "bin" / "mtm",
    state_root=HOME / ".local" / "share" / "mtm",
)
ROLLBACK_BINARY = LAYOUT.releases_root / ROLLBACK_VERSION / "mtm"


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


def ensure_shell_alias(expected: Path) -> None:
    if not CARGO_ALIAS.is_symlink():
        raise DeploymentError("login-shell-preferred ~/.cargo/bin/mtm is not the MTM selector alias")
    if CARGO_ALIAS.resolve(strict=True) != expected.resolve(strict=True):
        raise DeploymentError("login-shell-preferred mtm path does not follow the active selector")


def accepted_rollback() -> dict[str, Any]:
    if not ROLLBACK_BINARY.is_file():
        raise DeploymentError(f"preview.2 rollback binary is missing: {ROLLBACK_BINARY}")
    validate_rust_release(ROLLBACK_BINARY, ROLLBACK_VERSION, ROLLBACK_PROTOCOL)
    actual_sha = sha256_file(ROLLBACK_BINARY)
    if actual_sha != ROLLBACK_SHA256:
        raise DeploymentError(
            f"preview.2 rollback hash mismatch: expected {ROLLBACK_SHA256}, got {actual_sha}"
        )
    return {
        "kind": "symlink",
        "target": str(ROLLBACK_BINARY),
        "resolved_target": str(ROLLBACK_BINARY.resolve(strict=True)),
        "version": run_version(ROLLBACK_BINARY),
        "sha256": actual_sha,
        "workflow_protocol_version": ROLLBACK_PROTOCOL,
    }


def write_report(payload: dict[str, Any]) -> None:
    temporary = REPORT.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(REPORT)


def main() -> int:
    if sha256_file(BINARY) != EXPECTED_BINARY_SHA256:
        raise DeploymentError("release binary differs from the MTM-012 A4-qualified artifact")
    validate_rust_release(BINARY, VERSION, EXPECTED_PROTOCOL)
    if sha256_file(TUI_REPORT) != TUI_REPORT_SHA256:
        raise DeploymentError("MTM-012 TUI A4 evidence binding drifted")
    previous = accepted_rollback()
    if not LAYOUT.bin_link.is_symlink() or LAYOUT.bin_link.resolve() != ROLLBACK_BINARY.resolve():
        raise DeploymentError("pre-cutover selector is not the accepted preview.2 rollback target")
    ensure_shell_alias(ROLLBACK_BINARY)

    old_manifest = load_manifest(LAYOUT.manifest)
    release = install_release(BINARY, LAYOUT, VERSION, EXPECTED_PROTOCOL)
    now = utc_now()
    history = list(old_manifest.get("history") or [])
    history.append({"at": now, "action": "preview3_tui_cutover", "state": "rust_active"})
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
    verify_active_rust(LAYOUT, manifest, EXPECTED_PROTOCOL)
    ensure_shell_alias(Path(release["path"]))
    preview3_default = check_config(CARGO_ALIAS, None)
    preview3_protocol2 = check_config(CARGO_ALIAS, 2)
    if preview3_default.get("workflow_protocol_version") != 3:
        raise DeploymentError("preview.3 default runtime did not select protocol 3")
    if preview3_protocol2.get("workflow_protocol_version") != 2:
        raise DeploymentError("preview.3 explicit protocol-2 override failed")
    atomic_write_json(LAYOUT.manifest, manifest)

    rollback_at = utc_now()
    atomic_symlink(previous["target"], LAYOUT.bin_link)
    validate_rust_release(LAYOUT.bin_link.resolve(strict=True), ROLLBACK_VERSION, ROLLBACK_PROTOCOL)
    ensure_shell_alias(ROLLBACK_BINARY)
    rollback_default = check_config(CARGO_ALIAS, None)
    if rollback_default.get("workflow_protocol_version") != 3:
        raise DeploymentError("preview.2 selector rollback changed the accepted protocol-3 default")
    manifest["state"] = "previous_active"
    manifest["updated_at"] = rollback_at
    manifest["history"].append(
        {"at": rollback_at, "action": "preview3_tui_rollback", "state": "previous_active"}
    )
    atomic_write_json(LAYOUT.manifest, manifest)

    recutover_at = utc_now()
    atomic_symlink(release["path"], LAYOUT.bin_link)
    manifest["state"] = "rust_active"
    manifest["updated_at"] = recutover_at
    manifest["history"].append(
        {"at": recutover_at, "action": "preview3_tui_recutover", "state": "rust_active"}
    )
    verify_active_rust(LAYOUT, manifest, EXPECTED_PROTOCOL)
    ensure_shell_alias(Path(release["path"]))
    recutover_default = check_config(CARGO_ALIAS, None)
    if recutover_default.get("workflow_protocol_version") != 3:
        raise DeploymentError("preview.3 recutover did not restore the expected default")
    atomic_write_json(LAYOUT.manifest, manifest)

    report = {
        "schema_version": "1.0.0",
        "project": "MTM-reboot",
        "phase": "mtm012_preview_release",
        "milestone": "MTM-012",
        "milestone_status": "in_progress",
        "passed": True,
        "version": VERSION,
        "source_commit": SOURCE_COMMIT,
        "evidence_commit": EVIDENCE_COMMIT,
        "binary_sha256": release["sha256"],
        "production_command": str(LAYOUT.bin_link),
        "production_command_target": release["path"],
        "shell_command_alias": str(CARGO_ALIAS),
        "release_info": run_json(LAYOUT.bin_link.resolve(strict=True), "release-info"),
        "tui_a4": {
            "report": str(TUI_REPORT.relative_to(ROOT)),
            "report_sha256": TUI_REPORT_SHA256,
            "check_count": 20,
            "raw_tui_log_recorded": False,
            "generated_operator_key_recorded": False,
        },
        "runtime_probes": {
            "preview3_default_after_cutover": preview3_default["workflow_protocol_version"],
            "preview3_explicit_protocol2": preview3_protocol2["workflow_protocol_version"],
            "preview2_default_during_rollback": rollback_default["workflow_protocol_version"],
            "preview3_default_after_recutover": recutover_default["workflow_protocol_version"],
        },
        "rollback": {
            "target": previous["target"],
            "sha256": previous["sha256"],
            "version": previous["version"],
            "real_rollback_and_recutover_passed": True,
        },
        "existing_runs_rewritten": False,
        "workflow_protocols": {
            "production_default": 3,
            "rollback_override": 2,
        },
        "final_artifact": "proof_verified.tex",
    }
    write_report(report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
