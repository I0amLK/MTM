#!/usr/bin/env python3
"""Install MTM-015 preview.2, drill preview.1 rollback, and recutover."""
from __future__ import annotations

import copy
import fcntl
import json
import os
import shutil
import signal
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import mtm014_release_support as release_support
from mtm008_deployment import atomic_symlink, atomic_write_json, ensure_directory, fsync_directory, load_manifest
from validate_mtm015_candidate_stage import validate as validate_stage
from validate_mtm015_target_qualification import validate as validate_target
from validate_mtm015_web_client import validate as validate_web


ROOT = Path(__file__).resolve().parents[1]
HOME = Path("/home/lk")
STATE_ROOT = HOME / ".local/share/mtm"
VERSION = "0.5.0-preview.2"
CANDIDATE_SHA = "2164c84701b191b06a66a5d28ba595697d355f9a3bdc78ca31ea455d49793d6a"
PREVIOUS_VERSION = "0.5.0-preview.1"
PREVIOUS_SHA = "2b2cd48bea965fd21c5c54d3be3ead6917eaf40870e9aa801c48bb9484209036"
STABLE_SHA = "3312ca75a1de8707e740963cc0add4b09430dccc9dc63a3145e4456ff2b0cdf3"

SELECTOR = HOME / ".local/bin/mtm"
CARGO_ENTRY = HOME / ".cargo/bin/mtm"
PREVIOUS = STATE_ROOT / f"releases/{PREVIOUS_VERSION}/mtm"
STABLE = STATE_ROOT / "releases/0.4.0/mtm"
CANDIDATE = STATE_ROOT / f"candidates/MTM-015/{CANDIDATE_SHA}/mtm"
INSTALLED = STATE_ROOT / f"releases/{VERSION}/mtm"
MANIFEST = STATE_ROOT / "deployment/deployment-v1.json"
REPORT = ROOT / "records/evidence/MTM-015/preview-release.json"
TARGET = ROOT / "records/evidence/MTM-015/target-qualification.json"
STAGE = ROOT / "records/evidence/MTM-015/candidate-stage.json"
WEB = ROOT / "records/evidence/MTM-015/web-client.json"

CHECK_NAMES = {
    "target_evidence_valid",
    "candidate_stage_valid",
    "web_client_valid",
    "immutable_release_installed",
    "preview2_cutover_smoke",
    "preview1_rollback_smoke",
    "preview2_recutover_smoke",
    "post_recutover_soak",
    "both_entries_agree",
    "deployment_manifest_consistent",
    "stable_artifact_preserved",
}
HYGIENE = {
    "raw_capability_recorded": False,
    "raw_oauth_token_recorded": False,
    "raw_secret_recorded": False,
    "raw_logs_recorded": False,
}


class ReleaseFailure(RuntimeError):
    pass


def require(value: Any, label: str) -> None:
    if not value:
        raise ReleaseFailure(label)


def digest(path: Path) -> str:
    return release_support.digest(path)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def switch_pair(target: Path) -> None:
    atomic_symlink(str(target), SELECTOR)
    atomic_symlink(str(target), CARGO_ENTRY)
    require(
        SELECTOR.resolve(strict=True) == target.resolve(strict=True)
        and CARGO_ENTRY.resolve(strict=True) == target.resolve(strict=True),
        "selector_pair",
    )


def verify_pair(target: Path, version: str, expected_sha: str) -> None:
    require(target.is_file() and digest(target) == expected_sha, "pair_target_hash")
    for entry in (SELECTOR, CARGO_ENTRY):
        require(entry.is_symlink() and entry.resolve(strict=True) == target.resolve(strict=True),
                "pair_target")
        require(digest(entry) == expected_sha, "pair_hash")
        release_support.identity(entry, version)


def install_immutable() -> dict[str, Any]:
    require(CANDIDATE.is_file() and digest(CANDIDATE) == CANDIDATE_SHA, "candidate_hash")
    release_support.identity(CANDIDATE, VERSION)
    ensure_directory(INSTALLED.parent, 0o755)
    if INSTALLED.exists():
        require(INSTALLED.is_file() and digest(INSTALLED) == CANDIDATE_SHA,
                "immutable_release_conflict")
        release_support.identity(INSTALLED, VERSION)
    else:
        temporary = INSTALLED.with_name(f".{INSTALLED.name}.{os.getpid()}.tmp")
        try:
            with CANDIDATE.open("rb") as source, temporary.open("xb") as output:
                shutil.copyfileobj(source, output)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary, 0o755)
            try:
                os.link(temporary, INSTALLED)
            except FileExistsError:
                require(digest(INSTALLED) == CANDIDATE_SHA, "immutable_release_race")
            fsync_directory(INSTALLED.parent)
        finally:
            temporary.unlink(missing_ok=True)
        require(digest(INSTALLED) == CANDIDATE_SHA, "immutable_release_hash")
        release_support.identity(INSTALLED, VERSION)
    metadata = {
        "path": str(INSTALLED),
        "sha256": CANDIDATE_SHA,
        "size_bytes": INSTALLED.stat().st_size,
        "version": VERSION,
    }
    metadata_path = INSTALLED.parent / "release.json"
    if metadata_path.exists():
        existing = json.loads(metadata_path.read_text(encoding="utf-8"))
        require(all(existing.get(key) == value for key, value in metadata.items()),
                "release_metadata_conflict")
    else:
        atomic_write_json(metadata_path, {**metadata, "installed_at": utc_now()}, 0o644)
    return metadata


def smoke(target: Path, version: str, root: Path, label: str) -> bool:
    release_support.identity(target, version)
    return release_support.permission_smoke(target, root / label, legacy=False, tui=True)


def main() -> int:
    os.umask(0o077)
    stage = "preconditions"
    before: dict[str, Any] | None = None
    try:
        ensure_directory(MANIFEST.parent)
        with (MANIFEST.parent / "mtm015-rollout.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            signal.signal(signal.SIGTERM, lambda _signal, _frame: (_ for _ in ()).throw(KeyboardInterrupt()))
            require(not REPORT.exists(), "release_receipt_already_exists")
            require(not release_support.git("status", "--porcelain").strip(), "clean_release_tree")
            target_summary = validate_target()
            stage_summary = validate_stage()
            web_summary = validate_web()
            require(target_summary["binary_sha256"] == CANDIDATE_SHA, "target_binding")
            require(stage_summary["candidate_binary_sha256"] == CANDIDATE_SHA, "stage_binding")
            require(web_summary["candidate_binary_sha256"] == CANDIDATE_SHA, "web_binding")
            require(PREVIOUS.is_file() and digest(PREVIOUS) == PREVIOUS_SHA, "previous_hash")
            require(STABLE.is_file() and digest(STABLE) == STABLE_SHA, "stable_hash")
            verify_pair(PREVIOUS, PREVIOUS_VERSION, PREVIOUS_SHA)
            before = load_manifest(MANIFEST)
            release_object = before.get("release", {})
            require(release_object.get("path") == str(PREVIOUS), "previous_manifest_path")
            require(release_object.get("sha256") == PREVIOUS_SHA, "previous_manifest_hash")
            backup = STATE_ROOT / "rollback/mtm015-before-preview2-deployment.json"
            if backup.exists():
                require(json.loads(backup.read_text(encoding="utf-8")) == before,
                        "rollback_backup_conflict")
            else:
                atomic_write_json(backup, before)

            stage = "immutable_install"
            installed = install_immutable()
            new = copy.deepcopy(before)
            new["release"] = installed
            new["previous"] = {
                "kind": "symlink",
                "target": str(PREVIOUS),
                "resolved_target": str(PREVIOUS),
                "sha256": PREVIOUS_SHA,
                "version": PREVIOUS_VERSION,
            }

            checks = {
                "target_evidence_valid": True,
                "candidate_stage_valid": True,
                "web_client_valid": True,
                "immutable_release_installed": digest(INSTALLED) == CANDIDATE_SHA,
            }
            with tempfile.TemporaryDirectory(prefix="mtm015-release-drill-") as directory:
                root = Path(directory)
                stage = "preview2_cutover"
                switch_pair(INSTALLED)
                verify_pair(INSTALLED, VERSION, CANDIDATE_SHA)
                checks["preview2_cutover_smoke"] = smoke(INSTALLED, VERSION, root, "cutover")
                new["state"] = "rust_active"
                new.setdefault("history", []).append(
                    {"at": utc_now(), "action": "mtm015_preview2_cutover", "state": "rust_active"}
                )
                atomic_write_json(MANIFEST, new)

                stage = "preview1_rollback"
                switch_pair(PREVIOUS)
                verify_pair(PREVIOUS, PREVIOUS_VERSION, PREVIOUS_SHA)
                checks["preview1_rollback_smoke"] = smoke(PREVIOUS, PREVIOUS_VERSION, root, "rollback")
                new["state"] = "previous_active"
                new["history"].append(
                    {"at": utc_now(), "action": "mtm015_preview1_rollback", "state": "previous_active"}
                )
                atomic_write_json(MANIFEST, new)

                stage = "preview2_recutover"
                switch_pair(INSTALLED)
                verify_pair(INSTALLED, VERSION, CANDIDATE_SHA)
                checks["preview2_recutover_smoke"] = smoke(INSTALLED, VERSION, root, "recutover")
                soak = release_support.soak(INSTALLED, root / "post-recutover-soak")
                checks["post_recutover_soak"] = release_support.soak_ok(soak)

            new["state"] = "rust_active"
            new["updated_at"] = utc_now()
            new["history"].append(
                {"at": new["updated_at"], "action": "mtm015_preview2_recutover", "state": "rust_active"}
            )
            atomic_write_json(MANIFEST, new)
            checks["both_entries_agree"] = (
                SELECTOR.resolve(strict=True) == INSTALLED
                and CARGO_ENTRY.resolve(strict=True) == INSTALLED
                and digest(SELECTOR) == digest(CARGO_ENTRY) == CANDIDATE_SHA
            )
            deployed = load_manifest(MANIFEST)
            checks["deployment_manifest_consistent"] = (
                deployed.get("state") == "rust_active"
                and deployed.get("release", {}).get("path") == str(INSTALLED)
                and deployed.get("release", {}).get("sha256") == CANDIDATE_SHA
                and deployed.get("previous", {}).get("resolved_target") == str(PREVIOUS)
            )
            checks["stable_artifact_preserved"] = STABLE.is_file() and digest(STABLE) == STABLE_SHA
            require(set(checks) == CHECK_NAMES and all(checks.values()), "release_checks")

            report = {
                "schema_version": "1.0.0",
                "milestone": "MTM-015",
                "phase": "preview_release",
                "version": VERSION,
                "ok": True,
                "recorded_at": utc_now(),
                "release_commit": release_support.git("rev-parse", "HEAD").decode().strip(),
                "candidate_binary_sha256": CANDIDATE_SHA,
                "target_evidence_sha256": digest(TARGET),
                "candidate_stage_sha256": digest(STAGE),
                "web_client_sha256": digest(WEB),
                "previous_version": PREVIOUS_VERSION,
                "previous_sha256": PREVIOUS_SHA,
                "stable_sha256": STABLE_SHA,
                "release_path": str(INSTALLED),
                "checks": checks,
                "check_count": len(checks),
                "rollback": {
                    "previous_path": str(PREVIOUS),
                    "previous_version": PREVIOUS_VERSION,
                    "previous_sha256": PREVIOUS_SHA,
                    "real_rollback_and_recutover_passed": True,
                },
                "post_recutover_soak": soak,
                "existing_sessions_restarted": False,
                "production_state_rewritten": False,
                "performance_claim": False,
                "evidence_hygiene": HYGIENE,
                "harness_sha256": {
                    path: digest(ROOT / path)
                    for path in (
                        "scripts/release_mtm015_preview.py",
                        "scripts/validate_mtm015_preview_release.py",
                        "scripts/mtm008_deployment.py",
                        "scripts/mtm014_release_support.py",
                    )
                },
            }
            from validate_mtm015_preview_release import validate
            validate(report, deployed=True)
            with REPORT.open("x", encoding="utf-8") as handle:
                json.dump(report, handle, indent=2, sort_keys=True)
                handle.write("\n")
            print(json.dumps({
                "ok": True,
                "version": VERSION,
                "binary_sha256": CANDIDATE_SHA,
                "rollback_recutover_passed": True,
                "existing_sessions_restarted": False,
            }, indent=2))
            return 0
    except BaseException as error:
        restored = False
        if before is not None:
            try:
                switch_pair(PREVIOUS)
                atomic_write_json(MANIFEST, before)
                verify_pair(PREVIOUS, PREVIOUS_VERSION, PREVIOUS_SHA)
                restored = True
            except Exception:
                restored = False
        print(json.dumps({
            "ok": False,
            "stage": stage,
            "previous_restored": restored,
            "error": str(error) if isinstance(error, ReleaseFailure) else type(error).__name__,
        }))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
