#!/usr/bin/env python3
"""Install qualified MTM-014 preview, drill rollback, and retain stable on failure."""
from __future__ import annotations

import argparse
import copy
import fcntl
import json
import os
import signal
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import mtm014_release_support as s
from mtm008_deployment import (
    DeploymentLayout, atomic_symlink, atomic_write_json, install_release, load_manifest,
)
from validate_mtm014_preview_release import validate_qualification, validate_release


def switch_pair(target: Path, selector: Path = s.SELECTOR, cargo: Path = s.CARGO_ENTRY) -> None:
    """Each replacement is atomic. The caller compensates a partial pair change."""
    atomic_symlink(str(target), selector)
    atomic_symlink(str(target), cargo)
    s.require(selector.resolve(strict=True) == target.resolve(strict=True)
              and cargo.resolve(strict=True) == target.resolve(strict=True), "selector_pair")


def compensated_rollout(
    candidate: Path, stable: Path, manifest: Path, before: dict[str, Any],
    candidate_manifest: dict[str, Any], *,
    switch: Callable[[Path], None], smoke: Callable[[bool], bool],
    soak: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Finite rollout transaction; failures restore the previous entries/manifest."""
    new = copy.deepcopy(candidate_manifest)
    try:
        switch(candidate)
        s.require(smoke(False), "candidate_selector_smoke")
        new["history"].append({"at": datetime.now(timezone.utc).isoformat(),
                               "action": "mtm014_preview_cutover", "state": "rust_active"})
        atomic_write_json(manifest, new)
        switch(stable)
        s.require(smoke(True), "stable_rollback_smoke")
        new["state"] = "previous_active"
        new["history"].append({"at": datetime.now(timezone.utc).isoformat(),
                               "action": "mtm014_stable_rollback", "state": "previous_active"})
        atomic_write_json(manifest, new)
        switch(candidate)
        s.require(smoke(False), "candidate_recutover_smoke")
        summary = soak()
        new["state"] = "rust_active"
        new["updated_at"] = datetime.now(timezone.utc).isoformat()
        new["history"].append({"at": new["updated_at"], "action": "mtm014_preview_recutover",
                               "state": "rust_active"})
        atomic_write_json(manifest, new)
        return summary
    except BaseException:
        switch(stable)
        atomic_write_json(manifest, before)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rollback", action="store_true", help="restore stable command selection")
    args = parser.parse_args()
    os.umask(0o077)
    stage = "preconditions"
    before = None
    manifest = s.STATE_ROOT / "deployment/deployment-v1.json"
    layout = DeploymentLayout(s.SELECTOR, s.STATE_ROOT)
    def interrupted(_signal: int, _frame: Any) -> None:
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        with (manifest.parent / "mtm014-rollout.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            qualification = json.loads(s.QUALIFICATION.read_text())
            validate_qualification(qualification)
            s.require(s.digest(s.STABLE) == s.STABLE_SHA, "stable_rollback_hash")
            if args.rollback:
                release = json.loads(s.RELEASE.read_text())
                validate_release(release, qualification, deployed=True)
                old = load_manifest(manifest)
                switch_pair(s.STABLE)
                old["state"] = "previous_active"
                old["updated_at"] = datetime.now(timezone.utc).isoformat()
                old["history"].append({"at": old["updated_at"], "action": "mtm014_operator_rollback",
                                       "state": "previous_active"})
                atomic_write_json(manifest, old)
                print(json.dumps({"ok": True, "active_version": "0.4.0", "sessions_restarted": False}))
                return 0
            s.require(not s.git("status", "--porcelain").strip(), "clean_release_tree")
            s.require(s.stable_pair(), "stable_initial_selection")
            s.require(not s.RELEASE.exists(), "release_receipt_already_exists")
            s.require(s.digest(s.STAGED) == qualification["binary_sha256"], "qualified_binary_hash")
            before = load_manifest(manifest)
            backup = layout.rollback_root / "mtm014-before-preview-deployment.json"
            s.require(not backup.exists(), "rollback_backup_already_exists")
            atomic_write_json(backup, before)
            if s.INSTALLED.exists():
                s.require(s.digest(s.INSTALLED) == qualification["binary_sha256"], "version_directory_conflict")
            stage = "side_by_side_install"
            installed = install_release(s.STAGED, layout, s.VERSION, 3)
            s.require(installed["sha256"] == qualification["binary_sha256"], "installed_binary_hash")
            new = copy.deepcopy(before)
            new.update(release=installed, previous={"kind": "symlink", "target": str(s.STABLE),
                       "resolved_target": str(s.STABLE), "sha256": s.STABLE_SHA,
                       "version": "mtm 0.4.0"}, state="rust_active")
            stage = "rollback_recutover_soak"
            with tempfile.TemporaryDirectory(prefix="mtm014-release-drill-") as directory:
                root = Path(directory)
                counter = 0
                def smoke(legacy: bool) -> bool:
                    nonlocal counter
                    counter += 1
                    s.identity(s.SELECTOR, "0.4.0" if legacy else s.VERSION)
                    s.identity(s.CARGO_ENTRY, "0.4.0" if legacy else s.VERSION)
                    return s.permission_smoke(s.SELECTOR, root / f"smoke-{counter}",
                                              legacy=legacy, tui=True)
                summary = compensated_rollout(
                    s.INSTALLED, s.STABLE, manifest, before, new,
                    switch=switch_pair, smoke=smoke,
                    soak=lambda: s.soak(s.SELECTOR, root / "recutover-soak"),
                )
            report = {
                "schema_version": "1.0.0", "milestone": "MTM-014", "phase": "preview_release",
                "version": s.VERSION, "ok": True, "recorded_at": datetime.now(timezone.utc).isoformat(),
                "source_commit": qualification["source_commit"],
                "binary_sha256": qualification["binary_sha256"], "stable_sha256": s.STABLE_SHA,
                "qualification_sha256": s.digest(s.QUALIFICATION),
                "checks": dict.fromkeys(s.RELEASE_CHECKS, True), "check_count": len(s.RELEASE_CHECKS),
                "post_recutover_soak": summary, "existing_sessions_restarted": False,
                "production_state_rewritten": False, "performance_claim": False,
                "evidence_hygiene": s.HYGIENE,
            }
            stage = "release_receipt"
            validate_release(report, qualification, deployed=True)
            with s.RELEASE.open("x", encoding="utf-8") as handle:
                json.dump(report, handle, indent=2, sort_keys=True)
                handle.write("\n")
            print(json.dumps({"ok": True, "version": s.VERSION, "binary_sha256": installed["sha256"],
                              "rollback_recutover_passed": True, "existing_sessions_restarted": False}, indent=2))
            return 0
    except BaseException as error:
        restored = before is None
        if before is not None:
            try:
                switch_pair(s.STABLE)
                atomic_write_json(manifest, before)
                restored = s.stable_pair()
            except Exception:
                restored = False
        print(json.dumps({"ok": False, "stage": stage, "stable_restored": restored,
                          "error_kind": str(error) if isinstance(error, s.ReleaseFailure) else type(error).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
