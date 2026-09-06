#!/usr/bin/env python3
"""Stage the exact MTM-015 candidate side by side and smoke its installed endpoint."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import run_mtm013_runtime_hardening as capability
from run_checks import resolve_tool_environment
from run_mtm015_target_qualification import PersistedServer
from validate_mtm015_target_qualification import validate as validate_target


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "records/evidence/MTM-015/target-qualification.json"
REPORT = ROOT / "records/evidence/MTM-015/candidate-stage.json"
SELECTOR = Path("/home/lk/.local/bin/mtm")
CARGO_ENTRY = Path("/home/lk/.cargo/bin/mtm")
INSTALLED = Path("/home/lk/.local/share/mtm/releases/0.5.0-preview.1/mtm")
STABLE = Path("/home/lk/.local/share/mtm/releases/0.4.0/mtm")
STABLE_SHA = "3312ca75a1de8707e740963cc0add4b09430dccc9dc63a3145e4456ff2b0cdf3"
CHECK_NAMES = {
    "target_evidence_valid",
    "rebuilt_candidate_matches_target",
    "content_addressed_install_exact",
    "installed_endpoint_identity",
    "installed_endpoint_capability_roundtrip",
    "installed_persisted_secret_owner_only",
    "selectors_unchanged",
    "stable_rollback_artifact_preserved",
}
HYGIENE = {
    "raw_capability_recorded": False,
    "raw_oauth_token_recorded": False,
    "raw_secret_recorded": False,
    "raw_logs_recorded": False,
}


class StageFailure(RuntimeError):
    pass


def require(value: Any, label: str) -> None:
    if not value:
        raise StageFailure(label)


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def git(*arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], cwd=ROOT, text=True).strip()


def install_content_addressed(source: Path, expected_sha: str) -> Path:
    destination = Path(
        f"/home/lk/.local/share/mtm/candidates/MTM-015/{expected_sha}/mtm"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        require(destination.is_file() and digest(destination) == expected_sha,
                "existing_candidate_drift")
        return destination
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as handle:
        temporary = Path(handle.name)
        with source.open("rb") as input_stream:
            shutil.copyfileobj(input_stream, handle)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.chmod(temporary, 0o755)
        os.link(temporary, destination)
    except FileExistsError:
        require(digest(destination) == expected_sha, "candidate_install_race_drift")
    finally:
        temporary.unlink(missing_ok=True)
    require(digest(destination) == expected_sha, "candidate_install_hash")
    return destination


def endpoint_smoke(binary: Path, root: Path) -> dict[str, Any]:
    server = PersistedServer(binary, root)
    try:
        info_response = capability.tool_call(server.port, server.token, "server_info", {})
        info = capability.structured(info_response)
        require(not capability.is_error(info_response), "installed_server_info")
        task = capability.start_run(server.port, server.token, "mtm015-installed-candidate")
        response = capability.tool_call(
            server.port,
            server.token,
            "rethlas_step",
            capability.task_submission(task, str(task["capability"])),
        )
        value = capability.structured(response)
        expected = len(task["task"]["minimal_submission"].get("writes", []))
        roundtrip = (
            not capability.is_error(response)
            and value.get("ok") is True
            and value.get("state") != task.get("state")
            and value.get("writes_applied") == expected
        )
        owner_only = server.secret_path.is_file() and (
            server.secret_path.stat().st_mode & 0o777
        ) == 0o600
        return {
            "identity": (
                info.get("version") == "0.5.0-preview.1"
                and info.get("implementation") == "rust"
                and info.get("production_authority") == "rust"
                and info.get("public_tool_count") == 24
                and info.get("hidden_alias_count") == 11
                and info.get("state_schema_version") == 2
                and info.get("workflow_protocol_version") == 3
            ),
            "roundtrip": roundtrip,
            "owner_only": owner_only,
        }
    finally:
        server.close()


def main() -> int:
    os.umask(0o077)
    stage = "preconditions"
    try:
        require(not git("status", "--porcelain"), "clean_committed_source")
        target_summary = validate_target()
        target = json.loads(TARGET.read_text(encoding="utf-8"))
        expected_sha = str(target["binary_sha256"])
        stage_commit = git("rev-parse", "HEAD")
        selector_before = digest(SELECTOR)
        cargo_before = digest(CARGO_ENTRY)
        require(SELECTOR.resolve() == INSTALLED and CARGO_ENTRY.resolve() == INSTALLED,
                "selector_baseline")
        require(selector_before == cargo_before == digest(INSTALLED), "selector_bytes")
        require(STABLE.is_file() and digest(STABLE) == STABLE_SHA, "stable_baseline")

        environment, cargo, _ = resolve_tool_environment()
        require(cargo is not None, "pinned_cargo")
        environment["CARGO_INCREMENTAL"] = "0"
        (ROOT / "target").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="mtm015-stage-build-", dir=ROOT / "target"
        ) as build:
            stage = "rebuild"
            result = subprocess.run(
                [
                    str(cargo), "build", "--locked", "--release", "-p", "mtm-cli",
                    "--bin", "mtm", "--target-dir", build,
                ],
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=480,
                check=False,
            )
            require(result.returncode == 0, "candidate_rebuild")
            rebuilt = Path(build) / "release/mtm"
            require(digest(rebuilt) == expected_sha, "candidate_rebuild_hash")
            stage = "content_addressed_install"
            candidate = install_content_addressed(rebuilt, expected_sha)

        stage = "installed_endpoint"
        with tempfile.TemporaryDirectory(prefix="mtm015-installed-endpoint-") as directory:
            endpoint = endpoint_smoke(candidate, Path(directory))

        checks = {
            "target_evidence_valid": bool(target_summary),
            "rebuilt_candidate_matches_target": digest(candidate) == expected_sha,
            "content_addressed_install_exact": candidate.is_file() and digest(candidate) == expected_sha,
            "installed_endpoint_identity": endpoint["identity"],
            "installed_endpoint_capability_roundtrip": endpoint["roundtrip"],
            "installed_persisted_secret_owner_only": endpoint["owner_only"],
            "selectors_unchanged": (
                SELECTOR.resolve() == INSTALLED
                and CARGO_ENTRY.resolve() == INSTALLED
                and digest(SELECTOR) == selector_before
                and digest(CARGO_ENTRY) == cargo_before
            ),
            "stable_rollback_artifact_preserved": STABLE.is_file() and digest(STABLE) == STABLE_SHA,
        }
        require(set(checks) == CHECK_NAMES and all(checks.values()), "candidate_stage_checks")
        report = {
            "schema_version": "1.0.0",
            "milestone": "MTM-015",
            "phase": "candidate_stage",
            "version": "0.5.0-preview.1",
            "ok": True,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "implementation_commit": target["implementation_commit"],
            "target_qualification_commit": target["qualification_commit"],
            "stage_commit": stage_commit,
            "target_evidence_sha256": digest(TARGET),
            "candidate_binary_sha256": expected_sha,
            "candidate_path": str(candidate),
            "checks": checks,
            "check_count": len(checks),
            "endpoint": {
                "version": "0.5.0-preview.1",
                "transport": "loopback_oauth_mcp",
                "disposable_state": True,
                "persisted_secret_path_exercised": True,
            },
            "harness_sha256": {
                "scripts/run_mtm015_candidate_stage.py": digest(Path(__file__)),
                "scripts/validate_mtm015_candidate_stage.py": digest(
                    ROOT / "scripts/validate_mtm015_candidate_stage.py"
                ),
            },
            "web_client_tested": False,
            "installed_endpoint_tested": True,
            "selector_changed": False,
            "production_state_rewritten": False,
            "evidence_hygiene": HYGIENE,
        }
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        temporary = REPORT.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        os.replace(temporary, REPORT)
        print(json.dumps({"ok": True, "report": str(REPORT), "checks": len(checks)}))
        return 0
    except Exception as error:
        print(json.dumps({
            "ok": False,
            "stage": stage,
            "error": str(error) if isinstance(error, StageFailure) else type(error).__name__,
        }))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
