#!/usr/bin/env python3
"""Qualify an exact Git-installed preview; never change selected commands."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import mtm014_release_support as s
import run_mtm014_public_authority_target as public
import run_mtm013_exact_stable_semantic_regression as semantic
import run_mtm013_stable_qualification as historical
import run_mtm007_target_validation as legacy_target
from run_checks import resolve_tool_environment
from validate_mtm014_preview_release import validate_qualification


def old_run_roundtrip(root: Path) -> bool:
    # Use a stable-created disposable run. Production state is never opened RW.
    stable_root, upgrade_root = root / "stable", root / "copied"
    with s.server(s.STABLE, stable_root) as server:
        token, port = server.token, server.port
        started = semantic.start_run(port, token, "mtm014-upgrade", semantic.COMPACT_PROBLEM,
                                     "compact", "upgrade/proof_verified.tex")
        run_id = str(started["run_id"])
        before = public.assert_tool_success(server.call("rethlas_inspect", {
            "operation": "status", "run_id": run_id}))
    shutil.copytree(stable_root, upgrade_root)
    for binary in (s.STAGED, s.STABLE, s.STAGED):
        with s.server(binary, upgrade_root, port=port) as server:
            # Reuse the original OAuth principal; a new DCR client is not the owner.
            server.token = token
            current = public.assert_tool_success(server.call("rethlas_inspect", {
                "operation": "status", "run_id": run_id}))
            s.require(current["state"] == before["state"], "old_run_resume_state")
    return True


def main() -> int:
    os.umask(0o077)
    stage = "preconditions"
    try:
        s.require(not s.git("status", "--porcelain").strip(), "clean_committed_source")
        commit = s.git("rev-parse", "HEAD").decode().strip()
        s.require(s.source_scope_verified(commit), "runtime_source_scope_verified")
        s.require(s.stable_pair(), "stable_entries")
        s.require(not s.QUALIFICATION.exists(), "qualification_already_exists")
        tools = {name: shutil.which(name) is not None for name in
                 ("bwrap", "curl", "git", "latexmk", "pdflatex", "sage", "magma")}
        s.require(all(tools.values()), "required_tools")
        from validate_mtm014_public_authority_target import validate as validate_public
        validate_public(json.loads((s.ROOT / s.PREREQUISITES[-1]).read_text()))
        stage = "clean_git_install"
        env, cargo, _ = resolve_tool_environment()
        s.require(cargo is not None, "pinned_cargo")
        env["CARGO_INCREMENTAL"] = "0"
        build_directory = s.ROOT / "target/mtm014-preview-build" / commit
        # A fresh checkout alone is insufficient when Cargo shares old install
        # artifacts. Qualification uses an unused per-revision build directory.
        s.require(not build_directory.exists(), "fresh_build_directory_required")
        result = subprocess.run([
            str(cargo), "install", "--git", s.ROOT.as_uri(), "--rev", commit,
            "--locked", "--bin", "mtm", "mtm-cli", "--force",
            "--root", str(s.STAGED.parents[1]),
            "--target-dir", str(build_directory),
        ], cwd=s.ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=480, check=False)
        s.require(result.returncode == 0, "clean_git_install")
        s.identity(s.STAGED, s.VERSION)
        binary_sha = s.digest(s.STAGED)
        rejected = json.loads((s.ROOT / "records/evidence/MTM-014/preview-soak-rejected.json").read_text())
        s.require(binary_sha != rejected["binary_sha256"], "rejected_artifact_reused")
        checks = {"versioned_identity": True, "clean_git_install": True,
                  "runtime_source_scope_verified": True, "required_tools_present": True}
        with tempfile.TemporaryDirectory(prefix="mtm014-preview-") as directory:
            root = Path(directory)
            public.BINARY = s.STAGED
            stage = "safe_public_suite"
            safe = public.safe_public_case(root / "safe")
            checks[stage] = bool(safe) and all(value is True for value in safe.values())
            stage = "trusted_public_suite"
            trusted = public.trusted_public_case(root / "trusted")
            checks[stage] = bool(trusted) and all(value is True for value in trusted.values())
            stage = "dangerous_public_suite"
            dangerous, magma = public.dangerous_public_case(root / "dangerous")
            checks[stage] = bool(dangerous) and all(value is True for value in dangerous.values())
            stage = "all_mode_attestation"
            checks[stage] = all(public.attest_mode(mode) for mode in ("safe", "trusted", "dangerous"))
            stage = "required_latex_regression"
            proof_facts = {}
            with s.server(s.STAGED, root / "proof", latex="required") as server:
                for label, mode, problem, proof in (
                    ("qc", "full", semantic.QC_PROBLEM, semantic.QC_PROOF),
                    ("compact", "compact", semantic.COMPACT_PROBLEM, semantic.COMPACT_PROOF),
                ):
                    result = semantic.run_case(server.port, server.token, server.workspace,
                        problem_id=f"mtm014-preview-{label}", problem_tex=problem, proof=proof,
                        workflow_mode=mode)
                    checks[f"{label}_required_latex"] = (
                        result["state"] == "done" and result["verdict"] == "correct"
                        and result["latex_passed"] is True and result["sealed"] is True)
                    proof_facts[label] = {key: result[key] for key in (
                        "state", "verdict", "latex_passed", "sealed", "artifact_sha256", "artifact_bytes")}
            stage = "copied_existing_state"
            legacy_target.RELEASE_BINARY = s.STAGED
            copied = historical.existing_state_upgrade(root)
            checks[stage] = (copied["server_version"] == s.VERSION
                             and copied["state_schema_version"] == 2 and copied["projects_query_ok"] is True)
            stage = "old_run_upgrade_rollback"
            checks[stage] = old_run_roundtrip(root / "resume")
            stage = "protocol2_override"
            with s.server(s.STAGED, root / "protocol2", protocol=2) as server:
                info = public.assert_tool_success(server.call("server_info", {}))
                checks[stage] = info["research_workspace"]["workflow_protocol_version"] == 2
            stage = "tui_display_contract"
            tui_env = os.environ.copy()
            tui_report = root / "tui.json"
            tui_env.update(MTM012_BINARY=str(s.STAGED), MTM012_TUI_REPORT=str(tui_report))
            result = subprocess.run(["python3", str(s.ROOT / "scripts/run_mtm012_tui_validation.py")],
                                    cwd=s.ROOT, env=tui_env, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=120, check=False)
            tui = json.loads(tui_report.read_text()) if tui_report.exists() else {}
            checks[stage] = result.returncode == 0 and tui.get("ok") is True
            stage = "tui_native_permission_flow"
            checks[stage] = s.permission_smoke(s.STAGED, root / "tui-permission", tui=True)
            stage = "resource_non_regression"
            old = s.measure(s.STABLE, root / "resource-stable")
            new = s.measure(s.STAGED, root / "resource-preview")
            checks[stage] = s.resource_ok(old, new)
            stage = "permission_soak"
            soak = s.soak(s.STAGED, root / "soak")
            checks[stage] = s.soak_ok(soak)
        checks["stable_entries_unchanged"] = s.stable_pair()
        s.require(set(checks) == s.QUALIFICATION_CHECKS and all(checks.values()), "qualification_checks")
        report = {
            "schema_version": "1.0.0", "milestone": "MTM-014", "phase": "preview_qualification",
            "version": s.VERSION, "ok": True, "recorded_at": datetime.now(timezone.utc).isoformat(),
            "source_commit": commit, "binary_sha256": binary_sha, "stable_sha256": s.STABLE_SHA,
            "implementation_commit": s.IMPLEMENTATION,
            "runtime_repair_sha256": {s.RUNTIME_REPAIR_FILE: s.RUNTIME_REPAIR_SHA},
            "harness_sha256": {path: s.digest(s.ROOT / path) for path in s.HARNESS_FILES},
            "prerequisite_sha256": {path: s.digest(s.ROOT / path) for path in s.PREREQUISITES},
            "checks": checks, "check_count": len(checks), "public_suites": {
                "safe": safe, "trusted": trusted, "dangerous": dangerous},
            "proof_facts": proof_facts, "tui_checks": tui["checks"], "required_tools": tools,
            "magma_host_status": magma, "resource": {"stable": old, "preview": new}, "soak": soak,
            "new_human_consent_claimed": False, "performance_claim": False,
            "production_state_rewritten": False, "selector_changed": False,
            "evidence_hygiene": s.HYGIENE,
        }
        stage = "receipt_validation"
        validate_qualification(report)
        with s.QUALIFICATION.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(json.dumps({"ok": True, "report": str(s.QUALIFICATION.relative_to(s.ROOT)),
                          "binary_sha256": binary_sha, "checks": len(checks),
                          "soak_iterations": soak["iterations"]}, indent=2))
        return 0
    except Exception as error:
        # Third-party helpers may put tool bodies in exception strings. Never echo them.
        label = str(error) if isinstance(error, s.ReleaseFailure) else type(error).__name__
        print(json.dumps({"ok": False, "stage": stage, "error_kind": label}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
