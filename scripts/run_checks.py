#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "local-validation.json"


def run(
    name: str,
    command: list[str],
    *,
    env: dict[str, str],
    capture_json: bool = False,
) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    output = completed.stdout
    result: dict[str, Any] = {
        "name": name,
        "command": command,
        "passed": completed.returncode == 0,
        "exit_code": completed.returncode,
        "output_tail": output[-20_000:],
    }
    if capture_json and completed.returncode == 0:
        try:
            result["json"] = json.loads(output)
        except json.JSONDecodeError as exc:
            result["passed"] = False
            result["parse_error"] = str(exc)
    return result


def resolve_tool_environment() -> tuple[dict[str, str], str | None, str | None]:
    environment = os.environ.copy()
    project_cargo_home = ROOT / ".toolchain" / "cargo"
    project_rustup_home = ROOT / ".toolchain" / "rustup"
    project_cargo = project_cargo_home / "bin" / "cargo"
    project_rustc = project_cargo_home / "bin" / "rustc"

    cargo = shutil.which("cargo")
    rustc = shutil.which("rustc")
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
    channel = str(toolchain.get("toolchain", {}).get("channel") or "").strip()
    pinned_bins = sorted(project_rustup_home.glob(f"toolchains/{channel}-*/bin")) if channel else []
    if len(pinned_bins) == 1 and (pinned_bins[0] / "cargo").is_file() and (pinned_bins[0] / "rustc").is_file():
        cargo = str(pinned_bins[0] / "cargo")
        rustc = str(pinned_bins[0] / "rustc")
        environment["CARGO_HOME"] = str(project_cargo_home)
        environment["RUSTUP_HOME"] = str(project_rustup_home)
        environment["PATH"] = (
            str(pinned_bins[0])
            + os.pathsep
            + str(project_cargo_home / "bin")
            + os.pathsep
            + environment.get("PATH", "")
        )
    elif project_cargo.is_file() and project_rustc.is_file():
        cargo = str(project_cargo)
        rustc = str(project_rustc)
        environment["CARGO_HOME"] = str(project_cargo_home)
        environment["RUSTUP_HOME"] = str(project_rustup_home)
        environment["PATH"] = str(project_cargo_home / "bin") + os.pathsep + environment.get(
            "PATH", ""
        )
    return environment, cargo, rustc


def main() -> int:
    environment, cargo, rustc = resolve_tool_environment()
    progress = json.loads((ROOT / "project-progress.json").read_text(encoding="utf-8"))
    mtm009_preview_mode = (
        str(progress.get("version") or "").startswith("0.4.0-preview.")
        and progress.get("current_milestone") == "MTM-009"
        and progress.get("status") == "MTM-009-in-progress"
    )
    mtm011_preview_mode = (
        progress.get("version") == "0.4.0-preview.2"
        and progress.get("current_milestone") in {"MTM-011", "MTM-012"}
        and progress.get("status")
        in {"MTM-011-in-progress", "MTM-011-completed", "MTM-012-in-progress"}
    )
    mtm011_cutover_mode = mtm011_preview_mode
    mtm012_source_mode = (
        progress.get("current_milestone") == "MTM-012"
        and progress.get("status") == "MTM-012-in-progress"
    )
    checks: list[dict[str, Any]] = [
        run(
            "migration_graph",
            [sys.executable, "scripts/validate_migration_graph.py"],
            env=environment,
        ),
        run(
            "engineering_graph",
            [sys.executable, "scripts/validate_engineering_graph.py"],
            env=environment,
        ),
        run(
            "mtm009_research_contract",
            [sys.executable, "scripts/validate_mtm009_research_contract.py"],
            env=environment,
            capture_json=True,
        ),
        run(
            "python_governance_tests",
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
            env=environment,
        ),
    ]

    if cargo is None or rustc is None:
        checks.append(
            {
                "name": "rust_toolchain",
                "command": [],
                "passed": False,
                "exit_code": 127,
                "output_tail": "cargo/rustc not found; install the pinned rust-toolchain.toml toolchain",
            }
        )
    else:
        checks.extend(
            [
                run("rustc_version", [rustc, "--version"], env=environment),
                run("cargo_version", [cargo, "--version"], env=environment),
                run("cargo_fmt", [cargo, "fmt", "--all", "--", "--check"], env=environment),
                run(
                    "cargo_clippy",
                    [cargo, "clippy", "--workspace", "--all-targets", "--", "-D", "warnings"],
                    env=environment,
                ),
                run("cargo_test", [cargo, "test", "--workspace"], env=environment),
                run(
                    "mtm002_conformance",
                    [sys.executable, "scripts/run_mtm002_conformance.py"],
                    env=environment,
                    capture_json=True,
                ),
                *(
                    []
                    if mtm011_cutover_mode
                    else [
                        run(
                            "mtm003_conformance",
                            [sys.executable, "scripts/run_mtm003_conformance.py"],
                            env=environment,
                            capture_json=True,
                        )
                    ]
                ),
                run(
                    "mtm004_conformance",
                    [sys.executable, "scripts/run_mtm004_conformance.py"],
                    env=environment,
                    capture_json=True,
                ),
                run(
                    "mtm005_conformance",
                    [sys.executable, "scripts/run_mtm005_conformance.py"],
                    env=environment,
                    capture_json=True,
                ),
                run(
                    "mtm006_conformance",
                    [sys.executable, "scripts/run_mtm006_conformance.py"],
                    env=environment,
                    capture_json=True,
                ),
                run(
                    "mtm007_conformance",
                    [sys.executable, "scripts/run_mtm007_conformance.py"],
                    env=environment,
                    capture_json=True,
                ),
                *(
                    [
                        run(
                            "historical_release_evidence",
                            [sys.executable, "scripts/validate_historical_mtm_release_evidence.py"],
                            env=environment,
                            capture_json=True,
                        ),
                        *(
                            [
                                run(
                                    "mtm009_preview_release",
                                    [sys.executable, "scripts/validate_mtm009_preview_release.py"],
                                    env=environment,
                                    capture_json=True,
                                )
                            ]
                            if mtm009_preview_mode
                            else [
                                *(
                                    []
                                    if mtm012_source_mode
                                    else [
                                        run(
                                            "mtm011_cutover_source",
                                            [
                                                sys.executable,
                                                "scripts/validate_mtm011_cutover_source.py",
                                            ],
                                            env=environment,
                                            capture_json=True,
                                        )
                                    ]
                                ),
                                run(
                                    "mtm011_cutover_resource",
                                    [sys.executable, "scripts/validate_mtm011_cutover_resource.py"],
                                    env=environment,
                                    capture_json=True,
                                ),
                                run(
                                    "mtm011_preview_release",
                                    [sys.executable, "scripts/validate_mtm011_preview_release.py"],
                                    env=environment,
                                    capture_json=True,
                                ),
                            ]
                        ),
                    ]
                    if mtm009_preview_mode or mtm011_preview_mode
                    else [
                        run(
                            "mtm003_target_evidence",
                            [sys.executable, "scripts/validate_mtm003_target_evidence.py"],
                            env=environment,
                            capture_json=True,
                        ),
                        run(
                            "mtm004_target_evidence",
                            [sys.executable, "scripts/validate_mtm004_target_evidence.py"],
                            env=environment,
                            capture_json=True,
                        ),
                        run(
                            "mtm005_target_evidence",
                            [sys.executable, "scripts/validate_mtm005_target_evidence.py"],
                            env=environment,
                            capture_json=True,
                        ),
                        run(
                            "mtm006_target_evidence",
                            [sys.executable, "scripts/validate_mtm006_target_evidence.py"],
                            env=environment,
                            capture_json=True,
                        ),
                        run(
                            "mtm007_target_evidence",
                            [sys.executable, "scripts/validate_mtm007_target_evidence.py"],
                            env=environment,
                            capture_json=True,
                        ),
                        run(
                            "mtm008_candidate_evidence",
                            [sys.executable, "scripts/validate_mtm008_candidate_evidence.py"],
                            env=environment,
                            capture_json=True,
                        ),
                    ]
                ),
                run(
                    "mtm_command_namespace",
                    [sys.executable, "scripts/validate_mtm_command_namespace.py"],
                    env=environment,
                    capture_json=True,
                ),
                run(
                    "bootstrap_contract",
                    [cargo, "run", "-q", "-p", "mtm-cli", "--", "contract"],
                    env=environment,
                    capture_json=True,
                ),
                run(
                    "bootstrap_status",
                    [cargo, "run", "-q", "-p", "mtm-cli", "--", "status"],
                    env=environment,
                    capture_json=True,
                ),
                run(
                    "release_info",
                    [cargo, "run", "-q", "-p", "mtm-cli", "--", "release-info"],
                    env=environment,
                    capture_json=True,
                ),
            ]
        )

    contract_check = next((item for item in checks if item["name"] == "bootstrap_contract"), None)
    if contract_check is not None and contract_check.get("passed"):
        expected = json.loads(
            (ROOT / "conformance" / "golden" / "source-contract-v1.json").read_text(
                encoding="utf-8"
            )
        )
        actual = contract_check.get("json")
        checks.append(
            {
                "name": "golden_contract_match",
                "command": ["compare", "bootstrap_contract", "source-contract-v1.json"],
                "passed": actual == expected,
                "exit_code": 0 if actual == expected else 1,
                "output_tail": json.dumps(
                    {"expected": expected, "actual": actual}, ensure_ascii=False, sort_keys=True
                ),
            }
        )

    if (ROOT / ".git").exists():
        checks.append(run("git_diff_check", ["git", "diff", "--check"], env=environment))
        checks.append(
            run("git_staged_diff_check", ["git", "diff", "--cached", "--check"], env=environment)
        )

    payload = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "project": "MTM-reboot",
        "milestone": progress.get("current_milestone") or "MTM-008",
        "production_authority": progress.get("current_production_authority", "python"),
        "passed": all(item["passed"] for item in checks),
        "checks": checks,
        "local_claim": (
            "MTM-001 through MTM-008 remain accepted historical milestones with immutable "
            "hash-bound evidence. MTM 0.4.0-preview.1 is the current installed command for new "
            "launches under Rust authority, state schema 2, 24 public tools, 11 hidden aliases, "
            "and workflow protocol 2 as the production default. MTM-009 protocol 3 is an explicit "
            "opt-in mathematical research-state workflow with bounded advisory context; it does "
            "not become the production default until paired real-web A4 passes. The preview has "
            "current release, A5, rollback/recutover, namespace, TUI tool-visibility/redaction, "
            "and protocol-1/2 conformance evidence. Existing 0.3.0 sessions were deliberately not "
            "restarted. The only final mathematical artifact remains proof_verified.tex."
        ),
    }
    temporary = REPORT.with_name(REPORT.name + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(REPORT)
    print(json.dumps({"ok": payload["passed"], "report": str(REPORT)}, indent=2))
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
