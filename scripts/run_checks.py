#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
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
    if project_cargo.is_file() and project_rustc.is_file():
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
                run(
                    "mtm003_conformance",
                    [sys.executable, "scripts/run_mtm003_conformance.py"],
                    env=environment,
                    capture_json=True,
                ),
                run(
                    "mtm003_target_evidence",
                    [sys.executable, "scripts/validate_mtm003_target_evidence.py"],
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
        "milestone": "MTM-003",
        "production_authority": "python",
        "passed": all(item["passed"] for item in checks),
        "checks": checks,
        "local_claim": (
            "MTM-001 governance, MTM-002 pure Rust contracts/policies, and MTM-003 Native "
            "process/isolation code were validated by Rust tests plus frozen Python-Rust "
            "differential checks. This gate verifies the freshness and completeness of the "
            "separately executed MTM-003 target report but does not itself re-run Bubblewrap, "
            "Sage, Magma, or Quick Tunnel. No SQLite, OAuth/MCP, workflow, finalizer, packaging, "
            "A6 performance, or Python-retirement authority is claimed."
        ),
    }
    temporary = REPORT.with_name(REPORT.name + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(REPORT)
    print(json.dumps({"ok": payload["passed"], "report": str(REPORT)}, indent=2))
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
