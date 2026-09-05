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
REPORT = ROOT / "records/validation/local-validation.json"


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
    progress = json.loads((ROOT / "records/governance/project-progress.json").read_text(encoding="utf-8"))
    selector = Path("/home/lk/.local/bin/mtm")
    mtm014_source_mode = progress.get("current_milestone") == "MTM-014"
    mtm014_preview_selected = (
        mtm014_source_mode and selector.is_symlink()
        and "/releases/0.5.0-preview.1/" in str(selector.resolve())
    )
    mtm013_stable_deployed_mode = (
        progress.get("version") == "0.4.0"
        and progress.get("current_milestone") in {"MTM-013", "MTM-014"}
        and progress.get("status")
        in {"MTM-013-in-progress", "MTM-013-completed", "MTM-014-in-progress", "MTM-014-completed"}
        and (ROOT / "records/evidence/MTM-013/stable-release.json").is_file()
        and selector.is_symlink()
        and "/releases/0.4.0/" in str(selector.resolve())
    )
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
    mtm012_preview_mode = (
        progress.get("version") in {"0.4.0-preview.3", "0.4.0"}
        and progress.get("current_milestone") in {"MTM-012", "MTM-013"}
        and progress.get("status")
        in {"MTM-012-in-progress", "MTM-012-completed", "MTM-013-in-progress"}
        and not mtm013_stable_deployed_mode
    )
    current_preview_mode = mtm011_preview_mode or mtm012_preview_mode
    historical_release_mode = (
        mtm009_preview_mode or current_preview_mode or mtm013_stable_deployed_mode or mtm014_source_mode
    )
    mtm011_cutover_mode = current_preview_mode or mtm013_stable_deployed_mode or mtm014_source_mode
    mtm012_source_mode = (
        progress.get("current_milestone") == "MTM-012"
        and progress.get("status") == "MTM-012-in-progress"
    )
    mtm013_stable_source_mode = (
        progress.get("current_milestone") == "MTM-013"
        and progress.get("status") == "MTM-013-in-progress"
        and progress.get("version") == "0.4.0"
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
            "record_layout",
            [sys.executable, "scripts/validate_record_layout.py"],
            env=environment,
            capture_json=True,
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
    if (ROOT / "records/evidence/MTM-013/exact-stable-semantic-regression.json").is_file():
        checks.append(
            run(
                "mtm013_exact_stable_semantic_regression",
                [sys.executable, "scripts/validate_mtm013_exact_stable_semantic_regression.py"],
                env=environment,
                capture_json=True,
            )
        )
    if (ROOT / "records/evidence/MTM-014/elicitation-capability.json").is_file():
        checks.append(
            run(
                "mtm014_elicitation_capability",
                [sys.executable, "scripts/validate_mtm014_elicitation_capability.py"],
                env=environment,
                capture_json=True,
            )
        )
    if (ROOT / "records/evidence/MTM-014/native-permission-target.json").is_file():
        checks.append(
            run(
                "mtm014_native_permission_target",
                [sys.executable, "scripts/validate_mtm014_native_permission_target.py"],
                env=environment,
                capture_json=True,
            )
        )
    if (ROOT / "records/evidence/MTM-014/public-authority-target.json").is_file():
        checks.append(
            run(
                "mtm014_public_authority_target",
                [sys.executable, "scripts/validate_mtm014_public_authority_target.py"],
                env=environment,
                capture_json=True,
            )
        )
    if (ROOT / "records/evidence/MTM-014/preview-qualification.json").is_file():
        checks.append(run(
            "mtm014_preview_qualification", [sys.executable, "scripts/validate_mtm014_preview_release.py"],
            env=environment, capture_json=True,
        ))
    if (ROOT / "records/evidence/MTM-014/preview-release.json").is_file() or mtm014_preview_selected:
        checks.append(run(
            "mtm014_preview_deployment", [sys.executable, "scripts/validate_mtm014_preview_release.py", "--deployed"],
            env=environment, capture_json=True,
        ))
    if progress.get("current_milestone") == "MTM-013":
        checks.append(
            run(
                "mtm013_runtime_hardening",
                [sys.executable, "scripts/validate_mtm013_runtime_hardening.py"],
                env=environment,
                capture_json=True,
            )
        )
        if (ROOT / "records/evidence/MTM-013/stable-qualification.json").is_file():
            checks.append(
                run(
                    "mtm013_stable_qualification",
                    [sys.executable, "scripts/validate_mtm013_stable_qualification.py"],
                    env=environment,
                    capture_json=True,
                )
            )
            checks.append(
                run(
                    "mtm013_stable_resource",
                    [sys.executable, "scripts/validate_mtm013_stable_resource.py"],
                    env=environment,
                    capture_json=True,
                )
            )

        if (ROOT / "records/evidence/MTM-013/public-install.json").is_file():
            checks.append(
                run(
                    "mtm013_public_install",
                    [sys.executable, "scripts/validate_mtm013_public_install.py"],
                    env=environment,
                    capture_json=True,
                )
            )

        if (ROOT / "records/evidence/MTM-013/stable-release.json").is_file():
            checks.append(
                run(
                    "mtm013_stable_release",
                    [sys.executable, "scripts/validate_mtm013_stable_release.py"],
                    env=environment,
                    capture_json=True,
                )
            )

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
                            else (
                                []
                                if mtm013_stable_deployed_mode or mtm014_source_mode
                                else (
                                [
                                    *(
                                        []
                                        if mtm013_stable_source_mode
                                        else [
                                            run(
                                                "mtm012_tui_validation",
                                                [
                                                    sys.executable,
                                                    "scripts/validate_mtm012_tui_validation.py",
                                                ],
                                                env=environment,
                                                capture_json=True,
                                            )
                                        ]
                                    ),
                                    run(
                                        "mtm012_preview_release",
                                        [
                                            sys.executable,
                                            "scripts/validate_mtm012_preview_release.py",
                                        ],
                                        env=environment,
                                        capture_json=True,
                                    ),
                                ]
                                if mtm012_preview_mode
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
                                        [
                                            sys.executable,
                                            "scripts/validate_mtm011_cutover_resource.py",
                                        ],
                                        env=environment,
                                        capture_json=True,
                                    ),
                                    run(
                                        "mtm011_preview_release",
                                        [
                                            sys.executable,
                                            "scripts/validate_mtm011_preview_release.py",
                                        ],
                                        env=environment,
                                        capture_json=True,
                                    ),
                                ]
                                )
                            )
                        ),
                    ]
                    if historical_release_mode
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
            "MTM-014 preview is selected for new launches. Its separate release and deployment "
            "gates bind exact Native authority, rollback/recutover and bounded soak evidence; "
            "stable 0.4.0 is preserved. Existing sessions are not restarted by selector changes."
            if mtm014_preview_selected else
            (
                "MTM 0.4.0 is the active stable command for new launches under Rust authority. "
                "The public Git install, exact stable binary identity, workflow protocol 3 default, "
                "explicit protocol-2 rollback, selector rollback/recutover, command namespace, "
                "state schema 2, 24 public tools, 11 hidden aliases, and proof_verified.tex "
                "finalization path are locally validated. Historical MTM-001 through MTM-012 "
                "evidence remains immutable; existing runs are not rewritten by the stable cutover."
            )
            if mtm013_stable_deployed_mode
            else (
                "MTM-001 through MTM-012 remain accepted historical milestones with immutable "
                "hash-bound evidence while MTM-013 stable qualification is in progress. The only "
                "final mathematical artifact remains proof_verified.tex."
            )
        ),
    }
    temporary = REPORT.with_name(REPORT.name + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(REPORT)
    print(json.dumps({"ok": payload["passed"], "report": str(REPORT)}, indent=2))
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
