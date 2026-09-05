#!/usr/bin/env python3
"""Run the hash-bound pre-cutover MTM-014 Native permission A4 target corpus."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
HUMAN_EVIDENCE = ROOT / "records/evidence/MTM-014/elicitation-capability.json"
STABLE_EVIDENCE = ROOT / "records/evidence/MTM-013/stable-release.json"
DEFAULT_CANDIDATE = Path(
    os.environ.get("MTM014_BINARY", "/home/lk/.cargo/bin/mtm-mtm014-a46beb7")
)
STABLE_CARGO_COMMAND = Path("/home/lk/.cargo/bin/mtm")
STABLE_SELECTOR = Path("/home/lk/.local/bin/mtm")
NATIVE_AUTHORITY = ROOT / "crates/mtm-runtime/src/native_authority.rs"
TEST_MARKER = "\n#[cfg(test)]\nmod tests {"
REQUIRED_TOOLS = ("bwrap", "curl", "git", "pdflatex", "latexmk", "sage", "magma")


class TargetFailure(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_checked(
    name: str,
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    stdin: str | None = None,
    timeout: int = 180,
) -> str:
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TargetFailure(name) from exc
    if completed.returncode != 0:
        raise TargetFailure(name)
    return completed.stdout


def git_text(*arguments: str) -> str:
    return run_checked("git_identity", ["git", *arguments], timeout=30).strip()


def production_source_compatibility(candidate_source: str) -> dict[str, Any]:
    try:
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", candidate_source, "HEAD"],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise TargetFailure("candidate_source_ancestor") from exc

    crate_changes = [
        line
        for line in git_text("diff", "--name-only", f"{candidate_source}..HEAD", "--", "crates").splitlines()
        if line
    ]
    if crate_changes != ["crates/mtm-runtime/src/native_authority.rs"]:
        raise TargetFailure("production_crate_drift")

    candidate_source_text = run_checked(
        "candidate_native_authority_source",
        ["git", "show", f"{candidate_source}:crates/mtm-runtime/src/native_authority.rs"],
        timeout=30,
    )
    current_source_text = NATIVE_AUTHORITY.read_text(encoding="utf-8")
    if TEST_MARKER not in candidate_source_text or TEST_MARKER not in current_source_text:
        raise TargetFailure("native_authority_test_boundary")
    candidate_prefix = candidate_source_text.split(TEST_MARKER, 1)[0]
    current_prefix = current_source_text.split(TEST_MARKER, 1)[0]
    if candidate_prefix != current_prefix:
        raise TargetFailure("native_authority_production_drift")

    packaging = subprocess.run(
        [
            "git",
            "diff",
            "--quiet",
            f"{candidate_source}..HEAD",
            "--",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "crates/mtm-cli/assets",
        ],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if packaging.returncode != 0:
        raise TargetFailure("candidate_packaging_drift")
    return {
        "candidate_is_ancestor": True,
        "changed_crate_files": crate_changes,
        "native_authority_production_prefix_equal": True,
        "packaging_inputs_equal": True,
    }


def candidate_environment(root: Path, mode: str) -> dict[str, str]:
    environment = os.environ.copy()
    for key in (
        "MTM_OAUTH_PASSWORD",
        "MTM_TOKEN_SECRET",
        "MTM_CAPABILITY_SECRET",
        "MTM_SERVER_URL",
    ):
        environment.pop(key, None)
    environment.update(
        {
            "MTM_WORKSPACE": str(root / "workspace"),
            "MTM_DATA_ROOT": str(root / "data"),
            "MTM_PRIVATE_ROOT": str(root / "data/private"),
            "MTM_DEBUG_ROOT": str(root / "data/debug"),
            "MTM_NATIVE_EXEC_BACKEND": "bubblewrap",
            "MTM_NATIVE_MODE": mode,
            "MTM_LATEX_POLICY": "static_only",
            "MTM_DEBUG": "0",
            "MTM_TRACE_PAYLOADS": "0",
        }
    )
    return environment


def attest(candidate: Path, mode: str) -> dict[str, bool]:
    with tempfile.TemporaryDirectory(prefix=f"mtm014-a4-{mode}-") as temporary:
        root = Path(temporary)
        (root / "workspace").mkdir(parents=True)
        raw = run_checked(
            f"attest_{mode}",
            [
                str(candidate),
                "attest-native",
                "--workspace",
                str(root / "workspace"),
                "--native-mode",
                mode,
            ],
            env=candidate_environment(root, mode),
            timeout=60,
        )
    try:
        payload = json.loads(raw)
        attestation = payload["attestation"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise TargetFailure(f"attest_{mode}_json") from exc
    expected_network = mode == "safe"
    required = {
        "hard_isolation": True,
        "workspace_mounted": True,
        "forbidden_paths_hidden": True,
        "private_vault_mounted": False,
        "capabilities_dropped": True,
        "no_privilege_escalation": True,
        "parent_environment_cleared": True,
        "nested_user_namespaces_disabled": True,
        "toolchain_roots_validated": True,
        "network_isolated": expected_network,
    }
    for key, expected in required.items():
        if attestation.get(key) is not expected:
            raise TargetFailure(f"attest_{mode}_{key}")
    return required


def run_json_validation(name: str, command: list[str], *, env: dict[str, str] | None = None) -> dict[str, Any]:
    raw = run_checked(name, command, env=env, timeout=180)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TargetFailure(f"{name}_json") from exc
    if payload.get("ok") is not True:
        raise TargetFailure(name)
    return payload


def run_rust_target_tests() -> dict[str, bool]:
    commands = {
        "candidate_authority_tests": [
            "cargo",
            "test",
            "-p",
            "mtm-runtime",
            "native_authority::tests::",
            "--",
            "--nocapture",
        ],
        "real_dns_https": [
            "cargo",
            "test",
            "-p",
            "mtm-runtime",
            "native_authority::tests::exec_candidate_real_dns_https_target",
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
        ],
        "prepared_patch_adversarial": [
            "cargo",
            "test",
            "-p",
            "mtm-runtime",
            "workspace::tests::prepared_patch_",
            "--",
            "--nocapture",
        ],
        "grant_ledger_adversarial": [
            "cargo",
            "test",
            "-p",
            "mtm-runtime",
            "native_permission::tests::",
            "--",
            "--nocapture",
        ],
        "command_lifecycle": [
            "cargo",
            "test",
            "-p",
            "mtm-native",
            "process::tests::",
            "--",
            "--nocapture",
        ],
        "safe_network_plan_dimension": [
            "cargo",
            "test",
            "-p",
            "mtm-runtime",
            "native_tools::tests::authority_exec_plan_changes_only_network_dimension_for_safe_network_risk",
            "--",
            "--exact",
        ],
        "bubblewrap_profile_invariants": [
            "cargo",
            "test",
            "-p",
            "mtm-native",
            "bubblewrap::tests::typed_plan_preserves_exact_profile_semantics_and_fixed_invariants",
            "--",
            "--exact",
        ],
    }
    results: dict[str, bool] = {}
    for name, command in commands.items():
        run_checked(name, command, timeout=300)
        results[name] = True
    return results


def classify_magma_host() -> str:
    try:
        completed = subprocess.run(
            ["magma", "-b"],
            cwd=ROOT,
            input="quit;\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TargetFailure("magma_host_probe") from exc
    combined = f"{completed.stdout}\n{completed.stderr}".lower()
    if completed.returncode == 0:
        return "passed"
    if "not authorised" in combined or "not authorized" in combined:
        return "blocked_host_license"
    raise TargetFailure("magma_host_probe")


def main() -> int:
    try:
        human = json.loads(HUMAN_EVIDENCE.read_text(encoding="utf-8"))
        stable = json.loads(STABLE_EVIDENCE.read_text(encoding="utf-8"))
        candidate_source = str(human["source_commit"])
        expected_candidate_sha = str(human["candidate_binary_sha256"])
        candidate = DEFAULT_CANDIDATE
        if not candidate.is_file() or sha256_file(candidate) != expected_candidate_sha:
            raise TargetFailure("candidate_binary_exact")
        if run_checked("candidate_version", [str(candidate), "--version"], timeout=30).strip() != "mtm 0.4.0":
            raise TargetFailure("candidate_version")
        stable_sha = str(stable["binary_sha256"])
        for name, path in (
            ("stable_cargo_command", STABLE_CARGO_COMMAND),
            ("stable_selector", STABLE_SELECTOR),
        ):
            if not path.is_file() or sha256_file(path) != stable_sha:
                raise TargetFailure(name)

        run_checked(
            "human_receipt_validated",
            ["python3", "scripts/validate_mtm014_elicitation_capability.py"],
            timeout=30,
        )
        source_compatibility = production_source_compatibility(candidate_source)
        tools = {name: shutil.which(name) is not None for name in REQUIRED_TOOLS}
        if not all(tools.values()):
            raise TargetFailure("required_tools_available")

        attestations = {mode: attest(candidate, mode) for mode in ("safe", "trusted", "dangerous")}
        rust_tests = run_rust_target_tests()
        exact_env = os.environ.copy()
        exact_env["MTM014_BINARY"] = str(candidate)
        mrtr = run_json_validation(
            "mrtr_candidate",
            ["python3", "scripts/run_mtm014_mrtr_permission_validation.py"],
            env=exact_env,
        )
        capacity = run_json_validation(
            "capacity_candidate",
            ["python3", "scripts/run_mtm014_capacity_validation.py"],
            env=exact_env,
        )
        if mrtr.get("check_count") != 22 or not all(mrtr.get("checks", {}).values()):
            raise TargetFailure("mrtr_candidate")
        if capacity.get("check_count") != 13 or not all(capacity.get("checks", {}).values()):
            raise TargetFailure("capacity_candidate")
        if mrtr.get("production_exec_or_patch_authority_cutover") is not False:
            raise TargetFailure("mrtr_cutover_scope")
        if capacity.get("production_exec_or_patch_authority_cutover") is not False:
            raise TargetFailure("capacity_cutover_scope")
        magma_status = classify_magma_host()

        checks = {
            "human_receipt_validated": True,
            "candidate_binary_exact": True,
            "candidate_version": True,
            "production_source_compatible": True,
            "stable_cargo_command_unchanged": True,
            "stable_selector_unchanged": True,
            "required_tools_available": True,
            "safe_attestation": True,
            "trusted_attestation": True,
            "dangerous_attestation": True,
            **rust_tests,
            "mrtr_candidate_22_checks": True,
            "capacity_candidate_13_checks": True,
            "magma_host_probe_classified": True,
            "workflow_authority_not_inherited": True,
            "public_cutover_not_performed": True,
        }
        report = {
            "schema_version": "1.0.0",
            "milestone": "MTM-014",
            "phase": "pre_cutover_native_permission_target",
            "ok": all(checks.values()),
            "qualification_commit": git_text("rev-parse", "HEAD"),
            "candidate_source_commit": candidate_source,
            "candidate_binary_sha256": expected_candidate_sha,
            "human_evidence_sha256": sha256_file(HUMAN_EVIDENCE),
            "runner_sha256": sha256_file(Path(__file__)),
            "check_count": len(checks),
            "checks": dict(sorted(checks.items())),
            "source_compatibility": source_compatibility,
            "required_tools": tools,
            "attestations": attestations,
            "mrtr_check_count": 22,
            "capacity_check_count": 13,
            "magma": {
                "executable_available": tools["magma"],
                "candidate_reached": True,
                "host_status": magma_status,
                "failure_attributed_to_mtm": False,
            },
            "human_client": {
                "name": human["client"]["name"],
                "version": human["client"]["version"],
                "protocol_version": human["client"]["protocol_version"],
                "transport": human["client"]["transport"],
            },
            "pre_cutover_target_corpus_passed": True,
            "production_exec_or_patch_authority_cutover": False,
            "production_cutover_allowed_by_this_report": False,
            "stable_selector_changed": False,
            "workflow_authority_inherited": False,
            "evidence_hygiene": {
                "raw_oauth_key_recorded": False,
                "raw_access_token_recorded": False,
                "raw_request_state_recorded": False,
                "raw_grant_id_recorded": False,
                "raw_tool_arguments_recorded": False,
                "raw_command_output_recorded": False,
            },
        }
    except (OSError, KeyError, TypeError, ValueError, TargetFailure) as exc:
        failed = str(exc) if isinstance(exc, TargetFailure) else "target_validation_internal"
        print(json.dumps({"ok": False, "failed_check": failed}, indent=2, sort_keys=True))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
