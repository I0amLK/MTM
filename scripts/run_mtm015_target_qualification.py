#!/usr/bin/env python3
"""Qualify the committed MTM-015 capability repair without changing selectors."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import mtm014_release_support as release
import run_mtm013_exact_stable_semantic_regression as semantic
import run_mtm013_runtime_hardening as capability
import run_mtm013_stable_qualification as historical
import run_mtm007_target_validation as legacy_target
from mtm008_runtime_harness import OPERATOR_PASSWORD, form_request
from run_checks import resolve_tool_environment


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-015/target-qualification.json"
IMPLEMENTATION_COMMIT = "94e7bde4a9a0db30fe6459ce4352e3d6661c7384"
BASE_VERSION = "0.5.0-preview.1"
VERSION = "0.5.0-preview.2"
CHECK_NAMES = {
    "committed_rust_scope",
    "candidate_release_identity",
    "permanent_capability_gate",
    "persisted_secret_owner_only",
    "same_key_restart_reuses_authority",
    "changed_key_same_owner_rejects_old_capability",
    "diagnostic_signature_stage_redacted",
    "qc_required_latex",
    "compact_required_latex",
    "copied_existing_state",
    "resource_non_regression",
    "permission_soak",
    "selectors_unchanged",
    "stable_rollback_artifact_preserved",
}
HYGIENE = {
    "raw_capability_recorded": False,
    "raw_oauth_token_recorded": False,
    "raw_secret_recorded": False,
    "raw_proof_recorded": False,
    "raw_logs_recorded": False,
}


class QualificationFailure(RuntimeError):
    pass


def require(value: Any, label: str) -> None:
    if not value:
        raise QualificationFailure(label)


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def git(*arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], cwd=ROOT, text=True).strip()


def rust_scope_unchanged(qualification_commit: str) -> bool:
    changed = subprocess.check_output(
        [
            "git", "diff", "--name-only", IMPLEMENTATION_COMMIT, qualification_commit, "--",
            "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "crates",
        ],
        cwd=ROOT,
        text=True,
    ).splitlines()
    allowed = {"Cargo.toml", "Cargo.lock"}
    allowed.update(str(path.relative_to(ROOT)) for path in ROOT.glob("crates/*/Cargo.toml"))
    if not set(changed).issubset(allowed):
        return False
    for path in changed:
        before = subprocess.check_output(["git", "show", f"{IMPLEMENTATION_COMMIT}:{path}"], cwd=ROOT)
        after = subprocess.check_output(["git", "show", f"{qualification_commit}:{path}"], cwd=ROOT)
        if after != before.replace(BASE_VERSION.encode(), VERSION.encode()):
            return False
    return True


def jwt_client_id(token: str) -> str:
    parts = token.split(".")
    require(len(parts) == 3, "oauth_token_shape")
    body = parts[1] + "=" * (-len(parts[1]) % 4)
    payload = json.loads(base64.urlsafe_b64decode(body.encode()))
    client_id = payload.get("client_id")
    require(isinstance(client_id, str) and bool(client_id), "oauth_client_id")
    return client_id


def oauth_token_for_existing_client(port: int, base: str, client_id: str) -> str:
    redirect_uri = "http://127.0.0.1/mtm008-callback"
    verifier = "R" * 43
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    status, headers, _ = form_request(
        port,
        "/oauth/authorize",
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": base,
            "state": "mtm015-state",
            "password": OPERATOR_PASSWORD,
        },
    )
    require(status in (302, 303), "existing_client_authorization")
    location = headers.get("location", "")
    code = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query).get("code", [""])[0]
    require(bool(code), "existing_client_authorization_code")
    status, _, raw = form_request(
        port,
        "/oauth/token",
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
            "client_id": client_id,
            "resource": base,
        },
    )
    payload = json.loads(raw or b"{}")
    require(status == 200 and isinstance(payload, dict), "existing_client_token_exchange")
    token = payload.get("access_token")
    require(isinstance(token, str) and bool(token), "existing_client_access_token")
    return token


class PersistedServer:
    """Disposable server that intentionally exercises persisted secret creation."""

    def __init__(
        self,
        binary: Path,
        root: Path,
        *,
        port: int | None = None,
        issue_token: bool = True,
        diagnostics: bool = False,
    ) -> None:
        self.workspace = root / "workspace"
        self.data_root = root / "data"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.port = release.free_port() if port is None else port
        self.base = f"http://127.0.0.1:{self.port}"
        self.log = tempfile.TemporaryFile()
        self.output = tempfile.TemporaryFile()
        self.log_text = ""
        environment = release.runtime_environment(self.workspace, self.data_root, "rust")
        environment.pop("MTM_TOKEN_SECRET", None)
        environment.pop("MTM_CAPABILITY_SECRET", None)
        environment.update(
            MTM_NATIVE_EXEC_BACKEND="disabled",
            MTM_NATIVE_MODE="safe",
            MTM_LATEX_POLICY="static_only",
            MTM_WORKFLOW_PROTOCOL_VERSION="3",
            MTM_TRACE_PAYLOADS="0",
            MTM_DEBUG="1" if diagnostics else "0",
        )
        command = [str(binary), "tui" if diagnostics else "serve"]
        if diagnostics:
            command.append("--verbose")
        command.extend([
            "--host", "127.0.0.1", "--port", str(self.port),
            "--workspace", str(self.workspace), "--native-mode", "safe",
            "--latex-policy", "static_only",
        ])
        self.process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=self.output,
            stderr=self.log,
            start_new_session=True,
        )
        try:
            release.wait_for_port(self.port, self.process)
            self.token = (
                release.oauth_token(self.port, self.base, "MTM-015 target qualification")
                if issue_token else ""
            )
        except BaseException:
            self.close()
            raise

    @property
    def secret_path(self) -> Path:
        return self.data_root / "oauth-token-secret.hex"

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
        try:
            code = self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL)
            code = self.process.wait(timeout=3)
        self.log.seek(0)
        raw = self.log.read(1_048_577)
        require(len(raw) <= 1_048_576, "bounded_persisted_server_log")
        self.log_text = raw.decode("utf-8", errors="replace")
        self.log.close()
        self.output.close()
        require(code == 0, "persisted_server_shutdown")


def secret_restart_and_rotation(binary: Path, root: Path) -> dict[str, bool]:
    original = root / "original"
    changed = root / "changed-key-copy"
    port = release.free_port()
    first = PersistedServer(binary, original, port=port)
    try:
        task = capability.start_run(first.port, first.token, "mtm015-persisted-secret")
        old_token = first.token
        old_capability = str(task["capability"])
        client_id = jwt_client_id(old_token)
        require(first.secret_path.is_file(), "persisted_secret_missing")
        before_fingerprint = digest(first.secret_path)
        owner_only = (first.secret_path.stat().st_mode & 0o777) == 0o600
    finally:
        first.close()
    shutil.copytree(original, changed)

    same = PersistedServer(binary, original, port=port, issue_token=False)
    try:
        same.token = old_token
        before = capability.structured(capability.tool_call(
            same.port, same.token, "rethlas_inspect",
            {"operation": "status", "run_id": task["run_id"]},
        ))
        response = capability.tool_call(
            same.port, same.token, "rethlas_step",
            capability.task_submission(task, old_capability),
        )
        value = capability.structured(response)
        expected_writes = len(task["task"]["minimal_submission"].get("writes", []))
        same_restart = (
            not capability.is_error(response)
            and value.get("ok") is True
            and value.get("state") != before.get("state")
            and value.get("writes_applied") == expected_writes
            and digest(same.secret_path) == before_fingerprint
        )
    finally:
        same.close()

    changed_secret = changed / "data/oauth-token-secret.hex"
    changed_secret.write_text(os.urandom(32).hex() + "\n", encoding="utf-8")
    os.chmod(changed_secret, 0o600)
    require(digest(changed_secret) != before_fingerprint, "changed_secret_not_distinct")
    rotated = PersistedServer(binary, changed, port=port, issue_token=False)
    try:
        rotated.token = oauth_token_for_existing_client(rotated.port, rotated.base, client_id)
        current = capability.structured(capability.tool_call(
            rotated.port, rotated.token, "rethlas_inspect",
            {"operation": "status", "run_id": task["run_id"]},
        ))
        response = capability.tool_call(
            rotated.port, rotated.token, "rethlas_step",
            capability.task_submission(task, old_capability),
        )
        value = capability.structured(response)
        submission = value.get("submission", {})
        changed_key_rejected = (
            not capability.is_error(response)
            and submission.get("error", {}).get("code") == "CAPABILITY_INVALID"
            and submission.get("capability_refreshed") is True
            and value.get("writes_applied") == 0
            and value.get("state") == current.get("state") == task.get("state")
        )
    finally:
        rotated.close()
    return {
        "owner_only": owner_only,
        "same_restart": same_restart,
        "changed_key_rejected": changed_key_rejected,
    }


def diagnostic_redaction(binary: Path, root: Path) -> bool:
    server = PersistedServer(binary, root, diagnostics=True)
    raw_capability = ""
    raw_oauth = server.token
    try:
        task = capability.start_run(server.port, server.token, "mtm015-diagnostic-redaction")
        raw_capability = str(task["capability"])
        response = capability.tool_call(
            server.port,
            server.token,
            "rethlas_step",
            capability.task_submission(task, capability.mutate_signature(raw_capability)),
        )
        value = capability.structured(response)
        require(
            value.get("submission", {}).get("error", {}).get("code") == "CAPABILITY_INVALID",
            "diagnostic_invalid_not_observed",
        )
    finally:
        server.close()
    text = server.log_text
    return (
        "signature_mismatch" in text
        and re.search(r"token_sha256=[0-9a-f]{64}", text) is not None
        and re.search(r"signer=[0-9a-f]{64}", text) is not None
        and re.search(r"instance=[0-9a-f]{32}", text) is not None
        and raw_capability not in text
        and raw_oauth not in text
        and "Bearer " not in text
    )


def proof_regression(binary: Path, root: Path) -> tuple[dict[str, bool], dict[str, Any]]:
    checks: dict[str, bool] = {}
    facts: dict[str, Any] = {}
    with release.server(binary, root, latex="required") as server:
        for label, mode, problem, proof in (
            ("qc", "full", semantic.QC_PROBLEM, semantic.QC_PROOF),
            ("compact", "compact", semantic.COMPACT_PROBLEM, semantic.COMPACT_PROOF),
        ):
            result = semantic.run_case(
                server.port,
                server.token,
                server.workspace,
                problem_id=f"mtm015-target-{label}",
                problem_tex=problem,
                proof=proof,
                workflow_mode=mode,
            )
            checks[label] = (
                result["state"] == "done"
                and result["verdict"] == "correct"
                and result["latex_passed"] is True
                and result["sealed"] is True
            )
            facts[label] = {
                key: result[key]
                for key in (
                    "state", "verdict", "latex_passed", "sealed",
                    "artifact_sha256", "artifact_bytes",
                )
            }
    return checks, facts


def main() -> int:
    os.umask(0o077)
    stage = "preconditions"
    try:
        require(not git("status", "--porcelain"), "clean_committed_source")
        qualification_commit = git("rev-parse", "HEAD")
        require(rust_scope_unchanged(qualification_commit), "committed_rust_scope")
        require(release.SELECTOR.resolve() == release.INSTALLED, "qualified_selector_unchanged")
        require(release.CARGO_ENTRY.resolve() == release.INSTALLED, "qualified_cargo_entry_unchanged")
        selector_before = digest(release.SELECTOR)
        cargo_before = digest(release.CARGO_ENTRY)
        require(
            selector_before == cargo_before == release.digest(release.INSTALLED),
            "selector_identity",
        )
        require(release.digest(release.STABLE) == release.STABLE_SHA, "stable_rollback_identity")
        tools = {
            name: shutil.which(name) is not None
            for name in ("bwrap", "git", "latexmk", "pdflatex")
        }
        require(all(tools.values()), "required_tools")
        environment, cargo, _ = resolve_tool_environment()
        require(cargo is not None, "pinned_cargo")
        environment["CARGO_INCREMENTAL"] = "0"
        (ROOT / "target").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="mtm015-qualification-build-", dir=ROOT / "target"
        ) as build:
            stage = "candidate_build"
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
            require(result.returncode == 0, "candidate_release_build")
            binary = Path(build) / "release/mtm"
            release.identity(binary, VERSION)
            binary_sha = digest(binary)
            checks = {
                "committed_rust_scope": True,
                "candidate_release_identity": True,
            }
            with tempfile.TemporaryDirectory(prefix="mtm015-target-") as temporary:
                root = Path(temporary)
                stage = "permanent_capability_gate"
                current_report = root / "current-capability.json"
                result = subprocess.run(
                    [
                        "python3", str(ROOT / "scripts/check_capability_current.py"),
                        "--binary", str(binary), "--samples", "500",
                        "--report", str(current_report),
                    ],
                    cwd=ROOT,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=180,
                    check=False,
                )
                current = json.loads(current_report.read_text()) if current_report.exists() else {}
                checks[stage] = (
                    result.returncode == 0
                    and current.get("ok") is True
                    and current.get("normal_roundtrips") == 500
                    and current.get("normal_invalid") == 0
                )

                stage = "persisted_secret_restart"
                secret_facts = secret_restart_and_rotation(binary, root / "secret")
                checks["persisted_secret_owner_only"] = secret_facts["owner_only"]
                checks["same_key_restart_reuses_authority"] = secret_facts["same_restart"]
                checks["changed_key_same_owner_rejects_old_capability"] = secret_facts[
                    "changed_key_rejected"
                ]

                stage = "diagnostic_redaction"
                checks["diagnostic_signature_stage_redacted"] = diagnostic_redaction(
                    binary, root / "diagnostic"
                )

                stage = "required_latex"
                proof_checks, proof_facts = proof_regression(binary, root / "proof")
                checks["qc_required_latex"] = proof_checks["qc"]
                checks["compact_required_latex"] = proof_checks["compact"]

                stage = "copied_existing_state"
                legacy_target.RELEASE_BINARY = binary
                copied = historical.existing_state_upgrade(root / "copied")
                checks[stage] = (
                    copied["server_version"] == VERSION
                    and copied["state_schema_version"] == 2
                    and copied["projects_query_ok"] is True
                )

                stage = "resource_non_regression"
                baseline_resource = release.measure(release.INSTALLED, root / "resource-baseline")
                candidate_resource = release.measure(binary, root / "resource-candidate")
                checks[stage] = release.resource_ok(baseline_resource, candidate_resource)

                stage = "permission_soak"
                soak = release.soak(binary, root / "soak")
                checks[stage] = release.soak_ok(soak)

            checks["selectors_unchanged"] = (
                release.SELECTOR.resolve() == release.INSTALLED
                and release.CARGO_ENTRY.resolve() == release.INSTALLED
                and digest(release.SELECTOR) == selector_before
                and digest(release.CARGO_ENTRY) == cargo_before
            )
            checks["stable_rollback_artifact_preserved"] = (
                release.STABLE.is_file() and release.digest(release.STABLE) == release.STABLE_SHA
            )
            require(set(checks) == CHECK_NAMES, "target_check_set")
            require(all(checks.values()), "target_checks")
            report = {
                "schema_version": "1.0.0",
                "milestone": "MTM-015",
                "phase": "target_qualification",
                "version": VERSION,
                "ok": True,
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "implementation_commit": IMPLEMENTATION_COMMIT,
                "qualification_commit": qualification_commit,
                "binary_sha256": binary_sha,
                "rollback_binary_sha256": selector_before,
                "stable_sha256": release.STABLE_SHA,
                "checks": checks,
                "check_count": len(checks),
                "secret_reliability": {
                    "persisted_secret_owner_only": secret_facts["owner_only"],
                    "same_key_restart_reuses_authority": secret_facts["same_restart"],
                    "changed_key_same_owner_rejects_old_capability": secret_facts[
                        "changed_key_rejected"
                    ],
                    "secret_fingerprint_recorded": False,
                },
                "proof_facts": proof_facts,
                "copied_state": {
                    key: copied[key]
                    for key in (
                        "server_version", "state_schema_version", "workflow_protocol_version",
                        "production_default", "complete_flow_locally_validated", "projects_query_ok",
                    )
                },
                "resource": {"baseline": baseline_resource, "candidate": candidate_resource},
                "soak": soak,
                "required_tools": tools,
                "harness_sha256": {
                    "scripts/run_mtm015_target_qualification.py": digest(Path(__file__)),
                    "scripts/validate_mtm015_target_qualification.py": digest(
                        ROOT / "scripts/validate_mtm015_target_qualification.py"
                    ),
                    "scripts/check_capability_current.py": digest(
                        ROOT / "scripts/check_capability_current.py"
                    ),
                },
                "web_client_tested": False,
                "installed_running_endpoint_tested": False,
                "selector_changed": False,
                "production_state_rewritten": False,
                "performance_claim": False,
                "evidence_hygiene": HYGIENE,
            }
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        temporary_report = REPORT.with_suffix(".json.tmp")
        temporary_report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        os.replace(temporary_report, REPORT)
        print(json.dumps({"ok": True, "report": str(REPORT), "checks": len(checks)}))
        return 0
    except Exception as error:
        print(json.dumps({
            "ok": False,
            "stage": stage,
            "error": str(error) if isinstance(error, QualificationFailure) else type(error).__name__,
        }))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
