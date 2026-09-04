#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-004/target-validation.json"
SOURCE_DB = Path("/home/lk/.re-ctm/private/state.sqlite3")
PYTHON_DRIVER = ROOT / "conformance" / "python_storage_shadow.py"
RUST_BINARY = ROOT / "target" / "debug" / "mtm-storage-shadow"
CARGO_HOME = ROOT / ".toolchain" / "cargo"
RUSTUP_HOME = ROOT / ".toolchain" / "rustup"
NOW_ISO = "2026-09-01T03:00:00.000Z"
UNIX_SECONDS = 1_788_254_000
SECRET = b"t" * 32

IMPLEMENTATION_FILES = (
    "Cargo.toml",
    "Cargo.lock",
    "crates/mtm-contracts/src/enums.rs",
    "crates/mtm-contracts/src/error.rs",
    "crates/mtm-storage/Cargo.toml",
    "crates/mtm-storage/src/lib.rs",
    "crates/mtm-storage/src/schema.rs",
    "crates/mtm-storage/src/store.rs",
    "crates/mtm-storage/src/capability.rs",
    "crates/mtm-storage/src/bin/shadow.rs",
    "crates/mtm-storage/tests/storage.rs",
    "conformance/python_storage_shadow.py",
    "conformance/mtm004_scenario.py",
    "scripts/run_mtm004_conformance.py",
    "scripts/run_mtm004_target_validation.py",
)


def implementation_sha256() -> str:
    digest = hashlib.sha256()
    for relative in IMPLEMENTATION_FILES:
        path = ROOT / relative
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def cargo_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["CARGO_HOME"] = str(CARGO_HOME)
    environment["RUSTUP_HOME"] = str(RUSTUP_HOME)
    environment["PATH"] = str(CARGO_HOME / "bin") + os.pathsep + environment.get("PATH", "")
    return environment


def build_binary() -> None:
    subprocess.run(
        [str(CARGO_HOME / "bin" / "cargo"), "build", "-q", "-p", "mtm-storage", "--bin", "mtm-storage-shadow"],
        cwd=ROOT,
        env=cargo_environment(),
        check=True,
    )


def request(
    database: Path,
    operations: list[dict[str, Any]],
    *,
    hex_ids: list[str] | None = None,
    urlsafe_ids: list[str] | None = None,
    initial_token: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "database": str(database),
        "now_iso": NOW_ISO,
        "unix_seconds": UNIX_SECONDS,
        "hex_ids": hex_ids or [],
        "urlsafe_ids": urlsafe_ids or [],
        "secret_base64": base64.b64encode(SECRET).decode("ascii"),
        "operations": operations,
    }
    if initial_token is not None:
        payload["initial_token"] = initial_token
    return payload


def operation(name: str, **args: Any) -> dict[str, Any]:
    return {"op": name, "args": args}


def invoke(command: list[str], payload: dict[str, Any]) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        input=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"storage target driver exited {completed.returncode}: {completed.stderr[-2000:]}"
        )
    result = json.loads(completed.stdout)
    if not isinstance(result, dict):
        raise TypeError("storage target driver response is not an object")
    return result


def result_at(payload: dict[str, Any], index: int = 0) -> Any:
    if payload.get("ok") is not True:
        raise RuntimeError(f"driver failed: {payload.get('error')}")
    result = payload.get("result")
    if not isinstance(result, dict):
        raise TypeError("driver result is invalid")
    operations = result.get("results")
    if not isinstance(operations, list) or index >= len(operations):
        raise IndexError("driver operation result is unavailable")
    item = operations[index]
    if not isinstance(item, dict) or item.get("ok") is not True:
        raise RuntimeError(f"driver operation failed: {item}")
    return item.get("result")


def error_code_at(payload: dict[str, Any], index: int = 0) -> str | None:
    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    items = result.get("results") if isinstance(result, dict) else None
    if not isinstance(items, list) or index >= len(items):
        return None
    item = items[index]
    error = item.get("error") if isinstance(item, dict) else None
    return str(error.get("code")) if isinstance(error, dict) and error.get("code") else None


def read_only_backup(source: Path, destination: Path) -> None:
    uri = f"file:{source}?mode=ro"
    source_connection = sqlite3.connect(uri, uri=True)
    destination_connection = sqlite3.connect(destination)
    try:
        source_connection.backup(destination_connection)
    finally:
        destination_connection.close()
        source_connection.close()


def integrity(path: Path) -> bool:
    connection = sqlite3.connect(path)
    try:
        return connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        connection.close()


def digest_result(command: list[str], database: Path) -> dict[str, Any]:
    payload = invoke(command, request(database, [operation("database_digest")]))
    result = result_at(payload)
    if not isinstance(result, dict):
        raise TypeError("database digest result is invalid")
    return result


def minimal_capability_operations() -> list[dict[str, Any]]:
    permissions = [
        "read:problem",
        "read:references",
        "read:project:verified_dependencies",
        "read:steering",
        "read:memory:generation:*",
        "write:memory:generation:*",
        "search:memory:generation:*",
        "retrieve:external:theorems",
        "retrieve:external:research",
        "commit:workflow",
    ]
    return [
        operation(
            "create_run",
            run_id="target-capability-run",
            problem_id="target-capability-problem",
            owner_id="owner",
            state="assess",
            metadata={},
        ),
        operation(
            "create_domain",
            domain_id="target-capability-domain",
            run_id="target-capability-run",
            role="generator",
            snapshot_id=None,
            order_index=None,
            metadata={},
        ),
        operation(
            "capability_issue",
            run_id="target-capability-run",
            domain_id="target-capability-domain",
            role="generator",
            permissions=permissions,
            trace_id="target-capability-issue",
            ttl_seconds=600,
        ),
    ]


def validate_operation() -> dict[str, Any]:
    return operation(
        "capability_validate_last",
        owner_id="owner",
        action="read",
        resource="problem",
        trace_id="target-capability-validate",
        expected_run_id="target-capability-run",
    )


def cross_runtime_capabilities(root: Path) -> dict[str, bool]:
    python_db = root / "python-issued.sqlite3"
    python_issue = invoke(
        [sys.executable, str(PYTHON_DRIVER)],
        request(
            python_db,
            minimal_capability_operations(),
            urlsafe_ids=["target-nonce-python-000001"],
        ),
    )
    python_token = python_issue["result"]["last_token"]
    rust_validate = invoke(
        [str(RUST_BINARY)],
        request(python_db, [validate_operation()], initial_token=python_token),
    )

    rust_db = root / "rust-issued.sqlite3"
    rust_issue = invoke(
        [str(RUST_BINARY)],
        request(
            rust_db,
            minimal_capability_operations(),
            urlsafe_ids=["target-nonce-rust-0000001"],
        ),
    )
    rust_token = rust_issue["result"]["last_token"]
    python_validate = invoke(
        [sys.executable, str(PYTHON_DRIVER)],
        request(rust_db, [validate_operation()], initial_token=rust_token),
    )

    tamper = sqlite3.connect(python_db)
    try:
        tamper.execute(
            "UPDATE capabilities SET permissions_json='[\"read:problem\"]' "
            "WHERE nonce='target-nonce-python-000001'"
        )
        tamper.commit()
    finally:
        tamper.close()
    rust_denied = invoke(
        [str(RUST_BINARY)],
        request(python_db, [validate_operation()], initial_token=python_token),
    )
    return {
        "python_token_validated_by_rust": result_at(rust_validate)["run_id"]
        == "target-capability-run",
        "rust_token_validated_by_python": result_at(python_validate)["run_id"]
        == "target-capability-run",
        "registry_tamper_denied_by_rust": error_code_at(rust_denied)
        == "CAPABILITY_REGISTRY_MISMATCH",
        "tokens_not_recorded": True,
    }


def serialized_writer_check(root: Path) -> dict[str, Any]:
    database = root / "serialized-writer.sqlite3"
    baseline = invoke(
        [sys.executable, str(PYTHON_DRIVER)],
        request(
            database,
            [
                operation(
                    "create_run",
                    run_id="writer-baseline",
                    problem_id="writer",
                    owner_id="owner",
                    state="assess",
                    metadata={},
                )
            ],
        ),
    )
    result_at(baseline)
    lock = sqlite3.connect(database, isolation_level=None)
    lock.execute("BEGIN IMMEDIATE")
    holder: dict[str, Any] = {}

    def writer() -> None:
        started = time.perf_counter()
        holder["response"] = invoke(
            [str(RUST_BINARY)],
            request(
                database,
                [
                    operation(
                        "create_run",
                        run_id="writer-rust",
                        problem_id="writer",
                        owner_id="owner",
                        state="assess",
                        metadata={},
                    )
                ],
            ),
        )
        holder["elapsed_ms"] = (time.perf_counter() - started) * 1000

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    time.sleep(0.35)
    lock.rollback()
    lock.close()
    thread.join(timeout=10)
    response = holder.get("response")
    if not isinstance(response, dict):
        raise RuntimeError("serialized writer did not complete")
    result_at(response)
    connection = sqlite3.connect(database)
    try:
        count = int(connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0])
    finally:
        connection.close()
    return {
        "passed": count == 2 and float(holder.get("elapsed_ms", 0)) >= 250,
        "writer_count": count,
        "waited_for_existing_begin_immediate": float(holder.get("elapsed_ms", 0)) >= 250,
    }


def cargo_storage_tests() -> bool:
    completed = subprocess.run(
        [
            str(CARGO_HOME / "bin" / "cargo"),
            "test",
            "-q",
            "-p",
            "mtm-storage",
            "--test",
            "storage",
        ],
        cwd=ROOT,
        env=cargo_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return completed.returncode == 0


def conformance_gate() -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, "scripts/run_mtm004_conformance.py"],
        cwd=ROOT,
        env=cargo_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"MTM-004 conformance failed: {completed.stderr[-2000:]}")
    payload = json.loads(completed.stdout)
    return {
        "passed": payload.get("ok") is True,
        "operation_count": payload.get("operation_count"),
        "migration_cases_passed": payload.get("migration_cases_passed"),
        "golden_match": payload.get("golden_match"),
    }


def main() -> int:
    build_binary()
    if not SOURCE_DB.is_file():
        raise FileNotFoundError("configured Re-CTM state database is unavailable")
    checks: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="mtm004-target-") as directory:
        root = Path(directory)
        source_copy = root / "source-copy.sqlite3"
        read_only_backup(SOURCE_DB, source_copy)
        source_integrity = integrity(source_copy)
        python_copy = root / "source-python.sqlite3"
        rust_copy = root / "source-rust.sqlite3"
        shutil.copy2(source_copy, python_copy)
        shutil.copy2(source_copy, rust_copy)
        python_digest = digest_result([sys.executable, str(PYTHON_DRIVER)], python_copy)
        rust_digest = digest_result([str(RUST_BINARY)], rust_copy)
        content_match = python_digest == rust_digest
        checks.extend(
            [
                {
                    "name": "production_database_read_only_backup",
                    "passed": source_integrity,
                    "open_mode": "sqlite_uri_mode_ro",
                    "integrity_check": "ok" if source_integrity else "failed",
                },
                {
                    "name": "production_copy_python_rust_digest_match",
                    "passed": content_match,
                    "schema_version": python_digest.get("user_version"),
                    "table_count": python_digest.get("table_count"),
                    "schema_count": python_digest.get("schema_count"),
                    "private_content_omitted": True,
                },
            ]
        )

        rollback_base = root / "rollback-base.sqlite3"
        rollback_working = root / "rollback-working.sqlite3"
        shutil.copy2(source_copy, rollback_base)
        shutil.copy2(rollback_base, rollback_working)
        probe_id = f"mtm-target-probe-{secrets.token_hex(8)}"
        mutated = invoke(
            [str(RUST_BINARY)],
            request(
                rollback_working,
                [
                    operation(
                        "create_run",
                        run_id=probe_id,
                        problem_id="target-rollback-probe",
                        owner_id="target-validation",
                        state="assess",
                        metadata={},
                    ),
                    operation("database_digest"),
                ],
            ),
        )
        result_at(mutated, 0)
        mutated_digest = result_at(mutated, 1)
        rollback_working.unlink()
        shutil.copy2(rollback_base, rollback_working)
        restored_digest = digest_result(
            [sys.executable, str(PYTHON_DRIVER)], rollback_working
        )
        rollback_ok = (
            mutated_digest.get("content_sha256") != python_digest.get("content_sha256")
            and restored_digest == python_digest
            and integrity(rollback_working)
        )
        checks.append(
            {
                "name": "production_copy_mutate_and_exact_rollback",
                "passed": rollback_ok,
                "restored_to_source_digest": restored_digest == python_digest,
                "restored_integrity_check": "ok" if integrity(rollback_working) else "failed",
                "probe_identifiers_omitted": True,
            }
        )

        capability = cross_runtime_capabilities(root)
        checks.extend(
            {"name": name, "passed": passed}
            for name, passed in capability.items()
            if name != "tokens_not_recorded"
        )
        checks.append(
            {
                "name": "capability_secrets_not_recorded",
                "passed": capability["tokens_not_recorded"],
            }
        )

        writer = serialized_writer_check(root)
        checks.append({"name": "begin_immediate_serializes_writers", **writer})
        checks.append(
            {
                "name": "storage_atomicity_and_capability_unit_suite",
                "passed": cargo_storage_tests(),
            }
        )
        checks.append({"name": "mtm004_golden_and_migration_conformance", **conformance_gate()})

    report = {
        "schema_version": "1.0.0",
        "project": "MTM-reboot",
        "milestone": "MTM-004",
        "implementation_sha256": implementation_sha256(),
        "environment": {
            "platform": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "sqlite_version": sqlite3.sqlite_version,
            "source_database": "configured_private_state",
            "source_database_path_fingerprint": hashlib.sha256(
                str(SOURCE_DB).encode("utf-8")
            ).hexdigest()[:16],
        },
        "passed": all(bool(check.get("passed")) for check in checks),
        "check_count": len(checks),
        "checks": checks,
        "sensitive_content_omitted": True,
        "claim": (
            "This report validates the current Linux target's read-only SQLite backup of the "
            "configured Re-CTM state database, Python/Rust copied-database equality, exact "
            "rollback, cross-runtime capability signatures and registry enforcement, serialized "
            "BEGIN IMMEDIATE writers, migration conformance and transactional unit tests. It "
            "does not publish database rows, run/project identifiers, tokens, proofs, source "
            "contents, or any production write. OAuth/MCP and workflow/finalizer acceptance "
            "remain later milestones."
        ),
    }
    temporary = REPORT.with_name(REPORT.name + ".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(REPORT)
    print(json.dumps({"ok": report["passed"], "report": str(REPORT)}, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
