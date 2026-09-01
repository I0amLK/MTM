#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE_BASELINE = ROOT / "source-baseline.json"
GOLDEN_HASH = ROOT / "conformance" / "golden" / "mtm004-reference.sha256"
CARGO_HOME = ROOT / ".toolchain" / "cargo"
RUSTUP_HOME = ROOT / ".toolchain" / "rustup"
RUST_BINARY = ROOT / "target" / "debug" / "mtm-storage-shadow"
PYTHON_DRIVER = ROOT / "conformance" / "python_storage_shadow.py"
SAMPLES = 7
MAX_ELAPSED_SECONDS = 15.0
MAX_RSS_KIB = 262_144

sys.path.insert(0, str(ROOT / "conformance"))
from mtm004_scenario import NOW_ISO, SECRET, UNIX_SECONDS, request as scenario_request  # noqa: E402


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def load_source_baseline() -> tuple[Path, str, list[str]]:
    baseline = json.loads(SOURCE_BASELINE.read_text(encoding="utf-8"))
    source_path = (ROOT / baseline["source_path"]).resolve()
    return source_path, str(baseline["source_commit"]), list(baseline["reference_files"])


def source_status() -> tuple[Path, str, int, bool]:
    source_path, expected_commit, files = load_source_baseline()
    actual_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source_path,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    if actual_commit != expected_commit:
        raise RuntimeError(
            f"source baseline commit drift: expected {expected_commit}, got {actual_commit}"
        )
    dirty = subprocess.run(
        ["git", "status", "--porcelain=v1", "--", *files],
        cwd=source_path,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout
    return source_path, actual_commit, len(files), not bool(dirty.strip())


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


def git_status() -> str:
    return subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout


def run_timed(command: list[str], payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    encoded = canonical(payload).encode("utf-8")
    time_executable = shutil.which("time")
    if time_executable is None:
        raise RuntimeError("GNU time is required for MTM-004 resource evidence")
    with tempfile.NamedTemporaryFile(prefix="mtm004-time-", delete=False) as handle:
        report = Path(handle.name)
    try:
        started = time.perf_counter()
        completed = subprocess.run(
            [time_executable, "-f", "%M", "-o", str(report), *command],
            cwd=ROOT,
            input=encoded,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        elapsed = time.perf_counter() - started
        rss_kib = int(report.read_text(encoding="utf-8").strip())
    finally:
        report.unlink(missing_ok=True)
    if completed.returncode != 0:
        raise RuntimeError(
            f"driver failed with {completed.returncode}: "
            f"{completed.stderr.decode('utf-8', errors='replace')[-4000:]}"
        )
    result = json.loads(completed.stdout)
    if not isinstance(result, dict):
        raise TypeError("storage shadow response must be an object")
    return result, {
        "elapsed_ms": round(elapsed * 1000, 3),
        "max_rss_kib": rss_kib,
        "request_bytes": len(encoded),
        "response_bytes": len(completed.stdout),
    }


def summarize_samples(samples: list[dict[str, Any]]) -> dict[str, Any]:
    elapsed = sorted(float(item["elapsed_ms"]) for item in samples)
    p95_index = min(len(elapsed) - 1, max(0, int(len(elapsed) * 0.95 + 0.999) - 1))
    return {
        "samples": len(samples),
        "elapsed_ms_median": round(statistics.median(elapsed), 3),
        "elapsed_ms_p95": round(elapsed[p95_index], 3),
        "max_rss_kib": max(int(item["max_rss_kib"]) for item in samples),
        "request_bytes": max(int(item["request_bytes"]) for item in samples),
        "response_bytes": max(int(item["response_bytes"]) for item in samples),
    }


def source_schema_constants(source_path: Path) -> tuple[str, str, str]:
    namespace: dict[str, Any] = {}
    source = (source_path / "src" / "re_ctm" / "storage_schema.py").read_text(encoding="utf-8")
    exec(compile(source, "storage_schema.py", "exec"), namespace)  # noqa: S102 - frozen local source
    return (
        str(namespace["SCHEMA_MIGRATIONS_TABLE_SQL"]),
        str(namespace["V1_WORKFLOW_SCHEMA_SQL"]),
        str(namespace["V2_RESEARCH_SCHEMA_SQL"]),
    )


def create_fixture(
    path: Path,
    kind: str,
    *,
    schema_migrations_sql: str,
    v1_sql: str,
    v2_sql: str,
) -> None:
    connection = sqlite3.connect(path)
    try:
        if kind in {"v0", "v1", "v2"}:
            connection.executescript(v1_sql)
            connection.execute(
                "INSERT INTO runs(run_id, problem_id, owner_id, state, status, metadata_json, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "legacy-run",
                    "legacy-problem",
                    "owner",
                    "assess",
                    "active",
                    '{"legacy":true}',
                    "2025-01-01T00:00:00.000Z",
                    "2025-01-01T00:00:00.000Z",
                ),
            )
        if kind == "v2":
            connection.executescript(schema_migrations_sql)
            connection.executescript(v2_sql)
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at, description) VALUES(1, '2025-01-01T00:00:00.000Z', 'baseline workflow schema')"
            )
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at, description) VALUES(2, '2025-01-01T00:00:00.000Z', 'v0.2 research registry and provenance schema')"
            )
            connection.execute(
                "INSERT INTO projects(project_id, owner_id, title, created_at, updated_at) VALUES('legacy-project','owner','Legacy','2025-01-01T00:00:00.000Z','2025-01-01T00:00:00.000Z')"
            )
        if kind == "failed-v2":
            connection.execute("CREATE TABLE projects(x TEXT)")
        version = {"v0": 0, "v1": 1, "v2": 2, "newer": 3, "failed-v2": 1}[kind]
        connection.execute(f"PRAGMA user_version={version}")
        connection.commit()
    finally:
        connection.close()


def raw_database_state(path: Path) -> dict[str, Any]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        tables = [
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            if not str(row[0]).startswith("sqlite_")
        ]
        rows: dict[str, list[dict[str, Any]]] = {}
        for table in tables:
            values = [dict(row) for row in connection.execute(f'SELECT * FROM "{table}"')]
            values.sort(key=canonical)
            rows[table] = values
        return {"user_version": version, "tables": tables, "rows": rows}
    finally:
        connection.close()


def empty_driver_request(database: Path) -> dict[str, Any]:
    return {
        "database": str(database),
        "now_iso": NOW_ISO,
        "unix_seconds": UNIX_SECONDS,
        "hex_ids": [],
        "urlsafe_ids": [],
        "secret_base64": __import__("base64").b64encode(SECRET).decode("ascii"),
        "operations": [{"op": "schema_version", "args": {}}, {"op": "database_snapshot", "args": {}}],
    }


def normalized_top_error(payload: dict[str, Any]) -> dict[str, Any]:
    error = payload.get("error") if isinstance(payload.get("error"), dict) else {}
    return {
        "ok": payload.get("ok"),
        "code": error.get("code"),
        "category": error.get("category"),
        "retryable": error.get("retryable"),
    }


def run_migrations(source_path: Path, root: Path) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True)
    schema_migrations_sql, v1_sql, v2_sql = source_schema_constants(source_path)
    exact_cases: dict[str, Any] = {}
    for kind in ("v0", "v1", "v2"):
        baseline = root / f"{kind}-baseline.sqlite3"
        create_fixture(
            baseline,
            kind,
            schema_migrations_sql=schema_migrations_sql,
            v1_sql=v1_sql,
            v2_sql=v2_sql,
        )
        python_db = root / f"{kind}-python.sqlite3"
        rust_db = root / f"{kind}-rust.sqlite3"
        shutil.copy2(baseline, python_db)
        shutil.copy2(baseline, rust_db)
        python, _ = run_timed([sys.executable, str(PYTHON_DRIVER)], empty_driver_request(python_db))
        rust, _ = run_timed([str(RUST_BINARY)], empty_driver_request(rust_db))
        exact_cases[kind] = {
            "match": python == rust,
            "python": python,
            "rust": rust,
        }

    newer = root / "newer-baseline.sqlite3"
    create_fixture(
        newer,
        "newer",
        schema_migrations_sql=schema_migrations_sql,
        v1_sql=v1_sql,
        v2_sql=v2_sql,
    )
    newer_python = root / "newer-python.sqlite3"
    newer_rust = root / "newer-rust.sqlite3"
    shutil.copy2(newer, newer_python)
    shutil.copy2(newer, newer_rust)
    python_newer, _ = run_timed(
        [sys.executable, str(PYTHON_DRIVER)], empty_driver_request(newer_python)
    )
    rust_newer, _ = run_timed([str(RUST_BINARY)], empty_driver_request(newer_rust))

    failed = root / "failed-baseline.sqlite3"
    create_fixture(
        failed,
        "failed-v2",
        schema_migrations_sql=schema_migrations_sql,
        v1_sql=v1_sql,
        v2_sql=v2_sql,
    )
    failed_python = root / "failed-python.sqlite3"
    failed_rust = root / "failed-rust.sqlite3"
    shutil.copy2(failed, failed_python)
    shutil.copy2(failed, failed_rust)
    python_failed, _ = run_timed(
        [sys.executable, str(PYTHON_DRIVER)], empty_driver_request(failed_python)
    )
    rust_failed, _ = run_timed([str(RUST_BINARY)], empty_driver_request(failed_rust))
    python_failed_state = raw_database_state(failed_python)
    rust_failed_state = raw_database_state(failed_rust)

    rollback_baseline = root / "rollback-baseline.sqlite3"
    create_fixture(
        rollback_baseline,
        "v1",
        schema_migrations_sql=schema_migrations_sql,
        v1_sql=v1_sql,
        v2_sql=v2_sql,
    )
    migrated = root / "rollback-migrated.sqlite3"
    restored = root / "rollback-restored.sqlite3"
    shutil.copy2(rollback_baseline, migrated)
    shutil.copy2(rollback_baseline, restored)
    rust_migrated, _ = run_timed([str(RUST_BINARY)], empty_driver_request(migrated))
    restored_before = raw_database_state(restored)
    restored_python, _ = run_timed(
        [sys.executable, str(PYTHON_DRIVER)], empty_driver_request(restored)
    )

    exact_ok = all(case["match"] for case in exact_cases.values())
    newer_ok = (
        normalized_top_error(python_newer) == normalized_top_error(rust_newer)
        and normalized_top_error(python_newer)["code"] == "STATE_SCHEMA_NEWER_THAN_RUNTIME"
    )
    failed_ok = (
        normalized_top_error(python_failed) == normalized_top_error(rust_failed)
        and python_failed_state == rust_failed_state
        and python_failed_state["user_version"] == 1
        and python_failed_state["tables"] == ["projects"]
    )
    rollback_ok = (
        rust_migrated.get("ok") is True
        and restored_before["user_version"] == 1
        and restored_python.get("ok") is True
    )
    return {
        "ok": exact_ok and newer_ok and failed_ok and rollback_ok,
        "exact_cases": exact_cases,
        "newer_schema": {
            "match": newer_ok,
            "python": normalized_top_error(python_newer),
            "rust": normalized_top_error(rust_newer),
        },
        "failed_v2_rollback": {
            "match": failed_ok,
            "python_error": normalized_top_error(python_failed),
            "rust_error": normalized_top_error(rust_failed),
            "post_failure_state": python_failed_state,
        },
        "rollback_copy": {
            "passed": rollback_ok,
            "restored_before_source_open": restored_before,
            "rust_migration_ok": rust_migrated.get("ok"),
            "source_resume_ok": restored_python.get("ok"),
        },
    }


def reference_record(main_output: dict[str, Any], migrations: dict[str, Any]) -> dict[str, Any]:
    compact_migrations = {
        "exact": {
            key: value["python"]
            for key, value in sorted(migrations["exact_cases"].items())
        },
        "newer_schema": migrations["newer_schema"]["python"],
        "failed_v2_rollback": migrations["failed_v2_rollback"],
        "rollback_copy": migrations["rollback_copy"],
    }
    return {"main": main_output, "migrations": compact_migrations}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--print-golden", action="store_true")
    args = parser.parse_args(argv)

    source_path, source_commit, reference_file_count, source_files_clean = source_status()
    if not source_files_clean:
        print(json.dumps({"ok": False, "error": "source reference files are dirty"}, indent=2))
        return 1
    build_binary()
    before_status = git_status()
    python_samples: list[dict[str, Any]] = []
    rust_samples: list[dict[str, Any]] = []
    python_output: dict[str, Any] | None = None
    rust_output: dict[str, Any] | None = None
    with tempfile.TemporaryDirectory(prefix="mtm004-conformance-") as directory:
        root = Path(directory)
        for index in range(SAMPLES):
            python_db = root / f"main-python-{index}.sqlite3"
            rust_db = root / f"main-rust-{index}.sqlite3"
            python, python_resource = run_timed(
                [sys.executable, str(PYTHON_DRIVER)], scenario_request(python_db)
            )
            rust, rust_resource = run_timed([str(RUST_BINARY)], scenario_request(rust_db))
            python_samples.append(python_resource)
            rust_samples.append(rust_resource)
            if python_output is None:
                python_output = python
                rust_output = rust
            elif python != python_output or rust != rust_output:
                raise RuntimeError("MTM-004 scenario output was nondeterministic across samples")
        migrations = run_migrations(source_path, root / "migrations")

    if python_output is None or rust_output is None:
        raise RuntimeError("MTM-004 scenario produced no sample")
    after_status = git_status()
    exact_match = python_output == rust_output
    reference = reference_record(python_output, migrations)
    reference_sha256 = hashlib.sha256(canonical(reference).encode("utf-8")).hexdigest()
    recorded = GOLDEN_HASH.read_text(encoding="utf-8").strip() if GOLDEN_HASH.exists() else ""
    golden_match = args.print_golden or reference_sha256 == recorded
    python_resources = summarize_samples(python_samples)
    rust_resources = summarize_samples(rust_samples)
    rust_elapsed_limit = max(float(python_resources["elapsed_ms_p95"]) * 3.0, 3_000.0)
    rust_rss_limit = max(int(python_resources["max_rss_kib"]) * 2, 65_536)
    resources_ok = (
        float(python_resources["elapsed_ms_p95"]) <= MAX_ELAPSED_SECONDS * 1000
        and float(rust_resources["elapsed_ms_p95"]) <= MAX_ELAPSED_SECONDS * 1000
        and int(python_resources["max_rss_kib"]) <= MAX_RSS_KIB
        and int(rust_resources["max_rss_kib"]) <= MAX_RSS_KIB
        and float(rust_resources["elapsed_ms_p95"]) <= rust_elapsed_limit
        and int(rust_resources["max_rss_kib"]) <= rust_rss_limit
    )
    no_side_effects = before_status == after_status
    summary = {
        "ok": exact_match
        and migrations["ok"]
        and golden_match
        and resources_ok
        and no_side_effects,
        "source_commit": source_commit,
        "source_reference_file_count": reference_file_count,
        "source_reference_files_clean": source_files_clean,
        "operation_count": len(scenario_request(Path("<DATABASE>"))["operations"]),
        "main_exact_match": exact_match,
        "migration_cases_passed": migrations["ok"],
        "migration_summary": {
            "v0_match": migrations["exact_cases"]["v0"]["match"],
            "v1_match": migrations["exact_cases"]["v1"]["match"],
            "v2_match": migrations["exact_cases"]["v2"]["match"],
            "newer_schema_fail_closed": migrations["newer_schema"]["match"],
            "failed_v2_rollback": migrations["failed_v2_rollback"]["match"],
            "rollback_copy_resumed_by_source": migrations["rollback_copy"]["passed"],
        },
        "reference_sha256": reference_sha256,
        "recorded_sha256": recorded or None,
        "golden_match": golden_match,
        "resources": {
            "python_reference": python_resources,
            "rust_shadow": rust_resources,
            "rust_non_regression_limits": {
                "elapsed_ms_p95": round(rust_elapsed_limit, 3),
                "max_rss_kib": rust_rss_limit,
            },
        },
        "resource_gate_passed": resources_ok,
        "shadow_side_effect_free": no_side_effects,
        "authority": {
            "source_reference": "python",
            "rust_mode": "copied_database_shadow",
            "production_writer": "python",
        },
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
