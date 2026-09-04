#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE_BASELINE = ROOT / "records/governance/source-baseline.json"
GOLDEN_HASH = ROOT / "conformance" / "golden" / "mtm002-reference.sha256"
CARGO_HOME = ROOT / ".toolchain" / "cargo"
RUSTUP_HOME = ROOT / ".toolchain" / "rustup"
BINARY = ROOT / "target" / "debug" / "mtm"
MAX_BATCH_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 1_048_576
MAX_RSS_KIB = 131_072
MAX_ELAPSED_SECONDS = 10.0
RESOURCE_SAMPLES = 7

sys.path.insert(0, str(ROOT / "conformance"))
from mtm002_cases import cases  # noqa: E402


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def source_commit() -> tuple[Path, str, str, list[str], str]:
    baseline = json.loads(SOURCE_BASELINE.read_text(encoding="utf-8"))
    source_path = (ROOT / baseline["source_path"]).resolve()
    expected = str(baseline["source_commit"])
    reference_files = [str(item) for item in baseline.get("reference_files", [])]
    if not reference_files:
        raise ValueError("source baseline requires reference_files")
    actual = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source_path,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    reference_status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--", *reference_files],
        cwd=source_path,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout
    return source_path, expected, actual, reference_files, reference_status


def cargo_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["CARGO_HOME"] = str(CARGO_HOME)
    environment["RUSTUP_HOME"] = str(RUSTUP_HOME)
    return environment


def build_binary() -> None:
    subprocess.run(
        [str(CARGO_HOME / "bin" / "cargo"), "build", "-q", "-p", "mtm-cli"],
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


def timed_batch(
    command: list[str],
    encoded: bytes,
    *,
    label: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    payloads: list[list[dict[str, Any]]] = []
    elapsed_samples: list[float] = []
    rss_samples: list[int] = []
    response_bytes: list[int] = []
    for _ in range(RESOURCE_SAMPLES):
        payload, elapsed_ms, rss_kib, output_bytes = timed_sample(command, encoded, label=label)
        payloads.append(payload)
        elapsed_samples.append(elapsed_ms)
        rss_samples.append(rss_kib)
        response_bytes.append(output_bytes)
    reference_payload = payloads[0]
    if any(payload != reference_payload for payload in payloads[1:]):
        raise ValueError(f"{label} produced nondeterministic batch output")
    sorted_elapsed = sorted(elapsed_samples)
    p95_index = max(0, (95 * len(sorted_elapsed) + 99) // 100 - 1)
    return reference_payload, {
        "request_bytes": len(encoded),
        "response_bytes": max(response_bytes),
        "samples": RESOURCE_SAMPLES,
        "elapsed_ms_median": round(statistics.median(elapsed_samples), 3),
        "elapsed_ms_p95": round(sorted_elapsed[p95_index], 3),
        "max_rss_kib": max(rss_samples),
        "limits": {
            "request_bytes": MAX_BATCH_BYTES,
            "response_bytes": MAX_RESPONSE_BYTES,
            "elapsed_seconds": MAX_ELAPSED_SECONDS,
            "max_rss_kib": MAX_RSS_KIB,
        },
    }


def timed_sample(
    command: list[str],
    encoded: bytes,
    *,
    label: str,
) -> tuple[list[dict[str, Any]], float, int, int]:
    time_executable = shutil.which("time")
    if time_executable is None:
        raise RuntimeError("GNU time is required for the MTM-002 resource ceiling")
    with tempfile.NamedTemporaryFile(prefix="mtm002-time-", delete=False) as handle:
        time_report = Path(handle.name)
    try:
        started = time.perf_counter()
        completed = subprocess.run(
            [
                time_executable,
                "-f",
                "%M",
                "-o",
                str(time_report),
                *command,
            ],
            cwd=ROOT,
            input=encoded,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        elapsed = time.perf_counter() - started
        rss_kib = int(time_report.read_text(encoding="utf-8").strip())
    finally:
        time_report.unlink(missing_ok=True)
    if completed.returncode != 0:
        raise RuntimeError(
            f"{label} batch failed with {completed.returncode}: "
            f"{completed.stderr.decode('utf-8', errors='replace')}"
        )
    if len(completed.stdout) > MAX_RESPONSE_BYTES:
        raise ValueError(f"{label} response exceeds {MAX_RESPONSE_BYTES} bytes")
    payload = json.loads(completed.stdout)
    if not isinstance(payload, list):
        raise TypeError(f"{label} batch response must be an array")
    return payload, elapsed * 1000, rss_kib, len(completed.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--print-golden", action="store_true")
    args = parser.parse_args(argv)

    source_path, expected_commit, actual_commit, reference_files, reference_status = source_commit()
    if actual_commit != expected_commit:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "source baseline commit drift",
                    "expected": expected_commit,
                    "actual": actual_commit,
                    "source_path": str(source_path),
                },
                indent=2,
            )
        )
        return 1
    if reference_status:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "source reference files have working-tree changes",
                    "source_path": str(source_path),
                    "status": reference_status.splitlines(),
                },
                indent=2,
            )
        )
        return 1

    build_binary()
    before_status = git_status()
    corpus = cases()
    names = [str(item["name"]) for item in corpus]
    if len(names) != len(set(names)):
        raise ValueError("MTM-002 conformance case names must be unique")
    requests = [dict(item["request"]) for item in corpus]
    encoded = canonical(requests).encode("utf-8")
    if len(encoded) > MAX_BATCH_BYTES:
        raise ValueError(f"conformance batch exceeds {MAX_BATCH_BYTES} bytes")
    python_results, python_resources = timed_batch(
        [sys.executable, "conformance/python_batch_cli.py"],
        encoded,
        label="python",
    )
    rust_results, rust_resources = timed_batch(
        [str(BINARY), "evaluate-batch"],
        encoded,
        label="rust",
    )
    after_status = git_status()

    mismatches = []
    for item, expected, actual in zip(corpus, python_results, rust_results, strict=True):
        if expected != actual:
            mismatches.append(
                {
                    "name": item["name"],
                    "request": item["request"],
                    "python": expected,
                    "rust": actual,
                }
            )

    frozen_records = [
        {"name": item["name"], "request": item["request"], "response": response}
        for item, response in zip(corpus, python_results, strict=True)
    ]
    reference_hash = hashlib.sha256(canonical(frozen_records).encode("utf-8")).hexdigest()
    recorded_hash = GOLDEN_HASH.read_text(encoding="utf-8").strip() if GOLDEN_HASH.exists() else ""
    golden_match = args.print_golden or reference_hash == recorded_hash
    rust_elapsed_limit = max(python_resources["elapsed_ms_p95"] * 3.0, 2_000.0)
    rust_rss_limit = max(python_resources["max_rss_kib"] * 2, 65_536)
    resource_ok = all(
        resources["elapsed_ms_p95"] <= MAX_ELAPSED_SECONDS * 1000
        and resources["max_rss_kib"] <= MAX_RSS_KIB
        and resources["request_bytes"] <= MAX_BATCH_BYTES
        and resources["response_bytes"] <= MAX_RESPONSE_BYTES
        for resources in (python_resources, rust_resources)
    ) and (
        rust_resources["elapsed_ms_p95"] <= rust_elapsed_limit
        and rust_resources["max_rss_kib"] <= rust_rss_limit
    )
    no_side_effects = before_status == after_status
    summary = {
        "ok": not mismatches and golden_match and resource_ok and no_side_effects,
        "source_commit": actual_commit,
        "source_reference_file_count": len(reference_files),
        "source_reference_files_clean": True,
        "case_count": len(corpus),
        "operation_counts": dict(
            sorted(Counter(request["operation"] for request in requests).items())
        ),
        "reference_sha256": reference_hash,
        "recorded_sha256": recorded_hash or None,
        "golden_match": golden_match,
        "differential_mismatch_count": len(mismatches),
        "mismatches": mismatches[:20],
        "resources": {
            "python_reference": python_resources,
            "rust_shadow": rust_resources,
            "rust_non_regression_limits": {
                "elapsed_ms": round(rust_elapsed_limit, 3),
                "max_rss_kib": rust_rss_limit,
            },
        },
        "resource_gate_passed": resource_ok,
        "shadow_side_effect_free": no_side_effects,
        "authority": {
            "source_reference": "python",
            "rust_mode": "read_only_shadow",
            "production_authority": "python",
        },
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
