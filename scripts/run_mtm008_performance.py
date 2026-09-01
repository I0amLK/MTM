#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import platform
import statistics
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

try:
    from scripts.mtm008_runtime_harness import (
        ROOT,
        RUST_BINARY,
        SOURCE_ROOT,
        ProcessSampler,
        RuntimeServer,
        bootstrap_ci,
        build_release,
        cpu_model,
        prepare_workspace,
        summarize,
    )
except ModuleNotFoundError:
    from mtm008_runtime_harness import (
        ROOT,
        RUST_BINARY,
        SOURCE_ROOT,
        ProcessSampler,
        RuntimeServer,
        bootstrap_ci,
        build_release,
        cpu_model,
        prepare_workspace,
        summarize,
    )


REPORT = ROOT / "mtm008-performance.json"
REPETITIONS = 7
WARMUP_REQUESTS = 96
MEASURED_REQUESTS = 800
CONCURRENCY = 8


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def request_payload(index: int) -> tuple[str, dict[str, Any]]:
    selector = index % 20
    if selector < 10:
        return (
            "ping",
            {"jsonrpc": "2.0", "id": f"ping-{index}", "method": "ping", "params": {}},
        )
    if selector < 14:
        return (
            "tools_list",
            {
                "jsonrpc": "2.0",
                "id": f"list-{index}",
                "method": "tools/list",
                "params": {},
            },
        )
    tools = [
        ("server_info", {}),
        ("read_file", {"path": "README.txt"}),
        ("check_exec_environment", {}),
    ]
    name, arguments = tools[(selector - 14) % len(tools)]
    return (
        name,
        {
            "jsonrpc": "2.0",
            "id": f"call-{index}",
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )


def issue(server: RuntimeServer, index: int) -> tuple[str, float, str | None]:
    name, payload = request_payload(index)
    started = time.perf_counter_ns()
    try:
        response = server.rpc(payload)
        if payload["method"] == "tools/list":
            if len(response.get("result", {}).get("tools", [])) != 24:
                raise RuntimeError("public catalog count changed")
        elif payload["method"] == "tools/call":
            structured = response.get("result", {}).get("structuredContent", {})
            if structured.get("ok") is False:
                raise RuntimeError(str(structured.get("error", {}).get("code") or "tool error"))
        return name, (time.perf_counter_ns() - started) / 1_000_000, None
    except Exception as exc:  # benchmark records failures instead of hiding them
        return name, (time.perf_counter_ns() - started) / 1_000_000, type(exc).__name__


def run_repetition(kind: str, root: Path, repetition: int) -> dict[str, Any]:
    workspace = root / f"{kind}-{repetition}-workspace"
    data_root = root / f"{kind}-{repetition}-data"
    prepare_workspace(workspace)
    server = RuntimeServer(kind, workspace, data_root)
    sampler = ProcessSampler(server.pid)
    sampler.start()
    for index in range(WARMUP_REQUESTS):
        _, _, error = issue(server, -(index + 1))
        if error:
            raise RuntimeError(f"{kind} warmup failed: {error}")
    started = time.perf_counter_ns()
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        results = list(executor.map(lambda index: issue(server, index), range(MEASURED_REQUESTS)))
    elapsed_seconds = (time.perf_counter_ns() - started) / 1_000_000_000
    samples = sampler.stop()
    shutdown = server.close()
    latencies = [latency for _, latency, error in results if error is None]
    errors = [error for _, _, error in results if error is not None]
    by_operation: dict[str, list[float]] = {}
    for name, latency, error in results:
        if error is None:
            by_operation.setdefault(name, []).append(latency)
    rss_values = [sample.rss_kib for sample in samples]
    thread_values = [sample.threads for sample in samples]
    fd_values = [sample.file_descriptors for sample in samples]
    child_values = [sample.children for sample in samples]
    return {
        "repetition": repetition,
        "startup_ms": round(server.startup_ms, 6),
        "request_count": len(results),
        "success_count": len(latencies),
        "error_count": len(errors),
        "error_types": sorted(set(errors)),
        "elapsed_seconds": round(elapsed_seconds, 6),
        "throughput_requests_per_second": round(len(latencies) / elapsed_seconds, 6),
        "latency_ms": summarize(latencies),
        "operations": {name: summarize(values) for name, values in sorted(by_operation.items())},
        "resources": {
            "rss_kib_median": round(statistics.median(rss_values), 3) if rss_values else 0,
            "rss_kib_max": max(rss_values, default=0),
            "threads_max": max(thread_values, default=0),
            "file_descriptors_max": max(fd_values, default=0),
            "children_max": max(child_values, default=0),
        },
        "shutdown": shutdown,
    }


def aggregate(repetitions: list[dict[str, Any]]) -> dict[str, Any]:
    throughput = [float(item["throughput_requests_per_second"]) for item in repetitions]
    p50 = [float(item["latency_ms"]["median"]) for item in repetitions]
    p95 = [float(item["latency_ms"]["p95"]) for item in repetitions]
    p99 = [float(item["latency_ms"]["p99"]) for item in repetitions]
    startup = [float(item["startup_ms"]) for item in repetitions]
    rss = [float(item["resources"]["rss_kib_max"]) for item in repetitions]
    shutdown = [float(item["shutdown"]["elapsed_ms"]) for item in repetitions]
    return {
        "repetitions": len(repetitions),
        "total_requests": sum(int(item["request_count"]) for item in repetitions),
        "total_errors": sum(int(item["error_count"]) for item in repetitions),
        "throughput_requests_per_second": {
            **summarize(throughput),
            "median_ci_95": bootstrap_ci(throughput),
            "coefficient_of_variation": round(
                statistics.stdev(throughput) / statistics.fmean(throughput), 6
            )
            if len(throughput) > 1
            else 0.0,
        },
        "latency_ms": {
            "median_of_request_medians": round(statistics.median(p50), 6),
            "median_of_p95": round(statistics.median(p95), 6),
            "median_of_p99": round(statistics.median(p99), 6),
            "p95_median_ci_95": bootstrap_ci(p95),
            "p99_median_ci_95": bootstrap_ci(p99),
        },
        "startup_ms": {**summarize(startup), "median_ci_95": bootstrap_ci(startup)},
        "rss_kib_max": {**summarize(rss), "median_ci_95": bootstrap_ci(rss)},
        "shutdown_ms": summarize(shutdown),
    }


def ratio(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def performance_claim(python: dict[str, Any], rust: dict[str, Any]) -> dict[str, Any]:
    py_throughput = python["throughput_requests_per_second"]
    rs_throughput = rust["throughput_requests_per_second"]
    py_latency = python["latency_ms"]
    rs_latency = rust["latency_ms"]
    py_rss = python["rss_kib_max"]
    rs_rss = rust["rss_kib_max"]
    conservative_throughput_ratio = ratio(
        float(rs_throughput["median_ci_95"]["lower_95"]),
        float(py_throughput["median_ci_95"]["upper_95"]),
    )
    conservative_p95_ratio = ratio(
        float(rs_latency["p95_median_ci_95"]["upper_95"]),
        float(py_latency["p95_median_ci_95"]["lower_95"]),
    )
    conservative_rss_ratio = ratio(
        float(rs_rss["median_ci_95"]["upper_95"]),
        float(py_rss["median_ci_95"]["lower_95"]),
    )
    observed = {
        "throughput_median_ratio_rust_over_python": ratio(
            float(rs_throughput["median"]), float(py_throughput["median"])
        ),
        "p95_latency_ratio_rust_over_python": ratio(
            float(rs_latency["median_of_p95"]), float(py_latency["median_of_p95"])
        ),
        "p99_latency_ratio_rust_over_python": ratio(
            float(rs_latency["median_of_p99"]), float(py_latency["median_of_p99"])
        ),
        "rss_ratio_rust_over_python": ratio(float(rs_rss["median"]), float(py_rss["median"])),
        "startup_ratio_rust_over_python": ratio(
            float(rust["startup_ms"]["median"]), float(python["startup_ms"]["median"])
        ),
        "conservative_throughput_ratio": conservative_throughput_ratio,
        "conservative_p95_ratio": conservative_p95_ratio,
        "conservative_rss_ratio": conservative_rss_ratio,
    }
    passed = (
        python["total_errors"] == 0
        and rust["total_errors"] == 0
        and conservative_throughput_ratio >= 1.15
        and conservative_p95_ratio <= 0.90
        and conservative_rss_ratio <= 0.75
    )
    return {
        "passed": passed,
        "path": "authenticated local OAuth/MCP mixed request path",
        "scope": "ping, tools/list, server_info, read_file, and check_exec_environment under eight concurrent clients",
        "observed": observed,
        "thresholds": {
            "conservative_throughput_ratio_min": 1.15,
            "conservative_p95_ratio_max": 0.90,
            "conservative_rss_ratio_max": 0.75,
            "errors_required": 0,
        },
        "statement": (
            "The Rust release materially improves throughput, p95 latency, and peak RSS on the exact authenticated local MCP workload described in this report."
            if passed
            else "No A6 performance claim is accepted because one or more conservative thresholds did not pass."
        ),
    }


def main() -> int:
    build_release()
    results: dict[str, list[dict[str, Any]]] = {"python": [], "rust": []}
    with tempfile.TemporaryDirectory(prefix="mtm008-performance-") as directory:
        root = Path(directory)
        for kind in ("python", "rust"):
            for repetition in range(REPETITIONS):
                results[kind].append(run_repetition(kind, root, repetition))
    aggregated = {kind: aggregate(items) for kind, items in results.items()}
    claim = performance_claim(aggregated["python"], aggregated["rust"])
    rustc = subprocess.run(
        [
            str(
                ROOT
                / ".toolchain"
                / "rustup"
                / "toolchains"
                / "1.98.0-x86_64-unknown-linux-gnu"
                / "bin"
                / "rustc"
            ),
            "--version",
        ],
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout.strip()
    report = {
        "schema_version": "1.0.0",
        "project": "MTM-reboot",
        "milestone": "MTM-008",
        "passed": claim["passed"],
        "workload": {
            "repetitions": REPETITIONS,
            "warmup_requests_per_repetition": WARMUP_REQUESTS,
            "measured_requests_per_repetition": MEASURED_REQUESTS,
            "concurrency": CONCURRENCY,
            "total_measured_requests_per_runtime": REPETITIONS * MEASURED_REQUESTS,
            "request_mix": {
                "ping_percent": 50,
                "tools_list_percent": 20,
                "tool_calls_percent": 30,
                "tool_calls": ["server_info", "read_file", "check_exec_environment"],
            },
            "network": "IPv4 loopback HTTP",
            "native_backend": "disabled",
            "latex_policy": "static_only",
            "state": "fresh disposable SQLite and private roots per repetition",
        },
        "environment": {
            "platform": platform.system(),
            "kernel_release": platform.release(),
            "machine": platform.machine(),
            "logical_cpus": os.cpu_count(),
            "cpu_model": cpu_model(),
            "python": platform.python_version(),
            "rustc": rustc,
            "rust_binary_sha256": sha256_file(RUST_BINARY),
            "source_commit": subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=SOURCE_ROOT,
                stdout=subprocess.PIPE,
                text=True,
                check=True,
            ).stdout.strip(),
        },
        "runtimes": aggregated,
        "repetition_records": results,
        "claim": claim,
        "sensitive_content_recorded": False,
    }
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
