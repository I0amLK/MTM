#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import statistics
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

try:
    from scripts.mtm008_runtime_harness import (
        ROOT,
        ProcessSampler,
        RuntimeServer,
        build_release,
        linear_slope,
        percentile,
        prepare_workspace,
    )
except ModuleNotFoundError:
    from mtm008_runtime_harness import (
        ROOT,
        ProcessSampler,
        RuntimeServer,
        build_release,
        linear_slope,
        percentile,
        prepare_workspace,
    )


REPORT = ROOT / "mtm008-soak.json"
DURATION_SECONDS = 60.0
CONCURRENCY = 8


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def request_payload(index: int) -> dict[str, Any]:
    selector = index % 10
    if selector < 5:
        return {"jsonrpc": "2.0", "id": f"ping-{index}", "method": "ping", "params": {}}
    if selector < 7:
        return {
            "jsonrpc": "2.0",
            "id": f"list-{index}",
            "method": "tools/list",
            "params": {},
        }
    tool, arguments = (
        ("server_info", {})
        if selector == 7
        else ("read_file", {"path": "README.txt"})
        if selector == 8
        else ("check_exec_environment", {})
    )
    return {
        "jsonrpc": "2.0",
        "id": f"call-{index}",
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }


def run_worker(
    server: RuntimeServer,
    stop: threading.Event,
    counter: list[int],
    lock: threading.Lock,
) -> tuple[list[float], list[str]]:
    latencies: list[float] = []
    errors: list[str] = []
    while not stop.is_set():
        with lock:
            index = counter[0]
            counter[0] += 1
        started = time.perf_counter_ns()
        try:
            server.rpc(request_payload(index), timeout=15)
            latencies.append((time.perf_counter_ns() - started) / 1_000_000)
        except Exception as exc:
            errors.append(type(exc).__name__)
            stop.set()
    return latencies, errors


def stateful_cycles(server: RuntimeServer, stop: threading.Event) -> tuple[int, list[str]]:
    completed = 0
    errors: list[str] = []
    while not stop.wait(2.0):
        try:
            started = server.call(
                "rethlas_start",
                {
                    "problem_tex": "Prove that 1+1=2.",
                    "problem_id": f"soak-{completed}",
                    "workflow_mode": "compact",
                },
                f"soak-start-{completed}",
            )
            structured = started.get("result", {}).get("structuredContent", {})
            run_id = str(structured.get("run_id") or "")
            if not run_id:
                raise RuntimeError("rethlas_start returned no run_id")
            cancelled = server.call(
                "rethlas_control",
                {"action": "cancel", "run_id": run_id, "reason": "soak_cycle"},
                f"soak-cancel-{completed}",
            )
            cancelled_structured = cancelled.get("result", {}).get("structuredContent", {})
            if cancelled_structured.get("ok") is False:
                raise RuntimeError("rethlas_control reported failure")
            completed += 1
        except Exception as exc:
            errors.append(type(exc).__name__)
            stop.set()
    return completed, errors


def main() -> int:
    build_release()
    with tempfile.TemporaryDirectory(prefix="mtm008-soak-") as directory:
        root = Path(directory)
        workspace = root / "workspace"
        prepare_workspace(workspace)
        server = RuntimeServer("rust", workspace, root / "data")
        sampler = ProcessSampler(server.pid, interval_seconds=0.05)
        sampler.start()
        stop = threading.Event()
        counter = [0]
        lock = threading.Lock()
        started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY + 1) as executor:
            worker_futures = [
                executor.submit(run_worker, server, stop, counter, lock)
                for _ in range(CONCURRENCY)
            ]
            stateful_future = executor.submit(stateful_cycles, server, stop)
            while time.monotonic() - started < DURATION_SECONDS and not stop.is_set():
                time.sleep(0.1)
            stop.set()
            worker_results = [future.result(timeout=20) for future in worker_futures]
            stateful_count, stateful_errors = stateful_future.result(timeout=20)
        elapsed = time.monotonic() - started
        samples = sampler.stop()
        shutdown = server.close()

    latencies = [latency for values, _ in worker_results for latency in values]
    errors = [error for _, values in worker_results for error in values] + stateful_errors
    rss = [sample.rss_kib for sample in samples]
    fds = [sample.file_descriptors for sample in samples]
    threads = [sample.threads for sample in samples]
    children = [sample.children for sample in samples]
    rss_slope = linear_slope((sample.elapsed_seconds, float(sample.rss_kib)) for sample in samples)
    tail_samples = [sample for sample in samples if sample.elapsed_seconds >= 15.0]
    tail_rss_slope = linear_slope(
        (sample.elapsed_seconds, float(sample.rss_kib)) for sample in tail_samples
    )
    tail_rss_growth = (
        tail_samples[-1].rss_kib - tail_samples[0].rss_kib if len(tail_samples) >= 2 else 0
    )
    fd_growth = (fds[-1] - fds[0]) if len(fds) >= 2 else 0
    thread_growth = (threads[-1] - threads[0]) if len(threads) >= 2 else 0
    passed = (
        elapsed >= DURATION_SECONDS * 0.98
        and not errors
        and len(latencies) >= 50_000
        and stateful_count >= 20
        and tail_rss_slope <= 32.0
        and tail_rss_growth <= 16_384
        and max(rss, default=0) <= 65_536
        and fd_growth <= 8
        and thread_growth <= 4
        and max(children, default=0) == 0
        and shutdown["exit_code"] == 0
        and shutdown["forced"] is False
        and shutdown["elapsed_ms"] <= 5_000
    )
    report = {
        "schema_version": "1.0.0",
        "project": "MTM-reboot",
        "milestone": "MTM-008",
        "passed": passed,
        "duration_seconds": round(elapsed, 3),
        "concurrency": CONCURRENCY,
        "request_count": len(latencies),
        "request_errors": len(errors),
        "error_types": sorted(set(errors)),
        "stateful_start_cancel_cycles": stateful_count,
        "latency_ms": {
            "median": round(statistics.median(latencies), 6) if latencies else 0,
            "p95": round(percentile(latencies, 95), 6),
            "p99": round(percentile(latencies, 99), 6),
        },
        "throughput_requests_per_second": round(len(latencies) / elapsed, 3),
        "resources": {
            "sample_count": len(samples),
            "rss_kib_initial": rss[0] if rss else 0,
            "rss_kib_final": rss[-1] if rss else 0,
            "rss_kib_max": max(rss, default=0),
            "rss_slope_kib_per_second": round(rss_slope, 6),
            "rss_tail_slope_kib_per_second": round(tail_rss_slope, 6),
            "rss_tail_growth_kib": tail_rss_growth,
            "file_descriptors_initial": fds[0] if fds else 0,
            "file_descriptors_final": fds[-1] if fds else 0,
            "file_descriptor_growth": fd_growth,
            "threads_initial": threads[0] if threads else 0,
            "threads_final": threads[-1] if threads else 0,
            "thread_growth": thread_growth,
            "child_processes_max": max(children, default=0),
        },
        "shutdown": shutdown,
        "release_binary": {
            "path": "target/release/mtm",
            "sha256": sha256_file(ROOT / "target" / "release" / "mtm"),
        },
        "thresholds": {
            "minimum_duration_seconds": DURATION_SECONDS * 0.98,
            "minimum_requests": 50_000,
            "minimum_stateful_cycles": 20,
            "tail_starts_after_seconds": 15.0,
            "maximum_tail_rss_slope_kib_per_second": 32.0,
            "maximum_tail_rss_growth_kib": 16_384,
            "maximum_rss_kib": 65_536,
            "maximum_fd_growth": 8,
            "maximum_thread_growth": 4,
            "maximum_child_processes": 0,
            "maximum_shutdown_ms": 5_000,
        },
        "sensitive_content_recorded": False,
    }
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
