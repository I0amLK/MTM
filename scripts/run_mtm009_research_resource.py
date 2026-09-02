#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import math
import os
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.mtm008_runtime_harness import free_port, oauth_token, runtime_environment, wait_for_port
from scripts.run_mtm007_http_smoke import tool_call


REPORT = Path(os.environ.get("MTM009_RESOURCE_REPORT", ROOT / "mtm009-research-resource.json"))
BINARY = ROOT / "target" / "release" / "mtm"
SAMPLES = 40


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1))
    return ordered[index]


def process_facts(pid: int) -> dict[str, int]:
    status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    values: dict[str, int] = {}
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            values["rss_kib"] = int(line.split()[1])
        elif line.startswith("Threads:"):
            values["threads"] = int(line.split()[1])
    values["fds"] = len(list(Path(f"/proc/{pid}/fd").iterdir()))
    return values


def tree_facts(root: Path) -> dict[str, int]:
    files = [path for path in root.rglob("*") if path.is_file()]
    return {
        "files": len(files),
        "bytes": sum(path.stat().st_size for path in files),
    }


def close(process: subprocess.Popen[str]) -> int:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        return process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        return process.wait(timeout=3)


def structured(port: int, token: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    response = tool_call(port, token, name, arguments)
    content = response.get("result", {}).get("structuredContent")
    if not isinstance(content, dict):
        raise RuntimeError(f"{name} returned no structuredContent")
    if content.get("ok") is False:
        raise RuntimeError(f"{name} failed: {content}")
    return content


def timed_task(port: int, token: str, run_id: str) -> tuple[float, int, dict[str, Any]]:
    started = time.perf_counter_ns()
    task = structured(port, token, "rethlas_step", {"run_id": run_id})
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    encoded = json.dumps(task, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return elapsed_ms, len(encoded), task


def launch(workspace: Path, data_root: Path, protocol: int) -> tuple[subprocess.Popen[str], int, str]:
    port = free_port()
    environment = runtime_environment(workspace, data_root, "rust")
    environment["MTM_WORKFLOW_PROTOCOL_VERSION"] = str(protocol)
    process = subprocess.Popen(
        [
            str(BINARY),
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--workspace",
            str(workspace),
            "--native-mode",
            "safe",
            "--latex-policy",
            "static_only",
        ],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    wait_for_port(port, process)
    token = oauth_token(port, f"http://127.0.0.1:{port}", f"MTM-009 resource protocol {protocol}")
    return process, port, token


def advance_to_direct(port: int, token: str, protocol: int) -> tuple[str, dict[str, Any]]:
    started = structured(
        port,
        token,
        "rethlas_start",
        {
            "problem_tex": r"\begin{proposition}For every integer $n$, prove $n=n$.\end{proposition}",
            "problem_id": f"mtm009-resource-p{protocol}",
            "workflow_mode": "full",
            "register_result": True,
        },
    )
    run_id = str(started["run_id"])
    task = structured(port, token, "rethlas_step", {"run_id": run_id})

    def submit(writes: list[dict[str, Any]], payload: dict[str, Any]) -> dict[str, Any]:
        nonlocal task
        task = structured(
            port,
            token,
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": task["capability"],
                "writes": writes,
                "action": task["task"]["commit_action"],
                "payload": payload,
            },
        )
        return task

    submit(
        [
            {
                "resource": "memory:generation:immediate_conclusions",
                "content": {"summary": "Reflexivity should solve the target."},
            }
        ],
        {
            "route": "full",
            "route_reason": "resource comparison",
            "requires_external_retrieval": False,
            "requires_multiple_plans": True,
        },
    )
    exploration = {
        "event_type": "notation_resolution",
        "symbol": "=",
        "resolution": "ordinary equality",
        "summary": "No notation ambiguity remains.",
        "evidence_ids": [],
    }
    submit([{"resource": "memory:generation:events", "content": exploration}], {})
    if protocol == 3:
        plans: list[dict[str, Any]] = [
            {
                "summary": "Reflexivity route",
                "subgoals": [
                    {
                        "key": "reflexive",
                        "statement": "Apply reflexivity to n.",
                        "depends_on": [],
                        "critical": True,
                    }
                ],
                "motivation": ["Direct route"],
                "dependencies": [],
                "risks": [],
            },
            {
                "summary": "Equality-axiom route",
                "subgoals": [
                    {
                        "key": "axiom",
                        "statement": "Invoke the equality axiom.",
                        "depends_on": [],
                        "critical": True,
                    }
                ],
                "motivation": ["Alternative route"],
                "dependencies": [],
                "risks": ["Unnecessary abstraction"],
            },
        ]
    else:
        plans = [
            {
                "summary": "Reflexivity route",
                "subgoals": ["Apply reflexivity to n."],
                "motivation": ["Direct route"],
                "dependencies": [],
                "risks": [],
            },
            {
                "summary": "Equality-axiom route",
                "subgoals": ["Invoke the equality axiom."],
                "motivation": ["Alternative route"],
                "dependencies": [],
                "risks": ["Unnecessary abstraction"],
            },
        ]
    submit([], {"plans": plans})
    if task.get("state") != "direct_proving":
        raise RuntimeError(f"protocol {protocol} did not reach direct_proving")
    return run_id, task


def run_protocol(protocol: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix=f"mtm009-resource-p{protocol}-") as directory:
        root = Path(directory)
        workspace = root / "workspace"
        workspace.mkdir()
        (workspace / "README.txt").write_text("resource workload\n", encoding="utf-8")
        data_root = root / "data"
        process, port, token = launch(workspace, data_root, protocol)
        try:
            run_id, first_task = advance_to_direct(port, token, protocol)
            before = process_facts(process.pid)
            tree_before = tree_facts(data_root)
            latencies: list[float] = []
            sizes: list[int] = []
            last_task = first_task
            for _ in range(SAMPLES):
                latency, size, last_task = timed_task(port, token, run_id)
                latencies.append(latency)
                sizes.append(size)
            after = process_facts(process.pid)
            tree_after = tree_facts(data_root)
            view = last_task.get("context", {}).get("mathematical_research_state")
            view_bytes = (
                len(json.dumps(view, sort_keys=True, separators=(",", ":")).encode("utf-8"))
                if isinstance(view, dict)
                else 0
            )
            result = {
                "protocol": protocol,
                "samples": SAMPLES,
                "latency_ms_median": round(statistics.median(latencies), 6),
                "latency_ms_p95": round(percentile(latencies, 0.95), 6),
                "task_bytes_median": int(statistics.median(sizes)),
                "task_bytes_max": max(sizes),
                "research_view_bytes": view_bytes,
                "rss_kib_before": before.get("rss_kib", 0),
                "rss_kib_after": after.get("rss_kib", 0),
                "rss_kib_peak_proxy": max(before.get("rss_kib", 0), after.get("rss_kib", 0)),
                "threads_before": before.get("threads", 0),
                "threads_after": after.get("threads", 0),
                "fds_before": before.get("fds", 0),
                "fds_after": after.get("fds", 0),
                "state_bytes_before": tree_before["bytes"],
                "state_bytes_after": tree_after["bytes"],
                "state_byte_growth": tree_after["bytes"] - tree_before["bytes"],
                "state_files_before": tree_before["files"],
                "state_files_after": tree_after["files"],
            }
        finally:
            exit_code = close(process)
        if exit_code != 0:
            raise RuntimeError(f"protocol {protocol} server exited {exit_code}")
        result["exit_code"] = exit_code
        return result


def main() -> int:
    if not BINARY.is_file():
        raise RuntimeError("build target/release/mtm before running the MTM-009 resource gate")
    protocol2 = run_protocol(2)
    protocol3 = run_protocol(3)
    latency_limit = max(protocol2["latency_ms_p95"] * 3.0, protocol2["latency_ms_p95"] + 20.0)
    rss_limit = protocol2["rss_kib_peak_proxy"] + 8192
    task_growth_limit = 20_480
    state_growth_limit = protocol2["state_byte_growth"] + 262_144
    checks = {
        "protocol3_view_present_and_bounded": 0 < protocol3["research_view_bytes"] <= 16_384,
        "protocol2_view_absent": protocol2["research_view_bytes"] == 0,
        "p95_latency_non_regression": protocol3["latency_ms_p95"] <= latency_limit,
        "rss_non_regression": protocol3["rss_kib_peak_proxy"] <= rss_limit,
        "task_envelope_growth_bounded": (
            protocol3["task_bytes_max"] - protocol2["task_bytes_max"] <= task_growth_limit
        ),
        "state_write_growth_bounded": protocol3["state_byte_growth"] <= state_growth_limit,
        "thread_count_stable": protocol3["threads_after"] <= protocol3["threads_before"] + 1,
        "fd_count_stable": protocol3["fds_after"] <= protocol3["fds_before"] + 2,
    }
    payload = {
        "schema_version": "1.0.0",
        "milestone": "MTM-009",
        "purpose": "A5 non-regression only; not a performance claim.",
        "implementation_sha256": sha256_file(BINARY),
        "harness_sha256": sha256_file(Path(__file__)),
        "protocol2": protocol2,
        "protocol3": protocol3,
        "limits": {
            "protocol3_view_bytes": 16_384,
            "p95_latency_ms": round(latency_limit, 6),
            "rss_kib": rss_limit,
            "task_envelope_growth_bytes": task_growth_limit,
            "state_growth_bytes": state_growth_limit,
        },
        "checks": checks,
        "ok": all(checks.values()),
    }
    REPORT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
