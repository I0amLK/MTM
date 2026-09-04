#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.mtm008_runtime_harness import (
    free_port,
    oauth_token,
    runtime_environment,
    wait_for_port,
)
from scripts.run_mtm007_http_smoke import tool_call


CURRENT = ROOT / "target" / "release" / "mtm"
AUTHORITY_INVENTORY = ROOT / "records/governance/authority-inventory.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def accepted_prior_release() -> tuple[Path, str]:
    payload = json.loads(AUTHORITY_INVENTORY.read_text(encoding="utf-8"))
    release = payload.get("release")
    if not isinstance(release, dict):
        raise RuntimeError("authority inventory has no accepted release")
    path = Path(str(release.get("path") or ""))
    expected = str(release.get("sha256") or "")
    if not path.is_file() or not expected:
        raise RuntimeError("accepted prior MTM release is unavailable")
    actual = sha256_file(path)
    if actual != expected:
        raise RuntimeError(
            f"accepted prior MTM release hash mismatch: expected {expected}, got {actual}"
        )
    return path, expected


def launch(
    binary: Path,
    workspace: Path,
    data_root: Path,
    port: int,
    *,
    protocol: int | None,
    issue_token: bool,
) -> tuple[subprocess.Popen[str], str | None]:
    environment = runtime_environment(workspace, data_root, "rust")
    if protocol is not None:
        environment["MTM_WORKFLOW_PROTOCOL_VERSION"] = str(protocol)
    command = [
        str(binary),
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
    ]
    process = subprocess.Popen(
        command,
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
    token = (
        oauth_token(port, f"http://127.0.0.1:{port}", "MTM-009 protocol-3 rollback")
        if issue_token
        else None
    )
    return process, token


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


def create_protocol3_state(
    port: int,
    token: str,
) -> tuple[str, dict[str, Any]]:
    started = structured(
        port,
        token,
        "rethlas_start",
        {
            "problem_tex": r"\begin{proposition}Prove $1=1$.\end{proposition}",
            "problem_id": "mtm009-protocol3-rollback-probe",
            "workflow_mode": "full",
            "register_result": True,
        },
    )
    run_id = str(started["run_id"])
    task = structured(port, token, "rethlas_step", {"run_id": run_id})

    def submit(
        current: dict[str, Any],
        writes: list[dict[str, Any]],
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return structured(
            port,
            token,
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": current["capability"],
                "writes": writes,
                "action": current["task"]["commit_action"],
                "payload": payload,
            },
        )

    task = submit(
        task,
        [
            {
                "resource": "memory:generation:immediate_conclusions",
                "content": {"summary": "Reflexivity is enough."},
            }
        ],
        {
            "route": "full",
            "route_reason": "rollback probe",
            "requires_external_retrieval": False,
            "requires_multiple_plans": True,
        },
    )
    task = submit(
        task,
        [
            {
                "resource": "memory:generation:events",
                "content": {
                    "event_type": "notation_resolution",
                    "symbol": "=",
                    "resolution": "ordinary equality",
                    "summary": "Notation fixed.",
                    "evidence_ids": [],
                },
            }
        ],
        {},
    )
    task = submit(
        task,
        [],
        {
            "plans": [
                {
                    "summary": "Reflexivity route",
                    "subgoals": [
                        {
                            "key": "a",
                            "statement": "Use reflexivity.",
                            "depends_on": [],
                            "critical": True,
                        }
                    ],
                    "motivation": ["direct"],
                    "dependencies": [],
                    "risks": [],
                },
                {
                    "summary": "Alternative equality route",
                    "subgoals": [
                        {
                            "key": "b",
                            "statement": "Use equality axiom.",
                            "depends_on": [],
                            "critical": True,
                        }
                    ],
                    "motivation": ["alternative"],
                    "dependencies": [],
                    "risks": ["unnecessary"],
                },
            ]
        },
    )
    if task.get("state") != "direct_proving":
        raise RuntimeError("current binary did not reach direct_proving")
    if task.get("task", {}).get("workflow_protocol_version") != 3:
        raise RuntimeError("current binary did not create a protocol-3 run")
    plans = task.get("context", {}).get("active_plans")
    if not isinstance(plans, list) or not plans:
        raise RuntimeError("current binary returned no protocol-3 active plans")
    first_subgoals = plans[0].get("subgoals")
    if (
        not isinstance(first_subgoals, list)
        or not first_subgoals
        or not first_subgoals[0].get("node_id")
    ):
        raise RuntimeError("current binary did not expose canonical protocol-3 node ids")
    return run_id, task


def resume_with_prior(
    port: int,
    token: str,
    run_id: str,
) -> dict[str, Any]:
    task = structured(port, token, "rethlas_step", {"run_id": run_id})
    if task.get("state") != "direct_proving":
        raise RuntimeError(f"prior binary resumed unexpected state: {task.get('state')}")
    plans = task.get("context", {}).get("active_plans")
    if not isinstance(plans, list) or len(plans) != 2:
        raise RuntimeError("prior binary lost protocol-2-compatible plan projection")
    screening: dict[str, dict[str, dict[str, str]]] = {}
    for plan in plans:
        plan_id = str(plan["plan_id"])
        screening[plan_id] = {}
        for subgoal in plan["subgoals"]:
            screening[plan_id][str(subgoal["subgoal_id"])] = {
                "status": "partial",
                "summary": "Prior binary safely resumed this subgoal.",
            }
    progressed = structured(
        port,
        token,
        "rethlas_step",
        {
            "run_id": run_id,
            "capability": task["capability"],
            "writes": [
                {
                    "resource": "memory:generation:proof_steps",
                    "content": {"summary": "Prior binary compatibility probe."},
                }
            ],
            "action": task["task"]["commit_action"],
            "payload": {"screening": screening},
        },
    )
    if progressed.get("state") not in {"branch_prepare", "branch_run"}:
        raise RuntimeError(
            f"prior binary could not advance copied protocol-3 state: {progressed.get('state')}"
        )
    return progressed


def main() -> int:
    if not CURRENT.is_file():
        raise RuntimeError("build target/release/mtm before running the rollback probe")
    prior, prior_sha256 = accepted_prior_release()
    with tempfile.TemporaryDirectory(prefix="mtm009-protocol3-rollback-") as directory:
        root = Path(directory)
        workspace = root / "workspace"
        workspace.mkdir()
        (workspace / "README.txt").write_text("protocol-3 rollback probe\n", encoding="utf-8")
        data_root = root / "new-state"
        port = free_port()
        current, token = launch(
            CURRENT,
            workspace,
            data_root,
            port,
            protocol=3,
            issue_token=True,
        )
        if token is None:
            raise RuntimeError("current server did not issue an OAuth token")
        try:
            run_id, current_task = create_protocol3_state(port, token)
        finally:
            current_exit = close(current)
        if current_exit != 0:
            raise RuntimeError(f"current server did not shut down cleanly: {current_exit}")
        time.sleep(0.05)
        copied_root = root / "copied-state"
        shutil.copytree(data_root, copied_root)
        rollback, _ = launch(
            prior,
            workspace,
            copied_root,
            port,
            protocol=None,
            issue_token=False,
        )
        try:
            progressed = resume_with_prior(port, token, run_id)
        finally:
            prior_exit = close(rollback)
        if prior_exit != 0:
            raise RuntimeError(f"prior server did not shut down cleanly: {prior_exit}")
        print(
            json.dumps(
                {
                    "ok": True,
                    "current_binary_sha256": sha256_file(CURRENT),
                    "prior_binary_sha256": prior_sha256,
                    "created_protocol": current_task["task"]["workflow_protocol_version"],
                    "copied_state_start": "direct_proving",
                    "prior_resume_state": "direct_proving",
                    "prior_advanced_state": progressed["state"],
                    "same_oauth_origin": True,
                    "current_exit": current_exit,
                    "prior_exit": prior_exit,
                },
                indent=2,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
