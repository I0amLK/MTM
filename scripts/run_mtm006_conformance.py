#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = (ROOT / ".." / "Re-CTM").resolve()
BASELINE = ROOT / "records/governance/source-baseline.json"
GOLDEN = ROOT / "conformance" / "golden" / "mtm006-reference.sha256"
PYTHON_SHADOW = ROOT / "conformance" / "python_workflow_shadow.py"
RUST_SHADOW = ROOT / "target" / "debug" / "mtm_workflow_shadow"
METHODOLOGY = SOURCE_ROOT / "src" / "re_ctm" / "resources" / "methodology.json"

NOW_ISO = "2026-09-01T12:00:00.000Z"
UNIX_SECONDS = 1_788_264_000
CAPABILITY_SECRET_HEX = "63" * 32

PASS_LATEX = {
    "policy": "test",
    "static_valid": True,
    "compile_attempted": True,
    "compile_available": True,
    "compile_passed": True,
    "gate_passed": True,
    "errors": [],
    "warnings": [],
    "compiler_output": "",
}


class Driver:
    def __init__(self, command: list[str]) -> None:
        self.started = time.perf_counter()
        self.process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=minimal_environment(),
        )

    def request(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError("shadow process pipes are unavailable")
        line = json.dumps(
            {"operation": operation, "payload": payload},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        self.process.stdin.write(line + "\n")
        self.process.stdin.flush()
        response = self.process.stdout.readline()
        if not response:
            stderr = self.process.stderr.read() if self.process.stderr is not None else ""
            raise RuntimeError(f"shadow exited early: {stderr[-4000:]}")
        return json.loads(response)

    def close(self) -> dict[str, Any]:
        max_rss_kib = process_peak_rss_kib(self.process.pid)
        if self.process.stdin is not None:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        stderr = self.process.stderr.read() if self.process.stderr is not None else ""
        return {
            "elapsed_ms": round((time.perf_counter() - self.started) * 1000, 3),
            "max_rss_kib": max_rss_kib,
            "exit_code": self.process.returncode,
            "stderr_tail": stderr[-4000:],
        }


class Pair:
    def __init__(self, scenario: str, methodology: dict[str, Any], latex_results: list[dict[str, Any]]) -> None:
        self.temp_py = tempfile.TemporaryDirectory(prefix=f"mtm006-{scenario}-py-")
        self.temp_rs = tempfile.TemporaryDirectory(prefix=f"mtm006-{scenario}-rs-")
        self.root_py = Path(self.temp_py.name)
        self.root_rs = Path(self.temp_rs.name)
        self.python = Driver([sys.executable, str(PYTHON_SHADOW)])
        self.rust = Driver([str(RUST_SHADOW)])
        self.records: list[dict[str, Any]] = []
        self.mismatches: list[dict[str, Any]] = []
        self.scenario = scenario
        init_common = {
            "now_iso": NOW_ISO,
            "unix_seconds": UNIX_SECONDS,
            "hex_ids": [f"h{index:05d}" for index in range(500)],
            "urlsafe_ids": [f"u{index:05d}" for index in range(500)],
            "capability_secret_hex": CAPABILITY_SECRET_HEX,
            "methodology": methodology,
            "latex_results": latex_results,
        }
        py = self.python.request(
            "init",
            {
                **init_common,
                "database": str(self.root_py / "state.sqlite3"),
                "private_root": str(self.root_py / "private"),
            },
        )
        rs = self.rust.request(
            "init",
            {
                **init_common,
                "database": str(self.root_rs / "state.sqlite3"),
                "private_root": str(self.root_rs / "private"),
            },
        )
        self.compare("init", "init", {}, py, rs)

    def step(
        self,
        name: str,
        operation: str,
        payload: dict[str, Any],
        *,
        normalize: bool = True,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        py = self.python.request(operation, payload)
        rs = self.rust.request(operation, payload)
        self.compare(name, operation, payload, py, rs, normalize=normalize)
        return py, rs

    def compare(
        self,
        name: str,
        operation: str,
        payload: dict[str, Any],
        python_response: dict[str, Any],
        rust_response: dict[str, Any],
        *,
        normalize: bool = True,
    ) -> None:
        py = normalize_value(python_response, self.root_py) if normalize else python_response
        rs = normalize_value(rust_response, self.root_rs) if normalize else rust_response
        record = {
            "scenario": self.scenario,
            "name": name,
            "operation": operation,
            "response": py,
        }
        self.records.append(record)
        if py != rs:
            self.mismatches.append(
                {
                    "scenario": self.scenario,
                    "name": name,
                    "operation": operation,
                    "payload": redact_request(payload),
                    "python": py,
                    "rust": rs,
                }
            )

    def close(self) -> dict[str, Any]:
        resources = {
            "python": self.python.close(),
            "rust": self.rust.close(),
        }
        self.temp_py.cleanup()
        self.temp_rs.cleanup()
        return resources


def scenario_compact_correct(pair: Pair) -> None:
    started, _ = pair.step(
        "compact_start",
        "start",
        {
            "owner_id": "owner",
            "problem_tex": r"\begin{proposition}Prove $1=1$.\end{proposition}",
            "problem_id": "compact-correct",
            "references": [],
            "native_mode": "dangerous",
            "workflow_mode": "compact",
            "register_result": True,
            "workflow_protocol_version": 2,
            "trace_id": "tr-compact-start",
        },
    )
    run_id = result_text(started, "run_id")
    assess, _ = pair.step(
        "compact_assess_task",
        "next",
        {"owner_id": "owner", "run_id": run_id, "trace_id": "tr-compact-assess"},
    )
    assess_cap = result_text(assess, "capability")
    pair.step(
        "compact_assess_memory",
        "write",
        {
            "owner_id": "owner",
            "capability": assess_cap,
            "resource": "memory:generation:immediate_conclusions",
            "content": {"summary": "Reflexivity."},
            "trace_id": "tr-compact-assess-memory",
        },
    )
    pair.step(
        "compact_assessment_complete",
        "commit",
        {
            "owner_id": "owner",
            "capability": assess_cap,
            "action": "assessment_complete",
            "payload": {
                "route": "compact",
                "route_reason": "direct self-contained proof",
                "requires_external_retrieval": False,
                "requires_multiple_plans": False,
            },
            "trace_id": "tr-compact-assessment-complete",
        },
    )
    assembler, _ = pair.step(
        "compact_assembler_task",
        "next",
        {"owner_id": "owner", "run_id": run_id, "trace_id": "tr-compact-assembler"},
    )
    assembler_cap = result_text(assembler, "capability")
    proof = r"\begin{proof}By reflexivity.\end{proof}"
    pair.step(
        "compact_write_proof",
        "write",
        {
            "owner_id": "owner",
            "capability": assembler_cap,
            "resource": "proof",
            "content": proof,
            "trace_id": "tr-compact-proof",
        },
    )
    pair.step(
        "compact_write_manifest",
        "write",
        {
            "owner_id": "owner",
            "capability": assembler_cap,
            "resource": "proof_manifest",
            "content": {
                "target_statement_tex": "Prove $1=1$.",
                "dependency_revision_ids": [],
                "reference_ids": [],
                "conditional_hypotheses": [],
                "computational_evidence": [],
            },
            "trace_id": "tr-compact-manifest",
        },
    )
    pair.step(
        "compact_proof_submitted",
        "commit",
        {
            "owner_id": "owner",
            "capability": assembler_cap,
            "action": "proof_submitted",
            "payload": {"outcome": "proof"},
            "trace_id": "tr-compact-proof-submitted",
        },
    )
    verifier, _ = pair.step(
        "compact_verifier_task",
        "next",
        {"owner_id": "owner", "run_id": run_id, "trace_id": "tr-compact-verifier"},
    )
    verifier_cap = result_text(verifier, "capability")
    pair.step(
        "compact_verifier_statement",
        "write",
        {
            "owner_id": "owner",
            "capability": verifier_cap,
            "resource": "memory:verifier:statement_checks",
            "content": {"location": "proof", "status": "checked"},
            "trace_id": "tr-compact-statement",
        },
    )
    pair.step(
        "compact_verifier_event",
        "write",
        {
            "owner_id": "owner",
            "capability": verifier_cap,
            "resource": "memory:verifier:events",
            "content": {"event_type": "verification_audit_complete"},
            "trace_id": "tr-compact-verifier-event",
        },
    )
    pair.step(
        "compact_verification_report",
        "write",
        {
            "owner_id": "owner",
            "capability": verifier_cap,
            "resource": "verification_report",
            "content": {
                "verification_report": {
                    "summary": "Every step is valid.",
                    "critical_errors": [],
                    "gaps": [],
                },
                "verdict": "wrong",
                "repair_hints": "model verdict must be ignored",
            },
            "trace_id": "tr-compact-report",
        },
    )
    pair.step(
        "compact_verification_submitted",
        "commit",
        {
            "owner_id": "owner",
            "capability": verifier_cap,
            "action": "verification_submitted",
            "payload": {},
            "trace_id": "tr-compact-verification-submitted",
        },
    )
    pair.step(
        "compact_done",
        "next",
        {"owner_id": "owner", "run_id": run_id, "trace_id": "tr-compact-finalize"},
    )
    pair.step(
        "compact_final_artifact",
        "artifact",
        {"owner_id": "owner", "run_id": run_id, "artifact": "final_tex"},
    )
    pair.step(
        "compact_status",
        "status",
        {"owner_id": "owner", "run_id": run_id},
    )
    pair.step("compact_database_snapshot", "database_snapshot", {})
    pair.step("compact_vault_snapshot", "vault_snapshot", {})


def scenario_branch_barrier(pair: Pair) -> None:
    started, _ = pair.step(
        "branch_start",
        "start",
        {
            "owner_id": "owner",
            "problem_tex": "Prove a statement with two plausible routes.",
            "problem_id": "branch-barrier",
            "references": [],
            "native_mode": "dangerous",
            "workflow_mode": "full",
            "register_result": True,
            "workflow_protocol_version": 2,
            "trace_id": "tr-branch-start",
        },
    )
    run_id = result_text(started, "run_id")
    assess, _ = pair.step(
        "branch_assess_task",
        "next",
        {"owner_id": "owner", "run_id": run_id, "trace_id": "tr-branch-assess"},
    )
    cap = result_text(assess, "capability")
    pair.step(
        "branch_assess_memory",
        "write",
        {
            "owner_id": "owner",
            "capability": cap,
            "resource": "memory:generation:immediate_conclusions",
            "content": {"summary": "Two routes remain plausible."},
            "trace_id": "tr-branch-assess-memory",
        },
    )
    pair.step(
        "branch_assessment_complete",
        "commit",
        {
            "owner_id": "owner",
            "capability": cap,
            "action": "assessment_complete",
            "payload": {"route": "full"},
            "trace_id": "tr-branch-assessment-complete",
        },
    )
    explore, _ = pair.step(
        "branch_explore_task",
        "next",
        {"owner_id": "owner", "run_id": run_id, "trace_id": "tr-branch-explore"},
    )
    cap = result_text(explore, "capability")
    pair.step(
        "branch_explore_event",
        "write",
        {
            "owner_id": "owner",
            "capability": cap,
            "resource": "memory:generation:events",
            "content": {"event_type": "exploration"},
            "trace_id": "tr-branch-explore-event",
        },
    )
    pair.step(
        "branch_exploration_complete",
        "commit",
        {
            "owner_id": "owner",
            "capability": cap,
            "action": "exploration_complete",
            "payload": {},
            "trace_id": "tr-branch-exploration-complete",
        },
    )
    planning, _ = pair.step(
        "branch_planning_task",
        "next",
        {"owner_id": "owner", "run_id": run_id, "trace_id": "tr-branch-planning"},
    )
    cap = result_text(planning, "capability")
    pair.step(
        "branch_plans_proposed",
        "commit",
        {
            "owner_id": "owner",
            "capability": cap,
            "action": "plans_proposed",
            "payload": {
                "plans": [
                    {
                        "plan_id": "route-a",
                        "summary": "Split into cases",
                        "subgoals": ["case A"],
                    },
                    {
                        "plan_id": "route-b",
                        "summary": "Use an invariant",
                        "subgoals": ["invariant B"],
                    },
                ]
            },
            "trace_id": "tr-branch-plans",
        },
    )
    direct, _ = pair.step(
        "branch_direct_task",
        "next",
        {"owner_id": "owner", "run_id": run_id, "trace_id": "tr-branch-direct"},
    )
    cap = result_text(direct, "capability")
    pair.step(
        "branch_direct_memory",
        "write",
        {
            "owner_id": "owner",
            "capability": cap,
            "resource": "memory:generation:proof_steps",
            "content": {"attempt": "screen both plans"},
            "trace_id": "tr-branch-direct-memory",
        },
    )
    pair.step(
        "branch_direct_complete",
        "commit",
        {
            "owner_id": "owner",
            "capability": cap,
            "action": "direct_proving_complete",
            "payload": {
                "screening": {
                    "plan-r1-1": {
                        "sg-1": {"status": "stuck", "summary": "needs branch work"}
                    },
                    "plan-r1-2": {
                        "sg-1": {"status": "stuck", "summary": "needs independent work"}
                    },
                }
            },
            "trace_id": "tr-branch-direct-complete",
        },
    )
    branch_a, _ = pair.step(
        "branch_a_task",
        "next",
        {"owner_id": "owner", "run_id": run_id, "trace_id": "tr-branch-a"},
    )
    cap_a = result_text(branch_a, "capability")
    branch_a_id = nested_result_text(branch_a, "context", "branch_id")
    pair.step(
        "branch_a_memory",
        "write",
        {
            "owner_id": "owner",
            "capability": cap_a,
            "resource": "memory:branch:proof_steps",
            "content": {"step": "route A proof"},
            "trace_id": "tr-branch-a-memory",
        },
    )
    pair.step(
        "branch_a_complete",
        "commit",
        {
            "owner_id": "owner",
            "capability": cap_a,
            "action": "branch_complete",
            "payload": {
                "status": "solved",
                "summary": "route A works",
                "proof_route": "complete route A",
                "proved_subgoals": ["case A"],
            },
            "trace_id": "tr-branch-a-complete",
        },
    )
    pair.step(
        "branch_a_stale_capability",
        "read",
        {
            "owner_id": "owner",
            "capability": cap_a,
            "resource": "snapshot",
            "trace_id": "tr-branch-a-stale",
        },
    )
    branch_b, _ = pair.step(
        "branch_b_task",
        "next",
        {"owner_id": "owner", "run_id": run_id, "trace_id": "tr-branch-b"},
    )
    cap_b = result_text(branch_b, "capability")
    pair.step(
        "branch_b_cross_branch_denial",
        "read",
        {
            "owner_id": "owner",
            "capability": cap_b,
            "resource": f"branch:{branch_a_id}",
            "trace_id": "tr-branch-cross",
        },
    )
    pair.step(
        "branch_b_memory",
        "write",
        {
            "owner_id": "owner",
            "capability": cap_b,
            "resource": "memory:branch:proof_steps",
            "content": {"step": "route B obstruction"},
            "trace_id": "tr-branch-b-memory",
        },
    )
    pair.step(
        "branch_b_complete",
        "commit",
        {
            "owner_id": "owner",
            "capability": cap_b,
            "action": "branch_complete",
            "payload": {
                "status": "failed",
                "summary": "route B fails",
                "unproved_subgoals": ["invariant B"],
                "failure_evidence": ["obstruction"],
            },
            "trace_id": "tr-branch-b-complete",
        },
    )
    join, _ = pair.step(
        "branch_join_task",
        "next",
        {"owner_id": "owner", "run_id": run_id, "trace_id": "tr-branch-join"},
    )
    join_cap = result_text(join, "capability")
    pair.step(
        "branch_join_read_all",
        "read",
        {
            "owner_id": "owner",
            "capability": join_cap,
            "resource": "branch:sealed:all",
            "trace_id": "tr-branch-read-all",
        },
    )
    pair.step(
        "branch_join_complete",
        "commit",
        {
            "owner_id": "owner",
            "capability": join_cap,
            "action": "join_complete",
            "payload": {"selected_branch_id": branch_a_id},
            "trace_id": "tr-branch-join-complete",
        },
    )
    pair.step(
        "branch_database_snapshot",
        "database_snapshot",
        {},
    )
    pair.step("branch_vault_snapshot", "vault_snapshot", {})


def scenario_compact_repair_escalation(pair: Pair) -> None:
    started, _ = pair.step(
        "repair_start",
        "start",
        {
            "owner_id": "owner",
            "problem_tex": "Prove a compact statement.",
            "problem_id": "repair-escalation",
            "references": [],
            "native_mode": "dangerous",
            "workflow_mode": "compact",
            "register_result": True,
            "workflow_protocol_version": 2,
            "trace_id": "tr-repair-start",
        },
    )
    run_id = result_text(started, "run_id")
    assess, _ = pair.step(
        "repair_assess_task",
        "next",
        {"owner_id": "owner", "run_id": run_id, "trace_id": "tr-repair-assess"},
    )
    cap = result_text(assess, "capability")
    pair.step(
        "repair_assess_memory",
        "write",
        {
            "owner_id": "owner",
            "capability": cap,
            "resource": "memory:generation:immediate_conclusions",
            "content": {"summary": "direct"},
            "trace_id": "tr-repair-assess-memory",
        },
    )
    pair.step(
        "repair_assessment_complete",
        "commit",
        {
            "owner_id": "owner",
            "capability": cap,
            "action": "assessment_complete",
            "payload": {
                "route": "compact",
                "requires_external_retrieval": False,
                "requires_multiple_plans": False,
            },
            "trace_id": "tr-repair-assessment-complete",
        },
    )
    assembler, _ = pair.step(
        "repair_assembler_task",
        "next",
        {"owner_id": "owner", "run_id": run_id, "trace_id": "tr-repair-assembler"},
    )
    cap = result_text(assembler, "capability")
    write_proof_and_manifest(pair, "repair_first", cap, "proof version one")
    pair.step(
        "repair_first_proof_submit",
        "commit",
        {
            "owner_id": "owner",
            "capability": cap,
            "action": "proof_submitted",
            "payload": {"outcome": "proof"},
            "trace_id": "tr-repair-first-submit",
        },
    )
    verifier, _ = pair.step(
        "repair_first_verifier",
        "next",
        {"owner_id": "owner", "run_id": run_id, "trace_id": "tr-repair-first-verifier"},
    )
    cap = result_text(verifier, "capability")
    write_wrong_verification(pair, "repair_first_wrong", cap, "first gap")
    pair.step(
        "repair_first_wrong_commit",
        "commit",
        {
            "owner_id": "owner",
            "capability": cap,
            "action": "verification_submitted",
            "payload": {},
            "trace_id": "tr-repair-first-wrong-commit",
        },
    )
    repair, _ = pair.step(
        "repair_task",
        "next",
        {"owner_id": "owner", "run_id": run_id, "trace_id": "tr-repair-task"},
    )
    cap = result_text(repair, "capability")
    write_proof_and_manifest(pair, "repair_second", cap, "proof version two")
    pair.step(
        "repair_submitted",
        "commit",
        {
            "owner_id": "owner",
            "capability": cap,
            "action": "repair_submitted",
            "payload": {},
            "trace_id": "tr-repair-submit",
        },
    )
    verifier2, _ = pair.step(
        "repair_second_verifier",
        "next",
        {"owner_id": "owner", "run_id": run_id, "trace_id": "tr-repair-second-verifier"},
    )
    cap = result_text(verifier2, "capability")
    write_wrong_verification(pair, "repair_second_wrong", cap, "second gap")
    pair.step(
        "repair_second_wrong_commit",
        "commit",
        {
            "owner_id": "owner",
            "capability": cap,
            "action": "verification_submitted",
            "payload": {},
            "trace_id": "tr-repair-second-wrong-commit",
        },
    )
    pair.step(
        "repair_escalated_task",
        "next",
        {"owner_id": "owner", "run_id": run_id, "trace_id": "tr-repair-escalated"},
    )
    pair.step("repair_database_snapshot", "database_snapshot", {})
    pair.step("repair_vault_snapshot", "vault_snapshot", {})


def scenario_owner_cancel_and_reference_gap(pair: Pair) -> None:
    reference = {"name": "ref.txt", "content": "A quoted theorem statement.", "source": "inline"}
    started, _ = pair.step(
        "reference_start",
        "start",
        {
            "owner_id": "owner",
            "problem_tex": "Prove a statement using a supplied reference.",
            "problem_id": "reference-gap",
            "references": [reference],
            "native_mode": "dangerous",
            "workflow_mode": "full",
            "register_result": True,
            "workflow_protocol_version": 2,
            "trace_id": "tr-reference-start",
        },
    )
    run_id = result_text(started, "run_id")
    pair.step(
        "reference_owner_denial",
        "status",
        {"owner_id": "other-owner", "run_id": run_id},
    )
    assess, _ = pair.step(
        "reference_assess_task",
        "next",
        {"owner_id": "owner", "run_id": run_id, "trace_id": "tr-reference-assess"},
    )
    cap = result_text(assess, "capability")
    pair.step(
        "reference_problem_read",
        "read",
        {
            "owner_id": "owner",
            "capability": cap,
            "resource": "problem",
            "trace_id": "tr-reference-read",
        },
    )
    pair.step(
        "reference_wrong_owner_capability",
        "read",
        {
            "owner_id": "other-owner",
            "capability": cap,
            "resource": "problem",
            "trace_id": "tr-reference-wrong-owner",
        },
    )
    pair.step(
        "reference_steer",
        "steer",
        {
            "owner_id": "owner",
            "run_id": run_id,
            "message": "Prefer a source-grounded route.",
            "trace_id": "tr-reference-steer",
        },
    )
    pair.step(
        "reference_cancel",
        "cancel",
        {
            "owner_id": "owner",
            "run_id": run_id,
            "reason": "test cancellation",
            "trace_id": "tr-reference-cancel",
        },
    )
    pair.step(
        "reference_resume_terminal_denial",
        "resume",
        {"owner_id": "owner", "run_id": run_id},
    )
    pair.step("reference_database_snapshot", "database_snapshot", {})
    pair.step("reference_vault_snapshot", "vault_snapshot", {})


def write_proof_and_manifest(pair: Pair, prefix: str, capability: str, proof: str) -> None:
    pair.step(
        f"{prefix}_proof",
        "write",
        {
            "owner_id": "owner",
            "capability": capability,
            "resource": "proof",
            "content": proof,
            "trace_id": f"tr-{prefix}-proof",
        },
    )
    pair.step(
        f"{prefix}_manifest",
        "write",
        {
            "owner_id": "owner",
            "capability": capability,
            "resource": "proof_manifest",
            "content": {
                "target_statement_tex": "target",
                "dependency_revision_ids": [],
                "reference_ids": [],
                "conditional_hypotheses": [],
                "computational_evidence": [],
            },
            "trace_id": f"tr-{prefix}-manifest",
        },
    )


def write_wrong_verification(pair: Pair, prefix: str, capability: str, issue: str) -> None:
    pair.step(
        f"{prefix}_statement",
        "write",
        {
            "owner_id": "owner",
            "capability": capability,
            "resource": "memory:verifier:statement_checks",
            "content": {"location": "proof", "status": "gap", "summary": issue},
            "trace_id": f"tr-{prefix}-statement",
        },
    )
    pair.step(
        f"{prefix}_event",
        "write",
        {
            "owner_id": "owner",
            "capability": capability,
            "resource": "memory:verifier:events",
            "content": {"event_type": "verification_audit_complete"},
            "trace_id": f"tr-{prefix}-event",
        },
    )
    pair.step(
        f"{prefix}_report",
        "write",
        {
            "owner_id": "owner",
            "capability": capability,
            "resource": "verification_report",
            "content": {
                "verification_report": {
                    "summary": "needs repair",
                    "critical_errors": [],
                    "gaps": [{"location": "proof", "issue": issue}],
                },
                "verdict": "correct",
                "repair_hints": "repair the stated gap",
            },
            "trace_id": f"tr-{prefix}-report",
        },
    )


def result_text(response: dict[str, Any], key: str) -> str:
    value = response.get("result", {}).get(key)
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"response has no {key}: {response}")
    return value


def nested_result_text(response: dict[str, Any], first: str, second: str) -> str:
    value = response.get("result", {}).get(first, {}).get(second)
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"response has no {first}.{second}: {response}")
    return value


def normalize_value(value: Any, fixture_root: Path) -> Any:
    marker = fixture_root.as_posix()
    if isinstance(value, str):
        return value.replace(marker, "<FIXTURE_ROOT>")
    if isinstance(value, list):
        return [normalize_value(item, fixture_root) for item in value]
    if isinstance(value, dict):
        return {
            key: normalize_value(item, fixture_root)
            for key, item in sorted(value.items())
        }
    return value


def redact_request(payload: Any) -> Any:
    if isinstance(payload, dict):
        output = {}
        for key, value in payload.items():
            lowered = key.lower()
            if any(token in lowered for token in ("capability", "secret", "token", "password")):
                output[key] = "[redacted]"
            elif key == "content" and isinstance(value, str) and len(value) > 200:
                output[key] = f"[text:{len(value)} bytes]"
            else:
                output[key] = redact_request(value)
        return output
    if isinstance(payload, list):
        return [redact_request(item) for item in payload]
    return payload


def minimal_environment() -> dict[str, str]:
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")
    return {key: os.environ[key] for key in keep if key in os.environ}


def process_peak_rss_kib(pid: int) -> int | None:
    status = Path(f"/proc/{pid}/status")
    if not status.is_file():
        return None
    try:
        for line in status.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("VmHWM:"):
                parts = line.split()
                return int(parts[1]) if len(parts) >= 2 else None
    except (OSError, ValueError):
        return None
    return None


def source_reference_status() -> tuple[str, int, bool, list[str]]:
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    expected_commit = str(baseline["source_commit"])
    files = [str(item) for item in baseline["reference_files"]]
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=SOURCE_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout.strip()
    changed = set(
        subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=SOURCE_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout.splitlines()
    )
    dirty_paths = []
    for line in changed:
        raw = line[3:] if len(line) >= 4 else ""
        if " -> " in raw:
            raw = raw.split(" -> ", 1)[1]
        if raw in files:
            dirty_paths.append(raw)
    missing = [path for path in files if not (SOURCE_ROOT / path).is_file()]
    return head, len(files), head == expected_commit and not dirty_paths and not missing, sorted(dirty_paths + missing)


def build_shadow() -> None:
    environment = os.environ.copy()
    cargo_home = ROOT / ".toolchain" / "cargo"
    rustup_home = ROOT / ".toolchain" / "rustup"
    environment["CARGO_HOME"] = str(cargo_home)
    environment["RUSTUP_HOME"] = str(rustup_home)
    environment["PATH"] = str(cargo_home / "bin") + os.pathsep + environment.get("PATH", "")
    subprocess.run(
        [str(cargo_home / "bin" / "cargo"), "build", "-q", "-p", "mtm-workflow", "--bin", "mtm_workflow_shadow"],
        cwd=ROOT,
        env=environment,
        check=True,
    )


def main() -> int:
    build_shadow()
    head, reference_count, clean, dirty = source_reference_status()
    methodology = json.loads(METHODOLOGY.read_text(encoding="utf-8"))
    scenarios: list[tuple[str, Callable[[Pair], None], list[dict[str, Any]]]] = [
        ("compact_correct", scenario_compact_correct, [PASS_LATEX]),
        ("branch_barrier", scenario_branch_barrier, []),
        ("compact_repair_escalation", scenario_compact_repair_escalation, [PASS_LATEX, PASS_LATEX]),
        ("owner_cancel_reference", scenario_owner_cancel_and_reference_gap, []),
    ]
    all_records: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []
    resources: dict[str, Any] = {}
    for name, scenario, latex in scenarios:
        pair = Pair(name, methodology, [dict(item) for item in latex])
        try:
            scenario(pair)
        finally:
            resources[name] = pair.close()
        all_records.extend(pair.records)
        mismatches.extend(pair.mismatches)

    canonical = json.dumps(
        all_records,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    reference_hash = hashlib.sha256(canonical).hexdigest()
    recorded = GOLDEN.read_text(encoding="utf-8").strip() if GOLDEN.is_file() else None
    golden_match = recorded is None or recorded == reference_hash
    resource_gate = True
    for scenario_resource in resources.values():
        for runtime in ("python", "rust"):
            item = scenario_resource[runtime]
            resource_gate = resource_gate and item["exit_code"] == 0 and item["elapsed_ms"] < 30_000
    payload = {
        "ok": clean and not mismatches and golden_match and resource_gate,
        "source_commit": head,
        "source_reference_file_count": reference_count,
        "source_reference_files_clean": clean,
        "dirty_reference_files": dirty,
        "scenario_count": len(scenarios),
        "record_count": len(all_records),
        "differential_mismatch_count": len(mismatches),
        "mismatch_names": [
            f"{item['scenario']}::{item['name']}" for item in mismatches
        ],
        "mismatches": mismatches[:10],
        "reference_sha256": reference_hash,
        "recorded_sha256": recorded,
        "golden_match": golden_match,
        "resource_gate_passed": resource_gate,
        "resources": resources,
        "authority": {
            "source_reference": "python",
            "rust_mode": "workflow_vault_finalizer_shadow",
            "deployed_workflow_authority": "python",
            "shared_state_between_runtimes": False,
        },
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
