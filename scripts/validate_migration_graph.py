#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
GRAPH = ROOT / "migration-graph.json"
ID_RE = re.compile(r"MTM-\d{3}$")
COMMIT_RE = re.compile(
    r"(?:docs|test|build|feat|fix|refactor|perf|chore)"
    r"\([a-z0-9][a-z0-9-]*\): .+ \[MTM-\d{3}\]$"
)
ACTIONABLE = {"approved", "in_progress", "shadow", "authoritative", "blocked"}
TERMINAL = {"completed", "rejected", "superseded"}
ALLOWED_TRANSITIONS = {
    "proposed": {"approved", "rejected", "superseded"},
    "approved": {"in_progress", "blocked", "rejected", "superseded"},
    "in_progress": {"shadow", "blocked", "rejected", "superseded", "completed"},
    "shadow": {"authoritative", "blocked", "rejected", "superseded"},
    "authoritative": {"completed", "blocked"},
    "blocked": {"approved", "in_progress", "shadow", "authoritative", "rejected", "superseded"},
    "completed": set(),
    "rejected": set(),
    "superseded": set(),
}


def load_graph(path: Path = GRAPH) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("migration graph must be an object")
    return payload


def validate_graph(payload: dict[str, Any]) -> dict[str, Any]:
    milestones = payload.get("milestones")
    if not isinstance(milestones, list) or not milestones:
        raise ValueError("milestones must be a non-empty array")
    by_id: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(milestones):
        if not isinstance(item, dict):
            raise ValueError(f"milestones[{index}] must be an object")
        milestone_id = item.get("id")
        if not isinstance(milestone_id, str) or ID_RE.fullmatch(milestone_id) is None:
            raise ValueError(f"invalid milestone id at index {index}")
        if milestone_id in by_id:
            raise ValueError(f"duplicate milestone id: {milestone_id}")
        status = item.get("status")
        if status not in ALLOWED_TRANSITIONS:
            raise ValueError(f"invalid status for {milestone_id}: {status}")
        for field in (
            "title",
            "functional_goal",
            "scope",
            "non_goals",
            "acceptance_levels",
            "validation_commands",
            "rollback",
            "dependencies",
            "production_authority_before",
            "production_authority_after",
        ):
            if field not in item:
                raise ValueError(f"{milestone_id} missing {field}")
        if not isinstance(item["scope"], list) or not item["scope"]:
            raise ValueError(f"{milestone_id} requires non-empty scope")
        if not isinstance(item["non_goals"], list) or not item["non_goals"]:
            raise ValueError(f"{milestone_id} requires non-empty non_goals")
        by_id[milestone_id] = item

    dependencies: dict[str, set[str]] = {milestone_id: set() for milestone_id in by_id}
    for edge in payload.get("edges", []):
        if not isinstance(edge, dict):
            raise ValueError("edge must be an object")
        source = edge.get("source")
        target = edge.get("target")
        if source not in by_id or target not in by_id:
            raise ValueError(f"unknown dependency edge: {source}->{target}")
        if source == target:
            raise ValueError(f"self dependency: {source}")
        dependencies[str(source)].add(str(target))

    for milestone_id, item in by_id.items():
        declared = set(item.get("dependencies", []))
        if declared != dependencies[milestone_id]:
            raise ValueError(f"dependency mismatch for {milestone_id}")

    _assert_acyclic(dependencies)

    todo = payload.get("todo")
    if not isinstance(todo, list) or len(todo) != len(set(todo)):
        raise ValueError("todo must be a unique array")
    expected_todo = {
        milestone_id
        for milestone_id, item in by_id.items()
        if item["status"] in ACTIONABLE
    }
    if set(todo) != expected_todo:
        raise ValueError(f"todo mismatch: expected {sorted(expected_todo)}, got {sorted(todo)}")
    todo_index = {milestone_id: index for index, milestone_id in enumerate(todo)}
    for milestone_id in todo:
        for dependency in dependencies[milestone_id]:
            if dependency in todo_index and todo_index[dependency] > todo_index[milestone_id]:
                raise ValueError(f"todo dependency order violation: {milestone_id} before {dependency}")

    events = payload.get("events")
    if not isinstance(events, list):
        raise ValueError("events must be an array")
    event_ids: set[str] = set()
    current = {milestone_id: "proposed" for milestone_id in by_id}
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"events[{index}] must be an object")
        event_id = event.get("event_id")
        milestone_id = event.get("milestone_id")
        before = event.get("status_before")
        after = event.get("status_after")
        if not isinstance(event_id, str) or event_id in event_ids:
            raise ValueError(f"invalid or duplicate event id at index {index}")
        event_ids.add(event_id)
        if milestone_id not in by_id:
            raise ValueError(f"event for unknown milestone: {milestone_id}")
        if before != current[milestone_id]:
            raise ValueError(f"event chain broken for {milestone_id}")
        if after not in ALLOWED_TRANSITIONS[before]:
            raise ValueError(f"illegal transition {before}->{after}")
        current[milestone_id] = after
    for milestone_id, item in by_id.items():
        if current[milestone_id] != item["status"]:
            raise ValueError(f"event/current status mismatch for {milestone_id}")

    receipts = payload.get("receipts")
    if not isinstance(receipts, list):
        raise ValueError("receipts must be an array")
    receipt_contract = payload.get("receipt_contract")
    if not isinstance(receipt_contract, dict):
        raise ValueError("receipt_contract must be an object")
    required_fields = set(receipt_contract.get("required_fields", []))
    required_statuses = set(receipt_contract.get("required_for_statuses", []))
    receipt_by_milestone: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    receipt_ids: set[str] = set()
    for index, receipt in enumerate(receipts):
        if not isinstance(receipt, dict):
            raise ValueError(f"receipts[{index}] must be an object")
        missing = required_fields - set(receipt)
        if missing:
            raise ValueError(f"receipt missing fields: {sorted(missing)}")
        receipt_id = receipt.get("receipt_id")
        milestone_id = receipt.get("milestone_id")
        if not isinstance(receipt_id, str) or receipt_id in receipt_ids:
            raise ValueError(f"invalid or duplicate receipt id at index {index}")
        receipt_ids.add(receipt_id)
        if milestone_id not in by_id:
            raise ValueError(f"receipt for unknown milestone: {milestone_id}")
        subject = receipt.get("commit_subject")
        if not isinstance(subject, str) or COMMIT_RE.fullmatch(subject) is None:
            raise ValueError(f"invalid commit subject in receipt {receipt_id}")
        if f"[{milestone_id}]" not in subject:
            raise ValueError(f"receipt commit subject uses wrong milestone: {receipt_id}")
        receipt_by_milestone[milestone_id].append(receipt)
    for milestone_id, item in by_id.items():
        if item["status"] in required_statuses and not receipt_by_milestone[milestone_id]:
            raise ValueError(f"{milestone_id} requires matching receipt")

    return {
        "milestone_count": len(by_id),
        "edge_count": sum(len(items) for items in dependencies.values()),
        "todo_count": len(todo),
        "event_count": len(events),
        "receipt_count": len(receipts),
        "status_counts": dict(sorted(Counter(item["status"] for item in milestones).items())),
    }


def _assert_acyclic(graph: dict[str, set[str]]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise ValueError(f"dependency cycle at {node}")
        if node in visited:
            return
        visiting.add(node)
        for dependency in graph[node]:
            visit(dependency)
        visiting.remove(node)
        visited.add(node)

    for node in graph:
        visit(node)


def main() -> int:
    try:
        summary = validate_graph(load_graph())
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
