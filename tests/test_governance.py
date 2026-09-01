from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.validate_commit_message import validate_message
from scripts.validate_engineering_graph import validate_graph as validate_engineering
from scripts.validate_migration_graph import load_graph, validate_graph as validate_migration


ROOT = Path(__file__).resolve().parents[1]


class GovernanceTestCase(unittest.TestCase):
    def test_repository_migration_graph_is_valid(self) -> None:
        summary = validate_migration(load_graph())
        self.assertEqual(summary["milestone_count"], 8)
        self.assertEqual(summary["todo_count"], 1)

    def test_dependency_cycle_is_rejected(self) -> None:
        payload = copy.deepcopy(load_graph())
        payload["edges"].append({"source": "MTM-001", "target": "MTM-008"})
        payload["milestones"][0]["dependencies"].append("MTM-008")
        with self.assertRaisesRegex(ValueError, "dependency cycle"):
            validate_migration(payload)

    def test_completed_milestone_requires_receipt(self) -> None:
        payload = copy.deepcopy(load_graph())
        template = copy.deepcopy(payload["milestones"][-1])
        template["id"] = "MTM-900"
        template["title"] = "Synthetic receipt fixture"
        template["status"] = "completed"
        template["dependencies"] = []
        payload["milestones"].append(template)
        payload["events"].extend(
            [
                {
                    "event_id": "TEST-EVENT-1",
                    "milestone_id": "MTM-900",
                    "at": "2026-09-01T01:00:00-07:00",
                    "status_before": "proposed",
                    "status_after": "approved",
                    "summary": "test",
                },
                {
                    "event_id": "TEST-EVENT-2",
                    "milestone_id": "MTM-900",
                    "at": "2026-09-01T01:01:00-07:00",
                    "status_before": "approved",
                    "status_after": "in_progress",
                    "summary": "test",
                },
                {
                    "event_id": "TEST-EVENT-3",
                    "milestone_id": "MTM-900",
                    "at": "2026-09-01T01:02:00-07:00",
                    "status_before": "in_progress",
                    "status_after": "completed",
                    "summary": "test",
                },
            ]
        )
        with self.assertRaisesRegex(ValueError, "requires matching receipt"):
            validate_migration(payload)

    def test_target_crate_graph_is_acyclic(self) -> None:
        payload = json.loads((ROOT / "engineering-graph.json").read_text(encoding="utf-8"))
        summary = validate_engineering(payload)
        self.assertTrue(summary["crate_graph_acyclic"])
        self.assertEqual(summary["cargo_members"], ["mtm-cli", "mtm-contracts", "mtm-core"])

    def test_commit_message_contract(self) -> None:
        message = """docs(governance): establish project foundation [MTM-001]

Milestone: MTM-001
Authority-Before: python
Authority-After: python
Acceptance: A0
Receipt: records/iterations/ITER-001.json
Rollback: delete the bootstrap repository
Manual-Pending: all target acceptance
"""
        self.assertEqual(validate_message(message), "MTM-001")

    def test_perf_commit_requires_a6(self) -> None:
        message = """perf(core): accelerate parser [MTM-002]

Milestone: MTM-002
Authority-Before: rust-shadow
Authority-After: rust
Acceptance: A0,A1,A2
Receipt: records/iterations/ITER-002.json
Rollback: restore Python adapter
Manual-Pending: none
"""
        with self.assertRaisesRegex(ValueError, "requires A6"):
            validate_message(message)


if __name__ == "__main__":
    unittest.main()
