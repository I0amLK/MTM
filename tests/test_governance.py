from __future__ import annotations

import copy
import json
import tempfile
import tomllib
import unittest
from pathlib import Path

from scripts.validate_commit_message import validate_message
from scripts.validate_engineering_graph import validate_graph as validate_engineering
from scripts.validate_historical_mtm_release_evidence import validate as validate_historical_mtm_release_evidence
from scripts.validate_migration_graph import load_graph, validate_graph as validate_migration
from scripts.validate_mtm003_target_evidence import validate as validate_mtm003_target
from scripts.validate_mtm004_target_evidence import validate as validate_mtm004_target
from scripts.validate_mtm005_target_evidence import validate as validate_mtm005_target
from scripts.validate_mtm006_target_evidence import validate as validate_mtm006_target
from scripts.validate_mtm007_target_evidence import validate as validate_mtm007_target
from scripts.validate_mtm008_candidate_evidence import validate as validate_mtm008_candidate
from scripts.validate_mtm_command_namespace import validate as validate_mtm_command_namespace
from scripts.validate_mtm009_preview_release import validate as validate_mtm009_preview_release
from scripts.validate_mtm009_research_contract import validate as validate_mtm009_research_contract


ROOT = Path(__file__).resolve().parents[1]


def mtm009_preview_mode() -> bool:
    progress = json.loads((ROOT / "project-progress.json").read_text(encoding="utf-8"))
    return (
        str(progress.get("version") or "").startswith("0.4.0-preview.")
        and progress.get("current_milestone") == "MTM-009"
        and progress.get("status") == "MTM-009-in-progress"
    )


def historical_check_count(milestone: str) -> int:
    summary = validate_historical_mtm_release_evidence()
    evidence = summary["evidence"]
    assert isinstance(evidence, dict)
    item = evidence[milestone]
    assert isinstance(item, dict)
    return int(item["check_count"])


class GovernanceTestCase(unittest.TestCase):
    def test_repository_migration_graph_is_valid(self) -> None:
        summary = validate_migration(load_graph())
        self.assertEqual(summary["milestone_count"], 10)
        self.assertEqual(summary["todo_count"], 2)

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
        self.assertEqual(
            summary["cargo_members"],
            [
                "mtm-cli",
                "mtm-contracts",
                "mtm-core",
                "mtm-gateway",
                "mtm-native",
                "mtm-runtime",
                "mtm-storage",
                "mtm-workflow",
            ],
        )
        self.assertTrue(summary["mtm_runtime_single_composition_root"])
        self.assertTrue(summary["mtm_cli_presentation_boundary"])
        self.assertTrue(summary["oauth_principal_unforgeable_by_public_construction"])
        self.assertTrue(summary["operator_observer_presentation_only"])
        self.assertTrue(summary["mtm_runtime_namespace_isolated"])
        self.assertTrue(summary["mtm_public_identity"])
        self.assertTrue(summary["deployment_command_namespace_separated"])

    def test_current_mtm003_target_evidence_is_fresh(self) -> None:
        if mtm009_preview_mode():
            self.assertEqual(historical_check_count("MTM-003"), 14)
            return
        summary = validate_mtm003_target()
        self.assertEqual(summary["required_check_count"], 14)

    def test_current_mtm004_target_evidence_is_fresh_and_redacted(self) -> None:
        if mtm009_preview_mode():
            self.assertEqual(historical_check_count("MTM-004"), 10)
            return
        summary = validate_mtm004_target()
        self.assertEqual(summary["required_check_count"], 10)

    def test_current_mtm005_target_evidence_is_fresh_and_redacted(self) -> None:
        if mtm009_preview_mode():
            self.assertEqual(historical_check_count("MTM-005"), 15)
            return
        summary = validate_mtm005_target()
        self.assertEqual(summary["required_check_count"], 15)

    def test_current_mtm006_target_evidence_is_fresh_and_redacted(self) -> None:
        if mtm009_preview_mode():
            self.assertEqual(historical_check_count("MTM-006"), 8)
            return
        summary = validate_mtm006_target()
        self.assertEqual(summary["required_check_count"], 8)

    def test_current_mtm007_target_evidence_is_fresh_and_redacted(self) -> None:
        if mtm009_preview_mode():
            self.assertEqual(historical_check_count("MTM-007"), 12)
            return
        summary = validate_mtm007_target()
        self.assertEqual(summary["required_check_count"], 12)

    def test_current_mtm008_candidate_evidence_is_fresh_and_redacted(self) -> None:
        if mtm009_preview_mode():
            self.assertEqual(historical_check_count("MTM-008"), 10)
            return
        summary = validate_mtm008_candidate()
        self.assertEqual(summary["required_check_count"], 10)

    def test_current_mtm_and_re_ctm_command_namespaces_are_separate(self) -> None:
        summary = validate_mtm_command_namespace()
        if mtm009_preview_mode():
            self.assertEqual(summary["evidence"], "mtm009_preview_release")
            self.assertEqual(summary["mtm_version"], "0.4.0-preview.1")
            self.assertFalse(summary["existing_sessions_restarted_for_preview"])
        else:
            self.assertEqual(summary["required_check_count"], 10)

    def test_current_mtm009_preview_release_is_installed_and_bounded(self) -> None:
        if not mtm009_preview_mode():
            self.skipTest("MTM-009 preview release is not the current deployment mode")
        summary = validate_mtm009_preview_release()
        self.assertEqual(summary["version"], "0.4.0-preview.1")
        self.assertEqual(summary["production_default_workflow_protocol"], 2)
        self.assertTrue(summary["protocol3_opt_in"])
        self.assertFalse(summary["protocol3_default_cutover_allowed"])
        self.assertEqual(summary["real_web_a4"], "pending")
        self.assertEqual(summary["final_artifact"], "proof_verified.tex")

    def test_mtm009_research_contract_freezes_complexity_and_authority(self) -> None:
        summary = validate_mtm009_research_contract()
        self.assertEqual(summary["planned_workflow_protocol"], 3)
        self.assertEqual(summary["production_workflow_protocol"], 2)
        self.assertEqual(summary["workspace_crates"], 8)
        self.assertEqual(summary["public_tools"], 24)
        self.assertEqual(summary["hidden_aliases"], 11)
        self.assertEqual(summary["state_schema_version"], 2)
        self.assertEqual(summary["final_artifact"], "proof_verified.tex")
        self.assertTrue(summary["projector_pure_boundary"])
        self.assertEqual(summary["generic_graph_dependencies"], 0)
        self.assertRegex(summary["graph_golden_digest"], r"^sha256:[0-9a-f]{64}$")

    def test_mtm_cli_publishes_only_the_mtm_binary_name(self) -> None:
        manifest = tomllib.loads((ROOT / "crates" / "mtm-cli" / "Cargo.toml").read_text(encoding="utf-8"))
        self.assertEqual([item["name"] for item in manifest.get("bin", [])], ["mtm"])

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
