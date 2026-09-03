from __future__ import annotations

import copy
import json
import subprocess
import sys
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
from scripts.validate_mtm011_math_corpus import validate as validate_mtm011_math_corpus
from scripts.validate_mtm011_math_evaluation import (
    aggregate_complete as aggregate_mtm011_complete,
    validate as validate_mtm011_math_evaluation,
)
from scripts.validate_mtm011_preview_release import validate as validate_mtm011_preview_release


ROOT = Path(__file__).resolve().parents[1]


def deployment_mode() -> str:
    progress = json.loads((ROOT / "project-progress.json").read_text(encoding="utf-8"))
    milestone = progress.get("current_milestone")
    if (
        str(progress.get("version") or "").startswith("0.4.0-preview.")
        and milestone == "MTM-009"
        and progress.get("status") == "MTM-009-in-progress"
    ):
        return "mtm009_preview"
    if (
        progress.get("version") == "0.4.0-preview.2"
        and milestone == "MTM-011"
        and progress.get("status") in {"MTM-011-in-progress", "MTM-011-completed"}
    ):
        return "mtm011_preview"
    return "non_preview"


def historical_evidence_mode() -> bool:
    return deployment_mode() in {"mtm009_preview", "mtm011_preview"}


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
        self.assertEqual(summary["milestone_count"], 11)
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
        if historical_evidence_mode():
            self.assertEqual(historical_check_count("MTM-003"), 14)
            return
        summary = validate_mtm003_target()
        self.assertEqual(summary["required_check_count"], 14)

    def test_current_mtm004_target_evidence_is_fresh_and_redacted(self) -> None:
        if historical_evidence_mode():
            self.assertEqual(historical_check_count("MTM-004"), 10)
            return
        summary = validate_mtm004_target()
        self.assertEqual(summary["required_check_count"], 10)

    def test_current_mtm005_target_evidence_is_fresh_and_redacted(self) -> None:
        if historical_evidence_mode():
            self.assertEqual(historical_check_count("MTM-005"), 15)
            return
        summary = validate_mtm005_target()
        self.assertEqual(summary["required_check_count"], 15)

    def test_current_mtm006_target_evidence_is_fresh_and_redacted(self) -> None:
        if historical_evidence_mode():
            self.assertEqual(historical_check_count("MTM-006"), 8)
            return
        summary = validate_mtm006_target()
        self.assertEqual(summary["required_check_count"], 8)

    def test_current_mtm007_target_evidence_is_fresh_and_redacted(self) -> None:
        if historical_evidence_mode():
            self.assertEqual(historical_check_count("MTM-007"), 12)
            return
        summary = validate_mtm007_target()
        self.assertEqual(summary["required_check_count"], 12)

    def test_current_mtm008_candidate_evidence_is_fresh_and_redacted(self) -> None:
        if historical_evidence_mode():
            self.assertEqual(historical_check_count("MTM-008"), 10)
            return
        summary = validate_mtm008_candidate()
        self.assertEqual(summary["required_check_count"], 10)

    def test_current_mtm_and_re_ctm_command_namespaces_are_separate(self) -> None:
        summary = validate_mtm_command_namespace()
        if deployment_mode() == "mtm009_preview":
            self.assertEqual(summary["evidence"], "mtm009_preview_release")
            self.assertEqual(summary["mtm_version"], "0.4.0-preview.1")
            self.assertFalse(summary["existing_sessions_restarted_for_preview"])
        elif deployment_mode() == "mtm011_preview":
            self.assertEqual(summary["evidence"], "mtm011_preview_release")
            self.assertEqual(summary["mtm_version"], "0.4.0-preview.2")
            self.assertEqual(summary["production_default_workflow_protocol"], 3)
            self.assertEqual(summary["rollback_workflow_protocol"], 2)
            self.assertTrue(summary["real_rollback_and_recutover_passed"])
        else:
            self.assertEqual(summary["required_check_count"], 10)

    def test_current_mtm009_preview_release_is_installed_and_bounded(self) -> None:
        if deployment_mode() != "mtm009_preview":
            self.skipTest("MTM-009 preview release is not the current deployment mode")
        summary = validate_mtm009_preview_release()
        self.assertEqual(summary["version"], "0.4.0-preview.1")
        self.assertEqual(summary["production_default_workflow_protocol"], 2)
        self.assertTrue(summary["protocol3_opt_in"])
        self.assertFalse(summary["protocol3_default_cutover_allowed"])
        self.assertEqual(summary["real_web_a4"], "complete_rejected")
        self.assertEqual(summary["final_artifact"], "proof_verified.tex")

    def test_current_mtm011_preview_release_is_installed_and_rollback_qualified(self) -> None:
        if deployment_mode() != "mtm011_preview":
            self.skipTest("MTM-011 preview release is not the current deployment mode")
        summary = validate_mtm011_preview_release()
        self.assertEqual(summary["version"], "0.4.0-preview.2")
        self.assertEqual(summary["production_default_workflow_protocol"], 3)
        self.assertEqual(summary["rollback_workflow_protocol"], 2)
        self.assertTrue(summary["real_rollback_and_recutover_passed"])
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

    def test_mtm011_cutover_contract_remains_frozen_through_qualification(self) -> None:
        corpus_path = ROOT / "conformance" / "mtm011-math-corpus.json"
        evaluation_path = ROOT / "mtm011-protocol3-cutover-evaluation.json"
        corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
        corpus_summary = validate_mtm011_math_corpus(corpus)
        evaluation_summary = validate_mtm011_math_evaluation(evaluation)
        self.assertEqual(corpus_summary["case_count"], 6)
        self.assertEqual(corpus_summary["order_counts"], {"protocol2_first": 3, "protocol3_first": 3})
        self.assertEqual(
            corpus_summary["corpus_sha256"],
            "6420422bd4017ec811187fe27b37150fe01a90cf62da49d0b328f5ff8e71fa2c",
        )
        self.assertGreaterEqual(evaluation_summary["complete_pairs"], 0)
        self.assertLessEqual(evaluation_summary["complete_pairs"], 6)
        self.assertIn(evaluation_summary["status"], {"pending_web_runs", "in_progress", "complete"})
        if evaluation_summary["status"] == "complete":
            self.assertEqual(evaluation_summary["complete_pairs"], 6)
            self.assertTrue(evaluation_summary["release_gate_passed"])
            self.assertEqual(
                evaluation_summary["evaluation_sha256"],
                "1820027a361604fd77da2e303e1c7c43ab6f25edd7a7401cc6176705c280bd05",
            )
        else:
            self.assertFalse(evaluation_summary["release_gate_passed"])
        iteration = json.loads((ROOT / "records" / "iterations" / "ITER-011.json").read_text(encoding="utf-8"))
        frozen = iteration["frozen_a4_contract"]
        self.assertEqual(
            frozen["initial_evaluation_sha256"],
            "824a0c6700903a6e5e848f4492246ea87fb8d05572eebf39a0575d40ecc22460",
        )
        candidate_sha = evaluation["candidate"]["binary_sha256"]
        if candidate_sha is not None:
            resource = evaluation["resource_evidence"]
            self.assertEqual(resource["status"], "accepted_current_candidate")
            resource_payload = json.loads((ROOT / resource["path"]).read_text(encoding="utf-8"))
            self.assertEqual(candidate_sha, resource_payload["implementation_sha256"])
            self.assertEqual(candidate_sha, iteration["current_candidate_a5"]["binary_sha256"])
        self.assertEqual(evaluation["release_gate"]["minimum_strict_structural_primary_improvements"], 2)
        authority = json.loads((ROOT / "authority-inventory.json").read_text(encoding="utf-8"))
        protocols = authority["preview_policy"]
        if protocols["protocol3_default_cutover_allowed"]:
            self.assertEqual(protocols["production_default_workflow_protocol"], 3)
            self.assertEqual(evaluation_summary["status"], "complete")
            self.assertTrue(evaluation_summary["release_gate_passed"])
        else:
            self.assertEqual(protocols["production_default_workflow_protocol"], 2)
        self.assertTrue(protocols["mtm009_v1_evaluation_immutable"])

    def test_mtm011_gate_requires_two_structural_improvements_and_behavioral_non_regression(self) -> None:
        corpus = json.loads(
            (ROOT / "conformance" / "mtm011-math-corpus.json").read_text(encoding="utf-8")
        )
        cases = {item["case_id"]: item for item in corpus["cases"]}

        def run(protocol: int, case: dict[str, object]) -> dict[str, object]:
            applicability = case["metric_applicability"]
            assert isinstance(applicability, dict)
            return {
                "final_outcome": "verified_tex",
                "first_verification_pass": True,
                "repair_count": 0,
                "verifier_finding_count": 0,
                "repeated_failed_route_without_new_evidence": 0,
                "max_no_novelty_retrieval_streak": 0,
                "harmful_advice_events": 0,
                "counterexample_probe_on_blocker": False
                if applicability["counterexample_probe_on_blocker"]
                else None,
                "focused_retrieval_when_missing_reference": False
                if applicability["focused_retrieval_when_missing_reference"]
                else None,
                "refuted_target_state_preserved": False
                if applicability["refuted_target_state_preserved"]
                else None,
                "typed_obstruction_class_preserved": False
                if applicability["typed_obstruction_class_preserved"]
                else None,
                "canonical_partial_results_preserved": 0,
                "protocol": protocol,
            }

        pairs = []
        for case in corpus["cases"]:
            pairs.append(
                {
                    "case_id": case["case_id"],
                    "protocol2": run(2, case),
                    "protocol3": run(3, case),
                }
            )
        first = pairs[0]["protocol3"]
        first["refuted_target_state_preserved"] = True
        aggregate, gate = aggregate_mtm011_complete(pairs, cases)
        self.assertEqual(aggregate["strict_structural_improvement_count"], 1)
        self.assertFalse(gate)

        second = pairs[1]["protocol3"]
        second["typed_obstruction_class_preserved"] = True
        aggregate, gate = aggregate_mtm011_complete(pairs, cases)
        self.assertEqual(aggregate["strict_structural_improvement_count"], 2)
        self.assertTrue(gate)

        second["verifier_finding_count"] = 1
        aggregate, gate = aggregate_mtm011_complete(pairs, cases)
        self.assertFalse(aggregate["behavioral_non_regression"]["verifier_finding_count"])
        self.assertFalse(gate)

    def test_mtm011_recorders_can_use_isolated_evaluation_ledgers(self) -> None:
        production = ROOT / "mtm011-protocol3-cutover-evaluation.json"
        before = production.read_bytes()
        with tempfile.TemporaryDirectory(prefix="mtm011-ledger-") as raw_root:
            root = Path(raw_root)
            ledger = root / "evaluation.json"
            isolated_seed = json.loads(before)
            isolated_seed["status"] = "pending_web_runs"
            isolated_seed["aggregate"] = None
            isolated_seed["decision"] = "pending"
            for pair in isolated_seed["pairs"]:
                pair["protocol2"] = None
                pair["protocol3"] = None
                pair["blind_evaluation"] = None
            ledger.write_text(json.dumps(isolated_seed, indent=2) + "\n", encoding="utf-8")
            proof = root / "proof.tex"
            proof.write_text(
                "\\documentclass{article}\\begin{document}ok\\end{document}\n",
                encoding="utf-8",
            )
            common = [
                "--evaluation", str(ledger),
                "--case-id", "M011-C02-fixed-point-uniqueness",
                "--binary-sha256", "5cebde6458f29012f3da72564ad6a940cc319aae162f9695070474b77d83b036",
                "--model-surface", "isolated-test-surface",
                "--connector-profile", "isolated-test-profile",
                "--final-outcome", "verified_tex",
                "--final-tex", str(proof),
                "--first-verification-pass", "true",
                "--repair-count", "0",
                "--verifier-finding-count", "0",
                "--repeated-failed-route-without-new-evidence", "0",
                "--counterexample-probe-on-blocker", "true",
                "--focused-retrieval-when-missing-reference", "na",
                "--max-no-novelty-retrieval-streak", "0",
                "--harmful-advice-events", "0",
                "--canonical-partial-results-preserved", "0",
                "--transition-log-sha256", "b" * 64,
                "--verification-report-sha256", "c" * 64,
            ]
            for protocol, refuted, typed, fingerprint in (
                (2, "false", "false", "d" * 64),
                (3, "true", "true", "e" * 64),
            ):
                subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "scripts" / "record_mtm011_web_run.py"),
                        *common,
                        "--protocol", str(protocol),
                        "--run-fingerprint", fingerprint,
                        "--refuted-target-state-preserved", refuted,
                        "--typed-obstruction-class-preserved", typed,
                    ],
                    cwd=ROOT,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "record_mtm011_blind_score.py"),
                    "--evaluation", str(ledger),
                    "--case-id", "M011-C02-fixed-point-uniqueness",
                    "--evaluator-id-hash", "f" * 64,
                    "--a-logic", "5", "--a-readability", "5", "--a-efficiency", "5",
                    "--b-logic", "5", "--b-readability", "5", "--b-efficiency", "5",
                    "--winner", "tie",
                    "--rationale", "Isolated ledger smoke test.",
                ],
                cwd=ROOT,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            isolated = json.loads(ledger.read_text(encoding="utf-8"))
            pair = next(
                item
                for item in isolated["pairs"]
                if item["case_id"] == "M011-C02-fixed-point-uniqueness"
            )
            self.assertIsNotNone(pair["protocol2"])
            self.assertIsNotNone(pair["protocol3"])
            self.assertIsNotNone(pair["blind_evaluation"])
        self.assertEqual(production.read_bytes(), before)

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
