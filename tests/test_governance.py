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
from scripts.validate_record_layout import validate as validate_record_layout
from scripts.record_paths import resolve_repository_record
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
from scripts.validate_mtm012_preview_release import validate as validate_mtm012_preview_release
from scripts.validate_mtm013_runtime_hardening import validate as validate_mtm013_runtime_hardening
from scripts.validate_mtm013_exact_stable_semantic_regression import (
    validate as validate_mtm013_exact_stable_semantic_regression,
)


ROOT = Path(__file__).resolve().parents[1]


def deployment_mode() -> str:
    progress = json.loads((ROOT / "records/governance/project-progress.json").read_text(encoding="utf-8"))
    milestone = progress.get("current_milestone")
    stable_report = ROOT / "records/evidence/MTM-013/stable-release.json"
    stable_selector = Path("/home/lk/.local/bin/mtm")
    if (
        progress.get("version") == "0.4.0"
        and milestone in {"MTM-013", "MTM-014"}
        and progress.get("status")
        in {"MTM-013-in-progress", "MTM-013-completed", "MTM-014-in-progress", "MTM-014-completed"}
        and stable_report.is_file()
        and stable_selector.is_symlink()
        and "/releases/0.4.0/" in str(stable_selector.resolve())
    ):
        return "mtm013_stable"
    if (
        str(progress.get("version") or "").startswith("0.4.0-preview.")
        and milestone == "MTM-009"
        and progress.get("status") == "MTM-009-in-progress"
    ):
        return "mtm009_preview"
    if (
        progress.get("version") == "0.4.0-preview.2"
        and milestone in {"MTM-011", "MTM-012"}
        and progress.get("status")
        in {"MTM-011-in-progress", "MTM-011-completed", "MTM-012-in-progress"}
    ):
        return "mtm011_preview"
    if (
        progress.get("version") in {"0.4.0-preview.3", "0.4.0"}
        and milestone in {"MTM-012", "MTM-013"}
        and progress.get("status")
        in {"MTM-012-in-progress", "MTM-012-completed", "MTM-013-in-progress"}
    ):
        return "mtm012_preview"
    return "non_preview"


def historical_evidence_mode() -> bool:
    return deployment_mode() in {
        "mtm009_preview",
        "mtm011_preview",
        "mtm012_preview",
        "mtm013_stable",
    }


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
        self.assertEqual(summary["milestone_count"], 14)
        self.assertEqual(summary["todo_count"], 1)

    def test_mtm014_native_permission_contract_is_frozen(self) -> None:
        graph = load_graph()
        milestone = next(item for item in graph["milestones"] if item["id"] == "MTM-014")
        self.assertEqual(milestone["status"], "in_progress")
        self.assertEqual(milestone["dependencies"], ["MTM-013"])
        self.assertTrue(
            any(item.startswith("No Bubblewrap replacement") for item in milestone["non_goals"])
        )
        iteration = json.loads(
            (ROOT / "records" / "iterations" / "ITER-014.json").read_text(encoding="utf-8")
        )
        frozen = iteration["frozen_contract"]
        self.assertEqual(
            frozen["permission_kinds"],
            [
                "network",
                "destructive_command",
                "long_timeout",
                "sensitive_env",
                "shell_expansion",
                "inline_script",
                "privileged_executable",
                "write_generated_or_ignored",
            ],
        )
        self.assertEqual(frozen["permission_scopes"], ["once", "session"])
        self.assertEqual(frozen["permission_tools"], ["exec_command", "apply_patch"])
        self.assertTrue(frozen["plain_request_is_not_consent"])
        self.assertTrue(frozen["bubblewrap_remains_linux_isolation_actuator"])
        self.assertTrue(frozen["dangerous_native_never_inherits_workflow_authority"])
        delivery = {item["id"]: item["status"] for item in iteration["delivery"]}
        self.assertEqual(delivery["D1"], "accepted")
        self.assertEqual(delivery["D2"], "accepted")
        self.assertEqual(delivery["D3"], "accepted")
        self.assertEqual(delivery["D4"], "accepted")
        self.assertEqual(delivery["D5"], "in_progress")
        d3 = iteration["d3_contract"]
        self.assertEqual(
            d3["exec_permission_order"],
            [
                "sensitive_env",
                "destructive_command",
                "shell_expansion",
                "inline_script",
                "network",
                "long_timeout",
                "privileged_executable",
            ],
        )
        self.assertEqual(d3["long_timeout_threshold_ms_exclusive"], 30_000)
        self.assertEqual(d3["long_timeout_schema_max_ms"], 600_000)
        self.assertIn("0o6000", d3["privileged_executable_rule"])
        self.assertEqual(
            d3["generated_or_excluded_components"],
            [
                ".git",
                ".venv",
                "venv",
                "node_modules",
                "dist",
                "build",
                "__pycache__",
                ".pytest_cache",
                ".mypy_cache",
                ".ruff_cache",
                "target",
            ],
        )
        self.assertFalse(d3["dry_run_patch_requires_write_permission"])
        self.assertEqual(d3["authority_mode"], "shadow_only_before_d5")
        self.assertFalse(d3["production_check_command_policy_changed"])
        self.assertFalse(d3["production_exec_command_changed"])
        self.assertFalse(d3["production_apply_patch_changed"])
        self.assertFalse(d3["bubblewrap_changed"])
        d3_receipt = iteration["d3_receipt"]
        self.assertEqual(d3_receipt["authority_mode"], "shadow_only_before_d5")
        self.assertTrue(d3_receipt["complete_original_argument_digest"])
        self.assertTrue(d3_receipt["cmd_and_argv_remain_distinct"])
        self.assertTrue(d3_receipt["intrinsic_exec_classification_mode_neutral"])
        self.assertTrue(d3_receipt["effective_policy_deterministic"])
        self.assertFalse(d3_receipt["pure_explicit_labels_are_authority_bearing"])
        self.assertTrue(d3_receipt["ledger_grants_required_for_explicit_authority"])
        self.assertTrue(d3_receipt["atomic_multi_grant_lookup"])
        self.assertFalse(d3_receipt["client_supplied_grant_id_required"])
        self.assertFalse(d3_receipt["atomic_authorization_partial_consumption_possible"])
        self.assertFalse(d3_receipt["production_request_permissions_changed"])
        self.assertFalse(d3_receipt["production_check_command_policy_changed"])
        self.assertFalse(d3_receipt["production_exec_command_changed"])
        self.assertFalse(d3_receipt["production_apply_patch_changed"])
        self.assertFalse(d3_receipt["bubblewrap_changed"])
        self.assertFalse(d3_receipt["workflow_authority_changed"])
        self.assertFalse(d3_receipt["validation"]["accepted_mtm013_evidence_changed"])
        d4 = iteration["d4_progress"]
        self.assertEqual(d4["authority_mode"], "shadow_only_before_d5")
        self.assertTrue(d4["sandbox_plan_fields_private"])
        self.assertTrue(d4["sandbox_plan_debug_redacted"])
        self.assertEqual(d4["bubblewrap_compiler_input"], "validated SandboxPlan only")
        self.assertFalse(d4["bubblewrap_compiler_receives_native_mode"])
        self.assertFalse(d4["bubblewrap_compiler_receives_grant_or_permission"])
        self.assertFalse(d4["bubblewrap_compiler_receives_oauth_or_workflow_authority"])
        self.assertTrue(d4["resolver_mount_derived_from_network_plan"])
        self.assertTrue(d4["network_grant_widens_only_network_and_resolver_dimension"])
        self.assertFalse(d4["production_profile_behavior_changed"])
        self.assertFalse(d4["explicit_grant_authority_cutover"])
        self.assertFalse(d4["bubblewrap_replaced"])
        self.assertFalse(d4["workflow_authority_changed"])
        self.assertEqual(d4["prepared_patch_review_unit"], "accepted")
        prepared = d4["prepared_patch"]
        self.assertTrue(prepared["fields_private"])
        self.assertFalse(prepared["serializable"])
        self.assertTrue(prepared["debug_redacted"])
        self.assertTrue(prepared["zero_workspace_writes_before_final_authorization"])
        self.assertEqual(prepared["dry_run_authorization_calls"], 0)
        self.assertEqual(prepared["bounded_revalidation_attempts"], 3)
        self.assertEqual(
            prepared["stale_fact_error"], "NATIVE_PATCH_AUTHORITY_FACTS_CHANGED"
        )
        self.assertFalse(prepared["git_commands_held_under_commit_lock"])
        self.assertTrue(prepared["multi_file_rollback"])
        self.assertTrue(prepared["rollback_failure_retains_recovery_backups"])
        self.assertFalse(
            prepared["production_compatibility_path"]["collects_git_authority_facts"]
        )
        self.assertFalse(
            prepared["production_compatibility_path"]["successful_result_shape_changed"]
        )
        self.assertEqual(d4["sandbox_plan_validation"]["native_bubblewrap_tests"], "8 passed")
        self.assertEqual(d4["sandbox_plan_validation"]["full_run_checks"], "24 of 24 passed")
        self.assertFalse(d4["sandbox_plan_validation"]["accepted_mtm013_evidence_changed"])
        d4_receipt = iteration["d4_receipt"]
        self.assertEqual(d4_receipt["authority_mode"], "shadow_only_before_d5")
        self.assertTrue(d4_receipt["sandbox_plan_and_prepared_patch_complete"])
        self.assertTrue(d4_receipt["bubblewrap_compiler_accepts_only_validated_plan"])
        self.assertFalse(d4_receipt["prepared_patch_constructor_public"])
        self.assertFalse(d4_receipt["prepared_patch_serializable"])
        self.assertFalse(d4_receipt["writes_before_final_authorization"])
        self.assertFalse(d4_receipt["dry_run_consumes_authorization"])
        self.assertFalse(d4_receipt["production_permission_authority_changed"])
        self.assertFalse(d4_receipt["production_git_permission_dependency_added"])
        self.assertFalse(d4_receipt["explicit_grant_authority_cutover"])
        self.assertFalse(d4_receipt["validation"]["accepted_mtm013_evidence_changed"])

        d5a = iteration["d5a_contract"]
        self.assertEqual(
            d5a["selected_provider"], "mcp_2026_07_28_mrtr_form_elicitation"
        )
        self.assertEqual(d5a["required_protocol_version"], "2026-07-28")
        self.assertEqual(d5a["required_client_capability"], "elicitation.form")
        self.assertTrue(d5a["empty_elicitation_capability_means_form"])
        self.assertFalse(d5a["url_only_elicitation_supported_for_native_permission_consent"])
        self.assertEqual(d5a["legacy_protocol_behavior"], "unsupported")
        self.assertEqual(d5a["modern_without_form_elicitation_behavior"], "unsupported")
        self.assertEqual(d5a["input_required_rounds"], 1)
        self.assertEqual(d5a["input_request_method"], "elicitation/create")
        self.assertTrue(d5a["challenge_single_use"])
        self.assertEqual(d5a["challenge_store"], "process_local")
        self.assertTrue(d5a["accepted_response_revalidated_server_side"])
        self.assertFalse(d5a["plain_request_is_consent"])
        self.assertFalse(d5a["client_info_is_authority"])
        self.assertFalse(d5a["oauth_authentication_alone_is_consent"])
        self.assertFalse(d5a["model_generated_boolean_is_consent"])
        self.assertFalse(d5a["raw_arguments_in_prompt"])
        self.assertFalse(d5a["public_tool_schema_changed"])
        self.assertFalse(d5a["production_exec_or_patch_authority_changed"])
        self.assertFalse(d5a["workflow_authority_changed"])
        d5a_progress = iteration["d5a_progress"]
        self.assertEqual(d5a_progress["phase"], "mrtr_protocol_plumbing")
        self.assertTrue(d5a_progress["gateway_request_scoped_context"])
        self.assertTrue(d5a_progress["client_capabilities_preserved_per_request"])
        self.assertTrue(d5a_progress["input_responses_parsed_outside_tool_arguments"])
        self.assertTrue(d5a_progress["request_state_parsed_outside_tool_arguments"])
        self.assertEqual(d5a_progress["input_required_capability_gate_error"], -32021)
        self.assertEqual(d5a_progress["input_required_missing_capability_http_status"], 400)
        self.assertFalse(d5a_progress["public_tool_schema_changed"])
        self.assertFalse(d5a_progress["runtime_request_permissions_changed"])
        self.assertFalse(d5a_progress["verified_consent_constructor_connected"])
        self.assertFalse(d5a_progress["grant_minting_from_mrtr_enabled"])
        self.assertFalse(d5a_progress["production_exec_or_patch_authority_changed"])
        self.assertFalse(d5a_progress["real_human_consent_evidence_collected"])
        challenge = d5a_progress["consent_challenge_authority"]
        self.assertTrue(challenge["implemented"])
        self.assertEqual(challenge["store"], "process_local")
        self.assertEqual(challenge["ttl_seconds"], 300)
        self.assertTrue(challenge["single_use"])
        self.assertTrue(challenge["restart_invalidates"])
        self.assertFalse(challenge["cross_owner_attempt_consumes_challenge"])
        self.assertFalse(challenge["cross_workspace_attempt_consumes_challenge"])
        self.assertFalse(challenge["request_mutation_consumes_challenge"])
        self.assertFalse(challenge["decline_mints_grant"])
        self.assertFalse(challenge["cancel_mints_grant"])
        self.assertFalse(challenge["approved_false_mints_grant"])
        self.assertTrue(challenge["accepted_true_can_construct_verified_consent"])
        self.assertFalse(challenge["prompt_contains_raw_arguments"])
        self.assertTrue(challenge["prompt_contains_argument_fingerprint"])
        self.assertTrue(challenge["prompt_challenge_id_debug_redacted"])
        self.assertFalse(challenge["challenge_raw_arguments_retained"])
        self.assertFalse(challenge["runtime_application_connected"])
        self.assertFalse(challenge["request_permissions_connected"])

        bubblewrap_source = (
            ROOT / "crates" / "mtm-native" / "src" / "bubblewrap.rs"
        ).read_text(encoding="utf-8")
        self.assertNotIn("BubblewrapCommandSpec", bubblewrap_source)
        compiler_start = bubblewrap_source.index("pub fn build_bubblewrap_command")
        compiler_end = bubblewrap_source.index("\npub fn run_sandbox_probe", compiler_start)
        compiler = bubblewrap_source[compiler_start:compiler_end]
        self.assertIn("plan: &SandboxPlan", compiler)
        for forbidden_authority_input in (
            "NativeMode",
            "grant",
            "OAuth",
            "workflow",
            "permission",
        ):
            self.assertNotIn(forbidden_authority_input, compiler)
        d2 = iteration["d2_receipt"]
        self.assertTrue(d2["application_resident"])
        self.assertEqual(d2["persistence"], "none")
        self.assertTrue(d2["restart_invalidates_all_grants"])
        self.assertFalse(d2["verified_consent_public_constructor"])
        self.assertFalse(d2["verified_consent_cloneable"])
        self.assertFalse(d2["permit_cloneable"])
        self.assertFalse(d2["raw_arguments_retained_in_ledger"])
        self.assertFalse(d2["plain_request_mints_grant"])
        self.assertFalse(d2["production_request_permissions_changed"])
        self.assertFalse(d2["production_exec_command_changed"])
        self.assertFalse(d2["production_apply_patch_changed"])
        self.assertFalse(d2["bubblewrap_changed"])
        self.assertFalse(d2["workflow_authority_changed"])

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
        payload = json.loads((ROOT / "records/governance/engineering-graph.json").read_text(encoding="utf-8"))
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

    def test_repository_record_layout_is_canonical(self) -> None:
        payload = json.loads(
            (ROOT / "records/governance/record-layout.json").read_text(encoding="utf-8")
        )
        summary = validate_record_layout(payload)
        self.assertEqual(summary["root_json_count"], 0)
        self.assertGreaterEqual(summary["iteration_record_count"], 13)
        self.assertGreaterEqual(summary["evidence_milestone_count"], 9)
        self.assertGreaterEqual(summary["evidence_hashes_checked"], 26)

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
        elif deployment_mode() == "mtm012_preview":
            self.assertEqual(summary["evidence"], "mtm012_preview_release")
            self.assertEqual(summary["mtm_version"], "0.4.0-preview.3")
            self.assertEqual(summary["production_default_workflow_protocol"], 3)
            self.assertEqual(summary["rollback_workflow_protocol"], 2)
            self.assertTrue(summary["real_rollback_and_recutover_passed"])
        elif deployment_mode() == "mtm013_stable":
            self.assertEqual(summary["evidence"], "mtm013_stable_release")
            self.assertEqual(summary["mtm_version"], "0.4.0")
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

    def test_mtm013_runtime_hardening_evidence_is_bound_and_redacted(self) -> None:
        progress = json.loads((ROOT / "records/governance/project-progress.json").read_text(encoding="utf-8"))
        if progress.get("current_milestone") != "MTM-013":
            self.skipTest("MTM-013 hardening is not the current source-qualification mode")
        payload = json.loads((ROOT / "records/evidence/MTM-013/runtime-hardening.json").read_text(encoding="utf-8"))
        summary = validate_mtm013_runtime_hardening(payload)
        self.assertGreaterEqual(summary["check_count"], 12)
        self.assertEqual(summary["initial_state"], "assess")
        self.assertEqual(summary["advanced_state"], "explore")

    def test_mtm013_regression_receipt_preserves_preview_history_and_binds_exact_stable(self) -> None:
        iteration = json.loads(
            (ROOT / "records" / "iterations" / "ITER-013.json").read_text(encoding="utf-8")
        )
        receipt = iteration["regression_receipt"]
        capability = receipt["invalid_capability_edge_corpus"]
        self.assertEqual(capability["status"], "accepted_stable_candidate")
        self.assertEqual(capability["integration_checks"], 12)
        self.assertTrue(capability["single_character_mutation_refresh_zero_writes"])
        self.assertTrue(capability["truncation_refresh_zero_writes"])
        self.assertTrue(capability["fresh_resubmission_advances"])
        self.assertTrue(capability["revoked_remains_denied"])
        self.assertTrue(capability["cross_run_remains_denied"])
        self.assertTrue(capability["cross_owner_refresh_remains_denied"])
        self.assertTrue(capability["stale_not_refreshable"])
        self.assertTrue(capability["expired_not_refreshable"])
        self.assertTrue(capability["only_permission_capability_invalid_refreshable"])

        live_math = receipt["live_web_math_semantic_regression"]
        self.assertEqual(live_math["status"], "accepted_supplemental_not_exact_stable_binary")
        self.assertEqual(live_math["runtime_version"], "0.4.0-preview.3")
        self.assertTrue(live_math["exact_stable_live_rerun_pending"])
        self.assertEqual(live_math["qc_constituent_matching"]["verdict"], "correct")
        self.assertEqual(live_math["compact_proof"]["verdict"], "correct")
        exact = receipt["exact_stable_mcp_semantic_regression"]
        self.assertEqual(exact["status"], "accepted")
        self.assertEqual(exact["runtime_version"], "0.4.0")
        self.assertEqual(
            exact["binary_sha256"],
            "3312ca75a1de8707e740963cc0add4b09430dccc9dc63a3145e4456ff2b0cdf3",
        )
        payload = json.loads(
            (ROOT / "records/evidence/MTM-013/exact-stable-semantic-regression.json").read_text(
                encoding="utf-8"
            )
        )
        summary = validate_mtm013_exact_stable_semantic_regression(payload)
        self.assertEqual(summary["check_count"], 9)
        self.assertEqual(exact["qc_constituent_matching"]["verdict"], "correct")
        self.assertEqual(exact["compact_proof"]["verdict"], "correct")
        self.assertEqual(iteration["decision"], "completed")

    def test_current_mtm012_preview_release_is_installed_and_tui_qualified(self) -> None:
        if deployment_mode() != "mtm012_preview":
            self.skipTest("MTM-012 preview release is not the current deployment mode")
        summary = validate_mtm012_preview_release()
        self.assertEqual(summary["version"], "0.4.0-preview.3")
        self.assertEqual(summary["production_default_workflow_protocol"], 3)
        self.assertEqual(summary["rollback_workflow_protocol"], 2)
        self.assertEqual(summary["selector_rollback_version"], "0.4.0-preview.2")
        self.assertTrue(summary["real_rollback_and_recutover_passed"])
        self.assertEqual(summary["tui_check_count"], 20)
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

    def test_mtm009_lifecycle_closure_preserves_rejected_delivery6(self) -> None:
        graph = load_graph()
        milestone = next(item for item in graph["milestones"] if item["id"] == "MTM-009")
        self.assertEqual(milestone["status"], "completed")

        iteration = json.loads(
            (ROOT / "records" / "iterations" / "ITER-009.json").read_text(encoding="utf-8")
        )
        deliveries = {item["delivery"]: item for item in iteration["seven_deliveries"]}
        self.assertEqual(deliveries[6]["status"], "complete_rejected")
        self.assertEqual(deliveries[7]["status"], "superseded_by_mtm011")

        historical = iteration["delivery_6_stabilization_receipt"]
        self.assertEqual(
            historical["status"],
            "implemented_local_acceptance_passed_live_preview_requalification_pending",
        )
        closure = iteration["delivery_6_lifecycle_closure"]
        self.assertEqual(closure["status"], "closed_complete_rejected")
        self.assertTrue(closure["historical_stabilization_receipt_preserved"])
        self.assertFalse(closure["actionable_mtm009_pending"])
        terminal = closure["terminal_evaluation"]
        self.assertEqual(terminal["complete_pairs"], 8)
        self.assertEqual(terminal["protocol2_verified_tex"], 8)
        self.assertEqual(terminal["protocol3_verified_tex"], 8)
        self.assertFalse(terminal["release_gate_passed"])
        self.assertEqual(terminal["decision"], "rejected")
        self.assertEqual(
            iteration["decision"],
            "completed_with_v1_cutover_rejected_and_default_cutover_superseded_by_mtm011",
        )

    def test_mtm011_cutover_contract_remains_frozen_through_qualification(self) -> None:
        corpus_path = ROOT / "conformance" / "mtm011-math-corpus.json"
        evaluation_path = ROOT / "records/evidence/MTM-011/protocol3-cutover-evaluation.json"
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
            resource_payload = json.loads(
                resolve_repository_record(str(resource["path"])).read_text(encoding="utf-8")
            )
            self.assertEqual(candidate_sha, resource_payload["implementation_sha256"])
            self.assertEqual(candidate_sha, iteration["current_candidate_a5"]["binary_sha256"])
        self.assertEqual(evaluation["release_gate"]["minimum_strict_structural_primary_improvements"], 2)
        authority = json.loads((ROOT / "records/governance/authority-inventory.json").read_text(encoding="utf-8"))
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
        production = ROOT / "records/evidence/MTM-011/protocol3-cutover-evaluation.json"
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
