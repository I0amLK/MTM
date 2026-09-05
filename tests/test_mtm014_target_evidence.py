from __future__ import annotations

import copy
import unittest

from scripts.validate_mtm014_native_permission_target import CHECKS, validate


class TargetEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.human = {
            "source_commit": "a" * 40,
            "candidate_binary_sha256": "b" * 64,
        }
        self.payload = {
            "schema_version": "1.0.0",
            "milestone": "MTM-014",
            "phase": "pre_cutover_native_permission_target",
            "ok": True,
            "qualification_commit": "c" * 40,
            "candidate_source_commit": "a" * 40,
            "candidate_binary_sha256": "b" * 64,
            "human_evidence_sha256": "d" * 64,
            "runner_sha256": "e" * 64,
            "check_count": len(CHECKS),
            "checks": dict.fromkeys(CHECKS, True),
            "source_compatibility": {
                "candidate_is_ancestor": True,
                "changed_crate_files": ["crates/mtm-runtime/src/native_authority.rs"],
                "native_authority_production_prefix_equal": True,
                "packaging_inputs_equal": True,
            },
            "required_tools": dict.fromkeys(
                ["bwrap", "curl", "git", "pdflatex", "latexmk", "sage", "magma"], True
            ),
            "attestations": {
                mode: {
                    "hard_isolation": True,
                    "workspace_mounted": True,
                    "forbidden_paths_hidden": True,
                    "private_vault_mounted": False,
                    "capabilities_dropped": True,
                    "no_privilege_escalation": True,
                    "parent_environment_cleared": True,
                    "nested_user_namespaces_disabled": True,
                    "toolchain_roots_validated": True,
                    "network_isolated": mode == "safe",
                }
                for mode in ("safe", "trusted", "dangerous")
            },
            "mrtr_check_count": 22,
            "capacity_check_count": 13,
            "magma": {
                "executable_available": True,
                "candidate_reached": True,
                "host_status": "blocked_host_license",
                "failure_attributed_to_mtm": False,
            },
            "human_client": {
                "name": "MCP Inspector",
                "version": "2.5.0",
                "protocol_version": "2026-07-28",
                "transport": "streamable_http_over_cloudflare_quick_tunnel",
            },
            "pre_cutover_target_corpus_passed": True,
            "production_exec_or_patch_authority_cutover": False,
            "production_cutover_allowed_by_this_report": False,
            "stable_selector_changed": False,
            "workflow_authority_inherited": False,
            "evidence_hygiene": {
                "raw_oauth_key_recorded": False,
                "raw_access_token_recorded": False,
                "raw_request_state_recorded": False,
                "raw_grant_id_recorded": False,
                "raw_tool_arguments_recorded": False,
                "raw_command_output_recorded": False,
            },
        }

    def validate_fixture(self, payload: dict) -> dict:
        return validate(
            payload,
            human_payload=self.human,
            human_sha256="d" * 64,
            runner_sha256="e" * 64,
        )

    def test_valid_fixture_is_pre_cutover_only(self) -> None:
        summary = self.validate_fixture(self.payload)
        self.assertEqual(summary["scope"], "A4_pre_cutover")
        self.assertTrue(summary["target_corpus_passed"])
        self.assertFalse(summary["production_cutover_allowed"])

    def test_any_failed_check_is_rejected(self) -> None:
        payload = copy.deepcopy(self.payload)
        payload["checks"][next(iter(CHECKS))] = False
        with self.assertRaises(ValueError):
            self.validate_fixture(payload)

    def test_cutover_or_authority_leak_claims_are_rejected(self) -> None:
        for update in (
            {"production_exec_or_patch_authority_cutover": True},
            {"production_cutover_allowed_by_this_report": True},
            {"stable_selector_changed": True},
            {"workflow_authority_inherited": True},
        ):
            with self.subTest(update=update), self.assertRaises(ValueError):
                self.validate_fixture(dict(self.payload, **update))

    def test_source_compatibility_cannot_be_relaxed(self) -> None:
        for update in (
            {"candidate_is_ancestor": False},
            {"changed_crate_files": []},
            {"native_authority_production_prefix_equal": False},
            {"packaging_inputs_equal": False},
        ):
            payload = copy.deepcopy(self.payload)
            payload["source_compatibility"].update(update)
            with self.subTest(update=update), self.assertRaises(ValueError):
                self.validate_fixture(payload)

    def test_attestation_and_hygiene_fail_closed(self) -> None:
        payload = copy.deepcopy(self.payload)
        payload["attestations"]["safe"]["capabilities_dropped"] = False
        with self.assertRaises(ValueError):
            self.validate_fixture(payload)
        payload = copy.deepcopy(self.payload)
        payload["evidence_hygiene"]["raw_grant_id_recorded"] = True
        with self.assertRaises(ValueError):
            self.validate_fixture(payload)

    def test_magma_host_license_block_is_classified_not_hidden(self) -> None:
        payload = copy.deepcopy(self.payload)
        payload["magma"]["host_status"] = "unknown"
        with self.assertRaises(ValueError):
            self.validate_fixture(payload)
        payload = copy.deepcopy(self.payload)
        payload["magma"]["failure_attributed_to_mtm"] = True
        with self.assertRaises(ValueError):
            self.validate_fixture(payload)


if __name__ == "__main__":
    unittest.main()
