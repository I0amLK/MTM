from __future__ import annotations

import copy
import unittest

from scripts.validate_mtm014_public_authority_target import CHECKS, validate


class PublicAuthorityEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = {
            "schema_version": "1.0.0",
            "milestone": "MTM-014",
            "phase": "post_cutover_public_native_permission_target",
            "ok": True,
            "qualification_commit": "a" * 40,
            "implementation_commit": "2f11750c07317d879f1bedfd2198c36786b8ca74",
            "candidate_binary_sha256": "b" * 64,
            "candidate_version": "mtm 0.4.0",
            "runner_sha256": "c" * 64,
            "d5a_evidence_sha256": "d" * 64,
            "pre_cutover_target_evidence_sha256": "e" * 64,
            "check_count": len(CHECKS),
            "checks": dict.fromkeys(CHECKS, True),
            "required_tools": dict.fromkeys(
                ["bwrap", "curl", "git", "pdflatex", "latexmk", "sage", "magma"], True
            ),
            "magma_host_status": "blocked_host_license",
            "human_consent_reused_from_d5a": True,
            "scripted_response_is_not_human_evidence": True,
            "public_exec_apply_patch_authority": "typed_rust_native_permission_authority",
            "public_missing_grant_error": "PERMISSION_REQUIRED",
            "client_supplied_grant_id": False,
            "stable_selector_changed": False,
            "workflow_authority_inherited": False,
            "release_or_selector_cutover_performed": False,
            "evidence_hygiene": {
                "raw_oauth_key_recorded": False,
                "raw_access_token_recorded": False,
                "raw_request_state_recorded": False,
                "raw_grant_id_recorded": False,
                "raw_command_id_recorded": False,
                "raw_tool_arguments_recorded": False,
                "raw_command_output_recorded": False,
            },
        }

    def validate_fixture(self, payload: dict) -> dict:
        return validate(
            payload,
            d5a_sha256="d" * 64,
            pre_target_sha256="e" * 64,
            qualification_binding_verified=True,
        )

    def test_valid_fixture_is_post_cutover_a4_without_release_cutover(self) -> None:
        summary = self.validate_fixture(self.payload)
        self.assertEqual(summary["scope"], "A4_post_cutover_public")
        self.assertEqual(summary["check_count"], len(CHECKS))
        self.assertTrue(summary["public_authority_qualified"])
        self.assertFalse(summary["release_cutover_allowed"])

    def test_any_failed_or_non_boolean_check_is_rejected(self) -> None:
        for value in (False, 1, "true", None):
            payload = copy.deepcopy(self.payload)
            payload["checks"][next(iter(CHECKS))] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validate_fixture(payload)

    def test_authority_or_release_scope_cannot_be_widened(self) -> None:
        for update in (
            {"client_supplied_grant_id": True},
            {"stable_selector_changed": True},
            {"workflow_authority_inherited": True},
            {"release_or_selector_cutover_performed": True},
            {"public_missing_grant_error": "NATIVE_PERMISSION_GRANT_SET_INCOMPLETE"},
        ):
            with self.subTest(update=update), self.assertRaises(ValueError):
                self.validate_fixture(dict(self.payload, **update))

    def test_scripted_a4_response_cannot_claim_new_human_evidence(self) -> None:
        for update in (
            {"human_consent_reused_from_d5a": False},
            {"scripted_response_is_not_human_evidence": False},
        ):
            with self.subTest(update=update), self.assertRaises(ValueError):
                self.validate_fixture(dict(self.payload, **update))

    def test_raw_authority_material_is_rejected(self) -> None:
        payload = copy.deepcopy(self.payload)
        payload["evidence_hygiene"]["raw_grant_id_recorded"] = True
        with self.assertRaises(ValueError):
            self.validate_fixture(payload)

    def test_evidence_hash_drift_is_rejected(self) -> None:
        for key in ("d5a_evidence_sha256", "pre_cutover_target_evidence_sha256"):
            payload = dict(self.payload, **{key: "f" * 64})
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate_fixture(payload)

    def test_qualification_commit_binding_is_mandatory(self) -> None:
        with self.assertRaises(ValueError):
            validate(
                self.payload,
                d5a_sha256="d" * 64,
                pre_target_sha256="e" * 64,
                qualification_binding_verified=False,
            )


if __name__ == "__main__":
    unittest.main()
