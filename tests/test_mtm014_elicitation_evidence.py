from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from scripts.validate_mtm014_elicitation_capability import REPORT, validate


class ElicitationEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = json.loads(REPORT.read_text(encoding="utf-8"))

    def test_repository_human_elicitation_receipt_is_valid(self) -> None:
        summary = validate(self.payload)
        self.assertTrue(summary["human_ui_observed"])
        self.assertFalse(summary["production_cutover_allowed"])

    def test_human_flag_cannot_hide_missing_ui_or_unsafe_hygiene(self) -> None:
        for path, value in (
            (("client_owned_form_observed",), False),
            (("model_supplied_input_responses",), True),
            (("evidence_hygiene", "raw_grant_id_recorded"), True),
            (("form", "edit_as_json_used"), True),
        ):
            payload = copy.deepcopy(self.payload)
            target = payload
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate(payload)

    def test_accept_decline_cancel_are_all_required(self) -> None:
        for observation in ("accept", "decline", "cancel"):
            payload = copy.deepcopy(self.payload)
            del payload["observations"][observation]
            with self.subTest(observation=observation), self.assertRaises(ValueError):
                validate(payload)

    def test_receipt_cannot_claim_public_authority_cutover(self) -> None:
        for key in ("production_exec_or_patch_authority_cutover", "d5_authority_cutover_allowed"):
            payload = dict(self.payload, **{key: True})
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate(payload)

    def test_source_and_binary_identity_are_well_formed(self) -> None:
        for key, value in (("source_commit", "not-a-commit"), ("candidate_binary_sha256", "bad")):
            payload = dict(self.payload, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate(payload)


if __name__ == "__main__":
    unittest.main()
