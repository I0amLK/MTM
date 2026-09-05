from __future__ import annotations

import copy
import unittest

from scripts.validate_mtm014_capacity_validation import CHECKS, SCOPES, validate


class CapacityEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = {"binary_sha256": "a" * 64, "implementation_and_harness_sha256": "b" * 64}
        # Synthetic parser fixture, never a repository acceptance receipt.
        self.payload = {**SCOPES, **self.identity, "ok": True,
                        "checks": dict.fromkeys(CHECKS, True), "check_count": len(CHECKS)}

    def test_valid_a3_fixture_never_authorizes_cutover(self) -> None:
        self.assertFalse(validate(self.payload, identity=self.identity)["cutover_allowed"])

    def test_empty_missing_unknown_or_failed_checks_are_rejected(self) -> None:
        for checks in ({}, {"unrelated": True}, dict.fromkeys(CHECKS, False)):
            with self.subTest(checks=checks), self.assertRaises(ValueError):
                validate(dict(self.payload, checks=checks), identity=self.identity)
        for value in (1, "true", None):
            payload = copy.deepcopy(self.payload)
            payload["checks"][next(iter(CHECKS))] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate(payload, identity=self.identity)

    def test_scripted_response_cannot_be_relabelled_human_or_cutover(self) -> None:
        for key in ("real_human_consent_evidence", "production_exec_or_patch_authority_cutover"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate(dict(self.payload, **{key: True}), identity=self.identity)
        with self.assertRaises(ValueError):
            validate(dict(self.payload, consent_source="human"), identity=self.identity)

    def test_binary_and_source_drift_are_rejected(self) -> None:
        for key in self.identity:
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate(dict(self.payload, **{key: "c" * 64}), identity=self.identity)

    def test_counts_and_raw_fields_fail_closed(self) -> None:
        for update in ({"check_count": True}, {"check_count": 0}, {"ok": 1},
                       {"raw_request_state_recorded": True}, {"raw_request_state": "do-not-log"}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                validate(dict(self.payload, **update), identity=self.identity)

    def test_empty_or_malformed_identity_cannot_skip_binding(self) -> None:
        for identity in ({}, {"binary_sha256": "a" * 64},
                         dict(self.identity, binary_sha256="not-a-digest")):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                validate(self.payload, identity=identity)


if __name__ == "__main__":
    unittest.main()
