from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import mtm014_release_support as s
from release_mtm014_preview import compensated_rollout, switch_pair
from validate_mtm014_preview_release import validate_soak, validate_resources, validate_qualification, exact


class PreviewReleaseTests(unittest.TestCase):
    def qualification_fixture(self) -> dict:
        # Synthetic parser fixture only; never installed or saved as evidence.
        metrics = {"startup_samples": 3, "request_samples": 180, "startup_p50_ms": 50,
                   "startup_p95_ms": 60, "request_p95_ms": 3, "max_rss_kib": 12000,
                   "max_threads": 5, "max_fds": 10, "max_shutdown_ms": 20}
        frame = {"rss_kib": 10000, "threads": 5, "fds": 10, "children": 0}
        proof = {"state": "done", "verdict": "correct", "latex_passed": True,
                 "sealed": True, "artifact_sha256": "b" * 64, "artifact_bytes": 10}
        return {
            "schema_version": "1.0.0", "milestone": "MTM-014", "phase": "preview_qualification",
            "version": s.VERSION, "ok": True, "recorded_at": "2026-09-05T00:00:00+00:00",
            "source_commit": "a" * 40, "binary_sha256": "b" * 64, "stable_sha256": s.STABLE_SHA,
            "implementation_commit": s.IMPLEMENTATION,
            "runtime_repair_sha256": {s.RUNTIME_REPAIR_FILE: s.RUNTIME_REPAIR_SHA},
            "harness_sha256": dict.fromkeys(s.HARNESS_FILES, "a" * 64),
            "prerequisite_sha256": dict.fromkeys(s.PREREQUISITES, "a" * 64),
            "checks": dict.fromkeys(s.QUALIFICATION_CHECKS, True), "check_count": len(s.QUALIFICATION_CHECKS),
            "public_suites": {key: dict.fromkeys(names, True) for key, names in s.PUBLIC_SUITE_CHECKS.items()},
            "proof_facts": {"qc": proof.copy(), "compact": proof.copy()},
            "tui_checks": dict.fromkeys(s.TUI_CHECKS, True),
            "required_tools": dict.fromkeys(("bwrap", "curl", "git", "latexmk", "pdflatex", "sage", "magma"), True),
            "magma_host_status": "blocked_host_license", "resource": {"stable": metrics.copy(), "preview": metrics.copy()},
            "soak": {"duration_seconds": 60.1, "iterations": 1000, "shutdown_ms": 10,
                     "before": frame.copy(), "peak": frame.copy(), "after": frame.copy()},
            "new_human_consent_claimed": False, "performance_claim": False,
            "production_state_rewritten": False, "selector_changed": False, "evidence_hygiene": s.HYGIENE.copy(),
        }

    def test_qualification_checks_source_scope_and_hygiene_are_mandatory(self) -> None:
        valid = self.qualification_fixture()
        validate_qualification(valid, binding_verified=True)
        for key, value in (("source_commit", ""), ("ok", 1), ("selector_changed", True),
                           ("new_human_consent_claimed", True), ("performance_claim", True),
                           ("checks", {}), ("evidence_hygiene", {}), ("check_count", True)):
            modified = copy.deepcopy(valid); modified[key] = value
            with self.subTest(key=key), self.assertRaises(s.ReleaseFailure):
                validate_qualification(modified, binding_verified=True)
        for binding in (False, 1):
            with self.assertRaises(s.ReleaseFailure):
                validate_qualification(valid, binding_verified=binding)

    def test_unknown_suite_checks_and_raw_fields_fail_closed(self) -> None:
        for field in ("public_suites", "tui_checks", "evidence_hygiene"):
            value = self.qualification_fixture()
            if field == "public_suites":
                old = next(iter(value[field]["safe"])); del value[field]["safe"][old]
                value[field]["safe"]["invented_pass"] = True
            else:
                value[field]["raw_access_token"] = "synthetic-test-sentinel"
            with self.subTest(field=field), self.assertRaises(s.ReleaseFailure):
                validate_qualification(value, binding_verified=True)

    def test_source_scope_rejects_unpinned_runtime_changes(self) -> None:
        fixed = (s.ROOT / s.RUNTIME_REPAIR_FILE).read_bytes()
        files = (s.RUNTIME_REPAIR_FILE + "\ncrates/mtm-core/src/lib.rs\n").encode()
        for bad in (None, s.RUNTIME_REPAIR_FILE, "crates/mtm-core/src/lib.rs"):
            def git(*args: str) -> bytes:
                if args[0] == "merge-base":
                    return b""
                if args[0] == "ls-tree":
                    return files
                ref, path = args[1].split(":", 1)
                if ref != s.IMPLEMENTATION and path == bad:
                    return b"unexpected runtime modification"
                if path == s.RUNTIME_REPAIR_FILE:
                    return fixed if ref != s.IMPLEMENTATION else b"old watchdog"
                if path.endswith(".rs"):
                    return b"unchanged runtime"
                return b"0.4.0" if ref == s.IMPLEMENTATION else s.VERSION.encode()
            with self.subTest(bad=bad), patch.object(s, "git", git):
                self.assertEqual(s.source_scope_verified("test-commit"), bad is None)

    def test_rollout_failures_restore_both_selectors_and_manifest(self) -> None:
        for failure in (1, 2, 3, 4):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                stable, candidate = root / "stable", root / "preview"
                stable.write_text("old"); candidate.write_text("new")
                selector, cargo, manifest = root / "bin/mtm", root / "cargo/mtm", root / "state/manifest.json"
                before = {"state": "old", "history": []}
                switches = 0
                def switch(target: Path) -> None:
                    switch_pair(target, selector, cargo)
                def smoke(_legacy: bool) -> bool:
                    nonlocal switches
                    switches += 1
                    return switches != failure
                def soak() -> dict:
                    raise s.ReleaseFailure("injected_soak_failure")
                switch(stable)
                with self.assertRaises(s.ReleaseFailure):
                    compensated_rollout(candidate, stable, manifest, before,
                        {"state": "new", "history": []}, switch=switch, smoke=smoke, soak=soak)
                self.assertEqual(selector.resolve(), stable)
                self.assertEqual(cargo.resolve(), stable)
                self.assertEqual(json.loads(manifest.read_text()), before)

    def test_partial_pair_update_is_compensated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stable, candidate = root / "stable", root / "preview"
            stable.touch(); candidate.touch()
            left, right, manifest = root / "a/mtm", root / "b/mtm", root / "manifest.json"
            switch_pair(stable, left, right)
            def switch(target: Path) -> None:
                if target == candidate:
                    from mtm008_deployment import atomic_symlink
                    atomic_symlink(str(target), left)
                    raise OSError("injected pair replacement failure")
                switch_pair(target, left, right)
            with self.assertRaises(OSError):
                compensated_rollout(candidate, stable, manifest, {"history": []}, {"history": []},
                    switch=switch, smoke=lambda _: True, soak=lambda: {})
            self.assertEqual(left.resolve(), stable)
            self.assertEqual(right.resolve(), stable)

    def test_success_records_all_three_transitions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "state.json"
            targets: list[Path] = []
            stable, candidate = Path("/old"), Path("/new")
            compensated_rollout(candidate, stable, manifest, {"history": []}, {"history": []},
                switch=targets.append, smoke=lambda _: True, soak=lambda: {"observed": True})
            self.assertEqual(targets, [candidate, stable, candidate])
            self.assertEqual([x["action"] for x in json.loads(manifest.read_text())["history"]],
                ["mtm014_preview_cutover", "mtm014_stable_rollback", "mtm014_preview_recutover"])

    def test_nested_boolean_masquerading_is_rejected(self) -> None:
        for value in (1, "true", None):
            with self.subTest(value=value), self.assertRaises(s.ReleaseFailure):
                exact({"checks": [value]}, {"checks": [True]})

    def test_soak_cannot_hide_short_duration_growth_or_children(self) -> None:
        frame = {"rss_kib": 10000, "threads": 4, "fds": 10, "children": 0}
        baseline = {"duration_seconds": 60.1, "iterations": 1000, "shutdown_ms": 10,
                    "before": frame.copy(), "peak": frame.copy(), "after": frame.copy()}
        validate_soak(baseline)
        variants = []
        for key, value in (("duration_seconds", 1), ("iterations", 0), ("shutdown_ms", 9000),
                           ("duration_seconds", float("nan")), ("iterations", True)):
            item = copy.deepcopy(baseline); item[key] = value; variants.append(item)
        for key, value in (("rss_kib", 40000), ("fds", 100), ("threads", 20)):
            item = copy.deepcopy(baseline); item["peak"][key] = value; variants.append(item)
        item = copy.deepcopy(baseline); item["after"]["children"] = 1; variants.append(item)
        for item in variants:
            with self.assertRaises(s.ReleaseFailure):
                validate_soak(item)

    def test_resource_regression_cannot_be_marked_passed(self) -> None:
        metrics = {"startup_samples": 3, "request_samples": 180, "startup_p50_ms": 50,
                   "startup_p95_ms": 60, "request_p95_ms": 3, "max_rss_kib": 12000,
                   "max_threads": 5, "max_fds": 10, "max_shutdown_ms": 20}
        value = {"stable": metrics.copy(), "preview": metrics.copy()}
        validate_resources(value)
        for key, bad in (("max_rss_kib", 262145), ("request_p95_ms", 200), ("startup_samples", 0),
                         ("max_threads", 10), ("max_fds", 99), ("max_shutdown_ms", 9000)):
            changed = copy.deepcopy(value); changed["preview"][key] = bad
            with self.assertRaises(s.ReleaseFailure):
                validate_resources(changed)


if __name__ == "__main__":
    unittest.main()
