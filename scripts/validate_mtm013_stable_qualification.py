#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "mtm013-stable-qualification.json"
RESOURCE = ROOT / "mtm013-stable-resource.json"
BINARY = ROOT / "target" / "release" / "mtm"
SOURCE_COMMIT = "fcdc0cd09bb0852e46bb8cdc37de3b81ccff27e3"
EXPECTED_BINARY_SHA256 = "3312ca75a1de8707e740963cc0add4b09430dccc9dc63a3145e4456ff2b0cdf3"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "1.0.0" or payload.get("milestone") != "MTM-013":
        raise ValueError("unexpected stable qualification identity")
    if payload.get("phase") != "stable_0_4_0_qualification" or payload.get("version") != "0.4.0":
        raise ValueError("stable qualification phase/version drifted")
    if payload.get("source_commit") != SOURCE_COMMIT:
        raise ValueError("stable qualification is not bound to the frozen source commit")
    if not BINARY.is_file() or sha256_file(BINARY) != EXPECTED_BINARY_SHA256:
        raise ValueError("stable release binary is missing or drifted")
    if payload.get("binary_sha256") != EXPECTED_BINARY_SHA256:
        raise ValueError("stable qualification binary binding drifted")
    checks = payload.get("checks")
    if not isinstance(checks, dict) or len(checks) < 14 or not all(checks.values()):
        raise ValueError("stable qualification checks are incomplete or failed")
    clean = payload.get("clean_install")
    if not isinstance(clean, dict) or clean.get("source_commit") != SOURCE_COMMIT:
        raise ValueError("clean-clone install did not use the frozen source commit")
    if clean.get("version") != "mtm 0.4.0" or clean.get("identity_ok") is not True:
        raise ValueError("clean-clone install did not produce the stable identity")
    upgrade = payload.get("existing_state_upgrade")
    if not isinstance(upgrade, dict):
        raise ValueError("copied existing-state upgrade evidence is missing")
    if (
        upgrade.get("server_version") != "0.4.0"
        or upgrade.get("state_schema_version") != 2
        or upgrade.get("workflow_protocol_version") != 3
        or upgrade.get("production_default") != 3
        or upgrade.get("complete_flow_locally_validated") is not True
    ):
        raise ValueError("copied existing-state upgrade facts drifted")
    proof = payload.get("proof_finalization")
    if not isinstance(proof, dict) or not all(
        proof.get(key) is True
        for key in ("run_id_present", "final_exists", "final_contains_document", "export_relative")
    ):
        raise ValueError("stable proof finalization evidence is incomplete")
    soak = payload.get("soak")
    if not isinstance(soak, dict) or soak.get("duration_seconds", 0) < 9.5 or soak.get("requests", 0) < 100:
        raise ValueError("stable soak evidence is too short")
    distribution = payload.get("public_github_install")
    if not isinstance(distribution, dict) or distribution.get("local_clean_clone_exact_commit_passed") is not True:
        raise ValueError("stable distribution evidence lacks the exact local clean-clone control")
    if payload.get("raw_capability_recorded") is not False or payload.get("raw_oauth_token_recorded") is not False:
        raise ValueError("stable qualification evidence records secret material")
    if payload.get("raw_proof_recorded") is not False:
        raise ValueError("stable qualification evidence records raw proof content")
    if payload.get("ok") is not True:
        raise ValueError("stable local qualification is not accepted")
    resource = json.loads(RESOURCE.read_text(encoding="utf-8"))
    if resource.get("ok") is not True or resource.get("implementation_sha256") != EXPECTED_BINARY_SHA256:
        raise ValueError("stable A5 resource evidence is missing or stale")
    return {
        "report_sha256": sha256_file(REPORT),
        "resource_sha256": sha256_file(RESOURCE),
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "check_count": len(checks),
        "soak_requests": soak["requests"],
        "public_distribution_status": distribution.get("status"),
        "local_release_qualified": True,
        "stable_cutover_allowed": distribution.get("status") == "passed",
    }


def main() -> int:
    try:
        summary = validate(json.loads(REPORT.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
