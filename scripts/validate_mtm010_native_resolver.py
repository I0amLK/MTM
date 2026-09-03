#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from run_mtm010_native_resolver import (
    HELPER,
    REPORT,
    WEB_CASES,
    implementation_sha256,
    sha256_file,
)


REQUIRED_CHECKS = {
    "host_resolver_shape",
    "trusted_dns_and_https",
    "dangerous_dns_and_https",
    "safe_mode_network_isolation",
    "resolver_mount_boundary",
    "resource_non_regression",
    "no_persistent_helper_process",
}


def load_report(path: Path = REPORT) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("MTM-010 resolver report must be an object")
    return payload


def validate(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "1.0.0" or payload.get("milestone") != "MTM-010":
        raise ValueError("MTM-010 resolver report identity mismatch")
    if payload.get("implementation_sha256") != implementation_sha256():
        raise ValueError("MTM-010 resolver evidence is stale for the current implementation")
    if not HELPER.is_file() or payload.get("helper_sha256") != sha256_file(HELPER):
        raise ValueError("MTM-010 helper binary hash does not match the recorded target")

    host = payload.get("host_resolver")
    if not isinstance(host, dict) or host.get("target_is_file") is not True:
        raise ValueError("host resolver target was not recorded as a regular file")
    if host.get("is_symlink") is True and host.get("target_trusted_runtime_resolver") is not True:
        raise ValueError("host resolver symlink target is outside the approved runtime roots")

    checks = payload.get("checks")
    if not isinstance(checks, list):
        raise ValueError("MTM-010 checks must be an array")
    by_name = {
        str(check.get("name")): check
        for check in checks
        if isinstance(check, dict) and isinstance(check.get("name"), str)
    }
    if set(by_name) != REQUIRED_CHECKS:
        raise ValueError(f"MTM-010 check set mismatch: {sorted(by_name)}")
    failed = [name for name, check in by_name.items() if check.get("passed") is not True]
    if failed:
        raise ValueError(f"MTM-010 target checks failed: {failed}")

    for mode in ("trusted", "dangerous"):
        networked = by_name[f"{mode}_dns_and_https"]
        if (
            networked.get("network_isolated") is not False
            or networked.get("getent_rc") != 0
            or networked.get("getent_returned_address") is not True
            or networked.get("curl_rc") != 0
            or networked.get("http_code") != "200"
            or networked.get("resolver_target") != host.get("target")
        ):
            raise ValueError(f"{mode} resolver/HTTPS evidence is incomplete")

    safe = by_name["safe_mode_network_isolation"]
    if safe.get("network_isolated") is not True or safe.get("curl_rc") == 0:
        raise ValueError("safe-mode network isolation was not preserved")

    boundary = by_name["resolver_mount_boundary"]
    if (
        boundary.get("unexpected_run_entries") != []
        or boundary.get("missing_expected_run_entries") != []
        or boundary.get("sensitive_paths_visible") != []
    ):
        raise ValueError("resolver mount exposed an unexpected runtime or secret path")
    observed = set(boundary.get("observed_run_entries") or [])
    if "/run" in observed:
        raise ValueError("broad /run visibility is forbidden")

    resources = by_name["resource_non_regression"]
    if (
        resources.get("repetitions") != 20
        or resources.get("helper_delta") != 0
        or resources.get("thread_delta") != 0
        or not isinstance(resources.get("fd_delta"), int)
        or resources.get("fd_delta", 99) > 1
        or resources.get("performance_claim") is not False
    ):
        raise ValueError("resolver helper resource non-regression evidence is incomplete")

    web_cases = payload.get("web_cases")
    if not isinstance(web_cases, list):
        raise ValueError("MTM-010 web_cases must be an array")
    expected_names = [case[0] for case in WEB_CASES]
    actual_names = [case.get("name") for case in web_cases if isinstance(case, dict)]
    if actual_names != expected_names:
        raise ValueError("MTM-010 real-web case ordering changed")
    if any(case.get("passed") is not True for case in web_cases):
        raise ValueError("one or more MTM-010 real-web cases failed")
    if any(case.get("resolver_workaround") is not False for case in web_cases):
        raise ValueError("MTM-010 real-web evidence used a forbidden resolver workaround")

    cases = {str(case["name"]): case for case in web_cases}
    if cases["redirect_chain5"].get("redirects") != 5:
        raise ValueError("redirect-chain edge case did not traverse five redirects")
    if cases["http_404"].get("http_code") != "404" or cases["http_404"].get("curl_rc") != 0:
        raise ValueError("HTTP 404 edge-case semantics changed")
    if cases["slow_2s"].get("time_total_seconds", 0) < 1.5:
        raise ValueError("slow-response edge case completed implausibly early")
    if (
        cases["expired_tls"].get("curl_rc") != 60
        or cases["expired_tls"].get("ssl_verify_result") != "10"
    ):
        raise ValueError("expired TLS certificate was not rejected correctly")
    if (
        cases["wrong_host_tls"].get("curl_rc") != 60
        or cases["wrong_host_tls"].get("ssl_verify_result") != "1"
    ):
        raise ValueError("wrong-host TLS certificate was not rejected correctly")

    summary = payload.get("summary")
    if not isinstance(summary, dict) or summary.get("all_passed") is not True:
        raise ValueError("MTM-010 summary does not record complete acceptance")
    if summary.get("resolver_workaround_used") is not False:
        raise ValueError("resolver workaround must remain false")
    if summary.get("broad_run_mount_allowed") is not False:
        raise ValueError("broad /run mount must remain forbidden")
    if summary.get("safe_network_isolation_required") is not True:
        raise ValueError("safe-mode network isolation requirement is missing")

    serialized = json.dumps(payload, sort_keys=True).lower()
    for secret_marker in ("nameserver ", "oauth operator key", "token_secret", "capability_secret"):
        if secret_marker in serialized:
            raise ValueError(f"MTM-010 report contains disallowed sensitive marker: {secret_marker}")

    return {
        "evidence": "mtm010_native_resolver",
        "implementation_sha256": payload["implementation_sha256"],
        "helper_sha256": payload["helper_sha256"],
        "check_count": len(checks),
        "web_case_count": len(web_cases),
        "host_resolver_symlink": host.get("is_symlink"),
        "safe_network_isolated": safe.get("network_isolated"),
        "trusted_hostname_https": by_name["trusted_dns_and_https"].get("http_code"),
        "dangerous_hostname_https": by_name["dangerous_dns_and_https"].get("http_code"),
        "resolver_workaround_used": False,
        "broad_run_mount": False,
    }


def main() -> int:
    try:
        summary = validate(load_report())
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
