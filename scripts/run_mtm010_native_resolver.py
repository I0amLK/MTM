#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "mtm010-native-resolver.json"
CARGO_HOME = ROOT / ".toolchain" / "cargo"
RUSTUP_HOME = ROOT / ".toolchain" / "rustup"
HELPER = ROOT / "target" / "debug" / "mtm-native-helper"
TRUSTED_RESOLVER_ROOTS = (
    Path("/run/systemd/resolve"),
    Path("/run/NetworkManager"),
    Path("/run/resolvconf"),
)


WEB_CASES = (
    ("normal_https", "https://example.com/", 8, 0, "200", None, None),
    ("redirect_chain5", "https://httpbingo.org/redirect/5", 10, 0, "200", 5, None),
    ("gzip", "https://httpbingo.org/gzip", 8, 0, "200", None, None),
    ("utf8", "https://httpbingo.org/encoding/utf8", 8, 0, "200", None, None),
    ("http_404", "https://httpbingo.org/status/404", 8, 0, "404", None, None),
    ("slow_2s", "https://httpbingo.org/delay/2", 8, 0, "200", None, None),
    ("large_rfc", "https://www.rfc-editor.org/rfc/rfc9110.html", 12, 0, "200", None, None),
    (
        "zh_wikipedia",
        "https://zh.wikipedia.org/wiki/%E6%95%B0%E5%AD%A6",
        12,
        0,
        "200",
        None,
        None,
    ),
    ("expired_tls", "https://expired.badssl.com/", 8, 60, "000", None, "10"),
    ("wrong_host_tls", "https://wrong.host.badssl.com/", 8, 60, "000", None, "1"),
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def implementation_files() -> list[Path]:
    files = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "rust-toolchain.toml"]
    files.extend(path for path in (ROOT / "crates" / "mtm-native").rglob("*") if path.is_file())
    files.extend(
        [
            ROOT / "scripts" / "run_mtm010_native_resolver.py",
            ROOT / "scripts" / "validate_mtm010_native_resolver.py",
        ]
    )
    return sorted(path for path in files if path.is_file())


def implementation_sha256() -> str:
    digest = hashlib.sha256()
    for path in implementation_files():
        relative = path.relative_to(ROOT).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def tool_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["CARGO_HOME"] = str(CARGO_HOME)
    environment["RUSTUP_HOME"] = str(RUSTUP_HOME)
    environment["PATH"] = str(CARGO_HOME / "bin") + os.pathsep + environment.get("PATH", "")
    return environment


def helper_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": os.environ.get("HOME", "/nonexistent"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


def build_helper() -> None:
    subprocess.run(
        [str(CARGO_HOME / "bin" / "cargo"), "build", "-q", "-p", "mtm-native", "--bins"],
        cwd=ROOT,
        env=tool_environment(),
        check=True,
        timeout=120,
    )


def helper_execute(
    mode: str,
    request_id: str,
    argv: list[str],
    *,
    timeout_ms: int = 15_000,
) -> dict[str, Any]:
    request = {
        "protocol": "re-ctm-native-helper-v1",
        "operation": "execute",
        "request_id": request_id,
        "workspace": str(ROOT),
        "forbidden_paths": [str(Path.home() / ".ssh"), str(Path.home() / ".mtm" / "private")],
        "mode": mode,
        "argv": argv,
        "workdir": ".",
        "timeout_ms": timeout_ms,
        "host_path": "/usr/bin:/bin",
        "extra_read_roots": [],
    }
    completed = subprocess.run(
        [str(HELPER)],
        cwd=ROOT,
        input=json.dumps(request, sort_keys=True, separators=(",", ":")),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=helper_environment(),
        check=False,
        timeout=max(30, timeout_ms // 1000 + 15),
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"helper process failed for {request_id}: rc={completed.returncode}: "
            f"{completed.stderr[-1000:]}"
        )
    try:
        response = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"helper returned invalid JSON for {request_id}: {exc}") from exc
    if response.get("ok") is not True:
        raise RuntimeError(f"helper request failed for {request_id}: {response}")
    return response


def parse_assignments(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key:
            values[key] = value
    return values


def host_resolver() -> dict[str, Any]:
    resolv = Path("/etc/resolv.conf")
    is_symlink = resolv.is_symlink()
    target = resolv.resolve(strict=True)
    trusted = any(target.is_relative_to(root) for root in TRUSTED_RESOLVER_ROOTS)
    return {
        "path": str(resolv),
        "is_symlink": is_symlink,
        "target": str(target),
        "target_is_file": target.is_file(),
        "target_trusted_runtime_resolver": trusted,
    }


def allowed_runtime_entries(resolver: dict[str, Any]) -> set[str]:
    target = Path(str(resolver["target"]))
    if not resolver["is_symlink"] or not target.is_relative_to(Path("/run")):
        return set()
    allowed: set[str] = set()
    current = target
    while current != Path("/run"):
        allowed.add(str(current))
        current = current.parent
    return allowed


def networked_dns_check(mode: str, resolver: dict[str, Any]) -> dict[str, Any]:
    script = r'''
set +e
resolved=$(readlink -f /etc/resolv.conf 2>/dev/null)
getent ahostsv4 example.com >/tmp/mtm010-getent 2>/dev/null
getent_rc=$?
getent_first=$(head -1 /tmp/mtm010-getent | awk '{print $1}')
http_code=$(curl -sS --connect-timeout 4 --max-time 8 -o /dev/null -w '%{http_code}' https://example.com/ 2>/tmp/mtm010-curl.err)
curl_rc=$?
printf 'RESOLVED=%s\nGETENT_RC=%s\nGETENT_FIRST=%s\nCURL_RC=%s\nHTTP_CODE=%s\n' "$resolved" "$getent_rc" "$getent_first" "$curl_rc" "$http_code"
'''
    response = helper_execute(mode, f"mtm010-{mode}-dns", ["/bin/sh", "-lc", script])
    values = parse_assignments(str(response.get("stdout") or ""))
    attestation = response.get("attestation") or {}
    passed = (
        response.get("exit_code") == 0
        and attestation.get("network_isolated") is False
        and values.get("RESOLVED") == resolver["target"]
        and values.get("GETENT_RC") == "0"
        and bool(values.get("GETENT_FIRST"))
        and values.get("CURL_RC") == "0"
        and values.get("HTTP_CODE") == "200"
    )
    return {
        "name": f"{mode}_dns_and_https",
        "passed": passed,
        "network_isolated": attestation.get("network_isolated"),
        "resolver_target": values.get("RESOLVED", ""),
        "getent_rc": int(values.get("GETENT_RC", "-1")),
        "getent_returned_address": bool(values.get("GETENT_FIRST")),
        "curl_rc": int(values.get("CURL_RC", "-1")),
        "http_code": values.get("HTTP_CODE", ""),
    }


def safe_network_check() -> dict[str, Any]:
    script = r'''
set +e
getent ahostsv4 example.com >/dev/null 2>&1
getent_rc=$?
curl -sS --connect-timeout 2 --max-time 3 -o /dev/null https://example.com/ >/dev/null 2>&1
curl_rc=$?
printf 'GETENT_RC=%s\nCURL_RC=%s\n' "$getent_rc" "$curl_rc"
'''
    response = helper_execute("safe", "mtm010-safe-network", ["/bin/sh", "-lc", script], timeout_ms=8_000)
    values = parse_assignments(str(response.get("stdout") or ""))
    attestation = response.get("attestation") or {}
    curl_rc = int(values.get("CURL_RC", "0"))
    return {
        "name": "safe_mode_network_isolation",
        "passed": response.get("exit_code") == 0
        and attestation.get("network_isolated") is True
        and curl_rc != 0,
        "network_isolated": attestation.get("network_isolated"),
        "getent_rc": int(values.get("GETENT_RC", "-1")),
        "curl_rc": curl_rc,
    }


def boundary_check(resolver: dict[str, Any]) -> dict[str, Any]:
    script = r'''
set +e
find /run -mindepth 1 -maxdepth 5 -print 2>/dev/null | sort | sed 's/^/RUN_ENTRY=/'
for path in /run/systemd/system /run/dbus/system_bus_socket /run/secrets /home/lk/.ssh /home/lk/.config /root/.ssh; do
  if [ -e "$path" ]; then printf 'VISIBLE=%s\n' "$path"; fi
done
'''
    response = helper_execute("dangerous", "mtm010-boundary", ["/bin/sh", "-lc", script])
    entries: set[str] = set()
    visible: set[str] = set()
    for line in str(response.get("stdout") or "").splitlines():
        if line.startswith("RUN_ENTRY="):
            entries.add(line.removeprefix("RUN_ENTRY="))
        elif line.startswith("VISIBLE="):
            visible.add(line.removeprefix("VISIBLE="))
    allowed = allowed_runtime_entries(resolver)
    unexpected = sorted(entries - allowed)
    missing = sorted(allowed - entries)
    return {
        "name": "resolver_mount_boundary",
        "passed": response.get("exit_code") == 0 and not unexpected and not missing and not visible,
        "allowed_run_entries": sorted(allowed),
        "observed_run_entries": sorted(entries),
        "unexpected_run_entries": unexpected,
        "missing_expected_run_entries": missing,
        "sensitive_paths_visible": sorted(visible),
    }


def web_case(
    name: str,
    url: str,
    timeout: int,
    expected_rc: int,
    expected_http: str,
    expected_redirects: int | None,
    expected_ssl: str | None,
) -> dict[str, Any]:
    write_format = (
        "%{http_code}|%{size_download}|%{time_total}|%{num_redirects}|"
        "%{url_effective}|%{remote_ip}|%{ssl_verify_result}"
    )
    argv = [
        "/usr/bin/curl",
        "-L",
        "--compressed",
        "-sS",
        "--connect-timeout",
        "4",
        "--max-time",
        str(timeout),
        "-o",
        "/dev/null",
        "-w",
        write_format,
        url,
    ]
    if any(item in {"--resolve", "--dns-servers", "--doh-url"} for item in argv):
        raise RuntimeError("MTM-010 web corpus must not use a resolver workaround")
    response = helper_execute(
        "dangerous",
        f"mtm010-web-{name}",
        argv,
        timeout_ms=(timeout + 5) * 1000,
    )
    fields = str(response.get("stdout") or "").split("|", 6)
    if len(fields) != 7:
        raise RuntimeError(f"unexpected curl metrics for {name}: {response.get('stdout')!r}")
    http_code, size_download, time_total, redirects, effective_url, remote_ip, ssl_result = fields
    curl_rc = int(response.get("exit_code") if response.get("exit_code") is not None else -1)
    passed = curl_rc == expected_rc and http_code == expected_http
    if expected_redirects is not None:
        passed = passed and int(redirects) == expected_redirects
    if expected_ssl is not None:
        passed = passed and ssl_result == expected_ssl
    if name == "slow_2s":
        passed = passed and float(time_total) >= 1.5
    return {
        "name": name,
        "url": url,
        "passed": passed,
        "curl_rc": curl_rc,
        "http_code": http_code,
        "size_download": int(float(size_download)),
        "time_total_seconds": float(time_total),
        "redirects": int(redirects),
        "effective_url": effective_url,
        "remote_ip_present": bool(remote_ip),
        "ssl_verify_result": ssl_result,
        "resolver_workaround": False,
        "stderr_prefix": str(response.get("stderr") or "")[:180],
    }


def helper_process_count() -> int:
    helper = HELPER.resolve()
    count = 0
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if (entry / "exe").resolve(strict=True) == helper:
                count += 1
        except (FileNotFoundError, PermissionError, OSError):
            continue
    return count


def proc_entry_count(path: Path) -> int:
    try:
        return sum(1 for _ in path.iterdir())
    except OSError:
        return -1


def resource_non_regression_check() -> dict[str, Any]:
    before = {
        "fds": proc_entry_count(Path("/proc/self/fd")),
        "threads": proc_entry_count(Path("/proc/self/task")),
        "helpers": helper_process_count(),
    }
    repetitions = 20
    for index in range(repetitions):
        helper_execute(
            "dangerous",
            f"mtm010-resource-{index + 1}",
            ["/bin/true"],
            timeout_ms=5_000,
        )
    after = {
        "fds": proc_entry_count(Path("/proc/self/fd")),
        "threads": proc_entry_count(Path("/proc/self/task")),
        "helpers": helper_process_count(),
    }
    fd_delta = after["fds"] - before["fds"] if min(before["fds"], after["fds"]) >= 0 else None
    thread_delta = (
        after["threads"] - before["threads"]
        if min(before["threads"], after["threads"]) >= 0
        else None
    )
    helper_delta = after["helpers"] - before["helpers"]
    passed = (
        before["helpers"] == 0
        and after["helpers"] == 0
        and fd_delta is not None
        and fd_delta <= 1
        and thread_delta == 0
    )
    return {
        "name": "resource_non_regression",
        "passed": passed,
        "repetitions": repetitions,
        "before": before,
        "after": after,
        "fd_delta": fd_delta,
        "thread_delta": thread_delta,
        "helper_delta": helper_delta,
        "performance_claim": False,
    }


def main() -> int:
    build_helper()
    resolver = host_resolver()
    checks = [
        {
            "name": "host_resolver_shape",
            "passed": resolver["target_is_file"]
            and (not resolver["is_symlink"] or resolver["target_trusted_runtime_resolver"]),
            "details": resolver,
        },
        networked_dns_check("trusted", resolver),
        networked_dns_check("dangerous", resolver),
        safe_network_check(),
        boundary_check(resolver),
        resource_non_regression_check(),
    ]
    web_cases = [web_case(*case) for case in WEB_CASES]
    persistent_helpers = helper_process_count()
    checks.append(
        {
            "name": "no_persistent_helper_process",
            "passed": persistent_helpers == 0,
            "helper_process_count": persistent_helpers,
        }
    )
    all_passed = all(bool(check["passed"]) for check in checks) and all(
        bool(case["passed"]) for case in web_cases
    )
    report = {
        "schema_version": "1.0.0",
        "milestone": "MTM-010",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "baseline_commit": "67a28e24ed5f40ed5ab369bda3d50d26f308ea62",
        "implementation_sha256": implementation_sha256(),
        "helper_sha256": sha256_file(HELPER),
        "host_resolver": resolver,
        "checks": checks,
        "web_cases": web_cases,
        "summary": {
            "all_passed": all_passed,
            "check_count": len(checks),
            "web_case_count": len(web_cases),
            "resolver_workaround_used": False,
            "broad_run_mount_allowed": False,
            "safe_network_isolation_required": True,
        },
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"ok": all_passed, "report": str(REPORT)}, indent=2))
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
