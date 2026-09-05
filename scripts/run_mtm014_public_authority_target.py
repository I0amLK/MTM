#!/usr/bin/env python3
"""Run post-cutover public OAuth/MCP A4 for MTM-014 Native permission authority."""
from __future__ import annotations

import hashlib
import json
import os
import signal
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from mtm008_runtime_harness import (  # noqa: E402
    free_port,
    json_request,
    oauth_token,
    runtime_environment,
    wait_for_port,
)
from run_mtm014_mrtr_permission_validation import (  # noqa: E402
    consent_response,
    input_required,
    modern_tool_call,
    result,
    structured,
)


BINARY = Path(os.environ.get("MTM014_BINARY", ROOT / "target/debug/mtm"))
IMPLEMENTATION_COMMIT = "2f11750c07317d879f1bedfd2198c36786b8ca74"
D5A_EVIDENCE = ROOT / "records/evidence/MTM-014/elicitation-capability.json"
PRE_TARGET_EVIDENCE = ROOT / "records/evidence/MTM-014/native-permission-target.json"
STABLE_EVIDENCE = ROOT / "records/evidence/MTM-013/stable-release.json"
STABLE_CARGO = Path("/home/lk/.cargo/bin/mtm")
STABLE_SELECTOR = Path("/home/lk/.local/bin/mtm")
MODERN_VERSION = "2026-07-28"
CAPABILITIES = {"elicitation": {}}


class PublicTargetFailure(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fail(name: str) -> None:
    raise PublicTargetFailure(name)


def close_process(process: subprocess.Popen[str]) -> int:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        return process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        return process.wait(timeout=3)


def git_text(*arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        fail("git_identity")
    return completed.stdout.strip()


def build_candidate() -> tuple[str, str]:
    completed = subprocess.run(
        ["cargo", "build", "--locked", "-p", "mtm-cli", "--bin", "mtm"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
        check=False,
    )
    if completed.returncode != 0 or not BINARY.is_file():
        fail("candidate_build")
    version = subprocess.run(
        [str(BINARY), "--version"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=30,
        check=False,
    )
    if version.returncode != 0 or version.stdout.strip() != "mtm 0.4.0":
        fail("candidate_version")
    return sha256_file(BINARY), version.stdout.strip()


def validate_source_scope() -> None:
    commands = (
        ["git", "merge-base", "--is-ancestor", IMPLEMENTATION_COMMIT, "HEAD"],
        ["git", "diff", "--quiet", f"{IMPLEMENTATION_COMMIT}..HEAD", "--", "crates"],
        [
            "git",
            "diff",
            "--quiet",
            f"{IMPLEMENTATION_COMMIT}..HEAD",
            "--",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "crates/mtm-cli/assets",
        ],
    )
    for command in commands:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            fail("production_source_drift")


def launch(root: Path, mode: str, *, port: int | None = None) -> tuple[subprocess.Popen[str], int, str]:
    workspace = root / "workspace"
    data_root = root / "data"
    workspace.mkdir(parents=True, exist_ok=True)
    port = free_port() if port is None else port
    environment = runtime_environment(workspace, data_root, "rust")
    environment["MTM_NATIVE_MODE"] = mode
    environment["MTM_NATIVE_EXEC_BACKEND"] = "bubblewrap"
    environment["MTM_LATEX_POLICY"] = "static_only"
    environment["MTM_DEBUG"] = "0"
    environment["MTM_TRACE_PAYLOADS"] = "0"
    process = subprocess.Popen(
        [
            str(BINARY),
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--workspace",
            str(workspace),
            "--native-mode",
            mode,
            "--latex-policy",
            "static_only",
        ],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    wait_for_port(port, process)
    return process, port, f"http://127.0.0.1:{port}"


def rpc_error_code(payload: dict[str, Any]) -> str:
    rpc_result = payload.get("result")
    if isinstance(rpc_result, dict):
        value = rpc_result.get("structuredContent")
        if isinstance(value, dict):
            error = value.get("error")
            if isinstance(error, dict):
                return str(error.get("code") or "")
    error = payload.get("error")
    if isinstance(error, dict):
        data = error.get("data")
        if isinstance(data, dict) and data.get("code"):
            return str(data["code"])
        return str(error.get("code") or "")
    return ""


def assert_permission_required(
    payload: dict[str, Any],
    *,
    tool_name: str,
    permissions: list[str],
) -> None:
    if rpc_error_code(payload) != "PERMISSION_REQUIRED":
        fail(f"{tool_name}_permission_required")
    value = structured(payload)
    details = value.get("error", {}).get("details")
    if not isinstance(details, dict) or set(details) != {"permission", "permissions", "tool_name"}:
        fail(f"{tool_name}_permission_details")
    if details.get("tool_name") != tool_name or details.get("permissions") != permissions:
        fail(f"{tool_name}_permission_details")
    if details.get("permission") != permissions[0]:
        fail(f"{tool_name}_permission_details")


def assert_tool_success(payload: dict[str, Any]) -> dict[str, Any]:
    if result(payload).get("isError") is True:
        fail("public_tool_unexpected_error")
    return structured(payload)


def grant_permission(
    port: int,
    token: str,
    *,
    tool_name: str,
    permission: str,
    arguments: dict[str, Any],
    scope: str = "once",
) -> None:
    request = {
        "tool_name": tool_name,
        "permission": permission,
        "reason": "MTM-014 post-cutover public A4",
        "arguments": arguments,
        "scope": scope,
        "ttl_seconds": 300,
    }
    status, first = modern_tool_call(
        port,
        token,
        "request_permissions",
        request,
        capabilities=CAPABILITIES,
    )
    if status != 200:
        fail("permission_request_http")
    state, _ = input_required(first)
    status, accepted = modern_tool_call(
        port,
        token,
        "request_permissions",
        request,
        capabilities=CAPABILITIES,
        input_responses=consent_response(True),
        request_state=state,
    )
    if status != 200 or structured(accepted).get("status") != "granted":
        fail("permission_request_accept")


def call_tool(port: int, token: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    status, payload = modern_tool_call(
        port,
        token,
        name,
        arguments,
        capabilities=CAPABILITIES,
    )
    if status != 200:
        fail(f"{name}_http")
    return payload


def exercise_once(
    port: int,
    token: str,
    permission: str,
    arguments: dict[str, Any],
    *,
    verify: Callable[[dict[str, Any]], None] | None = None,
) -> None:
    denied = call_tool(port, token, "exec_command", arguments)
    assert_permission_required(denied, tool_name="exec_command", permissions=[permission])
    grant_permission(
        port,
        token,
        tool_name="exec_command",
        permission=permission,
        arguments=arguments,
    )
    value = assert_tool_success(call_tool(port, token, "exec_command", arguments))
    if value.get("status") != "exited" or value.get("exit_code") != 0:
        fail(f"{permission}_execution")
    if verify is not None:
        verify(value)
    replay = call_tool(port, token, "exec_command", arguments)
    assert_permission_required(replay, tool_name="exec_command", permissions=[permission])


def modern_tools_list(port: int, token: str) -> list[dict[str, Any]]:
    params = {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": CAPABILITIES,
            "io.modelcontextprotocol/clientInfo": {
                "name": "mtm014-post-cutover-a4",
                "version": "1",
            },
        }
    }
    status, _, payload = json_request(
        port,
        "POST",
        "/mcp",
        {"jsonrpc": "2.0", "id": "tools-list-a4", "method": "tools/list", "params": params},
        headers={
            "Authorization": f"Bearer {token}",
            "MCP-Protocol-Version": MODERN_VERSION,
            "Mcp-Method": "tools/list",
        },
    )
    if status != 200 or not isinstance(payload.get("result"), dict):
        fail("tools_list")
    tools = payload["result"].get("tools")
    if not isinstance(tools, list):
        fail("tools_list")
    return [item for item in tools if isinstance(item, dict)]


def assert_public_contract(tools: list[dict[str, Any]]) -> None:
    if len(tools) != 24:
        fail("public_tool_count")
    by_name = {str(tool.get("name")): tool for tool in tools}
    for name in ("exec_command", "apply_patch"):
        if name not in by_name:
            fail("public_tool_names")
        schema = by_name[name].get("inputSchema")
        if not isinstance(schema, dict) or "grant_id" in json.dumps(schema, sort_keys=True):
            fail("public_grant_id_schema")
    exec_properties = by_name["exec_command"]["inputSchema"].get("properties", {})
    if "cmd" not in exec_properties:
        fail("public_exec_cmd_schema")


def patch_add(path: str, content: str) -> str:
    return f"*** Begin Patch\n*** Add File: {path}\n+{content}\n*** End Patch\n"


def safe_public_case(root: Path) -> dict[str, bool]:
    process, port, base = launch(root, "safe")
    workspace = root / "workspace"
    try:
        token_a = oauth_token(port, base, "MTM-014 D5B safe A")
        token_b = oauth_token(port, base, "MTM-014 D5B safe B")
        assert_public_contract(modern_tools_list(port, token_a))

        ordinary = assert_tool_success(call_tool(port, token_a, "exec_command", {"cmd": "printf ordinary-public"}))
        if ordinary.get("stdout") != "ordinary-public":
            fail("safe_ordinary_command")

        exercise_once(
            port,
            token_a,
            "inline_script",
            {"cmd": 'sh -c "printf inline-public"', "yield_time_ms": 30_000},
            verify=lambda value: value.get("stdout") == "inline-public" or fail("inline_stdout"),
        )
        exercise_once(
            port,
            token_a,
            "shell_expansion",
            {"cmd": 'printf "$HOME"'},
        )
        exercise_once(
            port,
            token_a,
            "destructive_command",
            {"cmd": "rm -f harmless-public-missing.txt"},
        )
        exercise_once(
            port,
            token_a,
            "long_timeout",
            {"cmd": "printf long-public", "timeout_ms": 30_001},
            verify=lambda value: value.get("stdout") == "long-public" or fail("long_stdout"),
        )
        exercise_once(
            port,
            token_a,
            "sensitive_env",
            {"cmd": "env", "env": {"API_TOKEN": "public-sensitive"}},
            verify=lambda value: "API_TOKEN=public-sensitive" in str(value.get("stdout") or "")
            or fail("sensitive_env_stdout"),
        )
        exercise_once(
            port,
            token_a,
            "network",
            {
                "cmd": "curl --fail --silent --show-error --max-time 15 https://example.com/",
                "yield_time_ms": 30_000,
            },
            verify=lambda value: "Example Domain" in str(value.get("stdout") or "")
            or fail("public_dns_https"),
        )
        privileged = workspace / "privileged-probe"
        shutil.copy2("/bin/true", privileged)
        privileged.chmod(0o4755)
        exercise_once(port, token_a, "privileged_executable", {"cmd": "./privileged-probe"})

        mutation_original = {"cmd": 'sh -c "printf mutation-original"'}
        mutation_changed = {"cmd": 'sh -c "printf mutation-changed"'}
        grant_permission(
            port,
            token_a,
            tool_name="exec_command",
            permission="inline_script",
            arguments=mutation_original,
        )
        assert_permission_required(
            call_tool(port, token_a, "exec_command", mutation_changed),
            tool_name="exec_command",
            permissions=["inline_script"],
        )
        if assert_tool_success(call_tool(port, token_a, "exec_command", mutation_original)).get("stdout") != "mutation-original":
            fail("argument_mutation_preserved_grant")

        cross_owner = {"cmd": 'sh -c "printf owner-a-only"'}
        grant_permission(
            port,
            token_a,
            tool_name="exec_command",
            permission="inline_script",
            arguments=cross_owner,
        )
        assert_permission_required(
            call_tool(port, token_b, "exec_command", cross_owner),
            tool_name="exec_command",
            permissions=["inline_script"],
        )
        if assert_tool_success(call_tool(port, token_a, "exec_command", cross_owner)).get("stdout") != "owner-a-only":
            fail("cross_owner_preserved_grant")

        multi = {"cmd": 'sh -c "printf multi-public"', "timeout_ms": 30_001, "yield_time_ms": 30_000}
        grant_permission(
            port,
            token_a,
            tool_name="exec_command",
            permission="inline_script",
            arguments=multi,
        )
        assert_permission_required(
            call_tool(port, token_a, "exec_command", multi),
            tool_name="exec_command",
            permissions=["long_timeout"],
        )
        grant_permission(
            port,
            token_a,
            tool_name="exec_command",
            permission="long_timeout",
            arguments=multi,
        )
        if assert_tool_success(call_tool(port, token_a, "exec_command", multi)).get("stdout") != "multi-public":
            fail("multi_risk_all_or_none")

        concurrent = {"cmd": 'sh -c "printf concurrent-public"', "timeout_ms": 30_002, "yield_time_ms": 30_000}
        for permission in ("inline_script", "long_timeout"):
            grant_permission(
                port,
                token_a,
                tool_name="exec_command",
                permission=permission,
                arguments=concurrent,
            )
        replies: list[dict[str, Any]] = []
        barrier = threading.Barrier(2)

        def concurrent_call() -> None:
            barrier.wait()
            replies.append(call_tool(port, token_a, "exec_command", concurrent))

        threads = [threading.Thread(target=concurrent_call) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        if len(replies) != 2:
            fail("multi_risk_concurrency")
        winners = sum(result(reply).get("isError") is not True for reply in replies)
        losers = sum(rpc_error_code(reply) == "PERMISSION_REQUIRED" for reply in replies)
        if winners != 1 or losers != 1:
            fail("multi_risk_concurrency")

        tty = call_tool(
            port,
            token_a,
            "exec_command",
            {"cmd": "cat", "tty": True, "yield_time_ms": 0, "timeout_ms": 10_000},
        )
        tty_value = assert_tool_success(tty)
        command_id = tty_value.get("command_id")
        if tty_value.get("status") != "running" or not isinstance(command_id, str):
            fail("public_tty_start")
        tty_reply = assert_tool_success(
            call_tool(
                port,
                token_a,
                "write_stdin",
                {"command_id": command_id, "chars": "public-stdin-round-trip\n", "yield_time_ms": 1_000},
            )
        )
        if "public-stdin-round-trip" not in str(tty_reply.get("stdout") or ""):
            fail("public_tty_stdin")
        assert_tool_success(
            call_tool(
                port,
                token_a,
                "kill_command",
                {"command_id": command_id, "signal": "TERM", "wait_ms": 5_000},
            )
        )

        spawn = workspace / "spawn-descendant.sh"
        spawn.write_text(
            "#!/bin/sh\n(sleep 1; printf leaked > descendant-leak.txt) &\nprintf ready\nwait\n",
            encoding="utf-8",
        )
        spawn.chmod(0o755)
        child = assert_tool_success(
            call_tool(
                port,
                token_a,
                "exec_command",
                {"cmd": "./spawn-descendant.sh", "yield_time_ms": 100, "timeout_ms": 10_000},
            )
        )
        child_id = child.get("command_id")
        if child.get("status") != "running" or not isinstance(child_id, str):
            fail("public_descendant_start")
        assert_tool_success(
            call_tool(
                port,
                token_a,
                "kill_command",
                {"command_id": child_id, "signal": "TERM", "wait_ms": 5_000},
            )
        )
        time.sleep(1.3)
        if (workspace / "descendant-leak.txt").exists():
            fail("public_descendant_cleanup")

        subprocess.run(["git", "-C", str(workspace), "init", "-q"], check=True)
        (workspace / ".gitignore").write_text("ignored-*.txt\n", encoding="utf-8")
        normal = {"patch": patch_add("normal-public.txt", "normal"), "dry_run": False}
        assert_tool_success(call_tool(port, token_a, "apply_patch", normal))
        if (workspace / "normal-public.txt").read_text(encoding="utf-8") != "normal\n":
            fail("public_normal_patch")
        dry = {"patch": patch_add("ignored-dry.txt", "dry"), "dry_run": True}
        dry_value = assert_tool_success(call_tool(port, token_a, "apply_patch", dry))
        if dry_value.get("dry_run") is not True or (workspace / "ignored-dry.txt").exists():
            fail("public_ignored_dry_run")

        ignored_original = {"patch": patch_add("ignored-original.txt", "approved"), "dry_run": False}
        ignored_mutated = {"patch": patch_add("ignored-mutated.txt", "mutated"), "dry_run": False}
        assert_permission_required(
            call_tool(port, token_a, "apply_patch", ignored_original),
            tool_name="apply_patch",
            permissions=["write_generated_or_ignored"],
        )
        if (workspace / "ignored-original.txt").exists():
            fail("public_ignored_patch_pregrant_write")
        grant_permission(
            port,
            token_a,
            tool_name="apply_patch",
            permission="write_generated_or_ignored",
            arguments=ignored_original,
        )
        assert_permission_required(
            call_tool(port, token_a, "apply_patch", ignored_mutated),
            tool_name="apply_patch",
            permissions=["write_generated_or_ignored"],
        )
        assert_tool_success(call_tool(port, token_a, "apply_patch", ignored_original))
        if (workspace / "ignored-original.txt").read_text(encoding="utf-8") != "approved\n":
            fail("public_ignored_patch_commit")
        if (workspace / "ignored-mutated.txt").exists():
            fail("public_patch_mutation_write")

        outside = root / "outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        (workspace / "link.txt").symlink_to(outside)
        symlink_patch = {
            "patch": "*** Begin Patch\n*** Update File: link.txt\n@@\n-outside\n+changed\n*** End Patch\n",
            "dry_run": False,
        }
        symlink_result = call_tool(port, token_a, "apply_patch", symlink_patch)
        if result(symlink_result).get("isError") is not True or outside.read_text(encoding="utf-8") != "outside\n":
            fail("public_patch_symlink")
        escape = {"patch": patch_add("../escape.txt", "escape"), "dry_run": False}
        escape_result = call_tool(port, token_a, "apply_patch", escape)
        if result(escape_result).get("isError") is not True or (root / "escape.txt").exists():
            fail("public_patch_escape")

        session_args = {"cmd": 'sh -c "printf session-public"'}
        grant_permission(
            port,
            token_a,
            tool_name="exec_command",
            permission="inline_script",
            arguments=session_args,
            scope="session",
        )
        for _ in range(2):
            if assert_tool_success(call_tool(port, token_a, "exec_command", session_args)).get("stdout") != "session-public":
                fail("public_session_reuse")

        selected_port = port
        if close_process(process) != 0:
            fail("safe_server_shutdown")
        process, port, _ = launch(root, "safe", port=selected_port)
        if port != selected_port:
            fail("safe_restart_port")
        assert_permission_required(
            call_tool(port, token_a, "exec_command", session_args),
            tool_name="exec_command",
            permissions=["inline_script"],
        )
        return {
            "tool_contract": True,
            "all_seven_exec_permissions": True,
            "once_replay": True,
            "argument_mutation": True,
            "cross_owner": True,
            "multi_risk_atomicity": True,
            "concurrent_one_winner": True,
            "real_dns_https": True,
            "tty_stdin_kill": True,
            "descendant_cleanup": True,
            "patch_normal_dry_ignored_mutation": True,
            "patch_symlink_escape": True,
            "session_reuse_restart_invalidation": True,
        }
    finally:
        if process.poll() is None and close_process(process) != 0:
            fail("safe_server_shutdown")


def trusted_public_case(root: Path) -> dict[str, bool]:
    process, port, base = launch(root, "trusted")
    workspace = root / "workspace"
    try:
        token = oauth_token(port, base, "MTM-014 D5B trusted")
        for arguments in (
            {"cmd": 'sh -c "printf trusted-inline"'},
            {"cmd": 'printf "$HOME"'},
            {"cmd": "curl --fail --silent --show-error --max-time 15 https://example.com/", "yield_time_ms": 30_000},
        ):
            value = assert_tool_success(call_tool(port, token, "exec_command", arguments))
            if value.get("status") != "exited" or value.get("exit_code") != 0:
                fail("trusted_implicit_profile")
        gated = (
            ({"cmd": "env", "env": {"API_TOKEN": "trusted-secret"}}, ["sensitive_env"]),
            ({"cmd": "rm -f trusted-missing.txt"}, ["destructive_command"]),
            ({"cmd": "printf trusted-long", "timeout_ms": 30_001}, ["long_timeout"]),
        )
        for arguments, permissions in gated:
            assert_permission_required(
                call_tool(port, token, "exec_command", arguments),
                tool_name="exec_command",
                permissions=permissions,
            )
        privileged = workspace / "trusted-privileged"
        shutil.copy2("/bin/true", privileged)
        privileged.chmod(0o4755)
        assert_permission_required(
            call_tool(port, token, "exec_command", {"cmd": "./trusted-privileged"}),
            tool_name="exec_command",
            permissions=["privileged_executable"],
        )
        (workspace / "build").mkdir()
        generated = {"patch": patch_add("build/trusted-generated.txt", "generated"), "dry_run": False}
        assert_permission_required(
            call_tool(port, token, "apply_patch", generated),
            tool_name="apply_patch",
            permissions=["write_generated_or_ignored"],
        )
        return {"implicit_profile": True, "explicit_boundaries": True, "generated_patch_gated": True}
    finally:
        if close_process(process) != 0:
            fail("trusted_server_shutdown")


def classify_magma_public(value: dict[str, Any]) -> str:
    text = f"{value.get('stdout') or ''}\n{value.get('stderr') or ''}".lower()
    if value.get("status") == "exited" and value.get("exit_code") == 0:
        return "passed"
    if "not authorised" in text or "not authorized" in text:
        return "blocked_host_license"
    fail("public_magma_classification")
    return "unreachable"


def dangerous_public_case(root: Path) -> tuple[dict[str, bool], str]:
    process, port, base = launch(root, "dangerous")
    workspace = root / "workspace"
    try:
        token = oauth_token(port, base, "MTM-014 D5B dangerous")
        combined = assert_tool_success(
            call_tool(
                port,
                token,
                "exec_command",
                {
                    "cmd": 'printf "$API_TOKEN"',
                    "env": {"API_TOKEN": "dangerous-value"},
                    "timeout_ms": 30_001,
                    "yield_time_ms": 30_000,
                },
            )
        )
        if combined.get("stdout") != "dangerous-value":
            fail("dangerous_complete_profile")
        for command in (
            'sh -c "printf dangerous-inline"',
            "rm -f dangerous-missing.txt",
            "curl --fail --silent --show-error --max-time 15 https://example.com/",
            "git --version",
            "pdflatex --version",
            "latexmk -version",
            "sage --version",
        ):
            value = assert_tool_success(
                call_tool(port, token, "exec_command", {"cmd": command, "yield_time_ms": 30_000})
            )
            if value.get("status") != "exited" or value.get("exit_code") != 0:
                fail("dangerous_toolchain_profile")
        privileged = workspace / "dangerous-privileged"
        shutil.copy2("/bin/true", privileged)
        privileged.chmod(0o4755)
        assert_tool_success(call_tool(port, token, "exec_command", {"cmd": "./dangerous-privileged"}))

        (workspace / "build").mkdir()
        generated = {"patch": patch_add("build/dangerous-generated.txt", "generated"), "dry_run": False}
        assert_tool_success(call_tool(port, token, "apply_patch", generated))
        if not (workspace / "build/dangerous-generated.txt").is_file():
            fail("dangerous_generated_patch")

        permission_request = {
            "tool_name": "exec_command",
            "permission": "inline_script",
            "reason": "D5B dangerous non-inheritance",
            "arguments": {"cmd": 'sh -c "printf dangerous-permission"'},
            "scope": "once",
            "ttl_seconds": 300,
        }
        _, permission_reply = modern_tool_call(
            port,
            token,
            "request_permissions",
            permission_request,
            capabilities=CAPABILITIES,
        )
        permission_value = structured(permission_reply)
        if permission_value.get("constraints", {}).get("workflow_authority_inherited") is not False:
            fail("dangerous_workflow_non_inheritance")

        magma = assert_tool_success(
            call_tool(
                port,
                token,
                "exec_command",
                {"cmd": "magma -b", "stdin": "quit;\n", "timeout_ms": 10_000, "yield_time_ms": 30_000},
            )
        )
        magma_status = classify_magma_public(magma)
        return {
            "complete_implicit_profile": True,
            "real_network": True,
            "privileged_no_grant": True,
            "generated_patch_no_grant": True,
            "git_latex_sage": True,
            "workflow_non_inheritance": True,
        }, magma_status
    finally:
        if close_process(process) != 0:
            fail("dangerous_server_shutdown")


def attest_mode(mode: str) -> bool:
    with tempfile.TemporaryDirectory(prefix=f"mtm014-post-attest-{mode}-") as temporary:
        root = Path(temporary)
        workspace = root / "workspace"
        workspace.mkdir()
        environment = runtime_environment(workspace, root / "data", "rust")
        environment["MTM_NATIVE_EXEC_BACKEND"] = "bubblewrap"
        environment["MTM_NATIVE_MODE"] = mode
        completed = subprocess.run(
            [str(BINARY), "attest-native", "--workspace", str(workspace), "--native-mode", mode],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
        if completed.returncode != 0:
            fail(f"{mode}_attestation")
        try:
            payload = json.loads(completed.stdout)
            attestation = payload["attestation"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise PublicTargetFailure(f"{mode}_attestation") from exc
        expected = {
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
        if any(attestation.get(key) is not value for key, value in expected.items()):
            fail(f"{mode}_attestation")
        return True


def main() -> int:
    try:
        if git_text("status", "--porcelain"):
            fail("clean_tree_required")
        if git_text("rev-parse", "HEAD") == IMPLEMENTATION_COMMIT:
            fail("qualification_runner_not_committed")
        validate_source_scope()
        binary_sha256, version = build_candidate()

        d5a = json.loads(D5A_EVIDENCE.read_text(encoding="utf-8"))
        pre_target = json.loads(PRE_TARGET_EVIDENCE.read_text(encoding="utf-8"))
        stable = json.loads(STABLE_EVIDENCE.read_text(encoding="utf-8"))
        if d5a.get("d5a_accepted") is not True or pre_target.get("pre_cutover_target_corpus_passed") is not True:
            fail("accepted_preconditions")
        stable_sha = str(stable.get("binary_sha256") or "")
        if sha256_file(STABLE_CARGO) != stable_sha or sha256_file(STABLE_SELECTOR) != stable_sha:
            fail("stable_selector_changed")

        required_tools = {
            name: shutil.which(name) is not None
            for name in ("bwrap", "curl", "git", "pdflatex", "latexmk", "sage", "magma")
        }
        if not all(required_tools.values()):
            fail("required_tools")

        with tempfile.TemporaryDirectory(prefix="mtm014-post-cutover-a4-") as temporary:
            base = Path(temporary)
            safe = safe_public_case(base / "safe")
            trusted = trusted_public_case(base / "trusted")
            dangerous, magma_status = dangerous_public_case(base / "dangerous")
        attestations = {mode: attest_mode(mode) for mode in ("safe", "trusted", "dangerous")}

        checks = {
            "exact_committed_source": True,
            "candidate_build": True,
            "stable_selectors_unchanged": True,
            "required_tools_available": True,
            "public_tool_contract": safe["tool_contract"],
            "safe_all_seven_exec_permissions": safe["all_seven_exec_permissions"],
            "safe_once_replay": safe["once_replay"],
            "safe_argument_mutation": safe["argument_mutation"],
            "safe_cross_owner": safe["cross_owner"],
            "safe_multi_risk_atomicity": safe["multi_risk_atomicity"],
            "safe_concurrent_one_winner": safe["concurrent_one_winner"],
            "safe_real_dns_https": safe["real_dns_https"],
            "safe_tty_stdin_kill": safe["tty_stdin_kill"],
            "safe_descendant_cleanup": safe["descendant_cleanup"],
            "safe_patch_authority": safe["patch_normal_dry_ignored_mutation"],
            "safe_patch_symlink_escape": safe["patch_symlink_escape"],
            "safe_session_restart": safe["session_reuse_restart_invalidation"],
            "trusted_implicit_profile": trusted["implicit_profile"],
            "trusted_explicit_boundaries": trusted["explicit_boundaries"],
            "trusted_generated_patch_gated": trusted["generated_patch_gated"],
            "dangerous_complete_profile": dangerous["complete_implicit_profile"],
            "dangerous_real_network": dangerous["real_network"],
            "dangerous_privileged": dangerous["privileged_no_grant"],
            "dangerous_generated_patch": dangerous["generated_patch_no_grant"],
            "dangerous_git_latex_sage": dangerous["git_latex_sage"],
            "dangerous_workflow_non_inheritance": dangerous["workflow_non_inheritance"],
            "safe_attestation": attestations["safe"],
            "trusted_attestation": attestations["trusted"],
            "dangerous_attestation": attestations["dangerous"],
            "magma_host_status_classified": magma_status in {"passed", "blocked_host_license"},
        }
        report = {
            "schema_version": "1.0.0",
            "milestone": "MTM-014",
            "phase": "post_cutover_public_native_permission_target",
            "ok": all(checks.values()),
            "qualification_commit": git_text("rev-parse", "HEAD"),
            "implementation_commit": IMPLEMENTATION_COMMIT,
            "candidate_binary_sha256": binary_sha256,
            "candidate_version": version,
            "runner_sha256": sha256_file(Path(__file__)),
            "d5a_evidence_sha256": sha256_file(D5A_EVIDENCE),
            "pre_cutover_target_evidence_sha256": sha256_file(PRE_TARGET_EVIDENCE),
            "check_count": len(checks),
            "checks": dict(sorted(checks.items())),
            "required_tools": required_tools,
            "magma_host_status": magma_status,
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
    except (OSError, KeyError, TypeError, ValueError, PublicTargetFailure, subprocess.SubprocessError) as exc:
        failed = str(exc) if isinstance(exc, PublicTargetFailure) else "post_cutover_target_internal"
        print(json.dumps({"ok": False, "failed_check": failed}, indent=2, sort_keys=True))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
