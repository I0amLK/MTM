#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "../Re-CTM").resolve()
sys.path.insert(0, str(SOURCE / "src"))

from re_ctm.enums import NativeMode  # noqa: E402
from re_ctm.errors import ReCTMError  # noqa: E402
from re_ctm.native_helper_bwrap import _bubblewrap_command  # noqa: E402
from re_ctm.processes import CommandManager  # noqa: E402
from re_ctm.toolchains import build_toolchain_exposure_plan  # noqa: E402


class Runtime:
    def __init__(self) -> None:
        self.manager = CommandManager()

    def close(self) -> None:
        self.manager.close()

    def evaluate(self, request: dict[str, Any]) -> dict[str, Any]:
        operation = request.get("operation")
        payload = request.get("payload") or {}
        if operation == "process_start":
            return self.manager.start(
                list(payload["argv"]),
                env={str(key): str(value) for key, value in payload.get("env", {}).items()},
                timeout_ms=int(payload.get("timeout_ms", 30_000)),
                yield_time_ms=int(payload.get("yield_time_ms", 10_000)),
                max_output_bytes=int(payload.get("max_output_bytes", 65_536)),
                stdin_text=str(payload.get("stdin", "")),
                tty=bool(payload.get("tty", False)),
                verbosity=payload.get("verbosity"),
                preview_bytes=int(payload.get("preview_bytes", 4096)),
            )
        if operation == "process_poll":
            return self.manager.poll(
                str(payload["command_id"]),
                chars=str(payload.get("chars", "")),
                yield_time_ms=int(payload.get("yield_time_ms", 10_000)),
                max_output_bytes=int(payload.get("max_output_bytes", 65_536)),
                verbosity=payload.get("verbosity"),
                preview_bytes=int(payload.get("preview_bytes", 4096)),
            )
        if operation == "process_kill":
            return self.manager.kill(
                str(payload["command_id"]),
                signal_name=str(payload.get("signal", "TERM")),
                wait_ms=int(payload.get("wait_ms", 5000)),
                kill_wait_ms=int(payload.get("kill_wait_ms", 2000)),
                max_output_bytes=int(payload.get("max_output_bytes", 65_536)),
                verbosity=payload.get("verbosity"),
                preview_bytes=int(payload.get("preview_bytes", 4096)),
            )
        if operation == "process_read":
            return self.manager.read_output(
                str(payload["output_ref"]),
                stream=str(payload["stream"]) if payload.get("stream") is not None else None,
                offset=int(payload.get("offset", 0)),
                limit=int(payload.get("limit", 4096)),
            )
        if operation == "process_close":
            self.manager.close()
            return {"closed": True}
        if operation == "toolchain_plan":
            mode = NativeMode(str(payload["mode"]))
            plan = build_toolchain_exposure_plan(
                mode=mode,
                workspace=Path(payload["workspace"]),
                forbidden_paths=tuple(Path(value) for value in payload.get("forbidden_paths", [])),
                explicit_roots=tuple(Path(value) for value in payload.get("explicit_roots", [])),
                host_path=payload.get("host_path"),
            )
            return {
                "mode": plan.mode.value,
                "sandbox_path": plan.sandbox_path,
                "host_path_inherited": plan.host_path_inherited,
                "auto_discovery_enabled": plan.auto_discovery_enabled,
                "explicit_roots": [str(path) for path in plan.explicit_roots],
                "discovered_roots": [str(path) for path in plan.discovered_roots],
                "read_only_roots": [str(path) for path in plan.read_only_roots],
            }
        if operation == "bubblewrap_command":
            return {
                "command": _bubblewrap_command(
                    workspace=Path(payload["workspace"]),
                    workdir=str(payload.get("workdir", ".")),
                    mode=str(payload["mode"]),
                    argv=[str(value) for value in payload["argv"]],
                    extra_env={str(key): str(value) for key, value in payload.get("extra_env", {}).items()},
                    host_path=payload.get("host_path"),
                    extra_read_roots=tuple(Path(value) for value in payload.get("extra_read_roots", [])),
                    forbidden_paths=tuple(Path(value) for value in payload.get("forbidden_paths", [])),
                )
            }
        raise ReCTMError(
            "INVALID_ARGUMENT",
            "unsupported shadow operation",
            category="validation",
        )


def main() -> int:
    runtime = Runtime()
    try:
        for line in sys.stdin:
            if not line.strip():
                continue
            try:
                request = json.loads(line)
                result = runtime.evaluate(request)
                response = {"ok": True, "result": result}
            except ReCTMError as exc:
                response = {"ok": False, "error": exc.to_payload()}
            except Exception as exc:  # noqa: BLE001 - reference boundary must stay structured
                response = {
                    "ok": False,
                    "error": {
                        "code": "PYTHON_REFERENCE_INTERNAL_ERROR",
                        "message": str(exc),
                        "category": "internal",
                        "retryable": False,
                        "details": {"exception_type": type(exc).__name__},
                    },
                }
            print(json.dumps(response, ensure_ascii=False, sort_keys=True), flush=True)
    finally:
        runtime.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
