#!/usr/bin/env python3
from __future__ import annotations

import json
import sqlite3
import sys
from collections import deque
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / ".." / "Re-CTM" / "src").resolve()
sys.path.insert(0, str(SOURCE))

from python_storage_shadow import database_snapshot  # noqa: E402
from re_ctm.capabilities import CapabilityAuthority  # noqa: E402
from re_ctm.errors import ReCTMError  # noqa: E402
from re_ctm.latex import LatexValidationResult  # noqa: E402
from re_ctm.storage import StateStore  # noqa: E402
from re_ctm.vault import PrivateVault  # noqa: E402
from re_ctm.workflow import WorkflowEngine  # noqa: E402


class NullDebug:
    def emit(self, *_args: Any, **kwargs: Any) -> str:
        return str(kwargs.get("trace_id") or "trace")

    def write_last_error(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def write_state_snapshot(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class SequenceLatexGate:
    def __init__(self, values: list[dict[str, Any]]) -> None:
        self.values = deque(values)

    def validate(self, _content: str, _workdir: Path) -> LatexValidationResult:
        if not self.values:
            raise RuntimeError("latex result queue exhausted")
        return LatexValidationResult(**self.values.popleft())


class Context:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.now_iso = str(payload["now_iso"])
        self.unix_seconds = int(payload["unix_seconds"])
        self.hex_ids = deque(str(item) for item in payload["hex_ids"])
        self.urlsafe_ids = deque(str(item) for item in payload["urlsafe_ids"])
        self.patchers = [
            mock.patch("secrets.token_hex", side_effect=self.next_hex),
            mock.patch("secrets.token_urlsafe", side_effect=self.next_urlsafe),
            mock.patch("re_ctm.storage.utc_now", return_value=self.now_iso),
            mock.patch("re_ctm.workflow.utc_now", return_value=self.now_iso),
            mock.patch("re_ctm.capabilities.time.time", return_value=self.unix_seconds),
        ]
        for patcher in self.patchers:
            patcher.start()
        self.database = Path(payload["database"])
        self.private_root = Path(payload["private_root"])
        self.store = StateStore(self.database)
        self.vault = PrivateVault(self.private_root)
        self.capabilities = CapabilityAuthority(
            bytes.fromhex(str(payload["capability_secret_hex"])),
            self.store,
            NullDebug(),
            default_ttl_seconds=600,
        )
        self.engine = WorkflowEngine(
            self.store,
            self.vault,
            self.capabilities,
            NullDebug(),
            SequenceLatexGate(list(payload["latex_results"])),
        )

    def next_hex(self, _size: int) -> str:
        if not self.hex_ids:
            raise RuntimeError("hex id queue exhausted")
        return self.hex_ids.popleft()

    def next_urlsafe(self, _size: int) -> str:
        if not self.urlsafe_ids:
            raise RuntimeError("urlsafe id queue exhausted")
        return self.urlsafe_ids.popleft()

    def close(self) -> None:
        self.store.close()
        for patcher in reversed(self.patchers):
            patcher.stop()


def main() -> int:
    context: Context | None = None
    try:
        for line in sys.stdin:
            if not line.strip():
                continue
            try:
                request = json.loads(line)
                operation = str(request.get("operation") or "")
                payload = request.get("payload") or {}
                if operation == "init":
                    if context is not None:
                        context.close()
                    context = Context(dict(payload))
                    result = {"initialized": True}
                else:
                    if context is None:
                        raise RuntimeError("shadow must be initialized first")
                    result = dispatch(context, operation, dict(payload))
                response = {"ok": True, "result": result}
            except ReCTMError as exc:
                response = {"ok": False, "error": exc.to_payload()}
            except sqlite3.Error as exc:
                response = {
                    "ok": False,
                    "error": {
                        "code": "SQLITE_ERROR",
                        "message": str(exc),
                        "category": "internal",
                        "retryable": False,
                        "details": {},
                    },
                }
            except Exception as exc:  # noqa: BLE001 - test process boundary
                response = {
                    "ok": False,
                    "error": {
                        "code": "INTERNAL_ERROR",
                        "message": str(exc),
                        "category": "internal",
                        "retryable": False,
                        "details": {"exception_type": type(exc).__name__},
                    },
                }
            sys.stdout.write(
                json.dumps(response, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                + "\n"
            )
            sys.stdout.flush()
    finally:
        if context is not None:
            context.close()
    return 0


def dispatch(context: Context, operation: str, payload: dict[str, Any]) -> Any:
    engine = context.engine
    if operation == "start":
        return engine.start(
            owner_id=str(payload["owner_id"]),
            problem_tex=str(payload["problem_tex"]),
            problem_id=payload.get("problem_id"),
            references=list(payload.get("references") or []),
            native_mode=str(payload["native_mode"]),
            workspace_export_path=payload.get("workspace_export_path"),
            project_id=payload.get("project_id"),
            target_claim_id=payload.get("target_claim_id"),
            workflow_mode=str(payload["workflow_mode"]),
            register_result=bool(payload.get("register_result", True)),
            workflow_protocol_version=int(payload.get("workflow_protocol_version", 2)),
            trace_id=payload.get("trace_id"),
        )
    if operation == "next":
        return engine.next_task(
            owner_id=str(payload["owner_id"]),
            run_id=str(payload["run_id"]),
            trace_id=payload.get("trace_id"),
        )
    if operation == "write":
        return engine.write(
            owner_id=str(payload["owner_id"]),
            capability=str(payload["capability"]),
            resource=str(payload["resource"]),
            content=payload.get("content"),
            trace_id=payload.get("trace_id"),
        )
    if operation == "read":
        return engine.read(
            owner_id=str(payload["owner_id"]),
            capability=str(payload["capability"]),
            resource=str(payload["resource"]),
            trace_id=payload.get("trace_id"),
        )
    if operation == "search":
        return engine.search(
            owner_id=str(payload["owner_id"]),
            capability=str(payload["capability"]),
            resource=str(payload["resource"]),
            query=str(payload["query"]),
            limit=int(payload.get("limit", 20)),
            trace_id=payload.get("trace_id"),
        )
    if operation == "commit":
        return engine.commit(
            owner_id=str(payload["owner_id"]),
            capability=str(payload["capability"]),
            action=str(payload["action"]),
            payload=dict(payload.get("payload") or {}),
            trace_id=payload.get("trace_id"),
        )
    if operation == "status":
        return engine.status(owner_id=str(payload["owner_id"]), run_id=str(payload["run_id"]))
    if operation == "steer":
        return engine.steer(
            owner_id=str(payload["owner_id"]),
            run_id=str(payload["run_id"]),
            message=str(payload["message"]),
            trace_id=payload.get("trace_id"),
        )
    if operation == "cancel":
        return engine.cancel(
            owner_id=str(payload["owner_id"]),
            run_id=str(payload["run_id"]),
            reason=str(payload["reason"]),
            trace_id=payload.get("trace_id"),
        )
    if operation == "resume":
        return engine.resume(owner_id=str(payload["owner_id"]), run_id=str(payload["run_id"]))
    if operation == "artifact":
        return engine.get_artifact(
            owner_id=str(payload["owner_id"]),
            run_id=str(payload["run_id"]),
            artifact=str(payload["artifact"]),
        )
    if operation == "database_snapshot":
        return database_snapshot(context.store)
    if operation == "vault_snapshot":
        return vault_snapshot(context.private_root)
    raise RuntimeError(f"unsupported workflow shadow operation: {operation}")


def vault_snapshot(root: Path) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if not root.exists():
        return result
    import hashlib

    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        data = path.read_bytes()
        result.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
        )
    return result


if __name__ == "__main__":
    raise SystemExit(main())
