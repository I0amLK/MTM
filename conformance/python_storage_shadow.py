#!/usr/bin/env python3
from __future__ import annotations

import base64
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

from re_ctm.capabilities import CapabilityAuthority  # noqa: E402
from re_ctm.enums import WorkflowRole  # noqa: E402
from re_ctm.errors import ReCTMError  # noqa: E402
from re_ctm.storage import StateStore  # noqa: E402


class NullDebug:
    def emit(self, *_args: Any, **_kwargs: Any) -> str:
        return str(_kwargs.get("trace_id") or "trace")


def main() -> int:
    try:
        request = json.load(sys.stdin)
        result = run(request)
        payload = {"ok": True, "result": result}
    except ReCTMError as exc:
        payload = {"ok": False, "error": exc.to_payload()}
    except sqlite3.Error as exc:
        payload = {
            "ok": False,
            "error": {
                "code": "SQLITE_ERROR",
                "message": str(exc),
                "category": "internal",
                "retryable": False,
                "details": {},
            },
        }
    except Exception as exc:  # noqa: BLE001 - conformance boundary must stay structured
        payload = {
            "ok": False,
            "error": {
                "code": "INTERNAL_ERROR",
                "message": str(exc),
                "category": "internal",
                "retryable": False,
                "details": {"exception_type": type(exc).__name__},
            },
        }
    json.dump(payload, sys.stdout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


def run(request: dict[str, Any]) -> dict[str, Any]:
    database = Path(request["database"])
    now_iso = str(request["now_iso"])
    unix_seconds = int(request["unix_seconds"])
    hex_ids = deque(str(item) for item in request.get("hex_ids", []))
    urlsafe_ids = deque(str(item) for item in request.get("urlsafe_ids", []))

    def next_hex(_size: int) -> str:
        if not hex_ids:
            raise RuntimeError("deterministic hex ID queue is empty")
        return hex_ids.popleft()

    def next_urlsafe(_size: int) -> str:
        if not urlsafe_ids:
            raise RuntimeError("deterministic urlsafe ID queue is empty")
        return urlsafe_ids.popleft()

    secret = base64.b64decode(str(request["secret_base64"]))
    with (
        mock.patch("re_ctm.storage.utc_now", return_value=now_iso),
        mock.patch("re_ctm.storage.secrets.token_hex", side_effect=next_hex),
        mock.patch("re_ctm.capabilities.time.time", return_value=unix_seconds),
        mock.patch("re_ctm.capabilities.secrets.token_urlsafe", side_effect=next_urlsafe),
    ):
        store = StateStore(database)
        authority = CapabilityAuthority(secret, store, NullDebug(), default_ttl_seconds=3600)
        last_token = request.get("initial_token")
        results: list[dict[str, Any]] = []
        try:
            for operation in request["operations"]:
                try:
                    value, last_token = dispatch(
                        store,
                        authority,
                        database,
                        dict(operation),
                        last_token,
                    )
                    results.append({"ok": True, "result": value})
                except ReCTMError as exc:
                    results.append({"ok": False, "error": exc.to_payload()})
                except sqlite3.Error as exc:
                    results.append(
                        {
                            "ok": False,
                            "error": {
                                "code": "SQLITE_ERROR",
                                "message": str(exc),
                                "category": "internal",
                                "retryable": False,
                                "details": {},
                            },
                        }
                    )
            snapshot = database_snapshot(store)
            store._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")  # noqa: SLF001
        finally:
            store.close()
    return {"results": results, "snapshot": snapshot, "last_token": last_token}


def dispatch(
    store: StateStore,
    authority: CapabilityAuthority,
    database: Path,
    operation: dict[str, Any],
    last_token: str | None,
) -> tuple[Any, str | None]:
    op = str(operation["op"])
    args = dict(operation.get("args") or {})
    if op == "schema_version":
        return store.schema_version(), last_token
    if op == "database_snapshot":
        return database_snapshot(store), last_token
    if op == "database_digest":
        snapshot = database_snapshot(store)
        return {
            "user_version": snapshot["user_version"],
            "table_count": len(snapshot["tables"]),
            "schema_count": len(snapshot["schemas"]),
            "content_sha256": __import__("hashlib").sha256(
                canonical(snapshot).encode("utf-8")
            ).hexdigest(),
        }, last_token
    if op == "create_run":
        return store.create_run(**args), last_token
    if op == "get_run":
        return store.get_run(**args), last_token
    if op == "list_runs":
        return store.list_runs(**args), last_token
    if op == "update_run_metadata":
        return store.update_run_metadata(args["run_id"], args["updates"]), last_token
    if op == "transition_run":
        return store.transition_run(**args), last_token
    if op == "create_domain":
        return store.create_domain(**args), last_token
    if op == "get_domain":
        return store.get_domain(**args), last_token
    if op == "list_domains":
        return store.list_domains(**args), last_token
    if op == "seal_domain":
        return store.seal_domain(**args), last_token
    if op == "create_branch":
        return store.create_branch(**args), last_token
    if op == "get_branch":
        return store.get_branch(**args), last_token
    if op == "list_branches":
        return store.list_branches(**args), last_token
    if op == "update_branch_status":
        branch_id = args.pop("branch_id")
        status = args.pop("status")
        return store.update_branch_status(branch_id, status, **args), last_token
    if op == "add_steering":
        return store.add_steering(**args), last_token
    if op == "consume_steering":
        return store.consume_steering(**args), last_token
    if op == "list_transitions":
        return store.list_transitions(**args), last_token
    if op == "create_project":
        return store.create_project(**args), last_token
    if op == "get_project":
        return store.get_project(**args), last_token
    if op == "list_projects":
        return store.list_projects(**args), last_token
    if op == "create_claim":
        return store.create_claim(**args), last_token
    if op == "get_claim":
        return store.get_claim(**args), last_token
    if op == "list_claims":
        return store.list_claims(**args), last_token
    if op == "list_claim_revisions":
        return store.list_claim_revisions(**args), last_token
    if op == "get_claim_revision":
        return store.get_claim_revision(**args), last_token
    if op == "current_claim_revision":
        return store.current_claim_revision(**args), last_token
    if op == "create_open_claim_revision":
        return store.create_open_claim_revision(**args), last_token
    if op == "create_project_snapshot":
        project_id = args.pop("project_id")
        return store.create_project_snapshot(project_id, **args), last_token
    if op == "get_project_snapshot":
        snapshot_id = args.pop("snapshot_id")
        return store.get_project_snapshot(snapshot_id, **args), last_token
    if op == "link_run_to_project":
        return store.link_run_to_project(**args), last_token
    if op == "get_project_run":
        return store.get_project_run(**args), last_token
    if op == "set_project_run_mode":
        store.set_project_run_mode(**args)
        return {"updated": True}, last_token
    if op == "write_proof_manifest":
        return store.write_proof_manifest(**args), last_token
    if op == "read_proof_manifest":
        return store.read_proof_manifest(**args), last_token
    if op == "register_reference":
        return store.register_reference(**args), last_token
    if op == "get_reference":
        return store.get_reference(**args), last_token
    if op == "create_source_snapshot":
        return store.create_source_snapshot(**args), last_token
    if op == "list_source_snapshots":
        return store.list_source_snapshots(**args), last_token
    if op == "list_run_references":
        return store.list_run_references(**args), last_token
    if op == "write_reference_audit":
        return store.write_reference_audit(**args), last_token
    if op == "get_reference_audit":
        return store.get_reference_audit(**args), last_token
    if op == "list_reference_audits":
        return store.list_reference_audits(**args), last_token
    if op == "promote_verified_run":
        return store.promote_verified_run(**args), last_token
    if op == "project_dependency_graph":
        return store.project_dependency_graph(**args), last_token
    if op == "capability_issue":
        args["role"] = WorkflowRole(args["role"])
        token = authority.issue(**args)
        return token, token
    if op == "capability_validate_last":
        if last_token is None:
            raise RuntimeError("last_token is unavailable")
        claims = authority.validate(last_token, **args)
        return claims.to_payload(), last_token
    if op == "capability_revoke_last":
        if last_token is None:
            raise RuntimeError("last_token is unavailable")
        authority.revoke(last_token, **args)
        return {"revoked": True}, last_token
    if op == "capability_encode":
        token = authority._encode(args["payload"])  # noqa: SLF001
        return token, token
    if op == "capability_decode_last":
        if last_token is None:
            raise RuntimeError("last_token is unavailable")
        return authority._decode(last_token), last_token  # noqa: SLF001
    if op == "tamper_capability_permissions":
        connection = sqlite3.connect(database)
        try:
            connection.execute(
                "UPDATE capabilities SET permissions_json=? WHERE nonce=?",
                (
                    json.dumps(args["permissions"], separators=(",", ":")),
                    args["nonce"],
                ),
            )
            connection.commit()
        finally:
            connection.close()
        return {"tampered": True}, last_token
    if op == "checkpoint":
        store._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")  # noqa: SLF001
        return {"checkpointed": True}, last_token
    raise RuntimeError(f"unsupported storage shadow operation: {op}")


def database_snapshot(store: StateStore) -> dict[str, Any]:
    connection = store._connection  # noqa: SLF001
    user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    records = connection.execute(
        "SELECT name, sql FROM sqlite_master "
        "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    tables: dict[str, list[dict[str, Any]]] = {}
    schemas: dict[str, str] = {}
    for name, schema in records:
        rows = [dict(row) for row in connection.execute(f'SELECT * FROM "{name}"').fetchall()]
        rows.sort(key=canonical)
        tables[str(name)] = rows
        schemas[str(name)] = " ".join(str(schema or "").split())
    return {"user_version": user_version, "schemas": schemas, "tables": tables}


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


if __name__ == "__main__":
    raise SystemExit(main())
