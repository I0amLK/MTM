#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import sqlite3
import sys
from collections import deque
from pathlib import Path
from typing import Any

import re_ctm.oauth as oauth_module
from re_ctm.errors import ReCTMError
from re_ctm.mcp import (
    JSONRPCError,
    MCPDispatcher,
    decode_mirror_header,
    modern_http_status,
    validate_http_mirror_headers,
)
from re_ctm.oauth import OAuthPrincipal, OAuthService, OAuthStore
from re_ctm.rethlas_contracts import HIDDEN_LEGACY_ALIAS_SEMANTICS
from re_ctm.tools import PUBLIC_TOOL_NAMES, TOOL_SPECS


class DeterministicSource:
    def __init__(self, values: list[str], now_unix: int, now_iso: str) -> None:
        self.values = deque(values)
        self.now_unix = now_unix
        self.now_iso = now_iso

    def token_urlsafe(self, _bytes: int) -> str:
        if not self.values:
            raise RuntimeError("deterministic id source exhausted")
        return self.values.popleft()


class EventCollector:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def emit(
        self,
        event_type: str,
        component: str,
        *,
        trace_id: str,
        reason: str,
        details: dict[str, Any],
        **_ignored: Any,
    ) -> None:
        self.events.append(
            {
                "event_type": event_type,
                "component": component,
                "trace_id": trace_id,
                "reason": reason,
                "details": details,
            }
        )


class EchoTools:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def list_tools(self) -> list[dict[str, Any]]:
        return [TOOL_SPECS[name].definition(name) for name in PUBLIC_TOOL_NAMES]

    def call(
        self,
        name: str,
        arguments: dict[str, Any],
        principal: OAuthPrincipal,
        *,
        trace_id: str,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "tool": name,
                "arguments": arguments,
                "principal": {
                    "client_id": principal.client_id,
                    "subject": principal.subject,
                    "scope": principal.scope,
                },
                "trace_id": trace_id,
            }
        )
        return {
            "content": [{"type": "text", "text": f"tool {name} completed"}],
            "structuredContent": {
                "ok": True,
                "tool": name,
                "arguments": arguments,
                "client_id": principal.client_id,
            },
            "isError": False,
        }


class Context:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.source = DeterministicSource(
            [str(item) for item in payload["ids"]],
            int(payload["now_unix"]),
            str(payload["now_iso"]),
        )
        oauth_module.secrets.token_urlsafe = self.source.token_urlsafe
        oauth_module.time.time = lambda: self.source.now_unix
        oauth_module.utc_now = lambda: self.source.now_iso
        self.events = EventCollector()
        self.store = OAuthStore(Path(payload["database"]))
        self.database = Path(payload["database"])
        self.oauth = OAuthService(
            server_url=str(payload["server_url"]),
            password=str(payload["password"]),
            token_secret=base64.b64decode(payload["token_secret_b64"]),
            store=self.store,
            debug=self.events,  # type: ignore[arg-type]
            token_ttl=int(payload["token_ttl"]),
        )
        self.tools = EchoTools()
        self.dispatcher = MCPDispatcher(self.tools)  # type: ignore[arg-type]
        self.last_token: str | None = None

    def close(self) -> None:
        self.store.close()


def source_catalog() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "public_names": list(PUBLIC_TOOL_NAMES),
        "hidden_names": [name for name in TOOL_SPECS if name not in PUBLIC_TOOL_NAMES],
        "definitions": {
            name: TOOL_SPECS[name].definition(name)
            for name in TOOL_SPECS
        },
        "alias_semantics": {
            name: list(value)
            for name, value in HIDDEN_LEGACY_ALIAS_SEMANTICS.items()
        },
    }


def evaluate(context: Context | None, request: dict[str, Any]) -> tuple[Context | None, Any]:
    operation = request.get("operation")
    payload = request.get("payload") or {}
    if operation == "init":
        if context is not None:
            context.close()
        return Context(payload), {"initialized": True}
    if context is None:
        raise ReCTMError(
            "INVALID_ARGUMENT",
            "shadow must be initialized first",
            category="validation",
        )
    if operation == "authorization_server_metadata":
        result = context.oauth.authorization_server_metadata(
            base_url=payload.get("base_url")
        )
    elif operation == "protected_resource_metadata":
        result = context.oauth.protected_resource_metadata(
            base_url=payload.get("base_url")
        )
    elif operation == "register":
        result = context.oauth.register(
            payload.get("metadata") or {},
            trace_id=str(payload["trace_id"]),
        )
    elif operation == "validate_authorization_request":
        result = context.oauth.validate_authorization_request(
            payload.get("params") or {},
            base_url=payload.get("base_url"),
        )
    elif operation == "authorize":
        result = context.oauth.authorize(
            payload.get("params") or {},
            password=str(payload["password"]),
            trace_id=str(payload["trace_id"]),
            base_url=payload.get("base_url"),
        )
    elif operation == "exchange_code":
        result = context.oauth.exchange_code(
            payload.get("params") or {},
            basic_client_id=str(payload.get("basic_client_id") or ""),
            basic_client_secret=str(payload.get("basic_client_secret") or ""),
            trace_id=str(payload["trace_id"]),
            base_url=payload.get("base_url"),
        )
        context.last_token = result["access_token"]
    elif operation == "validate_last_token":
        if context.last_token is None:
            raise ReCTMError(
                "INVALID_ARGUMENT",
                "last token is unavailable",
                category="validation",
            )
        principal = context.oauth.validate_authorization_header(
            f"Bearer {context.last_token}",
            trace_id=str(payload["trace_id"]),
            base_url=payload.get("base_url"),
        )
        result = {
            "client_id": principal.client_id,
            "subject": principal.subject,
            "scope": principal.scope,
        }
    elif operation == "decode_last_token":
        if context.last_token is None:
            raise ReCTMError(
                "INVALID_ARGUMENT",
                "last token is unavailable",
                category="validation",
            )
        result = oauth_module._decode_signed_token(
            context.last_token,
            context.oauth.token_secret,
        )
    elif operation == "last_token":
        result = context.last_token
    elif operation == "set_last_token":
        context.last_token = str(payload["token"])
        result = {"updated": True}
    elif operation == "oauth_snapshot":
        connection = sqlite3.connect(context.database)
        try:
            result = {
                "clients": [
                    list(row)
                    for row in connection.execute(
                        "SELECT client_id, redirect_uris_json, token_endpoint_auth_method, client_name, secret_digest, issued_at FROM oauth_clients ORDER BY client_id"
                    ).fetchall()
                ],
                "codes": [
                    list(row)
                    for row in connection.execute(
                        "SELECT code_digest, client_id, redirect_uri, code_challenge, resource, expires_at, created_at FROM oauth_codes ORDER BY code_digest"
                    ).fetchall()
                ],
            }
        finally:
            connection.close()
    elif operation == "mcp_dispatch":
        principal_data = payload["principal"]
        principal = OAuthPrincipal(
            client_id=str(principal_data["client_id"]),
            subject=str(principal_data["subject"]),
            scope=str(principal_data["scope"]),
        )
        result = context.dispatcher.dispatch(
            payload["request"],
            principal,
            trace_id=payload.get("trace_id"),
            transport_protocol_version=payload.get("transport_protocol_version"),
        )
    elif operation == "mirror_validate":
        try:
            validate_http_mirror_headers(
                payload["request"],
                version_header=payload.get("version_header"),
                method_header=payload.get("method_header"),
                name_header=payload.get("name_header"),
            )
        except JSONRPCError as error:
            raise ReCTMError(
                "JSONRPC_ERROR",
                error.message,
                category="validation",
                details={"jsonrpc_code": error.code, "data": error.data},
            ) from error
        result = {"valid": True}
    elif operation == "mirror_decode":
        try:
            result = decode_mirror_header(str(payload["value"]))
        except JSONRPCError as error:
            raise ReCTMError(
                "JSONRPC_ERROR",
                error.message,
                category="validation",
                details={"jsonrpc_code": error.code, "data": error.data},
            ) from error
    elif operation == "modern_http_status":
        result = modern_http_status(payload["request"], payload["response"])
    elif operation == "catalog_public":
        result = context.tools.list_tools()
    elif operation == "events":
        result = context.events.events
    elif operation == "calls":
        result = context.tools.calls
    else:
        raise ReCTMError(
            "INVALID_ARGUMENT",
            "unsupported shadow operation",
            category="validation",
        )
    return context, result


def main() -> int:
    context: Context | None = None
    try:
        for raw in sys.stdin:
            if not raw.strip():
                continue
            try:
                request = json.loads(raw)
                context, result = evaluate(context, request)
                response = {"ok": True, "result": result}
            except ReCTMError as error:
                response = {"ok": False, "error": error.to_payload()}
            except Exception as error:  # noqa: BLE001 - structured shadow boundary
                response = {
                    "ok": False,
                    "error": {
                        "code": "INTERNAL_ERROR",
                        "message": str(error),
                        "category": "internal",
                        "retryable": False,
                        "details": {"exception_type": type(error).__name__},
                    },
                }
            print(
                json.dumps(
                    response,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                flush=True,
            )
    finally:
        if context is not None:
            context.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
