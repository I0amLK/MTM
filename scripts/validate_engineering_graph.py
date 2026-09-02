#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
import tomllib
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
GRAPH = ROOT / "engineering-graph.json"


def validate_graph(payload: dict[str, Any]) -> dict[str, Any]:
    crate_graph = payload.get("crate_dependency_graph")
    if not isinstance(crate_graph, dict):
        raise ValueError("missing crate_dependency_graph")
    vertices = crate_graph.get("vertices")
    edges = crate_graph.get("edges")
    if not isinstance(vertices, list) or not isinstance(edges, list):
        raise ValueError("crate graph vertices/edges must be arrays")
    ids: set[str] = set()
    statuses: Counter[str] = Counter()
    for vertex in vertices:
        if not isinstance(vertex, dict) or not isinstance(vertex.get("id"), str):
            raise ValueError("invalid crate vertex")
        vertex_id = vertex["id"]
        if vertex_id in ids:
            raise ValueError(f"duplicate crate vertex: {vertex_id}")
        ids.add(vertex_id)
        statuses[str(vertex.get("status"))] += 1
    graph: dict[str, set[str]] = {vertex_id: set() for vertex_id in ids}
    for edge in edges:
        if not isinstance(edge, dict):
            raise ValueError("invalid crate edge")
        source = edge.get("source")
        target = edge.get("target")
        if source not in ids or target not in ids:
            raise ValueError(f"unknown crate edge: {source}->{target}")
        if source == target:
            raise ValueError(f"self dependency: {source}")
        graph[str(source)].add(str(target))
    _assert_acyclic(graph)
    if graph["mtm-contracts"]:
        raise ValueError("mtm-contracts must not depend on another project crate")
    for crate, dependencies in graph.items():
        if len(dependencies) > 5 and crate != "mtm-runtime":
            raise ValueError(f"only mtm-runtime may be a broad composition root: {crate}")

    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    members = cargo.get("workspace", {}).get("members", [])
    member_crates = {Path(member).name for member in members}
    unknown_members = member_crates - ids
    if unknown_members:
        raise ValueError(f"Cargo members absent from target graph: {sorted(unknown_members)}")
    for member in member_crates:
        vertex = next(item for item in vertices if item["id"] == member)
        if vertex.get("status") not in {"bootstrap", "implemented"}:
            raise ValueError(f"Cargo member {member} is not marked bootstrap/implemented")

    core_manifest = tomllib.loads(
        (ROOT / "crates" / "mtm-core" / "Cargo.toml").read_text(encoding="utf-8")
    )
    core_dependencies = set(core_manifest.get("dependencies", {}))
    expected_core_dependencies = {
        "mtm-contracts",
        "regex",
        "serde",
        "serde_json",
        "sha2",
        "shell-words",
        "url",
    }
    if core_dependencies != expected_core_dependencies:
        raise ValueError(
            "mtm-core dependency boundary drift: "
            f"expected {sorted(expected_core_dependencies)}, got {sorted(core_dependencies)}"
        )
    forbidden_core_tokens = {
        "std::fs": "filesystem authority",
        "std::net": "network authority",
        "std::process": "process authority",
        "rusqlite": "database authority",
        "tokio": "async runtime authority",
        "reqwest": "network client authority",
    }
    core_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "crates" / "mtm-core" / "src").glob("*.rs"))
    )
    for token, boundary in forbidden_core_tokens.items():
        if token in core_source:
            raise ValueError(f"mtm-core acquired forbidden {boundary}: {token}")

    storage_manifest = tomllib.loads(
        (ROOT / "crates" / "mtm-storage" / "Cargo.toml").read_text(encoding="utf-8")
    )
    storage_dependencies = set(storage_manifest.get("dependencies", {}))
    expected_storage_dependencies = {
        "base64",
        "getrandom",
        "hmac",
        "mtm-contracts",
        "rusqlite",
        "serde",
        "serde_json",
        "sha2",
        "time",
    }
    if storage_dependencies != expected_storage_dependencies:
        raise ValueError(
            "mtm-storage dependency boundary drift: "
            f"expected {sorted(expected_storage_dependencies)}, got {sorted(storage_dependencies)}"
        )
    storage_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "crates" / "mtm-storage" / "src").glob("*.rs"))
    )
    forbidden_storage_tokens = {
        "std::net": "network authority",
        "std::process": "process authority",
        "reqwest": "network client authority",
        "tokio": "async runtime authority",
        "mtm_native": "Native execution authority",
    }
    for token, boundary in forbidden_storage_tokens.items():
        if token in storage_source:
            raise ValueError(f"mtm-storage acquired forbidden {boundary}: {token}")

    gateway_manifest = tomllib.loads(
        (ROOT / "crates" / "mtm-gateway" / "Cargo.toml").read_text(encoding="utf-8")
    )
    gateway_dependencies = set(gateway_manifest.get("dependencies", {}))
    expected_gateway_dependencies = {
        "axum",
        "base64",
        "getrandom",
        "hmac",
        "http",
        "mtm-contracts",
        "mtm-core",
        "rusqlite",
        "serde",
        "serde_json",
        "serde_urlencoded",
        "sha2",
        "time",
        "tokio",
        "url",
    }
    if gateway_dependencies != expected_gateway_dependencies:
        raise ValueError(
            "mtm-gateway dependency boundary drift: "
            f"expected {sorted(expected_gateway_dependencies)}, got {sorted(gateway_dependencies)}"
        )
    gateway_library_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "crates" / "mtm-gateway" / "src").glob("*.rs"))
    )
    forbidden_gateway_tokens = {
        "std::process": "child-process authority",
        "mtm_native": "Native execution authority",
        "mtm_storage": "workflow-state writer authority",
        "WorkflowEngine": "workflow transition authority",
        "PrivateVault": "private-vault authority",
    }
    for token, boundary in forbidden_gateway_tokens.items():
        if token in gateway_library_source:
            raise ValueError(f"mtm-gateway acquired forbidden {boundary}: {token}")
    catalog_source = (ROOT / "crates" / "mtm-gateway" / "src" / "catalog.rs").read_text(
        encoding="utf-8"
    )
    for required_hash in (
        "86c8ee7d53a0678d0aaaba47ce2f2f72f5c03747fcb443d78011e005dedaa343",
        "e89c5d2f8bec198fb4a90e7166aadb04b757e4b3ff0c8f459e5fdd468c59f87e",
    ):
        if required_hash not in catalog_source:
            raise ValueError("mtm-gateway lost a frozen tool-catalog hash")

    workflow_manifest = tomllib.loads(
        (ROOT / "crates" / "mtm-workflow" / "Cargo.toml").read_text(encoding="utf-8")
    )
    workflow_dependencies = set(workflow_manifest.get("dependencies", {}))
    expected_workflow_dependencies = {
        "mtm-contracts",
        "mtm-core",
        "mtm-storage",
        "regex",
        "serde",
        "serde_json",
        "sha2",
    }
    if workflow_dependencies != expected_workflow_dependencies:
        raise ValueError(
            "mtm-workflow dependency boundary drift: "
            f"expected {sorted(expected_workflow_dependencies)}, got {sorted(workflow_dependencies)}"
        )
    if graph["mtm-workflow"] != {"mtm-contracts", "mtm-core", "mtm-storage"}:
        raise ValueError("mtm-workflow crate graph must preserve contracts/core/storage authority edges")
    workflow_library_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "crates" / "mtm-workflow" / "src").glob("*.rs"))
    )
    forbidden_workflow_tokens = {
        "std::net": "network authority",
        "std::process": "child-process authority",
        "reqwest": "network client authority",
        "tokio": "async runtime authority",
        "mtm_native": "Native execution authority",
        "mtm_gateway": "transport authority",
    }
    for token, boundary in forbidden_workflow_tokens.items():
        if token in workflow_library_source:
            raise ValueError(f"mtm-workflow acquired forbidden {boundary}: {token}")

    capability_source = (ROOT / "crates" / "mtm-storage" / "src" / "capability.rs").read_text(
        encoding="utf-8"
    )
    claims_match = re.search(
        r"pub struct CapabilityClaims\s*\{(?P<body>.*?)\n\}",
        capability_source,
        flags=re.DOTALL,
    )
    if claims_match is None:
        raise ValueError("CapabilityClaims definition is missing")
    if re.search(r"^\s*pub\s+[A-Za-z_][A-Za-z0-9_]*\s*:", claims_match.group("body"), re.MULTILINE):
        raise ValueError("CapabilityClaims fields must remain non-public")
    claims_prefix = capability_source[: claims_match.start()].rsplit("#[derive", 1)[-1]
    if "Deserialize" in claims_prefix:
        raise ValueError("CapabilityClaims must not regain external Deserialize construction")

    verifier_source = (ROOT / "crates" / "mtm-workflow" / "src" / "verifier.rs").read_text(
        encoding="utf-8"
    )
    if "pub(crate) struct FinalizationPermit" not in verifier_source:
        raise ValueError("FinalizationPermit must remain crate-private to the verifier authority")
    if "pub(crate) fn issue(" in verifier_source or "pub fn issue(" in verifier_source:
        raise ValueError("FinalizationPermit constructor must remain private to verifier.rs")
    workflow_lib = (ROOT / "crates" / "mtm-workflow" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    if "pub use verifier::FinalizationPermit" in workflow_lib or "pub use kernel::FinalizationPermit" in workflow_lib:
        raise ValueError("FinalizationPermit must not be re-exported from mtm-workflow")

    runtime_manifest = tomllib.loads(
        (ROOT / "crates" / "mtm-runtime" / "Cargo.toml").read_text(encoding="utf-8")
    )
    runtime_dependencies = set(runtime_manifest.get("dependencies", {}))
    expected_runtime_dependencies = {
        "axum",
        "base64",
        "getrandom",
        "mtm-contracts",
        "mtm-core",
        "mtm-gateway",
        "mtm-native",
        "mtm-storage",
        "mtm-workflow",
        "regex",
        "serde",
        "serde_json",
        "sha2",
        "tokio",
        "url",
    }
    if runtime_dependencies != expected_runtime_dependencies:
        raise ValueError(
            "mtm-runtime dependency boundary drift: "
            f"expected {sorted(expected_runtime_dependencies)}, got {sorted(runtime_dependencies)}"
        )
    if graph["mtm-runtime"] != {
        "mtm-contracts",
        "mtm-core",
        "mtm-gateway",
        "mtm-native",
        "mtm-storage",
        "mtm-workflow",
    }:
        raise ValueError("mtm-runtime must remain the single wide composition root")

    cli_manifest = tomllib.loads(
        (ROOT / "crates" / "mtm-cli" / "Cargo.toml").read_text(encoding="utf-8")
    )
    cli_dependencies = set(cli_manifest.get("dependencies", {}))
    expected_cli_dependencies = {"mtm-contracts", "mtm-runtime", "serde_json"}
    if cli_dependencies != expected_cli_dependencies:
        raise ValueError(
            "mtm-cli dependency boundary drift: "
            f"expected {sorted(expected_cli_dependencies)}, got {sorted(cli_dependencies)}"
        )
    if graph["mtm-cli"] != {"mtm-contracts", "mtm-runtime"}:
        raise ValueError("mtm-cli must remain presentation over contracts/runtime only")

    oauth_source = (ROOT / "crates" / "mtm-gateway" / "src" / "oauth.rs").read_text(
        encoding="utf-8"
    )
    principal_match = re.search(
        r"pub struct OAuthPrincipal\s*\{(?P<body>.*?)\n\}",
        oauth_source,
        flags=re.DOTALL,
    )
    if principal_match is None:
        raise ValueError("OAuthPrincipal definition is missing")
    if re.search(
        r"^\s*pub\s+[A-Za-z_][A-Za-z0-9_]*\s*:",
        principal_match.group("body"),
        re.MULTILINE,
    ):
        raise ValueError("OAuthPrincipal fields must remain non-public")
    principal_prefix = oauth_source[: principal_match.start()].rsplit("#[derive", 1)[-1]
    if "Deserialize" in principal_prefix:
        raise ValueError("OAuthPrincipal must not regain external Deserialize construction")
    shadow_fixture_match = re.search(
        r'#\[cfg\(feature = "shadow-fixture"\)\]\s*#\[doc\(hidden\)\]\s*pub fn shadow_fixture',
        oauth_source,
    )
    if shadow_fixture_match is None:
        raise ValueError("OAuthPrincipal test constructor must remain shadow-fixture gated")
    gateway_features = gateway_manifest.get("features", {})
    if gateway_features.get("default") != [] or "shadow-fixture" not in gateway_features:
        raise ValueError("shadow-fixture must remain disabled by default")

    operator_source = (ROOT / "crates" / "mtm-runtime" / "src" / "operator.rs").read_text(
        encoding="utf-8"
    )
    for forbidden in ("StateStore", "CapabilityAuthority", "PrivateVault", "WorkflowEngine"):
        if forbidden in operator_source:
            raise ValueError(f"operator observer acquired authority-bearing type: {forbidden}")

    catalog_b64 = (ROOT / "crates" / "mtm-cli" / "assets" / "tool-catalog-v1.b64").read_text(
        encoding="utf-8"
    )
    try:
        catalog_bytes = base64.b64decode("".join(catalog_b64.split()), validate=True)
        json.loads(catalog_bytes)
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError("embedded tool catalog is not valid base64 JSON") from exc
    catalog_raw_sha256 = hashlib.sha256(catalog_bytes).hexdigest()
    if catalog_raw_sha256 != "46deeeb246f77056c75392c2d14a3d707521c043fbead29b76bb5a44c6915dc3":
        raise ValueError("embedded tool catalog raw bytes drifted from the frozen source snapshot")
    methodology_bytes = (ROOT / "crates" / "mtm-cli" / "assets" / "methodology-v2.json").read_bytes()
    try:
        json.loads(methodology_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError("embedded methodology asset is invalid JSON") from exc
    methodology_sha256 = hashlib.sha256(methodology_bytes).hexdigest()
    if methodology_sha256 != "0403ba1f6caeabfef563e3b2b22bf1472a84c470a76ddbcb5bafce1d5f18a4e8":
        raise ValueError("embedded methodology bytes drifted from the frozen source snapshot")

    runtime_graph = payload.get("runtime_authority_graph")
    if not isinstance(runtime_graph, dict):
        raise ValueError("missing runtime_authority_graph")
    runtime_vertices = runtime_graph.get("vertices", [])
    runtime_edges = runtime_graph.get("edges", [])
    runtime_ids = {item.get("id") for item in runtime_vertices if isinstance(item, dict)}
    if len(runtime_ids) != len(runtime_vertices):
        raise ValueError("duplicate or invalid runtime vertex")
    for edge in runtime_edges:
        if edge.get("source") not in runtime_ids or edge.get("target") not in runtime_ids:
            raise ValueError("runtime edge references unknown vertex")
        if not str(edge.get("guard") or "").strip():
            raise ValueError("runtime edge requires a guard")

    deployment_graph = payload.get("deployment_authority_graph")
    if not isinstance(deployment_graph, dict):
        raise ValueError("missing deployment_authority_graph")
    deployment_vertices = deployment_graph.get("vertices", [])
    deployment_edges = deployment_graph.get("edges", [])
    deployment_ids = {
        item.get("id") for item in deployment_vertices if isinstance(item, dict)
    }
    required_deployment_ids = {
        "mtm_rust_release",
        "mtm_command",
        "mtm_sessions",
        "re_ctm_python_release",
        "re_ctm_command",
        "re_ctm_wheel",
        "historical_source",
    }
    if deployment_ids != required_deployment_ids:
        raise ValueError("deployment authority vertices are incomplete or duplicated")
    for edge in deployment_edges:
        if edge.get("source") not in deployment_ids or edge.get("target") not in deployment_ids:
            raise ValueError("deployment edge references unknown vertex")
        if not str(edge.get("guard") or "").strip():
            raise ValueError("deployment edge requires a guard")
    mtm_command_sources = {
        edge.get("source")
        for edge in deployment_edges
        if edge.get("target") == "mtm_command"
    }
    if mtm_command_sources != {"mtm_rust_release"}:
        raise ValueError("mtm_command must select only the MTM Rust release")
    re_ctm_command_sources = {
        edge.get("source")
        for edge in deployment_edges
        if edge.get("target") == "re_ctm_command"
    }
    if re_ctm_command_sources != {"re_ctm_python_release"}:
        raise ValueError("re_ctm_command must select only the Re-CTM release")

    invariants = payload.get("invariants")
    if not isinstance(invariants, list):
        raise ValueError("invariants must be an array")
    invariant_ids = {item.get("id") for item in invariants if isinstance(item, dict)}
    required = {f"INV-{index:03d}" for index in range(1, 11)}
    if invariant_ids != required:
        raise ValueError("architecture invariants are incomplete or duplicated")

    return {
        "crate_vertices": len(ids),
        "crate_edges": sum(len(items) for items in graph.values()),
        "crate_graph_acyclic": True,
        "cargo_members": sorted(member_crates),
        "crate_statuses": dict(sorted(statuses.items())),
        "mtm_core_dependency_count": len(core_dependencies),
        "mtm_core_pure_boundary": True,
        "mtm_storage_dependency_count": len(storage_dependencies),
        "mtm_storage_single_writer_boundary": True,
        "mtm_gateway_dependency_count": len(gateway_dependencies),
        "mtm_gateway_transport_only_boundary": True,
        "mtm_workflow_dependency_count": len(workflow_dependencies),
        "mtm_workflow_authority_boundary": True,
        "capability_claims_unforgeable_by_public_construction": True,
        "finalization_permit_verifier_private": True,
        "mtm_runtime_dependency_count": len(runtime_dependencies),
        "mtm_runtime_single_composition_root": True,
        "mtm_cli_dependency_count": len(cli_dependencies),
        "mtm_cli_presentation_boundary": True,
        "oauth_principal_unforgeable_by_public_construction": True,
        "operator_observer_presentation_only": True,
        "embedded_tool_catalog_sha256": catalog_raw_sha256,
        "embedded_methodology_sha256": methodology_sha256,
        "runtime_vertices": len(runtime_ids),
        "runtime_edges": len(runtime_edges),
        "deployment_vertices": len(deployment_ids),
        "deployment_edges": len(deployment_edges),
        "deployment_command_namespace_separated": True,
        "invariants": len(invariants),
    }


def _assert_acyclic(graph: dict[str, set[str]]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise ValueError(f"crate dependency cycle at {node}")
        if node in visited:
            return
        visiting.add(node)
        for dependency in graph[node]:
            visit(dependency)
        visiting.remove(node)
        visited.add(node)

    for node in graph:
        visit(node)


def main() -> int:
    try:
        payload = json.loads(GRAPH.read_text(encoding="utf-8"))
        summary = validate_graph(payload)
    except (OSError, KeyError, TypeError, json.JSONDecodeError, tomllib.TOMLDecodeError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
