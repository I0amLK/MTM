#!/usr/bin/env python3
from __future__ import annotations

import json
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

    invariants = payload.get("invariants")
    if not isinstance(invariants, list):
        raise ValueError("invariants must be an array")
    invariant_ids = {item.get("id") for item in invariants if isinstance(item, dict)}
    required = {f"INV-{index:03d}" for index in range(1, 9)}
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
        "runtime_vertices": len(runtime_ids),
        "runtime_edges": len(runtime_edges),
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
