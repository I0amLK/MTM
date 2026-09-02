#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import re
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "conformance" / "golden" / "mtm009-research-state-contract-v1.json"
GRAPH_FIXTURE = ROOT / "conformance" / "golden" / "mtm009-research-graph-v1.json"

EXPECTED_MEMBERS = [
    "crates/mtm-contracts",
    "crates/mtm-core",
    "crates/mtm-native",
    "crates/mtm-storage",
    "crates/mtm-workflow",
    "crates/mtm-gateway",
    "crates/mtm-runtime",
    "crates/mtm-cli",
]

EXPECTED_WORKFLOW_STATES = [
    "Created",
    "Assess",
    "Explore",
    "ProposePlans",
    "DirectProving",
    "BranchPrepare",
    "BranchRun",
    "BranchJoin",
    "IdentifyFailures",
    "Replan",
    "Assemble",
    "LatexValidate",
    "Verify",
    "Repair",
    "Finalize",
    "Done",
    "Cancelled",
    "Failed",
]

EXPECTED_GENERATION_CHANNELS = {
    "immediate_conclusions",
    "toy_examples",
    "counterexamples",
    "big_decisions",
    "subgoals",
    "proof_steps",
    "failed_paths",
    "verification_reports",
    "branch_states",
    "events",
}

ZERO_BUDGET_KEYS = {
    "new_crates",
    "new_public_tools",
    "new_hidden_aliases",
    "new_workflow_states",
    "new_sqlite_schema_versions",
    "new_long_running_workers",
    "model_codex_api_integrations",
    "new_independent_web_apps",
    "new_final_artifact_kinds",
    "new_vault_channels",
    "generic_graph_dependencies",
}

FORBIDDEN_PRODUCTION_PATTERNS = (
    "codex exec",
    "codex resume",
    "openai_api_key",
    "anthropic_api_key",
    "gemini_api_key",
    "openai::",
    "anthropic::",
)

FORBIDDEN_PROJECTOR_PATTERNS = (
    "std::fs",
    "std::io",
    "std::net",
    "std::process",
    "std::time",
    "tokio",
    "reqwest",
    "mtm_storage",
    "crate::engine",
    "crate::vault",
    "crate::verifier",
    "capabilityclaims",
    "finalizationpermit",
    "workflowstate",
    "deserialize",
)

FORBIDDEN_GRAPH_DEPENDENCIES = {
    "petgraph",
    "graphlib",
    "daggy",
    "pathfinding",
}


def validate() -> dict[str, Any]:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    if fixture.get("schema_version") != "1.0.0" or fixture.get("milestone") != "MTM-009":
        raise ValueError("MTM-009 research contract identity is invalid")
    if fixture.get("planned_workflow_protocol") != 3:
        raise ValueError("MTM-009 must target workflow protocol 3")
    if fixture.get("accepted_baseline_protocols") != [1, 2]:
        raise ValueError("MTM-009 must preserve protocol 1 and 2 baselines")
    if fixture.get("generic_public_step_envelope_changes") != 0:
        raise ValueError("MTM-009 may not redesign the generic rethlas_step envelope")

    budget = fixture.get("complexity_budget")
    if not isinstance(budget, dict) or set(budget) != ZERO_BUDGET_KEYS:
        raise ValueError("MTM-009 complexity budget keys are incomplete or changed")
    nonzero = {key: value for key, value in budget.items() if value != 0}
    if nonzero:
        raise ValueError(f"MTM-009 zero complexity budgets were exceeded: {nonzero}")

    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    if workspace.get("workspace", {}).get("members") != EXPECTED_MEMBERS:
        raise ValueError("MTM-009 may not add, remove, or reorder workspace crates")
    workspace_dependencies = set(workspace.get("workspace", {}).get("dependencies", {}))
    workflow_manifest = tomllib.loads(
        (ROOT / "crates" / "mtm-workflow" / "Cargo.toml").read_text(encoding="utf-8")
    )
    workflow_dependencies = set(workflow_manifest.get("dependencies", {}))
    forbidden_graph_dependencies = FORBIDDEN_GRAPH_DEPENDENCIES & (
        workspace_dependencies | workflow_dependencies
    )
    if forbidden_graph_dependencies:
        raise ValueError(
            "MTM-009 may not add a generic graph dependency: "
            f"{sorted(forbidden_graph_dependencies)}"
        )

    catalog_raw = base64.b64decode(
        "".join((ROOT / "crates" / "mtm-cli" / "assets" / "tool-catalog-v1.b64").read_text(encoding="utf-8").split()),
        validate=True,
    )
    catalog = json.loads(catalog_raw)
    if len(catalog.get("public_names", [])) != 24 or len(catalog.get("hidden_names", [])) != 11:
        raise ValueError("MTM-009 may not change the 24 public / 11 hidden tool budget")

    schema_source = (ROOT / "crates" / "mtm-storage" / "src" / "schema.rs").read_text(encoding="utf-8")
    if "pub const STATE_SCHEMA_VERSION: i64 = 2;" not in schema_source:
        raise ValueError("MTM-009 Delivery 1 requires state schema version 2")

    contract_source = (ROOT / "crates" / "mtm-contracts" / "src" / "lib.rs").read_text(encoding="utf-8")
    if "pub const WORKFLOW_PROTOCOL_VERSION: u16 = 2;" not in contract_source:
        raise ValueError("MTM-009 Delivery 1 must not change the production workflow protocol")

    enum_source = (ROOT / "crates" / "mtm-contracts" / "src" / "enums.rs").read_text(encoding="utf-8")
    match = re.search(r"pub enum WorkflowState \{(?P<body>.*?)\n\}", enum_source, re.DOTALL)
    if match is None:
        raise ValueError("WorkflowState enum not found")
    variants = [line.strip().rstrip(",") for line in match.group("body").splitlines() if line.strip()]
    if variants != EXPECTED_WORKFLOW_STATES:
        raise ValueError(f"MTM-009 may not change workflow states: {variants}")

    vault_source = (ROOT / "crates" / "mtm-workflow" / "src" / "vault.rs").read_text(encoding="utf-8")
    channel_match = re.search(
        r"pub const GENERATION_CHANNELS: \[&str; \d+\] = \[(?P<body>.*?)\];",
        vault_source,
        re.DOTALL,
    )
    if channel_match is None:
        raise ValueError("generation memory channels not found")
    channels = set(re.findall(r'"([a-z_]+)"', channel_match.group("body")))
    if channels != EXPECTED_GENERATION_CHANNELS:
        raise ValueError("MTM-009 Delivery 1 may not add a research-state vault channel")

    for path in list((ROOT / "crates").rglob("*.rs")) + list(ROOT.rglob("Cargo.toml")):
        text = path.read_text(encoding="utf-8").lower()
        for pattern in FORBIDDEN_PRODUCTION_PATTERNS:
            if pattern in text:
                raise ValueError(f"forbidden model/Codex integration in production path: {path}: {pattern}")

    if "final/proof_verified.tex" not in vault_source:
        raise ValueError("verified .tex final artifact path changed")
    final_artifact = fixture.get("final_artifact", {})
    if final_artifact.get("vault_path_suffix") != "final/proof_verified.tex" or final_artifact.get("new_artifact_kinds") != 0:
        raise ValueError("MTM-009 final artifact contract is invalid")

    authority = fixture.get("authority_properties")
    required_authority = {
        "advisory_only": True,
        "projector_side_effect_free": True,
        "advice_can_transition": False,
        "advice_can_issue_capability": False,
        "advice_can_set_verdict": False,
        "advice_can_finalize": False,
        "route_solved_means_verified": False,
    }
    if authority != required_authority:
        raise ValueError("MTM-009 advisory authority contract drifted")

    reused = set(fixture.get("reused_generation_channels", []))
    if not reused or not reused.issubset(EXPECTED_GENERATION_CHANNELS):
        raise ValueError("MTM-009 must reuse only existing generation memory channels")

    workflow_lib = (ROOT / "crates" / "mtm-workflow" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    if "pub mod research_state;" not in workflow_lib:
        raise ValueError("MTM-009 pure research-state module is not exported")
    projector_path = ROOT / "crates" / "mtm-workflow" / "src" / "research_state.rs"
    projector_source = projector_path.read_text(encoding="utf-8")
    projector_lower = projector_source.lower()
    for pattern in FORBIDDEN_PROJECTOR_PATTERNS:
        if pattern in projector_lower:
            raise ValueError(
                f"research-state projector crossed its pure boundary: {pattern}"
            )
    for required in (
        "pub struct ResearchStateProjector;",
        "pub fn analyze(",
        "pub fn project(",
        "BTreeMap",
        "BTreeSet",
        "cycle_components",
        "topological_order",
        "dependency_closure",
        "actionable_frontier",
        "sha256:",
    ):
        if required not in projector_source:
            raise ValueError(f"research-state projector omits required pure fact: {required}")
    tests_path = (
        ROOT
        / "crates"
        / "mtm-workflow"
        / "src"
        / "research_state"
        / "tests.rs"
    )
    if not tests_path.is_file():
        raise ValueError("research-state edge tests must remain separated from production code")

    graph_fixture = json.loads(GRAPH_FIXTURE.read_text(encoding="utf-8"))
    if (
        graph_fixture.get("schema_version") != "1.0.0"
        or graph_fixture.get("case_id") != "chain-frontier"
    ):
        raise ValueError("MTM-009 research graph golden identity is invalid")
    expected_graph = graph_fixture.get("expected")
    if not isinstance(expected_graph, dict):
        raise ValueError("MTM-009 research graph golden expected payload is missing")
    graph_digest = expected_graph.get("digest")
    if (
        not isinstance(graph_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", graph_digest) is None
    ):
        raise ValueError("MTM-009 research graph golden digest is invalid")
    if expected_graph.get("topological_order") != ["a", "b", "target"]:
        raise ValueError("MTM-009 research graph golden ordering drifted")

    return {
        "planned_workflow_protocol": 3,
        "production_workflow_protocol": 2,
        "state_schema_version": 2,
        "workspace_crates": len(EXPECTED_MEMBERS),
        "public_tools": 24,
        "hidden_aliases": 11,
        "workflow_states": len(EXPECTED_WORKFLOW_STATES),
        "generation_channels": len(EXPECTED_GENERATION_CHANNELS),
        "zero_complexity_budgets": len(ZERO_BUDGET_KEYS),
        "final_artifact": "proof_verified.tex",
        "projector_pure_boundary": True,
        "generic_graph_dependencies": 0,
        "graph_golden_digest": graph_digest,
    }


def main() -> int:
    try:
        summary = validate()
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
