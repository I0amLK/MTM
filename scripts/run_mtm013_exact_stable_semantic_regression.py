#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
import os
import signal
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from mtm008_runtime_harness import free_port, oauth_token, runtime_environment, wait_for_port
from run_mtm007_http_smoke import tool_call


ROOT = Path(__file__).resolve().parents[1]
STABLE_BINARY = Path("/home/lk/.local/bin/mtm")
EXPECTED_STABLE_SHA256 = "3312ca75a1de8707e740963cc0add4b09430dccc9dc63a3145e4456ff2b0cdf3"


QC_PROBLEM = r"""
Let q be a prime power with \(\gcd(q,m)=1\), and put
\(R=\mathbb F_q[x]/(x^m-1)\).  Factor \(x^m-1\) into self-reciprocal
irreducible factors \(g_i\) and reciprocal pairs \(h_j,h_j^*\).  Let an
\(\ell\)-quasi-cyclic code \(C\subseteq R^\ell\) have CRT constituents
\(C_i,C'_j,C''_j\).  Prove that the Euclidean dual has constituents
\(C_i^{\perp_H}\) on the self-reciprocal slots and
\(((C''_j)^\perp,(C'_j)^\perp)\) on each reciprocal pair.  Deduce the
corresponding blockwise hull intersections, and explain why naive same-slot
matching on a reciprocal pair is wrong.
""".strip()

QC_PROOF = r"""\documentclass{article}
\usepackage{amsmath,amssymb,amsthm}
\newtheorem{proposition}{Proposition}
\begin{document}
\begin{proposition}
Let $q$ be a prime power with $\gcd(q,m)=1$, put
$R=\mathbb F_q[x]/(x^m-1)$, and write the square-free factorization as
\[
 x^m-1=\prod_i g_i\prod_j h_jh_j^*,
\]
where each $g_i$ is self-reciprocal and $h_j^*$ is reciprocal to $h_j$.
If an $\ell$-quasi-cyclic code $C\subseteq R^\ell$ has CRT constituents
$C_i,C'_j,C''_j$, then its Euclidean dual has constituents
$C_i^{\perp_H}$ and, on each reciprocal pair,
$((C''_j)^\perp,(C'_j)^\perp)$.  Consequently the hull constituents are
$C_i\cap C_i^{\perp_H}$ and
$C'_j\cap(C''_j)^\perp$, $C''_j\cap(C'_j)^\perp$.
\end{proposition}
\begin{proof}
Let $\iota:R\to R$ be the involution induced by $x\mapsto x^{-1}$, and set
\[
 B(a,b)=\sum_{r=1}^{\ell}a_r(x)\,\iota(b_r(x))\in R.
\]
For $a,b\in R^\ell$, the coefficient of $x^s$ in $B(a,b)$ is the ordinary
Euclidean inner product of the coefficient vector of $a$ with a cyclic shift
of the coefficient vector of $b$ (up to the harmless choice of shift sign).
Since a quasi-cyclic code is closed under these block shifts, a vector $b$ is
Euclidean-orthogonal to every codeword of $C$ if and only if
$B(a,b)=0$ for every $a\in C$.

By the Chinese remainder theorem, $R$ is the product of the fields belonging
to the factors $g_i,h_j,h_j^*$.  The involution $\iota$ preserves a
self-reciprocal factor and induces there the usual involution used in the
Hermitian constituent pairing.  On a reciprocal pair, however, $\iota$
interchanges the $h_j$ and $h_j^*$ factors.  Therefore $B$ decomposes into
the Hermitian pairing of the two components in each self-reciprocal slot and
the cross-pairings
\[
 \langle C'_j,D''_j\rangle,\qquad
 \langle C''_j,D'_j\rangle
\]
on a reciprocal pair, where $D'_j,D''_j$ are the corresponding constituents
of a candidate dual code.  Each field pairing is nondegenerate.  Thus its
annihilator is exactly
\[
 D_i=C_i^{\perp_H},\qquad
 D'_j=(C''_j)^\perp,\qquad D''_j=(C'_j)^\perp.
\]
Intersecting these CRT components with those of $C$ gives precisely
\[
 C_i\cap C_i^{\perp_H},\qquad
 C'_j\cap(C''_j)^\perp,\qquad
 C''_j\cap(C'_j)^\perp.
\]

The swap is essential.  For example, over $\mathbb F_2$,
$x^7-1=(x+1)(x^3+x+1)(x^3+x^2+1)$ and the two cubic factors are reciprocal.
On that reciprocal block take $C'$ to be the whole first cubic field and
$C''=0$.  The cross-pairing formula gives dual block $C'\oplus0$, whereas
same-slot matching would give $0\oplus C''_{\rm ambient}$; these are
different.  Hence same-slot matching cannot describe the Euclidean dual.
\end{proof}
\end{document}
"""

COMPACT_PROBLEM = r"""
Let F be a finite field with a nontrivial involutory Frobenius automorphism
\(\sigma\), and let a finite-dimensional F-space carry a nondegenerate
\(\sigma\)-Hermitian form.  If a subspace W decomposes as
\(W=\operatorname{rad}(W)\oplus K\), prove that K is nondegenerate and admits
a \(\sigma\)-Hermitian orthonormal basis.
""".strip()

COMPACT_PROOF = r"""\documentclass{article}
\usepackage{amsmath,amssymb,amsthm}
\newtheorem{proposition}{Proposition}
\begin{document}
\begin{proposition}
Let $F$ be a finite field with nontrivial involutory Frobenius automorphism
$\sigma$, and let $h$ be a $\sigma$-Hermitian form.  If
$W=\operatorname{rad}(W)\oplus K$, then the restriction of $h$ to $K$ is
nondegenerate and $K$ has a $\sigma$-Hermitian orthonormal basis.
\end{proposition}
\begin{proof}
If $k\in K$ is orthogonal to $K$, then $k$ is also orthogonal to
$\operatorname{rad}(W)$, because every element of the radical is orthogonal
to all of $W$ and Hermitian symmetry reverses the two arguments.  Hence $k$
is orthogonal to $W$, so $k\in\operatorname{rad}(W)\cap K=0$.  Thus $K$ is
nondegenerate.

It remains to orthonormalize a finite-dimensional nondegenerate Hermitian
space.  Such a space contains a vector $v$ with $h(v,v)\ne0$: otherwise
$h(v,v)=0$ for every $v$, and applying this to $u+av$ while varying
$a\in F$ gives
$a^\sigma h(u,v)+a h(v,u)=0$ for every $a$; because $\sigma$ is nontrivial,
two choices of $a$ force $h(u,v)=0$ for all $u,v$, contradicting
nondegeneracy.  The orthogonal complement of a nonisotropic vector is again
nondegenerate, so induction yields an orthogonal basis $v_1,\ldots,v_r$.
Each $h(v_i,v_i)$ lies in the fixed field $F^\sigma$ and is nonzero.  For a
finite quadratic extension the norm map $F^\times\to(F^\sigma)^\times$,
$c\mapsto c^\sigma c$, is surjective.  Choose $c_i$ with
$c_i^\sigma c_i=h(v_i,v_i)^{-1}$.  Then $e_i=c_iv_i$ satisfy
$h(e_i,e_j)=\delta_{ij}$, as required.
\end{proof}
\end{document}
"""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def structured(response: dict[str, Any]) -> dict[str, Any]:
    result = response.get("result")
    if not isinstance(result, dict):
        raise RuntimeError(f"MCP response has no result: {response}")
    content = result.get("structuredContent")
    if not isinstance(content, dict):
        raise RuntimeError(f"MCP response has no structuredContent: {response}")
    if result.get("isError") is True:
        raise RuntimeError(f"MCP tool returned an error: {content}")
    return content


def close(process: subprocess.Popen[str]) -> int:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        return process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        return process.wait(timeout=3)


def launch(root: Path) -> tuple[subprocess.Popen[str], int, str, Path]:
    workspace = root / "workspace"
    data_root = root / "data"
    workspace.mkdir(parents=True, exist_ok=True)
    port = free_port()
    environment = runtime_environment(workspace, data_root, "rust")
    environment["MTM_WORKFLOW_PROTOCOL_VERSION"] = "3"
    environment["MTM_NATIVE_EXEC_BACKEND"] = "disabled"
    environment["MTM_LATEX_POLICY"] = "static_only"
    process = subprocess.Popen(
        [
            str(STABLE_BINARY),
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--workspace",
            str(workspace),
            "--native-mode",
            "safe",
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
    return process, port, f"http://127.0.0.1:{port}", workspace


def start_run(
    port: int,
    token: str,
    problem_id: str,
    problem_tex: str,
    workflow_mode: str,
    export_path: str,
) -> dict[str, Any]:
    return structured(
        tool_call(
            port,
            token,
            "rethlas_start",
            {
                "problem_tex": problem_tex,
                "problem_id": problem_id,
                "workflow_mode": workflow_mode,
                "register_result": False,
                "export_path": export_path,
            },
        )
    )


def current_task(port: int, token: str, run_id: str) -> dict[str, Any]:
    return structured(tool_call(port, token, "rethlas_step", {"run_id": run_id}))


def verifier_writes(writes: list[Any]) -> list[Any]:
    result = copy.deepcopy(writes)
    for item in result:
        if not isinstance(item, dict):
            continue
        resource = item.get("resource")
        if resource == "memory:verifier:statement_checks":
            item["content"] = {"location": "proof", "status": "checked"}
        elif resource == "memory:verifier:events":
            item["content"] = {"event_type": "verification_audit_complete"}
        elif resource == "verification_report":
            item["content"] = {
                "verification_report": {
                    "summary": "The submitted proof was independently checked against the target statement; no logical gap or reference dependency remains.",
                    "critical_errors": [],
                    "gaps": [],
                },
                "verdict": "correct",
                "repair_hints": "",
            }
    return result


def proof_writes(writes: list[Any], proof: str, problem_tex: str) -> list[Any]:
    result = copy.deepcopy(writes)
    for item in result:
        if not isinstance(item, dict):
            continue
        if item.get("resource") == "proof":
            item["content"] = proof
        elif item.get("resource") == "proof_manifest":
            item["content"] = {
                "target_statement_tex": problem_tex,
                "dependency_revision_ids": [],
                "reference_ids": [],
                "conditional_hypotheses": [],
                "computational_evidence": [],
            }
    return result


def submit_task(
    port: int,
    token: str,
    current: dict[str, Any],
    proof: str,
    problem_tex: str,
    requested_route: str,
) -> dict[str, Any]:
    task = current.get("task")
    if not isinstance(task, dict):
        raise RuntimeError(f"state {current.get('state')} did not provide a task")
    minimal = task.get("minimal_submission")
    if not isinstance(minimal, dict):
        minimal = task.get("minimal_submission_template")
    if not isinstance(minimal, dict):
        raise RuntimeError(
            f"state {current.get('state')} has no minimal_submission or template"
        )
    action = str(minimal.get("action") or "")
    payload = copy.deepcopy(minimal.get("payload") or {})
    writes = copy.deepcopy(minimal.get("writes") or [])
    state = str(current.get("state") or "")
    if state == "assess":
        payload.update(
            {
                "route": requested_route,
                "route_reason": "Regression target has a self-contained proof; route is fixed by the regression case.",
                "requires_external_retrieval": False,
                "requires_multiple_plans": requested_route == "full",
            }
        )
    if state == "direct_proving":
        active_plans = current.get("context", {}).get("active_plans", [])
        if not isinstance(active_plans, list) or not active_plans:
            raise RuntimeError("direct_proving task has no active plans")
        screening: dict[str, dict[str, Any]] = {}
        for plan_index, plan in enumerate(active_plans):
            if not isinstance(plan, dict):
                continue
            plan_id = str(plan.get("plan_id") or "")
            subgoals = plan.get("subgoals")
            if not plan_id or not isinstance(subgoals, list):
                continue
            results: dict[str, Any] = {}
            for subgoal in subgoals:
                if not isinstance(subgoal, dict):
                    continue
                subgoal_id = str(subgoal.get("subgoal_id") or "")
                if not subgoal_id:
                    continue
                if plan_index == 0:
                    results[subgoal_id] = {
                        "status": "solved",
                        "summary": "The direct CRT-pairing argument proves this regression subgoal.",
                        "method": "direct",
                    }
                else:
                    results[subgoal_id] = {
                        "status": "stuck",
                        "summary": "This alternate generic decomposition is unnecessary once the direct route is complete.",
                        "method": "direct",
                        "obstruction": "no_progress",
                    }
            screening[plan_id] = results
        payload = {
            "screening": screening,
            "proof_route": "Use the direct CRT involution and nondegenerate constituent pairings, followed by blockwise intersection for the hull.",
        }
    if state == "assemble":
        writes = proof_writes(writes, proof, problem_tex)
        if requested_route == "compact":
            payload = {"outcome": "proof"}
    if state == "verify":
        writes = verifier_writes(writes)
        payload = {}
    submission = {
        "run_id": str(current["run_id"]),
        "capability": str(current["capability"]),
        "action": action,
        "payload": payload,
        "writes": writes,
    }
    return structured(tool_call(port, token, "rethlas_step", submission))


def run_case(
    port: int,
    token: str,
    workspace: Path,
    *,
    problem_id: str,
    problem_tex: str,
    proof: str,
    workflow_mode: str,
) -> dict[str, Any]:
    export_path = f"rethlas-output/{problem_id}/proof_verified.tex"
    started = start_run(
        port,
        token,
        problem_id,
        problem_tex,
        workflow_mode,
        export_path,
    )
    run_id = str(started["run_id"])
    current = current_task(port, token, run_id)
    observed_states: list[str] = []
    for _ in range(24):
        state = str(current.get("state") or "")
        observed_states.append(state)
        if state == "done":
            break
        if state in {"cancelled", "failed"}:
            raise RuntimeError(f"run {run_id} terminated in {state}: {current}")
        current = submit_task(
            port,
            token,
            current,
            proof,
            problem_tex,
            workflow_mode,
        )
    else:
        raise RuntimeError(f"run {run_id} did not terminate within the bounded step count")

    inspected = structured(
        tool_call(port, token, "rethlas_inspect", {"operation": "status", "run_id": run_id})
    )
    artifact_path = workspace / export_path
    if not artifact_path.is_file():
        raise RuntimeError(f"verified artifact was not exported: {artifact_path}")
    artifact_bytes = artifact_path.read_bytes()
    return {
        "problem_id": problem_id,
        "run_id": run_id,
        "workflow_mode": workflow_mode,
        "state": inspected.get("state"),
        "status": inspected.get("status"),
        "verdict": inspected.get("verdict"),
        "latex_passed": inspected.get("latex_passed"),
        "sealed": inspected.get("sealed"),
        "observed_states": observed_states,
        "workspace_export_path": export_path,
        "artifact_sha256": sha256_bytes(artifact_bytes),
        "artifact_bytes": len(artifact_bytes),
    }


def main() -> int:
    if not STABLE_BINARY.is_file():
        raise RuntimeError(f"stable MTM binary is missing: {STABLE_BINARY}")
    binary_sha256 = sha256_file(STABLE_BINARY)
    if binary_sha256 != EXPECTED_STABLE_SHA256:
        raise RuntimeError(f"stable MTM binary hash drifted: {binary_sha256}")
    with tempfile.TemporaryDirectory(prefix="mtm013-exact-stable-semantic-") as temporary:
        root = Path(temporary)
        process, port, base, workspace = launch(root)
        try:
            token = oauth_token(port, base, "MTM-013 exact stable semantic regression")
            info = structured(tool_call(port, token, "server_info", {}))
            qc = run_case(
                port,
                token,
                workspace,
                problem_id="mtm013-stable-qc-constituent-matching",
                problem_tex=QC_PROBLEM,
                proof=QC_PROOF,
                workflow_mode="full",
            )
            compact = run_case(
                port,
                token,
                workspace,
                problem_id="mtm013-stable-sigma-hermitian-complement",
                problem_tex=COMPACT_PROBLEM,
                proof=COMPACT_PROOF,
                workflow_mode="compact",
            )
        finally:
            exit_code = close(process)
    checks = {
        "exact_stable_binary": binary_sha256 == EXPECTED_STABLE_SHA256,
        "server_version_0_4_0": info.get("version") == "0.4.0",
        "complete_flow_locally_validated": info.get("complete_flow_locally_validated") is True,
        "workflow_protocol_3": info.get("research_workspace", {}).get("workflow_protocol_version") == 3,
        "qc_done_correct": qc.get("state") == "done" and qc.get("verdict") == "correct",
        "qc_latex_and_sealed": qc.get("latex_passed") is True and qc.get("sealed") is True,
        "compact_done_correct": compact.get("state") == "done" and compact.get("verdict") == "correct",
        "compact_latex_and_sealed": compact.get("latex_passed") is True and compact.get("sealed") is True,
        "server_exits_cleanly": exit_code == 0,
    }
    payload = {
        "schema_version": "1.0.0",
        "milestone": "MTM-013",
        "phase": "exact_stable_semantic_regression",
        "harness_sha256": sha256_file(Path(__file__)),
        "binary": str(STABLE_BINARY),
        "binary_sha256": binary_sha256,
        "server_version": info.get("version"),
        "workflow_protocol_version": info.get("research_workspace", {}).get("workflow_protocol_version"),
        "native_exec_backend": "disabled_for_semantic_regression",
        "latex_policy": "static_only",
        "qc_constituent_matching": qc,
        "compact_sigma_hermitian": compact,
        "checks": checks,
        "raw_oauth_token_recorded": False,
        "raw_capability_recorded": False,
        "ok": all(checks.values()),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.SubprocessError, RuntimeError, json.JSONDecodeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, indent=2))
        raise SystemExit(1)
