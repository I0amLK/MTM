//! Exact-candidate required-LaTeX qualification on a capable Native host.
//! Workflow submissions are scripted fixtures, not independent mathematical review.
use std::env;
use std::fs;

use serde_json::{Value, json};

use crate::candidate_lifecycle;
use crate::support::candidate;
use crate::support::loopback::{Client, Server};
use crate::support::{Result, require, text};

const ENABLE: &str = "MTM_TEST_COMPILED_LATEX_PROFILE";
const UNSAFE_PROOF: &str = r"\documentclass{article}
\begin{document}
\immediate\write18{printf leaked > shell-escape-leak.txt}
Unsafe shell escape must never reach finalization.
\end{document}
";

fn completed_exec(server: &Server, owner: &Client, arguments: Value) -> Result<Value> {
    let result = server.call(owner, "exec_command", arguments)?;
    require(
        result["ok"] == true && result["status"] == "exited" && result["exit_code"] == 0,
        "compiled-LaTeX executable check failed",
    )?;
    Ok(result)
}

fn check_environment(server: &Server, owner: &Client) -> Result {
    let environment = server.call(owner, "check_exec_environment", json!({}))?;
    require(
        environment["ok"] == true
            && environment["native_mode"] == "dangerous"
            && environment["native_exec_backend"] == "BubblewrapExecBackend"
            && environment["hard_isolation_attested"] == true
            && environment["private_vault_visible"] == false,
        "compiled-LaTeX profile isolation drift",
    )
}

fn toolchain_checks(server: &Server, owner: &Client) -> Result {
    let latexmk = completed_exec(
        server,
        owner,
        json!({"argv":["latexmk","-v"],"yield_time_ms":30_000}),
    )?;
    require(
        latexmk["stdout"]
            .as_str()
            .is_some_and(|value| !value.trim().is_empty())
            || latexmk["stderr"]
                .as_str()
                .is_some_and(|value| !value.trim().is_empty()),
        "latexmk version output missing",
    )?;

    let tex = server.workspace_path().join("pdflatex-check.tex");
    fs::write(
        &tex,
        b"\\documentclass{article}\n\\begin{document}42\\end{document}\n",
    )
    .map_err(|_| "pdflatex fixture write failed")?;
    completed_exec(
        server,
        owner,
        json!({
            "argv":["pdflatex","-interaction=nonstopmode","-halt-on-error","-no-shell-escape","pdflatex-check.tex"],
            "timeout_ms":120_000,"yield_time_ms":30_000
        }),
    )?;
    require(
        server.workspace_path().join("pdflatex-check.pdf").is_file(),
        "pdflatex did not produce the expected PDF",
    )
}

fn replace_proof(submission: &mut Value, proof: &str) -> Result {
    let writes = submission["writes"]
        .as_array_mut()
        .ok_or("assemble fixture writes missing")?;
    let proof_write = writes
        .iter_mut()
        .find(|write| write["resource"] == "proof")
        .ok_or("assemble fixture proof write missing")?;
    proof_write["content"] = json!(proof);
    Ok(())
}

fn shell_escape_rejected(server: &mut Server, owner: &Client) -> Result {
    let export = "qualification/shell-escape/proof_verified.tex";
    let started = server.call(
        owner,
        "rethlas_start",
        json!({
            "problem_tex":"\\begin{proposition}Prove $1=1$.\\end{proposition}",
            "problem_id":"compiled-latex-shell-escape",
            "workflow_mode":"compact",
            "register_result":false,
            "export_path":export
        }),
    )?;
    require(started["ok"] == true, "shell-escape fixture start failed")?;
    let run_id = text(&started, "run_id")?;
    let assess = server.call(owner, "rethlas_step", json!({"run_id":run_id}))?;
    require(
        assess["state"] == "assess",
        "shell-escape fixture assessment missing",
    )?;
    let assemble = server.call(
        owner,
        "rethlas_step",
        candidate_lifecycle::fixture_submission(&assess, "compact", false)?,
    )?;
    require(
        assemble["ok"] == true && assemble["state"] == "assemble",
        "shell-escape fixture did not reach assemble",
    )?;
    let mut submission = candidate_lifecycle::fixture_submission(&assemble, "compact", false)?;
    replace_proof(&mut submission, UNSAFE_PROOF)?;
    let verify = server.call(owner, "rethlas_step", submission)?;
    require(
        verify["ok"] == true && verify["state"] == "verify",
        "unsafe shell-escape proof bypassed verifier staging",
    )?;
    let rejected = server.call(
        owner,
        "rethlas_step",
        candidate_lifecycle::fixture_submission(&verify, "compact", false)?,
    )?;
    require(
        rejected["ok"] == true && rejected["state"] == "repair",
        "unsafe shell-escape proof did not route to repair after verification",
    )?;
    require(
        !server.workspace_path().join(export).exists()
            && !server
                .workspace_path()
                .join("shell-escape-leak.txt")
                .exists(),
        "unsafe shell-escape proof produced a final artifact or command side effect",
    )
}

#[test]
fn exact_candidate_required_latex_full_compact_and_repair() -> Result {
    if env::var_os(ENABLE).is_none() {
        return Ok(());
    }
    require(
        env::var(ENABLE).ok().as_deref() == Some("1"),
        "compiled-LaTeX profile flag must be exactly one",
    )?;
    let candidate = candidate::select()?;
    let mut server = Server::start_compiled_latex(&candidate.path)?;
    let owner = server.login()?;
    check_environment(&server, &owner)?;
    toolchain_checks(&server, &owner)?;

    let compact = candidate_lifecycle::completed_flow(&mut server, &owner, "compact", false)?;
    let full = candidate_lifecycle::completed_flow(&mut server, &owner, "full", false)?;
    let repair = candidate_lifecycle::completed_flow(&mut server, &owner, "compact", true)?;
    shell_escape_rejected(&mut server, &owner)?;
    server.stop()?;
    candidate.unchanged()?;

    let report = json!({
        "ok":true,
        "candidate_sha256":candidate.sha256,
        "native_backend":"bubblewrap",
        "hard_isolation_attested":true,
        "latex_policy":"required",
        "latexmk_used":true,
        "pdflatex_used":true,
        "shell_escape_disabled":true,
        "full_flow_compiled":full["states"] == json!(["assess","explore","propose_plans","direct_proving","assemble","verify","done"]),
        "compact_flow_compiled":compact["states"] == json!(["assess","assemble","verify","done"]),
        "repair_flow_compiled":repair["states"] == json!(["assess","assemble","verify","repair","verify","done"]),
        "final_artifacts_verified":full["artifact_matches"] == true && compact["artifact_matches"] == true && repair["artifact_matches"] == true,
        "flows":{"full":full,"compact":compact,"repair":repair},
        "shell_escape_probe_routed_to_repair":true,
        "independent_mathematical_verification":false,
        "browser_human_consent_tested":false,
        "production_changed":false,
        "release_qualified":false
    });
    println!("MTM_COMPILED_LATEX_RUNTIME {report}");
    Ok(())
}
