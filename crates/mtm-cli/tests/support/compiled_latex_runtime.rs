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

fn require_stage(condition: bool, stage: &'static str, message: &'static str) -> Result {
    if condition {
        Ok(())
    } else {
        eprintln!("MTM_COMPILED_LATEX_DIAGNOSTIC stage={stage}");
        Err(message)
    }
}

fn completed_exec(
    server: &Server,
    owner: &Client,
    stage: &'static str,
    arguments: Value,
) -> Result<Value> {
    let result = server.call(owner, "exec_command", arguments)?;
    if !(result["ok"] == true && result["status"] == "exited" && result["exit_code"] == 0) {
        eprintln!(
            "MTM_COMPILED_LATEX_DIAGNOSTIC stage={stage} ok={} status={} exit_code={} signal={} error_code={}",
            result["ok"],
            result["status"],
            result["exit_code"],
            result["signal"],
            result["error"]["code"]
        );
        return Err("compiled-LaTeX executable check failed");
    }
    Ok(result)
}

fn check_environment(server: &Server, owner: &Client) -> Result {
    let environment = server.call(owner, "check_exec_environment", json!({}))?;
    require_stage(
        environment["ok"] == true
            && environment["native_mode"] == "dangerous"
            && environment["native_exec_backend"] == "BubblewrapExecBackend"
            && environment["hard_isolation_attested"] == true
            && environment["private_vault_visible"] == false,
        "environment",
        "compiled-LaTeX profile isolation drift",
    )
}

fn toolchain_checks(server: &Server, owner: &Client) -> Result {
    let latexmk = completed_exec(
        server,
        owner,
        "latexmk_version",
        json!({"argv":["latexmk","-v"],"yield_time_ms":30_000}),
    )?;
    require_stage(
        latexmk["stdout"]
            .as_str()
            .is_some_and(|value| !value.trim().is_empty())
            || latexmk["stderr"]
                .as_str()
                .is_some_and(|value| !value.trim().is_empty()),
        "latexmk_version_output",
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
        "pdflatex_compile",
        json!({
            "argv":["pdflatex","-interaction=nonstopmode","-halt-on-error","-no-shell-escape","pdflatex-check.tex"],
            "timeout_ms":120_000,"yield_time_ms":30_000
        }),
    )?;
    require_stage(
        server.workspace_path().join("pdflatex-check.pdf").is_file(),
        "pdflatex_artifact",
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
    require_stage(
        started["ok"] == true,
        "shell_escape_start",
        "shell-escape fixture start failed",
    )?;
    let run_id = text(&started, "run_id")?;
    let assess = server.call(owner, "rethlas_step", json!({"run_id":run_id}))?;
    require_stage(
        assess["state"] == "assess",
        "shell_escape_assess",
        "shell-escape fixture assessment missing",
    )?;
    let assemble = server.call(
        owner,
        "rethlas_step",
        candidate_lifecycle::fixture_submission(&assess, "compact", false)?,
    )?;
    require_stage(
        assemble["ok"] == true && assemble["state"] == "assemble",
        "shell_escape_assemble",
        "shell-escape fixture did not reach assemble",
    )?;
    let mut submission = candidate_lifecycle::fixture_submission(&assemble, "compact", false)?;
    replace_proof(&mut submission, UNSAFE_PROOF)?;
    let verify = server.call(owner, "rethlas_step", submission)?;
    require_stage(
        verify["ok"] == true && verify["state"] == "verify",
        "shell_escape_verify",
        "unsafe shell-escape proof bypassed verifier staging",
    )?;
    let rejected = server.call(
        owner,
        "rethlas_step",
        candidate_lifecycle::fixture_submission(&verify, "compact", false)?,
    )?;
    require_stage(
        rejected["ok"] == true && rejected["state"] == "repair",
        "shell_escape_repair",
        "unsafe shell-escape proof did not route to repair after verification",
    )?;
    require_stage(
        !server.workspace_path().join(export).exists()
            && !server
                .workspace_path()
                .join("shell-escape-leak.txt")
                .exists(),
        "shell_escape_side_effect",
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

    let compact = candidate_lifecycle::completed_flow(&mut server, &owner, "compact", false)
        .map_err(|_| {
            eprintln!("MTM_COMPILED_LATEX_DIAGNOSTIC stage=compact_flow");
            "compiled-LaTeX compact flow failed"
        })?;
    let full =
        candidate_lifecycle::completed_flow(&mut server, &owner, "full", false).map_err(|_| {
            eprintln!("MTM_COMPILED_LATEX_DIAGNOSTIC stage=full_flow");
            "compiled-LaTeX full flow failed"
        })?;
    let repair = candidate_lifecycle::completed_flow(&mut server, &owner, "compact", true)
        .map_err(|_| {
            eprintln!("MTM_COMPILED_LATEX_DIAGNOSTIC stage=repair_flow");
            "compiled-LaTeX repair flow failed"
        })?;
    shell_escape_rejected(&mut server, &owner).map_err(|_| {
        eprintln!("MTM_COMPILED_LATEX_DIAGNOSTIC stage=shell_escape_flow");
        "compiled-LaTeX shell-escape flow failed"
    })?;
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
