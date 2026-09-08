//! Explicit target-profile fixture. It is inert during ordinary source tests.
//! The verifier writes are scripted, so this is Native/LaTeX/runtime acceptance,
//! not independent mathematical verification or release qualification.
use std::env;

use serde_json::json;

use crate::candidate_lifecycle;
use crate::support::candidate;
use crate::support::loopback::Server;
use crate::support::{Result, require, text};

const ENABLE: &str = "MTM_TEST_TARGET_PROFILE";

#[test]
fn exact_candidate_native_and_compiled_latex_target_profile() -> Result {
    if env::var_os(ENABLE).is_none() {
        return Ok(());
    }
    require(
        env::var(ENABLE).ok().as_deref() == Some("1"),
        "target profile flag must be exactly one",
    )?;
    let candidate = candidate::select()?;
    let mut server = Server::start_target(&candidate.path)?;
    let owner = server.login()?;

    let environment = server.call(&owner, "check_exec_environment", json!({}))?;
    require(
        environment["ok"] == true
            && environment["native_mode"] == "dangerous"
            && environment["native_exec_backend"] == "BubblewrapExecBackend"
            && environment["hard_isolation_attested"] == true
            && environment["private_vault_visible"] == false,
        "target Native environment was not the attested Bubblewrap profile",
    )?;

    // Dangerous mode is explicitly the no-elicitation target profile. The call
    // still traverses the public OAuth/MCP tool boundary and the production Native
    // authority/executor; it does not invoke a private test-only executor method.
    let executed = server.call(
        &owner,
        "exec_command",
        json!({
            "argv":["/usr/bin/printf","candidate-native-ok"],
            "yield_time_ms":30_000
        }),
    )?;
    require(
        executed["ok"] == true
            && executed["status"] == "exited"
            && executed["exit_code"] == 0
            && text(&executed, "stdout")? == "candidate-native-ok",
        "public Native command did not complete inside the candidate sandbox",
    )?;

    // In this server profile LatexPolicy::Required is fixed before launch. A done,
    // sealed flow with latex_passed=true therefore requires the isolated latexmk
    // compile gate; static-only fallback cannot satisfy this fixture.
    let flow = candidate_lifecycle::completed_flow(&mut server, &owner, "compact", false)?;
    require(
        flow["states"] == json!(["assess", "assemble", "verify", "done"])
            && flow["sealed"] == true
            && flow["artifact_matches"] == true
            && flow["restart_resumed"] == true,
        "compiled-LaTeX target flow did not complete its fixed route",
    )?;

    server.stop()?;
    candidate.unchanged()?;
    let report = json!({
        "ok":true,
        "binary_sha256":candidate.sha256,
        "native_execution_tested":true,
        "native_mode":"dangerous",
        "native_backend":"bubblewrap",
        "hard_isolation_attested":true,
        "private_vault_visible":false,
        "compiled_latex_tested":true,
        "latex_policy":"required",
        "flow":flow,
        "web_client_tested":false,
        "independent_mathematical_verification":false,
        "resource_non_regression_tested":false,
        "install_or_selector_changed":false,
        "release_qualified":false
    });
    println!("MTM_TARGET_RUNTIME {report}");
    Ok(())
}
