use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Flow {
    states: Vec<String>,
    sealed: bool,
    artifact_matches: bool,
    restart_resumed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompiledLatex {
    ok: bool,
    candidate_sha256: String,
    native_backend: String,
    hard_isolation_attested: bool,
    latex_policy: String,
    latexmk_used: bool,
    pdflatex_used: bool,
    shell_escape_disabled: bool,
    full_flow_compiled: bool,
    compact_flow_compiled: bool,
    repair_flow_compiled: bool,
    final_artifacts_verified: bool,
    flows: BTreeMap<String, Flow>,
    shell_escape_probe_routed_to_repair: bool,
    independent_mathematical_verification: bool,
    browser_human_consent_tested: bool,
    production_changed: bool,
    release_qualified: bool,
}

fn expected_states(name: &str) -> Option<Vec<String>> {
    match name {
        "compact" => Some(
            ["assess", "assemble", "verify", "done"]
                .map(str::to_owned)
                .to_vec(),
        ),
        "full" => Some(
            [
                "assess",
                "explore",
                "propose_plans",
                "direct_proving",
                "assemble",
                "verify",
                "done",
            ]
            .map(str::to_owned)
            .to_vec(),
        ),
        "repair" => Some(
            ["assess", "assemble", "verify", "repair", "verify", "done"]
                .map(str::to_owned)
                .to_vec(),
        ),
        _ => None,
    }
}

pub(crate) fn validate(stdout: &[u8], candidate: &str) -> Result<Value> {
    let text = std::str::from_utf8(stdout).map_err(|_| "qualification output is not UTF-8")?;
    for marker in [
        "MTM_TARGET_RUNTIME ",
        "MTM_RESOURCE_RUNTIME ",
        "MTM_UPGRADE_RUNTIME ",
        "MTM_PERMISSION_RUNTIME ",
        "MTM_USABILITY_CORPUS ",
        "MTM_INSTALL_SIGKILL ",
        "MTM_RETRIEVAL_RUNTIME ",
        "MTM_NATIVE_COMMAND_RUNTIME ",
    ] {
        if text.contains(marker) {
            return Err("compiled-LaTeX output contains foreign profile evidence".into());
        }
    }
    let report: CompiledLatex = extract(stdout, "MTM_COMPILED_LATEX_RUNTIME ")?;
    if !valid_hash(candidate)
        || !report.ok
        || report.candidate_sha256 != candidate
        || report.native_backend != "bubblewrap"
        || !report.hard_isolation_attested
        || report.latex_policy != "required"
        || !report.latexmk_used
        || !report.pdflatex_used
        || !report.shell_escape_disabled
        || !report.full_flow_compiled
        || !report.compact_flow_compiled
        || !report.repair_flow_compiled
        || !report.final_artifacts_verified
        || !report.shell_escape_probe_routed_to_repair
        || report.independent_mathematical_verification
        || report.browser_human_consent_tested
        || report.production_changed
        || report.release_qualified
        || report.flows.len() != 3
    {
        return Err("compiled-LaTeX summary has inconsistent identity or behavior".into());
    }
    for (name, flow) in &report.flows {
        if expected_states(name).as_ref() != Some(&flow.states)
            || !flow.sealed
            || !flow.artifact_matches
            || !flow.restart_resumed
        {
            return Err("compiled-LaTeX flow coverage or final artifact invalid".into());
        }
    }
    Ok(json!({
        "compiled_latex":extract::<Value>(stdout,"MTM_COMPILED_LATEX_RUNTIME ")?
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        let flow = |states: &[&str]| {
            json!({
                "states":states,"sealed":true,"artifact_matches":true,"restart_resumed":true
            })
        };
        json!({
            "ok":true,"candidate_sha256":"a".repeat(64),"native_backend":"bubblewrap",
            "hard_isolation_attested":true,"latex_policy":"required","latexmk_used":true,
            "pdflatex_used":true,"shell_escape_disabled":true,"full_flow_compiled":true,
            "compact_flow_compiled":true,"repair_flow_compiled":true,"final_artifacts_verified":true,
            "flows":{
                "compact":flow(&["assess","assemble","verify","done"]),
                "full":flow(&["assess","explore","propose_plans","direct_proving","assemble","verify","done"]),
                "repair":flow(&["assess","assemble","verify","repair","verify","done"])
            },
            "shell_escape_probe_routed_to_repair":true,"independent_mathematical_verification":false,
            "browser_human_consent_tested":false,"production_changed":false,"release_qualified":false
        })
    }

    #[test]
    fn compiled_latex_requires_all_routes_and_shell_escape_rejection() -> Result<()> {
        let good = fixture();
        let bytes = format!("MTM_COMPILED_LATEX_RUNTIME {good}\n").into_bytes();
        validate(&bytes, &"a".repeat(64))?;
        for pointer in [
            "/latexmk_used",
            "/pdflatex_used",
            "/shell_escape_disabled",
            "/full_flow_compiled",
            "/compact_flow_compiled",
            "/repair_flow_compiled",
            "/final_artifacts_verified",
            "/shell_escape_probe_routed_to_repair",
        ] {
            let mut changed = good.clone();
            *changed.pointer_mut(pointer).ok_or("fixture pointer")? = json!(false);
            let bytes = format!("MTM_COMPILED_LATEX_RUNTIME {changed}\n").into_bytes();
            assert!(validate(&bytes, &"a".repeat(64)).is_err());
        }
        Ok(())
    }
}
