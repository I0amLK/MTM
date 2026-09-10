use super::*;
use serde::Deserialize;

const KINDS: [&str; 7] = [
    "sensitive_env",
    "destructive_command",
    "shell_expansion",
    "inline_script",
    "network",
    "long_timeout",
    "privileged_executable",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeCommands {
    ok: bool,
    candidate_sha256: String,
    native_backend: String,
    hard_isolation_attested: bool,
    safe_mode_passed: bool,
    trusted_mode_passed: bool,
    dangerous_mode_passed: bool,
    tty_stdin_passed: bool,
    timeout_kill_passed: bool,
    descendant_cleanup_passed: bool,
    sage_functional_passed: bool,
    magma_functional_passed: bool,
    command_permission_kinds: Vec<String>,
    permission_kinds_granted: u64,
    permission_soak_cycles: u64,
    permission_grant_soak_passed: bool,
    scripted_consent_only: bool,
    browser_human_consent_tested: bool,
    production_changed: bool,
    release_qualified: bool,
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
        "MTM_COMPILED_LATEX_RUNTIME ",
    ] {
        if text.contains(marker) {
            return Err("Native command output contains foreign profile evidence".into());
        }
    }
    let report: NativeCommands = extract(stdout, "MTM_NATIVE_COMMAND_RUNTIME ")?;
    if !valid_hash(candidate)
        || !report.ok
        || report.candidate_sha256 != candidate
        || report.native_backend != "bubblewrap"
        || !report.hard_isolation_attested
        || !report.safe_mode_passed
        || !report.trusted_mode_passed
        || !report.dangerous_mode_passed
        || !report.tty_stdin_passed
        || !report.timeout_kill_passed
        || !report.descendant_cleanup_passed
        || !report.sage_functional_passed
        || !report.magma_functional_passed
        || report.command_permission_kinds != KINDS
        || report.permission_kinds_granted != 7
        || report.permission_soak_cycles != 32
        || !report.permission_grant_soak_passed
        || !report.scripted_consent_only
        || report.browser_human_consent_tested
        || report.production_changed
        || report.release_qualified
    {
        return Err("Native command summary has inconsistent identity or behavior".into());
    }
    Ok(json!({
        "native_commands":extract::<Value>(stdout,"MTM_NATIVE_COMMAND_RUNTIME ")?
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        json!({
            "ok":true,"candidate_sha256":"a".repeat(64),"native_backend":"bubblewrap",
            "hard_isolation_attested":true,"safe_mode_passed":true,"trusted_mode_passed":true,
            "dangerous_mode_passed":true,"tty_stdin_passed":true,"timeout_kill_passed":true,
            "descendant_cleanup_passed":true,"sage_functional_passed":true,"magma_functional_passed":true,
            "command_permission_kinds":KINDS,"permission_kinds_granted":7,"permission_soak_cycles":32,
            "permission_grant_soak_passed":true,"scripted_consent_only":true,
            "browser_human_consent_tested":false,"production_changed":false,"release_qualified":false
        })
    }

    #[test]
    fn every_native_command_claim_is_required() -> Result<()> {
        let good = fixture();
        let bytes = format!("MTM_NATIVE_COMMAND_RUNTIME {good}\n").into_bytes();
        validate(&bytes, &"a".repeat(64))?;
        for pointer in [
            "/safe_mode_passed",
            "/trusted_mode_passed",
            "/dangerous_mode_passed",
            "/tty_stdin_passed",
            "/timeout_kill_passed",
            "/descendant_cleanup_passed",
            "/sage_functional_passed",
            "/magma_functional_passed",
            "/permission_grant_soak_passed",
        ] {
            let mut changed = good.clone();
            *changed.pointer_mut(pointer).ok_or("fixture pointer")? = json!(false);
            let bytes = format!("MTM_NATIVE_COMMAND_RUNTIME {changed}\n").into_bytes();
            assert!(validate(&bytes, &"a".repeat(64)).is_err());
        }
        Ok(())
    }
}
