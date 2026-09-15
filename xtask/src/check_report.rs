//! Current-run conclusions only. Historical attribution requires reviewed evidence.
use serde_json::{Value, json};

const REQUIRED: [&str; 4] = ["format", "clippy", "rust_tests", "diff"];

fn outcome(checks: &[Value], name: &str) -> Option<bool> {
    let mut matched = checks.iter().filter(|check| check["name"] == name);
    let check = matched.next()?;
    if matched.next().is_some() {
        return None;
    }
    match (check["passed"].as_bool(), check["exit_code"].as_i64()) {
        (Some(true), Some(0)) => Some(true),
        (Some(false), Some(code)) if code != 0 => Some(false),
        (Some(false), None) if check.get("exit_code") == Some(&Value::Null) => Some(false),
        _ => None,
    }
}

pub(crate) fn summarize(checks: &[Value], native: &Value, source_unchanged: bool) -> Value {
    let environment_ready = native["passed"] == true && native["ready_for_native_tests"] == true;
    let tests = outcome(checks, "rust_tests");
    let all_checks_passed = checks.len() == REQUIRED.len()
        && REQUIRED
            .iter()
            .all(|name| outcome(checks, name) == Some(true));
    let interpretation = match (environment_ready, tests) {
        (true, Some(true)) => "workspace_command_passed_with_native_prerequisites",
        (true, Some(false)) => "workspace_command_failed_on_ready_environment",
        (false, Some(true)) => "workspace_command_passed_but_native_prerequisites_blocked",
        (false, Some(false)) => "workspace_command_failed_with_native_prerequisites_blocked",
        (_, None) => "workspace_command_outcome_missing_or_inconsistent",
    };
    json!({
        "scope":"current_run_not_historical_failure_attribution",
        "passed":all_checks_passed && environment_ready && source_unchanged,
        "native_environment_ready":environment_ready,
        "workspace_test_command_passed":tests,
        "required_checks_passed":all_checks_passed,
        "source_unchanged":source_unchanged,
        "interpretation":interpretation,
        "individual_test_counts_recorded":false,
        "previous_failure_attribution":"not_inferred_without_comparing_sealed_runs",
        "exact_candidate_release_qualified":false
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checks() -> Vec<Value> {
        REQUIRED
            .iter()
            .map(|name| json!({"name":name,"passed":true,"exit_code":0}))
            .collect()
    }

    #[test]
    fn current_host_success_is_distinct_from_historical_attribution() {
        let native = json!({"passed":true,"ready_for_native_tests":true});
        let result = summarize(&checks(), &native, true);
        assert_eq!(result["passed"], true);
        assert_eq!(result["workspace_test_command_passed"], true);
        assert_eq!(
            result["previous_failure_attribution"],
            "not_inferred_without_comparing_sealed_runs"
        );
        assert_eq!(result["exact_candidate_release_qualified"], false);
    }

    #[test]
    fn blocked_environment_does_not_erase_product_failure_or_create_success() {
        let mut checks = checks();
        for native in [json!({}), json!({"passed":false}), json!({"passed":true})] {
            assert_eq!(summarize(&checks, &native, true)["passed"], false);
        }
        checks[2] = json!({"name":"rust_tests","passed":false,"exit_code":101});
        let result = summarize(&checks, &json!({"passed":false}), true);
        assert_eq!(result["workspace_test_command_passed"], false);
        assert_eq!(
            result["interpretation"],
            "workspace_command_failed_with_native_prerequisites_blocked"
        );
    }

    #[test]
    fn missing_duplicate_inconsistent_or_forged_checks_never_pass() {
        let ready = json!({"passed":true,"ready_for_native_tests":true});
        assert_eq!(summarize(&[], &ready, true)["passed"], false);
        for replacement in [
            json!({"name":"rust_tests","passed":true,"exit_code":101}),
            json!({"name":"rust_tests","passed":true}),
            json!({"name":"format","passed":true,"exit_code":0}),
            json!({"name":"unknown","passed":true,"exit_code":0}),
        ] {
            let mut changed = checks();
            changed[2] = replacement;
            let result = summarize(&changed, &ready, true);
            assert_eq!(result["passed"], false);
            assert!(result["workspace_test_command_passed"].is_null());
        }
        let mut extra = checks();
        extra.push(json!({"name":"rust_tests","passed":true,"exit_code":0}));
        assert_eq!(summarize(&extra, &ready, true)["passed"], false);
    }

    #[test]
    fn changed_sources_and_signalled_tests_are_not_successful_qualification() {
        let ready = json!({"passed":true,"ready_for_native_tests":true});
        assert_eq!(summarize(&checks(), &ready, false)["passed"], false);
        let mut signalled = checks();
        signalled[2] = json!({"name":"rust_tests","passed":false,"exit_code":null});
        let result = summarize(&signalled, &ready, true);
        assert_eq!(result["passed"], false);
        assert_eq!(result["workspace_test_command_passed"], false);
    }
}
