use std::collections::{BTreeMap, BTreeSet};

use mtm_runtime::evaluate_request;
use serde_json::{Value, json};

#[path = "support/policy_cases.rs"]
mod policy_cases;

fn evaluate(request: &Value) -> Value {
    match evaluate_request(request) {
        Ok(result) => json!({"ok":true,"result":result}),
        Err(error) => json!({"ok":false,"error":error.to_payload()}),
    }
}

#[test]
fn every_policy_case_has_an_independent_expected_result() {
    for case in policy_cases::cases() {
        let actual = evaluate(&case.request);
        assert!(case.matches(&actual), "policy case failed: {}", case.name);
        assert_eq!(
            actual,
            evaluate(&case.request),
            "nondeterministic case: {}",
            case.name
        );
    }
}

#[test]
fn corpus_keeps_all_135_named_inputs_and_14_operation_groups() {
    let cases = policy_cases::cases();
    let mut names = BTreeSet::new();
    let mut counts = BTreeMap::new();
    for case in &cases {
        assert!(names.insert(&case.name));
        let operation = case.request["operation"].as_str().unwrap_or("");
        *counts.entry(operation).or_insert(0) += 1;
    }
    assert_eq!(cases.len(), 135);
    assert_eq!(
        counts,
        BTreeMap::from([
            ("apply_hunks", 7),
            ("command_policy", 11),
            ("filtered_env", 8),
            ("fingerprint", 2),
            ("inline_script", 12),
            ("oauth_server_url", 15),
            ("parse_patch", 7),
            ("quick_tunnel_origin", 12),
            ("redact", 4),
            ("redact_bytes", 1),
            ("redirect_uris", 14),
            ("schema_validate", 27),
            ("workflow_terminal", 5),
            ("workspace_path", 10),
        ])
    );
}
