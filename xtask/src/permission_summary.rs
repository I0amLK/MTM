//! Validate measured patch-permission evidence, never a human or host claim.
use super::*;

const CHECKS: [&str; 21] = [
    "explicit_safe_disabled_profile",
    "unapproved_patch_zero_write",
    "legacy_and_nonform_clients_no_grant",
    "decline_zero_write",
    "cancel_zero_write",
    "false_approval_zero_write",
    "challenge_owner_binding",
    "challenge_argument_binding",
    "invalid_responses_preserve_original_challenge",
    "active_exact_grant_suppresses_prompt",
    "challenge_single_use",
    "grant_owner_and_argument_binding",
    "dry_run_does_not_consume_grant",
    "once_grant_cannot_be_reused",
    "concurrent_once_grant_one_winner",
    "session_grant_reusable_in_process",
    "restart_invalidates_grants_and_challenges",
    "expired_grant_zero_write",
    "ordinary_path_not_required",
    "trusted_and_dangerous_patch_profiles",
    "clean_shutdown",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    ok: bool,
    binary_sha256: String,
    checks: BTreeMap<String, bool>,
    iterations: u64,
    duration_ms: u64,
    warmup_iterations: u64,
    initial_denials: u64,
    grants_issued: u64,
    duplicate_prompts_suppressed: u64,
    protected_patches_committed: u64,
    consumed_grants_rechallenged: u64,
    initial_rss_kib: u64,
    max_rss_kib: u64,
    initial_threads: u64,
    max_threads: u64,
    initial_fds: u64,
    max_fds: u64,
    retained_children: u64,
    shutdown_ms: u64,
    native_mode: String,
    native_backend: String,
    latex_policy: String,
    consent: String,
    protected_patch_execution_tested: bool,
    native_command_execution_tested: bool,
    compiled_latex_tested: bool,
    web_client_tested: bool,
    human_consent_tested: bool,
    baseline_resource_comparison: bool,
    production_state_modified: bool,
    selector_changed: bool,
    release_qualified: bool,
}

pub(crate) fn validate(stdout: &[u8], hash: &str) -> Result<Value> {
    let output = std::str::from_utf8(stdout).map_err(|_| "permission output is not UTF-8")?;
    if [
        "MTM_TARGET_RUNTIME ",
        "MTM_RESOURCE_RUNTIME ",
        "MTM_UPGRADE_RUNTIME ",
        "MTM_CANDIDATE_LIFECYCLE ",
    ]
    .iter()
    .any(|marker| output.contains(marker))
    {
        return Err("foreign profile evidence in permission summary".into());
    }
    let value: Report = extract(stdout, "MTM_PERMISSION_RUNTIME ")?;
    if !valid_hash(hash)
        || value.binary_sha256 != hash
        || !value.ok
        || value.checks.len() != CHECKS.len()
        || !CHECKS
            .iter()
            .all(|key| value.checks.get(*key) == Some(&true))
        || value.warmup_iterations != 5
        || !(60_000..=90_000).contains(&value.duration_ms)
        || [
            value.iterations,
            value.initial_denials,
            value.grants_issued,
            value.duplicate_prompts_suppressed,
            value.protected_patches_committed,
            value.consumed_grants_rechallenged,
        ]
        .iter()
        .any(|count| *count != 100)
        || !(1..=262_144).contains(&value.initial_rss_kib)
        || value.max_rss_kib < value.initial_rss_kib
        || value.max_rss_kib > value.initial_rss_kib.saturating_add(8192)
        || !(1..=512).contains(&value.initial_threads)
        || value.max_threads != value.initial_threads
        || !(1..=4096).contains(&value.initial_fds)
        || value.max_fds != value.initial_fds
        || value.retained_children != 0
        || value.shutdown_ms > 8000
        || value.native_mode != "safe"
        || value.native_backend != "disabled"
        || value.latex_policy != "static_only"
        || value.consent != "scripted_form_responses"
        || !value.protected_patch_execution_tested
        || value.native_command_execution_tested
        || value.compiled_latex_tested
        || value.web_client_tested
        || value.human_consent_tested
        || value.baseline_resource_comparison
        || value.production_state_modified
        || value.selector_changed
        || value.release_qualified
    {
        return Err(
            "permission evidence has inconsistent identity, counts, growth or scope".into(),
        );
    }
    Ok(json!({"permissions":extract::<Value>(stdout, "MTM_PERMISSION_RUNTIME ")?}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        json!({"ok":true,"binary_sha256":"a".repeat(64),
            "checks":CHECKS.into_iter().map(|key| (key,true)).collect::<BTreeMap<_,_>>(),
            "iterations":100,"duration_ms":60_000,"warmup_iterations":5,
            "initial_denials":100,"grants_issued":100,"duplicate_prompts_suppressed":100,
            "protected_patches_committed":100,"consumed_grants_rechallenged":100,
            "initial_rss_kib":20000,"max_rss_kib":21000,"initial_threads":4,"max_threads":4,
            "initial_fds":8,"max_fds":8,"retained_children":0,"shutdown_ms":20,
            "native_mode":"safe","native_backend":"disabled","latex_policy":"static_only",
            "consent":"scripted_form_responses","protected_patch_execution_tested":true,
            "native_command_execution_tested":false,"compiled_latex_tested":false,"web_client_tested":false,
            "human_consent_tested":false,"baseline_resource_comparison":false,"production_state_modified":false,
            "selector_changed":false,"release_qualified":false})
    }

    fn output(value: &Value) -> Vec<u8> {
        format!("MTM_PERMISSION_RUNTIME {value}\n").into_bytes()
    }

    #[test]
    fn every_permission_check_and_field_is_required_and_strictly_typed() -> Result<()> {
        let good = fixture();
        validate(&output(&good), &"a".repeat(64))?;
        for key in good.as_object().ok_or("fixture")?.keys() {
            let mut removed = good.clone();
            removed.as_object_mut().ok_or("fixture")?.remove(key);
            assert!(validate(&output(&removed), &"a".repeat(64)).is_err());
            let mut null = good.clone();
            null[key] = Value::Null;
            assert!(validate(&output(&null), &"a".repeat(64)).is_err());
        }
        for key in CHECKS {
            for replacement in [json!(false), json!(1), json!("true")] {
                let mut value = good.clone();
                value["checks"][key] = replacement;
                assert!(validate(&output(&value), &"a".repeat(64)).is_err());
            }
        }
        Ok(())
    }

    #[test]
    fn permission_scope_counts_and_resource_bounds_cannot_be_widened() {
        for (key, replacement) in [
            ("binary_sha256", json!("b".repeat(64))),
            ("iterations", json!(99)),
            ("iterations", json!(100.0)),
            ("duration_ms", json!(59999)),
            ("duration_ms", json!(90001)),
            ("warmup_iterations", json!(0)),
            ("initial_denials", json!(0)),
            ("grants_issued", json!(101)),
            ("protected_patches_committed", json!(99)),
            ("consumed_grants_rechallenged", json!(99)),
            ("duplicate_prompts_suppressed", json!(99)),
            ("max_rss_kib", json!(28193)),
            ("max_rss_kib", json!(1)),
            ("initial_rss_kib", json!(u64::MAX)),
            ("max_threads", json!(5)),
            ("max_fds", json!(9)),
            ("retained_children", json!(1)),
            ("shutdown_ms", json!(8001)),
            ("native_backend", json!("bubblewrap")),
            ("native_mode", json!("dangerous")),
            ("consent", json!("human")),
            ("protected_patch_execution_tested", json!(false)),
            ("native_command_execution_tested", json!(true)),
            ("compiled_latex_tested", json!(true)),
            ("web_client_tested", json!(true)),
            ("human_consent_tested", json!(true)),
            ("baseline_resource_comparison", json!(true)),
            ("production_state_modified", json!(true)),
            ("selector_changed", json!(true)),
            ("release_qualified", json!(true)),
            ("raw_token", json!("forbidden")),
        ] {
            let mut value = fixture();
            value[key] = replacement;
            assert!(validate(&output(&value), &"a".repeat(64)).is_err(), "{key}");
        }
        let good = output(&fixture());
        assert!(validate(&[good.clone(), good.clone()].concat(), &"a".repeat(64)).is_err());
        assert!(
            validate(
                &[good, b"MTM_TARGET_RUNTIME {}".to_vec()].concat(),
                &"a".repeat(64)
            )
            .is_err()
        );
        assert!(validate(b"no summary", &"a".repeat(64)).is_err());
    }
}
