use super::*;

fn resource_summary() -> Value {
    let metrics = json!({
        "startup_samples":3,"request_samples":180,"startup_p50_ms":20.0,
        "startup_p95_ms":30.0,"request_p95_ms":2.0,"max_rss_kib":20_000,
        "max_threads":8,"max_fds":16,"max_shutdown_ms":50.0
    });
    json!({
        "ok":true,"candidate_sha256":"a".repeat(64),"baseline_sha256":"b".repeat(64),
        "baseline":metrics,"candidate":metrics,"resource_non_regression_tested":true,
        "native_execution_tested":true,"native_mode":"dangerous","native_backend":"bubblewrap",
        "request_workload":"server_info_and_public_exec_command","permission_grant_soak_tested":false,
        "web_client_tested":false,"install_or_selector_changed":false,"performance_claim":false,
        "release_qualified":false
    })
}

#[test]
fn resource_summary_requires_explicit_distinct_artifacts_and_rechecks_bounds() -> Result<()> {
    let good = resource_summary();
    let output = |value: &Value| format!("MTM_RESOURCE_RUNTIME {value}\n").into_bytes();
    summary::validate_resource(&output(&good), &"a".repeat(64), &"b".repeat(64))?;
    for (key, value) in [
        ("candidate_sha256", json!("c".repeat(64))),
        ("baseline_sha256", json!("c".repeat(64))),
        ("ok", json!(false)),
        ("resource_non_regression_tested", json!(false)),
        ("native_execution_tested", json!(false)),
        ("permission_grant_soak_tested", json!(true)),
        ("performance_claim", json!(true)),
        ("release_qualified", json!(true)),
    ] {
        let mut changed = good.clone();
        changed[key] = value;
        assert!(
            summary::validate_resource(&output(&changed), &"a".repeat(64), &"b".repeat(64))
                .is_err()
        );
    }
    let mut slow = good.clone();
    slow["candidate"]["request_p95_ms"] = json!(100.0);
    assert!(summary::validate_resource(&output(&slow), &"a".repeat(64), &"b".repeat(64)).is_err());
    let mut huge = good.clone();
    huge["candidate"]["max_rss_kib"] = json!(262_145);
    assert!(summary::validate_resource(&output(&huge), &"a".repeat(64), &"b".repeat(64)).is_err());
    assert!(summary::validate_resource(&output(&good), &"a".repeat(64), &"a".repeat(64)).is_err());
    assert!(summary::validate_resource(b"no marker", &"a".repeat(64), &"b".repeat(64)).is_err());
    Ok(())
}

#[test]
fn resource_profile_requires_complete_baseline_selection() -> Result<()> {
    let base = [
        "--profile",
        "resource",
        "--binary",
        "target/release/mtm",
        "--sha256",
        &"a".repeat(64),
        "--baseline",
        "target/release/old-mtm",
        "--baseline-sha256",
        &"b".repeat(64),
    ]
    .map(str::to_owned);
    let parsed = Options::parse(&base)?;
    assert_eq!(parsed.profile, Profile::Resource);
    let expected_baseline_hash = "b".repeat(64);
    assert_eq!(
        parsed.baseline_sha256.as_deref(),
        Some(expected_baseline_hash.as_str())
    );
    for missing in [base[..6].to_vec(), base[..8].to_vec()] {
        assert!(Options::parse(&missing).is_err());
    }
    let mut protocol = base.to_vec();
    protocol[1] = "protocol".to_owned();
    assert!(Options::parse(&protocol).is_err());
    Ok(())
}

#[test]
fn upgrade_profile_requires_distinct_complete_artifact_pairs() -> Result<()> {
    let base = [
        "--profile",
        "upgrade",
        "--binary",
        "target/release/mtm",
        "--sha256",
        &"a".repeat(64),
        "--baseline",
        "target/release/old",
        "--baseline-sha256",
        &"b".repeat(64),
    ]
    .map(str::to_owned);
    let parsed = Options::parse(&base)?;
    assert_eq!(parsed.profile, Profile::Upgrade);
    assert_eq!(parsed.report_name(), "candidate-upgrade.json");
    for missing in [base[..6].to_vec(), base[..8].to_vec()] {
        assert!(Options::parse(&missing).is_err());
    }
    let mut equal = base.to_vec();
    equal[9] = "a".repeat(64);
    assert!(Options::parse(&equal).is_err());
    let mut foreign = base.to_vec();
    foreign.extend(["--state-root".into(), "/operator/data".into()]);
    assert!(Options::parse(&foreign).is_err());
    Ok(())
}
