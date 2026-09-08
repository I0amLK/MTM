use super::*;

fn options(path: &str, hash: &str) -> Options {
    Options {
        binary: path.into(),
        sha256: hash.into(),
        record: false,
    }
}

#[test]
fn selection_requires_explicit_profile_artifact_and_digest() -> Result<()> {
    let good = [
        "--profile",
        "protocol",
        "--binary",
        "target/release/mtm",
        "--sha256",
        &"a".repeat(64),
    ]
    .map(str::to_owned);
    Options::parse(&good)?;
    for changed in [
        vec![],
        good[..4].to_vec(),
        [good.to_vec(), vec!["--record".into(), "--record".into()]].concat(),
        [good.to_vec(), vec!["--binary".into(), "other".into()]].concat(),
        [good.to_vec(), vec!["--skip-native".into()]].concat(),
    ] {
        assert!(Options::parse(&changed).is_err());
    }
    for (index, value) in [(1, "release"), (5, "invalid"), (3, "")] {
        let mut changed = good.clone();
        changed[index] = value.to_owned();
        assert!(Options::parse(&changed).is_err());
    }
    Ok(())
}

#[test]
fn snapshot_is_private_exact_and_detects_drift_without_modifying_input() -> Result<()> {
    let root = tempfile::tempdir()?;
    let original = root.path().join("inert-elf");
    let bytes = [b"\x7fELF".as_slice(), &[0_u8; 100]].concat();
    fs::write(&original, &bytes)?;
    fs::set_permissions(&original, fs::Permissions::from_mode(0o755))?;
    let hash = format!("{:x}", Sha256::digest(&bytes));
    let snapshot = Snapshot::prepare(root.path(), &options("inert-elf", &hash))?;
    assert_eq!(fs::read(&snapshot.executable)?, bytes);
    assert_eq!(
        fs::metadata(&snapshot.executable)?.permissions().mode() & 0o777,
        0o500
    );
    assert_eq!(fs::metadata(&original)?.permissions().mode() & 0o777, 0o755);
    snapshot.unchanged()?;
    fs::write(&original, b"changed")?;
    assert!(snapshot.unchanged().is_err());
    Ok(())
}

#[test]
fn rejected_artifacts_never_start_a_runner() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("candidate");
    fs::write(&path, b"#!/bin/sh\nexit 0\n")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    for binary in ["candidate", "missing", "."] {
        let report = run(root.path(), &options(binary, &"a".repeat(64)))?;
        assert_eq!(report["passed"], false);
        assert_eq!(report["candidate_launched"], false);
        assert_eq!(report["failed_stage"], "candidate_snapshot");
        assert!(report.get("runner").is_none());
    }
    fs::write(&path, [b"\x7fELF".as_slice(), &[0_u8; 100]].concat())?;
    assert!(Snapshot::prepare(root.path(), &options("candidate", &"0".repeat(64))).is_err());
    let hash = digest(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o4755))?;
    assert!(Snapshot::prepare(root.path(), &options("candidate", &hash)).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    std::os::unix::fs::symlink(&path, root.path().join("link"))?;
    assert!(Snapshot::prepare(root.path(), &options("link", &hash)).is_err());
    File::options()
        .write(true)
        .open(&path)?
        .set_len(MAX_BINARY + 1)?;
    assert!(Snapshot::prepare(root.path(), &options("candidate", &hash)).is_err());
    Ok(())
}

fn summaries() -> [Value; 3] {
    let cap = capability::tests::fixture();
    let workspace = json!({"ok":true,"binary_sha256":"a".repeat(64),"git_tools_checked":5,
        "utf8_continuation_lossless":true,"changed_file_denied":true,"blame_continuation_preserved":true,
        "child_path":"curl_and_git_only","native_execution_tested":false,"web_client_tested":false,"release_qualified":false});
    let mut flows = json!({});
    for (mode, states) in [
        ("compact", vec!["assess", "assemble", "verify", "done"]),
        (
            "full",
            vec![
                "assess",
                "explore",
                "propose_plans",
                "direct_proving",
                "assemble",
                "verify",
                "done",
            ],
        ),
        (
            "repair",
            vec!["assess", "assemble", "verify", "repair", "verify", "done"],
        ),
    ] {
        flows[mode] =
            json!({"states":states,"sealed":true,"artifact_matches":true,"restart_resumed":true});
    }
    let lifecycle = json!({"ok":true,"binary_sha256":"a".repeat(64),"flows":flows,
        "persisted_secret_owner_only":true,"same_key_restart":true,"changed_key_old_bearer_denied":true,
        "changed_key_old_capability_zero_writes":true,"same_owner_fresh_recovery":true,"verifier_firewall":true,
        "no_premature_artifact":true,"clean_shutdown":true,"native_execution_tested":false,"latex_policy":"static_only",
        "web_client_tested":false,"independent_mathematical_verification":false,"release_qualified":false});
    [cap, workspace, lifecycle]
}

fn output(values: &[Value; 3]) -> Vec<u8> {
    format!(
        "MTM_CAPABILITY_GATE {}\nMTM_WORKSPACE_SMOKE {}\nMTM_CANDIDATE_LIFECYCLE {}\n",
        values[0], values[1], values[2]
    )
    .into_bytes()
}

#[test]
fn summaries_require_all_three_scopes_and_the_exact_candidate() -> Result<()> {
    let good = summaries();
    summary::validate(&output(&good), &"a".repeat(64))?;
    for index in 0..3 {
        for (key, value) in [
            ("binary_sha256", json!("b".repeat(64))),
            ("ok", json!(false)),
            ("release_qualified", json!(true)),
            ("capability", json!("must-not-be-recorded")),
        ] {
            let mut changed = good.clone();
            changed[index][key] = value;
            assert!(summary::validate(&output(&changed), &"a".repeat(64)).is_err());
        }
    }
    for (key, value) in [
        ("flows", json!({})),
        ("clean_shutdown", json!(false)),
        ("same_key_restart", Value::Null),
        ("native_execution_tested", json!(true)),
        ("latex_policy", json!("required")),
        ("independent_mathematical_verification", json!(true)),
        ("no_premature_artifact", json!(1)),
    ] {
        let mut changed = good.clone();
        changed[2][key] = value;
        assert!(summary::validate(&output(&changed), &"a".repeat(64)).is_err());
    }
    let mut changed = good.clone();
    changed[2]["flows"]["full"]["states"] = json!(["assess", "done"]);
    assert!(summary::validate(&output(&changed), &"a".repeat(64)).is_err());
    let duplicate = [output(&good), output(&good)].concat();
    assert!(summary::validate(&duplicate, &"a".repeat(64)).is_err());
    assert!(summary::validate(b"test result: ok", &"a".repeat(64)).is_err());
    Ok(())
}
