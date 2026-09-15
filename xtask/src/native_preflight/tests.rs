use super::*;

fn user(created: bool, error: Option<Errno>) -> UserProbe {
    UserProbe {
        protocol: PROTOCOL,
        operation: "unshare_user".into(),
        created,
        errno: error.map(|e| e as i32),
        errno_name: error.map(|e| errno_name(e).into()),
    }
}

fn context(prefix: &str) -> Context {
    Context {
        uid_map_shape: "restricted_mapping".into(),
        gid_map_shape: "restricted_mapping".into(),
        same_user_namespace_as_visible_pid1: Some(true),
        no_new_privs: Some(true),
        seccomp_mode: Some(2),
        effective_caps_zero: Some(true),
        permitted_caps_zero: Some(true),
        bounding_caps_zero: Some(true),
        visible_limits: BTreeMap::from([("max_user_namespaces".into(), Some(u64::MAX))]),
        namespaces: NAMESPACES
            .into_iter()
            .map(|name| (name.into(), format!("{prefix}-{name}")))
            .collect(),
    }
}

fn sandbox() -> SandboxProbe {
    SandboxProbe {
        protocol: PROTOCOL,
        operation: "minimal_sandbox".into(),
        context: context("child"),
        nested_user: user(false, Some(Errno::ENOSPC)),
        workspace_visible: false,
        environment_minimal: true,
    }
}

#[test]
fn namespace_mapping_and_limits_do_not_invent_host_or_depth() -> crate::Result<()> {
    assert_eq!(
        map_shape(Some("0 0 4294967295\n")),
        "initial_like_not_host_proof"
    );
    assert_eq!(map_shape(Some(" 0 1000 1\n")), "restricted_mapping");
    for malformed in [
        None,
        Some(""),
        Some("not a map"),
        Some("0 0 0"),
        Some("0 0 4294967296"),
    ] {
        assert_eq!(map_shape(malformed), "unknown");
    }
    let public = public_context(&context("sensitive-namespace-id"))?;
    assert_eq!(public["host_context_proven"], false);
    assert_eq!(public["ancestor_limits_inspected"], false);
    assert_eq!(public["namespace_occupancy_measured"], false);
    assert!(!public.to_string().contains("sensitive-namespace-id"));
    Ok(())
}

#[test]
fn namespace_errno_is_precise_but_attribution_is_conservative() {
    for error in [Errno::ENOSPC, Errno::EUSERS] {
        assert_eq!(
            user_class(Some(&user(false, Some(error)))),
            "namespace_limit_or_depth"
        );
    }
    for error in [Errno::EPERM, Errno::EACCES] {
        assert_eq!(
            user_class(Some(&user(false, Some(error)))),
            "namespace_permission_or_policy_denied"
        );
    }
    assert_eq!(
        user_class(Some(&user(false, Some(Errno::ENOMEM)))),
        "namespace_failure_unclassified"
    );
    assert_eq!(user_class(None), "probe_inconclusive");
    assert_eq!(user_class(Some(&user(true, None))), "available");
}

#[test]
fn malformed_probe_success_and_unknown_fields_fail_closed() -> crate::Result<()> {
    assert!(!valid_user(&user(true, Some(Errno::EPERM))));
    assert!(!valid_user(&user(false, None)));
    let mut wrong = user(false, Some(Errno::ENOSPC));
    wrong.errno_name = Some("EPERM".into());
    assert!(!valid_user(&wrong));
    let mut value = serde_json::to_value(user(true, None))?;
    value["untrusted_extra"] = json!(true);
    assert!(serde_json::from_value::<UserProbe>(value).is_err());
    assert!(serde_json::from_str::<UserProbe>("{\"created\":true}").is_err());
    Ok(())
}

#[test]
fn isolation_requires_observed_changes_and_security_properties() {
    let parent = context("parent");
    assert!(sandbox_checks(&parent, &sandbox()).values().all(|v| *v));
    for name in NAMESPACES {
        let mut changed = sandbox();
        changed.context.namespaces.remove(name);
        assert!(!sandbox_checks(&parent, &changed).values().all(|v| *v));
        changed
            .context
            .namespaces
            .insert(name.into(), format!("parent-{name}"));
        assert!(!sandbox_checks(&parent, &changed).values().all(|v| *v));
    }
    let mut weakened = sandbox();
    weakened.context.no_new_privs = None;
    assert!(!sandbox_checks(&parent, &weakened)["no_new_privileges"]);
    weakened = sandbox();
    weakened.context.bounding_caps_zero = Some(false);
    assert!(!sandbox_checks(&parent, &weakened)["capabilities_dropped"]);
    weakened = sandbox();
    weakened.nested_user = user(true, None);
    assert!(!sandbox_checks(&parent, &weakened)["further_user_namespace_denied"]);
    weakened = sandbox();
    weakened.workspace_visible = true;
    assert!(!sandbox_checks(&parent, &weakened)["workspace_not_mounted"]);
    weakened = sandbox();
    weakened.environment_minimal = false;
    assert!(!sandbox_checks(&parent, &weakened)["environment_cleared"]);
}

#[test]
fn probe_plan_never_weakens_isolation_or_mounts_the_repository() {
    let args = sandbox_arguments(Path::new("/fixture/probe"));
    for required in [
        "--unshare-user",
        "--disable-userns",
        "--unshare-net",
        "--die-with-parent",
        "--clearenv",
        "--cap-drop",
    ] {
        assert!(args.iter().any(|a| a == required));
    }
    for forbidden in [
        "--unshare-user-try",
        "--share-net",
        "--bind",
        "--dev-bind",
        "--userns",
        "--userns2",
        "--cap-add",
    ] {
        assert!(!args.iter().any(|a| a == forbidden));
    }
    for triple in args.windows(3).filter(|w| w[0] == "--ro-bind") {
        assert!(SYSTEM_ROOTS.contains(&triple[1].as_str()) || triple[1] == "/fixture/probe");
    }
    assert_eq!(
        args.last().map(String::as_str),
        Some("__native-sandbox-probe")
    );
}

#[test]
fn proc_values_reject_malformed_or_negative_settings() {
    assert_eq!(number(Some(" 2147483647\n")), Some(2_147_483_647));
    for input in [None, Some("-1"), Some("0\n1"), Some("unknown")] {
        assert_eq!(number(input), None);
    }
    assert_eq!(
        status_field("Name:\tignored\nNoNewPrivs:\t1\n", "NoNewPrivs"),
        Some("1")
    );
}

#[test]
fn bubblewrap_diagnostics_are_hints_and_raw_text_is_not_published() {
    use std::os::unix::process::ExitStatusExt;

    let mut output = process::Output {
        status: Some(std::process::ExitStatus::from_raw(256)),
        stdout: Vec::new(),
        stderr: Vec::new(),
        timed_out: false,
        output_limit: false,
        pipes_closed: true,
        reaped: true,
        elapsed_ms: 1,
    };
    for (message, expected) in [
        (
            "bwrap: Creating new namespace failed: nesting depth or quota (ENOSPC)",
            "namespace_limit_or_depth",
        ),
        (
            "bwrap: Operation not permitted",
            "permission_or_policy_denied",
        ),
        (
            "bwrap: Unknown option --disable-userns",
            "bubblewrap_option_unsupported",
        ),
        (
            "untrusted-diagnostic-must-not-be-published",
            "probe_failed_or_inconclusive",
        ),
    ] {
        output.stderr = message.as_bytes().to_vec();
        assert_eq!(bwrap_hint(&output), expected);
        assert!(!output.complete());
        assert!(!output.summary().to_string().contains(message));
    }
    output.timed_out = true;
    assert_eq!(bwrap_hint(&output), "probe_timeout");
    output.timed_out = false;
    output.output_limit = true;
    assert_eq!(bwrap_hint(&output), "probe_output_limit");
}

#[test]
fn successful_exit_alone_is_not_a_complete_probe() {
    use std::os::unix::process::ExitStatusExt;

    for (timed_out, output_limit, pipes_closed, reaped) in [
        (true, false, true, true),
        (false, true, true, true),
        (false, false, false, true),
        (false, false, true, false),
    ] {
        let output = process::Output {
            status: Some(std::process::ExitStatus::from_raw(0)),
            stdout: Vec::new(),
            stderr: Vec::new(),
            timed_out,
            output_limit,
            pipes_closed,
            reaped,
            elapsed_ms: 1,
        };
        assert!(!output.complete());
    }
}
