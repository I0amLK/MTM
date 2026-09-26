use super::*;
use mtm_contracts::NativePermissionKind;
use serde_json::Value;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;

fn file(root: &Path, path: &str, mode: u32) -> Result<PathBuf, ReCtmError> {
    let path = root.join(path);
    fs::create_dir_all(path.parent().ok_or_else(|| internal("test parent"))?)
        .map_err(|_| internal("test directory"))?;
    fs::write(&path, "fixture").map_err(|_| internal("test file"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(mode))
        .map_err(|_| internal("test mode"))?;
    Ok(path)
}

fn invocation(value: Value) -> Result<ExecInvocation, ReCtmError> {
    ExecInvocation::parse(
        value
            .as_object()
            .ok_or_else(|| internal("test arguments"))?,
    )
}

#[test]
fn explicit_path_override_selects_the_executed_file_and_its_permissions() -> Result<(), ReCtmError>
{
    let root = tempfile::tempdir().map_err(|_| internal("test root"))?;
    file(root.path(), "a/program", 0o755)?;
    let chosen = file(root.path(), "b/program", 0o4755)?;
    let request = invocation(json!({"argv":["program"],"env":{"PATH":"/workspace/b"}}))?;
    let facts = collect_exec_permission_facts(&request, root.path(), "/workspace/a", &[])?;
    assert_eq!(facts.resolved_executables()[0].resolved_path(), chosen);
    assert!(
        mtm_core::classify_exec_permissions(&request, &facts)?
            .contains(&NativePermissionKind::PrivilegedExecutable)
    );
    Ok(())
}

#[test]
fn relative_and_empty_path_entries_are_relative_to_invocation_workdir() -> Result<(), ReCtmError> {
    let root = tempfile::tempdir().map_err(|_| internal("test root"))?;
    let relative = file(root.path(), "sub/bin/program", 0o755)?;
    let current = file(root.path(), "sub/program", 0o755)?;
    for (path, expected) in [("bin", relative), ("", current)] {
        let request = invocation(json!({"argv":["program"],"workdir":"sub","env":{"PATH":path}}))?;
        let facts = collect_exec_permission_facts(&request, root.path(), "/usr/bin", &[])?;
        assert_eq!(facts.resolved_executables().len(), 1);
        assert_eq!(facts.resolved_executables()[0].resolved_path(), expected);
    }
    Ok(())
}

#[test]
fn path_search_skips_nonexecutables_but_explicit_paths_do_not_fall_back() -> Result<(), ReCtmError>
{
    let root = tempfile::tempdir().map_err(|_| internal("test root"))?;
    file(root.path(), "a/program", 0o644)?;
    let chosen = file(root.path(), "b/program", 0o755)?;
    let request = invocation(json!({"argv":["program"]}))?;
    let facts =
        collect_exec_permission_facts(&request, root.path(), "/workspace/a:/workspace/b", &[])?;
    assert_eq!(facts.resolved_executables()[0].resolved_path(), chosen);
    let explicit = invocation(json!({"argv":["./a/program"]}))?;
    assert!(collect_exec_permission_facts(&explicit, root.path(), "/workspace/b", &[]).is_err());
    Ok(())
}

#[test]
fn earlier_path_shadowing_is_detected_during_revalidation() -> Result<(), ReCtmError> {
    let root = tempfile::tempdir().map_err(|_| internal("test root"))?;
    file(root.path(), "b/program", 0o755)?;
    let request = invocation(json!({"argv":["program"]}))?;
    let path = "/workspace/a:/workspace/b";
    let facts = collect_exec_permission_facts(&request, root.path(), path, &[])?;
    file(root.path(), "a/program", 0o755)?;
    assert_eq!(
        revalidate_exec_permission_facts(&request, &facts, root.path(), path, &[])
            .map_err(|e| e.code),
        Err("NATIVE_EXECUTABLE_CHANGED".to_owned())
    );
    Ok(())
}

#[test]
fn unresolved_diagnostics_offer_recovery_without_echoing_tokens() -> Result<(), ReCtmError> {
    let root = tempfile::tempdir().map_err(|_| internal("test root"))?;
    let request =
        invocation(json!({"argv":["private-name-do-not-print"],"env":{"API_TOKEN":"secret"}}))?;
    let facts = collect_exec_permission_facts(&request, root.path(), "/usr/bin", &[])?;
    let error = mtm_core::classify_exec_permissions(&request, &facts)
        .err()
        .ok_or_else(|| internal("missing resolution failure"))?;
    assert_eq!(error.details["recovery"]["automatic_retry"], false);
    assert_eq!(error.details["recovery"]["side_effects"], "none");
    assert_eq!(error.details["unresolved_candidate_indexes"], json!([0]));
    let shown = error.to_payload().to_string();
    assert!(!shown.contains("private-name-do-not-print"));
    assert!(!shown.contains("secret"));
    Ok(())
}

#[test]
fn default_shell_is_non_login_and_preserves_the_declared_path() -> Result<(), ReCtmError> {
    let request =
        invocation(json!({"cmd":"printf '%s' \"$PATH\"","env":{"PATH":"fixture-explicit-path"}}))?;
    assert_eq!(request.argv()[1], "-c");
    let output = std::process::Command::new(&request.argv()[0])
        .args(&request.argv()[1..])
        .env_clear()
        .envs(request.environment())
        .output()
        .map_err(|_| internal("test shell failed"))?;
    assert!(output.status.success());
    assert_eq!(output.stdout, b"fixture-explicit-path");
    Ok(())
}
