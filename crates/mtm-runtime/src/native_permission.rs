//! Filesystem-dependent executable facts for Native execution.
//!
//! MTM-017 retired the consent/grant ledger together with the non-dangerous Native
//! modes: the dangerous profile implicitly grants every permission kind, so only
//! executable identity collection and its pre-start revalidation remain.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use mtm_contracts::{ErrorCategory, ReCtmError};
use mtm_core::{ExecInvocation, ExecPermissionFacts, ResolvedExecutableFact};

const SANDBOX_WORKSPACE_ROOT: &str = "/workspace";

#[cfg(test)]
#[path = "native_resolver_tests.rs"]
mod resolver_tests;
const SYSTEM_SANDBOX_ROOTS: [&str; 9] = [
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/etc",
    "/var/lib/texmf",
    "/var/cache/fontconfig",
    "/var/cache/fonts",
];

/// Collect filesystem-dependent executable facts for Native execution authority.
///
/// Resolution uses the exact sandbox PATH supplied by the existing toolchain
/// exposure plan, overridden by env.PATH exactly as in the sandbox actuator.
/// Relative and empty entries use the invocation workdir, never the server cwd.
/// This never starts a command.
pub fn collect_exec_permission_facts(
    invocation: &ExecInvocation,
    workspace: &Path,
    sandbox_path: &str,
    exposed_read_only_roots: &[PathBuf],
) -> Result<ExecPermissionFacts, ReCtmError> {
    let workspace = workspace.canonicalize().map_err(|_| {
        security(
            "NATIVE_EXECUTABLE_WORKSPACE_INVALID",
            "Native executable facts require an existing workspace.",
        )
    })?;
    let workdir = workspace
        .join(invocation.workdir())
        .canonicalize()
        .map_err(|_| {
            security(
                "NATIVE_EXECUTABLE_WORKDIR_CHANGED",
                "Native executable workdir could not be revalidated.",
            )
        })?;
    if !workdir.starts_with(&workspace) || !workdir.is_dir() {
        return Err(security(
            "NATIVE_EXECUTABLE_WORKDIR_CHANGED",
            "Native executable workdir escaped the workspace.",
        ));
    }
    let visible_roots = visible_read_roots(exposed_read_only_roots);
    let sandbox_path = invocation
        .environment()
        .get("PATH")
        .map_or(sandbox_path, String::as_str);
    let mut resolved = Vec::new();
    let mut unresolved = Vec::new();
    for requested in invocation.executable_candidates()? {
        match resolve_sandbox_executable(
            &requested,
            &workspace,
            &workdir,
            sandbox_path,
            &visible_roots,
        )? {
            Some(path) => resolved.push(executable_fact(&requested, path)?),
            None => unresolved.push(requested),
        }
    }
    ExecPermissionFacts::with_unresolved(invocation, resolved, unresolved)
}

/// Recheck executable identity and mode facts immediately before command start.
pub fn revalidate_exec_permission_facts(
    invocation: &ExecInvocation,
    expected: &ExecPermissionFacts,
    workspace: &Path,
    sandbox_path: &str,
    exposed_read_only_roots: &[PathBuf],
) -> Result<(), ReCtmError> {
    let current = collect_exec_permission_facts(
        invocation,
        workspace,
        sandbox_path,
        exposed_read_only_roots,
    )?;
    if &current != expected {
        return Err(security(
            "NATIVE_EXECUTABLE_CHANGED",
            "Command executable metadata changed after permission classification.",
        ));
    }
    Ok(())
}

fn visible_read_roots(exposed_read_only_roots: &[PathBuf]) -> Vec<PathBuf> {
    SYSTEM_SANDBOX_ROOTS
        .iter()
        .map(PathBuf::from)
        .chain(exposed_read_only_roots.iter().cloned())
        .filter_map(|path| path.canonicalize().ok())
        .collect()
}

fn resolve_sandbox_executable(
    requested: &str,
    workspace: &Path,
    workdir: &Path,
    sandbox_path: &str,
    visible_roots: &[PathBuf],
) -> Result<Option<PathBuf>, ReCtmError> {
    let requested_path = Path::new(requested);
    if requested_path.is_absolute() {
        if requested_path == Path::new(SANDBOX_WORKSPACE_ROOT)
            || requested_path.starts_with(SANDBOX_WORKSPACE_ROOT)
        {
            let relative = requested_path
                .strip_prefix(SANDBOX_WORKSPACE_ROOT)
                .map_err(|_| {
                    security(
                        "NATIVE_EXECUTABLE_PATH_DENIED",
                        "Absolute workspace executable could not be normalized.",
                    )
                })?;
            return inspect_workspace_candidate(&workspace.join(relative), workspace);
        }
        return inspect_visible_candidate(requested_path, visible_roots);
    }

    if requested.contains('/') {
        return inspect_workspace_candidate(&workdir.join(requested_path), workspace);
    }

    for entry in sandbox_path.split(':') {
        let entry_path = Path::new(entry);
        let candidate = if !entry_path.is_absolute() {
            workdir.join(entry_path).join(requested)
        } else if entry_path == Path::new(SANDBOX_WORKSPACE_ROOT)
            || entry_path.starts_with(SANDBOX_WORKSPACE_ROOT)
        {
            let relative = entry_path
                .strip_prefix(SANDBOX_WORKSPACE_ROOT)
                .map_err(|_| {
                    security(
                        "NATIVE_EXECUTABLE_PATH_DENIED",
                        "Sandbox PATH workspace entry could not be normalized.",
                    )
                })?;
            workspace.join(relative).join(requested)
        } else {
            entry_path.join(requested)
        };
        let resolved = match candidate.canonicalize() {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err(security(
                    "NATIVE_EXECUTABLE_INSPECTION_FAILED",
                    "A sandbox PATH executable could not be inspected.",
                ));
            }
        };
        if !entry_path.is_absolute() && !resolved.starts_with(workspace) {
            return Err(security(
                "NATIVE_EXECUTABLE_PATH_DENIED",
                "Relative PATH entries must remain in the workspace; use an exposed absolute sandbox path otherwise.",
            ));
        }
        if resolved.starts_with(workspace)
            || visible_roots
                .iter()
                .any(|root| resolved == *root || resolved.starts_with(root))
        {
            let metadata = fs::metadata(&resolved).map_err(|_| {
                security(
                    "NATIVE_EXECUTABLE_INSPECTION_FAILED",
                    "A PATH candidate could not be inspected.",
                )
            })?;
            // Like executable PATH search, skip non-executable entries instead
            // of checking a different file from the one that would run.
            if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
                continue;
            }
            return Ok(Some(resolved));
        }
        return Err(security(
            "NATIVE_EXECUTABLE_PATH_DENIED",
            "Sandbox PATH resolved outside the workspace and exposed read-only roots.",
        ));
    }
    Ok(None)
}

fn inspect_workspace_candidate(
    candidate: &Path,
    workspace: &Path,
) -> Result<Option<PathBuf>, ReCtmError> {
    let resolved = match candidate.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(security(
                "NATIVE_EXECUTABLE_INSPECTION_FAILED",
                "A workspace executable could not be inspected.",
            ));
        }
    };
    if !resolved.starts_with(workspace) {
        return Err(security(
            "NATIVE_EXECUTABLE_PATH_DENIED",
            "A workspace executable resolved outside the workspace.",
        ));
    }
    Ok(Some(resolved))
}

fn inspect_visible_candidate(
    candidate: &Path,
    visible_roots: &[PathBuf],
) -> Result<Option<PathBuf>, ReCtmError> {
    let resolved = match candidate.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(security(
                "NATIVE_EXECUTABLE_INSPECTION_FAILED",
                "An exposed executable could not be inspected.",
            ));
        }
    };
    if !visible_roots
        .iter()
        .any(|root| resolved == *root || resolved.starts_with(root))
    {
        return Err(security(
            "NATIVE_EXECUTABLE_PATH_DENIED",
            "Absolute executable is not visible in the Native sandbox.",
        ));
    }
    Ok(Some(resolved))
}

fn executable_fact(
    requested: &str,
    resolved_path: PathBuf,
) -> Result<ResolvedExecutableFact, ReCtmError> {
    let metadata = fs::metadata(&resolved_path).map_err(|_| {
        security(
            "NATIVE_EXECUTABLE_INSPECTION_FAILED",
            "Executable metadata could not be read.",
        )
    })?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        return Err(security(
            "NATIVE_EXECUTABLE_NOT_EXECUTABLE",
            "Resolved command executable is not an executable file.",
        ));
    }
    let modified_fingerprint = format!(
        "{}:{}:{}:{}",
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec()
    );
    Ok(ResolvedExecutableFact::new(
        requested,
        resolved_path,
        metadata.dev(),
        metadata.ino(),
        metadata.mode(),
        metadata.size(),
        Some(modified_fingerprint),
    ))
}

fn security(code: &str, message: &str) -> ReCtmError {
    ReCtmError::new(code, message).with_category(ErrorCategory::Security)
}

#[cfg(test)]
fn internal(message: &str) -> ReCtmError {
    ReCtmError::new("NATIVE_PERMISSION_INTERNAL_ERROR", message)
        .with_category(ErrorCategory::Internal)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use mtm_contracts::NativePermissionKind;

    use super::*;

    fn code(error: ReCtmError) -> String {
        error.code
    }

    #[test]
    fn adjacent_commands_keep_privileged_and_missing_file_checks() -> Result<(), ReCtmError> {
        let workspace = tempfile::tempdir().map_err(|error| internal(&error.to_string()))?;
        for (name, mode) in [("one", 0o755), ("two", 0o4755)] {
            let path = workspace.path().join(name);
            fs::write(&path, "fixture").map_err(|error| internal(&error.to_string()))?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode))
                .map_err(|error| internal(&error.to_string()))?;
        }
        let args = serde_json::json!({"cmd":"./one;./two"})
            .as_object()
            .cloned()
            .unwrap_or_default();
        let invocation = ExecInvocation::parse(&args)?;
        let facts = collect_exec_permission_facts(&invocation, workspace.path(), "/usr/bin", &[])?;
        assert_eq!(facts.resolved_executables().len(), 2);
        assert!(
            mtm_core::classify_exec_permissions(&invocation, &facts)?
                .contains(&NativePermissionKind::PrivilegedExecutable)
        );
        fs::remove_file(workspace.path().join("two"))
            .map_err(|error| internal(&error.to_string()))?;
        let missing =
            collect_exec_permission_facts(&invocation, workspace.path(), "/usr/bin", &[])?;
        assert_eq!(
            mtm_core::classify_exec_permissions(&invocation, &missing).map_err(code),
            Err("NATIVE_EXECUTABLE_UNRESOLVED".to_owned())
        );
        Ok(())
    }

    #[test]
    fn executable_facts_detect_privileged_bits_and_metadata_mutation() -> Result<(), ReCtmError> {
        let workspace = tempfile::tempdir().map_err(|error| internal(&error.to_string()))?;
        let bin = workspace.path().join("bin");
        fs::create_dir(&bin).map_err(|error| internal(&error.to_string()))?;
        let executable = bin.join("fixture");
        fs::write(&executable, "fixture").map_err(|error| internal(&error.to_string()))?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o4755))
            .map_err(|error| internal(&error.to_string()))?;
        let args = serde_json::json!({"argv":["fixture"],"workdir":"."})
            .as_object()
            .cloned()
            .unwrap_or_default();
        let invocation = ExecInvocation::parse(&args)?;
        let facts =
            collect_exec_permission_facts(&invocation, workspace.path(), "/workspace/bin", &[])?;
        assert_eq!(facts.resolved_executables().len(), 1);
        assert!(facts.resolved_executables()[0].is_privileged());
        assert_eq!(
            mtm_core::classify_exec_permissions(&invocation, &facts)?,
            vec![NativePermissionKind::PrivilegedExecutable]
        );
        let relative_args = serde_json::json!({"argv":["./fixture"],"workdir":"bin"})
            .as_object()
            .cloned()
            .unwrap_or_default();
        let relative_invocation = ExecInvocation::parse(&relative_args)?;
        let relative_facts =
            collect_exec_permission_facts(&relative_invocation, workspace.path(), "/usr/bin", &[])?;
        assert_eq!(relative_facts.resolved_executables().len(), 1);
        assert_eq!(
            relative_facts.resolved_executables()[0].resolved_path(),
            executable
        );
        assert!(relative_facts.resolved_executables()[0].is_privileged());
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .map_err(|error| internal(&error.to_string()))?;
        assert_eq!(
            revalidate_exec_permission_facts(
                &invocation,
                &facts,
                workspace.path(),
                "/workspace/bin",
                &[],
            )
            .map_err(code),
            Err("NATIVE_EXECUTABLE_CHANGED".to_owned())
        );
        Ok(())
    }

    #[test]
    fn unresolvable_executable_fails_closed_without_command_text_in_error() -> Result<(), ReCtmError>
    {
        let workspace = tempfile::tempdir().map_err(|error| internal(&error.to_string()))?;
        let secret = "secret-command-that-does-not-exist";
        let args = serde_json::json!({"argv":[secret]})
            .as_object()
            .cloned()
            .unwrap_or_default();
        let invocation = ExecInvocation::parse(&args)?;
        let facts = collect_exec_permission_facts(&invocation, workspace.path(), "/usr/bin", &[])?;
        let error = mtm_core::classify_exec_permissions(&invocation, &facts)
            .err()
            .ok_or_else(|| internal("unresolved test executable unexpectedly classified"))?;
        assert_eq!(error.code, "NATIVE_EXECUTABLE_UNRESOLVED");
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{facts:?}").contains(secret));
        Ok(())
    }
}
