#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "MTM-014 D5 cutover candidate must remain unreachable until real human MRTR evidence is accepted"
    )
)]

use std::collections::BTreeSet;
use std::sync::Arc;

use mtm_contracts::{ErrorCategory, NativePermissionKind, NativePermissionTool, ReCtmError};
use mtm_core::{
    EffectiveNativePolicy, NativeInvocation, PatchInvocation, classify_patch_permissions,
};
use serde_json::{Map, Value};

use crate::{NativePermissionGrantAuthority, NativeToolRuntime, NativeWorkspace};

/// Pre-cutover execution seam for MTM-014 D5.
///
/// This type is intentionally crate-private and is not reachable from MCP
/// dispatch. It exists so the complete grant -> SandboxPlan/PreparedPatch ->
/// execution path can be qualified before the independent human-consent gate
/// authorizes the final public cutover.
pub(crate) struct NativeAuthorityExecutor {
    native: Arc<NativeToolRuntime>,
    workspace: Arc<NativeWorkspace>,
    grants: Arc<NativePermissionGrantAuthority>,
}

impl NativeAuthorityExecutor {
    pub(crate) fn new(
        native: Arc<NativeToolRuntime>,
        workspace: Arc<NativeWorkspace>,
        grants: Arc<NativePermissionGrantAuthority>,
    ) -> Self {
        Self {
            native,
            workspace,
            grants,
        }
    }

    pub(crate) fn exec_command_candidate(
        &self,
        owner_id: &str,
        arguments: &Map<String, Value>,
    ) -> Result<Value, ReCtmError> {
        let prepared = self.native.prepare_authority_exec(arguments)?;
        let revalidated = self.native.revalidate_authority_exec(prepared)?;
        let permit = self.grants.authorize_invocation(
            owner_id,
            &self.workspace.root().display().to_string(),
            revalidated.policy(),
        )?;
        self.native.start_authority_exec(revalidated, permit)
    }

    pub(crate) fn apply_patch_candidate(
        &self,
        owner_id: &str,
        arguments: &Map<String, Value>,
    ) -> Result<Value, ReCtmError> {
        let invocation = PatchInvocation::parse(arguments)?;
        let prepared = self.workspace.prepare_patch(&invocation)?;
        let path_facts = prepared
            .path_facts()
            .ok_or_else(|| internal("authority patch preparation omitted path facts"))?;
        let required = classify_patch_permissions(&invocation, path_facts)?;
        let native_invocation = NativeInvocation::Patch(invocation.clone());
        let policy = EffectiveNativePolicy::evaluate(
            self.native.mode(),
            &native_invocation,
            &required,
            &BTreeSet::new(),
        )?;
        let workspace = self.workspace.root().display().to_string();
        let expected_explicit = policy
            .required()
            .iter()
            .copied()
            .filter(|kind| !policy.implicitly_granted().contains(kind))
            .collect::<Vec<_>>();
        let expected_digest = invocation.arguments_sha256().to_owned();
        self.workspace
            .commit_prepared_patch_with_authorization(prepared, || {
                let permit = self
                    .grants
                    .authorize_invocation(owner_id, &workspace, &policy)?;
                validate_permit(
                    &permit,
                    NativePermissionTool::ApplyPatch,
                    &expected_digest,
                    &expected_explicit,
                )
            })
    }
}

fn validate_permit(
    permit: &crate::NativeInvocationPermissionPermit,
    tool: NativePermissionTool,
    arguments_sha256: &str,
    expected_permissions: &[NativePermissionKind],
) -> Result<(), ReCtmError> {
    if permit.tool() != tool
        || permit.arguments_sha256() != arguments_sha256
        || permit.permissions() != expected_permissions
    {
        return Err(ReCtmError::new(
            "NATIVE_PERMISSION_PERMIT_MISMATCH",
            "Native invocation permit does not match the authorized operation.",
        )
        .with_category(ErrorCategory::Security));
    }
    Ok(())
}

fn internal(message: &str) -> ReCtmError {
    ReCtmError::new("NATIVE_PERMISSION_INTERNAL_ERROR", message)
        .with_category(ErrorCategory::Internal)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt;
    use std::thread;

    use mtm_contracts::{NativeMode, NativePermissionScope};
    use mtm_core::NativePermissionRequest;
    use mtm_storage::StoreRuntime;

    use crate::{NativePermissionConsentAuthority, NativePermissionConsentOutcome};

    use super::*;

    fn patch_arguments(path: &str, content: &str, dry_run: bool) -> Map<String, Value> {
        serde_json::json!({
            "patch":format!(
                "*** Begin Patch\n*** Add File: {path}\n+{content}\n*** End Patch\n"
            ),
            "dry_run":dry_run
        })
        .as_object()
        .cloned()
        .unwrap_or_default()
    }

    fn issue_patch_grant(
        grants: &NativePermissionGrantAuthority,
        consents: &NativePermissionConsentAuthority,
        owner: &str,
        workspace: &str,
        arguments: &Map<String, Value>,
    ) -> Result<(), ReCtmError> {
        let request = NativePermissionRequest::parse(
            serde_json::json!({
                "tool_name":"apply_patch",
                "permission":"write_generated_or_ignored",
                "reason":"candidate patch test",
                "arguments":arguments,
                "scope":NativePermissionScope::Once.as_str(),
                "ttl_seconds":300
            })
            .as_object()
            .ok_or_else(|| internal("test permission request must be an object"))?,
        )?;
        let prompt = consents.begin(owner, workspace, request.clone())?;
        let outcome = consents.complete(
            prompt.request_state(),
            owner,
            workspace,
            &request,
            &serde_json::json!({"action":"accept","content":{"approved":true}}),
        )?;
        let NativePermissionConsentOutcome::Accepted(consent) = outcome else {
            return Err(internal("test consent was not accepted"));
        };
        grants.issue_verified(consent)?;
        Ok(())
    }

    fn issue_exec_grant(
        grants: &NativePermissionGrantAuthority,
        consents: &NativePermissionConsentAuthority,
        owner: &str,
        workspace: &str,
        kind: NativePermissionKind,
        arguments: &Map<String, Value>,
    ) -> Result<(), ReCtmError> {
        issue_exec_grant_with_scope(
            grants,
            consents,
            owner,
            workspace,
            kind,
            NativePermissionScope::Once,
            arguments,
        )
    }

    fn issue_exec_grant_with_scope(
        grants: &NativePermissionGrantAuthority,
        consents: &NativePermissionConsentAuthority,
        owner: &str,
        workspace: &str,
        kind: NativePermissionKind,
        scope: NativePermissionScope,
        arguments: &Map<String, Value>,
    ) -> Result<(), ReCtmError> {
        let request = NativePermissionRequest::parse(
            serde_json::json!({
                "tool_name":"exec_command",
                "permission":kind.as_str(),
                "reason":"candidate exec matrix test",
                "arguments":arguments,
                "scope":scope.as_str(),
                "ttl_seconds":300
            })
            .as_object()
            .ok_or_else(|| internal("test permission request must be an object"))?,
        )?;
        let prompt = consents.begin(owner, workspace, request.clone())?;
        let outcome = consents.complete(
            prompt.request_state(),
            owner,
            workspace,
            &request,
            &serde_json::json!({"action":"accept","content":{"approved":true}}),
        )?;
        let NativePermissionConsentOutcome::Accepted(consent) = outcome else {
            return Err(internal("test consent was not accepted"));
        };
        grants.issue_verified(consent)?;
        Ok(())
    }

    struct CandidateFixture {
        _root: tempfile::TempDir,
        workspace: Arc<NativeWorkspace>,
        native: Arc<NativeToolRuntime>,
        grants: Arc<NativePermissionGrantAuthority>,
        consents: NativePermissionConsentAuthority,
        executor: NativeAuthorityExecutor,
    }

    fn candidate_fixture() -> Result<CandidateFixture, ReCtmError> {
        let root = tempfile::tempdir().map_err(|error| internal(&error.to_string()))?;
        let private = root.path().join("private-outside-workspace");
        let workspace_root = root.path().join("workspace");
        fs::create_dir_all(&private).map_err(|error| internal(&error.to_string()))?;
        fs::create_dir_all(&workspace_root).map_err(|error| internal(&error.to_string()))?;
        let workspace = Arc::new(NativeWorkspace::new(&workspace_root, &private)?);
        let native = Arc::new(NativeToolRuntime::new(
            Arc::clone(&workspace),
            NativeMode::Safe,
            "disabled",
            &[],
            std::slice::from_ref(&private),
        )?);
        let runtime = StoreRuntime::default();
        let grants = Arc::new(NativePermissionGrantAuthority::new(runtime.clone()));
        let consents = NativePermissionConsentAuthority::new(runtime);
        let executor = NativeAuthorityExecutor::new(
            Arc::clone(&native),
            Arc::clone(&workspace),
            Arc::clone(&grants),
        );
        Ok(CandidateFixture {
            _root: root,
            workspace,
            native,
            grants,
            consents,
            executor,
        })
    }

    #[cfg(target_os = "linux")]
    fn bubblewrap_candidate_fixture(mode: NativeMode) -> Result<CandidateFixture, ReCtmError> {
        let root = tempfile::tempdir().map_err(|error| internal(&error.to_string()))?;
        let private = root.path().join("private-outside-workspace");
        let workspace_root = root.path().join("workspace");
        fs::create_dir_all(&private).map_err(|error| internal(&error.to_string()))?;
        fs::create_dir_all(&workspace_root).map_err(|error| internal(&error.to_string()))?;
        let workspace = Arc::new(NativeWorkspace::new(&workspace_root, &private)?);
        let native = Arc::new(NativeToolRuntime::test_attested_bubblewrap(
            Arc::clone(&workspace),
            mode,
            std::slice::from_ref(&private),
        )?);
        let runtime = StoreRuntime::default();
        let grants = Arc::new(NativePermissionGrantAuthority::new(runtime.clone()));
        let consents = NativePermissionConsentAuthority::new(runtime);
        let executor = NativeAuthorityExecutor::new(
            Arc::clone(&native),
            Arc::clone(&workspace),
            Arc::clone(&grants),
        );
        Ok(CandidateFixture {
            _root: root,
            workspace,
            native,
            grants,
            consents,
            executor,
        })
    }

    #[cfg(target_os = "linux")]
    fn command_exists(name: &str) -> bool {
        std::process::Command::new("sh")
            .args(["-c", &format!("command -v {name} >/dev/null 2>&1")])
            .status()
            .is_ok_and(|status| status.success())
    }

    #[cfg(target_os = "linux")]
    fn run_exact_once_exec(
        fixture: &CandidateFixture,
        kind: NativePermissionKind,
        arguments: &Map<String, Value>,
    ) -> Result<Value, ReCtmError> {
        let owner = "owner-a";
        let workspace = fixture.workspace.root().display().to_string();
        assert_eq!(
            fixture
                .executor
                .exec_command_candidate(owner, arguments)
                .map_err(|error| error.code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );
        issue_exec_grant(
            &fixture.grants,
            &fixture.consents,
            owner,
            &workspace,
            kind,
            arguments,
        )?;
        let result = fixture.executor.exec_command_candidate(owner, arguments)?;
        assert_eq!(result["status"], "exited");
        assert_eq!(result["exit_code"], 0);
        assert_eq!(
            fixture
                .executor
                .exec_command_candidate(owner, arguments)
                .map_err(|error| error.code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );
        Ok(result)
    }

    #[cfg(target_os = "linux")]
    fn run_unprivileged_exec(
        fixture: &CandidateFixture,
        arguments: &Map<String, Value>,
    ) -> Result<Value, ReCtmError> {
        let result = fixture
            .executor
            .exec_command_candidate("owner-a", arguments)?;
        if result["status"] != "exited" || result["exit_code"] != 0 {
            return Err(ReCtmError::new(
                "TEST_TOOLCHAIN_EXECUTION_FAILED",
                "Candidate toolchain command did not exit successfully.",
            )
            .with_category(ErrorCategory::Runtime)
            .with_details(serde_json::json!({
                "status":result["status"],
                "exit_code":result["exit_code"]
            })));
        }
        Ok(result)
    }

    #[cfg(target_os = "linux")]
    fn run_named_unprivileged_exec(
        fixture: &CandidateFixture,
        label: &str,
        arguments: &Map<String, Value>,
    ) -> Result<Value, ReCtmError> {
        run_unprivileged_exec(fixture, arguments).map_err(|mut error| {
            error.message = format!("{label}: {}", error.message);
            error
        })
    }

    #[test]
    fn generated_patch_requires_exact_once_grant_and_consumes_it() -> Result<(), ReCtmError> {
        let fixture = candidate_fixture()?;
        fs::create_dir_all(fixture.workspace.root().join("build"))
            .map_err(|error| internal(&error.to_string()))?;
        let owner = "owner-a";
        let workspace_text = fixture.workspace.root().display().to_string();
        let arguments = patch_arguments("build/generated.txt", "approved", false);

        let denied = fixture.executor.apply_patch_candidate(owner, &arguments);
        assert_eq!(
            denied.map_err(|error| error.code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );
        assert!(
            !fixture
                .workspace
                .root()
                .join("build/generated.txt")
                .exists()
        );

        issue_patch_grant(
            &fixture.grants,
            &fixture.consents,
            owner,
            &workspace_text,
            &arguments,
        )?;
        let result = fixture.executor.apply_patch_candidate(owner, &arguments)?;
        assert_eq!(result["dry_run"], false);
        assert_eq!(
            fs::read_to_string(fixture.workspace.root().join("build/generated.txt"))
                .map_err(|error| internal(&error.to_string()))?,
            "approved\n"
        );
        assert_eq!(
            fixture
                .grants
                .authorize_matching_grants(
                    owner,
                    &workspace_text,
                    NativePermissionTool::ApplyPatch,
                    &[NativePermissionKind::WriteGeneratedOrIgnored],
                    &arguments,
                )
                .map_err(|error| error.code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );
        Ok(())
    }

    #[test]
    fn dry_run_and_normal_patch_need_no_explicit_grant() -> Result<(), ReCtmError> {
        let fixture = candidate_fixture()?;
        fs::create_dir_all(fixture.workspace.root().join("build"))
            .map_err(|error| internal(&error.to_string()))?;

        let dry = patch_arguments("build/dry.txt", "dry", true);
        let dry_result = fixture.executor.apply_patch_candidate("owner-a", &dry)?;
        assert_eq!(dry_result["dry_run"], true);
        assert!(!fixture.workspace.root().join("build/dry.txt").exists());

        let normal = patch_arguments("normal.txt", "normal", false);
        let result = fixture.executor.apply_patch_candidate("owner-a", &normal)?;
        assert_eq!(result["dry_run"], false);
        assert_eq!(
            fs::read_to_string(fixture.workspace.root().join("normal.txt"))
                .map_err(|error| internal(&error.to_string()))?,
            "normal\n"
        );
        Ok(())
    }

    #[test]
    fn patch_argument_mutation_cannot_reuse_grant() -> Result<(), ReCtmError> {
        let fixture = candidate_fixture()?;
        fs::create_dir_all(fixture.workspace.root().join("build"))
            .map_err(|error| internal(&error.to_string()))?;
        let owner = "owner-a";
        let workspace_text = fixture.workspace.root().display().to_string();
        let original = patch_arguments("build/original.txt", "one", false);
        let mutated = patch_arguments("build/mutated.txt", "two", false);
        issue_patch_grant(
            &fixture.grants,
            &fixture.consents,
            owner,
            &workspace_text,
            &original,
        )?;

        assert_eq!(
            fixture
                .executor
                .apply_patch_candidate(owner, &mutated)
                .map_err(|error| error.code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );
        assert!(!fixture.workspace.root().join("build/original.txt").exists());
        assert!(!fixture.workspace.root().join("build/mutated.txt").exists());

        fixture.executor.apply_patch_candidate(owner, &original)?;
        assert!(
            fixture
                .workspace
                .root()
                .join("build/original.txt")
                .is_file()
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exec_candidate_covers_all_seven_permission_kinds_on_real_bubblewrap()
    -> Result<(), ReCtmError> {
        if !command_exists("bwrap") || !command_exists("curl") {
            return Ok(());
        }
        let fixture = bubblewrap_candidate_fixture(NativeMode::Safe)?;

        let inline = Map::from_iter([
            (
                "argv".to_owned(),
                serde_json::json!(["sh", "-c", "printf inline"]),
            ),
            ("yield_time_ms".to_owned(), Value::from(30_000)),
        ]);
        assert_eq!(
            run_exact_once_exec(&fixture, NativePermissionKind::InlineScript, &inline)?["stdout"],
            "inline"
        );

        let shell_expansion = Map::from_iter([
            ("cmd".to_owned(), Value::String("printf ${HOME}".to_owned())),
            ("yield_time_ms".to_owned(), Value::from(30_000)),
        ]);
        assert!(
            run_exact_once_exec(
                &fixture,
                NativePermissionKind::ShellExpansion,
                &shell_expansion,
            )?["stdout"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );

        let sensitive_env = Map::from_iter([
            ("argv".to_owned(), serde_json::json!(["env"])),
            (
                "env".to_owned(),
                serde_json::json!({"API_TOKEN":"candidate-value"}),
            ),
            ("yield_time_ms".to_owned(), Value::from(30_000)),
        ]);
        assert!(
            run_exact_once_exec(
                &fixture,
                NativePermissionKind::SensitiveEnv,
                &sensitive_env,
            )?["stdout"]
                .as_str()
                .is_some_and(|value| value.contains("API_TOKEN=candidate-value"))
        );

        let long_timeout = Map::from_iter([
            (
                "argv".to_owned(),
                serde_json::json!(["printf", "long-timeout"]),
            ),
            ("timeout_ms".to_owned(), Value::from(30_001)),
            ("yield_time_ms".to_owned(), Value::from(30_000)),
        ]);
        assert_eq!(
            run_exact_once_exec(&fixture, NativePermissionKind::LongTimeout, &long_timeout)?["stdout"],
            "long-timeout"
        );

        let victim = fixture.workspace.root().join("victim");
        fs::create_dir_all(&victim).map_err(|error| internal(&error.to_string()))?;
        fs::write(victim.join("file.txt"), "delete-me")
            .map_err(|error| internal(&error.to_string()))?;
        let destructive = Map::from_iter([
            (
                "argv".to_owned(),
                serde_json::json!(["rm", "-rf", "victim"]),
            ),
            ("yield_time_ms".to_owned(), Value::from(30_000)),
        ]);
        run_exact_once_exec(
            &fixture,
            NativePermissionKind::DestructiveCommand,
            &destructive,
        )?;
        assert!(!victim.exists());

        let privileged_path = fixture.workspace.root().join("suid-script");
        fs::write(&privileged_path, "#!/bin/sh\nprintf privileged\n")
            .map_err(|error| internal(&error.to_string()))?;
        fs::set_permissions(&privileged_path, fs::Permissions::from_mode(0o4755))
            .map_err(|error| internal(&error.to_string()))?;
        let privileged = Map::from_iter([
            ("argv".to_owned(), serde_json::json!(["./suid-script"])),
            ("yield_time_ms".to_owned(), Value::from(30_000)),
        ]);
        assert_eq!(
            run_exact_once_exec(
                &fixture,
                NativePermissionKind::PrivilegedExecutable,
                &privileged,
            )?["stdout"],
            "privileged"
        );

        let listener =
            TcpListener::bind("127.0.0.1:0").map_err(|error| internal(&error.to_string()))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| internal(&error.to_string()))?;
        let address = listener
            .local_addr()
            .map_err(|error| internal(&error.to_string()))?;
        let server = thread::spawn(move || -> std::io::Result<()> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buffer = [0_u8; 4096];
                        let _ = stream.read(&mut buffer)?;
                        stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nnetwork-ok",
                        )?;
                        return Ok(());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() >= deadline {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "network candidate never connected",
                            ));
                        }
                        thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(error) => return Err(error),
                }
            }
        });
        let network = Map::from_iter([
            (
                "argv".to_owned(),
                serde_json::json!(["curl", "--fail", "--silent", format!("http://{address}")]),
            ),
            ("yield_time_ms".to_owned(), Value::from(30_000)),
        ]);
        assert_eq!(
            run_exact_once_exec(&fixture, NativePermissionKind::Network, &network)?["stdout"],
            "network-ok"
        );
        server
            .join()
            .map_err(|_| internal("network test server panicked"))?
            .map_err(|error| internal(&error.to_string()))?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exec_candidate_preserves_git_latex_sage_and_exposes_magma() -> Result<(), ReCtmError> {
        if !command_exists("bwrap") {
            return Ok(());
        }
        let fixture = bubblewrap_candidate_fixture(NativeMode::Dangerous)?;

        if command_exists("git") {
            let git =
                Map::from_iter([("argv".to_owned(), serde_json::json!(["git", "--version"]))]);
            assert!(
                run_named_unprivileged_exec(&fixture, "git", &git)?["stdout"]
                    .as_str()
                    .is_some_and(|value| value.starts_with("git version "))
            );
        }

        if command_exists("pdflatex") {
            let latex = Map::from_iter([(
                "argv".to_owned(),
                serde_json::json!(["pdflatex", "--version"]),
            )]);
            assert!(
                run_named_unprivileged_exec(&fixture, "pdflatex", &latex)?["stdout"]
                    .as_str()
                    .is_some_and(|value| value.contains("pdfTeX"))
            );
        }

        if command_exists("sage") {
            let sage =
                Map::from_iter([("argv".to_owned(), serde_json::json!(["sage", "--version"]))]);
            assert!(
                run_named_unprivileged_exec(&fixture, "sage", &sage)?["stdout"]
                    .as_str()
                    .is_some_and(|value| !value.trim().is_empty())
            );
        }

        if command_exists("magma") {
            let magma = Map::from_iter([
                ("argv".to_owned(), serde_json::json!(["magma", "-b"])),
                ("stdin".to_owned(), Value::String("quit;\n".to_owned())),
            ]);
            let result = fixture.executor.exec_command_candidate("owner-a", &magma)?;
            assert_eq!(result["status"], "exited");
            let combined = format!(
                "{}\n{}",
                result["stdout"].as_str().unwrap_or_default(),
                result["stderr"].as_str().unwrap_or_default()
            );
            assert!(
                combined.contains("Magma")
                    || combined.to_ascii_lowercase().contains("authorised")
                    || combined.to_ascii_lowercase().contains("authorized")
            );
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exec_candidate_preserves_tty_timeout_and_kill_lifecycle() -> Result<(), ReCtmError> {
        if !command_exists("bwrap") {
            return Ok(());
        }
        let fixture = bubblewrap_candidate_fixture(NativeMode::Safe)?;
        let owner = "owner-a";
        let workspace = fixture.workspace.root().display().to_string();

        let tty = Map::from_iter([
            (
                "argv".to_owned(),
                serde_json::json!(["sh", "-c", "printf tty-ok"]),
            ),
            ("tty".to_owned(), Value::Bool(true)),
            ("yield_time_ms".to_owned(), Value::from(30_000)),
        ]);
        issue_exec_grant(
            &fixture.grants,
            &fixture.consents,
            owner,
            &workspace,
            NativePermissionKind::InlineScript,
            &tty,
        )?;
        let tty_result = fixture
            .executor
            .exec_command_candidate(owner, &tty)
            .map_err(|mut error| {
                error.message = format!("tty: {}", error.message);
                error
            })?;
        assert_eq!(tty_result["status"], "exited");
        assert_eq!(tty_result["exit_code"], 0);
        assert!(
            tty_result["stdout"]
                .as_str()
                .is_some_and(|value| value.contains("tty-ok"))
        );

        let timeout = Map::from_iter([
            ("argv".to_owned(), serde_json::json!(["sleep", "1"])),
            ("timeout_ms".to_owned(), Value::from(10)),
            ("yield_time_ms".to_owned(), Value::from(30_000)),
        ]);
        let timeout_result = fixture
            .executor
            .exec_command_candidate(owner, &timeout)
            .map_err(|mut error| {
                error.message = format!("timeout: {}", error.message);
                error
            })?;
        assert_eq!(timeout_result["status"], "timeout");
        assert_eq!(timeout_result["timed_out"], true);

        let running = Map::from_iter([
            ("argv".to_owned(), serde_json::json!(["sleep", "30"])),
            ("yield_time_ms".to_owned(), Value::from(0)),
        ]);
        let running_result = fixture
            .executor
            .exec_command_candidate(owner, &running)
            .map_err(|mut error| {
                error.message = format!("running: {}", error.message);
                error
            })?;
        assert_eq!(running_result["status"], "running");
        let command_id = running_result["command_id"]
            .as_str()
            .ok_or_else(|| internal("candidate running command omitted command_id"))?;
        let killed = fixture.native.kill_command(&Map::from_iter([
            (
                "command_id".to_owned(),
                Value::String(command_id.to_owned()),
            ),
            ("signal".to_owned(), Value::String("TERM".to_owned())),
            ("wait_ms".to_owned(), Value::from(5_000)),
        ]))?;
        assert_ne!(killed["status"], "running");
        fixture.native.close()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exec_candidate_preserves_tty_stdin_and_descendant_cleanup() -> Result<(), ReCtmError> {
        if !command_exists("bwrap") || !command_exists("cat") {
            return Ok(());
        }
        let fixture = bubblewrap_candidate_fixture(NativeMode::Safe)?;

        let tty = Map::from_iter([
            ("argv".to_owned(), serde_json::json!(["cat"])),
            ("tty".to_owned(), Value::Bool(true)),
            ("yield_time_ms".to_owned(), Value::from(0)),
            ("timeout_ms".to_owned(), Value::from(10_000)),
        ]);
        let started = fixture.executor.exec_command_candidate("owner-a", &tty)?;
        assert_eq!(started["status"], "running");
        let command_id = started["command_id"]
            .as_str()
            .ok_or_else(|| internal("candidate TTY command omitted command_id"))?
            .to_owned();
        let reply = fixture.native.write_stdin(&Map::from_iter([
            ("command_id".to_owned(), Value::String(command_id.clone())),
            (
                "chars".to_owned(),
                Value::String("candidate-stdin-round-trip\n".to_owned()),
            ),
            ("yield_time_ms".to_owned(), Value::from(1_000)),
        ]))?;
        assert!(
            reply["stdout"]
                .as_str()
                .is_some_and(|value| value.contains("candidate-stdin-round-trip"))
        );
        fixture.native.kill_command(&Map::from_iter([
            ("command_id".to_owned(), Value::String(command_id)),
            ("signal".to_owned(), Value::String("TERM".to_owned())),
            ("wait_ms".to_owned(), Value::from(5_000)),
        ]))?;

        let descendant_script = fixture.workspace.root().join("spawn-descendant.sh");
        fs::write(
            &descendant_script,
            "#!/bin/sh\n(sleep 1; printf leaked > descendant-leak.txt) &\nprintf ready\nwait\n",
        )
        .map_err(|error| internal(&error.to_string()))?;
        fs::set_permissions(&descendant_script, fs::Permissions::from_mode(0o755))
            .map_err(|error| internal(&error.to_string()))?;
        let descendant = Map::from_iter([
            (
                "argv".to_owned(),
                serde_json::json!(["./spawn-descendant.sh"]),
            ),
            ("yield_time_ms".to_owned(), Value::from(100)),
            ("timeout_ms".to_owned(), Value::from(10_000)),
        ]);
        let running = fixture
            .executor
            .exec_command_candidate("owner-a", &descendant)?;
        assert_eq!(running["status"], "running");
        assert!(
            running["stdout"]
                .as_str()
                .is_some_and(|value| value.contains("ready"))
        );
        let descendant_command_id = running["command_id"]
            .as_str()
            .ok_or_else(|| internal("descendant candidate omitted command_id"))?;
        fixture.native.kill_command(&Map::from_iter([
            (
                "command_id".to_owned(),
                Value::String(descendant_command_id.to_owned()),
            ),
            ("signal".to_owned(), Value::String("TERM".to_owned())),
            ("wait_ms".to_owned(), Value::from(5_000)),
        ]))?;
        thread::sleep(std::time::Duration::from_millis(1_300));
        assert!(
            !fixture
                .workspace
                .root()
                .join("descendant-leak.txt")
                .exists(),
            "a descendant survived command-group termination and wrote after kill"
        );
        fixture.native.close()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exec_candidate_session_grant_reuses_in_process_and_restart_invalidates()
    -> Result<(), ReCtmError> {
        if !command_exists("bwrap") || !command_exists("curl") {
            return Ok(());
        }
        let fixture = bubblewrap_candidate_fixture(NativeMode::Safe)?;
        let owner = "owner-a";
        let workspace = fixture.workspace.root().display().to_string();
        let listener =
            TcpListener::bind("127.0.0.1:0").map_err(|error| internal(&error.to_string()))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| internal(&error.to_string()))?;
        let address = listener
            .local_addr()
            .map_err(|error| internal(&error.to_string()))?;
        let server = thread::spawn(move || -> std::io::Result<()> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut accepted = 0_u8;
            while accepted < 2 {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buffer = [0_u8; 4096];
                        let _ = stream.read(&mut buffer)?;
                        stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nsession-ok",
                        )?;
                        accepted += 1;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() >= deadline {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "session candidate did not make two network requests",
                            ));
                        }
                        thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        });
        let arguments = Map::from_iter([
            (
                "argv".to_owned(),
                serde_json::json!(["curl", "--fail", "--silent", format!("http://{address}")]),
            ),
            ("yield_time_ms".to_owned(), Value::from(30_000)),
        ]);
        issue_exec_grant_with_scope(
            &fixture.grants,
            &fixture.consents,
            owner,
            &workspace,
            NativePermissionKind::Network,
            NativePermissionScope::Session,
            &arguments,
        )?;
        for _ in 0..2 {
            let result = fixture.executor.exec_command_candidate(owner, &arguments)?;
            assert_eq!(result["status"], "exited");
            assert_eq!(result["stdout"], "session-ok");
        }
        server
            .join()
            .map_err(|_| internal("session network test server panicked"))?
            .map_err(|error| internal(&error.to_string()))?;

        let restarted_grants =
            Arc::new(NativePermissionGrantAuthority::new(StoreRuntime::default()));
        let restarted = NativeAuthorityExecutor::new(
            Arc::clone(&fixture.native),
            Arc::clone(&fixture.workspace),
            restarted_grants,
        );
        assert_eq!(
            restarted
                .exec_command_candidate(owner, &arguments)
                .map_err(|error| error.code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );
        fixture.native.close()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exec_candidate_cross_owner_and_workspace_fail_without_consuming_grant()
    -> Result<(), ReCtmError> {
        if !command_exists("bwrap") {
            return Ok(());
        }
        let fixture = bubblewrap_candidate_fixture(NativeMode::Safe)?;
        let owner = "owner-a";
        let workspace = fixture.workspace.root().display().to_string();
        let arguments = Map::from_iter([
            (
                "argv".to_owned(),
                serde_json::json!(["sh", "-c", "printf binding-ok"]),
            ),
            ("yield_time_ms".to_owned(), Value::from(30_000)),
        ]);
        issue_exec_grant(
            &fixture.grants,
            &fixture.consents,
            owner,
            &workspace,
            NativePermissionKind::InlineScript,
            &arguments,
        )?;
        assert_eq!(
            fixture
                .executor
                .exec_command_candidate("owner-b", &arguments)
                .map_err(|error| error.code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );

        let second_root = fixture._root.path().join("workspace-second");
        let second_private = fixture._root.path().join("private-second");
        fs::create_dir_all(&second_root).map_err(|error| internal(&error.to_string()))?;
        fs::create_dir_all(&second_private).map_err(|error| internal(&error.to_string()))?;
        let second_workspace = Arc::new(NativeWorkspace::new(&second_root, &second_private)?);
        let second_native = Arc::new(NativeToolRuntime::test_attested_bubblewrap(
            Arc::clone(&second_workspace),
            NativeMode::Safe,
            std::slice::from_ref(&second_private),
        )?);
        let second_executor = NativeAuthorityExecutor::new(
            Arc::clone(&second_native),
            second_workspace,
            Arc::clone(&fixture.grants),
        );
        assert_eq!(
            second_executor
                .exec_command_candidate(owner, &arguments)
                .map_err(|error| error.code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );
        second_native.close()?;

        let result = fixture.executor.exec_command_candidate(owner, &arguments)?;
        assert_eq!(result["stdout"], "binding-ok");
        fixture.native.close()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exec_candidate_preserves_trusted_and_dangerous_profiles() -> Result<(), ReCtmError> {
        if !command_exists("bwrap") {
            return Ok(());
        }
        let trusted = bubblewrap_candidate_fixture(NativeMode::Trusted)?;
        let implicit_inline = Map::from_iter([(
            "argv".to_owned(),
            serde_json::json!(["sh", "-c", "printf trusted-inline"]),
        )]);
        assert_eq!(
            trusted
                .executor
                .exec_command_candidate("owner-a", &implicit_inline)?["stdout"],
            "trusted-inline"
        );
        let sensitive = Map::from_iter([
            ("argv".to_owned(), serde_json::json!(["env"])),
            (
                "env".to_owned(),
                serde_json::json!({"API_TOKEN":"trusted-secret"}),
            ),
        ]);
        assert_eq!(
            trusted
                .executor
                .exec_command_candidate("owner-a", &sensitive)
                .map_err(|error| error.code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );
        trusted.native.close()?;

        let dangerous = bubblewrap_candidate_fixture(NativeMode::Dangerous)?;
        let all_implicit = Map::from_iter([
            (
                "argv".to_owned(),
                serde_json::json!(["sh", "-c", "printf \"$API_TOKEN\""]),
            ),
            (
                "env".to_owned(),
                serde_json::json!({"API_TOKEN":"dangerous-value"}),
            ),
            ("timeout_ms".to_owned(), Value::from(30_001)),
            ("yield_time_ms".to_owned(), Value::from(30_000)),
        ]);
        let result = dangerous
            .executor
            .exec_command_candidate("owner-a", &all_implicit)?;
        assert_eq!(result["stdout"], "dangerous-value");
        assert_eq!(
            dangerous.native.server_info()["workflow_authority_inherited"],
            false
        );
        assert_eq!(
            dangerous.native.server_info()["private_vault_visible"],
            false
        );
        dangerous.native.close()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exec_candidate_enforces_timeout_boundary_and_sensitive_env_binding() -> Result<(), ReCtmError>
    {
        if !command_exists("bwrap") {
            return Ok(());
        }
        let fixture = bubblewrap_candidate_fixture(NativeMode::Safe)?;
        let owner = "owner-a";
        let workspace = fixture.workspace.root().display().to_string();
        let boundary = Map::from_iter([
            ("argv".to_owned(), serde_json::json!(["printf", "boundary"])),
            ("timeout_ms".to_owned(), Value::from(30_000)),
        ]);
        assert_eq!(
            fixture.executor.exec_command_candidate(owner, &boundary)?["stdout"],
            "boundary"
        );
        let over = Map::from_iter([
            ("argv".to_owned(), serde_json::json!(["printf", "over"])),
            ("timeout_ms".to_owned(), Value::from(30_001)),
        ]);
        assert_eq!(
            fixture
                .executor
                .exec_command_candidate(owner, &over)
                .map_err(|error| error.code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );
        issue_exec_grant(
            &fixture.grants,
            &fixture.consents,
            owner,
            &workspace,
            NativePermissionKind::LongTimeout,
            &over,
        )?;
        assert_eq!(
            fixture.executor.exec_command_candidate(owner, &over)?["stdout"],
            "over"
        );

        let original = Map::from_iter([
            ("argv".to_owned(), serde_json::json!(["env"])),
            (
                "env".to_owned(),
                serde_json::json!({"API_TOKEN":"exact-one"}),
            ),
        ]);
        let mutated = Map::from_iter([
            ("argv".to_owned(), serde_json::json!(["env"])),
            (
                "env".to_owned(),
                serde_json::json!({"API_TOKEN":"exact-two"}),
            ),
        ]);
        issue_exec_grant(
            &fixture.grants,
            &fixture.consents,
            owner,
            &workspace,
            NativePermissionKind::SensitiveEnv,
            &original,
        )?;
        assert_eq!(
            fixture
                .executor
                .exec_command_candidate(owner, &mutated)
                .map_err(|error| error.code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );
        assert!(
            fixture.executor.exec_command_candidate(owner, &original)?["stdout"]
                .as_str()
                .is_some_and(|value| value.contains("API_TOKEN=exact-one"))
        );
        fixture.native.close()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "MTM-014 A4 target-only real DNS/HTTPS check"]
    fn exec_candidate_real_dns_https_target() -> Result<(), ReCtmError> {
        for command in ["bwrap", "curl"] {
            if !command_exists(command) {
                return Err(internal(&format!(
                    "required MTM-014 A4 target command is missing: {command}"
                )));
            }
        }
        let fixture = bubblewrap_candidate_fixture(NativeMode::Safe)?;
        let owner = "owner-a";
        let workspace = fixture.workspace.root().display().to_string();
        let arguments = Map::from_iter([
            (
                "argv".to_owned(),
                serde_json::json!([
                    "curl",
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "15",
                    "https://example.com/"
                ]),
            ),
            ("yield_time_ms".to_owned(), Value::from(30_000)),
        ]);
        issue_exec_grant(
            &fixture.grants,
            &fixture.consents,
            owner,
            &workspace,
            NativePermissionKind::Network,
            &arguments,
        )?;
        let result = fixture.executor.exec_command_candidate(owner, &arguments)?;
        assert_eq!(result["status"], "exited");
        assert_eq!(result["exit_code"], 0);
        assert!(
            result["stdout"]
                .as_str()
                .is_some_and(|value| value.contains("Example Domain"))
        );
        fixture.native.close()?;
        Ok(())
    }
}
