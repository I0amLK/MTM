use std::collections::BTreeSet;
use std::sync::Arc;

use mtm_contracts::{ErrorCategory, ReCtmError};
use mtm_core::{
    EffectiveNativePolicy, NativeInvocation, PatchInvocation, classify_patch_permissions,
};
use serde_json::{Map, Value};

use crate::{NativeToolRuntime, NativeWorkspace};

/// Production Native execution seam.
///
/// The type remains crate-private so the public MCP backend is the only production
/// caller. Since MTM-017 the dangerous profile is the only Native mode and it
/// implicitly grants every permission kind, so no grant ledger is consulted. Risk
/// classification, executable revalidation and protected-path facts still run
/// before any command start or patch mutation, and an incomplete profile fails
/// closed.
pub(crate) struct NativeAuthorityExecutor {
    native: Arc<NativeToolRuntime>,
    workspace: Arc<NativeWorkspace>,
}

impl NativeAuthorityExecutor {
    pub(crate) fn new(native: Arc<NativeToolRuntime>, workspace: Arc<NativeWorkspace>) -> Self {
        Self { native, workspace }
    }

    pub(crate) fn exec_command(&self, arguments: &Map<String, Value>) -> Result<Value, ReCtmError> {
        let prepared = self.native.prepare_authority_exec(arguments)?;
        let revalidated = self.native.revalidate_authority_exec(prepared)?;
        self.native.start_authority_exec(revalidated)
    }

    pub(crate) fn apply_patch(&self, arguments: &Map<String, Value>) -> Result<Value, ReCtmError> {
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
        self.workspace
            .commit_prepared_patch_with_authorization(prepared, || {
                if policy.missing().is_empty() {
                    Ok(())
                } else {
                    Err(ReCtmError::new(
                        "NATIVE_PERMISSION_PROFILE_INCOMPLETE",
                        "The Native mode profile does not cover every permission this patch requires.",
                    )
                    .with_category(ErrorCategory::Security))
                }
            })
    }
}

fn internal(message: &str) -> ReCtmError {
    ReCtmError::new("NATIVE_PERMISSION_INTERNAL_ERROR", message)
        .with_category(ErrorCategory::Internal)
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::io::{Read, Write};
    #[cfg(target_os = "linux")]
    use std::net::TcpListener;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(target_os = "linux")]
    use std::thread;

    use mtm_contracts::NativeMode;
    #[cfg(target_os = "linux")]
    use mtm_contracts::NativePermissionKind;

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

    struct CandidateFixture {
        _root: tempfile::TempDir,
        workspace: Arc<NativeWorkspace>,
        native: Arc<NativeToolRuntime>,
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
            NativeMode::Dangerous,
            "disabled",
            &[],
            std::slice::from_ref(&private),
        )?);
        let executor = NativeAuthorityExecutor::new(Arc::clone(&native), Arc::clone(&workspace));
        Ok(CandidateFixture {
            _root: root,
            workspace,
            native,
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
        let executor = NativeAuthorityExecutor::new(Arc::clone(&native), Arc::clone(&workspace));
        Ok(CandidateFixture {
            _root: root,
            workspace,
            native,
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

    /// Run a command whose risk the classifier must still record, with no grant.
    #[cfg(target_os = "linux")]
    fn run_classified_exec(
        fixture: &CandidateFixture,
        kind: NativePermissionKind,
        arguments: &Map<String, Value>,
    ) -> Result<Value, ReCtmError> {
        let prepared = fixture.native.prepare_authority_exec(arguments)?;
        assert!(prepared.policy().required().contains(&kind));
        assert!(prepared.policy().missing().is_empty());
        let result = fixture.executor.exec_command(arguments)?;
        assert_eq!(result["status"], "exited");
        assert_eq!(result["exit_code"], 0);
        Ok(result)
    }

    #[cfg(target_os = "linux")]
    fn run_unprivileged_exec(
        fixture: &CandidateFixture,
        arguments: &Map<String, Value>,
    ) -> Result<Value, ReCtmError> {
        let result = fixture.executor.exec_command(arguments)?;
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
    fn generated_patch_is_classified_and_applied_without_grant() -> Result<(), ReCtmError> {
        let fixture = candidate_fixture()?;
        fs::create_dir_all(fixture.workspace.root().join("build"))
            .map_err(|error| internal(&error.to_string()))?;
        let arguments = patch_arguments("build/generated.txt", "approved", false);
        let result = fixture.executor.apply_patch(&arguments)?;
        assert_eq!(result["dry_run"], false);
        assert_eq!(
            fs::read_to_string(fixture.workspace.root().join("build/generated.txt"))
                .map_err(|error| internal(&error.to_string()))?,
            "approved\n"
        );
        Ok(())
    }

    #[test]
    fn dry_run_and_normal_patch_need_no_explicit_grant() -> Result<(), ReCtmError> {
        let fixture = candidate_fixture()?;
        fs::create_dir_all(fixture.workspace.root().join("build"))
            .map_err(|error| internal(&error.to_string()))?;

        let dry = patch_arguments("build/dry.txt", "dry", true);
        let dry_result = fixture.executor.apply_patch(&dry)?;
        assert_eq!(dry_result["dry_run"], true);
        assert!(!fixture.workspace.root().join("build/dry.txt").exists());

        let normal = patch_arguments("normal.txt", "normal", false);
        let result = fixture.executor.apply_patch(&normal)?;
        assert_eq!(result["dry_run"], false);
        assert_eq!(
            fs::read_to_string(fixture.workspace.root().join("normal.txt"))
                .map_err(|error| internal(&error.to_string()))?,
            "normal\n"
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exec_candidate_runs_all_seven_permission_kinds_without_grants() -> Result<(), ReCtmError> {
        if !command_exists("bwrap") || !command_exists("curl") {
            return Ok(());
        }
        let fixture = bubblewrap_candidate_fixture(NativeMode::Dangerous)?;

        let inline = Map::from_iter([
            (
                "argv".to_owned(),
                serde_json::json!(["sh", "-c", "printf inline"]),
            ),
            ("yield_time_ms".to_owned(), Value::from(30_000)),
        ]);
        assert_eq!(
            run_classified_exec(&fixture, NativePermissionKind::InlineScript, &inline)?["stdout"],
            "inline"
        );

        let shell_expansion = Map::from_iter([
            ("cmd".to_owned(), Value::String("printf ${HOME}".to_owned())),
            ("yield_time_ms".to_owned(), Value::from(30_000)),
        ]);
        assert!(
            run_classified_exec(
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
            run_classified_exec(
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
            run_classified_exec(&fixture, NativePermissionKind::LongTimeout, &long_timeout)?["stdout"],
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
        run_classified_exec(
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
            run_classified_exec(
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
            run_classified_exec(&fixture, NativePermissionKind::Network, &network)?["stdout"],
            "network-ok"
        );
        server
            .join()
            .map_err(|_| internal("network test server panicked"))?
            .map_err(|error| internal(&error.to_string()))?;
        Ok(())
    }

    #[derive(Debug, Eq, PartialEq)]
    enum MagmaProbeOutcome {
        Functional,
        HostLicenseUnavailable,
    }

    fn magma_probe_outcome(result: &Value) -> Option<MagmaProbeOutcome> {
        if result["status"] != "exited"
            || result["timed_out"] != false
            || !result.get("signal").is_some_and(Value::is_null)
        {
            return None;
        }
        let stdout = result["stdout"].as_str()?;
        let stderr = result["stderr"].as_str()?;
        let exit_code = result["exit_code"].as_i64()?;
        if exit_code == 0 && stdout.lines().filter(|line| line.trim() == "42").count() == 1 {
            Some(MagmaProbeOutcome::Functional)
        } else {
            let combined = format!("{stdout}\n{stderr}").to_ascii_lowercase();
            (exit_code == 1
                && combined.contains("magma")
                && (combined.contains("not authorised") || combined.contains("not authorized")))
            .then_some(MagmaProbeOutcome::HostLicenseUnavailable)
        }
    }

    #[test]
    fn magma_batch_probe_requires_computation_not_a_banner() {
        let good = serde_json::json!({
            "status":"exited","exit_code":0,"timed_out":false,"signal":null,
            "stdout":"42\n","stderr":""
        });
        assert_eq!(
            magma_probe_outcome(&good),
            Some(MagmaProbeOutcome::Functional)
        );
        for (field, value) in [
            ("stdout", Value::String(String::new())),
            ("stdout", Value::String("Magma\n".to_owned())),
            ("stdout", Value::String("142\n".to_owned())),
            ("stdout", Value::String("42\n42\n".to_owned())),
            ("stdout", Value::Null),
            ("exit_code", Value::from(1)),
            ("exit_code", Value::Null),
            ("status", Value::String("running".to_owned())),
            ("timed_out", Value::Bool(true)),
            ("signal", Value::String("SIGTERM".to_owned())),
        ] {
            let mut changed = good.clone();
            changed[field] = value;
            assert_eq!(magma_probe_outcome(&changed), None);
        }
    }

    #[test]
    fn magma_license_denial_is_distinct_from_functional_execution() {
        let denied = serde_json::json!({
            "status":"exited","exit_code":1,"timed_out":false,"signal":null,
            "stdout":"","stderr":"Magma is not authorised to run on this machine."
        });
        assert_eq!(
            magma_probe_outcome(&denied),
            Some(MagmaProbeOutcome::HostLicenseUnavailable)
        );
        for message in [
            "Magma: startup failed",
            "authorized",
            "",
            "Magma: license file missing",
        ] {
            let mut changed = denied.clone();
            changed["stderr"] = Value::String(message.to_owned());
            assert_eq!(magma_probe_outcome(&changed), None);
        }
        let mut changed = denied;
        changed["exit_code"] = Value::from(0);
        assert_eq!(magma_probe_outcome(&changed), None);
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
                (
                    "stdin".to_owned(),
                    Value::String("print 6*7;\nquit;\n".to_owned()),
                ),
                ("timeout_ms".to_owned(), Value::from(30_000)),
                ("yield_time_ms".to_owned(), Value::from(30_000)),
            ]);
            let result = fixture.executor.exec_command(&magma)?;
            match magma_probe_outcome(&result) {
                Some(MagmaProbeOutcome::Functional) => {}
                Some(MagmaProbeOutcome::HostLicenseUnavailable) => {
                    // Preserve this optional source smoke's historical license
                    // classification. F6 still requires actual algebra success.
                    eprintln!("MTM_SOURCE_MAGMA host_license_unavailable functional_passed=false");
                }
                None => {
                    return Err(internal(
                        "Magma probe returned neither arithmetic success nor a recognized host-license denial",
                    ));
                }
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exec_candidate_preserves_tty_timeout_and_kill_lifecycle() -> Result<(), ReCtmError> {
        if !command_exists("bwrap") {
            return Ok(());
        }
        let fixture = bubblewrap_candidate_fixture(NativeMode::Dangerous)?;

        let tty = Map::from_iter([
            (
                "argv".to_owned(),
                serde_json::json!(["sh", "-c", "printf tty-ok"]),
            ),
            ("tty".to_owned(), Value::Bool(true)),
            ("yield_time_ms".to_owned(), Value::from(30_000)),
        ]);
        let tty_result = fixture.executor.exec_command(&tty).map_err(|mut error| {
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
            .exec_command(&timeout)
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
            .exec_command(&running)
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
        let fixture = bubblewrap_candidate_fixture(NativeMode::Dangerous)?;

        let tty = Map::from_iter([
            ("argv".to_owned(), serde_json::json!(["cat"])),
            ("tty".to_owned(), Value::Bool(true)),
            ("yield_time_ms".to_owned(), Value::from(0)),
            ("timeout_ms".to_owned(), Value::from(10_000)),
        ]);
        let started = fixture.executor.exec_command(&tty)?;
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
        let running = fixture.executor.exec_command(&descendant)?;
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
    fn exec_candidate_classifies_timeout_boundary_and_sensitive_env() -> Result<(), ReCtmError> {
        if !command_exists("bwrap") {
            return Ok(());
        }
        let fixture = bubblewrap_candidate_fixture(NativeMode::Dangerous)?;
        let boundary = Map::from_iter([
            ("argv".to_owned(), serde_json::json!(["printf", "boundary"])),
            ("timeout_ms".to_owned(), Value::from(30_000)),
        ]);
        let prepared = fixture.native.prepare_authority_exec(&boundary)?;
        assert!(
            !prepared
                .policy()
                .required()
                .contains(&NativePermissionKind::LongTimeout)
        );
        assert_eq!(
            fixture.executor.exec_command(&boundary)?["stdout"],
            "boundary"
        );
        let over = Map::from_iter([
            ("argv".to_owned(), serde_json::json!(["printf", "over"])),
            ("timeout_ms".to_owned(), Value::from(30_001)),
        ]);
        assert_eq!(
            run_classified_exec(&fixture, NativePermissionKind::LongTimeout, &over)?["stdout"],
            "over"
        );
        let sensitive = Map::from_iter([
            ("argv".to_owned(), serde_json::json!(["env"])),
            (
                "env".to_owned(),
                serde_json::json!({"API_TOKEN":"exact-one"}),
            ),
        ]);
        assert!(
            run_classified_exec(&fixture, NativePermissionKind::SensitiveEnv, &sensitive)?["stdout"]
                .as_str()
                .is_some_and(|value| value.contains("API_TOKEN=exact-one"))
        );
        fixture.native.close()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn patch_candidate_git_ignored_path_is_applied_without_grant() -> Result<(), ReCtmError> {
        if !command_exists("git") {
            return Ok(());
        }
        let fixture = candidate_fixture()?;
        let workspace_text = fixture.workspace.root().display().to_string();
        let status = std::process::Command::new("git")
            .args(["-C", &workspace_text, "init", "-q"])
            .status()
            .map_err(|error| internal(&error.to_string()))?;
        if !status.success() {
            return Err(internal("git init failed in ignored-patch candidate test"));
        }
        fs::write(fixture.workspace.root().join(".gitignore"), "ignored.txt\n")
            .map_err(|error| internal(&error.to_string()))?;
        let arguments = patch_arguments("ignored.txt", "approved-ignored", false);
        let result = fixture.executor.apply_patch(&arguments)?;
        assert_eq!(result["dry_run"], false);
        assert_eq!(
            fs::read_to_string(fixture.workspace.root().join("ignored.txt"))
                .map_err(|error| internal(&error.to_string()))?,
            "approved-ignored\n"
        );
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
        let fixture = bubblewrap_candidate_fixture(NativeMode::Dangerous)?;
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
        let result = run_classified_exec(&fixture, NativePermissionKind::Network, &arguments)?;
        assert!(
            result["stdout"]
                .as_str()
                .is_some_and(|value| value.contains("Example Domain"))
        );
        fixture.native.close()?;
        Ok(())
    }
}
