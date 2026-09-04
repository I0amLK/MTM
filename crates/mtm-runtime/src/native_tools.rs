use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use mtm_contracts::{ErrorCategory, NativeMode, ReCtmError};
use mtm_core::{ExecInvocation, ExecPermissionFacts, check_command_policy};
use mtm_native::{
    CommandManager, CommandManagerConfig, CommandRequest, DEFAULT_SANDBOX_PATH, KillRequest,
    NATIVE_HELPER_PROTOCOL, NativeHelperRequest, NativeHelperResponse, PollRequest,
    SandboxPlanInput, ToolchainExposurePlan, build_bubblewrap_command,
    build_toolchain_exposure_plan, network_namespace_for_mode, plan_sandbox,
    validate_helper_response,
};
use serde_json::{Map, Value};

use crate::helper::invoke_runtime_helper;
use crate::native_permission::collect_exec_permission_facts;
use crate::workspace::NativeWorkspace;

#[derive(Clone)]
pub struct NativeToolRuntime {
    workspace: Arc<NativeWorkspace>,
    mode: NativeMode,
    command_manager: CommandManager,
    backend: String,
    exposure: Option<ToolchainExposurePlan>,
    forbidden_paths: Vec<PathBuf>,
    attestation: Option<Value>,
}

impl NativeToolRuntime {
    pub fn new(
        workspace: Arc<NativeWorkspace>,
        mode: NativeMode,
        backend: &str,
        explicit_roots: &[PathBuf],
        forbidden_paths: &[PathBuf],
    ) -> Result<Self, ReCtmError> {
        let exposure = if backend == "bubblewrap" {
            Some(build_toolchain_exposure_plan(
                mode,
                workspace.root(),
                forbidden_paths,
                explicit_roots,
                std::env::var("PATH").ok().as_deref(),
            )?)
        } else {
            None
        };
        let attestation = if let Some(plan) = &exposure {
            let request = NativeHelperRequest {
                protocol: NATIVE_HELPER_PROTOCOL.to_owned(),
                operation: "attest".to_owned(),
                request_id: "runtime-startup-attestation".to_owned(),
                workspace: workspace.root().display().to_string(),
                forbidden_paths: forbidden_paths
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect(),
                mode,
                argv: Vec::new(),
                workdir: ".".to_owned(),
                timeout_ms: 15_000,
                host_path: std::env::var("PATH").unwrap_or_default(),
                extra_read_roots: plan
                    .read_only_roots
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect(),
            };
            let response = invoke_runtime_helper(&request)?;
            Some(validate_helper_response(
                &response,
                &request,
                mode == NativeMode::Safe,
                plan.read_only_roots.len(),
            )?)
        } else {
            None
        };
        Ok(Self {
            workspace,
            mode,
            command_manager: CommandManager::new(CommandManagerConfig::default()),
            backend: backend.to_owned(),
            exposure,
            forbidden_paths: forbidden_paths.to_vec(),
            attestation,
        })
    }

    #[must_use]
    pub fn mode(&self) -> NativeMode {
        self.mode
    }

    #[must_use]
    pub fn workspace(&self) -> &NativeWorkspace {
        &self.workspace
    }

    pub fn server_info(&self) -> Value {
        serde_json::json!({
            "workspace":self.workspace.root(),
            "native_mode":self.mode.as_str(),
            "workflow_authority_inherited":false,
            "private_vault_visible":false,
            "native_exec_backend":if self.backend=="bubblewrap"{"BubblewrapExecBackend"}else{"DisabledExecBackend"},
            "native_exec_attestation":self.attestation,
            "toolchain_exposure":self.exposure.as_ref().map_or_else(
                ||serde_json::json!({"policy":"unavailable","resolved_read_only_root_count":0}),
                |plan|plan.summary(false)
            ),
            "ctm_native_tool_compatibility":"18_of_18_surface",
            "command_lifecycle":{"max_active_commands":16,"write_stdin":true,"read_output":true,"kill_command":true}
        })
    }

    pub fn check_exec_environment(&self) -> Value {
        let global_tmp = match self.mode {
            NativeMode::Safe => "blocked",
            NativeMode::Trusted => "tmp-prefix",
            NativeMode::Dangerous => "allowed",
        };
        let mut warnings = Vec::new();
        if self.mode == NativeMode::Dangerous {
            warnings.push("permission_mode=dangerous disables MCP safety gates");
        }
        if self.backend != "bubblewrap" {
            warnings.push("Full interactive command lifecycle requires the built-in bubblewrap backend; disabled/external helpers may execute synchronously only.");
        }
        serde_json::json!({
            "ok":true,"native_mode":self.mode.as_str(),"permission_mode":self.mode.as_str(),
            "workspace":self.workspace.root(),"network_allowed":self.mode!=NativeMode::Safe,
            "runtime_dir":"/tmp","home":"/home/re-ctm","tmpdir":"/tmp","cache_dir":"/tmp/cache",
            "native_exec_backend":if self.backend=="bubblewrap"{"BubblewrapExecBackend"}else{"DisabledExecBackend"},
            "hard_isolation_attested":self.attestation.is_some(),"command_lifecycle_supported":self.backend=="bubblewrap",
            "max_active_commands":16,"private_vault_visible":false,"landlock_enabled":false,"landlock_abi":Value::Null,
            "global_tmp_write":global_tmp,"toolchain_exposure":self.exposure.as_ref().map_or_else(
                ||serde_json::json!({"policy":"unavailable","mount_mode":"none","resolved_read_only_root_count":0}),
                |plan|plan.summary(true)
            ),"warnings":warnings
        })
    }

    pub fn request_permissions(&self, arguments: &Map<String, Value>) -> Value {
        if self.mode == NativeMode::Dangerous {
            return serde_json::json!({
                "ok":true,"status":"granted","grant_id":"dangerously-skip-all-permissions","expires_at":Value::Null,
                "constraints":{"mode":"dangerously_skip_all_permissions","workspace":self.workspace.root(),"requested":arguments},
                "warnings":["dangerously-skip-all-permissions is enabled; permission-gated operations are auto-granted"]
            });
        }
        serde_json::json!({
            "ok":false,"status":"unsupported","grant_id":Value::Null,"expires_at":Value::Null,
            "error":{"code":"ELICITATION_UNSUPPORTED","message":"Permission elicitation is not available for this client.","category":"permission","retryable":false,"details":{"requested":arguments}}
        })
    }

    pub fn exec_command(&self, arguments: &Map<String, Value>) -> Result<Value, ReCtmError> {
        if self.backend != "bubblewrap" {
            return Err(ReCtmError::new(
                "NATIVE_EXEC_DISABLED",
                "Native command execution is disabled.",
            )
            .with_category(ErrorCategory::Permission));
        }
        if self.attestation.is_none() {
            return Err(ReCtmError::new(
                "NATIVE_ISOLATION_REQUIRED",
                "Native execution backend has not completed a valid hard-isolation attestation.",
            )
            .with_category(ErrorCategory::Security));
        }
        let cmd = arguments
            .get("cmd")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let raw_argv = arguments.get("argv").and_then(Value::as_array);
        let (argv, policy_text) = if !cmd.is_empty() {
            (
                vec!["/bin/sh".to_owned(), "-lc".to_owned(), cmd.to_owned()],
                cmd.to_owned(),
            )
        } else if let Some(items) = raw_argv {
            let parsed = items
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| validation("argv must contain only strings"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if parsed.is_empty() {
                return Err(validation("cmd is required"));
            }
            let policy_text = parsed.join(" ");
            (parsed, policy_text)
        } else {
            return Err(validation("cmd is required"));
        };
        let workdir = arguments
            .get("workdir")
            .or_else(|| arguments.get("cwd"))
            .and_then(Value::as_str)
            .unwrap_or(".");
        if let (Some(left), Some(right)) = (
            arguments.get("workdir").and_then(Value::as_str),
            arguments.get("cwd").and_then(Value::as_str),
        ) && left != right
        {
            return Err(validation("workdir and cwd refer to different directories"));
        }
        let resolved = self.workspace.resolve_existing(workdir)?;
        if !resolved.path.is_dir() {
            return Err(validation_code(
                "NOT_A_DIRECTORY",
                "workdir is not a directory.",
            ));
        }
        let environment = arguments
            .get("env")
            .and_then(Value::as_object)
            .map(|object| {
                object
                    .iter()
                    .map(|(key, value)| {
                        value
                            .as_str()
                            .map(|text| (key.clone(), text.to_owned()))
                            .ok_or_else(|| {
                                validation("env must be an object whose values are strings")
                            })
                    })
                    .collect::<Result<BTreeMap<_, _>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        check_command_policy(self.mode, &policy_text, &environment)?;
        let exposure = self
            .exposure
            .as_ref()
            .ok_or_else(|| internal("bubblewrap exposure plan is missing"))?;
        let host_path = std::env::var("PATH").ok();
        let sandbox_plan = plan_sandbox(&SandboxPlanInput {
            workspace: self.workspace.root(),
            workdir: &resolved.display,
            network: network_namespace_for_mode(self.mode),
            argv: &argv,
            environment: &environment,
            sandbox_path: host_path.as_deref(),
            read_only_roots: &exposure.read_only_roots,
            forbidden_paths: &self.forbidden_paths,
            probe_executable: None,
        })?;
        let command = build_bubblewrap_command(&sandbox_plan)?;
        self.command_manager.start(CommandRequest {
            argv: command,
            env: BTreeMap::new(),
            timeout_ms: integer(arguments, "timeout_ms", 30_000)?,
            yield_time_ms: integer(arguments, "yield_time_ms", 10_000)?,
            max_output_bytes: usize_value(arguments, "max_output_bytes", 65_536)?,
            stdin: arguments
                .get("stdin")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            tty: arguments
                .get("tty")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            verbosity: arguments
                .get("verbosity")
                .and_then(Value::as_str)
                .map(str::to_owned),
            preview_bytes: usize_value(arguments, "preview_bytes", 4096)?,
        })
    }

    /// Collect D3 executable facts without affecting the authoritative command
    /// policy or starting a process.
    pub fn collect_shadow_exec_permission_facts(
        &self,
        invocation: &ExecInvocation,
    ) -> Result<ExecPermissionFacts, ReCtmError> {
        let sandbox_path = self
            .exposure
            .as_ref()
            .map_or(DEFAULT_SANDBOX_PATH, |plan| plan.sandbox_path.as_str());
        let read_only_roots = self
            .exposure
            .as_ref()
            .map_or(&[][..], |plan| plan.read_only_roots.as_slice());
        collect_exec_permission_facts(
            invocation,
            self.workspace.root(),
            sandbox_path,
            read_only_roots,
        )
    }

    pub fn write_stdin(&self, arguments: &Map<String, Value>) -> Result<Value, ReCtmError> {
        self.command_manager.poll(PollRequest {
            command_id: required_text(arguments, "command_id")?.to_owned(),
            chars: arguments
                .get("chars")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            yield_time_ms: integer(arguments, "yield_time_ms", 10_000)?,
            max_output_bytes: usize_value(arguments, "max_output_bytes", 65_536)?,
            verbosity: arguments
                .get("verbosity")
                .and_then(Value::as_str)
                .map(str::to_owned),
            preview_bytes: usize_value(arguments, "preview_bytes", 4096)?,
        })
    }

    pub fn kill_command(&self, arguments: &Map<String, Value>) -> Result<Value, ReCtmError> {
        self.command_manager.kill(KillRequest {
            command_id: required_text(arguments, "command_id")?.to_owned(),
            signal: arguments
                .get("signal")
                .and_then(Value::as_str)
                .unwrap_or("TERM")
                .to_owned(),
            wait_ms: integer(arguments, "wait_ms", 5000)?,
            kill_wait_ms: integer(arguments, "kill_wait_ms", 2000)?,
            max_output_bytes: usize_value(arguments, "max_output_bytes", 65_536)?,
            verbosity: arguments
                .get("verbosity")
                .and_then(Value::as_str)
                .map(str::to_owned),
            preview_bytes: usize_value(arguments, "preview_bytes", 4096)?,
        })
    }

    pub fn read_output(&self, arguments: &Map<String, Value>) -> Result<Value, ReCtmError> {
        self.command_manager.read_output(
            required_text(arguments, "output_ref")?,
            arguments.get("stream").and_then(Value::as_str),
            usize_value(arguments, "offset", 0)?,
            usize_value(arguments, "limit", 4096)?,
        )
    }

    pub fn close(&self) -> Result<(), ReCtmError> {
        self.command_manager.close()
    }

    pub(crate) fn run_fixed_helper_in_workspace(
        &self,
        workspace: &std::path::Path,
        argv: &[String],
        timeout_ms: u64,
    ) -> Result<Value, ReCtmError> {
        if self.backend != "bubblewrap" || self.attestation.is_none() {
            return Err(ReCtmError::new(
                "NATIVE_ISOLATION_REQUIRED",
                "The fixed adapter requires an attested Bubblewrap backend.",
            )
            .with_category(ErrorCategory::Security));
        }
        let plan = self
            .exposure
            .as_ref()
            .ok_or_else(|| internal("bubblewrap exposure plan is missing"))?;
        let request = NativeHelperRequest {
            protocol: NATIVE_HELPER_PROTOCOL.to_owned(),
            operation: "execute".to_owned(),
            request_id: format!("fixed-adapter-{}", std::process::id()),
            workspace: workspace.display().to_string(),
            forbidden_paths: self
                .forbidden_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
            mode: NativeMode::Safe,
            argv: argv.to_vec(),
            workdir: ".".to_owned(),
            timeout_ms,
            host_path: std::env::var("PATH").unwrap_or_default(),
            extra_read_roots: plan
                .read_only_roots
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
        };
        let response = invoke_runtime_helper(&request)?;
        validated_execution_response(response, &request, true, plan.read_only_roots.len())
    }
}

fn validated_execution_response(
    response: NativeHelperResponse,
    request: &NativeHelperRequest,
    require_safe_network: bool,
    expected_toolchain_roots: usize,
) -> Result<Value, ReCtmError> {
    validate_helper_response(
        &response,
        request,
        require_safe_network,
        expected_toolchain_roots,
    )?;
    const REQUIRED_EXECUTION_FIELDS: [&str; 9] = [
        "status",
        "exit_code",
        "signal",
        "timed_out",
        "elapsed_ms",
        "stdout",
        "stderr",
        "stdout_meta",
        "stderr_meta",
    ];
    let missing = REQUIRED_EXECUTION_FIELDS
        .iter()
        .filter(|key| !response.fields.contains_key(**key))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(ReCtmError::new(
            "NATIVE_HELPER_PROTOCOL_ERROR",
            "Native helper execute response omitted required execution fields.",
        )
        .with_category(ErrorCategory::Runtime)
        .with_details(serde_json::json!({"missing_fields":missing})));
    }
    Ok(Value::Object(response.fields.into_iter().collect()))
}

fn required_text<'a>(arguments: &'a Map<String, Value>, key: &str) -> Result<&'a str, ReCtmError> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| validation(&format!("{key} is required")))
}

fn integer(arguments: &Map<String, Value>, key: &str, default: u64) -> Result<u64, ReCtmError> {
    match arguments.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(value) => value
            .as_u64()
            .ok_or_else(|| validation(&format!("{key} must be a non-negative integer"))),
    }
}

fn usize_value(
    arguments: &Map<String, Value>,
    key: &str,
    default: usize,
) -> Result<usize, ReCtmError> {
    let value = integer(arguments, key, u64::try_from(default).unwrap_or(u64::MAX))?;
    usize::try_from(value).map_err(|_| validation(&format!("{key} is too large")))
}

fn validation(message: &str) -> ReCtmError {
    ReCtmError::new("INVALID_ARGUMENT", message).with_category(ErrorCategory::Validation)
}

fn validation_code(code: &str, message: &str) -> ReCtmError {
    ReCtmError::new(code, message).with_category(ErrorCategory::Validation)
}

fn internal(message: &str) -> ReCtmError {
    ReCtmError::new("INTERNAL_ERROR", message).with_category(ErrorCategory::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validated_execution_response_preserves_execution_fields() -> Result<(), ReCtmError> {
        let request = NativeHelperRequest {
            protocol: NATIVE_HELPER_PROTOCOL.to_owned(),
            operation: "execute".to_owned(),
            request_id: "test-request".to_owned(),
            workspace: "/tmp/mtm-runtime-test".to_owned(),
            forbidden_paths: Vec::new(),
            mode: NativeMode::Safe,
            argv: vec!["/usr/bin/printf".to_owned(), "ok".to_owned()],
            workdir: ".".to_owned(),
            timeout_ms: 1000,
            host_path: "/usr/bin".to_owned(),
            extra_read_roots: Vec::new(),
        };
        let attestation = serde_json::json!({
            "hard_isolation":true,
            "workspace_mounted":true,
            "forbidden_paths_hidden":true,
            "no_privilege_escalation":true,
            "mount_namespace":true,
            "user_namespace":true,
            "pid_namespace":true,
            "ipc_namespace":true,
            "uts_namespace":true,
            "nested_user_namespaces_disabled":true,
            "parent_environment_cleared":true,
            "capabilities_dropped":true,
            "toolchain_roots_validated":true,
            "private_vault_mounted":false,
            "network_isolated":true,
            "toolchain_read_only_root_count":0
        });
        let response = NativeHelperResponse {
            protocol: NATIVE_HELPER_PROTOCOL.to_owned(),
            operation: "execute".to_owned(),
            request_id: "test-request".to_owned(),
            ok: true,
            fields: BTreeMap::from([
                ("status".to_owned(), Value::String("exited".to_owned())),
                ("exit_code".to_owned(), Value::from(0)),
                ("signal".to_owned(), Value::Null),
                ("timed_out".to_owned(), Value::Bool(false)),
                ("elapsed_ms".to_owned(), Value::from(1)),
                ("stdout".to_owned(), Value::String("ok".to_owned())),
                ("stderr".to_owned(), Value::String(String::new())),
                ("stdout_meta".to_owned(), serde_json::json!({})),
                ("stderr_meta".to_owned(), serde_json::json!({})),
                ("attestation".to_owned(), attestation),
            ]),
        };
        let payload = validated_execution_response(response, &request, true, 0)?;
        assert_eq!(payload.get("exit_code"), Some(&Value::from(0)));
        assert_eq!(payload.get("stdout"), Some(&Value::String("ok".to_owned())));
        Ok(())
    }
}
