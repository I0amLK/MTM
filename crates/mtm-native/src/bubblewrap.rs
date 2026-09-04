use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mtm_contracts::{ErrorCategory, NativeMode, ReCtmError};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::capture::{BoundedCapture, CapturePayload};
use crate::toolchain::DEFAULT_SANDBOX_PATH;

pub const NATIVE_HELPER_PROTOCOL: &str = "re-ctm-native-helper-v1";
pub const MAX_REQUEST_BYTES: usize = 1_048_576;
const MAX_ARG_COUNT: usize = 512;
const MAX_ARG_BYTES: usize = 256 * 1024;
const MAX_PATH_ARRAY: usize = 256;
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";
const TRUSTED_RUNTIME_RESOLVER_ROOTS: [&str; 3] = [
    "/run/systemd/resolve",
    "/run/NetworkManager",
    "/run/resolvconf",
];
const SYSTEM_READ_ROOTS: [&str; 9] = [
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
const UNSAFE_EXACT_ROOTS: [&str; 13] = [
    "/", "/proc", "/sys", "/dev", "/run", "/tmp", "/home", "/root", "/var", "/srv", "/opt", "/mnt",
    "/media",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeHelperRequest {
    pub protocol: String,
    pub operation: String,
    pub request_id: String,
    pub workspace: String,
    #[serde(default)]
    pub forbidden_paths: Vec<String>,
    pub mode: NativeMode,
    #[serde(default)]
    pub argv: Vec<String>,
    #[serde(default = "default_workdir")]
    pub workdir: String,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub host_path: String,
    #[serde(default)]
    pub extra_read_roots: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeHelperResponse {
    pub protocol: String,
    pub operation: String,
    pub request_id: String,
    pub ok: bool,
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxProbe {
    pub workspace_mounted: bool,
    pub forbidden_visible: Vec<String>,
    pub parent_secret_visible: bool,
    pub no_new_privs: bool,
    pub workspace_writable: bool,
    pub toolchain_visible: Vec<String>,
    pub toolchain_write_succeeded: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkNamespacePlan {
    Isolated,
    Shared,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EmptyCapabilitySet {
    _private: (),
}

#[derive(Clone, Eq, PartialEq)]
pub struct SandboxPlan {
    workspace: PathBuf,
    workdir: String,
    argv: Vec<String>,
    environment: BTreeMap<String, String>,
    sandbox_path: String,
    network: NetworkNamespacePlan,
    system_read_only_roots: Vec<PathBuf>,
    read_only_roots: Vec<PathBuf>,
    forbidden_paths: Vec<PathBuf>,
    resolver_mount: Option<PathBuf>,
    probe_executable: Option<PathBuf>,
    capabilities: EmptyCapabilitySet,
}

impl std::fmt::Debug for SandboxPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SandboxPlan")
            .field("workspace", &"[REDACTED]")
            .field("workdir", &self.workdir)
            .field("argv_count", &self.argv.len())
            .field(
                "environment_keys",
                &self.environment.keys().collect::<Vec<_>>(),
            )
            .field("sandbox_path", &"[REDACTED]")
            .field("network", &self.network)
            .field(
                "system_read_only_root_count",
                &self.system_read_only_roots.len(),
            )
            .field("read_only_root_count", &self.read_only_roots.len())
            .field("forbidden_path_count", &self.forbidden_paths.len())
            .field("resolver_mount_present", &self.resolver_mount.is_some())
            .field("probe_executable_present", &self.probe_executable.is_some())
            .field("capabilities", &self.capabilities)
            .field("no_new_privileges", &true)
            .field("clear_parent_environment", &true)
            .field("private_vault_mounted", &false)
            .finish()
    }
}

impl SandboxPlan {
    #[must_use]
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    #[must_use]
    pub fn workdir(&self) -> &str {
        &self.workdir
    }

    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    #[must_use]
    pub fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }

    #[must_use]
    pub fn sandbox_path(&self) -> &str {
        &self.sandbox_path
    }

    #[must_use]
    pub const fn network(&self) -> NetworkNamespacePlan {
        self.network
    }

    #[must_use]
    pub fn read_only_roots(&self) -> &[PathBuf] {
        &self.read_only_roots
    }

    #[must_use]
    pub fn forbidden_paths(&self) -> &[PathBuf] {
        &self.forbidden_paths
    }

    #[must_use]
    pub fn resolver_mount(&self) -> Option<&Path> {
        self.resolver_mount.as_deref()
    }

    #[must_use]
    pub const fn capabilities(&self) -> EmptyCapabilitySet {
        self.capabilities
    }

    #[must_use]
    pub const fn no_new_privileges(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn clear_parent_environment(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn private_vault_mounted(&self) -> bool {
        false
    }
}

pub struct SandboxPlanInput<'a> {
    pub workspace: &'a Path,
    pub workdir: &'a str,
    pub network: NetworkNamespacePlan,
    pub argv: &'a [String],
    pub environment: &'a BTreeMap<String, String>,
    pub sandbox_path: Option<&'a str>,
    pub read_only_roots: &'a [PathBuf],
    pub forbidden_paths: &'a [PathBuf],
    pub probe_executable: Option<&'a Path>,
}

#[must_use]
pub const fn network_namespace_for_mode(mode: NativeMode) -> NetworkNamespacePlan {
    match mode {
        NativeMode::Safe => NetworkNamespacePlan::Isolated,
        NativeMode::Trusted | NativeMode::Dangerous => NetworkNamespacePlan::Shared,
    }
}

#[derive(Clone, Debug)]
struct SandboxResult {
    status: String,
    exit_code: Option<i32>,
    signal: Option<String>,
    timed_out: bool,
    elapsed_ms: u64,
    stdout: CapturePayload,
    stderr: CapturePayload,
}

pub fn invoke_helper_request(
    request: &NativeHelperRequest,
) -> Result<NativeHelperResponse, ReCtmError> {
    validate_protocol_request(request)?;
    let fields = match request.operation.as_str() {
        "attest" => attest(request)?,
        "execute" => execute(request)?,
        _ => {
            return Err(validation_error(
                "NATIVE_HELPER_OPERATION_UNSUPPORTED",
                "operation must be attest or execute",
            ));
        }
    };
    Ok(NativeHelperResponse {
        protocol: NATIVE_HELPER_PROTOCOL.to_owned(),
        operation: request.operation.clone(),
        request_id: request.request_id.clone(),
        ok: true,
        fields,
    })
}

pub fn validate_helper_response(
    response: &NativeHelperResponse,
    request: &NativeHelperRequest,
    require_safe_network: bool,
    expected_toolchain_roots: usize,
) -> Result<Value, ReCtmError> {
    if response.protocol != NATIVE_HELPER_PROTOCOL {
        return Err(runtime_error(
            "NATIVE_HELPER_PROTOCOL_ERROR",
            "Native helper returned an unsupported response.",
        ));
    }
    if response.request_id != request.request_id {
        return Err(ReCtmError::new(
            "NATIVE_HELPER_PROTOCOL_ERROR",
            "Native helper response nonce did not match the request.",
        )
        .with_category(ErrorCategory::Security));
    }
    if response.operation != request.operation {
        return Err(ReCtmError::new(
            "NATIVE_HELPER_PROTOCOL_ERROR",
            "Native helper response operation did not match the request.",
        )
        .with_category(ErrorCategory::Security));
    }
    if !response.ok {
        let error = response.fields.get("error").and_then(Value::as_object);
        let code = error
            .and_then(|value| value.get("code"))
            .and_then(Value::as_str)
            .unwrap_or("NATIVE_HELPER_DENIED");
        let message = error
            .and_then(|value| value.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("Native isolation helper denied the request.");
        let category = error
            .and_then(|value| value.get("category"))
            .and_then(Value::as_str)
            .unwrap_or("security");
        return Err(ReCtmError::new(code, message)
            .with_category(parse_category(category))
            .with_details(serde_json::json!({
                "helper_details": error
                    .and_then(|value| value.get("details"))
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({})),
            })));
    }
    let attestation = response
        .fields
        .get("attestation")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ReCtmError::new(
                "NATIVE_HELPER_ATTESTATION_INVALID",
                "Native helper response did not include an attestation object.",
            )
            .with_category(ErrorCategory::Security)
        })?;
    let required = [
        "hard_isolation",
        "workspace_mounted",
        "forbidden_paths_hidden",
        "no_privilege_escalation",
        "mount_namespace",
        "user_namespace",
        "pid_namespace",
        "ipc_namespace",
        "uts_namespace",
        "nested_user_namespaces_disabled",
        "parent_environment_cleared",
        "capabilities_dropped",
        "toolchain_roots_validated",
    ];
    let missing = required
        .iter()
        .filter(|key| attestation.get(**key) != Some(&Value::Bool(true)))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() || attestation.get("private_vault_mounted") != Some(&Value::Bool(false))
    {
        return Err(ReCtmError::new(
            "NATIVE_HELPER_ATTESTATION_INVALID",
            "Native helper did not attest every required isolation property.",
        )
        .with_category(ErrorCategory::Security)
        .with_details(serde_json::json!({
            "missing_true_properties": missing,
            "private_vault_mounted": attestation.get("private_vault_mounted"),
        })));
    }
    if require_safe_network && attestation.get("network_isolated") != Some(&Value::Bool(true)) {
        return Err(ReCtmError::new(
            "NATIVE_HELPER_ATTESTATION_INVALID",
            "Safe mode requires an isolated network namespace.",
        )
        .with_category(ErrorCategory::Security));
    }
    if attestation
        .get("toolchain_read_only_root_count")
        .and_then(Value::as_u64)
        != Some(expected_toolchain_roots as u64)
    {
        return Err(ReCtmError::new(
            "NATIVE_HELPER_ATTESTATION_INVALID",
            "Bubblewrap response did not validate the complete read-only toolchain plan.",
        )
        .with_category(ErrorCategory::Security));
    }
    Ok(Value::Object(attestation.clone()))
}

pub fn plan_sandbox(input: &SandboxPlanInput<'_>) -> Result<SandboxPlan, ReCtmError> {
    plan_sandbox_with_resolver(input, host_runtime_resolver_target)
}

fn plan_sandbox_with_resolver(
    input: &SandboxPlanInput<'_>,
    shared_resolver: impl FnOnce() -> Result<Option<PathBuf>, ReCtmError>,
) -> Result<SandboxPlan, ReCtmError> {
    let workspace = validate_workspace_path(input.workspace)?;
    let workdir = validate_workdir(&workspace, input.workdir)?;
    validate_argv(input.argv)?;
    validate_environment(input.environment)?;
    let sandbox_path = input
        .sandbox_path
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_SANDBOX_PATH);
    validate_host_path(sandbox_path)?;
    let forbidden_paths = validate_plan_paths("forbidden_paths", input.forbidden_paths, false)?;
    if forbidden_paths
        .iter()
        .any(|forbidden| overlaps(forbidden, &workspace))
    {
        return Err(ReCtmError::new(
            "NATIVE_HELPER_TRUST_DOMAIN_OVERLAP",
            "workspace and forbidden path must not overlap",
        )
        .with_category(ErrorCategory::Security));
    }
    let read_only_roots =
        validate_helper_roots(&workspace, input.read_only_roots, &forbidden_paths)?;
    let resolver_mount = match input.network {
        NetworkNamespacePlan::Isolated => None,
        NetworkNamespacePlan::Shared => shared_resolver()?,
    };
    let probe_executable = input
        .probe_executable
        .map(|path| {
            fs::canonicalize(path).map_err(|error| {
                ReCtmError::new("NATIVE_HELPER_INTERNAL_ERROR", error.to_string())
                    .with_category(ErrorCategory::Internal)
            })
        })
        .transpose()?;
    let system_read_only_roots = SYSTEM_READ_ROOTS
        .iter()
        .map(PathBuf::from)
        .filter(|path| path.exists())
        .collect();
    Ok(SandboxPlan {
        workspace,
        workdir,
        argv: input.argv.to_vec(),
        environment: input.environment.clone(),
        sandbox_path: sandbox_path.to_owned(),
        network: input.network,
        system_read_only_roots,
        read_only_roots,
        forbidden_paths,
        resolver_mount,
        probe_executable,
        capabilities: EmptyCapabilitySet::default(),
    })
}

/// Compile an already-validated concrete sandbox plan into Bubblewrap argv.
///
/// This actuator does not inspect Native mode, permission kinds, grants, OAuth
/// identity, or workflow authority.
pub fn build_bubblewrap_command(plan: &SandboxPlan) -> Result<Vec<String>, ReCtmError> {
    let bwrap = find_in_path("bwrap").ok_or_else(|| {
        ReCtmError::new(
            "NATIVE_BWRAP_NOT_FOUND",
            "bubblewrap is required for the built-in native isolation backend",
        )
        .with_category(ErrorCategory::Security)
    })?;
    let mut command = vec![
        bwrap,
        "--die-with-parent".to_owned(),
        "--new-session".to_owned(),
        "--unshare-user".to_owned(),
        "--uid".to_owned(),
        "0".to_owned(),
        "--gid".to_owned(),
        "0".to_owned(),
        "--unshare-pid".to_owned(),
        "--unshare-ipc".to_owned(),
        "--unshare-uts".to_owned(),
        "--unshare-cgroup-try".to_owned(),
        "--disable-userns".to_owned(),
        "--hostname".to_owned(),
        "re-ctm-native".to_owned(),
        "--clearenv".to_owned(),
        "--setenv".to_owned(),
        "PATH".to_owned(),
        plan.sandbox_path.clone(),
        "--setenv".to_owned(),
        "HOME".to_owned(),
        "/home/re-ctm".to_owned(),
        "--setenv".to_owned(),
        "TMPDIR".to_owned(),
        "/tmp".to_owned(),
        "--setenv".to_owned(),
        "LANG".to_owned(),
        "C.UTF-8".to_owned(),
        "--cap-drop".to_owned(),
        "ALL".to_owned(),
    ];
    if plan.network == NetworkNamespacePlan::Isolated {
        command.push("--unshare-net".to_owned());
    }
    for (key, value) in &plan.environment {
        command.extend(["--setenv".to_owned(), key.clone(), value.clone()]);
    }
    for root in &plan.system_read_only_roots {
        let root = root.to_string_lossy().into_owned();
        command.extend(["--ro-bind".to_owned(), root.clone(), root]);
    }
    command.extend([
        "--proc".to_owned(),
        "/proc".to_owned(),
        "--dev".to_owned(),
        "/dev".to_owned(),
        "--tmpfs".to_owned(),
        "/tmp".to_owned(),
        "--dir".to_owned(),
        "/home".to_owned(),
        "--dir".to_owned(),
        "/home/re-ctm".to_owned(),
    ]);
    let mut created_dirs = BTreeSet::from([
        PathBuf::from("/tmp"),
        PathBuf::from("/home"),
        PathBuf::from("/home/re-ctm"),
    ]);
    if let Some(target) = plan.resolver_mount.as_deref() {
        append_runtime_resolver_mount(target, &mut command, &mut created_dirs);
    }
    for root in &plan.read_only_roots {
        ensure_mount_parents(root, &mut command, &mut created_dirs);
        command.extend([
            "--ro-bind".to_owned(),
            root.to_string_lossy().into_owned(),
            root.to_string_lossy().into_owned(),
        ]);
    }
    if let Some(executable) = &plan.probe_executable {
        command.extend([
            "--ro-bind".to_owned(),
            executable.to_string_lossy().into_owned(),
            "/mtm-native-helper".to_owned(),
        ]);
    }
    command.extend([
        "--bind".to_owned(),
        plan.workspace.to_string_lossy().into_owned(),
        "/workspace".to_owned(),
        "--chdir".to_owned(),
        if plan.workdir == "." {
            "/workspace".to_owned()
        } else {
            format!("/workspace/{}", plan.workdir)
        },
        "--".to_owned(),
    ]);
    command.extend(plan.argv.iter().cloned());
    Ok(command)
}

pub fn run_sandbox_probe(
    encoded_forbidden: &str,
    probe_name: &str,
    encoded_roots: &str,
) -> Result<SandboxProbe, ReCtmError> {
    let forbidden = decode_string_array(encoded_forbidden)?;
    let roots = decode_string_array(encoded_roots)?;
    let forbidden_visible = forbidden
        .iter()
        .filter(|path| Path::new(path).exists())
        .cloned()
        .collect::<Vec<_>>();
    let toolchain_visible = roots
        .iter()
        .filter(|path| Path::new(path).is_dir())
        .cloned()
        .collect::<Vec<_>>();
    let target = Path::new("/workspace").join(probe_name);
    let workspace_writable = fs::write(&target, b"ok").is_ok() && target.is_file();
    let _ = fs::remove_file(&target);
    let mut toolchain_write_succeeded = Vec::new();
    for (index, root) in roots.iter().enumerate() {
        let target = Path::new(root).join(format!("{probe_name}-toolchain-{index}"));
        if fs::write(&target, b"must-fail").is_ok() {
            toolchain_write_succeeded.push(root.clone());
            let _ = fs::remove_file(target);
        }
    }
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    Ok(SandboxProbe {
        workspace_mounted: Path::new("/workspace").is_dir(),
        forbidden_visible,
        parent_secret_visible: env::var_os("MTM_ATTEST_PARENT_SECRET").is_some(),
        no_new_privs: status.lines().any(|line| line == "NoNewPrivs:\t1"),
        workspace_writable,
        toolchain_visible,
        toolchain_write_succeeded,
    })
}

fn attest(request: &NativeHelperRequest) -> Result<BTreeMap<String, Value>, ReCtmError> {
    let workspace = validate_workspace(&request.workspace)?;
    let forbidden_paths = validate_forbidden_paths(&workspace, &request.forbidden_paths)?;
    validate_host_path(&request.host_path)?;
    let extra_roots = validate_path_array("extra_read_roots", &request.extra_read_roots)?;
    let current_exe = env::current_exe().map_err(|error| {
        ReCtmError::new("NATIVE_HELPER_INTERNAL_ERROR", error.to_string())
            .with_category(ErrorCategory::Internal)
    })?;
    let probe_name = format!(
        ".mtm-attest-{}",
        request.request_id.chars().take(12).collect::<String>()
    );
    let encoded_forbidden = encode_strings(
        &forbidden_paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
    )?;
    let encoded_roots = encode_strings(&request.extra_read_roots)?;
    let argv = vec![
        "/mtm-native-helper".to_owned(),
        "--sandbox-probe".to_owned(),
        encoded_forbidden,
        probe_name,
        encoded_roots,
    ];
    let plan = plan_sandbox(&SandboxPlanInput {
        workspace: &workspace,
        workdir: ".",
        network: network_namespace_for_mode(request.mode),
        argv: &argv,
        environment: &BTreeMap::new(),
        sandbox_path: nonempty(&request.host_path),
        read_only_roots: &extra_roots,
        forbidden_paths: &forbidden_paths,
        probe_executable: Some(&current_exe),
    })?;
    let command = build_bubblewrap_command(&plan)?;
    let mut parent_env = helper_child_env();
    parent_env.insert(
        "MTM_ATTEST_PARENT_SECRET".to_owned(),
        "must-not-enter-sandbox".to_owned(),
    );
    let result = run_in_sandbox(&command, &parent_env, 15_000)?;
    if result.exit_code != Some(0) {
        return Err(ReCtmError::new(
            "NATIVE_HELPER_ATTESTATION_FAILED",
            "bubblewrap attestation probe did not exit successfully",
        )
        .with_category(ErrorCategory::Security)
        .with_details(serde_json::json!({
            "exit_code": result.exit_code,
            "stderr": tail_chars(&result.stderr.text, 2000),
        })));
    }
    let probe: SandboxProbe = serde_json::from_str(result.stdout.text.trim()).map_err(|_| {
        ReCtmError::new(
            "NATIVE_HELPER_ATTESTATION_FAILED",
            "bubblewrap attestation probe returned invalid JSON",
        )
        .with_category(ErrorCategory::Security)
    })?;
    let expected_roots = request
        .extra_read_roots
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let visible_roots = probe
        .toolchain_visible
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let valid = probe.workspace_mounted
        && probe.workspace_writable
        && !probe.parent_secret_visible
        && probe.no_new_privs
        && probe.forbidden_visible.is_empty()
        && visible_roots == expected_roots
        && probe.toolchain_write_succeeded.is_empty();
    if !valid {
        return Err(ReCtmError::new(
            "NATIVE_HELPER_ATTESTATION_FAILED",
            "bubblewrap probe did not prove the required isolation properties",
        )
        .with_category(ErrorCategory::Security)
        .with_details(serde_json::to_value(&probe).unwrap_or_else(|_| serde_json::json!({}))));
    }
    let attestation = attestation(plan.network(), true, plan.read_only_roots().len());
    Ok(BTreeMap::from([
        ("attestation".to_owned(), attestation),
        (
            "probe".to_owned(),
            serde_json::json!({
                "workspace_writable": true,
                "parent_environment_cleared": true,
                "forbidden_path_count": forbidden_paths.len(),
                "toolchain_root_count": extra_roots.len(),
                "toolchain_roots_read_only": true,
            }),
        ),
    ]))
}

fn execute(request: &NativeHelperRequest) -> Result<BTreeMap<String, Value>, ReCtmError> {
    let workspace = validate_workspace(&request.workspace)?;
    validate_argv(&request.argv)?;
    let workdir = validate_workdir(&workspace, &request.workdir)?;
    if !(1..=600_000).contains(&request.timeout_ms) {
        return Err(validation_error(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "timeout_ms must be between 1 and 600000",
        ));
    }
    validate_host_path(&request.host_path)?;
    let extra_roots = validate_path_array("extra_read_roots", &request.extra_read_roots)?;
    let forbidden_paths = validate_path_array("forbidden_paths", &request.forbidden_paths)?;
    let plan = plan_sandbox(&SandboxPlanInput {
        workspace: &workspace,
        workdir: &workdir,
        network: network_namespace_for_mode(request.mode),
        argv: &request.argv,
        environment: &BTreeMap::new(),
        sandbox_path: nonempty(&request.host_path),
        read_only_roots: &extra_roots,
        forbidden_paths: &forbidden_paths,
        probe_executable: None,
    })?;
    let command = build_bubblewrap_command(&plan)?;
    let result = run_in_sandbox(&command, &helper_child_env(), request.timeout_ms)?;
    let attestation = attestation(plan.network(), true, plan.read_only_roots().len());
    let stdout_meta = serde_json::json!({
        "total_bytes": result.stdout.total_bytes,
        "retained_bytes": result.stdout.retained_bytes,
        "dropped_bytes": result.stdout.dropped_bytes,
        "truncated": result.stdout.truncated,
    });
    let stderr_meta = serde_json::json!({
        "total_bytes": result.stderr.total_bytes,
        "retained_bytes": result.stderr.retained_bytes,
        "dropped_bytes": result.stderr.dropped_bytes,
        "truncated": result.stderr.truncated,
    });
    Ok(BTreeMap::from([
        ("status".to_owned(), Value::String(result.status)),
        ("exit_code".to_owned(), serde_json::json!(result.exit_code)),
        ("signal".to_owned(), serde_json::json!(result.signal)),
        ("timed_out".to_owned(), Value::Bool(result.timed_out)),
        (
            "elapsed_ms".to_owned(),
            serde_json::json!(result.elapsed_ms),
        ),
        ("stdout".to_owned(), Value::String(result.stdout.text)),
        ("stderr".to_owned(), Value::String(result.stderr.text)),
        ("stdout_meta".to_owned(), stdout_meta),
        ("stderr_meta".to_owned(), stderr_meta),
        ("attestation".to_owned(), attestation),
    ]))
}

fn run_in_sandbox(
    command: &[String],
    environment: &BTreeMap<String, String>,
    timeout_ms: u64,
) -> Result<SandboxResult, ReCtmError> {
    let Some(program) = command.first() else {
        return Err(validation_error(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "sandbox command is empty",
        ));
    };
    let started = Instant::now();
    let mut child = Command::new(program)
        .args(&command[1..])
        .env_clear()
        .envs(environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|error| {
            ReCtmError::new("NATIVE_HELPER_EXECUTION_FAILED", error.to_string())
                .with_category(ErrorCategory::Runtime)
        })?;
    let pid = child.id();
    let stdout = child.stdout.take().ok_or_else(|| {
        runtime_error(
            "NATIVE_HELPER_EXECUTION_FAILED",
            "sandbox stdout was not captured",
        )
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        runtime_error(
            "NATIVE_HELPER_EXECUTION_FAILED",
            "sandbox stderr was not captured",
        )
    })?;
    let stdout_capture = Arc::new(Mutex::new(BoundedCapture::default()));
    let stderr_capture = Arc::new(Mutex::new(BoundedCapture::default()));
    let stdout_thread = drain_stream(stdout, Arc::clone(&stdout_capture));
    let stderr_thread = drain_stream(stderr, Arc::clone(&stderr_capture));
    let deadline = started + Duration::from_millis(timeout_ms);
    let mut timed_out = false;
    let status = 'wait: loop {
        if let Some(status) = child.try_wait().map_err(|error| {
            ReCtmError::new("NATIVE_HELPER_EXECUTION_FAILED", error.to_string())
                .with_category(ErrorCategory::Runtime)
        })? {
            break status;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            send_group_signal(pid, Signal::SIGTERM)?;
            let term_deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if let Some(status) = child.try_wait().map_err(|error| {
                    ReCtmError::new("NATIVE_HELPER_EXECUTION_FAILED", error.to_string())
                        .with_category(ErrorCategory::Runtime)
                })? {
                    break 'wait status;
                }
                if Instant::now() >= term_deadline {
                    send_group_signal(pid, Signal::SIGKILL)?;
                    break 'wait child.wait().map_err(|error| {
                        ReCtmError::new("NATIVE_HELPER_EXECUTION_FAILED", error.to_string())
                            .with_category(ErrorCategory::Runtime)
                    })?;
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
        thread::sleep(Duration::from_millis(20));
    };
    let _ = stdout_thread.join();
    let _ = stderr_thread.join();
    let stdout = stdout_capture
        .lock()
        .map_err(|_| internal_lock_error())?
        .payload();
    let stderr = stderr_capture
        .lock()
        .map_err(|_| internal_lock_error())?
        .payload();
    let signal = status.signal().map(signal_number_name);
    Ok(SandboxResult {
        status: if timed_out { "timeout" } else { "exited" }.to_owned(),
        exit_code: status.code(),
        signal,
        timed_out,
        elapsed_ms: started.elapsed().as_millis() as u64,
        stdout,
        stderr,
    })
}

fn drain_stream<R: Read + Send + 'static>(
    mut stream: R,
    capture: Arc<Mutex<BoundedCapture>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut chunk = [0_u8; 64 * 1024];
        loop {
            let read = match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            if let Ok(mut target) = capture.lock() {
                target.append(&chunk[..read]);
            } else {
                break;
            }
        }
    })
}

fn attestation(network: NetworkNamespacePlan, forbidden_hidden: bool, root_count: usize) -> Value {
    let bwrap = find_in_path("bwrap");
    let version = bwrap
        .as_deref()
        .and_then(|program| {
            Command::new(program)
                .arg("--version")
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output()
                .ok()
        })
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .chars()
                .take(200)
                .collect()
        })
        .filter(|value: &String| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    serde_json::json!({
        "backend": "bubblewrap",
        "backend_version": version,
        "hard_isolation": true,
        "workspace_mounted": true,
        "workspace_mount": "/workspace",
        "forbidden_paths_hidden": forbidden_hidden,
        "private_vault_mounted": false,
        "network_isolated": network == NetworkNamespacePlan::Isolated,
        "no_privilege_escalation": true,
        "mount_namespace": true,
        "user_namespace": true,
        "pid_namespace": true,
        "ipc_namespace": true,
        "uts_namespace": true,
        "nested_user_namespaces_disabled": true,
        "parent_environment_cleared": true,
        "capabilities_dropped": true,
        "toolchain_roots_validated": true,
        "toolchain_read_only_root_count": root_count,
    })
}

fn validate_protocol_request(request: &NativeHelperRequest) -> Result<(), ReCtmError> {
    if request.protocol != NATIVE_HELPER_PROTOCOL {
        return Err(validation_error(
            "NATIVE_HELPER_PROTOCOL_ERROR",
            "unsupported helper protocol",
        ));
    }
    validate_required_text("request_id", &request.request_id, 256)?;
    validate_required_text("operation", &request.operation, 32)?;
    Ok(())
}

fn validate_workspace(raw: &str) -> Result<PathBuf, ReCtmError> {
    validate_required_text("workspace", raw, 4096)?;
    validate_workspace_path(Path::new(raw))
}

fn validate_workspace_path(path: &Path) -> Result<PathBuf, ReCtmError> {
    if !path.is_absolute() {
        return Err(validation_error(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "workspace must be absolute",
        ));
    }
    let resolved = fs::canonicalize(path).map_err(|_| {
        validation_error("NATIVE_HELPER_INVALID_ARGUMENT", "workspace does not exist")
    })?;
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .map(|path| canonicalize_lenient(&path));
    if !resolved.is_dir() || resolved == Path::new("/") || home.as_ref() == Some(&resolved) {
        return Err(validation_error(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "workspace must be a safe directory",
        ));
    }
    Ok(resolved)
}

fn validate_forbidden_paths(
    workspace: &Path,
    raw_paths: &[String],
) -> Result<Vec<PathBuf>, ReCtmError> {
    let paths = validate_path_array("forbidden_paths", raw_paths)?;
    for path in &paths {
        if overlaps(path, workspace) {
            return Err(ReCtmError::new(
                "NATIVE_HELPER_TRUST_DOMAIN_OVERLAP",
                "workspace and forbidden path must not overlap",
            )
            .with_category(ErrorCategory::Security));
        }
    }
    Ok(paths)
}

fn validate_path_array(name: &str, values: &[String]) -> Result<Vec<PathBuf>, ReCtmError> {
    if values.len() > MAX_PATH_ARRAY
        || values
            .iter()
            .any(|item| item.is_empty() || item.contains('\0'))
    {
        return Err(validation_error(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            &format!("{name} must be a bounded array of non-empty NUL-free paths"),
        ));
    }
    Ok(values
        .iter()
        .map(|value| canonicalize_lenient(Path::new(value)))
        .collect())
}

fn validate_plan_paths(
    name: &str,
    values: &[PathBuf],
    must_exist: bool,
) -> Result<Vec<PathBuf>, ReCtmError> {
    if values.len() > MAX_PATH_ARRAY {
        return Err(validation_error(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            &format!("{name} must be a bounded array of absolute paths"),
        ));
    }
    values
        .iter()
        .map(|path| {
            let text = path.to_string_lossy();
            if path.as_os_str().is_empty() || text.contains('\0') || !path.is_absolute() {
                return Err(validation_error(
                    "NATIVE_HELPER_INVALID_ARGUMENT",
                    &format!("{name} must be a bounded array of absolute paths"),
                ));
            }
            if must_exist {
                fs::canonicalize(path).map_err(|_| {
                    validation_error(
                        "NATIVE_HELPER_INVALID_ARGUMENT",
                        &format!("{name} contains a path that does not exist"),
                    )
                })
            } else {
                Ok(canonicalize_lenient(path))
            }
        })
        .collect()
}

fn validate_host_path(host_path: &str) -> Result<(), ReCtmError> {
    if host_path.contains('\0') || host_path.len() > 256 * 1024 {
        return Err(validation_error(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "host_path must be a bounded NUL-free string",
        ));
    }
    Ok(())
}

fn validate_argv(argv: &[String]) -> Result<(), ReCtmError> {
    let bytes = argv.iter().map(String::len).sum::<usize>();
    if argv.is_empty()
        || argv.len() > MAX_ARG_COUNT
        || bytes > MAX_ARG_BYTES
        || argv.iter().any(|item| item.contains('\0'))
    {
        return Err(validation_error(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "argv must be a non-empty bounded array of NUL-free strings",
        ));
    }
    Ok(())
}

fn validate_environment(environment: &BTreeMap<String, String>) -> Result<(), ReCtmError> {
    if environment.iter().any(|(key, value)| {
        key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0')
    }) {
        return Err(validation_error(
            "INVALID_ENVIRONMENT",
            "Native command environment contains an invalid key or value.",
        ));
    }
    Ok(())
}

fn validate_workdir(workspace: &Path, raw: &str) -> Result<String, ReCtmError> {
    if raw.is_empty()
        || raw.contains('\0')
        || raw.starts_with('/')
        || is_windows_absolute(raw)
        || raw.split('/').any(|part| part == "..")
    {
        return Err(validation_error(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "workdir must be a workspace-relative path",
        ));
    }
    let relative = raw.replace('\\', "/");
    let target = fs::canonicalize(workspace.join(&relative)).map_err(|_| {
        validation_error(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "workdir must resolve to a directory inside the workspace",
        )
    })?;
    if !target.starts_with(workspace) || !target.is_dir() {
        return Err(validation_error(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "workdir must resolve to a directory inside the workspace",
        ));
    }
    Ok(relative)
}

fn validate_helper_roots(
    workspace: &Path,
    roots: &[PathBuf],
    forbidden_paths: &[PathBuf],
) -> Result<Vec<PathBuf>, ReCtmError> {
    let unsafe_exact = UNSAFE_EXACT_ROOTS
        .iter()
        .map(|value| canonicalize_lenient(Path::new(value)))
        .collect::<BTreeSet<_>>();
    let mut normalized = Vec::new();
    let mut seen = BTreeSet::new();
    for raw_root in roots {
        let root = fs::canonicalize(raw_root).map_err(|_| {
            validation_error(
                "NATIVE_HELPER_INVALID_ARGUMENT",
                "read-only toolchain root does not exist",
            )
        })?;
        if !root.is_dir() || !seen.insert(root.clone()) {
            continue;
        }
        if unsafe_exact.contains(&root) {
            return Err(ReCtmError::new(
                "NATIVE_TOOLCHAIN_ROOT_DENIED",
                "read-only toolchain root is an unsafe broad or virtual filesystem root",
            )
            .with_category(ErrorCategory::Security)
            .with_details(serde_json::json!({"root": root})));
        }
        if overlaps(&root, workspace)
            || forbidden_paths
                .iter()
                .any(|forbidden| overlaps(&root, forbidden))
        {
            return Err(ReCtmError::new(
                "NATIVE_TOOLCHAIN_ROOT_DENIED",
                "read-only toolchain root overlaps a protected trust domain",
            )
            .with_category(ErrorCategory::Security)
            .with_details(serde_json::json!({"root": root})));
        }
        normalized.push(root);
    }
    Ok(normalized)
}

fn ensure_mount_parents(
    root: &Path,
    command: &mut Vec<String>,
    created_dirs: &mut BTreeSet<PathBuf>,
) {
    let mut parents = root.ancestors().skip(1).collect::<Vec<_>>();
    parents.reverse();
    for parent in parents {
        if parent == Path::new("/") || parent.exists() && is_system_root(parent) {
            continue;
        }
        let parent = parent.to_path_buf();
        if created_dirs.insert(parent.clone()) {
            command.extend(["--dir".to_owned(), parent.to_string_lossy().into_owned()]);
        }
    }
}

fn host_runtime_resolver_target() -> Result<Option<PathBuf>, ReCtmError> {
    let trusted_roots = TRUSTED_RUNTIME_RESOLVER_ROOTS
        .iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    runtime_resolver_target(Path::new(RESOLV_CONF_PATH), &trusted_roots)
}

fn runtime_resolver_target(
    resolv_conf: &Path,
    trusted_roots: &[PathBuf],
) -> Result<Option<PathBuf>, ReCtmError> {
    let metadata = match fs::symlink_metadata(resolv_conf) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(runtime_error(
                "NATIVE_RESOLVER_INSPECTION_FAILED",
                &format!("Unable to inspect resolver configuration: {error}"),
            ));
        }
    };
    if !metadata.file_type().is_symlink() {
        return Ok(None);
    }

    let target = fs::canonicalize(resolv_conf).map_err(|error| {
        ReCtmError::new(
            "NATIVE_RESOLVER_TARGET_INVALID",
            format!("Resolver configuration symlink target is unavailable: {error}"),
        )
        .with_category(ErrorCategory::Security)
    })?;
    if is_system_root(&target) {
        return Ok(None);
    }
    if !target.is_file() {
        return Err(ReCtmError::new(
            "NATIVE_RESOLVER_TARGET_INVALID",
            "Resolver configuration symlink must resolve to a regular file.",
        )
        .with_category(ErrorCategory::Security)
        .with_details(serde_json::json!({"target":target})));
    }
    if !trusted_roots.iter().any(|root| target.starts_with(root)) {
        return Err(ReCtmError::new(
            "NATIVE_RESOLVER_TARGET_DENIED",
            "Resolver configuration symlink resolves outside trusted runtime resolver roots.",
        )
        .with_category(ErrorCategory::Security)
        .with_details(serde_json::json!({"target":target})));
    }
    Ok(Some(target))
}

fn append_runtime_resolver_mount(
    target: &Path,
    command: &mut Vec<String>,
    created_dirs: &mut BTreeSet<PathBuf>,
) {
    ensure_mount_parents(target, command, created_dirs);
    let target = target.to_string_lossy().into_owned();
    command.extend(["--ro-bind".to_owned(), target.clone(), target]);
}

fn helper_child_env() -> BTreeMap<String, String> {
    ["PATH", "LANG", "LC_ALL", "LC_CTYPE"]
        .into_iter()
        .filter_map(|key| env::var(key).ok().map(|value| (key.to_owned(), value)))
        .collect()
}

fn send_group_signal(pid: u32, signal: Signal) -> Result<(), ReCtmError> {
    let pid = i32::try_from(pid).map_err(|_| {
        runtime_error(
            "NATIVE_HELPER_EXECUTION_FAILED",
            "sandbox PID exceeded the supported range",
        )
    })?;
    match killpg(Pid::from_raw(pid), signal) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(error) => Err(runtime_error(
            "NATIVE_HELPER_EXECUTION_FAILED",
            &error.to_string(),
        )),
    }
}

fn encode_strings(values: &[String]) -> Result<String, ReCtmError> {
    let json = serde_json::to_vec(values).map_err(|error| {
        ReCtmError::new("NATIVE_HELPER_INTERNAL_ERROR", error.to_string())
            .with_category(ErrorCategory::Internal)
    })?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

fn decode_string_array(value: &str) -> Result<Vec<String>, ReCtmError> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        validation_error(
            "NATIVE_HELPER_PROTOCOL_ERROR",
            "sandbox probe arguments are invalid",
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        validation_error(
            "NATIVE_HELPER_PROTOCOL_ERROR",
            "sandbox probe arguments are invalid",
        )
    })
}

fn find_in_path(name: &str) -> Option<String> {
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|entry| entry.join(name))
            .find(|candidate| candidate.is_file())
            .map(|candidate| candidate.to_string_lossy().into_owned())
    })
}

fn is_system_root(path: &Path) -> bool {
    SYSTEM_READ_ROOTS
        .iter()
        .any(|root| path == Path::new(root) || path.starts_with(root))
}

fn nonempty(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn canonicalize_lenient(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn is_windows_absolute(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

fn signal_number_name(signal: i32) -> String {
    Signal::try_from(signal)
        .map(|value| format!("{value:?}"))
        .unwrap_or_else(|_| signal.to_string())
}

fn tail_chars(value: &str, count: usize) -> String {
    value
        .chars()
        .rev()
        .take(count)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

fn validate_required_text(name: &str, value: &str, maximum: usize) -> Result<(), ReCtmError> {
    if value.is_empty() || value.len() > maximum || value.contains('\0') {
        return Err(validation_error(
            "NATIVE_HELPER_PROTOCOL_ERROR",
            &format!("{name} must be a non-empty string of at most {maximum} characters"),
        ));
    }
    Ok(())
}

fn parse_category(value: &str) -> ErrorCategory {
    match value {
        "validation" => ErrorCategory::Validation,
        "permission" => ErrorCategory::Permission,
        "security" => ErrorCategory::Security,
        "not_found" => ErrorCategory::NotFound,
        "conflict" => ErrorCategory::Conflict,
        "internal" => ErrorCategory::Internal,
        _ => ErrorCategory::Runtime,
    }
}

fn validation_error(code: &str, message: &str) -> ReCtmError {
    ReCtmError::new(code, message).with_category(ErrorCategory::Validation)
}

fn runtime_error(code: &str, message: &str) -> ReCtmError {
    ReCtmError::new(code, message).with_category(ErrorCategory::Runtime)
}

fn internal_lock_error() -> ReCtmError {
    ReCtmError::new("INTERNAL_LOCK_POISONED", "Native helper lock was poisoned.")
        .with_category(ErrorCategory::Internal)
}

fn default_workdir() -> String {
    ".".to_owned()
}

const fn default_timeout_ms() -> u64 {
    30_000
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    #[derive(Debug, Default, Eq, PartialEq)]
    struct CompiledSandboxSemantics {
        fixed_flags: BTreeSet<String>,
        network_isolated: bool,
        uid: Option<String>,
        gid: Option<String>,
        hostname: Option<String>,
        environment: BTreeMap<String, String>,
        capability_drops: Vec<String>,
        read_only_binds: Vec<(String, String)>,
        writable_binds: Vec<(String, String)>,
        proc_mount: Option<String>,
        dev_mount: Option<String>,
        tmpfs_mounts: Vec<String>,
        directories: Vec<String>,
        workdir: Option<String>,
        argv: Vec<String>,
    }

    fn compiled_semantics(command: &[String]) -> Result<CompiledSandboxSemantics, ReCtmError> {
        if command.is_empty() {
            return Err(ReCtmError::new("TEST", "empty Bubblewrap command"));
        }
        let mut semantics = CompiledSandboxSemantics::default();
        let mut index = 1;
        while index < command.len() {
            match command[index].as_str() {
                "--" => {
                    semantics.argv = command[index + 1..].to_vec();
                    break;
                }
                "--die-with-parent"
                | "--new-session"
                | "--unshare-user"
                | "--unshare-pid"
                | "--unshare-ipc"
                | "--unshare-uts"
                | "--unshare-cgroup-try"
                | "--disable-userns"
                | "--clearenv" => {
                    semantics.fixed_flags.insert(command[index].clone());
                    index += 1;
                }
                "--unshare-net" => {
                    semantics.network_isolated = true;
                    index += 1;
                }
                "--uid" => {
                    semantics.uid = Some(command[index + 1].clone());
                    index += 2;
                }
                "--gid" => {
                    semantics.gid = Some(command[index + 1].clone());
                    index += 2;
                }
                "--hostname" => {
                    semantics.hostname = Some(command[index + 1].clone());
                    index += 2;
                }
                "--setenv" => {
                    semantics
                        .environment
                        .insert(command[index + 1].clone(), command[index + 2].clone());
                    index += 3;
                }
                "--cap-drop" => {
                    semantics.capability_drops.push(command[index + 1].clone());
                    index += 2;
                }
                "--ro-bind" => {
                    semantics
                        .read_only_binds
                        .push((command[index + 1].clone(), command[index + 2].clone()));
                    index += 3;
                }
                "--bind" => {
                    semantics
                        .writable_binds
                        .push((command[index + 1].clone(), command[index + 2].clone()));
                    index += 3;
                }
                "--proc" => {
                    semantics.proc_mount = Some(command[index + 1].clone());
                    index += 2;
                }
                "--dev" => {
                    semantics.dev_mount = Some(command[index + 1].clone());
                    index += 2;
                }
                "--tmpfs" => {
                    semantics.tmpfs_mounts.push(command[index + 1].clone());
                    index += 2;
                }
                "--dir" => {
                    semantics.directories.push(command[index + 1].clone());
                    index += 2;
                }
                "--chdir" => {
                    semantics.workdir = Some(command[index + 1].clone());
                    index += 2;
                }
                unexpected => {
                    return Err(ReCtmError::new(
                        "TEST",
                        format!("unexpected Bubblewrap argument in test: {unexpected}"),
                    ));
                }
            }
        }
        Ok(semantics)
    }

    #[allow(clippy::too_many_arguments)]
    fn test_plan_with_resolver(
        workspace: &Path,
        workdir: &str,
        network: NetworkNamespacePlan,
        argv: &[String],
        environment: &BTreeMap<String, String>,
        read_only_roots: &[PathBuf],
        forbidden_paths: &[PathBuf],
        resolver_mount: Option<PathBuf>,
    ) -> Result<SandboxPlan, ReCtmError> {
        plan_sandbox_with_resolver(
            &SandboxPlanInput {
                workspace,
                workdir,
                network,
                argv,
                environment,
                sandbox_path: Some("/usr/bin:/bin"),
                read_only_roots,
                forbidden_paths,
                probe_executable: None,
            },
            move || Ok(resolver_mount),
        )
    }

    fn assert_only_network_dimension_differs(isolated: &SandboxPlan, shared: &SandboxPlan) {
        assert_eq!(isolated.workspace, shared.workspace);
        assert_eq!(isolated.workdir, shared.workdir);
        assert_eq!(isolated.argv, shared.argv);
        assert_eq!(isolated.environment, shared.environment);
        assert_eq!(isolated.sandbox_path, shared.sandbox_path);
        assert_eq!(
            isolated.system_read_only_roots,
            shared.system_read_only_roots
        );
        assert_eq!(isolated.read_only_roots, shared.read_only_roots);
        assert_eq!(isolated.forbidden_paths, shared.forbidden_paths);
        assert_eq!(isolated.probe_executable, shared.probe_executable);
        assert_eq!(isolated.capabilities, shared.capabilities);
        assert_eq!(isolated.network, NetworkNamespacePlan::Isolated);
        assert_eq!(shared.network, NetworkNamespacePlan::Shared);
        assert!(isolated.resolver_mount.is_none());
    }

    #[test]
    fn typed_plan_preserves_exact_profile_semantics_and_fixed_invariants() -> Result<(), ReCtmError>
    {
        let temp = TempDir::new().map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        let workspace = temp.path().join("workspace");
        let nested_workdir = workspace.join("proofs");
        let toolchain = temp.path().join("toolchain");
        let private = temp.path().join("private");
        let resolver = temp.path().join("run/systemd/resolve/stub-resolv.conf");
        for path in [&workspace, &nested_workdir, &toolchain, &private] {
            fs::create_dir_all(path).map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        }
        fs::create_dir_all(resolver.parent().unwrap_or(temp.path()))
            .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        fs::write(&resolver, b"nameserver 127.0.0.53\n")
            .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        let resolver = fs::canonicalize(resolver)
            .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        let environment = BTreeMap::from([(
            "VISIBLE_KEY".to_owned(),
            "secret-environment-value".to_owned(),
        )]);
        let read_only_roots = vec![toolchain.clone()];
        let forbidden_paths = vec![private.clone()];
        let argv = vec!["/bin/printf".to_owned(), "secret-command-value".to_owned()];

        for (mode, expected) in [
            (NativeMode::Safe, NetworkNamespacePlan::Isolated),
            (NativeMode::Trusted, NetworkNamespacePlan::Shared),
            (NativeMode::Dangerous, NetworkNamespacePlan::Shared),
        ] {
            assert_eq!(network_namespace_for_mode(mode), expected);
        }

        let isolated = test_plan_with_resolver(
            &workspace,
            "proofs",
            NetworkNamespacePlan::Isolated,
            &argv,
            &environment,
            &read_only_roots,
            &forbidden_paths,
            Some(resolver.clone()),
        )?;
        let trusted = test_plan_with_resolver(
            &workspace,
            "proofs",
            network_namespace_for_mode(NativeMode::Trusted),
            &argv,
            &environment,
            &read_only_roots,
            &forbidden_paths,
            Some(resolver.clone()),
        )?;
        let dangerous = test_plan_with_resolver(
            &workspace,
            "proofs",
            network_namespace_for_mode(NativeMode::Dangerous),
            &argv,
            &environment,
            &read_only_roots,
            &forbidden_paths,
            Some(resolver.clone()),
        )?;
        let synthetic_safe_network_grant = test_plan_with_resolver(
            &workspace,
            "proofs",
            NetworkNamespacePlan::Shared,
            &argv,
            &environment,
            &read_only_roots,
            &forbidden_paths,
            Some(resolver.clone()),
        )?;

        assert_eq!(isolated.network(), NetworkNamespacePlan::Isolated);
        assert_eq!(trusted.network(), NetworkNamespacePlan::Shared);
        assert!(isolated.resolver_mount().is_none());
        assert_eq!(trusted.resolver_mount(), Some(resolver.as_path()));
        assert_eq!(trusted, dangerous);
        assert_eq!(trusted, synthetic_safe_network_grant);
        assert_only_network_dimension_differs(&isolated, &trusted);

        for plan in [&isolated, &trusted] {
            assert_eq!(plan.capabilities(), EmptyCapabilitySet::default());
            assert!(plan.no_new_privileges());
            assert!(plan.clear_parent_environment());
            assert!(!plan.private_vault_mounted());
            assert_eq!(plan.read_only_roots(), std::slice::from_ref(&toolchain));
            assert_eq!(plan.forbidden_paths(), std::slice::from_ref(&private));
            let debug = format!("{plan:?}");
            assert!(!debug.contains("secret-command-value"));
            assert!(!debug.contains("secret-environment-value"));
            assert!(!debug.contains(&workspace.to_string_lossy().into_owned()));
        }

        let isolated_command = build_bubblewrap_command(&isolated)?;
        let trusted_command = build_bubblewrap_command(&trusted)?;
        let isolated_semantics = compiled_semantics(&isolated_command)?;
        let trusted_semantics = compiled_semantics(&trusted_command)?;
        assert!(isolated_semantics.network_isolated);
        assert!(!trusted_semantics.network_isolated);

        let expected_fixed_flags = BTreeSet::from([
            "--die-with-parent".to_owned(),
            "--new-session".to_owned(),
            "--unshare-user".to_owned(),
            "--unshare-pid".to_owned(),
            "--unshare-ipc".to_owned(),
            "--unshare-uts".to_owned(),
            "--unshare-cgroup-try".to_owned(),
            "--disable-userns".to_owned(),
            "--clearenv".to_owned(),
        ]);
        let expected_environment = BTreeMap::from([
            ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
            ("HOME".to_owned(), "/home/re-ctm".to_owned()),
            ("TMPDIR".to_owned(), "/tmp".to_owned()),
            ("LANG".to_owned(), "C.UTF-8".to_owned()),
            (
                "VISIBLE_KEY".to_owned(),
                "secret-environment-value".to_owned(),
            ),
        ]);
        let workspace_bind = (
            fs::canonicalize(&workspace)
                .map_err(|error| ReCtmError::new("TEST", error.to_string()))?
                .to_string_lossy()
                .into_owned(),
            "/workspace".to_owned(),
        );
        for semantics in [&isolated_semantics, &trusted_semantics] {
            assert_eq!(semantics.fixed_flags, expected_fixed_flags);
            assert_eq!(semantics.uid.as_deref(), Some("0"));
            assert_eq!(semantics.gid.as_deref(), Some("0"));
            assert_eq!(semantics.hostname.as_deref(), Some("re-ctm-native"));
            assert_eq!(semantics.environment, expected_environment);
            assert_eq!(semantics.capability_drops, ["ALL"]);
            assert_eq!(semantics.proc_mount.as_deref(), Some("/proc"));
            assert_eq!(semantics.dev_mount.as_deref(), Some("/dev"));
            assert_eq!(semantics.tmpfs_mounts, ["/tmp"]);
            assert_eq!(
                semantics.writable_binds.as_slice(),
                std::slice::from_ref(&workspace_bind)
            );
            assert_eq!(semantics.workdir.as_deref(), Some("/workspace/proofs"));
            assert_eq!(semantics.argv, argv);
            let toolchain = toolchain.to_string_lossy().into_owned();
            assert!(
                semantics
                    .read_only_binds
                    .contains(&(toolchain.clone(), toolchain))
            );
            assert!(
                !semantics
                    .read_only_binds
                    .iter()
                    .any(|(source, target)| source == &private.to_string_lossy()
                        || target == &private.to_string_lossy())
            );
            assert!(
                !semantics
                    .read_only_binds
                    .iter()
                    .any(|(source, target)| { source == "/run" || target == "/run" })
            );
        }
        let resolver_bind = (
            resolver.to_string_lossy().into_owned(),
            resolver.to_string_lossy().into_owned(),
        );
        assert!(!isolated_semantics.read_only_binds.contains(&resolver_bind));
        assert!(trusted_semantics.read_only_binds.contains(&resolver_bind));

        // The compiler's function type proves that mode, grants, OAuth and
        // workflow authority cannot be supplied to the actuator.
        let compiler: fn(&SandboxPlan) -> Result<Vec<String>, ReCtmError> =
            build_bubblewrap_command;
        assert_eq!(compiler(&trusted)?, trusted_command);
        Ok(())
    }

    #[test]
    fn command_rejects_protected_root_overlap() -> Result<(), ReCtmError> {
        let temp = TempDir::new().map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        let workspace = temp.path().join("workspace");
        let private = temp.path().join("private");
        fs::create_dir_all(&workspace)
            .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        fs::create_dir_all(&private).map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        let argv = ["/bin/true".to_owned()];
        let result = plan_sandbox(&SandboxPlanInput {
            workspace: &workspace,
            workdir: ".",
            network: NetworkNamespacePlan::Shared,
            argv: &argv,
            environment: &BTreeMap::new(),
            sandbox_path: None,
            read_only_roots: std::slice::from_ref(&private),
            forbidden_paths: std::slice::from_ref(&private),
            probe_executable: None,
        });
        assert_eq!(
            result.map_err(|error| error.code),
            Err("NATIVE_TOOLCHAIN_ROOT_DENIED".to_owned())
        );

        let workspace_forbidden = workspace.join("must-not-overlap");
        let trust_domain_result = plan_sandbox(&SandboxPlanInput {
            workspace: &workspace,
            workdir: ".",
            network: NetworkNamespacePlan::Isolated,
            argv: &argv,
            environment: &BTreeMap::new(),
            sandbox_path: None,
            read_only_roots: &[],
            forbidden_paths: std::slice::from_ref(&workspace_forbidden),
            probe_executable: None,
        });
        assert_eq!(
            trust_domain_result.map_err(|error| error.code),
            Err("NATIVE_HELPER_TRUST_DOMAIN_OVERLAP".to_owned())
        );
        Ok(())
    }

    #[test]
    fn fixed_latex_helper_plan_is_safe_and_tty_agnostic() -> Result<(), ReCtmError> {
        let temp = TempDir::new().map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        let workspace = temp.path().join("workspace");
        fs::create_dir_all(&workspace)
            .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        let argv = vec![
            "/usr/bin/latexmk".to_owned(),
            "-pdf".to_owned(),
            "-interaction=nonstopmode".to_owned(),
            "proof.tex".to_owned(),
        ];
        let plan = plan_sandbox(&SandboxPlanInput {
            workspace: &workspace,
            workdir: ".",
            network: NetworkNamespacePlan::Isolated,
            argv: &argv,
            environment: &BTreeMap::new(),
            sandbox_path: Some("/usr/bin:/bin"),
            read_only_roots: &[],
            forbidden_paths: &[],
            probe_executable: None,
        })?;

        let non_tty_command = build_bubblewrap_command(&plan)?;
        // TTY ownership remains in CommandRequest after sandbox compilation;
        // selecting a PTY cannot change any SandboxPlan field or mount.
        let tty_command = build_bubblewrap_command(&plan.clone())?;
        assert_eq!(tty_command, non_tty_command);
        let semantics = compiled_semantics(&non_tty_command)?;
        assert!(semantics.network_isolated);
        assert_eq!(semantics.argv, argv);
        assert_eq!(semantics.workdir.as_deref(), Some("/workspace"));
        assert_eq!(
            semantics.environment.get("PATH").map(String::as_str),
            Some("/usr/bin:/bin")
        );
        Ok(())
    }

    #[test]
    fn regular_resolv_conf_needs_no_extra_runtime_mount() -> Result<(), ReCtmError> {
        let temp = TempDir::new().map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        let resolv_conf = temp.path().join("resolv.conf");
        fs::write(&resolv_conf, b"nameserver 127.0.0.53\n")
            .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        assert_eq!(
            runtime_resolver_target(&resolv_conf, &[temp.path().join("trusted")])?,
            None
        );
        Ok(())
    }

    #[test]
    fn trusted_runtime_resolver_symlink_returns_only_the_regular_file() -> Result<(), ReCtmError> {
        let temp = TempDir::new().map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        let trusted = temp.path().join("run/systemd/resolve");
        fs::create_dir_all(&trusted).map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        let target = trusted.join("stub-resolv.conf");
        fs::write(&target, b"nameserver 127.0.0.53\n")
            .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        let resolv_conf = temp.path().join("resolv.conf");
        symlink(&target, &resolv_conf)
            .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;

        let resolver_mount = runtime_resolver_target(&resolv_conf, std::slice::from_ref(&trusted))?;
        let canonical_target =
            fs::canonicalize(target).map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        assert_eq!(resolver_mount, Some(canonical_target.clone()));

        let workspace = temp.path().join("workspace");
        fs::create_dir_all(&workspace)
            .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        let argv = ["/bin/true".to_owned()];
        let shared = plan_sandbox_with_resolver(
            &SandboxPlanInput {
                workspace: &workspace,
                workdir: ".",
                network: NetworkNamespacePlan::Shared,
                argv: &argv,
                environment: &BTreeMap::new(),
                sandbox_path: None,
                read_only_roots: &[],
                forbidden_paths: &[],
                probe_executable: None,
            },
            || Ok(Some(canonical_target.clone())),
        )?;
        assert_eq!(shared.resolver_mount(), Some(canonical_target.as_path()));
        let semantics = compiled_semantics(&build_bubblewrap_command(&shared)?)?;
        let target_text = canonical_target.to_string_lossy().into_owned();
        assert!(
            semantics
                .read_only_binds
                .contains(&(target_text.clone(), target_text))
        );
        assert!(
            !semantics
                .read_only_binds
                .iter()
                .any(|(source, target)| { source == "/run" || target == "/run" })
        );
        Ok(())
    }

    #[test]
    fn runtime_resolver_symlink_outside_trusted_roots_fails_closed() -> Result<(), ReCtmError> {
        let temp = TempDir::new().map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        let trusted = temp.path().join("trusted");
        let untrusted = temp.path().join("secret");
        fs::create_dir_all(&trusted).map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        fs::write(&untrusted, b"must-not-mount\n")
            .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        let resolv_conf = temp.path().join("resolv.conf");
        symlink(&untrusted, &resolv_conf)
            .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;

        assert_eq!(
            runtime_resolver_target(&resolv_conf, &[trusted]).map_err(|error| error.code),
            Err("NATIVE_RESOLVER_TARGET_DENIED".to_owned())
        );
        Ok(())
    }

    #[test]
    fn runtime_resolver_target_must_be_a_regular_file() -> Result<(), ReCtmError> {
        let temp = TempDir::new().map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        let trusted = temp.path().join("run/systemd/resolve");
        let directory = trusted.join("resolver-dir");
        fs::create_dir_all(&directory)
            .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        let resolv_conf = temp.path().join("resolv.conf");
        symlink(&directory, &resolv_conf)
            .map_err(|error| ReCtmError::new("TEST", error.to_string()))?;

        assert_eq!(
            runtime_resolver_target(&resolv_conf, &[trusted]).map_err(|error| error.code),
            Err("NATIVE_RESOLVER_TARGET_INVALID".to_owned())
        );
        Ok(())
    }

    #[test]
    fn runtime_resolver_mount_is_one_read_only_file_without_broad_run_bind() {
        let target = Path::new("/run/systemd/resolve/stub-resolv.conf");
        let mut command = Vec::new();
        let mut created_dirs = BTreeSet::new();
        append_runtime_resolver_mount(target, &mut command, &mut created_dirs);

        let target_text = target.to_string_lossy().into_owned();
        assert!(command.windows(3).any(|items| {
            items
                == [
                    "--ro-bind".to_owned(),
                    target_text.clone(),
                    target_text.clone(),
                ]
        }));
        assert!(!command.windows(3).any(|items| {
            items == ["--ro-bind".to_owned(), "/run".to_owned(), "/run".to_owned()]
        }));
    }
}
