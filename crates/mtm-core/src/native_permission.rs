use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path, PathBuf};

use crate::command_policy::classify_current_command_permissions;
use crate::patch::{PatchOperation, parse_patch};
use crate::path_policy::validate_workspace_path;
use mtm_contracts::{
    NativeMode, NativePermissionKind, NativePermissionScope, NativePermissionTool, ReCtmError,
    invalid_argument,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const DEFAULT_PERMISSION_TTL_SECONDS: u64 = 300;
pub const MAX_PERMISSION_TTL_SECONDS: u64 = 3_600;

/// Public `exec_command` timeout defaults and bounds.
pub const DEFAULT_EXEC_TIMEOUT_MS: u64 = 30_000;
pub const MAX_EXEC_TIMEOUT_MS: u64 = 600_000;
pub const DEFAULT_EXEC_YIELD_TIME_MS: u64 = 10_000;
pub const MAX_EXEC_YIELD_TIME_MS: u64 = 30_000;
pub const DEFAULT_EXEC_MAX_OUTPUT_BYTES: usize = 65_536;
pub const MAX_EXEC_MAX_OUTPUT_BYTES: usize = 1_048_576;
pub const DEFAULT_EXEC_PREVIEW_BYTES: usize = 4_096;
pub const MAX_EXEC_PREVIEW_BYTES: usize = 1_048_576;
/// A timeout strictly greater than this value requires `long_timeout`.
pub const LONG_TIMEOUT_THRESHOLD_MS_EXCLUSIVE: u64 = 30_000;

pub const CANONICAL_GENERATED_OR_EXCLUDED_COMPONENTS: [&str; 11] = [
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "target",
];

const EXEC_PERMISSION_ORDER: [NativePermissionKind; 7] = [
    NativePermissionKind::SensitiveEnv,
    NativePermissionKind::DestructiveCommand,
    NativePermissionKind::ShellExpansion,
    NativePermissionKind::InlineScript,
    NativePermissionKind::Network,
    NativePermissionKind::LongTimeout,
    NativePermissionKind::PrivilegedExecutable,
];
const PATCH_PERMISSION_ORDER: [NativePermissionKind; 1] =
    [NativePermissionKind::WriteGeneratedOrIgnored];

/// Validated, non-authority-bearing form of the public `request_permissions` input.
///
/// The raw nested `arguments` object is deliberately not retained. Later grant records
/// bind this canonical digest together with authenticated owner/workspace facts and the
/// validated tool/kind/scope. Parsing a request never grants permission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativePermissionRequest {
    tool: NativePermissionTool,
    kind: NativePermissionKind,
    reason: String,
    arguments_sha256: String,
    scope: NativePermissionScope,
    ttl_seconds: u64,
}

impl NativePermissionRequest {
    pub fn parse(input: &Map<String, Value>) -> Result<Self, ReCtmError> {
        let tool = input
            .get("tool_name")
            .and_then(Value::as_str)
            .and_then(NativePermissionTool::from_wire)
            .ok_or_else(|| invalid_argument("tool_name must be exec_command or apply_patch"))?;
        let kind = input
            .get("permission")
            .and_then(Value::as_str)
            .and_then(NativePermissionKind::from_wire)
            .ok_or_else(|| {
                invalid_argument("permission is not a supported Native permission kind")
            })?;
        let reason = input
            .get("reason")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid_argument("reason must be a non-empty string"))?
            .to_owned();
        let arguments = input
            .get("arguments")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid_argument("arguments must be an object"))?;
        let scope = match input.get("scope") {
            None => NativePermissionScope::Once,
            Some(Value::String(value)) => NativePermissionScope::from_wire(value)
                .ok_or_else(|| invalid_argument("scope must be once or session"))?,
            Some(_) => return Err(invalid_argument("scope must be once or session")),
        };
        let ttl_seconds = match input.get("ttl_seconds") {
            None => DEFAULT_PERMISSION_TTL_SECONDS,
            Some(Value::Number(number)) => number
                .as_u64()
                .filter(|value| (1..=MAX_PERMISSION_TTL_SECONDS).contains(value))
                .ok_or_else(|| {
                    invalid_argument("ttl_seconds must be an integer between 1 and 3600")
                })?,
            Some(_) => {
                return Err(invalid_argument(
                    "ttl_seconds must be an integer between 1 and 3600",
                ));
            }
        };
        Ok(Self {
            tool,
            kind,
            reason,
            arguments_sha256: canonical_arguments_sha256(arguments)?,
            scope,
            ttl_seconds,
        })
    }

    #[must_use]
    pub const fn tool(&self) -> NativePermissionTool {
        self.tool
    }

    #[must_use]
    pub const fn kind(&self) -> NativePermissionKind {
        self.kind
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    #[must_use]
    pub fn arguments_sha256(&self) -> &str {
        &self.arguments_sha256
    }

    #[must_use]
    pub const fn scope(&self) -> NativePermissionScope {
        self.scope
    }

    #[must_use]
    pub const fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }
}

/// Return permissions implicitly present in the accepted Native mode profile.
///
/// This is profile data, not an explicit user grant, and it carries no workflow,
/// project, verifier, or finalizer authority.
#[must_use]
pub fn native_mode_implicitly_grants(mode: NativeMode, kind: NativePermissionKind) -> bool {
    match mode {
        NativeMode::Safe => false,
        NativeMode::Trusted => matches!(
            kind,
            NativePermissionKind::Network
                | NativePermissionKind::ShellExpansion
                | NativePermissionKind::InlineScript
        ),
        NativeMode::Dangerous => true,
    }
}

/// The form in which an `exec_command` invocation was supplied.
///
/// A command string is interpreted by `/bin/sh -lc`; an `argv` invocation is
/// passed directly to the executable.  Keeping this distinction in the typed
/// value prevents shell-only risks from being inferred from literal argv data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecInvocationForm {
    Cmd,
    Argv,
}

/// A validated, side-effect-free `exec_command` invocation.
///
/// The complete source argument object is represented only by its canonical
/// digest.  In particular, `Debug` never prints command text, stdin, or
/// environment values.
pub struct ExecInvocation {
    argv: Vec<String>,
    policy_text: String,
    form: ExecInvocationForm,
    workdir: String,
    timeout_ms: u64,
    yield_time_ms: u64,
    max_output_bytes: usize,
    preview_bytes: usize,
    stdin_present: bool,
    tty: bool,
    verbosity: Option<String>,
    environment: BTreeMap<String, String>,
    arguments_sha256: String,
}

impl Clone for ExecInvocation {
    fn clone(&self) -> Self {
        Self {
            argv: self.argv.clone(),
            policy_text: self.policy_text.clone(),
            form: self.form,
            workdir: self.workdir.clone(),
            timeout_ms: self.timeout_ms,
            yield_time_ms: self.yield_time_ms,
            max_output_bytes: self.max_output_bytes,
            preview_bytes: self.preview_bytes,
            stdin_present: self.stdin_present,
            tty: self.tty,
            verbosity: self.verbosity.clone(),
            environment: self.environment.clone(),
            arguments_sha256: self.arguments_sha256.clone(),
        }
    }
}

impl PartialEq for ExecInvocation {
    fn eq(&self, other: &Self) -> bool {
        self.argv == other.argv
            && self.policy_text == other.policy_text
            && self.form == other.form
            && self.workdir == other.workdir
            && self.timeout_ms == other.timeout_ms
            && self.yield_time_ms == other.yield_time_ms
            && self.max_output_bytes == other.max_output_bytes
            && self.preview_bytes == other.preview_bytes
            && self.stdin_present == other.stdin_present
            && self.tty == other.tty
            && self.verbosity == other.verbosity
            && self.environment == other.environment
            && self.arguments_sha256 == other.arguments_sha256
    }
}

impl Eq for ExecInvocation {}

impl fmt::Debug for ExecInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecInvocation")
            .field("form", &self.form)
            .field("argv_count", &self.argv.len())
            .field("policy_text", &"[REDACTED]")
            .field("workdir", &self.workdir)
            .field("timeout_ms", &self.timeout_ms)
            .field("yield_time_ms", &self.yield_time_ms)
            .field("max_output_bytes", &self.max_output_bytes)
            .field("preview_bytes", &self.preview_bytes)
            .field("stdin_present", &self.stdin_present)
            .field("tty", &self.tty)
            .field("verbosity", &self.verbosity)
            .field(
                "environment_keys",
                &self.environment.keys().collect::<Vec<_>>(),
            )
            .field("arguments_sha256", &self.arguments_sha256)
            .finish()
    }
}

impl ExecInvocation {
    /// Parse and validate the public `exec_command` argument object.
    pub fn parse(input: &Map<String, Value>) -> Result<Self, ReCtmError> {
        const ALLOWED: [&str; 12] = [
            "cmd",
            "argv",
            "cwd",
            "workdir",
            "env",
            "max_output_bytes",
            "preview_bytes",
            "stdin",
            "timeout_ms",
            "tty",
            "verbosity",
            "yield_time_ms",
        ];
        reject_unknown_keys(input, &ALLOWED)?;

        let (argv, policy_text, form) = match (input.get("cmd"), input.get("argv")) {
            (Some(_), Some(_)) => {
                return Err(invalid_argument(
                    "exec_command must provide cmd or argv, not both",
                ));
            }
            (Some(value), None) => {
                let command = value
                    .as_str()
                    .filter(|text| !text.is_empty())
                    .ok_or_else(|| invalid_argument("cmd must be a non-empty string"))?;
                if command.contains('\0') {
                    return Err(invalid_argument("cmd contains a NUL byte"));
                }
                (
                    vec!["/bin/sh".to_owned(), "-lc".to_owned(), command.to_owned()],
                    command.to_owned(),
                    ExecInvocationForm::Cmd,
                )
            }
            (None, Some(value)) => {
                let items = value
                    .as_array()
                    .ok_or_else(|| invalid_argument("argv must be an array of strings"))?;
                if items.is_empty() {
                    return Err(invalid_argument("argv must contain an executable"));
                }
                let parsed = items
                    .iter()
                    .map(|item| {
                        let text = item
                            .as_str()
                            .ok_or_else(|| invalid_argument("argv must contain only strings"))?;
                        if text.contains('\0') {
                            return Err(invalid_argument("argv contains a NUL byte"));
                        }
                        Ok(text.to_owned())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if parsed.first().is_none_or(String::is_empty) {
                    return Err(invalid_argument("argv executable must be non-empty"));
                }
                let policy_text = parsed.join(" ");
                (parsed, policy_text, ExecInvocationForm::Argv)
            }
            (None, None) => return Err(invalid_argument("cmd or argv is required")),
        };

        let workdir = parse_workdir(input)?;
        let environment = parse_environment(input.get("env"))?;
        let timeout_ms = parse_bounded_u64(
            input.get("timeout_ms"),
            "timeout_ms",
            DEFAULT_EXEC_TIMEOUT_MS,
            1,
            MAX_EXEC_TIMEOUT_MS,
        )?;
        let yield_time_ms = parse_bounded_u64(
            input.get("yield_time_ms"),
            "yield_time_ms",
            DEFAULT_EXEC_YIELD_TIME_MS,
            0,
            MAX_EXEC_YIELD_TIME_MS,
        )?;
        let max_output_bytes = parse_bounded_usize(
            input.get("max_output_bytes"),
            "max_output_bytes",
            DEFAULT_EXEC_MAX_OUTPUT_BYTES,
            1,
            MAX_EXEC_MAX_OUTPUT_BYTES,
        )?;
        let preview_bytes = parse_bounded_usize(
            input.get("preview_bytes"),
            "preview_bytes",
            DEFAULT_EXEC_PREVIEW_BYTES,
            1,
            MAX_EXEC_PREVIEW_BYTES,
        )?;
        let stdin_present = match input.get("stdin") {
            None => false,
            Some(Value::String(_)) => true,
            Some(_) => return Err(invalid_argument("stdin must be a string")),
        };
        let tty = parse_bool(input.get("tty"), "tty", false)?;
        let verbosity = parse_verbosity(input.get("verbosity"))?;

        Ok(Self {
            argv,
            policy_text,
            form,
            workdir,
            timeout_ms,
            yield_time_ms,
            max_output_bytes,
            preview_bytes,
            stdin_present,
            tty,
            verbosity,
            environment,
            arguments_sha256: canonical_arguments_sha256(input)?,
        })
    }

    /// Compatibility spelling for callers that parse a generic argument map.
    pub fn from_arguments(input: &Map<String, Value>) -> Result<Self, ReCtmError> {
        Self::parse(input)
    }

    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    #[must_use]
    pub fn policy_text(&self) -> &str {
        &self.policy_text
    }

    #[must_use]
    pub const fn form(&self) -> ExecInvocationForm {
        self.form
    }

    #[must_use]
    pub fn workdir(&self) -> &str {
        &self.workdir
    }

    #[must_use]
    pub const fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    #[must_use]
    pub const fn yield_time_ms(&self) -> u64 {
        self.yield_time_ms
    }

    #[must_use]
    pub const fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    #[must_use]
    pub const fn preview_bytes(&self) -> usize {
        self.preview_bytes
    }

    #[must_use]
    pub const fn stdin_present(&self) -> bool {
        self.stdin_present
    }

    #[must_use]
    pub const fn tty(&self) -> bool {
        self.tty
    }

    #[must_use]
    pub fn verbosity(&self) -> Option<&str> {
        self.verbosity.as_deref()
    }

    #[must_use]
    pub fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }

    #[must_use]
    pub fn arguments_sha256(&self) -> &str {
        &self.arguments_sha256
    }

    /// Return statically discoverable executable tokens in shell execution order.
    pub fn executable_candidates(&self) -> Result<Vec<String>, ReCtmError> {
        match self.form {
            ExecInvocationForm::Cmd => shell_executable_candidates(&self.policy_text, 0),
            ExecInvocationForm::Argv => argv_executable_candidates(&self.argv),
        }
    }
}

/// A validated, side-effect-free `apply_patch` invocation.
pub struct PatchInvocation {
    operations: Vec<PatchOperation>,
    dry_run: bool,
    arguments_sha256: String,
}

impl Clone for PatchInvocation {
    fn clone(&self) -> Self {
        Self {
            operations: self.operations.clone(),
            dry_run: self.dry_run,
            arguments_sha256: self.arguments_sha256.clone(),
        }
    }
}

impl PartialEq for PatchInvocation {
    fn eq(&self, other: &Self) -> bool {
        self.operations == other.operations
            && self.dry_run == other.dry_run
            && self.arguments_sha256 == other.arguments_sha256
    }
}

impl Eq for PatchInvocation {}

impl fmt::Debug for PatchInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PatchInvocation")
            .field("operation_count", &self.operations.len())
            .field("dry_run", &self.dry_run)
            .field("patch_body", &"[REDACTED]")
            .field("arguments_sha256", &self.arguments_sha256)
            .finish()
    }
}

impl PatchInvocation {
    /// Parse and validate the public `apply_patch` argument object.
    pub fn parse(input: &Map<String, Value>) -> Result<Self, ReCtmError> {
        const ALLOWED: [&str; 2] = ["patch", "dry_run"];
        reject_unknown_keys(input, &ALLOWED)?;
        let patch = input
            .get("patch")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .ok_or_else(|| invalid_argument("patch must be a non-empty string"))?;
        if patch.contains('\0') {
            return Err(invalid_argument("patch contains a NUL byte"));
        }
        let operations = parse_patch(patch)?;
        if operations.is_empty() {
            return Err(invalid_argument(
                "patch must contain at least one operation",
            ));
        }
        for operation in &operations {
            validate_workspace_path(&operation.path)?;
            if let Some(destination) = &operation.move_to {
                validate_workspace_path(destination)?;
            }
        }
        let dry_run = parse_bool(input.get("dry_run"), "dry_run", false)?;
        Ok(Self {
            operations,
            dry_run,
            arguments_sha256: canonical_arguments_sha256(input)?,
        })
    }

    /// Compatibility spelling for callers that parse a generic argument map.
    pub fn from_arguments(input: &Map<String, Value>) -> Result<Self, ReCtmError> {
        Self::parse(input)
    }

    #[must_use]
    pub fn operations(&self) -> &[PatchOperation] {
        &self.operations
    }

    #[must_use]
    pub const fn dry_run(&self) -> bool {
        self.dry_run
    }

    #[must_use]
    pub fn arguments_sha256(&self) -> &str {
        &self.arguments_sha256
    }
}

/// A typed Native invocation accepted by the shadow permission evaluator.
pub enum NativeInvocation {
    Exec(ExecInvocation),
    Patch(PatchInvocation),
}

impl Clone for NativeInvocation {
    fn clone(&self) -> Self {
        match self {
            Self::Exec(invocation) => Self::Exec(invocation.clone()),
            Self::Patch(invocation) => Self::Patch(invocation.clone()),
        }
    }
}

impl PartialEq for NativeInvocation {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Exec(left), Self::Exec(right)) => left == right,
            (Self::Patch(left), Self::Patch(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for NativeInvocation {}

impl fmt::Debug for NativeInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exec(invocation) => formatter
                .debug_tuple("NativeInvocation::Exec")
                .field(invocation)
                .finish(),
            Self::Patch(invocation) => formatter
                .debug_tuple("NativeInvocation::Patch")
                .field(invocation)
                .finish(),
        }
    }
}

impl NativeInvocation {
    pub fn parse(
        tool: NativePermissionTool,
        input: &Map<String, Value>,
    ) -> Result<Self, ReCtmError> {
        match tool {
            NativePermissionTool::ExecCommand => Ok(Self::Exec(ExecInvocation::parse(input)?)),
            NativePermissionTool::ApplyPatch => Ok(Self::Patch(PatchInvocation::parse(input)?)),
        }
    }

    #[must_use]
    pub const fn tool(&self) -> NativePermissionTool {
        match self {
            Self::Exec(_) => NativePermissionTool::ExecCommand,
            Self::Patch(_) => NativePermissionTool::ApplyPatch,
        }
    }

    #[must_use]
    pub fn arguments_sha256(&self) -> &str {
        match self {
            Self::Exec(invocation) => invocation.arguments_sha256(),
            Self::Patch(invocation) => invocation.arguments_sha256(),
        }
    }
}

/// Filesystem metadata collected outside `mtm-core` for one executable token.
#[derive(Clone, Eq, PartialEq)]
pub struct ResolvedExecutableFact {
    requested: String,
    resolved_path: PathBuf,
    device: u64,
    inode: u64,
    mode: u32,
    size: u64,
    modified_fingerprint: Option<String>,
}

impl fmt::Debug for ResolvedExecutableFact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedExecutableFact")
            .field("requested", &"[REDACTED]")
            .field("resolved_path", &"[REDACTED]")
            .field("device", &self.device)
            .field("inode", &self.inode)
            .field("mode", &format_args!("0o{:o}", self.mode))
            .field("size", &self.size)
            .field("modified_fingerprint", &self.modified_fingerprint)
            .finish()
    }
}

impl ResolvedExecutableFact {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        requested: impl Into<String>,
        resolved_path: PathBuf,
        device: u64,
        inode: u64,
        mode: u32,
        size: u64,
        modified_fingerprint: Option<String>,
    ) -> Self {
        Self {
            requested: requested.into(),
            resolved_path,
            device,
            inode,
            mode,
            size,
            modified_fingerprint,
        }
    }

    #[must_use]
    pub fn requested(&self) -> &str {
        &self.requested
    }

    #[must_use]
    pub fn resolved_path(&self) -> &std::path::Path {
        &self.resolved_path
    }

    #[must_use]
    pub const fn device(&self) -> u64 {
        self.device
    }

    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    #[must_use]
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    #[must_use]
    pub fn modified_fingerprint(&self) -> Option<&str> {
        self.modified_fingerprint.as_deref()
    }

    #[must_use]
    pub const fn is_privileged(&self) -> bool {
        self.mode & 0o6000 != 0
    }
}

/// Filesystem/Git facts for one patch path.  Git lookup is performed by the
/// runtime; this type itself has no I/O.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatchPathFact {
    path: String,
    canonical_generated_component: bool,
    git_ignored: bool,
}

impl PatchPathFact {
    pub fn new(path: impl Into<String>, git_ignored: bool) -> Result<Self, ReCtmError> {
        let path = path.into();
        if path.is_empty() || path.contains('\0') {
            return Err(invalid_argument(
                "patch path fact must contain a valid path",
            ));
        }
        validate_workspace_path(&path)?;
        Ok(Self {
            canonical_generated_component: has_canonical_generated_component(&path),
            path,
            git_ignored,
        })
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn canonical_generated_component(&self) -> bool {
        self.canonical_generated_component
    }

    #[must_use]
    pub const fn git_ignored(&self) -> bool {
        self.git_ignored
    }

    #[must_use]
    pub const fn requires_generated_write_permission(&self) -> bool {
        self.canonical_generated_component || self.git_ignored
    }
}

/// Validated executable/Git facts supplied to the pure evaluator.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecPermissionFacts {
    arguments_sha256: String,
    resolved_executables: Vec<ResolvedExecutableFact>,
    unresolved_executables: Vec<String>,
}

impl fmt::Debug for ExecPermissionFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecPermissionFacts")
            .field("arguments_sha256", &self.arguments_sha256)
            .field(
                "resolved_executable_count",
                &self.resolved_executables.len(),
            )
            .field(
                "unresolved_executable_count",
                &self.unresolved_executables.len(),
            )
            .finish()
    }
}

impl ExecPermissionFacts {
    /// Construct facts after runtime resolution.  Every statically discoverable
    /// executable must be represented; an omitted candidate is recorded as
    /// unresolved so classification fails closed.
    pub fn new(
        invocation: &ExecInvocation,
        resolved_executables: Vec<ResolvedExecutableFact>,
    ) -> Result<Self, ReCtmError> {
        let candidates = invocation.executable_candidates()?;
        let unresolved = candidates
            .into_iter()
            .filter(|candidate| {
                !resolved_executables
                    .iter()
                    .any(|fact| fact.requested() == candidate)
            })
            .collect::<Vec<_>>();
        Self::with_unresolved(invocation, resolved_executables, unresolved)
    }

    pub fn with_unresolved(
        invocation: &ExecInvocation,
        resolved_executables: Vec<ResolvedExecutableFact>,
        unresolved_executables: Vec<String>,
    ) -> Result<Self, ReCtmError> {
        if unresolved_executables
            .iter()
            .any(|value| value.is_empty() || value.contains('\0'))
        {
            return Err(invalid_argument("unresolved executable fact is invalid"));
        }
        let candidates = invocation.executable_candidates()?;
        if candidates.iter().any(|candidate| {
            !resolved_executables
                .iter()
                .any(|fact| fact.requested() == candidate)
                && !unresolved_executables.iter().any(|item| item == candidate)
        }) {
            return Err(ReCtmError::new(
                "NATIVE_EXECUTABLE_FACTS_INCOMPLETE",
                "Executable facts did not cover every statically discoverable executable.",
            )
            .with_category(mtm_contracts::ErrorCategory::Security));
        }
        Ok(Self {
            arguments_sha256: invocation.arguments_sha256().to_owned(),
            resolved_executables,
            unresolved_executables,
        })
    }

    #[must_use]
    pub fn arguments_sha256(&self) -> &str {
        &self.arguments_sha256
    }

    #[must_use]
    pub fn resolved_executables(&self) -> &[ResolvedExecutableFact] {
        &self.resolved_executables
    }

    #[must_use]
    pub fn unresolved_executables(&self) -> &[String] {
        &self.unresolved_executables
    }
}

/// Classify all intrinsic command risks in the frozen D3 order.
///
/// This function is deliberately independent of `NativeMode`: profiles are
/// applied later by [`EffectiveNativePolicy`].  Filesystem facts are supplied
/// by the caller and are never collected here.
pub fn classify_exec_permissions(
    invocation: &ExecInvocation,
    facts: &ExecPermissionFacts,
) -> Result<Vec<NativePermissionKind>, ReCtmError> {
    if facts.arguments_sha256() != invocation.arguments_sha256() {
        return Err(ReCtmError::new(
            "NATIVE_PERMISSION_FACTS_ARGUMENT_MISMATCH",
            "Executable facts are bound to a different invocation.",
        )
        .with_category(mtm_contracts::ErrorCategory::Security));
    }
    if !facts.unresolved_executables().is_empty() {
        return Err(ReCtmError::new(
            "NATIVE_EXECUTABLE_UNRESOLVED",
            "A statically resolvable command executable could not be inspected.",
        )
        .with_category(mtm_contracts::ErrorCategory::Security)
        .with_details(serde_json::json!({
            "unresolved_count": facts.unresolved_executables().len(),
        })));
    }

    // Reuse the accepted classifier for the five already-frozen dimensions so
    // its regexes and ordering remain one source of truth.  argv is direct
    // execution, so shell expansion syntax in a literal argument is not a
    // shell risk.
    let mut needs = classify_current_command_permissions(
        NativeMode::Safe,
        invocation.policy_text(),
        invocation.environment(),
    )?;
    if invocation.form() == ExecInvocationForm::Argv {
        needs.retain(|kind| *kind != NativePermissionKind::ShellExpansion);
    }
    if invocation.timeout_ms() > LONG_TIMEOUT_THRESHOLD_MS_EXCLUSIVE {
        needs.push(NativePermissionKind::LongTimeout);
    }
    if facts
        .resolved_executables()
        .iter()
        .any(ResolvedExecutableFact::is_privileged)
    {
        needs.push(NativePermissionKind::PrivilegedExecutable);
    }
    Ok(needs)
}

/// Classify the sole D3 patch risk dimension from runtime-collected path facts.
pub fn classify_patch_permissions(
    invocation: &PatchInvocation,
    facts: &[PatchPathFact],
) -> Result<Vec<NativePermissionKind>, ReCtmError> {
    let expected_paths = patch_paths(invocation.operations())?;
    let mut by_path = BTreeMap::new();
    for fact in facts {
        if by_path.insert(fact.path().to_owned(), fact).is_some() {
            return Err(ReCtmError::new(
                "NATIVE_PATCH_AUTHORITY_FACTS_AMBIGUOUS",
                "Patch path facts contained duplicate paths.",
            )
            .with_category(mtm_contracts::ErrorCategory::Security));
        }
    }
    let missing = expected_paths
        .iter()
        .filter(|path| !by_path.contains_key(*path))
        .count();
    let extra = by_path
        .keys()
        .filter(|path| !expected_paths.iter().any(|expected| expected == *path))
        .count();
    if missing != 0 || extra != 0 {
        return Err(ReCtmError::new(
            "NATIVE_PATCH_AUTHORITY_FACTS_INCOMPLETE",
            "Patch path facts did not cover exactly every affected path.",
        )
        .with_category(mtm_contracts::ErrorCategory::Security)
        .with_details(serde_json::json!({"missing_count":missing,"extra_count":extra})));
    }

    if invocation.dry_run() {
        return Ok(Vec::new());
    }
    if expected_paths.iter().any(|path| {
        by_path
            .get(path)
            .is_some_and(|fact| fact.requires_generated_write_permission())
    }) {
        return Ok(vec![NativePermissionKind::WriteGeneratedOrIgnored]);
    }
    Ok(Vec::new())
}

/// Return the canonical generated/excluded path components frozen by MTM-014.
#[must_use]
pub fn generated_or_excluded_components() -> &'static [&'static str; 11] {
    &CANONICAL_GENERATED_OR_EXCLUDED_COMPONENTS
}

/// Component-based generated/excluded path matching.  Substrings do not match:
/// `builder/file.txt` is intentionally distinct from `build/file.txt`.
#[must_use]
pub fn has_canonical_generated_component(path: &str) -> bool {
    Path::new(path).components().any(|component| {
        let Component::Normal(value) = component else {
            return false;
        };
        value
            .to_str()
            .is_some_and(|value| CANONICAL_GENERATED_OR_EXCLUDED_COMPONENTS.contains(&value))
    })
}

/// The deterministic permission order for an `exec_command` invocation.
#[must_use]
pub const fn exec_permission_order() -> [NativePermissionKind; 7] {
    EXEC_PERMISSION_ORDER
}

/// Deterministically combine intrinsic requirements with profile and explicit
/// grants.  Explicit grants are intersected with the invocation's requirements;
/// unrelated grants can never widen the resulting policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveNativePolicy {
    tool: NativePermissionTool,
    arguments_sha256: String,
    required: Vec<NativePermissionKind>,
    implicitly_granted: BTreeSet<NativePermissionKind>,
    explicitly_granted: BTreeSet<NativePermissionKind>,
    missing: Vec<NativePermissionKind>,
}

impl EffectiveNativePolicy {
    pub fn derive(
        mode: NativeMode,
        invocation: &NativeInvocation,
        required: &[NativePermissionKind],
        explicitly_granted: &BTreeSet<NativePermissionKind>,
    ) -> Result<Self, ReCtmError> {
        Self::evaluate(mode, invocation, required, explicitly_granted)
    }

    pub fn evaluate(
        mode: NativeMode,
        invocation: &NativeInvocation,
        required: &[NativePermissionKind],
        explicitly_granted: &BTreeSet<NativePermissionKind>,
    ) -> Result<Self, ReCtmError> {
        Self::from_parts(
            mode,
            invocation.tool(),
            invocation.arguments_sha256(),
            required,
            explicitly_granted,
        )
    }

    pub fn from_parts(
        mode: NativeMode,
        tool: NativePermissionTool,
        arguments_sha256: &str,
        required: &[NativePermissionKind],
        explicitly_granted: &BTreeSet<NativePermissionKind>,
    ) -> Result<Self, ReCtmError> {
        if !is_sha256_hex(arguments_sha256) {
            return Err(invalid_argument(
                "Native invocation argument digest must be a SHA-256 hex value",
            ));
        }
        let allowed = allowed_permissions_for_tool(tool);
        let mut seen = BTreeSet::new();
        for kind in required {
            if !allowed.contains(kind) {
                return Err(invalid_argument(
                    "permission kind is not valid for this Native tool",
                ));
            }
            if !seen.insert(*kind) {
                return Err(ReCtmError::new(
                    "NATIVE_PERMISSION_SET_AMBIGUOUS",
                    "An invocation listed the same permission kind more than once.",
                )
                .with_category(mtm_contracts::ErrorCategory::Security));
            }
        }
        let required = allowed
            .iter()
            .copied()
            .filter(|kind| seen.contains(kind))
            .collect::<Vec<_>>();
        let implicitly_granted = required
            .iter()
            .copied()
            .filter(|kind| native_mode_implicitly_grants(mode, *kind))
            .collect::<BTreeSet<_>>();
        let explicitly_granted = explicitly_granted
            .iter()
            .copied()
            .filter(|kind| seen.contains(kind))
            .collect::<BTreeSet<_>>();
        let missing = required
            .iter()
            .copied()
            .filter(|kind| !implicitly_granted.contains(kind) && !explicitly_granted.contains(kind))
            .collect::<Vec<_>>();
        Ok(Self {
            tool,
            arguments_sha256: arguments_sha256.to_owned(),
            required,
            implicitly_granted,
            explicitly_granted,
            missing,
        })
    }

    #[must_use]
    pub const fn tool(&self) -> NativePermissionTool {
        self.tool
    }

    #[must_use]
    pub fn arguments_sha256(&self) -> &str {
        &self.arguments_sha256
    }

    #[must_use]
    pub fn required(&self) -> &[NativePermissionKind] {
        &self.required
    }

    #[must_use]
    pub fn implicitly_granted(&self) -> &BTreeSet<NativePermissionKind> {
        &self.implicitly_granted
    }

    #[must_use]
    pub fn explicitly_granted(&self) -> &BTreeSet<NativePermissionKind> {
        &self.explicitly_granted
    }

    #[must_use]
    pub fn missing(&self) -> &[NativePermissionKind] {
        &self.missing
    }

    #[must_use]
    pub fn required_permissions(&self) -> &[NativePermissionKind] {
        self.required()
    }

    #[must_use]
    pub fn missing_permissions(&self) -> &[NativePermissionKind] {
        self.missing()
    }

    #[must_use]
    pub fn is_authorized(&self) -> bool {
        self.missing.is_empty()
    }

    #[must_use]
    pub fn authorized(&self) -> bool {
        self.is_authorized()
    }
}

/// Alias used by callers that prefer the verb-first name.
pub type NativeEffectivePolicy = EffectiveNativePolicy;

fn allowed_permissions_for_tool(tool: NativePermissionTool) -> &'static [NativePermissionKind] {
    match tool {
        NativePermissionTool::ExecCommand => &EXEC_PERMISSION_ORDER,
        NativePermissionTool::ApplyPatch => &PATCH_PERMISSION_ORDER,
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn reject_unknown_keys(input: &Map<String, Value>, allowed: &[&str]) -> Result<(), ReCtmError> {
    if let Some(key) = input.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid_argument(format!(
            "{key} is not a recognized argument"
        )));
    }
    Ok(())
}

fn parse_workdir(input: &Map<String, Value>) -> Result<String, ReCtmError> {
    let workdir = match input.get("workdir") {
        None => None,
        Some(Value::String(value)) => Some(value.as_str()),
        Some(_) => return Err(invalid_argument("workdir must be a string")),
    };
    let cwd = match input.get("cwd") {
        None => None,
        Some(Value::String(value)) => Some(value.as_str()),
        Some(_) => return Err(invalid_argument("cwd must be a string")),
    };
    if let (Some(left), Some(right)) = (workdir, cwd)
        && left != right
    {
        return Err(invalid_argument(
            "workdir and cwd refer to different directories",
        ));
    }
    validate_workspace_path(workdir.or(cwd).unwrap_or("."))
}

fn parse_environment(input: Option<&Value>) -> Result<BTreeMap<String, String>, ReCtmError> {
    let Some(value) = input else {
        return Ok(BTreeMap::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| invalid_argument("env must be an object whose values are strings"))?;
    let mut environment = BTreeMap::new();
    for (key, value) in object {
        if key.is_empty() || key.contains('\0') || key.contains('=') {
            return Err(invalid_argument("env contains an invalid variable name"));
        }
        let value = value
            .as_str()
            .ok_or_else(|| invalid_argument("env must be an object whose values are strings"))?;
        if value.contains('\0') {
            return Err(invalid_argument("env contains a NUL byte"));
        }
        environment.insert(key.clone(), value.to_owned());
    }
    Ok(environment)
}

fn parse_bounded_u64(
    value: Option<&Value>,
    name: &str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64, ReCtmError> {
    let value = match value {
        None => default,
        Some(Value::Number(number)) => number
            .as_u64()
            .ok_or_else(|| invalid_argument(format!("{name} must be a non-negative integer")))?,
        Some(_) => return Err(invalid_argument(format!("{name} must be an integer"))),
    };
    if !(minimum..=maximum).contains(&value) {
        return Err(invalid_argument(format!(
            "{name} must be between {minimum} and {maximum}"
        )));
    }
    Ok(value)
}

fn parse_bounded_usize(
    value: Option<&Value>,
    name: &str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, ReCtmError> {
    let value = parse_bounded_u64(
        value,
        name,
        u64::try_from(default).unwrap_or(u64::MAX),
        u64::try_from(minimum).unwrap_or(u64::MAX),
        u64::try_from(maximum).unwrap_or(u64::MAX),
    )?;
    usize::try_from(value)
        .map_err(|_| invalid_argument(format!("{name} is too large for this platform")))
}

fn parse_bool(value: Option<&Value>, name: &str, default: bool) -> Result<bool, ReCtmError> {
    match value {
        None => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(invalid_argument(format!("{name} must be a boolean"))),
    }
}

fn parse_verbosity(value: Option<&Value>) -> Result<Option<String>, ReCtmError> {
    match value {
        None => Ok(None),
        Some(Value::String(value)) if matches!(value.as_str(), "summary" | "preview" | "full") => {
            Ok(Some(value.clone()))
        }
        Some(Value::String(_)) => Err(invalid_argument(
            "verbosity must be summary, preview, or full",
        )),
        Some(_) => Err(invalid_argument("verbosity must be a string")),
    }
}

fn shell_executable_candidates(command: &str, depth: usize) -> Result<Vec<String>, ReCtmError> {
    if depth > 4 {
        return Err(ReCtmError::new(
            "NATIVE_EXECUTABLE_PARSE_LIMIT",
            "Nested shell command parsing exceeded its fixed bound.",
        )
        .with_category(mtm_contracts::ErrorCategory::Security));
    }
    let tokens = shell_words::split(command).map_err(|_| {
        ReCtmError::new(
            "NATIVE_EXECUTABLE_PARSE_FAILED",
            "Command could not be parsed for executable fact collection.",
        )
        .with_category(mtm_contracts::ErrorCategory::Security)
    })?;
    let mut candidates = Vec::new();
    let mut segment = Vec::new();
    for token in tokens {
        if is_shell_control_operator(&token) {
            append_segment_candidates(&segment, depth, &mut candidates)?;
            segment.clear();
        } else {
            segment.push(token);
        }
    }
    append_segment_candidates(&segment, depth, &mut candidates)?;
    Ok(candidates)
}

fn argv_executable_candidates(argv: &[String]) -> Result<Vec<String>, ReCtmError> {
    if argv.is_empty() || argv[0].is_empty() {
        return Err(invalid_argument("argv must contain an executable"));
    }
    let mut candidates = vec![argv[0].clone()];
    if is_shell_executable(&argv[0])
        && let Some(script) = shell_script_argument(argv)
    {
        candidates.extend(shell_executable_candidates(script, 1)?);
    }
    Ok(candidates)
}

fn append_segment_candidates(
    segment: &[String],
    depth: usize,
    output: &mut Vec<String>,
) -> Result<(), ReCtmError> {
    let mut index = 0;
    while index < segment.len() && is_assignment(&segment[index]) {
        index += 1;
    }
    while index < segment.len() {
        let name = executable_basename(&segment[index]);
        if matches!(
            name.as_str(),
            "env" | "command" | "exec" | "nohup" | "setsid" | "time"
        ) {
            index += 1;
            if name == "env" {
                while index < segment.len()
                    && (segment[index].starts_with('-') || is_assignment(&segment[index]))
                {
                    // `env -u NAME` consumes the name following -u.
                    if matches!(segment[index].as_str(), "-u" | "--unset") {
                        index = index.saturating_add(2);
                    } else {
                        index += 1;
                    }
                }
            }
            continue;
        }
        if is_shell_keyword(&name) {
            index += 1;
            continue;
        }
        let executable = segment[index].clone();
        output.push(executable);
        if is_shell_executable(&segment[index])
            && let Some(script) = shell_script_argument(&segment[index..])
        {
            output.extend(shell_executable_candidates(script, depth + 1)?);
        }
        break;
    }
    Ok(())
}

fn shell_script_argument(argv: &[String]) -> Option<&str> {
    argv.iter().enumerate().find_map(|(index, item)| {
        if matches!(item.as_str(), "-c" | "-ec" | "-ce" | "--command") {
            argv.get(index + 1).map(String::as_str)
        } else {
            None
        }
    })
}

fn is_shell_control_operator(token: &str) -> bool {
    matches!(token, "|" | "||" | "&" | "&&" | ";")
}

fn is_assignment(token: &str) -> bool {
    let Some((name, _)) = token.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_'
                || byte.is_ascii_alphanumeric() && index > 0
                || byte.is_ascii_alphabetic() && index == 0
        })
}

fn is_shell_keyword(name: &str) -> bool {
    matches!(
        name,
        "if" | "then"
            | "else"
            | "elif"
            | "fi"
            | "for"
            | "while"
            | "until"
            | "do"
            | "done"
            | "case"
            | "esac"
            | "in"
            | "function"
            | "{"
            | "}"
            | "("
            | ")"
    )
}

fn is_shell_executable(value: &str) -> bool {
    matches!(
        executable_basename(value).as_str(),
        "sh" | "bash" | "zsh" | "dash" | "ksh"
    )
}

fn executable_basename(value: &str) -> String {
    let normalized = value.replace('\\', "/");
    normalized
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn patch_paths(operations: &[PatchOperation]) -> Result<Vec<String>, ReCtmError> {
    let mut paths = Vec::new();
    for operation in operations {
        match operation.kind.as_str() {
            "add" | "delete" | "update" => {
                if operation.path.is_empty() || operation.path.contains('\0') {
                    return Err(invalid_argument("patch operation path is invalid"));
                }
                paths.push(operation.path.clone());
                if let Some(move_to) = &operation.move_to {
                    if move_to.is_empty() || move_to.contains('\0') {
                        return Err(invalid_argument("patch move destination is invalid"));
                    }
                    paths.push(move_to.clone());
                }
            }
            _ => {
                return Err(invalid_argument("patch operation kind is unsupported"));
            }
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

pub fn canonical_arguments_sha256(arguments: &Map<String, Value>) -> Result<String, ReCtmError> {
    let sorted = sort_json(&Value::Object(arguments.clone()));
    let bytes = serde_json::to_vec(&sorted)
        .map_err(|error| invalid_argument(format!("arguments are not serializable: {error}")))?;
    let digest = Sha256::digest(bytes);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn sort_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let sorted = object
                .iter()
                .map(|(key, value)| (key.clone(), sort_json(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_json).collect()),
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(arguments: Value) -> Map<String, Value> {
        serde_json::json!({
            "tool_name": "exec_command",
            "permission": "network",
            "reason": "fetch dependency metadata",
            "arguments": arguments,
        })
        .as_object()
        .cloned()
        .unwrap_or_default()
    }

    #[test]
    fn request_defaults_are_typed_and_digest_is_canonical() -> Result<(), ReCtmError> {
        let left = NativePermissionRequest::parse(&request(serde_json::json!({
            "cmd":"curl https://example.com",
            "env":{"B":"2","A":"1"}
        })))?;
        let right = NativePermissionRequest::parse(&request(serde_json::json!({
            "env":{"A":"1","B":"2"},
            "cmd":"curl https://example.com"
        })))?;
        assert_eq!(left.tool(), NativePermissionTool::ExecCommand);
        assert_eq!(left.kind(), NativePermissionKind::Network);
        assert_eq!(left.scope(), NativePermissionScope::Once);
        assert_eq!(left.ttl_seconds(), DEFAULT_PERMISSION_TTL_SECONDS);
        assert_eq!(left.reason(), "fetch dependency metadata");
        assert_eq!(left.arguments_sha256(), right.arguments_sha256());
        assert_eq!(left.arguments_sha256().len(), 64);
        Ok(())
    }

    #[test]
    fn request_binding_changes_when_arguments_change() -> Result<(), ReCtmError> {
        let left = NativePermissionRequest::parse(&request(serde_json::json!({
            "cmd":"curl https://a.example"
        })))?;
        let right = NativePermissionRequest::parse(&request(serde_json::json!({
            "cmd":"curl https://b.example"
        })))?;
        assert_ne!(left.arguments_sha256(), right.arguments_sha256());
        Ok(())
    }

    #[test]
    fn request_rejects_unknown_or_malformed_authority_fields() {
        for (key, value) in [
            ("tool_name", Value::String("rethlas_step".to_owned())),
            ("permission", Value::String("filesystem_escape".to_owned())),
            ("scope", Value::String("forever".to_owned())),
            ("ttl_seconds", Value::from(0)),
            ("ttl_seconds", Value::from(3_601)),
        ] {
            let mut input = request(serde_json::json!({"cmd":"true"}));
            input.insert(key.to_owned(), value);
            assert!(NativePermissionRequest::parse(&input).is_err());
        }
        let mut empty_reason = request(serde_json::json!({"cmd":"true"}));
        empty_reason.insert("reason".to_owned(), Value::String("   ".to_owned()));
        assert!(NativePermissionRequest::parse(&empty_reason).is_err());
        let mut non_object = request(serde_json::json!({"cmd":"true"}));
        non_object.insert("arguments".to_owned(), Value::String("true".to_owned()));
        assert!(NativePermissionRequest::parse(&non_object).is_err());
    }

    #[test]
    fn mode_profiles_are_explicit_data_not_workflow_authority() {
        for kind in NativePermissionKind::ALL {
            assert!(!native_mode_implicitly_grants(NativeMode::Safe, kind));
            assert!(native_mode_implicitly_grants(NativeMode::Dangerous, kind));
        }
        assert!(native_mode_implicitly_grants(
            NativeMode::Trusted,
            NativePermissionKind::Network
        ));
        assert!(native_mode_implicitly_grants(
            NativeMode::Trusted,
            NativePermissionKind::ShellExpansion
        ));
        assert!(native_mode_implicitly_grants(
            NativeMode::Trusted,
            NativePermissionKind::InlineScript
        ));
        for kind in [
            NativePermissionKind::DestructiveCommand,
            NativePermissionKind::LongTimeout,
            NativePermissionKind::SensitiveEnv,
            NativePermissionKind::PrivilegedExecutable,
            NativePermissionKind::WriteGeneratedOrIgnored,
        ] {
            assert!(!native_mode_implicitly_grants(NativeMode::Trusted, kind));
        }
    }

    fn exec(arguments: Value) -> Result<ExecInvocation, ReCtmError> {
        let object = arguments
            .as_object()
            .ok_or_else(|| invalid_argument("test exec arguments must be an object"))?;
        ExecInvocation::parse(object)
    }

    fn facts_for(
        invocation: &ExecInvocation,
        privileged_token: Option<&str>,
    ) -> Result<ExecPermissionFacts, ReCtmError> {
        let facts = invocation
            .executable_candidates()?
            .into_iter()
            .map(|candidate| {
                let mode =
                    u32::from(privileged_token.is_some_and(|token| token == candidate)) * 0o6000;
                ResolvedExecutableFact::new(
                    candidate.clone(),
                    std::path::PathBuf::from(format!("/sandbox/{candidate}")),
                    1,
                    2,
                    mode,
                    3,
                    Some("fingerprint".to_owned()),
                )
            })
            .collect::<Vec<_>>();
        ExecPermissionFacts::new(invocation, facts)
    }

    #[test]
    fn typed_exec_invocation_defaults_and_forms_are_distinct() -> Result<(), ReCtmError> {
        let command = exec(serde_json::json!({
            "cmd":"printf secret",
            "workdir":"./src",
            "env":{"TOKEN":"do-not-print"},
        }))?;
        assert_eq!(command.form(), ExecInvocationForm::Cmd);
        assert_eq!(command.argv(), &["/bin/sh", "-lc", "printf secret"]);
        assert_eq!(command.workdir(), "src");
        assert_eq!(command.timeout_ms(), DEFAULT_EXEC_TIMEOUT_MS);
        assert_eq!(command.yield_time_ms(), DEFAULT_EXEC_YIELD_TIME_MS);
        assert_eq!(command.max_output_bytes(), DEFAULT_EXEC_MAX_OUTPUT_BYTES);
        assert_eq!(command.preview_bytes(), DEFAULT_EXEC_PREVIEW_BYTES);
        assert!(!command.stdin_present());
        let direct = exec(serde_json::json!({"argv":["printf", "$(literal)"]}))?;
        assert_eq!(direct.form(), ExecInvocationForm::Argv);
        assert_eq!(direct.argv(), &["printf", "$(literal)"]);
        assert_ne!(command.arguments_sha256(), direct.arguments_sha256());
        Ok(())
    }

    #[test]
    fn typed_invocation_digest_covers_complete_original_arguments() -> Result<(), ReCtmError> {
        let baseline = serde_json::json!({
            "cmd":"printf value",
            "workdir":".",
            "env":{"PLAIN":"value"},
            "max_output_bytes":65_536,
            "preview_bytes":4_096,
            "stdin":"input",
            "timeout_ms":30_000,
            "tty":false,
            "verbosity":"summary",
            "yield_time_ms":10_000,
        })
        .as_object()
        .cloned()
        .unwrap_or_default();
        let baseline_digest = ExecInvocation::parse(&baseline)?
            .arguments_sha256()
            .to_owned();
        for (key, value) in [
            ("cmd", serde_json::json!("printf changed")),
            ("workdir", serde_json::json!("src")),
            ("env", serde_json::json!({"PLAIN":"changed"})),
            ("max_output_bytes", serde_json::json!(65_537)),
            ("preview_bytes", serde_json::json!(4_097)),
            ("stdin", serde_json::json!("changed")),
            ("timeout_ms", serde_json::json!(30_001)),
            ("tty", serde_json::json!(true)),
            ("verbosity", serde_json::json!("preview")),
            ("yield_time_ms", serde_json::json!(10_001)),
        ] {
            let mut mutated = baseline.clone();
            mutated.insert(key.to_owned(), value);
            assert_ne!(
                ExecInvocation::parse(&mutated)?.arguments_sha256(),
                baseline_digest,
                "{key} must participate in the canonical binding"
            );
        }

        let patch = "*** Begin Patch\n*** Add File: out.txt\n+secret\n*** End Patch\n";
        let real = PatchInvocation::parse(
            serde_json::json!({"patch":patch,"dry_run":false})
                .as_object()
                .ok_or_else(|| invalid_argument("test patch arguments must be an object"))?,
        )?;
        let dry = PatchInvocation::parse(
            serde_json::json!({"patch":patch,"dry_run":true})
                .as_object()
                .ok_or_else(|| invalid_argument("test patch arguments must be an object"))?,
        )?;
        assert_ne!(real.arguments_sha256(), dry.arguments_sha256());
        Ok(())
    }

    #[test]
    fn typed_exec_invocation_rejects_bounds_and_conflicts() {
        for (key, value) in [
            ("timeout_ms", Value::from(0)),
            ("timeout_ms", Value::from(600_001)),
            ("yield_time_ms", Value::from(30_001)),
            ("max_output_bytes", Value::from(0)),
            ("max_output_bytes", Value::from(1_048_577)),
            ("preview_bytes", Value::from(0)),
            ("preview_bytes", Value::from(1_048_577)),
        ] {
            let mut input = serde_json::json!({"cmd":"true"})
                .as_object()
                .cloned()
                .unwrap_or_default();
            input.insert(key.to_owned(), value);
            assert!(ExecInvocation::parse(&input).is_err());
        }
        let both = serde_json::json!({"cmd":"true","argv":["true"]});
        let both = both.as_object().cloned().unwrap_or_default();
        assert!(ExecInvocation::parse(&both).is_err());
        let conflicting_workdir = serde_json::json!({"cmd":"true","workdir":"a","cwd":"b"});
        let conflicting_workdir = conflicting_workdir.as_object().cloned().unwrap_or_default();
        assert!(ExecInvocation::parse(&conflicting_workdir).is_err());
    }

    #[test]
    fn intrinsic_classifier_reports_all_seven_in_frozen_order() -> Result<(), ReCtmError> {
        let invocation = exec(serde_json::json!({
            "cmd":"FOO=1 python3 -c 'print($(x))' && curl https://example.com && rm -rf build && /tmp/setuid-fixture",
            "env":{"API_TOKEN":"secret"},
            "timeout_ms":30_001,
        }))?;
        let facts = facts_for(&invocation, Some("/tmp/setuid-fixture"))?;
        assert_eq!(
            classify_exec_permissions(&invocation, &facts)?,
            exec_permission_order().to_vec()
        );
        Ok(())
    }

    #[test]
    fn intrinsic_classifier_handles_timeout_boundaries() -> Result<(), ReCtmError> {
        for (timeout, expected) in [(1, false), (30_000, false), (30_001, true), (600_000, true)] {
            let invocation = exec(serde_json::json!({"cmd":"true","timeout_ms":timeout}))?;
            let facts = facts_for(&invocation, None)?;
            let needs = classify_exec_permissions(&invocation, &facts)?;
            assert_eq!(needs.contains(&NativePermissionKind::LongTimeout), expected);
        }
        let yield_only = exec(serde_json::json!({"cmd":"true","yield_time_ms":30_000}))?;
        let yield_facts = facts_for(&yield_only, None)?;
        assert!(
            !classify_exec_permissions(&yield_only, &yield_facts)?
                .contains(&NativePermissionKind::LongTimeout)
        );
        Ok(())
    }

    #[test]
    fn argv_literal_metacharacters_do_not_become_shell_expansion() -> Result<(), ReCtmError> {
        let invocation = exec(serde_json::json!({"argv":["printf", "$(not-a-command)"]}))?;
        let facts = facts_for(&invocation, None)?;
        let needs = classify_exec_permissions(&invocation, &facts)?;
        assert!(!needs.contains(&NativePermissionKind::ShellExpansion));
        Ok(())
    }

    #[test]
    fn executable_candidates_cover_wrappers_and_control_segments() -> Result<(), ReCtmError> {
        let invocation = exec(serde_json::json!({
            "cmd":"env FOO=1 /opt/one | command /opt/two && /opt/three",
        }))?;
        assert_eq!(
            invocation.executable_candidates()?,
            vec!["/opt/one", "/opt/two", "/opt/three"]
        );
        Ok(())
    }

    #[test]
    fn executable_candidates_do_not_execute_quoted_or_heredoc_payloads() -> Result<(), ReCtmError> {
        let quoted = exec(serde_json::json!({"cmd":"printf '%s' 'literal | /opt/not-command'"}))?;
        assert_eq!(quoted.executable_candidates()?, vec!["printf"]);
        let heredoc = exec(serde_json::json!({
            "cmd":"cat <<'EOF'\n/opt/not-command --payload\nEOF",
        }))?;
        assert_eq!(heredoc.executable_candidates()?, vec!["cat"]);
        Ok(())
    }

    #[test]
    fn setgid_metadata_requires_privileged_executable() -> Result<(), ReCtmError> {
        let invocation = exec(serde_json::json!({"argv":["fixture"]}))?;
        let fact = ResolvedExecutableFact::new(
            "fixture",
            PathBuf::from("/sandbox/fixture"),
            1,
            2,
            0o2755,
            3,
            None,
        );
        let facts = ExecPermissionFacts::new(&invocation, vec![fact])?;
        assert_eq!(
            classify_exec_permissions(&invocation, &facts)?,
            vec![NativePermissionKind::PrivilegedExecutable]
        );
        Ok(())
    }

    #[test]
    fn unresolved_or_mismatched_executable_facts_fail_closed() -> Result<(), ReCtmError> {
        let invocation = exec(serde_json::json!({"cmd":"/opt/missing"}))?;
        let facts = ExecPermissionFacts::with_unresolved(
            &invocation,
            Vec::new(),
            vec!["/opt/missing".to_owned()],
        )?;
        assert_eq!(
            classify_exec_permissions(&invocation, &facts).map_err(|error| error.code),
            Err("NATIVE_EXECUTABLE_UNRESOLVED".to_owned())
        );
        let other = exec(serde_json::json!({"cmd":"true","timeout_ms":30_001}))?;
        let mismatched = facts_for(&other, None)?;
        assert_eq!(
            classify_exec_permissions(&invocation, &mismatched).map_err(|error| error.code),
            Err("NATIVE_PERMISSION_FACTS_ARGUMENT_MISMATCH".to_owned())
        );
        Ok(())
    }

    #[test]
    fn patch_classifier_only_requires_write_permission_for_real_generated_or_ignored_paths()
    -> Result<(), ReCtmError> {
        assert!(!has_canonical_generated_component("builder/file.txt"));
        #[cfg(unix)]
        assert!(!has_canonical_generated_component("build\\file.txt"));
        assert!(has_canonical_generated_component("build/file.txt"));
        assert!(has_canonical_generated_component("nested/.git/config"));
        let patch = "*** Begin Patch\n*** Add File: build/out.txt\n+generated\n*** End Patch\n";
        let dry = PatchInvocation::parse(
            serde_json::json!({"patch":patch,"dry_run":true})
                .as_object()
                .ok_or_else(|| invalid_argument("test patch arguments must be an object"))?,
        )?;
        let dry_facts = vec![PatchPathFact::new("build/out.txt", false)?];
        assert!(classify_patch_permissions(&dry, &dry_facts)?.is_empty());
        let real = PatchInvocation::parse(
            serde_json::json!({"patch":patch})
                .as_object()
                .ok_or_else(|| invalid_argument("test patch arguments must be an object"))?,
        )?;
        assert_eq!(
            classify_patch_permissions(&real, &dry_facts)?,
            vec![NativePermissionKind::WriteGeneratedOrIgnored]
        );

        let ordinary_patch =
            "*** Begin Patch\n*** Add File: src/out.txt\n+ordinary\n*** End Patch\n";
        let ordinary = PatchInvocation::parse(
            serde_json::json!({"patch":ordinary_patch})
                .as_object()
                .ok_or_else(|| invalid_argument("test patch arguments must be an object"))?,
        )?;
        assert!(
            classify_patch_permissions(&ordinary, &[PatchPathFact::new("src/out.txt", false)?])?
                .is_empty()
        );
        assert_eq!(
            classify_patch_permissions(&ordinary, &[PatchPathFact::new("src/out.txt", true)?])?,
            vec![NativePermissionKind::WriteGeneratedOrIgnored]
        );
        Ok(())
    }

    #[test]
    fn patch_classifier_requires_complete_source_and_destination_facts() -> Result<(), ReCtmError> {
        let patch = concat!(
            "*** Begin Patch\n",
            "*** Update File: src/a.txt\n",
            "*** Move to: target/b.txt\n",
            "@@\n",
            "-old\n",
            "+new\n",
            "*** End Patch\n"
        );
        let invocation = PatchInvocation::parse(
            serde_json::json!({"patch":patch})
                .as_object()
                .ok_or_else(|| invalid_argument("test patch arguments must be an object"))?,
        )?;
        let incomplete = vec![PatchPathFact::new("src/a.txt", false)?];
        assert_eq!(
            classify_patch_permissions(&invocation, &incomplete).map_err(|error| error.code),
            Err("NATIVE_PATCH_AUTHORITY_FACTS_INCOMPLETE".to_owned())
        );
        let complete = vec![
            PatchPathFact::new("src/a.txt", false)?,
            PatchPathFact::new("target/b.txt", false)?,
        ];
        assert_eq!(
            classify_patch_permissions(&invocation, &complete)?,
            vec![NativePermissionKind::WriteGeneratedOrIgnored]
        );
        Ok(())
    }

    #[test]
    fn typed_patch_invocation_rejects_escape_before_fact_collection() {
        for path in ["../outside.txt", "/absolute.txt"] {
            let patch = format!("*** Begin Patch\n*** Add File: {path}\n+text\n*** End Patch\n");
            let arguments = serde_json::json!({"patch":patch})
                .as_object()
                .cloned()
                .unwrap_or_default();
            assert!(PatchInvocation::parse(&arguments).is_err());
        }
    }

    #[test]
    fn effective_policy_is_deterministic_and_never_widens() -> Result<(), ReCtmError> {
        let invocation = NativeInvocation::Exec(exec(serde_json::json!({"cmd":"true"}))?);
        let required = exec_permission_order();
        let explicit = BTreeSet::from([
            NativePermissionKind::Network,
            NativePermissionKind::WriteGeneratedOrIgnored,
        ]);
        let safe =
            EffectiveNativePolicy::evaluate(NativeMode::Safe, &invocation, &required, &explicit)?;
        assert_eq!(safe.required(), &required);
        assert_eq!(
            safe.explicitly_granted(),
            &BTreeSet::from([NativePermissionKind::Network])
        );
        assert_eq!(
            safe.missing(),
            &[
                NativePermissionKind::SensitiveEnv,
                NativePermissionKind::DestructiveCommand,
                NativePermissionKind::ShellExpansion,
                NativePermissionKind::InlineScript,
                NativePermissionKind::LongTimeout,
                NativePermissionKind::PrivilegedExecutable,
            ]
        );
        assert!(!safe.is_authorized());
        let trusted = EffectiveNativePolicy::derive(
            NativeMode::Trusted,
            &invocation,
            &required,
            &BTreeSet::new(),
        )?;
        assert_eq!(
            trusted.implicitly_granted(),
            &BTreeSet::from([
                NativePermissionKind::Network,
                NativePermissionKind::ShellExpansion,
                NativePermissionKind::InlineScript,
            ])
        );
        let dangerous = EffectiveNativePolicy::evaluate(
            NativeMode::Dangerous,
            &invocation,
            &required,
            &BTreeSet::new(),
        )?;
        assert!(dangerous.authorized());
        Ok(())
    }

    #[test]
    fn typed_debug_redacts_command_environment_and_patch_bodies() -> Result<(), ReCtmError> {
        let command = "printf VERY_SECRET_COMMAND";
        let invocation = exec(serde_json::json!({
            "cmd":command,
            "env":{"TOKEN":"VERY_SECRET_ENV"},
        }))?;
        let debug = format!("{invocation:?}");
        assert!(!debug.contains(command));
        assert!(!debug.contains("VERY_SECRET_ENV"));
        let patch_body =
            "*** Begin Patch\n*** Add File: out.txt\n+VERY_SECRET_PATCH\n*** End Patch\n";
        let patch = PatchInvocation::parse(
            serde_json::json!({"patch":patch_body})
                .as_object()
                .ok_or_else(|| invalid_argument("test patch arguments must be an object"))?,
        )?;
        let patch_debug = format!("{patch:?}");
        assert!(!patch_debug.contains("VERY_SECRET_PATCH"));
        Ok(())
    }
}
