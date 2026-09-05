use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mtm_contracts::{
    ErrorCategory, NativePermissionKind, NativePermissionScope, NativePermissionTool, ReCtmError,
};
use mtm_core::{
    EffectiveNativePolicy, ExecInvocation, ExecPermissionFacts, NativeInvocation,
    NativePermissionRequest, ResolvedExecutableFact, canonical_arguments_sha256, redact_json,
};
use mtm_storage::StoreRuntime;
use serde_json::{Map, Value};

const SANDBOX_WORKSPACE_ROOT: &str = "/workspace";
pub const NATIVE_PERMISSION_CONSENT_CHALLENGE_TTL_SECONDS: i64 = 300;
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

/// Collect filesystem-dependent executable facts for the D3 shadow evaluator.
///
/// Resolution uses the exact sandbox PATH supplied by the existing toolchain
/// exposure plan.  It does not consult the caller's login-shell PATH and it
/// never starts a command.
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

/// Recheck all executable identity and mode facts immediately before a future
/// command start.  D3 exposes this only to shadow tests; production execution
/// remains on the accepted pre-cutover path.
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

    for entry in sandbox_path.split(':').filter(|entry| !entry.is_empty()) {
        let entry_path = Path::new(entry);
        let candidate = if entry_path == Path::new(SANDBOX_WORKSPACE_ROOT)
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
        if resolved.starts_with(workspace)
            || visible_roots
                .iter()
                .any(|root| resolved == *root || resolved.starts_with(root))
        {
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

#[derive(Clone, Eq, PartialEq)]
pub struct NativePermissionGrantId(String);

impl NativePermissionGrantId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NativePermissionGrantId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativePermissionGrantId([REDACTED])")
    }
}

/// Proof that an external consent path has already authenticated the owner and
/// verified the exact permission request.
///
/// MTM-014 D2 deliberately provides no public constructor. A later elicitation
/// delivery must add the only production constructor at the verified gateway
/// boundary rather than treating a plain `request_permissions` tool call as consent.
pub struct VerifiedNativePermissionConsent {
    owner_id: String,
    workspace: String,
    request: NativePermissionRequest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct NativePermissionConsentChallengeId(String);

impl NativePermissionConsentChallengeId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NativePermissionConsentChallengeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativePermissionConsentChallengeId([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
struct ConsentChallengeRecord {
    owner_id: String,
    workspace: String,
    request: NativePermissionRequest,
    expires_at: i64,
}

pub struct NativePermissionConsentPrompt {
    challenge_id: NativePermissionConsentChallengeId,
    message: String,
    requested_schema: Value,
    expires_at: i64,
}

impl fmt::Debug for NativePermissionConsentPrompt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativePermissionConsentPrompt")
            .field("challenge_id", &"[REDACTED]")
            .field("message", &self.message)
            .field("requested_schema", &self.requested_schema)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl NativePermissionConsentPrompt {
    #[must_use]
    pub fn request_state(&self) -> &str {
        self.challenge_id.as_str()
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub fn requested_schema(&self) -> &Value {
        &self.requested_schema
    }

    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

pub enum NativePermissionConsentOutcome {
    Accepted(VerifiedNativePermissionConsent),
    Declined,
    Cancelled,
}

impl fmt::Debug for NativePermissionConsentOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted(_) => formatter.write_str("NativePermissionConsentOutcome::Accepted"),
            Self::Declined => formatter.write_str("NativePermissionConsentOutcome::Declined"),
            Self::Cancelled => formatter.write_str("NativePermissionConsentOutcome::Cancelled"),
        }
    }
}

#[derive(Clone)]
pub struct NativePermissionConsentAuthority {
    runtime: StoreRuntime,
    challenges: Arc<Mutex<BTreeMap<String, ConsentChallengeRecord>>>,
}

impl NativePermissionConsentAuthority {
    #[must_use]
    pub fn new(runtime: StoreRuntime) -> Self {
        Self {
            runtime,
            challenges: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn begin(
        &self,
        owner_id: &str,
        workspace: &str,
        request: NativePermissionRequest,
    ) -> Result<NativePermissionConsentPrompt, ReCtmError> {
        if owner_id.is_empty() || workspace.is_empty() {
            return Err(permission_error(
                "ELICITATION_BINDING_INVALID",
                "Native permission consent requires an authenticated owner and workspace.",
            ));
        }
        let issued_at = self.runtime.clock.unix_seconds()?;
        let expires_at = issued_at
            .checked_add(NATIVE_PERMISSION_CONSENT_CHALLENGE_TTL_SECONDS)
            .ok_or_else(|| internal("Native permission consent challenge expiry overflowed"))?;
        let challenge_id = format!("npc-{}", self.runtime.ids.token_urlsafe(18)?);
        let record = ConsentChallengeRecord {
            owner_id: owner_id.to_owned(),
            workspace: workspace.to_owned(),
            request: request.clone(),
            expires_at,
        };
        let mut challenges = self.lock_challenges()?;
        if challenges.contains_key(&challenge_id) {
            return Err(internal("Native permission consent challenge id collision"));
        }
        challenges.insert(challenge_id.clone(), record);
        drop(challenges);

        Ok(NativePermissionConsentPrompt {
            challenge_id: NativePermissionConsentChallengeId(challenge_id),
            message: consent_prompt_message(workspace, &request)?,
            requested_schema: consent_requested_schema(),
            expires_at,
        })
    }

    pub fn complete(
        &self,
        request_state: &str,
        owner_id: &str,
        workspace: &str,
        request: &NativePermissionRequest,
        response: &Value,
    ) -> Result<NativePermissionConsentOutcome, ReCtmError> {
        if request_state.is_empty() {
            return Err(permission_error(
                "ELICITATION_STATE_INVALID",
                "Native permission consent state is missing.",
            ));
        }
        let now = self.runtime.clock.unix_seconds()?;
        let mut challenges = self.lock_challenges()?;
        let record = challenges.get(request_state).cloned().ok_or_else(|| {
            permission_error(
                "ELICITATION_STATE_INVALID",
                "Native permission consent state is unknown or no longer valid.",
            )
        })?;
        if record.owner_id != owner_id {
            return Err(permission_error(
                "ELICITATION_OWNER_MISMATCH",
                "Native permission consent belongs to a different OAuth owner.",
            ));
        }
        if record.workspace != workspace {
            return Err(permission_error(
                "ELICITATION_WORKSPACE_MISMATCH",
                "Native permission consent belongs to a different workspace.",
            ));
        }
        if &record.request != request {
            return Err(permission_error(
                "ELICITATION_REQUEST_MISMATCH",
                "Native permission consent is bound to a different permission request.",
            ));
        }
        if now >= record.expires_at {
            challenges.remove(request_state);
            return Err(permission_error(
                "ELICITATION_TIMEOUT",
                "Native permission consent challenge expired.",
            ));
        }

        let response = response.as_object().ok_or_else(|| {
            permission_error(
                "ELICITATION_RESPONSE_INVALID",
                "Native permission consent response must be an object.",
            )
        })?;
        let action = response
            .get("action")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                permission_error(
                    "ELICITATION_RESPONSE_INVALID",
                    "Native permission consent response is missing an action.",
                )
            })?;
        let outcome = match action {
            "accept" => {
                let content = response
                    .get("content")
                    .and_then(Value::as_object)
                    .ok_or_else(|| {
                        permission_error(
                            "ELICITATION_RESPONSE_INVALID",
                            "Accepted Native permission consent requires form content.",
                        )
                    })?;
                if content.len() != 1 || content.get("approved").and_then(Value::as_bool).is_none()
                {
                    return Err(permission_error(
                        "ELICITATION_RESPONSE_INVALID",
                        "Native permission consent content does not match the approved boolean schema.",
                    ));
                }
                if content.get("approved").and_then(Value::as_bool) == Some(true) {
                    NativePermissionConsentOutcome::Accepted(VerifiedNativePermissionConsent {
                        owner_id: record.owner_id.clone(),
                        workspace: record.workspace.clone(),
                        request: record.request.clone(),
                    })
                } else {
                    NativePermissionConsentOutcome::Declined
                }
            }
            "decline" => NativePermissionConsentOutcome::Declined,
            "cancel" => NativePermissionConsentOutcome::Cancelled,
            _ => {
                return Err(permission_error(
                    "ELICITATION_RESPONSE_INVALID",
                    "Native permission consent response action is invalid.",
                ));
            }
        };
        challenges.remove(request_state);
        Ok(outcome)
    }

    pub fn process_local_challenge_count(&self) -> Result<usize, ReCtmError> {
        Ok(self.lock_challenges()?.len())
    }

    fn lock_challenges(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, ConsentChallengeRecord>>, ReCtmError>
    {
        self.challenges
            .lock()
            .map_err(|_| internal("Native permission consent challenge lock is poisoned"))
    }
}

fn consent_prompt_message(
    workspace: &str,
    request: &NativePermissionRequest,
) -> Result<String, ReCtmError> {
    let workspace_label = Path::new(workspace)
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("workspace");
    let redacted_reason = redact_json(&Value::String(request.reason().to_owned()))?
        .as_str()
        .unwrap_or("permission requested")
        .chars()
        .take(240)
        .collect::<String>();
    let fingerprint = request
        .arguments_sha256()
        .chars()
        .take(12)
        .collect::<String>();
    Ok(format!(
        "MTM requests {} for {} in workspace {workspace_label}. Scope: {}; TTL: {}s. Reason: {redacted_reason}. Arguments fingerprint: {fingerprint}. Approve only if you expect this exact action.",
        request.kind().as_str(),
        request.tool().as_str(),
        request.scope().as_str(),
        request.ttl_seconds(),
    ))
}

fn consent_requested_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "properties":{
            "approved":{
                "type":"boolean",
                "title":"Approve Native permission",
                "description":"Approve this exact permission request.",
                "default":false
            }
        },
        "required":["approved"]
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativePermissionGrantReceipt {
    grant_id: NativePermissionGrantId,
    tool: NativePermissionTool,
    kind: NativePermissionKind,
    scope: NativePermissionScope,
    issued_at: i64,
    expires_at: i64,
}

impl NativePermissionGrantReceipt {
    #[must_use]
    pub fn grant_id(&self) -> &NativePermissionGrantId {
        &self.grant_id
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
    pub const fn scope(&self) -> NativePermissionScope {
        self.scope
    }

    #[must_use]
    pub const fn issued_at(&self) -> i64 {
        self.issued_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

/// Unforgeable result of checking one invocation against one explicit grant.
///
/// Downstream execution will consume this named type after MTM-014 authority
/// cutover. D2 does not wire it into `exec_command` or `apply_patch` yet.
#[derive(Debug, Eq, PartialEq)]
pub struct NativePermissionPermit {
    grant_id: NativePermissionGrantId,
    tool: NativePermissionTool,
    kind: NativePermissionKind,
    scope: NativePermissionScope,
}

impl NativePermissionPermit {
    #[must_use]
    pub fn grant_id(&self) -> &NativePermissionGrantId {
        &self.grant_id
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
    pub const fn scope(&self) -> NativePermissionScope {
        self.scope
    }
}

/// Invocation-level proof that every permission missing from the Native mode
/// profile was satisfied atomically by an exact process-local grant.
///
/// This type is deliberately non-`Clone`, has no public constructor, and stores
/// no grant identifiers or raw invocation arguments.
#[derive(Debug, Eq, PartialEq)]
pub struct NativeInvocationPermissionPermit {
    tool: NativePermissionTool,
    arguments_sha256: String,
    permissions: Vec<NativePermissionKind>,
    once_grant_count: usize,
    session_grant_count: usize,
}

impl NativeInvocationPermissionPermit {
    #[must_use]
    pub const fn tool(&self) -> NativePermissionTool {
        self.tool
    }

    #[must_use]
    pub fn arguments_sha256(&self) -> &str {
        &self.arguments_sha256
    }

    #[must_use]
    pub fn permissions(&self) -> &[NativePermissionKind] {
        &self.permissions
    }

    #[must_use]
    pub const fn once_grant_count(&self) -> usize {
        self.once_grant_count
    }

    #[must_use]
    pub const fn session_grant_count(&self) -> usize {
        self.session_grant_count
    }
}

/// Short compatibility name for the invocation-level permit.
pub type NativeInvocationPermit = NativeInvocationPermissionPermit;

#[derive(Clone, Debug, Eq, PartialEq)]
struct GrantRecord {
    owner_id: String,
    workspace: String,
    tool: NativePermissionTool,
    kind: NativePermissionKind,
    arguments_sha256: String,
    scope: NativePermissionScope,
    issued_at: i64,
    expires_at: i64,
    revoked: bool,
    consumed: bool,
}

#[derive(Clone)]
pub struct NativePermissionGrantAuthority {
    runtime: StoreRuntime,
    grants: Arc<Mutex<BTreeMap<String, GrantRecord>>>,
}

impl NativePermissionGrantAuthority {
    #[must_use]
    pub fn new(runtime: StoreRuntime) -> Self {
        Self {
            runtime,
            grants: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn issue_verified(
        &self,
        consent: VerifiedNativePermissionConsent,
    ) -> Result<NativePermissionGrantReceipt, ReCtmError> {
        let now = self.runtime.clock.unix_seconds()?;
        let ttl = i64::try_from(consent.request.ttl_seconds()).map_err(|_| {
            internal("validated Native permission TTL did not fit the runtime clock")
        })?;
        let expires_at = now.checked_add(ttl).ok_or_else(|| {
            internal("Native permission grant expiry overflowed the runtime clock")
        })?;
        let raw_id = format!("npg-{}", self.runtime.ids.token_urlsafe(18)?);
        let record = GrantRecord {
            owner_id: consent.owner_id,
            workspace: consent.workspace,
            tool: consent.request.tool(),
            kind: consent.request.kind(),
            arguments_sha256: consent.request.arguments_sha256().to_owned(),
            scope: consent.request.scope(),
            issued_at: now,
            expires_at,
            revoked: false,
            consumed: false,
        };
        let receipt = NativePermissionGrantReceipt {
            grant_id: NativePermissionGrantId(raw_id.clone()),
            tool: record.tool,
            kind: record.kind,
            scope: record.scope,
            issued_at: record.issued_at,
            expires_at: record.expires_at,
        };
        let mut grants = self.lock_grants()?;
        if grants.contains_key(&raw_id) {
            return Err(internal("Native permission grant id collision"));
        }
        grants.insert(raw_id, record);
        Ok(receipt)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        &self,
        grant_id: &NativePermissionGrantId,
        owner_id: &str,
        workspace: &str,
        tool: NativePermissionTool,
        kind: NativePermissionKind,
        arguments: &Map<String, Value>,
    ) -> Result<NativePermissionPermit, ReCtmError> {
        let arguments_sha256 = canonical_arguments_sha256(arguments)?;
        let now = self.runtime.clock.unix_seconds()?;
        let mut grants = self.lock_grants()?;
        let record = grants.get_mut(grant_id.as_str()).ok_or_else(|| {
            denied(
                "NATIVE_PERMISSION_GRANT_NOT_FOUND",
                "Permission grant was not found.",
            )
        })?;
        if record.owner_id != owner_id {
            return Err(denied(
                "NATIVE_PERMISSION_GRANT_OWNER_MISMATCH",
                "Permission grant belongs to a different OAuth owner.",
            ));
        }
        if record.workspace != workspace {
            return Err(denied(
                "NATIVE_PERMISSION_GRANT_WORKSPACE_MISMATCH",
                "Permission grant belongs to a different workspace.",
            ));
        }
        if record.revoked {
            return Err(denied(
                "NATIVE_PERMISSION_GRANT_REVOKED",
                "Permission grant has been revoked.",
            ));
        }
        if now >= record.expires_at {
            return Err(denied(
                "NATIVE_PERMISSION_GRANT_EXPIRED",
                "Permission grant has expired.",
            ));
        }
        if record.scope == NativePermissionScope::Once && record.consumed {
            return Err(denied(
                "NATIVE_PERMISSION_GRANT_CONSUMED",
                "One-shot permission grant has already been consumed.",
            ));
        }
        if record.tool != tool {
            return Err(denied(
                "NATIVE_PERMISSION_GRANT_TOOL_MISMATCH",
                "Permission grant is bound to a different tool.",
            ));
        }
        if record.kind != kind {
            return Err(denied(
                "NATIVE_PERMISSION_GRANT_KIND_MISMATCH",
                "Permission grant is bound to a different permission kind.",
            ));
        }
        if record.arguments_sha256 != arguments_sha256 {
            return Err(denied(
                "NATIVE_PERMISSION_GRANT_ARGUMENT_MISMATCH",
                "Permission grant is bound to different tool arguments.",
            ));
        }
        if record.scope == NativePermissionScope::Once {
            record.consumed = true;
        }
        Ok(NativePermissionPermit {
            grant_id: grant_id.clone(),
            tool: record.tool,
            kind: record.kind,
            scope: record.scope,
        })
    }

    /// Atomically locate and consume grants for every permission still missing
    /// from an effective profile evaluation.
    pub fn authorize_invocation(
        &self,
        owner_id: &str,
        workspace: &str,
        policy: &EffectiveNativePolicy,
    ) -> Result<NativeInvocationPermissionPermit, ReCtmError> {
        // `EffectiveNativePolicy` is a pure reporting value.  Its explicit set
        // is intentionally not authority-bearing, so only the profile-derived
        // implicit set may reduce the grants located in this ledger.
        let required = policy
            .required()
            .iter()
            .copied()
            .filter(|kind| !policy.implicitly_granted().contains(kind))
            .collect::<Vec<_>>();
        self.authorize_matching_digest(
            owner_id,
            workspace,
            policy.tool(),
            &required,
            policy.arguments_sha256(),
        )
    }

    /// Compatibility entry point for callers that still hold the complete raw
    /// public argument map.  The digest is computed exactly once before taking
    /// the ledger lock; grant IDs are never supplied by the caller.
    pub fn authorize_matching_grants(
        &self,
        owner_id: &str,
        workspace: &str,
        tool: NativePermissionTool,
        required: &[NativePermissionKind],
        arguments: &Map<String, Value>,
    ) -> Result<NativeInvocationPermissionPermit, ReCtmError> {
        let invocation = NativeInvocation::parse(tool, arguments)?;
        self.authorize_matching_digest(
            owner_id,
            workspace,
            tool,
            required,
            invocation.arguments_sha256(),
        )
    }

    fn authorize_matching_digest(
        &self,
        owner_id: &str,
        workspace: &str,
        tool: NativePermissionTool,
        required: &[NativePermissionKind],
        arguments_sha256: &str,
    ) -> Result<NativeInvocationPermissionPermit, ReCtmError> {
        let mut required_set = std::collections::BTreeSet::new();
        if required
            .iter()
            .any(|kind| !permission_matches_tool(tool, *kind) || !required_set.insert(*kind))
        {
            return Err(denied(
                "NATIVE_PERMISSION_GRANT_SET_AMBIGUOUS",
                "Permission requirements contain invalid or duplicate coverage.",
            ));
        }
        let ordered_required = match tool {
            NativePermissionTool::ExecCommand => mtm_core::exec_permission_order()
                .into_iter()
                .filter(|kind| required_set.contains(kind))
                .collect::<Vec<_>>(),
            NativePermissionTool::ApplyPatch => vec![NativePermissionKind::WriteGeneratedOrIgnored]
                .into_iter()
                .filter(|kind| required_set.contains(kind))
                .collect::<Vec<_>>(),
        };
        let mut grants = self.lock_grants()?;
        let now = self.runtime.clock.unix_seconds()?;
        let mut selected = Vec::new();

        for kind in &ordered_required {
            let candidates = grants
                .iter()
                .filter(|(_, record)| {
                    record.owner_id == owner_id
                        && record.workspace == workspace
                        && record.tool == tool
                        && record.kind == *kind
                        && record.arguments_sha256 == arguments_sha256
                        && !record.revoked
                        && now < record.expires_at
                        && !(record.scope == NativePermissionScope::Once && record.consumed)
                })
                .map(|(grant_id, _)| grant_id.clone())
                .collect::<Vec<_>>();
            match candidates.as_slice() {
                [grant_id] => selected.push((grant_id.clone(), *kind)),
                [] => {
                    return Err(denied(
                        "NATIVE_PERMISSION_GRANT_SET_INCOMPLETE",
                        "No complete exact grant set exists for this Native invocation.",
                    ));
                }
                _ => {
                    return Err(denied(
                        "NATIVE_PERMISSION_GRANT_SET_AMBIGUOUS",
                        "Multiple eligible grants cover one Native permission kind.",
                    ));
                }
            }
        }

        let mut once_grant_count = 0;
        let mut session_grant_count = 0;
        for (grant_id, _) in &selected {
            let record = grants.get_mut(grant_id).ok_or_else(|| {
                internal("Selected Native permission grant disappeared while holding the lock")
            })?;
            match record.scope {
                NativePermissionScope::Once => {
                    record.consumed = true;
                    once_grant_count += 1;
                }
                NativePermissionScope::Session => session_grant_count += 1,
            }
        }
        Ok(NativeInvocationPermissionPermit {
            tool,
            arguments_sha256: arguments_sha256.to_owned(),
            permissions: ordered_required,
            once_grant_count,
            session_grant_count,
        })
    }

    pub fn revoke(
        &self,
        grant_id: &NativePermissionGrantId,
        owner_id: &str,
        workspace: &str,
    ) -> Result<(), ReCtmError> {
        let mut grants = self.lock_grants()?;
        let record = grants.get_mut(grant_id.as_str()).ok_or_else(|| {
            denied(
                "NATIVE_PERMISSION_GRANT_NOT_FOUND",
                "Permission grant was not found.",
            )
        })?;
        if record.owner_id != owner_id {
            return Err(denied(
                "NATIVE_PERMISSION_GRANT_OWNER_MISMATCH",
                "Permission grant belongs to a different OAuth owner.",
            ));
        }
        if record.workspace != workspace {
            return Err(denied(
                "NATIVE_PERMISSION_GRANT_WORKSPACE_MISMATCH",
                "Permission grant belongs to a different workspace.",
            ));
        }
        record.revoked = true;
        Ok(())
    }

    pub fn process_local_grant_count(&self) -> Result<usize, ReCtmError> {
        Ok(self.lock_grants()?.len())
    }

    fn lock_grants(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, GrantRecord>>, ReCtmError> {
        self.grants
            .lock()
            .map_err(|_| internal("Native permission grant ledger lock is poisoned"))
    }
}

fn denied(code: &str, message: &str) -> ReCtmError {
    ReCtmError::new(code, message).with_category(ErrorCategory::Permission)
}

fn permission_error(code: &str, message: &str) -> ReCtmError {
    denied(code, message)
}

fn permission_matches_tool(tool: NativePermissionTool, kind: NativePermissionKind) -> bool {
    match tool {
        NativePermissionTool::ExecCommand => kind != NativePermissionKind::WriteGeneratedOrIgnored,
        NativePermissionTool::ApplyPatch => kind == NativePermissionKind::WriteGeneratedOrIgnored,
    }
}

fn security(code: &str, message: &str) -> ReCtmError {
    ReCtmError::new(code, message).with_category(ErrorCategory::Security)
}

fn internal(message: &str) -> ReCtmError {
    ReCtmError::new("NATIVE_PERMISSION_INTERNAL_ERROR", message)
        .with_category(ErrorCategory::Internal)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use mtm_storage::{Clock, IdSource};

    use super::*;

    struct ManualClock {
        now: AtomicI64,
    }

    impl ManualClock {
        fn new(now: i64) -> Self {
            Self {
                now: AtomicI64::new(now),
            }
        }

        fn set(&self, now: i64) {
            self.now.store(now, Ordering::SeqCst);
        }
    }

    impl Clock for ManualClock {
        fn now_iso(&self) -> Result<String, ReCtmError> {
            Ok(format!("test-{}", self.now.load(Ordering::SeqCst)))
        }

        fn unix_seconds(&self) -> Result<i64, ReCtmError> {
            Ok(self.now.load(Ordering::SeqCst))
        }
    }

    struct SequenceIds {
        next: AtomicUsize,
    }

    impl SequenceIds {
        fn new() -> Self {
            Self {
                next: AtomicUsize::new(1),
            }
        }
    }

    impl IdSource for SequenceIds {
        fn token_hex(&self, _bytes: usize) -> Result<String, ReCtmError> {
            Ok(format!("{:032x}", self.next.fetch_add(1, Ordering::SeqCst)))
        }

        fn token_urlsafe(&self, _bytes: usize) -> Result<String, ReCtmError> {
            Ok(format!(
                "grant-{}",
                self.next.fetch_add(1, Ordering::SeqCst)
            ))
        }
    }

    fn runtime(clock: Arc<ManualClock>) -> StoreRuntime {
        StoreRuntime {
            clock,
            ids: Arc::new(SequenceIds::new()),
        }
    }

    fn request(
        kind: NativePermissionKind,
        scope: NativePermissionScope,
        arguments: Value,
        ttl_seconds: u64,
    ) -> Result<NativePermissionRequest, ReCtmError> {
        let input = serde_json::json!({
            "tool_name":"exec_command",
            "permission":kind.as_str(),
            "reason":"verified test consent",
            "arguments":arguments,
            "scope":scope.as_str(),
            "ttl_seconds":ttl_seconds,
        });
        let object = input
            .as_object()
            .ok_or_else(|| internal("test request must be an object"))?;
        NativePermissionRequest::parse(object)
    }

    fn consent(
        owner_id: &str,
        workspace: &str,
        request: NativePermissionRequest,
    ) -> VerifiedNativePermissionConsent {
        VerifiedNativePermissionConsent {
            owner_id: owner_id.to_owned(),
            workspace: workspace.to_owned(),
            request,
        }
    }

    fn arguments(command: &str) -> Map<String, Value> {
        serde_json::json!({"cmd":command})
            .as_object()
            .cloned()
            .unwrap_or_default()
    }

    fn code(error: ReCtmError) -> String {
        error.code
    }

    fn completion_code(
        result: Result<NativePermissionConsentOutcome, ReCtmError>,
    ) -> Result<(), String> {
        result.map(|_| ()).map_err(code)
    }

    fn issue(
        authority: &NativePermissionGrantAuthority,
        owner: &str,
        workspace: &str,
        kind: NativePermissionKind,
        scope: NativePermissionScope,
        arguments: &Map<String, Value>,
        ttl_seconds: u64,
    ) -> Result<NativePermissionGrantReceipt, ReCtmError> {
        authority.issue_verified(consent(
            owner,
            workspace,
            request(kind, scope, Value::Object(arguments.clone()), ttl_seconds)?,
        ))
    }

    #[test]
    fn consent_challenge_accepts_exact_request_once_and_can_mint_grant() -> Result<(), ReCtmError> {
        let clock = Arc::new(ManualClock::new(900));
        let runtime = runtime(Arc::clone(&clock));
        let consent_authority = NativePermissionConsentAuthority::new(runtime.clone());
        let grant_authority = NativePermissionGrantAuthority::new(runtime);
        let args = arguments("curl https://example.com");
        let request = request(
            NativePermissionKind::Network,
            NativePermissionScope::Once,
            Value::Object(args.clone()),
            300,
        )?;
        let prompt = consent_authority.begin("owner-a", "/workspace/a", request.clone())?;
        assert_eq!(consent_authority.process_local_challenge_count()?, 1);
        assert_eq!(
            prompt.expires_at(),
            900 + NATIVE_PERMISSION_CONSENT_CHALLENGE_TTL_SECONDS
        );
        let state = prompt.request_state().to_owned();
        let outcome = consent_authority.complete(
            &state,
            "owner-a",
            "/workspace/a",
            &request,
            &serde_json::json!({"action":"accept","content":{"approved":true}}),
        )?;
        let NativePermissionConsentOutcome::Accepted(consent) = outcome else {
            return Err(internal("test consent was not accepted"));
        };
        assert_eq!(consent_authority.process_local_challenge_count()?, 0);
        let receipt = grant_authority.issue_verified(consent)?;
        let permit = grant_authority.authorize(
            receipt.grant_id(),
            "owner-a",
            "/workspace/a",
            NativePermissionTool::ExecCommand,
            NativePermissionKind::Network,
            &args,
        )?;
        assert_eq!(permit.kind(), NativePermissionKind::Network);
        assert_eq!(
            completion_code(consent_authority.complete(
                &state,
                "owner-a",
                "/workspace/a",
                &request,
                &serde_json::json!({"action":"accept","content":{"approved":true}}),
            )),
            Err("ELICITATION_STATE_INVALID".to_owned())
        );
        Ok(())
    }

    #[test]
    fn consent_challenge_decline_cancel_and_false_confirmation_mint_nothing()
    -> Result<(), ReCtmError> {
        let clock = Arc::new(ManualClock::new(1_000));
        let authority = NativePermissionConsentAuthority::new(runtime(clock));
        let args = Value::Object(arguments("curl https://example.com"));
        for response in [
            serde_json::json!({"action":"decline"}),
            serde_json::json!({"action":"cancel"}),
            serde_json::json!({"action":"accept","content":{"approved":false}}),
        ] {
            let request = request(
                NativePermissionKind::Network,
                NativePermissionScope::Once,
                args.clone(),
                300,
            )?;
            let prompt = authority.begin("owner-a", "/workspace/a", request.clone())?;
            let outcome = authority.complete(
                prompt.request_state(),
                "owner-a",
                "/workspace/a",
                &request,
                &response,
            )?;
            match response.get("action").and_then(Value::as_str) {
                Some("cancel") => {
                    assert!(matches!(outcome, NativePermissionConsentOutcome::Cancelled))
                }
                _ => assert!(matches!(outcome, NativePermissionConsentOutcome::Declined)),
            }
        }
        assert_eq!(authority.process_local_challenge_count()?, 0);
        Ok(())
    }

    #[test]
    fn consent_challenge_binding_mutation_and_expiry_fail_closed_without_cross_owner_dos()
    -> Result<(), ReCtmError> {
        let clock = Arc::new(ManualClock::new(2_000));
        let authority = NativePermissionConsentAuthority::new(runtime(Arc::clone(&clock)));
        let original_request = request(
            NativePermissionKind::Network,
            NativePermissionScope::Session,
            Value::Object(arguments("curl https://example.com")),
            600,
        )?;
        let prompt = authority.begin("owner-a", "/workspace/a", original_request.clone())?;
        let state = prompt.request_state().to_owned();
        let accepted = serde_json::json!({"action":"accept","content":{"approved":true}});
        assert_eq!(
            completion_code(authority.complete(
                &state,
                "owner-b",
                "/workspace/a",
                &original_request,
                &accepted,
            )),
            Err("ELICITATION_OWNER_MISMATCH".to_owned())
        );
        assert_eq!(authority.process_local_challenge_count()?, 1);
        assert_eq!(
            completion_code(authority.complete(
                &state,
                "owner-a",
                "/workspace/b",
                &original_request,
                &accepted,
            )),
            Err("ELICITATION_WORKSPACE_MISMATCH".to_owned())
        );
        let mutated = request(
            NativePermissionKind::Network,
            NativePermissionScope::Session,
            Value::Object(arguments("curl https://other.example")),
            600,
        )?;
        assert_eq!(
            completion_code(authority.complete(
                &state,
                "owner-a",
                "/workspace/a",
                &mutated,
                &accepted,
            )),
            Err("ELICITATION_REQUEST_MISMATCH".to_owned())
        );
        assert_eq!(authority.process_local_challenge_count()?, 1);
        clock.set(2_000 + NATIVE_PERMISSION_CONSENT_CHALLENGE_TTL_SECONDS);
        assert_eq!(
            completion_code(authority.complete(
                &state,
                "owner-a",
                "/workspace/a",
                &original_request,
                &accepted,
            )),
            Err("ELICITATION_TIMEOUT".to_owned())
        );
        assert_eq!(authority.process_local_challenge_count()?, 0);
        Ok(())
    }

    #[test]
    fn consent_challenge_is_process_local_and_prompt_is_redacted() -> Result<(), ReCtmError> {
        let clock = Arc::new(ManualClock::new(3_000));
        let runtime = runtime(Arc::clone(&clock));
        let first = NativePermissionConsentAuthority::new(runtime.clone());
        let input = serde_json::json!({
            "tool_name":"exec_command",
            "permission":"network",
            "reason":"download with Bearer abc.def-123",
            "arguments":{"cmd":"curl https://secret.example/private"},
            "scope":"once",
            "ttl_seconds":300
        });
        let request = NativePermissionRequest::parse(
            input
                .as_object()
                .ok_or_else(|| internal("test permission request must be an object"))?,
        )?;
        let prompt = first.begin("owner-a", "/home/user/project-alpha", request.clone())?;
        let state = prompt.request_state().to_owned();
        assert!(prompt.message().contains("project-alpha"));
        assert!(prompt.message().contains("network"));
        assert!(prompt.message().contains("exec_command"));
        assert!(prompt.message().contains(&request.arguments_sha256()[..12]));
        assert!(!prompt.message().contains("secret.example"));
        assert!(!prompt.message().contains("abc.def-123"));
        assert!(!format!("{prompt:?}").contains(&state));
        assert_eq!(
            prompt.requested_schema()["properties"]["approved"]["type"],
            "boolean"
        );

        let restarted = NativePermissionConsentAuthority::new(runtime);
        assert_eq!(
            completion_code(restarted.complete(
                &state,
                "owner-a",
                "/home/user/project-alpha",
                &request,
                &serde_json::json!({"action":"accept","content":{"approved":true}}),
            )),
            Err("ELICITATION_STATE_INVALID".to_owned())
        );
        assert_eq!(first.process_local_challenge_count()?, 1);
        Ok(())
    }

    #[test]
    fn once_grant_is_bound_and_consumed_exactly_once() -> Result<(), ReCtmError> {
        let clock = Arc::new(ManualClock::new(1_000));
        let authority = NativePermissionGrantAuthority::new(runtime(clock));
        let args = arguments("curl https://example.com");
        let request = request(
            NativePermissionKind::Network,
            NativePermissionScope::Once,
            Value::Object(args.clone()),
            300,
        )?;
        let receipt = authority.issue_verified(consent("owner-a", "/workspace/a", request))?;
        let permit = authority.authorize(
            receipt.grant_id(),
            "owner-a",
            "/workspace/a",
            NativePermissionTool::ExecCommand,
            NativePermissionKind::Network,
            &args,
        )?;
        assert_eq!(permit.kind(), NativePermissionKind::Network);
        assert_eq!(permit.scope(), NativePermissionScope::Once);
        assert_eq!(
            authority
                .authorize(
                    receipt.grant_id(),
                    "owner-a",
                    "/workspace/a",
                    NativePermissionTool::ExecCommand,
                    NativePermissionKind::Network,
                    &args,
                )
                .map_err(code),
            Err("NATIVE_PERMISSION_GRANT_CONSUMED".to_owned())
        );
        Ok(())
    }

    #[test]
    fn once_grant_has_one_concurrent_winner() -> Result<(), ReCtmError> {
        let clock = Arc::new(ManualClock::new(2_000));
        let authority = Arc::new(NativePermissionGrantAuthority::new(runtime(clock)));
        let args = arguments("curl https://example.com");
        let request = request(
            NativePermissionKind::Network,
            NativePermissionScope::Once,
            Value::Object(args.clone()),
            300,
        )?;
        let receipt = authority.issue_verified(consent("owner-a", "/workspace/a", request))?;
        let barrier = Arc::new(Barrier::new(8));
        let successes = Arc::new(AtomicUsize::new(0));
        let handles = (0..8)
            .map(|_| {
                let authority = Arc::clone(&authority);
                let barrier = Arc::clone(&barrier);
                let successes = Arc::clone(&successes);
                let args = args.clone();
                let grant_id = receipt.grant_id().clone();
                thread::spawn(move || {
                    barrier.wait();
                    if authority
                        .authorize(
                            &grant_id,
                            "owner-a",
                            "/workspace/a",
                            NativePermissionTool::ExecCommand,
                            NativePermissionKind::Network,
                            &args,
                        )
                        .is_ok()
                    {
                        successes.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            assert!(handle.join().is_ok());
        }
        assert_eq!(successes.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn session_grant_is_reusable_and_process_local() -> Result<(), ReCtmError> {
        let clock = Arc::new(ManualClock::new(3_000));
        let authority = NativePermissionGrantAuthority::new(runtime(Arc::clone(&clock)));
        let args = arguments("curl https://example.com");
        let request = request(
            NativePermissionKind::Network,
            NativePermissionScope::Session,
            Value::Object(args.clone()),
            300,
        )?;
        let receipt = authority.issue_verified(consent("owner-a", "/workspace/a", request))?;
        for _ in 0..2 {
            authority.authorize(
                receipt.grant_id(),
                "owner-a",
                "/workspace/a",
                NativePermissionTool::ExecCommand,
                NativePermissionKind::Network,
                &args,
            )?;
        }
        let restarted = NativePermissionGrantAuthority::new(runtime(clock));
        assert_eq!(
            restarted
                .authorize(
                    receipt.grant_id(),
                    "owner-a",
                    "/workspace/a",
                    NativePermissionTool::ExecCommand,
                    NativePermissionKind::Network,
                    &args,
                )
                .map_err(code),
            Err("NATIVE_PERMISSION_GRANT_NOT_FOUND".to_owned())
        );
        Ok(())
    }

    #[test]
    fn binding_mutation_fails_closed() -> Result<(), ReCtmError> {
        let clock = Arc::new(ManualClock::new(4_000));
        let authority = NativePermissionGrantAuthority::new(runtime(clock));
        let args = arguments("curl https://example.com");
        let request = request(
            NativePermissionKind::Network,
            NativePermissionScope::Session,
            Value::Object(args.clone()),
            300,
        )?;
        let receipt = authority.issue_verified(consent("owner-a", "/workspace/a", request))?;
        let cases = [
            (
                authority
                    .authorize(
                        receipt.grant_id(),
                        "owner-b",
                        "/workspace/a",
                        NativePermissionTool::ExecCommand,
                        NativePermissionKind::Network,
                        &args,
                    )
                    .map_err(code),
                "NATIVE_PERMISSION_GRANT_OWNER_MISMATCH",
            ),
            (
                authority
                    .authorize(
                        receipt.grant_id(),
                        "owner-a",
                        "/workspace/b",
                        NativePermissionTool::ExecCommand,
                        NativePermissionKind::Network,
                        &args,
                    )
                    .map_err(code),
                "NATIVE_PERMISSION_GRANT_WORKSPACE_MISMATCH",
            ),
            (
                authority
                    .authorize(
                        receipt.grant_id(),
                        "owner-a",
                        "/workspace/a",
                        NativePermissionTool::ApplyPatch,
                        NativePermissionKind::Network,
                        &args,
                    )
                    .map_err(code),
                "NATIVE_PERMISSION_GRANT_TOOL_MISMATCH",
            ),
            (
                authority
                    .authorize(
                        receipt.grant_id(),
                        "owner-a",
                        "/workspace/a",
                        NativePermissionTool::ExecCommand,
                        NativePermissionKind::DestructiveCommand,
                        &args,
                    )
                    .map_err(code),
                "NATIVE_PERMISSION_GRANT_KIND_MISMATCH",
            ),
            (
                authority
                    .authorize(
                        receipt.grant_id(),
                        "owner-a",
                        "/workspace/a",
                        NativePermissionTool::ExecCommand,
                        NativePermissionKind::Network,
                        &arguments("curl https://other.example"),
                    )
                    .map_err(code),
                "NATIVE_PERMISSION_GRANT_ARGUMENT_MISMATCH",
            ),
        ];
        for (result, expected) in cases {
            assert_eq!(result, Err(expected.to_owned()));
        }
        Ok(())
    }

    #[test]
    fn expiry_and_revocation_fail_closed() -> Result<(), ReCtmError> {
        let clock = Arc::new(ManualClock::new(5_000));
        let authority = NativePermissionGrantAuthority::new(runtime(Arc::clone(&clock)));
        let args = arguments("curl https://example.com");
        let expiring_request = request(
            NativePermissionKind::Network,
            NativePermissionScope::Session,
            Value::Object(args.clone()),
            10,
        )?;
        let expired =
            authority.issue_verified(consent("owner-a", "/workspace/a", expiring_request))?;
        clock.set(5_010);
        assert_eq!(
            authority
                .authorize(
                    expired.grant_id(),
                    "owner-a",
                    "/workspace/a",
                    NativePermissionTool::ExecCommand,
                    NativePermissionKind::Network,
                    &args,
                )
                .map_err(code),
            Err("NATIVE_PERMISSION_GRANT_EXPIRED".to_owned())
        );

        clock.set(6_000);
        let revocation_request = request(
            NativePermissionKind::Network,
            NativePermissionScope::Session,
            Value::Object(args.clone()),
            300,
        )?;
        let revoked =
            authority.issue_verified(consent("owner-a", "/workspace/a", revocation_request))?;
        authority.revoke(revoked.grant_id(), "owner-a", "/workspace/a")?;
        assert_eq!(
            authority
                .authorize(
                    revoked.grant_id(),
                    "owner-a",
                    "/workspace/a",
                    NativePermissionTool::ExecCommand,
                    NativePermissionKind::Network,
                    &args,
                )
                .map_err(code),
            Err("NATIVE_PERMISSION_GRANT_REVOKED".to_owned())
        );
        Ok(())
    }

    #[test]
    fn grant_debug_and_ledger_do_not_retain_raw_arguments() -> Result<(), ReCtmError> {
        let clock = Arc::new(ManualClock::new(7_000));
        let authority = NativePermissionGrantAuthority::new(runtime(clock));
        let secret_command = "curl https://example.com/?token=must-not-be-retained";
        let args = arguments(secret_command);
        let request = request(
            NativePermissionKind::Network,
            NativePermissionScope::Session,
            Value::Object(args),
            300,
        )?;
        let receipt = authority.issue_verified(consent("owner-a", "/workspace/a", request))?;
        let receipt_debug = format!("{receipt:?}");
        assert!(!receipt_debug.contains(receipt.grant_id().as_str()));
        assert!(!receipt_debug.contains("must-not-be-retained"));
        let grants = authority.lock_grants()?;
        let record_debug = grants
            .get(receipt.grant_id().as_str())
            .map(|record| format!("{record:?}"))
            .ok_or_else(|| internal("test grant record is missing"))?;
        assert!(!record_debug.contains(secret_command));
        Ok(())
    }

    #[test]
    fn multi_grant_authorization_consumes_all_or_none() -> Result<(), ReCtmError> {
        let clock = Arc::new(ManualClock::new(8_000));
        let authority = NativePermissionGrantAuthority::new(runtime(clock));
        let args = arguments("curl https://example.com");
        let network = issue(
            &authority,
            "owner-a",
            "/workspace/a",
            NativePermissionKind::Network,
            NativePermissionScope::Once,
            &args,
            300,
        )?;
        assert_eq!(
            authority
                .authorize_matching_grants(
                    "owner-a",
                    "/workspace/a",
                    NativePermissionTool::ExecCommand,
                    &[
                        NativePermissionKind::Network,
                        NativePermissionKind::LongTimeout,
                    ],
                    &args,
                )
                .map_err(code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );
        // The failed set lookup did not partially consume the network grant.
        authority.authorize(
            network.grant_id(),
            "owner-a",
            "/workspace/a",
            NativePermissionTool::ExecCommand,
            NativePermissionKind::Network,
            &args,
        )?;
        Ok(())
    }

    #[test]
    fn complete_multi_grant_set_is_consumed_in_one_critical_section() -> Result<(), ReCtmError> {
        let clock = Arc::new(ManualClock::new(9_000));
        let authority = NativePermissionGrantAuthority::new(runtime(clock));
        let args = arguments("curl https://example.com");
        for kind in [
            NativePermissionKind::Network,
            NativePermissionKind::LongTimeout,
        ] {
            issue(
                &authority,
                "owner-a",
                "/workspace/a",
                kind,
                NativePermissionScope::Once,
                &args,
                300,
            )?;
        }
        let permit = authority.authorize_matching_grants(
            "owner-a",
            "/workspace/a",
            NativePermissionTool::ExecCommand,
            &[
                NativePermissionKind::LongTimeout,
                NativePermissionKind::Network,
            ],
            &args,
        )?;
        assert_eq!(permit.once_grant_count(), 2);
        assert_eq!(permit.session_grant_count(), 0);
        assert_eq!(
            permit.permissions(),
            &[
                NativePermissionKind::Network,
                NativePermissionKind::LongTimeout,
            ]
        );
        assert_eq!(
            authority
                .authorize_matching_grants(
                    "owner-a",
                    "/workspace/a",
                    NativePermissionTool::ExecCommand,
                    permit.permissions(),
                    &args,
                )
                .map_err(code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );
        Ok(())
    }

    #[test]
    fn concurrent_multi_grant_set_has_exactly_one_full_winner() -> Result<(), ReCtmError> {
        let clock = Arc::new(ManualClock::new(10_000));
        let authority = Arc::new(NativePermissionGrantAuthority::new(runtime(clock)));
        let args = arguments("curl https://example.com");
        for kind in [
            NativePermissionKind::Network,
            NativePermissionKind::LongTimeout,
        ] {
            issue(
                &authority,
                "owner-a",
                "/workspace/a",
                kind,
                NativePermissionScope::Once,
                &args,
                300,
            )?;
        }
        let barrier = Arc::new(Barrier::new(8));
        let successes = Arc::new(AtomicUsize::new(0));
        let handles = (0..8)
            .map(|_| {
                let authority = Arc::clone(&authority);
                let barrier = Arc::clone(&barrier);
                let successes = Arc::clone(&successes);
                let args = args.clone();
                thread::spawn(move || {
                    barrier.wait();
                    if authority
                        .authorize_matching_grants(
                            "owner-a",
                            "/workspace/a",
                            NativePermissionTool::ExecCommand,
                            &[
                                NativePermissionKind::Network,
                                NativePermissionKind::LongTimeout,
                            ],
                            &args,
                        )
                        .is_ok()
                    {
                        successes.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            assert!(handle.join().is_ok());
        }
        assert_eq!(successes.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn mixed_session_and_once_grants_preserve_scope_semantics() -> Result<(), ReCtmError> {
        let clock = Arc::new(ManualClock::new(11_000));
        let authority = NativePermissionGrantAuthority::new(runtime(clock));
        let args = arguments("curl https://example.com");
        issue(
            &authority,
            "owner-a",
            "/workspace/a",
            NativePermissionKind::Network,
            NativePermissionScope::Session,
            &args,
            300,
        )?;
        issue(
            &authority,
            "owner-a",
            "/workspace/a",
            NativePermissionKind::LongTimeout,
            NativePermissionScope::Once,
            &args,
            300,
        )?;
        let required = [
            NativePermissionKind::Network,
            NativePermissionKind::LongTimeout,
        ];
        let permit = authority.authorize_matching_grants(
            "owner-a",
            "/workspace/a",
            NativePermissionTool::ExecCommand,
            &required,
            &args,
        )?;
        assert_eq!(permit.once_grant_count(), 1);
        assert_eq!(permit.session_grant_count(), 1);
        assert_eq!(
            authority
                .authorize_matching_grants(
                    "owner-a",
                    "/workspace/a",
                    NativePermissionTool::ExecCommand,
                    &required,
                    &args,
                )
                .map_err(code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );
        assert!(
            authority
                .authorize_matching_grants(
                    "owner-a",
                    "/workspace/a",
                    NativePermissionTool::ExecCommand,
                    &[NativePermissionKind::Network],
                    &args,
                )
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn atomic_lookup_rejects_cross_bindings_without_partial_consumption() -> Result<(), ReCtmError>
    {
        let args = arguments("curl https://example.com");
        let required = [
            NativePermissionKind::Network,
            NativePermissionKind::LongTimeout,
        ];

        for (wrong_owner, wrong_workspace) in
            [("owner-b", "/workspace/a"), ("owner-a", "/workspace/b")]
        {
            let authority =
                NativePermissionGrantAuthority::new(runtime(Arc::new(ManualClock::new(11_500))));
            let valid = issue(
                &authority,
                "owner-a",
                "/workspace/a",
                NativePermissionKind::Network,
                NativePermissionScope::Once,
                &args,
                300,
            )?;
            let cross_bound = issue(
                &authority,
                wrong_owner,
                wrong_workspace,
                NativePermissionKind::LongTimeout,
                NativePermissionScope::Once,
                &args,
                300,
            )?;
            assert_eq!(
                authority
                    .authorize_matching_grants(
                        "owner-a",
                        "/workspace/a",
                        NativePermissionTool::ExecCommand,
                        &required,
                        &args,
                    )
                    .map_err(code),
                Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
            );
            authority.authorize(
                valid.grant_id(),
                "owner-a",
                "/workspace/a",
                NativePermissionTool::ExecCommand,
                NativePermissionKind::Network,
                &args,
            )?;
            authority.authorize(
                cross_bound.grant_id(),
                wrong_owner,
                wrong_workspace,
                NativePermissionTool::ExecCommand,
                NativePermissionKind::LongTimeout,
                &args,
            )?;
        }

        let authority =
            NativePermissionGrantAuthority::new(runtime(Arc::new(ManualClock::new(11_750))));
        let valid = issue(
            &authority,
            "owner-a",
            "/workspace/a",
            NativePermissionKind::LongTimeout,
            NativePermissionScope::Once,
            &args,
            300,
        )?;
        let patch_arguments = serde_json::json!({
            "patch":"*** Begin Patch\n*** Add File: out.txt\n+text\n*** End Patch\n"
        })
        .as_object()
        .cloned()
        .unwrap_or_default();
        let cross_tool_input = serde_json::json!({
            "tool_name":"apply_patch",
            "permission":"write_generated_or_ignored",
            "reason":"verified test consent",
            "arguments":patch_arguments,
            "scope":"once",
            "ttl_seconds":300,
        });
        let cross_tool_request = NativePermissionRequest::parse(
            cross_tool_input
                .as_object()
                .ok_or_else(|| internal("test request must be an object"))?,
        )?;
        let cross_tool =
            authority.issue_verified(consent("owner-a", "/workspace/a", cross_tool_request))?;
        assert_eq!(
            authority
                .authorize_matching_grants(
                    "owner-a",
                    "/workspace/a",
                    NativePermissionTool::ExecCommand,
                    &required,
                    &args,
                )
                .map_err(code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );
        authority.authorize(
            valid.grant_id(),
            "owner-a",
            "/workspace/a",
            NativePermissionTool::ExecCommand,
            NativePermissionKind::LongTimeout,
            &args,
        )?;
        authority.authorize(
            cross_tool.grant_id(),
            "owner-a",
            "/workspace/a",
            NativePermissionTool::ApplyPatch,
            NativePermissionKind::WriteGeneratedOrIgnored,
            &patch_arguments,
        )?;
        assert_eq!(cross_tool.tool(), NativePermissionTool::ApplyPatch);

        let authority =
            NativePermissionGrantAuthority::new(runtime(Arc::new(ManualClock::new(11_900))));
        let network = issue(
            &authority,
            "owner-a",
            "/workspace/a",
            NativePermissionKind::Network,
            NativePermissionScope::Once,
            &args,
            300,
        )?;
        let mutated_args = arguments("curl https://other.example.com");
        let mutated = issue(
            &authority,
            "owner-a",
            "/workspace/a",
            NativePermissionKind::LongTimeout,
            NativePermissionScope::Once,
            &mutated_args,
            300,
        )?;
        assert_eq!(
            authority
                .authorize_matching_grants(
                    "owner-a",
                    "/workspace/a",
                    NativePermissionTool::ExecCommand,
                    &required,
                    &args,
                )
                .map_err(code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );
        authority.authorize(
            network.grant_id(),
            "owner-a",
            "/workspace/a",
            NativePermissionTool::ExecCommand,
            NativePermissionKind::Network,
            &args,
        )?;
        authority.authorize(
            mutated.grant_id(),
            "owner-a",
            "/workspace/a",
            NativePermissionTool::ExecCommand,
            NativePermissionKind::LongTimeout,
            &mutated_args,
        )?;
        Ok(())
    }

    #[test]
    fn patch_grant_rejects_one_byte_argument_mutation_without_consumption() -> Result<(), ReCtmError>
    {
        let authority =
            NativePermissionGrantAuthority::new(runtime(Arc::new(ManualClock::new(11_950))));
        let original = serde_json::json!({
            "patch":"*** Begin Patch\n*** Add File: target/out.txt\n+one\n*** End Patch\n",
            "dry_run":false,
        })
        .as_object()
        .cloned()
        .unwrap_or_default();
        let request_input = serde_json::json!({
            "tool_name":"apply_patch",
            "permission":"write_generated_or_ignored",
            "reason":"verified test consent",
            "arguments":original,
            "scope":"once",
            "ttl_seconds":300,
        });
        let permission_request = NativePermissionRequest::parse(
            request_input
                .as_object()
                .ok_or_else(|| internal("test request must be an object"))?,
        )?;
        authority.issue_verified(consent("owner-a", "/workspace/a", permission_request))?;

        let mutated = serde_json::json!({
            "patch":"*** Begin Patch\n*** Add File: target/out.txt\n+two\n*** End Patch\n",
            "dry_run":false,
        })
        .as_object()
        .cloned()
        .unwrap_or_default();
        let required = [NativePermissionKind::WriteGeneratedOrIgnored];
        assert_eq!(
            authority
                .authorize_matching_grants(
                    "owner-a",
                    "/workspace/a",
                    NativePermissionTool::ApplyPatch,
                    &required,
                    &mutated,
                )
                .map_err(code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );
        let permit = authority.authorize_matching_grants(
            "owner-a",
            "/workspace/a",
            NativePermissionTool::ApplyPatch,
            &required,
            &original,
        )?;
        assert_eq!(permit.once_grant_count(), 1);
        assert_eq!(permit.permissions(), &required);
        Ok(())
    }

    #[test]
    fn invalid_member_never_consumes_another_grant() -> Result<(), ReCtmError> {
        let clock = Arc::new(ManualClock::new(12_000));
        let authority = NativePermissionGrantAuthority::new(runtime(Arc::clone(&clock)));
        let args = arguments("curl https://example.com");
        let expired = issue(
            &authority,
            "owner-a",
            "/workspace/a",
            NativePermissionKind::Network,
            NativePermissionScope::Once,
            &args,
            1,
        )?;
        let valid = issue(
            &authority,
            "owner-a",
            "/workspace/a",
            NativePermissionKind::LongTimeout,
            NativePermissionScope::Once,
            &args,
            300,
        )?;
        clock.set(12_001);
        assert!(
            authority
                .authorize_matching_grants(
                    "owner-a",
                    "/workspace/a",
                    NativePermissionTool::ExecCommand,
                    &[
                        NativePermissionKind::Network,
                        NativePermissionKind::LongTimeout,
                    ],
                    &args,
                )
                .is_err()
        );
        authority.authorize(
            valid.grant_id(),
            "owner-a",
            "/workspace/a",
            NativePermissionTool::ExecCommand,
            NativePermissionKind::LongTimeout,
            &args,
        )?;
        assert_eq!(
            authority
                .authorize(
                    expired.grant_id(),
                    "owner-a",
                    "/workspace/a",
                    NativePermissionTool::ExecCommand,
                    NativePermissionKind::Network,
                    &args,
                )
                .map_err(code),
            Err("NATIVE_PERMISSION_GRANT_EXPIRED".to_owned())
        );
        Ok(())
    }

    #[test]
    fn revoked_member_never_consumes_another_grant() -> Result<(), ReCtmError> {
        let clock = Arc::new(ManualClock::new(12_500));
        let authority = NativePermissionGrantAuthority::new(runtime(clock));
        let args = arguments("curl https://example.com");
        let revoked = issue(
            &authority,
            "owner-a",
            "/workspace/a",
            NativePermissionKind::Network,
            NativePermissionScope::Once,
            &args,
            300,
        )?;
        let valid = issue(
            &authority,
            "owner-a",
            "/workspace/a",
            NativePermissionKind::LongTimeout,
            NativePermissionScope::Once,
            &args,
            300,
        )?;
        authority.revoke(revoked.grant_id(), "owner-a", "/workspace/a")?;
        assert!(
            authority
                .authorize_matching_grants(
                    "owner-a",
                    "/workspace/a",
                    NativePermissionTool::ExecCommand,
                    &[
                        NativePermissionKind::Network,
                        NativePermissionKind::LongTimeout,
                    ],
                    &args,
                )
                .is_err()
        );
        authority.authorize(
            valid.grant_id(),
            "owner-a",
            "/workspace/a",
            NativePermissionTool::ExecCommand,
            NativePermissionKind::LongTimeout,
            &args,
        )?;
        Ok(())
    }

    #[test]
    fn duplicate_grant_coverage_is_ambiguous_and_consumes_none() -> Result<(), ReCtmError> {
        let clock = Arc::new(ManualClock::new(13_000));
        let authority = NativePermissionGrantAuthority::new(runtime(clock));
        let args = arguments("curl https://example.com");
        let left = issue(
            &authority,
            "owner-a",
            "/workspace/a",
            NativePermissionKind::Network,
            NativePermissionScope::Once,
            &args,
            300,
        )?;
        let right = issue(
            &authority,
            "owner-a",
            "/workspace/a",
            NativePermissionKind::Network,
            NativePermissionScope::Once,
            &args,
            300,
        )?;
        assert_eq!(
            authority
                .authorize_matching_grants(
                    "owner-a",
                    "/workspace/a",
                    NativePermissionTool::ExecCommand,
                    &[NativePermissionKind::Network],
                    &args,
                )
                .map_err(code),
            Err("NATIVE_PERMISSION_GRANT_SET_AMBIGUOUS".to_owned())
        );
        for receipt in [&left, &right] {
            authority.authorize(
                receipt.grant_id(),
                "owner-a",
                "/workspace/a",
                NativePermissionTool::ExecCommand,
                NativePermissionKind::Network,
                &args,
            )?;
        }
        Ok(())
    }

    #[test]
    fn effective_policy_drives_automatic_grant_lookup() -> Result<(), ReCtmError> {
        let clock = Arc::new(ManualClock::new(14_000));
        let authority = NativePermissionGrantAuthority::new(runtime(clock));
        let args = arguments("curl https://example.com");
        issue(
            &authority,
            "owner-a",
            "/workspace/a",
            NativePermissionKind::Network,
            NativePermissionScope::Once,
            &args,
            300,
        )?;
        let invocation = mtm_core::NativeInvocation::Exec(ExecInvocation::parse(&args)?);
        let policy = EffectiveNativePolicy::evaluate(
            mtm_contracts::NativeMode::Safe,
            &invocation,
            &[NativePermissionKind::Network],
            &std::collections::BTreeSet::new(),
        )?;
        let permit = authority.authorize_invocation("owner-a", "/workspace/a", &policy)?;
        assert_eq!(permit.permissions(), &[NativePermissionKind::Network]);
        assert_eq!(permit.arguments_sha256(), policy.arguments_sha256());
        Ok(())
    }

    #[test]
    fn pure_policy_explicit_labels_cannot_bypass_grant_authority() -> Result<(), ReCtmError> {
        let clock = Arc::new(ManualClock::new(14_500));
        let authority = NativePermissionGrantAuthority::new(runtime(clock));
        let args = arguments("curl https://example.com");
        let invocation = mtm_core::NativeInvocation::Exec(ExecInvocation::parse(&args)?);
        let policy = EffectiveNativePolicy::evaluate(
            mtm_contracts::NativeMode::Safe,
            &invocation,
            &[NativePermissionKind::Network],
            &std::collections::BTreeSet::from([NativePermissionKind::Network]),
        )?;
        assert!(policy.is_authorized());
        assert_eq!(
            authority
                .authorize_invocation("owner-a", "/workspace/a", &policy)
                .map_err(code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );

        let trusted = EffectiveNativePolicy::evaluate(
            mtm_contracts::NativeMode::Trusted,
            &invocation,
            &[NativePermissionKind::Network],
            &std::collections::BTreeSet::new(),
        )?;
        let implicit = authority.authorize_invocation("owner-a", "/workspace/a", &trusted)?;
        assert!(implicit.permissions().is_empty());
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
