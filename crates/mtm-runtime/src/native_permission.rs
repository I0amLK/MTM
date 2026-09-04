use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use mtm_contracts::{
    ErrorCategory, NativePermissionKind, NativePermissionScope, NativePermissionTool, ReCtmError,
};
use mtm_core::{NativePermissionRequest, canonical_arguments_sha256};
use mtm_storage::StoreRuntime;
use serde_json::{Map, Value};

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

fn internal(message: &str) -> ReCtmError {
    ReCtmError::new("NATIVE_PERMISSION_INTERNAL_ERROR", message)
        .with_category(ErrorCategory::Internal)
}

#[cfg(test)]
mod tests {
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
}
