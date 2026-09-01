use std::collections::BTreeSet;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use mtm_contracts::{DomainStatus, ErrorCategory, ReCtmError, WorkflowRole, WorkflowState};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::store::{Clock, IdSource, StateStore};

const CAPABILITY_TOKEN_MIN_LENGTH: usize = 80;
const CAPABILITY_TOKEN_MAX_LENGTH: usize = 8192;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityClaims {
    nonce: String,
    run_id: String,
    owner_id: String,
    domain_id: String,
    role: WorkflowRole,
    epoch: i64,
    issued_state: WorkflowState,
    permissions: Vec<String>,
    issued_at: i64,
    expires_at: i64,
}

impl CapabilityClaims {
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    #[must_use]
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    #[must_use]
    pub fn domain_id(&self) -> &str {
        &self.domain_id
    }

    #[must_use]
    pub const fn role(&self) -> WorkflowRole {
        self.role
    }

    #[must_use]
    pub const fn epoch(&self) -> i64 {
        self.epoch
    }

    #[must_use]
    pub const fn issued_state(&self) -> WorkflowState {
        self.issued_state
    }

    #[must_use]
    pub fn permissions(&self) -> &[String] {
        &self.permissions
    }

    #[must_use]
    pub const fn issued_at(&self) -> i64 {
        self.issued_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    #[must_use]
    pub fn to_payload(&self) -> Value {
        serde_json::json!({
            "v": 1,
            "nonce": self.nonce,
            "run_id": self.run_id,
            "owner_id": self.owner_id,
            "domain_id": self.domain_id,
            "role": self.role,
            "epoch": self.epoch,
            "state": self.issued_state,
            "permissions": self.permissions,
            "iat": self.issued_at,
            "exp": self.expires_at,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityEvent {
    pub event_type: String,
    pub trace_id: String,
    pub run_id: Option<String>,
    pub role: Option<String>,
    pub domain_id: Option<String>,
    pub decision: String,
    pub reason: String,
    pub details: Value,
}

pub type CapabilityObserver = Arc<dyn Fn(CapabilityEvent) + Send + Sync + 'static>;

pub struct CapabilityAuthority {
    secret: Vec<u8>,
    store: Arc<StateStore>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdSource>,
    default_ttl_seconds: i64,
    observer: Option<CapabilityObserver>,
}

impl CapabilityAuthority {
    pub fn new(
        secret: &[u8],
        store: Arc<StateStore>,
        default_ttl_seconds: i64,
        observer: Option<CapabilityObserver>,
    ) -> Result<Self, ReCtmError> {
        if secret.len() < 32 {
            return Err(ReCtmError::new(
                "CAPABILITY_SECRET_REQUIRED",
                "Capability signing requires at least 32 secret bytes.",
            )
            .with_category(ErrorCategory::Security));
        }
        let runtime = store.runtime();
        Ok(Self {
            secret: secret.to_vec(),
            store,
            clock: runtime.clock,
            ids: runtime.ids,
            default_ttl_seconds,
            observer,
        })
    }

    pub fn issue(
        &self,
        run_id: &str,
        domain_id: &str,
        role: WorkflowRole,
        permissions: &[String],
        trace_id: &str,
        ttl_seconds: Option<i64>,
    ) -> Result<String, ReCtmError> {
        let run = self.store.get_run(run_id)?;
        let domain = self.store.get_domain(domain_id)?;
        if domain.get("run_id").and_then(Value::as_str) != Some(run_id)
            || domain.get("role").and_then(Value::as_str) != Some(role.as_str())
        {
            return Err(ReCtmError::new(
                "DOMAIN_ROLE_MISMATCH",
                "Domain does not belong to the requested run and role.",
            )
            .with_category(ErrorCategory::Security));
        }
        if domain.get("status").and_then(Value::as_str) != Some(DomainStatus::Open.as_str()) {
            return Err(ReCtmError::new(
                "DOMAIN_NOT_OPEN",
                "Capabilities can be issued only for open domains.",
            )
            .with_category(ErrorCategory::Conflict));
        }
        let state = parse_workflow_state(&run)?;
        let expected_role = role_for_state(state);
        if expected_role != Some(role) {
            return Err(ReCtmError::new(
                "ROLE_STATE_MISMATCH",
                "The requested role is not active in the current workflow state.",
            )
            .with_category(ErrorCategory::Permission)
            .with_details(serde_json::json!({
                "state": state.as_str(),
                "expected_role": expected_role.map(WorkflowRole::as_str),
            })));
        }
        let now = self.clock.unix_seconds()?;
        let ttl = ttl_seconds
            .filter(|value| *value != 0)
            .unwrap_or(self.default_ttl_seconds);
        let normalized_permissions = permissions
            .iter()
            .map(ToOwned::to_owned)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let claims = CapabilityClaims {
            nonce: self.ids.token_urlsafe(18)?,
            run_id: run_id.to_owned(),
            owner_id: required_text(&run, "owner_id")?.to_owned(),
            domain_id: domain_id.to_owned(),
            role,
            epoch: required_i64(&run, "epoch")?,
            issued_state: state,
            permissions: normalized_permissions,
            issued_at: now,
            expires_at: now + ttl,
        };
        let token = self.encode(&claims.to_payload())?;
        self.store.insert_capability(
            &claims.nonce,
            &claims.run_id,
            &claims.domain_id,
            claims.role.as_str(),
            claims.epoch,
            claims.issued_state.as_str(),
            &claims.permissions,
            claims.issued_at,
            claims.expires_at,
        )?;
        self.emit(CapabilityEvent {
            event_type: "capability.issued".to_owned(),
            trace_id: trace_id.to_owned(),
            run_id: Some(run_id.to_owned()),
            role: Some(role.as_str().to_owned()),
            domain_id: Some(domain_id.to_owned()),
            decision: "allow".to_owned(),
            reason: "role_state_preconditions_satisfied".to_owned(),
            details: serde_json::json!({
                "capability_fingerprint": token_fingerprint(&token),
                "permissions": claims.permissions,
                "expires_at": claims.expires_at,
            }),
        });
        Ok(token)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validate(
        &self,
        token: &str,
        owner_id: &str,
        action: &str,
        resource: &str,
        trace_id: &str,
        expected_run_id: Option<&str>,
    ) -> Result<CapabilityClaims, ReCtmError> {
        let fingerprint = token_fingerprint(token);
        let result = self.validate_inner(token, owner_id, action, resource, expected_run_id);
        match result {
            Ok(claims) => {
                self.emit(CapabilityEvent {
                    event_type: "capability.allowed".to_owned(),
                    trace_id: trace_id.to_owned(),
                    run_id: Some(claims.run_id.clone()),
                    role: Some(claims.role.as_str().to_owned()),
                    domain_id: Some(claims.domain_id.clone()),
                    decision: "allow".to_owned(),
                    reason: "signed_capability_role_acl_and_state_passed".to_owned(),
                    details: serde_json::json!({
                        "capability_fingerprint": fingerprint,
                        "action": action,
                        "resource": resource,
                    }),
                });
                Ok(claims)
            }
            Err(error) => {
                let payload = self.decode_unverified_payload(token).ok();
                self.emit(CapabilityEvent {
                    event_type: "capability.denied".to_owned(),
                    trace_id: trace_id.to_owned(),
                    run_id: payload
                        .as_ref()
                        .and_then(|value| safe_payload(value, "run_id")),
                    role: payload
                        .as_ref()
                        .and_then(|value| safe_payload(value, "role")),
                    domain_id: payload
                        .as_ref()
                        .and_then(|value| safe_payload(value, "domain_id")),
                    decision: "deny".to_owned(),
                    reason: error.code.clone(),
                    details: serde_json::json!({
                        "capability_fingerprint": fingerprint,
                        "action": action,
                        "resource": resource,
                        "error": error.to_payload(),
                    }),
                });
                Err(error)
            }
        }
    }

    fn validate_inner(
        &self,
        token: &str,
        owner_id: &str,
        action: &str,
        resource: &str,
        expected_run_id: Option<&str>,
    ) -> Result<CapabilityClaims, ReCtmError> {
        let payload = self.decode(token)?;
        let claims = claims_from_payload(&payload)?;
        if let Some(expected_run_id) = expected_run_id
            && claims.run_id != expected_run_id
        {
            return Err(denied(
                "CAPABILITY_RUN_MISMATCH",
                "Capability and run_id must come from the same server-issued task envelope.",
                serde_json::json!({
                    "expected_run_id": expected_run_id,
                    "capability_run_id": claims.run_id,
                }),
            ));
        }
        let record = self.store.get_capability(&claims.nonce)?.ok_or_else(|| {
            denied(
                "CAPABILITY_UNKNOWN",
                "Capability is not registered.",
                empty(),
            )
        })?;
        if !record_matches_claims(&record, &claims) {
            return Err(denied(
                "CAPABILITY_REGISTRY_MISMATCH",
                "Persisted capability facts do not match the signed capability claims.",
                empty(),
            ));
        }
        if record.get("revoked").and_then(Value::as_bool) == Some(true) {
            return Err(denied(
                "CAPABILITY_REVOKED",
                "Capability has been revoked.",
                serde_json::json!({"reason": record.get("revoke_reason").cloned().unwrap_or(Value::Null)}),
            ));
        }
        let now = self.clock.unix_seconds()?;
        if claims.expires_at < now
            || record
                .get("expires_at")
                .and_then(Value::as_i64)
                .unwrap_or(i64::MIN)
                < now
        {
            return Err(denied(
                "CAPABILITY_EXPIRED",
                "Capability has expired.",
                empty(),
            ));
        }
        let run = self.store.get_run(&claims.run_id)?;
        if claims.owner_id != owner_id
            || run.get("owner_id").and_then(Value::as_str) != Some(owner_id)
        {
            return Err(denied(
                "CAPABILITY_OWNER_MISMATCH",
                "Capability is not bound to the authenticated OAuth principal.",
                empty(),
            ));
        }
        if run.get("epoch").and_then(Value::as_i64) != Some(claims.epoch) {
            return Err(denied(
                "CAPABILITY_STALE",
                "Capability belongs to an earlier run epoch.",
                empty(),
            ));
        }
        let current_state = parse_workflow_state(&run)?;
        if current_state != claims.issued_state {
            return Err(denied(
                "CAPABILITY_STATE_MISMATCH",
                "Capability is not valid in the current workflow state.",
                serde_json::json!({
                    "issued_state": claims.issued_state.as_str(),
                    "current_state": current_state.as_str(),
                }),
            ));
        }
        let domain = self.store.get_domain(&claims.domain_id)?;
        if domain.get("status").and_then(Value::as_str) != Some(DomainStatus::Open.as_str()) {
            return Err(denied(
                "DOMAIN_SEALED",
                "Capability domain is no longer open.",
                empty(),
            ));
        }
        if domain.get("run_id").and_then(Value::as_str) != Some(claims.run_id.as_str())
            || domain.get("role").and_then(Value::as_str) != Some(claims.role.as_str())
        {
            return Err(denied(
                "CAPABILITY_DOMAIN_MISMATCH",
                "Capability/domain facts do not match.",
                empty(),
            ));
        }
        let required = format!("{action}:{resource}");
        if !claims
            .permissions
            .iter()
            .any(|pattern| wildcard_match(pattern, &required))
        {
            return Err(denied(
                "ROLE_ACCESS_DENIED",
                "Capability does not authorize this resource operation.",
                serde_json::json!({"action": action, "resource": resource}),
            ));
        }
        authorize_role_resource(claims.role, current_state, action, resource, &domain)?;
        Ok(claims)
    }

    pub fn revoke(&self, token: &str, reason: &str, trace_id: &str) -> Result<(), ReCtmError> {
        let payload = self.decode(token)?;
        let claims = claims_from_payload(&payload)?;
        self.store.revoke_capability(&claims.nonce, reason)?;
        self.emit(CapabilityEvent {
            event_type: "capability.revoked".to_owned(),
            trace_id: trace_id.to_owned(),
            run_id: Some(claims.run_id),
            role: Some(claims.role.as_str().to_owned()),
            domain_id: Some(claims.domain_id),
            decision: "allow".to_owned(),
            reason: reason.to_owned(),
            details: serde_json::json!({"capability_fingerprint": token_fingerprint(token)}),
        });
        Ok(())
    }

    pub fn encode(&self, payload: &Value) -> Result<String, ReCtmError> {
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).map_err(|error| {
            ReCtmError::new("CAPABILITY_SERIALIZATION_ERROR", error.to_string())
                .with_category(ErrorCategory::Internal)
        })?);
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).map_err(|error| {
            ReCtmError::new("CAPABILITY_SIGNING_ERROR", error.to_string())
                .with_category(ErrorCategory::Internal)
        })?;
        mac.update(body.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        Ok(format!("{body}.{signature}"))
    }

    pub fn decode(&self, token: &str) -> Result<Value, ReCtmError> {
        if !valid_token_shape(token) {
            return Err(capability_invalid());
        }
        let (body, signature) = token.split_once('.').ok_or_else(capability_invalid)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| capability_invalid())?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.secret).map_err(|_| capability_invalid())?;
        mac.update(body.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| capability_invalid())?;
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| capability_invalid())?;
        let payload: Value =
            serde_json::from_slice(&payload_bytes).map_err(|_| capability_invalid())?;
        if payload.get("v").and_then(Value::as_i64) != Some(1) || !payload.is_object() {
            return Err(denied(
                "CAPABILITY_INVALID",
                "Unsupported capability payload.",
                empty(),
            ));
        }
        Ok(payload)
    }

    fn decode_unverified_payload(&self, token: &str) -> Result<Value, ReCtmError> {
        let body = token
            .split_once('.')
            .map(|item| item.0)
            .ok_or_else(capability_invalid)?;
        let payload = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| capability_invalid())?;
        serde_json::from_slice(&payload).map_err(|_| capability_invalid())
    }

    fn emit(&self, event: CapabilityEvent) {
        if let Some(observer) = &self.observer {
            observer(event);
        }
    }
}

#[must_use]
pub const fn role_for_state(state: WorkflowState) -> Option<WorkflowRole> {
    match state {
        WorkflowState::Assess
        | WorkflowState::Explore
        | WorkflowState::ProposePlans
        | WorkflowState::DirectProving
        | WorkflowState::IdentifyFailures
        | WorkflowState::Replan => Some(WorkflowRole::Generator),
        WorkflowState::BranchRun => Some(WorkflowRole::Branch),
        WorkflowState::BranchJoin => Some(WorkflowRole::Join),
        WorkflowState::Assemble => Some(WorkflowRole::Assembler),
        WorkflowState::Verify => Some(WorkflowRole::Verifier),
        WorkflowState::Repair => Some(WorkflowRole::Repair),
        WorkflowState::Finalize => Some(WorkflowRole::Finalizer),
        _ => None,
    }
}

#[must_use]
pub fn default_permissions(role: WorkflowRole) -> &'static [&'static str] {
    match role {
        WorkflowRole::Generator => &[
            "read:problem",
            "read:references",
            "read:project:verified_dependencies",
            "read:steering",
            "read:memory:generation:*",
            "write:memory:generation:*",
            "search:memory:generation:*",
            "retrieve:external:theorems",
            "retrieve:external:research",
            "commit:workflow",
        ],
        WorkflowRole::Branch => &[
            "read:problem",
            "read:references",
            "read:project:verified_dependencies",
            "read:snapshot",
            "read:branch:self",
            "write:branch:self",
            "read:memory:branch:*",
            "write:memory:branch:*",
            "search:memory:branch:*",
            "retrieve:external:theorems",
            "retrieve:external:research",
            "commit:workflow",
        ],
        WorkflowRole::Join => &[
            "read:problem",
            "read:snapshot",
            "read:branch:sealed:*",
            "write:join_result",
            "write:memory:generation:*",
            "commit:workflow",
        ],
        WorkflowRole::Assembler => &[
            "read:problem",
            "read:references",
            "read:project:verified_dependencies",
            "read:memory:generation:*",
            "read:join_result",
            "write:proof",
            "write:proof_manifest",
            "commit:workflow",
        ],
        WorkflowRole::Verifier => &[
            "read:problem",
            "read:proof",
            "read:proof_manifest",
            "read:project:verified_dependencies",
            "read:references:approved",
            "read:references:candidates",
            "read:memory:verifier:*",
            "write:memory:verifier:*",
            "write:verification_report",
            "write:reference_audit",
            "retrieve:external:theorems",
            "retrieve:external:research",
            "commit:workflow",
        ],
        WorkflowRole::Repair => &[
            "read:problem",
            "read:proof",
            "read:proof_manifest",
            "read:project:verified_dependencies",
            "read:verification_report",
            "read:memory:generation:*",
            "write:memory:generation:*",
            "write:proof",
            "write:proof_manifest",
            "retrieve:external:theorems",
            "retrieve:external:research",
            "commit:workflow",
        ],
        WorkflowRole::Finalizer => &["commit:workflow"],
    }
}

pub fn authorize_role_resource(
    role: WorkflowRole,
    state: WorkflowState,
    action: &str,
    resource: &str,
    domain: &Value,
) -> Result<(), ReCtmError> {
    let expected = role_for_state(state);
    if expected != Some(role) {
        return Err(denied(
            "ROLE_STATE_MISMATCH",
            "Role is not active in the current workflow state.",
            serde_json::json!({"role": role.as_str(), "state": state.as_str()}),
        ));
    }
    if role == WorkflowRole::Verifier
        && (resource.starts_with("memory:generation:")
            || resource.starts_with("branch:")
            || matches!(resource, "steering" | "join_result" | "snapshot"))
    {
        return Err(denied(
            "VERIFIER_DATA_FIREWALL",
            "Verifier cannot access generation-private resources.",
            serde_json::json!({"resource": resource}),
        ));
    }
    if role == WorkflowRole::Branch && resource.starts_with("branch:") {
        let branch_id = domain
            .get("metadata")
            .and_then(Value::as_object)
            .and_then(|metadata| metadata.get("branch_id"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if resource != "branch:self" && resource != format!("branch:{branch_id}") {
            return Err(denied(
                "CROSS_BRANCH_ACCESS_DENIED",
                "Branch domains cannot access another branch.",
                serde_json::json!({"resource": resource, "branch_id": branch_id}),
            ));
        }
    }
    if role != WorkflowRole::Join && resource.starts_with("branch:sealed:") {
        return Err(denied(
            "JOIN_ONLY_RESOURCE",
            "Sealed branch sets are visible only in the join domain.",
            empty(),
        ));
    }
    if role == WorkflowRole::Finalizer && action != "commit" {
        return Err(denied(
            "FINALIZER_MECHANICAL_ONLY",
            "Finalizer does not expose model-controlled reads or writes.",
            empty(),
        ));
    }
    Ok(())
}

fn claims_from_payload(payload: &Value) -> Result<CapabilityClaims, ReCtmError> {
    let object = payload.as_object().ok_or_else(incomplete_capability)?;
    let required = BTreeSet::from([
        "v",
        "nonce",
        "run_id",
        "owner_id",
        "domain_id",
        "role",
        "epoch",
        "state",
        "permissions",
        "iat",
        "exp",
    ]);
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != required {
        return Err(incomplete_capability());
    }
    if object.get("v").and_then(Value::as_i64) != Some(1) {
        return Err(incomplete_capability());
    }
    let nonce = required_nonempty(object, "nonce")?;
    let run_id = required_nonempty(object, "run_id")?;
    let owner_id = required_nonempty(object, "owner_id")?;
    let domain_id = required_nonempty(object, "domain_id")?;
    let role = parse_role(required_nonempty(object, "role")?)?;
    let issued_state = parse_state(required_nonempty(object, "state")?)?;
    let epoch = exact_i64(object, "epoch")?;
    let issued_at = exact_i64(object, "iat")?;
    let expires_at = exact_i64(object, "exp")?;
    let permissions = object
        .get("permissions")
        .and_then(Value::as_array)
        .ok_or_else(incomplete_capability)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(incomplete_capability)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if permissions.is_empty() || epoch < 0 || issued_at < 0 || expires_at <= issued_at {
        return Err(incomplete_capability());
    }
    Ok(CapabilityClaims {
        nonce: nonce.to_owned(),
        run_id: run_id.to_owned(),
        owner_id: owner_id.to_owned(),
        domain_id: domain_id.to_owned(),
        role,
        epoch,
        issued_state,
        permissions,
        issued_at,
        expires_at,
    })
}

fn record_matches_claims(record: &Value, claims: &CapabilityClaims) -> bool {
    let permissions = record
        .get("permissions")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>());
    record.get("run_id").and_then(Value::as_str) == Some(claims.run_id.as_str())
        && record.get("domain_id").and_then(Value::as_str) == Some(claims.domain_id.as_str())
        && record.get("role").and_then(Value::as_str) == Some(claims.role.as_str())
        && record.get("epoch").and_then(Value::as_i64) == Some(claims.epoch)
        && record.get("issued_state").and_then(Value::as_str) == Some(claims.issued_state.as_str())
        && permissions
            == Some(
                claims
                    .permissions
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            )
        && record.get("issued_at").and_then(Value::as_i64) == Some(claims.issued_at)
        && record.get("expires_at").and_then(Value::as_i64) == Some(claims.expires_at)
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut previous = vec![false; value.len() + 1];
    previous[0] = true;
    for token in pattern {
        let mut current = vec![false; value.len() + 1];
        if *token == b'*' {
            current[0] = previous[0];
            for index in 1..=value.len() {
                current[index] = previous[index] || current[index - 1];
            }
        } else {
            for index in 1..=value.len() {
                current[index] =
                    previous[index - 1] && (*token == b'?' || *token == value[index - 1]);
            }
        }
        previous = current;
    }
    previous[value.len()]
}

fn valid_token_shape(token: &str) -> bool {
    (CAPABILITY_TOKEN_MIN_LENGTH..=CAPABILITY_TOKEN_MAX_LENGTH).contains(&token.len())
        && token.bytes().filter(|byte| *byte == b'.').count() == 1
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn parse_workflow_state(run: &Value) -> Result<WorkflowState, ReCtmError> {
    parse_state(required_text(run, "state")?)
}

fn parse_state(value: &str) -> Result<WorkflowState, ReCtmError> {
    serde_json::from_value(Value::String(value.to_owned())).map_err(|_| incomplete_capability())
}

fn parse_role(value: &str) -> Result<WorkflowRole, ReCtmError> {
    serde_json::from_value(Value::String(value.to_owned())).map_err(|_| incomplete_capability())
}

fn required_text<'a>(value: &'a Value, key: &str) -> Result<&'a str, ReCtmError> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| {
        ReCtmError::new(
            "STATE_ROW_INVALID",
            "State database row has an invalid shape.",
        )
        .with_category(ErrorCategory::Internal)
    })
}

fn required_i64(value: &Value, key: &str) -> Result<i64, ReCtmError> {
    value.get(key).and_then(Value::as_i64).ok_or_else(|| {
        ReCtmError::new(
            "STATE_ROW_INVALID",
            "State database row has an invalid shape.",
        )
        .with_category(ErrorCategory::Internal)
    })
}

fn required_nonempty<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, ReCtmError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(incomplete_capability)
}

fn exact_i64(object: &Map<String, Value>, key: &str) -> Result<i64, ReCtmError> {
    object
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(incomplete_capability)
}

fn denied(code: &str, message: &str, details: Value) -> ReCtmError {
    ReCtmError::new(code, message)
        .with_category(ErrorCategory::Permission)
        .with_details(details)
}

fn capability_invalid() -> ReCtmError {
    denied(
        "CAPABILITY_INVALID",
        "Capability is malformed or has an invalid signature.",
        empty(),
    )
}

fn incomplete_capability() -> ReCtmError {
    denied(
        "CAPABILITY_INVALID",
        "Capability payload is incomplete.",
        empty(),
    )
}

fn empty() -> Value {
    Value::Object(Map::new())
}

fn token_fingerprint(token: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(token.as_bytes());
    format!("{:x}", digest.finalize())[..12].to_owned()
}

fn safe_payload(payload: &Value, key: &str) -> Option<String> {
    payload.get(key).map(|value| match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_matrix_matches_source() {
        assert_eq!(
            default_permissions(WorkflowRole::Finalizer),
            &["commit:workflow"]
        );
        assert!(wildcard_match(
            "read:memory:generation:*",
            "read:memory:generation:events"
        ));
        assert!(!wildcard_match("read:problem", "write:problem"));
    }

    #[test]
    fn verifier_and_branch_firewalls_are_preserved() {
        let verifier = authorize_role_resource(
            WorkflowRole::Verifier,
            WorkflowState::Verify,
            "read",
            "memory:generation:events",
            &serde_json::json!({"metadata": {}}),
        );
        assert_eq!(
            verifier.map_err(|error| error.code),
            Err("VERIFIER_DATA_FIREWALL".to_owned())
        );
        let branch = authorize_role_resource(
            WorkflowRole::Branch,
            WorkflowState::BranchRun,
            "read",
            "branch:branch-b",
            &serde_json::json!({"metadata": {"branch_id": "branch-a"}}),
        );
        assert_eq!(
            branch.map_err(|error| error.code),
            Err("CROSS_BRANCH_ACCESS_DENIED".to_owned())
        );
    }
}
