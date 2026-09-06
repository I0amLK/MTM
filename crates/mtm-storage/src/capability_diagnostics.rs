//! Opt-in diagnostics. Tokens/keys never enter these events or Debug output.
//! This module classifies observations; it cannot grant or refresh authority.
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use mtm_contracts::{ErrorCategory, ReCtmError};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{CapabilityAuthority, CapabilityEvent, claims_from_payload, valid_token_shape};

pub(super) struct CapabilityDiagnostics {
    instance_id: String,
    signer_id: String,
}

impl CapabilityDiagnostics {
    pub(super) fn new(secret: &[u8]) -> Result<Self, ReCtmError> {
        let mut instance = [0_u8; 16];
        getrandom::fill(&mut instance).map_err(|error| {
            ReCtmError::new("RANDOM_SOURCE_ERROR", error.to_string())
                .with_category(ErrorCategory::Internal)
        })?;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| {
            ReCtmError::new(
                "CAPABILITY_SIGNING_ERROR",
                "Cannot initialize signer diagnostics.",
            )
            .with_category(ErrorCategory::Internal)
        })?;
        // Domain-separated PRF output, not key bytes or a capability signature.
        mac.update(b"MTM/capability-diagnostics/signer-id/v1");
        Ok(Self {
            instance_id: hex(&instance),
            signer_id: hex(&mac.finalize().into_bytes()),
        })
    }

    pub(super) fn event(
        &self,
        authority: &CapabilityAuthority,
        token: &str,
        phase: &str,
        trace_id: &str,
        run_id: Option<&str>,
        error_code: Option<&str>,
    ) -> CapabilityEvent {
        let stage = if error_code == Some("CAPABILITY_INVALID") {
            invalid_stage(authority, token)
        } else {
            error_code.unwrap_or("accepted")
        };
        CapabilityEvent {
            event_type: "capability.diagnostic".to_owned(),
            trace_id: trace_id.to_owned(),
            // Request context is NOT read from an unverified token body.
            run_id: run_id.map(str::to_owned),
            role: None,
            domain_id: None,
            decision: "observe".to_owned(),
            reason: phase.to_owned(),
            details: serde_json::json!({
                "token_sha256": format!("{:x}", Sha256::digest(token.as_bytes())),
                "token_bytes": token.len(),
                "signer_id": self.signer_id,
                "instance_id": self.instance_id,
                "validation_stage": stage,
                "context_trust": if phase == "issued" { "server_issued" } else { "request_supplied" },
            }),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// Runs only for INVALID with diagnostics enabled. Preserve the production decode
// order; never normalize, repair, or authorize these bytes. Public error codes
// and payloads remain unchanged. A stage alone is not a root-cause verdict.
fn invalid_stage(authority: &CapabilityAuthority, token: &str) -> &'static str {
    if !valid_token_shape(token) {
        return "token_shape";
    }
    let Some((body, signature)) = token.split_once('.') else {
        return "token_shape";
    };
    let Ok(signature) = URL_SAFE_NO_PAD.decode(signature) else {
        return "signature_encoding";
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&authority.secret) else {
        return "signer_initialization";
    };
    mac.update(body.as_bytes());
    if mac.verify_slice(&signature).is_err() {
        return "signature_mismatch";
    }
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(body) else {
        return "payload_encoding";
    };
    let Ok(payload) = serde_json::from_slice::<Value>(&bytes) else {
        return "payload_json";
    };
    if !payload.is_object() || payload.get("v").and_then(Value::as_i64) != Some(1) {
        return "payload_version";
    }
    if claims_from_payload(&payload).is_err() {
        return "claims_invalid";
    }
    "not_reproduced_by_diagnostic_decode"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StateStore;
    use std::sync::{Arc, Mutex};

    #[test]
    fn signer_identity_tracks_key_not_process() -> Result<(), ReCtmError> {
        let a = CapabilityDiagnostics::new(&[17; 32])?;
        let b = CapabilityDiagnostics::new(&[17; 32])?;
        let c = CapabilityDiagnostics::new(&[29; 32])?;
        assert!(a.signer_id == b.signer_id);
        assert!(a.instance_id != b.instance_id);
        assert!(a.signer_id != c.signer_id);
        Ok(())
    }

    #[test]
    fn diagnostics_are_opt_in_redacted_and_do_not_change_rejection() -> Result<(), ReCtmError> {
        let root =
            tempfile::tempdir().map_err(|error| ReCtmError::new("TEST_IO", error.to_string()))?;
        let store = Arc::new(StateStore::open(root.path().join("state.sqlite3"))?);
        let events = Arc::new(Mutex::new(Vec::<CapabilityEvent>::new()));
        let recorded = Arc::clone(&events);
        let observer: super::super::CapabilityObserver = Arc::new(move |event| {
            if let Ok(mut events) = recorded.lock() {
                events.push(event);
            }
        });
        let authority = CapabilityAuthority::new(&[17; 32], store, 600, Some(observer))?;
        let token = "intentionally-invalid-test-token";
        let code = authority
            .validate(token, "owner", "commit", "workflow", "t1", Some("run"))
            .err()
            .map(|error| error.code);
        assert_eq!(code.as_deref(), Some("CAPABILITY_INVALID"));
        assert_eq!(
            events
                .lock()
                .map_err(|_| ReCtmError::new("TEST_LOCK", "poisoned"))?
                .len(),
            1
        );
        let authority = authority.with_diagnostics(true)?;
        let code = authority
            .validate(token, "owner", "commit", "workflow", "t2", Some("run"))
            .err()
            .map(|error| error.code);
        assert_eq!(code.as_deref(), Some("CAPABILITY_INVALID"));
        let events = events
            .lock()
            .map_err(|_| ReCtmError::new("TEST_LOCK", "poisoned"))?;
        let diagnostics = events
            .iter()
            .filter(|event| event.event_type == "capability.diagnostic")
            .collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].details["validation_stage"], "token_shape");
        let serialized = serde_json::to_string(diagnostics[0])
            .map_err(|error| ReCtmError::new("TEST_JSON", error.to_string()))?;
        assert!(!serialized.contains(token));
        assert!(!serialized.contains(&"11".repeat(32)));
        Ok(())
    }

    #[test]
    fn diagnostic_stages_separate_shape_signature_and_payload() -> Result<(), ReCtmError> {
        let root =
            tempfile::tempdir().map_err(|error| ReCtmError::new("TEST_IO", error.to_string()))?;
        let store = Arc::new(StateStore::open(root.path().join("state.sqlite3"))?);
        let authority = CapabilityAuthority::new(&[17; 32], store, 600, None)?;
        let token = authority.encode(&serde_json::json!({
            "v":1,"nonce":"n","run_id":"r","owner_id":"o","domain_id":"d",
            "role":"generator","epoch":0,"state":"assess", "permissions":["commit:workflow"],
            "iat":1,"exp":1000
        }))?;
        assert!(authority.decode(&token).is_ok());
        let (body, signature) = token
            .split_once('.')
            .ok_or_else(|| ReCtmError::new("TEST_TOKEN", "shape"))?;
        let first = if signature.starts_with('A') { "B" } else { "A" };
        let changed = format!("{body}.{first}{}", &signature[1..]);
        assert_eq!(invalid_stage(&authority, &changed), "signature_mismatch");
        assert_eq!(
            invalid_stage(&authority, &format!("{token} ")),
            "token_shape"
        );
        let unsupported =
            authority.encode(&serde_json::json!({"v":2,"padding":"x".repeat(100)}))?;
        assert_eq!(invalid_stage(&authority, &unsupported), "payload_version");
        Ok(())
    }

    #[test]
    fn identical_bytes_verify_under_same_key_and_fail_under_different_key() -> Result<(), ReCtmError>
    {
        let root =
            tempfile::tempdir().map_err(|error| ReCtmError::new("TEST_IO", error.to_string()))?;
        let store = Arc::new(StateStore::open(root.path().join("state.sqlite3"))?);
        let first = CapabilityAuthority::new(&[17; 32], Arc::clone(&store), 600, None)?;
        let same = CapabilityAuthority::new(&[17; 32], Arc::clone(&store), 600, None)?;
        let other = CapabilityAuthority::new(&[29; 32], store, 600, None)?;
        let token = first.encode(&serde_json::json!({"v":1,"padding":"x".repeat(100)}))?;
        for _ in 0..200 {
            assert!(same.decode(&token).is_ok());
        }
        assert_eq!(invalid_stage(&other, &token), "signature_mismatch");
        assert_eq!(
            other
                .decode(&token)
                .err()
                .map(|error| error.code)
                .as_deref(),
            Some("CAPABILITY_INVALID")
        );
        Ok(())
    }
}
