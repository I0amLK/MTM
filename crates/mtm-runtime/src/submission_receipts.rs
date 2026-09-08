//! Receipt summaries carry no task context or authority, including on replay.
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::*;
use mtm_core::canonical_arguments_sha256;
use mtm_storage::{
    SubmissionDisposition, SubmissionReceipt, SubmissionReservation, SubmissionResult,
};
use serde_json::json;
use sha2::{Digest, Sha256};

fn workspace_digest(workspace: &Path) -> String {
    let mut hash = Sha256::new();
    hash.update(b"mtm-step-workspace-v1\0");
    hash.update(workspace.as_os_str().as_bytes());
    format!("{:x}", hash.finalize())
}

pub(super) fn creation_binding(
    workspace: &Path,
    key: &Value,
    request: &mtm_workflow::StartRequest<'_>,
) -> Result<mtm_storage::CreationIdentity, ReCtmError> {
    let key = key
        .as_str()
        .filter(|key| {
            (16..=128).contains(&key.len())
                && key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        })
        .ok_or_else(|| {
            validation(
                "creation_key must contain 16 to 128 ASCII letters, digits, underscores or hyphens",
            )
        })?;
    let normalized = json!({"version":"mtm-start-request-v1",
        "problem_id":request.problem_id.unwrap_or("problem"),"problem_tex":request.problem_tex,
        "references":request.references,"export_path":request.workspace_export_path,
        "project_id":request.project_id,"target_claim_id":request.target_claim_id,
        "workflow_mode":request.workflow_mode,"register_result":request.register_result,
        "workflow_protocol":request.workflow_protocol_version,"native_mode":request.native_mode});
    let digest = canonical_arguments_sha256(
        normalized
            .as_object()
            .ok_or_else(|| internal("creation request"))?,
    )?;
    mtm_storage::CreationIdentity::new(
        format!("{:x}", Sha256::digest(key.as_bytes())),
        workspace_digest(workspace),
        digest,
    )
}

pub(super) fn binding(
    workspace: &Path,
    run: &str,
    action: &str,
    payload: &Value,
    writes: &[Value],
) -> Result<(String, String), ReCtmError> {
    let workspace = workspace_digest(workspace);
    let request = json!({"version":"mtm-step-request-v1","run_id":run,
        "action":action,"payload":payload,"writes":writes});
    let request = canonical_arguments_sha256(
        request
            .as_object()
            .ok_or_else(|| internal("submission request must be an object"))?,
    )?;
    Ok((workspace, request))
}

fn unknown_result(code: Option<&str>) -> ReCtmError {
    let cause = code.filter(|value| {
        value.len() <= 80
            && value
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    });
    ReCtmError::new("RESULT_UNKNOWN", "A submission was reserved but its final outcome is not recorded. Do not execute it again or replace its capability. Inspect status or use recover_only=true with the exact original submission for evidenced reconciliation.")
        .with_category(ErrorCategory::Conflict)
        .with_retryable(false)
        .with_details(json!({"receipt_status":"pending","writes_applied":null,
            "automatic_retry":false,"receipt_grants_authority":false,"cause_code":cause}))
}

pub(super) fn replay(receipt: &SubmissionReceipt) -> Result<Value, ReCtmError> {
    receipt_response(receipt, true)
}

fn receipt_response(receipt: &SubmissionReceipt, replayed: bool) -> Result<Value, ReCtmError> {
    let Some(result) = receipt.result() else {
        return Err(unknown_result(None));
    };
    let applied = result.disposition == SubmissionDisposition::Applied;
    let mut submission = json!({"ok":applied,"complete":result.complete,
        "replayed":replayed,"retryable":false,"writes_retained":result.writes_applied>0});
    if !applied {
        submission["retained_write_prefix_len"] = json!(result.writes_applied);
        submission["error"] = json!({"code":result.error_code,
            "message":"The recorded submission requires correction. Do not reapply retained writes; fetch the current task separately.",
            "category":"validation","retryable":false,"details":{}});
    }
    let mut summary = receipt.summary();
    summary["replayed"] = json!(replayed);
    Ok(
        json!({"ok":true,"run_id":receipt.run_id(),"state":result.state,
        "state_is_historical":true,"writes_applied":if replayed {0} else {result.writes_applied},"submission":submission,
        "submission_receipt":summary,"task_required":true,
        "next_action":{"tool":"rethlas_step","arguments":{"run_id":receipt.run_id()}}}),
    )
}

pub(super) fn result_summary(value: &Value) -> Result<SubmissionResult, ReCtmError> {
    let submission = value
        .get("submission")
        .ok_or_else(|| unknown_result(Some("SUBMISSION_RESULT_MISSING")))?;
    let applied = submission["ok"]
        .as_bool()
        .ok_or_else(|| unknown_result(Some("SUBMISSION_RESULT_INVALID")))?;
    let state = serde_json::from_value(value["state"].clone())
        .map_err(|_| unknown_result(Some("SUBMISSION_RESULT_INVALID")))?;
    let writes_applied = value["writes_applied"]
        .as_u64()
        .ok_or_else(|| unknown_result(Some("SUBMISSION_RESULT_INVALID")))?;
    let complete = match submission.get("complete") {
        None => applied,
        Some(Value::Bool(value)) => *value && applied,
        Some(_) => return Err(unknown_result(Some("SUBMISSION_RESULT_INVALID"))),
    };
    Ok(SubmissionResult {
        disposition: if applied {
            SubmissionDisposition::Applied
        } else {
            SubmissionDisposition::CorrectionRequired
        },
        state,
        writes_applied,
        complete,
        error_code: if applied {
            None
        } else {
            submission["error"]["code"].as_str().map(str::to_owned)
        },
    })
}

impl RuntimeToolBackend {
    pub(super) fn finish_receipted_submission(
        &self,
        reservation: SubmissionReservation,
        result: Result<Value, ReCtmError>,
    ) -> Result<Value, ReCtmError> {
        let mut value = match result {
            Ok(value) => value,
            Err(error) => {
                let receipt = self.store.observed_submission(&reservation)?;
                if receipt.result().is_some() {
                    return receipt_response(&receipt, false);
                }
                return Err(unknown_result(Some(&error.code)));
            }
        };
        let summary = result_summary(&value)?;
        let receipt = self
            .store
            .complete_submission(reservation, &summary)
            .map_err(|error| unknown_result(Some(&error.code)))?;
        let mut summary = receipt.summary();
        summary["replayed"] = json!(false);
        value
            .as_object_mut()
            .ok_or_else(|| unknown_result(Some("SUBMISSION_RESULT_INVALID")))?
            .insert("submission_receipt".into(), summary);
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_identity_is_order_stable_but_writes_are_ordered() -> Result<(), ReCtmError> {
        let a = serde_json::from_str(r#"{"b":2,"a":1}"#).map_err(|_| internal("fixture"))?;
        let b = json!({"a":1,"b":2});
        let writes = [json!(1), json!(2)];
        let first = binding(Path::new("/workspace/a"), "r", "assess", &a, &writes)?;
        assert_eq!(
            first,
            binding(Path::new("/workspace/a"), "r", "assess", &b, &writes)?
        );
        let reversed = [json!(2), json!(1)];
        let swapped = binding(Path::new("/workspace/a"), "r", "assess", &b, &reversed)?;
        assert_ne!(first.1, swapped.1);
        let other = binding(Path::new("/workspace/b"), "r", "assess", &b, &writes)?;
        assert_ne!(first.0, other.0);
        let other = binding(Path::new("/workspace/a"), "other", "assess", &b, &writes)?;
        assert_ne!(first.1, other.1);
        Ok(())
    }

    #[test]
    fn unknown_result_never_claims_zero_writes_or_leaks_payload() {
        let error = unknown_result(Some("private text must not appear"));
        assert_eq!(error.code, "RESULT_UNKNOWN");
        assert!(!error.retryable);
        assert!(error.details["writes_applied"].is_null());
        assert!(!error.to_payload().to_string().contains("private text"));
    }

    #[test]
    fn malformed_completion_and_replay_text_cannot_masquerade_as_a_current_task()
    -> Result<(), ReCtmError> {
        let mut value = json!({"state":"assemble","writes_applied":2,
            "submission":{"ok":true,"complete":"true"}});
        assert!(result_summary(&value).is_err());
        value["submission_receipt"] = json!({"replayed":true});
        value["run_id"] = json!("fixture");
        let object = value
            .as_object()
            .ok_or_else(|| internal("fixture object"))?;
        let text = render_summary("rethlas_step", object);
        assert!(text.contains("historical") && text.contains("zero writes"));
        assert!(!text.contains("fresh capability"));
        Ok(())
    }
}
