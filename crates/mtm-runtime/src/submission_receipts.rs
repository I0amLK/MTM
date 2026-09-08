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

pub(super) fn binding(
    workspace: &Path,
    run: &str,
    action: &str,
    payload: &Value,
    writes: &[Value],
) -> Result<(String, String), ReCtmError> {
    let mut hash = Sha256::new();
    hash.update(b"mtm-step-workspace-v1\0");
    hash.update(workspace.as_os_str().as_bytes());
    let workspace = format!("{:x}", hash.finalize());
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
    ReCtmError::new("RESULT_UNKNOWN", "A submission was reserved but its final outcome is not recorded. Do not replay it or submit with another capability; inspect status for diagnosis.")
        .with_category(ErrorCategory::Conflict)
        .with_retryable(false)
        .with_details(json!({"receipt_status":"pending","writes_applied":null,
            "automatic_retry":false,"receipt_grants_authority":false,"cause_code":cause}))
}

pub(super) fn replay(receipt: &SubmissionReceipt) -> Result<Value, ReCtmError> {
    let Some(result) = receipt.result() else {
        return Err(unknown_result(None));
    };
    let applied = result.disposition == SubmissionDisposition::Applied;
    let mut submission = json!({"ok":applied,"complete":result.complete,
        "replayed":true,"retryable":false,"writes_retained":result.writes_applied>0});
    if !applied {
        submission["error"] = json!({"code":result.error_code,
            "message":"Original submission requires correction. This replay applied no writes; fetch the current task separately.",
            "category":"validation","retryable":false,"details":{}});
    }
    let mut summary = receipt.summary();
    summary["replayed"] = json!(true);
    Ok(
        json!({"ok":true,"run_id":receipt.run_id(),"state":result.state,
        "state_is_historical":true,"writes_applied":0,"submission":submission,
        "submission_receipt":summary,"task_required":true,
        "next_action":{"tool":"rethlas_step","arguments":{"run_id":receipt.run_id()}}}),
    )
}

fn result_summary(value: &Value) -> Result<SubmissionResult, ReCtmError> {
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
        let mut value = result.map_err(|error| unknown_result(Some(&error.code)))?;
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
