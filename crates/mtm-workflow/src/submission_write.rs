//! Caller writes use the same normalizers as ordinary workflow writes.
use super::*;
use mtm_storage::{SubmissionExecution, SubmissionReceipt};

pub(super) struct FileResource {
    pub(super) relative: String,
    pub(super) bytes: Vec<u8>,
    pub(super) append: bool,
    pub(super) result: Value,
}

impl WorkflowEngine {
    pub(super) fn prepare_file_resource(
        &self,
        claims: &CapabilityClaims,
        resource: &str,
        content: &Value,
    ) -> Result<Option<FileResource>, ReCtmError> {
        for (prefix, channels, directory, kind) in [
            (
                "memory:generation:",
                GENERATION_CHANNELS.as_slice(),
                "memory/generation",
                "generation_memory",
            ),
            (
                "memory:verifier:",
                VERIFIER_CHANNELS.as_slice(),
                "memory/verifier",
                "verifier_memory",
            ),
            (
                "memory:branch:",
                BRANCH_CHANNELS.as_slice(),
                "",
                "branch_memory",
            ),
        ] {
            if let Some(channel) = resource.strip_prefix(prefix) {
                if !channels.contains(&channel) || !content.is_object() {
                    return Err(invalid(
                        "memory writes require a known channel and JSON object",
                    ));
                }
                let normalized = if prefix == "memory:generation:" {
                    self.normalize_protocol3_generation_write(claims, channel, content)?
                } else {
                    content.clone()
                };
                let file = format!("{channel}.jsonl");
                let mut result =
                    serde_json::json!({"path_kind":kind,"channel":channel,"file":file});
                let directory = if prefix == "memory:branch:" {
                    let branch = self.branch_id_for_domain(claims.domain_id())?;
                    result["branch_id"] = Value::from(branch.clone());
                    format!("branches/{branch}/memory")
                } else {
                    directory.into()
                };
                return Ok(Some(FileResource {
                    relative: format!("{directory}/{file}"),
                    bytes: PrivateVault::file_effect_bytes(&normalized, true)?,
                    append: true,
                    result,
                }));
            }
        }
        let (relative, bytes, result) = match resource {
            "proof" => {
                let proof = content
                    .as_str()
                    .ok_or_else(|| invalid("proof must be a LaTeX string"))?;
                (
                    "draft/proof.tex",
                    proof.as_bytes().to_vec(),
                    serde_json::json!({"path_kind":"draft_tex","file":"proof.tex","size":proof.len()}),
                )
            }
            "join_result" => {
                if !content.is_object() {
                    return Err(invalid("join_result must be a JSON object"));
                }
                (
                    "join/result.json",
                    PrivateVault::file_effect_bytes(content, false)?,
                    serde_json::json!({"path_kind":"join_result","file":"result.json"}),
                )
            }
            "verification_report" => {
                let normalized =
                    VerificationDecision::from_submitted_report(content)?.normalized_payload();
                (
                    "verification/verification.json",
                    PrivateVault::file_effect_bytes(&normalized, false)?,
                    serde_json::json!({"path_kind":"verification_report","file":"verification.json"}),
                )
            }
            _ => return Ok(None),
        };
        Ok(Some(FileResource {
            relative: relative.into(),
            bytes,
            append: false,
            result,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn write_submission(
        &self,
        owner: &str,
        capability: &str,
        resource: &str,
        content: &Value,
        trace: &str,
        execution: &SubmissionExecution,
        index: usize,
    ) -> Result<Value, ReCtmError> {
        let claims = self
            .capabilities
            .validate(capability, owner, "write", resource, trace, None)?;
        if !execution.matches_claims(&claims) {
            return Err(ReCtmError::new(
                "SUBMISSION_AUTHORITY_CHANGED",
                "Write capability and reserved execution do not identify the same task.",
            )
            .with_category(ErrorCategory::Permission));
        }
        let result = if let Some(file) = self.prepare_file_resource(&claims, resource, content)? {
            let guard = self
                .vault
                .lock_file_effect(claims.run_id(), &file.relative)?;
            let (evidence, bytes) = guard.prepare(&file.bytes, file.append)?;
            self.store
                .begin_submission_write(execution, index, Some(&evidence))?;
            guard.publish(&evidence, &bytes)?;
            self.store
                .checkpoint_submission_write(execution, index + 1)?;
            file.result
        } else {
            self.store.begin_submission_write(execution, index, None)?;
            let result = self.write_resource(&claims, resource, content)?;
            self.store
                .checkpoint_submission_write(execution, index + 1)?;
            result
        };
        // The file guard is dropped before an observer is invoked.
        self.emit(WorkflowEvent {
            event_type: "workflow.resource_written".into(),
            trace_id: trace.into(),
            run_id: Some(claims.run_id().into()),
            actor_role: Some(role_name(claims.role()).into()),
            domain_id: Some(claims.domain_id().into()),
            before_state: None,
            after_state: None,
            decision: "allow".into(),
            reason: "resource_acl_passed".into(),
            details: serde_json::json!({"resource":resource,"result":result}),
        });
        Ok(
            serde_json::json!({"ok":true,"run_id":claims.run_id(),"resource":resource,"result":result,"trace_id":trace}),
        )
    }

    pub fn recover_submission(
        &self,
        receipt: SubmissionReceipt,
    ) -> Result<SubmissionReceipt, ReCtmError> {
        if receipt.result().is_some() {
            return Ok(receipt);
        }
        let run = receipt.run_id().to_owned();
        let recovery = self.store.submission_recovery(receipt)?;
        if let Some(evidence) = recovery.file_evidence() {
            let guard = self.vault.lock_file_effect(&run, &evidence.relative_path)?;
            let observed = guard.observe()?;
            // Keep the lock through the metadata CAS, never through a task/action.
            self.store.reconcile_caller_writes(recovery, Some(observed))
        } else {
            self.store.reconcile_caller_writes(recovery, None)
        }
    }
}
