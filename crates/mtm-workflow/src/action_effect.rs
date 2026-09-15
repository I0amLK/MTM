//! Restartable workflow-action file effects. Stores only hashes/evidence, never bodies.
use super::*;
use mtm_storage::FileEffectEvidence;
use serde::{Deserialize, Serialize};

const MAX_ACTION_SLOTS_PER_RUN: usize = 1024;
const MAX_SLOT_TEXT: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionEffectSlot {
    schema_version: u8,
    relative_path: String,
    content_sha256: String,
    append: bool,
    evidence: FileEffectEvidence,
}

impl PrivateVault {
    pub(crate) fn ensure_action_generation_record(
        &self,
        run_id: &str,
        slot: &str,
        channel: &str,
        record: &Value,
    ) -> Result<PathBuf, ReCtmError> {
        validate_channel(channel, &GENERATION_CHANNELS, "generation")?;
        let relative = format!("memory/generation/{channel}.jsonl");
        let bytes = Self::file_effect_bytes(record, true)?;
        self.ensure_action_effect(run_id, slot, &relative, &bytes, true)?;
        Ok(self.run_root(run_id)?.join(relative))
    }

    pub(crate) fn ensure_action_generation_records(
        &self,
        run_id: &str,
        slot: &str,
        channel: &str,
        records: &[Value],
    ) -> Result<PathBuf, ReCtmError> {
        validate_channel(channel, &GENERATION_CHANNELS, "generation")?;
        if records.is_empty() || records.len() > 128 {
            return Err(action_conflict());
        }
        let relative = format!("memory/generation/{channel}.jsonl");
        let mut content = Vec::new();
        for record in records {
            content.extend(Self::file_effect_bytes(record, true)?);
            if content.len() > 64 * 1024 * 1024 {
                return Err(action_conflict());
            }
        }
        self.ensure_action_effect(run_id, slot, &relative, &content, true)?;
        Ok(self.run_root(run_id)?.join(relative))
    }

    pub(crate) fn ensure_action_verifier_record(
        &self,
        run_id: &str,
        slot: &str,
        channel: &str,
        record: &Value,
    ) -> Result<PathBuf, ReCtmError> {
        validate_channel(channel, &VERIFIER_CHANNELS, "verifier")?;
        let relative = format!("memory/verifier/{channel}.jsonl");
        let bytes = Self::file_effect_bytes(record, true)?;
        self.ensure_action_effect(run_id, slot, &relative, &bytes, true)?;
        Ok(self.run_root(run_id)?.join(relative))
    }

    pub(crate) fn ensure_action_json(
        &self,
        run_id: &str,
        slot: &str,
        relative: &str,
        payload: &Value,
    ) -> Result<PathBuf, ReCtmError> {
        let bytes = pretty_json(payload)?.into_bytes();
        self.ensure_action_effect(run_id, slot, relative, &bytes, false)?;
        Ok(self.run_root(run_id)?.join(relative))
    }

    pub(crate) fn ensure_action_read_only_json(
        &self,
        run_id: &str,
        slot: &str,
        relative: &str,
        payload: &Value,
    ) -> Result<PathBuf, ReCtmError> {
        let path = self.ensure_action_json(run_id, slot, relative, payload)?;
        set_read_only(&path)?;
        Ok(path)
    }

    fn ensure_action_effect(
        &self,
        run_id: &str,
        slot: &str,
        relative: &str,
        content: &[u8],
        append: bool,
    ) -> Result<(), ReCtmError> {
        if slot.is_empty()
            || slot.len() > MAX_SLOT_TEXT
            || slot.as_bytes().contains(&0)
            || relative.len() > MAX_SLOT_TEXT
        {
            return Err(action_conflict());
        }
        let guard = self.lock_file_effect(run_id, relative)?;
        let content_sha256 = format!("{:x}", Sha256::digest(content));
        let slot_path = self.action_slot_path(run_id, slot)?;
        if slot_path.exists() {
            let persisted = self.read_action_slot(&slot_path)?;
            if persisted.schema_version != 1
                || persisted.relative_path != relative
                || persisted.content_sha256 != content_sha256
                || persisted.append != append
            {
                return Err(action_conflict());
            }
            let actual = guard.observe()?;
            if actual.as_ref() == Some(&persisted.evidence.after) {
                return Ok(());
            }
            if actual != persisted.evidence.before {
                return Err(action_conflict());
            }
            let (evidence, bytes) = guard.prepare(content, append)?;
            if evidence != persisted.evidence {
                return Err(action_conflict());
            }
            return guard.publish(&evidence, &bytes);
        }

        let (evidence, bytes) = guard.prepare(content, append)?;
        self.create_action_slot(
            &slot_path,
            &ActionEffectSlot {
                schema_version: 1,
                relative_path: relative.to_owned(),
                content_sha256,
                append,
                evidence: evidence.clone(),
            },
        )?;
        guard.publish(&evidence, &bytes)
    }

    fn action_slot_path(&self, run_id: &str, slot: &str) -> Result<PathBuf, ReCtmError> {
        require_safe_id(run_id, "run_id")?;
        let root = self
            .private_root
            .join("action-recovery")
            .join(sha256_text(run_id));
        create_private_dir(&root)?;
        Ok(root.join(format!("{}.json", sha256_text(slot))))
    }

    fn create_action_slot(&self, path: &Path, slot: &ActionEffectSlot) -> Result<(), ReCtmError> {
        let parent = path.parent().ok_or_else(action_conflict)?;
        let count = fs::read_dir(parent)
            .map_err(io_error)?
            .take(MAX_ACTION_SLOTS_PER_RUN + 1)
            .count();
        if count >= MAX_ACTION_SLOTS_PER_RUN {
            return Err(ReCtmError::new(
                "ACTION_EFFECT_CAPACITY",
                "Restartable action-effect capacity reached for this run.",
            )
            .with_category(ErrorCategory::Conflict));
        }
        self.atomic_json(path, &serde_json::to_value(slot).map_err(json_error)?)
    }

    fn read_action_slot(&self, path: &Path) -> Result<ActionEffectSlot, ReCtmError> {
        let meta = fs::symlink_metadata(path).map_err(io_error)?;
        if !meta.is_file() || meta.len() > 4096 {
            return Err(action_conflict());
        }
        serde_json::from_str(&fs::read_to_string(path).map_err(io_error)?)
            .map_err(|_| action_conflict())
    }
}

fn action_conflict() -> ReCtmError {
    ReCtmError::new(
        "ACTION_EFFECT_CONFLICT",
        "Restartable action files differ from the recorded effect; no action was replayed.",
    )
    .with_category(ErrorCategory::Conflict)
    .with_retryable(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_action_effect_reuses_bytes_and_sidecar_retains_no_body() -> Result<(), ReCtmError> {
        let root = tempfile::tempdir().map_err(io_error)?;
        let vault = PrivateVault::new(root.path())?;
        vault.initialize_run("run-a", "problem", &[], &serde_json::json!({}))?;
        let record = serde_json::json!({"summary":"private-fixture-body"});
        let path = vault.ensure_action_generation_record(
            "run-a",
            "run-a:1:propose_plans:plans_proposed:plan-1",
            "subgoals",
            &record,
        )?;
        let first = fs::read(&path).map_err(io_error)?;
        vault.ensure_action_generation_record(
            "run-a",
            "run-a:1:propose_plans:plans_proposed:plan-1",
            "subgoals",
            &record,
        )?;
        assert_eq!(fs::read(&path).map_err(io_error)?, first);

        let sidecars = fs::read_dir(
            root.path()
                .join("action-recovery")
                .join(sha256_text("run-a")),
        )
        .map_err(io_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io_error)?;
        assert_eq!(sidecars.len(), 1);
        let sidecar = fs::read_to_string(sidecars[0].path()).map_err(io_error)?;
        assert!(!sidecar.contains("private-fixture-body"));
        assert!(sidecar.contains("content_sha256"));
        Ok(())
    }

    #[test]
    fn missing_effect_is_republished_but_changed_payload_or_bytes_fail_closed()
    -> Result<(), ReCtmError> {
        let root = tempfile::tempdir().map_err(io_error)?;
        let vault = PrivateVault::new(root.path())?;
        vault.initialize_run("run-a", "problem", &[], &serde_json::json!({}))?;
        let slot = "run-a:1:branch_join:join_complete:result";
        let payload = serde_json::json!({"outcome":"failed","summary":"fixed"});
        let path = vault.ensure_action_json("run-a", slot, "join/result.json", &payload)?;
        let expected = fs::read(&path).map_err(io_error)?;

        fs::remove_file(&path).map_err(io_error)?;
        vault.ensure_action_json("run-a", slot, "join/result.json", &payload)?;
        assert_eq!(fs::read(&path).map_err(io_error)?, expected);

        let changed = vault.ensure_action_json(
            "run-a",
            slot,
            "join/result.json",
            &serde_json::json!({"outcome":"failed","summary":"changed"}),
        );
        assert_eq!(
            changed.err().map(|error| error.code),
            Some("ACTION_EFFECT_CONFLICT".to_owned())
        );
        fs::write(&path, b"conflicting bytes").map_err(io_error)?;
        let conflict = vault.ensure_action_json("run-a", slot, "join/result.json", &payload);
        assert_eq!(
            conflict.err().map(|error| error.code),
            Some("ACTION_EFFECT_CONFLICT".to_owned())
        );
        Ok(())
    }
}
