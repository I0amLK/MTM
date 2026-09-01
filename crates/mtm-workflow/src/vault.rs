use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use mtm_contracts::{ErrorCategory, ReCtmError};
use regex::Regex;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const GENERATION_CHANNELS: [&str; 10] = [
    "immediate_conclusions",
    "toy_examples",
    "counterexamples",
    "big_decisions",
    "subgoals",
    "proof_steps",
    "failed_paths",
    "verification_reports",
    "branch_states",
    "events",
];

pub const VERIFIER_CHANNELS: [&str; 5] = [
    "statement_checks",
    "reference_checks",
    "verification_reports",
    "failed_checks",
    "events",
];

pub const BRANCH_CHANNELS: [&str; 4] = ["branch_notes", "proof_steps", "failed_paths", "events"];

pub struct PrivateVault {
    private_root: PathBuf,
    runs_root: PathBuf,
    temp_counter: AtomicU64,
}

impl PrivateVault {
    pub fn new(private_root: impl AsRef<Path>) -> Result<Self, ReCtmError> {
        let private_root = absolute_normalized(private_root.as_ref())?;
        let runs_root = private_root.join("runs");
        create_private_dir(&runs_root)?;
        Ok(Self {
            private_root,
            runs_root,
            temp_counter: AtomicU64::new(0),
        })
    }

    #[must_use]
    pub fn private_root(&self) -> &Path {
        &self.private_root
    }

    pub fn initialize_run(
        &self,
        run_id: &str,
        problem_tex: &str,
        references: &[Value],
        metadata: &Value,
    ) -> Result<Value, ReCtmError> {
        let root = self.run_root(run_id)?;
        for relative in [
            "input",
            "references",
            "memory/generation",
            "memory/verifier",
            "branches",
            "snapshots",
            "join",
            "draft",
            "verification",
            "final",
            "debug/state",
        ] {
            create_private_dir(&root.join(relative))?;
        }
        self.atomic_text(&root.join("input/problem.tex"), problem_tex)?;
        let mut manifest = Vec::with_capacity(references.len());
        for (index, reference) in references.iter().enumerate() {
            let object = reference
                .as_object()
                .ok_or_else(|| validation("references must contain only JSON objects"))?;
            let default_name = format!("reference-{}.txt", index + 1);
            let name = safe_reference_name(
                object
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or(&default_name),
            )?;
            let content = object
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or_default();
            self.atomic_text(&root.join("references").join(&name), content)?;
            manifest.push(serde_json::json!({
                "name": name,
                "sha256": sha256_text(content),
                "size": content.len(),
                "source": object.get("source").and_then(Value::as_str).unwrap_or("inline"),
            }));
        }
        self.atomic_json(
            &root.join("references/manifest.json"),
            &Value::Array(manifest.clone()),
        )?;
        self.atomic_json(&root.join("run-metadata.json"), metadata)?;
        Ok(serde_json::json!({
            "run_root": root,
            "problem_sha256": sha256_text(problem_tex),
            "reference_count": manifest.len(),
        }))
    }

    pub fn run_root(&self, run_id: &str) -> Result<PathBuf, ReCtmError> {
        let safe = require_safe_id(run_id, "run_id")?;
        let root = self.runs_root.join(safe);
        if !lexically_within(&root, &self.runs_root) {
            return Err(ReCtmError::new(
                "VAULT_ESCAPE",
                "Run id resolves outside the private vault.",
            )
            .with_category(ErrorCategory::Security));
        }
        Ok(root)
    }

    pub fn read_problem(&self, run_id: &str) -> Result<String, ReCtmError> {
        self.read_text(&self.run_root(run_id)?.join("input/problem.tex"))
    }

    pub fn read_references_manifest(&self, run_id: &str) -> Result<Vec<Value>, ReCtmError> {
        let value = self.read_json(&self.run_root(run_id)?.join("references/manifest.json"))?;
        Ok(value.as_array().cloned().unwrap_or_default())
    }

    pub fn read_reference(&self, run_id: &str, name: &str) -> Result<String, ReCtmError> {
        let name = safe_reference_name(name)?;
        self.read_text(&self.run_root(run_id)?.join("references").join(name))
    }

    pub fn append_generation_memory(
        &self,
        run_id: &str,
        channel: &str,
        record: &Value,
    ) -> Result<PathBuf, ReCtmError> {
        validate_channel(channel, &GENERATION_CHANNELS, "generation")?;
        let target = self
            .run_root(run_id)?
            .join("memory/generation")
            .join(format!("{channel}.jsonl"));
        self.append_jsonl(&target, record)?;
        Ok(target)
    }

    pub fn read_generation_memory(
        &self,
        run_id: &str,
        channel: &str,
    ) -> Result<Vec<Value>, ReCtmError> {
        validate_channel(channel, &GENERATION_CHANNELS, "generation")?;
        read_jsonl(
            &self
                .run_root(run_id)?
                .join("memory/generation")
                .join(format!("{channel}.jsonl")),
        )
    }

    pub fn append_verifier_memory(
        &self,
        run_id: &str,
        channel: &str,
        record: &Value,
    ) -> Result<PathBuf, ReCtmError> {
        validate_channel(channel, &VERIFIER_CHANNELS, "verifier")?;
        let target = self
            .run_root(run_id)?
            .join("memory/verifier")
            .join(format!("{channel}.jsonl"));
        self.append_jsonl(&target, record)?;
        Ok(target)
    }

    pub fn read_verifier_memory(
        &self,
        run_id: &str,
        channel: &str,
    ) -> Result<Vec<Value>, ReCtmError> {
        validate_channel(channel, &VERIFIER_CHANNELS, "verifier")?;
        read_jsonl(
            &self
                .run_root(run_id)?
                .join("memory/verifier")
                .join(format!("{channel}.jsonl")),
        )
    }

    pub fn append_branch_memory(
        &self,
        run_id: &str,
        branch_id: &str,
        channel: &str,
        record: &Value,
    ) -> Result<PathBuf, ReCtmError> {
        validate_channel(channel, &BRANCH_CHANNELS, "branch")?;
        let branch = require_safe_id(branch_id, "branch_id")?;
        let target = self
            .run_root(run_id)?
            .join("branches")
            .join(branch)
            .join("memory")
            .join(format!("{channel}.jsonl"));
        self.append_jsonl(&target, record)?;
        Ok(target)
    }

    pub fn read_branch_memory(
        &self,
        run_id: &str,
        branch_id: &str,
        channel: &str,
    ) -> Result<Vec<Value>, ReCtmError> {
        validate_channel(channel, &BRANCH_CHANNELS, "branch")?;
        let branch = require_safe_id(branch_id, "branch_id")?;
        read_jsonl(
            &self
                .run_root(run_id)?
                .join("branches")
                .join(branch)
                .join("memory")
                .join(format!("{channel}.jsonl")),
        )
    }

    pub fn create_snapshot(
        &self,
        run_id: &str,
        snapshot_id: &str,
        payload: &Value,
    ) -> Result<Value, ReCtmError> {
        let snapshot = require_safe_id(snapshot_id, "snapshot_id")?;
        let target = self
            .run_root(run_id)?
            .join("snapshots")
            .join(format!("{snapshot}.json"));
        if target.exists() {
            return Err(ReCtmError::new(
                "SNAPSHOT_EXISTS",
                format!("Snapshot already exists: {snapshot_id}"),
            )
            .with_category(ErrorCategory::Conflict));
        }
        let serialized = pretty_json(payload)?;
        self.atomic_text(&target, &serialized)?;
        set_read_only(&target)?;
        Ok(serde_json::json!({
            "snapshot_id": snapshot_id,
            "sha256": sha256_text(&serialized),
            "path": target,
        }))
    }

    pub fn read_snapshot(&self, run_id: &str, snapshot_id: &str) -> Result<Value, ReCtmError> {
        let snapshot = require_safe_id(snapshot_id, "snapshot_id")?;
        let value = self.read_json(
            &self
                .run_root(run_id)?
                .join("snapshots")
                .join(format!("{snapshot}.json")),
        )?;
        if !value.is_object() {
            return Err(validation_code(
                "INVALID_SNAPSHOT",
                "Snapshot must contain an object.",
            ));
        }
        Ok(value)
    }

    pub fn initialize_branch(
        &self,
        run_id: &str,
        branch_id: &str,
        payload: &Value,
    ) -> Result<PathBuf, ReCtmError> {
        let branch = require_safe_id(branch_id, "branch_id")?;
        let root = self.run_root(run_id)?.join("branches").join(branch);
        create_private_dir(&root.join("memory"))?;
        self.atomic_json(&root.join("assignment.json"), payload)?;
        Ok(root)
    }

    pub fn read_branch_assignment(
        &self,
        run_id: &str,
        branch_id: &str,
    ) -> Result<Value, ReCtmError> {
        let branch = require_safe_id(branch_id, "branch_id")?;
        self.read_json(
            &self
                .run_root(run_id)?
                .join("branches")
                .join(branch)
                .join("assignment.json"),
        )
    }

    pub fn write_branch_result(
        &self,
        run_id: &str,
        branch_id: &str,
        payload: &Value,
    ) -> Result<PathBuf, ReCtmError> {
        let branch = require_safe_id(branch_id, "branch_id")?;
        let target = self
            .run_root(run_id)?
            .join("branches")
            .join(branch)
            .join("result.json");
        if target.exists() {
            return Err(ReCtmError::new(
                "BRANCH_ALREADY_COMMITTED",
                format!("Branch result already exists: {branch_id}"),
            )
            .with_category(ErrorCategory::Conflict));
        }
        self.atomic_json(&target, payload)?;
        set_read_only(&target)?;
        Ok(target)
    }

    pub fn read_branch_result(&self, run_id: &str, branch_id: &str) -> Result<Value, ReCtmError> {
        let branch = require_safe_id(branch_id, "branch_id")?;
        let value = self.read_json(
            &self
                .run_root(run_id)?
                .join("branches")
                .join(branch)
                .join("result.json"),
        )?;
        if !value.is_object() {
            return Err(validation_code(
                "INVALID_BRANCH_RESULT",
                "Branch result must be an object.",
            ));
        }
        Ok(value)
    }

    pub fn write_join_result(&self, run_id: &str, payload: &Value) -> Result<PathBuf, ReCtmError> {
        let target = self.run_root(run_id)?.join("join/result.json");
        self.atomic_json(&target, payload)?;
        Ok(target)
    }

    pub fn read_join_result(&self, run_id: &str) -> Result<Value, ReCtmError> {
        let target = self.run_root(run_id)?.join("join/result.json");
        if !target.exists() {
            return Ok(serde_json::json!({}));
        }
        self.read_json(&target)
    }

    pub fn write_proof(&self, run_id: &str, content: &str) -> Result<PathBuf, ReCtmError> {
        let target = self.run_root(run_id)?.join("draft/proof.tex");
        self.atomic_text(&target, content)?;
        Ok(target)
    }

    pub fn read_proof(&self, run_id: &str) -> Result<String, ReCtmError> {
        self.read_text(&self.run_root(run_id)?.join("draft/proof.tex"))
    }

    pub fn write_verification_report(
        &self,
        run_id: &str,
        payload: &Value,
    ) -> Result<PathBuf, ReCtmError> {
        let target = self
            .run_root(run_id)?
            .join("verification/verification.json");
        self.atomic_json(&target, payload)?;
        Ok(target)
    }

    pub fn read_verification_report(&self, run_id: &str) -> Result<Value, ReCtmError> {
        let target = self
            .run_root(run_id)?
            .join("verification/verification.json");
        if !target.exists() {
            return Ok(serde_json::json!({}));
        }
        self.read_json(&target)
    }

    pub(crate) fn finalize_proof(
        &self,
        run_id: &str,
        permit: &crate::kernel::FinalizationPermit,
    ) -> Result<PathBuf, ReCtmError> {
        if permit.run_id() != run_id {
            return Err(ReCtmError::new(
                "FINALIZATION_PERMIT_MISMATCH",
                "Finalization permit belongs to a different run.",
            )
            .with_category(ErrorCategory::Permission));
        }
        let source = self.run_root(run_id)?.join("draft/proof.tex");
        if !source.is_file() {
            return Err(
                ReCtmError::new("PROOF_NOT_FOUND", "Draft proof.tex does not exist.")
                    .with_category(ErrorCategory::NotFound),
            );
        }
        let target = self.run_root(run_id)?.join("final/proof_verified.tex");
        let proof = self.read_text(&source)?;
        if sha256_text(&proof) != permit.proof_sha256() {
            return Err(ReCtmError::new(
                "FINALIZATION_PERMIT_MISMATCH",
                "Draft proof changed after verifier approval.",
            )
            .with_category(ErrorCategory::Conflict));
        }
        self.atomic_text(&target, &proof)?;
        set_read_only(&target)?;
        Ok(target)
    }

    pub fn read_final_proof(&self, run_id: &str) -> Result<String, ReCtmError> {
        self.read_text(&self.run_root(run_id)?.join("final/proof_verified.tex"))
    }

    pub fn write_manual_validation_manifest(
        &self,
        run_id: &str,
        payload: &Value,
    ) -> Result<PathBuf, ReCtmError> {
        let target = self
            .run_root(run_id)?
            .join("debug/manual-validation-manifest.json");
        let object = payload
            .as_object()
            .ok_or_else(|| validation("manual validation manifest must be an object"))?;
        let manifest = ManualValidationManifest {
            run_id: object
                .get("run_id")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            state: object
                .get("state")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            verdict: object.get("verdict").and_then(Value::as_str),
            latex_passed: object
                .get("latex_passed")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            transition_count: object
                .get("transition_count")
                .and_then(Value::as_i64)
                .unwrap_or_default(),
            manual_checks_still_required: object
                .get("manual_checks_still_required")
                .and_then(Value::as_array)
                .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
                .unwrap_or_default(),
        };
        let mut text = serde_json::to_string_pretty(&manifest).map_err(json_error)?;
        text.push('\n');
        self.atomic_text(&target, &text)?;
        Ok(target)
    }

    pub fn search_records(&self, records: &[Value], query: &str, limit: usize) -> Vec<Value> {
        let tokens = query
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .filter(|token| !token.is_empty())
            .map(str::to_ascii_lowercase)
            .collect::<BTreeSet<_>>();
        if tokens.is_empty() {
            return Vec::new();
        }
        let mut matches = records
            .iter()
            .filter_map(|record| {
                let text = serde_json::to_string(record).ok()?.to_ascii_lowercase();
                let score = tokens
                    .iter()
                    .map(|token| text.matches(token).count())
                    .sum::<usize>();
                (score > 0).then_some((score, record.clone()))
            })
            .collect::<Vec<_>>();
        matches.sort_by_key(|left| std::cmp::Reverse(left.0));
        matches
            .into_iter()
            .take(limit)
            .map(|(score, record)| serde_json::json!({"score": score, "record": record}))
            .collect()
    }

    fn read_text(&self, path: &Path) -> Result<String, ReCtmError> {
        if !path.is_file() {
            return Err(ReCtmError::new(
                "RESOURCE_NOT_FOUND",
                format!(
                    "Private resource not found: {}",
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("resource")
                ),
            )
            .with_category(ErrorCategory::NotFound));
        }
        fs::read_to_string(path).map_err(io_error)
    }

    fn read_json(&self, path: &Path) -> Result<Value, ReCtmError> {
        serde_json::from_str(&self.read_text(path)?).map_err(json_error)
    }

    fn atomic_json(&self, path: &Path, payload: &Value) -> Result<(), ReCtmError> {
        self.atomic_text(path, &pretty_json(payload)?)
    }

    fn atomic_text(&self, path: &Path, content: &str) -> Result<(), ReCtmError> {
        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| validation("private path has no valid filename"))?;
        for _ in 0..32 {
            let sequence = self.temp_counter.fetch_add(1, Ordering::Relaxed);
            let temp = path.with_file_name(format!(".{file_name}.{sequence}.tmp"));
            let opened = OpenOptions::new().write(true).create_new(true).open(&temp);
            let mut file = match opened {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(io_error(error)),
            };
            if let Err(error) = file
                .write_all(content.as_bytes())
                .and_then(|_| file.sync_all())
            {
                let _ = fs::remove_file(&temp);
                return Err(io_error(error));
            }
            drop(file);
            if let Err(error) = fs::rename(&temp, path) {
                let _ = fs::remove_file(&temp);
                return Err(io_error(error));
            }
            return Ok(());
        }
        Err(ReCtmError::new(
            "VAULT_TEMPFILE_EXHAUSTED",
            "Unable to allocate a private atomic-write temporary file.",
        )
        .with_category(ErrorCategory::Runtime))
    }

    fn append_jsonl(&self, path: &Path, payload: &Value) -> Result<(), ReCtmError> {
        if !payload.is_object() {
            return Err(validation("memory records must be JSON objects"));
        }
        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(io_error)?;
        let mut line = python_json(&sort_json(payload))?;
        line.push('\n');
        file.write_all(line.as_bytes()).map_err(io_error)
    }
}

#[derive(Serialize)]
struct ManualValidationManifest<'a> {
    run_id: &'a str,
    state: &'a str,
    verdict: Option<&'a str>,
    latex_passed: bool,
    transition_count: i64,
    manual_checks_still_required: Vec<&'a str>,
}

fn validate_channel(channel: &str, allowed: &[&str], kind: &str) -> Result<(), ReCtmError> {
    if allowed.contains(&channel) {
        Ok(())
    } else {
        Err(validation_code(
            "UNKNOWN_MEMORY_CHANNEL",
            &format!("Unknown {kind} channel: {channel}"),
        ))
    }
}

fn require_safe_id(value: &str, label: &str) -> Result<String, ReCtmError> {
    let value = value.trim();
    let regex = Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$").map_err(|error| {
        ReCtmError::new("INTERNAL_REGEX_ERROR", error.to_string())
            .with_category(ErrorCategory::Internal)
    })?;
    if !regex.is_match(value) {
        return Err(
            ReCtmError::new("INVALID_IDENTIFIER", format!("Invalid {label}."))
                .with_category(ErrorCategory::Validation)
                .with_details(Map::from_iter([(
                    label.to_owned(),
                    Value::String(value.to_owned()),
                )])),
        );
    }
    Ok(value.to_owned())
}

fn safe_reference_name(value: &str) -> Result<String, ReCtmError> {
    let path = Path::new(value);
    let simple = path.components().count() == 1
        && path.file_name().and_then(|name| name.to_str()) == Some(value)
        && !matches!(value, "" | "." | ".." | "manifest.json");
    if !simple {
        return Err(ReCtmError::new(
            "INVALID_REFERENCE_NAME",
            "Reference names must be simple filenames.",
        )
        .with_category(ErrorCategory::Validation)
        .with_details(Map::from_iter([(
            "name".to_owned(),
            Value::String(value.to_owned()),
        )])));
    }
    Ok(value.to_owned())
}

fn read_jsonl(path: &Path) -> Result<Vec<Value>, ReCtmError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path).map_err(io_error)?;
    Ok(content
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .filter(Value::is_object)
        .collect())
}

fn python_json(value: &Value) -> Result<String, ReCtmError> {
    match value {
        Value::Null => Ok("null".to_owned()),
        Value::Bool(value) => Ok(if *value { "true" } else { "false" }.to_owned()),
        Value::Number(value) => Ok(value.to_string()),
        Value::String(value) => serde_json::to_string(value).map_err(json_error),
        Value::Array(items) => Ok(format!(
            "[{}]",
            items
                .iter()
                .map(python_json)
                .collect::<Result<Vec<_>, ReCtmError>>()?
                .join(", ")
        )),
        Value::Object(object) => Ok(format!(
            "{{{}}}",
            object
                .iter()
                .map(|(key, value)| {
                    Ok(format!(
                        "{}: {}",
                        serde_json::to_string(key).map_err(json_error)?,
                        python_json(value)?
                    ))
                })
                .collect::<Result<Vec<_>, ReCtmError>>()?
                .join(", ")
        )),
    }
}

fn pretty_json(payload: &Value) -> Result<String, ReCtmError> {
    let mut serialized = serde_json::to_string_pretty(&sort_json(payload)).map_err(json_error)?;
    serialized.push('\n');
    Ok(serialized)
}

fn sort_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(Map::from_iter(
            object
                .iter()
                .map(|(key, value)| (key.clone(), sort_json(value))),
        )),
        Value::Array(items) => Value::Array(items.iter().map(sort_json).collect()),
        _ => value.clone(),
    }
}

fn sha256_text(content: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(content.as_bytes());
    format!("{:x}", digest.finalize())
}

fn create_private_dir(path: &Path) -> Result<(), ReCtmError> {
    fs::create_dir_all(path).map_err(io_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    Ok(())
}

fn set_read_only(path: &Path) -> Result<(), ReCtmError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).map_err(io_error)?;
    }
    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(path).map_err(io_error)?.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(path, permissions).map_err(io_error)?;
    }
    Ok(())
}

fn absolute_normalized(path: &Path) -> Result<PathBuf, ReCtmError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|root| root.join(path))
            .map_err(io_error)
    }
}

fn lexically_within(path: &Path, root: &Path) -> bool {
    let mut stack = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                let _ = stack.pop();
            }
            std::path::Component::CurDir => {}
            other => stack.push(other.as_os_str().to_owned()),
        }
    }
    let normalized = stack.into_iter().collect::<PathBuf>();
    let mut root_stack = Vec::new();
    for component in root.components() {
        match component {
            std::path::Component::ParentDir => {
                let _ = root_stack.pop();
            }
            std::path::Component::CurDir => {}
            other => root_stack.push(other.as_os_str().to_owned()),
        }
    }
    let normalized_root = root_stack.into_iter().collect::<PathBuf>();
    normalized.starts_with(normalized_root)
}

fn validation(message: &str) -> ReCtmError {
    ReCtmError::new("INVALID_ARGUMENT", message).with_category(ErrorCategory::Validation)
}

fn validation_code(code: &str, message: &str) -> ReCtmError {
    ReCtmError::new(code, message).with_category(ErrorCategory::Validation)
}

fn io_error(error: std::io::Error) -> ReCtmError {
    ReCtmError::new("VAULT_IO_ERROR", error.to_string()).with_category(ErrorCategory::Runtime)
}

fn json_error(error: serde_json::Error) -> ReCtmError {
    ReCtmError::new("VAULT_JSON_ERROR", error.to_string()).with_category(ErrorCategory::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_rejects_path_authority_and_finalization_needs_permit() -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let vault = PrivateVault::new(temp.path())?;
        vault.initialize_run(
            "run-a",
            "problem",
            &[],
            &serde_json::json!({"owner_id": "owner"}),
        )?;
        assert!(vault.run_root("../escape").is_err());
        assert!(vault.read_reference("run-a", "../secret").is_err());
        Ok(())
    }

    #[test]
    fn memory_is_partitioned_by_role_and_branch() -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let vault = PrivateVault::new(temp.path())?;
        vault.initialize_run("run-a", "problem", &[], &serde_json::json!({}))?;
        vault.append_generation_memory("run-a", "events", &serde_json::json!({"x": 1}))?;
        vault.append_verifier_memory("run-a", "events", &serde_json::json!({"x": 2}))?;
        vault.initialize_branch("run-a", "branch-a", &serde_json::json!({}))?;
        vault.append_branch_memory("run-a", "branch-a", "events", &serde_json::json!({"x": 3}))?;
        assert_eq!(vault.read_generation_memory("run-a", "events")?.len(), 1);
        assert_eq!(vault.read_verifier_memory("run-a", "events")?.len(), 1);
        assert_eq!(
            vault
                .read_branch_memory("run-a", "branch-a", "events")?
                .len(),
            1
        );
        Ok(())
    }

    #[test]
    fn finalization_permit_is_bound_to_exact_proof_bytes() -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let vault = PrivateVault::new(temp.path())?;
        vault.initialize_run("run-a", "problem", &[], &serde_json::json!({}))?;
        vault.write_proof("run-a", "proof version one")?;
        let permit = crate::kernel::FinalizationPermit::issue(
            "run-a".to_owned(),
            sha256_text("proof version one"),
            None,
            "verifier-domain".to_owned(),
        );
        vault.write_proof("run-a", "proof version two")?;
        let denied = vault.finalize_proof("run-a", &permit);
        assert_eq!(
            denied.err().map(|error| error.code),
            Some("FINALIZATION_PERMIT_MISMATCH".to_owned())
        );
        assert!(
            !vault
                .run_root("run-a")?
                .join("final/proof_verified.tex")
                .exists()
        );
        Ok(())
    }
}
