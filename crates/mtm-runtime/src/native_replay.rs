//! Bounded caller-scoped native write replay. Never a workflow receipt or authority.
//! Pending/uncertain slots cannot be evicted into permission to execute again.
use mtm_contracts::{ErrorCategory, ReCtmError};
use mtm_gateway::OAuthPrincipal;
use serde_json::{Map, Value, json};
use std::collections::VecDeque;
use std::sync::Mutex;

const CAPACITY: usize = 64;
const MAX_RESULT_BYTES: usize = 1024 * 1024;
enum Outcome {
    Pending,
    Complete(Value),
    Unknown,
}
struct Entry {
    slot: String,
    fingerprint: String,
    outcome: Outcome,
}
#[derive(Default)]
pub(super) struct NativeReplay {
    entries: Mutex<VecDeque<Entry>>,
}

impl NativeReplay {
    pub(super) fn execute<F>(
        &self,
        principal: &OAuthPrincipal,
        tool: &str,
        args: &Map<String, Value>,
        operation: F,
    ) -> Result<Value, ReCtmError>
    where
        F: FnOnce() -> Result<Value, ReCtmError>,
    {
        let scope = json!({"subject":principal.subject,"client":principal.client_id,"scope":principal.scope});
        self.execute_scoped(&scope.to_string(), tool, args, operation)
    }
    fn execute_scoped<F>(
        &self,
        scope: &str,
        tool: &str,
        args: &Map<String, Value>,
        operation: F,
    ) -> Result<Value, ReCtmError>
    where
        F: FnOnce() -> Result<Value, ReCtmError>,
    {
        if !matches!(tool, "apply_patch" | "apply_changes") {
            return operation();
        }
        let Some(key) = args.get("idempotency_key") else {
            return operation();
        };
        let key = key
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 128 && !s.contains('\0'))
            .ok_or_else(|| {
                error(
                    "INVALID_ARGUMENT",
                    "idempotency_key must contain 1..128 bytes without NUL",
                    ErrorCategory::Validation,
                )
            })?;
        let slot = mtm_core::canonical_arguments_sha256(&Map::from_iter([
            ("scope".into(), json!(scope)),
            ("tool".into(), json!(tool)),
            ("key".into(), json!(key)),
        ]))?;
        let mut work = args.clone();
        work.remove("idempotency_key");
        let fingerprint = mtm_core::canonical_arguments_sha256(&work)?;
        let dry_run = args.get("dry_run").and_then(Value::as_bool) == Some(true);
        {
            let mut entries = self.entries.lock().map_err(|_| {
                error(
                    "NATIVE_REPLAY_LOCK_FAILED",
                    "Native replay state unavailable",
                    ErrorCategory::Internal,
                )
            })?;
            if let Some(index) = entries.iter().position(|e| e.slot == slot) {
                let entry = &entries[index];
                if entry.fingerprint != fingerprint {
                    return Err(error(
                        "IDEMPOTENCY_KEY_REUSED",
                        "Key is bound to different arguments; do not retry changed work under that key",
                        ErrorCategory::Conflict,
                    ));
                }
                match &entry.outcome {
                    Outcome::Pending => return Err(error(
                        "NATIVE_WRITE_IN_PROGRESS",
                        "Original keyed write is still in progress; no second execution occurred",
                        ErrorCategory::Conflict,
                    )
                    .with_retryable(true)),
                    Outcome::Unknown => {
                        return Err(error(
                            "NATIVE_WRITE_RESULT_UNKNOWN",
                            "Write outcome is uncertain. Inspect and reconcile files; neither a fresh key nor restart makes retry safe",
                            ErrorCategory::Conflict,
                        ));
                    }
                    Outcome::Complete(result) => {
                        let mut result = result.clone();
                        result["idempotent_replay"] = json!(true);
                        if let Some(entry) = entries.remove(index) {
                            entries.push_back(entry);
                        }
                        return Ok(result);
                    }
                }
            }
            if !dry_run {
                if entries.len() >= CAPACITY {
                    let index = entries
                        .iter()
                        .position(|e| matches!(e.outcome, Outcome::Complete(_)))
                        .ok_or_else(|| {
                            error(
                                "NATIVE_REPLAY_LIMIT",
                                "Replay capacity is occupied by active or unresolved writes",
                                ErrorCategory::Conflict,
                            )
                            .with_retryable(true)
                        })?;
                    entries.remove(index);
                }
                entries.push_back(Entry {
                    slot: slot.clone(),
                    fingerprint,
                    outcome: Outcome::Pending,
                });
            }
        }
        if dry_run {
            return operation();
        }
        // No replay lock spans filesystem operations, Git subprocesses, or commit.
        let result = operation();
        let mut entries = self.entries.lock().map_err(|_| {
            error(
                "NATIVE_REPLAY_LOCK_FAILED",
                "Write outcome could not be recorded; inspect files before retrying",
                ErrorCategory::Internal,
            )
        })?;
        let index = entries.iter().position(|e| e.slot == slot).ok_or_else(|| {
            error(
                "NATIVE_WRITE_RESULT_UNKNOWN",
                "Reserved write state was lost; inspect files before retrying",
                ErrorCategory::Internal,
            )
        })?;
        match &result {
            Ok(value) => {
                if value.get("ok").and_then(Value::as_bool) == Some(false)
                    || serde_json::to_vec(value)
                        .map_or(true, |bytes| bytes.len() > MAX_RESULT_BYTES)
                {
                    entries[index].outcome = Outcome::Unknown;
                } else {
                    entries[index].outcome = Outcome::Complete(value.clone());
                }
            }
            Err(e) if matches!(e.category, ErrorCategory::Runtime | ErrorCategory::Internal) => {
                entries[index].outcome = Outcome::Unknown;
            }
            Err(_) => {
                entries.remove(index);
            }
        }
        result
    }
}
fn error(code: &str, message: &str, category: ErrorCategory) -> ReCtmError {
    ReCtmError::new(code, message).with_category(category)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    fn arguments(key: &str, n: i64) -> Map<String, Value> {
        json!({"idempotency_key":key,"changes":[{"action":"create","path":"a","content":n.to_string()}]}).as_object().cloned().unwrap_or_default()
    }
    #[test]
    fn successes_are_caller_and_tool_scoped_and_changed_payloads_conflict() -> Result<(), ReCtmError>
    {
        let replay = NativeReplay::default();
        let count = Cell::new(0);
        let run = || {
            count.set(count.get() + 1);
            Ok(json!({"clean":true}))
        };
        let a = arguments("key", 1);
        replay.execute_scoped("alice", "apply_changes", &a, run)?;
        assert_eq!(
            replay.execute_scoped("alice", "apply_changes", &a, run)?["idempotent_replay"],
            true
        );
        assert_eq!(count.get(), 1);
        assert_eq!(
            replay
                .execute_scoped("alice", "apply_changes", &arguments("key", 2), run)
                .map_err(|e| e.code),
            Err("IDEMPOTENCY_KEY_REUSED".into())
        );
        replay.execute_scoped("bob", "apply_changes", &a, run)?;
        replay.execute_scoped("alice", "apply_patch", &a, run)?;
        assert_eq!(count.get(), 3);
        Ok(())
    }
    #[test]
    fn inflight_duplicate_never_executes_and_unknown_result_stays_blocked() -> Result<(), ReCtmError>
    {
        let replay = NativeReplay::default();
        let a = arguments("key", 1);
        let result = replay.execute_scoped("alice", "apply_changes", &a, || {
            let duplicate = replay.execute_scoped("alice", "apply_changes", &a, || {
                Ok(json!({"unexpected":true}))
            });
            assert_eq!(
                duplicate.map_err(|e| e.code),
                Err("NATIVE_WRITE_IN_PROGRESS".into())
            );
            Err(error(
                "NATIVE_PATCH_ROLLBACK_FAILED",
                "fixture",
                ErrorCategory::Internal,
            ))
        });
        assert!(result.is_err());
        assert_eq!(
            replay
                .execute_scoped("alice", "apply_changes", &a, || Ok(json!({})))
                .map_err(|e| e.code),
            Err("NATIVE_WRITE_RESULT_UNKNOWN".into())
        );
        Ok(())
    }
    #[test]
    fn dry_runs_are_not_recorded_and_pending_admission_is_bounded() -> Result<(), ReCtmError> {
        let replay = NativeReplay::default();
        let mut a = arguments("dry", 1);
        a.insert("dry_run".into(), json!(true));
        let count = Cell::new(0);
        for _ in 0..2 {
            replay.execute_scoped("a", "apply_changes", &a, || {
                count.set(count.get() + 1);
                Ok(json!({}))
            })?;
        }
        assert_eq!(count.get(), 2);
        for n in 0..CAPACITY {
            let _ = replay.execute_scoped(
                "a",
                "apply_changes",
                &arguments(&format!("unknown-{n}"), 1),
                || Err(error("IO_ERROR", "fixture", ErrorCategory::Runtime)),
            );
        }
        assert_eq!(
            replay
                .execute_scoped("a", "apply_changes", &arguments("new", 1), || Ok(json!({})))
                .map_err(|e| e.code),
            Err("NATIVE_REPLAY_LIMIT".into())
        );
        Ok(())
    }

    #[test]
    fn real_concurrent_duplicate_and_payload_conflict_do_not_execute_twice()
    -> Result<(), ReCtmError> {
        use std::sync::{Arc, mpsc};
        let replay = Arc::new(NativeReplay::default());
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let child = Arc::clone(&replay);
        let thread = std::thread::spawn(move || {
            child.execute_scoped("a", "apply_changes", &arguments("concurrent", 1), || {
                entered_tx
                    .send(())
                    .map_err(|_| error("TEST", "channel", ErrorCategory::Internal))?;
                release_rx
                    .recv()
                    .map_err(|_| error("TEST", "channel", ErrorCategory::Internal))?;
                Ok(json!({"ok":true}))
            })
        });
        entered_rx
            .recv()
            .map_err(|_| error("TEST", "channel", ErrorCategory::Internal))?;
        assert_eq!(
            replay
                .execute_scoped("a", "apply_changes", &arguments("concurrent", 1), || Ok(
                    json!({"unexpected":true})
                ))
                .map_err(|e| e.code),
            Err("NATIVE_WRITE_IN_PROGRESS".into())
        );
        assert_eq!(
            replay
                .execute_scoped("a", "apply_changes", &arguments("concurrent", 2), || Ok(
                    json!({})
                ))
                .map_err(|e| e.code),
            Err("IDEMPOTENCY_KEY_REUSED".into())
        );
        release_tx
            .send(())
            .map_err(|_| error("TEST", "channel", ErrorCategory::Internal))?;
        thread
            .join()
            .map_err(|_| error("TEST", "thread", ErrorCategory::Internal))??;
        assert_eq!(
            replay.execute_scoped("a", "apply_changes", &arguments("concurrent", 1), || Ok(
                json!({"unexpected":true})
            ))?["idempotent_replay"],
            true
        );
        Ok(())
    }
    #[test]
    fn success_lru_and_oversized_or_failed_payloads_have_explicit_limits() -> Result<(), ReCtmError>
    {
        let replay = NativeReplay::default();
        for n in 0..=CAPACITY {
            replay.execute_scoped(
                "a",
                "apply_changes",
                &arguments(&format!("k{n}"), 1),
                || Ok(json!({})),
            )?;
        }
        let fresh = replay.execute_scoped("a", "apply_changes", &arguments("k0", 1), || {
            Ok(json!({"executed_after_eviction":true}))
        })?;
        assert_eq!(fresh["executed_after_eviction"], true);
        for (key, result) in [
            ("large", json!({"data":"x".repeat(MAX_RESULT_BYTES+1)})),
            ("failure", json!({"ok":false})),
        ] {
            replay.execute_scoped("a", "apply_changes", &arguments(key, 1), || Ok(result))?;
            assert_eq!(
                replay
                    .execute_scoped("a", "apply_changes", &arguments(key, 1), || Ok(json!({})))
                    .map_err(|e| e.code),
                Err("NATIVE_WRITE_RESULT_UNKNOWN".into())
            );
        }
        Ok(())
    }
}
