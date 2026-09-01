use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mtm_contracts::{ErrorCategory, ReCtmError};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::macros::format_description;

use crate::schema::{
    SCHEMA_MIGRATIONS_TABLE_SQL, STATE_SCHEMA_VERSION, V1_WORKFLOW_SCHEMA_SQL,
    V2_RESEARCH_SCHEMA_SQL,
};

const REGISTRY_ID_MAX_BYTES: usize = 128;

pub trait Clock: Send + Sync {
    fn now_iso(&self) -> Result<String, ReCtmError>;
    fn unix_seconds(&self) -> Result<i64, ReCtmError>;
}

pub trait IdSource: Send + Sync {
    fn token_hex(&self, bytes: usize) -> Result<String, ReCtmError>;
    fn token_urlsafe(&self, bytes: usize) -> Result<String, ReCtmError>;
}

#[derive(Clone, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_iso(&self) -> Result<String, ReCtmError> {
        let format = format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        );
        OffsetDateTime::now_utc().format(&format).map_err(|error| {
            ReCtmError::new("CLOCK_FORMAT_ERROR", error.to_string())
                .with_category(ErrorCategory::Internal)
        })
    }

    fn unix_seconds(&self) -> Result<i64, ReCtmError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                ReCtmError::new("CLOCK_ERROR", error.to_string())
                    .with_category(ErrorCategory::Internal)
            })?;
        i64::try_from(duration.as_secs()).map_err(|_| {
            ReCtmError::new("CLOCK_ERROR", "Unix timestamp exceeded i64.")
                .with_category(ErrorCategory::Internal)
        })
    }
}

#[derive(Clone, Default)]
pub struct SystemIdSource;

impl IdSource for SystemIdSource {
    fn token_hex(&self, bytes: usize) -> Result<String, ReCtmError> {
        let mut data = vec![0_u8; bytes];
        getrandom::fill(&mut data).map_err(random_error)?;
        Ok(data.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    fn token_urlsafe(&self, bytes: usize) -> Result<String, ReCtmError> {
        let mut data = vec![0_u8; bytes];
        getrandom::fill(&mut data).map_err(random_error)?;
        Ok(URL_SAFE_NO_PAD.encode(data))
    }
}

fn random_error(error: getrandom::Error) -> ReCtmError {
    ReCtmError::new("RANDOM_SOURCE_ERROR", error.to_string()).with_category(ErrorCategory::Internal)
}

#[derive(Clone)]
pub struct StoreRuntime {
    pub clock: Arc<dyn Clock>,
    pub ids: Arc<dyn IdSource>,
}

impl Default for StoreRuntime {
    fn default() -> Self {
        Self {
            clock: Arc::new(SystemClock),
            ids: Arc::new(SystemIdSource),
        }
    }
}

pub struct StateStore {
    path: PathBuf,
    connection: Mutex<Connection>,
    runtime: StoreRuntime,
}

impl StateStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReCtmError> {
        Self::open_with_runtime(path, StoreRuntime::default())
    }

    pub fn open_with_runtime(
        path: impl AsRef<Path>,
        runtime: StoreRuntime,
    ) -> Result<Self, ReCtmError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(io_error)?;
        }
        let connection = Connection::open(&path).map_err(sql_error)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;\nPRAGMA foreign_keys=ON;\nPRAGMA synchronous=FULL;",
            )
            .map_err(sql_error)?;
        let store = Self {
            path,
            connection: Mutex::new(connection),
            runtime,
        };
        store.initialize()?;
        Ok(store)
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn runtime(&self) -> StoreRuntime {
        self.runtime.clone()
    }

    pub fn schema_version(&self) -> Result<i64, ReCtmError> {
        let connection = self.lock_connection()?;
        connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(sql_error)
    }

    fn initialize(&self) -> Result<(), ReCtmError> {
        let raw_version = self.schema_version()?;
        if raw_version > STATE_SCHEMA_VERSION {
            return Err(ReCtmError::new(
                "STATE_SCHEMA_NEWER_THAN_RUNTIME",
                "The Re-CTM state database was created by a newer runtime.",
            )
            .with_category(ErrorCategory::Conflict)
            .with_details(serde_json::json!({
                "database_version": raw_version,
                "runtime_version": STATE_SCHEMA_VERSION,
            })));
        }
        let mut version = raw_version;
        if version == 0 {
            self.migrate_0_to_1()?;
            version = 1;
        }
        if version == 1 {
            self.migrate_1_to_2()?;
            version = 2;
        }
        if version != STATE_SCHEMA_VERSION {
            return Err(ReCtmError::new(
                "STATE_SCHEMA_MIGRATION_FAILED",
                "The Re-CTM state database could not be migrated to the current schema.",
            )
            .with_category(ErrorCategory::Internal)
            .with_details(serde_json::json!({
                "database_version": version,
                "runtime_version": STATE_SCHEMA_VERSION,
            })));
        }
        Ok(())
    }

    fn migrate_0_to_1(&self) -> Result<(), ReCtmError> {
        let applied_at = self.runtime.clock.now_iso()?;
        self.immediate(|transaction| {
            transaction
                .execute_batch(V1_WORKFLOW_SCHEMA_SQL)
                .map_err(sql_error)?;
            transaction
                .execute_batch(SCHEMA_MIGRATIONS_TABLE_SQL)
                .map_err(sql_error)?;
            transaction
                .execute(
                    "INSERT OR IGNORE INTO schema_migrations(version, applied_at, description) VALUES(1, ?, 'baseline workflow schema')",
                    [applied_at],
                )
                .map_err(sql_error)?;
            transaction
                .execute_batch("PRAGMA user_version = 1;")
                .map_err(sql_error)?;
            Ok(())
        })
    }

    fn migrate_1_to_2(&self) -> Result<(), ReCtmError> {
        let applied_at = self.runtime.clock.now_iso()?;
        self.immediate(|transaction| {
            transaction
                .execute_batch(SCHEMA_MIGRATIONS_TABLE_SQL)
                .map_err(sql_error)?;
            transaction
                .execute_batch(V2_RESEARCH_SCHEMA_SQL)
                .map_err(sql_error)?;
            transaction
                .execute(
                    "INSERT OR IGNORE INTO schema_migrations(version, applied_at, description) VALUES(1, ?, 'baseline workflow schema')",
                    [&applied_at],
                )
                .map_err(sql_error)?;
            transaction
                .execute(
                    "INSERT OR IGNORE INTO schema_migrations(version, applied_at, description) VALUES(2, ?, 'v0.2 research registry and provenance schema')",
                    [&applied_at],
                )
                .map_err(sql_error)?;
            transaction
                .execute_batch("PRAGMA user_version = 2;")
                .map_err(sql_error)?;
            Ok(())
        })
    }

    fn immediate<T>(
        &self,
        operation: impl FnOnce(&Transaction<'_>) -> Result<T, ReCtmError>,
    ) -> Result<T, ReCtmError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let result = operation(&transaction)?;
        transaction.commit().map_err(sql_error)?;
        Ok(result)
    }

    fn lock_connection(&self) -> Result<MutexGuard<'_, Connection>, ReCtmError> {
        self.connection.lock().map_err(|_| {
            ReCtmError::new("STATE_STORE_LOCK_POISONED", "State store lock is poisoned.")
                .with_category(ErrorCategory::Internal)
        })
    }

    pub fn create_run(
        &self,
        run_id: &str,
        problem_id: &str,
        owner_id: &str,
        state: &str,
        metadata: &Value,
    ) -> Result<Value, ReCtmError> {
        let now = self.runtime.clock.now_iso()?;
        let result = self.immediate(|transaction| {
            transaction.execute(
                "INSERT INTO runs (run_id, problem_id, owner_id, state, status, metadata_json, created_at, updated_at) VALUES (?, ?, ?, ?, 'active', ?, ?, ?)",
                params![run_id, problem_id, owner_id, state, canonical_json(metadata)?, now, now],
            ).map_err(sql_error)
        });
        if let Err(error) = result {
            if is_constraint(&error) {
                return Err(ReCtmError::new(
                    "RUN_ALREADY_EXISTS",
                    format!("Run already exists: {run_id}"),
                )
                .with_category(ErrorCategory::Conflict)
                .with_details(serde_json::json!({"run_id": run_id})));
            }
            return Err(error);
        }
        self.get_run(run_id)
    }

    pub fn get_run(&self, run_id: &str) -> Result<Value, ReCtmError> {
        self.query_one(
            "SELECT * FROM runs WHERE run_id = ?",
            [run_id],
            &["metadata_json"],
        )?
        .ok_or_else(|| {
            ReCtmError::new("RUN_NOT_FOUND", format!("Unknown run: {run_id}"))
                .with_category(ErrorCategory::NotFound)
                .with_details(serde_json::json!({"run_id": run_id}))
        })
    }

    pub fn list_runs(&self, owner_id: &str, limit: i64) -> Result<Vec<Value>, ReCtmError> {
        self.query_all_params(
            "SELECT * FROM runs WHERE owner_id = ? ORDER BY created_at DESC LIMIT ?",
            params![owner_id, limit],
            &["metadata_json"],
        )
    }

    pub fn update_run_metadata(
        &self,
        run_id: &str,
        updates: &Map<String, Value>,
    ) -> Result<Value, ReCtmError> {
        let now = self.runtime.clock.now_iso()?;
        self.immediate(|transaction| {
            let raw: Option<String> = transaction
                .query_row(
                    "SELECT metadata_json FROM runs WHERE run_id = ?",
                    [run_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_error)?;
            let raw = raw.ok_or_else(|| {
                ReCtmError::new("RUN_NOT_FOUND", format!("Unknown run: {run_id}"))
                    .with_category(ErrorCategory::NotFound)
            })?;
            let mut metadata = parse_object_or_empty(&raw);
            metadata.extend(updates.clone());
            transaction
                .execute(
                    "UPDATE runs SET metadata_json = ?, updated_at = ? WHERE run_id = ?",
                    params![canonical_json(&Value::Object(metadata))?, now, run_id],
                )
                .map_err(sql_error)?;
            Ok(())
        })?;
        self.get_run(run_id)
    }

    pub fn transition_run(&self, request: TransitionRun<'_>) -> Result<Value, ReCtmError> {
        let now = self.runtime.clock.now_iso()?;
        self.immediate(|transaction| {
            let row = query_one_on(
                transaction,
                "SELECT * FROM runs WHERE run_id = ?",
                [request.run_id],
                &["metadata_json"],
            )?
            .ok_or_else(|| {
                ReCtmError::new("RUN_NOT_FOUND", format!("Unknown run: {}", request.run_id))
                    .with_category(ErrorCategory::NotFound)
            })?;
            let object = row.as_object().ok_or_else(internal_row_error)?;
            let actual_state = text_value(object, "state")?;
            if actual_state != request.expected_state {
                return Err(ReCtmError::new(
                    "STATE_CONFLICT",
                    "The run changed state before this transition was committed.",
                )
                .with_category(ErrorCategory::Conflict)
                .with_retryable(true)
                .with_details(serde_json::json!({
                    "run_id": request.run_id,
                    "expected": request.expected_state,
                    "actual": actual_state,
                })));
            }
            let sequence = integer_value(object, "transition_seq")? + 1;
            let epoch = integer_value(object, "epoch")? + i64::from(request.increment_epoch);
            let round_index = integer_value(object, "round_index")? + request.round_delta;
            let status = request.status.unwrap_or(text_value(object, "status")?);
            let latex_passed = request
                .latex_passed
                .map(i64::from)
                .unwrap_or(boolean_storage_value(object, "latex_passed")?);
            let verdict = request
                .verdict
                .map(ToOwned::to_owned)
                .or_else(|| optional_text_value(object, "verdict"));
            let sealed = request
                .sealed
                .map(i64::from)
                .unwrap_or(boolean_storage_value(object, "sealed")?);
            transaction.execute(
                "UPDATE runs SET state=?, epoch=?, transition_seq=?, round_index=?, updated_at=?, status=?, latex_passed=?, verdict=?, sealed=? WHERE run_id=?",
                params![request.after_state, epoch, sequence, round_index, now, status, latex_passed, verdict, sealed, request.run_id],
            ).map_err(sql_error)?;
            transaction.execute(
                "INSERT INTO transitions(run_id, sequence, trace_id, before_state, after_state, actor, reason, evidence_json, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![request.run_id, sequence, request.trace_id, request.expected_state, request.after_state, request.actor, request.reason, canonical_json(request.evidence)?, now],
            ).map_err(sql_error)?;
            if request.increment_epoch {
                transaction.execute(
                    "UPDATE capabilities SET revoked=1, revoked_at=?, revoke_reason='run_epoch_advanced' WHERE run_id=? AND revoked=0",
                    params![now, request.run_id],
                ).map_err(sql_error)?;
            }
            Ok(())
        })?;
        self.get_run(request.run_id)
    }

    pub fn create_domain(
        &self,
        domain_id: &str,
        run_id: &str,
        role: &str,
        snapshot_id: Option<&str>,
        order_index: Option<i64>,
        metadata: &Value,
    ) -> Result<Value, ReCtmError> {
        let now = self.runtime.clock.now_iso()?;
        self.immediate(|transaction| {
            transaction.execute(
                "INSERT INTO domains(domain_id, run_id, role, status, snapshot_id, order_index, metadata_json, created_at) VALUES(?, ?, ?, 'open', ?, ?, ?, ?)",
                params![domain_id, run_id, role, snapshot_id, order_index, canonical_json(metadata)?, now],
            ).map_err(sql_error)?;
            Ok(())
        })?;
        self.get_domain(domain_id)
    }

    pub fn get_domain(&self, domain_id: &str) -> Result<Value, ReCtmError> {
        self.query_one(
            "SELECT * FROM domains WHERE domain_id = ?",
            [domain_id],
            &["metadata_json"],
        )?
        .ok_or_else(|| {
            ReCtmError::new("DOMAIN_NOT_FOUND", format!("Unknown domain: {domain_id}"))
                .with_category(ErrorCategory::NotFound)
        })
    }

    pub fn list_domains(
        &self,
        run_id: &str,
        role: Option<&str>,
        status: Option<&str>,
    ) -> Result<Vec<Value>, ReCtmError> {
        match (role, status) {
            (None, None) => self.query_all(
                "SELECT * FROM domains WHERE run_id=? ORDER BY order_index, created_at",
                [run_id],
                &["metadata_json"],
            ),
            (Some(role), None) => self.query_all_params(
                "SELECT * FROM domains WHERE run_id=? AND role=? ORDER BY order_index, created_at",
                params![run_id, role],
                &["metadata_json"],
            ),
            (None, Some(status)) => self.query_all_params(
                "SELECT * FROM domains WHERE run_id=? AND status=? ORDER BY order_index, created_at",
                params![run_id, status],
                &["metadata_json"],
            ),
            (Some(role), Some(status)) => self.query_all_params(
                "SELECT * FROM domains WHERE run_id=? AND role=? AND status=? ORDER BY order_index, created_at",
                params![run_id, role, status],
                &["metadata_json"],
            ),
        }
    }

    pub fn seal_domain(&self, domain_id: &str) -> Result<Value, ReCtmError> {
        let now = self.runtime.clock.now_iso()?;
        self.immediate(|transaction| {
            let status: Option<String> = transaction
                .query_row(
                    "SELECT status FROM domains WHERE domain_id=?",
                    [domain_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_error)?;
            let status = status.ok_or_else(|| {
                ReCtmError::new("DOMAIN_NOT_FOUND", format!("Unknown domain: {domain_id}"))
                    .with_category(ErrorCategory::NotFound)
            })?;
            if status != "open" {
                return Err(ReCtmError::new(
                    "DOMAIN_NOT_OPEN",
                    format!("Domain is not open: {domain_id}"),
                )
                .with_category(ErrorCategory::Conflict));
            }
            transaction
                .execute(
                    "UPDATE domains SET status='sealed', sealed_at=? WHERE domain_id=?",
                    params![now, domain_id],
                )
                .map_err(sql_error)?;
            transaction
                .execute(
                    "UPDATE capabilities SET revoked=1, revoked_at=?, revoke_reason='domain_sealed' WHERE domain_id=? AND revoked=0",
                    params![now, domain_id],
                )
                .map_err(sql_error)?;
            Ok(())
        })?;
        self.get_domain(domain_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_capability(
        &self,
        nonce: &str,
        run_id: &str,
        domain_id: &str,
        role: &str,
        epoch: i64,
        issued_state: &str,
        permissions: &[String],
        issued_at: i64,
        expires_at: i64,
    ) -> Result<(), ReCtmError> {
        self.immediate(|transaction| {
            transaction.execute(
                "INSERT INTO capabilities(nonce, run_id, domain_id, role, epoch, issued_state, permissions_json, issued_at, expires_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![nonce, run_id, domain_id, role, epoch, issued_state, canonical_json(&serde_json::json!(permissions))?, issued_at, expires_at],
            ).map_err(sql_error)?;
            Ok(())
        })
    }

    pub fn get_capability(&self, nonce: &str) -> Result<Option<Value>, ReCtmError> {
        self.query_one(
            "SELECT * FROM capabilities WHERE nonce=?",
            [nonce],
            &["permissions_json"],
        )
    }

    pub fn revoke_capability(&self, nonce: &str, reason: &str) -> Result<(), ReCtmError> {
        let now = self.runtime.clock.now_iso()?;
        self.immediate(|transaction| {
            transaction
                .execute(
                    "UPDATE capabilities SET revoked=1, revoked_at=?, revoke_reason=? WHERE nonce=? AND revoked=0",
                    params![now, reason, nonce],
                )
                .map_err(sql_error)?;
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_branch(
        &self,
        branch_id: &str,
        run_id: &str,
        plan_id: &str,
        domain_id: &str,
        snapshot_id: &str,
        order_index: i64,
        metadata: &Value,
    ) -> Result<Value, ReCtmError> {
        let now = self.runtime.clock.now_iso()?;
        self.immediate(|transaction| {
            transaction.execute(
                "INSERT INTO branches(branch_id, run_id, plan_id, domain_id, snapshot_id, order_index, status, metadata_json, created_at) VALUES(?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
                params![branch_id, run_id, plan_id, domain_id, snapshot_id, order_index, canonical_json(metadata)?, now],
            ).map_err(sql_error)?;
            Ok(())
        })?;
        self.get_branch(branch_id)
    }

    pub fn get_branch(&self, branch_id: &str) -> Result<Value, ReCtmError> {
        self.query_one(
            "SELECT * FROM branches WHERE branch_id=?",
            [branch_id],
            &["metadata_json"],
        )?
        .ok_or_else(|| {
            ReCtmError::new("BRANCH_NOT_FOUND", format!("Unknown branch: {branch_id}"))
                .with_category(ErrorCategory::NotFound)
        })
    }

    pub fn list_branches(&self, run_id: &str) -> Result<Vec<Value>, ReCtmError> {
        self.query_all(
            "SELECT * FROM branches WHERE run_id=? ORDER BY order_index",
            [run_id],
            &["metadata_json"],
        )
    }

    pub fn update_branch_status(
        &self,
        branch_id: &str,
        status: &str,
        result_path: Option<&str>,
    ) -> Result<Value, ReCtmError> {
        let sealed_at = if status == "sealed" {
            Some(self.runtime.clock.now_iso()?)
        } else {
            None
        };
        self.immediate(|transaction| {
            let changed = transaction.execute(
                "UPDATE branches SET status=?, result_path=COALESCE(?, result_path), sealed_at=COALESCE(?, sealed_at) WHERE branch_id=?",
                params![status, result_path, sealed_at, branch_id],
            ).map_err(sql_error)?;
            if changed != 1 {
                return Err(ReCtmError::new(
                    "BRANCH_NOT_FOUND",
                    format!("Unknown branch: {branch_id}"),
                )
                .with_category(ErrorCategory::NotFound));
            }
            Ok(())
        })?;
        self.get_branch(branch_id)
    }

    pub fn add_steering(
        &self,
        run_id: &str,
        owner_id: &str,
        message: &str,
    ) -> Result<i64, ReCtmError> {
        let now = self.runtime.clock.now_iso()?;
        self.immediate(|transaction| {
            transaction.execute(
                "INSERT INTO steering(run_id, owner_id, message, created_at) VALUES(?, ?, ?, ?)",
                params![run_id, owner_id, message, now],
            ).map_err(sql_error)?;
            Ok(transaction.last_insert_rowid())
        })
    }

    pub fn consume_steering(&self, run_id: &str, limit: i64) -> Result<Vec<Value>, ReCtmError> {
        let now = self.runtime.clock.now_iso()?;
        self.immediate(|transaction| {
            let rows = query_all_raw_on_params(
                transaction,
                "SELECT * FROM steering WHERE run_id=? AND consumed=0 ORDER BY id LIMIT ?",
                params![run_id, limit],
            )?;
            let ids = rows
                .iter()
                .filter_map(|row| row.get("id").and_then(Value::as_i64))
                .collect::<Vec<_>>();
            for id in ids {
                transaction
                    .execute(
                        "UPDATE steering SET consumed=1, consumed_at=? WHERE id=?",
                        params![now, id],
                    )
                    .map_err(sql_error)?;
            }
            Ok(rows)
        })
    }

    pub fn list_transitions(&self, run_id: &str) -> Result<Vec<Value>, ReCtmError> {
        self.query_all(
            "SELECT * FROM transitions WHERE run_id=? ORDER BY sequence",
            [run_id],
            &["evidence_json"],
        )
    }

    pub fn create_project(
        &self,
        owner_id: &str,
        title: &str,
        project_id: Option<&str>,
        metadata: &Value,
    ) -> Result<Value, ReCtmError> {
        if owner_id.trim().is_empty() || title.trim().is_empty() {
            return Err(ReCtmError::new(
                "INVALID_PROJECT",
                "Project owner and title are required.",
            )
            .with_category(ErrorCategory::Validation));
        }
        let resolved = match project_id {
            Some(value) => value.trim().to_owned(),
            None => format!("project-{}", self.runtime.ids.token_hex(6)?),
        };
        if !validate_registry_id(&resolved) {
            return Err(ReCtmError::new(
                "INVALID_PROJECT_ID",
                "Project id must use only letters, digits, '.', '_', or '-' and start with an alphanumeric character.",
            )
            .with_category(ErrorCategory::Validation));
        }
        let now = self.runtime.clock.now_iso()?;
        let result = self.immediate(|transaction| {
            transaction.execute(
                "INSERT INTO projects(project_id, owner_id, title, metadata_json, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)",
                params![resolved, owner_id, title.trim(), canonical_json(metadata)?, now, now],
            ).map_err(sql_error)
        });
        if let Err(error) = result {
            if is_constraint(&error) {
                return Err(ReCtmError::new(
                    "PROJECT_ALREADY_EXISTS",
                    "A project with this id already exists.",
                )
                .with_category(ErrorCategory::Conflict)
                .with_details(serde_json::json!({"project_id": resolved})));
            }
            return Err(error);
        }
        self.get_project(&resolved, Some(owner_id))
    }

    pub fn get_project(
        &self,
        project_id: &str,
        owner_id: Option<&str>,
    ) -> Result<Value, ReCtmError> {
        let payload = self
            .query_one(
                "SELECT * FROM projects WHERE project_id=?",
                [project_id],
                &["metadata_json"],
            )?
            .ok_or_else(|| {
                ReCtmError::new("PROJECT_NOT_FOUND", "Unknown project.")
                    .with_category(ErrorCategory::NotFound)
                    .with_details(serde_json::json!({"project_id": project_id}))
            })?;
        if let Some(owner_id) = owner_id
            && payload.get("owner_id").and_then(Value::as_str) != Some(owner_id)
        {
            return Err(ReCtmError::new(
                "PROJECT_OWNER_MISMATCH",
                "Project is not owned by the authenticated principal.",
            )
            .with_category(ErrorCategory::Permission));
        }
        Ok(payload)
    }

    pub fn list_projects(&self, owner_id: &str, limit: i64) -> Result<Vec<Value>, ReCtmError> {
        self.query_all_params(
            "SELECT * FROM projects WHERE owner_id=? ORDER BY updated_at DESC LIMIT ?",
            params![owner_id, limit],
            &["metadata_json"],
        )
    }

    pub fn create_claim(
        &self,
        owner_id: &str,
        project_id: &str,
        title: &str,
        claim_id: Option<&str>,
        metadata: &Value,
    ) -> Result<Value, ReCtmError> {
        self.get_project(project_id, Some(owner_id))?;
        if title.trim().is_empty() {
            return Err(ReCtmError::new("INVALID_CLAIM", "Claim title is required.")
                .with_category(ErrorCategory::Validation));
        }
        let resolved = match claim_id {
            Some(value) => value.trim().to_owned(),
            None => format!("claim-{}", self.runtime.ids.token_hex(6)?),
        };
        if !validate_registry_id(&resolved) {
            return Err(ReCtmError::new(
                "INVALID_CLAIM_ID",
                "Claim id must use only letters, digits, '.', '_', or '-' and start with an alphanumeric character.",
            )
            .with_category(ErrorCategory::Validation));
        }
        let now = self.runtime.clock.now_iso()?;
        let result = self.immediate(|transaction| {
            transaction.execute(
                "INSERT INTO claims(claim_id, project_id, title, metadata_json, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)",
                params![resolved, project_id, title.trim(), canonical_json(metadata)?, now, now],
            ).map_err(sql_error)
        });
        if let Err(error) = result {
            if is_constraint(&error) {
                return Err(ReCtmError::new(
                    "CLAIM_ALREADY_EXISTS",
                    "A claim with this id already exists.",
                )
                .with_category(ErrorCategory::Conflict));
            }
            return Err(error);
        }
        self.get_claim(&resolved, Some(owner_id))
    }

    pub fn get_claim(&self, claim_id: &str, owner_id: Option<&str>) -> Result<Value, ReCtmError> {
        let payload = self
            .query_one(
                "SELECT * FROM claims WHERE claim_id=?",
                [claim_id],
                &["metadata_json"],
            )?
            .ok_or_else(|| {
                ReCtmError::new("CLAIM_NOT_FOUND", "Unknown claim.")
                    .with_category(ErrorCategory::NotFound)
                    .with_details(serde_json::json!({"claim_id": claim_id}))
            })?;
        if let Some(owner_id) = owner_id {
            let project_id = payload
                .get("project_id")
                .and_then(Value::as_str)
                .ok_or_else(internal_row_error)?;
            self.get_project(project_id, Some(owner_id))?;
        }
        Ok(payload)
    }

    pub fn list_claims(&self, project_id: &str, owner_id: &str) -> Result<Vec<Value>, ReCtmError> {
        self.get_project(project_id, Some(owner_id))?;
        self.query_all(
            "SELECT * FROM claims WHERE project_id=? ORDER BY created_at",
            [project_id],
            &["metadata_json"],
        )
    }

    pub fn list_claim_revisions(
        &self,
        claim_id: &str,
        owner_id: &str,
    ) -> Result<Vec<Value>, ReCtmError> {
        self.get_claim(claim_id, Some(owner_id))?;
        self.query_all(
            "SELECT * FROM claim_revisions WHERE claim_id=? ORDER BY revision_number",
            [claim_id],
            &["conditions_json", "metadata_json"],
        )
    }

    pub fn get_claim_revision(
        &self,
        revision_id: &str,
        owner_id: Option<&str>,
    ) -> Result<Value, ReCtmError> {
        let payload = self
            .query_one(
                "SELECT * FROM claim_revisions WHERE revision_id=?",
                [revision_id],
                &["conditions_json", "metadata_json"],
            )?
            .ok_or_else(|| {
                ReCtmError::new("CLAIM_REVISION_NOT_FOUND", "Unknown claim revision.")
                    .with_category(ErrorCategory::NotFound)
            })?;
        if let Some(owner_id) = owner_id {
            let claim_id = payload
                .get("claim_id")
                .and_then(Value::as_str)
                .ok_or_else(internal_row_error)?;
            self.get_claim(claim_id, Some(owner_id))?;
        }
        Ok(payload)
    }

    pub fn current_claim_revision(
        &self,
        claim_id: &str,
        owner_id: &str,
    ) -> Result<Option<Value>, ReCtmError> {
        self.get_claim(claim_id, Some(owner_id))?;
        self.query_one(
            "SELECT * FROM claim_revisions WHERE claim_id=? AND lifecycle_status='ACTIVE' ORDER BY revision_number DESC LIMIT 1",
            [claim_id],
            &["conditions_json", "metadata_json"],
        )
    }

    pub fn create_open_claim_revision(
        &self,
        owner_id: &str,
        claim_id: &str,
        statement_tex: &str,
        conditions: &[String],
        expected_base_revision_id: Option<&str>,
    ) -> Result<Value, ReCtmError> {
        self.get_claim(claim_id, Some(owner_id))?;
        if statement_tex.trim().is_empty() {
            return Err(ReCtmError::new(
                "INVALID_CLAIM_REVISION",
                "Open claim revision requires a statement.",
            )
            .with_category(ErrorCategory::Validation));
        }
        let mut normalized = Vec::with_capacity(conditions.len());
        for condition in conditions {
            if condition.trim().is_empty() {
                return Err(ReCtmError::new(
                    "INVALID_CLAIM_REVISION",
                    "Claim conditions must contain only non-empty strings.",
                )
                .with_category(ErrorCategory::Validation));
            }
            normalized.push(condition.trim().to_owned());
        }
        let now = self.runtime.clock.now_iso()?;
        let revision_id = self.immediate(|transaction| {
            let active: Option<(String, i64)> = transaction
                .query_row(
                    "SELECT revision_id, revision_number FROM claim_revisions WHERE claim_id=? AND lifecycle_status='ACTIVE' ORDER BY revision_number DESC LIMIT 1",
                    [claim_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(sql_error)?;
            let active_id = active.as_ref().map(|item| item.0.as_str());
            if expected_base_revision_id.is_some() && active_id != expected_base_revision_id {
                return Err(ReCtmError::new(
                    "CLAIM_REVISION_CONFLICT",
                    "The active claim revision changed before the owner revision was written.",
                )
                .with_category(ErrorCategory::Conflict)
                .with_retryable(true)
                .with_details(serde_json::json!({
                    "expected": expected_base_revision_id,
                    "actual": active_id,
                })));
            }
            let revision_number = active.as_ref().map_or(1, |item| item.1 + 1);
            let revision_id = format!("{claim_id}-r{revision_number}");
            if let Some(active_id) = active_id {
                transaction.execute(
                    "UPDATE claim_revisions SET lifecycle_status='SUPERSEDED' WHERE revision_id=?",
                    [active_id],
                ).map_err(sql_error)?;
            }
            transaction.execute(
                "INSERT INTO claim_revisions(revision_id, claim_id, revision_number, statement_tex, evidence_status, lifecycle_status, conditions_json, metadata_json, created_at) VALUES(?, ?, ?, ?, 'OPEN', 'ACTIVE', ?, '{}', ?)",
                params![revision_id, claim_id, revision_number, statement_tex.trim(), python_string_array_json(&normalized)?, now],
            ).map_err(sql_error)?;
            Ok(revision_id)
        })?;
        self.get_claim_revision(&revision_id, Some(owner_id))
    }

    pub fn create_project_snapshot(
        &self,
        project_id: &str,
        owner_id: &str,
    ) -> Result<Value, ReCtmError> {
        self.get_project(project_id, Some(owner_id))?;
        let rows = self.query_all(
            "SELECT cr.revision_id, cr.claim_id, cr.revision_number, cr.statement_tex, cr.evidence_status, cr.lifecycle_status, cr.conditions_json, cr.proof_sha256 FROM claim_revisions cr JOIN claims c ON c.claim_id=cr.claim_id WHERE c.project_id=? AND (cr.lifecycle_status='ACTIVE' OR cr.evidence_status IN ('VERIFIED','CONDITIONAL')) ORDER BY cr.claim_id, cr.revision_number",
            [project_id],
            &[],
        )?;
        let mut revisions = Vec::with_capacity(rows.len());
        for row in rows {
            let mut object = row.as_object().cloned().ok_or_else(internal_row_error)?;
            let raw = object
                .remove("conditions_json")
                .and_then(|value| value.as_str().map(ToOwned::to_owned))
                .unwrap_or_else(|| "[]".to_owned());
            object.insert(
                "conditions".to_owned(),
                serde_json::from_str(&raw).map_err(json_error)?,
            );
            revisions.push(Value::Object(object));
        }
        let canonical = canonical_json(&Value::Array(revisions))?;
        let digest = sha256_text(&canonical);
        let snapshot_id = format!("ps-{}", self.runtime.ids.token_hex(8)?);
        let now = self.runtime.clock.now_iso()?;
        self.immediate(|transaction| {
            transaction.execute(
                "INSERT INTO project_snapshots(snapshot_id, project_id, owner_id, revisions_json, snapshot_sha256, created_at) VALUES(?, ?, ?, ?, ?, ?)",
                params![snapshot_id, project_id, owner_id, canonical, digest, now],
            ).map_err(sql_error)?;
            Ok(())
        })?;
        self.get_project_snapshot(&snapshot_id, owner_id)
    }

    pub fn get_project_snapshot(
        &self,
        snapshot_id: &str,
        owner_id: &str,
    ) -> Result<Value, ReCtmError> {
        let mut payload = self
            .query_one(
                "SELECT * FROM project_snapshots WHERE snapshot_id=?",
                [snapshot_id],
                &[],
            )?
            .ok_or_else(|| {
                ReCtmError::new("PROJECT_SNAPSHOT_NOT_FOUND", "Unknown project snapshot.")
                    .with_category(ErrorCategory::NotFound)
            })?;
        let object = payload.as_object_mut().ok_or_else(internal_row_error)?;
        if object.get("owner_id").and_then(Value::as_str) != Some(owner_id) {
            return Err(ReCtmError::new(
                "PROJECT_OWNER_MISMATCH",
                "Project snapshot is not owned by the authenticated principal.",
            )
            .with_category(ErrorCategory::Permission));
        }
        let raw = object
            .remove("revisions_json")
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "[]".to_owned());
        object.insert(
            "revisions".to_owned(),
            serde_json::from_str(&raw).map_err(json_error)?,
        );
        Ok(payload)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn link_run_to_project(
        &self,
        run_id: &str,
        owner_id: &str,
        project_id: &str,
        project_snapshot_id: &str,
        target_claim_id: Option<&str>,
        base_revision_id: Option<&str>,
        requested_workflow_mode: &str,
        effective_workflow_mode: &str,
        register_result: bool,
    ) -> Result<Value, ReCtmError> {
        self.get_project(project_id, Some(owner_id))?;
        self.get_project_snapshot(project_snapshot_id, owner_id)?;
        if let Some(target_claim_id) = target_claim_id {
            let claim = self.get_claim(target_claim_id, Some(owner_id))?;
            if claim.get("project_id").and_then(Value::as_str) != Some(project_id) {
                return Err(ReCtmError::new(
                    "CLAIM_PROJECT_MISMATCH",
                    "Target claim does not belong to the selected project.",
                )
                .with_category(ErrorCategory::Validation));
            }
        }
        let now = self.runtime.clock.now_iso()?;
        self.immediate(|transaction| {
            transaction.execute(
                "INSERT INTO project_runs(run_id, project_id, project_snapshot_id, target_claim_id, base_revision_id, requested_workflow_mode, effective_workflow_mode, register_result, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![run_id, project_id, project_snapshot_id, target_claim_id, base_revision_id, requested_workflow_mode, effective_workflow_mode, i64::from(register_result), now, now],
            ).map_err(sql_error)?;
            Ok(())
        })?;
        Ok(self
            .get_project_run(run_id, Some(owner_id))?
            .unwrap_or(Value::Object(Map::new())))
    }

    pub fn get_project_run(
        &self,
        run_id: &str,
        owner_id: Option<&str>,
    ) -> Result<Option<Value>, ReCtmError> {
        let payload = self.query_one(
            "SELECT * FROM project_runs WHERE run_id=?",
            [run_id],
            &["promotion_json"],
        )?;
        if let (Some(owner_id), Some(payload)) = (owner_id, payload.as_ref()) {
            let project_id = payload
                .get("project_id")
                .and_then(Value::as_str)
                .ok_or_else(internal_row_error)?;
            self.get_project(project_id, Some(owner_id))?;
        }
        Ok(payload)
    }

    pub fn set_project_run_mode(&self, run_id: &str, mode: &str) -> Result<(), ReCtmError> {
        let now = self.runtime.clock.now_iso()?;
        self.immediate(|transaction| {
            transaction
                .execute(
                    "UPDATE project_runs SET effective_workflow_mode=?, updated_at=? WHERE run_id=?",
                    params![mode, now, run_id],
                )
                .map_err(sql_error)?;
            Ok(())
        })
    }

    pub fn write_proof_manifest(
        &self,
        run_id: &str,
        manifest: &Value,
    ) -> Result<Value, ReCtmError> {
        let canonical = canonical_json(manifest)?;
        let digest = sha256_text(&canonical);
        let now = self.runtime.clock.now_iso()?;
        self.immediate(|transaction| {
            transaction.execute(
                "INSERT INTO proof_manifests(run_id, manifest_json, sha256, created_at, updated_at) VALUES(?, ?, ?, ?, ?) ON CONFLICT(run_id) DO UPDATE SET manifest_json=excluded.manifest_json, sha256=excluded.sha256, updated_at=excluded.updated_at",
                params![run_id, canonical, digest, now, now],
            ).map_err(sql_error)?;
            Ok(())
        })?;
        Ok(serde_json::json!({
            "run_id": run_id,
            "manifest": serde_json::from_str::<Value>(&canonical).map_err(json_error)?,
            "sha256": digest,
        }))
    }

    pub fn read_proof_manifest(&self, run_id: &str) -> Result<Value, ReCtmError> {
        let payload = self
            .query_one(
                "SELECT * FROM proof_manifests WHERE run_id=?",
                [run_id],
                &[],
            )?
            .ok_or_else(|| {
                ReCtmError::new("PROOF_MANIFEST_NOT_FOUND", "The run has no proof manifest.")
                    .with_category(ErrorCategory::NotFound)
            })?;
        let raw = payload
            .get("manifest_json")
            .and_then(Value::as_str)
            .ok_or_else(internal_row_error)?;
        Ok(serde_json::json!({
            "run_id": run_id,
            "manifest": serde_json::from_str::<Value>(raw).map_err(json_error)?,
            "sha256": payload.get("sha256").cloned().unwrap_or(Value::Null),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_reference(
        &self,
        run_id: &str,
        project_id: Option<&str>,
        provider: &str,
        identity_key: &str,
        title: &str,
        paper_id: &str,
        arxiv_id: &str,
        doi: &str,
        theorem_id: &str,
        source_uri: &str,
        source_state: &str,
        source_sha256: &str,
        content_sha256: &str,
        metadata: &Value,
    ) -> Result<Value, ReCtmError> {
        if let Some(existing) = self.query_one_params(
            "SELECT reference_id FROM references_registry WHERE run_id=? AND identity_key=?",
            params![run_id, identity_key],
            &[],
        )? {
            let reference_id = existing
                .get("reference_id")
                .and_then(Value::as_str)
                .ok_or_else(internal_row_error)?;
            return self.get_reference(reference_id);
        }
        let reference_id = format!("ref-{}", self.runtime.ids.token_hex(8)?);
        let now = self.runtime.clock.now_iso()?;
        self.immediate(|transaction| {
            transaction.execute(
                "INSERT INTO references_registry(reference_id, run_id, project_id, identity_key, provider, title, paper_id, arxiv_id, doi, theorem_id, source_uri, source_state, source_sha256, content_sha256, metadata_json, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![reference_id, run_id, project_id, identity_key, provider, title, paper_id, arxiv_id, doi, theorem_id, source_uri, source_state, source_sha256, content_sha256, canonical_json(metadata)?, now, now],
            ).map_err(sql_error)?;
            Ok(())
        })?;
        self.get_reference(&reference_id)
    }

    pub fn get_reference(&self, reference_id: &str) -> Result<Value, ReCtmError> {
        self.query_one(
            "SELECT * FROM references_registry WHERE reference_id=?",
            [reference_id],
            &["metadata_json"],
        )?
        .ok_or_else(|| {
            ReCtmError::new("REFERENCE_NOT_FOUND", "Unknown reference.")
                .with_category(ErrorCategory::NotFound)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_source_snapshot(
        &self,
        reference_id: &str,
        provider: &str,
        source_uri: &str,
        content: &str,
        content_type: &str,
        metadata: &Map<String, Value>,
    ) -> Result<Value, ReCtmError> {
        self.get_reference(reference_id)?;
        let digest = sha256_text(content);
        let snapshot_id = format!("source-{}", self.runtime.ids.token_hex(8)?);
        let now = self.runtime.clock.now_iso()?;
        let mut snapshot_metadata = metadata.clone();
        snapshot_metadata.insert("content".to_owned(), Value::String(content.to_owned()));
        self.immediate(|transaction| {
            transaction.execute(
                "INSERT INTO source_snapshots(source_snapshot_id, reference_id, provider, source_uri, content_sha256, content_type, metadata_json, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                params![snapshot_id, reference_id, provider, source_uri, digest, content_type, canonical_json(&Value::Object(snapshot_metadata))?, now],
            ).map_err(sql_error)?;
            transaction.execute(
                "UPDATE references_registry SET source_sha256=?, content_sha256=?, updated_at=? WHERE reference_id=?",
                params![digest, digest, now, reference_id],
            ).map_err(sql_error)?;
            Ok(())
        })?;
        Ok(serde_json::json!({
            "source_snapshot_id": snapshot_id,
            "reference_id": reference_id,
            "content_sha256": digest,
            "source_uri": source_uri,
        }))
    }

    pub fn list_source_snapshots(&self, reference_id: &str) -> Result<Vec<Value>, ReCtmError> {
        self.query_all(
            "SELECT * FROM source_snapshots WHERE reference_id=? ORDER BY created_at",
            [reference_id],
            &["metadata_json"],
        )
    }

    pub fn list_run_references(&self, run_id: &str) -> Result<Vec<Value>, ReCtmError> {
        self.query_all(
            "SELECT * FROM references_registry WHERE run_id=? ORDER BY created_at",
            [run_id],
            &["metadata_json"],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn write_reference_audit(
        &self,
        run_id: &str,
        reference_id: &str,
        disposition: &str,
        evidence_basis: &str,
        evidence_locator: &str,
        verifier_domain_id: &str,
        proof_sha256: &str,
        proof_manifest_sha256: &str,
        material: bool,
        assumptions_checked: bool,
        notation_checked: bool,
        source_checked: bool,
        independently_rederived: bool,
        notes: &str,
    ) -> Result<Value, ReCtmError> {
        let reference = self.get_reference(reference_id)?;
        if reference.get("run_id").and_then(Value::as_str) != Some(run_id) {
            return Err(ReCtmError::new(
                "REFERENCE_RUN_MISMATCH",
                "Reference does not belong to this run.",
            )
            .with_category(ErrorCategory::Permission));
        }
        if !matches!(
            disposition,
            "SOURCE_VERIFIED" | "INDEPENDENTLY_REDERIVED" | "UNRESOLVED" | "NOT_MATERIAL"
        ) {
            return Err(ReCtmError::new(
                "INVALID_REFERENCE_DISPOSITION",
                "Unsupported reference audit disposition.",
            )
            .with_category(ErrorCategory::Validation));
        }
        let now = self.runtime.clock.now_iso()?;
        self.immediate(|transaction| {
            transaction.execute(
                "INSERT INTO reference_audits(run_id, reference_id, disposition, evidence_basis, evidence_locator, verifier_domain_id, proof_sha256, proof_manifest_sha256, material, assumptions_checked, notation_checked, source_checked, independently_rederived, notes, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(run_id, reference_id) DO UPDATE SET disposition=excluded.disposition, evidence_basis=excluded.evidence_basis, evidence_locator=excluded.evidence_locator, verifier_domain_id=excluded.verifier_domain_id, proof_sha256=excluded.proof_sha256, proof_manifest_sha256=excluded.proof_manifest_sha256, material=excluded.material, assumptions_checked=excluded.assumptions_checked, notation_checked=excluded.notation_checked, source_checked=excluded.source_checked, independently_rederived=excluded.independently_rederived, notes=excluded.notes, updated_at=excluded.updated_at",
                params![run_id, reference_id, disposition, evidence_basis, evidence_locator, verifier_domain_id, proof_sha256, proof_manifest_sha256, i64::from(material), i64::from(assumptions_checked), i64::from(notation_checked), i64::from(source_checked), i64::from(independently_rederived), notes, now, now],
            ).map_err(sql_error)?;
            Ok(())
        })?;
        self.get_reference_audit(run_id, reference_id)
    }

    pub fn get_reference_audit(
        &self,
        run_id: &str,
        reference_id: &str,
    ) -> Result<Value, ReCtmError> {
        self.query_one_params(
            "SELECT * FROM reference_audits WHERE run_id=? AND reference_id=?",
            params![run_id, reference_id],
            &[],
        )?
        .ok_or_else(|| {
            ReCtmError::new(
                "REFERENCE_AUDIT_NOT_FOUND",
                "Reference has not been audited.",
            )
            .with_category(ErrorCategory::NotFound)
        })
    }

    pub fn list_reference_audits(&self, run_id: &str) -> Result<Vec<Value>, ReCtmError> {
        self.query_all(
            "SELECT ra.*, rr.title, rr.paper_id, rr.arxiv_id, rr.doi, rr.theorem_id, rr.source_uri, rr.source_state, rr.source_sha256, rr.content_sha256 FROM reference_audits ra JOIN references_registry rr ON rr.reference_id=ra.reference_id WHERE ra.run_id=? ORDER BY ra.audit_id",
            [run_id],
            &[],
        )
    }

    pub fn promote_verified_run(
        &self,
        run_id: &str,
        owner_id: &str,
        statement_tex: &str,
        proof_sha256: &str,
        effective_conditions: &[String],
        manifest: &Value,
    ) -> Result<Value, ReCtmError> {
        let Some(project_run) = self.get_project_run(run_id, Some(owner_id))? else {
            return Ok(serde_json::json!({"status": "not_requested"}));
        };
        let register_result = project_run
            .get("register_result")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let target_claim_id = project_run.get("target_claim_id").and_then(Value::as_str);
        if !register_result || target_claim_id.is_none() {
            let result = serde_json::json!({"status": "not_requested"});
            let now = self.runtime.clock.now_iso()?;
            self.immediate(|transaction| {
                transaction.execute(
                    "UPDATE project_runs SET promotion_status='not_requested', promotion_json=?, updated_at=? WHERE run_id=?",
                    params![canonical_json(&result)?, now, run_id],
                ).map_err(sql_error)?;
                Ok(())
            })?;
            return Ok(result);
        }
        if let Some(promoted_revision_id) = project_run
            .get("promoted_revision_id")
            .and_then(Value::as_str)
        {
            return Ok(serde_json::json!({
                "status": "already_promoted",
                "revision": self.get_claim_revision(promoted_revision_id, Some(owner_id))?,
            }));
        }
        let claim_id = target_claim_id.ok_or_else(internal_row_error)?;
        let current = self.current_claim_revision(claim_id, owner_id)?;
        let expected_base = project_run.get("base_revision_id").and_then(Value::as_str);
        let current_id = current
            .as_ref()
            .and_then(|value| value.get("revision_id"))
            .and_then(Value::as_str);
        if current_id != expected_base {
            let conflict = serde_json::json!({
                "status": "conflict",
                "expected_base_revision_id": expected_base,
                "current_revision_id": current_id,
            });
            let now = self.runtime.clock.now_iso()?;
            self.immediate(|transaction| {
                transaction.execute(
                    "UPDATE project_runs SET promotion_status='conflict', promotion_json=?, updated_at=? WHERE run_id=?",
                    params![canonical_json(&conflict)?, now, run_id],
                ).map_err(sql_error)?;
                Ok(())
            })?;
            return Ok(conflict);
        }
        let mut conditions = effective_conditions
            .iter()
            .map(|item| item.trim())
            .filter(|item| !item.is_empty())
            .map(ToOwned::to_owned)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        conditions.sort();
        let evidence_status = if conditions.is_empty() {
            "VERIFIED"
        } else {
            "CONDITIONAL"
        };
        let dependencies = manifest
            .get("dependency_revision_ids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let now = self.runtime.clock.now_iso()?;
        let project_id = project_run
            .get("project_id")
            .and_then(Value::as_str)
            .ok_or_else(internal_row_error)?;
        let revision_id = self.immediate(|transaction| {
            let active: Option<(String, i64)> = transaction
                .query_row(
                    "SELECT revision_id, revision_number FROM claim_revisions WHERE claim_id=? AND lifecycle_status='ACTIVE' ORDER BY revision_number DESC LIMIT 1",
                    [claim_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(sql_error)?;
            let active_id = active.as_ref().map(|item| item.0.as_str());
            if active_id != expected_base {
                let conflict = serde_json::json!({
                    "status": "conflict",
                    "expected_base_revision_id": expected_base,
                    "current_revision_id": active_id,
                });
                transaction.execute(
                    "UPDATE project_runs SET promotion_status='conflict', promotion_json=?, updated_at=? WHERE run_id=?",
                    params![canonical_json(&conflict)?, now, run_id],
                ).map_err(sql_error)?;
                return Ok((None, Some(conflict)));
            }
            let revision_number = active.as_ref().map_or(1, |item| item.1 + 1);
            let revision_id = format!("{claim_id}-r{revision_number}");
            if let Some(active_id) = active_id {
                transaction.execute(
                    "UPDATE claim_revisions SET lifecycle_status='SUPERSEDED' WHERE revision_id=?",
                    [active_id],
                ).map_err(sql_error)?;
            }
            transaction.execute(
                "INSERT INTO claim_revisions(revision_id, claim_id, revision_number, statement_tex, evidence_status, lifecycle_status, source_run_id, proof_sha256, conditions_json, metadata_json, created_at) VALUES(?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?)",
                params![revision_id, claim_id, revision_number, statement_tex, evidence_status, run_id, proof_sha256, python_string_array_json(&conditions)?, canonical_json(&serde_json::json!({"workflow_protocol_version": 2}))?, now],
            ).map_err(sql_error)?;
            for dependency_id in &dependencies {
                let exists: Option<String> = transaction.query_row(
                    "SELECT cr.revision_id FROM claim_revisions cr JOIN claims c ON c.claim_id=cr.claim_id WHERE cr.revision_id=? AND c.project_id=?",
                    params![dependency_id, project_id],
                    |row| row.get(0),
                ).optional().map_err(sql_error)?;
                if exists.is_none() {
                    return Err(ReCtmError::new(
                        "DEPENDENCY_NOT_IN_PROJECT",
                        "Proof manifest dependency is not a revision in the project.",
                    )
                    .with_category(ErrorCategory::Validation)
                    .with_details(serde_json::json!({"revision_id": dependency_id})));
                }
                transaction.execute(
                    "INSERT OR IGNORE INTO claim_edges(project_id, from_revision_id, to_revision_id, edge_type, created_at) VALUES(?, ?, ?, 'depends_on', ?)",
                    params![project_id, revision_id, dependency_id, now],
                ).map_err(sql_error)?;
            }
            if let Some(active_id) = active_id {
                transaction.execute(
                    "INSERT OR IGNORE INTO claim_edges(project_id, from_revision_id, to_revision_id, edge_type, created_at) VALUES(?, ?, ?, 'supersedes', ?)",
                    params![project_id, revision_id, active_id, now],
                ).map_err(sql_error)?;
            }
            let promotion = serde_json::json!({"status": "promoted", "revision_id": revision_id});
            transaction.execute(
                "UPDATE project_runs SET promotion_status='promoted', promoted_revision_id=?, promotion_json=?, updated_at=? WHERE run_id=?",
                params![revision_id, canonical_json(&promotion)?, now, run_id],
            ).map_err(sql_error)?;
            Ok((Some(revision_id), None))
        })?;
        if let Some(conflict) = revision_id.1 {
            return Ok(conflict);
        }
        let revision_id = revision_id.0.ok_or_else(internal_row_error)?;
        Ok(serde_json::json!({
            "status": "promoted",
            "revision": self.get_claim_revision(&revision_id, Some(owner_id))?,
        }))
    }

    pub fn project_dependency_graph(
        &self,
        project_id: &str,
        owner_id: &str,
    ) -> Result<Value, ReCtmError> {
        let project = self.get_project(project_id, Some(owner_id))?;
        let claims = self.list_claims(project_id, owner_id)?;
        let mut revisions = Vec::new();
        for claim in &claims {
            let claim_id = claim
                .get("claim_id")
                .and_then(Value::as_str)
                .ok_or_else(internal_row_error)?;
            revisions.extend(self.list_claim_revisions(claim_id, owner_id)?);
        }
        let edges = self.query_all(
            "SELECT * FROM claim_edges WHERE project_id=? ORDER BY edge_id",
            [project_id],
            &[],
        )?;
        Ok(serde_json::json!({
            "project": project,
            "claims": claims,
            "revisions": revisions,
            "edges": edges,
        }))
    }

    pub fn database_snapshot(&self) -> Result<Value, ReCtmError> {
        let connection = self.lock_connection()?;
        let user_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(sql_error)?;
        let mut statement = connection
            .prepare(
                "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .map_err(sql_error)?;
        let table_records = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })
            .map_err(sql_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql_error)?;
        drop(statement);
        let mut tables = BTreeMap::new();
        let mut schemas = BTreeMap::new();
        for (name, schema) in table_records {
            if !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                return Err(ReCtmError::new(
                    "STATE_SCHEMA_INVALID",
                    "State database contains an unsafe table identifier.",
                )
                .with_category(ErrorCategory::Internal));
            }
            let query = format!("SELECT * FROM \"{name}\"");
            let mut rows = query_all_raw_on(&connection, &query, [])?;
            rows.sort_by_key(|value| serde_json::to_string(value).unwrap_or_default());
            tables.insert(name.clone(), Value::Array(rows));
            schemas.insert(
                name,
                Value::String(normalize_sql(schema.as_deref().unwrap_or(""))),
            );
        }
        Ok(serde_json::json!({
            "user_version": user_version,
            "schemas": schemas,
            "tables": tables,
        }))
    }

    pub fn database_digest(&self) -> Result<Value, ReCtmError> {
        let snapshot = self.database_snapshot()?;
        let table_count = snapshot
            .get("tables")
            .and_then(Value::as_object)
            .map_or(0, Map::len);
        let schema_count = snapshot
            .get("schemas")
            .and_then(Value::as_object)
            .map_or(0, Map::len);
        let content_sha256 = sha256_text(&canonical_json(&snapshot)?);
        Ok(serde_json::json!({
            "user_version": snapshot.get("user_version").cloned().unwrap_or(Value::Null),
            "table_count": table_count,
            "schema_count": schema_count,
            "content_sha256": content_sha256,
        }))
    }

    pub fn checkpoint(&self) -> Result<(), ReCtmError> {
        let connection = self.lock_connection()?;
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(sql_error)
    }

    fn query_one<const N: usize>(
        &self,
        query: &str,
        values: [&str; N],
        json_fields: &[&str],
    ) -> Result<Option<Value>, ReCtmError> {
        let connection = self.lock_connection()?;
        query_one_on(&connection, query, values, json_fields)
    }

    fn query_one_params(
        &self,
        query: &str,
        values: impl rusqlite::Params,
        json_fields: &[&str],
    ) -> Result<Option<Value>, ReCtmError> {
        let connection = self.lock_connection()?;
        query_one_on_params(&connection, query, values, json_fields)
    }

    fn query_all<const N: usize>(
        &self,
        query: &str,
        values: [&str; N],
        json_fields: &[&str],
    ) -> Result<Vec<Value>, ReCtmError> {
        let connection = self.lock_connection()?;
        query_all_on(&connection, query, values, json_fields)
    }

    fn query_all_params(
        &self,
        query: &str,
        values: impl rusqlite::Params,
        json_fields: &[&str],
    ) -> Result<Vec<Value>, ReCtmError> {
        let connection = self.lock_connection()?;
        query_all_on_params(&connection, query, values, json_fields)
    }
}

pub struct TransitionRun<'a> {
    pub run_id: &'a str,
    pub expected_state: &'a str,
    pub after_state: &'a str,
    pub trace_id: &'a str,
    pub actor: &'a str,
    pub reason: &'a str,
    pub evidence: &'a Value,
    pub increment_epoch: bool,
    pub status: Option<&'a str>,
    pub latex_passed: Option<bool>,
    pub verdict: Option<&'a str>,
    pub sealed: Option<bool>,
    pub round_delta: i64,
}

fn query_one_on<const N: usize>(
    connection: &Connection,
    query: &str,
    values: [&str; N],
    json_fields: &[&str],
) -> Result<Option<Value>, ReCtmError> {
    query_one_on_params(
        connection,
        query,
        rusqlite::params_from_iter(values),
        json_fields,
    )
}

fn query_one_on_params(
    connection: &Connection,
    query: &str,
    values: impl rusqlite::Params,
    json_fields: &[&str],
) -> Result<Option<Value>, ReCtmError> {
    let mut statement = connection.prepare(query).map_err(sql_error)?;
    statement
        .query_row(values, row_to_json)
        .optional()
        .map_err(sql_error)?
        .map(|value| normalize_row(value, json_fields))
        .transpose()
}

fn query_all_on<const N: usize>(
    connection: &Connection,
    query: &str,
    values: [&str; N],
    json_fields: &[&str],
) -> Result<Vec<Value>, ReCtmError> {
    query_all_on_params(
        connection,
        query,
        rusqlite::params_from_iter(values),
        json_fields,
    )
}

fn query_all_on_params(
    connection: &Connection,
    query: &str,
    values: impl rusqlite::Params,
    json_fields: &[&str],
) -> Result<Vec<Value>, ReCtmError> {
    let mut statement = connection.prepare(query).map_err(sql_error)?;
    let rows = statement
        .query_map(values, row_to_json)
        .map_err(sql_error)?;
    rows.map(|row| {
        row.map_err(sql_error)
            .and_then(|value| normalize_row(value, json_fields))
    })
    .collect()
}

fn query_all_raw_on<const N: usize>(
    connection: &Connection,
    query: &str,
    values: [&str; N],
) -> Result<Vec<Value>, ReCtmError> {
    query_all_raw_on_params(connection, query, rusqlite::params_from_iter(values))
}

fn query_all_raw_on_params(
    connection: &Connection,
    query: &str,
    values: impl rusqlite::Params,
) -> Result<Vec<Value>, ReCtmError> {
    let mut statement = connection.prepare(query).map_err(sql_error)?;
    let rows = statement
        .query_map(values, row_to_json)
        .map_err(sql_error)?;
    rows.map(|row| row.map_err(sql_error)).collect()
}

fn row_to_json(row: &Row<'_>) -> rusqlite::Result<Value> {
    let reference = row.as_ref();
    let mut object = Map::new();
    for index in 0..reference.column_count() {
        let name = reference.column_name(index)?.to_owned();
        let value = match row.get_ref(index)? {
            ValueRef::Null => Value::Null,
            ValueRef::Integer(value) => Value::from(value),
            ValueRef::Real(value) => Value::from(value),
            ValueRef::Text(value) => Value::String(String::from_utf8_lossy(value).into_owned()),
            ValueRef::Blob(value) => Value::String(URL_SAFE_NO_PAD.encode(value)),
        };
        object.insert(name, value);
    }
    Ok(Value::Object(object))
}

fn normalize_row(mut value: Value, json_fields: &[&str]) -> Result<Value, ReCtmError> {
    let object = value.as_object_mut().ok_or_else(internal_row_error)?;
    for field in json_fields {
        let raw = object.remove(*field).unwrap_or(Value::Null);
        let text = raw.as_str().unwrap_or("");
        let parsed = if text.is_empty() {
            Value::Object(Map::new())
        } else {
            serde_json::from_str(text).map_err(json_error)?
        };
        let name = field.strip_suffix("_json").unwrap_or(field).to_owned();
        object.insert(name, parsed);
    }
    for boolean in [
        "revoked",
        "sealed",
        "latex_passed",
        "consumed",
        "register_result",
        "material",
        "assumptions_checked",
        "notation_checked",
        "source_checked",
        "independently_rederived",
    ] {
        if let Some(raw) = object.get_mut(boolean) {
            if let Some(number) = raw.as_i64() {
                *raw = Value::Bool(number != 0);
            }
        }
    }
    Ok(value)
}

fn canonical_json(value: &Value) -> Result<String, ReCtmError> {
    serde_json::to_string(value).map_err(json_error)
}

fn parse_object_or_empty(raw: &str) -> Map<String, Value> {
    serde_json::from_str(raw)
        .ok()
        .and_then(|value: Value| value.as_object().cloned())
        .unwrap_or_default()
}

fn validate_registry_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= REGISTRY_ID_MAX_BYTES
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn sha256_text(value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(value.as_bytes());
    format!("{:x}", digest.finalize())
}

fn normalize_sql(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn python_string_array_json(values: &[String]) -> Result<String, ReCtmError> {
    let encoded = values
        .iter()
        .map(|value| serde_json::to_string(value).map_err(json_error))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(format!("[{}]", encoded.join(", ")))
}

fn text_value<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, ReCtmError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(internal_row_error)
}

fn optional_text_value(object: &Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn integer_value(object: &Map<String, Value>, key: &str) -> Result<i64, ReCtmError> {
    object
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(internal_row_error)
}

fn boolean_storage_value(object: &Map<String, Value>, key: &str) -> Result<i64, ReCtmError> {
    match object.get(key) {
        Some(Value::Bool(value)) => Ok(i64::from(*value)),
        Some(value) => value.as_i64().ok_or_else(internal_row_error),
        None => Err(internal_row_error()),
    }
}

fn internal_row_error() -> ReCtmError {
    ReCtmError::new(
        "STATE_ROW_INVALID",
        "State database row has an invalid shape.",
    )
    .with_category(ErrorCategory::Internal)
}

fn json_error(error: serde_json::Error) -> ReCtmError {
    ReCtmError::new("STATE_JSON_INVALID", error.to_string()).with_category(ErrorCategory::Internal)
}

fn io_error(error: std::io::Error) -> ReCtmError {
    ReCtmError::new("STATE_IO_ERROR", error.to_string()).with_category(ErrorCategory::Runtime)
}

fn sql_error(error: rusqlite::Error) -> ReCtmError {
    ReCtmError::new("SQLITE_ERROR", error.to_string()).with_category(ErrorCategory::Internal)
}

fn is_constraint(error: &ReCtmError) -> bool {
    error.code == "SQLITE_ERROR" && error.message.to_ascii_lowercase().contains("constraint")
}
