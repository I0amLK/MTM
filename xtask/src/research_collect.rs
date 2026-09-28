//! Private, read-only collection of one sealed research run into a precheck bundle.
use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{Result, evidence_json, native_preflight::process, research_precheck};

const FILE_LIMIT: u64 = 4 * 1024 * 1024;
const JSON_LIMIT: u64 = 1024 * 1024;

pub(crate) struct Options {
    session: PathBuf,
    run_id: String,
    sqlite: PathBuf,
}

impl Options {
    pub(crate) fn parse(args: &[String]) -> Result<Self> {
        if args.len() != 6
            || args[0] != "--session"
            || args[2] != "--run-id"
            || args[4] != "--sqlite"
        {
            return Err(
                "use research-collect --session <absolute-private-session> --run-id <run-id> --sqlite <absolute-sqlite3>"
                    .into(),
            );
        }
        let session = PathBuf::from(&args[1]);
        let sqlite = PathBuf::from(&args[5]);
        if !session.is_absolute() || !safe_id(&args[3], 256) || !sqlite.is_absolute() {
            return Err("research collection selector is invalid".into());
        }
        Ok(Self {
            session,
            run_id: args[3].clone(),
            sqlite,
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionManifest {
    schema: String,
    milestone: String,
    task_id: String,
    repeat: u8,
    case_id: String,
    workflow_mode: String,
    trial_id: String,
    candidate_sha256: String,
    candidate_source_commit: String,
    launcher_source_commit: String,
    launcher_sha256: String,
    case_registry_sha256: String,
    corpus_sha256: String,
    native_mode: String,
    latex_policy: String,
    session_prepared: bool,
    runtime_executed: bool,
    independent_review_recorded: bool,
    research_trial_passed: bool,
    release_qualified: bool,
}

struct RunEvidence {
    status: Value,
    owner_id: String,
    metadata: Value,
    transitions: Vec<Value>,
    manifest: Value,
    manifest_sha256: String,
    reference_audit: Value,
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_id(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn require(condition: bool, message: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn session_root_milestone(path: &Path) -> Result<&'static str> {
    let parts = path
        .components()
        .filter_map(|part| match part {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mtm016 = parts
        .windows(3)
        .any(|window| window == [".mtm-acceptance", "MTM-016", "research"]);
    let mtm017 = parts
        .windows(3)
        .any(|window| window == [".mtm-acceptance", "MTM-017", "research"]);
    match (mtm016, mtm017) {
        (true, false) => Ok("MTM-016"),
        (false, true) => Ok("MTM-017"),
        _ => Err("session is outside one exact versioned research root".into()),
    }
}

fn validate_session_path(path: &Path) -> Result<PathBuf> {
    require(
        path.is_absolute()
            && path != Path::new("/")
            && path.as_os_str().len() <= 4096
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "research session path must be absolute and non-traversing",
    )?;
    let canonical = path
        .canonicalize()
        .map_err(|_| "research session is unavailable")?;
    require(
        canonical == path,
        "research session path contains indirection",
    )?;
    session_root_milestone(path)?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("research session has no valid name")?;
    let (prefix, suffix) = name
        .rsplit_once('.')
        .ok_or("research session name is malformed")?;
    let task_repeat = prefix.split('-').collect::<Vec<_>>();
    require(
        task_repeat.len() == 2
            && matches!(task_repeat[0], "U21" | "U22" | "U23" | "U24" | "U25")
            && matches!(task_repeat[1], "r1" | "r2" | "r3")
            && suffix.len() == 8
            && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric()),
        "research session name is outside the fixed corpus",
    )?;
    private_directory(path)?;
    Ok(canonical)
}

fn private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "private directory unavailable")?;
    require(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.mode() & 0o7777 == 0o700,
        "research directory must be owner-private mode 0700",
    )
}

fn read_file(path: &Path, limit: u64, owner: u32) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "research input unavailable")?;
    require(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.nlink() == 1
            && metadata.uid() == owner
            && metadata.mode() & 0o6022 == 0
            && metadata.len() > 0
            && metadata.len() <= limit,
        "research input must be bounded, owned and non-writable by group/other",
    )?;
    let mut file = File::open(path).map_err(|_| "research input cannot be opened")?;
    let before = file
        .metadata()
        .map_err(|_| "research input metadata unavailable")?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "research input read failed")?;
    let after = file
        .metadata()
        .map_err(|_| "research input metadata unavailable")?;
    require(
        bytes.len() as u64 == before.len()
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(),
        "research input changed during read",
    )?;
    Ok(bytes)
}

fn strict_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_value(evidence_json::decode(bytes)?)
        .map_err(|_| "research collection JSON schema mismatch".into())
}

fn validate_session_manifest(
    value: &SessionManifest,
    session_name: &str,
    root_milestone: &str,
) -> Result<()> {
    let policy = research_precheck::research_policy_for(&value.milestone, &value.task_id)?;
    let identity = research_precheck::research_identity(&value.milestone)?;
    let expected_mode = if matches!(value.task_id.as_str(), "U21" | "U23") {
        "compact"
    } else {
        "full"
    };
    let expected_prefix = format!("{}-r{}.", value.task_id, value.repeat);
    require(
        value.schema == policy.session_schema
            && root_milestone == identity.acceptance_root
            && value.milestone == identity.milestone
            && matches!(
                value.task_id.as_str(),
                "U21" | "U22" | "U23" | "U24" | "U25"
            )
            && (1..=3).contains(&value.repeat)
            && value.case_id.starts_with(&format!(
                "{}-r{}-",
                value.task_id.to_lowercase(),
                value.repeat
            ))
            && value.workflow_mode == expected_mode
            && hex(&value.trial_id, 32)
            && value.candidate_sha256 == identity.candidate_sha256
            && value.candidate_source_commit == identity.candidate_source_commit
            && hex(&value.launcher_source_commit, 40)
            && hex(&value.launcher_sha256, 64)
            && value.case_registry_sha256 == research_precheck::REGISTRY_SHA
            && value.corpus_sha256 == research_precheck::CORPUS_SHA
            && value.native_mode == policy.native_mode
            && value.latex_policy == "required"
            && value.session_prepared
            && !value.runtime_executed
            && !value.independent_review_recorded
            && !value.research_trial_passed
            && !value.release_qualified
            && session_name.starts_with(&expected_prefix),
        "research session identity or immutable preparation policy mismatch",
    )
}

struct SqliteTool {
    path: PathBuf,
    sha256: String,
    version: String,
}

fn executable_digest(path: &Path, limit: u64) -> Result<String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "sqlite3 executable unavailable")?;
    require(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() > 0
            && metadata.len() <= limit
            && metadata.mode() & 0o111 != 0
            && metadata.mode() & 0o6000 == 0,
        "sqlite3 must resolve to a bounded regular executable",
    )?;
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        require(total <= limit, "sqlite3 executable grew beyond its bound")?;
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_sqlite(path: &Path) -> Result<SqliteTool> {
    require(
        path.is_absolute()
            && path.as_os_str().len() <= 4096
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "sqlite3 selector must be an absolute non-traversing path",
    )?;
    let canonical = path
        .canonicalize()
        .map_err(|_| "sqlite3 executable unavailable")?;
    let name = canonical
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("sqlite3 executable name unavailable")?;
    require(name == "sqlite3", "selected database tool is not sqlite3")?;
    let sha256 = executable_digest(&canonical, 64 * 1024 * 1024)?;
    let mut command = Command::new(&canonical);
    command
        .arg("--version")
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .current_dir("/");
    let output = process::capture_command(&mut command, Duration::from_secs(5), 4096, true)?;
    require(
        output.complete() && output.stderr.is_empty(),
        "sqlite3 version probe failed",
    )?;
    let version = std::str::from_utf8(&output.stdout)
        .map_err(|_| "sqlite3 version output is not UTF-8")?
        .trim();
    require(
        !version.is_empty() && version.len() <= 512,
        "sqlite3 version output is invalid",
    )?;
    Ok(SqliteTool {
        path: canonical,
        sha256,
        version: version.to_owned(),
    })
}

fn validate_database(path: &Path, owner: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "research state database unavailable")?;
    require(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.nlink() == 1
            && metadata.uid() == owner
            && metadata.mode() & 0o0022 == 0,
        "research state database must be an owned non-writable regular file",
    )
}

fn sqlite_json(tool: &SqliteTool, database: &Path, sql: &str) -> Result<Value> {
    require(
        sql.len() <= 65_536 && !sql.contains('\0'),
        "sqlite query exceeds fixed collector bounds",
    )?;
    let database = database
        .to_str()
        .ok_or("research database path is not UTF-8")?;
    let mut command = Command::new(&tool.path);
    command
        .args(["-readonly", "-json", "-batch", database, sql])
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .current_dir("/");
    let output = process::capture_command(
        &mut command,
        Duration::from_secs(10),
        JSON_LIMIT as usize,
        true,
    )?;
    require(
        output.complete() && output.stderr.is_empty(),
        "read-only sqlite3 query failed",
    )?;
    if output.stdout.is_empty() {
        return Ok(Value::Array(Vec::new()));
    }
    evidence_json::decode(&output.stdout)
}

fn rows(value: Value) -> Result<Vec<Value>> {
    value
        .as_array()
        .cloned()
        .ok_or_else(|| "sqlite3 JSON result must be an array".into())
}

fn exactly_one(value: Value, message: &'static str) -> Result<Value> {
    let mut values = rows(value)?;
    require(values.len() == 1, message)?;
    values.pop().ok_or_else(|| message.into())
}

fn bool_field(value: &Value, key: &str) -> Result<bool> {
    match value[key].as_i64() {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err("sqlite boolean field is invalid".into()),
    }
}

fn collect_database(
    tool: &SqliteTool,
    database: &Path,
    run_id: &str,
    include_references: bool,
    expected_schema_version: u64,
) -> Result<RunEvidence> {
    require(safe_id(run_id, 256), "unsafe research run id")?;
    let version = exactly_one(
        sqlite_json(tool, database, "PRAGMA query_only=ON; PRAGMA user_version;")?,
        "research schema version result is invalid",
    )?;
    require(
        version["user_version"] == expected_schema_version,
        "research state schema does not match the versioned research identity",
    )?;
    let run_sql = format!(
        "PRAGMA query_only=ON; SELECT problem_id,owner_id,state,status,round_index,transition_seq,latex_passed,verdict,sealed,metadata_json FROM runs WHERE run_id='{run_id}';"
    );
    let run = exactly_one(
        sqlite_json(tool, database, &run_sql)?,
        "selected research run is absent or ambiguous",
    )?;
    let metadata_text = run["metadata_json"]
        .as_str()
        .ok_or("research run metadata is not text")?;
    let metadata: Value = evidence_json::decode(metadata_text.as_bytes())?;
    let owner_id = run["owner_id"]
        .as_str()
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or("research run owner is invalid")?
        .to_owned();
    let pending_sql = format!(
        "PRAGMA query_only=ON; SELECT COUNT(*) AS pending FROM step_receipts WHERE run_id='{run_id}' AND status='pending';"
    );
    let pending = exactly_one(
        sqlite_json(tool, database, &pending_sql)?,
        "pending-submission count is invalid",
    )?;
    require(
        pending["pending"] == 0,
        "sealed research run still has a pending submission",
    )?;
    let status = json!({
        "ok":true,"run_id":run_id,"problem_id":run["problem_id"],"state":run["state"],
        "status":run["status"],"round_index":run["round_index"],"transition_seq":run["transition_seq"],
        "latex_passed":bool_field(&run,"latex_passed")?,"verdict":run["verdict"],
        "sealed":bool_field(&run,"sealed")?,"manual_validation_required":true,
        "pending_submission":Value::Null
    });

    let transition_sql = format!(
        "PRAGMA query_only=ON; SELECT sequence,before_state,after_state,actor,reason,evidence_json,created_at FROM transitions WHERE run_id='{run_id}' ORDER BY sequence;"
    );
    let transition_rows = rows(sqlite_json(tool, database, &transition_sql)?)?;
    require(
        !transition_rows.is_empty() && transition_rows.len() <= 256,
        "research transition log is empty or oversized",
    )?;
    let mut transitions = Vec::with_capacity(transition_rows.len());
    for row in transition_rows {
        let evidence = row["evidence_json"]
            .as_str()
            .ok_or("transition evidence is not text")?;
        transitions.push(json!({
            "run_id":run_id,"sequence":row["sequence"],"before_state":row["before_state"],
            "after_state":row["after_state"],"actor":row["actor"],"reason":row["reason"],
            "evidence":evidence_json::decode(evidence.as_bytes())?,"created_at":row["created_at"]
        }));
    }

    let manifest_sql = format!(
        "PRAGMA query_only=ON; SELECT manifest_json,sha256 FROM proof_manifests WHERE run_id='{run_id}';"
    );
    let manifest_row = exactly_one(
        sqlite_json(tool, database, &manifest_sql)?,
        "selected research run has no unique proof manifest",
    )?;
    let manifest_text = manifest_row["manifest_json"]
        .as_str()
        .ok_or("proof manifest is not text")?;
    let manifest_sha256 = manifest_row["sha256"]
        .as_str()
        .ok_or("proof manifest digest is missing")?
        .to_owned();
    require(
        hash(manifest_text.as_bytes()) == manifest_sha256,
        "proof manifest database digest mismatch",
    )?;
    let manifest = evidence_json::decode(manifest_text.as_bytes())?;

    let reference_audit = if include_references {
        let references_sql = format!(
            "PRAGMA query_only=ON; SELECT reference_id,provider,title,paper_id,arxiv_id,doi,theorem_id,source_uri,source_state,source_sha256,content_sha256 FROM references_registry WHERE run_id='{run_id}' ORDER BY reference_id;"
        );
        let references = rows(sqlite_json(tool, database, &references_sql)?)?;
        let audits_sql = format!(
            "PRAGMA query_only=ON; SELECT reference_id,disposition,evidence_basis,evidence_locator,verifier_domain_id,proof_sha256,proof_manifest_sha256,material,assumptions_checked,notation_checked,source_checked,independently_rederived,notes FROM reference_audits WHERE run_id='{run_id}' ORDER BY reference_id;"
        );
        let mut audits = rows(sqlite_json(tool, database, &audits_sql)?)?;
        for audit in &mut audits {
            for key in [
                "material",
                "assumptions_checked",
                "notation_checked",
                "source_checked",
                "independently_rederived",
            ] {
                audit[key] = Value::Bool(bool_field(audit, key)?);
            }
        }
        json!({"references":references,"audits":audits})
    } else {
        json!({"references":[],"audits":[]})
    };
    Ok(RunEvidence {
        status,
        owner_id,
        metadata,
        transitions,
        manifest,
        manifest_sha256,
        reference_audit,
    })
}

fn pretty(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn evidence_fingerprint(value: &RunEvidence) -> Result<String> {
    Ok(hash(&serde_json::to_vec(&json!({
        "status":value.status,"transitions":value.transitions,"manifest":value.manifest,
        "manifest_sha256":value.manifest_sha256,"reference_audit":value.reference_audit,
        "metadata":value.metadata,"owner_sha256":hash(value.owner_id.as_bytes())
    }))?))
}

fn fixed_input_names(task: &str) -> Result<Vec<(&'static str, &'static str)>> {
    let mut values = vec![("review", "review.json")];
    values.extend(match task {
        "U21" => vec![],
        "U22" => vec![("retrieval", "retrieval.json"), ("sources", "sources.json")],
        "U23" => vec![
            ("seeded_draft", "seeded_draft.tex"),
            ("first_findings", "first_findings.json"),
            ("repair_history", "repair_history.json"),
        ],
        "U24" => vec![("branches", "branches.json")],
        "U25" => vec![
            ("sage_input", "sage_input.txt"),
            ("sage_output", "sage_output.txt"),
            ("magma_input", "magma_input.txt"),
            ("magma_output", "magma_output.txt"),
            ("cas_observation", "cas_observation.json"),
        ],
        _ => return Err("research collection task is outside U21-U25".into()),
    });
    Ok(values)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn copy_input(session: &Path, name: &str, owner: u32) -> Result<Vec<u8>> {
    let root = session.join("workspace/research-evidence-input");
    private_directory(&session.join("workspace"))?;
    let metadata =
        fs::symlink_metadata(&root).map_err(|_| "research evidence input directory missing")?;
    require(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == owner
            && metadata.mode() & 0o0022 == 0,
        "research evidence input directory is unsafe",
    )?;
    read_file(
        &root.join(name),
        if name.ends_with(".json") {
            JSON_LIMIT
        } else {
            FILE_LIMIT
        },
        owner,
    )
}

fn compiler_material(transitions: &[Value], final_tex: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let gate = transitions
        .iter()
        .rev()
        .find(|row| row["before_state"] == "latex_validate" && row["after_state"] == "verify")
        .ok_or("research run has no successful compiler-to-verifier transition")?;
    let evidence = &gate["evidence"];
    let output = evidence["compiler_output"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or("compiler output is absent")?;
    require(
        evidence["policy"] == "required"
            && evidence["static_valid"] == true
            && evidence["compile_attempted"] == true
            && evidence["compile_available"] == true
            && evidence["compile_passed"] == true
            && evidence["gate_passed"] == true
            && evidence["errors"].as_array().is_some_and(Vec::is_empty),
        "required LaTeX compiler transition did not pass",
    )?;
    let output_bytes = output.as_bytes().to_vec();
    let compiler = pretty(&json!({
        "schema":"mtm-research-compiler-observation-v1",
        "run_id":gate["run_id"],"policy":"required","program":"latexmk","exit_code":0,
        "source_sha256":hash(final_tex),"output_sha256":hash(&output_bytes),
        "derived_from_transition_sequence":gate["sequence"]
    }))?;
    Ok((compiler, output_bytes))
}

fn validate_review(
    bytes: &[u8],
    run_id: &str,
    trial_id: &str,
    owner: &str,
    final_tex: &[u8],
    report: &[u8],
) -> Result<()> {
    let value = evidence_json::decode(bytes)?;
    let fingerprint = hash(owner.as_bytes());
    require(
        value["schema"] == "mtm-research-review-observation-v1"
            && value["trial_id"] == trial_id
            && value["run_id"] == run_id
            && value["generator_owner_fingerprint"] == fingerprint
            && value["reviewer_owner_fingerprint"] == fingerprint
            && value["reviewed_sha256"] == hash(final_tex)
            && value["verification_report_sha256"] == hash(report)
            && value["same_live_connection_observed"] == true
            && value["reviewed_before_finalization"] == true,
        "review observation is not bound to this owner/run/proof/report",
    )
}

fn safe_workspace_export(
    session: &Path,
    metadata: &Value,
    final_tex: &[u8],
    owner: u32,
) -> Result<()> {
    let export = metadata["workspace_export_path"]
        .as_str()
        .ok_or("run has no workspace export path")?;
    let path = Path::new(export);
    require(
        !path.is_absolute()
            && path
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
        "workspace export path is unsafe",
    )?;
    let published = read_file(&session.join("workspace").join(path), FILE_LIMIT, owner)?;
    require(
        published == final_tex,
        "published final TeX differs from private final bytes",
    )
}

pub(crate) fn run(root: &Path, options: &Options) -> Result<Value> {
    let session = validate_session_path(&options.session)?;
    let root_milestone = session_root_milestone(&session)?;
    let owner = fs::metadata(&session)?.uid();
    let session_bytes = read_file(&session.join("session.json"), JSON_LIMIT, owner)?;
    let manifest: SessionManifest = strict_json(&session_bytes)?;
    let identity = research_precheck::research_identity(&manifest.milestone)?;
    let session_name = session
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("research session name unavailable")?;
    validate_session_manifest(&manifest, session_name, root_milestone)?;

    let candidate = read_file(&session.join("candidate"), 268_435_456, owner)?;
    require(
        hash(&candidate) == identity.candidate_sha256,
        "research session candidate differs from the frozen candidate",
    )?;
    let candidate_mode = fs::metadata(session.join("candidate"))?.mode() & 0o7777;
    require(
        candidate_mode == 0o500,
        "research candidate mode is not 0500",
    )?;

    let database_path = session.join("data/private/state.sqlite3");
    validate_database(&database_path, owner)?;
    let sqlite = validate_sqlite(&options.sqlite)?;
    let before = collect_database(
        &sqlite,
        &database_path,
        &options.run_id,
        manifest.task_id == "U22",
        identity.state_schema_version,
    )?;
    require(
        before.status["problem_id"] == manifest.case_id
            && before.status["state"] == "done"
            && before.status["status"] == "done"
            && before.status["sealed"] == true
            && before.status["verdict"] == "correct"
            && before.status["latex_passed"] == true,
        "selected research run is not the sealed correct case from this session",
    )?;

    let run_root = session.join("data/private/runs").join(&options.run_id);
    private_directory(&run_root)?;
    let draft = read_file(&run_root.join("draft/proof.tex"), FILE_LIMIT, owner)?;
    let final_tex = read_file(
        &run_root.join("final/proof_verified.tex"),
        FILE_LIMIT,
        owner,
    )?;
    require(
        draft == final_tex,
        "verifier-reviewed draft and final proof bytes differ",
    )?;
    let verification = read_file(
        &run_root.join("verification/verification.json"),
        JSON_LIMIT,
        owner,
    )?;
    safe_workspace_export(&session, &before.metadata, &final_tex, owner)?;
    let last = before
        .transitions
        .last()
        .ok_or("research transition log is empty")?;
    require(
        last["after_state"] == "done" && last["evidence"]["sha256"] == hash(&final_tex),
        "finalizer transition is not bound to the final proof bytes",
    )?;
    let (compiler, compiler_output) = compiler_material(&before.transitions, &final_tex)?;

    let review = copy_input(&session, "review.json", owner)?;
    validate_review(
        &review,
        &options.run_id,
        &manifest.trial_id,
        &before.owner_id,
        &final_tex,
        &verification,
    )?;

    let mut material = BTreeMap::<String, Vec<u8>>::new();
    material.insert("session".into(), session_bytes.clone());
    material.insert("status".into(), pretty(&before.status)?);
    material.insert(
        "transitions".into(),
        pretty(&Value::Array(before.transitions.clone()))?,
    );
    material.insert("proof_manifest".into(), pretty(&before.manifest)?);
    material.insert("verification_report".into(), verification.clone());
    material.insert("compiler".into(), compiler);
    material.insert("compiler_output".into(), compiler_output);
    material.insert("final_tex".into(), final_tex.clone());
    material.insert("reviewed_tex".into(), draft.clone());
    material.insert("review".into(), review);
    if manifest.task_id == "U22" {
        material.insert("reference_audit".into(), pretty(&before.reference_audit)?);
    }
    for (kind, name) in fixed_input_names(&manifest.task_id)? {
        if kind != "review" {
            material.insert(kind.into(), copy_input(&session, name, owner)?);
        }
    }

    let after = collect_database(
        &sqlite,
        &database_path,
        &options.run_id,
        manifest.task_id == "U22",
        identity.state_schema_version,
    )?;
    require(
        evidence_fingerprint(&before)? == evidence_fingerprint(&after)?,
        "research run changed while evidence was collected",
    )?;
    let session_after = read_file(&session.join("session.json"), JSON_LIMIT, owner)?;
    let candidate_after = read_file(&session.join("candidate"), 268_435_456, owner)?;
    require(
        session_after == session_bytes && candidate_after == candidate,
        "research session inputs changed while evidence was collected",
    )?;

    let final_dir = session.join(format!("evidence-bundle.{}", manifest.trial_id));
    require(
        !final_dir.exists() && fs::symlink_metadata(&final_dir).is_err(),
        "research evidence bundle already exists; never overwrite it",
    )?;
    let staging = session.join(format!(
        ".evidence-bundle.{}.{}.partial",
        manifest.trial_id,
        std::process::id()
    ));
    require(
        !staging.exists() && fs::symlink_metadata(&staging).is_err(),
        "research evidence staging path already exists",
    )?;
    DirBuilder::new().mode(0o700).create(&staging)?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;

    let filenames = BTreeMap::from([
        ("session", "session.json"),
        ("status", "status.json"),
        ("transitions", "transitions.json"),
        ("proof_manifest", "proof_manifest.json"),
        ("verification_report", "verification_report.json"),
        ("compiler", "compiler.json"),
        ("compiler_output", "compiler_output.txt"),
        ("final_tex", "final.tex"),
        ("reviewed_tex", "reviewed.tex"),
        ("review", "review.json"),
        ("retrieval", "retrieval.json"),
        ("reference_audit", "reference_audit.json"),
        ("sources", "sources.json"),
        ("seeded_draft", "seeded_draft.tex"),
        ("first_findings", "first_findings.json"),
        ("repair_history", "repair_history.json"),
        ("branches", "branches.json"),
        ("sage_input", "sage_input.txt"),
        ("sage_output", "sage_output.txt"),
        ("magma_input", "magma_input.txt"),
        ("magma_output", "magma_output.txt"),
        ("cas_observation", "cas_observation.json"),
    ]);
    let mut bindings = Vec::new();
    for (kind, bytes) in &material {
        let filename = filenames
            .get(kind.as_str())
            .ok_or("unknown research evidence material kind")?;
        write_private(&staging.join(filename), bytes)?;
        bindings.push(json!({"kind":kind,"sha256":hash(bytes)}));
    }
    let bundle = pretty(&json!({
        "schema":"mtm-research-bundle-v1","task_id":manifest.task_id,"repeat":manifest.repeat,
        "trial_id":manifest.trial_id,"run_id":options.run_id,"artifacts":bindings
    }))?;
    write_private(&staging.join("bundle.json"), &bundle)?;
    let precheck = research_precheck::validate_bundle(root, &staging)?;
    require(
        precheck["required_material_present"] == true
            && precheck["existing_material_consistent"] == true
            && precheck["research_trial_passed"] == false
            && precheck["accepted_trials_delta"] == 0,
        "private research bundle did not pass the non-authorizing precheck",
    )?;
    fs::rename(&staging, &final_dir)?;
    File::open(&session)?.sync_all()?;

    Ok(json!({
        "schema":"mtm-research-collection-v1","milestone":manifest.milestone,
        "task_id":manifest.task_id,"repeat":manifest.repeat,"case_id":manifest.case_id,
        "trial_id":manifest.trial_id,"bundle_directory":final_dir.file_name().and_then(|v|v.to_str()),
        "bundle_manifest_sha256":hash(&bundle),"final_tex_sha256":hash(&final_tex),
        "verification_report_sha256":hash(&verification),"proof_manifest_sha256":before.manifest_sha256,
        "owner_fingerprint":hash(before.owner_id.as_bytes()),"required_material_present":true,
        "sqlite3_sha256":sqlite.sha256,"sqlite3_version":sqlite.version,
        "precheck_consistent":true,"research_trial_passed":false,"accepted_trials_delta":0,
        "mathematical_review_authenticated_by_collector":false,"production_state_modified":false,
        "workflow_mutations":0,"release_qualified":false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn options_reject_overrides_and_non_absolute_sessions() {
        assert!(Options::parse(&[]).is_err());
        assert!(
            Options::parse(&[
                "--session".into(),
                "/tmp/x".into(),
                "--run-id".into(),
                "run-a".into(),
                "--sqlite".into(),
                "/usr/bin/sqlite3".into()
            ])
            .is_ok()
        );
        assert!(
            Options::parse(&[
                "--session".into(),
                "relative".into(),
                "--run-id".into(),
                "run-a".into(),
                "--sqlite".into(),
                "/usr/bin/sqlite3".into()
            ])
            .is_err()
        );
        assert!(
            Options::parse(&[
                "--session".into(),
                "/tmp/x".into(),
                "--run-id".into(),
                "../run".into(),
                "--sqlite".into(),
                "/usr/bin/sqlite3".into()
            ])
            .is_err()
        );
        assert!(
            Options::parse(&[
                "--session".into(),
                "/tmp/x".into(),
                "--run-id".into(),
                "run-a".into(),
                "--sqlite".into(),
                "relative/sqlite3".into()
            ])
            .is_err()
        );
        assert!(
            Options::parse(&[
                "--session".into(),
                "/tmp/x".into(),
                "--run-id".into(),
                "run-a".into(),
                "--sqlite".into(),
                "/usr/bin/sqlite3".into(),
                "--accept".into()
            ])
            .is_err()
        );
    }

    #[test]
    fn manifest_never_allows_preaccepted_or_weakened_session() -> Result<()> {
        let base = SessionManifest {
            schema: "mtm-research-session-v1".into(),
            milestone: "MTM-016".into(),
            task_id: "U21".into(),
            repeat: 1,
            case_id: "u21-r1-subspace-dimension".into(),
            workflow_mode: "compact".into(),
            trial_id: "a".repeat(32),
            candidate_sha256: research_precheck::CANDIDATE_SHA.into(),
            candidate_source_commit: research_precheck::CANDIDATE_SOURCE.into(),
            launcher_source_commit: "b".repeat(40),
            launcher_sha256: "c".repeat(64),
            case_registry_sha256: research_precheck::REGISTRY_SHA.into(),
            corpus_sha256: research_precheck::CORPUS_SHA.into(),
            native_mode: "safe".into(),
            latex_policy: "required".into(),
            session_prepared: true,
            runtime_executed: false,
            independent_review_recorded: false,
            research_trial_passed: false,
            release_qualified: false,
        };
        validate_session_manifest(&base, "U21-r1.ABCdef12", "MTM-016")?;
        let mut bad = serde_json::to_value(&base)?;
        for (pointer, value) in [
            ("/schema", json!("mtm-research-session-v2")),
            ("/native_mode", json!("dangerous")),
            ("/latex_policy", json!("static_only")),
            ("/runtime_executed", json!(true)),
            ("/research_trial_passed", json!(true)),
            ("/release_qualified", json!(true)),
            ("/candidate_sha256", json!("9".repeat(64))),
        ] {
            let mut value_bad = bad.clone();
            *value_bad.pointer_mut(pointer).ok_or("fixture pointer")? = value;
            let parsed: SessionManifest = serde_json::from_value(value_bad)?;
            assert!(validate_session_manifest(&parsed, "U21-r1.ABCdef12", "MTM-016").is_err());
        }
        // Historical MTM-016 U25 v2 uses dangerous Native.
        let mut u25 = serde_json::to_value(&base)?;
        u25["schema"] = json!("mtm-research-session-v2");
        u25["task_id"] = json!("U25");
        u25["case_id"] = json!("u25-r1-rank-nullity");
        u25["workflow_mode"] = json!("full");
        u25["native_mode"] = json!("dangerous");
        let parsed: SessionManifest = serde_json::from_value(u25.clone())?;
        validate_session_manifest(&parsed, "U25-r1.ABCdef12", "MTM-016")?;
        for (key, replacement) in [
            ("schema", json!("mtm-research-session-v1")),
            ("native_mode", json!("safe")),
            ("native_mode", json!("trusted")),
            ("latex_policy", json!("static_only")),
            ("independent_review_recorded", json!(true)),
        ] {
            let mut changed = u25.clone();
            changed[key] = replacement;
            let parsed: SessionManifest = serde_json::from_value(changed)?;
            assert!(validate_session_manifest(&parsed, "U25-r1.ABCdef12", "MTM-016").is_err());
        }
        let mut mtm017 = u25.clone();
        mtm017["milestone"] = json!("MTM-017");
        mtm017["candidate_sha256"] = json!(research_precheck::MTM017_CANDIDATE_SHA);
        mtm017["candidate_source_commit"] = json!(research_precheck::MTM017_CANDIDATE_SOURCE);
        let parsed: SessionManifest = serde_json::from_value(mtm017.clone())?;
        validate_session_manifest(&parsed, "U25-r1.ABCdef12", "MTM-017")?;
        assert!(validate_session_manifest(&parsed, "U25-r1.ABCdef12", "MTM-016").is_err());
        mtm017["candidate_sha256"] = json!(research_precheck::CANDIDATE_SHA);
        let parsed: SessionManifest = serde_json::from_value(mtm017)?;
        assert!(validate_session_manifest(&parsed, "U25-r1.ABCdef12", "MTM-017").is_err());
        let mut mtm017_u21 = serde_json::to_value(&base)?;
        mtm017_u21["milestone"] = json!("MTM-017");
        mtm017_u21["candidate_sha256"] = json!(research_precheck::MTM017_CANDIDATE_SHA);
        mtm017_u21["candidate_source_commit"] = json!(research_precheck::MTM017_CANDIDATE_SOURCE);
        mtm017_u21["schema"] = json!("mtm-research-session-v2");
        mtm017_u21["native_mode"] = json!("dangerous");
        let parsed: SessionManifest = serde_json::from_value(mtm017_u21.clone())?;
        validate_session_manifest(&parsed, "U21-r1.ABCdef12", "MTM-017")?;
        assert!(validate_session_manifest(&parsed, "U21-r1.ABCdef12", "MTM-016").is_err());
        mtm017_u21["native_mode"] = json!("safe");
        let parsed: SessionManifest = serde_json::from_value(mtm017_u21)?;
        assert!(validate_session_manifest(&parsed, "U21-r1.ABCdef12", "MTM-017").is_err());
        bad["extra"] = json!(true);
        assert!(serde_json::from_value::<SessionManifest>(bad).is_err());
        Ok(())
    }

    #[test]
    fn compiler_material_requires_required_success_and_binds_output() -> Result<()> {
        let output = "Latexmk synthetic output";
        let row = json!({"run_id":"run-a","sequence":4,"before_state":"latex_validate","after_state":"verify",
            "evidence":{"policy":"required","static_valid":true,"compile_attempted":true,"compile_available":true,
                "compile_passed":true,"gate_passed":true,"errors":[],"compiler_output":output}});
        let final_tex = b"\\documentclass{article}\\begin{document}x\\end{document}";
        let (compiler, saved) = compiler_material(std::slice::from_ref(&row), final_tex)?;
        assert_eq!(saved, output.as_bytes());
        let value: Value = serde_json::from_slice(&compiler)?;
        assert_eq!(value["source_sha256"], hash(final_tex));
        assert_eq!(value["output_sha256"], hash(output.as_bytes()));
        for (key, replacement) in [
            ("policy", json!("static_only")),
            ("compile_passed", json!(false)),
            ("compile_attempted", json!(false)),
            ("compiler_output", json!("")),
        ] {
            let mut changed = row.clone();
            changed["evidence"][key] = replacement;
            assert!(compiler_material(&[changed], final_tex).is_err());
        }
        Ok(())
    }

    #[test]
    fn database_collection_is_read_only_and_binds_the_exact_sealed_run() -> Result<()> {
        let root = tempdir()?;
        let database = root.path().join("state.sqlite3");
        fs::write(&database, b"synthetic sqlite placeholder")?;
        fs::set_permissions(&database, fs::Permissions::from_mode(0o600))?;
        let manifest = r#"{"computational_evidence":[],"conditional_hypotheses":[],"dependency_revision_ids":[],"reference_ids":[],"target_statement_tex":"Synthetic target"}"#;
        let sqlite = root.path().join("sqlite3");
        let script = r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '%s\n' '3.99.0 synthetic'
  exit 0
fi
[ "$1" = "-readonly" ] && [ "$2" = "-json" ] && [ "$3" = "-batch" ] || exit 9
sql=$5
case "$sql" in
  *"PRAGMA user_version"*) printf '%s\n' '[{"user_version":7}]' ;;
  *"FROM runs"*)
    case "$sql" in *"run_id='missing'"*) printf '%s\n' '[]' ;;
    *) printf '%s\n' '[{"problem_id":"u21-r1-subspace-dimension","owner_id":"owner-a","state":"done","status":"done","round_index":0,"transition_seq":2,"latex_passed":1,"verdict":"correct","sealed":1,"metadata_json":"{\"workspace_export_path\":\"rethlas-output/run-a/proof_verified.tex\"}"}]' ;;
    esac ;;
  *"FROM step_receipts"*)
    case "$sql" in *"run_id='run-pending'"*) printf '%s\n' '[{"pending":1}]' ;;
    *) printf '%s\n' '[{"pending":0}]' ;;
    esac ;;
  *"FROM transitions"*) printf '%s\n' '[{"sequence":1,"before_state":"created","after_state":"latex_validate","actor":"assembler","reason":"proof_submitted","evidence_json":"{}","created_at":"2026-09-11T00:00:00Z"},{"sequence":2,"before_state":"latex_validate","after_state":"done","actor":"finalizer_gate","reason":"done","evidence_json":"{\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}","created_at":"2026-09-11T00:00:01Z"}]' ;;
  *"FROM proof_manifests"*) printf '%s\n' '[{"manifest_json":"{\"computational_evidence\":[],\"conditional_hypotheses\":[],\"dependency_revision_ids\":[],\"reference_ids\":[],\"target_statement_tex\":\"Synthetic target\"}","sha256":"MANIFEST_SHA"}]' ;;
  *) exit 8 ;;
esac
"#
        .replace("MANIFEST_SHA", &hash(manifest.as_bytes()));
        fs::write(&sqlite, script.as_bytes())?;
        fs::set_permissions(&sqlite, fs::Permissions::from_mode(0o700))?;
        let tool = validate_sqlite(&sqlite)?;
        validate_database(&database, fs::metadata(root.path())?.uid())?;
        let before = fs::read(&database)?;
        let evidence = collect_database(&tool, &database, "run-a", false, 7)?;
        assert_eq!(evidence.status["state"], "done");
        assert_eq!(evidence.status["problem_id"], "u21-r1-subspace-dimension");
        assert_eq!(evidence.owner_id, "owner-a");
        assert_eq!(evidence.transitions.len(), 2);
        assert_eq!(
            evidence.manifest["target_statement_tex"],
            "Synthetic target"
        );
        assert_eq!(fs::read(&database)?, before);
        assert!(collect_database(&tool, &database, "run-pending", false, 7).is_err());
        assert!(collect_database(&tool, &database, "missing", false, 7).is_err());
        assert!(collect_database(&tool, &database, "run-a", false, 8).is_err());

        let sqlite8_dir = root.path().join("v8");
        fs::create_dir(&sqlite8_dir)?;
        let sqlite8 = sqlite8_dir.join("sqlite3");
        let script8 = script.replace("[{\"user_version\":7}]", "[{\"user_version\":8}]");
        fs::write(&sqlite8, script8.as_bytes())?;
        fs::set_permissions(&sqlite8, fs::Permissions::from_mode(0o700))?;
        let tool8 = validate_sqlite(&sqlite8)?;
        let evidence8 = collect_database(&tool8, &database, "run-a", false, 8)?;
        assert_eq!(evidence8.status["state"], "done");
        assert!(collect_database(&tool8, &database, "run-a", false, 7).is_err());
        Ok(())
    }

    #[test]
    fn review_observation_must_match_owner_trial_run_proof_and_exact_report() -> Result<()> {
        let final_tex = b"\\documentclass{article}\\begin{document}ok\\end{document}\n";
        let report =
            br#"{"verification_report":{"summary":"checked","critical_errors":[],"gaps":[]}}"#;
        let owner = "private-owner-id";
        let trial = "0123456789abcdef0123456789abcdef";
        let run = "run-u21-r1";
        let good = json!({
            "schema":"mtm-research-review-observation-v1",
            "trial_id":trial,"run_id":run,
            "generator_session":"generator-chat","reviewer_session":"reviewer-chat",
            "generator_owner_fingerprint":hash(owner.as_bytes()),
            "reviewer_owner_fingerprint":hash(owner.as_bytes()),
            "reviewed_sha256":hash(final_tex),
            "verification_report_sha256":hash(report),
            "same_live_connection_observed":true,
            "reviewed_before_finalization":true,
            "statement_checks":[{"location":"step-1","summary":"checked"}]
        });
        let good_bytes = pretty(&good)?;
        validate_review(&good_bytes, run, trial, owner, final_tex, report)?;
        for (pointer, replacement) in [
            ("/trial_id", json!("fedcba9876543210fedcba9876543210")),
            ("/run_id", json!("other-run")),
            ("/generator_owner_fingerprint", json!("a".repeat(64))),
            ("/reviewed_sha256", json!("b".repeat(64))),
            ("/verification_report_sha256", json!("c".repeat(64))),
            ("/same_live_connection_observed", json!(false)),
            ("/reviewed_before_finalization", json!(false)),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).ok_or("review pointer")? = replacement;
            assert!(
                validate_review(&pretty(&bad)?, run, trial, owner, final_tex, report).is_err(),
                "mutated {pointer}"
            );
        }
        Ok(())
    }

    #[test]
    fn session_path_is_scoped_to_versioned_private_research_layouts() -> Result<()> {
        let root = tempdir()?;
        let mtm016 = root
            .path()
            .join(".mtm-acceptance/MTM-016/research/U21-r1.ABCdef12");
        fs::create_dir_all(&mtm016)?;
        fs::set_permissions(&mtm016, fs::Permissions::from_mode(0o700))?;
        assert_eq!(validate_session_path(&mtm016)?, mtm016);
        assert_eq!(session_root_milestone(&mtm016)?, "MTM-016");
        let mtm017 = root
            .path()
            .join(".mtm-acceptance/MTM-017/research/U25-r1.ZYXwvu98");
        fs::create_dir_all(&mtm017)?;
        fs::set_permissions(&mtm017, fs::Permissions::from_mode(0o700))?;
        assert_eq!(validate_session_path(&mtm017)?, mtm017);
        assert_eq!(session_root_milestone(&mtm017)?, "MTM-017");
        let outside = root.path().join("U21-r1.ABCdef12");
        fs::create_dir(&outside)?;
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o700))?;
        assert!(validate_session_path(&outside).is_err());
        let weak = root
            .path()
            .join(".mtm-acceptance/MTM-016/research/U22-r1.ABCdef12");
        fs::create_dir(&weak)?;
        fs::set_permissions(&weak, fs::Permissions::from_mode(0o755))?;
        assert!(validate_session_path(&weak).is_err());
        Ok(())
    }
}
