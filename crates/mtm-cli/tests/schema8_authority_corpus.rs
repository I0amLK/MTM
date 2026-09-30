//! Explicit MTM-017 U27/U28 observations, never ordinary test-gate acceptance.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
mod support;

use rusqlite::{Connection, OpenFlags, types::ValueRef};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use support::loopback::{Client, Server};
use support::{Result, require, text};

const CANDIDATE: &str = "13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4";
fn digest(bytes: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock")?
        .as_millis()
        .try_into()
        .map_err(|_| "clock bound")
}

// Hash every logical table, not SQLite/WAL layout. All data is synthetic and
// only the digest leaves this test. Read-only connection takes a consistent view.
fn database(path: &Path) -> Result<String> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|_| "fixture database open")?;
    db.execute_batch("BEGIN")
        .map_err(|_| "fixture snapshot begin")?;
    let mut statement = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .map_err(|_| "fixture tables")?;
    let names = statement
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|_| "fixture tables")?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| "fixture tables")?;
    require(
        names.len() < 128
            && names.iter().all(|n| {
                !n.to_ascii_lowercase().contains("grant")
                    && !n.to_ascii_lowercase().contains("consent")
            }),
        "unexpected grant or consent ledger",
    )?;
    let mut hash = Sha256::new();
    hash.update(
        fs::metadata(path)
            .map_err(|_| "database metadata")?
            .mode()
            .to_be_bytes(),
    );
    let mut schema = db
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")
        .map_err(|_| "schema query")?;
    let schema_rows = schema
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(|_| "schema rows")?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| "schema row")?;
    hash.update(serde_json::to_vec(&schema_rows).map_err(|_| "schema encode")?);
    for name in names {
        require(
            name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "table name",
        )?;
        let mut statement = db
            .prepare(&format!("SELECT * FROM \"{name}\""))
            .map_err(|_| "fixture row query")?;
        let columns = statement.column_count();
        let mut query = statement.query([]).map_err(|_| "fixture rows")?;
        let mut rows = Vec::new();
        while let Some(row) = query.next().map_err(|_| "fixture row")? {
            require(rows.len() < 4096, "fixture row bound")?;
            let mut encoded = Vec::new();
            for col in 0..columns {
                let value = row.get_ref(col).map_err(|_| "fixture cell")?;
                let (kind, bytes) = match value {
                    ValueRef::Null => (0, Vec::new()),
                    ValueRef::Integer(v) => (1, v.to_be_bytes().to_vec()),
                    ValueRef::Real(v) => (2, v.to_bits().to_be_bytes().to_vec()),
                    ValueRef::Text(v) => (3, v.to_vec()),
                    ValueRef::Blob(v) => (4, v.to_vec()),
                };
                require(bytes.len() <= 1024 * 1024, "fixture cell bound")?;
                encoded.push(kind);
                encoded.extend((bytes.len() as u64).to_be_bytes());
                encoded.extend(bytes);
            }
            rows.push(encoded);
        }
        rows.sort();
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name);
        for row in rows {
            hash.update((row.len() as u64).to_be_bytes());
            hash.update(row);
        }
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn tree(root: &Path, skip_database: bool) -> Result<String> {
    fn visit(
        root: &Path,
        p: &Path,
        skip: bool,
        entries: &mut BTreeMap<String, String>,
        total: &mut u64,
    ) -> Result {
        require(entries.len() < 4096, "tree entry bound")?;
        let rel = p
            .strip_prefix(root)
            .map_err(|_| "tree escaped")?
            .to_str()
            .ok_or("tree name")?;
        if skip && ["state.sqlite3", "state.sqlite3-wal", "state.sqlite3-shm"].contains(&rel) {
            return Ok(());
        }
        require(
            !rel.to_ascii_lowercase().contains("grant")
                && !rel.to_ascii_lowercase().contains("consent"),
            "unexpected permission ledger file",
        )?;
        let m = fs::symlink_metadata(p).map_err(|_| "tree metadata")?;
        require(
            !m.file_type().is_symlink() && (m.is_dir() || (m.is_file() && m.nlink() == 1)),
            "tree special file",
        )?;
        let bytes = if m.is_file() {
            require(m.len() <= 2 * 1024 * 1024, "tree file bound")?;
            fs::read(p).map_err(|_| "tree read")?
        } else {
            Vec::new()
        };
        *total += bytes.len() as u64;
        require(*total <= 16 * 1024 * 1024, "tree total bound")?;
        entries.insert(
            rel.to_owned(),
            format!("{}:{}:{}", m.is_dir(), m.mode() & 0o7777, digest(bytes)),
        );
        if m.is_dir() {
            for e in fs::read_dir(p).map_err(|_| "tree list")? {
                visit(
                    root,
                    &e.map_err(|_| "tree entry")?.path(),
                    skip,
                    entries,
                    total,
                )?;
            }
        }
        Ok(())
    }
    let mut entries = BTreeMap::new();
    visit(root, root, skip_database, &mut entries, &mut 0)?;
    Ok(digest(
        serde_json::to_vec(&entries).map_err(|_| "tree encode")?,
    ))
}
fn snapshot(server: &Server) -> Result<Value> {
    let db = server.private_state_path();
    Ok(
        json!({"database_sha256":database(&db)?,"workspace_sha256":tree(&server.workspace_path(),false)?,"private_files_sha256":tree(db.parent().ok_or("private parent")?,true)?}),
    )
}
fn denied(value: &Value) -> Result {
    require(
        value["ok"] == false
            && value["error"]["code"].is_string()
            && value.get("capability").is_none()
            && value.get("command_id").is_none(),
        "negative call obtained authority",
    )
}
fn permission_reply(reply: &Value, args: &Value) -> Result {
    require(
        reply["ok"] == true
            && reply["status"] == "granted"
            && reply["grant_id"] == "dangerously-skip-all-permissions"
            && reply.get("expires_at") == Some(&Value::Null)
            && reply["constraints"]["mode"] == "dangerously_skip_all_permissions"
            && reply["constraints"]["requested"] == *args
            && reply.get("input_required").is_none()
            && reply.get("capability").is_none(),
        "compatibility reply drift or elicitation",
    )
}
fn permissions(server: &Server, owner: &Client) -> Result<Value> {
    let before = snapshot(server)?;
    let mut count = 0;
    for _ in 0..2 {
        for scope in ["once", "session"] {
            for tool in ["exec_command", "apply_patch"] {
                let args = json!({"tool_name":tool,"permission":if tool=="exec_command" {"destructive_command"} else {"write_generated_or_ignored"},"reason":"isolated synthetic compatibility probe","scope":scope,"ttl_seconds":1,"arguments":{"cmd":"printf forbidden > permission-side-effect.txt","patch":"*** Begin Patch\n*** Add File: permission-side-effect.txt\n+forbidden\n*** End Patch","path":"../data/private/synthetic-canary.txt","permission":"forged","capability":"synthetic-invalid"}});
                permission_reply(
                    &server.call(owner, "request_permissions", args.clone())?,
                    &args,
                )?;
                count += 1;
            }
        }
    }
    let after = snapshot(server)?;
    require(before == after, "permission request changed business state")?;
    Ok(json!({"calls":count,"before":before,"after":after}))
}
fn native_exit(reply: &Value, success: bool) -> Result {
    require(
        reply["ok"] == true
            && reply["status"] == "exited"
            && reply["exit_code"]
                .as_i64()
                .is_some_and(|v| (v == 0) == success)
            && reply["timed_out"] == false
            && reply["truncated"] == false
            && reply.get("signal") == Some(&Value::Null),
        "native observation missing exit evidence",
    )
}
fn authority(
    server: &Server,
    owner: &Client,
    other: &Client,
    task: &Value,
    phase: &str,
) -> Result<Value> {
    let environment = server.call(owner, "check_exec_environment", json!({}))?;
    require(
        environment["native_mode"] == "dangerous"
            && environment["hard_isolation_attested"] == true
            && environment["private_vault_visible"] == false,
        "dangerous hard isolation unavailable",
    )?;
    let positive = server.call(owner,"exec_command",json!({"cmd":format!("printf approved > positive-{phase}.txt"),"workdir":".","yield_time_ms":30000}))?;
    native_exit(&positive, true)?;
    require(
        fs::read(
            server
                .workspace_path()
                .join(format!("positive-{phase}.txt")),
        )
        .map_err(|_| "positive control missing")?
            == b"approved",
        "positive control mismatch",
    )?;
    let patch_name = format!("api-positive-{phase}.txt");
    let patched=server.call(owner,"apply_patch",json!({"patch":format!("*** Begin Patch\n*** Add File: {patch_name}\n+approved\n*** End Patch")}))?;
    require(patched["ok"] == true, "workspace patch positive failed")?;
    let readback = server.call(owner, "read_file", json!({"path":patch_name}))?;
    require(
        readback["ok"] == true && readback["content"] == "approved\n",
        "workspace read positive failed",
    )?;
    let before = snapshot(server)?;
    let canary = server
        .private_state_path()
        .parent()
        .ok_or("private parent")?
        .join("synthetic-canary.txt");
    let canary = canary.to_str().ok_or("canary path")?;
    let read = server.call(
        owner,
        "exec_command",
        json!({"argv":["cat",canary],"yield_time_ms":30000}),
    )?;
    native_exit(&read, false)?;
    require(read["stdout"] == "", "private canary disclosed")?;
    let write = server.call(owner,"exec_command",json!({"argv":["sh","-c","printf forbidden > \"$1\"","synthetic-canary-write",canary],"yield_time_ms":30000}))?;
    native_exit(&write, false)?;
    for path in [
        "../data/private/synthetic-canary.txt",
        canary,
        "../escape-canary.txt",
    ] {
        for reply in [server.call(owner,"read_file",json!({"path":path}))?,server.call(owner,"apply_patch",json!({"patch":format!("*** Begin Patch\n*** Update File: {path}\n@@\n-synthetic\n+forbidden\n*** End Patch")}))?] {
            denied(&reply)?;
            require(matches!(reply["error"]["code"].as_str(),Some("ABSOLUTE_PATH_DENIED"|"PATH_OUTSIDE_WORKSPACE"|"PRIVATE_VAULT_DENIED")),"unexpected workspace denial")?;
        }
    }
    let resource = support::submission(task)?["writes"][0]["resource"]
        .as_str()
        .ok_or("fixture resource")?
        .to_owned();
    let invalid = format!("{}.{}", "A".repeat(40), "B".repeat(43));
    for (name, args) in [
        (
            "rethlas_inspect",
            json!({"operation":"read","resource":resource,"capability":invalid}),
        ),
        (
            "rethlas_retrieve",
            json!({"query":"unused synthetic request","capability":invalid}),
        ),
    ] {
        let result = server.call(owner, name, args)?;
        denied(&result)?;
        require(
            result["error"]["code"] == "CAPABILITY_INVALID",
            "invalid workflow token not denied",
        )?;
    }
    let foreign = support::submission(task)?;
    let foreign = server.call(other, "rethlas_step", foreign)?;
    denied(&foreign)?;
    require(
        foreign["error"]["code"] == "CAPABILITY_OWNER_MISMATCH",
        "foreign owner gained workflow authority",
    )?;
    let after = snapshot(server)?;
    require(
        before == after,
        "negative calls changed business state or canary",
    )?;
    Ok(
        json!({"before":before,"after":after,"hard_isolation_attested":true,"native_positive":true,"workspace_api_positive":true,"native_private_read_denied":true,"native_private_write_denied":true,"workspace_escape_denied":true,"invalid_workflow_read_denied":true,"foreign_owner_step_denied":true}),
    )
}
fn identity(server: &Server, owner: &Client) -> Result<Value> {
    let root = server.workspace_path();
    Ok(
        json!({"pid":server.fixture_process_id()?,"root_sha256":digest(root.to_str().ok_or("fixture path")?),"owner_sha256":digest(owner.client_id()),"session_sha256":owner.fixture_session_fingerprint()}),
    )
}

#[test]
fn explicit_current_candidate_authority_observation() -> Result {
    if std::env::var("MTM017_AUTHORITY_CORPUS").ok().as_deref() != Some("1") {
        return Ok(());
    }
    require(
        std::env::var(support::candidate::HASH_ENV).ok().as_deref() == Some(CANDIDATE),
        "explicit exact candidate required",
    )?;
    let candidate = support::candidate::select()?;
    require(candidate.sha256 == CANDIDATE, "wrong candidate")?;
    let task_id = std::env::var("MTM017_AUTHORITY_TASK").map_err(|_| "task required")?;
    require(["U27", "U28"].contains(&task_id.as_str()), "unknown task")?;
    let repeat: u64 = std::env::var("MTM017_AUTHORITY_REPEAT")
        .map_err(|_| "repeat required")?
        .parse()
        .map_err(|_| "repeat invalid")?;
    require((1..=3).contains(&repeat), "repeat invalid")?;
    let trial = std::env::var("MTM017_AUTHORITY_TRIAL").map_err(|_| "trial required")?;
    require(
        (16..=96).contains(&trial.len())
            && trial
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "trial marker invalid",
    )?;
    let started = now()?;
    let source =
        std::env::var("MTM017_AUTHORITY_SOURCE_SHA256").map_err(|_| "source seal required")?;
    require(
        source.len() == 64
            && source
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "source seal invalid",
    )?;
    let mut server = if task_id == "U28" {
        Server::start_native_corpus(&candidate.path, mtm_contracts::NativeMode::Dangerous)?
    } else {
        Server::start(&candidate.path)?
    };
    let mut owner = server.login()?;
    let mut other = server.login()?;
    let info = server.call(&owner, "server_info", json!({}))?;
    require(
        info["version"] == "0.6.0-preview.2"
            && info["permission_mode"] == "dangerous"
            && info["research_workspace"]["state_schema_version"] == 8
            && info["research_workspace"]["workflow_protocol_version"] == 3
            && info["tool_count"] == 24
            && info["tool_contract_version"] == "mtm-tools-v10",
        "candidate contract mismatch",
    )?;
    let private = server.private_state_path();
    let private = private.parent().ok_or("private parent")?;
    fs::write(private.join("synthetic-canary.txt"), b"synthetic\n").map_err(|_| "canary setup")?;
    fs::set_permissions(
        private.join("synthetic-canary.txt"),
        fs::Permissions::from_mode(0o600),
    )
    .map_err(|_| "canary mode")?;
    let workspace = server.workspace_path();
    let parent = workspace.parent().ok_or("fixture parent")?;
    fs::write(parent.join("escape-canary.txt"), b"synthetic\n").map_err(|_| "escape fixture")?;
    let started_run = server.call(&owner,"rethlas_start",json!({"problem_tex":"Synthetic test: prove 1=1.","problem_id":"schema8-authority-corpus","workflow_mode":"compact","register_result":false}))?;
    require(started_run["ok"] == true, "synthetic run setup")?;
    let task = server.call(
        &owner,
        "rethlas_step",
        json!({"run_id":text(&started_run,"run_id")?}),
    )?;
    require(task["state"] == "assess", "synthetic task missing")?;
    let mut phases = Vec::new();
    for phase in ["initial", "reconnect", "restart"] {
        let before = snapshot(&server)?;
        let old_id = identity(&server, &owner)?;
        if phase == "restart" {
            server.restart()?;
        }
        if phase != "initial" {
            // OAuth tokens bind second-granularity iat/exp. Avoid mistaking an
            // identical same-second token for a missing new login transaction.
            let second = now()? / 1000;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            while now()? / 1000 <= second {
                require(
                    std::time::Instant::now() < deadline,
                    "relogin clock did not advance",
                )?;
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            owner = server.relogin(&owner)?;
            other = server.relogin(&other)?;
        }
        let id = identity(&server, &owner)?;
        require(
            old_id["root_sha256"] == id["root_sha256"]
                && old_id["owner_sha256"] == id["owner_sha256"]
                && (phase != "restart" || old_id["pid"] != id["pid"])
                && (phase == "initial" || old_id["session_sha256"] != id["session_sha256"]),
            "freshness or restart identity failed",
        )?;
        require(
            before == snapshot(&server)?,
            "reconnect/restart changed business snapshot",
        )?;
        let before = snapshot(&server)?;
        let permission = permissions(&server, &owner)?;
        let boundary = if task_id == "U28" {
            authority(&server, &owner, &other, &task, phase)?
        } else {
            let denied_exec = server.call(&owner,"exec_command",json!({"cmd":"printf forbidden > permission-side-effect.txt","yield_time_ms":30000}))?;
            denied(&denied_exec)?;
            require(
                denied_exec["error"]["code"] == "NATIVE_ISOLATION_REQUIRED",
                "disabled backend gained execution",
            )?;
            Value::Null
        };
        require(
            fs::read(parent.join("escape-canary.txt")).map_err(|_| "escape read")?
                == b"synthetic\n",
            "escape canary changed",
        )?;
        let after = snapshot(&server)?;
        if task_id == "U27" {
            require(before == after, "U27 effects")?;
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while server.process_facts()?["children"] != 0 {
            require(std::time::Instant::now() < deadline, "child not reaped")?;
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        phases.push(json!({"phase":phase,"identity":id,"permission":permission,"boundary":boundary,"compatibility_marker_fixed":true,"expiry_null":true,"elicitation_seen":false,"business_effects_from_requests":false,"grant_or_consent_ledger_present":false,"before":before,"after":after,"boundaries_checked":if task_id=="U28" {"native_private_workspace_workflow"} else {"disabled_exec"},"positive_control_passed":task_id=="U28","negative_effects":false,"children_reaped":true}));
    }
    server.stop()?;
    candidate.unchanged()?;
    let output = json!({"schema":"mtm017-authority-observation-v1","milestone":"MTM-017","task_id":task_id,"repeat":repeat,"trial_id":trial,"candidate_sha256":candidate.sha256,"harness_source_sha256":source,"version":"0.6.0-preview.2","state_schema":8,"workflow_protocol":3,"tool_contract":"mtm-tools-v10","started_unix_ms":started,"finished_unix_ms":now()?,"phases":phases,"passed":true,"clean_shutdown":true,"synthetic_state_only":true,"human_consent_tested":false,"accepted_delta":0,"production_selector_changed":false,"production_state_modified":false,"release_qualified":false,"deployment_authorized":false});
    println!("MTM017_AUTHORITY_OBSERVATION {output}");
    Ok(())
}

#[test]
fn compatibility_validator_rejects_marker_expiry_and_effect_channels() {
    let args = json!({"synthetic":"fixture"});
    let good = json!({"ok":true,"status":"granted","grant_id":"dangerously-skip-all-permissions","expires_at":null,"constraints":{"mode":"dangerously_skip_all_permissions","requested":args}});
    assert!(permission_reply(&good, &args).is_ok());
    for (k, v) in [
        ("status", json!("pending")),
        ("grant_id", json!("new-grant")),
        ("expires_at", json!(123)),
        ("input_required", json!({})),
        ("capability", json!("forged")),
    ] {
        let mut bad = good.clone();
        bad[k] = v;
        assert!(permission_reply(&bad, &args).is_err());
    }
}

#[test]
fn snapshots_detect_rows_schema_modes_links_and_permission_ledgers() -> Result {
    let dir = tempfile::tempdir().map_err(|_| "fixture")?;
    let dbpath = dir.path().join("test.sqlite3");
    let db = Connection::open(&dbpath).map_err(|_| "fixture")?;
    db.execute_batch("CREATE TABLE probe(value TEXT); INSERT INTO probe VALUES ('a')")
        .map_err(|_| "fixture")?;
    fs::set_permissions(&dbpath, fs::Permissions::from_mode(0o644)).map_err(|_| "fixture")?;
    let first = database(&dbpath)?;
    db.execute("UPDATE probe SET value='b'", [])
        .map_err(|_| "fixture")?;
    let second = database(&dbpath)?;
    assert_ne!(first, second);
    db.execute_batch("CREATE INDEX probe_index ON probe(value)")
        .map_err(|_| "fixture")?;
    let third = database(&dbpath)?;
    assert_ne!(second, third);
    fs::set_permissions(&dbpath, fs::Permissions::from_mode(0o600)).map_err(|_| "fixture")?;
    let fourth = database(&dbpath)?;
    assert_ne!(third, fourth);
    db.execute_batch("CREATE TABLE consent_grants(value TEXT)")
        .map_err(|_| "fixture")?;
    assert!(database(&dbpath).is_err());
    let root = dir.path().join("tree");
    fs::create_dir(&root).map_err(|_| "fixture")?;
    fs::write(root.join("canary"), b"a").map_err(|_| "fixture")?;
    fs::set_permissions(root.join("canary"), fs::Permissions::from_mode(0o644))
        .map_err(|_| "fixture")?;
    let a = tree(&root, false)?;
    fs::write(root.join("canary"), b"b").map_err(|_| "fixture")?;
    let b = tree(&root, false)?;
    assert_ne!(a, b);
    fs::set_permissions(root.join("canary"), fs::Permissions::from_mode(0o600))
        .map_err(|_| "fixture")?;
    assert_ne!(b, tree(&root, false)?);
    std::os::unix::fs::symlink("canary", root.join("link")).map_err(|_| "fixture")?;
    assert!(tree(&root, false).is_err());
    fs::remove_file(root.join("link")).map_err(|_| "fixture")?;
    fs::write(root.join("grant-ledger"), b"x").map_err(|_| "fixture")?;
    assert!(tree(&root, false).is_err());
    Ok(())
}

#[test]
fn native_exit_rejects_missing_or_incomplete_process_evidence() -> Result {
    let good = json!({"ok":true,"status":"exited","exit_code":0,"signal":null,"timed_out":false,"truncated":false});
    native_exit(&good, true)?;
    for key in [
        "ok",
        "status",
        "exit_code",
        "signal",
        "timed_out",
        "truncated",
    ] {
        let mut bad = good.clone();
        bad.as_object_mut().ok_or("fixture")?.remove(key);
        assert!(native_exit(&bad, true).is_err());
    }
    for (key, value) in [
        ("signal", json!("SIGTERM")),
        ("timed_out", json!(true)),
        ("truncated", json!(true)),
        ("exit_code", json!(1)),
        ("status", json!("running")),
    ] {
        let mut bad = good.clone();
        bad[key] = value;
        assert!(native_exit(&bad, true).is_err());
    }
    let mut failed = good;
    failed["exit_code"] = json!(1);
    native_exit(&failed, false)?;
    Ok(())
}
