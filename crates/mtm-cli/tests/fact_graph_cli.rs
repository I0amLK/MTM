use std::process::Command;

use mtm_storage::StateStore;
use rusqlite::Connection;

#[test]
fn fact_graph_cli_exports_exact_bytes_and_cascades_operator_revocation()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("state.sqlite3");
    let store = StateStore::open(&path)?;
    store.create_project(
        "owner",
        "Graph",
        Some("project-graph"),
        &serde_json::json!({}),
    )?;
    store.create_run("run-graph", "p", "owner", "done", &serde_json::json!({}))?;
    let connection = Connection::open(&path)?;
    connection.execute_batch("INSERT INTO facts(fact_id,project_id,source_run_id,statement_tex,proof_tex,created_at) VALUES('aaaaaaaaaaaaaaaa','project-graph','run-graph','Lemma','Proof','2026-09-25');
        INSERT INTO facts(fact_id,project_id,source_run_id,statement_tex,proof_tex,created_at) VALUES('bbbbbbbbbbbbbbbb','project-graph','run-graph','Target','Proof','2026-09-25');
        INSERT INTO fact_edges(fact_id,predecessor_id) VALUES('bbbbbbbbbbbbbbbb','aaaaaaaaaaaaaaaa');")
        ?;
    drop(connection);

    let export = || {
        Command::new(env!("CARGO_BIN_EXE_mtm"))
            .args([
                "fact-graph",
                "export",
                "--project",
                "project-graph",
                "--state-db",
            ])
            .arg(&path)
            .output()
    };
    let first = export()?;
    let second = export()?;
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(first.stdout, second.stdout);
    let graph: serde_json::Value = serde_json::from_slice(&first.stdout)?;
    assert_eq!(graph["graph"]["edges"].as_array().map(Vec::len), Some(1));

    let revoked = Command::new(env!("CARGO_BIN_EXE_mtm"))
        .args([
            "fact-graph",
            "revoke",
            "aaaaaaaaaaaaaaaa",
            "--reason",
            "invalid premise",
            "--state-db",
        ])
        .arg(&path)
        .output()?;
    assert!(
        revoked.status.success(),
        "{}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&revoked.stdout)?;
    assert_eq!(result["revoked_fact_ids"].as_array().map(Vec::len), Some(2));
    assert!(
        store
            .active_project_fact_ids("project-graph", "owner")?
            .is_empty()
    );

    let absent = temp.path().join("absent.sqlite3");
    let rejected = Command::new(env!("CARGO_BIN_EXE_mtm"))
        .args([
            "fact-graph",
            "revoke",
            "aaaaaaaaaaaaaaaa",
            "--reason",
            "x",
            "--state-db",
        ])
        .arg(&absent)
        .output()?;
    assert!(!rejected.status.success());
    assert!(!absent.exists());
    Ok(())
}

#[test]
fn retired_native_modes_are_rejected_at_the_cli_boundary() -> Result<(), Box<dyn std::error::Error>>
{
    let cli = env!("CARGO_BIN_EXE_mtm");
    let safe = Command::new(cli)
        .args(["check-config", "--native-mode", "safe"])
        .output()?;
    assert!(!safe.status.success());
    assert!(String::from_utf8_lossy(&safe.stderr).contains("removed in MTM-017"));
    let trusted = Command::new(cli)
        .arg("check-config")
        .env("MTM_NATIVE_MODE", "trusted")
        .output()?;
    assert!(!trusted.status.success());
    assert!(String::from_utf8_lossy(&trusted.stderr).contains("removed in MTM-017"));
    Ok(())
}
