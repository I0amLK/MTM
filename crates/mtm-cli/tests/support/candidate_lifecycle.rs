//! Scripted protocol fixtures, not independent mathematical verification.
use std::collections::BTreeMap;
use std::fs;

use crate::support::candidate;
use crate::support::loopback::{Client, Server};
use crate::support::recovery::{adopt_refresh, error_code};
use crate::support::{Result, require, submission, text};
use mtm_storage::schema::V1_WORKFLOW_SCHEMA_SQL;
use rusqlite::Connection;
use serde_json::{Map, Value, json};

const PROBLEM: &str = r"\begin{proposition}For the integer $1$, prove $1=1$.\end{proposition}";
const PROOF: &str = r"\documentclass{article}
\usepackage{amsthm}
\begin{document}
\begin{proof}Equality is reflexive, hence $1=1$.\end{proof}
\end{document}
";

const REPAIRED_PROOF: &str = r"\documentclass{article}
\usepackage{amsthm}
\begin{document}
\begin{proof}
For every integer $x$, reflexivity of equality gives $x=x$.
The number $1$ is an integer. Substituting $x=1$ proves $1=1$.
\end{proof}
\end{document}
";

fn write(resource: &str, content: Value) -> Value {
    json!({"resource":resource,"content":content})
}

fn seed_v1_state(server: &mut Server, owner: &Client) -> Result {
    server.stop()?;
    let path = server.private_state_path();
    for candidate in [
        path.clone(),
        std::path::PathBuf::from(format!("{}-wal", path.display())),
        std::path::PathBuf::from(format!("{}-shm", path.display())),
    ] {
        match fs::remove_file(candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("copied-state fixture cleanup failed"),
        }
    }
    let connection = Connection::open(&path).map_err(|_| "copied-state fixture open failed")?;
    connection
        .execute_batch(V1_WORKFLOW_SCHEMA_SQL)
        .map_err(|_| "copied-state v1 schema setup failed")?;
    connection
        .execute(
            "INSERT INTO runs(run_id, problem_id, owner_id, state, status, created_at, updated_at) VALUES(?1,'legacy-problem',?2,'assess','active','old','old')",
            ("legacy-run", owner.client_id()),
        )
        .map_err(|_| "copied-state legacy row setup failed")?;
    connection
        .execute_batch("PRAGMA user_version=1;")
        .map_err(|_| "copied-state schema version setup failed")?;
    drop(connection);
    server.restart()
}

fn fixture_submission(task: &Value, mode: &str, report_gap: bool) -> Result<Value> {
    let state = text(task, "state")?;
    let minimal = task["task"]
        .get("minimal_submission")
        .or_else(|| task["task"].get("minimal_submission_template"))
        .ok_or("fixture task omitted submission contract")?;
    let mut args = json!({"run_id":text(task,"run_id")?,"capability":text(task,"capability")?,
        "action":text(minimal,"action")?,"payload":{},"writes":[]});
    match state {
        "assess" => {
            args["payload"] = json!({"route":mode,"requires_external_retrieval":false,
                "requires_multiple_plans":mode=="full","route_reason":"Fixed protocol regression route"});
            args["writes"] = json!([write(
                "memory:generation:immediate_conclusions",
                json!({"summary":"Use reflexivity for the fixed fixture."})
            )]);
        }
        "explore" => {
            args["writes"] = json!([write(
                "memory:generation:events",
                json!({
                "event_type":"notation_resolution","symbol":"=","resolution":"ordinary equality",
                "summary":"No notation ambiguity in the fixture","evidence_ids":[]})
            )]);
        }
        "propose_plans" => {
            args["payload"] = json!({"plans":[
                {"summary":"Use reflexivity","subgoals":[{"key":"direct","statement":"Apply reflexivity to 1","depends_on":[],"critical":true}],"motivation":[],"dependencies":[],"risks":[]},
                {"summary":"Alternative equality axiom","subgoals":[{"key":"alternate","statement":"Use the equality axiom","depends_on":[],"critical":true}],"motivation":[],"dependencies":[],"risks":[]}
            ]});
        }
        "direct_proving" => {
            let plans = task["context"]["active_plans"]
                .as_array()
                .ok_or("missing fixture plans")?;
            require(plans.len() == 2, "fixture requires two server-issued plans")?;
            let mut screening = Map::new();
            for (index, plan) in plans.iter().enumerate() {
                let mut results = Map::new();
                for subgoal in plan["subgoals"]
                    .as_array()
                    .ok_or("fixture plan omitted subgoals")?
                {
                    let result = if index == 0 {
                        json!({"status":"solved","summary":"Reflexivity applies",
                        "method":"direct","evidence_ids":[]})
                    } else {
                        json!({"status":"stuck",
                        "summary":"Alternative not needed","method":"direct","obstruction":"no_progress","evidence_ids":[]})
                    };
                    results.insert(text(subgoal, "subgoal_id")?.to_owned(), result);
                }
                screening.insert(text(plan, "plan_id")?.to_owned(), Value::Object(results));
            }
            args["payload"] = json!({"screening":screening,"selected_plan_id":text(&plans[0],"plan_id")?,"proof_route":"Apply reflexivity"});
            args["writes"] = json!([write(
                "memory:generation:proof_steps",
                json!({"summary":"Screened the fixed two routes"})
            )]);
        }
        "assemble" | "repair" => {
            args["payload"] = if state == "assemble" {
                json!({"outcome":"proof"})
            } else {
                json!({})
            };
            args["writes"] = json!([
                write(
                    "proof",
                    json!(if state == "repair" {
                        REPAIRED_PROOF
                    } else {
                        PROOF
                    })
                ),
                write(
                    "proof_manifest",
                    json!({
                "target_statement_tex":PROBLEM,"dependency_revision_ids":[],"reference_ids":[],
                "conditional_hypotheses":[],"computational_evidence":[]})
                )
            ]);
        }
        "verify" => {
            let gaps = if report_gap {
                json!([{"location":"proof","issue":"Deliberate fixture gap to exercise repair"}])
            } else {
                json!([])
            };
            args["writes"] = json!([
                write(
                    "memory:verifier:statement_checks",
                    json!({"location":"proof","status":if report_gap {"gap"} else {"checked"}})
                ),
                write(
                    "memory:verifier:events",
                    json!({"event_type":"verification_audit_complete"})
                ),
                write(
                    "verification_report",
                    json!({"verification_report":{"summary":"Scripted protocol fixture audit, not independent review","critical_errors":[],"gaps":gaps},
                    "verdict":"correct","repair_hints":if report_gap {"Address the fixture gap"} else {""}})
                )
            ]);
        }
        _ => return Err("unexpected fixture workflow state"),
    }
    Ok(args)
}

pub(super) fn completed_flow(
    server: &mut Server,
    owner: &Client,
    mode: &str,
    repair: bool,
) -> Result<Value> {
    let label = if repair { "repair" } else { mode };
    let export = format!("qualification/{label}/proof_verified.tex");
    let started = server.call(owner,"rethlas_start",json!({"problem_tex":PROBLEM,
        "problem_id":format!("candidate-{label}"),"workflow_mode":mode,"register_result":false,"export_path":export}))?;
    require(started["ok"] == true, "fixture run creation failed")?;
    let run_id = text(&started, "run_id")?;
    let mut current = server.call(owner, "rethlas_step", json!({"run_id":run_id}))?;
    let artifact = server.workspace_path().join(&export);
    let mut states = Vec::new();
    let mut gap_reported = false;
    let mut resumed = false;
    for _ in 0..16 {
        let state = text(&current, "state")?.to_owned();
        states.push(state.clone());
        if state == "done" {
            break;
        }
        require(
            !artifact.exists(),
            "final artifact published before verifier/finalizer completed",
        )?;
        if state == "verify" {
            require(
                current["role"] == "verifier"
                    && current["context"]
                        .get("mathematical_research_state")
                        .is_none(),
                "verifier received generator research context",
            )?;
            let denied = server.call(owner,"rethlas_inspect",json!({"operation":"read",
                "capability":text(&current,"capability")?,"resource":"memory:generation:immediate_conclusions"}))?;
            require(
                denied["ok"] == false
                    && error_code(&denied) == "ROLE_ACCESS_DENIED"
                    && denied.get("capability").is_none()
                    && denied.get("content").is_none(),
                "verifier crossed memory firewall",
            )?;
            let readable = server.call(
                owner,
                "rethlas_inspect",
                json!({"operation":"read","capability":text(&current,"capability")?,"resource":"proof"}),
            )?;
            let expected_proof = if gap_reported { REPAIRED_PROOF } else { PROOF };
            require(
                readable["ok"] == true && readable["content"] == expected_proof,
                "verifier could not read its authorized proof with the same capability",
            )?;
        }
        if state == "assemble" && !resumed {
            server.restart()?;
            resumed = true;
        }
        let report_gap = repair && state == "verify" && !gap_reported;
        let next = server.call(
            owner,
            "rethlas_step",
            fixture_submission(&current, mode, report_gap)?,
        )?;
        if next["ok"] != true || next["submission"]["ok"] != true || !error_code(&next).is_empty() {
            let code = error_code(&next);
            if code.len() <= 80 && code.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') {
                eprintln!("fixture {label} state {state} rejected: {code}");
            }
        }
        require(
            next["ok"] == true && next["submission"]["ok"] == true && error_code(&next).is_empty(),
            "complete workflow fixture submission failed",
        )?;
        if report_gap {
            require(
                next["state"] == "repair" && !artifact.exists(),
                "scripted correct verdict bypassed reported gap",
            )?;
            gap_reported = true;
        }
        current = next;
    }
    if current["state"] != "done" || !resumed {
        // Only fixed state names, never task payloads or credentials.
        let safe_states: Vec<_> = states
            .iter()
            .filter(|state| {
                [
                    "assess",
                    "explore",
                    "propose_plans",
                    "direct_proving",
                    "assemble",
                    "verify",
                    "repair",
                    "done",
                ]
                .contains(&state.as_str())
            })
            .collect();
        eprintln!("bounded fixture {label} states: {safe_states:?}");
        return Err("fixture did not reach done after restart");
    }
    let expected = if repair {
        vec!["assess", "assemble", "verify", "repair", "verify", "done"]
    } else if mode == "full" {
        vec![
            "assess",
            "explore",
            "propose_plans",
            "direct_proving",
            "assemble",
            "verify",
            "done",
        ]
    } else {
        vec!["assess", "assemble", "verify", "done"]
    };
    require(
        states == expected,
        "fixture did not traverse every expected stage",
    )?;
    let status = server.call(
        owner,
        "rethlas_inspect",
        json!({"operation":"status","run_id":run_id}),
    )?;
    require(
        status["state"] == "done"
            && status["sealed"] == true
            && status["verdict"] == "correct"
            && status["latex_passed"] == true,
        "finalization facts incomplete",
    )?;
    let expected_proof = if repair { REPAIRED_PROOF } else { PROOF };
    require(
        fs::read(&artifact).map_err(|_| "fixture artifact absent")? == expected_proof.as_bytes(),
        "final artifact bytes changed",
    )?;
    Ok(json!({"states":states,"sealed":true,"artifact_matches":true,"restart_resumed":true}))
}

#[test]
fn candidate_persistence_and_complete_protocol_flows() -> Result {
    let candidate = candidate::select()?;
    let mut server = Server::start(&candidate.path)?;
    let owner = server.login()?;
    let fingerprint = server.secret_fingerprint()?;
    let task = super::start(&server, &owner, "compact")?;
    server.restart()?;
    require(
        server.secret_fingerprint()? == fingerprint,
        "same-key restart changed persisted key",
    )?;
    let resumed = server.call(&owner, "rethlas_step", submission(&task)?)?;
    super::advances(&task, &resumed)?;
    super::cancel(&server, &owner, &resumed)?;

    let task = super::start(&server, &owner, "compact")?;
    server.restart_with_changed_test_secret()?;
    let old_auth = server.request(
        "POST",
        "/mcp",
        "application/json",
        br#"{"jsonrpc":"2.0","id":"gate","method":"ping"}"#,
        Some(&owner),
    )?;
    require(
        old_auth.status == 401,
        "old OAuth bearer survived key change",
    )?;
    let owner = server.relogin(&owner)?;
    let rejected = server.call(&owner, "rethlas_step", submission(&task)?)?;
    adopt_refresh(&task, &rejected)?;
    require(
        rejected["writes_applied"].as_u64() == Some(0),
        "old key authorized logical writes",
    )?;
    let fresh = server.call(&owner, "rethlas_step", submission(&rejected)?)?;
    super::advances(&rejected, &fresh)?;
    super::cancel(&server, &owner, &fresh)?;

    seed_v1_state(&mut server, &owner)?;
    let migrated_info = server.call(&owner, "server_info", json!({}))?;
    let legacy = server.call(
        &owner,
        "rethlas_inspect",
        json!({"operation":"status","run_id":"legacy-run"}),
    )?;
    require(
        migrated_info["research_workspace"]["state_schema_version"] == 5
            && legacy["ok"] == true
            && legacy["problem_id"] == "legacy-problem"
            && legacy["state"] == "assess",
        "candidate did not migrate and preserve copied v1 state",
    )?;
    let post_migration = super::start(&server, &owner, "compact")?;
    let advanced = server.call(&owner, "rethlas_step", submission(&post_migration)?)?;
    super::advances(&post_migration, &advanced)?;
    super::cancel(&server, &owner, &advanced)?;

    let mut flows = BTreeMap::new();
    for (mode, repair) in [("compact", false), ("full", false), ("compact", true)] {
        flows.insert(
            if repair { "repair" } else { mode },
            completed_flow(&mut server, &owner, mode, repair)?,
        );
    }
    server.stop()?;
    candidate.unchanged()?;
    let report = json!({"ok":true,"binary_sha256":candidate.sha256,"flows":flows,
        "persisted_secret_owner_only":true,"same_key_restart":true,"changed_key_old_bearer_denied":true,
        "changed_key_old_capability_zero_writes":true,"same_owner_fresh_recovery":true,
        "copied_v1_state_migrated":true,"legacy_row_preserved":true,"new_run_after_migration":true,
        "verifier_firewall":true,"no_premature_artifact":true,"clean_shutdown":true,
        "native_execution_tested":false,"latex_policy":"static_only","web_client_tested":false,
        "independent_mathematical_verification":false,"release_qualified":false});
    println!("MTM_CANDIDATE_LIFECYCLE {report}");
    Ok(())
}
