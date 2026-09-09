//! Three genuinely independent repeats per portable task; unsupported tasks stay blocked.
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::time::Instant;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::support::candidate;
use crate::support::loopback::{Client, Server};
use crate::support::recovery::error_code;
use crate::support::{Result, require, submission, text};

const ENABLE: &str = "MTM_TEST_CORPUS_PROFILE";
const CORPUS: &str = include_str!("../../../../conformance/mtm016-usability-corpus.json");

struct Corpus {
    schema: String,
    repeats: u64,
    tasks: Vec<Task>,
}

struct Task {
    id: String,
    scenario: String,
    requirement: String,
    expected: String,
}

fn definition() -> Result<Corpus> {
    let value: Value = serde_json::from_str(CORPUS).map_err(|_| "corpus definition invalid")?;
    require(
        value.as_object().is_some_and(|v| v.len() == 3),
        "corpus definition fields",
    )?;
    let mut tasks = Vec::new();
    for task in value["tasks"].as_array().ok_or("corpus tasks missing")? {
        require(
            task.as_object().is_some_and(|v| v.len() == 4),
            "corpus task fields",
        )?;
        tasks.push(Task {
            id: text(task, "id")?.to_owned(),
            scenario: text(task, "scenario")?.to_owned(),
            requirement: text(task, "requirement")?.to_owned(),
            expected: text(task, "expected")?.to_owned(),
        });
    }
    Ok(Corpus {
        schema: text(&value, "schema")?.to_owned(),
        repeats: value["repeats"].as_u64().ok_or("corpus repeat count")?,
        tasks,
    })
}

fn workspace_case(server: &Server, owner: &Client, scenario: &str) -> Result {
    let workspace = server.workspace_path();
    match scenario {
        "utf8_continuation" => {
            let original = "中文🙂abcdef\r\nlast line";
            fs::write(workspace.join("text.txt"), original).map_err(|_| "corpus fixture write")?;
            require(
                crate::workspace_smoke::page_text(
                    server,
                    owner,
                    json!({"path":"text.txt","max_bytes":7,"max_lines":1}),
                )? == original,
                "corpus continuation differs",
            )
        }
        "changed_read_cursor" => {
            fs::write(workspace.join("text.txt"), "before-first\nsecond\n")
                .map_err(|_| "corpus fixture write")?;
            let first =
                server.call(owner, "read_file", json!({"path":"text.txt","max_bytes":7}))?;
            require(first["truncated"] == true, "corpus cursor missing")?;
            fs::write(workspace.join("text.txt"), "after\n").map_err(|_| "corpus fixture write")?;
            let next = server.call(
                owner,
                "read_file",
                first["next_action"]["arguments"].clone(),
            )?;
            require(
                next["error"]["code"] == "READ_FILE_CHANGED",
                "corpus stale cursor accepted",
            )
        }
        "file_target_search" => {
            fs::write(workspace.join("one.txt"), "first\nneedle\nlast\n")
                .map_err(|_| "corpus fixture write")?;
            let result = server.call(
                owner,
                "search_text",
                json!({"path":"one.txt","query":"needle"}),
            )?;
            require(
                result["ok"] == true
                    && result["total_matches"] == 1
                    && result["matches"][0]["line"] == 2,
                "corpus regular-file search failed",
            )
        }
        "ordinary_patch" => {
            let result = server.call(owner, "apply_patch", json!({"patch":"*** Begin Patch\n*** Add File: ordinary.txt\n+corpus-exact\n*** End Patch\n"}))?;
            require(
                result["ok"] == true
                    && fs::read(workspace.join("ordinary.txt"))
                        .map_err(|_| "corpus patch bytes missing")?
                        == b"corpus-exact\n",
                "corpus patch differs",
            )
        }
        "workspace_escape" => {
            let result = server.call(owner, "read_file", json!({"path":"../outside.txt"}))?;
            require(
                result["ok"] == false && result["error"]["category"] == "security",
                "corpus parent escape did not fail at path boundary",
            )
        }
        _ => Err("unknown portable workspace case"),
    }
}

fn git_case(server: &Server, owner: &Client, scenario: &str) -> Result {
    let root = server.workspace_path();
    crate::workspace_smoke::repository(&root, "parent-fixture")?;
    let child = root.join("nested");
    crate::workspace_smoke::repository(&child, "child-fixture")?;
    fs::write(child.join("a.txt"), "changed-child\nsecond\n").map_err(|_| "corpus Git write")?;
    match scenario {
        "nested_git_status" => {
            let value = server.call(owner, "git_status", json!({"repo_path":"nested"}))?;
            require(
                value["ok"] == true && value["repo_path"] == "nested",
                "corpus wrong status repository",
            )
        }
        "nested_git_diff" => {
            let value = server.call(
                owner,
                "git_diff",
                json!({"repo_path":"nested","path":"a.txt"}),
            )?;
            require(
                value["diff"]
                    .as_str()
                    .is_some_and(|v| v.contains("changed-child")),
                "corpus child diff missing",
            )
        }
        "nested_git_log" => {
            let value = server.call(
                owner,
                "git_log",
                json!({"repo_path":"nested","path":"a.txt"}),
            )?;
            require(
                value["commits"][0]["subject"] == "child-fixture",
                "corpus parent history returned",
            )
        }
        "nested_git_show" => {
            let value = server.call(
                owner,
                "git_show",
                json!({"repo_path":"nested","include_diff":false}),
            )?;
            require(
                value["content"]
                    .as_str()
                    .is_some_and(|v| v.contains("child-fixture")),
                "corpus child show missing",
            )
        }
        "nested_git_blame" => {
            let value = server.call(
                owner,
                "git_blame",
                json!({"repo_path":"nested","path":"a.txt","rev":"HEAD","max_lines":1}),
            )?;
            require(
                value["lines"][0]["content"] == "child-fixture",
                "corpus blame first line",
            )?;
            let next = server.call(
                owner,
                "git_blame",
                value["next_action"]["arguments"].clone(),
            )?;
            require(
                next["lines"][0]["content"] == "second" && next["truncated"] == false,
                "corpus blame continuation",
            )
        }
        _ => Err("unknown portable Git case"),
    }
}

fn workflow_case(server: &mut Server, owner: &Client, scenario: &str) -> Result {
    if scenario == "keyed_start_restart" {
        let args = json!({"creation_key":"corpus-keyed-fixture","problem_id":"corpus-keyed",
            "problem_tex":"Disposable workflow protocol fixture","workflow_mode":"compact","register_result":false});
        let first = server.call(owner, "rethlas_start", args.clone())?;
        require(first["runs_created"] == 1, "corpus keyed start failed")?;
        server.restart()?;
        let next = server.call(owner, "rethlas_start", args)?;
        require(
            next["run_id"] == first["run_id"]
                && next["runs_created"] == 0
                && next["state_is_historical"] == true
                && next.get("capability").is_none(),
            "corpus keyed restart duplicated authority",
        )?;
        return crate::cancel(server, owner, &first);
    }
    let mode = if scenario == "full_assessment" {
        "full"
    } else {
        "compact"
    };
    let task = crate::start(server, owner, mode)?;
    match scenario {
        "compact_assessment" | "full_assessment" => {
            let args = crate::candidate_lifecycle::fixture_submission(&task, mode, false)?;
            let result = server.call(owner, "rethlas_step", args)?;
            let expected = if mode == "full" {
                "explore"
            } else {
                "assemble"
            };
            require(
                result["ok"] == true && result["state"] == expected,
                "corpus assessment did not advance",
            )?;
        }
        "recovery_only_missing" | "invalid_capability" => {
            let mut args = submission(&task)?;
            if scenario == "recovery_only_missing" {
                args["recover_only"] = json!(true);
            } else {
                // Syntax-only negative fixture from the catalog tests. No issued
                // capability is decoded or altered, and no signature is created.
                args["capability"] = json!(format!("{}.{}", "A".repeat(40), "B".repeat(43)));
            }
            let result = server.call(owner, "rethlas_step", args)?;
            let expected = if scenario == "recovery_only_missing" {
                "SUBMISSION_RECEIPT_NOT_FOUND"
            } else {
                "CAPABILITY_INVALID"
            };
            require(
                error_code(&result) == expected,
                "corpus invalid request unexpectedly accepted",
            )?;
            if scenario == "invalid_capability" {
                require(
                    result["writes_applied"] == 0,
                    "corpus denied request applied writes",
                )?;
            }
            let state = server.call(
                owner,
                "rethlas_inspect",
                json!({"operation":"status","run_id":task["run_id"]}),
            )?;
            require(
                state["state"] == "assess" && state["pending_submission"].is_null(),
                "corpus denial reserved or advanced work",
            )?;
        }
        _ => return Err("unknown portable workflow case"),
    }
    crate::cancel(server, owner, &task)
}

fn execute(binary: &str, scenario: &str) -> Result {
    // Every call creates a new TempDir, server process, key and OAuth owner.
    let mut server = Server::start_workspace(binary)?;
    let owner = server.login()?;
    if scenario.starts_with("nested_git_") {
        git_case(&server, &owner, scenario)?;
    } else if [
        "compact_assessment",
        "full_assessment",
        "keyed_start_restart",
        "recovery_only_missing",
        "invalid_capability",
    ]
    .contains(&scenario)
    {
        workflow_case(&mut server, &owner, scenario)?;
    } else {
        workspace_case(&server, &owner, scenario)?;
    }
    server.stop()
}

#[test]
fn invalid_corpus_handle_reaches_the_capability_guard() -> Result {
    let candidate = candidate::select()?;
    execute(&candidate.path, "invalid_capability")?;
    candidate.unchanged()
}

#[test]
fn exact_candidate_three_repeat_usability_matrix() -> Result {
    if env::var_os(ENABLE).is_none() {
        return Ok(());
    }
    require(
        env::var(ENABLE).ok().as_deref() == Some("1")
            && env::var_os(candidate::BINARY_ENV).is_some(),
        "corpus requires explicit candidate and exact flag",
    )?;
    let candidate = candidate::select()?;
    let corpus = definition()?;
    require(
        corpus.schema == "mtm-usability-corpus-v1"
            && corpus.repeats == 3
            && corpus.tasks.len() == 30,
        "corpus shape drift",
    )?;
    let mut ids = BTreeSet::new();
    let mut rows = Vec::new();
    for task in corpus.tasks {
        require(
            ids.insert(task.id.clone()) && !task.expected.is_empty(),
            "corpus task identity invalid",
        )?;
        for repeat in 1..=3 {
            let started = Instant::now();
            let (status, reason) = if task.requirement == "portable" {
                match execute(&candidate.path, &task.scenario) {
                    Ok(()) => ("passed", "checks_passed"),
                    Err(error) => {
                        // Only fixed, source-owned fixture diagnostics; no response bodies.
                        eprintln!("corpus {} repeat {}: {}", task.id, repeat, error);
                        ("failed", "scenario_check_failed")
                    }
                }
            } else {
                (
                    "blocked",
                    match task.requirement.as_str() {
                        "native" => "native_host_required",
                        "research" => "independent_research_and_toolchain_required",
                        "external" => "independent_client_or_operator_evidence_required",
                        _ => return Err("unknown corpus requirement"),
                    },
                )
            };
            rows.push(
                json!({"task_id":task.id,"repeat":repeat,"status":status,"reason":reason,
                "elapsed_ms":started.elapsed().as_millis()}),
            );
        }
    }
    candidate.unchanged()?;
    let passed = rows.iter().filter(|v| v["status"] == "passed").count();
    let failed = rows.iter().filter(|v| v["status"] == "failed").count();
    println!(
        "MTM_USABILITY_CORPUS {}",
        json!({
            "schema":"mtm-usability-result-v1","binary_sha256":candidate.sha256,
            "corpus_sha256":format!("{:x}", Sha256::digest(CORPUS.as_bytes())),
            "tasks":30,"repeats":3,"rows":rows,"passed_trials":passed,"failed_trials":failed,
            "blocked_trials":90-passed-failed,"passed":passed==90,
            "native_backend":"disabled","latex_policy":"static_only",
            "independent_research_tested":false,"human_consent_tested":false,"web_client_tested":false,
            "production_changed":false,"release_qualified":false
        })
    );
    require(failed == 0, "one or more portable corpus trials failed")
}
