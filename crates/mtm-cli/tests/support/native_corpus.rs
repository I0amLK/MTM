//! Independent U16-U20 trials. Never imports successful observations as runs.
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use mtm_contracts::NativeMode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::native_command_runtime::check_environment;
use crate::support::candidate;
use crate::support::loopback::{Client, Server};
use crate::support::{Result, require, text};

const ENABLE: &str = "MTM_TEST_NATIVE_CORPUS_PROFILE";
const CORPUS: &str = include_str!("../../../../conformance/mtm016-usability-corpus.json");
const TASKS: [(&str, &str, &[&str]); 5] = [
    (
        "U16",
        "native_direct_argv",
        &["literal_metacharacters", "exact_stdout"],
    ),
    (
        "U17",
        "native_compound_path",
        &["compound_path", "nested_cwd", "missing_executable_denied"],
    ),
    (
        "U18",
        "native_tty_stdin",
        &[
            "tty_running",
            "stdin_roundtrip",
            "bounded_output",
            "explicit_kill",
        ],
    ),
    (
        "U19",
        "native_timeout_descendants",
        &["timeout", "explicit_kill", "descendant_write_absent"],
    ),
    (
        "U20",
        "native_network_permissions",
        &[
            "dangerous_network",
            "repeated_without_grant",
            "network_shared_vault_hidden",
        ],
    ),
];
const COMMON_CHECKS: [&str; 4] = [
    "hard_isolation",
    "private_vault_hidden",
    "children_reaped",
    "clean_shutdown",
];

fn ordinary_exit(value: &Value) -> Result {
    require(
        value["ok"] == true
            && value["status"] == "exited"
            && value["exit_code"].as_i64() == Some(0)
            && value.get("signal") == Some(&Value::Null)
            && value["timed_out"] == false
            && value["truncated"] == false,
        "Native corpus command exit or output invalid",
    )
}

fn no_children(server: &Server) -> Result {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if server.process_facts()?["children"] == 0 {
            return Ok(());
        }
        require(
            Instant::now() < deadline,
            "Native corpus child was not reaped",
        )?;
        thread::sleep(Duration::from_millis(20));
    }
}

fn isolated_case(
    binary: &str,
    mode: NativeMode,
    body: impl FnOnce(&Server, &Client) -> Result,
) -> Result {
    // Fresh directory, process, signing key and OAuth owner for every call.
    let mut server = Server::start_native_corpus(binary, mode)?;
    let outcome = (|| {
        let owner = server.login()?;
        check_environment(&server, &owner, mode)?;
        body(&server, &owner)?;
        no_children(&server)
    })();
    let stopped = server.stop();
    outcome.and(stopped)
}

fn direct_argv(binary: &str, nonce: &str) -> Result {
    isolated_case(binary, NativeMode::Dangerous, |server, owner| {
        let literal = format!("{nonce}; $HOME | * ' \" $(not-a-command) \\");
        let reply = server.call(
            owner,
            "exec_command",
            json!({
                "argv":["printf","%s",literal],"yield_time_ms":30000
            }),
        )?;
        ordinary_exit(&reply)?;
        require(
            reply["stdout"] == literal && reply["stderr"] == "",
            "Native corpus argv was reinterpreted",
        )
    })
}

fn compound_path(binary: &str, nonce: &str) -> Result {
    isolated_case(binary, NativeMode::Dangerous, |server, owner| {
        let nested = server.workspace_path().join("nested");
        fs::create_dir(&nested).map_err(|_| "Native corpus cwd fixture creation failed")?;
        fs::write(nested.join("input.txt"), nonce)
            .map_err(|_| "Native corpus input write failed")?;
        let reply = server.call(
            owner,
            "exec_command",
            json!({
                "cmd":"printf 'compound:';cat input.txt","workdir":"nested","yield_time_ms":30000
            }),
        )?;
        ordinary_exit(&reply)?;
        require(
            reply["stdout"] == format!("compound:{nonce}"),
            "Native corpus compound PATH/cwd mismatch",
        )?;
        let direct = server.call(
            owner,
            "exec_command",
            json!({
                "argv":["cat","input.txt"],"workdir":"nested","yield_time_ms":30000
            }),
        )?;
        ordinary_exit(&direct)?;
        require(
            direct["stdout"] == nonce,
            "Native corpus direct cwd mismatch",
        )?;
        let denied = server.call(owner, "exec_command", json!({
            "cmd":"printf must-not-run;mtm-corpus-missing-executable","workdir":"nested","yield_time_ms":30000
        }))?;
        require(
            denied["ok"] == false
                && denied["error"]["code"] == "NATIVE_EXECUTABLE_UNRESOLVED"
                && denied.get("command_id").is_none(),
            "Native corpus unresolved compound was launched",
        )
    })
}

fn killed(server: &Server, owner: &Client, id: &str) -> Result {
    let reply = server.call(
        owner,
        "kill_command",
        json!({
            "command_id":id,"signal":"TERM","wait_ms":1000,"kill_wait_ms":1000
        }),
    )?;
    require(
        reply["ok"] == true
            && reply["killed"] == true
            && matches!(reply["status"].as_str(), Some("terminated" | "killed")),
        "Native corpus explicit kill did not terminate",
    )
}

fn tty_stdin(binary: &str, nonce: &str) -> Result {
    isolated_case(binary, NativeMode::Dangerous, |server, owner| {
        let reply = server.call(
            owner,
            "exec_command",
            json!({
                "argv":["cat"],"tty":true,"timeout_ms":10000,"yield_time_ms":0,
                "max_output_bytes":1024,"preview_bytes":1024
            }),
        )?;
        require(
            reply["ok"] == true && reply["status"] == "running",
            "Native corpus TTY did not start",
        )?;
        let id = text(&reply, "command_id")?;
        let echoed = server.call(
            owner,
            "write_stdin",
            json!({
                "command_id":id,"chars":format!("{nonce}\n"),"yield_time_ms":500,
                "max_output_bytes":1024,"preview_bytes":1024
            }),
        )?;
        require(
            echoed["ok"] == true
                && echoed["stdout"]
                    .as_str()
                    .is_some_and(|s| s.contains(nonce) && s.len() <= 1024)
                && echoed["truncated"] == false,
            "Native corpus TTY stdin or output bound failed",
        )?;
        let bounded = server.call(
            owner,
            "write_stdin",
            json!({
                "command_id":id,"chars":format!("{}\n", "x".repeat(2048)),
                "yield_time_ms":500,"max_output_bytes":128,"preview_bytes":128
            }),
        )?;
        require(
            bounded["ok"] == true
                && bounded["stdout"].as_str().is_some_and(|s| s.len() <= 128)
                && bounded["stdout_truncated"] == true
                && bounded["truncated"] == true,
            "Native corpus TTY large output was not bounded",
        )?;
        killed(server, owner, id)
    })
}

fn descendant_case(server: &Server, owner: &Client, manual_kill: bool) -> Result {
    let file = if manual_kill {
        "kill-leak"
    } else {
        "timeout-leak"
    };
    let script = server.workspace_path().join("spawn-descendant.sh");
    fs::write(
        &script,
        format!("#!/bin/sh\n(sleep 2; printf leaked > {file}) &\nprintf ready\nwait\n"),
    )
    .map_err(|_| "Native corpus descendant fixture write failed")?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755))
        .map_err(|_| "Native corpus descendant fixture mode failed")?;
    let started = server.call(
        owner,
        "exec_command",
        json!({
            "argv":["./spawn-descendant.sh"],"yield_time_ms":200,
            "timeout_ms":if manual_kill {10000} else {1000}
        }),
    )?;
    require(
        started["ok"] == true
            && started["status"] == "running"
            && started["stdout"]
                .as_str()
                .is_some_and(|s| s.contains("ready")),
        "Native corpus descendant fixture never became ready",
    )?;
    let id = text(&started, "command_id")?;
    if manual_kill {
        killed(server, owner, id)?;
    } else {
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            let state = server.call(
                owner,
                "write_stdin",
                json!({"command_id":id,"chars":"","yield_time_ms":200}),
            )?;
            require(state["ok"] == true, "Native corpus timeout polling failed")?;
            if state["status"] != "running" {
                require(
                    state["status"] == "timeout"
                        && state["timed_out"] == true
                        && (state["termination"]["term_sent_by_re_ctm"] == true
                            || state["termination"]["kill_sent_by_re_ctm"] == true),
                    "Native corpus timeout did not terminate its command",
                )?;
                break;
            }
            require(
                Instant::now() < deadline,
                "Native corpus timeout deadline exceeded",
            )?;
        }
    }
    thread::sleep(Duration::from_millis(2200));
    require(
        !server.workspace_path().join(file).exists(),
        "Native corpus descendant survived termination",
    )?;
    no_children(server)
}

/// An owned test endpoint, never an external service. All I/O and joining bounded.
struct Endpoint {
    address: String,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result>>,
}

impl Endpoint {
    fn start(nonce: &str) -> Result<Self> {
        let listener =
            TcpListener::bind("127.0.0.1:0").map_err(|_| "Native corpus endpoint bind failed")?;
        listener
            .set_nonblocking(true)
            .map_err(|_| "Native corpus endpoint configuration failed")?;
        let address = format!(
            "http://{}/{nonce}",
            listener
                .local_addr()
                .map_err(|_| "Native corpus endpoint identity unavailable")?
        );
        let stop = Arc::new(AtomicBool::new(false));
        let hits = Arc::new(AtomicUsize::new(0));
        let thread_stop = Arc::clone(&stop);
        let thread_hits = Arc::clone(&hits);
        let body = nonce.to_owned();
        let worker = thread::Builder::new().name("mtm-native-corpus-http".into()).spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(90);
            while !thread_stop.load(Ordering::SeqCst) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, peer)) => {
                        require(peer.ip().is_loopback(), "Native corpus endpoint peer invalid")?;
                        stream.set_write_timeout(Some(Duration::from_secs(1))).map_err(|_| "Native corpus endpoint write bound failed")?;
                        let mut request = Vec::new();
                        let mut buffer = [0_u8; 512];
                        let read_deadline = Instant::now() + Duration::from_secs(2);
                        while !request.windows(4).any(|s| s == b"\r\n\r\n") {
                            let remaining = read_deadline.saturating_duration_since(Instant::now());
                            require(!remaining.is_zero(), "Native corpus endpoint request deadline")?;
                            stream.set_read_timeout(Some(remaining)).map_err(|_| "Native corpus endpoint read bound failed")?;
                            let count = stream.read(&mut buffer).map_err(|_| "Native corpus endpoint read failed")?;
                            require(count != 0 && request.len() + count <= 4096, "Native corpus endpoint request bound")?;
                            request.extend_from_slice(&buffer[..count]);
                        }
                        require(request.starts_with(format!("GET /{body} HTTP/1.1\r\n").as_bytes()), "Native corpus endpoint request mismatch")?;
                        let count = thread_hits.fetch_add(1, Ordering::SeqCst) + 1;
                        require(count <= 3, "Native corpus endpoint received unexpected requests")?;
                        let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                        stream.write_all(response.as_bytes()).map_err(|_| "Native corpus endpoint response failed")?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(10)),
                    Err(_) => return Err("Native corpus endpoint accept failed"),
                }
            }
            require(Instant::now() < deadline, "Native corpus endpoint lifetime exceeded")
        }).map_err(|_| "Native corpus endpoint worker could not start")?;
        Ok(Self {
            address,
            hits,
            stop,
            worker: Some(worker),
        })
    }

    fn finish(mut self) -> Result {
        self.stop.store(true, Ordering::SeqCst);
        self.worker
            .take()
            .ok_or("Native corpus endpoint worker missing")?
            .join()
            .map_err(|_| "Native corpus endpoint worker failed")??;
        require(
            self.hits.load(Ordering::SeqCst) == 3,
            "Native corpus network hit count mismatch",
        )
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// U20 (MTM-017 dangerous-only revision): the shared network namespace reaches
/// an owned endpoint repeatedly with no grant, and the private vault stays
/// hidden while networking is shared. Safe/trusted/grant checks were retired.
fn network_permissions(binary: &str, nonce: &str) -> Result {
    let endpoint = Endpoint::start(nonce)?;
    let arguments = json!({"argv":["curl","-q","--silent","--show-error","--noproxy","*","--max-time","1","--http1.1",endpoint.address],"yield_time_ms":30000});
    isolated_case(binary, NativeMode::Dangerous, |server, owner| {
        for expected_hits in 1..=3 {
            let reply = server.call(owner, "exec_command", arguments.clone())?;
            ordinary_exit(&reply)?;
            require(
                reply["stdout"] == nonce && endpoint.hits.load(Ordering::SeqCst) == expected_hits,
                "Native corpus dangerous network request mismatch",
            )?;
        }
        let environment = server.call(owner, "check_exec_environment", json!({}))?;
        require(
            environment["network_allowed"] == true && environment["private_vault_visible"] == false,
            "Native corpus dangerous profile did not share network with a hidden vault",
        )
    })?;
    endpoint.finish()
}

#[test]
fn native_task_definitions_match_the_frozen_corpus() -> Result {
    let definition: Value =
        serde_json::from_str(CORPUS).map_err(|_| "Native corpus definition invalid")?;
    require(
        definition["repeats"] == 3,
        "Native corpus repeat definition changed",
    )?;
    let tasks = definition["tasks"]
        .as_array()
        .ok_or("Native corpus tasks missing")?;
    for (id, scenario, _) in TASKS {
        let matches: Vec<_> = tasks.iter().filter(|task| task["id"] == id).collect();
        require(
            matches.len() == 1
                && matches[0]["scenario"] == scenario
                && matches[0]["requirement"] == "native",
            "Native corpus task contract drift",
        )?;
    }
    Ok(())
}

#[test]
fn native_exit_check_rejects_missing_or_failed_process_evidence() -> Result {
    let good = json!({"ok":true,"status":"exited","exit_code":0,"signal":null,"timed_out":false,"truncated":false});
    assert!(ordinary_exit(&good).is_ok());
    for key in [
        "ok",
        "status",
        "exit_code",
        "signal",
        "timed_out",
        "truncated",
    ] {
        let mut missing = good.clone();
        missing.as_object_mut().ok_or("fixture object")?.remove(key);
        assert!(ordinary_exit(&missing).is_err());
    }
    for (key, value) in [
        ("exit_code", json!(1)),
        ("exit_code", json!(0.0)),
        ("signal", json!(15)),
        ("status", json!("running")),
        ("timed_out", json!(true)),
        ("truncated", json!(true)),
    ] {
        let mut bad = good.clone();
        bad[key] = value;
        assert!(ordinary_exit(&bad).is_err());
    }
    Ok(())
}

#[test]
fn owned_network_fixture_counts_and_joins_without_native_claims() -> Result {
    use std::net::TcpStream;
    let nonce = "fixture-only-public-evidence-id";
    let endpoint = Endpoint::start(nonce)?;
    let address = endpoint
        .address
        .strip_prefix("http://")
        .and_then(|s| s.split_once('/'))
        .ok_or("fixture address")?
        .0;
    for _ in 0..3 {
        let mut stream = TcpStream::connect(address).map_err(|_| "fixture connect")?;
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(|_| "fixture read bound")?;
        stream
            .write_all(format!("GET /{nonce} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .map_err(|_| "fixture write")?;
        let mut response = String::new();
        stream
            .take(4096)
            .read_to_string(&mut response)
            .map_err(|_| "fixture response")?;
        require(response.ends_with(nonce), "fixture response binding")?;
    }
    endpoint.finish()
}

#[test]
fn exact_candidate_three_repeat_native_matrix() -> Result {
    if env::var_os(ENABLE).is_none() {
        return Ok(());
    }
    require(
        env::var(ENABLE).ok().as_deref() == Some("1")
            && env::var_os(candidate::BINARY_ENV).is_some(),
        "Native corpus requires exact flag and selected candidate",
    )?;
    native_task_definitions_match_the_frozen_corpus()?;
    let candidate = candidate::select()?;
    let mut rows = Vec::new();
    let mut nonces = BTreeSet::new();
    for (id, scenario, checks) in TASKS {
        for repeat in 1..=3 {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random)
                .map_err(|_| "Native corpus trial randomness unavailable")?;
            // Public evidence ID, generated independently of all credentials.
            let trial_id: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            require(
                nonces.insert(trial_id.clone()),
                "Native corpus duplicate trial identity",
            )?;
            let started = Instant::now();
            let outcome = match id {
                "U16" => direct_argv(&candidate.path, &trial_id),
                "U17" => compound_path(&candidate.path, &trial_id),
                "U18" => tty_stdin(&candidate.path, &trial_id),
                "U19" => isolated_case(&candidate.path, NativeMode::Dangerous, |server, owner| {
                    descendant_case(server, owner, false)?;
                    descendant_case(server, owner, true)
                }),
                "U20" => network_permissions(&candidate.path, &trial_id),
                _ => return Err("unimplemented Native corpus task"),
            };
            let mut observed = Vec::new();
            if let Err(error) = outcome {
                eprintln!("MTM_NATIVE_CORPUS_DIAGNOSTIC task={id} repeat={repeat}: {error}");
            } else {
                observed.extend(COMMON_CHECKS);
                observed.extend_from_slice(checks);
            }
            rows.push(
                json!({"task_id":id,"scenario":scenario,"repeat":repeat,"trial_id":trial_id,
                "status":if outcome.is_ok() {"passed"} else {"failed"},
                "reason":if outcome.is_ok() {"checks_passed"} else {"scenario_check_failed"},
                "checks":observed,"elapsed_ms":started.elapsed().as_millis()}),
            );
        }
    }
    candidate.unchanged()?;
    let passed = rows.iter().filter(|row| row["status"] == "passed").count();
    println!(
        "MTM_NATIVE_CORPUS {}",
        json!({"schema":"mtm-native-corpus-result-v1",
        "candidate_sha256":candidate.sha256,"corpus_sha256":format!("{:x}",Sha256::digest(CORPUS.as_bytes())),
        "rows":rows,"tasks":5,"repeats":3,"passed_trials":passed,"failed_trials":15-passed,
        "passed":passed==15,"native_backend":"bubblewrap","latex_policy":"static_only",
        "scripted_consent_only":true,"human_consent_tested":false,"independent_research_tested":false,
        "production_changed":false,"release_qualified":false})
    );
    require(passed == 15, "one or more Native corpus trials failed")
}
