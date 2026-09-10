//! Exact-candidate capable-host Native command qualification.
//! Scripted permission form responses exercise the public OAuth/MCP boundary;
//! they are command-grant mechanics, not independent human-consent evidence.
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::thread;
use std::time::Duration;

use mtm_contracts::NativeMode;
use serde_json::{Value, json};

use crate::support::candidate;
use crate::support::loopback::{Client, Server};
use crate::support::{Result, require, text};

const ENABLE: &str = "MTM_TEST_NATIVE_COMMAND_PROFILE";
const FORM: &str = "native_permission_consent";
const SOAK_CYCLES: u64 = 32;
const COMMAND_PERMISSION_KINDS: [&str; 7] = [
    "sensitive_env",
    "destructive_command",
    "shell_expansion",
    "inline_script",
    "network",
    "long_timeout",
    "privileged_executable",
];

fn permission_data(result: &Value) -> Result<&Value> {
    require(
        result["resultType"] == "complete",
        "Native permission completion missing",
    )?;
    result
        .get("structuredContent")
        .filter(|value| value.is_object())
        .ok_or("Native permission structured result missing")
}

fn permission_request(kind: &str, arguments: &Value) -> Value {
    json!({
        "tool_name":"exec_command",
        "permission":kind,
        "reason":"Disposable exact-candidate Native command qualification",
        "arguments":arguments,
        "scope":"once",
        "ttl_seconds":300
    })
}

fn permission_challenge(
    server: &Server,
    owner: &Client,
    kind: &str,
    arguments: &Value,
) -> Result<String> {
    let request = permission_request(kind, arguments);
    let result =
        server.permission_message(owner, &request, json!({"elicitation":{"form":{}}}), None)?;
    require(
        result["resultType"] == "input_required",
        "Native command permission challenge missing",
    )?;
    let form = &result["inputRequests"][FORM];
    require(
        form["method"] == "elicitation/create"
            && form["params"]["mode"] == "form"
            && form["params"]["requestedSchema"]["properties"]["approved"]["type"] == "boolean",
        "Native command permission challenge schema invalid",
    )?;
    text(&result, "requestState").map(str::to_owned)
}

fn grant_once(server: &Server, owner: &Client, kind: &str, arguments: &Value) -> Result {
    let request = permission_request(kind, arguments);
    let state = permission_challenge(server, owner, kind, arguments)?;
    let result = server.permission_message(
        owner,
        &request,
        json!({"elicitation":{"form":{}}}),
        Some((
            &state,
            json!({FORM:{"action":"accept","content":{"approved":true}}}),
        )),
    )?;
    let data = permission_data(&result)?;
    require(
        data["ok"] == true
            && data["status"] == "granted"
            && data["constraints"]["workflow_authority_inherited"] == false,
        "Native command once grant was not issued exactly",
    )?;
    text(data, "grant_id")?;
    Ok(())
}

fn permission_required(server: &Server, owner: &Client, arguments: &Value) -> Result {
    let result = server.call(owner, "exec_command", arguments.clone())?;
    require(
        result["ok"] == false && result["error"]["code"] == "PERMISSION_REQUIRED",
        "Native command without exact grant was not denied",
    )
}

fn completed_exec(
    server: &Server,
    owner: &Client,
    stage: &'static str,
    arguments: &Value,
) -> Result<Value> {
    let result = server.call(owner, "exec_command", arguments.clone())?;
    if !(result["ok"] == true && result["status"] == "exited" && result["exit_code"] == 0) {
        eprintln!(
            "MTM_NATIVE_DIAGNOSTIC stage={stage} ok={} status={} exit_code={} signal={} error_code={}",
            result["ok"],
            result["status"],
            result["exit_code"],
            result["signal"],
            result["error"]["code"]
        );
        return Err("Native command did not exit successfully");
    }
    Ok(result)
}

fn exact_once_case(
    server: &Server,
    owner: &Client,
    kind: &'static str,
    arguments: &Value,
) -> Result {
    permission_required(server, owner, arguments)?;
    grant_once(server, owner, kind, arguments)?;
    completed_exec(server, owner, kind, arguments)?;
    permission_required(server, owner, arguments)
}

fn check_environment(server: &Server, owner: &Client, mode: NativeMode) -> Result {
    let environment = server.call(owner, "check_exec_environment", json!({}))?;
    require(
        environment["ok"] == true
            && environment["native_mode"] == mode.as_str()
            && environment["native_exec_backend"] == "BubblewrapExecBackend"
            && environment["hard_isolation_attested"] == true
            && environment["private_vault_visible"] == false,
        "Native command profile isolation or mode drift",
    )
}

fn mode_smoke(binary: &str, mode: NativeMode) -> Result {
    let mut server = Server::start_native_commands(binary, mode)?;
    let owner = server.login()?;
    check_environment(&server, &owner, mode)?;
    let arguments = match mode {
        NativeMode::Safe => json!({
            "argv":["printf","safe-ok"],"yield_time_ms":30_000
        }),
        NativeMode::Trusted => json!({
            "cmd":"printf trusted-${UNSET:-ok}","yield_time_ms":30_000
        }),
        NativeMode::Dangerous => json!({
            "argv":["printf","dangerous-ok"],
            "env":{"API_TOKEN":"fixture-value"},"yield_time_ms":30_000
        }),
    };
    let stage = match mode {
        NativeMode::Safe => "mode_safe",
        NativeMode::Trusted => "mode_trusted",
        NativeMode::Dangerous => "mode_dangerous",
    };
    let result = completed_exec(&server, &owner, stage, &arguments)?;
    require(
        text(&result, "stdout")?.contains("ok"),
        "Native mode smoke returned unexpected output",
    )?;
    server.stop()
}

fn command_permission_cases(binary: &str) -> Result<(u64, u64)> {
    let mut server = Server::start_native_commands(binary, NativeMode::Safe)?;
    let owner = server.login()?;
    check_environment(&server, &owner, NativeMode::Safe)?;

    let privileged = server.workspace_path().join("privileged-fixture");
    fs::copy("/bin/true", &privileged).map_err(|_| "privileged fixture copy failed")?;
    fs::set_permissions(&privileged, fs::Permissions::from_mode(0o4755))
        .map_err(|_| "privileged fixture mode failed")?;

    let cases = [
        (
            "sensitive_env",
            json!({"argv":["printf","sensitive-ok"],"env":{"API_TOKEN":"fixture-value"},"yield_time_ms":30_000}),
        ),
        (
            "destructive_command",
            json!({"argv":["rm","-rf","missing-disposable-target"],"yield_time_ms":30_000}),
        ),
        (
            "shell_expansion",
            json!({"cmd":"printf shell-${UNSET:-ok}","yield_time_ms":30_000}),
        ),
        (
            "inline_script",
            json!({"argv":["sh","-c","printf inline-ok"],"yield_time_ms":30_000}),
        ),
        (
            "network",
            json!({"argv":["curl","--version"],"yield_time_ms":30_000}),
        ),
        (
            "long_timeout",
            json!({"argv":["printf","long-ok"],"timeout_ms":30_001,"yield_time_ms":30_000}),
        ),
        (
            "privileged_executable",
            json!({"argv":["./privileged-fixture"],"yield_time_ms":30_000}),
        ),
    ];
    require(
        cases.iter().map(|(kind, _)| *kind).collect::<Vec<_>>() == COMMAND_PERMISSION_KINDS,
        "Native command permission fixture order drift",
    )?;
    for (kind, arguments) in &cases {
        exact_once_case(&server, &owner, kind, arguments)?;
    }

    let soak = json!({
        "argv":["printf","soak-ok"],"timeout_ms":30_001,"yield_time_ms":30_000
    });
    for _ in 0..SOAK_CYCLES {
        exact_once_case(&server, &owner, "long_timeout", &soak)?;
    }
    server.stop()?;
    Ok((cases.len() as u64, SOAK_CYCLES))
}

fn tty_timeout_and_descendants(binary: &str) -> Result<(bool, bool, bool)> {
    let mut server = Server::start_native_commands(binary, NativeMode::Dangerous)?;
    let owner = server.login()?;
    check_environment(&server, &owner, NativeMode::Dangerous)?;

    let started = server.call(
        &owner,
        "exec_command",
        json!({"argv":["cat"],"tty":true,"yield_time_ms":0,"timeout_ms":5_000}),
    )?;
    require(
        started["ok"] == true && started["status"] == "running",
        "TTY command did not remain owned and running",
    )?;
    let command_id = text(&started, "command_id")?;
    let echoed = server.call(
        &owner,
        "write_stdin",
        json!({"command_id":command_id,"chars":"tty-stdin-ok\n","yield_time_ms":500}),
    )?;
    require(
        echoed["ok"] == true
            && echoed["stdout"]
                .as_str()
                .is_some_and(|value| value.contains("tty-stdin-ok")),
        "TTY stdin did not round-trip through the owned command",
    )?;
    let killed = server.call(
        &owner,
        "kill_command",
        json!({"command_id":command_id,"signal":"TERM","wait_ms":1_000,"kill_wait_ms":1_000}),
    )?;
    require(
        killed["ok"] == true && killed["status"] != "running",
        "TTY command did not terminate through kill_command",
    )?;

    let timeout = server.call(
        &owner,
        "exec_command",
        json!({"argv":["sleep","5"],"timeout_ms":100,"yield_time_ms":30_000}),
    )?;
    require(
        timeout["ok"] == true
            && timeout["status"] == "timeout"
            && timeout["timed_out"] == true
            && (timeout["termination"]["term_sent_by_re_ctm"] == true
                || timeout["termination"]["kill_sent_by_re_ctm"] == true),
        "Native timeout did not exercise owned TERM/KILL lifecycle",
    )?;

    let leak = server.workspace_path().join("descendant-leak.txt");
    let descendant = server.call(
        &owner,
        "exec_command",
        json!({
            "cmd":"printf ready; (sleep 1; printf leaked > descendant-leak.txt) & wait",
            "timeout_ms":5_000,"yield_time_ms":200
        }),
    )?;
    if !(descendant["ok"] == true
        && descendant["status"] == "running"
        && descendant["stdout"]
            .as_str()
            .is_some_and(|value| value.contains("ready")))
    {
        eprintln!(
            "MTM_NATIVE_DIAGNOSTIC stage=descendant_start ok={} status={} exit_code={} signal={} error_code={}",
            descendant["ok"],
            descendant["status"],
            descendant["exit_code"],
            descendant["signal"],
            descendant["error"]["code"]
        );
        return Err("Native descendant fixture did not remain running");
    }
    let descendant_command_id = text(&descendant, "command_id")?;
    let descendant_killed = server.call(
        &owner,
        "kill_command",
        json!({
            "command_id":descendant_command_id,
            "signal":"TERM",
            "wait_ms":1_000,
            "kill_wait_ms":1_000
        }),
    )?;
    require(
        descendant_killed["ok"] == true
            && descendant_killed["killed"] == true
            && matches!(
                descendant_killed["status"].as_str(),
                Some("terminated" | "killed")
            ),
        "Native descendant command group did not terminate through kill_command",
    )?;
    thread::sleep(Duration::from_millis(1_300));
    require(
        !leak.exists(),
        "Native descendant survived process-group cleanup",
    )?;
    require(
        server.process_facts()?["children"] == 0,
        "Native command profile retained an owned child",
    )?;
    server.stop()?;
    Ok((true, true, true))
}

fn cas_functions(binary: &str) -> Result<(bool, bool)> {
    let mut server = Server::start_native_commands(binary, NativeMode::Dangerous)?;
    let owner = server.login()?;
    check_environment(&server, &owner, NativeMode::Dangerous)?;
    let sage = completed_exec(
        &server,
        &owner,
        "sage",
        &json!({"argv":["sage","-c","print(6*7)"],"timeout_ms":120_000,"yield_time_ms":30_000}),
    )?;
    require(
        sage["stdout"]
            .as_str()
            .is_some_and(|value| value.lines().any(|line| line.trim() == "42")),
        "Sage functional fixture did not return 42",
    )?;

    fs::write(
        server.workspace_path().join("magma-check.m"),
        b"print 6*7;\nquit;\n",
    )
    .map_err(|_| "Magma fixture write failed")?;
    let magma = completed_exec(
        &server,
        &owner,
        "magma",
        &json!({"argv":["magma","magma-check.m"],"timeout_ms":120_000,"yield_time_ms":30_000}),
    )?;
    require(
        magma["stdout"]
            .as_str()
            .is_some_and(|value| value.lines().any(|line| line.trim() == "42")),
        "Magma functional fixture did not return 42",
    )?;
    server.stop()?;
    Ok((true, true))
}

#[test]
fn exact_candidate_capable_host_native_commands_and_permission_soak() -> Result {
    if env::var_os(ENABLE).is_none() {
        return Ok(());
    }
    require(
        env::var(ENABLE).ok().as_deref() == Some("1"),
        "Native command profile flag must be exactly one",
    )?;
    let candidate = candidate::select()?;
    mode_smoke(&candidate.path, NativeMode::Safe)?;
    mode_smoke(&candidate.path, NativeMode::Trusted)?;
    mode_smoke(&candidate.path, NativeMode::Dangerous)?;
    let (permission_kinds_granted, soak_cycles) = command_permission_cases(&candidate.path)?;
    let (tty_stdin_passed, timeout_kill_passed, descendant_cleanup_passed) =
        tty_timeout_and_descendants(&candidate.path)?;
    let (sage_functional_passed, magma_functional_passed) = cas_functions(&candidate.path)?;
    candidate.unchanged()?;

    let report = json!({
        "ok":true,
        "candidate_sha256":candidate.sha256,
        "native_backend":"bubblewrap",
        "hard_isolation_attested":true,
        "safe_mode_passed":true,
        "trusted_mode_passed":true,
        "dangerous_mode_passed":true,
        "tty_stdin_passed":tty_stdin_passed,
        "timeout_kill_passed":timeout_kill_passed,
        "descendant_cleanup_passed":descendant_cleanup_passed,
        "sage_functional_passed":sage_functional_passed,
        "magma_functional_passed":magma_functional_passed,
        "command_permission_kinds":COMMAND_PERMISSION_KINDS,
        "permission_kinds_granted":permission_kinds_granted,
        "permission_soak_cycles":soak_cycles,
        "permission_grant_soak_passed":permission_kinds_granted==7 && soak_cycles==SOAK_CYCLES,
        "scripted_consent_only":true,
        "browser_human_consent_tested":false,
        "production_changed":false,
        "release_qualified":false
    });
    println!("MTM_NATIVE_COMMAND_RUNTIME {report}");
    Ok(())
}
