//! Public schema -> authenticated MCP -> actual workspace implementations.
//! Temporary state only; does not qualify Native execution or a browser.
use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};

use crate::support::loopback::{Client, Server};
use crate::support::{Result, require, text};

fn git(path: &Path, arguments: &[&str]) -> Result {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(arguments)
        .env("GIT_AUTHOR_NAME", "MTM fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "MTM fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .output()
        .map_err(|_| "disposable Git setup failed")?;
    require(
        output.status.success(),
        "disposable Git setup did not succeed",
    )
}

fn repository(path: &Path, label: &str) -> Result {
    fs::create_dir_all(path).map_err(|_| "repository directory setup failed")?;
    git(path, &["init", "--quiet"])?;
    fs::write(path.join("a.txt"), format!("{label}\nsecond\n"))
        .map_err(|_| "repository fixture file failed")?;
    git(path, &["add", "--", "a.txt"])?;
    git(
        path,
        &[
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "--quiet",
            "-m",
            label,
        ],
    )
}

fn page_text(server: &Server, owner: &Client, initial: Value) -> Result<String> {
    let mut arguments = initial;
    let mut combined = String::new();
    for _ in 0..64 {
        let result = server.call(owner, "read_file", arguments)?;
        require(result["ok"] == true, "public read_file failed")?;
        let content = text(&result, "content")?;
        require(
            content.len() <= 7,
            "read page exceeded the requested content budget",
        )?;
        combined.push_str(content);
        if result["truncated"] == false {
            require(
                result["next_action"].is_null(),
                "completed page retained a continuation",
            )?;
            return Ok(combined);
        }
        require(
            result["next_action"]["tool"] == "read_file",
            "wrong continuation tool",
        )?;
        arguments = result["next_action"]["arguments"].clone();
    }
    Err("public read continuation failed to make bounded progress")
}

#[test]
fn public_read_paging_and_git_selection_reach_the_real_runtime() -> Result {
    let candidate = crate::support::candidate::select()?;
    let mut server = Server::start_workspace(&candidate.path)?;
    let owner = server.login()?;
    let workspace = server.workspace_path();
    let input = "中文🙂abcdefgh\r\nlast line without newline";
    fs::write(workspace.join("text.txt"), input).map_err(|_| "read fixture failed")?;
    require(
        page_text(
            &server,
            &owner,
            json!({"path":"text.txt","max_bytes":7,"max_lines":1}),
        )? == input,
        "public continuation lost or duplicated content",
    )?;
    let first = server.call(
        &owner,
        "read_file",
        json!({"path":"text.txt","max_bytes":7}),
    )?;
    fs::write(workspace.join("text.txt"), "changed\n").map_err(|_| "changed fixture failed")?;
    let changed = server.call(
        &owner,
        "read_file",
        first["next_action"]["arguments"].clone(),
    )?;
    require(
        changed["error"]["code"] == "READ_FILE_CHANGED",
        "public continuation accepted changed contents",
    )?;

    repository(&workspace, "parent-fixture")?;
    let child = workspace.join("nested");
    repository(&child, "child-fixture")?;
    fs::write(child.join("a.txt"), "changed-child\nsecond\n")
        .map_err(|_| "changed Git fixture failed")?;
    let status = server.call(&owner, "git_status", json!({"repo_path":"nested"}))?;
    require(
        status["ok"] == true && status["repo_path"] == "nested",
        "public Git status selected the wrong repository",
    )?;
    let diff = server.call(
        &owner,
        "git_diff",
        json!({"repo_path":"nested","path":"a.txt"}),
    )?;
    require(
        text(&diff, "diff")?.contains("changed-child"),
        "public Git diff missed the child change",
    )?;
    let log = server.call(
        &owner,
        "git_log",
        json!({"repo_path":"nested","path":"a.txt"}),
    )?;
    require(
        log["commits"][0]["subject"] == "child-fixture",
        "public Git log returned parent history",
    )?;
    let show = server.call(
        &owner,
        "git_show",
        json!({"repo_path":"nested","include_diff":false}),
    )?;
    require(
        text(&show, "content")?.contains("child-fixture"),
        "public Git show returned parent revision",
    )?;
    let blame = server.call(
        &owner,
        "git_blame",
        json!({"repo_path":"nested","path":"a.txt","rev":"HEAD","max_lines":1}),
    )?;
    require(
        blame["lines"][0]["content"] == "child-fixture",
        "public Git blame returned wrong source",
    )?;
    let next = server.call(
        &owner,
        "git_blame",
        blame["next_action"]["arguments"].clone(),
    )?;
    require(
        next["lines"][0]["content"] == "second" && next["truncated"] == false,
        "public blame continuation failed",
    )?;
    let invalid = server.call(&owner, "git_log", json!({"repo_path":"nested/a.txt"}))?;
    require(
        invalid["error"]["code"] == "NOT_A_DIRECTORY",
        "file-valued repo_path was not rejected",
    )?;
    server.stop()?;
    candidate.unchanged()?;
    let summary = json!({"ok":true,"binary_sha256":candidate.sha256,"git_tools_checked":5,
        "utf8_continuation_lossless":true,"changed_file_denied":true,
        "blame_continuation_preserved":true,"child_path":"curl_and_git_only",
        "native_execution_tested":false,"web_client_tested":false,"release_qualified":false});
    println!("MTM_WORKSPACE_SMOKE {summary}");
    Ok(())
}
