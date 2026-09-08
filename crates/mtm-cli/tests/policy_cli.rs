//! Actual pure-policy CLI tests with no inherited environment or executable PATH.
//! Static inputs are data only: no command from the corpus is ever executed.
use std::error::Error;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

#[path = "support/policy_cases.rs"]
mod policy_cases;

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

fn read_bounded(mut file: File) -> Result<Vec<u8>> {
    if file.metadata()?.len() > 1_048_576 {
        return Err("policy subprocess output exceeded bound".into());
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(1_048_577).read_to_end(&mut bytes)?;
    if bytes.len() > 1_048_576 {
        return Err("policy subprocess output changed beyond bound".into());
    }
    Ok(bytes)
}

fn run(mode: &str, input: &[u8]) -> Result<(ExitStatus, Value)> {
    let directory = tempfile::tempdir()?;
    let mut stdin = tempfile::tempfile()?;
    stdin.write_all(input)?;
    stdin.seek(SeekFrom::Start(0))?;
    let stdout = tempfile::tempfile()?;
    let stderr = tempfile::tempfile()?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_mtm"))
        .arg(mode)
        .env_clear()
        .env("PATH", "")
        .current_dir(directory.path())
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?))
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("policy subprocess exceeded deadline or could not be observed".into());
            }
        }
    };
    if !read_bounded(stderr)?.is_empty() || std::fs::read_dir(directory.path())?.next().is_some() {
        return Err("pure policy evaluation emitted stderr or changed its workspace".into());
    }
    let value = serde_json::from_slice(&read_bounded(stdout)?)?;
    Ok((status, value))
}

#[test]
fn entire_policy_corpus_runs_without_python_or_reference_checkout() -> Result {
    let cases = policy_cases::cases();
    let requests: Vec<_> = cases.iter().map(|case| &case.request).collect();
    let input = serde_json::to_vec(&requests)?;
    // Original input byte count recorded in ITER-002, not an output golden hash.
    assert_eq!(input.len(), 13_719);
    let (status, result) = run("evaluate-batch", &input)?;
    assert!(status.success());
    let results = result.as_array().ok_or("policy batch was not an array")?;
    assert_eq!(results.len(), 135);
    for (case, actual) in cases.iter().zip(results) {
        assert!(
            case.matches(actual),
            "CLI policy case failed: {}",
            case.name
        );
    }
    let (second_status, second) = run("evaluate-batch", &input)?;
    assert!(second_status.success());
    assert_eq!(result, second);
    Ok(())
}

#[test]
fn single_and_batch_results_match_for_every_operation() -> Result {
    let cases = policy_cases::cases();
    let mut operations = std::collections::BTreeSet::new();
    for case in cases {
        if !operations.insert(case.request["operation"].as_str().unwrap_or("").to_owned()) {
            continue;
        }
        let (status, single) = run("evaluate", &serde_json::to_vec(&case.request)?)?;
        assert!(status.success());
        assert!(
            case.matches(&single),
            "single policy case failed: {}",
            case.name
        );
        let (status, batch) = run("evaluate-batch", &serde_json::to_vec(&vec![case.request])?)?;
        assert!(status.success());
        assert_eq!(batch, json!([single]));
    }
    assert_eq!(operations.len(), 14);
    Ok(())
}

#[test]
fn batch_count_boundary_accepts_1000_and_rejects_1001() -> Result {
    let request = json!({"operation":"workflow_terminal","value":"done"});
    let (status, output) = run(
        "evaluate-batch",
        &serde_json::to_vec(&vec![request.clone(); 1000])?,
    )?;
    assert!(status.success());
    let rows = output.as_array().ok_or("missing policy results")?;
    assert_eq!(rows.len(), 1000);
    assert!(
        rows.iter()
            .all(|row| row == &json!({"ok":true,"result":true}))
    );
    let (status, output) = run("evaluate-batch", &serde_json::to_vec(&vec![request; 1001])?)?;
    assert_eq!(status.code(), Some(2));
    assert_eq!(output["error"]["code"], "INPUT_TOO_LARGE");
    Ok(())
}

#[test]
fn input_byte_boundary_and_malformed_batches_are_rejected() -> Result {
    let mut exact = vec![b' '; 1_048_576];
    exact[..2].copy_from_slice(b"[]");
    let (status, output) = run("evaluate-batch", &exact)?;
    assert!(status.success());
    assert_eq!(output, json!([]));
    exact.push(b' ');
    let (status, output) = run("evaluate-batch", &exact)?;
    assert_eq!(status.code(), Some(2));
    assert_eq!(output["error"]["code"], "INPUT_TOO_LARGE");
    for (input, code) in [
        (b"{".as_slice(), "INVALID_JSON"),
        (b"{}".as_slice(), "INVALID_ARGUMENT"),
        (b"\xff".as_slice(), "INVALID_JSON"),
    ] {
        let (status, output) = run("evaluate-batch", input)?;
        assert_eq!(status.code(), Some(2));
        assert_eq!(output["error"]["code"], code);
    }
    Ok(())
}

#[test]
fn invalid_items_do_not_skip_or_change_other_batch_results() -> Result {
    let request = json!([null, {}, {"operation":"unknown"}, {"operation":"workflow_terminal","value":"done"}]);
    let (status, output) = run("evaluate-batch", &serde_json::to_vec(&request)?)?;
    assert!(status.success());
    let rows = output.as_array().ok_or("missing policy results")?;
    assert_eq!(rows.len(), 4);
    for row in &rows[..3] {
        assert_eq!(row["ok"], false);
        assert_eq!(row["error"]["code"], "INVALID_ARGUMENT");
    }
    assert_eq!(rows[3], json!({"ok":true,"result":true}));
    Ok(())
}
