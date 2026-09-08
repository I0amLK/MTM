//! Current-binary regression runner. Never loads a historical Python harness.
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{Result, git, inventory};

const MARKER: &str = "MTM_CAPABILITY_GATE ";
const CHECKS: [&str; 8] = [
    "cross_owner_refresh_denied",
    "cross_run_denied",
    "fresh_submission_advances",
    "invalid_submission_zero_memory_changes",
    "mutated_and_truncated_signature",
    "invalid_inspect_and_retrieve_denied",
    "revoked_inspect_and_retrieve_denied",
    "used_capability_revoked",
];

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Summary {
    schema_version: String,
    kind: String,
    version: String,
    ok: bool,
    binary_sha256: String,
    binary_unchanged: bool,
    bounded_clean_shutdown: bool,
    child_path_policy: String,
    samples_requested: u64,
    independent_normal_runs: u64,
    normal_roundtrips: u64,
    normal_invalid: u64,
    normal_rejections: u64,
    normal_modes: BTreeMap<String, u64>,
    adversarial_checks: BTreeMap<String, bool>,
    lost_outcome_no_automatic_replay: bool,
    same_identity_and_capability_survive_restart: bool,
    native_backend: String,
    latex_policy: String,
    external_retrieval_tested: bool,
    web_client_tested: bool,
    production_state_modified: bool,
    raw_capability_recorded: bool,
    raw_oauth_token_recorded: bool,
    release_qualified: bool,
}

fn extract(stdout: &[u8]) -> Result<Summary> {
    if stdout.len() > 2 * 1024 * 1024 {
        return Err("test output exceeded bound".into());
    }
    let text = std::str::from_utf8(stdout).map_err(|_| "test output was not UTF-8")?;
    let mut reports = text.lines().filter_map(|line| line.split_once(MARKER));
    let (_, report) = reports
        .next()
        .ok_or("capability test produced no summary")?;
    if reports.next().is_some() || report.len() > 16_384 {
        return Err("duplicate or oversized capability summary".into());
    }
    serde_json::from_str(report).map_err(|_| "capability summary schema invalid".into())
}

fn validate(summary: &Summary) -> Result<()> {
    let expected_checks = BTreeMap::from(CHECKS.map(|name| (name.to_owned(), true)));
    let expected_modes = BTreeMap::from([("compact".to_owned(), 250), ("full".to_owned(), 250)]);
    if !summary.ok
        || summary.schema_version != "1.0.0"
        || summary.kind != "rust_current_binary_loopback_capability_regression"
        || summary.binary_sha256.len() != 64
        || !summary.binary_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || summary.version.is_empty()
        || summary.version.len() > 64
        || !summary
            .version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
        || summary.samples_requested != 500
        || summary.independent_normal_runs != 500
        || summary.normal_roundtrips != 500
        || summary.normal_invalid != 0
        || summary.normal_rejections != 0
        || summary.normal_modes != expected_modes
        || summary.adversarial_checks != expected_checks
        || !summary.binary_unchanged
        || !summary.bounded_clean_shutdown
        || !summary.lost_outcome_no_automatic_replay
        || !summary.same_identity_and_capability_survive_restart
        || summary.child_path_policy != "curl_only_no_python"
        || summary.native_backend != "disabled"
        || summary.latex_policy != "static_only"
        || summary.external_retrieval_tested
        || summary.web_client_tested
        || summary.production_state_modified
        || summary.raw_capability_recorded
        || summary.raw_oauth_token_recorded
        || summary.release_qualified
    {
        return Err("capability regression did not meet its exact scope and counts".into());
    }
    Ok(())
}

pub(crate) fn checked_summary(stdout: &[u8]) -> Result<Value> {
    let summary = extract(stdout)?;
    validate(&summary)?;
    Ok(serde_json::to_value(summary)?)
}

pub(crate) fn source_hash(root: &Path) -> Result<String> {
    let listed = git(
        root,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
    )?;
    let deleted = git(root, &["ls-files", "-z", "--deleted"])?;
    let (paths, _) = inventory::current_paths(&listed, &deleted)?;
    let mut hash = Sha256::new();
    hash.update(b"mtm-rust-source-v1\0");
    for path in paths {
        if !path.starts_with("crates/")
            && !path.starts_with("xtask/")
            && ![
                "Cargo.toml",
                "Cargo.lock",
                "rust-toolchain.toml",
                ".cargo/config.toml",
            ]
            .contains(&path.as_str())
        {
            continue;
        }
        let file = root.join(&path);
        let metadata = fs::symlink_metadata(&file)?;
        if !metadata.is_file()
            || metadata.len() > 8 * 1024 * 1024
            || !file.canonicalize()?.starts_with(root)
        {
            return Err("source identity contains an unsupported file".into());
        }
        hash.update((path.len() as u64).to_be_bytes());
        hash.update(path.as_bytes());
        hash.update(Sha256::digest(fs::read(file)?));
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub(crate) fn run(root: &Path) -> Result<Value> {
    let before = source_hash(root)?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    eprintln!("[capability] built-binary socket/OAuth/500-run regression");
    let output = Command::new(cargo)
        .env_remove("MTM_TEST_CANDIDATE")
        .env_remove("MTM_TEST_CANDIDATE_SHA256")
        .args([
            "test",
            "--locked",
            "-p",
            "mtm-cli",
            "--test",
            "capability_runtime",
            "--",
            "--nocapture",
            "--test-threads=1",
        ])
        .current_dir(root)
        .stdin(Stdio::null())
        .output()?;
    let after = source_hash(root)?;
    let summary = extract(&output.stdout).and_then(|summary| {
        validate(&summary)?;
        Ok(summary)
    });
    let passed = output.status.success() && before == after && summary.is_ok();
    let mut report = json!({
        "schema_version":"1.0.0","milestone":"MTM-016","scope":"current_binary_loopback_not_release",
        "passed":passed,"exit_code":output.status.code(),"source_sha256":before,
        "source_unchanged":before==after,"release_qualified":false,
        "test_stdout_sha256":format!("{:x}",Sha256::digest(&output.stdout)),
        "test_stderr_sha256":format!("{:x}",Sha256::digest(&output.stderr)),
        "raw_test_output_recorded":false
    });
    if passed {
        report["summary"] =
            serde_json::to_value(summary.map_err(|_| "missing validated summary")?)?;
    } else {
        report["failure"] =
            json!("test runner failed, source changed, or summary did not meet gate");
    }
    Ok(report)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn fixture() -> Value {
        json!({
            "schema_version":"1.0.0","kind":"rust_current_binary_loopback_capability_regression",
            "version":"0.6.0-preview.1","ok":true,"binary_sha256":"a".repeat(64),
            "binary_unchanged":true,"bounded_clean_shutdown":true,"child_path_policy":"curl_only_no_python",
            "samples_requested":500,"independent_normal_runs":500,"normal_roundtrips":500,
            "normal_invalid":0,"normal_rejections":0,"normal_modes":{"compact":250,"full":250},
            "adversarial_checks":BTreeMap::from(CHECKS.map(|name|(name,true))),
            "lost_outcome_no_automatic_replay":true,"same_identity_and_capability_survive_restart":true,
            "native_backend":"disabled","latex_policy":"static_only","external_retrieval_tested":false,
            "web_client_tested":false,"production_state_modified":false,"raw_capability_recorded":false,
            "raw_oauth_token_recorded":false,"release_qualified":false
        })
    }

    #[test]
    fn summary_requires_real_counts_all_checks_and_honest_scope() -> Result<()> {
        validate(&serde_json::from_value(fixture())?)?;
        for (key, value) in [
            ("normal_roundtrips", json!(499)),
            ("normal_invalid", json!(1)),
            ("independent_normal_runs", json!(1)),
            ("adversarial_checks", json!({})),
            ("web_client_tested", json!(true)),
            ("release_qualified", json!(true)),
            ("bounded_clean_shutdown", json!(false)),
            ("binary_sha256", json!("invalid")),
        ] {
            let mut changed = fixture();
            changed[key] = value;
            assert!(validate(&serde_json::from_value(changed)?).is_err());
        }
        Ok(())
    }

    #[test]
    fn missing_duplicate_or_secret_bearing_summary_is_rejected() -> Result<()> {
        let line = format!("test current ... {MARKER}{}\nok\n", fixture());
        validate(&extract(line.as_bytes())?)?;
        assert!(extract(b"test result: ok; no actual summary").is_err());
        assert!(extract(format!("{line}{line}").as_bytes()).is_err());
        let mut extra = fixture();
        extra["capability"] = json!("not permitted in a report");
        assert!(extract(format!("{MARKER}{extra}").as_bytes()).is_err());
        Ok(())
    }
}
