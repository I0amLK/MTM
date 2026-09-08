//! Exact-artifact protocol profile. No installation, production data or Python.
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{Result, capability, git, native_preflight::process};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[path = "qualify_summary.rs"]
mod summary;
const MAX_BINARY: u64 = 256 * 1024 * 1024;

pub(crate) struct Options {
    binary: String,
    sha256: String,
    pub record: bool,
}

impl Options {
    pub fn parse(arguments: &[String]) -> Result<Self> {
        let mut options = BTreeMap::new();
        let mut record = false;
        let mut args = arguments.iter();
        while let Some(name) = args.next() {
            if name == "--record" && !record {
                record = true;
                continue;
            }
            if !["--binary", "--sha256", "--profile"].contains(&name.as_str())
                || options.contains_key(name)
            {
                return Err("unknown or duplicate qualification option".into());
            }
            let value = args
                .next()
                .filter(|s| !s.is_empty() && !s.starts_with("--"))
                .ok_or("qualification option requires a value")?;
            options.insert(name.clone(), value.clone());
        }
        if options.get("--profile").map(String::as_str) != Some("protocol") {
            return Err("explicit --profile protocol is required; release qualification is not implemented here".into());
        }
        let sha256 = options.remove("--sha256").ok_or("--sha256 is required")?;
        if !valid_hash(&sha256) {
            return Err("SHA-256 must be 64 lowercase hexadecimal characters".into());
        }
        Ok(Self {
            binary: options.remove("--binary").ok_or("--binary is required")?,
            sha256,
            record,
        })
    }
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn digest(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "candidate metadata unavailable")?;
    if !metadata.is_file()
        || metadata.len() > MAX_BINARY
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.permissions().mode() & 0o6000 != 0
    {
        return Err(
            "candidate must be a bounded regular executable without special permission bits".into(),
        );
    }
    let mut file = File::open(path).map_err(|_| "candidate cannot be read")?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    let mut total = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| "candidate read failed")?;
        if count == 0 {
            break;
        }
        if total == 0 && !buffer[..count].starts_with(b"\x7fELF") {
            return Err("candidate must be a Linux ELF artifact, not a script".into());
        }
        total += count as u64;
        if total > MAX_BINARY {
            return Err("candidate grew beyond bound".into());
        }
        hash.update(&buffer[..count]);
    }
    if total < 64 {
        return Err("candidate artifact truncated".into());
    }
    Ok(format!("{:x}", hash.finalize()))
}

struct Snapshot {
    _directory: tempfile::TempDir,
    original: PathBuf,
    executable: PathBuf,
    sha256: String,
}

impl Snapshot {
    fn prepare(root: &Path, options: &Options) -> Result<Self> {
        let original = root.join(&options.binary);
        if digest(&original)? != options.sha256 {
            return Err("candidate SHA-256 mismatch before launch".into());
        }
        let directory = tempfile::tempdir().map_err(|_| "candidate snapshot directory failed")?;
        let executable = directory.path().join("mtm-candidate");
        let mut target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&executable)
            .map_err(|_| "candidate snapshot creation failed")?;
        let mut source = File::open(&original)
            .map_err(|_| "candidate copy read failed")?
            .take(MAX_BINARY + 1);
        let copied = std::io::copy(&mut source, &mut target)
            .map_err(|_| "candidate snapshot copy failed")?;
        if copied > MAX_BINARY {
            return Err("candidate copy exceeded bound".into());
        }
        target
            .sync_all()
            .map_err(|_| "candidate snapshot sync failed")?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o500))
            .map_err(|_| "candidate snapshot mode failed")?;
        let snapshot = Self {
            _directory: directory,
            original,
            executable,
            sha256: options.sha256.clone(),
        };
        snapshot.unchanged()?;
        Ok(snapshot)
    }

    fn unchanged(&self) -> Result<()> {
        if digest(&self.original)? != self.sha256 || digest(&self.executable)? != self.sha256 {
            return Err("original or snapshot identity changed".into());
        }
        Ok(())
    }
}

pub(crate) fn run(root: &Path, options: &Options) -> Result<Value> {
    let mut report = json!({"schema_version":"1.0.0","milestone":"MTM-016","delivery":"D5",
        "profile":"protocol","scope":"exact_candidate_protocol_not_release","passed":false,
        "candidate_sha256":options.sha256,"candidate_launched":false,
        "release_qualified":false,"production_state_modified":false,"selector_changed":false,
        "raw_test_output_recorded":false,"python_invoked":false,
        "pending":["Native host","compiled LaTeX","browser","resources","upgrade and rollback","Python retirement"]});
    let mut stage = "candidate_snapshot";
    let outcome = (|| -> Result<()> {
        let snapshot = Snapshot::prepare(root, options)?;
        let before = capability::source_hash(root)?;
        let commit_before = git(root, &["rev-parse", "HEAD"])?;
        stage = "protocol_test_runner";
        let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let mut command = Command::new(cargo);
        command
            .args([
                "test",
                "--locked",
                "--offline",
                "-p",
                "mtm-cli",
                "--test",
                "capability_runtime",
                "--",
                "--nocapture",
                "--test-threads=1",
            ])
            .current_dir(root)
            .env("MTM_TEST_CANDIDATE", &snapshot.executable)
            .env("MTM_TEST_CANDIDATE_SHA256", &snapshot.sha256);
        eprintln!("[qualify] exact-artifact protocol, capability and workspace fixtures");
        let output = process::capture_command(
            &mut command,
            Duration::from_secs(600),
            2 * 1024 * 1024,
            true,
        )
        .map_err(|_| "qualification runner start or capture failed")?;
        report["runner"] = output.summary();
        report["test_stdout_sha256"] = json!(format!("{:x}", Sha256::digest(&output.stdout)));
        report["test_stderr_sha256"] = json!(format!("{:x}", Sha256::digest(&output.stderr)));
        stage = "identity_recheck";
        snapshot.unchanged()?;
        let after = capability::source_hash(root)?;
        let commit_after = git(root, &["rev-parse", "HEAD"])?;
        report["harness_source_identity"] = json!({"before_sha256":before,"after_sha256":after,
            "commit":String::from_utf8_lossy(&commit_before).trim(),"unchanged":before==after && commit_before==commit_after});
        if before != after || commit_before != commit_after {
            return Err("qualification harness source changed".into());
        }
        stage = "summary_validation";
        let summaries = summary::validate(&output.stdout, &snapshot.sha256)?;
        if !output.complete() {
            return Err("qualification runner failed or did not finish cleanly".into());
        }
        report["candidate_launched"] = json!(true);
        report["summaries"] = summaries;
        report["original_and_snapshot_unchanged"] = json!(true);
        Ok(())
    })();
    report["passed"] = json!(outcome.is_ok());
    if outcome.is_err() {
        report["failed_stage"] = json!(stage);
        report["failure"] = json!(
            "Required candidate identity, runner or profile evidence did not pass; raw diagnostics withheld"
        );
        if stage != "candidate_snapshot" {
            report["candidate_launched"] = Value::Null;
        }
    }
    report["recorded_unix_seconds"] =
        json!(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
    Ok(report)
}

#[cfg(test)]
#[path = "qualify_tests.rs"]
mod tests;
