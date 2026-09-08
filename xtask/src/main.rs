//! Portable maintenance only. Never installs a release or changes live state.
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

mod architecture;
mod capability;
mod commit_message;
mod inventory;
mod records;
mod retirement;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

fn root() -> Result<PathBuf> {
    // Bind to this checkout, not the caller's cwd or the author's home directory.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| "xtask has no workspace parent".into())
        .and_then(|path| path.canonicalize().map_err(Into::into))
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let root = root()?;
    let (name, options) = args
        .split_first()
        .map_or(("help", &[][..]), |(name, tail)| (name.as_str(), tail));
    if name == "commit-message" {
        return commit_message::run(options);
    }
    if options
        .iter()
        .any(|arg| arg != "--record" && !(name == "audit" && arg == "--strict"))
    {
        return Err("unknown option; use cargo xtask help".into());
    }
    let record = options.iter().any(|arg| arg == "--record");
    match name {
        "audit" => {
            let report = inventory::audit(&root)?;
            emit(&root, "mtm016-inventory.json", &report, record)?;
            if options.iter().any(|arg| arg == "--strict") && report["rust_only_ready"] != true {
                return Err("Rust-only retirement is not complete; see inventory".into());
            }
        }
        "records" => {
            emit(
                &root,
                "mtm016-record-integrity.json",
                &records::validate(&root)?,
                record,
            )?;
        }
        "retirement" => {
            emit(
                &root,
                "mtm016-retirement.json",
                &retirement::validate(&root)?,
                record,
            )?;
        }
        "capability" => {
            let report = capability::run(&root)?;
            emit(&root, "capability-current.json", &report, record)?;
            if report["passed"] != true {
                return Err("current-binary capability regression failed; see summary".into());
            }
        }
        "check" => {
            commit_message::check_hook(&root)?;
            let integrity = records::validate(&root)?;
            let architecture = architecture::validate(&root)?;
            let retirement = retirement::validate(&root)?;
            let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
            let mut checks = Vec::new();
            for (label, arguments) in [
                ("format", vec!["fmt", "--all", "--", "--check"]),
                (
                    "clippy",
                    vec![
                        "clippy",
                        "--workspace",
                        "--all-targets",
                        "--locked",
                        "--",
                        "-D",
                        "warnings",
                    ],
                ),
                (
                    "rust_tests",
                    vec!["test", "--workspace", "--locked", "--no-fail-fast"],
                ),
            ] {
                eprintln!("[source-check] {label}");
                let status = Command::new(&cargo)
                    .args(arguments)
                    .current_dir(&root)
                    .stdin(Stdio::null())
                    .status()?;
                checks.push(
                    json!({"name":label,"passed":status.success(),"exit_code":status.code()}),
                );
            }
            let status = Command::new("git")
                .args(["diff", "--check"])
                .current_dir(&root)
                .stdin(Stdio::null())
                .status()?;
            checks.push(json!({"name":"diff","passed":status.success(),"exit_code":status.code()}));
            let passed = checks.iter().all(|check| check["passed"] == true);
            let report = json!({
                "schema_version":"1.0.0", "milestone":"MTM-016", "scope":"rust_source_with_inherited_host_tests",
                "passed":passed, "checks":checks, "record_integrity":integrity,
                "architecture":architecture,"retirement":retirement,
                "commit_hook_executable_checked":true,
                "production_selector_changed":false, "production_state_modified":false,
                "release_qualified":false,
                "pending":["Python/shadow coverage retirement", "independent full API and capability suites", "real Native/browser/LaTeX/upgrade qualification"]
            });
            emit(&root, "mtm016-source-check.json", &report, record)?;
            if !passed {
                return Err("Rust source checks or inherited host tests failed; see report".into());
            }
        }
        "help" | "--help" | "-h" => {
            println!(
                "cargo xtask audit [--strict] [--record]\ncargo xtask records [--record]\ncargo xtask retirement [--record]\ncargo xtask capability [--record]\ncargo xtask check [--record]\ncargo xtask commit-message <file|--stdin>\n\ncheck is NOT release qualification. Orchestration is Rust; inherited host/toolchain tests are not skipped."
            );
        }
        _ => return Err("unknown task; use cargo xtask help".into()),
    }
    Ok(())
}

fn emit(root: &Path, filename: &str, value: &Value, record: bool) -> Result<()> {
    let text = serde_json::to_string_pretty(value)? + "\n";
    if record {
        let directory = root.join("records/validation");
        if !directory.canonicalize()?.starts_with(root)
            || fs::symlink_metadata(&directory)?.file_type().is_symlink()
        {
            return Err("unsafe validation output directory".into());
        }
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let temporary = directory.join(format!(".{filename}.{}.{}.tmp", std::process::id(), nonce));
        let destination = directory.join(filename);
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
            fs::rename(&temporary, &destination)?;
            Ok(())
        })();
        if temporary.exists() {
            fs::remove_file(&temporary)?;
        }
        result?;
    }
    print!("{text}");
    Ok(())
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err("Git metadata command failed".into());
    }
    if output.stdout.len() > 16 * 1024 * 1024 {
        return Err("Git metadata output exceeds fixed bound".into());
    }
    Ok(output.stdout)
}
