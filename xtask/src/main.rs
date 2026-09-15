//! Portable maintenance plus the explicitly authorized MTM-016 release cutover.
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

mod architecture;
mod capability;
mod check_report;
mod commit_message;
mod dist;
mod evidence_json;
mod inventory;
#[cfg(target_os = "linux")]
mod native_preflight;
#[cfg(target_os = "linux")]
mod qualify;
mod records;
#[cfg(target_os = "linux")]
mod release_check;
#[cfg(target_os = "linux")]
mod release_cutover;
#[cfg(target_os = "linux")]
mod research_collect;
#[cfg(target_os = "linux")]
mod research_precheck;
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
    #[cfg(target_os = "linux")]
    if args.len() == 1 && native_preflight::child_mode(&args[0])? {
        return Ok(());
    }
    let root = root()?;
    let (name, options) = args
        .split_first()
        .map_or(("help", &[][..]), |(name, tail)| (name.as_str(), tail));
    if name == "commit-message" {
        return commit_message::run(options);
    }
    #[cfg(target_os = "linux")]
    if name == "research-collect" {
        let options = research_collect::Options::parse(options)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&research_collect::run(&root, &options)?)?
        );
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if name == "research-precheck" {
        let options = research_precheck::Options::parse(options)?;
        let report = research_precheck::run(&root, &options)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        if report["required_material_present"] != true {
            return Err("research evidence is incomplete; no corpus row accepted".into());
        }
        return Ok(());
    }
    if name == "dist" {
        let options = dist::Options::parse(options)?;
        println!("{}", serde_json::to_string_pretty(&dist::run(&options)?)?);
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if name == "qualify" {
        let options = qualify::Options::parse(options)?;
        let report = qualify::run(&root, &options)?;
        emit(&root, options.report_name(), &report, options.record)?;
        if report["passed"] != true {
            return Err("exact-candidate qualification failed; see sanitized report".into());
        }
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if name == "release-check" {
        let options = release_check::Options::parse(options)?;
        let report = release_check::run(&root, &options)?;
        emit(&root, "mtm016-release-check.json", &report, options.record)?;
        if report["passed"] != true {
            return Err("release readiness blocked; no deployment authorized".into());
        }
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if name == "release-cutover" {
        let options = release_cutover::Options::parse(options)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&release_cutover::run(&root, &options)?)?
        );
        return Ok(());
    }
    if options
        .iter()
        .any(|arg| arg != "--record" && !(name == "audit" && arg == "--strict"))
    {
        return Err("unknown option; use cargo xtask help".into());
    }
    let record = options.iter().any(|arg| arg == "--record");
    match name {
        "native-preflight" => {
            let report = native_environment()?;
            emit(&root, "mtm016-native-preflight.json", &report, record)?;
            if report["passed"] != true {
                return Err("Native environment is blocked or inconclusive; see preflight report. No test was waived.".into());
            }
        }
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
            let commit_before = git(&root, &["rev-parse", "HEAD"])?;
            let source_before = capability::source_hash(&root)?;
            commit_message::check_hook(&root)?;
            let integrity = records::validate(&root)?;
            let architecture = architecture::validate(&root)?;
            let retirement = retirement::validate(&root)?;
            eprintln!("[source-check] native_environment (diagnostic; never skips tests)");
            let native = native_environment()?;
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
                    .env_remove("MTM_TEST_CORPUS_PROFILE")
                    .env_remove("MTM_TEST_NATIVE_CORPUS_PROFILE")
                    .env_remove("MTM_TEST_INSTALL_SIGKILL_PROFILE")
                    .env_remove("MTM_TEST_RETRIEVAL_PROFILE")
                    .env_remove("MTM_TEST_DEPLOYMENT_CANDIDATE")
                    .env_remove("MTM_TEST_DEPLOYMENT_CANDIDATE_SHA256")
                    .env_remove("MTM_TEST_CANDIDATE")
                    .env_remove("MTM_TEST_CANDIDATE_SHA256")
                    .env_remove("MTM_TEST_TARGET_PROFILE")
                    .env_remove("MTM_TEST_RESOURCE_PROFILE")
                    .env_remove("MTM_TEST_UPGRADE_PROFILE")
                    .env_remove("MTM_TEST_PERMISSION_PROFILE")
                    .env_remove("MTM_TEST_BASELINE")
                    .env_remove("MTM_TEST_BASELINE_SHA256")
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
            let source_after = capability::source_hash(&root)?;
            let commit_after = git(&root, &["rev-parse", "HEAD"])?;
            let source_unchanged = source_before == source_after && commit_before == commit_after;
            let evaluation = check_report::summarize(&checks, &native, source_unchanged);
            let passed = evaluation["passed"] == true;
            let report = json!({
                "schema_version":"1.0.0", "milestone":"MTM-016", "scope":"rust_source_with_inherited_host_tests",
                "passed":passed, "checks":checks, "record_integrity":integrity,
                "architecture":architecture,"retirement":retirement,
                "native_environment":native,"tests_skipped_by_preflight":false,
                "product_test_evaluation":evaluation,
                "source_identity":{"hash_scope":"mtm-rust-source-v1","before_sha256":source_before,
                    "after_sha256":source_after,"unchanged":source_unchanged,
                    "commit_before":String::from_utf8_lossy(&commit_before).trim(),
                    "commit_after":String::from_utf8_lossy(&commit_after).trim()},
                "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                "test_failure_attribution":"Historical comparisons belong in reviewed evidence, not the prerequisite probe.",
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
                "cargo xtask research-collect --session <absolute-private-session> --run-id <run-id> --sqlite <absolute-sqlite3>\n  Create and precheck a private evidence bundle from one sealed disposable research run using explicit read-only sqlite3; NOT corpus acceptance."
            );
            println!(
                "cargo xtask research-precheck --bundle <absolute-private-directory>\n  Read-only evidence integrity/checklist, NOT mathematical acceptance or corpus import."
            );
            println!(
                "cargo xtask qualify --profile retrieval --binary <artifact> --sha256 <sha256> [--record]"
            );
            println!(
                "cargo xtask qualify --profile install_sigkill --binary <artifact> --sha256 <sha256> [--record]"
            );
            println!(
                "cargo xtask qualify --profile corpus --binary <artifact> --sha256 <sha256> [--record]"
            );
            println!(
                "cargo xtask release-check --binary <artifact> --manifest <repo-relative-json> [--record]"
            );
            println!(
                "cargo xtask release-cutover --binary target/mtm016-f6-frozen/mtm-0.6.0-preview.1-f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034/mtm --manifest records/governance/mtm016-release-inputs.json --authorize MTM-016\n  Explicit MTM-016 production selector cutover with mandatory readiness revalidation and rollback/recutover drill."
            );
            println!(
                "cargo xtask qualify --profile permissions --binary <artifact> --sha256 <sha256> [--record]"
            );
            println!(
                "cargo xtask qualify --profile upgrade --binary <artifact> --sha256 <sha256> --baseline <artifact> --baseline-sha256 <sha256> [--record]"
            );
            println!(
                "cargo xtask qualify --profile <protocol|target|native_commands|compiled_latex> --binary <artifact> --sha256 <sha256> [--record]\ncargo xtask qualify --profile resource --binary <artifact> --sha256 <sha256> --baseline <artifact> --baseline-sha256 <sha256> [--record]\ncargo xtask dist --binary <artifact> --sha256 <sha256> --version <version> --out <absolute-directory>"
            );
            println!(
                "cargo xtask audit [--strict] [--record]\ncargo xtask records [--record]\ncargo xtask retirement [--record]\ncargo xtask capability [--record]\ncargo xtask native-preflight [--record]\ncargo xtask check [--record]\ncargo xtask commit-message <file|--stdin>\n\ncheck is NOT release qualification. Orchestration is Rust; inherited host/toolchain tests are not skipped. A blocked preflight never suppresses a test failure."
            );
        }
        _ => return Err("unknown task; use cargo xtask help".into()),
    }
    Ok(())
}

fn native_environment() -> Result<Value> {
    #[cfg(target_os = "linux")]
    {
        native_preflight::run()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(
            json!({"schema_version":"1.0.0","scope":"current_environment_native_prerequisites_only",
        "supported":false,"passed":false,"ready_for_native_tests":false,
        "classification":"platform_not_supported","release_qualified":false,
        "tests_skipped_by_preflight":false}),
        )
    }
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
