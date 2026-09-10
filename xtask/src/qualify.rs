//! Exact-artifact protocol profile. No installation, production data or Python.
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{Result, capability, git, native_preflight, native_preflight::process};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[path = "qualification_receipt.rs"]
mod receipt;
#[path = "qualify_summary.rs"]
mod summary;
pub(crate) use receipt::validate as validate_receipt;
const MAX_BINARY: u64 = 256 * 1024 * 1024;

pub(crate) fn validate_corpus_summary(summaries: &Value, hash: &str) -> Result<bool> {
    let corpus = summaries
        .get("corpus")
        .ok_or("corpus qualification summary missing")?;
    let bytes = format!("MTM_USABILITY_CORPUS {corpus}\n").into_bytes();
    let checked = summary::validate_corpus(&bytes, hash)?;
    if &checked != summaries {
        return Err("corpus qualification summary has extra or inconsistent fields".into());
    }
    Ok(corpus["passed"] == true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Profile {
    Protocol,
    Target,
    Resource,
    Upgrade,
    Permissions,
    Corpus,
    InstallSigkill,
}

impl Profile {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "protocol" => Ok(Self::Protocol),
            "target" => Ok(Self::Target),
            "resource" => Ok(Self::Resource),
            "upgrade" => Ok(Self::Upgrade),
            "permissions" => Ok(Self::Permissions),
            "corpus" => Ok(Self::Corpus),
            "install_sigkill" => Ok(Self::InstallSigkill),
            _ => Err("qualification profile must be protocol, target, resource, upgrade, permissions, corpus or install_sigkill; release qualification is not implemented here".into()),
        }
    }

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Protocol => "protocol",
            Self::Target => "target",
            Self::Resource => "resource",
            Self::Upgrade => "upgrade",
            Self::Permissions => "permissions",
            Self::Corpus => "corpus",
            Self::InstallSigkill => "install_sigkill",
        }
    }

    const fn delivery(self) -> &'static str {
        match self {
            Self::Protocol => "D5",
            Self::Target => "D6",
            Self::Resource => "D7",
            Self::Upgrade => "F1",
            Self::Permissions => "F2",
            Self::Corpus => "F5",
            Self::InstallSigkill => "F4",
        }
    }

    const fn report_name(self) -> &'static str {
        match self {
            Self::Protocol => "candidate-protocol.json",
            Self::Target => "candidate-target.json",
            Self::Resource => "candidate-resource.json",
            Self::Upgrade => "candidate-upgrade.json",
            Self::Permissions => "candidate-permissions.json",
            Self::Corpus => "candidate-corpus.json",
            Self::InstallSigkill => "candidate-install-sigkill.json",
        }
    }
}

pub(crate) struct Options {
    binary: String,
    sha256: String,
    profile: Profile,
    baseline_binary: Option<String>,
    baseline_sha256: Option<String>,
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
            if ![
                "--binary",
                "--sha256",
                "--profile",
                "--baseline",
                "--baseline-sha256",
            ]
            .contains(&name.as_str())
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
        let profile = Profile::parse(
            options
                .remove("--profile")
                .ok_or("explicit --profile is required")?
                .as_str(),
        )?;
        let sha256 = options.remove("--sha256").ok_or("--sha256 is required")?;
        if !valid_hash(&sha256) {
            return Err("SHA-256 must be 64 lowercase hexadecimal characters".into());
        }
        let baseline_binary = options.remove("--baseline");
        let baseline_sha256 = options.remove("--baseline-sha256");
        match profile {
            Profile::Resource | Profile::Upgrade => {
                if baseline_binary.is_none() || baseline_sha256.is_none() {
                    return Err("paired profile requires --baseline and --baseline-sha256".into());
                }
                if !baseline_sha256.as_deref().is_some_and(valid_hash) {
                    return Err(
                        "baseline SHA-256 must be 64 lowercase hexadecimal characters".into(),
                    );
                }
                if baseline_sha256.as_deref() == Some(sha256.as_str()) {
                    return Err(
                        "paired profile requires distinct candidate and baseline digests".into(),
                    );
                }
            }
            Profile::Protocol
            | Profile::Target
            | Profile::Permissions
            | Profile::Corpus
            | Profile::InstallSigkill => {
                if baseline_binary.is_some() || baseline_sha256.is_some() {
                    return Err("baseline options require a resource or upgrade profile".into());
                }
            }
        }
        Ok(Self {
            binary: options.remove("--binary").ok_or("--binary is required")?,
            sha256,
            profile,
            baseline_binary,
            baseline_sha256,
            record,
        })
    }

    pub(crate) const fn report_name(&self) -> &'static str {
        self.profile.report_name()
    }
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn digest(path: &Path) -> Result<String> {
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
        Self::prepare_artifact(root, &options.binary, &options.sha256)
    }

    fn prepare_artifact(root: &Path, binary: &str, sha256: &str) -> Result<Self> {
        let original = root.join(binary);
        if digest(&original)? != sha256 {
            return Err("artifact SHA-256 mismatch before launch".into());
        }
        let directory = tempfile::tempdir().map_err(|_| "candidate snapshot directory failed")?;
        let executable = directory.path().join("mtm-artifact");
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
            sha256: sha256.to_owned(),
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
    let target = options.profile == Profile::Target;
    let resource = options.profile == Profile::Resource;
    let upgrade = options.profile == Profile::Upgrade;
    let permissions = options.profile == Profile::Permissions;
    let corpus = options.profile == Profile::Corpus;
    let install_sigkill = options.profile == Profile::InstallSigkill;
    let paired = resource || upgrade;
    let needs_native = target || resource;
    let scope = match options.profile {
        Profile::Protocol => "exact_candidate_protocol_not_release",
        Profile::Target => "exact_candidate_target_not_release",
        Profile::Resource => "exact_candidate_resource_not_release",
        Profile::Upgrade => "exact_candidate_installed_upgrade_fixture_not_release",
        Profile::Permissions => "exact_candidate_scripted_patch_permissions_not_release",
        Profile::Corpus => "exact_candidate_partial_usability_corpus_not_release",
        Profile::InstallSigkill => "exact_candidate_external_sigkill_install_recovery_not_release",
    };
    let mut report = json!({"schema_version":"1.0.0","milestone":"MTM-016","delivery":options.profile.delivery(),
    "profile":options.profile.as_str(),"scope":scope,"passed":false,
    "candidate_sha256":options.sha256,"candidate_launched":false,
    "baseline_sha256":options.baseline_sha256,"baseline_launched":if paired {Value::Bool(false)} else {Value::Null},
    "release_qualified":false,"production_state_modified":false,"selector_changed":false,
    "production_selectors_changed":false,
    "raw_test_output_recorded":false,"python_invoked":false,
    "pending":match options.profile {
        Profile::Protocol => json!(["Native host","compiled LaTeX","browser","resources","upgrade and rollback","Python retirement"]),
        Profile::Target => json!(["browser","resources","upgrade and rollback","Python retirement"]),
        Profile::Resource => json!(["compiled-LaTeX target pass","permission-grant soak","browser","upgrade and rollback","Python retirement"]),
        Profile::Upgrade => json!(["real Native and compiled LaTeX","resources and permission-grant soak","browser and human consent","operator-authorized production-state copy","abrupt installation interruption","Python retirement and full release gate"]),
        Profile::Permissions => json!(["real Native command execution and command-grant soak","compiled LaTeX and external retrieval","browser and independent human consent","baseline resource comparison","production upgrade and abrupt installation interruption","Python retirement and full release gate"]),
        Profile::Corpus => json!(["Native tasks U16-U20","independent research tasks U21-U25","external-client/operator tasks U26-U30","full release gates"]),
        Profile::InstallSigkill => json!(["physical power-loss/device-cache durability","production selector drill","shared-filesystem semantics","full release gates"]),
    }});
    let mut stage = if needs_native {
        "native_preflight"
    } else {
        "candidate_snapshot"
    };
    let outcome = (|| -> Result<()> {
        if needs_native {
            let native = native_preflight::run()?;
            report["native_preflight"] = native.clone();
            if native["passed"] != true || native["ready_for_native_tests"] != true {
                return Err("selected profile requires a capable Native host".into());
            }
        }
        stage = "candidate_snapshot";
        let snapshot = Snapshot::prepare(root, options)?;
        let baseline = if paired {
            stage = "baseline_snapshot";
            Some(Snapshot::prepare_artifact(
                root,
                options
                    .baseline_binary
                    .as_deref()
                    .ok_or("resource baseline path missing")?,
                options
                    .baseline_sha256
                    .as_deref()
                    .ok_or("resource baseline digest missing")?,
            )?)
        } else {
            None
        };
        let before = capability::source_hash(root)?;
        let corpus_before = if corpus {
            Some(crate::records::read_bytes(
                root,
                "conformance/mtm016-usability-corpus.json",
                64 * 1024,
            )?)
        } else {
            None
        };
        let commit_before = git(root, &["rev-parse", "HEAD"])?;
        stage = "protocol_test_runner";
        if upgrade {
            stage = "upgrade_test_runner";
        }
        if permissions {
            stage = "permission_test_runner";
        }
        if install_sigkill {
            stage = "install_sigkill_test_runner";
        }
        let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let mut command = Command::new(cargo);
        command
            .current_dir(root)
            .env_remove("MTM_TEST_CORPUS_PROFILE")
            .env_remove("MTM_TEST_PERMISSION_PROFILE")
            .env_remove("MTM_TEST_INSTALL_SIGKILL_PROFILE")
            .env_remove("MTM_TEST_DEPLOYMENT_CANDIDATE")
            .env_remove("MTM_TEST_DEPLOYMENT_CANDIDATE_SHA256")
            .env_remove("MTM_TEST_UPGRADE_PROFILE")
            .env_remove("MTM_TEST_TARGET_PROFILE")
            .env_remove("MTM_TEST_RESOURCE_PROFILE")
            .env_remove("MTM_TEST_BASELINE")
            .env_remove("MTM_TEST_BASELINE_SHA256");
        if install_sigkill {
            command
                .args([
                    "test",
                    "--locked",
                    "--offline",
                    "-p",
                    "mtm-cli",
                    "--test",
                    "deployment",
                    "--",
                    "external_sigkill_during_real_rollback_recovers_exact_candidate",
                    "--exact",
                ])
                .env("MTM_TEST_INSTALL_SIGKILL_PROFILE", "1")
                .env("MTM_TEST_DEPLOYMENT_CANDIDATE", &snapshot.executable)
                .env("MTM_TEST_DEPLOYMENT_CANDIDATE_SHA256", &snapshot.sha256);
        } else {
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
                ])
                .env("MTM_TEST_CANDIDATE", &snapshot.executable)
                .env("MTM_TEST_CANDIDATE_SHA256", &snapshot.sha256);
        }
        if paired {
            command
                .arg(if upgrade {
                    "upgrade_runtime::exact_installed_upgrade_and_preupgrade_state_rollback"
                } else {
                    "resource_runtime::explicit_baseline_and_candidate_resource_non_regression"
                })
                .env(
                    if upgrade {
                        "MTM_TEST_UPGRADE_PROFILE"
                    } else {
                        "MTM_TEST_RESOURCE_PROFILE"
                    },
                    "1",
                )
                .env(
                    "MTM_TEST_BASELINE",
                    &baseline
                        .as_ref()
                        .ok_or("resource baseline snapshot missing")?
                        .executable,
                )
                .env(
                    "MTM_TEST_BASELINE_SHA256",
                    &baseline
                        .as_ref()
                        .ok_or("resource baseline snapshot missing")?
                        .sha256,
                )
                .env_remove("MTM_TEST_TARGET_PROFILE");
        } else if corpus {
            command
                .arg("corpus_runtime::exact_candidate_three_repeat_usability_matrix")
                .arg("--exact")
                .env("MTM_TEST_CORPUS_PROFILE", "1");
        } else if permissions {
            command
                .arg("permission_runtime::exact_candidate_permission_patch_soak")
                .arg("--exact")
                .env("MTM_TEST_PERMISSION_PROFILE", "1");
        } else if target {
            command.env("MTM_TEST_TARGET_PROFILE", "1");
            command.env_remove("MTM_TEST_RESOURCE_PROFILE");
        } else {
            command.env_remove("MTM_TEST_TARGET_PROFILE");
            command.env_remove("MTM_TEST_RESOURCE_PROFILE");
        }
        command.args(["--nocapture", "--test-threads=1"]);
        eprintln!(
            "[qualify] exact-artifact {} fixtures",
            options.profile.as_str()
        );
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
        if let Some(baseline) = &baseline {
            baseline.unchanged()?;
        }
        let after = capability::source_hash(root)?;
        let commit_after = git(root, &["rev-parse", "HEAD"])?;
        report["harness_source_identity"] = json!({"before_sha256":before,"after_sha256":after,
            "commit":String::from_utf8_lossy(&commit_before).trim(),"unchanged":before==after && commit_before==commit_after});
        if before != after || commit_before != commit_after {
            return Err("qualification harness source changed".into());
        }
        if let Some(bytes) = &corpus_before {
            if crate::records::read_bytes(
                root,
                "conformance/mtm016-usability-corpus.json",
                64 * 1024,
            )? != *bytes
            {
                return Err("corpus input changed during execution".into());
            }
            report["corpus_definition_sha256"] = json!(format!("{:x}", Sha256::digest(bytes)));
        }
        stage = "summary_validation";
        let summaries = if install_sigkill {
            summary::validate_install_sigkill(&output.stdout, &snapshot.sha256)?
        } else if corpus {
            summary::validate_corpus(&output.stdout, &snapshot.sha256)?
        } else if permissions {
            summary::validate_permissions(&output.stdout, &snapshot.sha256)?
        } else if upgrade {
            summary::validate_upgrade(
                &output.stdout,
                &snapshot.sha256,
                baseline
                    .as_ref()
                    .map(|value| value.sha256.as_str())
                    .ok_or("upgrade baseline missing")?,
            )?
        } else if resource {
            summary::validate_resource(
                &output.stdout,
                &snapshot.sha256,
                baseline
                    .as_ref()
                    .map(|value| value.sha256.as_str())
                    .ok_or("resource baseline snapshot missing")?,
            )?
        } else {
            summary::validate(&output.stdout, &snapshot.sha256, options.profile)?
        };
        if corpus {
            if report["corpus_definition_sha256"] != summaries["corpus"]["corpus_sha256"] {
                return Err("compiled corpus differs from current input file".into());
            }
            // Preserve validated partial rows even if a portable scenario fails.
            // This does not turn the failing runner or incomplete matrix green.
            report["summaries"] = summaries.clone();
        }
        if !output.complete() {
            return Err("qualification runner failed or did not finish cleanly".into());
        }
        report["candidate_launched"] = json!(true);
        if paired {
            report["baseline_launched"] = json!(true);
        }
        if upgrade {
            report["selector_changed"] = json!(true);
            report["selector_scope"] = json!("owned_disposable_fixture_only");
        }
        report["summaries"] = summaries;
        report["original_and_snapshot_unchanged"] = json!(true);
        Ok(())
    })();
    report["passed"] = json!(outcome.is_ok());
    if outcome.is_ok() && corpus && report["summaries"]["corpus"]["passed"] != true {
        report["passed"] = json!(false);
        report["failed_stage"] = json!("corpus_coverage");
        report["failure"] =
            json!("Corpus contains blocked or failed trials; completed trials remain recorded");
    }
    if outcome.is_err() {
        report["failed_stage"] = json!(stage);
        report["failure"] = json!(
            "Required candidate identity, runner or profile evidence did not pass; raw diagnostics withheld"
        );
        if !matches!(
            stage,
            "native_preflight" | "candidate_snapshot" | "baseline_snapshot"
        ) {
            report["candidate_launched"] = Value::Null;
            if paired {
                report["baseline_launched"] = Value::Null;
            }
            if upgrade {
                report["selector_changed"] = Value::Null;
            }
        }
    }
    report["recorded_unix_seconds"] =
        json!(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
    Ok(report)
}

#[cfg(test)]
#[path = "qualify_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "qualify_resource_tests.rs"]
mod resource_tests;
