//! Linux environment prerequisites, not product authority or release acceptance.
//! Unknown/blocked probes never waive a Rust test or prove a candidate defect.
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nix::errno::Errno;
use nix::sched::{CloneFlags, unshare};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(crate) mod process;
#[cfg(test)]
mod tests;

const PROTOCOL: u32 = 1;
const TIMEOUT: Duration = Duration::from_secs(5);
const NAMESPACES: [&str; 6] = ["user", "mnt", "pid", "ipc", "uts", "net"];
const SYSTEM_ROOTS: [&str; 5] = ["/usr", "/bin", "/sbin", "/lib", "/lib64"];

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Context {
    uid_map_shape: String,
    gid_map_shape: String,
    same_user_namespace_as_visible_pid1: Option<bool>,
    no_new_privs: Option<bool>,
    seccomp_mode: Option<u64>,
    effective_caps_zero: Option<bool>,
    permitted_caps_zero: Option<bool>,
    bounding_caps_zero: Option<bool>,
    visible_limits: BTreeMap<String, Option<u64>>,
    namespaces: BTreeMap<String, String>,
}

fn bounded_text(path: &Path, limit: u64) -> Option<String> {
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > limit {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn map_shape(text: Option<&str>) -> &'static str {
    let Some(text) = text else {
        return "unknown";
    };
    let mut rows = Vec::new();
    for line in text.lines() {
        let row = line
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>();
        let Ok(row) = row else {
            return "unknown";
        };
        if row.len() != 3 || row[2] == 0 {
            return "unknown";
        }
        rows.push(row);
    }
    if rows.is_empty() {
        "unknown"
    } else if rows == [vec![0, 0, u32::MAX]] {
        "initial_like_not_host_proof"
    } else {
        "restricted_mapping"
    }
}

fn number(text: Option<&str>) -> Option<u64> {
    text?.trim().parse().ok()
}

fn status_field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(key, value)| (key == name).then_some(value.trim()))
}

fn observe() -> Context {
    let status = bounded_text(Path::new("/proc/self/status"), 65_536).unwrap_or_default();
    let cap_zero = |key| {
        status_field(&status, key)
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .map(|n| n == 0)
    };
    let namespaces: BTreeMap<_, _> = NAMESPACES
        .into_iter()
        .filter_map(|name| {
            fs::read_link(format!("/proc/self/ns/{name}"))
                .ok()
                .and_then(|p| p.to_str().filter(|s| s.len() <= 128).map(str::to_owned))
                .map(|value| (name.to_owned(), value))
        })
        .collect();
    let pid1 = fs::read_link("/proc/1/ns/user").ok();
    let same = namespaces
        .get("user")
        .and_then(|own| pid1.as_ref().map(|other| Path::new(own) == other));
    let mut limits = BTreeMap::new();
    for name in [
        "max_user_namespaces",
        "max_mnt_namespaces",
        "max_pid_namespaces",
        "max_net_namespaces",
        "max_ipc_namespaces",
        "max_uts_namespaces",
    ] {
        let value = bounded_text(&PathBuf::from(format!("/proc/sys/user/{name}")), 64);
        limits.insert(name.to_owned(), number(value.as_deref()));
    }
    for name in [
        "unprivileged_userns_clone",
        "apparmor_restrict_unprivileged_userns",
    ] {
        let value = bounded_text(&PathBuf::from(format!("/proc/sys/kernel/{name}")), 64);
        limits.insert(name.to_owned(), number(value.as_deref()));
    }
    Context {
        uid_map_shape: map_shape(bounded_text(Path::new("/proc/self/uid_map"), 4096).as_deref())
            .into(),
        gid_map_shape: map_shape(bounded_text(Path::new("/proc/self/gid_map"), 4096).as_deref())
            .into(),
        same_user_namespace_as_visible_pid1: same,
        no_new_privs: number(status_field(&status, "NoNewPrivs"))
            .filter(|n| *n <= 1)
            .map(|n| n == 1),
        seccomp_mode: number(status_field(&status, "Seccomp")),
        effective_caps_zero: cap_zero("CapEff"),
        permitted_caps_zero: cap_zero("CapPrm"),
        bounding_caps_zero: cap_zero("CapBnd"),
        visible_limits: limits,
        namespaces,
    }
}

fn public_context(context: &Context) -> crate::Result<Value> {
    let mut value = serde_json::to_value(context)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("namespaces");
    }
    value["ancestor_limits_inspected"] = json!(false);
    value["host_context_proven"] = json!(false);
    value["namespace_occupancy_measured"] = json!(false);
    Ok(value)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UserProbe {
    protocol: u32,
    operation: String,
    created: bool,
    errno: Option<i32>,
    errno_name: Option<String>,
}

fn errno_name(error: Errno) -> &'static str {
    match error {
        Errno::ENOSPC => "ENOSPC",
        Errno::EUSERS => "EUSERS",
        Errno::EPERM => "EPERM",
        Errno::EACCES => "EACCES",
        Errno::EINVAL => "EINVAL",
        Errno::ENOSYS => "ENOSYS",
        _ => "OTHER",
    }
}

fn user_probe() -> UserProbe {
    // Runs only in a fresh, single-threaded, short-lived maintenance child.
    // No uid_map writes, setns, privilege escalation or user-supplied command.
    let result = unshare(CloneFlags::CLONE_NEWUSER);
    UserProbe {
        protocol: PROTOCOL,
        operation: "unshare_user".into(),
        created: result.is_ok(),
        errno: result.err().map(|e| e as i32),
        errno_name: result.err().map(|e| errno_name(e).into()),
    }
}

fn valid_user(probe: &UserProbe) -> bool {
    probe.protocol == PROTOCOL
        && probe.operation == "unshare_user"
        && if probe.created {
            probe.errno.is_none() && probe.errno_name.is_none()
        } else {
            probe.errno.is_some_and(|n| {
                n > 0 && probe.errno_name.as_deref() == Some(errno_name(Errno::from_raw(n)))
            })
        }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SandboxProbe {
    protocol: u32,
    operation: String,
    context: Context,
    nested_user: UserProbe,
    workspace_visible: bool,
    environment_minimal: bool,
}

/// Internal diagnostics are handled before checkout resolution, including in the
/// empty probe mount namespace. They expose no execution or authorization API.
pub(crate) fn child_mode(name: &str) -> crate::Result<bool> {
    match name {
        "__native-userns-probe" => println!("{}", serde_json::to_string(&user_probe())?),
        "__native-sandbox-probe" => {
            let probe = SandboxProbe {
                protocol: PROTOCOL,
                operation: "minimal_sandbox".into(),
                context: observe(),
                workspace_visible: Path::new("/workspace").exists(),
                environment_minimal: env::vars_os()
                    .all(|(k, _)| ["PATH", "LANG", "LC_ALL", "PWD"].iter().any(|s| k == *s)),
                nested_user: user_probe(),
            };
            println!("{}", serde_json::to_string(&probe)?);
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn executable(name: &str) -> Option<PathBuf> {
    env::split_paths(&env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find_map(|path| {
            let meta = fs::metadata(&path).ok()?;
            if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
                path.canonicalize().ok()
            } else {
                None
            }
        })
}

fn digest(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    if file.metadata().ok()?.len() > 128 * 1024 * 1024 {
        return None;
    }
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer).ok()?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > 128 * 1024 * 1024 {
            return None;
        }
        hash.update(&buffer[..count]);
    }
    Some(format!("{:x}", hash.finalize()))
}

fn sandbox_arguments(exe: &Path) -> Vec<String> {
    let mut args = [
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--uid",
        "0",
        "--gid",
        "0",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-net",
        "--unshare-cgroup-try",
        "--disable-userns",
        "--clearenv",
        "--cap-drop",
        "ALL",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "LANG",
        "C",
        "--setenv",
        "LC_ALL",
        "C",
    ]
    .map(str::to_owned)
    .to_vec();
    // No root/home/workspace/data directory is mounted. The only additional
    // host file is this maintenance executable, mounted read-only.
    for root in SYSTEM_ROOTS {
        if Path::new(root).is_dir() {
            args.extend(["--ro-bind".into(), root.into(), root.into()]);
        }
    }
    args.extend(
        [
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/home",
            "--chdir",
            "/",
            "--ro-bind",
        ]
        .map(str::to_owned),
    );
    args.extend([
        exe.display().to_string(),
        "/mtm-native-preflight".into(),
        "--".into(),
        "/mtm-native-preflight".into(),
        "__native-sandbox-probe".into(),
    ]);
    args
}

fn sandbox_checks(parent: &Context, probe: &SandboxProbe) -> BTreeMap<String, bool> {
    let mut checks: BTreeMap<_, _> = NAMESPACES
        .into_iter()
        .map(|name| {
            let changed = parent
                .namespaces
                .get(name)
                .zip(probe.context.namespaces.get(name))
                .is_some_and(|(a, b)| a != b);
            (format!("new_{name}_namespace"), changed)
        })
        .collect();
    checks.insert(
        "protocol_valid".into(),
        probe.protocol == PROTOCOL && probe.operation == "minimal_sandbox",
    );
    checks.insert(
        "no_new_privileges".into(),
        probe.context.no_new_privs == Some(true),
    );
    checks.insert(
        "capabilities_dropped".into(),
        [
            probe.context.effective_caps_zero,
            probe.context.permitted_caps_zero,
            probe.context.bounding_caps_zero,
        ]
        .into_iter()
        .all(|n| n == Some(true)),
    );
    checks.insert("workspace_not_mounted".into(), !probe.workspace_visible);
    checks.insert("environment_cleared".into(), probe.environment_minimal);
    checks.insert(
        "further_user_namespace_denied".into(),
        valid_user(&probe.nested_user)
            && !probe.nested_user.created
            && matches!(
                probe.nested_user.errno_name.as_deref(),
                Some("ENOSPC" | "EUSERS" | "EPERM" | "EACCES")
            ),
    );
    checks
}

fn user_class(probe: Option<&UserProbe>) -> &'static str {
    let Some(probe) = probe.filter(|p| valid_user(p)) else {
        return "probe_inconclusive";
    };
    if probe.created {
        return "available";
    }
    match probe.errno_name.as_deref() {
        Some("ENOSPC" | "EUSERS") => "namespace_limit_or_depth",
        Some("EPERM" | "EACCES") => "namespace_permission_or_policy_denied",
        Some("EINVAL" | "ENOSYS") => "namespace_support_or_context_unavailable",
        _ => "namespace_failure_unclassified",
    }
}

fn bwrap_hint(output: &process::Output) -> &'static str {
    if output.timed_out {
        return "probe_timeout";
    }
    if output.output_limit {
        return "probe_output_limit";
    }
    let text = String::from_utf8_lossy(&output.stderr);
    if text.contains("Creating new namespace failed")
        && (text.contains("No space left")
            || text.contains("ENOSPC")
            || text.contains("nesting depth"))
    {
        "namespace_limit_or_depth"
    } else if text.contains("Operation not permitted") || text.contains("Permission denied") {
        "permission_or_policy_denied"
    } else if text.contains("Unknown option") || text.contains("unrecognized option") {
        "bubblewrap_option_unsupported"
    } else {
        "probe_failed_or_inconclusive"
    }
}

pub(crate) fn run() -> crate::Result<Value> {
    let parent = observe();
    let exe = env::current_exe().map_err(|_| "cannot identify maintenance probe executable")?;
    let exe_before = digest(&exe);
    let bwrap = executable("bwrap");
    let bwrap_before = bwrap.as_deref().and_then(digest);
    let user_output = process::capture(&exe, &["__native-userns-probe".into()], TIMEOUT).ok();
    let user: Option<UserProbe> = user_output
        .as_ref()
        .filter(|o| o.complete())
        .and_then(|o| serde_json::from_slice(&o.stdout).ok())
        .filter(valid_user);
    let bwrap_output = bwrap
        .as_deref()
        .and_then(|program| process::capture(program, &sandbox_arguments(&exe), TIMEOUT).ok());
    let sandbox: Option<SandboxProbe> = bwrap_output
        .as_ref()
        .filter(|o| o.complete())
        .and_then(|o| serde_json::from_slice(&o.stdout).ok());
    let checks = sandbox.as_ref().map(|p| sandbox_checks(&parent, p));
    let identities_stable = exe_before.is_some()
        && exe_before == digest(&exe)
        && bwrap_before.is_some()
        && bwrap_before == bwrap.as_deref().and_then(digest);
    let ready = identities_stable
        && user.as_ref().is_some_and(|p| p.created)
        && checks
            .as_ref()
            .is_some_and(|c| c.values().all(|passed| *passed));
    let classification = if bwrap.is_none() {
        "bubblewrap_unavailable"
    } else if user_class(user.as_ref()) != "available" {
        user_class(user.as_ref())
    } else if !identities_stable {
        "probe_identity_unstable_or_unreadable"
    } else if ready {
        "ready_for_native_tests_not_qualified"
    } else {
        "bubblewrap_probe_failed_or_inconclusive"
    };
    Ok(json!({
        "schema_version":"1.0.0","milestone":"MTM-016","scope":"current_environment_native_prerequisites_only",
        "supported":true,"passed":ready,"ready_for_native_tests":ready,"classification":classification,
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "context":public_context(&parent)?,
        "user_namespace_probe":{"measurement":user,"classification":user_class(user.as_ref()),
            "process":user_output.as_ref().map(|o|o.summary())},
        "bubblewrap_probe":{"found":bwrap.is_some(),"binary_sha256":bwrap_before,
            "process":bwrap_output.as_ref().map(|o|o.summary()),"isolation_checks":checks,
            "diagnostic_hint":if ready {"none"} else {bwrap_output.as_ref().map_or("not_available_or_spawn_failed",bwrap_hint)}},
        "maintenance_binary_sha256":exe_before,"probe_identities_unchanged":identities_stable,
        "raw_output_recorded":false,"python_invoked":false,"native_product_runtime_tested":false,
        "production_state_modified":false,"host_settings_modified":false,"release_qualified":false,
        "candidate_defect_attribution":"not_evaluated_by_preflight",
        "source_tests_passed":Value::Null,"tests_skipped_by_preflight":false,
        "recovery":{"automatic_retry":false,
            "action":if ready {"run_product_tests_in_this_environment"} else {"run_the_same_checkout_tests_on_a_capable_native_host"},
            "do_not_disable_isolation_or_raise_sysctls_automatically":true},
        "limitations":["Positive visible namespace limits do not reveal ancestor quotas or current occupancy.",
            "Restricted UID mappings and namespace equality to visible PID 1 do not identify the host or prove nesting depth.",
            "ENOSPC/EUSERS alone cannot distinguish a configured nesting prohibition from depth/quota exhaustion.",
            "Passing this probe is not full Native, TTY, external-tool, private-vault, workflow or release qualification."]
    }))
}
