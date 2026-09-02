use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use mtm_contracts::{ErrorCategory, NativeMode, ReCtmError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DEFAULT_SANDBOX_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

const SYSTEM_PREFIXES: [&str; 5] = ["/usr", "/bin", "/sbin", "/lib", "/lib64"];
const UNSAFE_EXACT_ROOTS: [&str; 13] = [
    "/", "/proc", "/sys", "/dev", "/run", "/tmp", "/home", "/root", "/var", "/srv", "/opt", "/mnt",
    "/media",
];
const EXECUTABLE_DIRECTORY_NAMES: [&str; 3] = ["bin", "executables", "sbin"];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ToolchainExposurePlan {
    pub mode: NativeMode,
    pub sandbox_path: String,
    pub host_path_inherited: bool,
    pub auto_discovery_enabled: bool,
    pub explicit_roots: Vec<PathBuf>,
    pub discovered_roots: Vec<PathBuf>,
    pub read_only_roots: Vec<PathBuf>,
}

impl ToolchainExposurePlan {
    #[must_use]
    pub fn summary(&self, include_paths: bool) -> serde_json::Value {
        let fingerprints = self
            .read_only_roots
            .iter()
            .map(|path| {
                let digest = Sha256::digest(path.to_string_lossy().as_bytes());
                format!("{digest:x}")[..16].to_owned()
            })
            .collect::<Vec<_>>();
        let mut value = serde_json::json!({
            "policy": "system_plus_path_discovery_plus_explicit_roots",
            "mount_mode": "read_only",
            "host_path_inherited": self.host_path_inherited,
            "auto_discovery_enabled": self.auto_discovery_enabled,
            "explicit_root_count": self.explicit_roots.len(),
            "discovered_root_count": self.discovered_roots.len(),
            "resolved_read_only_root_count": self.read_only_roots.len(),
            "root_fingerprints": fingerprints,
        });
        if include_paths {
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "explicit_roots".to_owned(),
                    paths_json(&self.explicit_roots),
                );
                object.insert(
                    "discovered_roots".to_owned(),
                    paths_json(&self.discovered_roots),
                );
                object.insert(
                    "resolved_read_only_roots".to_owned(),
                    paths_json(&self.read_only_roots),
                );
                object.insert(
                    "sandbox_path".to_owned(),
                    serde_json::Value::String(self.sandbox_path.clone()),
                );
            }
        }
        value
    }
}

pub fn parse_native_exec_allow_roots(raw: Option<&str>) -> Result<Vec<PathBuf>, ReCtmError> {
    let mut roots = Vec::new();
    for item in raw.unwrap_or_default().split(':') {
        let value = item.trim();
        if value.is_empty() {
            continue;
        }
        let path = expand_home(Path::new(value));
        if !path.is_absolute() {
            return Err(ReCtmError::new(
                "INVALID_NATIVE_EXEC_ALLOW_ROOT",
                "MTM_NATIVE_EXEC_ALLOW_ROOTS entries must be absolute paths.",
            )
            .with_category(ErrorCategory::Validation)
            .with_details(serde_json::json!({"root": value})));
        }
        roots.push(canonicalize_lenient(&path));
    }
    Ok(roots)
}

pub fn validate_explicit_toolchain_roots(
    roots: &[PathBuf],
    workspace: &Path,
    forbidden_paths: &[PathBuf],
) -> Result<Vec<PathBuf>, ReCtmError> {
    let policy = RootPolicy::new(workspace, forbidden_paths)?;
    let mut validated = Vec::new();
    for root in roots {
        if let Some(path) = policy.validate(root, "explicit", true)? {
            validated.push(path);
        }
    }
    Ok(collapse_roots(&validated))
}

pub fn build_toolchain_exposure_plan(
    mode: NativeMode,
    workspace: &Path,
    forbidden_paths: &[PathBuf],
    explicit_roots: &[PathBuf],
    host_path: Option<&str>,
) -> Result<ToolchainExposurePlan, ReCtmError> {
    let policy = RootPolicy::new(workspace, forbidden_paths)?;
    let explicit = validate_explicit_toolchain_roots(explicit_roots, workspace, forbidden_paths)?;
    let auto_discovery = matches!(mode, NativeMode::Trusted | NativeMode::Dangerous);
    let inherited = host_path
        .map(ToOwned::to_owned)
        .or_else(|| env::var("PATH").ok())
        .unwrap_or_default();
    let (discovered, path_entries) = if auto_discovery {
        discover_path_view(&inherited, &policy)
    } else {
        (Vec::new(), Vec::new())
    };
    let mut combined = discovered.clone();
    combined.extend(explicit.iter().cloned());
    let read_only_roots = collapse_roots(&combined);
    let base_path = if auto_discovery {
        if path_entries.is_empty() {
            DEFAULT_SANDBOX_PATH.to_owned()
        } else {
            join_paths(&path_entries)
        }
    } else {
        DEFAULT_SANDBOX_PATH.to_owned()
    };
    let sandbox_path = extend_path_for_explicit_roots(&base_path, &explicit);
    Ok(ToolchainExposurePlan {
        mode,
        sandbox_path,
        host_path_inherited: auto_discovery,
        auto_discovery_enabled: auto_discovery,
        explicit_roots: explicit,
        discovered_roots: discovered,
        read_only_roots,
    })
}

struct RootPolicy {
    workspace: PathBuf,
    forbidden_paths: Vec<PathBuf>,
    home: PathBuf,
    system_prefixes: Vec<PathBuf>,
    unsafe_roots: BTreeSet<PathBuf>,
}

impl RootPolicy {
    fn new(workspace: &Path, forbidden_paths: &[PathBuf]) -> Result<Self, ReCtmError> {
        let workspace = fs::canonicalize(workspace).map_err(|error| {
            ReCtmError::new("INVALID_WORKSPACE", error.to_string())
                .with_category(ErrorCategory::Validation)
        })?;
        let home = env::var_os("HOME").map(PathBuf::from).map_or_else(
            || PathBuf::from("/nonexistent"),
            |path| canonicalize_lenient(&path),
        );
        Ok(Self {
            workspace,
            forbidden_paths: forbidden_paths
                .iter()
                .map(|path| canonicalize_lenient(path))
                .collect(),
            home,
            system_prefixes: SYSTEM_PREFIXES
                .iter()
                .map(|value| canonicalize_lenient(Path::new(value)))
                .collect(),
            unsafe_roots: UNSAFE_EXACT_ROOTS
                .iter()
                .map(|value| canonicalize_lenient(Path::new(value)))
                .collect(),
        })
    }

    fn validate(
        &self,
        raw_path: &Path,
        source: &str,
        strict: bool,
    ) -> Result<Option<PathBuf>, ReCtmError> {
        let path = match fs::canonicalize(expand_home(raw_path)) {
            Ok(path) => path,
            Err(error) => {
                if strict {
                    return Err(ReCtmError::new(
                        "INVALID_NATIVE_EXEC_ALLOW_ROOT",
                        "Declared native toolchain root does not exist.",
                    )
                    .with_category(ErrorCategory::Validation)
                    .with_details(
                        serde_json::json!({"root": raw_path, "error": error.to_string()}),
                    ));
                }
                return Ok(None);
            }
        };
        if !path.is_dir() {
            if strict {
                return Err(ReCtmError::new(
                    "INVALID_NATIVE_EXEC_ALLOW_ROOT",
                    "Declared native toolchain root must be a directory.",
                )
                .with_category(ErrorCategory::Validation)
                .with_details(serde_json::json!({"root": path})));
            }
            return Ok(None);
        }
        let denied_reason = if self.unsafe_roots.contains(&path) {
            Some("unsafe broad or virtual filesystem root")
        } else if path == self.home {
            Some("the complete user home is too broad")
        } else if overlaps(&path, &self.workspace) {
            Some("root overlaps the writable workspace")
        } else if self
            .forbidden_paths
            .iter()
            .any(|forbidden| overlaps(&path, forbidden))
        {
            Some("root overlaps MTM data/private state")
        } else {
            None
        };
        if let Some(reason) = denied_reason {
            if strict {
                return Err(ReCtmError::new(
                    "NATIVE_TOOLCHAIN_ROOT_DENIED",
                    "Native toolchain root violates the isolation policy.",
                )
                .with_category(ErrorCategory::Security)
                .with_details(serde_json::json!({
                    "root": path,
                    "source": source,
                    "reason": reason,
                })));
            }
            return Ok(None);
        }
        if self.is_system_path(&path) {
            return Ok(None);
        }
        Ok(Some(path))
    }

    fn is_system_path(&self, path: &Path) -> bool {
        self.system_prefixes
            .iter()
            .any(|root| path == root || path.starts_with(root))
    }
}

fn discover_path_view(host_path: &str, policy: &RootPolicy) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut candidates = Vec::new();
    let mut path_entries = Vec::new();
    let mut seen_entries = BTreeSet::new();
    for raw_entry in host_path.split(':') {
        if raw_entry.is_empty() {
            continue;
        }
        let entry = expand_home(Path::new(raw_entry));
        if !entry.is_absolute() {
            continue;
        }
        let Ok(resolved_entry) = fs::canonicalize(&entry) else {
            continue;
        };
        if !resolved_entry.is_dir() {
            continue;
        }
        if policy.is_system_path(&resolved_entry) {
            add_path_entry(&resolved_entry, &mut path_entries, &mut seen_entries);
            continue;
        }
        let inferred = executable_prefix(&resolved_entry);
        let accepted = policy
            .validate(&inferred, "path_discovery", false)
            .ok()
            .flatten()
            .or_else(|| {
                policy
                    .validate(&resolved_entry, "path_discovery", false)
                    .ok()
                    .flatten()
            });
        if let Some(root) = accepted {
            candidates.push(root);
            add_path_entry(&resolved_entry, &mut path_entries, &mut seen_entries);
        } else {
            continue;
        }
        let Ok(read_dir) = fs::read_dir(&resolved_entry) else {
            continue;
        };
        let mut entries = read_dir
            .filter_map(Result::ok)
            .take(4096)
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for executable in entries {
            let Ok(file_type) = executable.file_type() else {
                continue;
            };
            if !file_type.is_symlink() {
                continue;
            }
            let Ok(target) = fs::canonicalize(executable.path()) else {
                continue;
            };
            if !target.is_file() {
                continue;
            }
            let Some(directory) = target.parent() else {
                continue;
            };
            let inferred_target = executable_prefix(directory);
            if let Some(root) = policy
                .validate(&inferred_target, "path_discovery", false)
                .ok()
                .flatten()
                .or_else(|| {
                    policy
                        .validate(directory, "path_discovery", false)
                        .ok()
                        .flatten()
                })
            {
                candidates.push(root);
            }
        }
    }
    (collapse_roots(&candidates), path_entries)
}

fn executable_prefix(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if EXECUTABLE_DIRECTORY_NAMES.contains(&name.as_str()) {
        path.parent()
            .map_or_else(|| path.to_path_buf(), Path::to_path_buf)
    } else {
        path.to_path_buf()
    }
}

fn extend_path_for_explicit_roots(base_path: &str, roots: &[PathBuf]) -> String {
    let mut entries = base_path
        .split(':')
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let mut seen = entries.iter().cloned().collect::<BTreeSet<_>>();
    for root in roots {
        let mut candidates = vec![root.clone()];
        let children = fs::read_dir(root)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let file_type = entry.file_type().ok()?;
                file_type.is_dir().then_some(entry)
            })
            .map(|entry| {
                (
                    entry.file_name().to_string_lossy().to_ascii_lowercase(),
                    entry.path(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        for name in EXECUTABLE_DIRECTORY_NAMES {
            if let Some(candidate) = children.get(name) {
                candidates.push(candidate.clone());
            }
        }
        for candidate in candidates {
            let value = candidate.to_string_lossy().into_owned();
            if seen.insert(value.clone()) {
                entries.push(value);
            }
        }
    }
    entries.join(":")
}

fn collapse_roots(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut ordered = roots
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    ordered.sort_by_key(|path| {
        (
            path.components().count(),
            path.to_string_lossy().into_owned(),
        )
    });
    let mut result = Vec::<PathBuf>::new();
    for root in ordered {
        if result
            .iter()
            .any(|existing| root == *existing || root.starts_with(existing))
        {
            continue;
        }
        result.retain(|existing| !existing.starts_with(&root));
        result.push(root);
    }
    result.sort();
    result
}

fn add_path_entry(path: &Path, entries: &mut Vec<PathBuf>, seen: &mut BTreeSet<PathBuf>) {
    let path = path.to_path_buf();
    if seen.insert(path.clone()) {
        entries.push(path);
    }
}

fn join_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.to_string_lossy())
        .collect::<Vec<_>>()
        .join(":")
}

fn paths_json(paths: &[PathBuf]) -> serde_json::Value {
    serde_json::Value::Array(
        paths
            .iter()
            .map(|path| serde_json::Value::String(path.to_string_lossy().into_owned()))
            .collect(),
    )
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn canonicalize_lenient(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn expand_home(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if text == "~" {
        return env::var_os("HOME").map_or_else(|| path.to_path_buf(), PathBuf::from);
    }
    if let Some(rest) = text.strip_prefix("~/") {
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    #[test]
    fn generic_discovery_and_explicit_roots_match_source_policy() -> Result<(), ReCtmError> {
        let temp = TempDir::new().map_err(|error| ReCtmError::new("TEST", error.to_string()))?;
        let workspace = temp.path().join("workspace");
        let data = temp.path().join("data");
        let private = data.join("private");
        fs::create_dir_all(&workspace).map_err(io_error)?;
        fs::create_dir_all(&private).map_err(io_error)?;
        let environment = temp.path().join("science-stack");
        let environment_bin = environment.join("bin");
        fs::create_dir_all(&environment_bin).map_err(io_error)?;
        let wrapper_bin = temp.path().join("wrapper-bin");
        fs::create_dir_all(&wrapper_bin).map_err(io_error)?;
        let product = temp.path().join("product");
        let product_exec = product.join("Executables");
        fs::create_dir_all(&product_exec).map_err(io_error)?;
        let target = product_exec.join("symbolic-b");
        fs::write(&target, b"#!/bin/sh\n").map_err(io_error)?;
        symlink(&target, wrapper_bin.join("symbolic-b")).map_err(io_error)?;
        let explicit = temp.path().join("explicit");
        fs::create_dir_all(explicit.join("bin")).map_err(io_error)?;
        let host_path = format!(
            "{}:{}:/usr/bin:/bin",
            environment_bin.display(),
            wrapper_bin.display()
        );
        let plan = build_toolchain_exposure_plan(
            NativeMode::Dangerous,
            &workspace,
            &[data, private],
            std::slice::from_ref(&explicit),
            Some(&host_path),
        )?;
        assert!(plan.discovered_roots.contains(&environment));
        assert!(plan.discovered_roots.contains(&product));
        assert!(plan.discovered_roots.contains(&wrapper_bin));
        assert_eq!(plan.explicit_roots, vec![explicit]);
        Ok(())
    }

    fn io_error(error: std::io::Error) -> ReCtmError {
        ReCtmError::new("TEST_IO", error.to_string())
    }
}
