use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use mtm_contracts::{ErrorCategory, LatexPolicy, NativeMode, ReCtmError};
use mtm_native::validate_explicit_toolchain_roots;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct RuntimeSettings {
    pub workspace: PathBuf,
    pub data_root: PathBuf,
    pub private_root: PathBuf,
    pub debug_root: PathBuf,
    pub native_mode: NativeMode,
    pub native_exec_backend: String,
    pub native_exec_allow_roots: Vec<PathBuf>,
    pub latex_policy: LatexPolicy,
    pub debug_enabled: bool,
    pub trace_payloads: bool,
    pub oauth_server_url: String,
    pub oauth_password: String,
    pub allowed_origins: BTreeSet<String>,
    pub theorem_search_url: String,
    pub theorem_search_timeout_seconds: u64,
    pub token_secret: Vec<u8>,
    pub capability_secret: Vec<u8>,
}

impl RuntimeSettings {
    pub fn from_env() -> Result<Self, ReCtmError> {
        let cwd = env::current_dir().map_err(io_error)?;
        let workspace = absolute_path(env::var("MTM_WORKSPACE").ok().as_deref(), &cwd)?;
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| validation("HOME is required to resolve default MTM data paths."))?;
        let data_root = absolute_path(
            env::var("MTM_DATA_ROOT").ok().as_deref(),
            &home.join(".mtm"),
        )?;
        let private_root = absolute_path(
            env::var("MTM_PRIVATE_ROOT").ok().as_deref(),
            &data_root.join("private"),
        )?;
        let debug_root = absolute_path(
            env::var("MTM_DEBUG_ROOT").ok().as_deref(),
            &data_root.join("debug"),
        )?;
        let native_mode = parse_native_mode(
            env::var("MTM_NATIVE_MODE")
                .ok()
                .as_deref()
                .unwrap_or("safe"),
        )?;
        let configured_backend = env::var("MTM_NATIVE_EXEC_BACKEND")
            .unwrap_or_default()
            .trim()
            .to_owned();
        let native_exec_backend = if configured_backend.is_empty() {
            if cfg!(target_os = "linux") && executable_on_path("bwrap") {
                "bubblewrap".to_owned()
            } else {
                "disabled".to_owned()
            }
        } else {
            configured_backend
        };
        let native_exec_allow_roots = parse_allow_roots(
            env::var("MTM_NATIVE_EXEC_ALLOW_ROOTS")
                .ok()
                .as_deref()
                .unwrap_or_default(),
        )?;
        let latex_policy = parse_latex_policy(
            env::var("MTM_LATEX_POLICY")
                .ok()
                .as_deref()
                .unwrap_or("required"),
        )?;
        let token_secret = decode_secret(
            env::var("MTM_TOKEN_SECRET").unwrap_or_default().trim(),
            "MTM_TOKEN_SECRET",
        )?;
        let mut capability_secret = decode_secret(
            env::var("MTM_CAPABILITY_SECRET").unwrap_or_default().trim(),
            "MTM_CAPABILITY_SECRET",
        )?;
        if capability_secret.is_empty() && !token_secret.is_empty() {
            capability_secret = derive_capability_secret(&token_secret);
        }
        let allowed_origins = env::var("MTM_ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.trim_end_matches('/').to_owned())
            .collect::<BTreeSet<_>>();
        let timeout = env::var("MTM_THEOREM_SEARCH_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "30".to_owned())
            .parse::<u64>()
            .map_err(|_| validation("MTM_THEOREM_SEARCH_TIMEOUT_SECONDS must be an integer."))?;

        let settings = Self {
            workspace,
            data_root,
            private_root,
            debug_root,
            native_mode,
            native_exec_backend,
            native_exec_allow_roots,
            latex_policy,
            debug_enabled: truthy(env::var("MTM_DEBUG").ok().as_deref()),
            trace_payloads: truthy(env::var("MTM_TRACE_PAYLOADS").ok().as_deref()),
            oauth_server_url: env::var("MTM_SERVER_URL")
                .unwrap_or_default()
                .trim_end_matches('/')
                .to_owned(),
            oauth_password: env::var("MTM_OAUTH_PASSWORD").unwrap_or_default(),
            allowed_origins,
            theorem_search_url: env::var("MTM_THEOREM_SEARCH_URL")
                .unwrap_or_else(|_| "https://leansearch.net/thm/search".to_owned())
                .trim()
                .to_owned(),
            theorem_search_timeout_seconds: timeout,
            token_secret,
            capability_secret,
        };
        settings.validate()?;
        Ok(settings)
    }

    pub fn validate(&self) -> Result<(), ReCtmError> {
        if !self.workspace.is_dir() {
            return Err(ReCtmError::new(
                "INVALID_WORKSPACE",
                "MTM_WORKSPACE must be an existing directory.",
            )
            .with_category(ErrorCategory::Validation)
            .with_details(serde_json::json!({"workspace":self.workspace})));
        }
        let root = Path::new("/");
        let home = env::var_os("HOME").map(PathBuf::from);
        if self.workspace == root || home.as_ref().is_some_and(|path| path == &self.workspace) {
            return Err(ReCtmError::new(
                "UNSAFE_WORKSPACE",
                "The filesystem root and home directory cannot be the native workspace.",
            )
            .with_category(ErrorCategory::Security));
        }
        if overlaps(&self.workspace, &self.data_root)
            || overlaps(&self.workspace, &self.private_root)
        {
            return Err(ReCtmError::new(
                "TRUST_DOMAIN_OVERLAP",
                "The server data/private roots and native workspace must not overlap.",
            )
            .with_category(ErrorCategory::Security)
            .with_details(serde_json::json!({
                "workspace":self.workspace,"data_root":self.data_root,"private_root":self.private_root
            })));
        }
        if !matches!(self.native_exec_backend.as_str(), "disabled" | "bubblewrap") {
            return Err(ReCtmError::new(
                "INVALID_NATIVE_EXEC_BACKEND",
                "MTM currently supports disabled or bubblewrap Native execution.",
            )
            .with_category(ErrorCategory::Validation));
        }
        if !self.native_exec_allow_roots.is_empty() && self.native_exec_backend != "bubblewrap" {
            return Err(ReCtmError::new(
                "NATIVE_TOOLCHAIN_ROOTS_UNSUPPORTED",
                "MTM_NATIVE_EXEC_ALLOW_ROOTS requires the built-in Bubblewrap backend.",
            )
            .with_category(ErrorCategory::Validation));
        }
        if !self.native_exec_allow_roots.is_empty() {
            validate_explicit_toolchain_roots(
                &self.native_exec_allow_roots,
                &self.workspace,
                &[self.data_root.clone(), self.private_root.clone()],
            )?;
        }
        if !(1..=300).contains(&self.theorem_search_timeout_seconds) {
            return Err(ReCtmError::new(
                "INVALID_RESEARCH_TIMEOUT",
                "MTM_THEOREM_SEARCH_TIMEOUT_SECONDS must be between 1 and 300.",
            )
            .with_category(ErrorCategory::Validation));
        }
        validate_https_endpoint(&self.theorem_search_url)?;
        Ok(())
    }

    pub fn ensure_directories(&self) -> Result<(), ReCtmError> {
        for path in [&self.data_root, &self.private_root, &self.debug_root] {
            fs::create_dir_all(path).map_err(io_error)?;
            set_owner_only_dir(path)?;
        }
        Ok(())
    }
}

pub fn materialize_secrets(mut settings: RuntimeSettings) -> Result<RuntimeSettings, ReCtmError> {
    settings.ensure_directories()?;
    if settings.token_secret.is_empty() {
        settings.token_secret =
            load_or_create_secret(&settings.data_root.join("oauth-token-secret.hex"))?;
    }
    if settings.capability_secret.is_empty() {
        settings.capability_secret = derive_capability_secret(&settings.token_secret);
    }
    Ok(settings)
}

pub fn generate_operator_password() -> Result<String, ReCtmError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| {
        ReCtmError::new("RANDOM_SOURCE_ERROR", error.to_string())
            .with_category(ErrorCategory::Internal)
    })?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn validate_https_endpoint(value: &str) -> Result<(), ReCtmError> {
    let parsed = url::Url::parse(value).map_err(|_| {
        ReCtmError::new(
            "INVALID_RESEARCH_ENDPOINT",
            "The theorem-search endpoint must be an absolute HTTPS URL without user info.",
        )
        .with_category(ErrorCategory::Security)
    })?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(ReCtmError::new(
            "INVALID_RESEARCH_ENDPOINT",
            "The theorem-search endpoint must be an absolute HTTPS URL without user info.",
        )
        .with_category(ErrorCategory::Security));
    }
    Ok(())
}

fn load_or_create_secret(path: &Path) -> Result<Vec<u8>, ReCtmError> {
    if path.exists() {
        let raw = fs::read_to_string(path).map_err(io_error)?;
        return decode_secret(raw.trim(), &path.display().to_string());
    }
    let mut secret = vec![0_u8; 32];
    getrandom::fill(&mut secret).map_err(|error| {
        ReCtmError::new("RANDOM_SOURCE_ERROR", error.to_string())
            .with_category(ErrorCategory::Internal)
    })?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(io_error)?;
    }
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    fs::write(&temporary, format!("{}\n", encode_hex(&secret))).map_err(io_error)?;
    set_owner_only_file(&temporary)?;
    fs::rename(&temporary, path).map_err(io_error)?;
    set_owner_only_file(path)?;
    Ok(secret)
}

fn parse_allow_roots(value: &str) -> Result<Vec<PathBuf>, ReCtmError> {
    value
        .split(':')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| {
            let path = PathBuf::from(item);
            if !path.is_absolute() {
                return Err(validation(
                    "MTM_NATIVE_EXEC_ALLOW_ROOTS entries must be absolute paths.",
                ));
            }
            path.canonicalize().map_err(io_error)
        })
        .collect()
}

fn absolute_path(raw: Option<&str>, default: &Path) -> Result<PathBuf, ReCtmError> {
    let path = raw
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| default.to_path_buf());
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(env::current_dir().map_err(io_error)?.join(path))
    }
}

fn parse_native_mode(value: &str) -> Result<NativeMode, ReCtmError> {
    match value {
        "safe" => Ok(NativeMode::Safe),
        "trusted" => Ok(NativeMode::Trusted),
        "dangerous" => Ok(NativeMode::Dangerous),
        _ => Err(validation(
            "MTM_NATIVE_MODE must be safe, trusted, or dangerous.",
        )),
    }
}

fn parse_latex_policy(value: &str) -> Result<LatexPolicy, ReCtmError> {
    match value {
        "static_only" => Ok(LatexPolicy::StaticOnly),
        "if_available" => Ok(LatexPolicy::IfAvailable),
        "required" => Ok(LatexPolicy::Required),
        _ => Err(validation(
            "MTM_LATEX_POLICY must be static_only, if_available, or required.",
        )),
    }
}

fn decode_secret(raw: &str, name: &str) -> Result<Vec<u8>, ReCtmError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    if raw.len() % 2 != 0 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ReCtmError::new(
            "INVALID_SECRET",
            format!("{name} must be hex-encoded bytes."),
        )
        .with_category(ErrorCategory::Validation));
    }
    let bytes = raw
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| validation("invalid secret"))?;
            u8::from_str_radix(text, 16).map_err(|_| validation("invalid secret"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if bytes.len() < 32 {
        return Err(ReCtmError::new(
            "INVALID_SECRET",
            format!("{name} must contain at least 32 bytes."),
        )
        .with_category(ErrorCategory::Validation));
    }
    Ok(bytes)
}

fn derive_capability_secret(token_secret: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(token_secret);
    digest.update(b"/capability");
    digest.finalize().to_vec()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn truthy(value: Option<&str>) -> bool {
    value.is_some_and(|raw| {
        matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn executable_on_path(name: &str) -> bool {
    env::var_os("PATH")
        .is_some_and(|path| env::split_paths(&path).any(|directory| directory.join(name).is_file()))
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

#[cfg(unix)]
fn set_owner_only_dir(path: &Path) -> Result<(), ReCtmError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)
}

#[cfg(not(unix))]
fn set_owner_only_dir(_path: &Path) -> Result<(), ReCtmError> {
    Ok(())
}

#[cfg(unix)]
fn set_owner_only_file(path: &Path) -> Result<(), ReCtmError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(io_error)
}

#[cfg(not(unix))]
fn set_owner_only_file(_path: &Path) -> Result<(), ReCtmError> {
    Ok(())
}

fn validation(message: &str) -> ReCtmError {
    ReCtmError::new("INVALID_ARGUMENT", message).with_category(ErrorCategory::Validation)
}

fn io_error(error: std::io::Error) -> ReCtmError {
    ReCtmError::new("RUNTIME_IO_ERROR", error.to_string()).with_category(ErrorCategory::Runtime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_round_trip_and_capability_derivation() -> Result<(), ReCtmError> {
        let raw = "11".repeat(32);
        let secret = decode_secret(&raw, "TEST")?;
        assert_eq!(secret.len(), 32);
        assert_eq!(derive_capability_secret(&secret).len(), 32);
        Ok(())
    }
}
