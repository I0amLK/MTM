//! Explicit test-only candidate selection. Never used by the product runtime.
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::loopback::sha256_file;
use super::{Result, require};

pub const BINARY_ENV: &str = "MTM_TEST_CANDIDATE";
pub const HASH_ENV: &str = "MTM_TEST_CANDIDATE_SHA256";
pub const BASELINE_ENV: &str = "MTM_TEST_BASELINE";
pub const BASELINE_HASH_ENV: &str = "MTM_TEST_BASELINE_SHA256";

pub struct Candidate {
    pub path: String,
    pub sha256: String,
}

pub fn select() -> Result<Candidate> {
    select_pair(BINARY_ENV, HASH_ENV, Some(env!("CARGO_BIN_EXE_mtm")))
}

pub fn select_baseline() -> Result<Candidate> {
    select_pair(BASELINE_ENV, BASELINE_HASH_ENV, None)
}

fn select_pair(path_env: &str, hash_env: &str, fallback: Option<&str>) -> Result<Candidate> {
    let (path, expected) = match (env::var_os(path_env), env::var_os(hash_env)) {
        (None, None) => match fallback {
            Some(path) => (path.to_owned(), None),
            None => return Err("explicit baseline selection is required"),
        },
        (Some(path), Some(hash)) => (
            path.into_string()
                .map_err(|_| "candidate path is not UTF-8")?,
            Some(
                hash.into_string()
                    .map_err(|_| "candidate digest is not UTF-8")?,
            ),
        ),
        _ => return Err("artifact selection requires both path and SHA-256"),
    };
    inspect(&path, expected.as_deref())
}

fn inspect(path: &str, expected: Option<&str>) -> Result<Candidate> {
    let path = Path::new(path);
    require(path.is_absolute(), "candidate path must be absolute")?;
    let metadata = fs::symlink_metadata(path).map_err(|_| "candidate cannot be inspected")?;
    require(
        metadata.is_file()
            && metadata.permissions().mode() & 0o111 != 0
            && metadata.permissions().mode() & 0o6000 == 0,
        "candidate must be a regular executable without special permission bits",
    )?;
    let sha256 = sha256_file(path)?;
    if let Some(expected) = expected {
        require(
            expected == sha256,
            "candidate digest mismatch before execution",
        )?;
    }
    Ok(Candidate {
        path: path
            .to_str()
            .ok_or("candidate path is not UTF-8")?
            .to_owned(),
        sha256,
    })
}

impl Candidate {
    pub fn unchanged(&self) -> Result {
        require(
            sha256_file(Path::new(&self.path))? == self.sha256,
            "candidate changed during test",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_missing_relative_and_privileged_candidates_are_rejected_without_execution() -> Result {
        require(
            inspect("relative", None).is_err(),
            "relative selection accepted",
        )?;
        let dir = tempfile::tempdir().map_err(|_| "fixture directory")?;
        let path = dir.path().join("candidate");
        let name = path.to_str().ok_or("fixture path")?;
        require(inspect(name, None).is_err(), "missing selection accepted")?;
        fs::write(&path, b"inert fixture bytes").map_err(|_| "fixture write")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .map_err(|_| "fixture mode")?;
        require(
            inspect(name, Some(&"0".repeat(64))).is_err(),
            "wrong digest accepted",
        )?;
        let selected = inspect(name, None)?;
        selected.unchanged()?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o4755))
            .map_err(|_| "fixture mode")?;
        require(inspect(name, None).is_err(), "special bits accepted")?;
        fs::write(&path, b"changed").map_err(|_| "fixture change")?;
        require(selected.unchanged().is_err(), "candidate drift accepted")
    }
}
