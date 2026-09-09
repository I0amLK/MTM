//! Byte-bound distribution staging. This never installs or selects a release.
use std::fs::{self, File};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::Result;

const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

pub(crate) struct Options {
    binary: PathBuf,
    sha256: String,
    version: String,
    out: PathBuf,
}

fn require(value: bool, message: &str) -> Result<()> {
    if value { Ok(()) } else { Err(message.into()) }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'))
}

impl Options {
    pub(crate) fn parse(arguments: &[String]) -> Result<Self> {
        let mut binary = None;
        let mut sha256 = None;
        let mut version = None;
        let mut out = None;
        let mut index = 0;
        while index < arguments.len() {
            let key = arguments[index].as_str();
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| format!("{key} requires a value"))?;
            match key {
                "--binary" if binary.is_none() => binary = Some(PathBuf::from(value)),
                "--sha256" if sha256.is_none() => sha256 = Some(value.to_owned()),
                "--version" if version.is_none() => version = Some(value.to_owned()),
                "--out" if out.is_none() => out = Some(PathBuf::from(value)),
                _ => return Err(format!("unknown or duplicate dist option: {key}").into()),
            }
            index += 2;
        }
        let options = Self {
            binary: binary.ok_or("dist requires --binary")?,
            sha256: sha256.ok_or("dist requires --sha256")?,
            version: version.ok_or("dist requires --version")?,
            out: out.ok_or("dist requires --out")?,
        };
        require(options.binary.is_absolute(), "dist binary must be absolute")?;
        require(options.out.is_absolute(), "dist output must be absolute")?;
        require(valid_sha256(&options.sha256), "dist SHA-256 is invalid")?;
        require(safe_version(&options.version), "dist version is unsafe")?;
        Ok(options)
    }
}

fn digest(path: &Path) -> Result<String> {
    directory_chain(path.parent().ok_or("artifact parent missing")?)?;
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "dist artifact must be a regular non-symlink file",
    )?;
    require(
        metadata.len() <= MAX_ARTIFACT_BYTES,
        "dist artifact exceeds fixed size bound",
    )?;
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        require(total <= MAX_ARTIFACT_BYTES, "dist source grew beyond bound")?;
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn directory_chain(path: &Path) -> Result<()> {
    let text = path.to_str().ok_or("dist path must be UTF-8")?;
    require(
        path.is_absolute()
            && text.len() <= 4096
            && (text == "/"
                || text
                    .split('/')
                    .skip(1)
                    .all(|part| !matches!(part, "" | "." | ".."))),
        "dist path must be normalized and absolute",
    )?;
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => require(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "dist ancestor must be a real directory",
            )?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn directory(path: &Path) -> Result<()> {
    directory_chain(path)?;
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        require(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "dist directory must be a real directory",
        )?;
    } else {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

fn copy_exact(source: &Path, target: &Path, expected: &str) -> Result<()> {
    if fs::symlink_metadata(target).is_ok() {
        return require(
            digest(target)? == expected,
            "dist target conflicts with requested artifact",
        );
    }
    let parent = target.parent().ok_or("dist target has no parent")?;
    directory(parent)?;
    let mut input = File::open(source)?.take(MAX_ARTIFACT_BYTES + 1);
    let mut output = tempfile::NamedTempFile::new_in(parent)?;
    let copied = std::io::copy(&mut input, &mut output)?;
    require(copied <= MAX_ARTIFACT_BYTES, "dist copy exceeded bound")?;
    #[cfg(unix)]
    output
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o755))?;
    output.as_file().sync_all()?;
    require(
        digest(output.path())? == expected && digest(source)? == expected,
        "dist copy SHA-256 mismatch",
    )?;
    match output.persist_noclobber(target) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            require(
                digest(target)? == expected,
                "dist publication race conflict",
            )?;
        }
        Err(error) => return Err(error.error.into()),
    }
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub(crate) fn run(options: &Options) -> Result<Value> {
    let metadata = fs::symlink_metadata(&options.binary)?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "dist source must be a regular non-symlink file",
    )?;
    #[cfg(unix)]
    require(
        metadata.permissions().mode() & 0o111 != 0 && metadata.permissions().mode() & 0o6000 == 0,
        "dist source must be executable",
    )?;
    require(
        digest(&options.binary)? == options.sha256,
        "dist source SHA-256 mismatch",
    )?;
    directory(&options.out)?;
    let bundle = options
        .out
        .join(format!("mtm-{}-{}", options.version, options.sha256));
    directory(&bundle)?;
    let artifact = bundle.join("mtm");
    copy_exact(&options.binary, &artifact, &options.sha256)?;
    #[cfg(unix)]
    require(
        fs::metadata(&artifact)?.permissions().mode() & 0o7777 == 0o755,
        "dist artifact executable mode changed",
    )?;
    let report = json!({
        "schema_version":"1.0.0","scope":"byte_bound_distribution_staging",
        "version":options.version,"version_label_verified":false,"sha256":options.sha256,"size_bytes":fs::metadata(&artifact)?.len(),
        "artifact":artifact,"installed":false,"selector_changed":false,
        "release_qualified":false,"python_invoked":false
    });
    let metadata_path = bundle.join("dist.json");
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    if fs::symlink_metadata(&metadata_path).is_ok() {
        let metadata = fs::symlink_metadata(&metadata_path)?;
        require(
            metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 16_384,
            "unsafe or oversized dist metadata",
        )?;
        let mut previous = Vec::new();
        File::open(&metadata_path)?
            .take(16_385)
            .read_to_end(&mut previous)?;
        require(previous.len() <= 16_384, "dist metadata grew beyond bound")?;
        let existing: Value = serde_json::from_slice(&previous)?;
        require(
            existing == report,
            "dist metadata conflicts with requested bundle",
        )?;
    } else {
        let mut file = tempfile::NamedTempFile::new_in(&bundle)?;
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        file.persist_noclobber(&metadata_path)
            .map_err(|error| error.error)?;
        File::open(&bundle)?.sync_all()?;
    }
    require(
        digest(&options.binary)? == options.sha256 && digest(&artifact)? == options.sha256,
        "dist final identity drift",
    )?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_rejects_implicit_and_unsafe_locations() {
        let args = [
            "--binary",
            "/tmp/mtm",
            "--sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--version",
            "0.6.0-preview.1",
            "--out",
            "/tmp/dist",
        ]
        .map(str::to_owned);
        assert!(Options::parse(&args).is_ok());
        let mut relative = args.to_vec();
        relative[7] = "relative".to_owned();
        assert!(Options::parse(&relative).is_err());
        let mut version = args.to_vec();
        version[5] = "../escape".to_owned();
        assert!(Options::parse(&version).is_err());
    }
}
