use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;

use mtm_contracts::{ErrorCategory, ReCtmError};

#[cfg(unix)]
use super::encode_hex;
use super::{io_error, load_or_create_secret, publish_secret_candidate};

fn join_error() -> ReCtmError {
    ReCtmError::new(
        "TEST_THREAD_FAILED",
        "Secret initialization test thread failed.",
    )
    .with_category(ErrorCategory::Internal)
}

#[test]
fn concurrent_candidates_return_one_persisted_key() -> Result<(), ReCtmError> {
    let root = tempfile::tempdir().map_err(io_error)?;
    let path = root.path().join("secret.hex");
    let barrier = Arc::new(Barrier::new(16));
    let handles = (0_u8..16)
        .map(|index| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let candidate = vec![index; 32];
                barrier.wait();
                publish_secret_candidate(&path, &candidate)
            })
        })
        .collect::<Vec<_>>();
    // Join every worker, including on failure, before the temporary root is removed.
    let results = handles
        .into_iter()
        .map(|handle| {
            handle
                .join()
                .map_err(|_| join_error())
                .and_then(|value| value)
        })
        .collect::<Vec<_>>();
    let persisted = load_or_create_secret(&path)?;
    for result in results {
        assert!(result? == persisted);
    }
    assert_eq!(fs::read_dir(root.path()).map_err(io_error)?.count(), 1);
    Ok(())
}

#[test]
fn existing_key_is_never_replaced() -> Result<(), ReCtmError> {
    let root = tempfile::tempdir().map_err(io_error)?;
    let path = root.path().join("secret.hex");
    let first = load_or_create_secret(&path)?;
    let bytes = fs::read(&path).map_err(io_error)?;
    let second = publish_secret_candidate(&path, &[37; 32])?;
    assert!(first == second);
    assert!(bytes == fs::read(&path).map_err(io_error)?);
    Ok(())
}

#[test]
fn invalid_and_empty_persisted_keys_are_not_regenerated() -> Result<(), ReCtmError> {
    let root = tempfile::tempdir().map_err(io_error)?;
    for (index, contents) in ["", "\n", "not-hex", "abcd"].iter().enumerate() {
        let path = root.path().join(format!("invalid-{index}.hex"));
        fs::write(&path, contents).map_err(io_error)?;
        let code = load_or_create_secret(&path).err().map(|error| error.code);
        assert_eq!(code.as_deref(), Some("INVALID_SECRET"));
        assert_eq!(fs::read_to_string(path).map_err(io_error)?, *contents);
    }
    Ok(())
}

#[test]
fn directory_secret_is_rejected() -> Result<(), ReCtmError> {
    let root = tempfile::tempdir().map_err(io_error)?;
    let code = load_or_create_secret(root.path())
        .err()
        .map(|error| error.code);
    assert_eq!(code.as_deref(), Some("INVALID_SECRET"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn secret_symlinks_are_rejected_without_touching_target() -> Result<(), ReCtmError> {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().map_err(io_error)?;
    let target = root.path().join("target.hex");
    let original = format!("{}\n", encode_hex(&[19; 32]));
    fs::write(&target, &original).map_err(io_error)?;
    let path = root.path().join("secret.hex");
    symlink(&target, &path).map_err(io_error)?;
    let code = load_or_create_secret(&path).err().map(|error| error.code);
    assert_eq!(code.as_deref(), Some("INVALID_SECRET"));
    assert_eq!(fs::read_to_string(target).map_err(io_error)?, original);
    Ok(())
}

#[cfg(unix)]
#[test]
fn generated_key_is_owner_only() -> Result<(), ReCtmError> {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().map_err(io_error)?;
    let path = root.path().join("secret.hex");
    let _secret = load_or_create_secret(&path)?;
    assert_eq!(
        fs::metadata(path).map_err(io_error)?.permissions().mode() & 0o777,
        0o600
    );
    Ok(())
}
