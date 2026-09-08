use std::cell::Cell;
use std::os::unix::fs::PermissionsExt;

use super::*;

fn invocation(patch: &str) -> Result<PatchInvocation, ReCtmError> {
    PatchInvocation::parse(&Map::from_iter([("patch".to_owned(), Value::from(patch))]))
}

fn update() -> &'static str {
    "*** Begin Patch\n*** Update File: script\n@@\n-old\n+new\n*** End Patch\n"
}

fn fixture(
    mode: u32,
) -> Result<(tempfile::TempDir, tempfile::TempDir, NativeWorkspace), ReCtmError> {
    let root = tempfile::tempdir().map_err(io_error)?;
    let private = tempfile::tempdir().map_err(io_error)?;
    fs::write(root.path().join("script"), "old\n").map_err(io_error)?;
    fs::set_permissions(root.path().join("script"), fs::Permissions::from_mode(mode))
        .map_err(io_error)?;
    let workspace = NativeWorkspace::new(root.path(), private.path())?;
    Ok((root, private, workspace))
}

fn mode(path: &Path) -> Result<u32, ReCtmError> {
    Ok(fs::metadata(path).map_err(io_error)?.permissions().mode() & 0o7777)
}

#[test]
fn patch_preserves_executable_mode() -> Result<(), ReCtmError> {
    let (root, _private, workspace) = fixture(0o755)?;
    let prepared = workspace.prepare_patch(&invocation(update())?)?;
    workspace.commit_prepared_patch_with_authorization(prepared, || Ok(()))?;
    assert_eq!(mode(&root.path().join("script"))?, 0o755);
    assert_eq!(
        fs::read_to_string(root.path().join("script")).map_err(io_error)?,
        "new\n"
    );
    Ok(())
}

#[test]
fn patch_does_not_widen_private_file_permissions() -> Result<(), ReCtmError> {
    for expected in [0o600, 0o640, 0o700, 0o444] {
        let (root, _private, workspace) = fixture(expected)?;
        let prepared = workspace.prepare_patch(&invocation(update())?)?;
        workspace.commit_prepared_patch_with_authorization(prepared, || Ok(()))?;
        assert_eq!(mode(&root.path().join("script"))?, expected);
    }
    Ok(())
}

#[test]
fn patch_move_preserves_source_mode() -> Result<(), ReCtmError> {
    let (root, _private, workspace) = fixture(0o700)?;
    let patch = "*** Begin Patch\n*** Update File: script\n*** Move to: nested/moved\n@@\n-old\n+new\n*** End Patch\n";
    let prepared = workspace.prepare_patch(&invocation(patch)?)?;
    workspace.commit_prepared_patch_with_authorization(prepared, || Ok(()))?;
    assert!(!root.path().join("script").exists());
    assert_eq!(mode(&root.path().join("nested/moved"))?, 0o700);
    Ok(())
}

#[test]
fn mode_changes_after_preparation_are_denied_before_authorization() -> Result<(), ReCtmError> {
    let (root, _private, workspace) = fixture(0o755)?;
    let prepared = workspace.prepare_patch(&invocation(update())?)?;
    fs::set_permissions(
        root.path().join("script"),
        fs::Permissions::from_mode(0o700),
    )
    .map_err(io_error)?;
    let called = Cell::new(false);
    assert!(
        workspace
            .commit_prepared_patch_with_authorization(prepared, || {
                called.set(true);
                Ok(())
            })
            .is_err()
    );
    assert!(!called.get());
    assert_eq!(mode(&root.path().join("script"))?, 0o700);
    Ok(())
}

#[test]
fn failed_transaction_restores_original_content_and_mode() -> Result<(), ReCtmError> {
    let (root, _private, workspace) = fixture(0o755)?;
    fs::write(root.path().join("z-last"), "last\n").map_err(io_error)?;
    let patch = "*** Begin Patch\n*** Update File: script\n@@\n-old\n+new\n*** Update File: z-last\n@@\n-last\n+changed\n*** End Patch\n";
    let prepared = workspace.prepare_patch(&invocation(patch)?)?;
    let result = workspace.commit_prepared_patch_with_hook(
        prepared,
        || Ok(()),
        |index| {
            if index == 1 {
                Err(internal("injected test failure"))
            } else {
                Ok(())
            }
        },
    );
    assert!(result.is_err());
    assert_eq!(mode(&root.path().join("script"))?, 0o755);
    assert_eq!(
        fs::read_to_string(root.path().join("script")).map_err(io_error)?,
        "old\n"
    );
    assert_eq!(fs::read_dir(root.path()).map_err(io_error)?.count(), 2);
    Ok(())
}

#[test]
fn content_update_does_not_preserve_special_permission_bits() -> Result<(), ReCtmError> {
    let (root, _private, workspace) = fixture(0o6755)?;
    let prepared = workspace.prepare_patch(&invocation(update())?)?;
    workspace.commit_prepared_patch_with_authorization(prepared, || Ok(()))?;
    assert_eq!(mode(&root.path().join("script"))?, 0o755);
    Ok(())
}

#[test]
fn adding_a_script_does_not_implicitly_grant_executable_permissions() -> Result<(), ReCtmError> {
    let (root, _private, workspace) = fixture(0o600)?;
    let prepared = workspace.prepare_patch(&invocation(
        "*** Begin Patch\n*** Add File: added\n+#!/bin/sh\n*** End Patch\n",
    )?)?;
    workspace.commit_prepared_patch_with_authorization(prepared, || Ok(()))?;
    assert_eq!(mode(&root.path().join("added"))? & 0o111, 0);
    Ok(())
}
