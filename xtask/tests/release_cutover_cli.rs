#![cfg(target_os = "linux")]

use std::error::Error;
use std::process::{Command, Stdio};

#[test]
fn release_cutover_rejects_missing_or_wrong_authority_before_touching_state()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let candidate = "target/mtm016-f6-frozen/mtm-0.6.0-preview.1-f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034/mtm";
    let manifest = "records/governance/mtm016-release-inputs.json";
    for arguments in [
        vec![
            "release-cutover",
            "--binary",
            candidate,
            "--manifest",
            manifest,
        ],
        vec![
            "release-cutover",
            "--binary",
            candidate,
            "--manifest",
            manifest,
            "--authorize",
            "MTM-015",
        ],
        vec![
            "release-cutover",
            "--binary",
            "target/other/mtm",
            "--manifest",
            manifest,
            "--authorize",
            "MTM-016",
        ],
        vec![
            "release-cutover",
            "--binary",
            candidate,
            "--manifest",
            manifest,
            "--authorize",
            "MTM-016",
            "--skip-readiness",
            "true",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
            .args(arguments)
            .env_clear()
            .current_dir(directory.path())
            .stdin(Stdio::null())
            .output()?;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(std::fs::read_dir(directory.path())?.count(), 0);
    }
    Ok(())
}
