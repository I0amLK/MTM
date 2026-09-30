//! Execute the actual built CLI with no inherited toolchain or Python PATH.
//! This checks offline identity commands, not installation or server qualification.
use std::error::Error;
use std::process::{Command, Stdio};

use serde_json::Value;

fn read(command: &str) -> Result<Value, Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_mtm"))
        .arg(command)
        .env_clear()
        .current_dir(std::env::temp_dir())
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() || output.stdout.len() > 256 * 1024 {
        return Err("offline CLI identity command failed".into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[test]
fn current_identity_does_not_publish_the_migration_baseline() -> Result<(), Box<dyn Error>> {
    let info = read("release-info")?;
    let contract = read("contract")?;
    let status = read("status")?;
    assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(info["version"], "0.6.0-preview.2");
    assert_eq!(info["public_tool_count"], 24);
    assert_eq!(info["hidden_alias_count"], 0);
    assert_eq!(info["workflow_protocol_version"], 3);
    assert_eq!(info["state_schema_version"], 8);
    assert_eq!(info["python_runtime_required"], false);
    assert_eq!(contract["authority"], "rust");
    assert_eq!(contract["hidden_aliases"], 0);
    assert_eq!(contract["workflow_protocol"], 3);
    assert_eq!(status["scope"], "compiled_runtime_identity");
    assert_eq!(status["installed_selector_checked"], false);
    assert_eq!(status["release_qualification_checked"], false);
    assert!(status.get("completed_milestones").is_none());
    assert_eq!(status["version"], info["version"]);
    Ok(())
}

#[test]
fn cli_catalog_is_complete_and_exposes_real_argument_properties() -> Result<(), Box<dyn Error>> {
    let catalog = read("tool-catalog")?;
    let info = read("release-info")?;
    let definitions = catalog["definitions"]
        .as_object()
        .ok_or("missing definitions")?;
    let names = catalog["public_names"].as_array().ok_or("missing names")?;
    assert_eq!(definitions.len(), 24);
    assert_eq!(names.len(), 24);
    assert_eq!(
        catalog["tool_contract_version"],
        info["tool_contract_version"]
    );
    assert!(catalog.get("hidden_names").is_none());
    for name in names {
        let name = name.as_str().ok_or("non-string tool name")?;
        let definition = definitions.get(name).ok_or("missing public tool")?;
        assert_eq!(definition["name"], name);
        assert!(definition["inputSchema"]["properties"].is_object());
        assert_eq!(definition["inputSchema"]["additionalProperties"], false);
    }
    assert_eq!(
        definitions["exec_command"]["inputSchema"]["properties"]["argv"]["type"],
        "array"
    );
    assert_eq!(
        definitions["rethlas_inspect"]["inputSchema"]["properties"]["operation"]["type"],
        "string"
    );
    for alias in [
        "rethlas_next",
        "rethlas_read",
        "rethlas_write",
        "rethlas_search",
        "rethlas_commit",
        "rethlas_status",
        "rethlas_steer",
        "rethlas_resume",
        "rethlas_cancel",
        "rethlas_get_artifact",
        "rethlas_export_final",
    ] {
        assert!(!definitions.contains_key(alias));
    }
    assert_eq!(catalog, read("tool-catalog")?);
    Ok(())
}
