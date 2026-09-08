use std::collections::BTreeSet;

use mtm_core::validate_schema_value;

use super::*;

#[test]
fn creation_identity_and_recovery_only_have_bounded_distinct_contracts() -> Result<(), ReCtmError> {
    for key in [
        "a".repeat(16),
        "z".repeat(128),
        "idempotent_start-01".into(),
    ] {
        validate_schema_value(
            &json!({"problem_tex":"fixture","creation_key":key}),
            &schema::input(ToolId::RethlasStart),
            "arguments",
        )?;
    }
    for key in [
        json!("short"),
        json!("z".repeat(129)),
        json!(false),
        json!(null),
        json!("invalid key with spaces"),
    ] {
        assert!(
            validate_schema_value(
                &json!({"problem_tex":"fixture","creation_key":key}),
                &schema::input(ToolId::RethlasStart),
                "arguments",
            )
            .is_err()
        );
    }
    // Schema-only fixture, not an authenticated or server-issued capability.
    let capability = format!("{}.{}", "a".repeat(64), "b".repeat(43));
    let request = json!({"run_id":"run","capability":capability,"action":"assessment_complete","recover_only":true});
    validate_schema_value(&request, &schema::input(ToolId::RethlasStep), "arguments")?;
    for request in [
        json!({"run_id":"run","recover_only":true}),
        json!({"run_id":"run","capability":capability,"action":"assessment_complete","recover_only":"true"}),
    ] {
        assert!(
            validate_schema_value(&request, &schema::input(ToolId::RethlasStep), "arguments")
                .is_err()
        );
    }
    Ok(())
}

const RETIRED: [&str; 11] = [
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
];

#[test]
fn workspace_continuations_and_repository_selectors_are_model_visible() -> Result<(), ReCtmError> {
    for id in [
        ToolId::GitStatus,
        ToolId::GitDiff,
        ToolId::GitLog,
        ToolId::GitShow,
        ToolId::GitBlame,
    ] {
        let mut value = json!({"repo_path":"nested"});
        if id == ToolId::GitBlame {
            value["path"] = json!("a.txt");
        }
        validate_schema_value(&value, &schema::input(id), "arguments")?;
        assert_eq!(
            schema::input(id)["properties"]["repo_path"]["type"],
            "string"
        );
    }
    validate_schema_value(
        &json!({"path":"a.txt","start_line":1,"end_line":4,"max_lines":2,
        "line_byte_offset":6,"max_bytes":7,"expected_sha256":"a".repeat(64)}),
        &schema::input(ToolId::ReadFile),
        "arguments",
    )?;
    assert!(
        validate_schema_value(
            &json!({"path":"a.txt","line_byte_offset":-1}),
            &schema::input(ToolId::ReadFile),
            "arguments"
        )
        .is_err()
    );
    Ok(())
}

// Syntax-only fixture, not a signed credential or an authority-bearing object.
fn capability_shape() -> String {
    format!("{}.{}", "A".repeat(40), "B".repeat(43))
}

fn native_and_start_cases() -> Vec<(ToolId, Value)> {
    use ToolId as T;
    vec![
        (T::ServerInfo, json!({})),
        (T::CheckExecEnvironment, json!({})),
        (
            T::ReadFile,
            json!({"path":"a.txt","start_line":2,"max_lines":3}),
        ),
        (T::ListDir, json!({})),
        (T::ListFiles, json!({"patterns":["*.rs"]})),
        (T::SearchText, json!({"path":"a.txt","query":"数学"})),
        (T::ApplyPatch, json!({"patch":"fixture","dry_run":true})),
        (T::ExecCommand, json!({"argv":["printf","%s",""]})),
        (T::WriteStdin, json!({"command_id":"cmd-fixture"})),
        (
            T::KillCommand,
            json!({"command_id":"cmd-fixture","signal":"INT"}),
        ),
        (
            T::ReadOutput,
            json!({"output_ref":"command:fixture:stdout"}),
        ),
        (T::GitStatus, json!({})),
        (T::GitDiff, json!({"paths":["src/a.rs"]})),
        (T::GitLog, json!({})),
        (T::GitShow, json!({"rev":"HEAD"})),
        (T::GitBlame, json!({"path":"src/a.rs"})),
        (
            T::RequestPermissions,
            json!({"tool_name":"exec_command","permission":"inline_script","reason":"fixture","arguments":{"cmd":"sh -c true"}}),
        ),
        (T::ViewImage, json!({"path":"fixture.png"})),
        (
            T::RethlasStart,
            json!({"problem_tex":"fixture statement","workflow_mode":"compact","register_result":false}),
        ),
    ]
}

fn workflow_cases() -> Vec<(ToolId, Value)> {
    use ToolId as T;
    let cap = capability_shape();
    vec![
        (T::RethlasStep, json!({"run_id":"run-fixture"})),
        (
            T::RethlasStep,
            json!({"run_id":"run-fixture","capability":cap,"action":"fixture","payload":{},"writes":[]}),
        ),
        (
            T::RethlasInspect,
            json!({"operation":"status","run_id":"run-fixture"}),
        ),
        (
            T::RethlasInspect,
            json!({"operation":"read","capability":cap,"resource":"memory"}),
        ),
        (
            T::RethlasInspect,
            json!({"operation":"search","capability":cap,"resource":"memory","query":"","limit":100}),
        ),
        (T::RethlasInspect, json!({"operation":"projects"})),
        (
            T::RethlasInspect,
            json!({"operation":"project_status","project_id":"project-fixture"}),
        ),
        (
            T::RethlasInspect,
            json!({"operation":"claim","claim_id":"claim-fixture"}),
        ),
        (
            T::RethlasInspect,
            json!({"operation":"theorem_search","project_id":"project-fixture","query":"fixture"}),
        ),
        (
            T::RethlasInspect,
            json!({"operation":"dependency_graph","project_id":"project-fixture"}),
        ),
        (
            T::RethlasInspect,
            json!({"operation":"reference_audit","run_id":"run-fixture"}),
        ),
        (
            T::RethlasRetrieve,
            json!({"capability":cap,"query":"fixture"}),
        ),
        (
            T::RethlasRetrieve,
            json!({"operation":"theorem_search","capability":cap,"query":"fixture","search_intent":"counterexample"}),
        ),
        (
            T::RethlasRetrieve,
            json!({"operation":"paper_search","capability":cap,"author":"fixture"}),
        ),
        (
            T::RethlasRetrieve,
            json!({"operation":"paper_lookup","capability":cap,"query":"fixture"}),
        ),
        (
            T::RethlasRetrieve,
            json!({"operation":"theorem_context","capability":cap,"query":"fixture"}),
        ),
        (
            T::RethlasControl,
            json!({"action":"steer","run_id":"run-fixture","message":"fixture"}),
        ),
        (
            T::RethlasControl,
            json!({"action":"cancel","run_id":"run-fixture"}),
        ),
        (
            T::RethlasControl,
            json!({"action":"project_create","title":"fixture"}),
        ),
        (
            T::RethlasControl,
            json!({"action":"claim_create","project_id":"project-fixture","title":"fixture"}),
        ),
        (
            T::RethlasControl,
            json!({"action":"claim_revise","claim_id":"claim-fixture","statement_tex":"fixture"}),
        ),
        (
            T::RethlasArtifact,
            json!({"action":"get","run_id":"run-fixture","artifact":"final_tex"}),
        ),
        (
            T::RethlasArtifact,
            json!({"action":"get","project_id":"project-fixture","artifact":"project_manifest"}),
        ),
        (
            T::RethlasArtifact,
            json!({"action":"export","run_id":"run-fixture","artifact":"final_tex"}),
        ),
        (
            T::RethlasArtifact,
            json!({"action":"export","project_id":"project-fixture","artifact":"project_summary_tex"}),
        ),
    ]
}

fn validate(id: ToolId, arguments: &Value) -> Result<(), ReCtmError> {
    validate_schema_value(arguments, &schema::input(id), "arguments")
}

#[test]
fn registry_is_complete_unique_deterministic_and_mtm_owned() -> Result<(), ReCtmError> {
    let catalog = ToolCatalog::new();
    assert_eq!(ToolId::ALL.len(), 24);
    assert_eq!(catalog.list_public().len(), 24);
    assert_eq!(
        PUBLIC_TOOL_NAMES.into_iter().collect::<BTreeSet<_>>().len(),
        24
    );
    assert_eq!(catalog.fingerprint()?, ToolCatalog::new().fingerprint()?);
    assert_eq!(catalog.fingerprint()?.len(), 64);
    assert_eq!(
        catalog.snapshot()["tool_contract_version"],
        TOOL_CONTRACT_VERSION
    );
    for id in ToolId::ALL {
        assert_eq!(ToolId::parse(id.as_str()), Some(id));
        assert_eq!(
            catalog.definition(id.as_str()).map(|v| &v["name"]),
            Some(&json!(id.as_str()))
        );
    }
    Ok(())
}

#[test]
fn snapshots_cannot_inject_aliases_or_change_schema_or_description() -> Result<(), ReCtmError> {
    let original = ToolCatalog::new().snapshot();
    ToolCatalog::from_snapshot(&original)?;
    let mut changed = original.clone();
    changed["definitions"]["server_info"]["inputSchema"]["additionalProperties"] = json!(true);
    assert!(ToolCatalog::from_snapshot(&changed).is_err());
    let mut changed = original.clone();
    changed["definitions"]["rethlas_next"] = original["definitions"]["rethlas_step"].clone();
    assert!(ToolCatalog::from_snapshot(&changed).is_err());
    let mut changed = original;
    changed["definitions"]["server_info"]["description"] = json!("caller override");
    assert!(ToolCatalog::from_snapshot(&changed).is_err());
    assert!(ToolCatalog::from_snapshot(&json!({})).is_err());
    Ok(())
}

#[test]
fn every_public_tool_and_workflow_operation_has_a_valid_fixture() -> Result<(), ReCtmError> {
    let cases = native_and_start_cases().into_iter().chain(workflow_cases());
    let mut covered = BTreeSet::new();
    for (id, args) in cases {
        validate(id, &args)?;
        covered.insert(id);
    }
    assert_eq!(covered, ToolId::ALL.into_iter().collect());
    Ok(())
}

#[test]
fn unknown_arguments_and_wrong_top_level_types_are_always_rejected() {
    for (id, mut args) in native_and_start_cases().into_iter().chain(workflow_cases()) {
        args["unexpected"] = json!(true);
        assert!(validate(id, &args).is_err(), "{}", id.as_str());
    }
    for id in ToolId::ALL {
        for malformed in [Value::Null, json!(true), json!([]), json!("object")] {
            assert!(validate(id, &malformed).is_err(), "{}", id.as_str());
        }
    }
}

#[test]
fn direct_argv_and_shell_cmd_are_exclusive_and_keep_empty_arguments() -> Result<(), ReCtmError> {
    validate(ToolId::ExecCommand, &json!({"cmd":"pwd; pwd"}))?;
    validate(ToolId::ExecCommand, &json!({"argv":["printf","%s",""]}))?;
    for args in [
        json!({}),
        json!({"cmd":""}),
        json!({"argv":[]}),
        json!({"argv":[""]}),
        json!({"argv":[17]}),
        json!({"cmd":"true","argv":["true"]}),
        json!({"cmd":"true","timeout_ms":600001}),
        json!({"cmd":"true","env":{"X":true}}),
    ] {
        assert!(validate(ToolId::ExecCommand, &args).is_err());
    }
    Ok(())
}

#[test]
fn workflow_fields_do_not_bleed_across_operations() {
    use ToolId as T;
    let cap = capability_shape();
    let cases = [
        (T::RethlasStep, json!({"run_id":"run","capability":cap})),
        (T::RethlasStep, json!({"run_id":"run","writes":[]})),
        (
            T::RethlasStep,
            json!({"run_id":"run","action":"fixture","capability":cap,"writes":[{"resource":"m"}]}),
        ),
        (
            T::RethlasInspect,
            json!({"operation":"status","run_id":"run","capability":cap}),
        ),
        (
            T::RethlasInspect,
            json!({"operation":"read","run_id":"run","resource":"m"}),
        ),
        (
            T::RethlasInspect,
            json!({"operation":"projects","limit":101}),
        ),
        (
            T::RethlasRetrieve,
            json!({"operation":"paper_search","capability":cap}),
        ),
        (
            T::RethlasRetrieve,
            json!({"operation":"paper_search","capability":cap,"query":""}),
        ),
        (
            T::RethlasRetrieve,
            json!({"operation":"paper_lookup","capability":cap,"query":"fixture","author":"x"}),
        ),
        (
            T::RethlasRetrieve,
            json!({"operation":"theorem_search","capability":cap,"query":"x","num_results":true}),
        ),
        (
            T::RethlasRetrieve,
            json!({"capability":cap,"query":"x","search_intent":"unknown"}),
        ),
        (T::RethlasControl, json!({"action":"steer","run_id":"run"})),
        (
            T::RethlasControl,
            json!({"action":"cancel","run_id":"run","statement_tex":"x"}),
        ),
        (
            T::RethlasControl,
            json!({"action":"claim_revise","claim_id":"claim","statement_tex":"x","verified":true}),
        ),
        (
            T::RethlasArtifact,
            json!({"action":"export","run_id":"run","artifact":"draft_tex"}),
        ),
        (
            T::RethlasArtifact,
            json!({"action":"get","run_id":"run","project_id":"project","artifact":"final_tex"}),
        ),
    ];
    for (id, args) in cases {
        assert!(validate(id, &args).is_err(), "{}", id.as_str());
    }
}

#[test]
fn all_capability_tools_explain_task_domain_and_uncertain_transport() {
    let catalog = ToolCatalog::new();
    for name in ["rethlas_step", "rethlas_inspect", "rethlas_retrieve"] {
        let description = catalog
            .definition(name)
            .and_then(|d| d["description"].as_str())
            .unwrap_or("");
        for term in [
            "task domain",
            "REVOKED",
            "transport failure",
            "retained writes",
            "does not grant workflow authority",
        ] {
            assert!(description.contains(term), "{name}: missing {term}");
        }
    }
}

#[test]
fn retired_aliases_have_no_registered_identity_definition_or_schema() {
    let catalog = ToolCatalog::new();
    for name in RETIRED {
        assert!(ToolId::parse(name).is_none());
        assert!(!catalog.contains(name));
        assert!(catalog.definition(name).is_none());
        assert!(catalog.input_schema(name).is_none());
    }
}
