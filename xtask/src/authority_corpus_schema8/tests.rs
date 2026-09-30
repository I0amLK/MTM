use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};
fn fixture(task: &str) -> Value {
    let snap = |workspace: &str| json!({"database_sha256":"a".repeat(64),"workspace_sha256":workspace.repeat(64),"private_files_sha256":"b".repeat(64)});
    let mut prior = snap("c");
    let mut phases = Vec::new();
    for (i, phase) in ["initial", "reconnect", "restart"].iter().enumerate() {
        let before = prior.clone();
        let after = if task == "U28" {
            snap(["d", "e", "f"][i])
        } else {
            before.clone()
        };
        let boundary = if task == "U28" {
            json!({"before":after,"after":after,"hard_isolation_attested":true,"native_positive":true,"workspace_api_positive":true,"native_private_read_denied":true,"native_private_write_denied":true,"workspace_escape_denied":true,"invalid_workflow_read_denied":true,"foreign_owner_step_denied":true})
        } else {
            Value::Null
        };
        phases.push(json!({"phase":phase,"identity":{"pid":if i==2{222}else{111},"root_sha256":"1".repeat(64),"owner_sha256":"2".repeat(64),"session_sha256":format!("{i:064x}")},"permission":{"calls":8,"before":before,"after":before},"boundary":boundary,"compatibility_marker_fixed":true,"expiry_null":true,"elicitation_seen":false,"business_effects_from_requests":false,"grant_or_consent_ledger_present":false,"before":before,"after":after,"boundaries_checked":if task=="U28"{"native_private_workspace_workflow"}else{"disabled_exec"},"positive_control_passed":task=="U28","negative_effects":false,"children_reaped":true}));
        prior = after;
    }
    json!({"schema":"mtm017-authority-observation-v1","milestone":"MTM-017","task_id":task,"repeat":1,"trial_id":"synthetic-negative-fixture","candidate_sha256":CANDIDATE,"harness_source_sha256":"9".repeat(64),"version":"0.6.0-preview.2","state_schema":8,"workflow_protocol":3,"tool_contract":"mtm-tools-v10","started_unix_ms":1790758000000_u64,"finished_unix_ms":1790758005000_u64,"phases":phases,"passed":true,"clean_shutdown":true,"synthetic_state_only":true,"human_consent_tested":false,"accepted_delta":0,"production_selector_changed":false,"production_state_modified":false,"release_qualified":false,"deployment_authorized":false})
}
fn checked(v: Value) -> Result<()> {
    let o: Observation = serde_json::from_value(v)?;
    validate(&o, &"9".repeat(64))
}
#[test]
fn typed_observations_require_all_identity_scope_and_zero_authority_fields() {
    for task in ["U27", "U28"] {
        let good = fixture(task);
        assert!(checked(good.clone()).is_ok());
        for (key, value) in [
            ("candidate_sha256", json!("0".repeat(64))),
            ("harness_source_sha256", json!("0".repeat(64))),
            ("schema", json!("legacy")),
            ("milestone", json!("MTM-016")),
            ("task_id", json!("U26")),
            ("repeat", json!(4)),
            ("state_schema", json!(7)),
            ("workflow_protocol", json!(2)),
            ("tool_contract", json!("mtm-tools-v9")),
            ("version", json!("0.6.0-preview.1")),
            ("accepted_delta", json!(1)),
            ("human_consent_tested", json!(true)),
            ("production_selector_changed", json!(true)),
            ("production_state_modified", json!(true)),
            ("release_qualified", json!(true)),
            ("deployment_authorized", json!(true)),
            ("passed", json!(false)),
            ("synthetic_state_only", json!(false)),
            ("clean_shutdown", json!(false)),
            ("extra", json!(true)),
        ] {
            let mut v = good.clone();
            v[key] = value;
            assert!(checked(v).is_err(), "{key}");
        }
    }
}
#[test]
fn semantic_mutations_reject_effects_missing_phases_false_freshness_and_legacy_grants() -> Result<()>
{
    for task in ["U27", "U28"] {
        let good = fixture(task);
        for pointer in [
            "/phases/0/compatibility_marker_fixed",
            "/phases/0/expiry_null",
            "/phases/0/children_reaped",
        ] {
            let mut v = good.clone();
            *v.pointer_mut(pointer).ok_or("fixture")? = json!(false);
            assert!(checked(v).is_err());
        }
        for pointer in [
            "/phases/0/elicitation_seen",
            "/phases/0/business_effects_from_requests",
            "/phases/0/grant_or_consent_ledger_present",
            "/phases/0/negative_effects",
        ] {
            let mut v = good.clone();
            *v.pointer_mut(pointer).ok_or("fixture")? = json!(true);
            assert!(checked(v).is_err());
        }
        for (pointer, value) in [
            ("/phases/0/permission/calls", json!(0)),
            (
                "/phases/0/permission/after/database_sha256",
                json!("0".repeat(64)),
            ),
            ("/phases/2/identity/pid", json!(111)),
            ("/phases/1/identity/session_sha256", json!("0".repeat(64))),
            ("/phases/2/identity/root_sha256", json!("0".repeat(64))),
            ("/phases/1/phase", json!("initial")),
        ] {
            let mut v = good.clone();
            *v.pointer_mut(pointer).ok_or("fixture")? = value;
            assert!(checked(v).is_err());
        }
        let mut v = good.clone();
        v["phases"].as_array_mut().ok_or("fixture")?.pop();
        assert!(checked(v).is_err());
    }
    let good = fixture("U28");
    for key in [
        "hard_isolation_attested",
        "native_positive",
        "workspace_api_positive",
        "native_private_read_denied",
        "native_private_write_denied",
        "workspace_escape_denied",
        "invalid_workflow_read_denied",
        "foreign_owner_step_denied",
    ] {
        let mut v = good.clone();
        v["phases"][0]["boundary"][key] = json!(false);
        assert!(checked(v).is_err());
    }
    let mut v = good;
    v["phases"][0]["boundary"]["after"]["private_files_sha256"] = json!("0".repeat(64));
    assert!(checked(v).is_err());
    Ok(())
}
#[test]
fn paths_json_and_descriptors_fail_closed() -> Result<()> {
    for name in [
        "/etc/passwd",
        "records/evidence/MTM-017/../x.json",
        "records/evidence/MTM-017/nested/x.json",
    ] {
        assert!(!path(name));
    }
    for bytes in [b"{\"a\":1,\"a\":2}".as_slice(), b"{} trailing".as_slice()] {
        assert!(evidence_json::decode(bytes).is_err());
    }
    let temp = tempfile::tempdir()?;
    let p = temp.path().join("x.json");
    std::fs::write(&p, b"{}").map_err(|_| "fixture")?;
    let a = files::read(temp.path(), "x.json", 4096, false)?;
    std::fs::write(&p, b"{ }")?;
    assert!(
        a.recheck(&files::read(temp.path(), "x.json", 4096, false)?)
            .is_err()
    );
    symlink("x.json", temp.path().join("link.json"))?;
    assert!(files::read(temp.path(), "link.json", 4096, false).is_err());
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666))?;
    assert!(files::read(temp.path(), "x.json", 4096, false).is_err());
    Ok(())
}
fn group_fixture() -> Vec<Value> {
    (0..6).map(|i| {let mut v=fixture(if i<3{"U27"}else{"U28"});v["repeat"]=json!(i%3+1);v["trial_id"]=json!(format!("synthetic-distinct-trial-{i}"));v["started_unix_ms"]=json!(1790758000000_u64+i*10000);v["finished_unix_ms"]=json!(1790758005000_u64+i*10000);
 for j in 0..3 {v["phases"][j]["identity"]=json!({"pid":100+i*2+u64::from(j==2),"root_sha256":format!("{:064x}",100+i),"owner_sha256":format!("{:064x}",200+i),"session_sha256":format!("{:064x}",300+i*3+j as u64)});}
 v}).collect()
}
fn group_check(values: Vec<Value>, refs: &[Reference]) -> Result<()> {
    let items = values
        .into_iter()
        .zip(refs)
        .map(|(v, r)| Ok((r, serde_json::from_value(v)?)))
        .collect::<Result<Vec<_>>>()?;
    collection(&items, &"9".repeat(64))
}
#[test]
fn collection_rejects_missing_duplicate_cells_identities_raws_and_time() -> Result<()> {
    let good = group_fixture();
    let refs = (0..6)
        .map(|i| Reference {
            path: format!("records/evidence/MTM-017/synthetic-{i}.json"),
            sha256: format!("{:064x}", 500 + i),
        })
        .collect::<Vec<_>>();
    assert!(group_check(good.clone(), &refs).is_ok());
    let mut v = good.clone();
    v.pop();
    assert!(group_check(v, &refs).is_err());
    for pointer in [
        "/repeat",
        "/trial_id",
        "/phases/0/identity/root_sha256",
        "/phases/0/identity/owner_sha256",
        "/phases/0/identity/pid",
        "/phases/0/identity/session_sha256",
        "/started_unix_ms",
    ] {
        let mut v = good.clone();
        let value = v[0].pointer(pointer).ok_or("fixture")?.clone();
        *v[1].pointer_mut(pointer).ok_or("fixture")? = value;
        assert!(group_check(v, &refs).is_err(), "{pointer}");
    }
    // Each mutated observation remains internally coherent: these exercise
    // collection uniqueness rather than an earlier single-phase mismatch.
    for field in ["root_sha256", "owner_sha256"] {
        let mut v = good.clone();
        let copied = v[0]["phases"][0]["identity"][field].clone();
        for phase in v[1]["phases"].as_array_mut().ok_or("fixture")? {
            phase["identity"][field] = copied.clone();
        }
        assert!(checked(v[1].clone()).is_ok());
        assert!(group_check(v, &refs).is_err());
    }
    let mut v = good.clone();
    let copied = v[0]["phases"][0]["identity"]["pid"].clone();
    for phase in v[1]["phases"]
        .as_array_mut()
        .ok_or("fixture")?
        .iter_mut()
        .take(2)
    {
        phase["identity"]["pid"] = copied.clone();
    }
    assert!(checked(v[1].clone()).is_ok());
    assert!(group_check(v, &refs).is_err());
    let mut v = fixture("U27");
    for pointer in [
        "/phases/1/before/workspace_sha256",
        "/phases/1/after/workspace_sha256",
        "/phases/1/permission/before/workspace_sha256",
        "/phases/1/permission/after/workspace_sha256",
    ] {
        *v.pointer_mut(pointer).ok_or("fixture")? = json!("8".repeat(64));
    }
    assert!(checked(v).is_err());
    for field in ["path", "sha256"] {
        let mut r = refs.clone();
        if field == "path" {
            r[1].path = r[0].path.clone();
        } else {
            r[1].sha256 = r[0].sha256.clone();
        }
        assert!(group_check(good.clone(), &r).is_err());
    }
    for value in [1790812800000_u64, 1790758000000, 1790758400000] {
        let mut v = fixture("U27");
        v["finished_unix_ms"] = json!(value);
        assert!(checked(v).is_err());
    }
    for pointer in [
        "/phases/1/before/database_sha256",
        "/phases/0/boundary/before/database_sha256",
        "/phases/0/boundary/before/private_files_sha256",
    ] {
        let mut v = fixture("U28");
        *v.pointer_mut(pointer).ok_or("fixture")? = json!("0".repeat(64));
        assert!(checked(v).is_err());
    }
    let mut v = fixture("U27");
    v.as_object_mut()
        .ok_or("fixture")?
        .remove("candidate_sha256");
    assert!(checked(v).is_err());
    let temp = tempfile::tempdir()?;
    std::fs::write(temp.path().join("a"), b"data")?;
    std::fs::hard_link(temp.path().join("a"), temp.path().join("b"))?;
    assert!(files::read(temp.path(), "a", 16, false).is_err());
    std::fs::write(temp.path().join("large"), b"oversized")?;
    assert!(files::read(temp.path(), "large", 2, false).is_err());
    Ok(())
}
