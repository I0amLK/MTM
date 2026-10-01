//! Role denials are corrections only with an exact, durable write prefix.
//! Every server and database used here is a disposable test fixture.
use super::*;

fn assembly_resources(server: &Server, task: &Value) -> Result<(Vec<u8>, String)> {
    // Independent observation of disposable fixture state, never a model read.
    let path = server.private_state_path();
    let proof = std::fs::read(
        path.parent()
            .ok_or("fixture state parent")?
            .join("runs")
            .join(text(task, "run_id")?)
            .join("draft/proof.tex"),
    )
    .map_err(|_| "fixture proof observation")?;
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|_| "fixture manifest observation")?;
    let manifest = db.query_row("SELECT json_object('manifest',manifest_json,'sha256',sha256,'created_at',created_at,'updated_at',updated_at) FROM proof_manifests WHERE run_id=?",
        [text(task, "run_id")?], |row| row.get(0)).map_err(|_| "fixture manifest row")?;
    Ok((proof, manifest))
}

#[test]
fn invalid_proof_facts_remain_a_correctable_validation_with_explicit_guidance() -> Result {
    let candidate = candidate::select()?;
    let mut server = Server::start(&candidate.path)?;
    let owner = server.login()?;
    let assess = crate::start(&server, &owner, "compact")?;
    let task = server.call(&owner, "rethlas_step", submission(&assess)?)?;
    let contract = task["task"]["write_contract"]
        .as_array()
        .ok_or("write contracts")?
        .iter()
        .find(|c| c["resource"] == "proof_manifest")
        .ok_or("manifest contract")?;
    let facts = &contract["content_schema"]["properties"]["facts"];
    let description = text(facts, "description")?;
    require(
        description.contains("Keys must be unique")
            && description.contains("whitespace normalization")
            && description.contains("verbatim"),
        "fact semantics missing from task guidance",
    )?;
    require(
        facts["items"]["properties"]["key"]["maxLength"] == 128
            && facts["items"]["properties"]["predecessors"]["maxItems"] == 64,
        "fact bounds missing from task schema",
    )?;
    require(
        text(&facts["items"]["properties"]["proof_tex"], "description")?.contains("UTF-8 bytes"),
        "fact byte limit mislabeled as character limit",
    )?;
    let mut request = crate::candidate_lifecycle::fixture_submission(&task, "compact", false)?;
    let writes = request["writes"].as_array_mut().ok_or("assembler writes")?;
    let index = writes
        .iter()
        .position(|w| w["resource"] == "proof_manifest")
        .ok_or("manifest write")?;
    let valid_manifest = writes[index].clone();
    writes[index]["content"]["facts"] = json!([{"key":"target","statement_tex":"A different target","proof_tex":"fixture proof","predecessors":[],"glossary_introduces":{}}]);
    let rejected = server.call(&owner, "rethlas_step", request.clone())?;
    require(
        rejected["submission"]["error"]["code"] == "INVALID_PROOF_FACTS"
            && rejected["submission"]["error"]["category"] == "validation"
            && rejected["submission"]["error"]["message"]
                == "the final fact must state the proof target"
            && rejected["writes_applied"] == index as u64,
        "invalid fact target was accepted or lost exact-prefix correction",
    )?;
    require(
        status(&server, &owner, &task)?["pending_submission"].is_null(),
        "fact validation left pending",
    )?;
    assert_receipt(&server.call(&owner, "rethlas_step", request)?, index as u64)?;
    let mut missing = submission(&rejected)?;
    missing["writes"] = json!([]);
    let before_missing = status(&server, &owner, &task)?;
    let missing_result = server.call(&owner, "rethlas_step", missing.clone())?;
    require(
        missing_result["submission"]["ok"] == false
            && missing_result["submission"]["error"]["code"] == "PROOF_MANIFEST_NOT_FOUND"
            && missing_result["submission"]["error"]["category"] == "validation"
            && missing_result["writes_applied"] == 0,
        "missing prerequisite was not a zero-write correction",
    )?;
    let after_missing = status(&server, &owner, &task)?;
    require(
        after_missing["state"] == before_missing["state"]
            && after_missing["transition_seq"] == before_missing["transition_seq"]
            && after_missing["pending_submission"].is_null(),
        "missing prerequisite changed the run or left pending",
    )?;
    server.restart()?;
    assert_receipt(&server.call(&owner, "rethlas_step", missing)?, 0)?;
    let mut correction = submission(&missing_result)?;
    correction["writes"] = json!([valid_manifest]);
    let advanced = server.call(&owner, "rethlas_step", correction)?;
    require(
        advanced["state"] == "verify"
            && advanced["submission"]["ok"] == true
            && advanced["writes_applied"] == 1,
        "fact correction did not preserve previous proof write",
    )?;
    crate::cancel(&server, &owner, &task)?;
    server.stop()?;
    candidate.unchanged()
}

#[test]
fn role_denial_closes_only_the_exact_durable_prefix_across_restart() -> Result {
    let candidate = candidate::select()?;
    let mut server = Server::start(&candidate.path)?;
    let owner = server.login()?;
    let other = server.login()?;
    for prefix in [false, true] {
        let task = crate::start(&server, &owner, "compact")?;
        let before = status(&server, &owner, &task)?;
        let original = submission(&task)?;
        let resource = text(&original["writes"][0], "resource")?;
        let old_memory = memory(&server, &owner, &task, resource)?;
        let mut request = original.clone();
        if !prefix {
            request["writes"] = json!([]);
        }
        let writes = request["writes"].as_array_mut().ok_or("fixture writes")?;
        let count = writes.len() as u64;
        writes.push(
            json!({"resource":"memory:verifier:events","content":{"summary":"denied fixture"}}),
        );
        let result = server.call(&owner, "rethlas_step", request.clone())?;
        require(
            result["ok"] == true
                && result["submission"]["ok"] == false
                && result["submission"]["complete"] == false
                && result["submission"]["error"]["code"] == "ROLE_ACCESS_DENIED"
                && result["submission"]["error"]["category"] == "permission"
                && result["submission"]["failed_write"]["index"] == count
                && result["submission"]["failed_write"]["resource"] == "memory:verifier:events"
                && result["submission"]["retained_write_prefix_len"] == count
                && result["writes_applied"] == count
                && result["submission_receipt"]["status"] == "completed",
            "role denial did not close as an exact-prefix correction",
        )?;
        let after = status(&server, &owner, &task)?;
        require(
            after["state"] == before["state"]
                && after["transition_seq"] == before["transition_seq"]
                && after["pending_submission"].is_null(),
            "role denial changed workflow or left a poisoned pending receipt",
        )?;
        let retained = memory(&server, &owner, &result, resource)?;
        require(
            prefix || retained == old_memory,
            "zero-write denial changed memory",
        )?;
        for restart in [false, true] {
            if restart {
                server.restart()?;
            }
            let replay = server.call(&owner, "rethlas_step", request.clone())?;
            assert_receipt(&replay, count)?;
            require(
                replay["submission"]["ok"] == false
                    && replay["submission"]["error"]["code"] == "ROLE_ACCESS_DENIED"
                    && replay["submission"]["error"]["category"] == "permission"
                    && replay["submission"]["retained_write_prefix_len"] == count,
                "denial replay changed its unsuccessful permission classification",
            )?;
            require(
                memory(&server, &owner, &result, resource)? == retained,
                "denial replay duplicated memory",
            )?;
        }
        let foreign = server.call(&other, "rethlas_step", request.clone())?;
        require(
            foreign["ok"] == false && foreign.get("submission_receipt").is_none(),
            "foreign owner read denial receipt",
        )?;
        let mut changed = request;
        changed["writes"] = json!([]);
        require(
            error_code(&server.call(&owner, "rethlas_step", changed)?) == "IDEMPOTENCY_CONFLICT",
            "changed denial replay bypassed identity",
        )?;
        let denied_read = server.call(&owner, "rethlas_inspect", json!({"operation":"read","capability":result["capability"],"resource":"memory:verifier:events"}))?;
        require(
            error_code(&denied_read) == "ROLE_ACCESS_DENIED",
            "correction widened the role firewall",
        )?;
        let mut correction = submission(&result)?;
        if prefix {
            correction["writes"] = json!([]);
        }
        let advanced = server.call(&owner, "rethlas_step", correction)?;
        require(
            advanced["state"] == "assemble" && advanced["submission"]["ok"] == true,
            "denial correction could not advance",
        )?;
        if prefix {
            require(
                memory(&server, &owner, &advanced, resource)? == retained,
                "corrected submission duplicated retained memory",
            )?;
        }
        crate::cancel(&server, &owner, &task)?;
    }
    server.stop()?;
    candidate.unchanged()
}

#[test]
fn role_denial_preserves_file_and_database_writes_without_reapplying_them() -> Result {
    let candidate = candidate::select()?;
    let mut server = Server::start(&candidate.path)?;
    let owner = server.login()?;
    let assess = crate::start(&server, &owner, "compact")?;
    let task = server.call(&owner, "rethlas_step", submission(&assess)?)?;
    require(
        task["state"] == "assemble",
        "fixture did not enter assemble",
    )?;
    let mut request = crate::candidate_lifecycle::fixture_submission(&task, "compact", false)?;
    let writes = request["writes"].as_array_mut().ok_or("assembler writes")?;
    require(
        writes.iter().any(|w| w["resource"] == "proof")
            && writes.iter().any(|w| w["resource"] == "proof_manifest"),
        "fixture lacks file/database prefix",
    )?;
    let count = writes.len() as u64;
    writes.push(json!({"resource":"memory:generation:events","content":{"summary":"denied assembler write"}}));
    let result = server.call(&owner, "rethlas_step", request.clone())?;
    require(
        result["submission"]["error"]["code"] == "ROLE_ACCESS_DENIED"
            && result["writes_applied"] == count
            && result["submission"]["retained_write_prefix_len"] == count,
        "assembler denial lost its mixed prefix",
    )?;
    let resources = assembly_resources(&server, &task)?;
    let denied_read = server.call(
        &owner,
        "rethlas_inspect",
        json!({"operation":"read","capability":result["capability"],"resource":"proof"}),
    )?;
    require(
        error_code(&denied_read) == "ROLE_ACCESS_DENIED",
        "assembler acquired proof-read authority",
    )?;
    require(
        status(&server, &owner, &task)?["pending_submission"].is_null(),
        "mixed-prefix denial left pending",
    )?;
    server.restart()?;
    assert_receipt(&server.call(&owner, "rethlas_step", request)?, count)?;
    require(
        assembly_resources(&server, &task)? == resources,
        "mixed-prefix replay changed retained bytes",
    )?;
    let mut correction = submission(&result)?;
    correction["writes"] = json!([]);
    let advanced = server.call(&owner, "rethlas_step", correction)?;
    require(
        advanced["state"] == "verify"
            && advanced["submission"]["ok"] == true
            && advanced["writes_applied"] == 0,
        "mixed-prefix correction did not reuse retained writes",
    )?;
    require(
        assembly_resources(&server, &task)? == resources,
        "correction changed retained file/database resources",
    )?;
    let denied_read = server.call(&owner, "rethlas_inspect", json!({"operation":"read","capability":advanced["capability"],"resource":"memory:generation:events"}))?;
    require(
        error_code(&denied_read) == "ROLE_ACCESS_DENIED",
        "verifier acquired generation-memory access",
    )?;
    crate::cancel(&server, &owner, &task)?;
    server.stop()?;
    candidate.unchanged()
}
