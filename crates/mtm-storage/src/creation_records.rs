//! One transactional initialization unit. No filesystem I/O or workflow transition.
use super::*;
use serde::Serialize;

#[derive(Serialize)]
pub struct CreationReference {
    pub name: String,
    pub content: String,
    pub source: String,
}

/// Private initial data, never a public receipt or an authority permit.
#[derive(Serialize)]
pub struct CreationInitialization<'a> {
    pub problem_id: &'a str,
    pub metadata: &'a Value,
    pub project_id: Option<&'a str>,
    pub target_claim_id: Option<&'a str>,
    pub workflow_mode: &'a str,
    pub register_result: bool,
    pub references: &'a [CreationReference],
}

impl StateStore {
    pub fn prepare_creation_records(
        &self,
        reservation: &CreationReservation,
        material: &CreationInitialization<'_>,
    ) -> Result<Value, ReCtmError> {
        let encoded = serde_json::to_value(material).map_err(json_error)?;
        let encoded = canonical_json(&encoded)?;
        if encoded.len() > 16 * 1024 * 1024
            || material.references.len() > 128
            || !material.metadata.is_object()
            || !validate_registry_id(material.problem_id)
            || !matches!(material.workflow_mode, "auto" | "compact" | "full")
            || (material.target_claim_id.is_some() && material.project_id.is_none())
        {
            return Err(invalid());
        }
        let material_hash = sha256_text(&encoded);
        let expected = &reservation.receipt.row;
        self.immediate(|tx| {
            let current = find(tx, &expected.owner_id, &expected.key_sha256)?.ok_or_else(invalid)?;
            if current.row.status != "pending" || current.row.run_id != expected.run_id
                || current.row.execution_id != expected.execution_id
                || current.row.request_sha256 != expected.request_sha256
                || current.row.workspace_sha256 != expected.workspace_sha256 { return Err(invalid()); }
            let checkpoint = query_one_on(tx, "SELECT * FROM creation_initializations WHERE run_id=?", [&expected.run_id], &[])?.ok_or_else(invalid)?;
            if let Some(saved) = checkpoint["database_sha256"].as_str() {
                if checkpoint["material_sha256"] != material_hash || projection(tx, &expected.run_id)?.0 != saved {
                    return Err(conflict("CREATION_DATABASE_CONFLICT", "Initialization database facts changed; no records were replaced."));
                }
                return Ok(projection(tx, &expected.run_id)?.1);
            }
            // An unenrolled/foreign row is never silently adopted.
            let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM runs WHERE run_id=?)", [&expected.run_id], |r| r.get(0)).map_err(sql_error)?;
            if exists || !checkpoint["material_sha256"].is_null() { return Err(invalid()); }
            let project = prepare_project(tx, material, &current.row)?;
            let snapshot = project.as_ref().map(|p| p.0.as_str());
            let mut metadata = material.metadata.clone();
            metadata["project_snapshot_id"] = snapshot.map(Value::from).unwrap_or(Value::Null);
            tx.execute("INSERT INTO runs(run_id,problem_id,owner_id,state,status,metadata_json,created_at,updated_at) VALUES(?,?,?,'created','active',?,?,?)",
                params![expected.run_id,material.problem_id,expected.owner_id,canonical_json(&metadata)?,expected.created_at,expected.created_at]).map_err(sql_error)?;
            if let Some((snapshot, revision)) = project {
                tx.execute("INSERT INTO project_runs(run_id,project_id,project_snapshot_id,target_claim_id,base_revision_id,requested_workflow_mode,effective_workflow_mode,register_result,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    params![expected.run_id,material.project_id,snapshot,material.target_claim_id,revision,material.workflow_mode,
                        if material.workflow_mode=="full" {"full"} else {"pending"},i64::from(material.register_result),expected.created_at,expected.created_at]).map_err(sql_error)?;
            }
            insert_references(tx, material, &current.row)?;
            let (hash, run) = projection(tx, &expected.run_id)?;
            let changed = tx.execute("UPDATE creation_initializations SET material_sha256=?,database_sha256=? WHERE run_id=? AND database_sha256 IS NULL",
                params![material_hash,hash,expected.run_id]).map_err(sql_error)?;
            if changed != 1 { return Err(invalid()); }
            Ok(run)
        })
    }
}

fn prepare_project(
    tx: &Transaction<'_>,
    material: &CreationInitialization<'_>,
    row: &RowData,
) -> Result<Option<(String, Option<String>)>, ReCtmError> {
    let Some(project) = material.project_id else {
        return Ok(None);
    };
    let owner = query_one_on(
        tx,
        "SELECT owner_id FROM projects WHERE project_id=?",
        [project],
        &[],
    )?
    .ok_or_else(invalid)?;
    if owner["owner_id"] != row.owner_id {
        return Err(invalid());
    }
    let mut base = None;
    if let Some(claim) = material.target_claim_id {
        let found = query_one_on(
            tx,
            "SELECT project_id FROM claims WHERE claim_id=?",
            [claim],
            &[],
        )?
        .ok_or_else(invalid)?;
        if found["project_id"] != project {
            return Err(invalid());
        }
        base = tx.query_row("SELECT revision_id FROM claim_revisions WHERE claim_id=? AND lifecycle_status='ACTIVE' ORDER BY revision_number DESC LIMIT 1", [claim], |r| r.get::<_, String>(0)).optional().map_err(sql_error)?;
    }
    let mut statement = tx.prepare("SELECT cr.revision_id,cr.claim_id,cr.revision_number,cr.statement_tex,cr.evidence_status,cr.lifecycle_status,cr.conditions_json,cr.proof_sha256 FROM claim_revisions cr JOIN claims c ON c.claim_id=cr.claim_id WHERE c.project_id=? AND (cr.lifecycle_status='ACTIVE' OR cr.evidence_status IN ('VERIFIED','CONDITIONAL')) ORDER BY cr.claim_id,cr.revision_number LIMIT 4097").map_err(sql_error)?;
    let mut rows = statement.query([project]).map_err(sql_error)?;
    let mut revisions = Vec::new();
    while let Some(r) = rows.next().map_err(sql_error)? {
        if revisions.len() == 4096 {
            return Err(invalid());
        }
        let conditions: String = r.get(6).map_err(sql_error)?;
        revisions.push(serde_json::json!({"revision_id":r.get::<_,String>(0).map_err(sql_error)?,
            "claim_id":r.get::<_,String>(1).map_err(sql_error)?,"revision_number":r.get::<_,i64>(2).map_err(sql_error)?,
            "statement_tex":r.get::<_,String>(3).map_err(sql_error)?,"evidence_status":r.get::<_,String>(4).map_err(sql_error)?,
            "lifecycle_status":r.get::<_,String>(5).map_err(sql_error)?,"conditions":serde_json::from_str::<Value>(&conditions).map_err(json_error)?,
            "proof_sha256":r.get::<_,Option<String>>(7).map_err(sql_error)?}));
    }
    let text = canonical_json(&Value::Array(revisions))?;
    if text.len() > 8 * 1024 * 1024 {
        return Err(invalid());
    }
    let snapshot = format!("ps-{}", row.execution_id);
    tx.execute("INSERT INTO project_snapshots(snapshot_id,project_id,owner_id,revisions_json,snapshot_sha256,created_at) VALUES(?,?,?,?,?,?)",
        params![snapshot,project,row.owner_id,text,sha256_text(&text),row.created_at]).map_err(sql_error)?;
    Ok(Some((snapshot, base)))
}

fn insert_references(
    tx: &Transaction<'_>,
    material: &CreationInitialization<'_>,
    row: &RowData,
) -> Result<(), ReCtmError> {
    let mut names = BTreeSet::new();
    for (index, reference) in material.references.iter().enumerate() {
        if !names.insert(&reference.name) {
            return Err(invalid());
        }
        let hash = sha256_text(&reference.content);
        let id = format!("ref-{}-{index}", row.execution_id);
        let source_id = format!("source-{}-{index}", row.execution_id);
        let metadata = canonical_json(
            &serde_json::json!({"vault_name":reference.name,"size":reference.content.len()}),
        )?;
        tx.execute("INSERT INTO references_registry(reference_id,run_id,project_id,identity_key,provider,title,source_uri,source_state,source_sha256,content_sha256,metadata_json,created_at,updated_at) VALUES(?,?,?,?,'inline',?,?,'candidate',?,?,?,?,?)",
            params![id,row.run_id,material.project_id,format!("inline:{}:{hash}",reference.name),reference.name,reference.source,hash,hash,metadata,row.created_at,row.created_at]).map_err(sql_error)?;
        let source_metadata = canonical_json(
            &serde_json::json!({"vault_name":reference.name,"content":reference.content}),
        )?;
        tx.execute("INSERT INTO source_snapshots(source_snapshot_id,reference_id,provider,source_uri,content_sha256,content_type,metadata_json,created_at) VALUES(?,?,'inline',?,?,'text/plain',?,?)",
            params![source_id,id,reference.source,hash,source_metadata,row.created_at]).map_err(sql_error)?;
    }
    Ok(())
}

// Fixed projection of only the enrolled run's initialization rows; no global DB hash.
fn projection(connection: &Connection, run: &str) -> Result<(String, Value), ReCtmError> {
    let run_row = query_one_on(
        connection,
        "SELECT * FROM runs WHERE run_id=?",
        [run],
        &["metadata_json"],
    )?
    .ok_or_else(invalid)?;
    if run_row["state"] != "created"
        || run_row["transition_seq"] != 0
        || run_row["status"] != "active"
    {
        return Err(invalid());
    }
    let mut projection = vec![run_row.clone()];
    for sql in [
        "SELECT * FROM project_runs WHERE run_id=?",
        "SELECT * FROM project_snapshots WHERE snapshot_id IN (SELECT project_snapshot_id FROM project_runs WHERE run_id=?)",
        "SELECT * FROM references_registry WHERE run_id=? ORDER BY reference_id",
        "SELECT * FROM source_snapshots WHERE reference_id IN (SELECT reference_id FROM references_registry WHERE run_id=?) ORDER BY source_snapshot_id",
    ] {
        let mut statement = connection.prepare(sql).map_err(sql_error)?;
        let names = statement
            .column_names()
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>();
        let mut rows = statement.query([run]).map_err(sql_error)?;
        let mut items = Vec::new();
        while let Some(row) = rows.next().map_err(sql_error)? {
            if items.len() > 128 {
                return Err(invalid());
            }
            let mut item = Map::new();
            for (index, name) in names.iter().enumerate() {
                let value = match row.get_ref(index).map_err(sql_error)? {
                    ValueRef::Null => Value::Null,
                    ValueRef::Integer(n) => Value::from(n),
                    ValueRef::Text(bytes) => {
                        Value::from(std::str::from_utf8(bytes).map_err(|_| invalid())?)
                    }
                    _ => return Err(invalid()),
                };
                item.insert(name.clone(), value);
            }
            items.push(Value::Object(item));
        }
        projection.push(Value::Array(items));
    }
    Ok((
        sha256_text(&canonical_json(&Value::Array(projection))?),
        run_row,
    ))
}
