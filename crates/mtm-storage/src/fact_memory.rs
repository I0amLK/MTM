use std::collections::BTreeSet;

use mtm_contracts::{ErrorCategory, ReCtmError};
use rusqlite::{OptionalExtension, Transaction, params};
use serde_json::Value;

use super::{StateStore, normalize_sql, query_all_on, sql_error};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactForPromotion {
    pub fact_id: String,
    pub statement_tex: String,
    pub proof_tex: String,
    pub intuition: String,
    pub glossary_json: String,
    pub predecessors: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingForStorage {
    pub finding_id: String,
    pub kind: String,
    pub claim: String,
    pub evidence: String,
    pub verifiable: bool,
    pub links_json: String,
}

fn fact_conflict(message: &str) -> ReCtmError {
    ReCtmError::new("FACT_GRAPH_CONFLICT", message).with_category(ErrorCategory::Conflict)
}

pub(super) fn insert_promoted_facts(
    tx: &Transaction<'_>,
    project_id: &str,
    run_id: &str,
    facts: &[FactForPromotion],
    now: &str,
) -> Result<String, ReCtmError> {
    if facts.is_empty() || facts.len() > 32 {
        return Err(fact_conflict(
            "A verified promotion needs a bounded fact batch.",
        ));
    }
    let mut batch_ids = BTreeSet::new();
    for fact in facts {
        if fact.fact_id.len() != 16
            || !fact.fact_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || fact.statement_tex.trim().is_empty()
            || fact.proof_tex.trim().is_empty()
            || fact.predecessors.len() > 64
            || !batch_ids.insert(&fact.fact_id)
        {
            return Err(fact_conflict(
                "Fact batch contains invalid or repeated data.",
            ));
        }
        for predecessor in &fact.predecessors {
            let predecessor_project: Option<String> = tx.query_row(
                "SELECT project_id FROM facts WHERE fact_id=? AND NOT EXISTS(SELECT 1 FROM fact_revocations WHERE fact_revocations.fact_id=facts.fact_id)",
                [predecessor], |row| row.get(0)
            ).optional().map_err(sql_error)?;
            if predecessor_project.as_deref() != Some(project_id) {
                return Err(fact_conflict(
                    "Fact predecessor is missing, revoked, or belongs to another project.",
                ));
            }
        }
        let existing: Option<(String, String, String, String)> = tx.query_row(
            "SELECT project_id,statement_tex,proof_tex,glossary_json FROM facts WHERE fact_id=?",
            [&fact.fact_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))
        ).optional().map_err(sql_error)?;
        if let Some((project, statement, proof, glossary)) = existing {
            if project != project_id
                || normalize_sql(&statement) != normalize_sql(&fact.statement_tex)
                || normalize_sql(&proof) != normalize_sql(&fact.proof_tex)
                || glossary != fact.glossary_json
            {
                return Err(fact_conflict(
                    "An existing fact ID has different immutable content.",
                ));
            }
            let existing_edges = query_all_on(
                tx,
                "SELECT predecessor_id FROM fact_edges WHERE fact_id=? ORDER BY predecessor_id",
                [&fact.fact_id],
                &[],
            )?;
            let prior = existing_edges
                .iter()
                .filter_map(|row| row["predecessor_id"].as_str())
                .collect::<BTreeSet<_>>();
            let requested = fact
                .predecessors
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            if prior != requested {
                return Err(fact_conflict(
                    "An existing fact ID has different predecessors.",
                ));
            }
            let revoked: i64 = tx
                .query_row(
                    "SELECT count(*) FROM fact_revocations WHERE fact_id=?",
                    [&fact.fact_id],
                    |row| row.get(0),
                )
                .map_err(sql_error)?;
            if revoked != 0 {
                return Err(fact_conflict("A revoked fact cannot be promoted again."));
            }
        } else {
            tx.execute(
                "INSERT INTO facts(fact_id,project_id,source_run_id,statement_tex,proof_tex,intuition,glossary_json,external_refs_json,created_at) VALUES(?,?,?,?,?,?,?,'[]',?)",
                params![fact.fact_id,project_id,run_id,fact.statement_tex,fact.proof_tex,fact.intuition,fact.glossary_json,now]
            ).map_err(sql_error)?;
            for predecessor in &fact.predecessors {
                tx.execute(
                    "INSERT INTO fact_edges(fact_id,predecessor_id) VALUES(?,?)",
                    params![fact.fact_id, predecessor],
                )
                .map_err(sql_error)?;
            }
        }
    }
    facts
        .last()
        .map(|fact| fact.fact_id.clone())
        .ok_or_else(|| fact_conflict("Missing target fact."))
}

pub(super) fn verify_matching_findings(
    tx: &Transaction<'_>,
    run_id: &str,
    facts: &[FactForPromotion],
    now: &str,
) -> Result<(), ReCtmError> {
    let findings = query_all_on(
        tx,
        "SELECT finding_id,claim FROM memory_findings WHERE run_id=? AND verifiable=1 AND kind IN ('conclusion','example','counterexample','proof_attempt') ORDER BY finding_id",
        [run_id],
        &[],
    )?;
    for finding in findings {
        let Some(claim) = finding["claim"].as_str() else {
            continue;
        };
        let Some(fact) = facts
            .iter()
            .find(|fact| normalize_sql(&fact.statement_tex) == normalize_sql(claim))
        else {
            continue;
        };
        let finding_id = finding["finding_id"]
            .as_str()
            .ok_or_else(|| fact_conflict("Finding has no ID."))?;
        let status: Option<String> = tx.query_row("SELECT status FROM memory_finding_status WHERE finding_id=? ORDER BY seq DESC LIMIT 1", [finding_id], |row| row.get(0)).optional().map_err(sql_error)?;
        if status.as_deref() != Some("verified") {
            tx.execute("INSERT INTO memory_finding_status(finding_id,seq,status,fact_id,created_at) VALUES(?,(SELECT COALESCE(MAX(seq),0)+1 FROM memory_finding_status WHERE finding_id=?),'verified',?,?)",
                params![finding_id,finding_id,fact.fact_id,now]).map_err(sql_error)?;
        }
    }
    Ok(())
}

impl StateStore {
    pub fn insert_project_findings(
        &self,
        project_id: &str,
        run_id: &str,
        owner_id: &str,
        findings: &[FindingForStorage],
    ) -> Result<(), ReCtmError> {
        if findings.len() > 8192 {
            return Err(fact_conflict("Finding projection exceeds its fixed bound."));
        }
        self.get_project(project_id, Some(owner_id))?;
        let project_run = self
            .get_project_run(run_id, Some(owner_id))?
            .ok_or_else(|| fact_conflict("Finding run has no project."))?;
        if project_run["project_id"] != project_id {
            return Err(fact_conflict("Finding run belongs to another project."));
        }
        let now = self.runtime.clock.now_iso()?;
        self.immediate(|tx| {
            for finding in findings {
                if finding.finding_id.len()!=64 || !finding.finding_id.bytes().all(|byte|byte.is_ascii_hexdigit())
                    || finding.claim.is_empty() || finding.claim.len()>8192 || finding.evidence.len()>8192
                    || !matches!(finding.kind.as_str(), "conclusion"|"example"|"counterexample"|"proof_attempt"|"plan"|"dead_end"|"direction"|"obstacle") {
                    return Err(fact_conflict("Finding data is invalid."));
                }
                let inserted = tx.execute("INSERT OR IGNORE INTO memory_findings(finding_id,project_id,run_id,kind,claim,evidence,verifiable,links_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    params![finding.finding_id,project_id,run_id,finding.kind,finding.claim,finding.evidence,i64::from(finding.verifiable),finding.links_json,now]).map_err(sql_error)?;
                if inserted > 0 {
                    tx.execute("INSERT INTO memory_finding_status(finding_id,seq,status,created_at) VALUES(?,1,'active',?)", params![finding.finding_id,now]).map_err(sql_error)?;
                }
            }
            Ok(())
        })
    }

    pub fn list_project_findings(
        &self,
        project_id: &str,
        owner_id: &str,
    ) -> Result<Vec<Value>, ReCtmError> {
        self.get_project(project_id, Some(owner_id))?;
        self.query_all("SELECT f.finding_id,f.project_id,f.run_id,f.kind,f.claim,f.evidence,f.verifiable,f.links_json,f.created_at,s.status,s.fact_id FROM memory_findings f JOIN memory_finding_status s ON s.finding_id=f.finding_id AND s.seq=(SELECT MAX(seq) FROM memory_finding_status WHERE finding_id=f.finding_id) WHERE f.project_id=? ORDER BY f.created_at DESC,f.finding_id LIMIT 1024",
            [project_id], &["links_json"])
    }
    pub fn list_project_facts(
        &self,
        project_id: &str,
        owner_id: &str,
    ) -> Result<Vec<Value>, ReCtmError> {
        self.get_project(project_id, Some(owner_id))?;
        self.query_all(
            "SELECT f.fact_id,f.project_id,f.source_run_id,f.statement_tex,f.intuition,f.glossary_json,f.external_refs_json,f.created_at, EXISTS(SELECT 1 FROM fact_revocations r WHERE r.fact_id=f.fact_id) AS revoked FROM facts f WHERE f.project_id=? ORDER BY f.fact_id",
            [project_id], &["glossary_json","external_refs_json"]
        )
    }

    pub fn memory_fact_candidates(
        &self,
        project_id: &str,
        owner_id: &str,
    ) -> Result<Vec<Value>, ReCtmError> {
        self.get_project(project_id, Some(owner_id))?;
        self.query_all("SELECT fact_id,substr(statement_tex,1,4096) AS statement_tex,substr(intuition,1,1024) AS intuition FROM facts f WHERE project_id=? AND NOT EXISTS(SELECT 1 FROM fact_revocations r WHERE r.fact_id=f.fact_id) ORDER BY created_at DESC,fact_id LIMIT 512",
            [project_id], &[])
    }

    pub fn memory_fact_summary(
        &self,
        project_id: &str,
        fact_id: &str,
    ) -> Result<Value, ReCtmError> {
        self.query_one_params("SELECT fact_id,substr(statement_tex,1,4096) AS statement_tex,substr(intuition,1,1024) AS intuition FROM facts f WHERE project_id=? AND fact_id=? AND NOT EXISTS(SELECT 1 FROM fact_revocations r WHERE r.fact_id=f.fact_id)",
            params![project_id,fact_id], &[])?
            .ok_or_else(|| fact_conflict("Selected fact predecessor is missing or revoked."))
    }

    pub fn memory_fact_predecessors(
        &self,
        project_id: &str,
        fact_id: &str,
    ) -> Result<Vec<String>, ReCtmError> {
        let rows = self.query_all_params("SELECT e.predecessor_id FROM fact_edges e JOIN facts f ON f.fact_id=e.fact_id WHERE f.project_id=? AND e.fact_id=? ORDER BY e.predecessor_id",
            params![project_id,fact_id], &[])?;
        rows.into_iter()
            .map(|row| {
                row["predecessor_id"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| fact_conflict("Fact edge has no predecessor ID."))
            })
            .collect()
    }

    pub fn active_project_fact_ids(
        &self,
        project_id: &str,
        owner_id: &str,
    ) -> Result<BTreeSet<String>, ReCtmError> {
        Ok(self
            .list_project_facts(project_id, owner_id)?
            .into_iter()
            .filter(|fact| fact["revoked"] == false)
            .filter_map(|fact| fact["fact_id"].as_str().map(str::to_owned))
            .collect())
    }

    pub fn project_fact_graph(
        &self,
        project_id: &str,
        owner_id: &str,
    ) -> Result<Value, ReCtmError> {
        self.get_project(project_id, Some(owner_id))?;
        self.project_fact_graph_operator(project_id)
    }

    pub fn project_fact_graph_operator(&self, project_id: &str) -> Result<Value, ReCtmError> {
        self.get_project(project_id, None)?;
        // Nodes, revocations and edges must come from the same SQLite snapshot,
        // including when another connection promotes facts during an export.
        let mut connection = self.lock_connection()?;
        let tx = connection.transaction().map_err(sql_error)?;
        let facts = query_all_on(
            &tx,
            "SELECT f.fact_id,f.project_id,f.source_run_id,f.statement_tex,f.intuition,f.glossary_json,f.external_refs_json,f.created_at, EXISTS(SELECT 1 FROM fact_revocations r WHERE r.fact_id=f.fact_id) AS revoked FROM facts f WHERE f.project_id=? ORDER BY f.fact_id",
            [project_id],
            &["glossary_json", "external_refs_json"],
        )?;
        let edges = query_all_on(
            &tx,
            "SELECT e.fact_id,e.predecessor_id FROM fact_edges e JOIN facts f ON f.fact_id=e.fact_id WHERE f.project_id=? ORDER BY e.fact_id,e.predecessor_id",
            [project_id],
            &[],
        )?;
        tx.commit().map_err(sql_error)?;
        drop(connection);
        let mut nodes = serde_json::Map::new();
        for fact in facts {
            let id = fact["fact_id"]
                .as_str()
                .ok_or_else(|| fact_conflict("Fact row has no ID."))?
                .to_owned();
            nodes.insert(id, serde_json::json!({"label":fact["statement_tex"],"metadata":{
                "source_run_id":fact["source_run_id"],"intuition":fact["intuition"],"glossary":fact["glossary"],"revoked":fact["revoked"]
            }}));
        }
        let edges = edges.into_iter().map(|edge| serde_json::json!({"source":edge["fact_id"],"target":edge["predecessor_id"],"relation":"depends_on"})).collect::<Vec<_>>();
        Ok(serde_json::json!({"graph":{"id":project_id,"nodes":nodes,"edges":edges}}))
    }

    pub fn revoke_project_fact(
        &self,
        fact_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<Value, ReCtmError> {
        if actor.trim().is_empty() || reason.trim().is_empty() || reason.len() > 4096 {
            return Err(ReCtmError::new(
                "INVALID_FACT_REVOCATION",
                "Actor and a bounded reason are required.",
            )
            .with_category(ErrorCategory::Validation));
        }
        let now = self.runtime.clock.now_iso()?;
        self.immediate(|tx| {
            let root: Option<String> = tx.query_row("SELECT project_id FROM facts WHERE fact_id=?", [fact_id], |row| row.get(0)).optional().map_err(sql_error)?;
            let project_id = root.ok_or_else(|| ReCtmError::new("FACT_NOT_FOUND", "Unknown fact.").with_category(ErrorCategory::NotFound))?;
            let descendants = query_all_on(tx,
                "WITH RECURSIVE descendants(fact_id) AS (SELECT ? UNION SELECT e.fact_id FROM fact_edges e JOIN descendants d ON e.predecessor_id=d.fact_id JOIN facts f ON f.fact_id=e.fact_id WHERE f.project_id=?) SELECT fact_id FROM descendants ORDER BY fact_id",
                [fact_id, project_id.as_str()], &[])?;
            let mut ids = Vec::new();
            for row in descendants {
                let id = row["fact_id"].as_str().ok_or_else(|| fact_conflict("Invalid descendant ID."))?;
                let count: i64 = tx.query_row("SELECT count(*) FROM fact_revocations WHERE fact_id=?", [id], |row| row.get(0)).map_err(sql_error)?;
                if count == 0 {
                    tx.execute("INSERT INTO fact_revocations(fact_id,reason,actor,created_at) VALUES(?,?,?,?)", params![id,reason,actor,now]).map_err(sql_error)?;
                    let linked_findings = query_all_on(tx,
                        "SELECT s.finding_id FROM memory_finding_status s WHERE s.fact_id=? AND s.status='verified' AND s.seq=(SELECT MAX(seq) FROM memory_finding_status WHERE finding_id=s.finding_id) ORDER BY s.finding_id",
                        [id], &[])?;
                    for finding in linked_findings {
                        let finding_id = finding["finding_id"].as_str().ok_or_else(|| fact_conflict("Invalid linked finding ID."))?;
                        tx.execute("INSERT INTO memory_finding_status(finding_id,seq,status,created_at) VALUES(?,(SELECT COALESCE(MAX(seq),0)+1 FROM memory_finding_status WHERE finding_id=?),'superseded',?)",
                            params![finding_id,finding_id,now]).map_err(sql_error)?;
                    }
                    ids.push(id.to_owned());
                }
            }
            Ok(serde_json::json!({"project_id":project_id,"revoked_fact_ids":ids}))
        })
    }
}
