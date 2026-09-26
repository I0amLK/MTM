//! Pure, bounded preparation of facts from an already verified final proof.

use std::collections::{BTreeMap, BTreeSet};

use mtm_contracts::{ErrorCategory, ReCtmError};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::research_state::{
    ResearchAttemptMethod, ResearchAttemptOutcome, ResearchNodeStatus, ResearchState,
};

#[path = "memory/bm25.rs"]
mod bm25;
pub use bm25::rank as bm25_rank;
#[path = "memory/graph.rs"]
mod graph;
pub use graph::FactGraph;

pub const MAX_MANIFEST_FACTS: usize = 32;
const MAX_FACT_TEXT_BYTES: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedFact {
    pub fact_id: String,
    pub statement_tex: String,
    pub proof_tex: String,
    pub intuition: String,
    pub glossary_introduces: BTreeMap<String, String>,
    pub predecessors: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectFinding {
    pub finding_id: String,
    pub kind: &'static str,
    pub claim: String,
    pub evidence: String,
    pub verifiable: bool,
    pub links_json: String,
}

pub fn project_findings(
    project_id: &str,
    run_id: &str,
    state: &ResearchState,
) -> Vec<ProjectFinding> {
    let mut findings = BTreeMap::new();
    for node in state.nodes().values() {
        let kind = match node.status() {
            ResearchNodeStatus::Partial => "conclusion",
            ResearchNodeStatus::RouteSolved => "proof_attempt",
            _ => continue,
        };
        if node.node_id() == state.target_node_id() {
            continue;
        }
        add_finding(
            &mut findings,
            project_id,
            run_id,
            kind,
            node.statement(),
            node.status().as_str(),
            true,
            serde_json::json!({"node_id":node.node_id().as_str()}),
        );
    }
    for attempt in state.attempts() {
        let links = serde_json::json!({"node_id":attempt.node_id().as_str(),"attempt_id":attempt.attempt_id().as_str()});
        if matches!(
            attempt.outcome(),
            ResearchAttemptOutcome::Failed | ResearchAttemptOutcome::Refuted
        ) {
            add_finding(
                &mut findings,
                project_id,
                run_id,
                "dead_end",
                attempt.summary(),
                attempt.method().as_str(),
                false,
                links.clone(),
            );
        }
        if attempt.method() == ResearchAttemptMethod::Counterexample {
            add_finding(
                &mut findings,
                project_id,
                run_id,
                "counterexample",
                attempt.summary(),
                attempt.outcome().as_str(),
                attempt.outcome() == ResearchAttemptOutcome::RouteSolved,
                links.clone(),
            );
        }
        if let Some(obstruction) = attempt.obstruction() {
            add_finding(
                &mut findings,
                project_id,
                run_id,
                "obstacle",
                obstruction.as_str(),
                attempt.summary(),
                false,
                links,
            );
        }
    }
    for plan_id in state.active_plan_ids() {
        let summary = state
            .nodes()
            .values()
            .filter(|node| node.plan_id() == Some(plan_id))
            .take(8)
            .map(|node| node.statement())
            .collect::<Vec<_>>()
            .join("; ");
        if !summary.is_empty() {
            add_finding(
                &mut findings,
                project_id,
                run_id,
                "plan",
                &summary,
                "Active normalized research plan",
                false,
                serde_json::json!({"plan_id":plan_id.as_str()}),
            );
        }
    }
    findings.into_values().collect()
}

#[allow(clippy::too_many_arguments)]
fn add_finding(
    findings: &mut BTreeMap<String, ProjectFinding>,
    project_id: &str,
    run_id: &str,
    kind: &'static str,
    claim: &str,
    evidence: &str,
    verifiable: bool,
    links: Value,
) {
    let claim = claim.chars().take(2048).collect::<String>();
    let evidence = evidence.chars().take(2048).collect::<String>();
    let body = serde_json::json!({"project_id":project_id,"run_id":run_id,"kind":kind,
        "claim":claim,"evidence":evidence,"verifiable":verifiable,"links":links});
    let canonical = serde_json::to_string(&body).unwrap_or_default();
    let finding_id = format!("{:x}", Sha256::digest(canonical.as_bytes()));
    let links_json = serde_json::to_string(&links).unwrap_or_default();
    findings.insert(
        finding_id.clone(),
        ProjectFinding {
            finding_id,
            kind,
            claim,
            evidence,
            verifiable,
            links_json,
        },
    );
}

fn invalid(message: &str) -> ReCtmError {
    ReCtmError::new("INVALID_PROOF_FACTS", message).with_category(ErrorCategory::Validation)
}

pub fn normalize(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn compute_fact_id(
    project_id: &str,
    predecessors: &[String],
    glossary: &BTreeMap<String, String>,
    statement: &str,
    proof: &str,
) -> String {
    let mut predecessors = predecessors.to_vec();
    predecessors.sort();
    let glossary = glossary
        .iter()
        .map(|(key, value)| format!("{}: {}", quoted(key), quoted(value)))
        .collect::<Vec<_>>()
        .join(", ");
    let predecessors = predecessors
        .iter()
        .map(|value| quoted(value))
        .collect::<Vec<_>>()
        .join(", ");
    let canonical = format!(
        "{{\"glossary_introduces\": {{{glossary}}}, \"predecessors\": [{predecessors}], \"problem_id\": {}, \"proof\": {}, \"statement\": {}}}",
        quoted(project_id),
        quoted(&normalize(proof)),
        quoted(&normalize(statement))
    );
    let digest = Sha256::digest(canonical.as_bytes());
    format!("{:x}", digest)[..16].to_owned()
}

fn quoted(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

pub fn validate_manifest_facts(value: &Value, target: &str) -> Result<Value, ReCtmError> {
    let entries = value
        .as_array()
        .ok_or_else(|| invalid("facts must be an array"))?;
    if entries.is_empty() || entries.len() > MAX_MANIFEST_FACTS {
        return Err(invalid("facts must contain between 1 and 32 entries"));
    }
    let mut keys = BTreeSet::new();
    let mut normalized = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let object = entry
            .as_object()
            .ok_or_else(|| invalid("each fact must be an object"))?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "key"
                    | "statement_tex"
                    | "proof_tex"
                    | "predecessors"
                    | "glossary_introduces"
                    | "intuition"
            )
        }) {
            return Err(invalid("fact has an unknown field"));
        }
        let key = required_text(entry, "key", 128)?;
        if !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || !keys.insert(key.to_owned())
        {
            return Err(invalid("fact keys must be unique ASCII identifiers"));
        }
        let statement = required_text(entry, "statement_tex", MAX_FACT_TEXT_BYTES)?;
        let proof = required_text(entry, "proof_tex", MAX_FACT_TEXT_BYTES)?;
        let predecessors = entry
            .get("predecessors")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("fact predecessors must be an array"))?;
        if predecessors.len() > 64
            || predecessors
                .iter()
                .any(|item| item.as_str().is_none_or(str::is_empty))
        {
            return Err(invalid(
                "fact predecessors must be bounded non-empty strings",
            ));
        }
        let glossary = entry
            .get("glossary_introduces")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("fact glossary_introduces must be an object"))?;
        if glossary.len() > 64
            || glossary.iter().any(|(key, item)| {
                key.len() > 256 || item.as_str().is_none_or(|text| text.len() > 4096)
            })
        {
            return Err(invalid("fact glossary is invalid or too large"));
        }
        let intuition = match entry.get("intuition") {
            Some(Value::String(text)) if text.len() <= 4096 => text.as_str(),
            None => "",
            _ => return Err(invalid("fact intuition must be a bounded string")),
        };
        if index + 1 == entries.len() && normalize(statement) != normalize(target) {
            return Err(invalid("the final fact must state the proof target"));
        }
        normalized.push(serde_json::json!({
            "key":key,"statement_tex":statement,"proof_tex":proof,
            "predecessors":predecessors,"glossary_introduces":glossary,"intuition":intuition
        }));
    }
    Ok(Value::Array(normalized))
}

fn required_text<'a>(entry: &'a Value, field: &str, maximum: usize) -> Result<&'a str, ReCtmError> {
    entry
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty() && text.len() <= maximum)
        .ok_or_else(|| invalid("fact contains a missing or oversized text field"))
}

pub fn prepare_verified_facts(
    project_id: &str,
    target: &str,
    final_proof: &str,
    manifest: &Value,
    dependency_fact_ids: &[String],
    known_fact_ids: &BTreeSet<String>,
) -> Result<Vec<VerifiedFact>, ReCtmError> {
    let entries = if let Some(facts) = manifest.get("facts") {
        validate_manifest_facts(facts, target)?
            .as_array()
            .cloned()
            .ok_or_else(|| invalid("facts are invalid"))?
    } else {
        vec![
            serde_json::json!({"key":"target","statement_tex":target,"proof_tex":final_proof,
            "predecessors":[],"glossary_introduces":{},"intuition":""}),
        ]
    };
    let fact_count = entries.len();
    let mut by_key = BTreeMap::new();
    let mut batch_ids = BTreeSet::new();
    let mut result = Vec::with_capacity(fact_count);
    for (index, entry) in entries.into_iter().enumerate() {
        let key = required_text(&entry, "key", 128)?.to_owned();
        let statement = required_text(&entry, "statement_tex", MAX_FACT_TEXT_BYTES)?.to_owned();
        let proof = required_text(&entry, "proof_tex", MAX_FACT_TEXT_BYTES)?.to_owned();
        if !final_proof.contains(&proof)
            || !final_proof.contains(&statement) && manifest.get("facts").is_some()
        {
            return Err(invalid(
                "each declared fact statement and proof must occur in the final verified proof",
            ));
        }
        let mut predecessors = BTreeSet::new();
        // Revision dependencies belong to the whole proof, represented by its final target.
        // Intermediate facts depend only on their explicitly declared predecessors.
        if index + 1 == fact_count {
            predecessors.extend(dependency_fact_ids.iter().cloned());
        }
        for predecessor in entry["predecessors"]
            .as_array()
            .ok_or_else(|| invalid("fact predecessors are missing"))?
        {
            let reference = predecessor
                .as_str()
                .ok_or_else(|| invalid("fact predecessor must be a string"))?;
            let id = by_key
                .get(reference)
                .cloned()
                .or_else(|| {
                    known_fact_ids
                        .contains(reference)
                        .then(|| reference.to_owned())
                })
                .ok_or_else(|| {
                    invalid("fact predecessor must name an earlier fact or a verified project fact")
                })?;
            predecessors.insert(id);
        }
        if predecessors.len() > 64 {
            return Err(invalid("merged fact predecessors exceed the 64-fact bound"));
        }
        let glossary = entry["glossary_introduces"]
            .as_object()
            .ok_or_else(|| invalid("fact glossary is missing"))?
            .iter()
            .map(|(key, value)| {
                Ok((
                    key.clone(),
                    value
                        .as_str()
                        .ok_or_else(|| invalid("fact glossary value must be a string"))?
                        .to_owned(),
                ))
            })
            .collect::<Result<BTreeMap<_, _>, ReCtmError>>()?;
        let predecessors = predecessors.into_iter().collect::<Vec<_>>();
        let fact_id = compute_fact_id(project_id, &predecessors, &glossary, &statement, &proof);
        if predecessors.iter().any(|id| id == &fact_id) {
            return Err(invalid("fact cannot depend on itself"));
        }
        if !batch_ids.insert(fact_id.clone()) {
            return Err(invalid(
                "fact manifest contains duplicate content-addressed facts",
            ));
        }
        by_key.insert(key, fact_id.clone());
        result.push(VerifiedFact {
            fact_id,
            statement_tex: statement,
            proof_tex: proof,
            intuition: entry["intuition"].as_str().unwrap_or_default().to_owned(),
            glossary_introduces: glossary,
            predecessors,
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn danus_fact_id_golden_vectors() {
        assert_eq!(
            compute_fact_id(
                "project-main",
                &[],
                &BTreeMap::new(),
                "$1=1$.",
                "Proof.  1=1.\\qed"
            ),
            "3931cde730056bca"
        );
        let glossary = BTreeMap::from([
            ("x".to_owned(), "the variable".to_owned()),
            ("α".to_owned(), "alpha".to_owned()),
        ]);
        assert_eq!(
            compute_fact_id(
                "P",
                &["bbb".to_owned(), "aaa".to_owned()],
                &glossary,
                " A  implies B ",
                " Proof\n done "
            ),
            "d6efc332d3843518"
        );
    }

    #[test]
    fn manifest_requires_final_target_and_embedded_proofs() {
        let manifest = serde_json::json!({"facts":[{"key":"target","statement_tex":"A","proof_tex":"proof","predecessors":[],"glossary_introduces":{}}]});
        assert!(
            prepare_verified_facts("P", "A", "A proof", &manifest, &[], &BTreeSet::new()).is_ok()
        );
        assert!(
            prepare_verified_facts("P", "B", "A proof", &manifest, &[], &BTreeSet::new()).is_err()
        );
        assert!(
            prepare_verified_facts("P", "A", "A different", &manifest, &[], &BTreeSet::new())
                .is_err()
        );
    }

    #[test]
    fn revision_dependencies_only_attach_to_the_target_fact() -> Result<(), ReCtmError> {
        let manifest = serde_json::json!({"facts":[
            {"key":"a","statement_tex":"Lemma A.","proof_tex":"Step A.","predecessors":[],"glossary_introduces":{}},
            {"key":"b","statement_tex":"Lemma B.","proof_tex":"Step B.","predecessors":["a"],"glossary_introduces":{}},
            {"key":"target","statement_tex":"Target.","proof_tex":"Step C.","predecessors":["b"],"glossary_introduces":{}}
        ]});
        let proof = "Lemma A. Step A. Lemma B. Step B. Target. Step C.";
        let x = "1111111111111111".to_owned();
        let y = "2222222222222222".to_owned();
        let known = BTreeSet::from([x.clone(), y.clone()]);
        let baseline = prepare_verified_facts("P", "Target.", proof, &manifest, &[], &known)?;
        assert_eq!(baseline.len(), 3);
        assert!(baseline[0].predecessors.is_empty());
        assert_eq!(baseline[1].predecessors, vec![baseline[0].fact_id.clone()]);
        assert_eq!(baseline[2].predecessors, vec![baseline[1].fact_id.clone()]);

        let mut target_ids = BTreeSet::from([baseline[2].fact_id.clone()]);
        for dependencies in [vec![x.clone()], vec![y.clone()], vec![y.clone(), x.clone()]] {
            let facts =
                prepare_verified_facts("P", "Target.", proof, &manifest, &dependencies, &known)?;
            assert_eq!(facts.len(), 3);
            assert_eq!(&facts[..2], &baseline[..2]);
            let mut expected = dependencies.into_iter().collect::<BTreeSet<_>>();
            expected.insert(baseline[1].fact_id.clone());
            assert_eq!(
                facts[2].predecessors,
                expected.into_iter().collect::<Vec<_>>()
            );
            assert!(target_ids.insert(facts[2].fact_id.clone()));
        }
        Ok(())
    }

    #[test]
    fn explicit_fact_dependencies_are_preserved_and_target_dependencies_are_deduplicated()
    -> Result<(), ReCtmError> {
        let x = "1111111111111111".to_owned();
        let y = "2222222222222222".to_owned();
        let known = BTreeSet::from([x.clone(), y.clone()]);
        let manifest = serde_json::json!({"facts":[
            {"key":"a","statement_tex":"Lemma A.","proof_tex":"Step A.","predecessors":[x,x],"glossary_introduces":{}},
            {"key":"b","statement_tex":"Lemma B.","proof_tex":"Step B.","predecessors":["a"],"glossary_introduces":{}},
            {"key":"target","statement_tex":"Target.","proof_tex":"Step C.","predecessors":["b",x],"glossary_introduces":{}}
        ]});
        let proof = "Lemma A. Step A. Lemma B. Step B. Target. Step C.";
        let baseline = prepare_verified_facts("P", "Target.", proof, &manifest, &[], &known)?;
        let facts = prepare_verified_facts(
            "P",
            "Target.",
            proof,
            &manifest,
            &[y.clone(), x.clone(), y.clone()],
            &known,
        )?;
        assert_eq!(facts.len(), 3);
        assert_eq!(&facts[..2], &baseline[..2]);
        assert_eq!(facts[0].predecessors, vec![x.clone()]);
        assert_eq!(facts[1].predecessors, vec![facts[0].fact_id.clone()]);
        let expected = BTreeSet::from([facts[1].fact_id.clone(), x.clone(), y.clone()]);
        assert_eq!(
            facts[2].predecessors,
            expected.into_iter().collect::<Vec<_>>()
        );
        assert_eq!(
            facts,
            prepare_verified_facts("P", "Target.", proof, &manifest, &[x, y], &known)?
        );
        Ok(())
    }

    #[test]
    fn single_and_implicit_target_facts_keep_revision_dependencies() -> Result<(), ReCtmError> {
        let x = "1111111111111111".to_owned();
        let y = "2222222222222222".to_owned();
        let known = BTreeSet::from([x.clone(), y.clone()]);
        let proof = "Target. Proof.";
        for manifest in [
            serde_json::json!({}),
            serde_json::json!({"facts":[
                {"key":"target","statement_tex":"Target.","proof_tex":"Proof.","predecessors":[x],"glossary_introduces":{}}
            ]}),
        ] {
            let facts = prepare_verified_facts(
                "P",
                "Target.",
                proof,
                &manifest,
                &[y.clone(), x.clone(), x.clone()],
                &known,
            )?;
            assert_eq!(facts.len(), 1);
            assert_eq!(facts[0].predecessors, vec![x.clone(), y.clone()]);
            assert_eq!(
                facts[0].fact_id,
                compute_fact_id(
                    "P",
                    &[x.clone(), y.clone()],
                    &BTreeMap::new(),
                    "Target.",
                    &facts[0].proof_tex
                )
            );
        }
        Ok(())
    }

    #[test]
    fn merged_dependencies_are_bounded_before_promotion() -> Result<(), ReCtmError> {
        let dependencies = (1..=64).map(|id| format!("{id:016x}")).collect::<Vec<_>>();
        let extra = format!("{:016x}", 65);
        let mut known = dependencies.iter().cloned().collect::<BTreeSet<_>>();
        known.insert(extra.clone());
        let mut manifest = serde_json::json!({"facts":[
            {"key":"target","statement_tex":"Target.","proof_tex":"Proof.",
             "predecessors":[extra],"glossary_introduces":{}}
        ]});
        let rejected = prepare_verified_facts(
            "P",
            "Target.",
            "Target. Proof.",
            &manifest,
            &dependencies,
            &known,
        );
        assert!(rejected.is_err_and(|error| error.code == "INVALID_PROOF_FACTS"));
        manifest["facts"][0]["predecessors"] = serde_json::json!([dependencies[0]]);
        let accepted = prepare_verified_facts(
            "P",
            "Target.",
            "Target. Proof.",
            &manifest,
            &dependencies,
            &known,
        )?;
        assert_eq!(accepted[0].predecessors, dependencies);
        Ok(())
    }

    #[test]
    fn duplicate_content_is_rejected_even_with_distinct_local_keys() {
        let manifest = serde_json::json!({"facts":[
            {"key":"lemma","statement_tex":"Target.","proof_tex":"Proof.",
             "predecessors":[],"glossary_introduces":{}},
            {"key":"target","statement_tex":"Target.","proof_tex":"Proof.",
             "predecessors":[],"glossary_introduces":{}}
        ]});
        assert!(
            prepare_verified_facts(
                "P",
                "Target.",
                "Target. Proof.",
                &manifest,
                &[],
                &BTreeSet::new(),
            )
            .is_err_and(|error| error.code == "INVALID_PROOF_FACTS")
        );
    }

    #[test]
    fn fact_ids_ignore_local_names_and_intuition_but_bind_project_and_proof()
    -> Result<(), ReCtmError> {
        let manifest = serde_json::json!({"facts":[
            {"key":"a","statement_tex":"Lemma.","proof_tex":"Step.",
             "predecessors":[],"glossary_introduces":{"x":"variable"}},
            {"key":"target","statement_tex":"Target.","proof_tex":"Proof.",
             "predecessors":["a"],"glossary_introduces":{}}
        ]});
        let proof = "Lemma. Step. Target. Proof.";
        let baseline =
            prepare_verified_facts("P", "Target.", proof, &manifest, &[], &BTreeSet::new())?;
        let mut renamed = manifest.clone();
        renamed["facts"][0]["key"] = serde_json::json!("renamed");
        renamed["facts"][0]["intuition"] = serde_json::json!("Advisory annotation");
        renamed["facts"][1]["predecessors"] = serde_json::json!(["renamed"]);
        let facts = prepare_verified_facts("P", "Target.", proof, &renamed, &[], &BTreeSet::new())?;
        for (before, after) in baseline.iter().zip(&facts) {
            assert_eq!(before.fact_id, after.fact_id);
            assert_eq!(before.predecessors, after.predecessors);
        }
        let other =
            prepare_verified_facts("Q", "Target.", proof, &manifest, &[], &BTreeSet::new())?;
        assert_ne!(baseline[0].fact_id, other[0].fact_id);
        assert_ne!(baseline[1].fact_id, other[1].fact_id);
        renamed["facts"][1]["proof_tex"] = serde_json::json!("Other proof.");
        let changed = prepare_verified_facts(
            "P",
            "Target.",
            "Lemma. Step. Target. Other proof.",
            &renamed,
            &[],
            &BTreeSet::new(),
        )?;
        assert_ne!(baseline[1].fact_id, changed[1].fact_id);
        Ok(())
    }

    #[test]
    fn normalized_attempts_project_typed_stable_findings()
    -> Result<(), crate::research_state::ResearchStateError> {
        use crate::research_state::{
            ResearchAttempt, ResearchAttemptId, ResearchDomainId, ResearchNode, ResearchNodeId,
            ResearchNodeKind, ResearchObstruction, ResearchSnapshot, ResearchStateProjector,
        };
        let target = ResearchNodeId::parse("target")?;
        let lemma = ResearchNodeId::parse("lemma")?;
        let snapshot = ResearchSnapshot::new(target.clone())
            .with_node(ResearchNode::new(
                target,
                "Target",
                ResearchNodeKind::Target,
            )?)
            .with_node(
                ResearchNode::new(lemma.clone(), "Partial lemma", ResearchNodeKind::Lemma)?
                    .with_status(ResearchNodeStatus::Partial),
            )
            .with_attempt(
                ResearchAttempt::new(
                    ResearchAttemptId::parse("attempt")?,
                    lemma,
                    ResearchDomainId::parse("domain")?,
                    ResearchAttemptMethod::Counterexample,
                    ResearchAttemptOutcome::Failed,
                    "This route fails",
                )?
                .with_obstruction(ResearchObstruction::MissingLemma),
            );
        let state = ResearchStateProjector::analyze(&snapshot)?;
        let first = project_findings("project", "run", &state);
        assert_eq!(first, project_findings("project", "run", &state));
        assert_eq!(
            first.iter().map(|item| item.kind).collect::<BTreeSet<_>>(),
            BTreeSet::from(["conclusion", "counterexample", "dead_end", "obstacle"])
        );
        assert!(
            first
                .iter()
                .find(|item| item.kind == "conclusion")
                .is_some_and(|item| item.verifiable)
        );
        assert!(
            first
                .iter()
                .filter(|item| item.kind != "conclusion")
                .all(|item| !item.verifiable)
        );
        Ok(())
    }
}
