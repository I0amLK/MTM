//! A complete matrix is required; unsupported real-world tasks cannot be relabelled.
use std::collections::BTreeSet;

use serde::Deserialize;

use super::*;

pub(crate) const DEFINITION: &str = include_str!("../../conformance/mtm016-usability-corpus.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Definition {
    schema: String,
    repeats: u64,
    tasks: Vec<Task>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Task {
    id: String,
    scenario: String,
    requirement: String,
    expected: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    task_id: String,
    repeat: u64,
    status: String,
    reason: String,
    elapsed_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema: String,
    binary_sha256: String,
    corpus_sha256: String,
    tasks: u64,
    repeats: u64,
    rows: Vec<Row>,
    passed_trials: u64,
    failed_trials: u64,
    blocked_trials: u64,
    passed: bool,
    native_backend: String,
    latex_policy: String,
    independent_research_tested: bool,
    human_consent_tested: bool,
    web_client_tested: bool,
    production_changed: bool,
    release_qualified: bool,
}

pub(crate) fn validate(stdout: &[u8], hash: &str) -> Result<Value> {
    let report: Report = extract(stdout, "MTM_USABILITY_CORPUS ")?;
    let definition: Definition = serde_json::from_str(DEFINITION)?;
    if definition.schema != "mtm-usability-corpus-v1"
        || definition.repeats != 3
        || definition.tasks.len() != 30
        || report.schema != "mtm-usability-result-v1"
        || !valid_hash(hash)
        || report.binary_sha256 != hash
        || report.corpus_sha256 != format!("{:x}", Sha256::digest(DEFINITION.as_bytes()))
        || report.tasks != 30
        || report.repeats != 3
        || report.rows.len() != 90
        || report.native_backend != "disabled"
        || report.latex_policy != "static_only"
        || report.independent_research_tested
        || report.human_consent_tested
        || report.web_client_tested
        || report.production_changed
        || report.release_qualified
    {
        return Err("corpus identity or scope invalid".into());
    }
    let mut ids = BTreeSet::new();
    let mut scenarios = BTreeSet::new();
    let mut expected = BTreeSet::new();
    for task in &definition.tasks {
        if !ids.insert(&task.id) || !scenarios.insert(&task.scenario) || task.expected.is_empty() {
            return Err("corpus definition has duplicate or empty cases".into());
        }
        for repeat in 1..=3 {
            expected.insert((task.id.as_str(), repeat));
        }
    }
    let mut actual = BTreeSet::new();
    let mut passed = 0;
    let mut failed = 0;
    let mut blocked = 0;
    for row in &report.rows {
        if !actual.insert((row.task_id.as_str(), row.repeat)) || row.elapsed_ms > 610_000 {
            return Err("duplicate or unbounded corpus row".into());
        }
        let task = definition
            .tasks
            .iter()
            .find(|task| task.id == row.task_id)
            .ok_or("unknown corpus task")?;
        match task.requirement.as_str() {
            "portable" => match (row.status.as_str(), row.reason.as_str()) {
                ("passed", "checks_passed") => passed += 1,
                ("failed", "scenario_check_failed") => failed += 1,
                _ => return Err("portable trial was skipped or relabelled".into()),
            },
            requirement => {
                let reason = match requirement {
                    "native" => "native_host_required",
                    "research" => "independent_research_and_toolchain_required",
                    "external" => "independent_client_or_operator_evidence_required",
                    _ => return Err("unknown corpus task requirement".into()),
                };
                if row.status != "blocked" || row.reason != reason {
                    return Err("unimplemented real-world trial cannot be certified".into());
                }
                blocked += 1;
            }
        }
    }
    if actual != expected
        || report.passed_trials != passed
        || report.failed_trials != failed
        || report.blocked_trials != blocked
        || report.passed != (passed == 90)
    {
        return Err("corpus counts or three-repeat coverage inconsistent".into());
    }
    Ok(json!({"corpus":extract::<Value>(stdout, "MTM_USABILITY_CORPUS ")?}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Result<Value> {
        let definition: Definition = serde_json::from_str(DEFINITION)?;
        let mut rows = Vec::new();
        for task in definition.tasks {
            let (status, reason) = match task.requirement.as_str() {
                "portable" => ("passed", "checks_passed"),
                "native" => ("blocked", "native_host_required"),
                "research" => ("blocked", "independent_research_and_toolchain_required"),
                _ => (
                    "blocked",
                    "independent_client_or_operator_evidence_required",
                ),
            };
            for repeat in 1..=3 {
                rows.push(json!({"task_id":task.id,"repeat":repeat,"status":status,"reason":reason,"elapsed_ms":1}));
            }
        }
        Ok(
            json!({"schema":"mtm-usability-result-v1","binary_sha256":"a".repeat(64),
            "corpus_sha256":format!("{:x}",Sha256::digest(DEFINITION.as_bytes())),
            "tasks":30,"repeats":3,"rows":rows,"passed_trials":45,"failed_trials":0,"blocked_trials":45,
            "passed":false,"native_backend":"disabled","latex_policy":"static_only",
            "independent_research_tested":false,"human_consent_tested":false,"web_client_tested":false,
            "production_changed":false,"release_qualified":false}),
        )
    }

    fn output(value: &Value) -> Vec<u8> {
        format!("MTM_USABILITY_CORPUS {value}\n").into_bytes()
    }

    #[test]
    fn partial_matrix_is_valid_evidence_but_never_a_complete_corpus() -> Result<()> {
        let good = fixture()?;
        let result = validate(&output(&good), &"a".repeat(64))?;
        assert_eq!(result["corpus"]["passed"], false);
        for (key, replacement) in [
            ("passed", json!(true)),
            ("passed_trials", json!(90)),
            ("blocked_trials", json!(0)),
            ("repeats", json!(1)),
            ("repeats", json!(3.0)),
            ("binary_sha256", json!("b".repeat(64))),
            ("human_consent_tested", json!(true)),
            ("corpus_sha256", json!("b".repeat(64))),
            ("release_qualified", json!(true)),
        ] {
            let mut changed = good.clone();
            changed[key] = replacement;
            assert!(validate(&output(&changed), &"a".repeat(64)).is_err());
        }
        Ok(())
    }

    #[test]
    fn duplicated_missing_or_fake_real_world_rows_fail_closed() -> Result<()> {
        let good = fixture()?;
        let mut duplicate = good.clone();
        duplicate["rows"][1] = duplicate["rows"][0].clone();
        assert!(validate(&output(&duplicate), &"a".repeat(64)).is_err());
        let mut missing = good.clone();
        missing["rows"].as_array_mut().ok_or("rows")?.pop();
        assert!(validate(&output(&missing), &"a".repeat(64)).is_err());
        let mut fake = good.clone();
        fake["rows"][45]["status"] = json!("passed");
        fake["rows"][45]["reason"] = json!("checks_passed");
        assert!(validate(&output(&fake), &"a".repeat(64)).is_err());
        let mut extra = good.clone();
        extra["rows"][0]["token"] = json!("must-not-be-recorded");
        assert!(validate(&output(&extra), &"a".repeat(64)).is_err());
        assert!(validate(&[output(&good), output(&good)].concat(), &"a".repeat(64)).is_err());
        Ok(())
    }
}
