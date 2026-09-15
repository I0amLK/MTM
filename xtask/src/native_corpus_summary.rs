//! Closed U16-U20 adapter. This cannot certify research, browser or full corpus.
use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{Result, evidence_json};

const MARKER: &str = "MTM_NATIVE_CORPUS ";
const CORPUS: &str = include_str!("../../conformance/mtm016-usability-corpus.json");
const TASKS: [(&str, &str, &[&str]); 5] = [
    (
        "U16",
        "native_direct_argv",
        &["literal_metacharacters", "exact_stdout"],
    ),
    (
        "U17",
        "native_compound_path",
        &["compound_path", "nested_cwd", "missing_executable_denied"],
    ),
    (
        "U18",
        "native_tty_stdin",
        &[
            "tty_running",
            "stdin_roundtrip",
            "bounded_output",
            "explicit_kill",
        ],
    ),
    (
        "U19",
        "native_timeout_descendants",
        &["timeout", "explicit_kill", "descendant_write_absent"],
    ),
    (
        "U20",
        "native_network_permissions",
        &[
            "safe_denial",
            "exact_grant_binding",
            "once_consumed",
            "safe_network_isolated",
            "safe_granted_network",
            "trusted_network",
            "dangerous_network",
        ],
    ),
];
const COMMON: [&str; 4] = [
    "hard_isolation",
    "private_vault_hidden",
    "children_reaped",
    "clean_shutdown",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    task_id: String,
    scenario: String,
    repeat: u64,
    trial_id: String,
    status: String,
    reason: String,
    checks: Vec<String>,
    elapsed_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema: String,
    candidate_sha256: String,
    corpus_sha256: String,
    rows: Vec<Row>,
    tasks: u64,
    repeats: u64,
    passed_trials: u64,
    failed_trials: u64,
    passed: bool,
    native_backend: String,
    latex_policy: String,
    scripted_consent_only: bool,
    human_consent_tested: bool,
    independent_research_tested: bool,
    production_changed: bool,
    release_qualified: bool,
}

pub(super) fn validate(stdout: &[u8], candidate: &str) -> Result<Value> {
    let text = std::str::from_utf8(stdout).map_err(|_| "Native corpus output encoding invalid")?;
    let mut matching = text.lines().filter_map(|line| line.split_once(MARKER));
    let (_, serialized) = matching.next().ok_or("Native corpus summary missing")?;
    if serialized.len() > 32768 || matching.next().is_some() {
        return Err("Native corpus summary duplicated or oversized".into());
    }
    for line in text.lines() {
        if line.contains("MTM_")
            && !line.contains(MARKER)
            && !line.contains("MTM_NATIVE_CORPUS_DIAGNOSTIC ")
        {
            return Err("Native corpus output contains foreign evidence".into());
        }
    }
    let value = evidence_json::decode(serialized.as_bytes())?;
    let report: Report = serde_json::from_value(value.clone())
        .map_err(|_| "Native corpus summary schema invalid")?;
    let corpus_hash = format!("{:x}", Sha256::digest(CORPUS.as_bytes()));
    if !super::valid_hash(candidate)
        || report.candidate_sha256 != candidate
        || report.corpus_sha256 != corpus_hash
        || report.schema != "mtm-native-corpus-result-v1"
        || report.tasks != 5
        || report.repeats != 3
        || report.rows.len() != 15
        || report.native_backend != "bubblewrap"
        || report.latex_policy != "static_only"
        || !report.scripted_consent_only
        || report.human_consent_tested
        || report.independent_research_tested
        || report.production_changed
        || report.release_qualified
    {
        return Err("Native corpus identity or scope invalid".into());
    }
    let mut identities = BTreeSet::new();
    let mut cells = BTreeSet::new();
    let mut passed = 0_u64;
    for row in &report.rows {
        let (_, scenario, checks) = TASKS
            .iter()
            .find(|(id, _, _)| *id == row.task_id)
            .ok_or("Native corpus has unsupported task")?;
        if row.scenario != *scenario
            || !(1..=3).contains(&row.repeat)
            || !cells.insert((&row.task_id, row.repeat))
            || !identities.insert(&row.trial_id)
            || row.trial_id.len() != 32
            || !row
                .trial_id
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            || row.elapsed_ms > 120000
        {
            return Err("Native corpus row identity, repeat or bound invalid".into());
        }
        let expected: Vec<&str> = COMMON
            .iter()
            .copied()
            .chain(checks.iter().copied())
            .collect();
        match row.status.as_str() {
            "passed" if row.reason == "checks_passed" && row.checks == expected => passed += 1,
            "failed" if row.reason == "scenario_check_failed" && row.checks.is_empty() => {}
            _ => return Err("Native corpus row status or checks inconsistent".into()),
        }
    }
    if report.passed_trials != passed
        || report.failed_trials != 15 - passed
        || report.passed != (passed == 15)
    {
        return Err("Native corpus totals disagree with actual rows".into());
    }
    Ok(json!({"corpus_native":value}))
}

#[cfg(test)]
pub(crate) fn fixture(candidate: &str) -> Value {
    let mut rows = Vec::new();
    for (index, (id, scenario, checks)) in TASKS.iter().enumerate() {
        for repeat in 1..=3 {
            let checks: Vec<_> = COMMON.iter().chain(checks.iter()).collect();
            rows.push(json!({"task_id":id,"scenario":scenario,"repeat":repeat,
                "trial_id":format!("{:032x}",index*3+repeat),"status":"passed","reason":"checks_passed",
                "checks":checks,"elapsed_ms":100}));
        }
    }
    json!({"schema":"mtm-native-corpus-result-v1","candidate_sha256":candidate,
        "corpus_sha256":format!("{:x}",Sha256::digest(CORPUS.as_bytes())),"rows":rows,
        "tasks":5,"repeats":3,"passed_trials":15,"failed_trials":0,"passed":true,
        "native_backend":"bubblewrap","latex_policy":"static_only","scripted_consent_only":true,
        "human_consent_tested":false,"independent_research_tested":false,"production_changed":false,"release_qualified":false})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted(value: &Value) -> bool {
        validate(format!("{MARKER}{value}\n").as_bytes(), &"a".repeat(64)).is_ok()
    }

    #[test]
    fn native_matrix_requires_every_field_and_exact_trial_checks() -> Result<()> {
        let good = fixture(&"a".repeat(64));
        assert!(accepted(&good));
        for key in good.as_object().ok_or("fixture object")?.keys() {
            let mut bad = good.clone();
            bad.as_object_mut().ok_or("fixture object")?.remove(key);
            assert!(!accepted(&bad), "missing {key}");
        }
        for (pointer, value) in [
            ("/candidate_sha256", json!("b".repeat(64))),
            ("/corpus_sha256", json!("b".repeat(64))),
            ("/human_consent_tested", json!(true)),
            ("/scripted_consent_only", json!(false)),
            ("/independent_research_tested", json!(true)),
            ("/production_changed", json!(true)),
            ("/release_qualified", json!(true)),
            ("/native_backend", json!("disabled")),
            ("/passed_trials", json!(90)),
            ("/repeats", json!(3.0)),
            ("/passed", json!(1)),
            ("/rows/0/task_id", json!("U21")),
            ("/rows/0/repeat", json!(0)),
            ("/rows/0/repeat", json!(2)),
            ("/rows/0/repeat", json!(4)),
            ("/rows/0/scenario", json!("native_compound_path")),
            ("/rows/0/trial_id", good["rows"][1]["trial_id"].clone()),
            ("/rows/0/checks", json!([])),
            ("/rows/0/elapsed_ms", json!(120001)),
            ("/rows/0/status", json!("blocked")),
            ("/rows/0/reason", json!("copied_from_native_gate")),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).ok_or("fixture pointer")? = value;
            assert!(!accepted(&bad), "mutated {pointer}");
        }
        let mut bad = good.clone();
        bad["rows"].as_array_mut().ok_or("rows")?.pop();
        assert!(!accepted(&bad));
        for index in 0..15 {
            for key in good["rows"][index].as_object().ok_or("row")?.keys() {
                let mut bad = good.clone();
                bad["rows"][index].as_object_mut().ok_or("row")?.remove(key);
                assert!(!accepted(&bad));
            }
            let mut bad = good.clone();
            bad["rows"][index]["token"] = json!("must-not-be-evidence");
            assert!(!accepted(&bad));
        }
        Ok(())
    }

    #[test]
    fn failed_rows_preserved_but_not_promoted_and_duplicate_json_rejected() {
        let mut partial = fixture(&"a".repeat(64));
        partial["rows"][0]["status"] = json!("failed");
        partial["rows"][0]["reason"] = json!("scenario_check_failed");
        partial["rows"][0]["checks"] = json!([]);
        assert!(!accepted(&partial));
        partial["passed_trials"] = json!(14);
        partial["failed_trials"] = json!(1);
        partial["passed"] = json!(false);
        assert!(accepted(&partial));
        let line = format!("{MARKER}{partial}\n");
        assert!(validate(format!("{line}{line}").as_bytes(), &"a".repeat(64)).is_err());
        assert!(
            validate(
                format!("{line}MTM_NATIVE_COMMAND_RUNTIME {{}}\n").as_bytes(),
                &"a".repeat(64)
            )
            .is_err()
        );
        let duplicate = line.replacen("\"repeat\":1", "\"repeat\":1,\"repeat\":1", 1);
        assert_ne!(duplicate, line);
        assert!(validate(duplicate.as_bytes(), &"a".repeat(64)).is_err());
    }
}
