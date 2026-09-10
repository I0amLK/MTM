//! Exact real-network retrieval summary with no returned research bodies.
use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::{Value, json};

use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema: String,
    ok: bool,
    binary_sha256: String,
    request_count: u64,
    successful_external_requests: u64,
    independent_source_count: u64,
    theorem_result_count: u64,
    paper_result_count: u64,
    lookup_result_count: u64,
    actual_external_retrieval: bool,
    https_only: bool,
    redirect_policy_checked: bool,
    redirect_rejected_code: String,
    sources: Vec<String>,
    raw_credentials_recorded: bool,
    raw_retrieval_bodies_recorded: bool,
    native_execution_tested: bool,
    compiled_latex_tested: bool,
    web_client_tested: bool,
    human_consent_tested: bool,
    production_changed: bool,
    release_qualified: bool,
}

pub(crate) fn validate(stdout: &[u8], hash: &str) -> Result<Value> {
    let report: Report = extract(stdout, "MTM_RETRIEVAL_RUNTIME ")?;
    let sources = report
        .sources
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if report.schema != "mtm-retrieval-runtime-v1"
        || !report.ok
        || !valid_hash(hash)
        || report.binary_sha256 != hash
        || report.request_count != 4
        || report.successful_external_requests != 3
        || report.independent_source_count != 2
        || report.theorem_result_count == 0
        || report.paper_result_count == 0
        || report.lookup_result_count != 1
        || !report.actual_external_retrieval
        || !report.https_only
        || !report.redirect_policy_checked
        || report.redirect_rejected_code != "RESEARCH_REDIRECT_DENIED"
        || sources != BTreeSet::from(["api.openalex.org", "leansearch.net"])
        || report.raw_credentials_recorded
        || report.raw_retrieval_bodies_recorded
        || report.native_execution_tested
        || report.compiled_latex_tested
        || report.web_client_tested
        || report.human_consent_tested
        || report.production_changed
        || report.release_qualified
    {
        return Err(
            "retrieval summary has inconsistent identity, counts, trust policy or scope".into(),
        );
    }
    Ok(json!({"retrieval":extract::<Value>(stdout, "MTM_RETRIEVAL_RUNTIME ")?}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        json!({
            "schema":"mtm-retrieval-runtime-v1","ok":true,"binary_sha256":"a".repeat(64),
            "request_count":4,"successful_external_requests":3,"independent_source_count":2,
            "theorem_result_count":2,"paper_result_count":2,"lookup_result_count":1,
            "actual_external_retrieval":true,"https_only":true,"redirect_policy_checked":true,
            "redirect_rejected_code":"RESEARCH_REDIRECT_DENIED",
            "sources":["leansearch.net","api.openalex.org"],
            "raw_credentials_recorded":false,"raw_retrieval_bodies_recorded":false,
            "native_execution_tested":false,"compiled_latex_tested":false,
            "web_client_tested":false,"human_consent_tested":false,
            "production_changed":false,"release_qualified":false
        })
    }

    fn output(value: &Value) -> Vec<u8> {
        format!("MTM_RETRIEVAL_RUNTIME {value}\n").into_bytes()
    }

    #[test]
    fn every_network_count_and_scope_boundary_is_required() -> Result<()> {
        validate(&output(&fixture()), &"a".repeat(64))?;
        for (key, value) in [
            ("request_count", json!(3)),
            ("successful_external_requests", json!(2)),
            ("independent_source_count", json!(1)),
            ("theorem_result_count", json!(0)),
            ("lookup_result_count", json!(0)),
            ("actual_external_retrieval", json!(false)),
            ("https_only", json!(false)),
            ("redirect_policy_checked", json!(false)),
            ("redirect_rejected_code", json!("OTHER")),
            ("sources", json!(["api.openalex.org"])),
            ("raw_credentials_recorded", json!(true)),
            ("raw_retrieval_bodies_recorded", json!(true)),
            ("compiled_latex_tested", json!(true)),
            ("production_changed", json!(true)),
            ("release_qualified", json!(true)),
        ] {
            let mut changed = fixture();
            changed[key] = value;
            assert!(validate(&output(&changed), &"a".repeat(64)).is_err());
        }
        assert!(
            validate(
                &[output(&fixture()), output(&fixture())].concat(),
                &"a".repeat(64)
            )
            .is_err()
        );
        Ok(())
    }
}
