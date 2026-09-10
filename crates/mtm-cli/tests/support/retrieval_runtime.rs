//! Exact-candidate real external retrieval. Records counts and trust-domain facts only.
use std::env;

use serde_json::{Value, json};

use crate::support::candidate;
use crate::support::loopback::{Client, Server};
use crate::support::recovery::error_code;
use crate::support::{Result, require, text};

const ENABLE: &str = "MTM_TEST_RETRIEVAL_PROFILE";

fn explore(server: &Server, owner: &Client) -> Result<Value> {
    let assess = crate::start(server, owner, "full")?;
    let mut request = crate::candidate_lifecycle::fixture_submission(&assess, "full", false)?;
    request["payload"]["requires_external_retrieval"] = json!(true);
    let task = server.call(owner, "rethlas_step", request)?;
    require(
        task["ok"] == true && task["state"] == "explore",
        "retrieval fixture did not enter explore state",
    )?;
    text(&task, "capability")?;
    Ok(task)
}

fn count_results(value: &Value) -> Result<u64> {
    require(value["ok"] == true, "external retrieval returned an error")?;
    let count = value["count"]
        .as_u64()
        .ok_or("external retrieval count missing")?;
    require(count > 0, "external retrieval returned no results")?;
    Ok(count)
}

#[test]
fn exact_candidate_real_external_retrieval_and_redirect_policy() -> Result {
    if env::var_os(ENABLE).is_none() {
        return Ok(());
    }
    require(
        env::var(ENABLE).ok().as_deref() == Some("1")
            && env::var_os(candidate::BINARY_ENV).is_some(),
        "retrieval profile requires explicit candidate and exact flag",
    )?;
    let candidate = candidate::select()?;

    let mut server = Server::start(&candidate.path)?;
    let owner = server.login()?;
    let task = explore(&server, &owner)?;
    let capability = text(&task, "capability")?.to_owned();

    let theorem = server.call(
        &owner,
        "rethlas_retrieve",
        json!({
            "operation":"theorem_search","query":"finite field polynomial irreducible",
            "search_intent":"background","num_results":2,"capability":capability
        }),
    )?;
    let theorem_count = count_results(&theorem)?;
    require(
        theorem["endpoint"] == "https://leansearch.net/thm/search"
            && theorem["source_trust"] == "external_unverified",
        "theorem retrieval trust domain or source label drifted",
    )?;

    let papers = server.call(
        &owner,
        "rethlas_retrieve",
        json!({
            "operation":"paper_search","query":"quasi-cyclic codes finite fields",
            "num_results":2,"capability":capability
        }),
    )?;
    let paper_count = count_results(&papers)?;
    require(
        papers["endpoint"] == "https://api.openalex.org/works"
            && papers["source_trust"] == "external_unverified",
        "paper retrieval trust domain or source label drifted",
    )?;
    let paper_id = papers["results"]
        .as_array()
        .and_then(|rows| rows.first())
        .and_then(|row| row.get("paper_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("OpenAlex result omitted a paper identifier")?
        .to_owned();

    let lookup = server.call(
        &owner,
        "rethlas_retrieve",
        json!({
            "operation":"paper_lookup","query":paper_id,
            "capability":capability
        }),
    )?;
    let lookup_count = count_results(&lookup)?;
    require(
        lookup_count == 1
            && lookup["endpoint"] == "https://api.openalex.org/works"
            && lookup["source_trust"] == "external_unverified",
        "paper lookup did not remain on fixed OpenAlex HTTPS trust domain",
    )?;
    crate::cancel(&server, &owner, &task)?;
    server.stop()?;

    // Exercise the candidate's own post-redirect trust-domain check. The initial
    // endpoint is HTTPS; following it crosses to example.com and must be rejected.
    let redirect_url = "https://httpbin.org/redirect-to?url=https%3A%2F%2Fexample.com%2F";
    let mut redirect_server = Server::start_retrieval_redirect(&candidate.path, redirect_url)?;
    let redirect_owner = redirect_server.login()?;
    let redirect_task = explore(&redirect_server, &redirect_owner)?;
    let rejected = redirect_server.call(
        &redirect_owner,
        "rethlas_retrieve",
        json!({
            "operation":"theorem_search","query":"redirect policy probe",
            "search_intent":"background","num_results":1,
            "capability":text(&redirect_task,"capability")?
        }),
    )?;
    require(
        rejected["ok"] == false && error_code(&rejected) == "RESEARCH_REDIRECT_DENIED",
        "cross-domain research redirect was not rejected by the candidate",
    )?;
    crate::cancel(&redirect_server, &redirect_owner, &redirect_task)?;
    redirect_server.stop()?;
    candidate.unchanged()?;

    println!(
        "MTM_RETRIEVAL_RUNTIME {}",
        json!({
            "schema":"mtm-retrieval-runtime-v1","ok":true,
            "binary_sha256":candidate.sha256,"request_count":4,
            "successful_external_requests":3,"independent_source_count":2,
            "theorem_result_count":theorem_count,"paper_result_count":paper_count,
            "lookup_result_count":lookup_count,"actual_external_retrieval":true,
            "https_only":true,"redirect_policy_checked":true,
            "redirect_rejected_code":"RESEARCH_REDIRECT_DENIED",
            "sources":["leansearch.net","api.openalex.org"],
            "raw_credentials_recorded":false,"raw_retrieval_bodies_recorded":false,
            "native_execution_tested":false,"compiled_latex_tested":false,
            "web_client_tested":false,"human_consent_tested":false,
            "production_changed":false,"release_qualified":false
        })
    );
    Ok(())
}
