use std::collections::BTreeMap;
use std::path::PathBuf;

use mtm_contracts::{ErrorCategory, ReCtmError};
use mtm_native::{CommandManager, CommandManagerConfig, CommandRequest, PollRequest};
use mtm_workflow::{ResearchProvider, ResearchRequest};
use serde_json::Value;
use url::Url;

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const META_SENTINEL: &str = "\n__MTM_HTTP_META__";
const DEFAULT_TASK: &str = "Given a math statement, retrieve useful references, such as theorems, lemmas, and definitions, that are useful for solving the given problem.";

pub struct CurlResearchProvider {
    theorem_endpoint: Url,
    paper_endpoint: Url,
    timeout_seconds: u64,
    curl: PathBuf,
    commands: CommandManager,
}

impl CurlResearchProvider {
    pub fn new(theorem_endpoint: &str, timeout_seconds: u64) -> Result<Self, ReCtmError> {
        let theorem_endpoint = validate_endpoint(theorem_endpoint, None)?;
        let paper_endpoint =
            validate_endpoint("https://api.openalex.org/works", Some("api.openalex.org"))?;
        let curl = find_in_path("curl").ok_or_else(|| {
            ReCtmError::new(
                "RESEARCH_SERVICE_UNAVAILABLE",
                "curl is required for the bounded research adapter.",
            )
            .with_category(ErrorCategory::Runtime)
        })?;
        Ok(Self {
            theorem_endpoint,
            paper_endpoint,
            timeout_seconds,
            curl,
            commands: CommandManager::new(CommandManagerConfig {
                buffer_bytes: MAX_RESPONSE_BYTES + 65_536,
                max_active_commands: 4,
                max_retained_commands: 8,
                ..CommandManagerConfig::default()
            }),
        })
    }

    fn theorem_search(&self, request: &ResearchRequest) -> Result<Value, ReCtmError> {
        let query = request.query.trim();
        if query.is_empty() {
            return Err(validation("query is required"));
        }
        validate_num_results(request.num_results)?;
        if !matches!(
            request.search_intent.as_str(),
            "theorem" | "construction" | "example" | "counterexample" | "background"
        ) {
            return Err(validation_details(
                "unsupported search_intent",
                serde_json::json!({"search_intent":request.search_intent}),
            ));
        }
        let body = serde_json::to_string(&serde_json::json!({
            "query":query,"task":DEFAULT_TASK,"num_results":request.num_results
        }))
        .map_err(json_error)?;
        let response = self.http(
            "POST",
            self.theorem_endpoint.clone(),
            Some(body),
            self.theorem_endpoint.host_str().unwrap_or_default(),
            "RESEARCH",
        )?;
        if response.status != 200 {
            return Err(ReCtmError::new(
                "RESEARCH_SERVICE_ERROR",
                "The theorem-search service returned a non-success status.",
            )
            .with_category(ErrorCategory::Runtime)
            .with_retryable(response.status >= 500)
            .with_details(serde_json::json!({"status":response.status})));
        }
        if !response.content_type.to_ascii_lowercase().contains("json") {
            return Err(protocol_error(
                "RESEARCH_SERVICE_PROTOCOL_ERROR",
                "The theorem-search service returned a non-JSON content type.",
            ));
        }
        let raw: Value = serde_json::from_slice(&response.body).map_err(|_| {
            protocol_error(
                "RESEARCH_SERVICE_PROTOCOL_ERROR",
                "The theorem-search service returned invalid JSON.",
            )
        })?;
        let rows = raw.as_array().ok_or_else(|| {
            protocol_error(
                "RESEARCH_SERVICE_PROTOCOL_ERROR",
                "The theorem-search response must be a JSON array.",
            )
        })?;
        let results = rows
            .iter()
            .take(request.num_results)
            .filter_map(|item| item.as_object())
            .filter_map(|item| {
                let result = serde_json::json!({
                    "title":bounded_text(item.get("title"),1000),
                    "theorem":bounded_text(item.get("theorem"),20_000),
                    "arxiv_id":bounded_text(item.get("arxiv_id"),200),
                    "theorem_id":bounded_text(item.get("theorem_id"),500),
                    "paper_id":bounded_text(item.get("paper_id"),500),
                });
                let useful = !result["title"].as_str().unwrap_or_default().is_empty()
                    || !result["theorem"].as_str().unwrap_or_default().is_empty();
                useful.then_some(result)
            })
            .collect::<Vec<_>>();
        Ok(serde_json::json!({
            "query":query,"search_intent":request.search_intent,"count":results.len(),"results":results,
            "endpoint":self.theorem_endpoint.as_str(),"source_trust":"external_unverified",
            "usage_rule":"Read the paper context and proof, expand local definitions, and verify applicability before relying on any returned statement."
        }))
    }

    fn paper_search(&self, request: &ResearchRequest) -> Result<Value, ReCtmError> {
        validate_num_results(request.num_results)?;
        let search_text = [
            request.author.trim(),
            request.title.trim(),
            request.keywords.trim(),
            request.query.trim(),
        ]
        .into_iter()
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
        if search_text.is_empty() {
            return Err(validation(
                "paper search requires query, author, title, or keywords",
            ));
        }
        let mut url = self.paper_endpoint.clone();
        url.query_pairs_mut()
            .append_pair("search", &search_text)
            .append_pair("per-page", &request.num_results.to_string());
        let response = self.http("GET", url, None, "api.openalex.org", "PAPER_SEARCH")?;
        let raw = parse_paper_json(response)?;
        let rows = raw
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                protocol_error(
                    "PAPER_SEARCH_PROTOCOL_ERROR",
                    "OpenAlex paper search response did not contain a results array.",
                )
            })?;
        let results = rows
            .iter()
            .take(request.num_results)
            .filter_map(normalize_openalex_work)
            .collect::<Vec<_>>();
        Ok(serde_json::json!({
            "query":search_text,"count":results.len(),"results":results,"endpoint":self.paper_endpoint.as_str(),
            "source_trust":"external_unverified",
            "usage_rule":"Bibliographic metadata is discovery evidence only; inspect source context before relying on mathematical claims."
        }))
    }

    fn paper_lookup(&self, request: &ResearchRequest) -> Result<Value, ReCtmError> {
        let identifier = request.query.trim();
        if identifier.is_empty() {
            return Err(validation("paper identifier is required"));
        }
        let mut value = identifier.to_owned();
        if let Some(id) = value.strip_prefix("https://openalex.org/") {
            value = id.to_owned();
        }
        let path = if value
            .strip_prefix(['W', 'w'])
            .is_some_and(|digits| !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()))
        {
            value.to_ascii_uppercase()
        } else if value.starts_with("10.") {
            format!("https://doi.org/{value}")
        } else {
            return Err(validation(
                "paper_lookup identifier must be an OpenAlex W-id or DOI",
            ));
        };
        let mut url = self.paper_endpoint.clone();
        url.path_segments_mut()
            .map_err(|_| internal("OpenAlex endpoint cannot accept path segments"))?
            .push(&path);
        let raw =
            parse_paper_json(self.http("GET", url, None, "api.openalex.org", "PAPER_SEARCH")?)?;
        let result = normalize_openalex_work(&raw).ok_or_else(|| {
            protocol_error(
                "PAPER_LOOKUP_PROTOCOL_ERROR",
                "OpenAlex paper lookup returned no work.",
            )
        })?;
        Ok(serde_json::json!({
            "query":identifier,"count":1,"results":[result],"endpoint":self.paper_endpoint.as_str(),
            "source_trust":"external_unverified",
            "usage_rule":"Bibliographic metadata is discovery evidence only; inspect source context before relying on mathematical claims."
        }))
    }

    fn http(
        &self,
        method: &str,
        url: Url,
        body: Option<String>,
        expected_host: &str,
        family: &str,
    ) -> Result<HttpResult, ReCtmError> {
        if url.scheme() != "https" || url.host_str() != Some(expected_host) {
            return Err(ReCtmError::new(
                if family == "PAPER_SEARCH" {
                    "PAPER_SEARCH_URL_DENIED"
                } else {
                    "RESEARCH_REDIRECT_DENIED"
                },
                "Research request left the configured HTTPS trust domain.",
            )
            .with_category(ErrorCategory::Security));
        }
        let mut argv = vec![
            self.curl.display().to_string(),
            "--silent".to_owned(),
            "--show-error".to_owned(),
            "--location".to_owned(),
            "--max-redirs".to_owned(),
            "3".to_owned(),
            "--proto".to_owned(),
            "=https".to_owned(),
            "--proto-redir".to_owned(),
            "=https".to_owned(),
            "--max-time".to_owned(),
            self.timeout_seconds.to_string(),
            "--request".to_owned(),
            method.to_owned(),
            "--header".to_owned(),
            "Accept: application/json".to_owned(),
            "--user-agent".to_owned(),
            "MTM-reboot/0.1 research".to_owned(),
        ];
        let stdin = if let Some(body) = body {
            argv.extend([
                "--header".to_owned(),
                "Content-Type: application/json".to_owned(),
                "--data-binary".to_owned(),
                "@-".to_owned(),
            ]);
            body
        } else {
            String::new()
        };
        argv.extend([
            "--write-out".to_owned(),
            format!("{META_SENTINEL}%{{http_code}}\t%{{content_type}}\t%{{url_effective}}"),
            url.to_string(),
        ]);
        let mut result = self.commands.start(CommandRequest {
            argv,
            env: BTreeMap::new(),
            timeout_ms: self.timeout_seconds.saturating_mul(1000),
            yield_time_ms: 30_000,
            max_output_bytes: MAX_RESPONSE_BYTES + 32_768,
            stdin,
            tty: false,
            verbosity: None,
            preview_bytes: 4096,
        })?;
        let command_id = result
            .get("command_id")
            .and_then(Value::as_str)
            .map(str::to_owned);
        while result.get("status").and_then(Value::as_str) == Some("running") {
            result = self.commands.poll(PollRequest {
                command_id: command_id
                    .clone()
                    .ok_or_else(|| internal("research command id is missing"))?,
                chars: String::new(),
                yield_time_ms: 30_000,
                max_output_bytes: MAX_RESPONSE_BYTES + 32_768,
                verbosity: None,
                preview_bytes: 4096,
            })?;
        }
        if result.get("exit_code").and_then(Value::as_i64) != Some(0) {
            let code = if family == "PAPER_SEARCH" {
                "PAPER_SEARCH_UNAVAILABLE"
            } else {
                "RESEARCH_SERVICE_UNAVAILABLE"
            };
            return Err(ReCtmError::new(
                code,
                if family == "PAPER_SEARCH" {
                    "The paper-search service could not be reached."
                } else {
                    "The theorem-search service could not be reached."
                },
            )
            .with_category(ErrorCategory::Runtime)
            .with_retryable(true));
        }
        let stdout = result
            .get("stdout")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let (body, metadata) = stdout.rsplit_once(META_SENTINEL).ok_or_else(|| {
            protocol_error(
                if family == "PAPER_SEARCH" {
                    "PAPER_SEARCH_PROTOCOL_ERROR"
                } else {
                    "RESEARCH_SERVICE_PROTOCOL_ERROR"
                },
                "Research HTTP metadata was missing.",
            )
        })?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(ReCtmError::new(
                "RESEARCH_RESPONSE_TOO_LARGE",
                "The research response exceeded the configured limit.",
            )
            .with_category(ErrorCategory::Runtime));
        }
        let mut fields = metadata.splitn(3, '\t');
        let status = fields
            .next()
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| internal("curl status metadata is invalid"))?;
        let content_type = fields.next().unwrap_or_default().to_owned();
        let final_url = Url::parse(fields.next().unwrap_or_default().trim())
            .map_err(|_| internal("curl final URL metadata is invalid"))?;
        if final_url.scheme() != "https" || final_url.host_str() != Some(expected_host) {
            return Err(ReCtmError::new(
                if family == "PAPER_SEARCH" {
                    "PAPER_SEARCH_URL_DENIED"
                } else {
                    "RESEARCH_REDIRECT_DENIED"
                },
                if family == "PAPER_SEARCH" {
                    "Paper retrieval redirect left the fixed OpenAlex trust domain."
                } else {
                    "The theorem-search response left the configured HTTPS trust domain."
                },
            )
            .with_category(ErrorCategory::Security));
        }
        Ok(HttpResult {
            status,
            content_type,
            body: body.as_bytes().to_vec(),
        })
    }
}

impl ResearchProvider for CurlResearchProvider {
    fn retrieve(&self, request: &ResearchRequest) -> Result<Value, ReCtmError> {
        match request.operation.as_str() {
            "theorem_search" => self.theorem_search(request),
            "paper_search" => self.paper_search(request),
            "paper_lookup" => self.paper_lookup(request),
            operation => Err(validation_details(
                "unsupported retrieval operation",
                serde_json::json!({"operation":operation}),
            )),
        }
    }
}

struct HttpResult {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

fn parse_paper_json(response: HttpResult) -> Result<Value, ReCtmError> {
    if response.status != 200 {
        return Err(ReCtmError::new(
            "PAPER_SEARCH_ERROR",
            "The paper-search service returned a non-success status.",
        )
        .with_category(ErrorCategory::Runtime)
        .with_retryable(response.status >= 500)
        .with_details(serde_json::json!({"status":response.status})));
    }
    if !response.content_type.to_ascii_lowercase().contains("json") {
        return Err(protocol_error(
            "PAPER_SEARCH_PROTOCOL_ERROR",
            "Paper search returned non-JSON content.",
        ));
    }
    serde_json::from_slice(&response.body).map_err(|_| {
        protocol_error(
            "PAPER_SEARCH_PROTOCOL_ERROR",
            "Paper search returned invalid JSON.",
        )
    })
}

fn normalize_openalex_work(value: &Value) -> Option<Value> {
    let object = value.as_object()?;
    let authors = object
        .get("authorships")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(50)
        .filter_map(|item| item.get("author")?.get("display_name")?.as_str())
        .map(|name| Value::String(name.chars().take(500).collect()))
        .collect::<Vec<_>>();
    let primary = object
        .get("primary_location")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let open_access = object
        .get("open_access")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let doi = bounded_text(object.get("doi"), 1000)
        .strip_prefix("https://doi.org/")
        .unwrap_or(&bounded_text(object.get("doi"), 1000))
        .to_owned();
    let id = bounded_text(object.get("id"), 1000);
    Some(serde_json::json!({
        "title":bounded_text(object.get("display_name").or_else(||object.get("title")),2000),
        "paper_id":id.rsplit('/').next().unwrap_or_default(),"doi":doi,
        "publication_year":object.get("publication_year").cloned().unwrap_or(Value::Null),"authors":authors,
        "source_uri":id,"landing_page_url":bounded_text(primary.get("landing_page_url"),2000),
        "open_access_url":bounded_text(open_access.get("oa_url"),2000)
    }))
}

fn validate_endpoint(value: &str, required_host: Option<&str>) -> Result<Url, ReCtmError> {
    let url = Url::parse(value).map_err(|_| security_endpoint(required_host))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || required_host.is_some_and(|host| url.host_str() != Some(host))
    {
        return Err(security_endpoint(required_host));
    }
    Ok(url)
}

fn security_endpoint(required_host: Option<&str>) -> ReCtmError {
    if required_host.is_some() {
        ReCtmError::new(
            "INVALID_PAPER_SEARCH_ENDPOINT",
            "Paper search must use the fixed HTTPS api.openalex.org trust domain.",
        )
        .with_category(ErrorCategory::Security)
    } else {
        ReCtmError::new(
            "INVALID_RESEARCH_ENDPOINT",
            "The theorem-search endpoint must be an absolute HTTPS URL without user info.",
        )
        .with_category(ErrorCategory::Security)
    }
}

fn validate_num_results(value: usize) -> Result<(), ReCtmError> {
    if (1..=50).contains(&value) {
        Ok(())
    } else {
        Err(validation("num_results must be between 1 and 50"))
    }
}

fn bounded_text(value: Option<&Value>, maximum: usize) -> String {
    value
        .map(|value| match value {
            Value::String(text) => text.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        })
        .unwrap_or_default()
        .chars()
        .take(maximum)
        .collect()
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    })
}

fn protocol_error(code: &str, message: &str) -> ReCtmError {
    ReCtmError::new(code, message).with_category(ErrorCategory::Runtime)
}

fn validation(message: &str) -> ReCtmError {
    ReCtmError::new("INVALID_ARGUMENT", message).with_category(ErrorCategory::Validation)
}

fn validation_details(message: &str, details: Value) -> ReCtmError {
    validation(message).with_details(details)
}

fn internal(message: &str) -> ReCtmError {
    ReCtmError::new("INTERNAL_ERROR", message).with_category(ErrorCategory::Internal)
}

fn json_error(error: serde_json::Error) -> ReCtmError {
    ReCtmError::new("RESEARCH_JSON_ERROR", error.to_string()).with_category(ErrorCategory::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_fail_closed() {
        assert!(CurlResearchProvider::new("http://example.com", 30).is_err());
        assert!(validate_endpoint("https://evil.example/works", Some("api.openalex.org")).is_err());
    }
}
