use std::collections::HashSet;

use mtm_contracts::{ErrorCategory, ReCtmError, invalid_argument};
use regex::Regex;
use serde_json::Value;
use url::Url;

const MAX_REDIRECT_URIS: usize = 10;
const URL_CANDIDATE_PATTERN: &str = r#"https://[^\s<>\"']+"#;
const TRY_CLOUDFLARE_HOST_PATTERN: &str = r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.trycloudflare\.com$";

pub fn validate_oauth_server_url(value: &str) -> Result<(), ReCtmError> {
    let parsed = Url::parse(value).map_err(|_| malformed_oauth_url())?;
    let hostname = parsed.host_str().ok_or_else(malformed_oauth_url)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || has_userinfo(value)
        || parsed.query().is_some_and(|query| !query.is_empty())
        || parsed
            .fragment()
            .is_some_and(|fragment| !fragment.is_empty())
        || parsed.path() != "/"
    {
        return Err(ReCtmError::new(
            "OAUTH_SERVER_URL_INVALID",
            "OAuth server URL must be an origin URL without user info, path, query, or fragment.",
        )
        .with_category(ErrorCategory::Validation));
    }
    if parsed.scheme() == "http" && !is_loopback_hostname(hostname) {
        return Err(ReCtmError::new(
            "OAUTH_SERVER_URL_INVALID",
            "OAuth server URL must be HTTPS or a loopback HTTP URL.",
        )
        .with_category(ErrorCategory::Validation));
    }
    Ok(())
}

pub fn validate_redirect_uris(value: &Value) -> Result<Vec<String>, ReCtmError> {
    let items = value
        .as_array()
        .filter(|items| !items.is_empty() && items.len() <= MAX_REDIRECT_URIS);
    let items = items.ok_or_else(|| {
        invalid_argument(format!(
            "redirect_uris must contain between 1 and {MAX_REDIRECT_URIS} entries"
        ))
    })?;
    let mut redirects = Vec::with_capacity(items.len());
    let mut seen = HashSet::with_capacity(items.len());
    for item in items {
        let text = item.as_str().filter(|text| text.chars().count() <= 2048);
        let text = text.ok_or_else(|| {
            invalid_argument("redirect_uri must be a string of at most 2048 characters")
        })?;
        let parsed = Url::parse(text)
            .map_err(|_| invalid_argument("redirect_uri must be absolute and have no fragment"))?;
        let hostname = parsed.host_str().ok_or_else(|| {
            invalid_argument("redirect_uri must be absolute and have no fragment")
        })?;
        if parsed
            .fragment()
            .is_some_and(|fragment| !fragment.is_empty())
        {
            return Err(invalid_argument(
                "redirect_uri must be absolute and have no fragment",
            ));
        }
        if has_userinfo(text) {
            return Err(invalid_argument(
                "redirect_uri must not contain user information",
            ));
        }
        if parsed.scheme() == "http" && !is_loopback_hostname(hostname) {
            return Err(invalid_argument(
                "HTTP redirect_uri is allowed only for loopback hosts",
            ));
        }
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(invalid_argument(
                "redirect_uri must use HTTPS or loopback HTTP",
            ));
        }
        if !seen.insert(text.to_owned()) {
            return Err(invalid_argument("redirect_uris must be unique"));
        }
        redirects.push(text.to_owned());
    }
    Ok(redirects)
}

pub fn extract_quick_tunnel_origin(text: &str) -> Result<Option<String>, ReCtmError> {
    let candidate_regex = Regex::new(URL_CANDIDATE_PATTERN).map_err(internal_regex_error)?;
    let host_regex = Regex::new(TRY_CLOUDFLARE_HOST_PATTERN).map_err(internal_regex_error)?;
    for candidate_match in candidate_regex.find_iter(text) {
        let candidate = candidate_match
            .as_str()
            .trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '}']);
        let Ok(parsed) = Url::parse(candidate) else {
            continue;
        };
        let Some(hostname) = parsed.host_str() else {
            continue;
        };
        let hostname = hostname.to_ascii_lowercase();
        let hostname = hostname.trim_end_matches('.');
        if parsed.scheme() != "https"
            || has_userinfo(candidate)
            || !matches!(parsed.port(), None | Some(443))
            || !host_regex.is_match(hostname)
        {
            continue;
        }
        return Ok(Some(format!("https://{hostname}")));
    }
    Ok(None)
}

fn malformed_oauth_url() -> ReCtmError {
    ReCtmError::new("OAUTH_SERVER_URL_INVALID", "OAuth server URL is malformed.")
        .with_category(ErrorCategory::Validation)
}

fn is_loopback_hostname(hostname: &str) -> bool {
    let hostname = hostname.trim_matches(['[', ']']);
    matches!(
        hostname.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1"
    )
}

fn has_userinfo(value: &str) -> bool {
    let Some((_, remainder)) = value.split_once("://") else {
        return false;
    };
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
    authority.contains('@')
}

fn internal_regex_error(error: regex::Error) -> ReCtmError {
    ReCtmError::new(
        "INTERNAL_REGEX_ERROR",
        format!("Internal URL pattern is invalid: {error}"),
    )
    .with_category(ErrorCategory::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_origin_policy_matches_source_rules() {
        assert!(validate_oauth_server_url("https://example.com").is_ok());
        assert!(validate_oauth_server_url("http://127.0.0.1:8765").is_ok());
        assert_eq!(
            validate_oauth_server_url("http://example.com").map_err(|error| error.message),
            Err("OAuth server URL must be HTTPS or a loopback HTTP URL.".to_owned())
        );
    }

    #[test]
    fn quick_tunnel_parser_is_strict() -> Result<(), ReCtmError> {
        assert_eq!(
            extract_quick_tunnel_origin(
                "INF https://alpha-beta.trycloudflare.com/path, connected"
            )?,
            Some("https://alpha-beta.trycloudflare.com".to_owned())
        );
        assert_eq!(
            extract_quick_tunnel_origin("https://evil.example.com")?,
            None
        );
        assert_eq!(
            extract_quick_tunnel_origin("http://alpha.trycloudflare.com")?,
            None
        );
        Ok(())
    }
}
