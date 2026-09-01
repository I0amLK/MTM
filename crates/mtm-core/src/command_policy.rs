use std::collections::BTreeMap;
use std::path::Path;

use mtm_contracts::{ErrorCategory, NativeMode, ReCtmError};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

const NETWORK_PATTERN: &str = r"(https?://|urllib\.request|urllib3|requests\.|http\.client|\bHTTPConnection\b|\bHTTPSConnection\b|socket\.|aiohttp|httpx|\bcurl\b|\bwget\b|\bnc\b|\bnetcat\b|\bssh\b|\bscp\b|\bftp\b)";
const SHELL_EXPANSION_PATTERN: &str = r"(`|\$\(|\$\{)";
const DESTRUCTIVE_PATTERN: &str = r"(^|\s)(sudo|su|chmod\s+-R|chown\s+-R|mkfs|mount|umount|find\b[^;&|]*\s-delete\b|git\b[^;&|]*\breset\s+--hard\b|git\b[^;&|]*\bclean\s+-[^\s]*[fx][^\s]*|rm\s+-[^\s]*r[^\s]*f|rm\s+-[^\s]*f[^\s]*r)\b";
const SENSITIVE_ENV_PATTERN: &str =
    r"(token|secret|credential|api[_-]?key|password|passwd|private)";
const SENSITIVE_VALUE_PATTERN: &str = r"(COMPLIANCE_SHOULD_NOT_LEAK|-----BEGIN [A-Z ]*PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16})";

const RISKY_ENV_NAMES: [&str; 12] = [
    "BASH_ENV",
    "ENV",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "NODE_OPTIONS",
    "PERL5LIB",
    "PERL5OPT",
    "RUBYOPT",
    "RUBYLIB",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InlineScript {
    pub command: String,
    pub option: String,
}

pub fn check_command_policy(
    mode: NativeMode,
    command: &str,
    environment: &BTreeMap<String, String>,
) -> Result<(), ReCtmError> {
    if mode == NativeMode::Dangerous {
        return Ok(());
    }

    let mut filtered = environment
        .iter()
        .filter_map(|(key, value)| match is_filtered_env_var(key, value) {
            Ok(true) => Some(Ok(key.clone())),
            Ok(false) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    filtered.sort();
    if !filtered.is_empty() {
        let mut details = permission_details("sensitive_env");
        details.insert(
            "env_keys".to_owned(),
            Value::Array(filtered.into_iter().map(Value::String).collect()),
        );
        return Err(permission_required(
            "Sensitive or loader/startup environment variables require explicit permission.",
            details,
        ));
    }

    if case_insensitive_regex(DESTRUCTIVE_PATTERN)?.is_match(command) {
        return Err(permission_required(
            "Destructive commands are blocked without explicit permission.",
            permission_details("destructive_command"),
        ));
    }
    if mode == NativeMode::Trusted {
        return Ok(());
    }
    if Regex::new(SHELL_EXPANSION_PATTERN)
        .map_err(internal_regex_error)?
        .is_match(command)
    {
        return Err(permission_required(
            "Shell command substitution and parameter expansion require explicit permission.",
            permission_details("shell_expansion"),
        ));
    }
    if let Some(inline) = inline_script_command(command) {
        let mut details = permission_details("inline_script");
        details.insert("command".to_owned(), Value::String(inline.command));
        details.insert("option".to_owned(), Value::String(inline.option));
        return Err(permission_required(
            "Inline interpreter or shell code requires explicit permission.",
            details,
        ));
    }
    if case_insensitive_regex(NETWORK_PATTERN)?.is_match(command) {
        return Err(permission_required(
            "Network access is denied by default.",
            permission_details("network"),
        ));
    }
    Ok(())
}

pub fn is_filtered_env_var(name: &str, value: &str) -> Result<bool, ReCtmError> {
    let upper = name.to_ascii_uppercase();
    let risky = RISKY_ENV_NAMES.contains(&upper.as_str()) || upper.starts_with("DYLD_");
    Ok(
        case_insensitive_regex(SENSITIVE_ENV_PATTERN)?.is_match(name)
            || risky
            || Regex::new(SENSITIVE_VALUE_PATTERN)
                .map_err(internal_regex_error)?
                .is_match(value),
    )
}

#[must_use]
pub fn inline_script_command(command: &str) -> Option<InlineScript> {
    let tokens = shell_words::split(command)
        .unwrap_or_else(|_| command.split_whitespace().map(str::to_owned).collect());
    let mut segments: Vec<Vec<String>> = vec![Vec::new()];
    for token in tokens {
        if matches!(token.as_str(), "|" | "||" | "&" | "&&" | ";") {
            segments.push(Vec::new());
        } else if let Some(segment) = segments.last_mut() {
            segment.push(token);
        }
    }

    for mut segment in segments {
        if segment.is_empty() {
            continue;
        }
        while segment
            .first()
            .is_some_and(|item| item.contains('=') && !item.starts_with('='))
        {
            segment.remove(0);
        }
        if segment.is_empty() {
            continue;
        }

        let mut name = executable_name(&segment[0]);
        let mut args = segment.into_iter().skip(1).collect::<Vec<_>>();
        if name == "env" {
            while args
                .first()
                .is_some_and(|item| item.starts_with('-') || item.contains('='))
            {
                args.remove(0);
            }
            if let Some(executable) = args.first() {
                name = executable_name(executable);
                args.remove(0);
            }
        }

        if matches!(name.as_str(), "bash" | "sh" | "zsh")
            && let Some(option) = args.iter().find(|argument| {
                argument.starts_with('-') && argument.trim_start_matches('-').contains('c')
            })
        {
            return Some(InlineScript {
                command: name,
                option: option.clone(),
            });
        }
        if matches!(name.as_str(), "python" | "python3") {
            if args.iter().any(|argument| argument == "-c") {
                return Some(InlineScript {
                    command: name,
                    option: "-c".to_owned(),
                });
            }
            if args.iter().any(|argument| argument == "-") {
                return Some(InlineScript {
                    command: name,
                    option: "-".to_owned(),
                });
            }
        }
        if name == "node" {
            for option in ["-e", "--eval", "-p", "--print"] {
                if args.iter().any(|argument| argument == option) {
                    return Some(InlineScript {
                        command: name,
                        option: option.to_owned(),
                    });
                }
            }
        }
        if matches!(name.as_str(), "ruby" | "perl") && args.iter().any(|argument| argument == "-e")
        {
            return Some(InlineScript {
                command: name,
                option: "-e".to_owned(),
            });
        }
    }
    None
}

fn executable_name(value: &str) -> String {
    let normalized = value.replace('\\', "/");
    Path::new(&normalized)
        .file_name()
        .and_then(|name| name.to_str())
        .map_or_else(String::new, str::to_lowercase)
}

fn permission_details(permission: &str) -> Map<String, Value> {
    let mut details = Map::new();
    details.insert(
        "permission".to_owned(),
        Value::String(permission.to_owned()),
    );
    details
}

fn permission_required(message: &str, details: Map<String, Value>) -> ReCtmError {
    ReCtmError::new("PERMISSION_REQUIRED", message)
        .with_category(ErrorCategory::Permission)
        .with_details(details)
}

fn case_insensitive_regex(pattern: &str) -> Result<Regex, ReCtmError> {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .map_err(internal_regex_error)
}

fn internal_regex_error(error: regex::Error) -> ReCtmError {
    ReCtmError::new(
        "INTERNAL_REGEX_ERROR",
        format!("Internal command policy pattern is invalid: {error}"),
    )
    .with_category(ErrorCategory::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn identifies_source_inline_interpreters() {
        assert_eq!(
            inline_script_command("env FOO=1 python3 -c 'print(1)'"),
            Some(InlineScript {
                command: "python3".to_owned(),
                option: "-c".to_owned(),
            })
        );
        assert_eq!(inline_script_command("python3 script.py"), None);
    }

    #[test]
    fn safe_policy_preserves_permission_order() {
        let environment = BTreeMap::new();
        let result =
            check_command_policy(NativeMode::Safe, "curl https://example.com", &environment);
        assert_eq!(
            result.map_err(|error| error.details.get("permission").cloned()),
            Err(Some(Value::String("network".to_owned())))
        );
    }

    #[test]
    fn filtered_environment_matches_source_facts() -> Result<(), ReCtmError> {
        let cases = BTreeSet::from([
            ("API_KEY", "plain", true),
            ("PATH", "plain", false),
            ("NODE_OPTIONS", "plain", true),
            ("VALUE", "sk-abcdefghijklmnop", true),
        ]);
        for (name, value, expected) in cases {
            assert_eq!(is_filtered_env_var(name, value)?, expected);
        }
        Ok(())
    }
}
