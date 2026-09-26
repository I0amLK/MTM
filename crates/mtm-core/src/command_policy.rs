use std::collections::BTreeMap;
use std::path::Path;

use mtm_contracts::{ErrorCategory, NativeMode, NativePermissionKind, ReCtmError};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

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

/// Enforce the command policy of the active Native mode.
///
/// The `dangerous` profile (the only mode since MTM-017) implicitly grants every
/// command permission kind, so no command is blocked here. Risk dimensions are
/// still classified by [`classify_command_permissions`] for permission records.
pub fn check_command_policy(
    mode: NativeMode,
    _command: &str,
    _environment: &BTreeMap<String, String>,
) -> Result<(), ReCtmError> {
    match mode {
        NativeMode::Dangerous => Ok(()),
    }
}

/// Classify every permission dimension exercised by a command, independent of mode.
///
/// The order (sensitive env, destructive, shell expansion, inline script, network)
/// is part of the recorded permission contract. Kinds that need runtime facts
/// (`long_timeout`, `privileged_executable`, `write_generated_or_ignored`) are
/// added by `native_permission`, not here.
pub fn classify_command_permissions(
    command: &str,
    environment: &BTreeMap<String, String>,
) -> Result<Vec<NativePermissionKind>, ReCtmError> {
    let mut needs = Vec::new();
    let filtered = environment
        .iter()
        .map(|(key, value)| is_filtered_env_var(key, value))
        .collect::<Result<Vec<_>, _>>()?;
    if filtered.into_iter().any(|item| item) {
        needs.push(NativePermissionKind::SensitiveEnv);
    }
    if destructive_command(command)? {
        needs.push(NativePermissionKind::DestructiveCommand);
    }
    if Regex::new(SHELL_EXPANSION_PATTERN)
        .map_err(internal_regex_error)?
        .is_match(command)
    {
        needs.push(NativePermissionKind::ShellExpansion);
    }
    if inline_script_command(command).is_some() {
        needs.push(NativePermissionKind::InlineScript);
    }
    if case_insensitive_regex(NETWORK_PATTERN)?.is_match(command) {
        needs.push(NativePermissionKind::Network);
    }
    Ok(needs)
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
    let segments = crate::shell_segments::literal_command_segments(command)
        .ok()
        .flatten()
        .and_then(|segments| {
            segments
                .into_iter()
                .map(shell_words::split)
                .collect::<Result<Vec<_>, _>>()
                .ok()
        })
        .unwrap_or_else(|| existing_command_segments(command));

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

fn destructive_command(command: &str) -> Result<bool, ReCtmError> {
    let pattern = case_insensitive_regex(DESTRUCTIVE_PATTERN)?;
    if pattern.is_match(command) {
        return Ok(true);
    }
    if let Some(segments) = crate::shell_segments::literal_command_segments(command)? {
        for segment in segments {
            let words = shell_words::split(segment).map_err(|_| {
                ReCtmError::new(
                    "NATIVE_EXECUTABLE_PARSE_FAILED",
                    "Invalid literal shell segment.",
                )
                .with_category(ErrorCategory::Security)
            })?;
            // Normalize escaped executable names while retaining argument quoting.
            if pattern.is_match(&shell_words::join(words)) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn existing_command_segments(command: &str) -> Vec<Vec<String>> {
    let tokens = shell_words::split(command)
        .unwrap_or_else(|_| command.split_whitespace().map(str::to_owned).collect());
    let mut segments = vec![Vec::new()];
    for token in tokens {
        if matches!(token.as_str(), "|" | "||" | "&" | "&&" | ";") {
            segments.push(Vec::new());
        } else if let Some(segment) = segments.last_mut() {
            segment.push(token);
        }
    }
    segments
}

fn executable_name(value: &str) -> String {
    let normalized = value.replace('\\', "/");
    Path::new(&normalized)
        .file_name()
        .and_then(|name| name.to_str())
        .map_or_else(String::new, str::to_lowercase)
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
    fn adjacent_commands_cannot_hide_destructive_or_inline_permissions() -> Result<(), ReCtmError> {
        let needs = classify_command_permissions(
            "printf ok;rm -rf build;python3 -c 'print(1)'",
            &BTreeMap::new(),
        )?;
        assert!(needs.contains(&NativePermissionKind::DestructiveCommand));
        assert!(needs.contains(&NativePermissionKind::InlineScript));
        Ok(())
    }

    #[test]
    fn quoted_arguments_are_not_commands_but_escaped_names_are_checked() -> Result<(), ReCtmError> {
        let environment = BTreeMap::new();
        assert!(
            !classify_command_permissions("printf '%s' 'rm -rf build'", &environment)?
                .contains(&NativePermissionKind::DestructiveCommand)
        );
        assert!(
            classify_command_permissions("printf ok;r\\m -rf build", &environment)?
                .contains(&NativePermissionKind::DestructiveCommand)
        );
        Ok(())
    }

    #[test]
    fn dangerous_policy_blocks_no_command() -> Result<(), ReCtmError> {
        let environment = BTreeMap::from([("API_TOKEN".to_owned(), "secret".to_owned())]);
        check_command_policy(
            NativeMode::Dangerous,
            "python3 -c 'print(1)' && curl https://example.com && rm -rf build",
            &environment,
        )
    }

    #[test]
    fn permission_classifier_preserves_recorded_order() -> Result<(), ReCtmError> {
        let environment = BTreeMap::from([("API_TOKEN".to_owned(), "secret".to_owned())]);
        let command =
            "python3 -c 'print(1)' && echo $(id) && curl https://example.com && rm -rf build";
        assert_eq!(
            classify_command_permissions(command, &environment)?,
            vec![
                NativePermissionKind::SensitiveEnv,
                NativePermissionKind::DestructiveCommand,
                NativePermissionKind::ShellExpansion,
                NativePermissionKind::InlineScript,
                NativePermissionKind::Network,
            ]
        );
        assert!(classify_command_permissions("printf ok", &BTreeMap::new())?.is_empty());
        Ok(())
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
