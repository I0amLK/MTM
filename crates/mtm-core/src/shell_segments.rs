//! Literal shell command-list boundaries shared by facts and risk classification.
//!
//! This is deliberately not a complete shell grammar. Complex constructs keep
//! their existing collection path until the separately tracked grammar work is
//! qualified. In particular, never interpret a heredoc body as a command list.
use mtm_contracts::{ErrorCategory, ReCtmError};

const MAX_SEGMENTS: usize = 1024;
const MAX_SOURCE_BYTES: usize = 1_048_576;

pub(crate) fn literal_command_segments(command: &str) -> Result<Option<Vec<&str>>, ReCtmError> {
    if command.len() > MAX_SOURCE_BYTES {
        return Err(parse_error("NATIVE_EXECUTABLE_PARSE_LIMIT"));
    }
    let mut quote = None;
    let mut escaped = false;
    let mut start = 0;
    let mut segments = Vec::new();
    for (index, ch) in command.char_indices() {
        if quote == Some('\'') {
            if ch == '\'' {
                quote = None;
            }
            continue;
        }
        if escaped {
            if ch == '\n' {
                return Ok(None);
            }
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if matches!(ch, '$' | '`') {
            return Ok(None);
        }
        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '\n' | '\r' | '<' | '>' | '(' | ')' | '{' | '}' | '#' => return Ok(None),
            ';' | '|' | '&' => {
                let segment = &command[start..index];
                if !segment.trim().is_empty() {
                    segments.push(segment);
                    if segments.len() > MAX_SEGMENTS {
                        return Err(parse_error("NATIVE_EXECUTABLE_PARSE_LIMIT"));
                    }
                }
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    if quote.is_some() || escaped {
        return Err(parse_error("NATIVE_EXECUTABLE_PARSE_FAILED"));
    }
    if !command[start..].trim().is_empty() {
        if segments.len() == MAX_SEGMENTS {
            return Err(parse_error("NATIVE_EXECUTABLE_PARSE_LIMIT"));
        }
        segments.push(&command[start..]);
    }
    Ok(Some(segments))
}

fn parse_error(code: &str) -> ReCtmError {
    ReCtmError::new(
        code,
        "Literal shell command boundaries could not be safely collected.",
    )
    .with_category(ErrorCategory::Security)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_and_escapes_do_not_become_operators() -> Result<(), ReCtmError> {
        assert_eq!(
            literal_command_segments("printf ';'\\;;pwd|cat&&true")?,
            Some(vec!["printf ';'\\;", "pwd", "cat", "true"])
        );
        assert_eq!(
            literal_command_segments("printf '数学;数据'")?,
            Some(vec!["printf '数学;数据'"])
        );
        Ok(())
    }

    #[test]
    fn complex_shell_syntax_does_not_get_a_partial_interpretation() -> Result<(), ReCtmError> {
        for command in [
            "cat <<'EOF'\nhello;not-a-command\nEOF",
            "printf ok > file;pwd",
            "printf \"$(pwd)\";pwd",
            "pwd\npwd",
            "pwd # ;comment",
        ] {
            assert!(literal_command_segments(command)?.is_none());
        }
        Ok(())
    }

    #[test]
    fn malformed_and_excessive_lists_fail_closed() {
        assert!(literal_command_segments("printf 'unterminated").is_err());
        assert!(literal_command_segments("pwd\\").is_err());
        assert!(literal_command_segments(&"pwd;".repeat(MAX_SEGMENTS + 1)).is_err());
    }
}
