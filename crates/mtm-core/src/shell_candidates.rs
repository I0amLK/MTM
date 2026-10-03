//! Narrow shell-list/for-loop collection. Quotes remain attached to source
//! segments until their boundaries are known; shell_words is NOT a shell lexer.
//! Complex grammar retains the preexisting collection path, not partial success.
use super::{
    append_segment_candidates, executable_basename, is_shell_executable,
    shell_executable_candidates, shell_script_argument,
};
use mtm_contracts::{ErrorCategory, ReCtmError};

pub(super) fn simple_candidates(
    command: &str,
    depth: usize,
) -> Result<Option<Vec<String>>, ReCtmError> {
    let Some(segments) = crate::shell_segments::executable_command_segments(command)? else {
        return Ok(None);
    };
    // Do not reinterpret other compound grammars as a partially parsed for-loop.
    if segments.iter().any(|segment| {
        [
            "if", "then", "elif", "else", "fi", "while", "until", "case", "esac", "select",
            "function",
        ]
        .iter()
        .any(|keyword| keyword_rest(segment.trim(), keyword).is_some())
    }) {
        return Ok(None);
    }
    let mut candidates = Vec::new();
    let mut loops = Vec::new(); // true: header awaits 'do'; false: inside body.
    for segment in segments {
        let mut segment = segment.trim();
        if let Some(rest) = keyword_rest(segment, "do") {
            match loops.last_mut() {
                Some(waiting @ true) => *waiting = false,
                _ => return Err(parse_error()),
            }
            segment = rest.trim_start();
        } else if loops.last() == Some(&true) {
            return Err(parse_error());
        }
        if ["if", "while", "until", "case", "select", "function"]
            .iter()
            .any(|keyword| keyword_rest(segment, keyword).is_some())
        {
            return Ok(None);
        }
        if keyword_rest(segment, "for").is_some() {
            let words = split(segment)?;
            if words.len() < 2
                || !variable_name(&words[1])
                || words.len() > 2 && words[2] != "in"
                || loops.len() >= 32
            {
                return Err(parse_error());
            }
            loops.push(true);
        } else if let Some(rest) = keyword_rest(segment, "done") {
            if !rest.trim().is_empty() || loops.pop() != Some(false) {
                return Err(parse_error());
            }
        } else if !segment.is_empty() {
            append_simple(&split(segment)?, depth, &mut candidates)?;
        }
    }
    if !loops.is_empty() {
        return Err(parse_error());
    }
    Ok(Some(candidates))
}

fn append_simple(
    words: &[String],
    depth: usize,
    output: &mut Vec<String>,
) -> Result<(), ReCtmError> {
    let Some(first) = words.first() else {
        return Ok(());
    };
    if first == "command" {
        let mut cursor = 1;
        let mut query = false;
        let mut default_path = false;
        while let Some(option) = words.get(cursor) {
            if option == "--" {
                cursor += 1;
                break;
            }
            let Some(flags) = option.strip_prefix('-') else {
                break;
            };
            if flags.is_empty() || !flags.bytes().all(|b| matches!(b, b'p' | b'v' | b'V')) {
                return Err(parse_error());
            }
            query |= flags.contains(['v', 'V']);
            default_path |= flags.contains('p');
            cursor += 1;
        }
        if query {
            // command -v/-V describes a name; it never runs that target.
            return Ok(());
        }
        if default_path {
            // -p execution changes PATH semantics; do not inspect the wrong file.
            return Err(parse_error());
        }
        if cursor < words.len() {
            if depth >= 4 {
                return Err(parse_error());
            }
            return append_simple(&words[cursor..], depth + 1, output);
        }
        return Ok(());
    }
    if first.contains('/')
        && !matches!(
            executable_basename(first).as_str(),
            "env" | "exec" | "nohup" | "setsid" | "time"
        )
    {
        // /some/path/command is an external file, never the command builtin.
        output.push(first.clone());
        if is_shell_executable(first)
            && let Some(script) = shell_script_argument(words)
        {
            output.extend(shell_executable_candidates(script, depth + 1)?);
        }
        return Ok(());
    }
    append_segment_candidates(words, depth, output)
}

fn keyword_rest<'a>(segment: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = segment.strip_prefix(keyword)?;
    (rest.is_empty() || rest.starts_with(char::is_whitespace)).then_some(rest)
}

fn variable_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || index > 0 && byte.is_ascii_digit()
        })
}

fn split(segment: &str) -> Result<Vec<String>, ReCtmError> {
    shell_words::split(segment).map_err(|_| parse_error())
}

fn parse_error() -> ReCtmError {
    ReCtmError::new("NATIVE_EXECUTABLE_PARSE_FAILED",
        "Shell command collection requires supported literal lists, bounded for loops and command queries; use literal argv for unsupported syntax.")
        .with_category(ErrorCategory::Security)
}

#[cfg(test)]
#[path = "shell_candidates_tests.rs"]
mod tests;
