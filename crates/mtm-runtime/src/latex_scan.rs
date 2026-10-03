//! Bounded lexical view for the static gate, not a TeX interpreter or sandbox.
//!
//! Mask comments and only explicitly supported literal constructs. Never strip
//! comments before finding a verbatim terminator: percent is literal there.
//! Configurations that can execute text or change its tokenization fail closed.

const ENVIRONMENTS: [&str; 4] = ["verbatim", "verbatim*", "Verbatim", "Verbatim*"];

pub(super) fn active_source(source: &str) -> Result<String, String> {
    let bytes = source.as_bytes();
    let mut view = bytes.to_vec();
    let mut cursor = 0;
    let mut depth = 0_usize;
    let mut literal_seen = false;
    let mut reconfigured = false;
    while cursor < bytes.len() {
        let start = cursor;
        match bytes[cursor] {
            b'%' => {
                cursor = line_end(bytes, cursor);
                mask(&mut view[start..cursor]);
            }
            b'{' => {
                depth += 1;
                cursor += 1;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
                cursor += 1;
            }
            b'^' if bytes.get(cursor + 1) == Some(&b'^') => {
                reconfigured = true;
                cursor += 2;
            }
            b'\\' => {
                cursor += 1;
                while bytes.get(cursor).is_some_and(u8::is_ascii_alphabetic) {
                    cursor += 1;
                }
                if cursor == start + 1 {
                    // A control symbol consumes its following character, so the
                    // second slash of \\\\ must not become an active \\begin/input.
                    if let Some(character) = source[cursor..].chars().next() {
                        cursor += character.len_utf8();
                        if character == '\\' {
                            mask(&mut view[start..cursor]);
                        }
                    }
                    continue;
                }
                let command = &source[start + 1..cursor];
                if changes_literal_semantics(command) {
                    reconfigured = true;
                }
                if command == "fvset" {
                    if let Some((options, end)) = group(source, cursor) {
                        reconfigured |= validate_options(options).is_err();
                        cursor = end;
                    } else {
                        reconfigured = true;
                    }
                } else if command == "verb" {
                    if depth != 0 {
                        return Err(unsupported("verb inside a braced argument"));
                    }
                    literal_seen = true;
                    cursor = inline_end(source, cursor)?;
                    mask(&mut view[start..cursor]);
                } else if command == "begin"
                    && let Some((environment, end)) = group(source, cursor)
                    && ENVIRONMENTS.contains(&environment)
                {
                    if depth != 0 || !line_prefix_is_whitespace(source, start) {
                        return Err(unsupported(
                            "literal environment must start on its own line outside a braced argument",
                        ));
                    }
                    literal_seen = true;
                    let body_start = environment_body(source, end, environment)?;
                    let terminator = format!("\\end{{{environment}}}");
                    let offset = source[body_start..].find(&terminator).ok_or_else(|| {
                        format!("unterminated LaTeX literal environment: {environment}")
                    })?;
                    // Stop at the FIRST raw terminator, even after '%' or '\\'.
                    // Requiring a whole-line end could hide active trailing TeX.
                    cursor = body_start + offset + terminator.len();
                    mask(&mut view[start..cursor]);
                }
            }
            _ => cursor += 1,
        }
    }
    if literal_seen && reconfigured {
        return Err(unsupported(
            "macro, environment or catcode reconfiguration with literal text",
        ));
    }
    String::from_utf8(view).map_err(|_| unsupported("invalid literal text boundary"))
}

fn line_end(bytes: &[u8], mut cursor: usize) -> usize {
    while cursor < bytes.len() && !matches!(bytes[cursor], b'\r' | b'\n') {
        cursor += 1;
    }
    cursor
}

fn mask(bytes: &mut [u8]) {
    for byte in bytes {
        if !matches!(byte, b'\r' | b'\n') {
            *byte = b' ';
        }
    }
}

fn group(source: &str, cursor: usize) -> Option<(&str, usize)> {
    let rest = &source[cursor..];
    let trimmed = rest.trim_start_matches(char::is_whitespace);
    let start = source.len() - trimmed.len();
    let body = trimmed.strip_prefix('{')?;
    let end = body.find('}')?;
    if body[..end].contains('{') {
        return None;
    }
    Some((&body[..end], start + end + 2))
}

fn line_prefix_is_whitespace(source: &str, cursor: usize) -> bool {
    let start = source[..cursor].rfind(['\n', '\r']).map_or(0, |i| i + 1);
    source[start..cursor]
        .bytes()
        .all(|b| matches!(b, b' ' | b'\t'))
}

fn environment_body(source: &str, mut cursor: usize, name: &str) -> Result<usize, String> {
    let bytes = source.as_bytes();
    while bytes.get(cursor).is_some_and(|b| matches!(b, b' ' | b'\t')) {
        cursor += 1;
    }
    if name.starts_with('V') && bytes.get(cursor) == Some(&b'[') {
        let end = source[cursor + 1..]
            .find(']')
            .ok_or_else(|| unsupported("unterminated Verbatim options"))?
            + cursor
            + 1;
        validate_options(&source[cursor + 1..end])?;
        cursor = end + 1;
        while bytes.get(cursor).is_some_and(|b| matches!(b, b' ' | b'\t')) {
            cursor += 1;
        }
    }
    if !bytes
        .get(cursor)
        .is_some_and(|b| matches!(b, b'\n' | b'\r'))
    {
        return Err(unsupported(
            "literal environment header must end with a newline",
        ));
    }
    Ok(cursor + 1)
}

fn inline_end(source: &str, mut cursor: usize) -> Result<usize, String> {
    let bytes = source.as_bytes();
    if bytes.get(cursor) == Some(&b'*') {
        cursor += 1;
    }
    let delimiter = *bytes
        .get(cursor)
        .ok_or_else(|| unsupported("missing verb delimiter"))?;
    if !delimiter.is_ascii_graphic() || delimiter.is_ascii_alphabetic() {
        return Err(unsupported("verb requires a non-letter ASCII delimiter"));
    }
    let end = line_end(bytes, cursor);
    bytes[cursor + 1..end]
        .iter()
        .position(|b| *b == delimiter)
        .map(|offset| cursor + offset + 2)
        .ok_or_else(|| unsupported("unterminated verb before line end"))
}

fn validate_options(options: &str) -> Result<(), String> {
    if options.len() > 4096 {
        return Err(unsupported("Verbatim options exceed 4096 bytes"));
    }
    for option in options.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (key, value) = option
            .split_once('=')
            .map_or((option, "true"), |(k, v)| (k.trim(), v.trim()));
        let valid = match key {
            "frame" => matches!(
                value,
                "none" | "single" | "lines" | "leftline" | "topline" | "bottomline"
            ),
            "numbers" => matches!(value, "none" | "left" | "right"),
            "fontsize" => matches!(
                value,
                "\\tiny"
                    | "\\scriptsize"
                    | "\\footnotesize"
                    | "\\small"
                    | "\\normalsize"
                    | "\\large"
                    | "\\Large"
                    | "\\LARGE"
                    | "\\huge"
                    | "\\Huge"
            ),
            "showspaces" | "showtabs" | "resetmargins" | "samepage" => {
                matches!(value, "true" | "false")
            }
            "tabsize" => value.parse::<u8>().is_ok_and(|n| (1..=64).contains(&n)),
            "gobble" => value.parse::<u8>().is_ok_and(|n| n <= 9),
            "numbersep" | "framesep" | "framerule" | "xleftmargin" | "xrightmargin" => {
                literal_dimension(value)
            }
            _ => false,
        };
        if !valid {
            return Err(unsupported(
                "only documented literal formatting options are supported; executable or unknown options are refused",
            ));
        }
    }
    Ok(())
}

fn literal_dimension(value: &str) -> bool {
    ["pt", "em", "ex", "mm", "cm", "in"].iter().any(|unit| {
        value.strip_suffix(unit).is_some_and(|number| {
            let number = number.strip_prefix('-').unwrap_or(number);
            !number.is_empty()
                && number.bytes().any(|b| b.is_ascii_digit())
                && number.bytes().all(|b| b.is_ascii_digit() || b == b'.')
                && number.bytes().filter(|b| *b == b'.').count() <= 1
        })
    })
}

fn changes_literal_semantics(command: &str) -> bool {
    command.starts_with("if")
        || matches!(
            command,
            "catcode"
                | "endlinechar"
                | "escapechar"
                | "scantokens"
                | "ExplSyntaxOn"
                | "makeatletter"
                | "setkeys"
                | "AddToHook"
                | "AddToHookNext"
                | "AtBeginEnvironment"
                | "BeforeBeginEnvironment"
                | "csname"
                | "def"
                | "gdef"
                | "edef"
                | "xdef"
                | "let"
                | "futurelet"
                | "renewcommand"
                | "renewenvironment"
                | "newenvironment"
                | "provideenvironment"
                | "DeclareRobustCommand"
                | "DefineVerbatimEnvironment"
                | "CustomVerbatimEnvironment"
                | "RecustomVerbatimEnvironment"
                | "CustomVerbatimCommand"
                | "RecustomVerbatimCommand"
                | "VerbatimEnvironment"
                | "MakeShortVerb"
                | "DefineShortVerb"
        )
}

fn unsupported(reason: &str) -> String {
    format!("unsupported LaTeX literal configuration: {reason}")
}
