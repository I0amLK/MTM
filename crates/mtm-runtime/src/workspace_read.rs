//! Lossless, range-bounded UTF-8 pages. Continuations bind to content, not authority.
use super::*;
use serde_json::json;

const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

struct ReadRequest {
    start: usize,
    end: Option<usize>,
    max_lines: usize,
    max_bytes: usize,
    offset: usize,
}

impl ReadRequest {
    fn parse(arguments: &Map<String, Value>) -> Result<Self, ReCtmError> {
        if optional_text(arguments, "encoding").unwrap_or("utf-8") != "utf-8" {
            return Err(validation_code(
                "UNSUPPORTED_ENCODING",
                "Only utf-8 is supported.",
            ));
        }
        let start = usize_from(arguments, "start_line", 1)?;
        let end = optional_integer(arguments, "end_line")?
            .map(|n| usize::try_from(n).map_err(|_| validation("end_line must be positive")))
            .transpose()?;
        let max_lines = usize_from(arguments, "max_lines", 500)?;
        let max_bytes = usize_from(arguments, "max_bytes", 131_072)?;
        let offset = usize_from(arguments, "line_byte_offset", 0)?;
        if start == 0 || end.is_some_and(|end| end < start) || max_lines == 0 {
            return Err(validation(
                "start_line/max_lines must be positive; end_line must be >= start_line",
            ));
        }
        if !(1..=1_048_576).contains(&max_bytes) || offset as u64 > MAX_FILE_BYTES {
            return Err(validation(
                "max_bytes must be 1..1048576 and line_byte_offset must be within the file limit",
            ));
        }
        Ok(Self {
            start,
            end,
            max_lines,
            max_bytes,
            offset,
        })
    }
}

pub(super) fn read(
    workspace: &NativeWorkspace,
    arguments: &Map<String, Value>,
) -> Result<Value, ReCtmError> {
    let request = ReadRequest::parse(arguments)?;
    let path = optional_text(arguments, "path")
        .filter(|p| !p.is_empty())
        .ok_or_else(|| validation("path is required"))?;
    let resolved = workspace.resolve_existing(path)?;
    let before = fs::metadata(&resolved.path).map_err(io_error)?;
    if before.is_dir() {
        return Err(validation_code("IS_DIRECTORY", "Path is a directory."));
    }
    if !before.is_file() {
        return Err(validation_code(
            "NOT_A_REGULAR_FILE",
            "Only regular text files can be paged.",
        ));
    }
    if before.len() > MAX_FILE_BYTES {
        return Err(validation_code(
            "FILE_TOO_LARGE",
            "read_file supports files up to 64 MiB; use a bounded extraction for larger files.",
        ));
    }
    let mut file = fs::File::open(&resolved.path).map_err(io_error)?;
    if file_identity(&file.metadata().map_err(io_error)?) != file_identity(&before) {
        return Err(changed());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(validation_code(
            "FILE_TOO_LARGE",
            "File exceeded the 64 MiB read limit.",
        ));
    }
    if file_identity(&file.metadata().map_err(io_error)?) != file_identity(&before)
        || file_identity(&fs::metadata(&resolved.path).map_err(io_error)?) != file_identity(&before)
    {
        return Err(changed());
    }
    let digest = sha256_bytes(&bytes);
    if let Some(expected) = arguments.get("expected_sha256") {
        let expected = expected
            .as_str()
            .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| validation("expected_sha256 must be a 64-character hex digest"))?;
        if expected != digest {
            return Err(changed());
        }
    }
    let text = String::from_utf8(bytes).map_err(|_| {
        validation_code("BINARY_FILE", "Native read_file supports UTF-8 text only.")
    })?;
    let total = text.split_inclusive('\n').count();
    let end_limit = request.end.unwrap_or(total).min(total);
    let mut index = request.start - 1;
    let mut offset = request.offset;
    let mut selected = String::new();
    let mut last_line = request.start;
    if index >= total && offset != 0 {
        return Err(validation("line_byte_offset requires an existing line"));
    }
    for line in text
        .split_inclusive('\n')
        .skip(index)
        .take(request.max_lines)
    {
        if index >= end_limit {
            break;
        }
        if offset >= line.len() || !line.is_char_boundary(offset) {
            return Err(validation(
                "line_byte_offset must identify a UTF-8 boundary inside the requested line",
            ));
        }
        let rest = &line[offset..];
        let mut count = rest.len().min(request.max_bytes - selected.len());
        while !rest.is_char_boundary(count) {
            count -= 1;
        }
        if count == 0 {
            if selected.is_empty() {
                return Err(validation_code(
                    "READ_PAGE_TOO_SMALL",
                    "max_bytes cannot hold the next UTF-8 character; use at least 4 bytes.",
                ));
            }
            break;
        }
        selected.push_str(&rest[..count]);
        last_line = index + 1;
        if count < rest.len() {
            offset += count;
            break;
        }
        index += 1;
        offset = 0;
    }
    let truncated = index < end_limit;
    let next_line = truncated.then_some(index + 1);
    let next_offset = truncated.then_some(offset);
    let next_action = if truncated {
        let mut next = arguments.clone();
        next.insert("path".into(), json!(resolved.display));
        next.insert("start_line".into(), json!(index + 1));
        next.insert("line_byte_offset".into(), json!(offset));
        next.insert("expected_sha256".into(), json!(digest));
        json!({"tool":"read_file","arguments":next})
    } else {
        Value::Null
    };
    Ok(json!({
        "path":resolved.display,"content":selected,"start_line":request.start,"end_line":last_line,
        "line_byte_offset":request.offset,"total_lines":total,"total_bytes":text.len(),"sha256":digest,
        "truncated":truncated,"next_start_line":next_line,"next_line_byte_offset":next_offset,
        "next_action":next_action
    }))
}

fn changed() -> ReCtmError {
    ReCtmError::new(
        "READ_FILE_CHANGED",
        "File changed; restart the read instead of combining pages from different contents.",
    )
    .with_category(ErrorCategory::Conflict)
}
