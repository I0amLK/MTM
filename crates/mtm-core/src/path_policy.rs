use mtm_contracts::{ErrorCategory, ReCtmError, invalid_argument};

pub fn validate_workspace_path(raw_path: &str) -> Result<String, ReCtmError> {
    if raw_path.is_empty() {
        return Err(invalid_argument("Path must be a non-empty string."));
    }
    if raw_path.contains('\0') {
        return Err(invalid_argument("Path contains a NUL byte."));
    }
    if raw_path.starts_with('/') || has_windows_drive_prefix(raw_path) {
        return Err(
            ReCtmError::new("ABSOLUTE_PATH_DENIED", "Absolute paths are denied.")
                .with_category(ErrorCategory::Security),
        );
    }

    let mut components = Vec::new();
    for component in raw_path.split('/') {
        if component == ".." {
            return Err(ReCtmError::new(
                "PATH_OUTSIDE_WORKSPACE",
                "Path escapes the native workspace.",
            )
            .with_category(ErrorCategory::Security));
        }
        if component.is_empty() || component == "." {
            continue;
        }
        components.push(component);
    }
    Ok(if components.is_empty() {
        ".".to_owned()
    } else {
        components.join("/")
    })
}

fn has_windows_drive_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_safe_relative_paths() -> Result<(), ReCtmError> {
        assert_eq!(validate_workspace_path("./a//b/")?, "a/b");
        assert_eq!(validate_workspace_path(".")?, ".");
        assert_eq!(validate_workspace_path(r"a\b")?, r"a\b");
        Ok(())
    }

    #[test]
    fn rejects_absolute_and_parent_paths() {
        assert_eq!(
            validate_workspace_path("/etc/passwd").map_err(|error| error.code),
            Err("ABSOLUTE_PATH_DENIED".to_owned())
        );
        assert_eq!(
            validate_workspace_path("a/../b").map_err(|error| error.code),
            Err("PATH_OUTSIDE_WORKSPACE".to_owned())
        );
        assert_eq!(
            validate_workspace_path(r"C:\temp").map_err(|error| error.code),
            Err("ABSOLUTE_PATH_DENIED".to_owned())
        );
    }
}
