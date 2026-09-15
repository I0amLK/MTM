//! Repository selection is separate from literal repository-relative file filters.
use super::*;

pub(super) struct Repository {
    pub root: PathBuf,
    pub display: String,
    git_dir: PathBuf,
}

impl Repository {
    pub fn command(&self, operation: &str) -> Vec<String> {
        vec![
            "git".into(),
            "--no-pager".into(),
            "--literal-pathspecs".into(),
            "--no-optional-locks".into(),
            "-C".into(),
            self.root.display().to_string(),
            format!("--git-dir={}", self.git_dir.display()),
            format!("--work-tree={}", self.root.display()),
            "-c".into(),
            "core.fsmonitor=false".into(),
            "-c".into(),
            "core.hooksPath=/dev/null".into(),
            "-c".into(),
            "color.ui=false".into(),
            operation.into(),
        ]
    }

    pub fn filters(
        &self,
        workspace: &NativeWorkspace,
        arguments: &Map<String, Value>,
    ) -> Result<Vec<String>, ReCtmError> {
        let mut filters = Vec::new();
        if let Some(path) = arguments.get("path") {
            let path = path
                .as_str()
                .ok_or_else(|| validation("path must be a string"))?;
            if !path.is_empty() {
                filters.push(path.to_owned());
            }
        }
        if let Some(paths) = arguments.get("paths") {
            let paths = paths
                .as_array()
                .ok_or_else(|| validation("paths must be an array"))?;
            for path in paths {
                filters.push(
                    path.as_str()
                        .ok_or_else(|| validation("paths must contain strings"))?
                        .to_owned(),
                );
            }
        }
        if filters.len() > 256 {
            return Err(validation("at most 256 Git file filters are supported"));
        }
        for filter in &mut filters {
            let relative = validate_relative_path(filter)?;
            let candidate = self.root.join(&relative);
            let mut existing = candidate.as_path();
            loop {
                match fs::symlink_metadata(existing) {
                    Ok(_) => {
                        let resolved = existing.canonicalize().map_err(io_error)?;
                        workspace.assert_inside(&resolved, existing)?;
                        if !resolved.starts_with(&self.root) {
                            return Err(validation_code(
                                "GIT_PATH_OUTSIDE_REPOSITORY",
                                "File filter escapes the selected repository.",
                            ));
                        }
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        existing = existing
                            .parent()
                            .ok_or_else(|| validation("invalid Git file filter"))?;
                    }
                    Err(error) => return Err(io_error(error)),
                }
            }
            *filter = relative
                .to_str()
                .ok_or_else(|| validation("Git paths must be UTF-8"))?
                .to_owned();
        }
        Ok(filters)
    }
}

pub(super) fn select(
    workspace: &NativeWorkspace,
    arguments: &Map<String, Value>,
    fallback: &str,
) -> Result<Option<Repository>, ReCtmError> {
    let raw = match arguments.get("repo_path") {
        Some(value) => value
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| validation("repo_path must be a nonempty directory path"))?,
        None => fallback,
    };
    let requested = workspace.resolve_existing(raw)?;
    if !requested.path.is_dir() {
        return Err(validation_code(
            "NOT_A_DIRECTORY",
            "repo_path selects a directory; use path/paths for file filters.",
        ));
    }
    let mut directory = requested.path.as_path();
    loop {
        let marker = directory.join(".git");
        match fs::symlink_metadata(&marker) {
            Ok(_) => {
                let marker_path = marker.canonicalize().map_err(io_error)?;
                workspace.assert_inside(&marker_path, &marker)?;
                let git_dir = if marker_path.is_dir() {
                    marker_path
                } else {
                    let text = small_text(&marker_path)?;
                    let target = text
                        .trim()
                        .strip_prefix("gitdir: ")
                        .filter(|s| !s.is_empty())
                        .ok_or_else(|| validation("invalid Git directory pointer"))?;
                    directory.join(target).canonicalize().map_err(io_error)?
                };
                workspace.assert_inside(&git_dir, &marker)?;
                if !git_dir.is_dir() {
                    return Err(validation("Git metadata must name a directory"));
                }
                let common = git_dir.join("commondir");
                match fs::symlink_metadata(&common) {
                    Ok(_) => {
                        let pointer = common.canonicalize().map_err(io_error)?;
                        workspace.assert_inside(&pointer, &common)?;
                        let text = small_text(&pointer)?;
                        if text.trim().is_empty() {
                            return Err(validation("Git common directory pointer is empty"));
                        }
                        let target = git_dir.join(text.trim()).canonicalize().map_err(io_error)?;
                        workspace.assert_inside(&target, &common)?;
                        if !target.is_dir() {
                            return Err(validation("Git common metadata must be a directory"));
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(io_error(error)),
                }
                return Ok(Some(Repository {
                    root: directory.to_owned(),
                    display: display_path(directory, &workspace.root),
                    git_dir,
                }));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
        if directory == workspace.root {
            return Ok(None);
        }
        directory = directory
            .parent()
            .ok_or_else(|| internal("Git discovery escaped workspace"))?;
    }
}

fn small_text(path: &Path) -> Result<String, ReCtmError> {
    let metadata = fs::metadata(path).map_err(io_error)?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err(validation(
            "Git metadata pointer must be a bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(io_error)?
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > 4096 {
        return Err(validation("Git metadata pointer exceeded its bound"));
    }
    String::from_utf8(bytes).map_err(|_| validation("Git metadata pointer must be UTF-8"))
}

pub(super) fn output_truncated(output: &Value) -> bool {
    output["stdout_truncated"] == true
        || output["stdout_dropped_bytes"]
            .as_u64()
            .is_some_and(|n| n > 0)
        || output["stdout_omitted_bytes"]
            .as_u64()
            .is_some_and(|n| n > 0)
}

pub(super) fn complete_output(output: &Value) -> Result<(), ReCtmError> {
    if output_truncated(output) {
        return Err(validation_code(
            "GIT_OUTPUT_TRUNCATED",
            "Git output exceeded the parse limit; narrow the requested scope.",
        ));
    }
    Ok(())
}
