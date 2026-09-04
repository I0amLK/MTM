use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use mtm_contracts::{ErrorCategory, ReCtmError};
use mtm_core::{PatchInvocation, PatchPathFact, apply_update_hunks, parse_patch};
use mtm_native::{CommandManager, CommandManagerConfig, CommandRequest, PollRequest};
use regex::{Regex, RegexBuilder};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const DEFAULT_EXCLUDED: [&str; 11] = [
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "target",
];

#[derive(Clone, Debug)]
pub struct ResolvedPath {
    pub display: String,
    pub path: PathBuf,
    pub existed: bool,
}

#[derive(Clone)]
pub struct NativeWorkspace {
    root: PathBuf,
    private_root: PathBuf,
    commands: CommandManager,
}

impl NativeWorkspace {
    pub fn new(root: &Path, private_root: &Path) -> Result<Self, ReCtmError> {
        let root = root.canonicalize().map_err(io_error)?;
        let private_root = absolute_normalized(private_root)?;
        if !root.is_dir() {
            return Err(validation_code(
                "INVALID_WORKSPACE",
                "Native workspace must be a directory.",
            ));
        }
        let home = std::env::var_os("HOME").map(PathBuf::from);
        if root == Path::new("/") || home.as_ref().is_some_and(|path| path == &root) {
            return Err(ReCtmError::new(
                "UNSAFE_WORKSPACE",
                "Filesystem root and home directory cannot be native workspaces.",
            )
            .with_category(ErrorCategory::Security));
        }
        if root.starts_with(&private_root) || private_root.starts_with(&root) {
            return Err(ReCtmError::new(
                "TRUST_DOMAIN_OVERLAP",
                "Native workspace and workflow-private root must not overlap.",
            )
            .with_category(ErrorCategory::Security));
        }
        Ok(Self {
            root,
            private_root,
            commands: CommandManager::new(CommandManagerConfig::default()),
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn resolve_existing(&self, raw_path: &str) -> Result<ResolvedPath, ReCtmError> {
        let relative = validate_relative_path(if raw_path.is_empty() { "." } else { raw_path })?;
        let candidate = self.root.join(relative);
        let resolved = candidate.canonicalize().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ReCtmError::new("NOT_FOUND", format!("Path not found: {raw_path}"))
                    .with_category(ErrorCategory::NotFound)
            } else {
                io_error(error)
            }
        })?;
        self.assert_inside(&resolved, &candidate)?;
        Ok(ResolvedPath {
            display: display_path(&resolved, &self.root),
            path: resolved,
            existed: true,
        })
    }

    pub fn resolve_for_write(&self, raw_path: &str) -> Result<ResolvedPath, ReCtmError> {
        let relative = validate_relative_path(raw_path)?;
        if relative.as_os_str().is_empty() || relative == Path::new(".") {
            return Err(validation("Invalid write target."));
        }
        let candidate = self.root.join(&relative);
        if fs::symlink_metadata(&candidate).is_ok() {
            let metadata = fs::symlink_metadata(&candidate).map_err(io_error)?;
            let resolved = candidate.canonicalize().map_err(io_error)?;
            self.assert_inside(&resolved, &candidate)?;
            if metadata.file_type().is_symlink() {
                return Err(ReCtmError::new(
                    "SYMLINK_WRITE_DENIED",
                    "Writing through symlinks is denied.",
                )
                .with_category(ErrorCategory::Security));
            }
            return Ok(ResolvedPath {
                display: display_path(&resolved, &self.root),
                path: resolved,
                existed: true,
            });
        }
        let mut ancestor = candidate
            .parent()
            .ok_or_else(|| validation("Invalid write target."))?;
        let mut missing = Vec::new();
        while !ancestor.exists() {
            let name = ancestor
                .file_name()
                .ok_or_else(|| validation("Invalid write target."))?
                .to_os_string();
            missing.push(name);
            ancestor = ancestor
                .parent()
                .ok_or_else(|| validation("Invalid write target."))?;
        }
        let resolved_parent = ancestor.canonicalize().map_err(io_error)?;
        self.assert_inside(&resolved_parent, ancestor)?;
        let mut target = resolved_parent;
        for name in missing.into_iter().rev() {
            target.push(name);
        }
        target.push(
            candidate
                .file_name()
                .ok_or_else(|| validation("Invalid write target."))?,
        );
        Ok(ResolvedPath {
            display: display_path(&target, &self.root),
            path: target,
            existed: false,
        })
    }

    pub fn read_file(&self, arguments: &Map<String, Value>) -> Result<Value, ReCtmError> {
        let encoding = optional_text(arguments, "encoding").unwrap_or("utf-8");
        if encoding != "utf-8" {
            return Err(validation_code(
                "UNSUPPORTED_ENCODING",
                "Only utf-8 is supported.",
            ));
        }
        let start_line = integer_or(arguments, "start_line", 1)?;
        if start_line < 1 {
            return Err(validation("start_line must be >= 1"));
        }
        let end_line = optional_integer(arguments, "end_line")?;
        let max_lines_arg = optional_integer(arguments, "max_lines")?;
        if let (Some(end), Some(max_lines)) = (end_line, max_lines_arg)
            && end != start_line + max_lines - 1
        {
            return Err(validation("end_line and max_lines select different ranges"));
        }
        let max_lines = if let Some(end) = end_line {
            (end - start_line + 1).max(1)
        } else {
            max_lines_arg.unwrap_or(500)
        };
        let max_bytes = usize_from(arguments, "max_bytes", 131_072)?;
        let resolved = self.resolve_existing(text_or(arguments, "path", ""))?;
        if resolved.path.is_dir() {
            return Err(validation_code("IS_DIRECTORY", "Path is a directory."));
        }
        let data = fs::read(&resolved.path).map_err(io_error)?;
        let text = String::from_utf8(data.clone()).map_err(|_| {
            validation_code("BINARY_FILE", "Native read_file supports UTF-8 text only.")
        })?;
        let lines = split_lines_keep_ends(&text);
        let mut selected = String::new();
        let mut bytes_used = 0_usize;
        let mut index = usize::try_from(start_line - 1).unwrap_or(usize::MAX);
        let max_lines = usize::try_from(max_lines).unwrap_or(usize::MAX);
        let mut selected_count = 0_usize;
        while index < lines.len() && selected_count < max_lines {
            let encoded = lines[index].as_bytes();
            if selected_count > 0 && bytes_used.saturating_add(encoded.len()) > max_bytes {
                break;
            }
            if selected_count == 0 && encoded.len() > max_bytes {
                let clipped = &encoded[..max_bytes.min(encoded.len())];
                selected.push_str(&String::from_utf8_lossy(clipped));
                index += 1;
                selected_count += 1;
                break;
            }
            selected.push_str(lines[index]);
            bytes_used = bytes_used.saturating_add(encoded.len());
            index += 1;
            selected_count += 1;
        }
        let end = if selected_count == 0 {
            start_line
        } else {
            start_line + i64::try_from(selected_count).unwrap_or(i64::MAX) - 1
        };
        Ok(serde_json::json!({
            "path":resolved.display,"content":selected,"start_line":start_line,"end_line":end,
            "total_lines":lines.len(),"total_bytes":data.len(),"truncated":index < lines.len(),
            "next_start_line":if index < lines.len(){Some(index+1)}else{None}
        }))
    }

    pub fn list_dir(&self, arguments: &Map<String, Value>) -> Result<Value, ReCtmError> {
        let resolved = self.resolve_existing(text_or(arguments, "path", "."))?;
        if !resolved.path.is_dir() {
            return Err(validation_code(
                "NOT_A_DIRECTORY",
                "Path is not a directory.",
            ));
        }
        let recursive = bool_or(arguments, "recursive", false);
        let max_depth = usize_from(arguments, "max_depth", 1)?;
        let max_entries = usize_from(arguments, "max_entries", 1000)?;
        let include_hidden = bool_or(arguments, "include_hidden", false);
        let include_ignored = bool_or(arguments, "include_ignored", false);
        let sort = text_or(arguments, "sort", "name");
        let mut entries = Vec::new();
        let mut truncated = false;
        self.visit_directory(
            &resolved.path,
            1,
            recursive,
            max_depth,
            max_entries,
            include_hidden,
            include_ignored,
            &mut entries,
            &mut truncated,
        )?;
        entries.sort_by(|left, right| match sort {
            "type" => json_text(left, "type")
                .cmp(json_text(right, "type"))
                .then_with(|| json_text(left, "path").cmp(json_text(right, "path"))),
            "modified" => json_f64(right, "modified")
                .total_cmp(&json_f64(left, "modified"))
                .then_with(|| json_text(left, "path").cmp(json_text(right, "path"))),
            _ => json_text(left, "path").cmp(json_text(right, "path")),
        });
        Ok(serde_json::json!({
            "path":resolved.display,"entries":entries,"truncated":truncated,
            "warnings":if truncated{vec!["entry limit reached"]}else{Vec::<&str>::new()}
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn visit_directory(
        &self,
        directory: &Path,
        depth: usize,
        recursive: bool,
        max_depth: usize,
        max_entries: usize,
        include_hidden: bool,
        include_ignored: bool,
        entries: &mut Vec<Value>,
        truncated: &mut bool,
    ) -> Result<(), ReCtmError> {
        if *truncated {
            return Ok(());
        }
        let mut children = fs::read_dir(directory)
            .map_err(io_error)?
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            let name = child.file_name().to_string_lossy().into_owned();
            if ignored(&name, include_hidden, include_ignored) {
                continue;
            }
            let path = child.path();
            let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
            let file_type = if metadata.file_type().is_symlink() {
                "symlink"
            } else if metadata.is_dir() {
                "directory"
            } else {
                "file"
            };
            entries.push(serde_json::json!({
                "name":name,"path":display_path(&path,&self.root),"type":file_type,
                "size_bytes":metadata.len(),"modified":modified_seconds(&metadata),
                "is_hidden":name.starts_with('.'),"is_ignored":ignored(&name,true,false)
            }));
            if entries.len() >= max_entries {
                *truncated = true;
                return Ok(());
            }
            if recursive
                && depth < max_depth
                && metadata.is_dir()
                && !metadata.file_type().is_symlink()
            {
                self.visit_directory(
                    &path,
                    depth + 1,
                    recursive,
                    max_depth,
                    max_entries,
                    include_hidden,
                    include_ignored,
                    entries,
                    truncated,
                )?;
            }
        }
        Ok(())
    }

    pub fn list_files(&self, arguments: &Map<String, Value>) -> Result<Value, ReCtmError> {
        let resolved = self.resolve_existing(text_or(arguments, "path", "."))?;
        if !resolved.path.is_dir() {
            return Err(validation_code(
                "NOT_A_DIRECTORY",
                "Path is not a directory.",
            ));
        }
        let patterns = string_array(arguments.get("patterns"))
            .filter(|items| !items.is_empty())
            .or_else(|| optional_text(arguments, "glob").map(|value| vec![value.to_owned()]))
            .unwrap_or_else(|| vec!["**/*".to_owned()]);
        let excludes = string_array(arguments.get("exclude_patterns")).unwrap_or_default();
        let include_hidden = bool_or(arguments, "include_hidden", false);
        let include_ignored = bool_or(arguments, "include_ignored", false);
        let max_results = usize_from(arguments, "max_results", 5000)?;
        let sort = text_or(arguments, "sort", "path");
        let mut files = Vec::new();
        self.walk_files(
            &resolved.path,
            &resolved.path,
            &patterns,
            &excludes,
            include_hidden,
            include_ignored,
            &mut files,
        )?;
        files.sort_by(|left, right| {
            if sort == "modified" {
                json_f64(right, "modified")
                    .total_cmp(&json_f64(left, "modified"))
                    .then_with(|| json_text(left, "path").cmp(json_text(right, "path")))
            } else {
                json_text(left, "path").cmp(json_text(right, "path"))
            }
        });
        let truncated = files.len() > max_results;
        files.truncate(max_results);
        Ok(serde_json::json!({"count":files.len(),"files":files,"truncated":truncated}))
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_files(
        &self,
        directory: &Path,
        base: &Path,
        patterns: &[String],
        excludes: &[String],
        include_hidden: bool,
        include_ignored: bool,
        files: &mut Vec<Value>,
    ) -> Result<(), ReCtmError> {
        let mut children = fs::read_dir(directory)
            .map_err(io_error)?
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            let path = child.path();
            let name = child.file_name().to_string_lossy().into_owned();
            if ignored(&name, include_hidden, include_ignored) {
                continue;
            }
            let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                self.walk_files(
                    &path,
                    base,
                    patterns,
                    excludes,
                    include_hidden,
                    include_ignored,
                    files,
                )?;
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let local = path
                .strip_prefix(base)
                .map_err(|_| internal("file walk escaped base"))?;
            let local_text = local.to_string_lossy().replace('\\', "/");
            let display = display_path(&path, &self.root);
            if !patterns
                .iter()
                .any(|pattern| glob_match(&local_text, pattern))
            {
                continue;
            }
            if excludes
                .iter()
                .any(|pattern| glob_match(&local_text, pattern) || glob_match(&display, pattern))
            {
                continue;
            }
            files.push(serde_json::json!({
                "path":display,"type":"file","size_bytes":metadata.len(),"modified":modified_seconds(&metadata)
            }));
        }
        Ok(())
    }

    pub fn search_text(&self, arguments: &Map<String, Value>) -> Result<Value, ReCtmError> {
        let query = text_or(arguments, "query", "");
        if query.is_empty() {
            return Err(validation("query is required"));
        }
        let regex_mode = bool_or(arguments, "regex", false);
        let case_sensitive = bool_or(arguments, "case_sensitive", false);
        let context_lines = usize_from(arguments, "context_lines", 0)?;
        let max_results = usize_from(arguments, "max_results", 1000)?;
        let max_preview = usize_from(arguments, "max_preview_bytes", 512)?;
        let mut include = string_array(arguments.get("include_globs")).unwrap_or_default();
        if let Some(glob) = optional_text(arguments, "glob")
            && !glob.is_empty()
        {
            include.push(glob.to_owned());
        }
        let exclude = string_array(arguments.get("exclude_globs")).unwrap_or_default();
        let listed = self.list_files(&Map::from_iter([
            (
                "path".to_owned(),
                Value::String(text_or(arguments, "path", ".").to_owned()),
            ),
            (
                "patterns".to_owned(),
                serde_json::json!(if include.is_empty() {
                    vec!["**/*".to_owned()]
                } else {
                    include
                }),
            ),
            ("exclude_patterns".to_owned(), serde_json::json!(exclude)),
            ("max_results".to_owned(), Value::from(50_000)),
        ]))?;
        let escaped_query = regex::escape(query);
        let pattern_text = if regex_mode { query } else { &escaped_query };
        let pattern = RegexBuilder::new(pattern_text)
            .case_insensitive(!case_sensitive)
            .build()
            .map_err(|error| {
                invalid_details(
                    "invalid regular expression",
                    serde_json::json!({"error":error.to_string()}),
                )
            })?;
        let mut matches = Vec::new();
        for item in listed["files"].as_array().into_iter().flatten() {
            let Some(path_text) = item.get("path").and_then(Value::as_str) else {
                continue;
            };
            let path = self.resolve_existing(path_text)?.path;
            let Ok(text) = fs::read_to_string(path) else {
                continue;
            };
            let lines = text.lines().collect::<Vec<_>>();
            for (index, line) in lines.iter().enumerate() {
                let Some(found) = pattern.find(line) else {
                    continue;
                };
                let preview = truncate_utf8_bytes(line, max_preview);
                matches.push(serde_json::json!({
                    "path":path_text,"line":index+1,"column":found.start()+1,"preview":preview,
                    "before":lines[index.saturating_sub(context_lines)..index],
                    "after":lines[index+1..(index+1+context_lines).min(lines.len())]
                }));
                if matches.len() >= max_results {
                    return Ok(
                        serde_json::json!({"matches":matches,"total_matches":matches.len(),"truncated":true}),
                    );
                }
            }
        }
        Ok(serde_json::json!({"matches":matches,"total_matches":matches.len(),"truncated":false}))
    }

    /// Collect the path and Git-ignore facts used by the D3 shadow permission
    /// evaluator.  This validates every source and destination but performs no
    /// write and does not affect the authoritative `apply_patch` path.
    pub fn collect_patch_permission_facts(
        &self,
        invocation: &PatchInvocation,
    ) -> Result<Vec<PatchPathFact>, ReCtmError> {
        let mut paths = BTreeSet::new();
        for operation in invocation.operations() {
            match operation.kind.as_str() {
                "add" => {
                    self.resolve_for_write(&operation.path)?;
                    paths.insert(operation.path.clone());
                }
                "delete" => {
                    let source = self.resolve_existing(&operation.path)?;
                    if source.path.is_dir() {
                        return Err(validation_code("PATCH_FAILED", "Cannot patch a directory."));
                    }
                    fs::read_to_string(&source.path).map_err(|_| {
                        validation_code("UNSUPPORTED_ENCODING", "Patch target is not valid UTF-8.")
                    })?;
                    paths.insert(operation.path.clone());
                }
                "update" => {
                    let source = self.resolve_existing(&operation.path)?;
                    if source.path.is_dir() {
                        return Err(validation_code("PATCH_FAILED", "Cannot patch a directory."));
                    }
                    let old = fs::read_to_string(&source.path).map_err(|_| {
                        validation_code("UNSUPPORTED_ENCODING", "Patch target is not valid UTF-8.")
                    })?;
                    apply_update_hunks(&old, &operation.hunks, &operation.path)?;
                    paths.insert(operation.path.clone());
                    if let Some(destination) = &operation.move_to {
                        self.resolve_for_write(destination)?;
                        paths.insert(destination.clone());
                    }
                }
                _ => return Err(validation_code("PATCH_FAILED", "Unknown patch operation.")),
            }
        }

        let repository = self.permission_git_repository()?;
        paths
            .into_iter()
            .map(|path| {
                let git_ignored = if repository {
                    self.permission_git_ignored(&path)?
                } else {
                    false
                };
                PatchPathFact::new(path, git_ignored)
            })
            .collect()
    }

    fn permission_git_repository(&self) -> Result<bool, ReCtmError> {
        let output = self.run_sync(
            vec![
                "git".to_owned(),
                "-C".to_owned(),
                self.root.display().to_string(),
                "rev-parse".to_owned(),
                "--is-inside-work-tree".to_owned(),
            ],
            5_000,
            16_384,
        )
        .map_err(|_| {
            ReCtmError::new(
                "NATIVE_GIT_IGNORE_LOOKUP_FAILED",
                "Git repository detection could not be started during patch permission classification.",
            )
            .with_category(ErrorCategory::Security)
        })?;
        let declared_repository = self.root.join(".git").exists();
        match output["exit_code"].as_i64() {
            Some(0)
                if output["stdout"]
                    .as_str()
                    .is_some_and(|text| text.trim() == "true") =>
            {
                Ok(true)
            }
            Some(128)
                if !declared_repository
                    && output["stderr"]
                        .as_str()
                        .is_some_and(|text| text.contains("not a git repository")) =>
            {
                Ok(false)
            }
            Some(128)
                if output["stderr"]
                    .as_str()
                    .is_some_and(|text| text.contains("not a git repository")) =>
            {
                Err(ReCtmError::new(
                    "NATIVE_GIT_IGNORE_LOOKUP_FAILED",
                    "A declared Git repository could not be inspected during patch permission classification.",
                )
                .with_category(ErrorCategory::Security))
            }
            _ => Err(ReCtmError::new(
                "NATIVE_GIT_IGNORE_LOOKUP_FAILED",
                "Git repository detection failed during patch permission classification.",
            )
            .with_category(ErrorCategory::Security)),
        }
    }

    fn permission_git_ignored(&self, path: &str) -> Result<bool, ReCtmError> {
        let output = self
            .run_sync(
                vec![
                    "git".to_owned(),
                    "-C".to_owned(),
                    self.root.display().to_string(),
                    "check-ignore".to_owned(),
                    "--quiet".to_owned(),
                    "--no-index".to_owned(),
                    "--".to_owned(),
                    path.to_owned(),
                ],
                5_000,
                16_384,
            )
            .map_err(|_| {
                ReCtmError::new(
                "NATIVE_GIT_IGNORE_LOOKUP_FAILED",
                "Git ignore lookup could not be started during patch permission classification.",
            )
            .with_category(ErrorCategory::Security)
            })?;
        match output["exit_code"].as_i64() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(ReCtmError::new(
                "NATIVE_GIT_IGNORE_LOOKUP_FAILED",
                "Git ignore lookup failed during patch permission classification.",
            )
            .with_category(ErrorCategory::Security)),
        }
    }

    pub fn apply_patch(&self, patch: &str, dry_run: bool) -> Result<Value, ReCtmError> {
        let operations = parse_patch(patch)?;
        let mut prepared = Vec::new();
        let mut additions = 0_usize;
        let mut removals = 0_usize;
        let mut summaries = Vec::new();
        for operation in operations {
            match operation.kind.as_str() {
                "add" => {
                    let target = self.resolve_for_write(&operation.path)?;
                    if target.existed {
                        return Err(
                            ReCtmError::new("PATCH_FAILED", "Add target already exists.")
                                .with_category(ErrorCategory::Conflict),
                        );
                    }
                    let content = operation.add_content.unwrap_or_default();
                    additions += content.lines().count();
                    summaries.push(format!("A {}", operation.path));
                    prepared.push(("add".to_owned(), target, content, None::<ResolvedPath>));
                }
                "delete" => {
                    let source = self.resolve_existing(&operation.path)?;
                    if source.path.is_dir() {
                        return Err(validation_code("PATCH_FAILED", "Cannot patch a directory."));
                    }
                    let old = fs::read_to_string(&source.path).map_err(|_| {
                        validation_code("UNSUPPORTED_ENCODING", "Patch target is not valid UTF-8.")
                    })?;
                    removals += old.lines().count();
                    summaries.push(format!("D {}", operation.path));
                    prepared.push(("delete".to_owned(), source, String::new(), None));
                }
                "update" => {
                    let source = self.resolve_existing(&operation.path)?;
                    if source.path.is_dir() {
                        return Err(validation_code("PATCH_FAILED", "Cannot patch a directory."));
                    }
                    let old = fs::read_to_string(&source.path).map_err(|_| {
                        validation_code("UNSUPPORTED_ENCODING", "Patch target is not valid UTF-8.")
                    })?;
                    let updated = apply_update_hunks(&old, &operation.hunks, &operation.path)?;
                    additions += updated.lines().count().saturating_sub(old.lines().count());
                    removals += old.lines().count().saturating_sub(updated.lines().count());
                    let move_target = operation
                        .move_to
                        .as_deref()
                        .map(|target| self.resolve_for_write(target))
                        .transpose()?;
                    summaries.push(if let Some(target) = &operation.move_to {
                        format!("R {} -> {target}", operation.path)
                    } else {
                        format!("M {}", operation.path)
                    });
                    prepared.push(("update".to_owned(), source, updated, move_target));
                }
                _ => return Err(validation_code("PATCH_FAILED", "Unknown patch operation.")),
            }
        }
        if !dry_run {
            for (kind, source, content, move_target) in &prepared {
                match kind.as_str() {
                    "add" => atomic_write(&source.path, content.as_bytes())?,
                    "delete" => fs::remove_file(&source.path).map_err(io_error)?,
                    "update" => {
                        if let Some(target) = move_target {
                            atomic_write(&target.path, content.as_bytes())?;
                            fs::remove_file(&source.path).map_err(io_error)?;
                        } else {
                            atomic_write(&source.path, content.as_bytes())?;
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(serde_json::json!({
            "clean":true,"dry_run":dry_run,"summary":summaries.join("\n"),"additions":additions,"removals":removals,
            "affected_files":prepared.iter().map(|(kind,source,_,target)|serde_json::json!({
                "operation":kind,"path":target.as_ref().map_or(source.display.as_str(),|value|value.display.as_str())
            })).collect::<Vec<_>>(),"warnings":[]
        }))
    }

    pub fn git_status(&self, arguments: &Map<String, Value>) -> Result<Value, ReCtmError> {
        let resolved = self.resolve_existing(text_or(arguments, "path", "."))?;
        if !is_git_repo(&resolved.path) {
            return Ok(
                serde_json::json!({"is_repo":false,"clean":true,"entries":[],"truncated":false,"warnings":[]}),
            );
        }
        let max_entries = usize_from(arguments, "max_entries", 1000)?;
        let mut argv = vec![
            "git".to_owned(),
            "-C".to_owned(),
            resolved.path.display().to_string(),
            "status".to_owned(),
            "--porcelain=v1".to_owned(),
            "-b".to_owned(),
        ];
        if !bool_or(arguments, "include_untracked", true) {
            argv.push("--untracked-files=no".to_owned());
        }
        let output = self.run_sync(argv, 15_000, 2_000_000)?;
        ensure_exit_ok(&output, "git status failed")?;
        let stdout = output["stdout"].as_str().unwrap_or_default();
        let mut branch = String::new();
        let mut upstream = String::new();
        let mut ahead = 0_i64;
        let mut behind = 0_i64;
        let mut entries = Vec::new();
        for line in stdout.lines() {
            if let Some(header) = line.strip_prefix("## ") {
                (branch, upstream, ahead, behind) = parse_branch(header);
                continue;
            }
            if line.len() < 3 {
                continue;
            }
            let mut path_text = line[3..].to_owned();
            let mut original = Value::Null;
            if let Some((before, after)) = path_text.split_once(" -> ") {
                original = Value::String(before.to_owned());
                path_text = after.to_owned();
            }
            entries.push(serde_json::json!({"path":path_text,"original_path":original,"index_status":&line[0..1],"worktree_status":&line[1..2]}));
            if entries.len() >= max_entries {
                break;
            }
        }
        let head = self.run_sync(
            vec![
                "git".into(),
                "-C".into(),
                resolved.path.display().to_string(),
                "rev-parse".into(),
                "HEAD".into(),
            ],
            5000,
            4096,
        )?;
        Ok(
            serde_json::json!({"is_repo":true,"branch":branch,"head":head["stdout"].as_str().unwrap_or_default().trim(),"upstream":upstream,"ahead":ahead,"behind":behind,"clean":entries.is_empty(),"truncated":entries.len()>=max_entries,"entries":entries}),
        )
    }

    pub fn git_diff(&self, arguments: &Map<String, Value>) -> Result<Value, ReCtmError> {
        if !is_git_repo(&self.root) {
            return Ok(
                serde_json::json!({"diff":"","files":[],"truncated":false,"warnings":["not a git repository"]}),
            );
        }
        let context = integer_or(arguments, "context_lines", 3)?;
        let max_bytes = usize_from(arguments, "max_bytes", 262_144)?;
        let mut chunks = Vec::new();
        let filters = path_filters(arguments)?;
        for staged in [false, true] {
            if staged && !bool_or(arguments, "staged", false) {
                continue;
            }
            if !staged && !bool_or(arguments, "unstaged", true) {
                continue;
            }
            let mut argv = vec![
                "git".into(),
                "-C".into(),
                self.root.display().to_string(),
                "-c".into(),
                "diff.external=".into(),
                "diff".into(),
                "--no-ext-diff".into(),
                "--no-textconv".into(),
                format!("--unified={context}"),
            ];
            if staged {
                argv.push("--cached".into());
            }
            if !filters.is_empty() {
                argv.push("--".into());
                argv.extend(filters.clone());
            }
            let output = self.run_sync(argv, 15_000, max_bytes.saturating_mul(2).max(65536))?;
            let code = output["exit_code"].as_i64().unwrap_or(-1);
            if !matches!(code, 0 | 1) {
                return Err(git_error(&output, "git diff failed"));
            }
            chunks.push(
                output["stdout"]
                    .as_str()
                    .unwrap_or_default()
                    .trim_end_matches('\n')
                    .to_owned(),
            );
        }
        let mut text = chunks
            .into_iter()
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        if !text.is_empty() {
            text.push('\n');
        }
        let (text, truncated) = truncate_string_bytes(&text, max_bytes);
        Ok(
            serde_json::json!({"diff":text,"files":parse_diff_files(&text),"truncated":truncated,"warnings":if truncated{vec!["diff truncated"]}else{Vec::<&str>::new()}}),
        )
    }

    pub fn git_log(&self, arguments: &Map<String, Value>) -> Result<Value, ReCtmError> {
        let requested = self.resolve_existing(text_or(arguments, "path", "."))?;
        if !is_git_repo(&requested.path) {
            return Ok(
                serde_json::json!({"is_repo":false,"commits":[],"truncated":false,"warnings":[]}),
            );
        }
        let reference = validate_git_ref(text_or(arguments, "ref", "HEAD"))?;
        let count = usize_from(arguments, "max_count", 20)?;
        let skip = usize_from(arguments, "skip", 0)?;
        let mut argv = vec![
            "git".into(),
            "-C".into(),
            self.root.display().to_string(),
            "log".into(),
            format!("--max-count={}", count + 1),
            format!("--skip={skip}"),
            "--date=iso-strict".into(),
            "--pretty=format:%H%x1f%h%x1f%an%x1f%ae%x1f%ad%x1f%s%x1e".into(),
            reference.clone(),
        ];
        if requested.display != "." {
            argv.extend(["--".into(), requested.display.clone()]);
        }
        let output = self.run_sync(argv, 15_000, 2_000_000)?;
        ensure_exit_ok(&output, "git log failed")?;
        let mut commits = Vec::new();
        for record in output["stdout"].as_str().unwrap_or_default().split('\x1e') {
            let fields = record.trim_matches('\n').split('\x1f').collect::<Vec<_>>();
            if fields.len() >= 6 && !fields[0].is_empty() {
                commits.push(serde_json::json!({"hash":fields[0],"short_hash":fields[1],"author_name":fields[2],"author_email":fields[3],"author_date":fields[4],"subject":fields[5]}));
            }
        }
        let truncated = commits.len() > count;
        commits.truncate(count);
        Ok(
            serde_json::json!({"is_repo":true,"ref":reference,"path":requested.display,"max_count":count,"skip":skip,"commits":commits,"truncated":truncated,"warnings":if truncated{vec!["commit limit reached"]}else{Vec::<&str>::new()}}),
        )
    }

    pub fn git_show(&self, arguments: &Map<String, Value>) -> Result<Value, ReCtmError> {
        if !is_git_repo(&self.root) {
            return Ok(
                serde_json::json!({"is_repo":false,"content":"","files":[],"truncated":false,"warnings":[]}),
            );
        }
        let reference = validate_git_ref(text_or(arguments, "rev", "HEAD"))?;
        let context = integer_or(arguments, "context_lines", 3)?;
        let max_bytes = usize_from(arguments, "max_bytes", 262_144)?;
        let mut argv = vec![
            "git".into(),
            "-C".into(),
            self.root.display().to_string(),
            "show".into(),
            "--no-ext-diff".into(),
            "--no-textconv".into(),
            "--format=fuller".into(),
            format!("--unified={context}"),
        ];
        if !bool_or(arguments, "include_diff", true) {
            argv.push("--no-patch".into());
        }
        argv.push(reference.clone());
        let filters = path_filters(arguments)?;
        if !filters.is_empty() {
            argv.push("--".into());
            argv.extend(filters);
        }
        let output = self.run_sync(argv, 15_000, max_bytes.saturating_mul(2).max(65536))?;
        ensure_exit_ok(&output, "git show failed")?;
        let (content, truncated) =
            truncate_string_bytes(output["stdout"].as_str().unwrap_or_default(), max_bytes);
        Ok(
            serde_json::json!({"is_repo":true,"rev":reference,"files":parse_diff_files(&content),"content":content,"truncated":truncated,"warnings":if truncated{vec!["output truncated"]}else{Vec::<&str>::new()}}),
        )
    }

    pub fn git_blame(&self, arguments: &Map<String, Value>) -> Result<Value, ReCtmError> {
        let requested = text_or(arguments, "path", "");
        let resolved = self.resolve_existing(requested)?;
        if resolved.path.is_dir() {
            return Err(validation_code("IS_DIRECTORY", "Path is a directory."));
        }
        if !is_git_repo(&self.root) {
            return Ok(
                serde_json::json!({"is_repo":false,"path":resolved.display,"lines":[],"truncated":false,"warnings":[]}),
            );
        }
        let start = integer_or(arguments, "start_line", 1)?;
        let max_lines = integer_or(arguments, "max_lines", 200)?;
        let requested_end =
            optional_integer(arguments, "end_line")?.unwrap_or(start + max_lines - 1);
        if requested_end < start {
            return Err(validation("end_line must be >= start_line"));
        }
        let final_line = requested_end.min(start + max_lines - 1);
        let reference = optional_text(arguments, "rev")
            .map(validate_git_ref)
            .transpose()?;
        let mut argv = vec![
            "git".into(),
            "-C".into(),
            self.root.display().to_string(),
            "blame".into(),
            "--line-porcelain".into(),
            "-L".into(),
            format!("{start},{final_line}"),
        ];
        if let Some(value) = &reference {
            argv.push(value.clone());
        }
        argv.extend(["--".into(), resolved.display.clone()]);
        let output = self.run_sync(argv, 15_000, 2_000_000)?;
        ensure_exit_ok(&output, "git blame failed")?;
        let lines = parse_blame(output["stdout"].as_str().unwrap_or_default());
        let truncated = requested_end > final_line;
        let mut result = serde_json::json!({"is_repo":true,"path":resolved.display,"rev":reference,"start_line":start,"end_line":final_line,"max_lines":max_lines,"lines":lines,"truncated":truncated,"warnings":if truncated{vec!["line limit reached"]}else{Vec::<&str>::new()}});
        if truncated {
            result["next_action"] = serde_json::json!({"tool":"git_blame","arguments":{"path":requested,"start_line":final_line+1,"end_line":requested_end,"max_lines":max_lines}});
        }
        Ok(result)
    }

    pub fn view_image(&self, arguments: &Map<String, Value>) -> Result<Value, ReCtmError> {
        let resolved = self.resolve_existing(text_or(arguments, "path", ""))?;
        if resolved.path.is_dir() {
            return Err(validation_code("IS_DIRECTORY", "Path is a directory."));
        }
        let max_bytes = usize_from(arguments, "max_bytes", 5_242_880)?;
        let data = fs::read(&resolved.path).map_err(io_error)?;
        let (mime, width, height) = identify_image(&data)
            .ok_or_else(|| validation_code("BINARY_FILE", "File is not a supported image."))?;
        if data.len() > max_bytes {
            return Err(
                ReCtmError::new("OUTPUT_TOO_LARGE", "Image exceeds max_bytes.")
                    .with_category(ErrorCategory::Validation)
                    .with_details(serde_json::json!({"bytes":data.len(),"max_bytes":max_bytes})),
            );
        }
        Ok(
            serde_json::json!({"path":resolved.display,"mime_type":mime,"bytes":data.len(),"width":width,"height":height,"resized":false,"original":{"bytes":data.len(),"width":width,"height":height,"mime_type":mime},"_mcp_image_data":STANDARD.encode(data),"warnings":[]}),
        )
    }

    pub fn export_text(
        &self,
        path: &str,
        content: &str,
        expected_sha256: Option<&str>,
    ) -> Result<Value, ReCtmError> {
        let target = self.resolve_for_write(path)?;
        if target.existed {
            let actual = sha256_file(&target.path)?;
            let Some(expected) = expected_sha256 else {
                return Err(ReCtmError::new(
                    "EXPORT_BASELINE_REQUIRED",
                    "Overwriting an existing research artifact requires expected_sha256.",
                )
                .with_category(ErrorCategory::Conflict)
                .with_retryable(true)
                .with_details(serde_json::json!({"path":target.display,"actual_sha256":actual})));
            };
            if expected != actual {
                return Err(ReCtmError::new(
                    "PATCH_BASELINE_MISMATCH",
                    "File changed before write.",
                )
                .with_category(ErrorCategory::Conflict)
                .with_retryable(true));
            }
        }
        atomic_write(&target.path, content.as_bytes())?;
        Ok(
            serde_json::json!({"ok":true,"path":target.display,"sha256":sha256_text(content),"bytes":content.len()}),
        )
    }
    pub fn ensure_verified_latex(&self, path: &str, content: &str) -> Result<Value, ReCtmError> {
        let target = self.resolve_for_write(path)?;
        let digest = sha256_text(content);
        if target.existed {
            let actual = sha256_file(&target.path)?;
            if actual != digest {
                return Err(ReCtmError::new("EXPORT_PATH_CONFLICT","Automatic verified export will not overwrite different workspace content.").with_category(ErrorCategory::Conflict).with_retryable(true).with_details(serde_json::json!({"path":target.display,"actual_sha256":actual,"verified_sha256":digest})));
            }
            return Ok(
                serde_json::json!({"ok":true,"status":"unchanged","path":target.display,"sha256":digest,"bytes":content.len()}),
            );
        }
        atomic_write(&target.path, content.as_bytes())?;
        Ok(
            serde_json::json!({"ok":true,"status":"created","path":target.display,"sha256":digest,"bytes":content.len()}),
        )
    }

    fn run_sync(
        &self,
        argv: Vec<String>,
        timeout_ms: u64,
        max_output_bytes: usize,
    ) -> Result<Value, ReCtmError> {
        let result = self.commands.start(CommandRequest {
            argv,
            env: BTreeMap::new(),
            timeout_ms,
            yield_time_ms: 30_000,
            max_output_bytes,
            stdin: String::new(),
            tty: false,
            verbosity: None,
            preview_bytes: max_output_bytes.min(4096),
        })?;
        if result.get("status").and_then(Value::as_str) == Some("running") {
            let id = result
                .get("command_id")
                .and_then(Value::as_str)
                .ok_or_else(|| internal("command id missing"))?
                .to_owned();
            return self.commands.poll(PollRequest {
                command_id: id,
                chars: String::new(),
                yield_time_ms: 30_000,
                max_output_bytes,
                verbosity: None,
                preview_bytes: max_output_bytes.min(4096),
            });
        }
        Ok(result)
    }
    pub fn close(&self) -> Result<(), ReCtmError> {
        self.commands.close()
    }

    fn assert_inside(&self, resolved: &Path, candidate: &Path) -> Result<(), ReCtmError> {
        if !resolved.starts_with(&self.root) {
            let code = if fs::symlink_metadata(candidate)
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                "SYMLINK_ESCAPE"
            } else {
                "PATH_OUTSIDE_WORKSPACE"
            };
            return Err(ReCtmError::new(code, "Path escapes the native workspace.")
                .with_category(ErrorCategory::Security));
        }
        if resolved.starts_with(&self.private_root) {
            return Err(ReCtmError::new(
                "PRIVATE_VAULT_DENIED",
                "Native tools cannot access the Rethlas private vault.",
            )
            .with_category(ErrorCategory::Security));
        }
        Ok(())
    }
}

fn validate_relative_path(raw: &str) -> Result<PathBuf, ReCtmError> {
    if raw.is_empty() || raw.contains('\0') {
        return Err(validation("Path must be a non-empty string."));
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        return Err(
            ReCtmError::new("ABSOLUTE_PATH_DENIED", "Absolute paths are denied.")
                .with_category(ErrorCategory::Security),
        );
    }
    for component in path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::Prefix(_) | Component::RootDir
        ) {
            return Err(ReCtmError::new(
                "PATH_OUTSIDE_WORKSPACE",
                "Path escapes the native workspace.",
            )
            .with_category(ErrorCategory::Security));
        }
    }
    Ok(path.to_path_buf())
}
fn display_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .map(|value| {
            if value.as_os_str().is_empty() {
                ".".to_owned()
            } else {
                value.to_string_lossy().replace('\\', "/")
            }
        })
        .unwrap_or_else(|| path.display().to_string())
}
fn ignored(name: &str, include_hidden: bool, include_ignored: bool) -> bool {
    (!include_hidden && name.starts_with('.'))
        || (!include_ignored && DEFAULT_EXCLUDED.contains(&name))
}
fn modified_seconds(metadata: &fs::Metadata) -> f64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map_or(0.0, |duration| duration.as_secs_f64())
}
fn glob_match(path: &str, pattern: &str) -> bool {
    if matches!(pattern, "*" | "**/*") {
        return true;
    }
    let mut regex = String::from("^");
    let chars = pattern.chars().collect::<Vec<_>>();
    let mut index = 0;
    while index < chars.len() {
        match chars[index] {
            '*' if index + 1 < chars.len() && chars[index + 1] == '*' => {
                regex.push_str(".*");
                index += 2;
                continue;
            }
            '*' => regex.push_str("[^/]*"),
            '?' => regex.push('.'),
            c => regex.push_str(&regex::escape(&c.to_string())),
        }
        index += 1;
    }
    regex.push('$');
    Regex::new(&regex).is_ok_and(|compiled| compiled.is_match(path))
}
fn split_lines_keep_ends(text: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0;
    for (index, character) in text.char_indices() {
        if character == '\n' {
            result.push(&text[start..=index]);
            start = index + 1;
        }
    }
    if start < text.len() {
        result.push(&text[start..]);
    }
    result
}
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), ReCtmError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(io_error)?;
    }
    let temporary = path.with_extension(format!("{}.mtm.tmp", std::process::id()));
    fs::write(&temporary, data).map_err(io_error)?;
    fs::rename(&temporary, path).map_err(io_error)
}
fn sha256_file(path: &Path) -> Result<String, ReCtmError> {
    Ok(sha256_bytes(&fs::read(path).map_err(io_error)?))
}
fn sha256_text(value: &str) -> String {
    sha256_bytes(value.as_bytes())
}
fn sha256_bytes(value: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(value);
    format!("{:x}", digest.finalize())
}
fn absolute_normalized(path: &Path) -> Result<PathBuf, ReCtmError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir().map_err(io_error)?.join(path))
    }
}
fn is_git_repo(path: &Path) -> bool {
    path.join(".git").exists()
        || std::process::Command::new("git")
            .args(["-C", &path.display().to_string(), "rev-parse", "--git-dir"])
            .output()
            .is_ok_and(|output| output.status.success())
}
fn ensure_exit_ok(output: &Value, fallback: &str) -> Result<(), ReCtmError> {
    if output["exit_code"].as_i64() == Some(0) {
        Ok(())
    } else {
        Err(git_error(output, fallback))
    }
}
fn git_error(output: &Value, fallback: &str) -> ReCtmError {
    ReCtmError::new(
        "GIT_ERROR",
        output["stderr"]
            .as_str()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or(fallback)
            .trim(),
    )
    .with_category(ErrorCategory::Runtime)
}
fn parse_branch(value: &str) -> (String, String, i64, i64) {
    let mut branch = value.to_owned();
    let mut upstream = String::new();
    let mut ahead = 0;
    let mut behind = 0;
    if let Some((left, tracking)) = value.split_once("...") {
        branch = left.to_owned();
        let (right, status) = tracking.split_once(' ').unwrap_or((tracking, ""));
        upstream = right.to_owned();
        if let Some(raw) = status.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
            for part in raw.split(',').map(str::trim) {
                if let Some(n) = part.strip_prefix("ahead ").and_then(|v| v.parse().ok()) {
                    ahead = n;
                }
                if let Some(n) = part.strip_prefix("behind ").and_then(|v| v.parse().ok()) {
                    behind = n;
                }
            }
        }
    }
    (branch, upstream, ahead, behind)
}
fn path_filters(arguments: &Map<String, Value>) -> Result<Vec<String>, ReCtmError> {
    let mut result = Vec::new();
    if let Some(path) = optional_text(arguments, "path") {
        if !path.is_empty() {
            result.push(
                validate_relative_path(path)?
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    if let Some(paths) = string_array(arguments.get("paths")) {
        for path in paths {
            result.push(
                validate_relative_path(&path)?
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    Ok(result)
}
fn validate_git_ref(value: &str) -> Result<String, ReCtmError> {
    if value.is_empty()
        || value.starts_with('-')
        || value.contains(char::is_whitespace)
        || value.contains("..")
        || value.contains("@{")
    {
        return Err(validation("invalid git ref"));
    }
    Ok(value.to_owned())
}
fn parse_diff_files(text: &str) -> Vec<String> {
    let mut files = BTreeSet::new();
    for line in text.lines() {
        if let Some(path) = line
            .strip_prefix("+++ b/")
            .or_else(|| line.strip_prefix("--- a/"))
        {
            if path != "/dev/null" {
                files.insert(path.to_owned());
            }
        }
    }
    files.into_iter().collect()
}
fn parse_blame(text: &str) -> Vec<Value> {
    let mut rows = Vec::new();
    let mut current = Map::new();
    for line in text.lines() {
        if let Some(stripped) = line.strip_prefix('\t') {
            current.insert("content".to_owned(), Value::String(stripped.to_owned()));
            rows.push(Value::Object(std::mem::take(&mut current)));
            continue;
        }
        let mut split = line.splitn(2, ' ');
        let key = split.next().unwrap_or_default();
        let value = split.next().unwrap_or_default();
        match key {
            "author" | "summary" => {
                current.insert(key.to_owned(), Value::String(value.to_owned()));
            }
            "author-mail" => {
                current.insert(
                    "author_email".to_owned(),
                    Value::String(value.trim_matches(['<', '>']).to_owned()),
                );
            }
            "author-time" => {
                if let Ok(timestamp) = value.parse::<i64>() {
                    current.insert("author_time".to_owned(), Value::from(timestamp));
                }
            }
            _ if current.is_empty() && key.len() == 40 => {
                current.insert("commit".to_owned(), Value::String(key.to_owned()));
                let fields = line.split_whitespace().collect::<Vec<_>>();
                if let Some(line_no) = fields.get(1).and_then(|value| value.parse::<i64>().ok()) {
                    current.insert("original_line".to_owned(), Value::from(line_no));
                }
                if let Some(line_no) = fields.get(2).and_then(|value| value.parse::<i64>().ok()) {
                    current.insert("line".to_owned(), Value::from(line_no));
                }
            }
            _ => {}
        }
    }
    rows
}
fn identify_image(data: &[u8]) -> Option<(&'static str, Option<u32>, Option<u32>)> {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") && data.len() >= 24 {
        return Some((
            "image/png",
            Some(u32::from_be_bytes(data[16..20].try_into().ok()?)),
            Some(u32::from_be_bytes(data[20..24].try_into().ok()?)),
        ));
    }
    if (data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a")) && data.len() >= 10 {
        return Some((
            "image/gif",
            Some(u16::from_le_bytes(data[6..8].try_into().ok()?) as u32),
            Some(u16::from_le_bytes(data[8..10].try_into().ok()?) as u32),
        ));
    }
    if data.starts_with(b"\xff\xd8\xff") {
        return Some(("image/jpeg", None, None));
    }
    if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return Some(("image/webp", None, None));
    }
    None
}
fn truncate_utf8_bytes(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    String::from_utf8_lossy(&value.as_bytes()[..max]).into_owned()
}
fn truncate_string_bytes(value: &str, max: usize) -> (String, bool) {
    if value.len() <= max {
        (value.to_owned(), false)
    } else {
        (
            String::from_utf8_lossy(&value.as_bytes()[..max]).into_owned(),
            true,
        )
    }
}
fn text_or<'a>(map: &'a Map<String, Value>, key: &str, default: &'a str) -> &'a str {
    map.get(key).and_then(Value::as_str).unwrap_or(default)
}
fn optional_text<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}
fn bool_or(map: &Map<String, Value>, key: &str, default: bool) -> bool {
    map.get(key).and_then(Value::as_bool).unwrap_or(default)
}
fn optional_integer(map: &Map<String, Value>, key: &str) -> Result<Option<i64>, ReCtmError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_i64()
            .map(Some)
            .ok_or_else(|| validation(&format!("{key} must be an integer"))),
    }
}
fn integer_or(map: &Map<String, Value>, key: &str, default: i64) -> Result<i64, ReCtmError> {
    optional_integer(map, key).map(|value| value.unwrap_or(default))
}
fn usize_from(map: &Map<String, Value>, key: &str, default: usize) -> Result<usize, ReCtmError> {
    let raw = integer_or(map, key, i64::try_from(default).unwrap_or(i64::MAX))?;
    usize::try_from(raw).map_err(|_| validation(&format!("{key} must be non-negative")))
}
fn string_array(value: Option<&Value>) -> Option<Vec<String>> {
    value.and_then(Value::as_array).map(|items| {
        items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    })
}
fn json_text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}
fn json_f64(value: &Value, key: &str) -> f64 {
    value.get(key).and_then(Value::as_f64).unwrap_or_default()
}
fn validation(message: &str) -> ReCtmError {
    ReCtmError::new("INVALID_ARGUMENT", message).with_category(ErrorCategory::Validation)
}
fn validation_code(code: &str, message: &str) -> ReCtmError {
    ReCtmError::new(code, message).with_category(ErrorCategory::Validation)
}
fn invalid_details(message: &str, details: Value) -> ReCtmError {
    validation(message).with_details(details)
}
fn internal(message: &str) -> ReCtmError {
    ReCtmError::new("INTERNAL_ERROR", message).with_category(ErrorCategory::Internal)
}
fn io_error(error: std::io::Error) -> ReCtmError {
    ReCtmError::new("RUNTIME_IO_ERROR", error.to_string()).with_category(ErrorCategory::Runtime)
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;
    #[test]
    fn workspace_rejects_escape_and_reads_text() -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        fs::write(temp.path().join("a.txt"), "one\ntwo\n").map_err(io_error)?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        assert!(workspace.resolve_existing("../escape").is_err());
        let result = workspace.read_file(&Map::from_iter([(
            "path".into(),
            Value::String("a.txt".into()),
        )]))?;
        assert_eq!(result["total_lines"], 2);
        Ok(())
    }

    fn run_git(root: &Path, arguments: &[&str]) -> Result<(), ReCtmError> {
        let status = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(arguments)
            .status()
            .map_err(io_error)?;
        if !status.success() {
            return Err(internal("test git command failed"));
        }
        Ok(())
    }

    fn patch_invocation(patch: &str, dry_run: bool) -> Result<PatchInvocation, ReCtmError> {
        let arguments = serde_json::json!({"patch":patch,"dry_run":dry_run})
            .as_object()
            .cloned()
            .unwrap_or_default();
        PatchInvocation::parse(&arguments)
    }

    #[test]
    fn patch_permission_facts_follow_git_ignore_and_component_rules() -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        fs::create_dir(temp.path().join("ignored")).map_err(io_error)?;
        fs::create_dir(temp.path().join("nested")).map_err(io_error)?;
        fs::create_dir(temp.path().join("builder")).map_err(io_error)?;
        fs::create_dir(temp.path().join("target")).map_err(io_error)?;
        fs::write(temp.path().join(".gitignore"), "ignored/\n").map_err(io_error)?;
        fs::write(temp.path().join("nested/.gitignore"), "*.tmp\n!keep.tmp\n").map_err(io_error)?;
        run_git(temp.path(), &["init", "--quiet"])?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        let patch = concat!(
            "*** Begin Patch\n",
            "*** Add File: ignored/root.txt\n",
            "+root\n",
            "*** Add File: nested/drop.tmp\n",
            "+drop\n",
            "*** Add File: nested/keep.tmp\n",
            "+keep\n",
            "*** Add File: builder/file.txt\n",
            "+builder\n",
            "*** Add File: target/file.txt\n",
            "+target\n",
            "*** End Patch\n",
        );
        let invocation = patch_invocation(patch, false)?;
        let facts = workspace.collect_patch_permission_facts(&invocation)?;
        let facts = facts
            .iter()
            .map(|fact| (fact.path(), fact))
            .collect::<BTreeMap<_, _>>();
        assert!(facts["ignored/root.txt"].git_ignored());
        assert!(facts["nested/drop.tmp"].git_ignored());
        assert!(!facts["nested/keep.tmp"].git_ignored());
        assert!(!facts["builder/file.txt"].canonical_generated_component());
        assert!(facts["target/file.txt"].canonical_generated_component());
        Ok(())
    }

    #[test]
    fn patch_permission_facts_cover_ignored_updates_deletes_and_moves() -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        fs::create_dir(temp.path().join("ignored")).map_err(io_error)?;
        fs::create_dir(temp.path().join("ordinary")).map_err(io_error)?;
        fs::write(temp.path().join(".gitignore"), "ignored/\n").map_err(io_error)?;
        for path in [
            "ignored/update.txt",
            "ignored/delete.txt",
            "ordinary/move-in.txt",
            "ignored/move-out.txt",
        ] {
            fs::write(temp.path().join(path), "old\n").map_err(io_error)?;
        }
        run_git(temp.path(), &["init", "--quiet"])?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;

        let patches = [
            concat!(
                "*** Begin Patch\n",
                "*** Update File: ignored/update.txt\n",
                "@@\n",
                "-old\n",
                "+new\n",
                "*** End Patch\n",
            ),
            concat!(
                "*** Begin Patch\n",
                "*** Delete File: ignored/delete.txt\n",
                "*** End Patch\n",
            ),
            concat!(
                "*** Begin Patch\n",
                "*** Update File: ordinary/move-in.txt\n",
                "*** Move to: ignored/move-in.txt\n",
                "@@\n",
                "-old\n",
                "+new\n",
                "*** End Patch\n",
            ),
            concat!(
                "*** Begin Patch\n",
                "*** Update File: ignored/move-out.txt\n",
                "*** Move to: ordinary/move-out.txt\n",
                "@@\n",
                "-old\n",
                "+new\n",
                "*** End Patch\n",
            ),
        ];
        for patch in patches {
            let invocation = patch_invocation(patch, false)?;
            let facts = workspace.collect_patch_permission_facts(&invocation)?;
            assert_eq!(
                mtm_core::classify_patch_permissions(&invocation, &facts)?,
                vec![mtm_contracts::NativePermissionKind::WriteGeneratedOrIgnored]
            );
        }

        let ignored_add = concat!(
            "*** Begin Patch\n",
            "*** Add File: ignored/dry-run.txt\n",
            "+new\n",
            "*** End Patch\n",
        );
        let dry_run = patch_invocation(ignored_add, true)?;
        let dry_run_facts = workspace.collect_patch_permission_facts(&dry_run)?;
        assert!(dry_run_facts[0].git_ignored());
        assert!(mtm_core::classify_patch_permissions(&dry_run, &dry_run_facts)?.is_empty());
        assert!(!temp.path().join("ignored/dry-run.txt").exists());

        let real = patch_invocation(ignored_add, false)?;
        let real_facts = workspace.collect_patch_permission_facts(&real)?;
        assert_eq!(
            mtm_core::classify_patch_permissions(&real, &real_facts)?,
            vec![mtm_contracts::NativePermissionKind::WriteGeneratedOrIgnored]
        );
        assert!(!temp.path().join("ignored/dry-run.txt").exists());
        assert_eq!(
            fs::read_to_string(temp.path().join("ignored/update.txt")).map_err(io_error)?,
            "old\n"
        );
        assert!(temp.path().join("ignored/delete.txt").exists());
        assert!(!temp.path().join("ignored/move-in.txt").exists());
        assert!(!temp.path().join("ordinary/move-out.txt").exists());
        Ok(())
    }

    #[test]
    fn patch_permission_fact_collection_denies_symlink_destination() -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        fs::write(temp.path().join("real.txt"), "unchanged\n").map_err(io_error)?;
        std::os::unix::fs::symlink("real.txt", temp.path().join("link.txt")).map_err(io_error)?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        let invocation = patch_invocation(
            "*** Begin Patch\n*** Add File: link.txt\n+changed\n*** End Patch\n",
            false,
        )?;
        assert_eq!(
            workspace
                .collect_patch_permission_facts(&invocation)
                .map_err(|error| error.code),
            Err("SYMLINK_WRITE_DENIED".to_owned())
        );
        assert_eq!(
            fs::read_to_string(temp.path().join("real.txt")).map_err(io_error)?,
            "unchanged\n"
        );
        Ok(())
    }

    #[test]
    fn patch_permission_facts_support_non_repository_dry_run_without_writes()
    -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        let patch = "*** Begin Patch\n*** Add File: ordinary.txt\n+text\n*** End Patch\n";
        let invocation = patch_invocation(patch, true)?;
        let facts = workspace.collect_patch_permission_facts(&invocation)?;
        assert_eq!(facts.len(), 1);
        assert!(!facts[0].git_ignored());
        assert!(!temp.path().join("ordinary.txt").exists());
        assert!(mtm_core::classify_patch_permissions(&invocation, &facts)?.is_empty());
        Ok(())
    }

    #[test]
    fn patch_permission_facts_fail_closed_on_broken_git_metadata() -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        fs::write(temp.path().join(".git"), "gitdir: /definitely/missing\n").map_err(io_error)?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        let invocation = patch_invocation(
            "*** Begin Patch\n*** Add File: ordinary.txt\n+text\n*** End Patch\n",
            false,
        )?;
        assert_eq!(
            workspace
                .collect_patch_permission_facts(&invocation)
                .map_err(|error| error.code),
            Err("NATIVE_GIT_IGNORE_LOOKUP_FAILED".to_owned())
        );
        Ok(())
    }

    #[test]
    fn dry_run_fact_collection_validates_hunks_without_writing() -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        let target = temp.path().join("source.txt");
        fs::write(&target, "actual\n").map_err(io_error)?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        let invalid = patch_invocation(
            "*** Begin Patch\n*** Update File: source.txt\n@@\n-missing\n+changed\n*** End Patch\n",
            true,
        )?;
        assert_eq!(
            workspace
                .collect_patch_permission_facts(&invalid)
                .map_err(|error| error.code),
            Err("PATCH_CONTEXT_NOT_FOUND".to_owned())
        );
        assert_eq!(fs::read_to_string(target).map_err(io_error)?, "actual\n");
        Ok(())
    }
}
