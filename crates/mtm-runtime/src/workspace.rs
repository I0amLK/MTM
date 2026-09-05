use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use mtm_contracts::{ErrorCategory, ReCtmError};
use mtm_core::{
    PatchInvocation, PatchOperation, PatchPathFact, apply_update_hunks, canonical_arguments_sha256,
    parse_patch,
};
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
const PATCH_REVALIDATION_ATTEMPTS: usize = 3;
const PATCH_TEMP_NAME_ATTEMPTS: usize = 8;
const MAX_GIT_METADATA_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct ResolvedPath {
    pub display: String,
    pub path: PathBuf,
    pub existed: bool,
}

#[derive(Clone, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

#[derive(Clone, Eq, PartialEq)]
struct FileFingerprint {
    identity: FileIdentity,
    sha256: String,
}

#[derive(Eq, PartialEq)]
enum PatchBaseline {
    Missing,
    File { fingerprint: FileFingerprint },
}

struct PreparedPathChange {
    relative_path: String,
    resolution: PatchPathResolution,
    resolved: ResolvedPath,
    baseline: PatchBaseline,
    final_content: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PatchPathResolution {
    ExistingCompatibility,
    ForWrite,
}

struct PreparedAffectedFile {
    operation: String,
    path: String,
}

enum PatchAuthoritySnapshot {
    /// The accepted 0.4.0 production path has no Git-based permission
    /// authority. Keeping that state explicit prevents D4 from silently
    /// introducing a new production dependency on Git before D5 cutover.
    ProductionCompatibility,
    Classified {
        path_facts: Vec<PatchPathFact>,
        git_metadata: GitMetadataSnapshot,
    },
}

#[derive(Clone, Copy)]
enum PatchPreparationSemantics {
    ProductionCompatibility,
    Authority,
}

#[derive(Clone, Eq, PartialEq)]
enum MetadataNodeFingerprint {
    Missing,
    Regular(FileFingerprint),
    Directory(FileIdentity),
    Symlink {
        identity: FileIdentity,
        target: PathBuf,
    },
    Other(FileIdentity),
}

#[derive(Eq, PartialEq)]
struct GitMetadataSnapshot {
    entries: Vec<(PathBuf, MetadataNodeFingerprint)>,
}

/// A fully parsed and validated patch whose file contents and authority facts
/// have been prepared without writing to the workspace.
pub(crate) struct PreparedPatch {
    workspace_root: PathBuf,
    workspace_identity: FileIdentity,
    arguments_sha256: String,
    dry_run: bool,
    changes: Vec<PreparedPathChange>,
    authority: PatchAuthoritySnapshot,
    summary: Vec<String>,
    additions: usize,
    removals: usize,
    affected_files: Vec<PreparedAffectedFile>,
}

impl fmt::Debug for PreparedPatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (authority_state, path_fact_count, git_metadata_fingerprint_count) = match &self
            .authority
        {
            PatchAuthoritySnapshot::ProductionCompatibility => ("production_compatibility", 0, 0),
            PatchAuthoritySnapshot::Classified {
                path_facts,
                git_metadata,
            } => ("classified", path_facts.len(), git_metadata.entries.len()),
        };
        formatter
            .debug_struct("PreparedPatch")
            .field("workspace_root", &"[REDACTED]")
            .field("arguments_sha256", &self.arguments_sha256)
            .field("dry_run", &self.dry_run)
            .field("change_count", &self.changes.len())
            .field("authority_state", &authority_state)
            .field("path_fact_count", &path_fact_count)
            .field(
                "git_metadata_fingerprint_count",
                &git_metadata_fingerprint_count,
            )
            .field("patch_content", &"[REDACTED]")
            .finish()
    }
}

impl PreparedPatch {
    #[must_use]
    pub(crate) const fn dry_run(&self) -> bool {
        self.dry_run
    }

    #[must_use]
    pub(crate) fn arguments_sha256(&self) -> &str {
        &self.arguments_sha256
    }

    #[must_use]
    pub(crate) fn path_facts(&self) -> Option<&[PatchPathFact]> {
        match &self.authority {
            PatchAuthoritySnapshot::ProductionCompatibility => None,
            PatchAuthoritySnapshot::Classified { path_facts, .. } => Some(path_facts),
        }
    }

    fn git_metadata(&self) -> Option<&GitMetadataSnapshot> {
        match &self.authority {
            PatchAuthoritySnapshot::ProductionCompatibility => None,
            PatchAuthoritySnapshot::Classified { git_metadata, .. } => Some(git_metadata),
        }
    }

    fn result(&self, warnings: Vec<String>) -> Value {
        serde_json::json!({
            "clean":true,
            "dry_run":self.dry_run,
            "summary":self.summary.join("\n"),
            "additions":self.additions,
            "removals":self.removals,
            "affected_files":self.affected_files.iter().map(|affected|serde_json::json!({
                "operation":affected.operation,
                "path":affected.path,
            })).collect::<Vec<_>>(),
            "warnings":warnings,
        })
    }
}

#[derive(Clone)]
pub struct NativeWorkspace {
    root: PathBuf,
    private_root: PathBuf,
    commands: CommandManager,
    patch_commit_lock: Arc<Mutex<()>>,
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
            patch_commit_lock: Arc::new(Mutex::new(())),
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

    /// Collect path and Git-ignore facts with the authority-ready no-write
    /// preparation path. Production keeps its explicit compatibility variant
    /// until the D5 permission cutover.
    pub fn collect_patch_permission_facts(
        &self,
        invocation: &PatchInvocation,
    ) -> Result<Vec<PatchPathFact>, ReCtmError> {
        self.prepare_patch(invocation)?
            .path_facts()
            .map(<[PatchPathFact]>::to_vec)
            .ok_or_else(|| internal("authority patch preparation omitted path facts"))
    }

    /// Prepare an already parsed typed invocation without a workspace write.
    pub(crate) fn prepare_patch(
        &self,
        invocation: &PatchInvocation,
    ) -> Result<PreparedPatch, ReCtmError> {
        self.prepare_patch_operations(
            invocation.operations(),
            invocation.dry_run(),
            invocation.arguments_sha256(),
            PatchPreparationSemantics::Authority,
        )
    }

    fn prepare_patch_operations(
        &self,
        operations: &[PatchOperation],
        dry_run: bool,
        arguments_sha256: &str,
        semantics: PatchPreparationSemantics,
    ) -> Result<PreparedPatch, ReCtmError> {
        let workspace_identity = stable_directory_identity(&self.root)?;
        let mut changes = BTreeMap::new();
        let mut virtual_existence = BTreeMap::new();
        let mut affected_paths = BTreeSet::new();
        let mut additions = 0_usize;
        let mut removals = 0_usize;
        let mut summary = Vec::new();
        let mut affected_files = Vec::new();

        for operation in operations {
            if matches!(semantics, PatchPreparationSemantics::Authority) {
                self.deny_patch_symlink_components(&operation.path)?;
                if let Some(destination) = &operation.move_to {
                    self.deny_patch_symlink_components(destination)?;
                }
            }
            match operation.kind.as_str() {
                "add" => {
                    let target = self.resolve_for_write(&operation.path)?;
                    if target.existed {
                        return Err(
                            ReCtmError::new("PATCH_FAILED", "Add target already exists.")
                                .with_category(ErrorCategory::Conflict),
                        );
                    }
                    let content = operation.add_content.clone().unwrap_or_default();
                    additions += content.lines().count();
                    summary.push(format!("A {}", operation.path));
                    affected_files.push(PreparedAffectedFile {
                        operation: "add".to_owned(),
                        path: target.display.clone(),
                    });
                    affected_paths.insert(operation.path.clone());
                    set_prepared_virtual_existence(&mut virtual_existence, &target.path, true);
                    insert_prepared_change(
                        &mut changes,
                        PreparedPathChange {
                            relative_path: operation.path.clone(),
                            resolution: PatchPathResolution::ForWrite,
                            resolved: target,
                            baseline: PatchBaseline::Missing,
                            final_content: Some(content.into_bytes()),
                        },
                    )?;
                }
                "delete" => {
                    let (source, baseline, old) =
                        self.capture_existing_patch_file(&operation.path, semantics)?;
                    removals += old.lines().count();
                    summary.push(format!("D {}", operation.path));
                    affected_files.push(PreparedAffectedFile {
                        operation: "delete".to_owned(),
                        path: source.display.clone(),
                    });
                    affected_paths.insert(operation.path.clone());
                    remove_prepared_virtual_path(&mut virtual_existence, &source.path, &baseline)?;
                    insert_prepared_change(
                        &mut changes,
                        PreparedPathChange {
                            relative_path: operation.path.clone(),
                            resolution: patch_source_resolution(semantics),
                            resolved: source,
                            baseline,
                            final_content: None,
                        },
                    )?;
                }
                "update" => {
                    let (source, baseline, old) =
                        self.capture_existing_patch_file(&operation.path, semantics)?;
                    let updated = apply_update_hunks(&old, &operation.hunks, &operation.path)?;
                    additions += updated.lines().count().saturating_sub(old.lines().count());
                    removals += old.lines().count().saturating_sub(updated.lines().count());
                    affected_paths.insert(operation.path.clone());
                    if let Some(destination) = &operation.move_to {
                        let (target, target_baseline) =
                            self.capture_patch_destination(destination)?;
                        summary.push(format!("R {} -> {destination}", operation.path));
                        affected_files.push(PreparedAffectedFile {
                            operation: "update".to_owned(),
                            path: target.display.clone(),
                        });
                        affected_paths.insert(destination.clone());
                        set_prepared_virtual_existence(&mut virtual_existence, &target.path, true);
                        insert_prepared_change(
                            &mut changes,
                            PreparedPathChange {
                                relative_path: destination.clone(),
                                resolution: PatchPathResolution::ForWrite,
                                resolved: target,
                                baseline: target_baseline,
                                final_content: Some(updated.into_bytes()),
                            },
                        )?;
                        remove_prepared_virtual_path(
                            &mut virtual_existence,
                            &source.path,
                            &baseline,
                        )?;
                        insert_prepared_change(
                            &mut changes,
                            PreparedPathChange {
                                relative_path: operation.path.clone(),
                                resolution: patch_source_resolution(semantics),
                                resolved: source,
                                baseline,
                                final_content: None,
                            },
                        )?;
                    } else {
                        summary.push(format!("M {}", operation.path));
                        affected_files.push(PreparedAffectedFile {
                            operation: "update".to_owned(),
                            path: source.display.clone(),
                        });
                        set_prepared_virtual_existence(&mut virtual_existence, &source.path, true);
                        insert_prepared_change(
                            &mut changes,
                            PreparedPathChange {
                                relative_path: operation.path.clone(),
                                resolution: patch_source_resolution(semantics),
                                resolved: source,
                                baseline,
                                final_content: Some(updated.into_bytes()),
                            },
                        )?;
                    }
                }
                _ => return Err(validation_code("PATCH_FAILED", "Unknown patch operation.")),
            }
        }

        let authority = match semantics {
            PatchPreparationSemantics::ProductionCompatibility => {
                PatchAuthoritySnapshot::ProductionCompatibility
            }
            PatchPreparationSemantics::Authority => {
                let (path_facts, git_metadata) =
                    self.collect_patch_authority_facts(&affected_paths)?;
                PatchAuthoritySnapshot::Classified {
                    path_facts,
                    git_metadata,
                }
            }
        };
        if stable_directory_identity(&self.root)? != workspace_identity {
            return Err(patch_authority_facts_changed(
                "The Native workspace root changed during patch preparation.",
            ));
        }
        Ok(PreparedPatch {
            workspace_root: self.root.clone(),
            workspace_identity,
            arguments_sha256: arguments_sha256.to_owned(),
            dry_run,
            changes: changes.into_values().collect(),
            authority,
            summary,
            additions,
            removals,
            affected_files,
        })
    }

    fn capture_existing_patch_file(
        &self,
        path: &str,
        semantics: PatchPreparationSemantics,
    ) -> Result<(ResolvedPath, PatchBaseline, String), ReCtmError> {
        let resolved = match semantics {
            PatchPreparationSemantics::ProductionCompatibility => self.resolve_existing(path)?,
            PatchPreparationSemantics::Authority => {
                let resolved = self.resolve_for_write(path)?;
                if !resolved.existed {
                    return Err(
                        ReCtmError::new("NOT_FOUND", format!("Path not found: {path}"))
                            .with_category(ErrorCategory::NotFound),
                    );
                }
                resolved
            }
        };
        if resolved.path.is_dir() {
            return Err(validation_code("PATCH_FAILED", "Cannot patch a directory."));
        }
        let (content, fingerprint) = read_stable_regular_file(&resolved.path)?;
        let text = String::from_utf8(content).map_err(|_| {
            validation_code("UNSUPPORTED_ENCODING", "Patch target is not valid UTF-8.")
        })?;
        Ok((resolved, PatchBaseline::File { fingerprint }, text))
    }

    fn deny_patch_symlink_components(&self, path: &str) -> Result<(), ReCtmError> {
        let relative = validate_relative_path(path)?;
        let mut current = self.root.clone();
        for component in relative.components() {
            current.push(component.as_os_str());
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(ReCtmError::new(
                        "SYMLINK_WRITE_DENIED",
                        "Writing through symlinks is denied.",
                    )
                    .with_category(ErrorCategory::Security));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => return Err(io_error(error)),
            }
        }
        Ok(())
    }

    fn capture_patch_destination(
        &self,
        path: &str,
    ) -> Result<(ResolvedPath, PatchBaseline), ReCtmError> {
        let resolved = self.resolve_for_write(path)?;
        if !resolved.existed {
            return Ok((resolved, PatchBaseline::Missing));
        }
        if resolved.path.is_dir() {
            return Err(validation_code("PATCH_FAILED", "Cannot patch a directory."));
        }
        let (_content, fingerprint) = read_stable_regular_file(&resolved.path)?;
        Ok((resolved, PatchBaseline::File { fingerprint }))
    }

    fn collect_patch_authority_facts(
        &self,
        paths: &BTreeSet<String>,
    ) -> Result<(Vec<PatchPathFact>, GitMetadataSnapshot), ReCtmError> {
        for _ in 0..PATCH_REVALIDATION_ATTEMPTS {
            let repository = self.permission_git_repository()?;
            let metadata_paths = self.git_metadata_paths(paths, repository)?;
            let before = GitMetadataSnapshot::capture(&metadata_paths)?;
            let path_facts = paths
                .iter()
                .map(|path| {
                    let git_ignored = if repository {
                        self.permission_git_ignored(path)?
                    } else {
                        false
                    };
                    PatchPathFact::new(path.clone(), git_ignored)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let repository_after = self.permission_git_repository()?;
            let metadata_paths_after = self.git_metadata_paths(paths, repository_after)?;
            if repository_after != repository || metadata_paths_after != metadata_paths {
                continue;
            }
            let after = GitMetadataSnapshot::capture(&metadata_paths_after)?;
            if before == after {
                return Ok((path_facts, after));
            }
        }
        Err(patch_authority_facts_changed(
            "Git ignore metadata changed during patch preparation.",
        ))
    }

    fn git_metadata_paths(
        &self,
        paths: &BTreeSet<String>,
        repository: bool,
    ) -> Result<Vec<PathBuf>, ReCtmError> {
        let mut metadata = git_default_config_paths(&self.root);
        for ancestor in self.root.ancestors() {
            metadata.insert(ancestor.join(".git"));
        }
        if !repository {
            return expand_git_metadata_referents(metadata);
        }

        let repository_root = self.permission_git_required_path("--show-toplevel")?;
        let git_directory = self.permission_git_required_path("--absolute-git-dir")?;
        let git_common_directory = self.permission_git_required_path("--git-common-dir")?;
        if !self.root.starts_with(&repository_root) {
            return Err(git_ignore_lookup_failed(
                "Git reported a worktree that does not contain the Native workspace.",
            ));
        }
        metadata.extend([
            repository_root.join(".git"),
            git_directory.join("config"),
            git_directory.join("config.worktree"),
            git_directory.join("HEAD"),
            git_directory.join("index"),
            git_common_directory.join("config"),
            git_common_directory.join("info/exclude"),
        ]);
        metadata.extend(self.permission_git_config_paths()?);
        metadata.extend(self.permission_git_include_paths()?);
        if let Some(global_excludes) = self.permission_git_optional_config_path()? {
            metadata.insert(global_excludes);
        }
        for path in paths {
            let relative = validate_relative_path(path)?;
            let target = self.root.join(relative);
            let mut directory = target.parent();
            while let Some(current) = directory {
                if !current.starts_with(&repository_root) {
                    break;
                }
                metadata.insert(current.join(".gitignore"));
                if current == repository_root {
                    break;
                }
                directory = current.parent();
            }
        }
        expand_git_metadata_referents(metadata)
    }

    fn permission_git_config_paths(&self) -> Result<Vec<PathBuf>, ReCtmError> {
        const MAX_CONFIG_ORIGIN_BYTES: usize = 524_288;
        let output = self
            .run_sync(
                vec![
                    "git".to_owned(),
                    "-C".to_owned(),
                    self.root.display().to_string(),
                    "config".to_owned(),
                    "--null".to_owned(),
                    "--show-origin".to_owned(),
                    "--name-only".to_owned(),
                    "--list".to_owned(),
                ],
                5_000,
                MAX_CONFIG_ORIGIN_BYTES,
            )
            .map_err(|_| {
                git_ignore_lookup_failed(
                    "Git configuration origins could not be inspected during patch preparation.",
                )
            })?;
        if output["exit_code"].as_i64() != Some(0) || output["truncated"].as_bool() != Some(false) {
            return Err(git_ignore_lookup_failed(
                "Git configuration origin lookup failed or exceeded its bounded output.",
            ));
        }
        let stdout = output["stdout"].as_str().ok_or_else(|| {
            git_ignore_lookup_failed(
                "Git configuration origin lookup returned invalid text output.",
            )
        })?;
        if stdout.contains('\u{fffd}') {
            return Err(git_ignore_lookup_failed(
                "Git configuration origin paths are not valid UTF-8.",
            ));
        }

        let mut fields = stdout.split_terminator('\0');
        let mut paths = BTreeSet::new();
        while let Some(origin) = fields.next() {
            let Some(_key) = fields.next() else {
                return Err(git_ignore_lookup_failed(
                    "Git configuration origin lookup returned a malformed record.",
                ));
            };
            if let Some(raw_path) = origin.strip_prefix("file:") {
                paths.insert(self.absolute_git_config_path(raw_path));
            }
        }

        paths.extend(git_default_config_paths(&self.root));
        Ok(paths.into_iter().collect())
    }

    fn permission_git_include_paths(&self) -> Result<Vec<PathBuf>, ReCtmError> {
        const MAX_CONFIG_INCLUDE_BYTES: usize = 524_288;
        let output = self
            .run_sync(
                vec![
                    "git".to_owned(),
                    "-C".to_owned(),
                    self.root.display().to_string(),
                    "config".to_owned(),
                    "--null".to_owned(),
                    "--show-origin".to_owned(),
                    "--path".to_owned(),
                    "--get-regexp".to_owned(),
                    "^include(\\..*)?\\.path$".to_owned(),
                ],
                5_000,
                MAX_CONFIG_INCLUDE_BYTES,
            )
            .map_err(|_| {
                git_ignore_lookup_failed(
                    "Git configuration includes could not be inspected during patch preparation.",
                )
            })?;
        match output["exit_code"].as_i64() {
            Some(1) => return Ok(Vec::new()),
            Some(0) if output["truncated"].as_bool() == Some(false) => {}
            _ => {
                return Err(git_ignore_lookup_failed(
                    "Git configuration include lookup failed or exceeded its bounded output.",
                ));
            }
        }
        let stdout = output["stdout"].as_str().ok_or_else(|| {
            git_ignore_lookup_failed(
                "Git configuration include lookup returned invalid text output.",
            )
        })?;
        if stdout.contains('\u{fffd}') {
            return Err(git_ignore_lookup_failed(
                "Git configuration include paths are not valid UTF-8.",
            ));
        }

        let mut fields = stdout.split_terminator('\0');
        let mut paths = BTreeSet::new();
        while let Some(origin) = fields.next() {
            let Some(record) = fields.next() else {
                return Err(git_ignore_lookup_failed(
                    "Git configuration include lookup returned a malformed record.",
                ));
            };
            let Some((_key, raw_path)) = record.split_once('\n') else {
                return Err(git_ignore_lookup_failed(
                    "Git configuration include lookup returned a malformed path.",
                ));
            };
            if raw_path.is_empty() {
                return Err(git_ignore_lookup_failed(
                    "Git configuration include lookup returned an empty path.",
                ));
            }
            let include_path = PathBuf::from(raw_path);
            if include_path.is_absolute() {
                paths.insert(include_path);
                continue;
            }
            let origin_path = origin
                .strip_prefix("file:")
                .map(|path| self.absolute_git_config_path(path));
            let base = origin_path
                .as_deref()
                .and_then(Path::parent)
                .unwrap_or(&self.root);
            paths.insert(base.join(include_path));
        }
        Ok(paths.into_iter().collect())
    }

    fn absolute_git_config_path(&self, raw_path: &str) -> PathBuf {
        let path = PathBuf::from(raw_path);
        if path.is_absolute() {
            path
        } else {
            self.root.join(path)
        }
    }

    fn permission_git_required_path(&self, argument: &str) -> Result<PathBuf, ReCtmError> {
        let output = self
            .run_sync(
                vec![
                    "git".to_owned(),
                    "-C".to_owned(),
                    self.root.display().to_string(),
                    "rev-parse".to_owned(),
                    argument.to_owned(),
                ],
                5_000,
                16_384,
            )
            .map_err(|_| {
                git_ignore_lookup_failed(
                    "Git metadata location could not be inspected during patch preparation.",
                )
            })?;
        if output["exit_code"].as_i64() != Some(0) {
            return Err(git_ignore_lookup_failed(
                "Git metadata location lookup failed during patch preparation.",
            ));
        }
        let raw = output["stdout"]
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                git_ignore_lookup_failed(
                    "Git metadata location lookup returned an empty path during patch preparation.",
                )
            })?;
        let path = PathBuf::from(raw);
        let absolute = if path.is_absolute() {
            path
        } else {
            self.root.join(path)
        };
        absolute.canonicalize().map_err(|_| {
            git_ignore_lookup_failed(
                "Git metadata location could not be canonicalized during patch preparation.",
            )
        })
    }

    fn permission_git_optional_config_path(&self) -> Result<Option<PathBuf>, ReCtmError> {
        let output = self
            .run_sync(
                vec![
                    "git".to_owned(),
                    "-C".to_owned(),
                    self.root.display().to_string(),
                    "config".to_owned(),
                    "--path".to_owned(),
                    "--get".to_owned(),
                    "core.excludesFile".to_owned(),
                ],
                5_000,
                16_384,
            )
            .map_err(|_| {
                git_ignore_lookup_failed(
                    "Git excludes configuration could not be inspected during patch preparation.",
                )
            })?;
        match output["exit_code"].as_i64() {
            Some(1) => Ok(None),
            Some(0) => {
                let raw = output["stdout"]
                    .as_str()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        git_ignore_lookup_failed(
                            "Git excludes configuration returned an empty path during patch preparation.",
                        )
                    })?;
                let path = PathBuf::from(raw);
                Ok(Some(if path.is_absolute() {
                    path
                } else {
                    self.root.join(path)
                }))
            }
            _ => Err(git_ignore_lookup_failed(
                "Git excludes configuration lookup failed during patch preparation.",
            )),
        }
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

    pub(crate) fn commit_prepared_patch_with_authorization<Authorize>(
        &self,
        prepared: PreparedPatch,
        authorize: Authorize,
    ) -> Result<Value, ReCtmError>
    where
        Authorize: FnOnce() -> Result<(), ReCtmError>,
    {
        self.commit_prepared_patch_with_hook(prepared, authorize, |_| Ok(()))
    }

    fn commit_prepared_patch_with_hook<Authorize, Hook>(
        &self,
        prepared: PreparedPatch,
        authorize: Authorize,
        mut before_change: Hook,
    ) -> Result<Value, ReCtmError>
    where
        Authorize: FnOnce() -> Result<(), ReCtmError>,
        Hook: FnMut(usize) -> Result<(), ReCtmError>,
    {
        if prepared.dry_run() {
            return Ok(prepared.result(Vec::new()));
        }
        if prepared.workspace_root != self.root || prepared.arguments_sha256().len() != 64 {
            return Err(patch_authority_facts_changed(
                "Prepared patch binding does not match this Native workspace.",
            ));
        }
        let _commit_guard = self.patch_commit_lock.lock().map_err(|_| {
            ReCtmError::new(
                "INTERNAL_LOCK_POISONED",
                "Native patch commit lock was poisoned.",
            )
            .with_category(ErrorCategory::Internal)
        })?;
        self.revalidate_prepared_patch(&prepared)?;
        authorize()?;
        let cleanup_failures = apply_prepared_patch_transaction(&prepared, &mut before_change)?;
        let warnings = if cleanup_failures == 0 {
            Vec::new()
        } else {
            vec!["Patch committed, but temporary-file cleanup was incomplete.".to_owned()]
        };
        Ok(prepared.result(warnings))
    }

    fn revalidate_prepared_patch(&self, prepared: &PreparedPatch) -> Result<(), ReCtmError> {
        revalidate_workspace_identity(prepared)?;
        if let Some(git_metadata) = prepared.git_metadata() {
            git_metadata.revalidate()?;
        }
        for change in &prepared.changes {
            let current = match change.resolution {
                PatchPathResolution::ExistingCompatibility => {
                    self.resolve_existing(&change.relative_path)
                }
                PatchPathResolution::ForWrite => self.resolve_for_write(&change.relative_path),
            }
            .map_err(|_| {
                patch_authority_facts_changed(
                    "A patch path changed after preparation and before commit.",
                )
            })?;
            if current.path != change.resolved.path
                || current.display != change.resolved.display
                || current.existed != change.resolved.existed
            {
                return Err(patch_authority_facts_changed(
                    "A patch path changed after preparation and before commit.",
                ));
            }
            match &change.baseline {
                PatchBaseline::Missing if current.existed => {
                    return Err(patch_authority_facts_changed(
                        "A patch target was created after preparation.",
                    ));
                }
                PatchBaseline::Missing => {}
                PatchBaseline::File { fingerprint } => {
                    if !current.existed
                        || read_stable_regular_file(&current.path)
                            .map(|(_, current)| current != *fingerprint)
                            .unwrap_or(true)
                    {
                        return Err(patch_authority_facts_changed(
                            "A patch source baseline changed after preparation.",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn apply_patch(&self, patch: &str, dry_run: bool) -> Result<Value, ReCtmError> {
        // Preserve the accepted production parser/path behavior until D5. The
        // authority-ready path above intentionally performs stricter typed
        // validation and Git fact collection, but D4 is not an authority
        // cutover.
        let operations = parse_patch(patch)?;
        let arguments = Map::from_iter([
            ("patch".to_owned(), Value::String(patch.to_owned())),
            ("dry_run".to_owned(), Value::Bool(dry_run)),
        ]);
        let arguments_sha256 = canonical_arguments_sha256(&arguments)?;
        let attempts = if dry_run {
            1
        } else {
            PATCH_REVALIDATION_ATTEMPTS
        };
        for attempt in 0..attempts {
            let prepared = self.prepare_patch_operations(
                &operations,
                dry_run,
                &arguments_sha256,
                PatchPreparationSemantics::ProductionCompatibility,
            )?;
            match self.commit_prepared_patch_with_authorization(prepared, || Ok(())) {
                Err(error)
                    if error.code == "NATIVE_PATCH_AUTHORITY_FACTS_CHANGED"
                        && attempt + 1 < attempts =>
                {
                    continue;
                }
                result => return result,
            }
        }
        Err(patch_authority_facts_changed(
            "Patch facts did not stabilize within the bounded retry limit.",
        ))
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

impl GitMetadataSnapshot {
    fn capture(paths: &[PathBuf]) -> Result<Self, ReCtmError> {
        let entries = paths
            .iter()
            .map(|path| {
                fingerprint_metadata_node(path)
                    .map(|fingerprint| (path.clone(), fingerprint))
                    .map_err(|_| {
                        git_ignore_lookup_failed(
                            "Git ignore metadata could not be fingerprinted during patch preparation.",
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { entries })
    }

    fn revalidate(&self) -> Result<(), ReCtmError> {
        for (path, expected) in &self.entries {
            let current = fingerprint_metadata_node(path).map_err(|_| {
                patch_authority_facts_changed(
                    "Git ignore metadata could not be revalidated before patch commit.",
                )
            })?;
            if current != *expected {
                return Err(patch_authority_facts_changed(
                    "Git ignore metadata changed after patch preparation.",
                ));
            }
        }
        Ok(())
    }
}

const fn patch_source_resolution(semantics: PatchPreparationSemantics) -> PatchPathResolution {
    match semantics {
        PatchPreparationSemantics::ProductionCompatibility => {
            PatchPathResolution::ExistingCompatibility
        }
        PatchPreparationSemantics::Authority => PatchPathResolution::ForWrite,
    }
}

fn insert_prepared_change(
    changes: &mut BTreeMap<PathBuf, PreparedPathChange>,
    change: PreparedPathChange,
) -> Result<(), ReCtmError> {
    match changes.entry(change.resolved.path.clone()) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(change);
            Ok(())
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            let existing = entry.get_mut();
            if existing.baseline != change.baseline
                || existing.resolved.path != change.resolved.path
                || existing.resolved.existed != change.resolved.existed
            {
                return Err(patch_authority_facts_changed(
                    "Repeated patch paths did not share one stable baseline.",
                ));
            }
            if change.resolution == PatchPathResolution::ForWrite {
                existing.relative_path = change.relative_path;
                existing.resolution = PatchPathResolution::ForWrite;
            }
            existing.final_content = change.final_content;
            Ok(())
        }
    }
}

fn set_prepared_virtual_existence(
    virtual_existence: &mut BTreeMap<PathBuf, bool>,
    path: &Path,
    exists: bool,
) {
    virtual_existence.insert(path.to_path_buf(), exists);
}

fn remove_prepared_virtual_path(
    virtual_existence: &mut BTreeMap<PathBuf, bool>,
    path: &Path,
    baseline: &PatchBaseline,
) -> Result<(), ReCtmError> {
    let baseline_exists = matches!(baseline, PatchBaseline::File { .. });
    let exists = virtual_existence
        .entry(path.to_path_buf())
        .or_insert(baseline_exists);
    if !*exists {
        return Err(io_error(std::io::Error::from(std::io::ErrorKind::NotFound)));
    }
    *exists = false;
    Ok(())
}

fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    }
}

fn stable_directory_identity(path: &Path) -> Result<FileIdentity, ReCtmError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        patch_authority_facts_changed("The Native workspace root could not be inspected.")
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(patch_authority_facts_changed(
            "The Native workspace root changed during patch preparation.",
        ));
    }
    Ok(FileIdentity {
        size: 0,
        modified_seconds: 0,
        modified_nanoseconds: 0,
        ..file_identity(&metadata)
    })
}

fn revalidate_workspace_identity(prepared: &PreparedPatch) -> Result<(), ReCtmError> {
    if stable_directory_identity(&prepared.workspace_root)? == prepared.workspace_identity {
        Ok(())
    } else {
        Err(patch_authority_facts_changed(
            "The Native workspace root changed after patch preparation.",
        ))
    }
}

fn read_stable_regular_file(path: &Path) -> Result<(Vec<u8>, FileFingerprint), ReCtmError> {
    for _ in 0..PATCH_REVALIDATION_ATTEMPTS {
        let before = fs::symlink_metadata(path).map_err(io_error)?;
        if before.file_type().is_symlink() {
            return Err(ReCtmError::new(
                "SYMLINK_WRITE_DENIED",
                "Writing through symlinks is denied.",
            )
            .with_category(ErrorCategory::Security));
        }
        if !before.is_file() {
            return Err(validation_code("PATCH_FAILED", "Cannot patch a directory."));
        }
        let before_identity = file_identity(&before);
        let mut file = fs::File::open(path).map_err(io_error)?;
        let opened_identity = file
            .metadata()
            .map(|metadata| file_identity(&metadata))
            .map_err(io_error)?;
        if opened_identity != before_identity {
            continue;
        }
        let mut content = Vec::new();
        file.read_to_end(&mut content).map_err(io_error)?;
        let read_identity = file
            .metadata()
            .map(|metadata| file_identity(&metadata))
            .map_err(io_error)?;
        let after = fs::symlink_metadata(path).map_err(io_error)?;
        let after_identity = file_identity(&after);
        if before_identity == read_identity && before_identity == after_identity {
            let sha256 = sha256_bytes(&content);
            return Ok((
                content,
                FileFingerprint {
                    identity: after_identity,
                    sha256,
                },
            ));
        }
    }
    Err(patch_authority_facts_changed(
        "A patch source changed while its baseline was being read.",
    ))
}

fn expand_git_metadata_referents(mut paths: BTreeSet<PathBuf>) -> Result<Vec<PathBuf>, ReCtmError> {
    let symlink_paths = paths.iter().cloned().collect::<Vec<_>>();
    for path in symlink_paths {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err(git_ignore_lookup_failed(
                    "Git metadata symlinks could not be inspected during patch preparation.",
                ));
            }
        };
        if metadata.file_type().is_symlink() {
            let referent = path.canonicalize().map_err(|_| {
                git_ignore_lookup_failed(
                    "A Git metadata symlink referent could not be resolved during patch preparation.",
                )
            })?;
            paths.insert(referent);
        }
    }
    Ok(paths.into_iter().collect())
}

fn fingerprint_metadata_node(path: &Path) -> Result<MetadataNodeFingerprint, ReCtmError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(MetadataNodeFingerprint::Missing);
        }
        Err(error) => return Err(io_error(error)),
    };
    let identity = file_identity(&metadata);
    if metadata.file_type().is_symlink() {
        return fs::read_link(path)
            .map(|target| MetadataNodeFingerprint::Symlink { identity, target })
            .map_err(io_error);
    }
    if metadata.is_dir() {
        return Ok(MetadataNodeFingerprint::Directory(FileIdentity {
            size: 0,
            modified_seconds: 0,
            modified_nanoseconds: 0,
            ..identity
        }));
    }
    if !metadata.is_file() {
        return Ok(MetadataNodeFingerprint::Other(identity));
    }
    if metadata.len() > MAX_GIT_METADATA_BYTES {
        return Err(ReCtmError::new(
            "NATIVE_GIT_IGNORE_LOOKUP_FAILED",
            "Git ignore metadata exceeds the bounded fingerprint size.",
        )
        .with_category(ErrorCategory::Security));
    }
    let mut file = fs::File::open(path).map_err(io_error)?;
    let opened_identity = file
        .metadata()
        .map(|value| file_identity(&value))
        .map_err(io_error)?;
    if opened_identity != identity {
        return Err(patch_authority_facts_changed(
            "Git ignore metadata changed while it was being fingerprinted.",
        ));
    }
    let mut content = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_GIT_METADATA_BYTES + 1)
        .read_to_end(&mut content)
        .map_err(io_error)?;
    if u64::try_from(content.len()).unwrap_or(u64::MAX) > MAX_GIT_METADATA_BYTES {
        return Err(ReCtmError::new(
            "NATIVE_GIT_IGNORE_LOOKUP_FAILED",
            "Git ignore metadata exceeds the bounded fingerprint size.",
        )
        .with_category(ErrorCategory::Security));
    }
    let after = fs::symlink_metadata(path).map_err(io_error)?;
    if file_identity(&after) != identity {
        return Err(patch_authority_facts_changed(
            "Git ignore metadata changed while it was being fingerprinted.",
        ));
    }
    Ok(MetadataNodeFingerprint::Regular(FileFingerprint {
        identity,
        sha256: sha256_bytes(&content),
    }))
}

struct StagedPatchChange {
    target: PathBuf,
    baseline_existed: bool,
    expected_fingerprint: Option<FileFingerprint>,
    stage: Option<PathBuf>,
    backup: Option<PathBuf>,
}

struct PatchTransactionCleanup {
    temporary_paths: Vec<PathBuf>,
    created_directories: Vec<PathBuf>,
    remove_created_directories: bool,
}

impl PatchTransactionCleanup {
    fn new() -> Self {
        Self {
            temporary_paths: Vec::new(),
            created_directories: Vec::new(),
            remove_created_directories: true,
        }
    }

    fn track_temporary(&mut self, path: PathBuf) {
        self.temporary_paths.push(path);
    }

    fn track_directory(&mut self, path: PathBuf) {
        self.created_directories.push(path);
    }

    fn preserve_temporary(&mut self, path: &Path) {
        self.temporary_paths.retain(|temporary| temporary != path);
    }

    fn finish_success(mut self) -> usize {
        self.remove_created_directories = false;
        let mut failures = 0;
        self.temporary_paths
            .retain(|path| match fs::remove_file(path) {
                Ok(()) => false,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(_) => {
                    failures += 1;
                    true
                }
            });
        failures
    }
}

impl Drop for PatchTransactionCleanup {
    fn drop(&mut self) {
        for path in self.temporary_paths.iter().rev() {
            let _ = fs::remove_file(path);
        }
        if self.remove_created_directories {
            for path in self.created_directories.iter().rev() {
                let _ = fs::remove_dir(path);
            }
        }
    }
}

fn apply_prepared_patch_transaction<Hook>(
    prepared: &PreparedPatch,
    before_change: &mut Hook,
) -> Result<usize, ReCtmError>
where
    Hook: FnMut(usize) -> Result<(), ReCtmError>,
{
    revalidate_workspace_identity(prepared)?;
    let mut cleanup = PatchTransactionCleanup::new();
    let mut staged = Vec::with_capacity(prepared.changes.len());
    for (index, change) in prepared.changes.iter().enumerate() {
        revalidate_patch_target(&change.resolved.path, &change.baseline)?;
        ensure_patch_parent_directories(
            &prepared.workspace_root,
            &change.resolved.path,
            &mut cleanup,
        )?;
        let parent = change
            .resolved
            .path
            .parent()
            .ok_or_else(|| validation("Invalid patch target."))?;
        let stage = change
            .final_content
            .as_deref()
            .map(|content| create_patch_stage_file(parent, index, content))
            .transpose()?;
        if let Some(path) = &stage {
            cleanup.track_temporary(path.clone());
        }
        let (baseline_existed, expected_fingerprint, backup) = match &change.baseline {
            PatchBaseline::Missing => {
                if change.final_content.is_none() {
                    return Err(internal("prepared patch has an empty missing-path change"));
                }
                (false, None, None)
            }
            PatchBaseline::File { fingerprint } => {
                let backup = create_patch_backup(&change.resolved.path, parent, index)?;
                cleanup.track_temporary(backup.clone());
                let (_, backup_fingerprint) = read_stable_regular_file(&backup)?;
                if backup_fingerprint != *fingerprint {
                    return Err(patch_authority_facts_changed(
                        "A patch source changed while its rollback link was being created.",
                    ));
                }
                (true, Some(fingerprint.clone()), Some(backup))
            }
        };
        staged.push(StagedPatchChange {
            target: change.resolved.path.clone(),
            baseline_existed,
            expected_fingerprint,
            stage,
            backup,
        });
    }

    if let Some(git_metadata) = prepared.git_metadata() {
        git_metadata.revalidate()?;
    }
    for change in &staged {
        revalidate_staged_patch_target(change)?;
        if let (Some(backup), Some(expected)) = (&change.backup, &change.expected_fingerprint)
            && read_stable_regular_file(backup)
                .map(|(_, current)| current != *expected)
                .unwrap_or(true)
        {
            return Err(patch_authority_facts_changed(
                "A patch source changed after authorization and before commit.",
            ));
        }
    }

    let mut committed = Vec::new();
    for (index, change) in staged.iter().enumerate() {
        if let Err(error) = before_change(index) {
            rollback_patch_changes(&staged, &committed, &mut cleanup)?;
            return Err(error);
        }
        if let Err(error) = revalidate_staged_patch_target(change) {
            rollback_patch_changes(&staged, &committed, &mut cleanup)?;
            return Err(error);
        }
        let result = if let Some(stage) = &change.stage {
            if change.baseline_existed {
                fs::rename(stage, &change.target)
            } else {
                // Unlike rename, hard_link has create-new semantics for the
                // destination. A target created in the final race window is
                // therefore preserved and the patch fails closed.
                fs::hard_link(stage, &change.target)
            }
        } else {
            fs::remove_file(&change.target)
        };
        if let Err(error) = result {
            rollback_patch_changes(&staged, &committed, &mut cleanup)?;
            return Err(io_error(error));
        }
        committed.push(index);
    }
    Ok(cleanup.finish_success())
}

fn revalidate_patch_target(target: &Path, baseline: &PatchBaseline) -> Result<(), ReCtmError> {
    match baseline {
        PatchBaseline::Missing => match fs::symlink_metadata(target) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(patch_authority_facts_changed(
                "A patch target was created after preparation.",
            )),
            Err(_) => Err(patch_authority_facts_changed(
                "A patch target could not be revalidated before commit.",
            )),
        },
        PatchBaseline::File { fingerprint } => {
            if read_stable_regular_file(target)
                .map(|(_, current)| current == *fingerprint)
                .unwrap_or(false)
            {
                Ok(())
            } else {
                Err(patch_authority_facts_changed(
                    "A patch source baseline changed after preparation.",
                ))
            }
        }
    }
}

fn revalidate_staged_patch_target(change: &StagedPatchChange) -> Result<(), ReCtmError> {
    match &change.expected_fingerprint {
        Some(expected) => {
            if read_stable_regular_file(&change.target)
                .map(|(_, current)| current == *expected)
                .unwrap_or(false)
            {
                Ok(())
            } else {
                Err(patch_authority_facts_changed(
                    "A patch source changed after authorization and before commit.",
                ))
            }
        }
        None => match fs::symlink_metadata(&change.target) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(patch_authority_facts_changed(
                "A patch target was created after authorization and before commit.",
            )),
            Err(_) => Err(patch_authority_facts_changed(
                "A patch target could not be revalidated before commit.",
            )),
        },
    }
}

fn rollback_patch_changes(
    staged: &[StagedPatchChange],
    committed: &[usize],
    cleanup: &mut PatchTransactionCleanup,
) -> Result<(), ReCtmError> {
    let mut failures = 0_usize;
    for index in committed.iter().rev() {
        let change = &staged[*index];
        let result = if change.baseline_existed {
            change.backup.as_ref().map_or_else(
                || Err(std::io::Error::other("patch rollback backup is missing")),
                |backup| fs::rename(backup, &change.target),
            )
        } else {
            match fs::remove_file(&change.target) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        };
        if result.is_err() {
            failures += 1;
            if let Some(backup) = &change.backup {
                cleanup.preserve_temporary(backup);
            }
        }
    }
    if failures == 0 {
        Ok(())
    } else {
        Err(ReCtmError::new(
            "NATIVE_PATCH_ROLLBACK_FAILED",
            "Patch rollback could not restore every target; recovery backups were retained.",
        )
        .with_category(ErrorCategory::Internal)
        .with_details(serde_json::json!({"failed_restore_count":failures})))
    }
}

fn ensure_patch_parent_directories(
    workspace_root: &Path,
    target: &Path,
    cleanup: &mut PatchTransactionCleanup,
) -> Result<(), ReCtmError> {
    let parent = target
        .parent()
        .ok_or_else(|| validation("Invalid patch target."))?;
    let relative = parent.strip_prefix(workspace_root).map_err(|_| {
        patch_authority_facts_changed("A patch target escaped its prepared workspace.")
    })?;
    let mut current = workspace_root.to_path_buf();
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(patch_authority_facts_changed(
                "A patch parent directory changed before commit.",
            ));
        }
        current.push(component.as_os_str());
        match fs::create_dir(&current) {
            Ok(()) => cleanup.track_directory(current.clone()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(io_error(error)),
        }
        let metadata = fs::symlink_metadata(&current).map_err(|_| {
            patch_authority_facts_changed("A patch parent directory changed before commit.")
        })?;
        let resolved = current.canonicalize().map_err(|_| {
            patch_authority_facts_changed("A patch parent directory changed before commit.")
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() || resolved != current {
            return Err(patch_authority_facts_changed(
                "A patch parent directory changed before commit.",
            ));
        }
    }
    Ok(())
}

fn create_patch_stage_file(
    parent: &Path,
    index: usize,
    content: &[u8],
) -> Result<PathBuf, ReCtmError> {
    for _ in 0..PATCH_TEMP_NAME_ATTEMPTS {
        let path = patch_temporary_path(parent, "stage", index)?;
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let result = file.write_all(content).and_then(|()| file.sync_all());
                if let Err(error) = result {
                    let _ = fs::remove_file(&path);
                    return Err(io_error(error));
                }
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io_error(error)),
        }
    }
    Err(ReCtmError::new(
        "PATCH_TEMPORARY_FILE_FAILED",
        "Unable to reserve a unique patch staging file.",
    )
    .with_category(ErrorCategory::Runtime))
}

fn create_patch_backup(source: &Path, parent: &Path, index: usize) -> Result<PathBuf, ReCtmError> {
    for _ in 0..PATCH_TEMP_NAME_ATTEMPTS {
        let path = patch_temporary_path(parent, "backup", index)?;
        match fs::hard_link(source, &path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io_error(error)),
        }
    }
    Err(ReCtmError::new(
        "PATCH_TEMPORARY_FILE_FAILED",
        "Unable to reserve a unique patch rollback file.",
    )
    .with_category(ErrorCategory::Runtime))
}

fn patch_temporary_path(parent: &Path, kind: &str, index: usize) -> Result<PathBuf, ReCtmError> {
    let mut random = [0_u8; 12];
    getrandom::fill(&mut random).map_err(|_| {
        ReCtmError::new(
            "PATCH_TEMPORARY_FILE_FAILED",
            "Secure randomness is unavailable for patch staging.",
        )
        .with_category(ErrorCategory::Internal)
    })?;
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(parent.join(format!(
        ".mtm-patch-{}-{kind}-{index}-{suffix}",
        std::process::id()
    )))
}

fn git_default_config_paths(base: &Path) -> BTreeSet<PathBuf> {
    let mut paths = BTreeSet::new();
    if let Some(path) = std::env::var_os("GIT_CONFIG_SYSTEM") {
        paths.insert(absolute_from(base, PathBuf::from(path)));
    } else {
        paths.insert(PathBuf::from("/etc/gitconfig"));
    }
    if let Some(path) = std::env::var_os("GIT_CONFIG_GLOBAL") {
        paths.insert(absolute_from(base, PathBuf::from(path)));
        return paths;
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        paths.insert(home.join(".gitconfig"));
        paths.insert(home.join(".config/git/config"));
    }
    if let Some(xdg_config) = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from) {
        paths.insert(xdg_config.join("git/config"));
    }
    paths
}

fn absolute_from(base: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn git_ignore_lookup_failed(message: &str) -> ReCtmError {
    ReCtmError::new("NATIVE_GIT_IGNORE_LOOKUP_FAILED", message)
        .with_category(ErrorCategory::Security)
}

fn patch_authority_facts_changed(message: &str) -> ReCtmError {
    ReCtmError::new("NATIVE_PATCH_AUTHORITY_FACTS_CHANGED", message)
        .with_category(ErrorCategory::Security)
        .with_retryable(true)
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
    use std::cell::Cell;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

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

    fn snapshot_tree(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, ReCtmError> {
        fn visit(
            root: &Path,
            directory: &Path,
            snapshot: &mut BTreeMap<String, Vec<u8>>,
        ) -> Result<(), ReCtmError> {
            let mut entries = fs::read_dir(directory)
                .map_err(io_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(io_error)?;
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| internal("test snapshot escaped root"))?
                    .to_string_lossy()
                    .into_owned();
                let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
                if metadata.file_type().is_symlink() {
                    snapshot.insert(
                        format!("L:{relative}"),
                        fs::read_link(&path)
                            .map_err(io_error)?
                            .to_string_lossy()
                            .as_bytes()
                            .to_vec(),
                    );
                } else if metadata.is_dir() {
                    snapshot.insert(format!("D:{relative}"), Vec::new());
                    visit(root, &path, snapshot)?;
                } else {
                    snapshot.insert(format!("F:{relative}"), fs::read(&path).map_err(io_error)?);
                }
            }
            Ok(())
        }

        let mut snapshot = BTreeMap::new();
        visit(root, root, &mut snapshot)?;
        Ok(snapshot)
    }

    fn patch_temporary_files(root: &Path) -> Result<Vec<PathBuf>, ReCtmError> {
        fn visit(root: &Path, found: &mut Vec<PathBuf>) -> Result<(), ReCtmError> {
            for entry in fs::read_dir(root).map_err(io_error)? {
                let entry = entry.map_err(io_error)?;
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".mtm-patch-")
                {
                    found.push(path.clone());
                }
                if metadata.is_dir() && !metadata.file_type().is_symlink() {
                    visit(&path, found)?;
                }
            }
            Ok(())
        }

        let mut found = Vec::new();
        visit(root, &mut found)?;
        Ok(found)
    }

    #[test]
    fn prepared_patch_writes_nothing_before_authorization_and_commits_every_change()
    -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        fs::write(temp.path().join("update.txt"), "old\n").map_err(io_error)?;
        fs::write(temp.path().join("delete.txt"), "gone\n").map_err(io_error)?;
        fs::write(temp.path().join("move.txt"), "move-old\n").map_err(io_error)?;
        run_git(temp.path(), &["init", "--quiet"])?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        let patch = concat!(
            "*** Begin Patch\n",
            "*** Add File: nested/added.txt\n",
            "+secret-added-content\n",
            "*** Update File: update.txt\n",
            "@@\n",
            "-old\n",
            "+new\n",
            "*** Delete File: delete.txt\n",
            "*** Update File: move.txt\n",
            "*** Move to: nested/moved.txt\n",
            "@@\n",
            "-move-old\n",
            "+move-new\n",
            "*** End Patch\n",
        );
        let invocation = patch_invocation(patch, false)?;
        let before = snapshot_tree(temp.path())?;
        let prepared = workspace.prepare_patch(&invocation)?;
        let after_preparation = snapshot_tree(temp.path())?;
        assert_eq!(before, after_preparation);
        assert_eq!(prepared.arguments_sha256(), invocation.arguments_sha256());
        assert_eq!(
            prepared
                .path_facts()
                .ok_or_else(|| internal("prepared test patch omitted authority facts"))?
                .len(),
            5
        );
        let debug = format!("{prepared:?}");
        assert!(!debug.contains("secret-added-content"));
        assert!(!debug.contains(&temp.path().to_string_lossy().into_owned()));

        let authorized = Cell::new(0_usize);
        let result = workspace.commit_prepared_patch_with_authorization(prepared, || {
            authorized.set(authorized.get() + 1);
            Ok(())
        })?;
        assert_eq!(authorized.get(), 1);
        assert_eq!(result["dry_run"], false);
        assert_eq!(result["affected_files"].as_array().map(Vec::len), Some(4));
        assert_eq!(
            fs::read_to_string(temp.path().join("nested/added.txt")).map_err(io_error)?,
            "secret-added-content\n"
        );
        assert_eq!(
            fs::read_to_string(temp.path().join("update.txt")).map_err(io_error)?,
            "new\n"
        );
        assert!(!temp.path().join("delete.txt").exists());
        assert!(!temp.path().join("move.txt").exists());
        assert_eq!(
            fs::read_to_string(temp.path().join("nested/moved.txt")).map_err(io_error)?,
            "move-new\n"
        );
        assert!(patch_temporary_files(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn prepared_patch_dry_run_never_invokes_authorization_or_writes() -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        let invocation = patch_invocation(
            "*** Begin Patch\n*** Add File: target/dry.txt\n+dry-secret\n*** End Patch\n",
            true,
        )?;
        let before = snapshot_tree(temp.path())?;
        let prepared = workspace.prepare_patch(&invocation)?;
        let authorization_calls = Cell::new(0_usize);
        let result = workspace.commit_prepared_patch_with_authorization(prepared, || {
            authorization_calls.set(authorization_calls.get() + 1);
            Err(internal("dry-run authorization must not be called"))
        })?;
        assert_eq!(authorization_calls.get(), 0);
        assert_eq!(result["dry_run"], true);
        assert_eq!(snapshot_tree(temp.path())?, before);
        assert!(!temp.path().join("target/dry.txt").exists());
        assert!(patch_temporary_files(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn prepared_patch_authorization_failure_leaves_no_workspace_artifacts() -> Result<(), ReCtmError>
    {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        let invocation = patch_invocation(
            "*** Begin Patch\n*** Add File: nested/denied.txt\n+denied\n*** End Patch\n",
            false,
        )?;
        let before = snapshot_tree(temp.path())?;
        let prepared = workspace.prepare_patch(&invocation)?;
        let error = workspace
            .commit_prepared_patch_with_authorization(prepared, || {
                if snapshot_tree(temp.path())? != before {
                    return Err(internal("patch wrote before final authorization"));
                }
                Err(ReCtmError::new(
                    "TEST_AUTHORIZATION_DENIED",
                    "injected authorization denial",
                ))
            })
            .map_err(|error| error.code);
        assert_eq!(error, Err("TEST_AUTHORIZATION_DENIED".to_owned()));
        assert_eq!(snapshot_tree(temp.path())?, before);
        assert!(patch_temporary_files(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn prepared_patch_revalidates_new_target_after_authorization() -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        let target = temp.path().join("target.txt");
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        let invocation = patch_invocation(
            "*** Begin Patch\n*** Add File: target.txt\n+prepared\n*** End Patch\n",
            false,
        )?;
        let prepared = workspace.prepare_patch(&invocation)?;
        let error = workspace
            .commit_prepared_patch_with_authorization(prepared, || {
                fs::write(&target, "external\n").map_err(io_error)
            })
            .map_err(|error| error.code);
        assert_eq!(
            error,
            Err("NATIVE_PATCH_AUTHORITY_FACTS_CHANGED".to_owned())
        );
        assert_eq!(fs::read_to_string(&target).map_err(io_error)?, "external\n");
        assert!(patch_temporary_files(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn prepared_patch_rejects_parent_symlink_created_during_authorization() -> Result<(), ReCtmError>
    {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let outside = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        let invocation = patch_invocation(
            "*** Begin Patch\n*** Add File: nested/target.txt\n+prepared\n*** End Patch\n",
            false,
        )?;
        let prepared = workspace.prepare_patch(&invocation)?;
        let error = workspace
            .commit_prepared_patch_with_authorization(prepared, || {
                std::os::unix::fs::symlink(outside.path(), temp.path().join("nested"))
                    .map_err(io_error)
            })
            .map_err(|error| error.code);
        assert_eq!(
            error,
            Err("NATIVE_PATCH_AUTHORITY_FACTS_CHANGED".to_owned())
        );
        assert!(!outside.path().join("target.txt").exists());
        assert!(patch_temporary_files(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn prepared_patch_rejects_stale_file_baseline_before_authorization() -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        fs::write(temp.path().join("source.txt"), "old\n").map_err(io_error)?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        let invocation = patch_invocation(
            concat!(
                "*** Begin Patch\n",
                "*** Update File: source.txt\n",
                "@@\n",
                "-old\n",
                "+new\n",
                "*** Add File: added.txt\n",
                "+added\n",
                "*** End Patch\n",
            ),
            false,
        )?;
        let prepared = workspace.prepare_patch(&invocation)?;
        fs::write(temp.path().join("source.txt"), "external-change\n").map_err(io_error)?;
        let authorization_calls = Cell::new(0_usize);
        let error = workspace
            .commit_prepared_patch_with_authorization(prepared, || {
                authorization_calls.set(authorization_calls.get() + 1);
                Ok(())
            })
            .map_err(|error| error.code);
        assert_eq!(
            error,
            Err("NATIVE_PATCH_AUTHORITY_FACTS_CHANGED".to_owned())
        );
        assert_eq!(authorization_calls.get(), 0);
        assert_eq!(
            fs::read_to_string(temp.path().join("source.txt")).map_err(io_error)?,
            "external-change\n"
        );
        assert!(!temp.path().join("added.txt").exists());
        assert!(patch_temporary_files(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn prepared_patch_rejects_changed_git_ignore_metadata_before_authorization()
    -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        fs::create_dir(temp.path().join("ignored")).map_err(io_error)?;
        fs::write(temp.path().join(".gitignore"), "ignored/\n").map_err(io_error)?;
        run_git(temp.path(), &["init", "--quiet"])?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        let invocation = patch_invocation(
            "*** Begin Patch\n*** Add File: ignored/new.txt\n+new\n*** End Patch\n",
            false,
        )?;
        let prepared = workspace.prepare_patch(&invocation)?;
        assert!(
            prepared
                .path_facts()
                .ok_or_else(|| internal("prepared test patch omitted authority facts"))?[0]
                .git_ignored()
        );
        assert!(
            prepared
                .git_metadata()
                .ok_or_else(|| internal("prepared test patch omitted Git metadata"))?
                .entries
                .iter()
                .any(|(path, _)| path.ends_with("index"))
        );
        fs::write(temp.path().join(".gitignore"), "different/\n").map_err(io_error)?;
        let authorization_calls = Cell::new(0_usize);
        let error = workspace
            .commit_prepared_patch_with_authorization(prepared, || {
                authorization_calls.set(authorization_calls.get() + 1);
                Ok(())
            })
            .map_err(|error| error.code);
        assert_eq!(
            error,
            Err("NATIVE_PATCH_AUTHORITY_FACTS_CHANGED".to_owned())
        );
        assert_eq!(authorization_calls.get(), 0);
        assert!(!temp.path().join("ignored/new.txt").exists());
        assert!(patch_temporary_files(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn prepared_patch_tracks_included_git_configuration_before_authorization()
    -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let metadata = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        let include = metadata.path().join("included.config");
        let first_excludes = metadata.path().join("first.excludes");
        let second_excludes = metadata.path().join("second.excludes");
        fs::write(&first_excludes, "ignored.txt\n").map_err(io_error)?;
        fs::write(&second_excludes, "different.txt\n").map_err(io_error)?;
        fs::write(
            &include,
            format!("[core]\n\texcludesFile = {}\n", first_excludes.display()),
        )
        .map_err(io_error)?;
        run_git(temp.path(), &["init", "--quiet"])?;
        run_git(
            temp.path(),
            &[
                "config",
                "--local",
                "include.path",
                &include.display().to_string(),
            ],
        )?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        let invocation = patch_invocation(
            "*** Begin Patch\n*** Add File: ignored.txt\n+new\n*** End Patch\n",
            false,
        )?;
        let prepared = workspace.prepare_patch(&invocation)?;
        assert!(
            prepared
                .path_facts()
                .ok_or_else(|| internal("prepared test patch omitted authority facts"))?[0]
                .git_ignored()
        );

        fs::write(
            &include,
            format!("[core]\n\texcludesFile = {}\n", second_excludes.display()),
        )
        .map_err(io_error)?;
        let authorization_calls = Cell::new(0_usize);
        let error = workspace
            .commit_prepared_patch_with_authorization(prepared, || {
                authorization_calls.set(authorization_calls.get() + 1);
                Ok(())
            })
            .map_err(|error| error.code);
        assert_eq!(
            error,
            Err("NATIVE_PATCH_AUTHORITY_FACTS_CHANGED".to_owned())
        );
        assert_eq!(authorization_calls.get(), 0);
        assert!(!temp.path().join("ignored.txt").exists());
        assert!(patch_temporary_files(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn prepared_patch_rolls_back_every_file_after_mid_commit_failure() -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        fs::write(temp.path().join("a.txt"), "a-old\n").map_err(io_error)?;
        fs::write(temp.path().join("b.txt"), "b-old\n").map_err(io_error)?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        let invocation = patch_invocation(
            concat!(
                "*** Begin Patch\n",
                "*** Update File: a.txt\n",
                "@@\n",
                "-a-old\n",
                "+a-new\n",
                "*** Update File: b.txt\n",
                "@@\n",
                "-b-old\n",
                "+b-new\n",
                "*** End Patch\n",
            ),
            false,
        )?;
        let prepared = workspace.prepare_patch(&invocation)?;
        let authorization_calls = Cell::new(0_usize);
        let error = workspace
            .commit_prepared_patch_with_hook(
                prepared,
                || {
                    authorization_calls.set(authorization_calls.get() + 1);
                    Ok(())
                },
                |index| {
                    if index == 1 {
                        Err(ReCtmError::new("TEST_COMMIT_FAILURE", "injected failure"))
                    } else {
                        Ok(())
                    }
                },
            )
            .map_err(|error| error.code);
        assert_eq!(error, Err("TEST_COMMIT_FAILURE".to_owned()));
        assert_eq!(authorization_calls.get(), 1);
        assert_eq!(
            fs::read_to_string(temp.path().join("a.txt")).map_err(io_error)?,
            "a-old\n"
        );
        assert_eq!(
            fs::read_to_string(temp.path().join("b.txt")).map_err(io_error)?,
            "b-old\n"
        );
        assert!(patch_temporary_files(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn prepared_patch_retains_recovery_backup_when_rollback_is_obstructed() -> Result<(), ReCtmError>
    {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        let first = temp.path().join("a.txt");
        fs::write(&first, "a-old\n").map_err(io_error)?;
        fs::write(temp.path().join("b.txt"), "b-old\n").map_err(io_error)?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        let invocation = patch_invocation(
            concat!(
                "*** Begin Patch\n",
                "*** Update File: a.txt\n",
                "@@\n",
                "-a-old\n",
                "+a-new\n",
                "*** Update File: b.txt\n",
                "@@\n",
                "-b-old\n",
                "+b-new\n",
                "*** End Patch\n",
            ),
            false,
        )?;
        let prepared = workspace.prepare_patch(&invocation)?;
        let error = workspace
            .commit_prepared_patch_with_hook(
                prepared,
                || Ok(()),
                |index| {
                    if index == 1 {
                        fs::remove_file(&first).map_err(io_error)?;
                        fs::create_dir(&first).map_err(io_error)?;
                        Err(ReCtmError::new("TEST_COMMIT_FAILURE", "injected failure"))
                    } else {
                        Ok(())
                    }
                },
            )
            .map_err(|error| error.code);
        assert_eq!(error, Err("NATIVE_PATCH_ROLLBACK_FAILED".to_owned()));
        let recovery = patch_temporary_files(temp.path())?;
        assert_eq!(recovery.len(), 1);
        assert!(
            recovery[0]
                .file_name()
                .is_some_and(|name| name.to_string_lossy().contains("backup-0"))
        );
        assert_eq!(
            fs::read_to_string(&recovery[0]).map_err(io_error)?,
            "a-old\n"
        );
        assert_eq!(
            fs::read_to_string(temp.path().join("b.txt")).map_err(io_error)?,
            "b-old\n"
        );
        Ok(())
    }

    #[test]
    fn prepared_patch_commit_lock_allows_one_concurrent_baseline_winner() -> Result<(), ReCtmError>
    {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        let invocation = patch_invocation(
            "*** Begin Patch\n*** Add File: winner.txt\n+winner\n*** End Patch\n",
            false,
        )?;
        let first = workspace.prepare_patch(&invocation)?;
        let second = workspace.prepare_patch(&invocation)?;
        let barrier = Arc::new(Barrier::new(3));
        let authorization_calls = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for (copy, prepared) in [(workspace.clone(), first), (workspace.clone(), second)] {
            let barrier = Arc::clone(&barrier);
            let authorization_calls = Arc::clone(&authorization_calls);
            handles.push(thread::spawn(move || {
                barrier.wait();
                copy.commit_prepared_patch_with_authorization(prepared, || {
                    authorization_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
            }));
        }
        barrier.wait();
        let results = handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| internal("prepared patch test thread panicked"))?
            })
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter_map(|result| result.as_ref().err())
                .filter(|error| error.code == "NATIVE_PATCH_AUTHORITY_FACTS_CHANGED")
                .count(),
            1
        );
        assert_eq!(authorization_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            fs::read_to_string(temp.path().join("winner.txt")).map_err(io_error)?,
            "winner\n"
        );
        assert!(patch_temporary_files(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn prepared_patch_rejects_symlink_sources_without_writing() -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        fs::write(temp.path().join("real.txt"), "unchanged\n").map_err(io_error)?;
        std::os::unix::fs::symlink("real.txt", temp.path().join("link.txt")).map_err(io_error)?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        let invocation = patch_invocation(
            "*** Begin Patch\n*** Update File: link.txt\n@@\n-unchanged\n+changed\n*** End Patch\n",
            false,
        )?;
        assert_eq!(
            workspace
                .prepare_patch(&invocation)
                .map(|_| ())
                .map_err(|error| error.code),
            Err("SYMLINK_WRITE_DENIED".to_owned())
        );
        assert_eq!(
            fs::read_to_string(temp.path().join("real.txt")).map_err(io_error)?,
            "unchanged\n"
        );
        fs::create_dir(temp.path().join("real-directory")).map_err(io_error)?;
        std::os::unix::fs::symlink("real-directory", temp.path().join("directory-link"))
            .map_err(io_error)?;
        let parent_symlink = patch_invocation(
            "*** Begin Patch\n*** Add File: directory-link/new.txt\n+changed\n*** End Patch\n",
            false,
        )?;
        assert_eq!(
            workspace
                .prepare_patch(&parent_symlink)
                .map(|_| ())
                .map_err(|error| error.code),
            Err("SYMLINK_WRITE_DENIED".to_owned())
        );
        assert!(!temp.path().join("real-directory/new.txt").exists());
        assert!(patch_temporary_files(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn public_apply_patch_preserves_pre_cutover_results_without_git_facts() -> Result<(), ReCtmError>
    {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        fs::write(temp.path().join(".git"), "gitdir: /definitely/missing\n").map_err(io_error)?;
        fs::write(temp.path().join("update.txt"), "update-old\n").map_err(io_error)?;
        fs::write(temp.path().join("delete.txt"), "delete-old\n").map_err(io_error)?;
        fs::write(temp.path().join("move-source.txt"), "move-old\n").map_err(io_error)?;
        fs::write(temp.path().join("move-target.txt"), "overwritten\n").map_err(io_error)?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        let patch = concat!(
            "*** Begin Patch\n",
            "*** Add File: nested/added.txt\n",
            "+added\n",
            "*** Update File: update.txt\n",
            "@@\n",
            "-update-old\n",
            "+update-new\n",
            "*** Delete File: delete.txt\n",
            "*** Update File: move-source.txt\n",
            "*** Move to: move-target.txt\n",
            "@@\n",
            "-move-old\n",
            "+move-new\n",
            "*** End Patch\n",
        );

        let result = workspace.apply_patch(patch, false)?;
        assert_eq!(
            result,
            serde_json::json!({
                "clean": true,
                "dry_run": false,
                "summary": concat!(
                    "A nested/added.txt\n",
                    "M update.txt\n",
                    "D delete.txt\n",
                    "R move-source.txt -> move-target.txt"
                ),
                "additions": 1,
                "removals": 1,
                "affected_files": [
                    {"operation": "add", "path": "nested/added.txt"},
                    {"operation": "update", "path": "update.txt"},
                    {"operation": "delete", "path": "delete.txt"},
                    {"operation": "update", "path": "move-target.txt"},
                ],
                "warnings": [],
            })
        );
        assert_eq!(
            fs::read_to_string(temp.path().join("nested/added.txt")).map_err(io_error)?,
            "added\n"
        );
        assert_eq!(
            fs::read_to_string(temp.path().join("update.txt")).map_err(io_error)?,
            "update-new\n"
        );
        assert!(!temp.path().join("delete.txt").exists());
        assert!(!temp.path().join("move-source.txt").exists());
        assert_eq!(
            fs::read_to_string(temp.path().join("move-target.txt")).map_err(io_error)?,
            "move-new\n"
        );
        assert!(patch_temporary_files(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn public_apply_patch_preserves_empty_and_repeated_path_semantics() -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        fs::write(temp.path().join("source.txt"), "original\n").map_err(io_error)?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;

        assert_eq!(
            workspace.apply_patch("*** Begin Patch\n*** End Patch\n", false)?,
            serde_json::json!({
                "clean": true,
                "dry_run": false,
                "summary": "",
                "additions": 0,
                "removals": 0,
                "affected_files": [],
                "warnings": [],
            })
        );

        let repeated = concat!(
            "*** Begin Patch\n",
            "*** Update File: source.txt\n",
            "@@\n",
            "-original\n",
            "+first\n",
            "*** Update File: source.txt\n",
            "@@\n",
            "-original\n",
            "+second\n",
            "*** End Patch\n",
        );
        let result = workspace.apply_patch(repeated, false)?;
        assert_eq!(result["summary"], "M source.txt\nM source.txt");
        assert_eq!(result["affected_files"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            fs::read_to_string(temp.path().join("source.txt")).map_err(io_error)?,
            "second\n"
        );
        assert!(patch_temporary_files(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn public_apply_patch_keeps_internal_source_symlink_compatibility() -> Result<(), ReCtmError> {
        let temp = tempfile::tempdir().map_err(io_error)?;
        let private = tempfile::tempdir().map_err(io_error)?;
        fs::write(temp.path().join("real.txt"), "old\n").map_err(io_error)?;
        std::os::unix::fs::symlink("real.txt", temp.path().join("link.txt")).map_err(io_error)?;
        let workspace = NativeWorkspace::new(temp.path(), private.path())?;
        let result = workspace.apply_patch(
            "*** Begin Patch\n*** Update File: link.txt\n@@\n-old\n+new\n*** End Patch\n",
            false,
        )?;
        assert_eq!(result["affected_files"][0]["path"], "real.txt");
        assert!(temp.path().join("link.txt").is_symlink());
        assert_eq!(
            fs::read_to_string(temp.path().join("real.txt")).map_err(io_error)?,
            "new\n"
        );
        Ok(())
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
