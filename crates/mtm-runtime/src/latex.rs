use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use mtm_contracts::{ErrorCategory, LatexPolicy, ReCtmError};
use mtm_workflow::{LatexGate, LatexGateResult};
use regex::Regex;

use crate::NativeToolRuntime;

pub struct RuntimeLatexGate {
    policy: LatexPolicy,
    native: Arc<NativeToolRuntime>,
    timeout_ms: u64,
    output_limit: usize,
}

impl RuntimeLatexGate {
    #[must_use]
    pub fn new(policy: LatexPolicy, native: Arc<NativeToolRuntime>) -> Self {
        Self {
            policy,
            native,
            timeout_ms: 120_000,
            output_limit: 32_000,
        }
    }
}

impl LatexGate for RuntimeLatexGate {
    fn validate(&self, proof: &str, workdir: &Path) -> Result<LatexGateResult, ReCtmError> {
        let mut errors = static_latex_errors(proof)?;
        let mut warnings = Vec::new();
        let static_valid = errors.is_empty();
        let latexmk = find_in_path("latexmk");
        let compile_available = latexmk.is_some();
        let mut compile_attempted = false;
        let mut compile_passed = false;
        let mut compiler_output = String::new();

        if static_valid && self.policy != LatexPolicy::StaticOnly {
            let Some(latexmk) = latexmk else {
                warnings.push("latexmk is unavailable in the current environment".to_owned());
                return Ok(result(
                    self.policy,
                    static_valid,
                    false,
                    false,
                    self.policy == LatexPolicy::IfAvailable,
                    errors,
                    warnings,
                    compiler_output,
                ));
            };
            compile_attempted = true;
            let scratch = TempWorkspace::new()?;
            fs::write(scratch.path().join("proof.tex"), proof).map_err(io_error)?;
            let execution = self.native.run_fixed_helper_in_workspace(
                scratch.path(),
                &[
                    latexmk.display().to_string(),
                    "-pdf".to_owned(),
                    "-interaction=nonstopmode".to_owned(),
                    "-halt-on-error".to_owned(),
                    "-no-shell-escape".to_owned(),
                    "proof.tex".to_owned(),
                ],
                self.timeout_ms,
            );
            match execution {
                Ok(value) => {
                    let stdout = value
                        .get("stdout")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();
                    let stderr = value
                        .get("stderr")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();
                    compiler_output = match (stdout.is_empty(), stderr.is_empty()) {
                        (false, false) => format!("{stdout}\n{stderr}"),
                        (false, true) => stdout.to_owned(),
                        (true, false) => stderr.to_owned(),
                        (true, true) => String::new(),
                    };
                    compiler_output = tail_bytes(&compiler_output, self.output_limit);
                    let timed_out =
                        value.get("timed_out").and_then(serde_json::Value::as_bool) == Some(true);
                    let exit_code = value.get("exit_code").and_then(serde_json::Value::as_i64);
                    compile_passed = exit_code == Some(0)
                        && !timed_out
                        && scratch.path().join("proof.pdf").is_file();
                    if timed_out {
                        errors.push(format!(
                            "latexmk timed out after {} seconds",
                            self.timeout_ms / 1000
                        ));
                    } else if !compile_passed {
                        errors.push(format!(
                            "latexmk exited with code {}",
                            exit_code.unwrap_or(-1)
                        ));
                    }
                }
                Err(error) => {
                    errors.push(format!("isolated LaTeX compiler failed: {}", error.code));
                    compiler_output = tail_bytes(&error.message, self.output_limit);
                }
            }
            fs::create_dir_all(workdir).map_err(io_error)?;
            fs::write(workdir.join("compiler.log"), &compiler_output).map_err(io_error)?;
        }

        if self.policy == LatexPolicy::StaticOnly {
            compile_passed = static_valid;
            warnings.push(
                "static_only policy does not prove target LaTeX toolchain compatibility".to_owned(),
            );
        } else if self.policy == LatexPolicy::IfAvailable && !compile_available {
            compile_passed = static_valid;
        }
        Ok(result(
            self.policy,
            static_valid,
            compile_attempted,
            compile_available,
            compile_passed,
            errors,
            warnings,
            compiler_output,
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn result(
    policy: LatexPolicy,
    static_valid: bool,
    compile_attempted: bool,
    compile_available: bool,
    compile_passed: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
    compiler_output: String,
) -> LatexGateResult {
    LatexGateResult {
        policy: policy.as_str().to_owned(),
        static_valid,
        compile_attempted,
        compile_available,
        compile_passed,
        gate_passed: static_valid && compile_passed,
        errors,
        warnings,
        compiler_output,
    }
}

pub fn static_latex_errors(content: &str) -> Result<Vec<String>, ReCtmError> {
    if content.trim().is_empty() {
        return Ok(vec!["proof.tex is empty".to_owned()]);
    }
    let mut errors = Vec::new();
    if content.len() > 2 * 1024 * 1024 {
        errors.push("proof.tex exceeds the 2 MiB source limit".to_owned());
    }
    let stripped = strip_comments(content);
    if !Regex::new(r"\\documentclass(?:\[[^\]]*\])?\{[^}]+\}")
        .map_err(regex_error)?
        .is_match(&stripped)
    {
        errors.push("missing documentclass".to_owned());
    }
    if stripped.matches("\\begin{document}").count() != 1 {
        errors.push("proof.tex must contain exactly one \\begin{document}".to_owned());
    }
    if stripped.matches("\\end{document}").count() != 1 {
        errors.push("proof.tex must contain exactly one \\end{document}".to_owned());
    }
    if let (Some(begin), Some(end)) = (
        stripped.find("\\begin{document}"),
        stripped.find("\\end{document}"),
    ) && begin > end
    {
        errors.push("document environment is out of order".to_owned());
    }
    if !balanced_braces(&stripped) {
        errors.push("unbalanced LaTeX braces".to_owned());
    }
    let forbidden = [
        ("shell_escape", r"\\(?:immediate\s*)?write18\b"),
        ("input", r"\\(?:input|include|includeonly)\b"),
        ("file_write", r"\\(?:openout|write|read)\b"),
        ("file_read", r"\\(?:openin|newread|readline)\b"),
        (
            "shellesc_package",
            r"\\usepackage(?:\[[^\]]*\])?\{shellesc\}",
        ),
        ("bibliography_file", r"\\(?:bibliography|addbibresource)\b"),
        ("external_graphic", r"\\includegraphics\b"),
        (
            "external_listing",
            r"\\(?:lstinputlisting|verbatiminput|includepdf)\b",
        ),
        ("external_auxiliary", r"\\externaldocument\b"),
    ];
    for (name, pattern) in forbidden {
        if Regex::new(&format!("(?i){pattern}"))
            .map_err(regex_error)?
            .is_match(&stripped)
        {
            errors.push(format!("forbidden LaTeX operation: {name}"));
        }
    }
    Ok(errors)
}

fn strip_comments(content: &str) -> String {
    content
        .lines()
        .map(|line| {
            let mut escaped = false;
            for (index, character) in line.char_indices() {
                if character == '%' && !escaped {
                    return &line[..index];
                }
                escaped = character == '\\' && !escaped;
                if character != '\\' {
                    escaped = false;
                }
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn balanced_braces(content: &str) -> bool {
    let mut depth = 0_i64;
    let mut escaped = false;
    for character in content.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
        } else if character == '{' {
            depth += 1;
        } else if character == '}' {
            depth -= 1;
            if depth < 0 {
                return false;
            }
        }
    }
    depth == 0
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    })
}

struct TempWorkspace {
    path: PathBuf,
}

impl TempWorkspace {
    fn new() -> Result<Self, ReCtmError> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| internal(&format!("system clock before Unix epoch: {error}")))?
            .as_nanos();
        let path = std::env::temp_dir().join(format!("mtm-latex-{}-{nanos}", std::process::id()));
        fs::create_dir(&path).map_err(io_error)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn tail_bytes(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        value.to_owned()
    } else {
        String::from_utf8_lossy(&value.as_bytes()[value.len() - limit..]).into_owned()
    }
}

fn regex_error(error: regex::Error) -> ReCtmError {
    ReCtmError::new("LATEX_REGEX_ERROR", error.to_string()).with_category(ErrorCategory::Internal)
}

fn internal(message: &str) -> ReCtmError {
    ReCtmError::new("INTERNAL_ERROR", message).with_category(ErrorCategory::Internal)
}

fn io_error(error: std::io::Error) -> ReCtmError {
    ReCtmError::new("LATEX_IO_ERROR", error.to_string()).with_category(ErrorCategory::Runtime)
}
