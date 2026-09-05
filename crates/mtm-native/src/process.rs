use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mtm_contracts::{ErrorCategory, ReCtmError, invalid_argument};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

const COMMAND_BUFFER_BYTES: usize = 524_288;
const COMMAND_HEAD_BUFFER_DIVISOR: usize = 8;
const MAX_ACTIVE_COMMANDS: usize = 16;
const MAX_RETAINED_COMMANDS: usize = 32;
const COMPLETED_COMMAND_TTL: Duration = Duration::from_secs(300);
static COMMAND_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub struct CommandManagerConfig {
    pub buffer_bytes: usize,
    pub max_active_commands: usize,
    pub max_retained_commands: usize,
    pub completed_ttl: Duration,
}

impl Default for CommandManagerConfig {
    fn default() -> Self {
        Self {
            buffer_bytes: COMMAND_BUFFER_BYTES,
            max_active_commands: MAX_ACTIVE_COMMANDS,
            max_retained_commands: MAX_RETAINED_COMMANDS,
            completed_ttl: COMPLETED_COMMAND_TTL,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandRequest {
    pub argv: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_yield_ms")]
    pub yield_time_ms: u64,
    #[serde(default = "default_output_bytes")]
    pub max_output_bytes: usize,
    #[serde(default)]
    pub stdin: String,
    #[serde(default)]
    pub tty: bool,
    pub verbosity: Option<String>,
    #[serde(default = "default_preview_bytes")]
    pub preview_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PollRequest {
    pub command_id: String,
    #[serde(default)]
    pub chars: String,
    #[serde(default = "default_yield_ms")]
    pub yield_time_ms: u64,
    #[serde(default = "default_output_bytes")]
    pub max_output_bytes: usize,
    pub verbosity: Option<String>,
    #[serde(default = "default_preview_bytes")]
    pub preview_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KillRequest {
    pub command_id: String,
    #[serde(default = "default_signal")]
    pub signal: String,
    #[serde(default = "default_wait_ms")]
    pub wait_ms: u64,
    #[serde(default = "default_kill_wait_ms")]
    pub kill_wait_ms: u64,
    #[serde(default = "default_output_bytes")]
    pub max_output_bytes: usize,
    pub verbosity: Option<String>,
    #[serde(default = "default_preview_bytes")]
    pub preview_bytes: usize,
}

#[derive(Clone)]
pub struct CommandManager {
    inner: Arc<ManagerInner>,
}

struct ManagerInner {
    config: CommandManagerConfig,
    state: Mutex<ManagerState>,
}

struct ManagerState {
    active: HashMap<String, Arc<CommandRun>>,
    retained: HashMap<String, Arc<CommandRun>>,
    retained_order: VecDeque<String>,
    closed: bool,
}

struct CommandRun {
    command_id: String,
    pid: u32,
    child: Mutex<Child>,
    stdin: Mutex<Option<ChildStdin>>,
    stdout: Mutex<StreamBuffer>,
    stderr: Mutex<StreamBuffer>,
    status: Mutex<RunStatus>,
    started_at: Instant,
    timeout_at: Option<Instant>,
    requested_timeout_ms: Option<u64>,
    warnings: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct RunStatus {
    completed_at: Option<Instant>,
    exit_code: Option<i32>,
    signal_name: Option<String>,
    timed_out: bool,
    terminating: bool,
    termination_source: Option<String>,
    term_sent_by_mtm: bool,
    kill_sent_by_mtm: bool,
}

#[derive(Clone, Debug)]
struct StreamBuffer {
    buffer_limit: usize,
    head_limit: usize,
    head: Vec<u8>,
    tail: Vec<u8>,
    start_offset: usize,
    cursor: usize,
    total_bytes: usize,
    dropped_bytes: usize,
}

impl StreamBuffer {
    fn new(buffer_limit: usize) -> Self {
        let head_limit = buffer_limit / COMMAND_HEAD_BUFFER_DIVISOR;
        Self {
            buffer_limit,
            head_limit,
            head: Vec::with_capacity(head_limit),
            tail: Vec::with_capacity(buffer_limit.saturating_sub(head_limit)),
            start_offset: 0,
            cursor: 0,
            total_bytes: 0,
            dropped_bytes: 0,
        }
    }

    fn append(&mut self, chunk: &[u8]) {
        let capacity = self.head_limit.saturating_sub(self.head.len());
        let take = capacity.min(chunk.len());
        if take > 0 {
            self.head.extend_from_slice(&chunk[..take]);
        }
        self.tail.extend_from_slice(chunk);
        self.total_bytes = self.total_bytes.saturating_add(chunk.len());
        let tail_limit = self.buffer_limit.saturating_sub(self.head_limit);
        if self.tail.len() > tail_limit {
            let overflow = self.tail.len() - tail_limit;
            self.tail.drain(..overflow);
            self.start_offset = self.total_bytes.saturating_sub(self.tail.len());
            self.dropped_bytes = self.dropped_bytes.saturating_add(overflow);
        }
    }

    fn take_since_cursor(&mut self) -> StreamSnapshot {
        let omitted = self.start_offset.saturating_sub(self.cursor);
        let start = self.cursor.saturating_sub(self.start_offset);
        let bytes = if start < self.tail.len() {
            self.tail[start..].to_vec()
        } else {
            Vec::new()
        };
        self.cursor = self.total_bytes;
        StreamSnapshot { bytes, omitted }
    }
}

struct StreamSnapshot {
    bytes: Vec<u8>,
    omitted: usize,
}

impl CommandManager {
    #[must_use]
    pub fn new(config: CommandManagerConfig) -> Self {
        Self {
            inner: Arc::new(ManagerInner {
                config,
                state: Mutex::new(ManagerState {
                    active: HashMap::new(),
                    retained: HashMap::new(),
                    retained_order: VecDeque::new(),
                    closed: false,
                }),
            }),
        }
    }

    pub fn start(&self, request: CommandRequest) -> Result<Value, ReCtmError> {
        validate_request(&request)?;
        self.prune()?;
        {
            let state = lock(&self.inner.state)?;
            if state.closed {
                return Err(runtime_error(
                    "COMMAND_CLOSED",
                    "Command manager is closed.",
                ));
            }
            if state.active.len() >= self.inner.config.max_active_commands {
                return Err(ReCtmError::new(
                    "COMMAND_LIMIT_REACHED",
                    "Too many commands are already running.",
                )
                .with_category(ErrorCategory::Runtime)
                .with_retryable(true)
                .with_details(serde_json::json!({
                    "max_active_commands": self.inner.config.max_active_commands,
                })));
            }
        }

        let mut command = spawn_command(&request.argv, &request.env, request.tty)?;
        let pid = command.id();
        let stdin = command.stdin.take();
        let stdout = command.stdout.take().ok_or_else(|| {
            runtime_error("COMMAND_START_FAILED", "Command stdout was not captured.")
        })?;
        let stderr = command.stderr.take().ok_or_else(|| {
            runtime_error("COMMAND_START_FAILED", "Command stderr was not captured.")
        })?;
        let command_id = new_command_id();
        let run = Arc::new(CommandRun {
            command_id: command_id.clone(),
            pid,
            child: Mutex::new(command),
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(StreamBuffer::new(self.inner.config.buffer_bytes)),
            stderr: Mutex::new(StreamBuffer::new(self.inner.config.buffer_bytes)),
            status: Mutex::new(RunStatus::default()),
            started_at: Instant::now(),
            timeout_at: Some(Instant::now() + Duration::from_millis(request.timeout_ms)),
            requested_timeout_ms: Some(request.timeout_ms),
            warnings: Vec::new(),
        });
        spawn_reader(stdout, Arc::clone(&run), StreamKind::Stdout);
        spawn_reader(stderr, Arc::clone(&run), StreamKind::Stderr);
        start_watchdog(Arc::clone(&run));
        {
            let mut state = lock(&self.inner.state)?;
            state.active.insert(command_id, Arc::clone(&run));
        }
        if !request.stdin.is_empty() {
            write_input(&run, request.stdin.as_bytes())?;
        }
        if !request.tty {
            close_stdin(&run)?;
        }
        wait_until(&run, request.yield_time_ms, false)?;
        refresh_status(&run)?;
        let payload = snapshot(&run, request.max_output_bytes)?;
        self.format_and_retain(
            &run,
            payload,
            request.verbosity.as_deref(),
            request.preview_bytes,
        )
    }

    pub fn poll(&self, request: PollRequest) -> Result<Value, ReCtmError> {
        let run = self.get(&request.command_id, true)?;
        refresh_status(&run)?;
        if is_terminal(&run)? && !request.chars.is_empty() {
            return Err(runtime_error(
                "COMMAND_CLOSED",
                "Command is closed; stdin write blocked.",
            ));
        }
        if !request.chars.is_empty() && !is_terminal(&run)? {
            write_input(&run, request.chars.as_bytes())?;
        }
        wait_until(&run, request.yield_time_ms, true)?;
        let payload = snapshot(&run, request.max_output_bytes)?;
        self.format_and_retain(
            &run,
            payload,
            request.verbosity.as_deref(),
            request.preview_bytes,
        )
    }

    pub fn kill(&self, request: KillRequest) -> Result<Value, ReCtmError> {
        let run = self.get(&request.command_id, false)?;
        let (signal, mut force) = match request.signal.as_str() {
            "TERM" => (Signal::SIGTERM, false),
            "KILL" => (Signal::SIGKILL, true),
            "INT" => (Signal::SIGINT, false),
            _ => return Err(invalid_argument("signal must be TERM, KILL, or INT")),
        };
        let original_running = !is_terminal(&run)?;
        let mut killed = false;
        let mut evicted = true;
        if original_running {
            {
                let mut status = lock(&run.status)?;
                status.terminating = true;
                status.termination_source = Some("explicit_kill".to_owned());
                if signal == Signal::SIGTERM {
                    status.term_sent_by_mtm = true;
                }
                if signal == Signal::SIGKILL {
                    status.kill_sent_by_mtm = true;
                }
            }
            send_signal(&run, signal)?;
            if !wait_for_exit(&run, Duration::from_millis(request.wait_ms))? && !force {
                force = true;
                {
                    let mut status = lock(&run.status)?;
                    status.kill_sent_by_mtm = true;
                }
                send_signal(&run, Signal::SIGKILL)?;
                let _ = wait_for_exit(&run, Duration::from_millis(request.kill_wait_ms))?;
            }
            killed = is_terminal(&run)?;
        }
        refresh_status(&run)?;
        let mut payload = snapshot(&run, request.max_output_bytes)?;
        let status = if original_running && !killed {
            evicted = false;
            "terminating"
        } else if original_running {
            if force { "killed" } else { "terminated" }
        } else {
            "exited"
        };
        let object = payload.as_object_mut().ok_or_else(|| {
            runtime_error(
                "INTERNAL_SERIALIZATION_ERROR",
                "Command payload was not an object.",
            )
        })?;
        object.insert("killed".to_owned(), Value::Bool(killed));
        object.insert("status".to_owned(), Value::String(status.to_owned()));
        object.insert("evicted".to_owned(), Value::Bool(evicted));
        object.insert(
            "signal_sent".to_owned(),
            Value::String(if force {
                "SIGKILL".to_owned()
            } else {
                signal_name(signal).to_owned()
            }),
        );
        let mut formatted = self.format_and_retain(
            &run,
            payload,
            request.verbosity.as_deref(),
            request.preview_bytes,
        )?;
        if status == "terminating" {
            if let Some(object) = formatted.as_object_mut() {
                let warnings = object
                    .entry("warnings")
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let Some(items) = warnings.as_array_mut() {
                    items.push(Value::String(
                        "Process did not exit after TERM/SIGKILL; command retained for retry or watchdog cleanup."
                            .to_owned(),
                    ));
                }
                object.insert(
                    "next_action".to_owned(),
                    Value::String("retry kill_command or wait for watchdog cleanup".to_owned()),
                );
            }
        }
        if evicted {
            let mut state = lock(&self.inner.state)?;
            state.active.remove(&run.command_id);
            state.retained.remove(&run.command_id);
            state
                .retained_order
                .retain(|value| value != &run.command_id);
        }
        Ok(formatted)
    }

    pub fn read_output(
        &self,
        output_ref: &str,
        stream: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<Value, ReCtmError> {
        let parts = output_ref.split(':').collect::<Vec<_>>();
        if parts.len() != 3
            || parts.first() != Some(&"command")
            || !matches!(parts.get(2), Some(&"stdout" | &"stderr"))
        {
            return Err(invalid_argument(
                "output_ref must look like command:<id>:stdout or command:<id>:stderr",
            ));
        }
        let selected = parts[2];
        if stream.is_some_and(|value| value != selected) {
            return Err(invalid_argument("stream does not match output_ref"));
        }
        let run = self.get(parts[1], false)?;
        let buffer = if selected == "stdout" {
            lock(&run.stdout)?
        } else {
            lock(&run.stderr)?
        };
        let requested = offset;
        let limit = limit.clamp(1, self.inner.config.buffer_bytes);
        let head_len = buffer.head.len();
        let gap = buffer.start_offset.saturating_sub(head_len);
        let (actual, chunk) = if requested >= buffer.start_offset {
            let actual = requested;
            let start = actual
                .saturating_sub(buffer.start_offset)
                .min(buffer.tail.len());
            (
                actual,
                buffer.tail[start..buffer.tail.len().min(start + limit)].to_vec(),
            )
        } else if requested < head_len {
            let end = head_len.min(requested + limit);
            (requested, buffer.head[requested..end].to_vec())
        } else {
            (
                buffer.start_offset,
                buffer.tail[..buffer.tail.len().min(limit)].to_vec(),
            )
        };
        let next_offset =
            (actual + chunk.len() < buffer.total_bytes).then_some(actual + chunk.len());
        let omitted_bytes = actual.saturating_sub(requested);
        let mut warnings = Vec::new();
        if omitted_bytes > 0 {
            warnings.push(format!("{selected} offset skipped dropped bytes"));
        }
        if gap > 0 {
            warnings.push(format!(
                "{selected} output between the retained head and the rolling tail was evicted; redirect large output to a file (cmd > out.log 2>&1) to keep everything"
            ));
        }
        let retained = buffer.tail.len() + head_len.min(buffer.start_offset);
        let retained_start_offset = buffer.start_offset;
        let total_stream_bytes = buffer.total_bytes;
        let stream_dropped_bytes = buffer.dropped_bytes;
        drop(buffer);
        let stdout_dropped_bytes = if selected == "stdout" {
            stream_dropped_bytes
        } else {
            lock(&run.stdout)?.dropped_bytes
        };
        let stderr_dropped_bytes = if selected == "stderr" {
            stream_dropped_bytes
        } else {
            lock(&run.stderr)?.dropped_bytes
        };
        Ok(serde_json::json!({
            "ok": true,
            "output_ref": output_ref,
            "stream_output_ref": format!("command:{}:{selected}", run.command_id),
            "stream": selected,
            "offset": actual,
            "requested_offset": requested,
            "limit": limit,
            "content": String::from_utf8_lossy(&chunk),
            "next_offset": next_offset,
            "total_retained_bytes": retained,
            "head_retained_bytes": head_len,
            "evicted_gap_bytes": gap,
            "retained_start_offset": retained_start_offset,
            "total_stream_bytes": total_stream_bytes,
            "stdout_dropped_bytes": stdout_dropped_bytes,
            "stderr_dropped_bytes": stderr_dropped_bytes,
            "stream_dropped_bytes": stream_dropped_bytes,
            "omitted_bytes": omitted_bytes,
            "truncated": next_offset.is_some(),
            "warnings": warnings,
            "next_action": next_offset.map(|next| serde_json::json!({
                "tool": "read_output",
                "arguments": {"output_ref": output_ref, "offset": next, "limit": limit},
            })),
        }))
    }

    pub fn close(&self) -> Result<(), ReCtmError> {
        let active = {
            let mut state = lock(&self.inner.state)?;
            state.closed = true;
            state.active.values().cloned().collect::<Vec<_>>()
        };
        for run in active {
            if !is_terminal(&run)? {
                {
                    let mut status = lock(&run.status)?;
                    if status.termination_source.is_none() {
                        status.termination_source = Some("parent_shutdown".to_owned());
                    }
                    status.term_sent_by_mtm = true;
                }
                let _ = send_signal(&run, Signal::SIGTERM);
            }
        }
        Ok(())
    }

    fn get(&self, command_id: &str, stdin: bool) -> Result<Arc<CommandRun>, ReCtmError> {
        self.prune()?;
        let state = lock(&self.inner.state)?;
        state
            .active
            .get(command_id)
            .or_else(|| state.retained.get(command_id))
            .cloned()
            .ok_or_else(|| {
                ReCtmError::new(
                    "COMMAND_NOT_FOUND",
                    if stdin {
                        "Command not found; stdin access denied."
                    } else {
                        "Output command not found."
                    },
                )
                .with_category(ErrorCategory::NotFound)
            })
    }

    fn prune(&self) -> Result<(), ReCtmError> {
        let active = {
            let state = lock(&self.inner.state)?;
            state.active.values().cloned().collect::<Vec<_>>()
        };
        for run in active {
            refresh_status(&run)?;
            if is_terminal(&run)? {
                self.retain_terminal(&run)?;
            }
        }
        let now = Instant::now();
        let mut state = lock(&self.inner.state)?;
        let expired = state
            .retained
            .iter()
            .filter_map(|(id, run)| {
                let status = run.status.lock().ok()?;
                let completed = status.completed_at?;
                (now.saturating_duration_since(completed) > self.inner.config.completed_ttl)
                    .then_some(id.clone())
            })
            .collect::<Vec<_>>();
        for id in expired {
            state.retained.remove(&id);
            state.retained_order.retain(|value| value != &id);
        }
        while state.retained_order.len() > self.inner.config.max_retained_commands {
            if let Some(id) = state.retained_order.pop_front() {
                state.retained.remove(&id);
            }
        }
        Ok(())
    }

    fn retain_terminal(&self, run: &Arc<CommandRun>) -> Result<(), ReCtmError> {
        let mut state = lock(&self.inner.state)?;
        if state.active.remove(&run.command_id).is_some() {
            state
                .retained
                .insert(run.command_id.clone(), Arc::clone(run));
            state
                .retained_order
                .retain(|value| value != &run.command_id);
            state.retained_order.push_back(run.command_id.clone());
        }
        Ok(())
    }

    fn format_and_retain(
        &self,
        run: &Arc<CommandRun>,
        mut payload: Value,
        verbosity: Option<&str>,
        preview_bytes: usize,
    ) -> Result<Value, ReCtmError> {
        let selected = verbosity.unwrap_or_default().trim().to_ascii_lowercase();
        if !selected.is_empty() && !matches!(selected.as_str(), "summary" | "preview" | "full") {
            return Err(invalid_argument(
                "verbosity must be summary, preview, or full",
            ));
        }
        let terminal = payload
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| status != "running");
        if terminal {
            self.retain_terminal(run)?;
        } else if let Some(object) = payload.as_object_mut() {
            object.insert(
                "next_action".to_owned(),
                serde_json::json!({
                    "tool": "write_stdin",
                    "arguments": {"command_id": run.command_id, "chars": "", "yield_time_ms": 10000},
                }),
            );
        }
        if let Some(object) = payload.as_object_mut() {
            let refs = serde_json::json!({
                "stdout": format!("command:{}:stdout", run.command_id),
                "stderr": format!("command:{}:stderr", run.command_id),
            });
            let output_ref = if object.get("stdout").is_none_or(is_empty_string)
                && object
                    .get("stderr")
                    .is_some_and(|value| !is_empty_string(value))
            {
                format!("command:{}:stderr", run.command_id)
            } else {
                format!("command:{}:stdout", run.command_id)
            };
            object.insert("output_refs".to_owned(), refs);
            object.insert("output_ref".to_owned(), Value::String(output_ref));
        }
        if matches!(selected.as_str(), "summary" | "preview") {
            let object = payload.as_object().ok_or_else(|| {
                runtime_error(
                    "INTERNAL_SERIALIZATION_ERROR",
                    "Command payload was not an object.",
                )
            })?;
            let mut compact = object
                .iter()
                .filter(|(key, _)| !matches!(key.as_str(), "stdout" | "stderr"))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Map<_, _>>();
            compact.insert("summary".to_owned(), Value::String(summary(run, &payload)?));
            if selected == "preview" {
                let combined = combined_output(run)?;
                let (preview, truncated) = tail_text(&combined, preview_bytes.max(1));
                compact.insert("preview".to_owned(), Value::String(preview));
                compact.insert("preview_truncated".to_owned(), Value::Bool(truncated));
            }
            return Ok(Value::Object(compact));
        }
        Ok(payload)
    }
}

impl Drop for CommandManager {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1 {
            let _ = self.close();
        }
    }
}

fn spawn_command(
    argv: &[String],
    environment: &BTreeMap<String, String>,
    tty: bool,
) -> Result<Child, ReCtmError> {
    let mut command = if tty {
        let script = find_in_path("script").ok_or_else(|| {
            runtime_error(
                "TTY_UNSUPPORTED",
                "A POSIX pseudo-terminal could not be created.",
            )
        })?;
        let mut command = Command::new(script);
        command
            .arg("-qefc")
            .arg(shell_words::join(argv))
            .arg("/dev/null");
        command
    } else {
        let Some(program) = argv.first() else {
            return Err(invalid_argument(
                "argv must be a non-empty array of strings",
            ));
        };
        let mut command = Command::new(program);
        command.args(&argv[1..]);
        command
    };
    command
        .env_clear()
        .envs(environment)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    command.spawn().map_err(|error| {
        ReCtmError::new("COMMAND_START_FAILED", error.to_string())
            .with_category(ErrorCategory::Runtime)
    })
}

fn spawn_reader<R: Read + Send + 'static>(mut stream: R, run: Arc<CommandRun>, kind: StreamKind) {
    thread::spawn(move || {
        let mut chunk = [0_u8; 4096];
        loop {
            let read = match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            let target = match kind {
                StreamKind::Stdout => &run.stdout,
                StreamKind::Stderr => &run.stderr,
            };
            if let Ok(mut buffer) = target.lock() {
                buffer.append(&chunk[..read]);
            } else {
                break;
            }
        }
    });
}

#[derive(Clone, Copy)]
enum StreamKind {
    Stdout,
    Stderr,
}

fn start_watchdog(run: Arc<CommandRun>) {
    let Some(timeout_at) = run.timeout_at else {
        return;
    };
    thread::spawn(move || {
        // Completed commands must not keep a thread and their output buffers
        // alive until a potentially ten-minute timeout. This observer also
        // reaps a naturally exited child when nobody polls the command again.
        loop {
            if is_terminal(&run).unwrap_or(true) {
                return;
            }
            let remaining = timeout_at.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            thread::sleep(remaining.min(Duration::from_millis(20)));
        }
        if is_terminal(&run).unwrap_or(true) {
            return;
        }
        if let Ok(mut status) = run.status.lock() {
            status.timed_out = true;
            if status.termination_source.is_none() {
                status.termination_source = Some("command_timeout".to_owned());
            }
            status.term_sent_by_mtm = true;
        }
        let _ = send_signal(&run, Signal::SIGTERM);
        let _ = refresh_status(&run);
    });
}

fn refresh_status(run: &Arc<CommandRun>) -> Result<(), ReCtmError> {
    let exit = {
        let mut child = lock(&run.child)?;
        child.try_wait().map_err(|error| {
            ReCtmError::new("COMMAND_STATUS_FAILED", error.to_string())
                .with_category(ErrorCategory::Runtime)
        })?
    };
    let Some(exit) = exit else {
        return Ok(());
    };
    thread::sleep(Duration::from_millis(10));
    let mut status = lock(&run.status)?;
    if status.completed_at.is_some() {
        return Ok(());
    }
    status.terminating = false;
    if let Some(code) = exit.code() {
        status.exit_code = Some(code);
    } else if let Some(signal) = exit.signal() {
        status.exit_code = Some(-signal);
        status.signal_name = Some(signal_number_name(signal));
        if status.termination_source.is_none() {
            status.termination_source = Some("external_or_unknown".to_owned());
        }
    }
    status.completed_at = Some(Instant::now());
    Ok(())
}

fn snapshot(run: &Arc<CommandRun>, max_output_bytes: usize) -> Result<Value, ReCtmError> {
    refresh_status(run)?;
    let stdout_snapshot = lock(&run.stdout)?.take_since_cursor();
    let stderr_snapshot = lock(&run.stderr)?.take_since_cursor();
    let (stdout, stdout_truncated) = tail_text(&stdout_snapshot.bytes, max_output_bytes);
    let (stderr, stderr_truncated) = tail_text(&stderr_snapshot.bytes, max_output_bytes);
    let stdout_dropped = lock(&run.stdout)?.dropped_bytes;
    let stderr_dropped = lock(&run.stderr)?.dropped_bytes;
    let status = lock(&run.status)?.clone();
    let running = status.completed_at.is_none();
    let status_label = if status.timed_out {
        "timeout"
    } else if status.terminating && running {
        "running"
    } else if status.signal_name.is_some() {
        "terminated"
    } else if running {
        "running"
    } else {
        "exited"
    };
    let elapsed_ms = status
        .completed_at
        .unwrap_or_else(Instant::now)
        .saturating_duration_since(run.started_at)
        .as_millis() as u64;
    let mut payload = serde_json::json!({
        "ok": true,
        "command_id": run.command_id,
        "status": status_label,
        "exit_code": status.exit_code,
        "signal": status.signal_name,
        "timed_out": status.timed_out,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "stdout_dropped_bytes": stdout_dropped,
        "stderr_dropped_bytes": stderr_dropped,
        "stdout_omitted_bytes": stdout_snapshot.omitted,
        "stderr_omitted_bytes": stderr_snapshot.omitted,
        "truncated": stdout_truncated || stderr_truncated || stdout_snapshot.omitted > 0 || stderr_snapshot.omitted > 0,
        "termination": {
            "source": status.termination_source,
            "requested_timeout_ms": run.requested_timeout_ms,
            "elapsed_ms": elapsed_ms,
            "observed_signal": status.signal_name,
            "term_sent_by_re_ctm": status.term_sent_by_mtm,
            "kill_sent_by_re_ctm": status.kill_sent_by_mtm,
        },
        "elapsed_ms": elapsed_ms,
    });
    if !run.warnings.is_empty() {
        if let Some(object) = payload.as_object_mut() {
            object.insert("warnings".to_owned(), serde_json::json!(run.warnings));
        }
    }
    Ok(payload)
}

fn wait_until(
    run: &Arc<CommandRun>,
    yield_time_ms: u64,
    stop_on_output: bool,
) -> Result<(), ReCtmError> {
    let deadline = Instant::now() + Duration::from_millis(yield_time_ms.min(30_000));
    let stdout_cursor = lock(&run.stdout)?.total_bytes;
    let stderr_cursor = lock(&run.stderr)?.total_bytes;
    while Instant::now() < deadline && !is_terminal(run)? {
        if stop_on_output {
            let stdout_changed = lock(&run.stdout)?.total_bytes > stdout_cursor;
            let stderr_changed = lock(&run.stderr)?.total_bytes > stderr_cursor;
            if stdout_changed || stderr_changed {
                break;
            }
        }
        thread::sleep(Duration::from_millis(20));
        refresh_status(run)?;
    }
    Ok(())
}

fn wait_for_exit(run: &Arc<CommandRun>, timeout: Duration) -> Result<bool, ReCtmError> {
    let deadline = Instant::now() + timeout;
    loop {
        refresh_status(run)?;
        if is_terminal(run)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn is_terminal(run: &Arc<CommandRun>) -> Result<bool, ReCtmError> {
    refresh_status(run)?;
    Ok(lock(&run.status)?.completed_at.is_some())
}

fn write_input(run: &Arc<CommandRun>, data: &[u8]) -> Result<(), ReCtmError> {
    let mut stdin = lock(&run.stdin)?;
    let Some(handle) = stdin.as_mut() else {
        return Err(runtime_error("COMMAND_CLOSED", "Command stdin is closed."));
    };
    handle
        .write_all(data)
        .and_then(|_| handle.flush())
        .map_err(|_| runtime_error("COMMAND_CLOSED", "Command stdin is closed."))
}

fn close_stdin(run: &Arc<CommandRun>) -> Result<(), ReCtmError> {
    lock(&run.stdin)?.take();
    Ok(())
}

fn send_signal(run: &Arc<CommandRun>, signal: Signal) -> Result<(), ReCtmError> {
    let pid = i32::try_from(run.pid).map_err(|_| {
        runtime_error(
            "COMMAND_SIGNAL_FAILED",
            "Command PID exceeded the supported range.",
        )
    })?;
    match killpg(Pid::from_raw(pid), signal) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(error) => Err(ReCtmError::new("COMMAND_SIGNAL_FAILED", error.to_string())
            .with_category(ErrorCategory::Runtime)),
    }
}

fn combined_output(run: &Arc<CommandRun>) -> Result<Vec<u8>, ReCtmError> {
    let stdout = lock(&run.stdout)?.tail.clone();
    let stderr = lock(&run.stderr)?.tail.clone();
    let mut pieces = Vec::new();
    if !stdout.is_empty() {
        pieces.extend_from_slice(b"--- stdout ---\n");
        pieces.extend_from_slice(&stdout);
    }
    if !stderr.is_empty() {
        if !pieces.is_empty() {
            pieces.push(b'\n');
        }
        pieces.extend_from_slice(b"--- stderr ---\n");
        pieces.extend_from_slice(&stderr);
    }
    Ok(pieces)
}

fn summary(run: &Arc<CommandRun>, payload: &Value) -> Result<String, ReCtmError> {
    let text = String::from_utf8_lossy(&combined_output(run)?).into_owned();
    let lines = text.lines().collect::<Vec<_>>();
    let tail = lines
        .iter()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().chars().take(120).collect::<String>())
        .unwrap_or_default();
    let elapsed = payload
        .get("elapsed_ms")
        .and_then(Value::as_f64)
        .unwrap_or(0.0)
        / 1000.0;
    let status = payload
        .get("exit_code")
        .and_then(Value::as_i64)
        .map_or_else(
            || {
                payload
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("running")
                    .to_owned()
            },
            |code| format!("exit {code}"),
        );
    let mut parts = vec![
        status,
        format!("{elapsed:.1}s"),
        format!("{} lines", lines.len()),
    ];
    if !tail.is_empty() {
        parts.push(format!("tail: {tail:?}"));
    }
    Ok(parts.join(" | "))
}

fn tail_text(data: &[u8], max_bytes: usize) -> (String, bool) {
    if data.len() <= max_bytes {
        return (String::from_utf8_lossy(data).into_owned(), false);
    }
    (
        String::from_utf8_lossy(&data[data.len() - max_bytes..]).into_owned(),
        true,
    )
}

fn validate_request(request: &CommandRequest) -> Result<(), ReCtmError> {
    if request.argv.is_empty()
        || request
            .argv
            .iter()
            .any(|item| item.is_empty() || item.contains('\0'))
    {
        return Err(invalid_argument(
            "argv must be a non-empty array of NUL-free strings",
        ));
    }
    if request.timeout_ms == 0 || request.timeout_ms > 600_000 {
        return Err(invalid_argument("timeout_ms must be between 1 and 600000"));
    }
    if request.env.iter().any(|(key, value)| {
        key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0')
    }) {
        return Err(invalid_argument("env contains an invalid key or value"));
    }
    Ok(())
}

fn new_command_id() -> String {
    let counter = COMMAND_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!("cmd-{}-{counter:x}-{nanos:x}", std::process::id())
}

fn find_in_path(name: &str) -> Option<String> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|entry| entry.join(name))
            .find(|candidate| candidate.is_file())
            .map(|candidate| candidate.to_string_lossy().into_owned())
    })
}

fn signal_name(signal: Signal) -> &'static str {
    match signal {
        Signal::SIGTERM => "SIGTERM",
        Signal::SIGKILL => "SIGKILL",
        Signal::SIGINT => "SIGINT",
        _ => "SIGNAL",
    }
}

fn signal_number_name(signal: i32) -> String {
    Signal::try_from(signal)
        .map(|value| format!("{value:?}"))
        .unwrap_or_else(|_| signal.to_string())
}

fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, ReCtmError> {
    mutex.lock().map_err(|_| {
        ReCtmError::new(
            "INTERNAL_LOCK_POISONED",
            "Native runtime lock was poisoned.",
        )
        .with_category(ErrorCategory::Internal)
    })
}

fn runtime_error(code: &str, message: &str) -> ReCtmError {
    ReCtmError::new(code, message).with_category(ErrorCategory::Runtime)
}

fn is_empty_string(value: &Value) -> bool {
    value.as_str().is_some_and(str::is_empty)
}

const fn default_timeout_ms() -> u64 {
    30_000
}

const fn default_yield_ms() -> u64 {
    10_000
}

const fn default_output_bytes() -> usize {
    65_536
}

const fn default_preview_bytes() -> usize {
    4096
}

fn default_signal() -> String {
    "TERM".to_owned()
}

const fn default_wait_ms() -> u64 {
    5000
}

const fn default_kill_wait_ms() -> u64 {
    2000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watchdog_request(argv: Vec<String>, timeout_ms: u64) -> CommandRequest {
        CommandRequest {
            argv,
            env: minimal_env(),
            timeout_ms,
            yield_time_ms: 3_000,
            max_output_bytes: 65_536,
            stdin: String::new(),
            tty: false,
            verbosity: None,
            preview_bytes: 4096,
        }
    }

    #[test]
    fn completed_watchdogs_release_owned_runs_before_long_timeouts() -> Result<(), ReCtmError> {
        let manager = CommandManager::new(CommandManagerConfig::default());
        let mut runs = Vec::new();
        for _ in 0..40 {
            let reply = manager.start(watchdog_request(vec!["/bin/true".to_owned()], 600_000))?;
            assert_eq!(reply["status"], "exited");
            let id = reply["command_id"]
                .as_str()
                .ok_or_else(|| runtime_error("TEST", "missing command id"))?;
            runs.push(Arc::downgrade(&manager.get(id, false)?));
        }
        manager.close()?;
        drop(manager);
        let deadline = Instant::now() + Duration::from_secs(2);
        while runs.iter().any(|run| run.strong_count() != 0) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(runs.iter().all(|run| run.strong_count() == 0));
        Ok(())
    }

    #[test]
    fn watchdog_still_enforces_a_live_command_deadline() -> Result<(), ReCtmError> {
        let manager = CommandManager::new(CommandManagerConfig::default());
        let reply = manager.start(watchdog_request(
            vec!["/bin/sleep".to_owned(), "20".to_owned()],
            50,
        ))?;
        assert_eq!(reply["status"], "timeout");
        assert_eq!(reply["timed_out"], true);
        manager.close()?;
        Ok(())
    }

    #[test]
    fn watchdog_reaps_unpolled_short_commands() -> Result<(), ReCtmError> {
        let manager = CommandManager::new(CommandManagerConfig::default());
        let mut request =
            watchdog_request(vec!["/bin/sleep".to_owned(), "0.1".to_owned()], 600_000);
        request.yield_time_ms = 0;
        let reply = manager.start(request)?;
        let id = reply["command_id"]
            .as_str()
            .ok_or_else(|| runtime_error("TEST", "missing command id"))?;
        let run = manager.get(id, false)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while lock(&run.status)?.completed_at.is_none() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(lock(&run.status)?.completed_at.is_some());
        manager.close()?;
        Ok(())
    }

    #[test]
    fn command_lifecycle_poll_read_and_kill() -> Result<(), ReCtmError> {
        let manager = CommandManager::new(CommandManagerConfig::default());
        let started = manager.start(CommandRequest {
            argv: vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "printf 'started\\n'; sleep 20".to_owned(),
            ],
            env: minimal_env(),
            timeout_ms: 30_000,
            yield_time_ms: 100,
            max_output_bytes: 65_536,
            stdin: String::new(),
            tty: false,
            verbosity: None,
            preview_bytes: 4096,
        })?;
        assert_eq!(started["status"], "running");
        let command_id = started["command_id"]
            .as_str()
            .ok_or_else(|| runtime_error("TEST", "missing command id"))?
            .to_owned();
        let output = manager.read_output(&format!("command:{command_id}:stdout"), None, 0, 4096)?;
        assert!(
            output["content"]
                .as_str()
                .unwrap_or_default()
                .contains("started")
        );
        let killed = manager.kill(KillRequest {
            command_id,
            signal: "TERM".to_owned(),
            wait_ms: 2000,
            kill_wait_ms: 2000,
            max_output_bytes: 65_536,
            verbosity: None,
            preview_bytes: 4096,
        })?;
        assert!(matches!(
            killed["status"].as_str(),
            Some("terminated" | "killed" | "exited")
        ));
        manager.close()?;
        Ok(())
    }

    #[test]
    fn tty_round_trip_uses_owned_terminal_process() -> Result<(), ReCtmError> {
        if find_in_path("script").is_none() {
            return Ok(());
        }
        let manager = CommandManager::new(CommandManagerConfig::default());
        let started = manager.start(CommandRequest {
            argv: vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "printf 'ready\\n'; read value; printf 'got:%s\\n' \"$value\"".to_owned(),
            ],
            env: minimal_env(),
            timeout_ms: 10_000,
            yield_time_ms: 100,
            max_output_bytes: 65_536,
            stdin: String::new(),
            tty: true,
            verbosity: None,
            preview_bytes: 4096,
        })?;
        let command_id = started["command_id"]
            .as_str()
            .ok_or_else(|| runtime_error("TEST", "missing command id"))?
            .to_owned();
        let reply = manager.poll(PollRequest {
            command_id,
            chars: "hello-lifecycle\n".to_owned(),
            yield_time_ms: 1000,
            max_output_bytes: 65_536,
            verbosity: None,
            preview_bytes: 4096,
        })?;
        assert!(
            reply["stdout"]
                .as_str()
                .unwrap_or_default()
                .contains("got:hello-lifecycle")
        );
        manager.close()?;
        Ok(())
    }

    fn minimal_env() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
            ("LANG".to_owned(), "C.UTF-8".to_owned()),
        ])
    }
}
