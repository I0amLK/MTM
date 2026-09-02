use std::collections::BTreeMap;
use std::env;
use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use mtm_contracts::{ErrorCategory, ReCtmError};
use mtm_core::extract_quick_tunnel_origin;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};

const MAX_LOG_CHUNK: usize = 16_384;
const SECRET_ENV_KEYS: [&str; 11] = [
    "MTM_OAUTH_PASSWORD",
    "MTM_TOKEN_SECRET",
    "MTM_CAPABILITY_SECRET",
    "RE_CTM_OAUTH_PASSWORD",
    "RE_CTM_TOKEN_SECRET",
    "RE_CTM_CAPABILITY_SECRET",
    "TUNNEL_ORIGIN_CERT",
    "TUNNEL_CRED_FILE",
    "TUNNEL_CRED_CONTENTS",
    "TUNNEL_TOKEN",
    "TUNNEL_TOKEN_FILE",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelState {
    Starting,
    Connected,
    Unavailable,
    Disconnected,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TunnelEvent {
    pub state: TunnelState,
    pub message: String,
    pub public_mcp_url: Option<String>,
    pub exit_code: Option<i32>,
}

type EventSink = Arc<dyn Fn(TunnelEvent) + Send + Sync + 'static>;

pub struct QuickTunnel {
    executable: Option<PathBuf>,
    sink: EventSink,
    child: Option<Arc<Mutex<Child>>>,
    reader: Option<JoinHandle<()>>,
    stopping: Arc<AtomicBool>,
    closed: bool,
}

impl QuickTunnel {
    #[must_use]
    pub fn new(executable: Option<PathBuf>, sink: EventSink) -> Self {
        Self {
            executable,
            sink,
            child: None,
            reader: None,
            stopping: Arc::new(AtomicBool::new(false)),
            closed: false,
        }
    }

    pub fn start(&mut self, local_origin: &str) -> Result<bool, ReCtmError> {
        if self.child.is_some() || self.stopping.load(Ordering::SeqCst) {
            return Ok(false);
        }
        let executable = self
            .executable
            .clone()
            .or_else(|| find_in_path("cloudflared"));
        let Some(executable) = executable else {
            (self.sink)(TunnelEvent {
                state: TunnelState::Unavailable,
                message: "cloudflared not found; local MCP remains available".to_owned(),
                public_mcp_url: None,
                exit_code: None,
            });
            return Ok(false);
        };
        let environment = sanitized_environment();
        let mut command = Command::new(&executable);
        command
            .args([
                "tunnel",
                "--config",
                "/dev/null",
                "--no-autoupdate",
                "--url",
                local_origin,
            ])
            .env_clear()
            .envs(&environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                (self.sink)(TunnelEvent {
                    state: TunnelState::Unavailable,
                    message: format!(
                        "failed to start cloudflared ({}); local MCP remains available",
                        error.kind()
                    ),
                    public_mcp_url: None,
                    exit_code: None,
                });
                return Ok(false);
            }
        };
        let stdout = child.stdout.take().ok_or_else(|| {
            ReCtmError::new(
                "QUICK_TUNNEL_START_FAILED",
                "cloudflared stdout was not captured",
            )
            .with_category(ErrorCategory::Runtime)
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            ReCtmError::new(
                "QUICK_TUNNEL_START_FAILED",
                "cloudflared stderr was not captured",
            )
            .with_category(ErrorCategory::Runtime)
        })?;
        let child = Arc::new(Mutex::new(child));
        self.child = Some(Arc::clone(&child));
        (self.sink)(TunnelEvent {
            state: TunnelState::Starting,
            message: "starting".to_owned(),
            public_mcp_url: None,
            exit_code: None,
        });
        let sink = Arc::clone(&self.sink);
        let stopping = Arc::clone(&self.stopping);
        self.reader = Some(thread::spawn(move || {
            let (sender, receiver) = std::sync::mpsc::channel::<String>();
            spawn_log_reader(stdout, sender.clone());
            spawn_log_reader(stderr, sender);
            let mut published = String::new();
            while !stopping.load(Ordering::SeqCst) {
                match receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(line) => {
                        if let Ok(Some(origin)) = extract_quick_tunnel_origin(&line)
                            && origin != published
                        {
                            published = origin.clone();
                            sink(TunnelEvent {
                                state: TunnelState::Connected,
                                message: "connected".to_owned(),
                                public_mcp_url: Some(format!(
                                    "{}/mcp",
                                    origin.trim_end_matches('/')
                                )),
                                exit_code: None,
                            });
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
                let exited = child
                    .lock()
                    .ok()
                    .and_then(|mut guard| guard.try_wait().ok().flatten());
                if exited.is_some() {
                    break;
                }
            }
            if stopping.load(Ordering::SeqCst) {
                return;
            }
            let exit_code = child
                .lock()
                .ok()
                .and_then(|mut guard| guard.try_wait().ok().flatten())
                .and_then(|status| status.code());
            if published.is_empty() {
                sink(TunnelEvent {
                    state: TunnelState::Unavailable,
                    message: format!(
                        "cloudflared exited with code {}; local MCP remains available",
                        display_exit(exit_code)
                    ),
                    public_mcp_url: None,
                    exit_code,
                });
            } else {
                sink(TunnelEvent {
                    state: TunnelState::Disconnected,
                    message: format!("cloudflared exited with code {}", display_exit(exit_code)),
                    public_mcp_url: None,
                    exit_code,
                });
            }
        }));
        Ok(true)
    }

    pub fn close(&mut self) -> Result<(), ReCtmError> {
        if self.closed {
            return Ok(());
        }
        self.stopping.store(true, Ordering::SeqCst);
        if let Some(child) = &self.child {
            let pid = child.lock().map_err(|_| lock_error())?.id();
            let running = child
                .lock()
                .map_err(|_| lock_error())?
                .try_wait()
                .map_err(io_error)?
                .is_none();
            if running {
                send_signal(pid, Signal::SIGTERM)?;
                if !wait_for_child(child, Duration::from_millis(1500))? {
                    send_signal(pid, Signal::SIGKILL)?;
                    let _ = wait_for_child(child, Duration::from_millis(500))?;
                }
            }
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        self.child = None;
        self.closed = true;
        (self.sink)(TunnelEvent {
            state: TunnelState::Closed,
            message: "closed".to_owned(),
            public_mcp_url: None,
            exit_code: None,
        });
        Ok(())
    }

    #[must_use]
    pub fn child_environment_snapshot() -> BTreeMap<String, String> {
        sanitized_environment()
    }

    #[must_use]
    pub fn sanitize_environment(input: BTreeMap<String, String>) -> BTreeMap<String, String> {
        input
            .into_iter()
            .filter(|(key, _)| !SECRET_ENV_KEYS.contains(&key.as_str()))
            .collect()
    }
}

impl Drop for QuickTunnel {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn spawn_log_reader<R: std::io::Read + Send + 'static>(
    stream: R,
    sender: std::sync::mpsc::Sender<String>,
) {
    thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if line.len() > MAX_LOG_CHUNK {
                        line.truncate(MAX_LOG_CHUNK);
                    }
                    if sender.send(line).is_err() {
                        break;
                    }
                }
            }
        }
    });
}

fn sanitized_environment() -> BTreeMap<String, String> {
    QuickTunnel::sanitize_environment(env::vars().collect())
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|entry| entry.join(name))
            .find(|candidate| candidate.is_file())
    })
}

fn send_signal(pid: u32, signal: Signal) -> Result<(), ReCtmError> {
    let pid = i32::try_from(pid).map_err(|_| {
        ReCtmError::new("QUICK_TUNNEL_SIGNAL_FAILED", "cloudflared PID is invalid")
            .with_category(ErrorCategory::Runtime)
    })?;
    match killpg(Pid::from_raw(pid), signal) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

fn wait_for_child(child: &Arc<Mutex<Child>>, timeout: Duration) -> Result<bool, ReCtmError> {
    let deadline = Instant::now() + timeout;
    loop {
        if child
            .lock()
            .map_err(|_| lock_error())?
            .try_wait()
            .map_err(io_error)?
            .is_some()
        {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn display_exit(value: Option<i32>) -> String {
    value.map_or_else(|| "unknown".to_owned(), |code| code.to_string())
}

fn io_error(error: impl std::fmt::Display) -> ReCtmError {
    ReCtmError::new("QUICK_TUNNEL_RUNTIME_ERROR", error.to_string())
        .with_category(ErrorCategory::Runtime)
}

fn lock_error() -> ReCtmError {
    ReCtmError::new("INTERNAL_LOCK_POISONED", "Quick Tunnel lock was poisoned.")
        .with_category(ErrorCategory::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn child_environment_strips_all_known_credentials() {
        let input = SECRET_ENV_KEYS
            .into_iter()
            .map(|key| (key.to_owned(), "secret".to_owned()))
            .chain(std::iter::once(("PATH".to_owned(), "/usr/bin".to_owned())))
            .collect();
        let snapshot = QuickTunnel::sanitize_environment(input);
        for key in SECRET_ENV_KEYS {
            assert!(!snapshot.contains_key(key));
        }
        assert_eq!(snapshot.get("PATH").map(String::as_str), Some("/usr/bin"));
    }

    #[test]
    fn close_is_idempotent_and_emits_one_closed_event() -> Result<(), ReCtmError> {
        let temporary = TempDir::new().map_err(io_error)?;
        let missing = temporary.path().join("missing-cloudflared");
        let events = Arc::new(Mutex::new(Vec::<TunnelEvent>::new()));
        let sink_events = Arc::clone(&events);
        let sink = Arc::new(move |event: TunnelEvent| {
            if let Ok(mut target) = sink_events.lock() {
                target.push(event);
            }
        });
        let mut tunnel = QuickTunnel::new(Some(missing), sink);
        assert!(!tunnel.start("http://127.0.0.1:44567")?);
        tunnel.close()?;
        tunnel.close()?;
        let closed = events
            .lock()
            .map_err(|_| lock_error())?
            .iter()
            .filter(|event| event.state == TunnelState::Closed)
            .count();
        assert_eq!(closed, 1);
        Ok(())
    }
}
