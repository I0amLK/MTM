//! Bounded capture for fixed, owned diagnostic children, never user commands.
use std::io::{self, Read};
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use serde_json::{Value, json};

const OUTPUT_LIMIT: usize = 16_384;

pub(crate) struct Output {
    pub status: Option<ExitStatus>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
    pub output_limit: bool,
    pub pipes_closed: bool,
    pub reaped: bool,
    pub elapsed_ms: u128,
}

impl Output {
    pub fn complete(&self) -> bool {
        self.status.is_some_and(|s| s.success())
            && !self.timed_out
            && !self.output_limit
            && self.pipes_closed
            && self.reaped
    }

    pub fn summary(&self) -> Value {
        json!({"exit_code":self.status.and_then(|s|s.code()),
            "signal":self.status.and_then(|s|s.signal()),"timed_out":self.timed_out,
            "output_limit_exceeded":self.output_limit,"pipes_closed":self.pipes_closed,
            "child_reaped":self.reaped,"elapsed_ms":self.elapsed_ms,
            "stdout_bytes_retained":self.stdout.len(),"stderr_bytes_retained":self.stderr.len(),
            "raw_output_recorded":false})
    }
}

struct OwnedChild {
    child: Child,
    status: Option<ExitStatus>,
    signal_group: bool,
}

impl OwnedChild {
    fn poll(&mut self) -> io::Result<()> {
        if self.status.is_none() {
            self.status = self.child.try_wait()?;
        }
        Ok(())
    }

    fn stop(&mut self) {
        if self.status.is_some() {
            return;
        }
        // Only signal the still-owned direct child. Bubblewrap's fixed
        // --die-with-parent and PID namespace own its diagnostic descendants.
        // A qualification caller owns a separate process group. Signal it only
        // while its leader is still owned and unreaped.
        if self.signal_group
            && let Ok(pid) = i32::try_from(self.child.id())
        {
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        let _ = self.child.kill();
        let deadline = Instant::now() + Duration::from_secs(1);
        while self.status.is_none() && Instant::now() < deadline {
            if self.poll().is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        self.stop();
    }
}

fn nonblocking(fd: &impl AsFd) -> io::Result<()> {
    let convert = |error| io::Error::from_raw_os_error(error as i32);
    let flags = fcntl(fd, FcntlArg::F_GETFL).map_err(convert)?;
    fcntl(
        fd,
        FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
    )
    .map_err(convert)?;
    Ok(())
}

fn drain(reader: &mut impl Read, bytes: &mut Vec<u8>, limit: usize) -> io::Result<(bool, bool)> {
    let mut buffer = [0_u8; 4096];
    // A continuously writing child must not prevent the deadline check.
    for _ in 0..8 {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok((true, false)),
            Ok(count) => {
                let retained = count.min(limit - bytes.len());
                bytes.extend_from_slice(&buffer[..retained]);
                if retained < count {
                    return Ok((false, true));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok((false, false)),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok((false, false))
}

pub(super) fn capture(
    program: &Path,
    arguments: &[String],
    timeout: Duration,
) -> io::Result<Output> {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .current_dir("/");
    capture_command(&mut command, timeout, OUTPUT_LIMIT, false)
}

/// Fixed maintenance callers configure the command; not a public execution API.
pub(crate) fn capture_command(
    command: &mut Command,
    timeout: Duration,
    limit: usize,
    signal_group: bool,
) -> io::Result<Output> {
    if !(1..=2 * 1024 * 1024).contains(&limit)
        || timeout.is_zero()
        || timeout > Duration::from_secs(600)
    {
        return Err(io::Error::other("maintenance capture bounds invalid"));
    }
    if signal_group {
        command.process_group(0);
    }
    let started = Instant::now();
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut owned = OwnedChild {
        child,
        status: None,
        signal_group,
    };
    let mut stdout = owned
        .child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing pipe"))?;
    let mut stderr = owned
        .child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("missing pipe"))?;
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let mut result = Output {
        status: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
        timed_out: false,
        output_limit: false,
        pipes_closed: false,
        reaped: false,
        elapsed_ms: 0,
    };
    loop {
        let (out_closed, out_limit) = drain(&mut stdout, &mut result.stdout, limit)?;
        let (err_closed, err_limit) = drain(&mut stderr, &mut result.stderr, limit)?;
        result.pipes_closed = out_closed && err_closed;
        result.output_limit = out_limit || err_limit;
        owned.poll()?;
        if result.output_limit || (owned.status.is_some() && result.pipes_closed) {
            break;
        }
        if started.elapsed() >= timeout {
            result.timed_out = true;
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    owned.stop();
    result.status = owned.status;
    result.reaped = owned.status.is_some();
    result.elapsed_ms = started.elapsed().as_millis();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_keeps_exit_status_and_separates_stderr() -> io::Result<()> {
        let out = capture(
            Path::new("/bin/sh"),
            &["-c".into(), "printf ok; printf error >&2; exit 7".into()],
            Duration::from_secs(2),
        )?;
        assert_eq!(out.status.and_then(|s| s.code()), Some(7));
        assert_eq!(out.stdout, b"ok");
        assert_eq!(out.stderr, b"error");
        assert!(out.reaped && out.pipes_closed);
        assert!(!out.complete());
        Ok(())
    }

    #[test]
    fn qualification_capture_honors_custom_budget_and_owned_group_timeout() -> io::Result<()> {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "while :; do printf 1234567890; done"])
            .env_clear();
        let output = capture_command(&mut command, Duration::from_secs(2), 512, true)?;
        assert!(output.output_limit && output.reaped);
        assert_eq!(output.stdout.len(), 512);
        assert!(!output.complete());

        let mut command = Command::new("/bin/sh");
        command.args(["-c", "/bin/sleep 30 & wait"]).env_clear();
        let output = capture_command(&mut command, Duration::from_millis(80), 512, true)?;
        assert!(output.timed_out && output.reaped);
        assert!(output.elapsed_ms < 3000);
        assert!(!output.complete());
        Ok(())
    }

    #[test]
    fn invalid_qualification_capture_bounds_fail_before_spawn() {
        for (timeout, limit) in [
            (Duration::ZERO, 512),
            (Duration::from_secs(601), 512),
            (Duration::from_secs(1), 0),
            (Duration::from_secs(1), 2 * 1024 * 1024 + 1),
        ] {
            let mut command = Command::new("/not-a-program");
            let result = capture_command(&mut command, timeout, limit, true);
            assert!(
                result
                    .is_err_and(|error| error.to_string() == "maintenance capture bounds invalid")
            );
        }
    }

    #[test]
    fn continuous_output_cannot_escape_capture_budget() -> io::Result<()> {
        let out = capture(
            Path::new("/bin/sh"),
            &["-c".into(), "while :; do printf 1234567890; done".into()],
            Duration::from_secs(2),
        )?;
        assert!(out.output_limit && out.reaped);
        assert_eq!(out.stdout.len(), OUTPUT_LIMIT);
        assert!(!out.complete());
        Ok(())
    }

    #[test]
    fn a_stalled_child_is_killed_and_reaped_without_unbounded_wait() -> io::Result<()> {
        let out = capture(
            Path::new("/bin/sh"),
            &["-c".into(), "while :; do :; done".into()],
            Duration::from_millis(80),
        )?;
        assert!(out.timed_out && out.reaped);
        assert!(out.elapsed_ms < 3000);
        assert!(!out.complete());
        Ok(())
    }
}
