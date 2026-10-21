//! Real terminal rendering with disposable state and a synthetic tunnel child.
use std::error::Error;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::pty::{Winsize, openpty};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use url::{Url, form_urlencoded};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
const PASSWORD: &str = "terminal-only-fixture-key";

struct Fixture {
    child: Child,
    master: File,
    slave: File,
    directory: TempDir,
    endpoint: SocketAddr,
    output: String,
    original_modes: rustix::termios::Termios,
}

impl Fixture {
    fn start(verbose: bool, generated: bool, term: &str) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        for path in ["home", "workspace", "bin"] {
            fs::create_dir(directory.path().join(path))?;
        }
        let tunnel = directory.path().join("bin/cloudflared");
        fs::write(
            &tunnel,
            "#!/bin/sh\nprintf 'https://fixture-one.trycloudflare.com\\n' >&2\nwhile [ ! -f \"$HOME/change\" ]; do sleep 0.05; done\nprintf 'https://fixture-two.trycloudflare.com\\n' >&2\nwhile [ ! -f \"$HOME/disconnect\" ]; do sleep 0.05; done\n",
        )?;
        fs::set_permissions(&tunnel, fs::Permissions::from_mode(0o700))?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?;
        drop(listener);
        let pty = openpty(
            Some(&Winsize {
                ws_row: 24,
                ws_col: 120,
                ws_xpixel: 0,
                ws_ypixel: 0,
            }),
            None,
        )?;
        let master = File::from(pty.master);
        let slave = File::from(pty.slave);
        fcntl(&master, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
        let original_modes = rustix::termios::tcgetattr(&slave)?;
        let mut command = Command::new(env!("CARGO_BIN_EXE_mtm"));
        command
            .env_clear()
            .env("HOME", directory.path().join("home"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", directory.path().join("bin").display()),
            )
            .env("TERM", term)
            .env("MTM_DATA_ROOT", directory.path().join("data"))
            .env("MTM_WORKSPACE", directory.path().join("workspace"))
            .env("MTM_NATIVE_EXEC_BACKEND", "disabled")
            .env("MTM_LATEX_POLICY", "static_only")
            .env("MTM_DEBUG", "1")
            .current_dir(directory.path().join("workspace"))
            .args([
                "tui",
                "--quick-tunnel",
                "--port",
                &endpoint.port().to_string(),
            ])
            .stdin(slave.try_clone()?)
            .stdout(Stdio::null())
            .stderr(slave.try_clone()?);
        if !generated {
            command.env("MTM_OAUTH_PASSWORD", PASSWORD);
        }
        if verbose {
            command.arg("--verbose");
        }
        let child = command.spawn()?;
        let mut fixture = Self {
            child,
            master,
            slave,
            directory,
            endpoint,
            output: String::new(),
            original_modes,
        };
        fixture.wait_for("fixture-one.trycloudflare.com/mcp")?;
        Ok(fixture)
    }

    fn drain(&mut self) -> Result {
        let mut buffer = [0_u8; 32768];
        loop {
            match self.master.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => self
                    .output
                    .push_str(&String::from_utf8_lossy(&buffer[..count])),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        if self.output.len() > 8 * 1024 * 1024 {
            return Err("fixture terminal output exceeded bound".into());
        }
        Ok(())
    }

    fn wait_for(&mut self, expected: &str) -> Result {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            self.drain()?;
            if self.output.contains(expected) {
                return Ok(());
            }
            if self.child.try_wait()?.is_some() {
                return Err("TUI exited unexpectedly".into());
            }
            if Instant::now() >= deadline {
                return Err("TUI fixture timed out".into());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn resize(&self, columns: u16, rows: u16) -> Result {
        rustix::termios::tcsetwinsize(
            &self.slave,
            rustix::termios::Winsize {
                ws_col: columns,
                ws_row: rows,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )?;
        Ok(())
    }

    fn stop(&mut self, signal: Signal) -> Result {
        kill(Pid::from_raw(self.child.id().try_into()?), signal)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            self.drain()?;
            if let Some(status) = self.child.try_wait()? {
                assert!(status.success());
                self.drain()?;
                let restored = rustix::termios::tcgetattr(&self.slave)?;
                assert_eq!(restored.local_modes, self.original_modes.local_modes);
                assert_eq!(restored.input_modes, self.original_modes.input_modes);
                assert_eq!(restored.output_modes, self.original_modes.output_modes);
                assert_eq!(restored.control_modes, self.original_modes.control_modes);
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("TUI shutdown timed out".into());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn request(
        &self,
        path: &str,
        body: &[u8],
        content_type: &str,
        token: Option<&str>,
    ) -> Result<(u16, String)> {
        let mut stream = TcpStream::connect_timeout(&self.endpoint, Duration::from_secs(3))?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        let auth = token
            .map(|token| format!("Authorization: Bearer {token}\r\n"))
            .unwrap_or_default();
        write!(
            stream,
            "POST {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{auth}\r\n",
            self.endpoint,
            body.len()
        )?;
        stream.write_all(body)?;
        let mut reply = String::new();
        stream.take(1024 * 1024).read_to_string(&mut reply)?;
        let status = reply
            .split_whitespace()
            .nth(1)
            .ok_or("missing status")?
            .parse()?;
        Ok((status, reply))
    }

    fn post(&self, path: &str, payload: &Value, token: Option<&str>) -> Result<(u16, String)> {
        self.request(
            path,
            &serde_json::to_vec(payload)?,
            "application/json",
            token,
        )
    }

    fn form(&self, path: &str, fields: &[(&str, &str)]) -> Result<(u16, String)> {
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().copied())
            .finish();
        self.request(
            path,
            body.as_bytes(),
            "application/x-www-form-urlencoded",
            None,
        )
    }

    fn login(&self) -> Result<String> {
        let redirect = "http://127.0.0.1/test-callback";
        let (status, reply) = self.post("/oauth/register", &json!({"redirect_uris":[redirect],"token_endpoint_auth_method":"none","client_name":"Terminal fixture"}), None)?;
        assert_eq!(status, 201);
        let registration: Value =
            serde_json::from_str(reply.split_once("\r\n\r\n").ok_or("missing body")?.1)?;
        let client = registration["client_id"].as_str().ok_or("missing client")?;
        let verifier = "v".repeat(64);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let resource = format!("http://{}/mcp", self.endpoint);
        let (status, authorization) = self.form(
            "/oauth/authorize",
            &[
                ("client_id", client),
                ("redirect_uri", redirect),
                ("response_type", "code"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("resource", &resource),
                ("state", "terminal-test"),
                ("password", PASSWORD),
            ],
        )?;
        assert_eq!(status, 302);
        let location = authorization
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("location").then(|| value.trim())
            })
            .ok_or("missing redirect")?;
        let url = Url::parse(location)?;
        let code = url
            .query_pairs()
            .find(|(key, _)| key == "code")
            .ok_or("missing code")?
            .1;
        let (status, token) = self.form(
            "/oauth/token",
            &[
                ("client_id", client),
                ("redirect_uri", redirect),
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("code_verifier", &verifier),
                ("resource", &resource),
            ],
        )?;
        assert_eq!(status, 200);
        let token: Value =
            serde_json::from_str(token.split_once("\r\n\r\n").ok_or("missing token body")?.1)?;
        Ok(token["access_token"]
            .as_str()
            .ok_or("missing token")?
            .into())
    }

    fn last_frame(&self) -> &str {
        self.output
            .rsplit("\x1b[H\x1b[2J")
            .next()
            .unwrap_or_default()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = kill(Pid::from_raw(self.child.id() as i32), Signal::SIGTERM);
            thread::sleep(Duration::from_millis(300));
            if matches!(self.child.try_wait(), Ok(None)) {
                let _ = self.child.kill();
            }
        }
        let _ = self.child.wait();
    }
}

#[test]
fn fixed_header_survives_real_calls_tunnel_changes_and_resize() -> Result {
    let mut fixture = Fixture::start(false, false, "xterm-256color")?;
    assert!(fixture.output.contains("\x1b[?1049h"));
    assert!(
        fixture
            .last_frame()
            .contains(&format!("\x1b[3;1HOAuth key: {PASSWORD}"))
    );
    let modes = rustix::termios::tcgetattr(&fixture.slave)?;
    assert!(
        !modes
            .local_modes
            .contains(rustix::termios::LocalModes::ECHO)
    );
    assert!(
        modes
            .local_modes
            .contains(rustix::termios::LocalModes::ISIG)
    );
    let token = fixture.login()?;
    for index in 0..30 {
        let (status, _) = fixture.post("/mcp", &json!({"jsonrpc":"2.0","id":index,"method":"tools/call","params":{"name":"server_info","arguments":{}}}), Some(&token))?;
        assert_eq!(status, 200);
        fixture.drain()?;
    }
    fixture.wait_for("tool: server_info")?;
    assert!(
        fixture
            .last_frame()
            .contains(&format!("\x1b[3;1HOAuth key: {PASSWORD}"))
    );
    assert!(fixture.last_frame().contains("tool: server_info"));
    assert!(!fixture.output.contains("[tool:done]"));
    assert!(!fixture.output.contains(&token));
    fs::write(fixture.directory.path().join("home/change"), b"")?;
    fixture.wait_for("fixture-two.trycloudflare.com/mcp")?;
    assert!(
        fixture
            .last_frame()
            .contains("\x1b[2;1HPublic MCP: https://fixture-two")
    );
    fixture.output.clear();
    fixture.resize(40, 24)?;
    fixture.wait_for("OAuth key:")?;
    assert!(fixture.last_frame().contains(PASSWORD));
    fixture.output.clear();
    fixture.resize(20, 6)?;
    fixture.wait_for("Terminal too small")?;
    fixture.output.clear();
    fixture.resize(120, 24)?;
    fixture.wait_for(PASSWORD)?;
    fs::write(fixture.directory.path().join("home/disconnect"), b"")?;
    fixture.wait_for("Public MCP: disconnected")?;
    assert!(fixture.last_frame().contains(PASSWORD));
    fixture.stop(Signal::SIGINT)?;
    assert!(fixture.output.contains("\x1b[?25h\x1b[?1049l"));
    let debug = fixture.directory.path().join("data/debug");
    for entry in fs::read_dir(debug)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let content = fs::read(entry.path())?;
            assert!(
                !content
                    .windows(PASSWORD.len())
                    .any(|part| part == PASSWORD.as_bytes())
            );
            assert!(
                !content
                    .windows(token.len())
                    .any(|part| part == token.as_bytes())
            );
        }
    }
    Ok(())
}

#[test]
fn verbose_terminal_restores_on_sigterm_and_keeps_redaction() -> Result {
    let mut fixture = Fixture::start(true, false, "xterm")?;
    assert!(fixture.output.contains("| verbose"));
    let token = fixture.login()?;
    fixture.post("/mcp", &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"missing-fixture"}}}), Some(&token))?;
    fixture.wait_for("[tool:error] read_file")?;
    assert!(fixture.output.contains("args=[path]"));
    assert!(!fixture.output.contains("missing-fixture"));
    assert!(!fixture.output.contains(&token));
    fixture.stop(Signal::SIGTERM)?;
    assert!(fixture.output.contains("\x1b[?1049l"));
    Ok(())
}

#[test]
fn generated_password_is_in_the_header_and_dumb_terminal_stays_plain() -> Result {
    let mut fixture = Fixture::start(false, true, "xterm")?;
    let key = fixture
        .last_frame()
        .split("OAuth key: ")
        .nth(1)
        .ok_or("missing generated key")?
        .chars()
        .take_while(|ch| ch.is_ascii_hexdigit())
        .collect::<String>();
    assert_eq!(key.len(), 64);
    fixture.stop(Signal::SIGINT)?;
    let mut plain = Fixture::start(false, false, "dumb")?;
    assert!(!plain.output.contains('\x1b'));
    assert!(!plain.output.contains(PASSWORD));
    assert!(plain.output.contains("MCP: http://"));
    plain.stop(Signal::SIGINT)?;
    Ok(())
}

#[test]
fn redirected_tui_stays_plain_and_does_not_reveal_configured_password() -> Result {
    let directory = tempfile::tempdir()?;
    fs::create_dir(directory.path().join("workspace"))?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let stderr = File::create(directory.path().join("stderr"))?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_mtm"))
        .env_clear()
        .env("HOME", directory.path())
        .env("PATH", "/usr/bin:/bin")
        .env("TERM", "xterm")
        .env("MTM_DATA_ROOT", directory.path().join("data"))
        .env("MTM_NATIVE_EXEC_BACKEND", "disabled")
        .env("MTM_OAUTH_PASSWORD", PASSWORD)
        .current_dir(directory.path().join("workspace"))
        .args(["tui", "--verbose", "--port", &port.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()?;
    let result = (|| -> Result {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let output = fs::read_to_string(directory.path().join("stderr"))?;
            if output.contains("TUI: verbose operator diagnostics active") {
                assert!(output.contains("OAuth operator key: configured externally"));
                assert!(!output.contains(PASSWORD));
                assert!(!output.contains('\x1b'));
                // Let the server install its shutdown handler after startup output.
                thread::sleep(Duration::from_millis(100));
                kill(Pid::from_raw(child.id().try_into()?), Signal::SIGINT)?;
                break;
            }
            if child.try_wait()?.is_some() || Instant::now() > deadline {
                return Err("redirected TUI startup failed".into());
            }
            thread::sleep(Duration::from_millis(20));
        }
        while child.try_wait()?.is_none() {
            if Instant::now() > deadline {
                return Err("redirected TUI shutdown timed out".into());
            }
            thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    })();
    if matches!(child.try_wait(), Ok(None)) {
        let _ = child.kill();
    }
    let _ = child.wait();
    result
}
