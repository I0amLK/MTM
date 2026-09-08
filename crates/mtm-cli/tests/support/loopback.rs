//! Deliberately limited HTTP/1.1 client for an owned disposable loopback process.
//! Rejects redirects, chunked/ambiguous framing, oversized bodies and slow reads.
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::{Url, form_urlencoded};

use super::{Result, require, text};

const MAX_RESPONSE: usize = 2 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Reply {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn json(&self) -> Result<Value> {
        serde_json::from_slice(&self.body).map_err(|_| "invalid response JSON")
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        let boundary = bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or("missing HTTP header boundary")?;
        require(boundary <= 16_384, "HTTP headers exceed bound")?;
        let mut lines = std::str::from_utf8(&bytes[..boundary])
            .map_err(|_| "non-UTF8 HTTP headers")?
            .split("\r\n");
        let mut status = lines
            .next()
            .ok_or("missing HTTP status")?
            .split_whitespace();
        require(status.next() == Some("HTTP/1.1"), "unexpected HTTP version")?;
        let status = status
            .next()
            .ok_or("missing HTTP status code")?
            .parse()
            .map_err(|_| "invalid HTTP status code")?;
        let mut headers = BTreeMap::new();
        for line in lines {
            let (name, value) = line.split_once(':').ok_or("invalid HTTP header")?;
            require(
                headers
                    .insert(name.to_ascii_lowercase(), value.trim().to_owned())
                    .is_none(),
                "duplicate HTTP response header",
            )?;
        }
        require(
            !headers.contains_key("transfer-encoding"),
            "unsupported HTTP transfer framing",
        )?;
        let body = &bytes[boundary + 4..];
        let length: usize = headers
            .get("content-length")
            .ok_or("missing response length")?
            .parse()
            .map_err(|_| "invalid response length")?;
        require(
            length == body.len() && length <= MAX_RESPONSE,
            "truncated or oversized HTTP body",
        )?;
        Ok(Self {
            status,
            headers,
            body: body.to_vec(),
        })
    }
}

// These are opaque client credentials, not authenticated server principal types.
pub struct Client {
    endpoint: SocketAddr,
    token: String,
}

pub struct Server {
    child: Option<Child>,
    logs_closed: Option<Receiver<()>>,
    pub endpoint: SocketAddr,
    password: String,
    binary: String,
    directory: tempfile::TempDir,
    deadline: Instant,
}

impl Server {
    pub fn start(binary: &str) -> Result<Self> {
        let directory = tempfile::tempdir().map_err(|_| "temporary server directory failed")?;
        fs::create_dir(directory.path().join("workspace")).map_err(|_| "workspace setup failed")?;
        // The existing research adapter resolves curl during startup even when unused.
        // Expose the actual installed curl, not a stub or the host's Python/toolchain PATH.
        let curl = std::env::var_os("PATH")
            .and_then(|paths| {
                std::env::split_paths(&paths)
                    .map(|path| path.join("curl"))
                    .find(|path| path.is_file())
            })
            .ok_or("existing runtime prerequisite curl is unavailable")?
            .canonicalize()
            .map_err(|_| "curl prerequisite cannot be resolved")?;
        let tools = directory.path().join("tool-bin");
        fs::create_dir(&tools).map_err(|_| "minimal test PATH setup failed")?;
        std::os::unix::fs::symlink(curl, tools.join("curl"))
            .map_err(|_| "curl-only test PATH setup failed")?;
        let mut random = [0_u8; 32];
        getrandom::fill(&mut random).map_err(|_| "test randomness unavailable")?;
        let mut server = Self {
            child: None,
            logs_closed: None,
            endpoint: ([127, 0, 0, 1], 0).into(),
            password: URL_SAFE_NO_PAD.encode(random),
            binary: binary.to_owned(),
            directory,
            deadline: Instant::now() + Duration::from_secs(240),
        };
        server.spawn()?;
        Ok(server)
    }

    fn spawn(&mut self) -> Result {
        let root = self.directory.path();
        let child = Command::new(&self.binary)
            .env_clear()
            .env("PATH", root.join("tool-bin"))
            .env("HOME", root)
            .env("TMPDIR", root)
            .env("MTM_WORKSPACE", root.join("workspace"))
            .env("MTM_DATA_ROOT", root.join("data"))
            .env("MTM_PRIVATE_ROOT", root.join("data/private"))
            .env("MTM_DEBUG_ROOT", root.join("data/debug"))
            .env("MTM_NATIVE_EXEC_BACKEND", "disabled")
            .env("MTM_WORKFLOW_PROTOCOL_VERSION", "3")
            .env("MTM_OAUTH_PASSWORD", &self.password)
            .args([
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                &self.endpoint.port().to_string(),
                "--native-mode",
                "safe",
                "--latex-policy",
                "static_only",
                "--workspace",
            ])
            .arg(root.join("workspace"))
            .current_dir(root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "test server failed to spawn")?;
        self.child = Some(child);
        let mut stderr = self
            .child
            .as_mut()
            .and_then(|child| child.stderr.take())
            .ok_or("test server stderr missing")?;
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (closed_tx, closed_rx) = mpsc::sync_channel(1);
        self.logs_closed = Some(closed_rx);
        thread::Builder::new()
            .name("mtm-test-log-drain".into())
            .spawn(move || {
                let mut chunk = [0_u8; 1024];
                let mut line = Vec::new();
                let mut announced = false;
                while let Ok(count) = stderr.read(&mut chunk) {
                    if count == 0 {
                        break;
                    }
                    for byte in &chunk[..count] {
                        if *byte == b'\n' {
                            if !announced
                                && let Ok(line) = std::str::from_utf8(&line)
                                && let Some(address) = line
                                    .strip_prefix("local MCP: http://")
                                    .and_then(|s| s.strip_suffix("/mcp"))
                                && let Ok(address) = address.parse::<SocketAddr>()
                            {
                                let _ = ready_tx.try_send(address);
                                announced = true;
                            }
                            line.clear();
                        } else if line.len() < 8192 {
                            line.push(*byte);
                        }
                    }
                }
                let _ = closed_tx.try_send(());
            })
            .map_err(|_| "test log drain failed")?;
        let endpoint = ready_rx
            .recv_timeout(Duration::from_secs(15))
            .map_err(|_| "test server startup failed or timed out; raw logs withheld")?;
        require(
            endpoint.ip() == std::net::Ipv4Addr::LOCALHOST && endpoint.port() != 0,
            "test server announced a non-loopback endpoint",
        )?;
        require(
            self.endpoint.port() == 0 || self.endpoint == endpoint,
            "restart endpoint drift",
        )?;
        self.endpoint = endpoint;
        let health = self.request("GET", "/health", "application/json", b"", None)?;
        require(
            health.status == 200 && health.json()?["ok"] == true,
            "server not healthy",
        )
    }

    pub fn request(
        &self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
        client: Option<&Client>,
    ) -> Result<Reply> {
        require(
            self.deadline > Instant::now(),
            "capability gate exceeded total deadline",
        )?;
        require(
            path.starts_with('/') && !path.contains(['\r', '\n']) && body.len() <= MAX_RESPONSE,
            "invalid bounded loopback request",
        )?;
        let timeout = IO_TIMEOUT.min(self.deadline.saturating_duration_since(Instant::now()));
        let mut stream = TcpStream::connect_timeout(&self.endpoint, timeout)
            .map_err(|_| "loopback connection failed; operation outcome unknown")?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|_| "socket timeout setup failed")?;
        let auth = if let Some(client) = client {
            require(
                client.endpoint == self.endpoint && !client.token.contains(['\r', '\n']),
                "client belongs to another endpoint",
            )?;
            format!("Authorization: Bearer {}\r\n", client.token)
        } else {
            String::new()
        };
        let headers = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{auth}\r\n",
            self.endpoint,
            body.len()
        );
        stream
            .write_all(headers.as_bytes())
            .and_then(|()| stream.write_all(body))
            .map_err(|_| "loopback send failed; operation outcome unknown")?;
        let deadline = Instant::now() + timeout;
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            require(
                !remaining.is_zero(),
                "HTTP deadline exceeded; operation outcome unknown",
            )?;
            stream
                .set_read_timeout(Some(remaining))
                .map_err(|_| "socket read timeout setup failed")?;
            let count = stream
                .read(&mut chunk)
                .map_err(|_| "loopback receive failed; operation outcome unknown")?;
            if count == 0 {
                break;
            }
            require(
                bytes.len() + count <= MAX_RESPONSE + 16_388,
                "HTTP response exceeded bound",
            )?;
            bytes.extend_from_slice(&chunk[..count]);
        }
        Reply::parse(&bytes)
    }

    fn post(&self, path: &str, payload: &Value, client: Option<&Client>) -> Result<Reply> {
        let bytes = serde_json::to_vec(payload).map_err(|_| "request serialization failed")?;
        self.request("POST", path, "application/json", &bytes, client)
    }

    fn form(&self, path: &str, fields: &[(&str, &str)]) -> Result<Reply> {
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().copied())
            .finish();
        self.request(
            "POST",
            path,
            "application/x-www-form-urlencoded",
            body.as_bytes(),
            None,
        )
    }

    pub fn login(&self) -> Result<Client> {
        let redirect = "http://127.0.0.1/test-callback";
        let registration = self.post("/oauth/register", &json!({
            "redirect_uris":[redirect],"token_endpoint_auth_method":"none","client_name":"Rust disposable gate"
        }), None)?;
        require(registration.status == 201, "test DCR failed")?;
        let registration = registration.json()?;
        let id = text(&registration, "client_id")?;
        let verifier = "v".repeat(64);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let resource = format!("http://{}/mcp", self.endpoint);
        let authorization = self.form(
            "/oauth/authorize",
            &[
                ("client_id", id),
                ("redirect_uri", redirect),
                ("response_type", "code"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("resource", &resource),
                ("state", "rust-gate"),
                ("password", &self.password),
            ],
        )?;
        require(
            authorization.status == 302,
            "test operator authorization failed",
        )?;
        let location = Url::parse(
            authorization
                .headers
                .get("location")
                .ok_or("missing callback")?,
        )
        .map_err(|_| "invalid authorization callback")?;
        let values: BTreeMap<String, String> = location.query_pairs().into_owned().collect();
        require(
            values.get("state").map(String::as_str) == Some("rust-gate"),
            "OAuth state mismatch",
        )?;
        let code = values.get("code").ok_or("missing authorization code")?;
        let token = self.form(
            "/oauth/token",
            &[
                ("client_id", id),
                ("redirect_uri", redirect),
                ("grant_type", "authorization_code"),
                ("code", code),
                ("code_verifier", &verifier),
                ("resource", &resource),
            ],
        )?;
        require(token.status == 200, "test PKCE exchange failed")?;
        let token = token.json()?;
        require(token["token_type"] == "Bearer", "unexpected token type")?;
        Ok(Client {
            endpoint: self.endpoint,
            token: text(&token, "access_token")?.to_owned(),
        })
    }

    pub fn call(&self, client: &Client, name: &str, arguments: Value) -> Result<Value> {
        let reply = self.post(
            "/mcp",
            &json!({"jsonrpc":"2.0","id":"gate",
            "method":"tools/call","params":{"name":name,"arguments":arguments}}),
            Some(client),
        )?;
        require(reply.status == 200, "MCP HTTP failure; no automatic replay")?;
        let reply = reply.json()?;
        require(reply.get("error").is_none(), "MCP protocol failure")?;
        let result = reply.get("result").ok_or("missing MCP result")?;
        let data = result
            .get("structuredContent")
            .filter(|v| v.is_object())
            .ok_or("missing structured tool outcome")?;
        require(
            result["isError"].is_boolean(),
            "missing explicit tool outcome",
        )?;
        require(
            result["isError"] != true || data["ok"] == false,
            "inconsistent tool error flags",
        )?;
        Ok(data.clone())
    }

    pub fn restart(&mut self) -> Result {
        self.stop()?;
        self.spawn()
    }

    pub fn stop(&mut self) -> Result {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        if child
            .try_wait()
            .map_err(|_| "cannot inspect owned server")?
            .is_none()
        {
            let pid = i32::try_from(child.id()).map_err(|_| "owned PID out of range")?;
            kill(Pid::from_raw(pid), Signal::SIGINT)
                .map_err(|_| "owned server interrupt failed")?;
        }
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if let Some(status) = child.try_wait().map_err(|_| "server wait failed")? {
                self.child = None;
                require(status.success(), "server did not shut down cleanly")?;
                if let Some(closed) = self.logs_closed.take() {
                    closed
                        .recv_timeout(Duration::from_secs(2))
                        .map_err(|_| "server log drain did not close")?;
                }
                return Ok(());
            }
            require(
                Instant::now() < deadline,
                "server graceful shutdown timed out",
            )?;
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline && matches!(child.try_wait(), Ok(None)) {
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(|_| "cannot read binary identity")?;
    let mut digest = Sha256::new();
    let mut bytes = [0_u8; 65_536];
    loop {
        let count = file
            .read(&mut bytes)
            .map_err(|_| "binary identity read failed")?;
        if count == 0 {
            break;
        }
        digest.update(&bytes[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ambiguous_truncated_or_non_http_responses_fail_closed() {
        for response in [
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "not an HTTP response",
        ] {
            assert!(Reply::parse(response.as_bytes()).is_err());
        }
        assert!(Reply::parse(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").is_ok());
    }
}
