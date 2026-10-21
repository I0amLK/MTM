use std::collections::VecDeque;
use std::env;
use std::io::{self, IsTerminal, Write};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mtm_runtime::{OperatorSession, TunnelEvent, TunnelState};
use unicode_width::UnicodeWidthChar;

const ENTER: &str = "\x1b[?1049h\x1b[?25l";
const LEAVE: &str = "\x1b[r\x1b[0m\x1b[?25h\x1b[?1049l";
const MAX_LOG_LINES: usize = 256;
const MAX_LINE_CHARS: usize = 2048;
const MAX_KEY_CHARS: usize = 4096;

// Credentials belong only to the live terminal header, never the event/log queue.
pub(crate) struct Header {
    pub(crate) identity: String,
    pub(crate) local_mcp: String,
    pub(crate) oauth_key: String,
    pub(crate) quick_tunnel: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Size {
    columns: usize,
    rows: usize,
}

struct Screen {
    header: Header,
    public_mcp: String,
    logs: VecDeque<String>,
    size: Size,
    active: bool,
}

impl Screen {
    fn new(header: Header, size: Size) -> Self {
        let public_mcp = if header.quick_tunnel {
            "starting temporary tunnel..."
        } else {
            "disabled (local only)"
        }
        .to_owned();
        Self {
            header,
            public_mcp,
            logs: VecDeque::new(),
            size,
            active: false,
        }
    }

    fn push(&mut self, line: &str) {
        if self.logs.len() == MAX_LOG_LINES {
            self.logs.pop_front();
        }
        self.logs.push_back(terminal_text(line, MAX_LINE_CHARS));
    }

    fn tunnel(&mut self, event: &TunnelEvent) {
        self.public_mcp = match event.state {
            TunnelState::Connected => event
                .public_mcp_url
                .as_deref()
                .unwrap_or("connected; awaiting public address")
                .to_owned(),
            TunnelState::Starting => "starting temporary tunnel...".to_owned(),
            TunnelState::Unavailable => "unavailable (local MCP still available)".to_owned(),
            TunnelState::Disconnected => "disconnected (local MCP still available)".to_owned(),
            TunnelState::Closed => "closed".to_owned(),
        };
    }

    fn frame(&self) -> String {
        let width = self.size.columns.saturating_sub(1).max(1);
        let mut header = Vec::new();
        let key = if self.header.oauth_key.chars().count() > MAX_KEY_CHARS {
            "password too long to display; check MTM_OAUTH_PASSWORD"
        } else {
            &self.header.oauth_key
        };
        for line in [
            self.header.identity.clone(),
            format!("Public MCP: {}", self.public_mcp),
            format!("OAuth key: {key}"),
            format!("Local MCP: {}", self.header.local_mcp),
        ] {
            header.extend(wrap(&terminal_text(&line, 8192), width));
        }
        header.push("-".repeat(width));
        let mut frame = String::from("\x1b[H\x1b[2J");
        if header.len() + 2 > self.size.rows {
            for (row, line) in wrap(
                "Terminal too small; enlarge to view MCP and OAuth key.",
                width,
            )
            .iter()
            .take(self.size.rows.saturating_sub(1))
            .enumerate()
            {
                frame.push_str(&format!("\x1b[{};1H{line}", row + 1));
            }
            return frame;
        }
        for (row, line) in header.iter().enumerate() {
            frame.push_str(&format!("\x1b[{};1H{line}", row + 1));
        }
        let available = self.size.rows - header.len() - 1;
        let mut visible = VecDeque::new();
        for line in self.logs.iter().rev() {
            for part in wrap(line, width).into_iter().rev() {
                visible.push_front(part);
                if visible.len() == available {
                    break;
                }
            }
            if visible.len() == available {
                break;
            }
        }
        for (offset, line) in visible.iter().enumerate() {
            frame.push_str(&format!("\x1b[{};1H{line}", header.len() + offset + 1));
        }
        frame.push_str(&format!(
            "\x1b[{};1H{}",
            self.size.rows,
            wrap("Logs | Ctrl+C to stop", width)
                .first()
                .map(String::as_str)
                .unwrap_or_default()
        ));
        frame
    }

    fn draw(&mut self) {
        if self.active && write_terminal(&self.frame()).is_err() {
            self.active = false;
            let _ = write_terminal(LEAVE);
        }
    }
}

pub(crate) struct TerminalSession {
    screen: Arc<Mutex<Screen>>,
    stop: Option<mpsc::Sender<()>>,
    resize: Option<JoinHandle<()>>,
    terminal_modes: Option<rustix::termios::Termios>,
}

impl TerminalSession {
    pub(crate) fn new(header: Header) -> Option<Self> {
        if !io::stderr().is_terminal()
            || env::var("TERM").map_or(true, |term| term.is_empty() || term == "dumb")
        {
            return None;
        }
        Some(Self {
            screen: Arc::new(Mutex::new(Screen::new(header, terminal_size()?))),
            stop: None,
            resize: None,
            terminal_modes: None,
        })
    }

    pub(crate) fn operator(&self, operator: OperatorSession) -> OperatorSession {
        let lines = Arc::clone(&self.screen);
        let tunnels = Arc::clone(&self.screen);
        operator.with_output(
            Arc::new(move |line| {
                if let Ok(mut screen) = lines.lock() {
                    screen.push(line);
                    screen.draw();
                }
            }),
            Arc::new(move |event| {
                if let Ok(mut screen) = tunnels.lock() {
                    screen.tunnel(event);
                    screen.draw();
                }
            }),
        )
    }

    pub(crate) fn start(&mut self) -> io::Result<()> {
        let original = rustix::termios::tcgetattr(io::stderr())?;
        let mut modes = original.clone();
        modes
            .local_modes
            .remove(rustix::termios::LocalModes::ECHO | rustix::termios::LocalModes::ECHONL);
        // Keep canonical input and ISIG so Ctrl+C retains its normal behavior.
        rustix::termios::tcsetattr(io::stderr(), rustix::termios::OptionalActions::Now, &modes)?;
        self.terminal_modes = Some(original);
        if let Err(error) = write_terminal(ENTER) {
            let _ = write_terminal(LEAVE);
            return Err(error);
        }
        if let Ok(mut screen) = self.screen.lock() {
            screen.active = true;
            screen.draw();
        }
        let screen = Arc::clone(&self.screen);
        let (sender, receiver) = mpsc::channel();
        self.resize = Some(thread::Builder::new().name("mtm-tui-resize".into()).spawn(
            move || {
                while matches!(
                    receiver.recv_timeout(Duration::from_millis(150)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    if let Some(size) = terminal_size()
                        && let Ok(mut screen) = screen.lock()
                        && size != screen.size
                    {
                        screen.size = size;
                        screen.draw();
                    }
                }
            },
        )?);
        self.stop = Some(sender);
        Ok(())
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(resize) = self.resize.take() {
            let _ = resize.join();
        }
        if let Ok(mut screen) = self.screen.lock()
            && screen.active
        {
            screen.active = false;
            let _ = write_terminal(LEAVE);
        }
        if let Some(modes) = &self.terminal_modes {
            let _ = rustix::termios::tcsetattr(
                io::stderr(),
                rustix::termios::OptionalActions::Now,
                modes,
            );
        }
    }
}

fn terminal_size() -> Option<Size> {
    let size = rustix::termios::tcgetwinsize(io::stderr()).ok()?;
    (size.ws_col > 0 && size.ws_row > 0).then_some(Size {
        columns: usize::from(size.ws_col).min(1000),
        rows: usize::from(size.ws_row).min(500),
    })
}

fn write_terminal(text: &str) -> io::Result<()> {
    let mut stderr = io::stderr().lock();
    stderr.write_all(text.as_bytes())?;
    stderr.flush()
}

fn terminal_text(value: &str, limit: usize) -> String {
    let mut text = String::new();
    for character in value.chars().take(limit) {
        if character.is_control()
            || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            text.extend(character.escape_default());
        } else {
            text.push(character);
        }
    }
    text
}

fn wrap(value: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut cells = 0;
    for character in value.chars() {
        let size = character.width().unwrap_or(0);
        if cells + size > width && !line.is_empty() {
            lines.push(std::mem::take(&mut line));
            cells = 0;
        }
        line.push(character);
        cells += size;
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

#[cfg(test)]
#[path = "terminal_tests.rs"]
mod tests;
