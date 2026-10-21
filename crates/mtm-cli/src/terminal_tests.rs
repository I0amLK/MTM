use super::*;

fn screen(columns: usize, rows: usize) -> Screen {
    Screen::new(
        Header {
            identity: "MTM test | P3 | dangerous".into(),
            local_mcp: "http://127.0.0.1:8000/mcp".into(),
            oauth_key: "terminal-only-fixture-key".into(),
            quick_tunnel: true,
        },
        Size { columns, rows },
    )
}

#[test]
fn credentials_remain_in_header_after_log_overflow() {
    let mut screen = screen(100, 24);
    for index in 0..MAX_LOG_LINES + 10 {
        screen.push(&format!("tool: fixture_{index}"));
    }
    let frame = screen.frame();
    assert!(frame.contains("\x1b[3;1HOAuth key: terminal-only-fixture-key"));
    assert!(frame.contains("\x1b[4;1HLocal MCP:"));
    assert!(!frame.contains("tool: fixture_0"));
    assert!(frame.contains("tool: fixture_265"));
    assert_eq!(screen.logs.len(), MAX_LOG_LINES);
    assert!(!screen.logs.iter().any(|line| line.contains("fixture-key")));
}

#[test]
fn tunnel_changes_replace_the_header_and_remove_dead_urls() {
    let mut screen = screen(100, 24);
    for (state, url, expected) in [
        (
            TunnelState::Connected,
            Some("https://first.trycloudflare.com/mcp"),
            "first",
        ),
        (
            TunnelState::Connected,
            Some("https://second.trycloudflare.com/mcp"),
            "second",
        ),
        (TunnelState::Disconnected, None, "disconnected"),
        (TunnelState::Unavailable, None, "unavailable"),
        (TunnelState::Closed, None, "closed"),
    ] {
        screen.tunnel(&TunnelEvent {
            state,
            message: "not rendered as terminal control".into(),
            public_mcp_url: url.map(str::to_owned),
            exit_code: None,
        });
        assert!(screen.frame().contains(expected));
        if url.is_none() {
            assert!(!screen.frame().contains("trycloudflare.com"));
        }
    }
}

#[test]
fn narrow_header_wraps_the_whole_key_and_resize_recovers() {
    let mut screen = screen(40, 24);
    screen.header.oauth_key = "k".repeat(64);
    let lines = wrap(&format!("OAuth key: {}", screen.header.oauth_key), 39);
    assert_eq!(lines.concat(), format!("OAuth key: {}", "k".repeat(64)));
    for part in &lines {
        assert!(screen.frame().contains(part));
    }
    screen.size = Size {
        columns: 20,
        rows: 6,
    };
    assert!(!screen.frame().contains("kkkk"));
    assert!(screen.frame().contains("Terminal too small"));
    screen.size = Size {
        columns: 120,
        rows: 30,
    };
    assert!(screen.frame().contains(&"k".repeat(64)));
}

#[test]
fn terminal_controls_are_escaped_and_unicode_width_is_respected() {
    assert_eq!(
        terminal_text("hello\x1b[2J\r\n", 100),
        "hello\\u{1b}[2J\\r\\n"
    );
    assert!(!terminal_text("a\u{202e}b", 100).contains('\u{202e}'));
    assert_eq!(
        wrap("ab\u{4e2d}\u{6587}c", 4),
        vec!["ab\u{4e2d}", "\u{6587}c"]
    );
    let mut screen = screen(100, 24);
    screen.push(&"x".repeat(MAX_LINE_CHARS + 100));
    assert_eq!(screen.logs[0].len(), MAX_LINE_CHARS);
}

#[test]
fn configured_key_and_local_only_mode_use_the_same_header() {
    let mut header = screen(100, 24).header;
    header.quick_tunnel = false;
    let screen = Screen::new(
        header,
        Size {
            columns: 100,
            rows: 24,
        },
    );
    assert!(screen.frame().contains("disabled (local only)"));
    assert!(
        screen
            .frame()
            .contains("OAuth key: terminal-only-fixture-key")
    );
}

#[test]
fn oversized_configured_key_is_not_shown_as_a_valid_partial_password() {
    let mut screen = screen(100, 24);
    screen.header.oauth_key = "s".repeat(MAX_KEY_CHARS + 1);
    let frame = screen.frame();
    assert!(frame.contains("password too long to display"));
    assert!(!frame.contains("ssss"));
}
