use super::super::ExecInvocation;
use super::*;
use serde_json::{Map, Value};

fn candidates(command: &str) -> Result<Vec<String>, ReCtmError> {
    let arguments = Map::from_iter([("cmd".to_owned(), Value::String(command.to_owned()))]);
    ExecInvocation::parse(&arguments)?.executable_candidates()
}

#[test]
fn query_flags_do_not_become_executables_or_hide_following_commands() -> Result<(), ReCtmError> {
    for query in [
        "command -v missing",
        "command -V missing",
        "command -pv missing",
        "command -v -- missing",
        "command -v \"$name\"",
    ] {
        assert_eq!(
            candidates(&format!("{query}; /opt/actual"))?,
            vec!["/opt/actual"]
        );
    }
    assert_eq!(candidates("command -- /opt/actual")?, vec!["/opt/actual"]);
    assert!(candidates("command -p /opt/actual").is_err());
    assert!(candidates("command --invalid missing").is_err());
    Ok(())
}

#[test]
fn loop_lists_and_nested_loops_keep_only_real_command_positions() -> Result<(), ReCtmError> {
    assert_eq!(
        candidates("for c in missing other; do command -v \"$c\"; done; /opt/after")?,
        vec!["/opt/after"]
    );
    assert_eq!(
        candidates("for c in missing\ndo /opt/body \"$c\"\ndone\n/opt/after")?,
        vec!["/opt/body", "/opt/after"]
    );
    assert_eq!(
        candidates("for c in a; do for d in b; do /opt/body; done; done; /opt/after")?,
        vec!["/opt/body", "/opt/after"]
    );
    assert_eq!(candidates("for c; do /opt/body; done")?, vec!["/opt/body"]);
    assert_eq!(
        candidates("for c in /opt/name; do \"$c\"; done")?,
        vec!["$c"]
    );
    Ok(())
}

#[test]
fn malformed_and_excessively_nested_loops_fail_closed() {
    for command in [
        "for c in a; /opt/body; done",
        "for c in a; do /opt/body",
        "do /opt/body; done",
        "for 1bad in a; do /opt/body; done",
        "for c bad a; do /opt/body; done",
        "done /opt/body",
    ] {
        assert!(candidates(command).is_err(), "{command}");
    }
    let nested = format!(
        "{} /opt/body; {}",
        "for c in a; do ".repeat(33),
        "done; ".repeat(33)
    );
    assert!(candidates(&nested).is_err());
}

#[test]
fn quotes_heredocs_and_substitution_do_not_become_safe_query_payloads() -> Result<(), ReCtmError> {
    assert_eq!(
        candidates("printf '%s' 'literal ; | $name'; /opt/actual")?,
        vec!["printf", "/opt/actual"]
    );
    assert_eq!(
        candidates("cat <<'EOF'\n/opt/not-executed; $name\nEOF")?,
        vec!["cat"]
    );
    for command in [
        "command -v \"$(/opt/actual)\"",
        "command -v `/opt/actual`",
        "for c in a; do while true; do /opt/actual; done; done",
    ] {
        assert!(simple_candidates(command, 0)?.is_none(), "{command}");
    }
    assert_eq!(
        candidates("sh -c 'command -v missing; /opt/nested'")?,
        vec!["sh", "/opt/nested"]
    );
    Ok(())
}

#[test]
fn external_wrappers_and_direct_argv_retain_file_inspection() -> Result<(), ReCtmError> {
    assert_eq!(candidates("/opt/command -v missing")?, vec!["/opt/command"]);
    assert_eq!(
        candidates("/usr/bin/env FOO=1 /opt/actual")?,
        vec!["/opt/actual"]
    );
    assert_eq!(
        candidates("/usr/bin/nohup /opt/actual")?,
        vec!["/opt/actual"]
    );
    let arguments = Map::from_iter([(
        "argv".to_owned(),
        serde_json::json!(["command", "-v", "missing"]),
    )]);
    assert_eq!(
        ExecInvocation::parse(&arguments)?.executable_candidates()?,
        vec!["command"]
    );
    Ok(())
}
