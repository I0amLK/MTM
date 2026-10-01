use super::*;
fn request(script: &str, yield_ms: u64, timeout: u64) -> CommandRequest {
    CommandRequest {
        argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
        env: BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
        timeout_ms: timeout,
        yield_time_ms: yield_ms,
        max_output_bytes: 4096,
        stdin: String::new(),
        tty: false,
        verbosity: Some("full".into()),
        preview_bytes: 4096,
    }
}
#[test]
fn terminal_outcomes_are_truthful_and_observed_once_across_tools() -> Result<(), ReCtmError> {
    let manager = CommandManager::new(CommandManagerConfig::default());
    for (script, timeout, expected) in [
        ("exit 0", 2000, "exited_0"),
        ("exit 7", 2000, "exited_nonzero"),
        ("sleep 2", 30, "timeout"),
        ("kill -TERM $$", 2000, "signal"),
    ] {
        let result = manager.start(request(script, 3000, timeout))?;
        assert_eq!(result["operation_outcome"], expected);
        assert_eq!(result["ok"], true);
        assert_eq!(result["_native_first_terminal"], true);
        let id = result["command_id"]
            .as_str()
            .ok_or_else(|| runtime_error("TEST", "id missing"))?;
        let read = manager.read_output(&format!("command:{id}:stdout"), None, 0, 4096)?;
        assert_eq!(read["operation_outcome"], expected);
        assert_eq!(read["_native_first_terminal"], false);
    }
    manager.close()?;
    Ok(())
}
#[test]
fn read_output_can_be_first_terminal_observer_without_consuming_poll_bytes()
-> Result<(), ReCtmError> {
    let manager = CommandManager::new(CommandManagerConfig::default());
    let started = manager.start(request("sleep 0.03; printf result; exit 7", 0, 2000))?;
    assert_eq!(started["operation_outcome"], "running");
    let id = started["command_id"]
        .as_str()
        .ok_or_else(|| runtime_error("TEST", "id missing"))?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let read = manager.read_output(&format!("command:{id}:stdout"), None, 0, 4096)?;
        if read["operation_outcome"] != "running" {
            assert_eq!(read["_native_first_terminal"], true);
            break;
        }
        if Instant::now() > deadline {
            return Err(runtime_error("TEST", "command deadline"));
        }
        thread::sleep(Duration::from_millis(10));
    }
    let polled = manager.poll(PollRequest {
        command_id: id.into(),
        chars: String::new(),
        yield_time_ms: 1000,
        max_output_bytes: 4096,
        verbosity: Some("full".into()),
        preview_bytes: 4096,
    })?;
    assert_eq!(polled["operation_outcome"], "exited_nonzero");
    assert_eq!(polled["_native_first_terminal"], false);
    assert!(
        polled["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("result")
    );
    manager.close()?;
    Ok(())
}
