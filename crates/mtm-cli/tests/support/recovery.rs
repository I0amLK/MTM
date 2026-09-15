//! Bounded test-client policy, not an SDK or server permission-grant mechanism.
//! Each caller supplies one endpoint/identity closure and one task-domain cursor.
use serde_json::Value;

use super::{Result, require, text};

pub fn error_code(response: &Value) -> &str {
    response
        .pointer("/submission/error/code")
        .or_else(|| response.pointer("/error/code"))
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn check_task(task: &Value) -> Result {
    for key in ["run_id", "state", "role", "domain_id", "capability"] {
        text(task, key)?;
    }
    let contract = task
        .get("task")
        .filter(|v| v.is_object())
        .ok_or("missing task contract")?;
    text(contract, "commit_action")?;
    require(
        (contract["write_contract"].is_object() || contract["write_contract"].is_array())
            && contract["commit_payload_schema"].is_object(),
        "incomplete task contract",
    )
}

pub fn adopt_refresh<'a>(current: &Value, response: &'a Value) -> Result<&'a Value> {
    check_task(current)?;
    check_task(response)?;
    let sub = &response["submission"];
    require(
        error_code(response) == "CAPABILITY_INVALID"
            && sub["capability_refreshed"] == true
            && sub["recoverable"] == true
            && sub["retryable"] == true
            && sub["writes_retained"] == false
            && response["writes_applied"].as_u64() == Some(0),
        "response does not permit a zero-write capability retry",
    )?;
    require(
        current["capability"] != response["capability"],
        "refresh supplied no new capability",
    )?;
    for key in ["run_id", "state", "role", "domain_id", "epoch"] {
        require(
            current.get(key) == response.get(key),
            "refresh changed task authority context",
        )?;
    }
    for key in ["commit_action", "write_contract", "commit_payload_schema"] {
        require(
            current["task"].get(key) == response["task"].get(key),
            "refresh changed task contract",
        )?;
    }
    Ok(response)
}

fn check_arguments(task: &Value, arguments: &Value) -> Result {
    check_task(task)?;
    require(
        arguments["run_id"] == task["run_id"]
            && arguments["capability"] == task["capability"]
            && arguments["action"] == task["task"]["commit_action"],
        "submission must use the exact current task envelope",
    )
}

pub fn submit_with_one_refresh(
    current: &Value,
    mut prepare: impl FnMut(&Value) -> Result<Value>,
    mut call: impl FnMut(Value) -> Result<Value>,
) -> Result<Value> {
    let arguments = prepare(current)?;
    check_arguments(current, &arguments)?;
    let response = call(arguments)?;
    if response.pointer("/submission/capability_refreshed") != Some(&Value::Bool(true)) {
        return Ok(response);
    }
    let refreshed = adopt_refresh(current, &response)?;
    let arguments = prepare(refreshed)?;
    check_arguments(refreshed, &arguments)?;
    let response = call(arguments)?;
    require(
        error_code(&response) != "CAPABILITY_INVALID"
            && response.pointer("/submission/capability_refreshed") != Some(&Value::Bool(true)),
        "second capability rejection; stop and inspect current task",
    )?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn task(run: &str, token: &str) -> Value {
        json!({"run_id":run,"state":"assess","role":"generator","domain_id":"domain-A",
            "capability":token,"task":{"commit_action":"assess_done","write_contract":{},"commit_payload_schema":{}}})
    }

    fn refresh() -> Value {
        let mut value = task("A", "fresh-fixture");
        value["writes_applied"] = json!(0);
        value["submission"] = json!({"capability_refreshed":true,"recoverable":true,
            "retryable":true,"writes_retained":false,"error":{"code":"CAPABILITY_INVALID"}});
        value
    }

    fn prepare(task: &Value) -> Result<Value> {
        Ok(
            json!({"run_id":task["run_id"],"capability":task["capability"],"action":task["task"]["commit_action"]}),
        )
    }

    #[test]
    fn normal_submission_is_one_request() -> Result {
        let mut count = 0;
        submit_with_one_refresh(&task("A", "original"), prepare, |_| {
            count += 1;
            Ok(json!({"ok":true}))
        })?;
        assert_eq!(count, 1);
        Ok(())
    }

    #[test]
    fn refresh_is_adopted_once_without_mutating_other_cursors() -> Result {
        let current = task("A", "original");
        let other = task("B", "other");
        let saved = (current.clone(), other.clone());
        let mut calls = 0;
        let result = submit_with_one_refresh(&current, prepare, |args| {
            calls += 1;
            require(
                args["capability"]
                    == if calls == 1 {
                        "original"
                    } else {
                        "fresh-fixture"
                    },
                "wrong cursor used",
            )?;
            Ok(if calls == 1 {
                refresh()
            } else {
                json!({"state":"assemble"})
            })
        })?;
        assert_eq!(result["state"], "assemble");
        assert_eq!(calls, 2);
        assert!((current, other) == saved);
        Ok(())
    }

    #[test]
    fn second_rejection_stops_at_two_requests() {
        let mut calls = 0;
        assert!(
            submit_with_one_refresh(&task("A", "original"), prepare, |_| {
                calls += 1;
                Ok(refresh())
            })
            .is_err()
        );
        assert_eq!(calls, 2);
    }

    #[test]
    fn cross_run_and_state_changes_are_not_replayed() {
        for key in ["run_id", "state", "role", "domain_id", "epoch"] {
            let mut changed = refresh();
            changed[key] = json!("different");
            assert!(adopt_refresh(&task("A", "original"), &changed).is_err());
        }
    }

    #[test]
    fn changed_or_missing_contract_is_not_replayed() {
        for key in ["commit_action", "write_contract", "commit_payload_schema"] {
            let mut changed = refresh();
            changed["task"][key] = json!({"changed":true});
            assert!(adopt_refresh(&task("A", "original"), &changed).is_err());
        }
        let mut changed = refresh();
        changed["task"] = Value::Null;
        assert!(adopt_refresh(&task("A", "original"), &changed).is_err());
    }

    #[test]
    fn retained_unknown_boolean_or_fractional_write_counts_are_denied() {
        for writes in [json!(1), Value::Null, json!(false), json!(-1), json!(0.0)] {
            let mut changed = refresh();
            changed["writes_applied"] = writes;
            assert!(adopt_refresh(&task("A", "original"), &changed).is_err());
        }
        let mut changed = refresh();
        changed["submission"]["writes_retained"] = json!(true);
        assert!(adopt_refresh(&task("A", "original"), &changed).is_err());
    }

    #[test]
    fn revoked_stale_and_expired_do_not_allow_refresh() {
        for code in [
            "CAPABILITY_REVOKED",
            "CAPABILITY_STALE",
            "CAPABILITY_EXPIRED",
        ] {
            let mut changed = refresh();
            changed["submission"]["error"]["code"] = json!(code);
            assert!(adopt_refresh(&task("A", "original"), &changed).is_err());
        }
    }

    #[test]
    fn stale_preparer_is_stopped_before_sending() {
        let mut calls = 0;
        assert!(
            submit_with_one_refresh(
                &task("A", "original"),
                |_| prepare(&task("B", "other")),
                |_| {
                    calls += 1;
                    Ok(json!({}))
                }
            )
            .is_err()
        );
        assert_eq!(calls, 0);
    }

    #[test]
    fn empty_unchanged_or_missing_token_has_safe_errors() {
        for token in [Value::Null, json!(""), json!("private-token-fixture")] {
            let mut changed = refresh();
            changed["capability"] = token;
            let result = adopt_refresh(&task("A", "private-token-fixture"), &changed);
            assert!(result.is_err());
            assert!(!result.err().unwrap_or("").contains("private-token-fixture"));
        }
    }

    #[test]
    fn transport_uncertainty_never_causes_an_automatic_replay() {
        let mut calls = 0;
        let outcome = submit_with_one_refresh(&task("A", "original"), prepare, |_| {
            calls += 1;
            Err("transport failure; outcome unknown")
        });
        assert!(outcome.is_err());
        assert_eq!(calls, 1);
    }

    #[test]
    fn incomplete_refresh_flags_never_allow_a_second_request() {
        for key in [
            "capability_refreshed",
            "recoverable",
            "retryable",
            "writes_retained",
        ] {
            let mut changed = refresh();
            changed["submission"][key] = Value::Null;
            assert!(adopt_refresh(&task("A", "original"), &changed).is_err());
        }
    }
}
