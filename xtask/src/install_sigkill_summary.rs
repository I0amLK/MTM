//! Exact external-process SIGKILL recovery evidence for disposable deployment selectors.
use serde::Deserialize;
use serde_json::{Value, json};

use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema: String,
    ok: bool,
    binary_sha256: String,
    selector_count: u64,
    partial_restored_selectors: u64,
    kill_signal: i64,
    external_process_sigkill: bool,
    pending_journal_observed_before_kill: bool,
    recovered_state: String,
    all_candidate_selectors_recovered: bool,
    pending_journal_cleared: bool,
    final_state: String,
    previous_selector_bytes_and_modes_restored: bool,
    elapsed_ms: u64,
    physical_power_loss_tested: bool,
    shared_filesystem_tested: bool,
    production_state_modified: bool,
    production_selectors_changed: bool,
    release_qualified: bool,
}

pub(crate) fn validate(stdout: &[u8], hash: &str) -> Result<Value> {
    let report: Report = extract(stdout, "MTM_INSTALL_SIGKILL ")?;
    if report.schema != "mtm-install-sigkill-v1"
        || !report.ok
        || !valid_hash(hash)
        || report.binary_sha256 != hash
        || report.selector_count != 8
        || !(1..report.selector_count).contains(&report.partial_restored_selectors)
        || report.kill_signal != 9
        || !report.external_process_sigkill
        || !report.pending_journal_observed_before_kill
        || report.recovered_state != "active"
        || !report.all_candidate_selectors_recovered
        || !report.pending_journal_cleared
        || report.final_state != "previous_active"
        || !report.previous_selector_bytes_and_modes_restored
        || report.elapsed_ms == 0
        || report.elapsed_ms > 120_000
        || report.physical_power_loss_tested
        || report.shared_filesystem_tested
        || report.production_state_modified
        || report.production_selectors_changed
        || report.release_qualified
    {
        return Err("install SIGKILL summary has inconsistent identity, recovery or scope".into());
    }
    Ok(json!({"install_sigkill":extract::<Value>(stdout, "MTM_INSTALL_SIGKILL ")?}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        json!({
            "schema":"mtm-install-sigkill-v1","ok":true,"binary_sha256":"a".repeat(64),
            "selector_count":8,"partial_restored_selectors":3,"kill_signal":9,
            "external_process_sigkill":true,"pending_journal_observed_before_kill":true,
            "recovered_state":"active","all_candidate_selectors_recovered":true,
            "pending_journal_cleared":true,"final_state":"previous_active",
            "previous_selector_bytes_and_modes_restored":true,"elapsed_ms":2500,
            "physical_power_loss_tested":false,"shared_filesystem_tested":false,
            "production_state_modified":false,"production_selectors_changed":false,
            "release_qualified":false
        })
    }

    fn output(value: &Value) -> Vec<u8> {
        format!("MTM_INSTALL_SIGKILL {value}\n").into_bytes()
    }

    #[test]
    fn requires_actual_signal_partial_prefix_and_full_recovery() -> Result<()> {
        validate(&output(&fixture()), &"a".repeat(64))?;
        for (key, value) in [
            ("kill_signal", json!(15)),
            ("partial_restored_selectors", json!(0)),
            ("partial_restored_selectors", json!(8)),
            ("external_process_sigkill", json!(false)),
            ("pending_journal_observed_before_kill", json!(false)),
            ("recovered_state", json!("previous_active")),
            ("all_candidate_selectors_recovered", json!(false)),
            ("pending_journal_cleared", json!(false)),
            ("final_state", json!("active")),
            ("previous_selector_bytes_and_modes_restored", json!(false)),
            ("physical_power_loss_tested", json!(true)),
            ("production_state_modified", json!(true)),
            ("release_qualified", json!(true)),
        ] {
            let mut changed = fixture();
            changed[key] = value;
            assert!(validate(&output(&changed), &"a".repeat(64)).is_err());
        }
        assert!(
            validate(
                &[output(&fixture()), output(&fixture())].concat(),
                &"a".repeat(64)
            )
            .is_err()
        );
        Ok(())
    }
}
