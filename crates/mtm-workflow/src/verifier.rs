use mtm_contracts::{ErrorCategory, ReCtmError};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::kernel::FinalizationPermit;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerificationFinding {
    pub location: String,
    pub issue: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub summary: String,
    pub critical_errors: Vec<VerificationFinding>,
    pub gaps: Vec<VerificationFinding>,
    pub repair_hints: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationVerdict {
    Correct,
    Wrong,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationDecision {
    report: VerificationReport,
    verdict: VerificationVerdict,
}

impl VerificationDecision {
    pub fn from_submitted_report(value: &Value) -> Result<Self, ReCtmError> {
        let outer = value.as_object().ok_or_else(invalid_report)?;
        let report = outer
            .get("verification_report")
            .and_then(Value::as_object)
            .ok_or_else(invalid_report)?;
        let summary = nonempty_text(report, "summary")?;
        let critical_errors = findings(report.get("critical_errors"), "critical_errors")?;
        let gaps = findings(report.get("gaps"), "gaps")?;
        let repair_hints = outer
            .get("repair_hints")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let verdict = if critical_errors.is_empty() && gaps.is_empty() {
            VerificationVerdict::Correct
        } else {
            if repair_hints.trim().is_empty() {
                return Err(ReCtmError::new(
                    "INVALID_ARGUMENT",
                    "wrong verification requires non-empty repair_hints",
                )
                .with_category(ErrorCategory::Validation));
            }
            VerificationVerdict::Wrong
        };
        Ok(Self {
            report: VerificationReport {
                summary,
                critical_errors,
                gaps,
                repair_hints: if verdict == VerificationVerdict::Correct {
                    String::new()
                } else {
                    repair_hints
                },
            },
            verdict,
        })
    }

    pub fn with_server_gap(mut self, finding: VerificationFinding) -> Self {
        self.report.gaps.push(finding);
        self.verdict = VerificationVerdict::Wrong;
        self
    }

    #[must_use]
    pub const fn verdict(&self) -> VerificationVerdict {
        self.verdict
    }

    #[must_use]
    pub fn report(&self) -> &VerificationReport {
        &self.report
    }

    #[must_use]
    pub fn normalized_payload(&self) -> Value {
        serde_json::json!({
            "verification_report": {
                "summary": self.report.summary,
                "critical_errors": self.report.critical_errors,
                "gaps": self.report.gaps,
            },
            "verdict": match self.verdict { VerificationVerdict::Correct => "correct", VerificationVerdict::Wrong => "wrong" },
            "repair_hints": self.report.repair_hints,
        })
    }

    pub fn finalization_permit(
        &self,
        run_id: &str,
        latex_passed: bool,
        proof_sha256: &str,
        proof_manifest_sha256: Option<&str>,
        verifier_domain_id: &str,
    ) -> Result<FinalizationPermit, ReCtmError> {
        if self.verdict != VerificationVerdict::Correct || !latex_passed {
            return Err(ReCtmError::new(
                "FINALIZATION_GATE_DENIED",
                "Finalization requires a passed LaTeX gate and server-computed correct verdict.",
            )
            .with_category(ErrorCategory::Permission));
        }
        if !self.report.critical_errors.is_empty() || !self.report.gaps.is_empty() {
            return Err(ReCtmError::new(
                "FINALIZATION_GATE_DENIED",
                "Verification findings are not empty.",
            )
            .with_category(ErrorCategory::Permission));
        }
        Ok(FinalizationPermit::issue(
            run_id.to_owned(),
            proof_sha256.to_owned(),
            proof_manifest_sha256.map(str::to_owned),
            verifier_domain_id.to_owned(),
        ))
    }
}

fn nonempty_text(object: &Map<String, Value>, key: &str) -> Result<String, ReCtmError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(invalid_report)
}

fn findings(value: Option<&Value>, label: &str) -> Result<Vec<VerificationFinding>, ReCtmError> {
    let items = value.and_then(Value::as_array).ok_or_else(invalid_report)?;
    items
        .iter()
        .map(|item| {
            let object = item.as_object().ok_or_else(invalid_report)?;
            Ok(VerificationFinding {
                location: nonempty_text(object, "location")?,
                issue: nonempty_text(object, "issue")?,
            })
        })
        .collect::<Result<Vec<_>, ReCtmError>>()
        .map_err(|error| {
            if error.code == "VERIFICATION_REPORT_INVALID" {
                ReCtmError::new(
                    "VERIFICATION_REPORT_INVALID",
                    format!("verification_report.{label} contains an invalid finding."),
                )
                .with_category(ErrorCategory::Validation)
            } else {
                error
            }
        })
}

fn invalid_report() -> ReCtmError {
    ReCtmError::new(
        "VERIFICATION_REPORT_INVALID",
        "Verification report has an invalid shape.",
    )
    .with_category(ErrorCategory::Validation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submitted_verdict_is_ignored_and_server_computes_correctness() -> Result<(), ReCtmError> {
        let decision = VerificationDecision::from_submitted_report(&serde_json::json!({
            "verification_report": {"summary":"checked", "critical_errors":[], "gaps":[]},
            "verdict":"wrong",
            "repair_hints":"model tried to override server"
        }))?;
        assert_eq!(decision.verdict(), VerificationVerdict::Correct);
        assert_eq!(decision.normalized_payload()["verdict"], "correct");
        Ok(())
    }

    #[test]
    fn finalization_permit_requires_both_verifier_and_latex() -> Result<(), ReCtmError> {
        let decision = VerificationDecision::from_submitted_report(&serde_json::json!({
            "verification_report": {"summary":"checked", "critical_errors":[], "gaps":[]},
            "repair_hints":""
        }))?;
        assert!(
            decision
                .finalization_permit("run", false, "abc", None, "verifier")
                .is_err()
        );
        assert!(
            decision
                .finalization_permit("run", true, "abc", None, "verifier")
                .is_ok()
        );
        Ok(())
    }
}
