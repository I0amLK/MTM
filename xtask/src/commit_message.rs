//! Commit policy belongs to the Rust maintenance entry, not a Python hook.
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};

use crate::Result;

const MAX_MESSAGE_BYTES: u64 = 65_536;
const TRAILERS: [&str; 7] = [
    "Milestone",
    "Authority-Before",
    "Authority-After",
    "Acceptance",
    "Receipt",
    "Rollback",
    "Manual-Pending",
];
const TYPES: [&str; 8] = [
    "docs", "test", "build", "feat", "fix", "refactor", "perf", "chore",
];

fn bounded_message(reader: impl Read) -> Result<String> {
    let mut bytes = Vec::new();
    reader.take(MAX_MESSAGE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_MESSAGE_BYTES as usize {
        return Err("commit message exceeds 64 KiB".into());
    }
    String::from_utf8(bytes).map_err(|_| "commit message must be UTF-8".into())
}

pub(crate) fn run(options: &[String]) -> Result<()> {
    let [path] = options else {
        return Err("usage: cargo xtask commit-message <file|--stdin>".into());
    };
    let message = if path == "--stdin" {
        bounded_message(io::stdin().lock())?
    } else if path.starts_with('-') {
        return Err("unknown commit-message option".into());
    } else {
        let file = File::open(path)?;
        if !file.metadata()?.is_file() {
            return Err("commit message input must be a regular file".into());
        }
        bounded_message(file)?
    };
    let milestone = validate(&message)?;
    println!("{}", serde_json::json!({"ok":true,"milestone":milestone}));
    Ok(())
}

pub(crate) fn validate(message: &str) -> Result<&str> {
    if message.len() > MAX_MESSAGE_BYTES as usize || message.contains('\0') {
        return Err("invalid commit message size or encoding".into());
    }
    let mut lines = message.lines();
    let subject = lines.next().ok_or("empty commit message")?.trim();
    let (kind_scope, summary_id) = subject.split_once(": ").ok_or("invalid commit subject")?;
    let (kind, scope) = kind_scope
        .split_once('(')
        .ok_or("invalid commit type/scope")?;
    let scope = scope.strip_suffix(')').ok_or("invalid commit scope")?;
    if !TYPES.contains(&kind)
        || scope.is_empty()
        || !scope.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || (index > 0 && byte == b'-')
        })
    {
        return Err("invalid commit type/scope".into());
    }
    let (summary, tagged) = summary_id
        .rsplit_once(" [")
        .ok_or("missing milestone tag")?;
    let milestone = tagged.strip_suffix(']').ok_or("invalid milestone tag")?;
    let digits = milestone
        .strip_prefix("MTM-")
        .ok_or("invalid milestone id")?;
    if summary.trim().is_empty()
        || subject.chars().any(char::is_control)
        || digits.len() != 3
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("invalid commit subject or milestone id".into());
    }
    let mut trailers = BTreeMap::new();
    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if TRAILERS.contains(&key) && trailers.insert(key, value.trim()).is_some() {
            return Err("duplicate required commit trailer".into());
        }
    }
    if TRAILERS
        .iter()
        .any(|key| trailers.get(key).is_none_or(|value| value.is_empty()))
    {
        return Err("missing required commit trailer".into());
    }
    if trailers["Milestone"] != milestone {
        return Err("subject and Milestone trailer disagree".into());
    }
    for key in ["Authority-Before", "Authority-After"] {
        if !matches!(
            trailers[key],
            "none" | "python" | "rust-shadow" | "rust" | "retired"
        ) {
            return Err("invalid authority trailer".into());
        }
    }
    if trailers["Receipt"] != format!("records/iterations/ITER-{digits}.json") {
        return Err("Receipt must name this milestone's canonical iteration record".into());
    }
    let mut acceptance = std::collections::BTreeSet::new();
    for level in trailers["Acceptance"].split(',') {
        if !matches!(level, "A0" | "A1" | "A2" | "A3" | "A4" | "A5" | "A6")
            || !acceptance.insert(level)
        {
            return Err("invalid or duplicate acceptance level".into());
        }
    }
    if kind == "perf" && !acceptance.contains("A6") {
        return Err("perf commit requires A6".into());
    }
    Ok(milestone)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message() -> String {
        "docs(governance): establish project foundation [MTM-001]\n\nMilestone: MTM-001\nAuthority-Before: python\nAuthority-After: python\nAcceptance: A0\nReceipt: records/iterations/ITER-001.json\nRollback: revert the checkpoint\nManual-Pending: target checks\n".to_owned()
    }

    #[test]
    fn accepts_historical_contract_and_crlf() -> Result<()> {
        assert_eq!(validate(&message())?, "MTM-001");
        assert_eq!(validate(&message().replace('\n', "\r\n"))?, "MTM-001");
        assert!(validate(&message().replace("foundation", "基础")).is_ok());
        Ok(())
    }

    #[test]
    fn perf_requires_explicit_a6_not_a_substring() {
        let perf = message().replacen("docs(", "perf(", 1);
        assert!(validate(&perf).is_err());
        assert!(validate(&perf.replace("Acceptance: A0", "Acceptance: A0,A6")).is_ok());
        assert!(validate(&perf.replace("Acceptance: A0", "Acceptance: A60")).is_err());
    }

    #[test]
    fn every_required_trailer_is_required_and_unique() {
        for key in TRAILERS {
            let missing = message()
                .lines()
                .filter(|line| !line.starts_with(&format!("{key}:")))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(validate(&missing).is_err(), "{key}");
            assert!(
                validate(&format!("{}{key}: replacement\n", message())).is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn rejects_cross_milestone_receipts_and_path_escape() {
        for replacement in [
            "records/iterations/ITER-002.json",
            "records/iterations/ITER-001.json/../x",
            "../ITER-001.json",
        ] {
            assert!(
                validate(&message().replace("records/iterations/ITER-001.json", replacement))
                    .is_err()
            );
        }
        assert!(validate(&message().replace("Milestone: MTM-001", "Milestone: MTM-002")).is_err());
    }

    #[test]
    fn rejects_invalid_subject_authority_and_acceptance() {
        for (old, new) in [
            ("docs(governance)", "unknown(governance)"),
            ("docs(governance)", "docs(-invalid)"),
            ("MTM-001]", "MTM-01]"),
            ("Authority-After: python", "Authority-After: unrestricted"),
            ("Acceptance: A0", "Acceptance: A0,A0"),
            ("Acceptance: A0", "Acceptance: A7"),
        ] {
            assert!(validate(&message().replace(old, new)).is_err());
        }
        assert!(validate("").is_err());
        assert!(validate(&format!("{}\0", message())).is_err());
    }

    #[test]
    fn input_reads_are_bounded_and_utf8_checked() -> Result<()> {
        assert_eq!(bounded_message(message().as_bytes())?, message());
        assert!(bounded_message(vec![b'x'; MAX_MESSAGE_BYTES as usize + 1].as_slice()).is_err());
        assert!(bounded_message(&b"\xff"[..]).is_err());
        Ok(())
    }
}
