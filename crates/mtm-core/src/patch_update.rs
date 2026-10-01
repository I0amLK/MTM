//! Forward-only, language-neutral patch placement with bounded repair evidence.
//! Inspired by Coding Tools MCP v0.5.0; MTM retains its own path/commit authority.
use mtm_contracts::{ErrorCategory, ReCtmError};
use serde::Serialize;
use serde_json::json;

#[derive(Clone, Debug, Serialize)]
pub struct PatchChangedRange {
    pub start_line: usize,
    pub end_line: usize,
    pub added_lines: usize,
    pub removed_lines: usize,
}
pub struct PatchUpdate {
    pub content: String,
    pub changed_ranges: Vec<PatchChangedRange>,
    pub match_quality: &'static str,
    pub already_applied: bool,
    pub additions: usize,
    pub removals: usize,
}
struct Hunk {
    anchor: Option<String>,
    old: Vec<String>,
    new: Vec<String>,
    context: bool,
    eof: bool,
}
fn parse(raw: &[String]) -> Result<Hunk, ReCtmError> {
    let mut h = Hunk {
        anchor: None,
        old: Vec::new(),
        new: Vec::new(),
        context: false,
        eof: false,
    };
    for line in raw {
        if let Some(anchor) = line.strip_prefix("@@") {
            h.anchor = (!anchor.trim().is_empty()).then(|| anchor.trim().to_owned());
            continue;
        }
        if line == "*** End of File" {
            h.eof = true;
            continue;
        }
        if line.is_empty() {
            h.old.push(String::new());
            h.new.push(String::new());
            h.context = true;
            continue;
        }
        match line.as_bytes()[0] {
            b' ' => {
                h.old.push(line[1..].into());
                h.new.push(line[1..].into());
                h.context = true;
            }
            b'-' => h.old.push(line[1..].into()),
            b'+' => h.new.push(line[1..].into()),
            _ => {
                return Err(failure(
                    "PATCH_FAILED",
                    "Update lines need a context/add/remove marker",
                    0,
                    &[],
                    0,
                    &[],
                ));
            }
        }
    }
    Ok(h)
}
fn equal(a: &str, b: &str, grade: usize) -> bool {
    match grade {
        0 => a == b,
        1 => a.trim_end() == b.trim_end(),
        _ => a.trim() == b.trim(),
    }
}
fn positions(
    lines: &[String],
    needle: &[String],
    cursor: usize,
    eof: bool,
    grade: usize,
) -> Vec<usize> {
    if needle.is_empty() || needle.len() > lines.len() {
        return Vec::new();
    }
    let last = lines.len() - needle.len();
    if cursor > last {
        return Vec::new();
    }
    (cursor..=last)
        .filter(|i| {
            (!eof || *i == last)
                && lines[*i..*i + needle.len()]
                    .iter()
                    .zip(needle)
                    .all(|(a, b)| equal(a, b, grade))
        })
        .take(9)
        .collect()
}
fn failure(
    code: &str,
    message: &str,
    index: usize,
    lines: &[String],
    cursor: usize,
    candidates: &[usize],
) -> ReCtmError {
    let nearby = lines
        .iter()
        .enumerate()
        .skip(cursor.saturating_sub(3))
        .take(12)
        .map(|(i, s)| format!("{}: {}", i + 1, s.chars().take(240).collect::<String>()))
        .collect::<Vec<_>>()
        .join("\n");
    ReCtmError::new(code,message).with_category(ErrorCategory::Validation).with_retryable(true)
        .with_details(json!({"hunk_index":index,"candidate_lines":candidates.iter().map(|n|n+1).collect::<Vec<_>>(),"nearby_text":nearby,"total_lines":lines.len()}))
}
pub fn apply_update_hunks_detailed(
    content: &str,
    hunks: &[Vec<String>],
    path: &str,
) -> Result<PatchUpdate, ReCtmError> {
    if content.len() > 64 * 1024 * 1024 || hunks.len() > 200 {
        return Err(failure(
            "PATCH_LIMIT",
            "Patch text or hunk bound exceeded",
            0,
            &[],
            0,
            &[],
        ));
    }
    let crlf = content.contains("\r\n");
    let normalized = content.replace("\r\n", "\n").replace('\r', "\n");
    let trailing = normalized.ends_with('\n');
    let lines: Vec<String> = normalized
        .split_inclusive('\n')
        .map(|s| s.strip_suffix('\n').unwrap_or(s).to_owned())
        .collect();
    let mut cursor = 0usize;
    let mut placements = Vec::new();
    let mut max_grade = 0;
    // Conservative byte-comparison budget, including trim scans and fallback
    // grades. Repeated near-matches must not multiply unbounded CPU work.
    let mut work_remaining = 512_u64 * 1024 * 1024;
    for (index, raw) in hunks.iter().enumerate() {
        let h = parse(raw)?;
        let span = h.old.len().max(h.new.len()).max(1) as u64;
        let needle_bytes = h
            .old
            .iter()
            .chain(&h.new)
            .map(|s| s.len() as u64)
            .sum::<u64>();
        let estimate = (content.len() as u64)
            .saturating_mul(span)
            .saturating_add(needle_bytes.saturating_mul(lines.len() as u64))
            .saturating_mul(5)
            .saturating_add(h.anchor.as_ref().map_or(0, |anchor| {
                (content.len() as u64)
                    .saturating_add((anchor.len() as u64).saturating_mul(lines.len() as u64))
                    .saturating_mul(3)
            }));
        if estimate > work_remaining {
            return Err(ReCtmError::new(
                "PATCH_LIMIT",
                "Patch matching exceeds its comparison budget; use smaller hunks or apply_changes",
            )
            .with_category(ErrorCategory::Validation));
        }
        work_remaining -= estimate;
        if let Some(anchor) = &h.anchor {
            let found = (0..3).find_map(|grade| {
                (cursor..lines.len())
                    .find(|i| equal(&lines[*i], anchor, grade))
                    .map(|i| (i, grade))
            });
            let Some((line, grade)) = found else {
                return Err(failure(
                    "PATCH_CONTEXT_NOT_FOUND",
                    &format!("Forward anchor not found in {path}"),
                    index,
                    &lines,
                    cursor,
                    &[],
                ));
            };
            cursor = line + 1;
            max_grade = max_grade.max(grade);
        }
        if h.old.is_empty() {
            let safe_repeat = h.new.len() >= 2 && h.new.iter().any(|s| !s.trim().is_empty());
            let repeat_grade = if safe_repeat {
                (0..2).find(|grade| positions(&lines, &h.new, cursor, true, *grade).len() == 1)
            } else {
                None
            };
            if let Some(grade) = repeat_grade {
                max_grade = max_grade.max(grade);
            }
            let repeat = repeat_grade.is_some();
            if !repeat && !h.new.is_empty() {
                placements.push((lines.len(), lines.len(), h.new));
            }
            cursor = lines.len();
            continue;
        }
        let located = (0..3).find_map(|grade| {
            let found = positions(&lines, &h.old, cursor, h.eof, grade);
            (!found.is_empty()).then_some((found, grade))
        });
        if let Some((found, grade)) = located {
            if found.len() != 1 {
                return Err(failure(
                    "PATCH_CONTEXT_AMBIGUOUS",
                    &format!("Patch context is ambiguous in {path}"),
                    index,
                    &lines,
                    cursor,
                    &found,
                ));
            }
            let mut start = found[0];
            let mut end = start + h.old.len();
            cursor = end;
            let mut new = h.new;
            let prefix = lines[start..end]
                .iter()
                .zip(&new)
                .take_while(|(old, new)| old == new)
                .count();
            start += prefix;
            new.drain(..prefix);
            while start < end && !new.is_empty() && lines[end - 1] == new[new.len() - 1] {
                end -= 1;
                new.pop();
            }
            if start != end || !new.is_empty() {
                placements.push((start, end, new));
            }
            max_grade = max_grade.max(grade);
            continue;
        }
        // Only unique, nonblank, sufficiently contextual evidence may suppress
        // a duplicate; a coincidental context-free one-line replacement cannot.
        if (h.context || h.new.len() >= 2) && h.new.iter().any(|s| !s.trim().is_empty()) {
            if let Some((found, grade)) = (0..2).find_map(|grade| {
                let found = positions(&lines, &h.new, cursor, h.eof, grade);
                (found.len() == 1).then_some((found, grade))
            }) {
                cursor = found[0] + h.new.len();
                max_grade = max_grade.max(grade);
                continue;
            }
        }
        return Err(failure(
            "PATCH_CONTEXT_NOT_FOUND",
            &format!("Patch context did not match in {path}"),
            index,
            &lines,
            cursor,
            &[],
        ));
    }
    let mut added = 0usize;
    let mut removed = 0usize;
    let mut ranges = Vec::new();
    for (start, end, new) in &placements {
        let first = start + added + 1 - removed;
        ranges.push(PatchChangedRange {
            start_line: first,
            end_line: first + new.len() - 1,
            added_lines: new.len(),
            removed_lines: end - start,
        });
        added += new.len();
        removed += end - start;
    }
    let mut updated = lines;
    for (start, end, new) in placements.iter().rev() {
        updated.splice(*start..*end, new.iter().cloned());
    }
    let mut text = updated.join("\n");
    if !updated.is_empty() && (trailing || content.is_empty()) {
        text.push('\n');
    }
    if crlf {
        text = text.replace('\n', "\r\n");
    }
    if placements.is_empty() {
        text = content.to_owned();
    }
    Ok(PatchUpdate {
        content: text,
        changed_ranges: ranges,
        match_quality: ["exact", "trailing_whitespace", "indentation"][max_grade],
        already_applied: placements.is_empty(),
        additions: added,
        removals: removed,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn h(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|s| s.to_string()).collect()
    }
    #[test]
    fn anchors_are_forward_and_missing_anchors_never_fall_back() -> Result<(), ReCtmError> {
        let source = "old\nanchor\nold\n";
        let r = apply_update_hunks_detailed(source, &[h(&["@@ anchor", "-old", "+new"])], "a")?;
        assert_eq!(r.content, "old\nanchor\nnew\n");
        assert!(
            apply_update_hunks_detailed(source, &[h(&["@@ missing", "-old", "+new"])], "a")
                .is_err()
        );
        assert!(
            apply_update_hunks_detailed("old\nanchor\n", &[h(&["@@ anchor", "-old", "+new"])], "a")
                .is_err()
        );
        Ok(())
    }
    #[test]
    fn eof_graded_evidence_and_conservative_repetition() -> Result<(), ReCtmError> {
        let r = apply_update_hunks_detailed(
            "x\nx\n",
            &[h(&["@@", "-x", "+y", "*** End of File"])],
            "a",
        )?;
        assert_eq!(r.content, "x\ny\n");
        assert_eq!(r.additions, 1);
        assert_eq!(r.removals, 1);
        let r = apply_update_hunks_detailed("  x   \n", &[h(&["-x", "+y"])], "a")?;
        assert_eq!(r.match_quality, "indentation");
        assert!(apply_update_hunks_detailed("new\n", &[h(&["-old", "+new"])], "a").is_err());
        let repeated = apply_update_hunks_detailed(
            "context\nnew\n",
            &[h(&[" context", "-old", "+new"])],
            "a",
        )?;
        assert!(repeated.already_applied);
        Ok(())
    }
    #[test]
    fn pure_additions_append_and_validate_anchor() -> Result<(), ReCtmError> {
        let r = apply_update_hunks_detailed("a\n", &[h(&["@@ a", "+b", "+c"])], "a")?;
        assert_eq!(r.content, "a\nb\nc\n");
        assert!(apply_update_hunks_detailed("a\n", &[h(&["@@ absent", "+b"])], "a").is_err());
        assert!(apply_update_hunks_detailed(&r.content, &[h(&["+b", "+c"])], "a")?.already_applied);
        Ok(())
    }

    #[test]
    fn repeated_near_matches_are_bounded_before_scanning() {
        let content = "same\n".repeat(20_000);
        let mut hunk = vec!["-same".to_owned(); 1_000];
        hunk.push("-different".into());
        hunk.push("+changed".into());
        assert_eq!(
            apply_update_hunks_detailed(&content, &[hunk], "a")
                .map_err(|e| e.code)
                .err(),
            Some("PATCH_LIMIT".into())
        );
    }
}
