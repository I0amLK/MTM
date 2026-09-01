#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


SUBJECT_RE = re.compile(
    r"(?:docs|test|build|feat|fix|refactor|perf|chore)"
    r"\([a-z0-9][a-z0-9-]*\): .+ \[(MTM-\d{3})\]$"
)
REQUIRED_TRAILERS = (
    "Milestone",
    "Authority-Before",
    "Authority-After",
    "Acceptance",
    "Receipt",
    "Rollback",
    "Manual-Pending",
)


def validate_message(text: str) -> str:
    lines = text.splitlines()
    if not lines:
        raise ValueError("empty commit message")
    match = SUBJECT_RE.fullmatch(lines[0].strip())
    if match is None:
        raise ValueError("invalid commit subject")
    milestone = match.group(1)
    trailers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in REQUIRED_TRAILERS:
            trailers[key] = value.strip()
    missing = [key for key in REQUIRED_TRAILERS if not trailers.get(key)]
    if missing:
        raise ValueError(f"missing commit trailers: {missing}")
    if trailers["Milestone"] != milestone:
        raise ValueError("subject and Milestone trailer disagree")
    if trailers["Authority-Before"] not in {"none", "python", "rust-shadow", "rust", "retired"}:
        raise ValueError("invalid Authority-Before")
    if trailers["Authority-After"] not in {"none", "python", "rust-shadow", "rust", "retired"}:
        raise ValueError("invalid Authority-After")
    if not trailers["Receipt"].startswith("records/iterations/ITER-"):
        raise ValueError("Receipt must reference an iteration record")
    if lines[0].startswith("perf(") and "A6" not in trailers["Acceptance"].split(","):
        raise ValueError("perf commit requires A6")
    return milestone


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: validate_commit_message.py <message-file>", file=sys.stderr)
        return 2
    try:
        milestone = validate_message(Path(argv[1]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"invalid commit message: {exc}", file=sys.stderr)
        return 1
    print(f"commit message valid for {milestone}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
