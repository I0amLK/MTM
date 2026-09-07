#!/usr/bin/env python3
"""Validate the accepted MTM-014 release receipt after a later release supersedes it."""
from __future__ import annotations

import json

import mtm014_release_support as support
from validate_mtm014_preview_release import validate_release


def main() -> int:
    try:
        qualification = json.loads(support.QUALIFICATION.read_text(encoding="utf-8"))
        release = json.loads(support.RELEASE.read_text(encoding="utf-8"))
        summary = validate_release(release, qualification, deployed=False)
    except Exception:
        print(json.dumps({"ok": False, "error": "historical MTM-014 release receipt invalid"}))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
