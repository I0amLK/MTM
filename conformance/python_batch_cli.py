#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from typing import Any

from python_reference import evaluate_request


MAX_INPUT_BYTES = 1_048_576
MAX_REQUESTS = 1_000


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        print(json.dumps({"ok": False, "error": "input too large"}))
        return 2
    payload: Any = json.loads(raw)
    if not isinstance(payload, list) or len(payload) > MAX_REQUESTS:
        print(json.dumps({"ok": False, "error": "batch must be a bounded array"}))
        return 2
    result = [evaluate_request(request) for request in payload]
    sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
