from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAYOUT = ROOT / "records" / "governance" / "record-layout.json"


@lru_cache(maxsize=1)
def _legacy_relocations() -> dict[str, str]:
    payload = json.loads(LAYOUT.read_text(encoding="utf-8"))
    relocations = payload.get("relocations")
    if not isinstance(relocations, list):
        raise ValueError("record relocation index is missing")
    result: dict[str, str] = {}
    for item in relocations:
        if not isinstance(item, dict):
            continue
        legacy = item.get("legacy_path")
        current = item.get("current_path")
        if isinstance(legacy, str) and isinstance(current, str):
            result[legacy] = current
    return result


def resolve_repository_record(path_text: str) -> Path:
    """Resolve a canonical or relocated historical repository record path.

    Historical evidence payloads may retain the root-relative locator that was
    true when they were sealed. Layout migration must not rewrite those payloads;
    this resolver follows the machine-audited relocation index instead.
    """

    raw = Path(path_text)
    if raw.is_absolute():
        return raw
    direct = ROOT / raw
    if direct.exists():
        return direct
    relocated = _legacy_relocations().get(path_text)
    if relocated is not None:
        return ROOT / relocated
    return direct
