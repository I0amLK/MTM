#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "conformance" / "mtm011-math-corpus.json"
MAX_TEX_BYTES = 2 * 1024 * 1024


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_tex(path: Path, label: str) -> None:
    if not path.is_file() or path.suffix.lower() != ".tex":
        raise ValueError(f"{label} must be an existing .tex file")
    if not (1 <= path.stat().st_size <= MAX_TEX_BYTES):
        raise ValueError(f"{label} size is outside the accepted range")
    path.read_text(encoding="utf-8")


def case_ids() -> set[str]:
    payload = json.loads(CORPUS.read_text(encoding="utf-8"))
    return {item["case_id"] for item in payload["cases"]}


def write_owner_only(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Create one treatment-blind MTM-011 A/B artifact bundle.")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--protocol2-tex", type=Path, required=True)
    parser.add_argument("--protocol3-tex", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--mapping-path", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.case_id not in case_ids():
        raise SystemExit("unknown frozen MTM-011 case")
    validate_tex(arguments.protocol2_tex, "protocol2-tex")
    validate_tex(arguments.protocol3_tex, "protocol3-tex")
    if arguments.output_dir.exists() and any(arguments.output_dir.iterdir()):
        raise SystemExit("output-dir must not contain existing files")
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    if arguments.mapping_path.exists():
        raise SystemExit("mapping-path already exists; refusing overwrite")
    assignments = ["protocol2", "protocol3"]
    if secrets.randbits(1):
        assignments.reverse()
    labels = {"A": assignments[0], "B": assignments[1]}
    source = {"protocol2": arguments.protocol2_tex, "protocol3": arguments.protocol3_tex}
    hashes: dict[str, str] = {}
    for label, treatment in labels.items():
        destination = arguments.output_dir / f"{label}.tex"
        shutil.copyfile(source[treatment], destination)
        hashes[label] = sha256_file(destination)
    corpus_sha = sha256_file(CORPUS)
    (arguments.output_dir / "manifest.json").write_text(json.dumps({
        "schema_version": "1.0.0",
        "case_id": arguments.case_id,
        "corpus_sha256": corpus_sha,
        "artifacts": {label: {"path": f"{label}.tex", "sha256": hashes[label]} for label in ("A", "B")},
        "treatment_labels_present": False
    }, indent=2) + "\n", encoding="utf-8")
    write_owner_only(arguments.mapping_path, {
        "schema_version": "1.0.0",
        "case_id": arguments.case_id,
        "mapping": labels,
        "artifact_hashes": hashes,
        "corpus_sha256": corpus_sha,
        "mode": "owner_only_until_scores_frozen"
    })
    print(json.dumps({"ok": True, "case_id": arguments.case_id, "bundle": str(arguments.output_dir), "mapping": str(arguments.mapping_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
