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
CORPUS = ROOT / "conformance" / "mtm009-math-corpus.json"
MAX_TEX_BYTES = 2 * 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_tex(path: Path, label: str) -> None:
    if not path.is_file() or path.suffix.lower() != ".tex":
        raise ValueError(f"{label} must be an existing .tex file")
    size = path.stat().st_size
    if not (1 <= size <= MAX_TEX_BYTES):
        raise ValueError(f"{label} size is outside the accepted range")
    path.read_text(encoding="utf-8")


def case_ids() -> set[str]:
    payload = json.loads(CORPUS.read_text(encoding="utf-8"))
    return {
        str(item["case_id"])
        for item in payload.get("cases", [])
        if isinstance(item, dict) and isinstance(item.get("case_id"), str)
    }


def write_owner_only(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a treatment-blind A/B bundle for one MTM-009 .tex pair."
    )
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--protocol2-tex", type=Path, required=True)
    parser.add_argument("--protocol3-tex", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--mapping-path", type=Path, required=True)
    arguments = parser.parse_args()

    if arguments.case_id not in case_ids():
        raise SystemExit(f"unknown frozen MTM-009 case: {arguments.case_id}")
    validate_tex(arguments.protocol2_tex, "protocol2-tex")
    validate_tex(arguments.protocol3_tex, "protocol3-tex")
    if arguments.output_dir.exists() and any(arguments.output_dir.iterdir()):
        raise SystemExit("output-dir must not contain existing files")
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    if arguments.mapping_path.exists():
        raise SystemExit("mapping-path already exists; refusing to overwrite blinding map")

    assignments = ["protocol2", "protocol3"]
    if secrets.randbits(1):
        assignments.reverse()
    source = {
        "protocol2": arguments.protocol2_tex,
        "protocol3": arguments.protocol3_tex,
    }
    labels = {"A": assignments[0], "B": assignments[1]}
    artifact_hashes: dict[str, str] = {}
    for label, treatment in labels.items():
        destination = arguments.output_dir / f"{label}.tex"
        shutil.copyfile(source[treatment], destination)
        artifact_hashes[label] = sha256_file(destination)

    manifest = {
        "schema_version": "1.0.0",
        "case_id": arguments.case_id,
        "corpus_sha256": sha256_file(CORPUS),
        "artifacts": {
            label: {"path": f"{label}.tex", "sha256": artifact_hashes[label]}
            for label in ("A", "B")
        },
        "treatment_labels_present": False,
    }
    (arguments.output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    write_owner_only(
        arguments.mapping_path,
        {
            "schema_version": "1.0.0",
            "case_id": arguments.case_id,
            "mapping": labels,
            "artifact_hashes": artifact_hashes,
            "corpus_sha256": manifest["corpus_sha256"],
            "mode": "owner_only_until_scores_frozen",
        },
    )
    print(
        json.dumps(
            {
                "ok": True,
                "case_id": arguments.case_id,
                "bundle": str(arguments.output_dir),
                "mapping": str(arguments.mapping_path),
                "mapping_mode": oct(arguments.mapping_path.stat().st_mode & 0o777),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
