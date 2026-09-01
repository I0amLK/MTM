#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "mtm006-target-validation.json"
METHODOLOGY = (ROOT / ".." / "Re-CTM" / "src" / "re_ctm" / "resources" / "methodology.json").resolve()


def implementation_sha256() -> str:
    digest = hashlib.sha256()
    roots = [
        ROOT / "Cargo.toml",
        ROOT / "Cargo.lock",
        ROOT / "rust-toolchain.toml",
        ROOT / "crates" / "mtm-contracts" / "src",
        ROOT / "crates" / "mtm-core" / "src",
        ROOT / "crates" / "mtm-storage" / "src" / "lib.rs",
        ROOT / "crates" / "mtm-storage" / "src" / "schema.rs",
        ROOT / "crates" / "mtm-storage" / "src" / "store.rs",
        ROOT / "crates" / "mtm-storage" / "src" / "capability.rs",
        ROOT / "crates" / "mtm-workflow" / "Cargo.toml",
        ROOT / "crates" / "mtm-workflow" / "src" / "lib.rs",
        ROOT / "crates" / "mtm-workflow" / "src" / "engine.rs",
        ROOT / "crates" / "mtm-workflow" / "src" / "kernel.rs",
        ROOT / "crates" / "mtm-workflow" / "src" / "methodology.rs",
        ROOT / "crates" / "mtm-workflow" / "src" / "vault.rs",
        ROOT / "crates" / "mtm-workflow" / "src" / "verifier.rs",
        ROOT / "crates" / "mtm-workflow" / "src" / "bin" / "target_validation.rs",
        ROOT / "scripts" / "run_mtm006_target_validation.py",
        ROOT / "scripts" / "validate_mtm006_target_evidence.py",
    ]
    files: list[Path] = []
    for root in roots:
        if root.is_file():
            files.append(root)
        elif root.is_dir():
            files.extend(path for path in root.rglob("*") if path.is_file())
    for path in sorted(set(files)):
        relative = path.relative_to(ROOT).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def cargo_environment() -> dict[str, str]:
    env = os.environ.copy()
    cargo_home = ROOT / ".toolchain" / "cargo"
    rustup_home = ROOT / ".toolchain" / "rustup"
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
    channel = str(toolchain.get("toolchain", {}).get("channel") or "").strip()
    candidates = sorted(rustup_home.glob(f"toolchains/{channel}-*/bin")) if channel else []
    if len(candidates) != 1:
        raise RuntimeError(f"expected exactly one project toolchain for {channel!r}")
    toolchain_bin = candidates[0]
    env["CARGO_HOME"] = str(cargo_home)
    env["RUSTUP_HOME"] = str(rustup_home)
    env["PATH"] = (
        str(toolchain_bin)
        + os.pathsep
        + str(cargo_home / "bin")
        + os.pathsep
        + env.get("PATH", "")
    )
    env["MTM_PINNED_CARGO"] = str(toolchain_bin / "cargo")
    return env


def main() -> int:
    pdflatex = shutil.which("pdflatex")
    if not pdflatex:
        print(json.dumps({"ok": False, "error": "pdflatex not found"}, indent=2))
        return 1
    env = cargo_environment()
    cargo = env["MTM_PINNED_CARGO"]
    completed = subprocess.run(
        [
            cargo,
            "run",
            "-q",
            "-p",
            "mtm-workflow",
            "--bin",
            "target_validation",
            "--",
            str(METHODOLOGY),
            pdflatex,
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=180,
    )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        result = {"ok": False, "error": f"target binary returned invalid JSON: {exc}"}
    version = subprocess.run(
        [pdflatex, "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout=10,
    ).stdout.splitlines()
    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "project": "MTM-reboot",
        "milestone": "MTM-006",
        "implementation_sha256": implementation_sha256(),
        "environment": {
            "platform": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "pdflatex": Path(pdflatex).name,
            "pdflatex_version": version[0] if version else "unknown",
        },
        "passed": completed.returncode == 0 and result.get("ok") is True,
        "check_count": int(result.get("check_count") or 0),
        "checks": result.get("checks") if isinstance(result.get("checks"), list) else [],
        "sensitive_content_omitted": True,
        "claim": (
            "This report validates the current Linux target's real pdflatex workflow gate, "
            "mechanical finalization, read-only verified artifact, project promotion, server-owned "
            "verdict, post-verifier proof-tamper denial, and server-derived missing-reference gap. "
            "It uses temporary state/private roots and records no capabilities, proofs, project/run "
            "identifiers, private-vault contents, or source database rows."
        ),
    }
    temporary = REPORT.with_name(REPORT.name + ".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(REPORT)
    print(json.dumps({"ok": report["passed"], "report": str(REPORT)}, indent=2))
    if not report["passed"] and completed.stderr:
        print(completed.stderr[-4000:])
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
