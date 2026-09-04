#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE_COMMIT = "fcdc0cd09bb0852e46bb8cdc37de3b81ccff27e3"
VERSION = "0.4.0"
REPOSITORY = "https://github.com/I0amLK/MTM.git"
REPORT = ROOT / "mtm013-public-install.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_json(executable: Path, *arguments: str) -> dict[str, Any]:
    completed = subprocess.run(
        [str(executable), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=True,
    )
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("release-info returned a non-object")
    return value


def stable_identity(executable: Path) -> bool:
    info = run_json(executable, "release-info")
    expected = {
        "name": "mtm",
        "version": VERSION,
        "implementation": "rust",
        "production_authority": "rust",
        "python_runtime_required": False,
        "public_tool_count": 24,
        "hidden_alias_count": 11,
        "state_schema_version": 2,
        "workflow_protocol_version": 3,
    }
    return all(info.get(key) == value for key, value in expected.items())


def main() -> int:
    cargo = ROOT / ".toolchain" / "rustup" / "toolchains" / "1.98.0-x86_64-unknown-linux-gnu" / "bin" / "cargo"
    rustc = cargo.with_name("rustc")
    environment = os.environ.copy()
    environment["CARGO_HOME"] = str(ROOT / ".toolchain" / "cargo")
    environment["RUSTUP_HOME"] = str(ROOT / ".toolchain" / "rustup")
    environment["RUSTC"] = str(rustc)
    environment["PATH"] = os.pathsep.join([str(cargo.parent), environment.get("PATH", "")])
    environment["GIT_TERMINAL_PROMPT"] = "0"

    with tempfile.TemporaryDirectory(prefix="mtm013-public-install-") as directory:
        root = Path(directory)
        clone = root / "clone"
        install_root = root / "install"
        subprocess.run(
            ["git", "clone", "--quiet", REPOSITORY, str(clone)],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            check=True,
        )
        public_head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=clone,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()
        commit_present = (
            subprocess.run(
                ["git", "cat-file", "-e", f"{SOURCE_COMMIT}^{{commit}}"],
                cwd=clone,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            ).returncode
            == 0
        )
        ancestor = commit_present and (
            subprocess.run(
                ["git", "merge-base", "--is-ancestor", SOURCE_COMMIT, "HEAD"],
                cwd=clone,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            ).returncode
            == 0
        )
        if not ancestor:
            raise RuntimeError(
                f"public main {public_head} does not contain frozen stable source {SOURCE_COMMIT}"
            )
        subprocess.run(
            [
                str(cargo),
                "install",
                "--git",
                REPOSITORY,
                "--rev",
                SOURCE_COMMIT,
                "--locked",
                "--bin",
                "mtm",
                "mtm-cli",
                "--root",
                str(install_root),
                "--force",
            ],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=420,
            check=True,
        )
        installed = install_root / "bin" / "mtm"
        identity_ok = installed.is_file() and stable_identity(installed)
        version = subprocess.run(
            [str(installed), "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()
        binary_sha = sha256_file(installed)

    checks = {
        "public_main_contains_frozen_source": ancestor,
        "public_git_install_identity": identity_ok,
        "public_git_install_version": version == "mtm 0.4.0",
    }
    payload = {
        "schema_version": "1.0.0",
        "milestone": "MTM-013",
        "phase": "public_git_install",
        "repository": REPOSITORY,
        "public_main": public_head,
        "source_commit": SOURCE_COMMIT,
        "version": VERSION,
        "installed_binary_sha256": binary_sha,
        "checks": checks,
        "raw_git_credentials_recorded": False,
        "ok": all(checks.values()),
    }
    REPORT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.SubprocessError, RuntimeError, json.JSONDecodeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, indent=2))
        raise SystemExit(1)
