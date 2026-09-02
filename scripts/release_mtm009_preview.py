#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from mtm008_deployment import (
    MANIFEST_SCHEMA,
    DeploymentLayout,
    DeploymentError,
    atomic_symlink,
    atomic_write_json,
    install_release,
    run_version,
    sha256_file,
    utc_now,
    validate_rust_release,
    verify_active_rust,
)


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.4.0-preview.1"
BINARY = ROOT / "target" / "release" / "mtm"
ROLLBACK_VERSION = "0.3.0"
ROLLBACK_SHA256 = "0a785a122396a3f8961cbc33b967e7a48874b90311333c8860a1e5c75582fd7f"
HOME = Path.home()
LAYOUT = DeploymentLayout(
    bin_link=HOME / ".local" / "bin" / "mtm",
    state_root=HOME / ".local" / "share" / "mtm",
)
ROLLBACK_BINARY = LAYOUT.releases_root / ROLLBACK_VERSION / "mtm"


def accepted_rollback() -> dict[str, str]:
    if not ROLLBACK_BINARY.is_file():
        raise DeploymentError(f"accepted rollback binary is missing: {ROLLBACK_BINARY}")
    validate_rust_release(ROLLBACK_BINARY, ROLLBACK_VERSION)
    actual_sha = sha256_file(ROLLBACK_BINARY)
    if actual_sha != ROLLBACK_SHA256:
        raise DeploymentError(
            f"accepted rollback binary hash mismatch: expected {ROLLBACK_SHA256}, got {actual_sha}"
        )
    resolved = ROLLBACK_BINARY.resolve(strict=True)
    return {
        "kind": "symlink",
        "target": str(ROLLBACK_BINARY),
        "resolved_target": str(resolved),
        "version": run_version(resolved),
    }


def main() -> int:
    previous = accepted_rollback()
    release = install_release(BINARY, LAYOUT, VERSION)
    now = utc_now()
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "created_at": now,
        "updated_at": now,
        "state": "rust_active",
        "command_link": str(LAYOUT.bin_link),
        "release": release,
        "previous": previous,
        "rollback_wheel": None,
        "history": [{"at": now, "action": "preview_cutover", "state": "rust_active"}],
    }
    atomic_symlink(release["path"], LAYOUT.bin_link)
    verify_active_rust(LAYOUT, manifest)
    atomic_write_json(LAYOUT.manifest, manifest)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
