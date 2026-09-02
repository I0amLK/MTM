#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from mtm008_deployment import DeploymentLayout, cutover


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.4.0-preview.1"
BINARY = ROOT / "target" / "release" / "mtm"
HOME = Path.home()
LAYOUT = DeploymentLayout(
    bin_link=HOME / ".local" / "bin" / "mtm",
    state_root=HOME / ".local" / "share" / "mtm",
)


def main() -> int:
    manifest = cutover(BINARY, LAYOUT, VERSION, replace_manifest=True)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
