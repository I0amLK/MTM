from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from scripts.mtm008_deployment import (
    DeploymentError,
    DeploymentLayout,
    cutover,
    load_manifest,
    recutover,
    retire_python,
    rollback,
    sha256_file,
)


def executable(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    os.chmod(path, 0o755)
    return path


class Mtm008DeploymentTestCase(unittest.TestCase):
    def test_atomic_cutover_rollback_recutover_and_retirement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mtm008-deploy-") as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            old_root = root / "python-tool"
            old_root.mkdir()
            old = executable(
                old_root / "re-ctm",
                "#!/bin/sh\nprintf '%s\\n' 're-ctm 0.3.0-python'\n",
            )
            link = bin_dir / "re-ctm"
            link.symlink_to(old)
            rust = executable(
                root / "rust-re-ctm",
                """#!/bin/sh
if [ "$1" = "release-info" ]; then
  printf '%s\n' '{"name":"re-ctm","version":"0.3.0","implementation":"rust","python_runtime_required":false,"public_tool_count":24,"hidden_alias_count":11,"state_schema_version":2,"workflow_protocol_version":2}'
else
  printf '%s\n' 're-ctm 0.3.0'
fi
""",
            )
            wheel = root / "re_ctm-0.3.0-py3-none-any.whl"
            wheel.write_bytes(b"rollback-wheel-fixture")
            layout = DeploymentLayout(link, root / "state")
            manifest = cutover(rust, layout, "0.3.0", wheel)
            self.assertEqual(link.resolve(), Path(manifest["release"]["path"]).resolve())
            self.assertEqual(sha256_file(wheel), manifest["rollback_wheel"]["sha256"])

            rolled = rollback(layout.manifest)
            self.assertEqual(rolled["state"], "previous_active")
            self.assertEqual(link.resolve(), old.resolve())

            active = recutover(layout.manifest)
            self.assertEqual(active["state"], "rust_active")
            self.assertNotEqual(link.resolve(), old.resolve())

            retired = retire_python(layout.manifest, old_root)
            self.assertFalse(old_root.exists())
            self.assertEqual(retired["state"], "rust_active_python_retired")
            self.assertEqual(load_manifest(layout.manifest)["schema"], "re-ctm-deployment-v1")

    def test_existing_manifest_requires_explicit_replacement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mtm008-existing-") as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            rust = executable(
                root / "rust-re-ctm",
                """#!/bin/sh
if [ "$1" = "release-info" ]; then
  printf '%s\n' '{"name":"re-ctm","version":"0.3.0","implementation":"rust","python_runtime_required":false,"public_tool_count":24,"hidden_alias_count":11,"state_schema_version":2,"workflow_protocol_version":2}'
else
  printf '%s\n' 're-ctm 0.3.0'
fi
""",
            )
            layout = DeploymentLayout(root / "bin" / "re-ctm", root / "state")
            cutover(rust, layout, "0.3.0")
            with self.assertRaisesRegex(DeploymentError, "manifest already exists"):
                cutover(rust, layout, "0.3.0")

    def test_manifest_is_owner_only_and_release_is_executable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mtm008-mode-") as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            rust = executable(
                root / "rust-re-ctm",
                """#!/bin/sh
if [ "$1" = "release-info" ]; then
  printf '%s\n' '{"name":"re-ctm","version":"0.3.0","implementation":"rust","python_runtime_required":false,"public_tool_count":24,"hidden_alias_count":11,"state_schema_version":2,"workflow_protocol_version":2}'
else
  printf '%s\n' 're-ctm 0.3.0'
fi
""",
            )
            layout = DeploymentLayout(root / "bin" / "re-ctm", root / "state")
            manifest = cutover(rust, layout, "0.3.0")
            manifest_mode = stat.S_IMODE(layout.manifest.stat().st_mode)
            release_mode = stat.S_IMODE(Path(manifest["release"]["path"]).stat().st_mode)
            self.assertEqual(manifest_mode, 0o600)
            self.assertEqual(release_mode, 0o755)

    def test_release_identity_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mtm008-invalid-") as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            fake = executable(
                root / "fake",
                "#!/bin/sh\nprintf '%s\\n' '{\"implementation\":\"python\"}'\n",
            )
            layout = DeploymentLayout(root / "bin" / "re-ctm", root / "state")
            with self.assertRaisesRegex(DeploymentError, "release identity mismatch"):
                cutover(fake, layout, "0.3.0")


if __name__ == "__main__":
    unittest.main()
