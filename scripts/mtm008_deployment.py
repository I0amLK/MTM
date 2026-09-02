#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MANIFEST_SCHEMA = "mtm-deployment-v1"
COMMAND_NAME = "mtm"
RELEASE_INFO_TIMEOUT_SECONDS = 10


class DeploymentError(RuntimeError):
    pass


@dataclass(frozen=True)
class DeploymentLayout:
    bin_link: Path
    state_root: Path

    @property
    def releases_root(self) -> Path:
        return self.state_root / "releases"

    @property
    def deployment_root(self) -> Path:
        return self.state_root / "deployment"

    @property
    def rollback_root(self) -> Path:
        return self.state_root / "rollback"

    @property
    def manifest(self) -> Path:
        return self.deployment_root / "deployment-v1.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_absolute(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise DeploymentError(f"{label} must be absolute: {path}")
    return path


def ensure_directory(path: Path, mode: int = 0o700) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise DeploymentError(f"expected a real directory: {path}")
    os.chmod(path, mode)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_json(path: Path, payload: dict[str, Any], mode: int = 0o600) -> None:
    ensure_directory(path.parent)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_symlink(target: str, link: Path) -> None:
    ensure_directory(link.parent, 0o755)
    temporary = link.with_name(f".{link.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    try:
        os.symlink(target, temporary)
        os.replace(temporary, link)
        fsync_directory(link.parent)
    finally:
        temporary.unlink(missing_ok=True)


def run_json(executable: Path, *arguments: str) -> dict[str, Any]:
    completed = subprocess.run(
        [str(executable), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=RELEASE_INFO_TIMEOUT_SECONDS,
        check=False,
        env={"PATH": os.environ.get("PATH", "")},
    )
    if completed.returncode != 0:
        raise DeploymentError(
            f"{executable} {' '.join(arguments)} failed with exit {completed.returncode}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise DeploymentError(f"{executable} returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise DeploymentError(f"{executable} returned a non-object JSON value")
    return payload


def run_version(executable: Path) -> str:
    completed = subprocess.run(
        [str(executable), "--version"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=RELEASE_INFO_TIMEOUT_SECONDS,
        check=False,
        env={"PATH": os.environ.get("PATH", "")},
    )
    if completed.returncode != 0:
        raise DeploymentError(f"{executable} --version failed with exit {completed.returncode}")
    return completed.stdout.strip()


def validate_rust_release(binary: Path, expected_version: str) -> dict[str, Any]:
    binary = ensure_absolute(binary, "release binary").resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise DeploymentError(f"release binary must be an executable regular file: {binary}")
    info = run_json(binary, "release-info")
    expected = {
        "name": COMMAND_NAME,
        "version": expected_version,
        "implementation": "rust",
        "python_runtime_required": False,
        "public_tool_count": 24,
        "hidden_alias_count": 11,
        "state_schema_version": 2,
        "workflow_protocol_version": 2,
    }
    mismatches = {
        key: {"expected": value, "actual": info.get(key)}
        for key, value in expected.items()
        if info.get(key) != value
    }
    if mismatches:
        raise DeploymentError(f"release identity mismatch: {mismatches}")
    if run_version(binary) != f"mtm {expected_version}":
        raise DeploymentError("release --version output is not the compatibility command identity")
    return info


def capture_previous_entry(link: Path, rollback_root: Path) -> dict[str, Any]:
    if not link.exists() and not link.is_symlink():
        return {"kind": "missing"}
    if link.is_symlink():
        target = os.readlink(link)
        resolved = (link.parent / target).resolve() if not os.path.isabs(target) else Path(target).resolve()
        return {
            "kind": "symlink",
            "target": target,
            "resolved_target": str(resolved),
            "version": run_version(resolved) if resolved.is_file() and os.access(resolved, os.X_OK) else None,
        }
    if link.is_file():
        ensure_directory(rollback_root)
        stored = rollback_root / "previous-mtm"
        shutil.copy2(link, stored)
        os.chmod(stored, stat.S_IMODE(link.stat().st_mode))
        return {
            "kind": "file",
            "stored_path": str(stored),
            "sha256": sha256_file(stored),
            "version": run_version(stored) if os.access(stored, os.X_OK) else None,
        }
    raise DeploymentError(f"existing command entry is neither a symlink nor regular file: {link}")


def install_release(binary: Path, layout: DeploymentLayout, version: str) -> dict[str, Any]:
    validate_rust_release(binary, version)
    destination_dir = layout.releases_root / version
    ensure_directory(destination_dir, 0o755)
    destination = destination_dir / COMMAND_NAME
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        shutil.copyfile(binary, temporary)
        os.chmod(temporary, 0o755)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        fsync_directory(destination_dir)
    finally:
        temporary.unlink(missing_ok=True)
    validate_rust_release(destination, version)
    metadata = {
        "path": str(destination),
        "sha256": sha256_file(destination),
        "size_bytes": destination.stat().st_size,
        "version": version,
        "installed_at": utc_now(),
    }
    atomic_write_json(destination_dir / "release.json", metadata, 0o644)
    return metadata


def cutover(
    binary: Path,
    layout: DeploymentLayout,
    version: str,
    rollback_wheel: Path | None = None,
    *,
    replace_manifest: bool = False,
) -> dict[str, Any]:
    ensure_absolute(layout.bin_link, "command link")
    ensure_absolute(layout.state_root, "deployment state root")
    ensure_directory(layout.state_root)
    if layout.bin_link.name != COMMAND_NAME:
        raise DeploymentError(f"command link must be named {COMMAND_NAME}")
    if layout.manifest.exists() and not replace_manifest:
        raise DeploymentError(f"deployment manifest already exists: {layout.manifest}")
    release = install_release(binary, layout, version)
    previous = capture_previous_entry(layout.bin_link, layout.rollback_root)
    wheel: dict[str, Any] | None = None
    if rollback_wheel is not None:
        rollback_wheel = ensure_absolute(rollback_wheel, "rollback wheel").resolve(strict=True)
        if not rollback_wheel.is_file():
            raise DeploymentError("rollback wheel must be a regular file")
        wheel = {
            "path": str(rollback_wheel),
            "sha256": sha256_file(rollback_wheel),
            "size_bytes": rollback_wheel.stat().st_size,
        }
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "state": "rust_active",
        "command_link": str(layout.bin_link),
        "release": release,
        "previous": previous,
        "rollback_wheel": wheel,
        "history": [{"at": utc_now(), "action": "cutover", "state": "rust_active"}],
    }
    atomic_symlink(release["path"], layout.bin_link)
    verify_active_rust(layout, manifest)
    atomic_write_json(layout.manifest, manifest)
    return manifest


def load_manifest(path: Path) -> dict[str, Any]:
    path = ensure_absolute(path, "deployment manifest")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DeploymentError(f"cannot read deployment manifest: {path}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != MANIFEST_SCHEMA:
        raise DeploymentError("deployment manifest schema is invalid")
    return payload


def manifest_layout(manifest: dict[str, Any]) -> DeploymentLayout:
    link = Path(str(manifest.get("command_link") or ""))
    release_path = Path(str(manifest.get("release", {}).get("path") or ""))
    if not link.is_absolute() or not release_path.is_absolute():
        raise DeploymentError("deployment manifest contains non-absolute paths")
    try:
        state_root = release_path.parents[2]
    except IndexError as exc:
        raise DeploymentError("release path is not inside a versioned deployment root") from exc
    return DeploymentLayout(bin_link=link, state_root=state_root)


def verify_active_rust(layout: DeploymentLayout, manifest: dict[str, Any]) -> None:
    release = manifest.get("release")
    if not isinstance(release, dict):
        raise DeploymentError("deployment manifest has no release object")
    target = Path(str(release.get("path") or ""))
    version = str(release.get("version") or "")
    expected_sha = str(release.get("sha256") or "")
    if not layout.bin_link.is_symlink():
        raise DeploymentError("active command is not an atomic release symlink")
    if layout.bin_link.resolve() != target.resolve(strict=True):
        raise DeploymentError("active command does not resolve to the recorded Rust release")
    if sha256_file(target) != expected_sha:
        raise DeploymentError("active Rust release hash does not match the deployment manifest")
    validate_rust_release(target, version)


def rollback(manifest_path: Path) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    layout = manifest_layout(manifest)
    previous = manifest.get("previous")
    if not isinstance(previous, dict):
        raise DeploymentError("deployment manifest has no previous entry")
    kind = previous.get("kind")
    if kind == "symlink":
        target = str(previous.get("target") or "")
        if not target:
            raise DeploymentError("previous symlink target is missing")
        atomic_symlink(target, layout.bin_link)
    elif kind == "file":
        source = Path(str(previous.get("stored_path") or ""))
        if sha256_file(source) != previous.get("sha256"):
            raise DeploymentError("stored previous command hash mismatch")
        temporary = layout.bin_link.with_name(f".{layout.bin_link.name}.{os.getpid()}.tmp")
        try:
            shutil.copy2(source, temporary)
            os.replace(temporary, layout.bin_link)
            fsync_directory(layout.bin_link.parent)
        finally:
            temporary.unlink(missing_ok=True)
    elif kind == "missing":
        layout.bin_link.unlink(missing_ok=True)
        fsync_directory(layout.bin_link.parent)
    else:
        raise DeploymentError(f"unsupported previous command kind: {kind}")
    manifest["state"] = "previous_active"
    manifest["updated_at"] = utc_now()
    manifest.setdefault("history", []).append(
        {"at": utc_now(), "action": "rollback", "state": "previous_active"}
    )
    atomic_write_json(manifest_path, manifest)
    return manifest


def recutover(manifest_path: Path) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    layout = manifest_layout(manifest)
    release = manifest.get("release")
    if not isinstance(release, dict):
        raise DeploymentError("deployment manifest has no release object")
    atomic_symlink(str(release.get("path") or ""), layout.bin_link)
    verify_active_rust(layout, manifest)
    manifest["state"] = "rust_active"
    manifest["updated_at"] = utc_now()
    manifest.setdefault("history", []).append(
        {"at": utc_now(), "action": "recutover", "state": "rust_active"}
    )
    atomic_write_json(manifest_path, manifest)
    return manifest


def processes_using(root: Path) -> list[dict[str, Any]]:
    root = root.resolve(strict=False)
    matches: list[dict[str, Any]] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
            command = [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]
            executable = (entry / "exe").resolve()
        except (FileNotFoundError, PermissionError, OSError):
            continue
        uses_root = executable == root or root in executable.parents
        if not uses_root:
            uses_root = any(
                candidate == str(root) or candidate.startswith(str(root) + os.sep)
                for candidate in command
            )
        if uses_root:
            matches.append(
                {
                    "pid": int(entry.name),
                    "executable": str(executable),
                    "command_name": Path(command[0]).name if command else "",
                }
            )
    return sorted(matches, key=lambda item: int(item["pid"]))


def stop_processes_using(root: Path, grace_seconds: float = 8.0) -> dict[str, Any]:
    before = processes_using(root)
    for item in before:
        try:
            os.kill(int(item["pid"]), signal.SIGINT)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline and processes_using(root):
        time.sleep(0.1)
    remaining = processes_using(root)
    for item in remaining:
        try:
            os.kill(int(item["pid"]), signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and processes_using(root):
        time.sleep(0.1)
    forced = processes_using(root)
    for item in forced:
        try:
            os.kill(int(item["pid"]), signal.SIGKILL)
        except ProcessLookupError:
            pass
    return {
        "matched_before": len(before),
        "required_sigterm": len(remaining),
        "required_sigkill": len(forced),
        "remaining_after": len(processes_using(root)),
    }


def retire_python(manifest_path: Path, python_tool_root: Path) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    layout = manifest_layout(manifest)
    verify_active_rust(layout, manifest)
    wheel = manifest.get("rollback_wheel")
    if not isinstance(wheel, dict):
        raise DeploymentError("Python retirement requires a recorded rollback wheel")
    wheel_path = Path(str(wheel.get("path") or ""))
    if not wheel_path.is_file() or sha256_file(wheel_path) != wheel.get("sha256"):
        raise DeploymentError("recorded rollback wheel is missing or has changed")
    python_tool_root = ensure_absolute(python_tool_root, "Python tool root")
    active = processes_using(python_tool_root)
    if active:
        raise DeploymentError(f"Python tool root still has active processes: {len(active)}")
    if python_tool_root.exists():
        if python_tool_root.is_symlink() or not python_tool_root.is_dir():
            raise DeploymentError("Python tool root is not a real directory")
        shutil.rmtree(python_tool_root)
    manifest["python_runtime_retired"] = {
        "at": utc_now(),
        "tool_root": str(python_tool_root),
        "removed": not python_tool_root.exists(),
        "rollback_wheel_sha256": wheel["sha256"],
    }
    manifest["state"] = "rust_active_python_retired"
    manifest["updated_at"] = utc_now()
    manifest.setdefault("history", []).append(
        {"at": utc_now(), "action": "retire_python", "state": manifest["state"]}
    )
    atomic_write_json(manifest_path, manifest)
    return manifest


def public_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": manifest.get("schema"),
        "state": manifest.get("state"),
        "command_link": manifest.get("command_link"),
        "release": manifest.get("release"),
        "previous_kind": manifest.get("previous", {}).get("kind"),
        "previous_version": manifest.get("previous", {}).get("version"),
        "rollback_wheel": manifest.get("rollback_wheel"),
        "python_runtime_retired": manifest.get("python_runtime_retired"),
        "history_actions": [item.get("action") for item in manifest.get("history", [])],
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Atomic MTM-008 Re-CTM deployment manager")
    subparsers = parser.add_subparsers(dest="command", required=True)

    cutover_parser = subparsers.add_parser("cutover")
    cutover_parser.add_argument("--binary", type=Path, required=True)
    cutover_parser.add_argument("--bin-link", type=Path, required=True)
    cutover_parser.add_argument("--state-root", type=Path, required=True)
    cutover_parser.add_argument("--version", required=True)
    cutover_parser.add_argument("--rollback-wheel", type=Path)
    cutover_parser.add_argument("--replace-manifest", action="store_true")

    for name in ("rollback", "recutover", "status"):
        command_parser = subparsers.add_parser(name)
        command_parser.add_argument("--manifest", type=Path, required=True)

    retire_parser = subparsers.add_parser("retire-python")
    retire_parser.add_argument("--manifest", type=Path, required=True)
    retire_parser.add_argument("--python-tool-root", type=Path, required=True)

    stop_parser = subparsers.add_parser("stop-python-processes")
    stop_parser.add_argument("--python-tool-root", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        if arguments.command == "cutover":
            layout = DeploymentLayout(
                bin_link=arguments.bin_link,
                state_root=arguments.state_root,
            )
            result = cutover(
                arguments.binary,
                layout,
                arguments.version,
                arguments.rollback_wheel,
                replace_manifest=arguments.replace_manifest,
            )
        elif arguments.command == "rollback":
            result = rollback(arguments.manifest)
        elif arguments.command == "recutover":
            result = recutover(arguments.manifest)
        elif arguments.command == "retire-python":
            result = retire_python(arguments.manifest, arguments.python_tool_root)
        elif arguments.command == "stop-python-processes":
            print(json.dumps(stop_processes_using(arguments.python_tool_root), indent=2))
            return 0
        else:
            result = load_manifest(arguments.manifest)
        print(json.dumps({"ok": True, "deployment": public_summary(result)}, indent=2))
        return 0
    except (DeploymentError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
