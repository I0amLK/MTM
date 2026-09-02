from __future__ import annotations

import base64
import hashlib
import http.client
import json
import math
import os
import random
import signal
import socket
import statistics
import subprocess
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT.parent / "Re-CTM"
RUST_BINARY = ROOT / "target" / "release" / "mtm"
TOKEN_SECRET = "61" * 32
CAPABILITY_SECRET = "62" * 32
OPERATOR_PASSWORD = "mtm008-benchmark-operator"


def cargo_environment() -> dict[str, str]:
    environment = os.environ.copy()
    cargo_home = ROOT / ".toolchain" / "cargo"
    rustup_home = ROOT / ".toolchain" / "rustup"
    toolchain_bin = rustup_home / "toolchains" / "1.98.0-x86_64-unknown-linux-gnu" / "bin"
    environment["CARGO_HOME"] = str(cargo_home)
    environment["RUSTUP_HOME"] = str(rustup_home)
    environment["PATH"] = os.pathsep.join(
        [str(toolchain_bin), str(cargo_home / "bin"), environment.get("PATH", "")]
    )
    return environment


def build_release() -> None:
    cargo = (
        ROOT
        / ".toolchain"
        / "rustup"
        / "toolchains"
        / "1.98.0-x86_64-unknown-linux-gnu"
        / "bin"
        / "cargo"
    )
    subprocess.run(
        [str(cargo), "build", "--release", "--locked", "-p", "mtm-cli"],
        cwd=ROOT,
        env=cargo_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=600,
        check=True,
    )


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_port(port: int, process: subprocess.Popen[str], timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stderr = process.stderr.read() if process.stderr is not None else ""
            raise RuntimeError(f"server exited during startup: {stderr[-4000:]}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.02)
    raise RuntimeError(f"server did not listen on port {port}")


def prepare_workspace(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "README.txt").write_text("alpha\nbeta\ngamma\n", encoding="utf-8")
    nested = path / "nested"
    nested.mkdir(exist_ok=True)
    (nested / "note.txt").write_text("needle in nested file\n", encoding="utf-8")


def request(
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    provided = dict(headers or {})
    if body is not None:
        provided.setdefault("Content-Length", str(len(body)))
    connection.request(method, path, body=body, headers=provided)
    response = connection.getresponse()
    data = response.read()
    result_headers = {key.lower(): value for key, value in response.getheaders()}
    status = response.status
    connection.close()
    return status, result_headers, data


def json_request(
    port: int,
    method: str,
    path: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, str], dict[str, Any]]:
    encoded = json.dumps(payload, separators=(",", ":")).encode()
    provided = {"Content-Type": "application/json", **(headers or {})}
    status, response_headers, data = request(
        port,
        method,
        path,
        body=encoded,
        headers=provided,
        timeout=timeout,
    )
    try:
        decoded = json.loads(data or b"{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON response from {path}: {data[:200]!r}") from exc
    if not isinstance(decoded, dict):
        raise RuntimeError(f"non-object JSON response from {path}")
    return status, response_headers, decoded


def form_request(
    port: int,
    path: str,
    payload: dict[str, str],
) -> tuple[int, dict[str, str], bytes]:
    encoded = urllib.parse.urlencode(payload).encode()
    return request(
        port,
        "POST",
        path,
        body=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )


def oauth_token(port: int, base: str, client_name: str) -> str:
    redirect_uri = "http://127.0.0.1/mtm008-callback"
    status, _, registered = json_request(
        port,
        "POST",
        "/oauth/register",
        {
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "none",
            "client_name": client_name,
        },
    )
    if status != 201:
        raise RuntimeError(f"registration failed: {status} {registered}")
    client_id = str(registered["client_id"])
    verifier = "M" * 43
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    authorization = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": base,
        "state": "mtm008-state",
        "password": OPERATOR_PASSWORD,
    }
    status, headers, _ = form_request(port, "/oauth/authorize", authorization)
    if status not in (302, 303):
        raise RuntimeError(f"authorization failed: {status}")
    location = headers.get("location", "")
    code = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query).get("code", [""])[0]
    if not code:
        raise RuntimeError("authorization did not return a code")
    status, _, raw = form_request(
        port,
        "/oauth/token",
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
            "client_id": client_id,
            "resource": base,
        },
    )
    result = json.loads(raw or b"{}")
    if status != 200 or not isinstance(result, dict) or not result.get("access_token"):
        raise RuntimeError(f"token exchange failed: {status}")
    return str(result["access_token"])


def runtime_environment(workspace: Path, data_root: Path, kind: str = "rust") -> dict[str, str]:
    environment = os.environ.copy()
    prefix = "MTM" if kind == "rust" else "RE_CTM"
    environment.update(
        {
            f"{prefix}_WORKSPACE": str(workspace),
            f"{prefix}_DATA_ROOT": str(data_root),
            f"{prefix}_PRIVATE_ROOT": str(data_root / "private"),
            f"{prefix}_DEBUG_ROOT": str(data_root / "debug"),
            f"{prefix}_NATIVE_EXEC_BACKEND": "disabled",
            f"{prefix}_NATIVE_MODE": "safe",
            f"{prefix}_LATEX_POLICY": "static_only",
            f"{prefix}_OAUTH_PASSWORD": OPERATOR_PASSWORD,
            f"{prefix}_TOKEN_SECRET": TOKEN_SECRET,
            f"{prefix}_CAPABILITY_SECRET": CAPABILITY_SECRET,
            f"{prefix}_SERVER_URL": "",
            f"{prefix}_DEBUG": "0",
        }
    )
    return environment


class RuntimeServer:
    def __init__(
        self,
        kind: str,
        workspace: Path,
        data_root: Path,
        *,
        authenticate: bool = True,
    ) -> None:
        self.kind = kind
        self.workspace = workspace
        self.data_root = data_root
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        environment = runtime_environment(workspace, data_root, kind)
        if kind == "rust":
            command = [
                str(RUST_BINARY),
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--workspace",
                str(workspace),
                "--native-mode",
                "safe",
                "--latex-policy",
                "static_only",
            ]
            cwd = ROOT
        elif kind == "python":
            environment["PYTHONPATH"] = str(SOURCE_ROOT / "src")
            command = [
                sys_executable(),
                "-m",
                "re_ctm",
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--workspace",
                str(workspace),
                "--native-mode",
                "safe",
                "--latex-policy",
                "static_only",
            ]
            cwd = SOURCE_ROOT
        else:
            raise ValueError(kind)
        started = time.perf_counter_ns()
        self.process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        wait_for_port(self.port, self.process)
        self.startup_ms = (time.perf_counter_ns() - started) / 1_000_000
        self.token = (
            oauth_token(self.port, self.base, f"MTM-008 {kind} benchmark")
            if authenticate
            else ""
        )

    @property
    def pid(self) -> int:
        return self.process.pid

    def auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def rpc(self, payload: dict[str, Any], timeout: float = 10.0) -> dict[str, Any]:
        status, _, response = json_request(
            self.port,
            "POST",
            "/mcp",
            payload,
            headers=self.auth_headers(),
            timeout=timeout,
        )
        if status != 200:
            raise RuntimeError(f"{self.kind} MCP status {status}: {response}")
        if response.get("error"):
            raise RuntimeError(f"{self.kind} MCP error: {response['error']}")
        return response

    def call(self, name: str, arguments: dict[str, Any], request_id: str) -> dict[str, Any]:
        return self.rpc(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )

    def close(self, *, graceful: bool = True) -> dict[str, Any]:
        started = time.perf_counter_ns()
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT if graceful else signal.SIGTERM)
        forced = False
        try:
            code = self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            forced = True
            self.process.kill()
            code = self.process.wait(timeout=3)
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        stdout = self.process.stdout.read() if self.process.stdout is not None else ""
        stderr = self.process.stderr.read() if self.process.stderr is not None else ""
        return {
            "exit_code": code,
            "forced": forced,
            "elapsed_ms": round(elapsed_ms, 3),
            "stdout_bytes": len(stdout.encode()),
            "stderr_bytes": len(stderr.encode()),
        }


def sys_executable() -> str:
    return os.environ.get("PYTHON", "python3")


@dataclass(frozen=True)
class ProcessSample:
    elapsed_seconds: float
    rss_kib: int
    threads: int
    file_descriptors: int
    children: int


def process_sample(pid: int, started: float) -> ProcessSample | None:
    process_root = Path("/proc") / str(pid)
    try:
        status = (process_root / "status").read_text(encoding="utf-8")
        rss = 0
        threads = 0
        for line in status.splitlines():
            if line.startswith("VmRSS:"):
                rss = int(line.split()[1])
            elif line.startswith("Threads:"):
                threads = int(line.split()[1])
        fds = sum(1 for _ in (process_root / "fd").iterdir())
        children_file = process_root / "task" / str(pid) / "children"
        children = len(children_file.read_text(encoding="utf-8").split())
        return ProcessSample(time.monotonic() - started, rss, threads, fds, children)
    except (FileNotFoundError, PermissionError, OSError, ValueError):
        return None


class ProcessSampler:
    def __init__(self, pid: int, interval_seconds: float = 0.02) -> None:
        self.pid = pid
        self.interval_seconds = interval_seconds
        self.samples: list[ProcessSample] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started = time.monotonic()

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("sampler already started")
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            sample = process_sample(self.pid, self._started)
            if sample is not None:
                self.samples.append(sample)
            self._stop.wait(self.interval_seconds)

    def stop(self) -> list[ProcessSample]:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        sample = process_sample(self.pid, self._started)
        if sample is not None:
            self.samples.append(sample)
        return list(self.samples)


def percentile(values: Sequence[float], percent: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * percent / 100.0
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return float(ordered[lower] * (1 - weight) + ordered[upper] * weight)


def summarize(values: Sequence[float]) -> dict[str, float | int]:
    if not values:
        return {"count": 0, "median": 0.0, "p95": 0.0, "p99": 0.0, "mean": 0.0, "stdev": 0.0}
    return {
        "count": len(values),
        "median": round(statistics.median(values), 6),
        "p95": round(percentile(values, 95), 6),
        "p99": round(percentile(values, 99), 6),
        "mean": round(statistics.fmean(values), 6),
        "stdev": round(statistics.stdev(values), 6) if len(values) > 1 else 0.0,
    }


def bootstrap_ci(
    values: Sequence[float],
    statistic: Callable[[Sequence[float]], float] = statistics.median,
    *,
    samples: int = 2000,
    seed: int = 20260901,
) -> dict[str, float]:
    if not values:
        return {"lower_95": 0.0, "upper_95": 0.0}
    generator = random.Random(seed)
    observed = list(values)
    estimates = [
        statistic([generator.choice(observed) for _ in observed]) for _ in range(samples)
    ]
    return {
        "lower_95": round(percentile(estimates, 2.5), 6),
        "upper_95": round(percentile(estimates, 97.5), 6),
    }


def cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


def linear_slope(samples: Iterable[tuple[float, float]]) -> float:
    points = list(samples)
    if len(points) < 2:
        return 0.0
    mean_x = statistics.fmean(point[0] for point in points)
    mean_y = statistics.fmean(point[1] for point in points)
    denominator = sum((x - mean_x) ** 2 for x, _ in points)
    if denominator == 0:
        return 0.0
    return sum((x - mean_x) * (y - mean_y) for x, y in points) / denominator
