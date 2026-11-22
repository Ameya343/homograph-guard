"""Run checks in an isolated worker and stream the JSON reports back.

The GUI process never parses or resolves a suspect link itself. Each batch
goes, via stdin, to one of:

* ``docker`` - the hardened ``homograph-guard`` image: read-only filesystem,
  no Linux capabilities, no privilege escalation, memory/CPU/PID limits,
  non-root user, and no network at all when DNS checks are off;
* ``local``  - a separate ``python -I`` process with the in-process sandbox
  guard installed (no subprocesses, no file writes, network only to the
  pinned DNS resolvers).

Links are passed on stdin, never on the command line, so they cannot be
mistaken for options and do not show up in process listings.
"""

from __future__ import annotations

import json
import os
import shutil
# subprocess is used with fixed argument lists only (no shell); links travel via stdin.
import subprocess  # nosec B404
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

DEFAULT_IMAGE = os.environ.get("HGUARD_IMAGE", "homograph-guard:latest")
FIREWALLED_NETWORK = "hguard-egress"  # created by sandbox/egress-firewall.sh (Linux)
MAX_LINE = 4 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_STDERR = 64 * 1024
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class WorkerError(RuntimeError):
    pass


@dataclass
class WorkerConfig:
    mode: str = "local"  # docker | local
    image: str = DEFAULT_IMAGE
    network: str | None = None  # docker network when DNS is on (default: firewalled net if present)
    dns: bool = True
    asn: bool = True
    tls_peek: bool = False
    expand: bool = True  # ask link-shortening services where short links lead
    transport: str = "doh"
    timeout: float = 4.0


def _run_quiet(cmd: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,  # nosec B603
                              creationflags=_NO_WINDOW, check=False)
    except (OSError, subprocess.SubprocessError):
        return None


def docker_status(image: str = DEFAULT_IMAGE) -> tuple[bool, str]:
    exe = shutil.which("docker")
    if not exe:
        return False, "Docker is not installed, so checks run in a guarded local process."
    res = _run_quiet([exe, "image", "inspect", "--format", "{{.Id}}", image])
    if res is None or res.returncode != 0:
        detail = (res.stderr if res else "").lower()
        if "permission denied" in detail:
            return False, "Docker needs permission (add your user to the docker group). Using a guarded local process."
        if "cannot connect" in detail or "daemon" in detail or res is None:
            return False, "Docker is not running, so checks run in a guarded local process."
        return False, f"Docker image {image} is not built yet (docker build -t {image} .). Using a guarded local process."
    return True, "Docker sandbox ready"


def firewalled_network_exists() -> bool:
    exe = shutil.which("docker")
    if not exe:
        return False
    res = _run_quiet([exe, "network", "inspect", FIREWALLED_NETWORK], timeout=8)
    return bool(res and res.returncode == 0)


INPUT_FORMATS = ("eml", "html", "text")


def build_command(cfg: WorkerConfig, input_format: str | None = None) -> list[str]:
    """``input_format`` (eml/html/text) makes the worker extract links from stdin itself."""
    if input_format and input_format not in INPUT_FORMATS:
        raise ValueError(f"unknown input format {input_format!r}")
    source = [f"--{input_format}", "-"] if input_format else ["--stdin"]
    args = ["--jsonl", *source, "--no-color", "--transport", cfg.transport, "--timeout", str(cfg.timeout)]
    if not cfg.dns:
        args.append("--no-dns")
    if not cfg.asn:
        args.append("--no-asn")
    if cfg.tls_peek:
        args.append("--tls-peek")
    if not cfg.expand:
        args.append("--no-expand")
    if cfg.mode == "docker":
        exe = shutil.which("docker") or "docker"
        # "/tmp" below is a tmpfs inside the container, not a host temp file.
        cmd = [exe, "run", "--rm", "-i", "--read-only",  # nosec B108
               "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=8m",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
               "--pids-limit", "64", "--memory", "256m", "--memory-swap", "256m", "--cpus", "1",
               "--user", "10001:10001"]
        if cfg.dns:
            network = cfg.network or (FIREWALLED_NETWORK if firewalled_network_exists() else "bridge")
            cmd += ["--network", network, "--dns", "127.0.0.1"]  # the app never uses the system resolver
        else:
            cmd += ["--network", "none"]
        return [*cmd, cfg.image, *args]
    if getattr(sys, "frozen", False):
        # Installed app: the bundled command-line program (its Python ignores PYTHON* variables).
        return [str(Path(sys.executable).with_name("homograph-guard.exe")), *args]
    entry = Path(__file__).resolve().parent.parent / "_entry.py"
    return [sys.executable, "-I", "-B", str(entry), *args]


def run_batch(cfg: WorkerConfig, targets: list[str], on_report=None, holder: dict | None = None,
              timeout: float | None = None, payload: bytes | None = None,
              input_format: str | None = None) -> list[dict]:
    """Run one batch; ``on_report`` is called for every report as it arrives.

    Pass ``payload`` (raw bytes of an email, page or chat export) with ``input_format``
    to let the worker find the links: the untrusted document is parsed only inside it.
    """
    cmd = build_command(cfg, input_format if payload is not None else None)
    expected = len(targets) if payload is None else 200
    budget = timeout or min(900.0, 30.0 + expected * (cfg.timeout * 4 + 2))
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,  # nosec B603
                                stderr=subprocess.PIPE, creationflags=_NO_WINDOW)
    except OSError as exc:
        raise WorkerError(f"could not start the worker: {exc}") from exc
    if holder is not None:
        holder["proc"] = proc
    err_chunks: list[bytes] = []

    def drain_stderr() -> None:
        size = 0
        for chunk in iter(lambda: proc.stderr.read(4096), b""):
            if size < MAX_STDERR:
                err_chunks.append(chunk)
            size += len(chunk)

    drainer = threading.Thread(target=drain_stderr, daemon=True)
    drainer.start()
    timer = threading.Timer(budget, proc.kill)
    timer.start()
    reports: list[dict] = []
    try:
        try:
            proc.stdin.write(payload if payload is not None else "\n".join(targets).encode("utf-8") + b"\n")
            proc.stdin.close()
        except OSError:
            pass
        total = 0
        for raw in iter(lambda: proc.stdout.readline(MAX_LINE), b""):
            total += len(raw)
            if total > MAX_TOTAL:
                proc.kill()
                raise WorkerError("worker produced more output than expected; stopped it")
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            try:
                rep = json.loads(line)
            except ValueError:
                continue
            if isinstance(rep, dict):
                reports.append(rep)
                if on_report:
                    on_report(rep)
        proc.wait(timeout=10)
    finally:
        timer.cancel()
        if holder is not None:
            holder.pop("proc", None)
        if proc.poll() is None:  # an error above left the worker running
            proc.kill()
            proc.wait(timeout=10)
        drainer.join(timeout=5)
        proc.stdout.close()
        proc.stderr.close()
    stderr = b"".join(err_chunks).decode("utf-8", "replace").strip()
    if proc.returncode not in (0, 3, 4) and not reports:
        tail = stderr.splitlines()[-1] if stderr else f"exit code {proc.returncode}"
        raise WorkerError(f"the worker failed: {tail[:300]}")
    return reports
