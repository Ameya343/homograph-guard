"""In-process sandbox guard built on Python audit hooks (PEP 578).

Once installed it cannot be removed for the life of the process. It blocks:

* process creation (subprocess, os.system, exec*, spawn*, fork, pty),
* native code loading (ctypes),
* every network connection except to allow-listed (ip, port, proto) tuples,
* resolving hostnames through the system resolver (only IP literals pass),
* opening files for writing, except paths explicitly allowed,
* web browsers and urllib/ftplib/smtplib/... clients.

Purpose: if a bug, a parser quirk or a compromised dependency ever tried to
*act* on attacker-controlled input - fetch the URL, run a helper, write a
file - the attempt fails loudly instead of happening silently.

Audit hooks are a guardrail, not a security boundary: code that is already
running inside the interpreter could find ways around them. The real
boundary is the container (read-only filesystem, no capabilities, no new
privileges, egress firewall) described in ``sandbox/``.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import sys
import threading


class SandboxViolation(PermissionError):
    """Raised when guarded code attempts a forbidden action."""


_BLOCKED_EVENTS = frozenset(
    {
        # process creation
        "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork",
        "os.forkpty", "os.startfile", "pty.spawn",
        # native code
        "ctypes.dlopen", "ctypes.dlsym", "ctypes.call_function", "ctypes.cdata",
        "ctypes.addressof", "ctypes.string_at", "ctypes.wstring_at", "ctypes.set_errno",
        # other network clients / browsers
        "webbrowser.open", "urllib.Request", "http.client.connect", "ftplib.connect",
        "smtplib.connect", "poplib.connect", "imaplib.open", "nntplib.connect",
        "telnetlib.Telnet.open",
        # filesystem changes
        "os.remove", "os.rmdir", "os.rename", "os.symlink", "os.link", "os.chmod", "os.chown",
        "os.truncate", "os.mkdir", "os.utime", "os.chflags", "os.lchflags", "os.setxattr",
        "os.removexattr", "shutil.rmtree", "shutil.move", "shutil.copyfile", "shutil.copytree",
        "shutil.chown", "shutil.make_archive", "shutil.unpack_archive",
        # signals / identity / tampering
        "os.kill", "os.killpg", "signal.pthread_kill", "socket.sethostname", "sys.addaudithook",
        "socket.gethostbyname", "socket.gethostbyaddr", "socket.getnameinfo",
        # SQLite extensions are native code
        "sqlite3.enable_load_extension", "sqlite3.load_extension",
    }
)
# Only the feed updater may use HTTP clients, and only towards allow-listed hosts.
_HTTP_CLIENT_EVENTS = frozenset({"urllib.Request", "http.client.connect"})
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC


class _Policy:
    def __init__(self) -> None:
        self.endpoints: set[tuple[str, int, str]] = set()
        self.write_paths: set[str] = set()
        self.sqlite_paths: set[str] = set()
        self.dns_names: set[str] = set()  # hostnames the system resolver may look up (updater)
        self.tcp_any_ports: set[int] = set()  # TCP ports reachable on any address (updater: 443, proxy)
        self.http_clients = False
        self.lock = threading.Lock()
        self.violations: list[str] = []


_policy = _Policy()
_installed = False


def _norm_ip(host: object) -> str | None:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return None
    try:
        ip = ipaddress.ip_address(host.strip("[]").split("%", 1)[0])
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def installed() -> bool:
    return _installed


def allow_endpoint(ip: str, port: int, proto: str = "tcp") -> None:
    norm = _norm_ip(ip)
    if norm is None:
        raise ValueError(f"not an IP address: {ip!r}")
    with _policy.lock:
        _policy.endpoints.add((norm, int(port), proto))


def _deny(what: str) -> None:
    msg = f"sandbox: {what} is not allowed"
    with _policy.lock:
        if len(_policy.violations) < 100:
            _policy.violations.append(msg)
    raise SandboxViolation(msg)


def violations() -> list[str]:
    with _policy.lock:
        return list(_policy.violations)


def _check_address(sock: object, address: object, default_proto: str) -> None:
    if address is None:
        return
    if not isinstance(address, tuple) or len(address) < 2:
        _deny(f"connecting to {str(address)[:80]!r}")
    stype = getattr(sock, "type", None)
    proto = "udp" if stype == socket.SOCK_DGRAM else ("tcp" if stype == socket.SOCK_STREAM else default_proto)
    ip = _norm_ip(address[0])
    try:
        port = int(address[1])
    except (TypeError, ValueError):
        port = -1
    if ip is not None and proto == "tcp" and port in _policy.tcp_any_ports:
        return
    if ip is None or (ip, port, proto) not in _policy.endpoints:
        _deny(f"network access to {str(address[0])[:80]}:{port}/{proto}")


def _real(path: object) -> str:
    try:
        return os.path.realpath(os.fsdecode(path))
    except (TypeError, ValueError):
        return str(path)


def _hook(event: str, args: tuple) -> None:
    if event in _HTTP_CLIENT_EVENTS:
        if not _policy.http_clients:
            _deny(f"'{event}'")
        return
    if event == "os.rename":
        # Atomic saves (write a temp file, then replace) are allowed between allow-listed paths only.
        if len(args) >= 2 and all(_real(p) in _policy.write_paths for p in args[:2]):
            return
        _deny(f"'{event}'")
    if event in _BLOCKED_EVENTS:
        _deny(f"'{event}'")
    if event == "sqlite3.connect":
        db = args[0] if args else None
        if db in (":memory:", b":memory:") or _real(db) in _policy.sqlite_paths:
            return
        _deny(f"opening database {str(db)[:120]!r}")
    if event == "open":
        path, mode, flags = (tuple(args) + (None, None, None))[:3]
        if isinstance(path, int):
            return
        writing = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
            isinstance(flags, int) and bool(flags & _WRITE_FLAGS)
        )
        if writing:
            try:
                real = os.path.realpath(os.fsdecode(path))
            except (TypeError, ValueError):
                real = str(path)
            if real not in _policy.write_paths:
                _deny(f"writing to {real[:120]!r}")
        return
    if not event.startswith("socket."):
        return
    if event == "socket.__new__":
        family, stype = args[1], args[2]
        if family not in (socket.AF_INET, socket.AF_INET6):
            _deny(f"socket family {family}")
        if isinstance(stype, int) and (stype & 0xF) == socket.SOCK_RAW:
            _deny("raw sockets")
    elif event == "socket.connect":
        _check_address(args[0], args[1], "tcp")
    elif event in ("socket.sendto", "socket.sendmsg"):
        _check_address(args[0], args[1] if len(args) > 1 else None, "udp")
    elif event == "socket.bind":
        address = args[1]
        if not (isinstance(address, tuple) and len(address) >= 2 and address[1] == 0):
            _deny(f"binding {str(address)[:80]}")
    elif event == "socket.getaddrinfo":
        host = args[0]
        if isinstance(host, bytes):
            host = host.decode("ascii", "replace")
        if host is not None and _norm_ip(host) is None and str(host).lower().rstrip(".") not in _policy.dns_names:
            _deny(f"system DNS lookup of {str(host)[:80]!r}")


def install(endpoints: tuple[tuple[str, int, str], ...] | list = (), write_paths: tuple[str, ...] | list = (),
            sqlite_paths: tuple[str, ...] | list = (), dns_names: tuple[str, ...] | list = (),
            tcp_any_ports: tuple[int, ...] | list = (), http_clients: bool = False) -> None:
    """Install the guard (idempotent; later calls only extend the allowlist).

    ``sqlite_paths`` are the only databases that may be opened. ``dns_names``,
    ``tcp_any_ports`` and ``http_clients`` exist for the feed updater, which must
    resolve and reach the (allow-listed) feed servers over HTTPS.
    """
    global _installed
    for ep in endpoints:
        allow_endpoint(*ep)
    with _policy.lock:
        for p in write_paths:
            _policy.write_paths.add(os.path.realpath(p))
        for p in sqlite_paths:
            _policy.sqlite_paths.add(os.path.realpath(p))
        _policy.dns_names.update(n.lower().rstrip(".") for n in dns_names)
        _policy.tcp_any_ports.update(int(p) for p in tcp_any_ports)
        _policy.http_clients = _policy.http_clients or http_clients
    if _installed:
        return
    sys.dont_write_bytecode = True
    sys.addaudithook(_hook)
    _installed = True
