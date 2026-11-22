"""The audit-hook guard must stop everything except allow-listed DNS traffic.

Each check runs in a fresh interpreter because an installed guard cannot be removed.
"""

import json
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

PROBE = textwrap.dedent(
    """
    import json, os, socket, subprocess, sys
    sys.path.insert(0, {src!r})
    from homograph_guard import guard
    from homograph_guard.dns_resolvers import Resolver
    from homograph_guard.dns_transport import DnsClient

    r = Resolver("google", "Lab", "lab", False, ("127.0.0.11",), "google.dns.test",
                doh_port=18443, dot_port=18853, udp_port=18053)
    client = DnsClient("doh", 3, cafile={ca!r})
    guard.install(client.endpoints(r), write_paths=[{allowed!r}])
    results = {{"dns_ok": client.query(r, "allowed.example", "A").ok}}

    def denied_by_guard(exc):
        # Some stdlib code re-raises the guard's PermissionError as another type
        # (Python 3.15's ctypes turns it into AttributeError), so walk the chain.
        seen = set()
        while exc is not None and id(exc) not in seen:
            if isinstance(exc, PermissionError):
                return True
            seen.add(id(exc))
            exc = exc.__cause__ or exc.__context__
        return False

    def attempt(name, fn):
        try:
            fn()
            results[name] = "allowed"
        except Exception as exc:
            results[name] = "blocked" if denied_by_guard(exc) else "other:" + type(exc).__name__

    attempt("tcp_other_port", lambda: socket.create_connection(("127.0.0.11", 18054), 1))
    attempt("udp_other_host", lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.12", 18053)))
    attempt("system_dns", lambda: socket.getaddrinfo("example.com", 443))
    attempt("gethostbyname", lambda: socket.gethostbyname("example.com"))
    attempt("subprocess", lambda: subprocess.run(["true"]))
    attempt("os_system", lambda: os.system("true"))
    attempt("write_file", lambda: open({denied!r}, "w"))
    attempt("write_allowed", lambda: open({allowed!r}, "w").close())
    attempt("delete_file", lambda: os.remove({allowed!r}))
    attempt("urllib", lambda: __import__("urllib.request").request.urlopen("https://127.0.0.11:18443/"))
    def browser():
        if not __import__("webbrowser").open("https://example.com"):
            raise PermissionError("nothing was opened")
    attempt("webbrowser", browser)
    attempt("unix_socket", lambda: socket.socket(getattr(socket, "AF_UNIX", 1)))  # Windows lacks the constant
    attempt("listen_port", lambda: socket.socket().bind(("127.0.0.1", 18999)))
    attempt("ctypes", lambda: __import__("ctypes").CDLL("kernel32" if os.name == "nt" else None))
    called = []
    def second_hook():
        sys.addaudithook(lambda *a: called.append(a))  # silently refused by our hook
        open(__file__).close()
        if not called:
            raise PermissionError("hook was not installed")
    attempt("new_hook", second_hook)
    print(json.dumps(results))
    """
)


def test_guard_blocks_everything_but_dns(lab, tmp_path):
    script = tmp_path / "probe.py"
    script.write_text(PROBE.format(src=str(SRC), ca=str(lab.ca), allowed=str(tmp_path / "ok.txt"),
                                   denied=str(tmp_path / "nope.txt")))
    proc = subprocess.run([sys.executable, "-I", str(script)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    res = json.loads(proc.stdout.strip().splitlines()[-1])
    assert res.pop("dns_ok") is True
    assert res.pop("write_allowed") == "allowed"
    assert all(v == "blocked" for v in res.values()), json.dumps(res)
    assert not (tmp_path / "nope.txt").exists()
