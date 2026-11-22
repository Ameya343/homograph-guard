"""Command-line interface.

    homograph-guard https://xn--80ak6aa92e.com
    homograph-guard --no-dns "pаypal.com"            # fully offline
    homograph-guard --json -f urls.txt > report.json
    echo "PayPal <service@paypa1.com>" | homograph-guard --stdin
    homograph-guard --eml suspicious.eml             # every link in a message, hidden ones too
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__, guard
from . import paths
from . import settings as settings_mod
from .analyzer import Analyzer, Options
from .brands import BrandIndex, default_domains, normalize_domain, read_domain_file
from .commands import COMMANDS
from .commands import main as commands_main
from .dns_check import DnsInvestigator
from .dns_resolvers import CATALOG, DEFAULT_RESOLVERS, select
from .dns_transport import TRANSPORTS, DnsClient
from .extract import extract_eml, extract_html, extract_text
from .report import render_text, to_json, to_jsonl
from .scoring import exit_code
from .textsafe import safe_text
from .unicode_tools import ConfusableMap

MAX_STDIN = 4 * 1024 * 1024
MAX_FILE = 16 * 1024 * 1024


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="homograph-guard",
        description="Detect IDN homograph phishing in URLs, domains and email addresses, and "
                    "compare what Google, Cloudflare and AdGuard DNS say about them. "
                    "The suspect URL is never opened.",
        epilog="Exit codes: 0 no/low indicators, 3 suspicious, 4 high risk, 1 error, 2 usage.",
    )
    p.add_argument("targets", nargs="*", help="URLs, domains or email addresses ('-' reads stdin)")
    p.add_argument("-f", "--file", action="append", default=[], metavar="FILE",
                   help="read targets from FILE, one per line ('#' starts a comment)")
    p.add_argument("--stdin", action="store_true", help="read targets from standard input")
    ex = p.add_argument_group("scan a message or page (finds hidden links and fake link text too)")
    ex.add_argument("--eml", action="append", default=[], metavar="FILE",
                    help="email message (.eml): headers, bodies and HTML/SVG attachments ('-' = stdin)")
    ex.add_argument("--html", action="append", default=[], metavar="FILE", help="saved web page or HTML mail ('-' = stdin)")
    ex.add_argument("--text", action="append", default=[], metavar="FILE",
                    help="free text such as an exported chat; every address in it is checked ('-' = stdin)")
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="JSON array output")
    fmt.add_argument("--jsonl", action="store_true", help="JSON Lines output (one report per line, for SIEMs)")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE")
    net = p.add_argument_group("network")
    net.add_argument("--no-dns", action="store_true", help="offline: static analysis only, zero network access")
    net.add_argument("--transport", choices=TRANSPORTS, default="doh",
                     help="doh (default, encrypted), dot (encrypted) or udp (plain, interceptable)")
    net.add_argument("--resolvers", default=",".join(DEFAULT_RESOLVERS),
                     help="comma list of resolver keys (see --list-resolvers)")
    net.add_argument("--list-resolvers", action="store_true", help="show the resolver catalogue and exit")
    net.add_argument("--timeout", type=float, default=4.0, help="per-query timeout in seconds (default 4)")
    net.add_argument("--no-asn", action="store_true", help="skip IP-to-ASN lookups (Team Cymru, over DNS)")
    net.add_argument("--cafile", metavar="FILE", help="extra CA bundle, e.g. for corporate TLS inspection")
    net.add_argument("--tls-peek", action="store_true",
                     help="OPT-IN: TLS handshake with the suspect server to read its certificate. "
                          "No HTTP is sent, but the server learns your IP.")
    net.add_argument("--no-expand", action="store_true",
                     help="do not ask link-shortening services (bit.ly, shorturl.at, ...) where short links lead")
    net.add_argument("--expand-in-messages", action="store_true",
                     help="also expand short links found in emails and chats. The service counts this like a "
                          "click, which the person who made the link can see - fine when scanning mail on delivery")
    br = p.add_argument_group("brands")
    br.add_argument("--brand", action="append", default=[], metavar="DOMAIN", help="add a protected domain")
    br.add_argument("--brands", action="append", default=[], metavar="FILE", help="file of protected domains")
    br.add_argument("--only-my-brands", action="store_true", help="ignore the built-in brand list")
    br.add_argument("--confusables", metavar="FILE",
                    help="official Unicode confusables.txt to extend the built-in table")
    p.add_argument("--no-db", action="store_true",
                   help="do not use the threat database and your allow/block lists on this device")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    p.add_argument("--no-guard", action="store_true",
                   help="disable the in-process sandbox guard (debugging only)")
    p.add_argument("--max-targets", type=int, default=1000, help="refuse batches larger than this")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):
            pass


def _lines(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


BOM = b"\xef\xbb\xbf"  # Windows PowerShell and Notepad prefix text with a UTF-8 byte-order mark


def _read_stdin(limit: int = MAX_STDIN) -> bytes:
    data = sys.stdin.buffer.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"standard input is larger than {limit // (1024 * 1024)} MB")
    return data.removeprefix(BOM)


def _read_bytes(path: str) -> bytes:
    if path == "-":
        return _read_stdin(MAX_FILE)
    if os.path.getsize(path) > MAX_FILE:
        raise ValueError(f"{path} is larger than {MAX_FILE // (1024 * 1024)} MB")
    with open(path, "rb") as fh:
        return fh.read().removeprefix(BOM)


Target = tuple[str, dict | None]


def _collect(args: argparse.Namespace) -> list[Target]:
    targets: list[Target] = []
    stdin_users = [x for x in (*args.eml, *args.html, *args.text) if x == "-"]
    wants_stdin = args.stdin or "-" in args.targets
    if len(stdin_users) + bool(wants_stdin) > 1:
        raise ValueError("only one input can be read from standard input")
    targets += [(t, None) for t in args.targets if t != "-"]
    for path in args.file:
        if os.path.getsize(path) > MAX_FILE:
            raise ValueError(f"{path} is larger than {MAX_FILE // (1024 * 1024)} MB")
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            targets += [(t, None) for t in _lines(fh.read())]
    if wants_stdin:
        targets += [(t, None) for t in _lines(_read_stdin().decode("utf-8", errors="replace"))]
    for path in args.eml:
        targets += [(lk.url, {**(lk.context() or {}), "medium": "email"}) for lk in extract_eml(_read_bytes(path))]
    for path in args.html:
        html = _read_bytes(path).decode("utf-8", errors="replace")
        targets += [(lk.url, lk.context()) for lk in extract_html(html, "HTML page")]
    for path in args.text:
        text = _read_bytes(path).decode("utf-8", errors="replace")
        targets += [(lk.url, lk.context()) for lk in extract_text(text, "text")]
    seen: set = set()
    unique: list[Target] = []
    for t, ctx in targets:
        key = (t, tuple(sorted((ctx or {}).items())))
        if key not in seen:
            seen.add(key)
            unique.append((t, ctx))
    return unique


def _print_resolvers() -> None:
    print(f"{'key':<21} {'filter':<7} {'IPs':<32} TLS name")
    for r in CATALOG.values():
        mark = "*" if r.key in DEFAULT_RESOLVERS else " "
        print(f"{mark}{r.key:<20} {'yes' if r.filtering else 'no':<7} {', '.join(r.ips):<32} {r.tls_host}")
    print("\n* = default. Filtering resolvers are compared with their unfiltered twin to detect blocking.")


def main(argv: list[str] | None = None) -> int:
    _utf8_stdio()
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] in COMMANDS:
        return commands_main(raw)
    parser = build_parser()
    parser.epilog = (parser.epilog or "") + "  More: homograph-guard {" + ",".join(COMMANDS) + "} --help"
    args = parser.parse_args(raw)
    if args.list_resolvers:
        _print_resolvers()
        return 0
    if args.timeout <= 0 or args.timeout > 60:
        parser.error("--timeout must be between 0 and 60 seconds")
    try:
        resolvers = [] if args.no_dns else select(args.resolvers.split(","))
    except ValueError as exc:
        parser.error(str(exc))
    if args.tls_peek and args.no_dns:
        parser.error("--tls-peek needs DNS (it never uses the system resolver)")

    client = None if args.no_dns else DnsClient(args.transport, args.timeout, args.cafile)
    use_db = not args.no_db and paths.db_path().is_file()
    if use_db:
        paths.ensure_data_dir()  # owner-only files (SQLite may add its -wal/-shm files), before the guard
    if not args.no_guard:
        # Installed before any untrusted input (messages, pages) is parsed.
        endpoints = [ep for r in resolvers for ep in client.endpoints(r)] if client else []
        guard.install(endpoints, write_paths=[args.output] if args.output else [],
                      sqlite_paths=[str(p) for p in paths.db_files()] if use_db else [])
    elif args.tls_peek or not args.no_dns:
        print("warning: sandbox guard disabled", file=sys.stderr)

    try:
        targets = _collect(args)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    if not targets:
        if args.eml or args.html or args.text:
            print("No links or sender addresses were found.", file=sys.stderr)
            return 0
        parser.error("no targets given (pass URLs, -f FILE, --stdin, --eml, --html or --text)")
    if len(targets) > args.max_targets:
        parser.error(f"{len(targets)} targets exceeds --max-targets {args.max_targets}")

    try:
        cmap = ConfusableMap.load(args.confusables)
        domains = [] if args.only_my_brands else default_domains()
        for path in args.brands:
            domains += read_domain_file(path)
        for d in args.brand:
            norm = normalize_domain(d)
            if not norm:
                parser.error(f"--brand {d!r} is not a valid domain")
            domains.append(norm)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    brands = BrandIndex(domains, cmap)
    investigator = DnsInvestigator(client, resolvers, asn=not args.no_asn) if client else None
    threatdb = None
    if use_db:
        from .threatdb import ThreatDB

        threatdb = ThreatDB(paths.db_path())
    user_settings = settings_mod.load()
    no_expand_reason = None
    if user_settings.short_links != "app":
        no_expand_reason = ("asking link-shortening services is switched off"
                            + (" by your organisation's policy" if "short_links" in user_settings.locked else "")
                            + ("; only your browser asks, when you choose \"Show where this short link leads\""
                               if user_settings.short_links == "browser" else ""))
    analyzer = Analyzer(brands, cmap, investigator,
                        Options(tls_peek=args.tls_peek, timeout=args.timeout, cafile=args.cafile,
                                expand=not args.no_expand and no_expand_reason is None,
                                expand_in_messages=args.expand_in_messages, no_expand_reason=no_expand_reason),
                        threatdb=threatdb, settings=settings_mod.load() if use_db else None)

    out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout  # noqa: SIM115 - closed in finally
    color = (not args.no_color and not args.output and "NO_COLOR" not in os.environ
             and hasattr(sys.stdout, "isatty") and sys.stdout.isatty())
    reports: list[dict] = []
    try:
        for i, (target, ctx) in enumerate(targets, 1):
            try:
                rep = analyzer.analyze(target, ctx)
            except Exception as exc:  # noqa: BLE001 - one bad input must not end the batch; fail closed
                why = f"sandbox violation: {exc}" if isinstance(exc, guard.SandboxViolation) else \
                    f"internal error ({type(exc).__name__}): {exc}"
                rep = {"input": target[:2048], "verdict": "error", "verdict_label": "ERROR", "score": 0,
                       "summary": why[:300], "error": why[:300], "findings": []}
            reports.append(rep)
            if args.jsonl:
                out.write(to_jsonl(rep) + "\n")
            elif not args.json:
                out.write(render_text(rep, color=color, index=i, total=len(targets)) + "\n")
            out.flush()
        if args.json:
            out.write(to_json(reports) + "\n")
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    finally:
        if out is not sys.stdout:
            out.close()
    for v in guard.violations():
        print(f"warning: {safe_text(v, 200)}", file=sys.stderr)
    return exit_code([r.get("verdict", "error") for r in reports])


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
