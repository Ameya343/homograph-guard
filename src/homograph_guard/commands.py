"""Database, list and setup commands of the command-line tool.

    homograph-guard update                     # refresh the threat database (daily task)
    homograph-guard db status
    homograph-guard allow add example.com --note "our supplier"
    homograph-guard block add https://evil.example/login
    homograph-guard report add https://phish.example/x
    homograph-guard allow list | block list | report list
    homograph-guard lists export my-lists.json | lists import my-lists.json
    homograph-guard settings show | settings set dns_mode suspicious
    homograph-guard native-host install [--browser chrome edge firefox] [--machine]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

from . import guard, paths
from . import settings as settings_mod
from .textsafe import safe_text

COMMANDS = ("update", "db", "allow", "block", "report", "lists", "settings", "native-host", "setup")


def _db_guard(extra_writes: list[str] | None = None) -> None:
    from .threatdb import backup_files

    paths.ensure_data_dir()  # the sandbox below forbids creating it (first use, before any update)
    guard.install(write_paths=[str(paths.settings_path()), str(paths.settings_path()) + ".tmp",
                               *(str(p) for p in backup_files(paths.db_path())), *(extra_writes or [])],
                  sqlite_paths=[str(p) for p in paths.db_files()])


def _open_db():
    from .threatdb import ThreatDB

    paths.ensure_data_dir()
    return ThreatDB(paths.db_path())


def cmd_update(args) -> int:
    from . import feeds

    exe = Path(sys.executable)
    if getattr(sys, "frozen", False) and exe.name.lower() == "homograph-guard.exe" and exe.with_name("hg-update.exe").exists():
        # Installed app: the firewall lets only the updater download feeds, so hand over to it.
        import subprocess  # nosec B404 - our own program, fixed arguments

        passthrough = [*(["--force"] if args.force else []), *(f"--feed={f}" for f in args.feed or [])]
        print("Updating the threat database (this can take a minute)...", flush=True)
        rc = subprocess.run([str(exe.with_name("hg-update.exe")), *passthrough], check=False).returncode  # nosec B603
        args.json = False
        cmd_db(args)
        return rc

    from .threatdb import ensure_healthy

    paths.ensure_data_dir()
    # A power cut or a failing disk can damage the file: check every page, rebuild it (keeping the
    # user's lists) if needed. Before the sandbox, which forbids setting the damaged file aside.
    repaired = ensure_healthy(paths.db_path(), thorough=True)
    if repaired:
        print(repaired, flush=True)
    s = settings_mod.load()
    if args.cafile:
        s.cafile = args.cafile
    if args.proxy:
        s.proxy = settings_mod._validate("proxy", args.proxy, from_policy=False)
    hosts = feeds.allowed_hosts(s)
    ports = {443} | {urlsplit(feeds.feed_url(f, s)).port or 443 for f in feeds.FEEDS}  # an organisation mirror may use its own port
    proxy = s.proxy or feeds.urllib.request.getproxies().get("https")
    if proxy:
        p = urlsplit(proxy if "://" in proxy else "http://" + proxy)
        if p.hostname:
            hosts.add(p.hostname.lower())
            ports.add(p.port or 8080)
    # The updater may resolve and reach only the feed servers (or the proxy), over HTTPS.
    guard.install(sqlite_paths=[str(p) for p in paths.db_files()], dns_names=sorted(hosts), tcp_any_ports=sorted(ports),
                  http_clients=True)
    db = _open_db()
    only = args.feed or None
    if args.if_due:
        # Only what is due: feeds older than 20 hours, never downloaded, or whose last attempt was
        # cut off or failed (retried with a growing pause). An interrupted update resumes here.
        due = [n for n in feeds.due_feeds(db, s) if not only or n in only]
        if not due:
            if not args.quiet:
                print("The threat database is up to date; nothing to do.")
            return 0
        only = due

    def progress(feed):
        if not args.quiet:
            print(f"  downloading {feed.title} ...", flush=True)

    results = feeds.update(db, s, only=only, force=args.force, progress=progress)
    failed = [r for r in results if r.status == "failed"]
    if not args.quiet or failed:
        for r in results:
            extra = f"{r.domains} domains, {r.urls} links" if r.status == "updated" else r.detail
            print(f"{r.name:<16} {r.status:<10} {safe_text(extra, 200)}")
    st = db.status()
    if not args.quiet:
        print(f"\nDatabase: {st['domains']} domains and {st['urls']} links from {len(st['feeds'])} feeds.")
    return 1 if failed and len(failed) == len([r for r in results if r.status != "disabled"]) else 0


def cmd_db(args) -> int:
    _db_guard()
    st = _open_db().status()
    if args.json:
        print(json.dumps(st, indent=2))
        return 0
    when = st["updated"] or "never"
    print(f"Threat database on this device - last update: {when}")
    print(f"  {st['domains']} domains, {st['urls']} links; your lists: {st['allow']} allowed, {st['block']} blocked, "
          f"{st['reported']} reported")
    for f in st["feeds"]:
        state = f["status"] + (f" ({safe_text(f['error'], 120)})" if f["error"] else "")
        print(f"  {f['name']:<16} {f['domains'] or 0:>8} domains {f['urls'] or 0:>7} links  {state}")
    return 0


def cmd_list(args) -> int:
    _db_guard()
    db = _open_db()
    kind = args.command
    if args.action == "list":
        rows = db.reports() if kind == "report" else db.entries(kind)
        for r in rows:
            value = r.get("url") or r.get("value")
            print(f"{safe_text(value, 300)}" + (f"    # {safe_text(r['note'], 120)}" if r.get("note") else ""))
        if not rows:
            print(f"(the {kind} list is empty)")
        return 0
    if not args.entry:
        raise SystemExit(f"{kind} {args.action}: give a domain or link")
    try:
        if kind == "report":
            if args.action == "add":
                print(f"reported {db.report(args.entry, args.note or '')}")
            else:
                print("removed" if db.unreport(args.entry) else "not on the list")
        elif args.action == "add":
            m, v = db.add_entry(kind, args.entry, args.note or "")
            print(f"added {m} {v} to the {kind}list")
        else:
            print("removed" if db.remove_entry(kind, args.entry) else "not on the list")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def cmd_lists(args) -> int:
    _db_guard([args.file] if args.action == "export" else [])
    db = _open_db()
    if args.action == "export":
        with open(args.file, "w", encoding="utf-8") as fh:
            json.dump(db.export_lists(), fh, indent=2)
        print(f"exported to {args.file}")
        return 0
    with open(args.file, encoding="utf-8-sig") as fh:
        if fh.seek(0, 2) > 16 * 1024 * 1024:
            raise SystemExit("file is too large")
        fh.seek(0)
        n = db.import_lists(json.load(fh))
    print(f"imported {n} entries")
    return 0


def cmd_settings(args) -> int:
    paths.ensure_data_dir()
    _db_guard()
    if args.action == "set":
        try:
            s = settings_mod.set_value(args.key, args.value)
        except (ValueError, PermissionError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    else:
        s = settings_mod.load()
    print(f"dns_mode     {s.dns_mode}   ({settings_mod.DNS_MODE_HELP[s.dns_mode]})")
    print(f"short_links  {s.short_links}   ({settings_mod.SHORT_LINK_HELP[s.short_links]})")
    print(f"proxy        {s.proxy or 'system settings'}")
    print(f"cafile       {s.cafile or '-'}")
    if s.locked:
        print(f"set by your organisation: {', '.join(sorted(s.locked))}")
    return 0


def cmd_native_host(args) -> int:
    from . import native_install

    browsers = args.browser or list(native_install.BROWSERS)
    try:
        if args.action == "install":
            done = native_install.register(browsers, machine=args.machine, extra_ids=tuple(args.extension_id or ()))
            print(f"registered for: {', '.join(done)}")
            skipped = [b for b in browsers if b not in done]
            if skipped:
                print(f"not registered for every user (the browser has no system-wide folder): {', '.join(skipped)}")
        elif args.action == "uninstall":
            done = native_install.unregister(browsers, machine=args.machine)
            print(f"removed from: {', '.join(done) or 'nothing was registered'}")
    except PermissionError as exc:
        where = "administrator" if sys.platform == "win32" else "root"
        print(f"error: {exc.filename or exc}: --machine needs {where} rights", file=sys.stderr)
        return 2
    else:
        for b, where in native_install.registered(args.machine).items():
            print(f"{b:<8} {'registered' if where else 'not registered'}")
    return 0


def cmd_setup(args) -> int:
    from . import schedule, winsetup

    if args.install_dir:
        install_dir = Path(args.install_dir)
    elif getattr(sys, "frozen", False):
        install_dir = Path(sys.executable).parent
    else:
        install_dir = None
    if args.what == "schedule":
        s = settings_mod.load()
        if args.hour is None:
            args.hour = s.update_hour  # the organisation's choice, or 9
        elif "update_hour" in s.locked and args.hour != s.update_hour:
            raise SystemExit(f"your organisation's policy fixes the daily run at {s.update_hour:02d}:00")
        if not 0 <= args.hour <= 23:
            raise SystemExit("--hour must be between 0 and 23")
        if args.action == "install":
            err = schedule.install(install_dir, args.hour)
            print(err or f"daily update created ({schedule.describe()}, around {args.hour:02d}:00)")
            return 1 if err else 0
        if args.action == "uninstall":
            print("removed" if schedule.uninstall() else "no daily update to remove")
            return 0
        if args.action == "show":
            print(f"# command: {schedule.display(schedule.update_argv(install_dir))}")
            for where, text in schedule.preview(install_dir, args.hour).items():
                print(f"\n# {where}\n{text.rstrip()}")
            return 0
        print(schedule.status() or "no daily update")
        return 0
    if sys.platform != "win32":
        print("firewall rules are part of the Windows installer; for macOS and Linux see ENTERPRISE.md", file=sys.stderr)
        return 2
    if args.action in ("install", "show") and install_dir is None:
        raise SystemExit("setup firewall: give --install-dir (the folder with the Homograph Guard programs)")
    if args.action == "show":
        from .winsetup import firewall_rules, netsh_add

        for rule in firewall_rules(install_dir, tuple(args.updater_port or ())):
            print(" ".join(netsh_add(rule)))
        return 0
    if args.action == "install":
        if not winsetup.is_admin():
            print("error: firewall rules need administrator rights (run from an elevated prompt)", file=sys.stderr)
            return 2
        errors = winsetup.firewall_install(install_dir, tuple(args.updater_port or ()))
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        print(f"{len(winsetup.firewall_rules(install_dir)) - len(errors)} firewall rules in place")
        return 1 if errors else 0
    if args.action == "uninstall":
        print(f"removed {winsetup.firewall_uninstall()} firewall rules")
        return 0
    present = winsetup.firewall_status()
    print("\n".join(present) if present else "no Homograph Guard firewall rules")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="homograph-guard", description="Threat database and list commands")
    sub = p.add_subparsers(dest="command", required=True)
    u = sub.add_parser("update", help="download the threat feeds into the database on this device")
    u.add_argument("--force", action="store_true", help="re-import even if a feed did not change")
    u.add_argument("--if-due", action="store_true", help="only if the last update is older than 20 hours")
    u.add_argument("--feed", action="append", help="update only this feed (repeatable)")
    u.add_argument("--cafile", help="extra CA bundle (corporate TLS inspection)")
    u.add_argument("--proxy", help="HTTPS proxy, e.g. http://proxy.example:8080 (default: system settings)")
    u.add_argument("--quiet", action="store_true")
    d = sub.add_parser("db", help="show the database status")
    d.add_argument("action", nargs="?", default="status", choices=["status"])
    d.add_argument("--json", action="store_true")
    for name, what in (("allow", "your allowlist"), ("block", "your blocklist"), ("report", "links you reported as phishing")):
        lp = sub.add_parser(name, help=f"manage {what}")
        lp.add_argument("action", choices=["add", "remove", "list"])
        lp.add_argument("entry", nargs="?")
        lp.add_argument("--note")
    lx = sub.add_parser("lists", help="export or import your lists")
    lx.add_argument("action", choices=["export", "import"])
    lx.add_argument("file")
    st = sub.add_parser("settings", help="show or change settings")
    st.add_argument("action", nargs="?", default="show", choices=["show", "set"])
    st.add_argument("key", nargs="?", choices=list(settings_mod.USER_KEYS))
    st.add_argument("value", nargs="?")
    nh = sub.add_parser("native-host", help="register the browser helper with Chrome, Edge, Brave, Chromium and Firefox")
    nh.add_argument("action", choices=["install", "uninstall", "status"])
    nh.add_argument("--browser", nargs="+", choices=["chrome", "edge", "brave", "chromium", "firefox"])
    nh.add_argument("--machine", action="store_true", help="for all users (needs administrator/root rights)")
    nh.add_argument("--extension-id", nargs="+", help="also allow these extension IDs (e.g. a store build)")
    su = sub.add_parser("setup", help="daily database update (Windows, macOS, Linux) and firewall rules (Windows)")
    su.add_argument("what", choices=["schedule", "firewall"])
    su.add_argument("action", choices=["install", "uninstall", "status", "show"])
    su.add_argument("--install-dir", help="folder with the Homograph Guard programs")
    su.add_argument("--hour", type=int, help="daily update time (hour, 0-23; default: the policy's update_hour, else 9)")
    su.add_argument("--updater-port", type=int, action="append", help="extra proxy port the updater may use")
    return p


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "settings" and args.action == "set":
        if not args.key or args.value is None:
            raise SystemExit("settings set KEY VALUE")
        if args.key == "feeds":
            args.value = json.loads(args.value)
    handler = {"update": cmd_update, "db": cmd_db, "allow": cmd_list, "block": cmd_list, "report": cmd_list,
               "lists": cmd_lists, "settings": cmd_settings, "native-host": cmd_native_host,
               "setup": cmd_setup}[args.command]
    return handler(args)
