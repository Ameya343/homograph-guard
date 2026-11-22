"""The threat database on this device (SQLite).

It holds:

* domains and links published by public threat-intelligence feeds (refreshed
  daily by ``feeds.update``), including links people reported as phishing;
* your own allowlist and blocklist;
* the links you reported as phishing yourself.

Lookups never leave the device. A domain entry also covers its sub-domains
(``evil.example`` matches ``login.evil.example``); a link entry also covers longer
links under it (``https://evil.example/login`` matches ``.../login?step=2``).

Interruptions (power cuts, shutdowns, forced restarts) cannot leave it half-written:
every change is one SQLite transaction in WAL mode with full fsync. Your lists are also
kept in ``lists-backup.json`` next to the database, so ``ensure_healthy`` can rebuild a
damaged database without losing them.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import sqlite3
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .brands import normalize_domain

SCHEMA_VERSION = "1"
MAX_ENTRY = 2048
MAX_NOTE = 300
DEFAULT_PORTS = {"http": 80, "https": 443}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS feed_domains(domain TEXT NOT NULL, feed TEXT NOT NULL, PRIMARY KEY(domain, feed)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS feed_urls(url TEXT NOT NULL, feed TEXT NOT NULL, PRIMARY KEY(url, feed)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS feeds(name TEXT PRIMARY KEY, title TEXT, category TEXT, url TEXT, updated TEXT,
    domains INTEGER NOT NULL DEFAULT 0, urls INTEGER NOT NULL DEFAULT 0, status TEXT, error TEXT, sha256 TEXT,
    checked TEXT, ok_at TEXT, failures INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS user_entries(kind TEXT NOT NULL CHECK(kind IN ('allow', 'block')),
    match TEXT NOT NULL CHECK(match IN ('domain', 'url')), value TEXT NOT NULL, note TEXT NOT NULL DEFAULT '',
    origin TEXT NOT NULL DEFAULT 'user', added TEXT NOT NULL, PRIMARY KEY(kind, match, value)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS reports(url TEXT PRIMARY KEY, note TEXT NOT NULL DEFAULT '', reported TEXT NOT NULL,
    origin TEXT NOT NULL DEFAULT 'user') WITHOUT ROWID;
"""


def _now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()


def backup_path(db_path: Path | str) -> Path:
    """Where a copy of the user's lists is kept, next to the database."""
    return Path(db_path).with_name("lists-backup.json")


def backup_files(db_path: Path | str) -> list[Path]:
    """The backup and its temporary file (what a sandboxed process must be allowed to write)."""
    b = backup_path(db_path)
    return [b, b.with_name(b.name + ".tmp")]


def side_files(db_path: Path | str) -> list[Path]:
    p = Path(db_path)
    return [p, *(p.with_name(p.name + s) for s in ("-wal", "-shm", "-journal"))]


def _host(host: str) -> str | None:
    host = host.strip().lower().rstrip(".").strip("[]")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return normalize_domain(host)


def normalize_url(url: str) -> str | None:
    """Canonical http(s) link used for matching, or None if it is not one."""
    if not isinstance(url, str) or len(url) > 8192:
        return None
    try:
        parts = urlsplit(url.strip())
        scheme = parts.scheme.lower()
        port = parts.port
    except ValueError:
        return None
    if scheme not in DEFAULT_PORTS or not parts.hostname:
        return None
    host = _host(parts.hostname)
    if not host:
        return None
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port in (None, DEFAULT_PORTS[scheme]) else f"{host}:{port}"
    path = parts.path or "/"
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    return f"{scheme}://{netloc}{path}" + (f"?{parts.query}" if parts.query else "")


def url_candidates(norm: str) -> list[str]:
    """The link itself, without its query, and every parent path: what an entry may be a prefix of."""
    base, _, query = norm.partition("?")
    scheme_host, _, path = base.partition("://")[2].partition("/")
    root = base[: base.index("://") + 3] + scheme_host
    out = [norm] if query else []
    segments = [s for s in path.split("/") if s]
    for i in range(len(segments), 0, -1):
        out.append(root + "/" + "/".join(segments[:i]))
    out.append(root + "/")
    return list(dict.fromkeys(out))


def host_candidates(host: str) -> list[str]:
    host = host.lower().rstrip(".")
    try:
        return [str(ipaddress.ip_address(host.strip("[]")))]
    except ValueError:
        pass
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)] or [host]


def normalize_entry(text: str) -> tuple[str, str]:
    """('domain', 'evil.example') or ('url', 'https://evil.example/login'); ValueError if neither."""
    if not isinstance(text, str):
        raise ValueError("entry must be text")
    text = text.strip()
    if not text or len(text) > MAX_ENTRY:
        raise ValueError("entry is empty or too long")
    if "://" in text or "/" in text:
        candidate = text if "://" in text else "https://" + text
        norm = normalize_url(candidate)
        if not norm:
            raise ValueError("not a web link (http/https) or domain")
        # "evil.example/" is just the domain
        if norm.endswith("/") and norm.count("/") == 3 and "?" not in norm:
            return "domain", norm.split("://", 1)[1].rstrip("/").strip("[]")
        return "url", norm
    host = _host(text)
    if not host:
        raise ValueError("not a valid domain")
    if ":" not in host and not host.replace(".", "").isdigit():
        from .domains import split_domain

        if not split_domain(host).registrable:
            raise ValueError(f"{host} is a public suffix: it would cover every site under it")
    return "domain", host


@dataclass
class Hit:
    source: str  # feed name, "allowlist", "blocklist", "reported", "organisation"
    match: str  # domain | url
    value: str
    note: str = ""


@dataclass
class Lookup:
    allowed: Hit | None = None
    blocked: Hit | None = None
    reported: Hit | None = None
    feeds: list[Hit] = field(default_factory=list)


class ThreatDB:
    """Thread-safe wrapper around one SQLite file (WAL mode, so readers never wait for the updater)."""

    def __init__(self, path: Path | str, readonly: bool = False):
        self.path = str(path)
        self.lock = threading.RLock()
        if readonly:
            uri = Path(self.path).resolve().as_uri() + "?mode=ro"
            self.conn = sqlite3.connect(uri, uri=True, timeout=15, check_same_thread=False)
        else:
            self.conn = sqlite3.connect(self.path, timeout=15, check_same_thread=False)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=FULL")  # a commit is on disk before it counts, even if power fails
            self.conn.executescript(_SCHEMA)
            cols = {r[1] for r in self.conn.execute("PRAGMA table_info(feeds)")}
            if "ok_at" not in cols:  # a database from before retry tracking
                self.conn.execute("ALTER TABLE feeds ADD COLUMN ok_at TEXT")
                self.conn.execute("UPDATE feeds SET ok_at=checked WHERE status IN ('ok', 'kept')")
            if "failures" not in cols:
                self.conn.execute("ALTER TABLE feeds ADD COLUMN failures INTEGER NOT NULL DEFAULT 0")
            self.conn.execute("INSERT OR IGNORE INTO meta VALUES ('schema', ?)", (SCHEMA_VERSION,))
            self.conn.commit()
        self.readonly = readonly
        self._bulk = False
        self.conn.execute("PRAGMA trusted_schema=OFF")
        self.conn.execute("PRAGMA foreign_keys=ON")

    def close(self) -> None:
        with self.lock:
            self.conn.close()

    def save_backup(self) -> None:
        """Copy the user's lists to lists-backup.json, atomically. Best effort: the database is the original."""
        if self.readonly or self._bulk or self.path == ":memory:":
            return
        try:
            _write_backup(self.path, self.export_lists())
        except (OSError, sqlite3.Error):
            pass

    # ------------------------------------------------------------------ lookups
    def lookup(self, host: str | None, url: str | None, org_allow: Iterable[str] = (),
               org_block: Iterable[str] = ()) -> Lookup:
        res = Lookup()
        hosts = host_candidates(host) if host else []
        norm = normalize_url(url) if url else None
        urls = url_candidates(norm) if norm else []
        if not hosts and not urls:
            return res
        # Organisation lists (from the policy file) come first, then the user's own entries.
        for kind, entries in (("block", org_block), ("allow", org_allow)):
            for entry in entries:
                try:
                    m, v = normalize_entry(entry)
                except ValueError:
                    continue
                if (m == "domain" and v in hosts) or (m == "url" and v in urls):
                    hit = Hit("organisation", m, v)
                    if kind == "block" and not res.blocked:
                        res.blocked = hit
                    elif kind == "allow" and not res.allowed:
                        res.allowed = hit
        with self.lock:
            q_h = ",".join("?" * len(hosts)) or "''"
            q_u = ",".join("?" * len(urls)) or "''"
            rows = self.conn.execute(
                f"SELECT kind, match, value, note FROM user_entries WHERE (match='domain' AND value IN ({q_h})) "  # nosec B608 - placeholders only
                f"OR (match='url' AND value IN ({q_u}))", (*hosts, *urls)).fetchall()
            reported = self.conn.execute(f"SELECT url, note FROM reports WHERE url IN ({q_u})", urls).fetchall()  # nosec B608
            feed_d = self.conn.execute(
                f"SELECT domain, feed FROM feed_domains WHERE domain IN ({q_h})", hosts).fetchall()  # nosec B608
            feed_u = self.conn.execute(f"SELECT url, feed FROM feed_urls WHERE url IN ({q_u})", urls).fetchall()  # nosec B608
        # most specific user entry first (a link beats its domain, a sub-domain beats its parent)
        def specificity(row) -> int:
            return (10000 if row[1] == "url" else 0) + len(row[2])

        for kind, m, v, note in sorted(rows, key=specificity, reverse=True):
            if kind == "block" and not res.blocked:
                res.blocked = Hit("blocklist", m, v, note)
            elif kind == "allow" and not res.allowed:
                res.allowed = Hit("allowlist", m, v, note)
        if reported:
            res.reported = Hit("reported", "url", reported[0][0], reported[0][1])
        seen = set()
        for value, feed in [*feed_u, *feed_d]:
            if feed not in seen:
                seen.add(feed)
                res.feeds.append(Hit(feed, "url" if "://" in value else "domain", value))
        return res

    # ------------------------------------------------------------------ user lists
    def add_entry(self, kind: str, text: str, note: str = "", origin: str = "user") -> tuple[str, str]:
        if kind not in ("allow", "block"):
            raise ValueError("kind must be allow or block")
        m, v = normalize_entry(text)
        with self.lock, self.conn:
            other = "block" if kind == "allow" else "allow"
            self.conn.execute("DELETE FROM user_entries WHERE kind=? AND match=? AND value=?", (other, m, v))
            self.conn.execute("INSERT OR REPLACE INTO user_entries VALUES (?, ?, ?, ?, ?, ?)",
                              (kind, m, v, str(note)[:MAX_NOTE], origin[:20], _now()))
        self.save_backup()
        return m, v

    def remove_entry(self, kind: str, text: str) -> bool:
        m, v = normalize_entry(text)
        with self.lock, self.conn:
            cur = self.conn.execute("DELETE FROM user_entries WHERE kind=? AND match=? AND value=?", (kind, m, v))
        self.save_backup()
        return cur.rowcount > 0

    def entries(self, kind: str, limit: int = 1000, offset: int = 0) -> list[dict]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT match, value, note, origin, added FROM user_entries WHERE kind=? ORDER BY added DESC "
                "LIMIT ? OFFSET ?", (kind, max(1, min(limit, 5000)), max(0, offset))).fetchall()
        return [{"match": m, "value": v, "note": n, "origin": o, "added": a} for m, v, n, o, a in rows]

    def report(self, url: str, note: str = "", origin: str = "user") -> str:
        norm = normalize_url(url if "://" in url else "https://" + url)
        if not norm:
            raise ValueError("only web links (http/https) can be reported")
        with self.lock, self.conn:
            self.conn.execute("INSERT OR REPLACE INTO reports VALUES (?, ?, ?, ?)", (norm, str(note)[:MAX_NOTE], _now(), origin[:20]))
            # a reported link is never on the allowlist at the same time
            self.conn.execute("DELETE FROM user_entries WHERE kind='allow' AND match='url' AND value=?", (norm,))
        self.save_backup()
        return norm

    def unreport(self, url: str) -> bool:
        norm = normalize_url(url if "://" in url else "https://" + url)
        with self.lock, self.conn:
            cur = self.conn.execute("DELETE FROM reports WHERE url=?", (norm,))
        self.save_backup()
        return cur.rowcount > 0

    def reports(self, limit: int = 1000, offset: int = 0) -> list[dict]:
        with self.lock:
            rows = self.conn.execute("SELECT url, note, reported, origin FROM reports ORDER BY reported DESC LIMIT ? OFFSET ?",
                                     (max(1, min(limit, 5000)), max(0, offset))).fetchall()
        return [{"url": u, "note": n, "reported": r, "origin": o} for u, n, r, o in rows]

    def export_lists(self) -> dict:
        return {"format": "homograph-guard-lists/1", "allow": self.entries("allow", 5000),
                "block": self.entries("block", 5000), "reported": self.reports(5000)}

    def import_lists(self, data: dict) -> int:
        if not isinstance(data, dict) or data.get("format") != "homograph-guard-lists/1":
            raise ValueError("not a Homograph Guard lists file")
        self._bulk = True  # one backup at the end, not one per entry
        try:
            n = self._import(data)
        finally:
            self._bulk = False
        self.save_backup()
        return n

    def _import(self, data: dict) -> int:
        n = 0
        for kind in ("allow", "block"):
            for e in (data.get(kind) or [])[:5000]:
                if isinstance(e, dict) and isinstance(e.get("value"), str):
                    try:
                        self.add_entry(kind, e["value"], str(e.get("note", "")), "import")
                        n += 1
                    except ValueError:
                        continue
        for r in (data.get("reported") or [])[:5000]:
            if isinstance(r, dict) and isinstance(r.get("url"), str):
                try:
                    self.report(r["url"], str(r.get("note", "")), "import")
                    n += 1
                except ValueError:
                    continue
        return n

    # ------------------------------------------------------------------ feeds
    def replace_feed(self, name: str, title: str, category: str, url: str, domains: Iterable[str],
                     urls: Iterable[str], sha256: str) -> tuple[int, int]:
        d, u = sorted(set(domains)), sorted(set(urls))
        with self.lock, self.conn:  # one transaction: readers see either the old or the new list
            self.conn.execute("DELETE FROM feed_domains WHERE feed=?", (name,))
            self.conn.executemany("INSERT OR IGNORE INTO feed_domains VALUES (?, ?)", ((x, name) for x in d))
            self.conn.execute("DELETE FROM feed_urls WHERE feed=?", (name,))
            self.conn.executemany("INSERT OR IGNORE INTO feed_urls VALUES (?, ?)", ((x, name) for x in u))
            now = _now()
            self.conn.execute("INSERT OR REPLACE INTO feeds(name, title, category, url, updated, domains, urls, status, "
                              "error, sha256, checked, ok_at, failures) VALUES (?, ?, ?, ?, ?, ?, ?, 'ok', '', ?, ?, ?, 0)",
                              (name, title, category, url, now, len(d), len(u), sha256, now, now))
            self.conn.execute("INSERT OR REPLACE INTO meta VALUES ('updated', ?)", (now,))
        return len(d), len(u)

    def feed_failed(self, name: str, title: str, category: str, url: str, error: str, status: str = "failed") -> None:
        """Record a failed refresh; the previous entries of the feed stay in use.

        ``failed`` counts towards the retry back-off. ``kept`` (downloaded, but rejected as a sudden
        shrink) waits for the next daily refresh, like a successful download.
        """
        now = _now()
        kept = status == "kept"
        with self.lock, self.conn:
            row = self.conn.execute("SELECT name FROM feeds WHERE name=?", (name,)).fetchone()
            if row and kept:
                self.conn.execute("UPDATE feeds SET status=?, error=?, checked=?, ok_at=?, failures=0 WHERE name=?",
                                  (status, error[:300], now, now, name))
            elif row:
                self.conn.execute("UPDATE feeds SET status=?, error=?, checked=?, failures=failures+1 WHERE name=?",
                                  (status, error[:300], now, name))
            else:
                self.conn.execute("INSERT INTO feeds(name, title, category, url, updated, domains, urls, status, error, "
                                  "sha256, checked, ok_at, failures) VALUES (?, ?, ?, ?, NULL, 0, 0, ?, ?, NULL, ?, ?, ?)",
                                  (name, title, category, url, status, error[:300], now, now if kept else None,
                                   0 if kept else 1))

    def drop_feed(self, name: str) -> None:
        with self.lock, self.conn:
            self.conn.execute("DELETE FROM feed_domains WHERE feed=?", (name,))
            self.conn.execute("DELETE FROM feed_urls WHERE feed=?", (name,))
            self.conn.execute("DELETE FROM feeds WHERE name=?", (name,))

    def feed_count(self, name: str) -> int:
        with self.lock:
            row = self.conn.execute("SELECT domains + urls FROM feeds WHERE name=?", (name,)).fetchone()
        return int(row[0]) if row else 0

    def feed_hash(self, name: str) -> str | None:
        with self.lock:
            row = self.conn.execute("SELECT sha256 FROM feeds WHERE name=?", (name,)).fetchone()
        return row[0] if row else None

    def touch_feed(self, name: str) -> None:
        now = _now()
        with self.lock, self.conn:
            self.conn.execute("UPDATE feeds SET checked=?, ok_at=?, status='ok', error='', failures=0 WHERE name=?",
                              (now, now, name))
            self.conn.execute("INSERT OR REPLACE INTO meta VALUES ('updated', ?)", (now,))

    def feed_states(self) -> dict[str, dict]:
        """Per feed: status, last attempt (checked), last good download (ok_at) and failures in a row."""
        with self.lock:
            rows = self.conn.execute("SELECT name, status, checked, ok_at, failures FROM feeds").fetchall()
        return {n: {"status": st, "checked": c, "ok_at": o, "failures": f or 0} for n, st, c, o, f in rows}

    def status(self) -> dict:
        with self.lock:
            feeds = [dict(zip(("name", "title", "category", "updated", "domains", "urls", "status", "error", "checked"), r, strict=True))
                     for r in self.conn.execute("SELECT name, title, category, updated, domains, urls, status, error, checked "
                                                "FROM feeds ORDER BY name")]
            updated = self.conn.execute("SELECT value FROM meta WHERE key='updated'").fetchone()
            counts = {k: self.conn.execute(q).fetchone()[0] for k, q in (
                ("domains", "SELECT COUNT(DISTINCT domain) FROM feed_domains"),
                ("urls", "SELECT COUNT(DISTINCT url) FROM feed_urls"),
                ("allow", "SELECT COUNT(*) FROM user_entries WHERE kind='allow'"),
                ("block", "SELECT COUNT(*) FROM user_entries WHERE kind='block'"),
                ("reported", "SELECT COUNT(*) FROM reports"))}
        return {"updated": updated[0] if updated else None, **counts, "feeds": feeds}

    def last_update(self) -> dt.datetime | None:
        with self.lock:
            row = self.conn.execute("SELECT value FROM meta WHERE key='updated'").fetchone()
        try:
            return dt.datetime.fromisoformat(row[0]) if row else None
        except ValueError:
            return None


# ---------------------------------------------------------------------- repair
def _write_backup(db_path: Path | str, lists: dict) -> None:
    """Write lists-backup.json atomically: a temporary file, flushed to disk, then renamed."""
    target, tmp = backup_files(db_path)
    data = json.dumps(lists, ensure_ascii=True, indent=1)
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, target)


def _salvage(path: Path) -> dict | None:
    """The user's lists from a damaged database, if those pages can still be read."""
    try:
        old = ThreatDB(path, readonly=True)
        try:
            return old.export_lists()
        finally:
            old.close()
    except (sqlite3.Error, OSError, ValueError):
        return None


def _read_backup(path: Path) -> dict | None:
    try:
        data = json.loads(backup_path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("format") == "homograph-guard-lists/1" else None


def ensure_healthy(path: Path | str, thorough: bool = True) -> str | None:
    """Check the database; if it is damaged, set it aside and start a new one with the user's lists.

    ``thorough`` reads every page (``PRAGMA quick_check``, for the updater); otherwise only the
    header and schema are read, which is cheap enough for every program start. Returns what was
    done, or None. Run it before the sandbox is installed: it renames files.
    """
    path = Path(path)
    if not path.exists():
        return None
    try:
        con = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=15)
        try:
            if thorough:
                healthy = con.execute("PRAGMA quick_check").fetchall() == [("ok",)]
            else:
                con.execute("SELECT count(*) FROM sqlite_master").fetchone()
                healthy = True
        finally:
            con.close()
    except sqlite3.OperationalError as exc:
        if "locked" in str(exc) or "busy" in str(exc):
            return None  # an update is writing right now: busy, not damaged
        healthy = False
    except sqlite3.DatabaseError:
        healthy = False
    if healthy:
        if not backup_path(path).exists():  # e.g. lists from before backups existed: keep a copy now
            try:
                old = ThreatDB(path, readonly=True)  # read-only: never waits for an update in progress
                try:
                    _write_backup(path, old.export_lists())
                finally:
                    old.close()
            except (OSError, sqlite3.Error):
                pass
        return None
    lists = _salvage(path) or _read_backup(path)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    for f in side_files(path):
        if f.exists():
            os.replace(f, f.with_name(f"{f.name}.damaged-{stamp}"))
    db = ThreatDB(path)
    try:
        n = db.import_lists(lists) if lists else 0
    finally:
        db.close()
    return (f"The threat database was damaged, so it was set aside ({path.name}.damaged-{stamp}) and a new one "
            f"was created with your lists ({n} entr{'y' if n == 1 else 'ies'}).")
