"""Interrupted and failed updates, and a damaged database.

A power cut, a shutdown or a forced restart kills the updater at an arbitrary moment; from
the program's point of view that is a hard kill. These tests kill the real command in the
middle of a download, then check that the database is intact and that the next run resumes
with exactly what was missing. They also damage the database file on purpose and check that
it is rebuilt without losing the user's lists.
"""

import datetime as dt
import json
import os
import sqlite3
import subprocess
import sys
import time

import pytest
from test_feeds_update import ENTRY, FeedServer

from homograph_guard import feeds
from homograph_guard.analyzer import Analyzer
from homograph_guard.settings import Settings
from homograph_guard.threatdb import ThreatDB, backup_path, ensure_healthy

NOW = dt.datetime(2026, 11, 19, 12, 0, tzinfo=dt.UTC)
ORDER = [f.name for f in feeds.FEEDS if f.default]  # the order the updater downloads in


def ago(**kw) -> str:
    return (NOW - dt.timedelta(**kw)).isoformat()


@pytest.fixture
def server(tmp_path):
    s = FeedServer(tmp_path)
    yield s
    s.close()


@pytest.fixture(autouse=True)
def quick_retry(monkeypatch):
    monkeypatch.setattr(feeds, "RETRY_PAUSE", 0.1)


# ------------------------------------------------------------------ what is due
def test_feed_due_rules():
    assert feeds.feed_due(None, NOW)  # never downloaded
    assert not feeds.feed_due({"status": "ok", "checked": ago(hours=3), "ok_at": ago(hours=3)}, NOW)
    assert feeds.feed_due({"status": "ok", "checked": ago(hours=21), "ok_at": ago(hours=21)}, NOW)
    # a failed attempt waits 15 minutes, then 30, 60, ... but never longer than a normal day
    failed = {"status": "failed", "ok_at": ago(hours=5)}
    assert not feeds.feed_due({**failed, "checked": ago(minutes=10), "failures": 1}, NOW)
    assert feeds.feed_due({**failed, "checked": ago(minutes=16), "failures": 1}, NOW)
    assert not feeds.feed_due({**failed, "checked": ago(minutes=50), "failures": 3}, NOW)
    assert feeds.feed_due({**failed, "checked": ago(minutes=61), "failures": 3}, NOW)
    assert feeds.feed_due({**failed, "checked": ago(hours=20, minutes=1), "failures": 40}, NOW)
    # downloaded but rejected as a sudden shrink: no hourly retries, the next daily refresh decides
    assert not feeds.feed_due({"status": "kept", "checked": ago(hours=2), "ok_at": ago(hours=2)}, NOW)


def test_failures_are_counted_and_cleared(server, tmp_path):
    db = ThreatDB(tmp_path / "threats.db")
    s = Settings(feed_mirror=server.mirror, cafile=str(server.ca))
    server.files.pop("phishing-army.txt")
    feeds.update(db, s)
    feeds.update(db, s, only=["phishing-army"])
    st = db.feed_states()
    assert st["phishing-army"]["status"] == "failed" and st["phishing-army"]["failures"] == 2
    assert "phishing-army" not in feeds.due_feeds(db, s)  # just failed: wait before trying again
    later = dt.datetime.now(dt.UTC) + dt.timedelta(minutes=31)
    assert feeds.due_feeds(db, s, later) == ["phishing-army"]  # only the failed one, not the rest
    server.files["phishing-army.txt"] = "army-phish.com\n"
    feeds.update(db, s, only=["phishing-army"])
    assert db.feed_states()["phishing-army"] == {**db.feed_states()["phishing-army"], "status": "ok", "failures": 0}
    db.close()


def test_a_dropped_connection_is_retried_in_the_same_run(server, tmp_path):
    db = ThreatDB(tmp_path / "threats.db")
    s = Settings(feed_mirror=server.mirror, cafile=str(server.ca))
    server.failures["cert-pl.txt"] = 1  # e.g. the network is still waking up
    server.files.pop("phishing-army.txt")  # a missing file is not worth retrying
    r = {x.name: x for x in feeds.update(db, s)}
    assert r["cert-pl"].status == "updated"
    assert r["phishing-army"].status == "failed"
    assert server.requests.count("cert-pl.txt") == 2 and server.requests.count("phishing-army.txt") == 1
    db.close()


# ------------------------------------------------------------------ the real command, killed mid-download
def test_killed_update_leaves_a_sound_database_and_resumes(server, tmp_path):
    home = tmp_path / "home"
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"feed_mirror": server.mirror, "cafile": str(server.ca)}))
    env = {**os.environ, "HGUARD_HOME": str(home), "HGUARD_POLICY": str(policy)}
    server.delays["cert-pl.txt"] = 30  # the fourth feed is still downloading when the power goes

    proc = subprocess.Popen([sys.executable, "-I", str(ENTRY), "update"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env=env)
    deadline = time.time() + 60
    while "cert-pl.txt" not in server.requests and time.time() < deadline:
        time.sleep(0.05)
    assert "cert-pl.txt" in server.requests
    proc.kill()  # what a power cut or a forced restart does to the process
    proc.wait(timeout=30)

    db_file = home / "threats.db"
    con = sqlite3.connect(db_file)
    assert con.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    con.close()
    db = ThreatDB(db_file)
    done = [n for n, st in db.feed_states().items() if st["status"] == "ok"]
    assert sorted(done) == sorted(ORDER[: ORDER.index("cert-pl")])  # finished feeds are complete
    s = Settings(feed_mirror=server.mirror, cafile=str(server.ca))
    assert feeds.due_feeds(db, s) == ORDER[ORDER.index("cert-pl"):]  # the rest is due right away
    db.close()

    server.delays.clear()
    server.requests.clear()
    res = subprocess.run([sys.executable, "-I", str(ENTRY), "update", "--if-due"], capture_output=True, text=True,
                         encoding="utf-8", timeout=120, env=env)
    assert res.returncode == 0, res.stdout + res.stderr
    assert sorted(server.requests) == sorted(f"{n}.txt" for n in ORDER[ORDER.index("cert-pl"):])  # only what was missing
    again = subprocess.run([sys.executable, "-I", str(ENTRY), "update", "--if-due"], capture_output=True, text=True,
                           encoding="utf-8", timeout=120, env=env)
    assert "up to date" in again.stdout


# ------------------------------------------------------------------ damaged database
def _damage(path, offset=0):
    with open(path, "r+b") as fh:
        fh.seek(offset)
        fh.write(b"\x00garbage from a failed write\x00" * 64)


def test_damaged_database_is_rebuilt_with_the_users_lists(tmp_path):
    db_file = tmp_path / "threats.db"
    db = ThreatDB(db_file)
    db.add_entry("block", "my-own-block.example", "from a test")
    db.add_entry("allow", "partner.example")
    db.report("https://phish.example/login")
    db.close()
    assert json.loads(backup_path(db_file).read_text())["block"][0]["value"] == "my-own-block.example"
    assert ensure_healthy(db_file) is None  # a sound file is left alone

    _damage(db_file)  # the header is gone: SQLite no longer recognises the file at all
    msg = ensure_healthy(db_file)
    assert msg and "3 entries" in msg
    assert list(tmp_path.glob("threats.db.damaged-*")), "the damaged file is kept for inspection"
    db = ThreatDB(db_file)
    assert db.conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"  # the rebuilt file is sound
    assert db.lookup("www.my-own-block.example", None).blocked.value == "my-own-block.example"
    assert db.lookup("partner.example", None).allowed
    assert db.lookup(None, "https://phish.example/login").reported
    db.close()


def test_damage_inside_the_file_is_found_by_the_thorough_check(tmp_path):
    db_file = tmp_path / "threats.db"
    db = ThreatDB(db_file)
    db.replace_feed("cert-pl", "t", "phishing", "u", [f"d{i}.pl" for i in range(5000)], [], "h")
    db.add_entry("block", "kept-through-repair.example")
    db.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    db.close()
    _damage(db_file, offset=db_file.stat().st_size // 2)  # a page in the middle of the feed table
    assert ensure_healthy(db_file, thorough=False) is None  # the cheap start-up check reads only the schema
    assert ensure_healthy(db_file, thorough=True)  # the updater's check reads every page
    db = ThreatDB(db_file)
    assert db.lookup("kept-through-repair.example", None).blocked
    assert feeds.due_feeds(db, Settings()) == ORDER  # every feed downloads again
    db.close()


def test_backup_is_written_by_the_sandboxed_command(tmp_path):
    env = {**os.environ, "HGUARD_HOME": str(tmp_path / "home"), "HGUARD_POLICY": str(tmp_path / "none.json")}
    res = subprocess.run([sys.executable, "-I", str(ENTRY), "block", "add", "sandboxed-backup.example"],
                         capture_output=True, text=True, encoding="utf-8", timeout=120, env=env)
    assert res.returncode == 0, res.stderr
    data = json.loads((tmp_path / "home" / "lists-backup.json").read_text())
    assert [e["value"] for e in data["block"]] == ["sandboxed-backup.example"]


def test_old_database_gains_retry_columns(tmp_path):
    db_file = tmp_path / "threats.db"
    con = sqlite3.connect(db_file)
    con.executescript("""
        CREATE TABLE feeds(name TEXT PRIMARY KEY, title TEXT, category TEXT, url TEXT, updated TEXT,
            domains INTEGER NOT NULL DEFAULT 0, urls INTEGER NOT NULL DEFAULT 0, status TEXT, error TEXT,
            sha256 TEXT, checked TEXT) WITHOUT ROWID;
        INSERT INTO feeds VALUES ('cert-pl', 't', 'phishing', 'u', '2026-11-18T09:00:00+00:00', 5, 0, 'ok', '', 'h',
            '2026-11-18T09:00:00+00:00');
    """)
    con.close()
    db = ThreatDB(db_file)
    st = db.feed_states()["cert-pl"]
    assert st["ok_at"] == "2026-11-18T09:00:00+00:00" and st["failures"] == 0
    db.close()


def test_analysis_continues_when_the_database_cannot_be_read(brands, cmap):
    class Broken:
        def lookup(self, *a, **k):
            raise sqlite3.DatabaseError("database disk image is malformed")

    rep = Analyzer(brands, cmap, threatdb=Broken()).analyze("https://xn--80ak6aa92e.com/")
    codes = {f["code"] for f in rep["findings"]}
    assert "DB_UNAVAILABLE" in codes and rep["verdict"] == "high_risk"  # the homograph is still caught


def test_health_check_creates_a_missing_backup(tmp_path):
    """Lists saved before backups existed get one at the next start or update."""
    db_file = tmp_path / "threats.db"
    db = ThreatDB(db_file)
    db.add_entry("block", "older-entry.example")
    db.close()
    backup_path(db_file).unlink()  # as on a database from before this version
    assert ensure_healthy(db_file, thorough=False) is None
    assert json.loads(backup_path(db_file).read_text())["block"][0]["value"] == "older-entry.example"
