"""Where the app keeps its data on this device.

Everything stays on the device: the threat database, your allow/block lists, the
links you reported and your settings. An organisation can add a read-only policy
file that overrides settings for every user (see ENTERPRISE.md).

``HGUARD_HOME`` overrides the data directory (tests, portable use, containers) and
``HGUARD_POLICY`` the policy file.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP = "HomographGuard"


def data_dir() -> Path:
    env = os.environ.get("HGUARD_HOME")
    if env:
        return Path(env)
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "homograph-guard"


def policy_file() -> Path:
    env = os.environ.get("HGUARD_POLICY")
    if env:
        return Path(env)
    if sys.platform == "win32":
        return Path(os.environ.get("PROGRAMDATA") or r"C:\ProgramData") / APP / "policy.json"
    if sys.platform == "darwin":
        return Path("/Library/Application Support") / APP / "policy.json"
    return Path("/etc/homograph-guard/policy.json")


def db_path() -> Path:
    return data_dir() / "threats.db"


def db_files() -> list[Path]:
    """The database and the side files SQLite keeps next to it in WAL mode."""
    p = db_path()
    return [p, p.with_name(p.name + "-wal"), p.with_name(p.name + "-shm"), p.with_name(p.name + "-journal")]


def settings_path() -> Path:
    return data_dir() / "settings.json"


def ensure_data_dir() -> Path:
    """Create the data folder (owner-only on macOS and Linux).

    Call it before the sandbox is switched on: it then forbids creating folders and changing
    permissions, so when the folder is already in order nothing is touched here.
    """
    d = data_dir()
    if os.name == "posix":
        os.umask(0o077)  # what the app creates from now on (database, settings, exports) is owner-only
    if not d.is_dir():
        d.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        for p in (d, *db_files(), settings_path()):  # nobody else on the machine needs to read your lists
            if p.exists() and p.stat().st_mode & 0o077:
                os.chmod(p, 0o700 if p.is_dir() else 0o600)
    return d
