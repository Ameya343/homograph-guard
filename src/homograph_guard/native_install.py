"""Register (or remove) the native messaging host with Chrome, Edge, Brave, Chromium and Firefox.

Browsers find the host through a small JSON manifest that names the program and the only
extension IDs allowed to start it.

* Windows: the manifest's location is recorded in the registry, per user (HKCU) or for every
  user (HKLM, administrators). Chromium builds read Chrome's key.
* macOS and Linux: the manifest goes into each browser's NativeMessagingHosts folder, in your
  home folder or, for every user of the machine (root), in the browser's documented system
  folder. Brave documents no system folder, so a machine-wide install skips it.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path

from . import paths
from .native_host import CHROME_EXTENSION_IDS, FIREFOX_EXTENSION_IDS, HOST_NAME

BROWSERS = ("chrome", "edge", "brave", "chromium", "firefox")
_WIN_KEYS = {
    "chrome": r"Software\Google\Chrome\NativeMessagingHosts",
    "edge": r"Software\Microsoft\Edge\NativeMessagingHosts",
    "brave": r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
    "chromium": r"Software\Google\Chrome\NativeMessagingHosts",  # Chromium builds on Windows read Chrome's key
    "firefox": r"Software\Mozilla\NativeMessagingHosts",
}
# Per user: macOS under ~/Library/Application Support, Linux under $XDG_CONFIG_HOME (~/.config)
_MAC_DIRS = {
    "chrome": "Google/Chrome", "edge": "Microsoft Edge", "brave": "BraveSoftware/Brave-Browser", "chromium": "Chromium",
    "firefox": "Mozilla",
}
_LINUX_DIRS = {"chrome": "google-chrome", "edge": "microsoft-edge", "brave": "BraveSoftware/Brave-Browser", "chromium": "chromium"}
# For every user of the machine, as documented by Google, Microsoft and Mozilla
_MAC_SYSTEM_DIRS = {
    "chrome": "/Library/Google/Chrome/NativeMessagingHosts",
    "edge": "/Library/Microsoft/Edge/NativeMessagingHosts",
    "chromium": "/Library/Application Support/Chromium/NativeMessagingHosts",
    "firefox": "/Library/Application Support/Mozilla/NativeMessagingHosts",
}
_LINUX_SYSTEM_DIRS = {
    "chrome": "/etc/opt/chrome/native-messaging-hosts",
    "edge": "/etc/opt/edge/native-messaging-hosts",
    "chromium": "/etc/chromium/native-messaging-hosts",
    "firefox": "/usr/lib/mozilla/native-messaging-hosts",
}


def _platform() -> str:
    return "windows" if sys.platform == "win32" else "mac" if sys.platform == "darwin" else "linux"


def manifest_dir(browser: str, machine: bool = False) -> Path | None:
    """The folder (macOS, Linux) where ``browser`` looks for the manifest; None on Windows or if there is none."""
    plat = _platform()
    if plat == "windows":
        return None
    if machine:
        table = _MAC_SYSTEM_DIRS if plat == "mac" else _LINUX_SYSTEM_DIRS
        return Path(table[browser]) if browser in table else None
    home = Path.home()
    if plat == "mac":
        return home / "Library" / "Application Support" / _MAC_DIRS[browser] / "NativeMessagingHosts"
    if browser == "firefox":
        return home / ".mozilla" / "native-messaging-hosts"
    return Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config") / _LINUX_DIRS[browser] / "NativeMessagingHosts"


def manifest(browser: str, host_path: str, extra_ids: tuple[str, ...] = ()) -> dict:
    m = {"name": HOST_NAME, "description": "Homograph Guard - checks links on this device", "path": host_path, "type": "stdio"}
    if browser == "firefox":
        m["allowed_extensions"] = [*FIREFOX_EXTENSION_IDS, *(i for i in extra_ids if i.startswith("{") or "@" in i)]
    else:
        ids = [*CHROME_EXTENSION_IDS, *(i for i in extra_ids if len(i) == 32 and set(i) <= set("abcdefghijklmnop"))]
        m["allowed_origins"] = [f"chrome-extension://{i}/" for i in dict.fromkeys(ids)]
    return m


def host_command(target_dir: Path) -> str:
    """The program the browser starts: the bundled .exe, or a small launcher for a pip installation."""
    windows = _platform() == "windows"
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).with_name("hg-native-host.exe" if windows else "hg-native-host"))
    entry = Path(__file__).resolve().with_name("_native_entry.py")
    target_dir.mkdir(parents=True, exist_ok=True)
    if windows:
        launcher = target_dir / "hg-native-host.cmd"
        python, script = (str(p).replace("%", "%%") for p in (sys.executable, entry))  # %VAR% expands even in quotes
        launcher.write_text(f'@echo off\r\n"{python}" -I -B "{script}" %*\r\n', encoding="utf-8", newline="")
    else:
        launcher = target_dir / "hg-native-host"
        launcher.write_text(f'#!/bin/sh\nexec {shlex.quote(sys.executable)} -I -B {shlex.quote(str(entry))} "$@"\n',
                            encoding="utf-8")
        launcher.chmod(0o755)
    return str(launcher)


def _program_dir(machine: bool) -> Path:
    """Where the launcher (and, on Windows, the manifest files) are kept."""
    plat = _platform()
    if not machine:
        return paths.data_dir() / "native-messaging"
    if plat == "windows":
        return Path(os.environ.get("PROGRAMDATA") or r"C:\ProgramData") / paths.APP / "native-messaging"
    if plat == "mac":
        return Path("/Library/Application Support") / paths.APP / "native-messaging"
    return Path("/usr/local/lib/homograph-guard/native-messaging")


def register(browsers=BROWSERS, machine: bool = False, extra_ids: tuple[str, ...] = (), host_path: str | None = None) -> list[str]:
    """Register for ``browsers``; returns those done. Raises PermissionError without the needed rights."""
    folder = _program_dir(machine)
    folder.mkdir(parents=True, exist_ok=True)
    if machine and _platform() != "windows":
        for d in (folder.parent, folder):  # every user's browser must reach the launcher; only root may change it
            os.chmod(d, 0o755)  # nosec B103
    cmd = host_path or host_command(folder)
    done = []
    keys_written: set[str] = set()
    for b in browsers:
        data = json.dumps(manifest(b, cmd, extra_ids), indent=2)
        if _platform() == "windows":
            import winreg

            if _WIN_KEYS[b] in keys_written:  # Chrome and Chromium share one registration
                done.append(b)
                continue
            keys_written.add(_WIN_KEYS[b])
            file = folder / f"{HOST_NAME}.{b}.json"
            file.write_text(data, encoding="utf-8")
            root = winreg.HKEY_LOCAL_MACHINE if machine else winreg.HKEY_CURRENT_USER
            with winreg.CreateKey(root, f"{_WIN_KEYS[b]}\\{HOST_NAME}") as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, str(file))
            done.append(b)
            continue
        target = manifest_dir(b, machine)
        if target is None:
            continue
        target.mkdir(parents=True, exist_ok=True)
        file = target / f"{HOST_NAME}.json"
        file.write_text(data, encoding="utf-8")
        if machine:
            os.chmod(file, 0o644)
        done.append(b)
    return done


def unregister(browsers=BROWSERS, machine: bool = False) -> list[str]:
    done = []
    keys_removed: set[str] = set()
    for b in browsers:
        if _platform() == "windows":
            import winreg

            root = winreg.HKEY_LOCAL_MACHINE if machine else winreg.HKEY_CURRENT_USER
            try:
                winreg.DeleteKey(root, f"{_WIN_KEYS[b]}\\{HOST_NAME}")
                keys_removed.add(_WIN_KEYS[b])
                done.append(b)
            except OSError:
                if _WIN_KEYS[b] in keys_removed:
                    done.append(b)
            (_program_dir(machine) / f"{HOST_NAME}.{b}.json").unlink(missing_ok=True)
            continue
        target = manifest_dir(b, machine)
        file = target / f"{HOST_NAME}.json" if target else None
        if file and file.exists():
            file.unlink()
            done.append(b)
    return done


def registered(machine: bool = False) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for b in BROWSERS:
        if _platform() == "windows":
            import winreg

            root = winreg.HKEY_LOCAL_MACHINE if machine else winreg.HKEY_CURRENT_USER
            try:
                with winreg.OpenKey(root, f"{_WIN_KEYS[b]}\\{HOST_NAME}") as key:
                    out[b] = winreg.QueryValueEx(key, "")[0]
            except OSError:
                out[b] = None
            continue
        target = manifest_dir(b, machine)
        file = target / f"{HOST_NAME}.json" if target else None
        out[b] = str(file) if file and file.exists() else None
    return out
