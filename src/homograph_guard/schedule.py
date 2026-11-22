"""Refresh the threat database once a day, as the signed-in user (never as root or administrator).

* Windows: a Task Scheduler task (see ``winsetup``).
* Linux: a systemd user timer in ``~/.config/systemd/user``, or a crontab line where there is
  no systemd user session.
* macOS: a launchd agent in ``~/Library/LaunchAgents``.

The update starts at the chosen hour and is retried every hour for the next 12 hours, and
shortly after sign-in, so a download cut off by a power cut, a shutdown, a forced restart or a
lost network finishes on its own. Each run fetches only what is due (``--if-due``: feeds older
than 20 hours, or whose last attempt failed), so the retries cost nothing once it worked. Only
the public lists are downloaded; nothing about the user is sent.
"""

from __future__ import annotations

import os
import plistlib
import shlex
import shutil
import subprocess  # nosec B404 - fixed programs (systemctl, crontab, launchctl), never a shell
import sys
from pathlib import Path

UNIT = "homograph-guard-update"
LAUNCHD_LABEL = "com.homograph_guard.update"
CRON_TAG = "# homograph-guard daily update"


def _platform() -> str:
    return "windows" if sys.platform == "win32" else "mac" if sys.platform == "darwin" else "linux"


def _run(args: list[str], input_text: str | None = None) -> subprocess.CompletedProcess:
    # fixed programs (systemctl, crontab, launchctl) with fixed arguments, never a shell
    return subprocess.run(args, input=input_text, capture_output=True, text=True, timeout=60, check=False)  # nosec B603


def _failed(what: str, res: subprocess.CompletedProcess) -> str:
    return f"{what} failed: {((res.stdout or '') + (res.stderr or '')).strip()[:300]}"


RETRY_HOURS = 12


def retry_hours(hour: int) -> list[int]:
    """The daily hour and the 12 hours after it; a run with nothing due exits at once."""
    return sorted({(hour + i) % 24 for i in range(RETRY_HOURS + 1)})


def update_argv(install_dir: Path | None = None) -> list[str]:
    """The command the schedule runs: the bundled updater, or this Python in isolated mode."""
    if install_dir or getattr(sys, "frozen", False):
        base = install_dir or Path(sys.executable).parent
        return [str(base / ("hg-update.exe" if _platform() == "windows" else "hg-update"))]
    entry = Path(__file__).resolve().with_name("_entry.py")
    python = Path(sys.executable)
    if _platform() == "windows" and python.with_name("pythonw.exe").exists():
        python = python.with_name("pythonw.exe")  # no console window, as in the task winsetup creates
    return [str(python), "-I", "-B", str(entry), "update", "--if-due", "--quiet"]


# ------------------------------------------------------------------ Linux: systemd user timer, cron
def _systemd_arg(arg: str) -> str:
    """Quote one ExecStart= argument (systemd expands %specifiers and $VARIABLES)."""
    arg = arg.replace("%", "%%").replace("$", "$$")
    if not arg or any(c.isspace() or c in "\"'\\;" for c in arg):
        arg = '"' + arg.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return arg


def systemd_units(argv: list[str], hour: int = 9) -> dict[str, str]:
    service = [
        "[Unit]",
        "Description=Homograph Guard: refresh the threat database (public phishing lists)",
        "",
        "[Service]",
        "Type=oneshot",
        "ExecStart=" + " ".join(_systemd_arg(a) for a in argv),
        "Nice=10",
        "UMask=0077",
        # Sandboxing an unprivileged user manager can apply (seccomp; no namespaces needed,
        # so it also works where unprivileged user namespaces are disabled).
        "NoNewPrivileges=yes",
        "LockPersonality=yes",
        "RestrictRealtime=yes",
        "RestrictSUIDSGID=yes",
        "RestrictNamespaces=yes",
        "SystemCallArchitectures=native",
        "SystemCallFilter=@system-service",
        "SystemCallErrorNumber=EPERM",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
    ]
    timer = [
        "[Unit]",
        "Description=Homograph Guard: daily threat database refresh",
        "",
        "[Timer]",
        f"OnCalendar=*-*-* {','.join(f'{h:02d}' for h in retry_hours(hour))}:00:00",
        "OnStartupSec=10min",  # after sign-in: finishes what a shutdown cut off
        "RandomizedDelaySec=15min",
        "Persistent=true",
        "",
        "[Install]",
        "WantedBy=timers.target",
    ]
    return {f"{UNIT}.service": "\n".join(service) + "\n", f"{UNIT}.timer": "\n".join(timer) + "\n"}


def _systemd_dir() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "systemd" / "user"


def _user_systemd(run) -> bool:
    if not shutil.which("systemctl"):
        return False
    try:
        return run(["systemctl", "--user", "show-environment"]).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def cron_lines(argv: list[str], hour: int = 9) -> list[str]:
    cmd = shlex.join(argv).replace("%", "\\%")  # cron turns a bare % into a newline
    hours = ",".join(str(h) for h in retry_hours(hour))
    return [f"0 {hours} * * * {cmd} >/dev/null 2>&1 {CRON_TAG}",
            f"@reboot sleep 600; {cmd} >/dev/null 2>&1 {CRON_TAG}"]  # catch up after the computer was off


def _crontab(run) -> list[str] | None:
    if not shutil.which("crontab"):
        return None
    res = run(["crontab", "-l"])
    return res.stdout.splitlines() if res.returncode == 0 else []


def _linux_install(argv: list[str], hour: int, run) -> str | None:
    if _user_systemd(run):
        folder = _systemd_dir()
        folder.mkdir(parents=True, exist_ok=True)
        for name, text in systemd_units(argv, hour).items():
            (folder / name).write_text(text, encoding="utf-8")
        for cmd in (["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", "--now", f"{UNIT}.timer"]):
            res = run(cmd)
            if res.returncode:
                return _failed(" ".join(cmd), res)
        return None
    lines = _crontab(run)
    if lines is None:
        return "no systemd user session and no cron on this computer: run 'homograph-guard update --if-due' once a day"
    lines = [line for line in lines if CRON_TAG not in line] + cron_lines(argv, hour)
    res = run(["crontab", "-"], "\n".join(lines) + "\n")
    return None if res.returncode == 0 else _failed("crontab", res)


def _linux_uninstall(run) -> bool:
    removed = False
    folder = _systemd_dir()
    if (folder / f"{UNIT}.timer").exists() or (folder / f"{UNIT}.service").exists():
        if _user_systemd(run):
            run(["systemctl", "--user", "disable", "--now", f"{UNIT}.timer"])
        for name in (f"{UNIT}.timer", f"{UNIT}.service"):
            (folder / name).unlink(missing_ok=True)
        if _user_systemd(run):
            run(["systemctl", "--user", "daemon-reload"])
        removed = True
    lines = _crontab(run)
    if lines and any(CRON_TAG in line for line in lines):
        kept = [line for line in lines if CRON_TAG not in line]
        run(["crontab", "-"], "\n".join(kept) + "\n" if kept else "")
        removed = True
    return removed


def _linux_status(run) -> str | None:
    if (_systemd_dir() / f"{UNIT}.timer").exists():
        if _user_systemd(run):
            res = run(["systemctl", "--user", "list-timers", f"{UNIT}.timer", "--all", "--no-pager"])
            return f"systemd user timer {UNIT}.timer\n{res.stdout.strip()}"
        return f"systemd user timer {UNIT}.timer (installed; no user session right now)"
    tagged = [line for line in (_crontab(run) or []) if CRON_TAG in line]
    return "crontab:\n" + "\n".join(tagged) if tagged else None


# ------------------------------------------------------------------ macOS: launchd agent
def _launch_agent() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"


def launchd_plist(argv: list[str], hour: int = 9) -> bytes:
    return plistlib.dumps({
        "Label": LAUNCHD_LABEL,
        "ProgramArguments": list(argv),
        "StartCalendarInterval": [{"Hour": h, "Minute": 0} for h in retry_hours(hour)],
        "RunAtLoad": True,  # catch up at login; --if-due keeps that free when nothing is due
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "Nice": 10,
        "Umask": 0o077,
        "StandardOutPath": "/dev/null",
        "StandardErrorPath": "/dev/null",
    })


def _gui_domain() -> str:
    return f"gui/{os.getuid()}"


def _mac_install(argv: list[str], hour: int, run) -> str | None:
    plist = _launch_agent()
    plist.parent.mkdir(parents=True, exist_ok=True)
    plist.write_bytes(launchd_plist(argv, hour))
    run(["launchctl", "bootout", f"{_gui_domain()}/{LAUNCHD_LABEL}"])  # replace an older copy
    res = run(["launchctl", "bootstrap", _gui_domain(), str(plist)])
    if res.returncode:
        res = run(["launchctl", "load", "-w", str(plist)])  # macOS before 10.10
    return None if res.returncode == 0 else _failed("launchctl", res)


def _mac_uninstall(run) -> bool:
    plist = _launch_agent()
    if not plist.exists():
        return False
    run(["launchctl", "bootout", f"{_gui_domain()}/{LAUNCHD_LABEL}"])
    plist.unlink()
    return True


def _mac_status(run) -> str | None:
    if not _launch_agent().exists():
        return None
    res = run(["launchctl", "print", f"{_gui_domain()}/{LAUNCHD_LABEL}"])
    return f"launchd agent {LAUNCHD_LABEL} ({'loaded' if res.returncode == 0 else 'installed, not loaded'})"


# ------------------------------------------------------------------ public API
def preview(install_dir: Path | None = None, hour: int = 9) -> dict[str, str]:
    """What ``install`` would create, by location (for review or machine-wide deployment)."""
    argv = update_argv(install_dir)
    plat = _platform()
    if plat == "windows":
        from . import winsetup

        program, arguments = winsetup.update_command(install_dir)
        return {f"Task Scheduler task '{winsetup.TASK_NAME}'": winsetup.task_xml(program, arguments, hour)}
    if plat == "mac":
        return {str(_launch_agent()): launchd_plist(argv, hour).decode("utf-8")}
    return {str(_systemd_dir() / name): text for name, text in systemd_units(argv, hour).items()}


def display(argv: list[str]) -> str:
    """The command as you would type it in this system's shell."""
    return subprocess.list2cmdline(argv) if _platform() == "windows" else shlex.join(argv)


def describe() -> str:
    return {"windows": "Task Scheduler task", "mac": "launchd agent", "linux": "systemd user timer (or cron)"}[_platform()]


def install(install_dir: Path | None = None, hour: int = 9, run=_run) -> str | None:
    """Create the daily update; returns an error message, or None when it worked."""
    if not 0 <= hour <= 23:
        raise ValueError("hour must be between 0 and 23")
    plat = _platform()
    if plat == "windows":
        from . import winsetup

        return winsetup.schedule_install(install_dir, hour)
    argv = update_argv(install_dir)
    return _mac_install(argv, hour, run) if plat == "mac" else _linux_install(argv, hour, run)


def uninstall(run=_run) -> bool:
    plat = _platform()
    if plat == "windows":
        from . import winsetup

        return winsetup.schedule_uninstall()
    return _mac_uninstall(run) if plat == "mac" else _linux_uninstall(run)


def status(run=_run) -> str | None:
    plat = _platform()
    if plat == "windows":
        from . import winsetup

        return winsetup.schedule_status()
    return _mac_status(run) if plat == "mac" else _linux_status(run)
