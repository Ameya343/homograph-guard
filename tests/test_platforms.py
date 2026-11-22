"""macOS and Linux behaviour, checked on every OS by simulating the platform.

On a real Mac or Linux machine the same tests run without simulation (CI runs them on
ubuntu-latest and macos-latest as well as Windows).
"""

import json
import plistlib
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from homograph_guard import native_install, paths, schedule
from homograph_guard.native_host import HOST_NAME


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: h))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    return h


def oncalendar(hour: int) -> str:
    return "OnCalendar=*-*-* " + ",".join(f"{h:02d}" for h in schedule.retry_hours(hour)) + ":00:00"


def as_platform(monkeypatch, name: str) -> None:
    monkeypatch.setattr(sys, "platform", {"mac": "darwin", "linux": "linux"}[name])
    monkeypatch.setattr(native_install, "_platform", lambda: name)
    monkeypatch.setattr(schedule, "_platform", lambda: name)


# ------------------------------------------------------------------ data and policy locations
def test_data_and_policy_locations_on_macos(home, monkeypatch):
    as_platform(monkeypatch, "mac")
    monkeypatch.delenv("HGUARD_HOME")
    monkeypatch.delenv("HGUARD_POLICY")
    assert paths.data_dir() == home / "Library" / "Application Support" / "HomographGuard"
    assert paths.policy_file() == Path("/Library/Application Support/HomographGuard/policy.json")
    assert paths.db_path().name == "threats.db"


def test_data_and_policy_locations_on_linux(home, monkeypatch, tmp_path):
    as_platform(monkeypatch, "linux")
    monkeypatch.delenv("HGUARD_HOME")
    monkeypatch.delenv("HGUARD_POLICY")
    assert paths.data_dir() == home / ".local" / "share" / "homograph-guard"
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    assert paths.data_dir() == tmp_path / "xdg-data" / "homograph-guard"
    assert paths.policy_file() == Path("/etc/homograph-guard/policy.json")


# ------------------------------------------------------------------ native messaging manifests
EXPECTED_USER = {
    "mac": {
        "chrome": "Library/Application Support/Google/Chrome/NativeMessagingHosts",
        "edge": "Library/Application Support/Microsoft Edge/NativeMessagingHosts",
        "brave": "Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts",
        "chromium": "Library/Application Support/Chromium/NativeMessagingHosts",
        "firefox": "Library/Application Support/Mozilla/NativeMessagingHosts",
    },
    "linux": {
        "chrome": ".config/google-chrome/NativeMessagingHosts",
        "edge": ".config/microsoft-edge/NativeMessagingHosts",
        "brave": ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts",
        "chromium": ".config/chromium/NativeMessagingHosts",
        "firefox": ".mozilla/native-messaging-hosts",
    },
}


@pytest.mark.parametrize("plat", ["mac", "linux"])
def test_register_for_every_browser_in_the_home_folder(home, monkeypatch, plat):
    as_platform(monkeypatch, plat)
    done = native_install.register()
    assert done == list(native_install.BROWSERS)
    launcher = paths.data_dir() / "native-messaging" / "hg-native-host"
    exec_line = launcher.read_text(encoding="utf-8").splitlines()[1]
    assert shlex.split(exec_line)[:4] == ["exec", sys.executable, "-I", "-B"]  # isolated mode: no PYTHONPATH injection
    assert shlex.split(exec_line)[-1] == "$@"
    status = native_install.registered()
    for browser, folder in EXPECTED_USER[plat].items():
        file = home / folder / f"{HOST_NAME}.json"
        assert status[browser] == str(file)
        m = json.loads(file.read_text(encoding="utf-8"))
        assert m["name"] == HOST_NAME and m["type"] == "stdio" and m["path"] == str(launcher)
        if browser == "firefox":
            assert m["allowed_extensions"] == ["{b8a89689-dc16-48f4-936e-100f254404d8}"]
            assert "allowed_origins" not in m
        else:
            assert m["allowed_origins"] == ["chrome-extension://lfcmpmjjgdljkicfeikalojnocghgibe/"]
    assert native_install.unregister() == list(native_install.BROWSERS)
    assert not any(native_install.registered().values())
    assert native_install.unregister() == []


def test_linux_follows_xdg_config_home(home, monkeypatch, tmp_path):
    as_platform(monkeypatch, "linux")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    native_install.register(["chrome", "firefox"])
    assert (tmp_path / "cfg" / "google-chrome" / "NativeMessagingHosts" / f"{HOST_NAME}.json").exists()
    assert (home / ".mozilla" / "native-messaging-hosts" / f"{HOST_NAME}.json").exists()  # Firefox reads only ~/.mozilla


def test_machine_wide_folders_are_the_documented_ones(monkeypatch):
    as_platform(monkeypatch, "linux")
    assert native_install.manifest_dir("chrome", machine=True) == Path("/etc/opt/chrome/native-messaging-hosts")
    assert native_install.manifest_dir("edge", machine=True) == Path("/etc/opt/edge/native-messaging-hosts")
    assert native_install.manifest_dir("chromium", machine=True) == Path("/etc/chromium/native-messaging-hosts")
    assert native_install.manifest_dir("firefox", machine=True) == Path("/usr/lib/mozilla/native-messaging-hosts")
    assert native_install.manifest_dir("brave", machine=True) is None  # Brave documents no system folder
    assert native_install._program_dir(True) == Path("/usr/local/lib/homograph-guard/native-messaging")
    as_platform(monkeypatch, "mac")
    assert native_install.manifest_dir("chrome", machine=True) == Path("/Library/Google/Chrome/NativeMessagingHosts")
    assert native_install.manifest_dir("edge", machine=True) == Path("/Library/Microsoft/Edge/NativeMessagingHosts")
    assert native_install.manifest_dir("firefox", machine=True) == Path("/Library/Application Support/Mozilla/NativeMessagingHosts")
    assert native_install.manifest_dir("brave", machine=True) is None


def test_launcher_quotes_unusual_paths(home, monkeypatch, tmp_path):
    as_platform(monkeypatch, "linux")
    odd = tmp_path / "my env $HOME `x`" / "bin" / "python3"
    monkeypatch.setattr(sys, "executable", str(odd))
    launcher = Path(native_install.host_command(tmp_path / "nm"))
    assert shlex.split(launcher.read_text(encoding="utf-8").splitlines()[1])[1] == str(odd)


# ------------------------------------------------------------------ daily update schedule
class FakeRun:
    """Records the commands the schedule would run; answers from a table."""

    def __init__(self, answers=None):
        self.calls: list[tuple[list[str], str | None]] = []
        self.answers = answers or {}

    def __call__(self, args, input_text=None):
        self.calls.append((args, input_text))
        rc, out = self.answers.get(" ".join(args[:3]), (0, ""))
        return subprocess.CompletedProcess(args, rc, out, "")

    def ran(self, *args) -> bool:
        return any(c[: len(args)] == list(args) for c, _ in self.calls)


def test_systemd_units(tmp_path):
    argv = ["/opt/my tools/python3", "-I", "-B", "/x/_entry.py", "update", "--if-due", "--quiet", "100%", "$HOME"]
    units = schedule.systemd_units(argv, hour=7)
    service, timer = units[f"{schedule.UNIT}.service"], units[f"{schedule.UNIT}.timer"]
    exec_start = next(line for line in service.splitlines() if line.startswith("ExecStart="))
    assert exec_start == 'ExecStart="/opt/my tools/python3" -I -B /x/_entry.py update --if-due --quiet 100%% $$HOME'
    for line in ("Type=oneshot", "NoNewPrivileges=yes", "SystemCallFilter=@system-service", "UMask=0077",
                 "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6"):
        assert line in service.splitlines()
    assert "User=" not in service and "ProtectSystem" not in service  # nothing that needs root or namespaces
    assert oncalendar(7) in timer.splitlines() and "Persistent=true" in timer and "WantedBy=timers.target" in timer
    assert oncalendar(7) == "OnCalendar=*-*-* 07,08,09,10,11,12,13,14,15,16,17,18,19:00:00"  # retried for 12 hours
    assert "OnStartupSec=10min" in timer  # and soon after sign-in


def test_linux_install_with_systemd(home, monkeypatch):
    as_platform(monkeypatch, "linux")
    monkeypatch.setattr(schedule.shutil, "which", lambda name: f"/usr/bin/{name}")
    run = FakeRun()
    assert schedule.install(hour=6, run=run) is None
    folder = home / ".config" / "systemd" / "user"
    assert oncalendar(6) in (folder / f"{schedule.UNIT}.timer").read_text(encoding="utf-8")
    exec_start = next(line for line in (folder / f"{schedule.UNIT}.service").read_text(encoding="utf-8").splitlines()
                      if line.startswith("ExecStart="))
    assert "update --if-due --quiet" in exec_start
    assert run.ran("systemctl", "--user", "daemon-reload")
    assert run.ran("systemctl", "--user", "enable", "--now", f"{schedule.UNIT}.timer")
    assert not any(c[0] == "sudo" or "--system" in c for c, _ in run.calls)
    assert "systemd user timer" in schedule.status(run=run)
    assert schedule.uninstall(run=run) is True
    assert not (folder / f"{schedule.UNIT}.timer").exists() and not (folder / f"{schedule.UNIT}.service").exists()
    assert run.ran("systemctl", "--user", "disable", "--now")


def test_linux_falls_back_to_cron_and_keeps_other_entries(home, monkeypatch):
    as_platform(monkeypatch, "linux")
    monkeypatch.setattr(schedule.shutil, "which", lambda name: None if name == "systemctl" else f"/usr/bin/{name}")
    old = f"0 3 * * * /old/python update {schedule.CRON_TAG}"
    run = FakeRun({"crontab -l": (0, f"MAILTO=me\n30 1 * * * backup.sh\n{old}\n")})
    assert schedule.install(hour=21, run=run) is None
    written = next(text for args, text in run.calls if args == ["crontab", "-"])
    lines = written.splitlines()
    assert lines[:2] == ["MAILTO=me", "30 1 * * * backup.sh"] and old not in lines
    assert lines[2].startswith("0 0,1,2,3,4,5,6,7,8,9,21,22,23 * * * ") and lines[2].endswith(schedule.CRON_TAG)
    assert lines[3].startswith("@reboot ") and len(lines) == 4
    run.answers["crontab -l"] = (0, written)
    assert schedule.CRON_TAG in schedule.status(run=run)
    assert schedule.uninstall(run=run) is True
    assert [args for args, _ in run.calls][-1] == ["crontab", "-"]
    assert run.calls[-1][1] == "MAILTO=me\n30 1 * * * backup.sh\n"


def test_cron_escapes_percent_signs():
    line = schedule.cron_lines(["/data/100%/python3", "update"], 9)[0]
    assert "100\\%" in line and line.startswith("0 9,10,11,12,13,14,15,16,17,18,19,20,21 * * * ")


def test_linux_without_systemd_or_cron_explains_what_to_do(home, monkeypatch):
    as_platform(monkeypatch, "linux")
    monkeypatch.setattr(schedule.shutil, "which", lambda name: None)
    assert "update --if-due" in schedule.install(run=FakeRun())


def test_macos_launch_agent(home, monkeypatch):
    as_platform(monkeypatch, "mac")
    monkeypatch.setattr(schedule.os, "getuid", lambda: 501, raising=False)
    run = FakeRun()
    assert schedule.install(hour=8, run=run) is None
    plist_file = home / "Library" / "LaunchAgents" / f"{schedule.LAUNCHD_LABEL}.plist"
    plist = plistlib.loads(plist_file.read_bytes())
    assert plist["Label"] == schedule.LAUNCHD_LABEL
    assert plist["ProgramArguments"][-3:] == ["update", "--if-due", "--quiet"]
    assert plist["StartCalendarInterval"] == [{"Hour": h, "Minute": 0} for h in range(8, 21)]
    assert plist["RunAtLoad"] is True and plist["ProcessType"] == "Background" and plist["Umask"] == 0o077
    assert run.ran("launchctl", "bootstrap", "gui/501", str(plist_file))
    assert "loaded" in schedule.status(run=run)
    assert schedule.uninstall(run=run) is True and not plist_file.exists()
    assert run.ran("launchctl", "bootout", f"gui/501/{schedule.LAUNCHD_LABEL}")
    assert schedule.uninstall(run=run) is False


def test_hour_is_checked():
    with pytest.raises(ValueError):
        schedule.install(hour=24, run=FakeRun())


@pytest.mark.parametrize("plat", ["mac", "linux"])
def test_preview_shows_what_install_would_create(home, monkeypatch, plat):
    as_platform(monkeypatch, plat)
    files = schedule.preview(hour=5)
    if plat == "mac":
        (where, text), = files.items()
        assert where.endswith(f"LaunchAgents{'/' if '/' in where else chr(92)}{schedule.LAUNCHD_LABEL}.plist")
        assert plistlib.loads(text.encode())["StartCalendarInterval"][0] == {"Hour": 5, "Minute": 0}
    else:
        assert sorted(Path(w).name for w in files) == [f"{schedule.UNIT}.service", f"{schedule.UNIT}.timer"]
        assert any(oncalendar(5) in t for t in files.values())
    assert not (home / "Library").exists() and not (home / ".config").exists()  # nothing was written


def test_schedule_uses_the_organisations_update_hour(home, monkeypatch, tmp_path, capsys):
    from homograph_guard import commands

    as_platform(monkeypatch, "linux")
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"update_hour": 6}), encoding="utf-8")
    monkeypatch.setenv("HGUARD_POLICY", str(policy))
    assert commands.main(["setup", "schedule", "show"]) == 0
    assert oncalendar(6) in capsys.readouterr().out
    with pytest.raises(SystemExit, match="organisation"):
        commands.main(["setup", "schedule", "show", "--hour", "22"])
    policy.write_text("{}", encoding="utf-8")
    assert commands.main(["setup", "schedule", "show"]) == 0
    assert oncalendar(9) in capsys.readouterr().out
