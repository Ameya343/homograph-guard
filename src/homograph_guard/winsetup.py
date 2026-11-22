"""Windows setup: the daily update task and Windows Defender Firewall rules.

Used by the installer (and available as ``homograph-guard setup ...``).

Firewall rules (they only ever *restrict* Homograph Guard's own programs):

* no Homograph Guard program accepts inbound connections;
* the browser helper and the command-line tool may only talk to the pinned DNS
  resolvers (DNS ports only) - nothing else on the internet or your network;
* the desktop window never uses the network at all (checks run in a worker);
* the updater may only use HTTPS (and common proxy ports) - no UDP, no other ports.

Rules are created with ``netsh`` and need administrator rights; the task is a
normal per-user task that needs none.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import subprocess  # nosec B404 - fixed argument lists, no shell
import sys
import tempfile
from pathlib import Path
from xml.sax.saxutils import escape  # nosec B406 - only writes XML (the task definition), never parses it

from .dns_resolvers import CATALOG

TASK_NAME = "Homograph Guard daily update"
RULE_PREFIX = "Homograph Guard - "
EXES = {"gui": "HomographGuard.exe", "cli": "homograph-guard.exe", "host": "hg-native-host.exe", "update": "hg-update.exe"}
UPDATER_PORTS = (80, 443, 3128, 8080, 8443)  # HTTPS plus common proxy ports
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=60, creationflags=_NO_WINDOW, check=False)  # nosec B603


# ------------------------------------------------------------------ address and port arithmetic
def complement(addresses: list[str], version: int) -> list[str]:
    """Every address of the IP version except ``addresses``, as netsh ranges ("a-b")."""
    top = (1 << 32) - 1 if version == 4 else (1 << 128) - 1
    make = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    taken = sorted({int(ipaddress.ip_address(a)) for a in addresses if ipaddress.ip_address(a).version == version})
    out, start = [], 0
    for n in taken:
        if n > start:
            out.append(f"{make(start)}-{make(n - 1)}")
        start = n + 1
    if start <= top:
        out.append(f"{make(start)}-{make(top)}")
    return out


def port_complement(ports: tuple[int, ...] | list[int]) -> str:
    out, start = [], 1
    for p in sorted(set(ports)):
        if p > start:
            out.append(f"{start}-{p - 1}" if p - 1 > start else str(start))
        start = p + 1
    if start <= 65535:
        out.append(f"{start}-65535")
    return ",".join(out)


def resolver_ips(keys: tuple[str, ...] | None = None) -> list[str]:
    keys = keys or tuple(CATALOG)
    return sorted({ip for k in keys for ip in CATALOG[k].ips})


# ------------------------------------------------------------------ firewall rules
def firewall_rules(install_dir: Path, extra_updater_ports: tuple[int, ...] = ()) -> list[dict]:
    """The rule set as data (name + netsh arguments), so it can be reviewed and tested."""
    exe = {k: str(install_dir / v) for k, v in EXES.items()}
    resolvers = resolver_ips()
    not_resolvers = complement(resolvers, 4) + complement([], 6)
    rules: list[dict] = []
    for key, path in exe.items():
        rules.append({"name": f"{RULE_PREFIX}no inbound ({EXES[key]})", "dir": "in", "action": "block", "program": path,
                      "protocol": "any"})
    for key in ("host", "cli"):
        rules.append({"name": f"{RULE_PREFIX}only DNS resolvers ({EXES[key]})", "dir": "out", "action": "block",
                      "program": exe[key], "protocol": "any", "remoteip": ",".join(not_resolvers)})
        rules.append({"name": f"{RULE_PREFIX}only DNS ports TCP ({EXES[key]})", "dir": "out", "action": "block",
                      "program": exe[key], "protocol": "TCP", "remoteip": ",".join(resolvers),
                      "remoteport": port_complement((53, 443, 853))})
        rules.append({"name": f"{RULE_PREFIX}only DNS ports UDP ({EXES[key]})", "dir": "out", "action": "block",
                      "program": exe[key], "protocol": "UDP", "remoteip": ",".join(resolvers),
                      "remoteport": port_complement((53,))})
    rules.append({"name": f"{RULE_PREFIX}no network ({EXES['gui']})", "dir": "out", "action": "block",
                  "program": exe["gui"], "protocol": "any"})
    rules.append({"name": f"{RULE_PREFIX}updater HTTPS only TCP ({EXES['update']})", "dir": "out", "action": "block",
                  "program": exe["update"], "protocol": "TCP", "remoteport": port_complement((*UPDATER_PORTS, *extra_updater_ports))})
    rules.append({"name": f"{RULE_PREFIX}updater no UDP ({EXES['update']})", "dir": "out", "action": "block",
                  "program": exe["update"], "protocol": "UDP"})
    return rules


def netsh_add(rule: dict) -> list[str]:
    args = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule['name']}", f"dir={rule['dir']}",
            f"action={rule['action']}", f"program={rule['program']}", "enable=yes", "profile=any",
            f"protocol={rule['protocol']}"]
    if rule.get("remoteip"):
        args.append(f"remoteip={rule['remoteip']}")
    if rule.get("remoteport"):
        args.append(f"remoteport={rule['remoteport']}")
    return args


def firewall_install(install_dir: Path, extra_updater_ports: tuple[int, ...] = ()) -> list[str]:
    firewall_uninstall()  # replace, never duplicate
    errors = []
    for rule in firewall_rules(install_dir, extra_updater_ports):
        res = _run(netsh_add(rule))
        if res.returncode != 0:
            errors.append(f"{rule['name']}: {(res.stdout + res.stderr).strip()[:200]}")
    return errors


def firewall_uninstall() -> int:
    removed = 0
    for rule in firewall_rules(Path("C:/")):  # names do not depend on the path
        if _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule['name']}"]).returncode == 0:
            removed += 1
    return removed


def firewall_status() -> list[str]:
    present = []
    for rule in firewall_rules(Path("C:/")):
        if _run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule['name']}"]).returncode == 0:
            present.append(rule["name"])
    return present


# ------------------------------------------------------------------ daily update task
def update_command(install_dir: Path | None = None) -> tuple[str, str]:
    """(program, arguments) the task runs: the windowless updater, or Python for a pip installation."""
    if install_dir or getattr(sys, "frozen", False):
        base = install_dir or Path(sys.executable).parent
        return str(base / EXES["update"]), ""
    pyw = Path(sys.executable).with_name("pythonw.exe")
    entry = Path(__file__).resolve().with_name("_entry.py")
    return str(pyw if pyw.exists() else sys.executable), f'-I -B "{entry}" update --if-due --quiet'


def task_xml(program: str, arguments: str, hour: int = 9) -> str:
    user = f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}".strip("\\")
    start = dt.datetime.now().replace(hour=hour, minute=0, second=0, microsecond=0).isoformat()
    args = f"<Arguments>{escape(arguments)}</Arguments>" if arguments else ""
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Homograph Guard</Author>
    <Description>Refreshes the Homograph Guard threat database (public phishing and malware lists) once a day. If a download was interrupted or failed, it is retried every hour for the next 12 hours and after you sign in. Nothing about your browsing is sent.</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <Repetition>
        <Interval>PT1H</Interval>
        <Duration>PT12H</Duration>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>{start}</StartBoundary>
      <Enabled>true</Enabled>
      <RandomDelay>PT30M</RandomDelay>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT10M</Delay>
      <UserId>{escape(user)}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{escape(user)}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT30M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(program)}</Command>
      {args}
    </Exec>
  </Actions>
</Task>
"""


def schedule_install(install_dir: Path | None = None, hour: int = 9) -> str | None:
    program, arguments = update_command(install_dir)
    with tempfile.TemporaryDirectory() as tmp:
        xml = Path(tmp) / "task.xml"
        xml.write_text(task_xml(program, arguments, hour), encoding="utf-16")
        res = _run(["schtasks", "/Create", "/TN", TASK_NAME, "/XML", str(xml), "/F"])
    return None if res.returncode == 0 else (res.stdout + res.stderr).strip()[:300]


def schedule_uninstall() -> bool:
    return _run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"]).returncode == 0


def schedule_status() -> str | None:
    res = _run(["schtasks", "/Query", "/TN", TASK_NAME, "/FO", "LIST"])
    return res.stdout if res.returncode == 0 else None


def is_admin() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False
