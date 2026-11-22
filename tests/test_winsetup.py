import ipaddress
import xml.etree.ElementTree as ET
from pathlib import Path

from homograph_guard import winsetup


def _covers(ranges: list[str], ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    for r in ranges:
        lo, hi = (ipaddress.ip_address(x) for x in r.split("-"))
        if lo.version == a.version and lo <= a <= hi:
            return True
    return False


def test_complement_excludes_exactly_the_resolvers():
    resolvers = winsetup.resolver_ips()
    assert "8.8.8.8" in resolvers and "1.1.1.2" in resolvers and "94.140.14.140" in resolvers
    ranges = winsetup.complement(resolvers, 4)
    for ip in resolvers:
        assert not _covers(ranges, ip), ip
    for ip in ("0.0.0.0", "8.8.8.7", "8.8.8.9", "1.1.1.3", "10.0.0.1", "192.168.1.1", "255.255.255.255", "93.184.215.14"):
        assert _covers(ranges, ip), ip
    v6 = winsetup.complement([], 6)
    assert v6 == ["::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]


def test_port_complement():
    assert winsetup.port_complement((53, 443, 853)) == "1-52,54-442,444-852,854-65535"
    assert winsetup.port_complement((1, 65535)) == "2-65534"
    assert winsetup.port_complement((2,)) == "1,3-65535"


def test_rules_only_restrict_our_programs():
    rules = winsetup.firewall_rules(Path(r"C:\Program Files\HomographGuard"))
    assert all(r["action"] == "block" for r in rules)
    assert all(r["program"].startswith(r"C:\Program Files\HomographGuard") for r in rules)
    assert all(r["name"].startswith(winsetup.RULE_PREFIX) for r in rules)
    inbound = [r for r in rules if r["dir"] == "in"]
    assert len(inbound) == 4
    host = [r for r in rules if "hg-native-host.exe" in r["program"] and r["dir"] == "out"]
    assert {r["protocol"] for r in host} == {"any", "TCP", "UDP"}
    cmd = winsetup.netsh_add(host[0])
    assert cmd[:5] == ["netsh", "advfirewall", "firewall", "add", "rule"] and any(a.startswith("remoteip=") for a in cmd)
    assert len({r["name"] for r in rules}) == len(rules)


def test_task_definition_is_valid_xml():
    xml = winsetup.task_xml(r"C:\Program Files\HomographGuard\hg-update.exe", "", 9)
    root = ET.fromstring(xml.replace('encoding="UTF-16"', ""))
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    assert root.find("t:Actions/t:Exec/t:Command", ns).text.endswith("hg-update.exe")
    assert root.find("t:Principals/t:Principal/t:RunLevel", ns).text == "LeastPrivilege"
    assert root.find("t:Settings/t:StartWhenAvailable", ns).text == "true"
    evil = winsetup.task_xml(r"C:\x<y>&z\hg-update.exe", '--x "<a>"', 9)
    ET.fromstring(evil.replace('encoding="UTF-16"', ""))  # escaped, still well formed


def test_task_retries_hourly_and_after_sign_in():
    import xml.etree.ElementTree as ET

    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    root = ET.fromstring(winsetup.task_xml(r"C:\x\hg-update.exe", "", 9).replace('encoding="UTF-16"', ""))
    rep = root.find("t:Triggers/t:CalendarTrigger/t:Repetition", ns)
    assert rep.find("t:Interval", ns).text == "PT1H" and rep.find("t:Duration", ns).text == "PT12H"
    assert list(root.find("t:Triggers/t:CalendarTrigger", ns))[0].tag.endswith("Repetition")  # schema order
    assert root.find("t:Triggers/t:LogonTrigger/t:Delay", ns).text == "PT10M"
    assert root.find("t:Settings/t:StartWhenAvailable", ns).text == "true"
    assert root.find("t:Settings/t:MultipleInstancesPolicy", ns).text == "IgnoreNew"
