import os
import sys

import pytest

from homograph_guard.gui.worker import WorkerConfig, build_command, run_batch


def test_docker_command_is_locked_down():
    cmd = build_command(WorkerConfig(mode="docker", dns=False, image="homograph-guard:test"))
    joined = " ".join(cmd)
    for flag in ("--read-only", "--cap-drop ALL", "no-new-privileges:true", "--network none",
                 "--pids-limit 64", "--memory 256m", "--user 10001:10001", "--rm"):
        assert flag in joined, flag
    assert cmd[cmd.index("homograph-guard:test") + 1:][:2] == ["--jsonl", "--stdin"]
    assert "--no-dns" in cmd and "--dns" not in cmd


def test_docker_command_with_dns_blocks_system_resolver():
    cmd = build_command(WorkerConfig(mode="docker", dns=True, network="bridge"))
    i = cmd.index("--network")
    assert cmd[i + 1] == "bridge" and cmd[cmd.index("--dns") + 1] == "127.0.0.1"


def test_local_command_uses_isolated_python():
    cmd = build_command(WorkerConfig(mode="local", dns=False))
    assert cmd[0] == sys.executable and cmd[1] == "-I" and cmd[3].endswith("_entry.py")


def test_targets_never_appear_on_the_command_line():
    cmd = build_command(WorkerConfig(mode="local", tls_peek=True))
    assert not any("://" in part for part in cmd)


def test_local_batch_streams_reports():
    seen = []
    reports = run_batch(WorkerConfig(mode="local", dns=False),
                        ["https://pаypal.com", "https://google.com", "-rf --help"],
                        on_report=seen.append)
    assert [r["verdict"] for r in reports][:2] == ["high_risk", "no_indicators"]
    assert len(seen) == 3 and reports[2]["input"] == "-rf --help"  # treated as data, not an option


def test_document_is_parsed_by_the_worker_not_the_gui():
    cmd = build_command(WorkerConfig(mode="local", dns=False), "eml")
    assert cmd[cmd.index("--jsonl") + 1:][:2] == ["--eml", "-"] and "--stdin" not in cmd
    with pytest.raises(ValueError):
        build_command(WorkerConfig(mode="local"), "exe")
    eml = (b'From: PayPal <service@paypa1.com>\nSubject: x\nContent-Type: text/html\n\n'
           b'<a href="https://paypa1.com/login">https://www.paypal.com/</a>'
           b'<span style="display:none">https://hidden.example/</span>')
    reports = run_batch(WorkerConfig(mode="local", dns=False), [], payload=eml, input_format="eml")
    assert len(reports) == 3
    link = next(r for r in reports if r["input"] == "https://paypa1.com/login")
    assert link["verdict"] == "high_risk" and link["context"]["text"] == "https://www.paypal.com/"
    assert any((r.get("context") or {}).get("hidden") == "display:none" for r in reports)


def test_document_format_detection():
    from homograph_guard.gui.app import document_format

    assert document_format("mail.EML", b"") == "eml"
    assert document_format("page.htm", b"") == "html"
    assert document_format("saved", b"<!DOCTYPE html><html>") == "html"
    assert document_format("msg.txt", b"Received: from x\nMessage-ID: <1@x>\n\nhi") == "eml"
    assert document_format("chat.txt", b"[10:15] Bank: update at sbi-kyc-update.in\n[10:16] Me: ok\n") == "text"
    assert document_format("links.txt", b"https://a.example\nhttps://b.example\n") is None


@pytest.mark.skipif(sys.platform.startswith("linux") and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")),
                    reason="needs a display (run under xvfb-run)")
def test_gui_smoke():
    # ImportError too: tkinter can exist while the Tk shared library is missing (slim images)
    tk = pytest.importorskip("tkinter", exc_type=ImportError)
    from homograph_guard.gui.app import App

    root = tk.Tk()
    try:
        app = App(root, force_local=True)
        app._add_report({"verdict": "high_risk", "score": 90, "input": "https://x", "defanged": "hxxps[://]x",
                         "summary": "s", "findings": [{"code": "C", "severity": "high", "weight": 50,
                                                       "title": "t‮", "detail": "d"}],
                         "labels": [{"unicode": "pаy", "chars": [{"position": 2, "char": "а",
                                     "codepoint": "U+0430", "script": "Cyrillic", "looks_like": "a",
                                     "lookalike_kind": "confusable", "odd_script": True, "name": "CYRILLIC"}]}],
                         "url": {"host_unicode": "pаy", "host_ascii": "xn--py-8kc"}, "dns": None})
        root.update()
        app._show_selected()
        assert "‮" not in app.t_findings.get("1.0", "end")
        app._add_report({"verdict": "high_risk", "score": 100, "input": "https://x", "summary": "s", "findings": [],
                         "context": {"source": "anchor", "text": "paypal.com", "hidden": "display:none",
                                     "where": "HTML body"},
                         "wrapped": {"destination": "https://y", "hops": [
                             {"service": "FortiMail URL click protection", "host": "fm.example", "trusted": False}]}})
        app.results.selection_set("1")
        root.update()
        app._show_selected()
        assert app.fact_vars["Found"].get() == "link in HTML body, hidden (display:none)"
        assert "unverified" in app.fact_vars["Rewritten by"].get()
        assert app.results.item("1")["values"][2].startswith("[hidden]")
    finally:
        root.destroy()
