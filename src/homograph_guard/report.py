"""Human-readable rendering. Every attacker-controlled string passes through safe_text()."""

from __future__ import annotations

import json
import shutil
import textwrap

from .textsafe import safe_text

_COLORS = {
    "critical": "\033[1;97;41m", "high": "\033[1;91m", "medium": "\033[1;93m", "low": "\033[96m",
    "info": "\033[2m", "good": "\033[92m", "bold": "\033[1m", "dim": "\033[2m", "reset": "\033[0m",
    "high_risk": "\033[1;97;41m", "suspicious": "\033[1;30;43m", "caution": "\033[1;30;46m",
    "no_indicators": "\033[1;30;42m", "error": "\033[1;97;45m",
}


class Painter:
    def __init__(self, color: bool):
        self.color = color

    def __call__(self, text: str, style: str) -> str:
        if not self.color or style not in _COLORS:
            return text
        return f"{_COLORS[style]}{text}{_COLORS['reset']}"


def to_json(reports: list[dict]) -> str:
    # ensure_ascii keeps bidi/invisible characters escaped in raw JSON (safe in terminals and SIEMs)
    return json.dumps(reports, ensure_ascii=True, indent=2)


def to_jsonl(report: dict) -> str:
    return json.dumps(report, ensure_ascii=True, separators=(",", ":"))


_SOURCES = {
    "anchor": "link", "area": "image-map link", "form": "form target", "iframe": "embedded frame",
    "frame": "frame", "embed": "embedded object", "object": "embedded object",
    "meta-refresh": "automatic redirect", "attribute": "link attribute", "text": "address written as text",
    "header": "sender address", "button": "form button", "input": "form button",
}


def group_regions(per_region: dict[str, list[str]]) -> str:
    """{"US East": [ip], "India": [ip2], ...} -> "ip (US East, UK); ip2 (India)", or "ip (all 10 regions)"."""
    groups: dict[str, list[str]] = {}
    for region, ips in per_region.items():
        groups.setdefault(", ".join(ips[:2]) or "no answer", []).append(region)
    if len(groups) == 1:
        (ips, regions), = groups.items()
        return f"{ips} (all {len(regions)} regions)" if len(regions) > 1 else f"{ips} ({regions[0]})"
    return "; ".join(f"{ips} ({', '.join(regions)})" for ips, regions in groups.items())


def describe_context(ctx: dict) -> str:
    what = _SOURCES.get(ctx.get("source", ""), ctx.get("source", "link"))
    out = what + (f" in {ctx['where']}" if ctx.get("where") else "")
    if ctx.get("hidden"):
        out += f", hidden ({ctx['hidden']})"
    return out


def _wrap(text: str, indent: int, width: int) -> list[str]:
    return textwrap.wrap(text, width=max(40, width - indent), break_long_words=True) or [""]


def render_text(report: dict, color: bool = False, index: int | None = None, total: int | None = None) -> str:
    paint = Painter(color)
    width = min(110, shutil.get_terminal_size((100, 24)).columns)
    lines: list[str] = []
    head = "homograph-guard"
    if index is not None and total:
        head += f"  [{index}/{total}]"
    lines.append(paint(head, "dim"))

    url = report.get("url") or {}
    rows = [("Input", safe_text(report.get("input"), 300))]
    ctx = report.get("context") or {}
    if ctx:
        rows.append(("Found", safe_text(describe_context(ctx), 200)))
    if ctx.get("text"):
        rows.append(("Link text", safe_text(ctx["text"], 200)))
    wrapped = report.get("wrapped") or {}
    hops = wrapped.get("hops") or []
    for hop in hops:
        if hop.get("kind") == "advert":
            rows.append(("Ad network", safe_text(f"{hop['vendor']} on {hop['host']}", 200)))
            continue
        if hop.get("kind") == "shortener":
            rows.append(("Short link", safe_text(hop["wrapper_url"], 200)))
            continue
        note = "" if hop.get("trusted") else "  (unverified host)"
        rows.append(("Rewritten by", safe_text(f"{hop['service']} on {hop['host']}", 200) + note))
    if hops and hops[-1].get("kind") == "advert":
        rows.append(("Destination", "chosen by the ad server when the link is clicked"))
    elif hops:
        rows.append(("Destination", safe_text(wrapped.get("destination"), 300)))
    if wrapped.get("embedded"):
        rows.append(("Carries", safe_text(wrapped["embedded"]["url"], 300)))
    short = report.get("short_link") or {}
    if short and not short.get("destination"):
        rows.append(("Leads to", "not known - " + safe_text(short.get("reason") or "the service did not say", 300)))
    elif short.get("by") == "browser":
        rows.append(("Found by", "your browser, at your request (the destination was not opened)"))
    if report.get("defanged"):
        rows.append(("Defanged", safe_text(report["defanged"], 300)))
    if url.get("host_unicode") and url.get("host_unicode") != url.get("host_ascii"):
        rows.append(("Displays as", safe_text(url["host_unicode"], 200)))
    if url.get("host_ascii"):
        rows.append(("DNS name", safe_text(url["host_ascii"], 200)))
    if url.get("registrable"):
        extra = f"   (suffix .{url['suffix']})" if url.get("suffix") else ""
        rows.append(("Registrable", safe_text(url["registrable"], 200) + extra))
    if url.get("display_name"):
        rows.append(("Sender name", safe_text(url["display_name"], 200)))
    for k, v in rows:
        lines.append(f"  {k:<12} {v}")

    verdict = report.get("verdict", "error")
    badge = paint(f" {report.get('verdict_label', verdict.upper())} ", verdict)
    lines.append("")
    lines.append(f"  {badge}  {paint(str(report.get('score', 0)) + '/100', 'bold')}  {safe_text(report.get('summary'), 200)}")
    if report.get("error"):
        lines.append(f"  {paint('error:', 'high')} {safe_text(report['error'], 300)}")

    findings = report.get("findings") or []
    if findings:
        lines.append("")
        lines.append(paint("  Findings", "bold"))
        for f in sorted(findings, key=lambda f: -abs(f["weight"])):
            sev = f["severity"]
            w = f["weight"]
            wtxt = f"{w:+d}" if w else " 0"
            style = "good" if w < 0 else sev
            lines.append(f"  {paint(f'{sev.upper():<8}', style)} {wtxt:>4}  {safe_text(f['title'], 160)}")
            if f.get("detail"):
                for part in _wrap(safe_text(f["detail"], 600), 17, width):
                    lines.append(" " * 17 + paint(part, "dim"))

    for lb in report.get("labels") or []:
        chars = lb.get("chars") or []
        if not chars:
            continue
        lines.append("")
        lines.append(paint(f"  Characters of label '{safe_text(lb['unicode'], 80)}'  "
                           f"(scripts: {', '.join(lb['scripts']) or '-'}; {lb['restriction']})", "bold"))
        lines.append(paint(f"  {'#':>3}  {'chr':<4} {'code':<8} {'script':<11} {'looks like':<11} name", "dim"))
        for c in chars[:64]:
            look = c.get("looks_like") or ""
            style = "high" if c.get("odd_script") else ("medium" if c.get("lookalike_kind") == "confusable" else None)
            glyph = safe_text(c["char"], 8)
            row = f"  {c['position']:>3}  {glyph:<4} {c['codepoint']:<8} {c['script']:<11} {safe_text(look, 10):<11} {c['name'][:48]}"
            lines.append(paint(row, style) if style else row)

    dns = report.get("dns")
    if dns and dns.get("resolvers"):
        lines.append("")
        lines.append(paint(f"  DNS comparison  (transport: {dns.get('transport', '?').upper()}, pinned resolver IPs)", "bold"))
        asn = dns.get("asn") or {}
        for r in dns["resolvers"]:
            a = r["a"]
            if a.get("error"):
                status, addrs = paint(f"{'ERROR':<9}", "medium"), safe_text(a["error"], 60)
            else:
                ips = a.get("addresses") or []
                addrs = ", ".join(ips[:3]) + (f" (+{len(ips) - 3})" if len(ips) > 3 else "") or "-"
                status = f"{a.get('rcode') or '?':<9}"
                if r.get("blocked"):
                    status = paint(f"{'BLOCKED':<9}", "high")
            net = ""
            first = next((ip for ip in (a.get("addresses") or []) if ip in asn), None)
            if first:
                info = asn[first]
                net = f"AS{info['asn']} {safe_text(info.get('as_name', ''), 30)}"
            tag = "filter" if r["filtering"] else "      "
            lines.append(f"  {safe_text(r['name'], 38):<38} {tag} {status} {addrs:<34} {net}")
            if r.get("blocked"):
                lines.append(" " * 4 + paint(f"-> {safe_text(r['block_reason'], 80)}", "high"))
        lines.append(f"  consensus: {dns.get('consensus')}")
        if dns.get("looked_up"):
            lines.append(f"  looked up: {safe_text(dns['looked_up'], 200)} only (a link in a message: sub-domains can carry a per-reader token)")
        if dns.get("ns"):
            lines.append(f"  nameservers: {safe_text(', '.join(dns['ns'][:4]), 200)}")
        if dns.get("mx") is not None:
            lines.append(f"  mail (MX): {safe_text(', '.join(dns['mx'][:3]) or 'none', 200)}")
        b = dns.get("brand")
        if b:
            regions = f" from {b['regions_checked']} regions" if b.get("regions_checked") else ""
            counts = ""
            if b.get("addresses"):
                n_ip, n_net = len(b["addresses"]), len(b.get("asns") or [])
                counts = f"  ({n_ip} address{'es' if n_ip != 1 else ''}, {n_net} network{'s' if n_net != 1 else ''})"
            lines.append(f"  compared with real {safe_text(b['domain'], 60)}{regions}: {b['relation']}{counts}")
            for label, key in (("real site", "brand_regions"), ("look-alike", "suspect_regions")):
                per = b.get(key) or {}
                if per:
                    lines.append(f"    {label} by region: {safe_text(group_regions(per), 400)}")
        for w in dns.get("warnings") or []:
            lines.append("  " + paint("warning: " + safe_text(w, 300), "medium"))
    elif dns and dns.get("asn"):
        lines.append("")
        for ip, info in dns["asn"].items():
            lines.append(f"  {ip}: AS{info['asn']} {safe_text(info.get('as_name', ''), 40)} ({info.get('country', '')})")

    tls = report.get("tls")
    if tls:
        lines.append("")
        lines.append(paint("  TLS certificate (opt-in peek, no HTTP sent)", "bold"))
        if tls.get("error") and not tls.get("sha256"):
            lines.append(f"  {safe_text(tls['error'], 200)}")
        else:
            lines.append(f"  issuer: {safe_text(tls.get('issuer'), 120)}   verified: {tls.get('verified')}"
                         + (f"   age: {tls['age_days']} days" if tls.get("age_days") is not None else ""))
            if tls.get("verify_error"):
                lines.append(f"  verify error: {safe_text(tls['verify_error'], 160)}")
            if tls.get("san"):
                lines.append(f"  SAN: {safe_text(', '.join(tls['san'][:6]), 300)}")
    lines.append("")
    return "\n".join(lines)
