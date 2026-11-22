"""Opt-in TLS certificate inspection of the suspect host (``--tls-peek``).

This is the ONLY feature that touches the suspect's own server: one TCP
connection to port 443 and a TLS handshake using the punycode hostname as SNI.
No HTTP request is ever sent, so no page, script, cookie or redirect can be
received. The server operator *does* learn your IP address - run it through
a VPN or lab egress if that matters.
"""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
import time

from . import guard


def _cert_fields(cert: dict) -> dict:
    def rdn(seq) -> dict:
        out: dict[str, str] = {}
        for item in seq or ():
            for key, value in item:
                out.setdefault(key, value)
        return out

    subject, issuer = rdn(cert.get("subject")), rdn(cert.get("issuer"))
    out = {
        "subject_cn": subject.get("commonName"),
        "issuer": " / ".join(x for x in (issuer.get("organizationName"), issuer.get("commonName")) if x),
        "san": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:100],
    }
    for key, field in (("not_before", "notBefore"), ("not_after", "notAfter")):
        if cert.get(field):
            try:
                out[key] = int(ssl.cert_time_to_seconds(cert[field]))
            except ValueError:
                pass
    return out


def _parse_der(der: bytes) -> dict:
    """Parse an unverified certificate with `cryptography`, if it is installed."""
    try:
        from cryptography import x509
    except ImportError:
        return {}
    try:
        cert = x509.load_der_x509_certificate(der)
        out: dict = {
            "issuer": cert.issuer.rfc4514_string()[:300],
            "subject_cn": next((a.value for a in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)), None),
            "not_before": int(cert.not_valid_before_utc.timestamp()),
            "not_after": int(cert.not_valid_after_utc.timestamp()),
            "san": [],
        }
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            out["san"] = ext.value.get_values_for_type(x509.DNSName)[:100]
        except x509.ExtensionNotFound:
            pass
        return out
    except Exception:  # malformed attacker certificate - report nothing rather than crash
        return {}


def _target_allowed(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Never touch private, loopback or link-local hosts (no SSRF into your own network)."""
    return addr.is_global


def tls_peek(ip: str, sni: str, port: int = 443, timeout: float = 5.0, cafile: str | None = None) -> dict:
    result: dict = {"ip": ip, "port": port, "sni": sni, "verified": False}
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        result["error"] = "not an IP address"
        return result
    if not _target_allowed(addr):
        result["error"] = "refused: will not connect to a private or local address"
        return result
    if guard.installed():
        guard.allow_endpoint(ip, port, "tcp")

    ctx = ssl.create_default_context()
    if cafile:
        ctx.load_verify_locations(cafile=cafile)
    started = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                cert = tls.getpeercert() or {}
                der = tls.getpeercert(binary_form=True) or b""
                result.update(_cert_fields(cert))
                result.update(verified=True, tls_version=tls.version(), sha256=hashlib.sha256(der).hexdigest())
    except ssl.SSLCertVerificationError as exc:
        result["verify_error"] = (exc.verify_message or str(exc))[:200]
        # Second handshake WITHOUT verification, only to fingerprint and describe the
        # certificate the server presented. No application data is exchanged.
        loose = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        loose.check_hostname = False
        # Inspection only: no application data is ever sent over this connection.
        loose.verify_mode = ssl.CERT_NONE  # nosec B502
        try:
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with loose.wrap_socket(raw, server_hostname=sni) as tls:
                    der = tls.getpeercert(binary_form=True) or b""
                    result["tls_version"] = tls.version()
            result["sha256"] = hashlib.sha256(der).hexdigest()
            result.update(_parse_der(der))
        except (OSError, ssl.SSLError) as exc2:
            result["error"] = f"{type(exc2).__name__}: {exc2}"[:200]
    except (OSError, ssl.SSLError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"[:200]
    result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    if result.get("not_before"):
        result["age_days"] = round((time.time() - result["not_before"]) / 86400, 1)
    return result
