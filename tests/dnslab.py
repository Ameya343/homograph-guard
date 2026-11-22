"""A tiny, local, multi-resolver DNS lab for tests.

Each fake "resolver" listens on its own loopback address and answers over
UDP, TCP, DNS-over-TLS and DNS-over-HTTPS with a certificate from a throwaway
test CA. Answers come from a scenario table, so tests can simulate a
phishing domain, a defensive registration, a hijacked resolver, and so on.
No packet ever leaves the machine.
"""

from __future__ import annotations

import base64
import datetime as dt
import http.server
import socket
import socketserver
import ssl
import struct
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import dns.edns
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset

from homograph_guard.dns_resolvers import Resolver

BASE_PORT = 18000


def make_pki(directory: Path, hostnames: list[str]) -> tuple[Path, Path, Path]:
    """Create a test CA and one server certificate valid for ``hostnames``."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "homograph-guard test lab"),
                         x509.NameAttribute(NameOID.COMMON_NAME, "Test Lab Root")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                       content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False,
                                       encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])]))
            .issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in hostnames]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_pem, cert_pem, key_pem = directory / "ca.pem", directory / "server.pem", directory / "server.key"
    ca_pem.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    return ca_pem, cert_pem, key_pem


class Lab:
    """Scenario table: (resolver_key, qname, rdtype) -> (rcode, [values], {"ede": (code, text), "ttl": n})."""

    def __init__(self, directory: Path):
        self.table: dict[tuple[str, str, str, str | None], tuple[str, list[str], dict]] = {}
        self.queries: list[tuple[str, str, str, str]] = []
        self.ecs_seen: list[str | None] = []
        self._threads: list[threading.Thread] = []
        self._servers: list = []
        self._socks: list[socket.socket] = []
        specs = [
            ("google", False, None, ()),
            ("cloudflare", False, None, ()),
            ("cloudflare-security", True, "cloudflare", ()),
            ("adguard-unfiltered", False, None, ()),
            ("adguard", True, "adguard-unfiltered", ("198.51.100.0/24",)),
        ]
        self.resolvers: list[Resolver] = []
        for i, (key, filtering, peer, nets) in enumerate(specs):
            ip = f"127.0.0.{11 + i}"
            self.resolvers.append(Resolver(
                key=key, provider=key.split("-")[0].title(), name=f"{key} (lab)", filtering=filtering,
                ips=(ip,), tls_host=f"{key}.dns.test", peer=peer, block_networks=nets,
                security_only=(key == "cloudflare-security"),
                doh_port=BASE_PORT + 443, dot_port=BASE_PORT + 853, udp_port=BASE_PORT + 53,
            ))
        self.by_ip = {r.ips[0]: r.key for r in self.resolvers}
        hostnames = [r.tls_host for r in self.resolvers]
        self.ca, cert, key = make_pki(directory, hostnames)
        self.server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.server_ctx.load_cert_chain(cert, key)
        self.server_ctx.set_alpn_protocols(["http/1.1", "dot"])

    # ------------------------------------------------------------ scenario helpers
    def set(self, key: str, qname: str, rdtype: str, rcode: str = "NOERROR",
            values: list[str] | None = None, ecs: str | None = None, **opts) -> None:
        """``ecs`` makes the answer apply only to queries carrying that client subnet (GeoDNS)."""
        self.table[(key, qname.lower().rstrip("."), rdtype, ecs)] = (rcode, values or [], opts)

    def set_all(self, keys, qname, rdtype, rcode="NOERROR", values=None, **opts):
        for k in keys:
            self.set(k, qname, rdtype, rcode, values, **opts)

    def answer(self, server_ip: str, wire: bytes) -> bytes:
        query = dns.message.from_wire(wire)
        key = self.by_ip.get(server_ip, "?")
        q = query.question[0]
        qname = q.name.to_text(omit_final_dot=True).lower()
        rdtype = dns.rdatatype.to_text(q.rdtype)
        ecs = next((f"{o.address}/{o.srclen}" for o in query.options if isinstance(o, dns.edns.ECSOption)), None)
        self.queries.append((key, qname, rdtype, server_ip))
        self.ecs_seen.append(ecs)
        resp = dns.message.make_response(query)
        rcode, values, opts = self.table.get((key, qname, rdtype, ecs)) or self.table.get(
            (key, qname, rdtype, None), ("NOERROR", [], {}))
        resp.set_rcode(dns.rcode.from_text(rcode))
        for v in values:
            resp.answer.append(dns.rrset.from_text(q.name, opts.get("ttl", 300), "IN", rdtype, v))
        if opts.get("ede"):
            code, text = opts["ede"]
            resp.use_edns(0, options=[dns.edns.EDEOption(code, text)])
        if opts.get("ad"):
            resp.flags |= dns.flags.AD
        return resp.to_wire()

    # ------------------------------------------------------------ servers
    def start(self) -> Lab:
        for r in self.resolvers:
            ip = r.ips[0]
            self._start_udp(ip, r.udp_port)
            self._start_tcp(ip, r.udp_port, tls=False)
            self._start_tcp(ip, r.dot_port, tls=True)
            self._start_doh(ip, r.doh_port)
        return self

    def stop(self) -> None:
        for srv in self._servers:
            srv.shutdown()
            srv.server_close()
        for s in self._socks:
            s.close()

    def _spawn(self, target) -> None:
        t = threading.Thread(target=target, daemon=True)
        t.start()
        self._threads.append(t)

    def _start_udp(self, ip: str, port: int) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((ip, port))
        self._socks.append(sock)

        def loop() -> None:
            while True:
                try:
                    data, addr = sock.recvfrom(65535)
                except OSError:
                    return
                try:
                    sock.sendto(self.answer(ip, data), addr)
                except Exception:  # noqa: BLE001 - test server
                    pass

        self._spawn(loop)

    def _start_tcp(self, ip: str, port: int, tls: bool) -> None:
        lab = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                conn = self.request
                if tls:
                    try:
                        conn = lab.server_ctx.wrap_socket(conn, server_side=True)
                    except (ssl.SSLError, OSError):
                        return
                try:
                    while True:
                        hdr = _recv_exact(conn, 2)
                        if not hdr:
                            return
                        (n,) = struct.unpack("!H", hdr)
                        out = lab.answer(ip, _recv_exact(conn, n))
                        conn.sendall(struct.pack("!H", len(out)) + out)
                except (OSError, ssl.SSLError, ValueError):
                    return
                finally:
                    # wrap_socket() detached self.request, so socketserver will not close the TLS socket
                    if conn is not self.request:
                        conn.close()

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        srv = Server((ip, port), Handler)
        self._servers.append(srv)
        self._spawn(srv.serve_forever)

    def _start_doh(self, ip: str, port: int) -> None:
        lab = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args) -> None:  # silence
                pass

            def do_GET(self) -> None:
                qs = parse_qs(urlsplit(self.path).query)
                raw = qs.get("dns", [""])[0]
                try:
                    wire = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
                    body = lab.answer(ip, wire)
                except Exception:  # noqa: BLE001
                    self.send_error(400)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/dns-message")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

        class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
            allow_reuse_address = True
            daemon_threads = True

            def get_request(self):
                conn, addr = super().get_request()
                return lab.server_ctx.wrap_socket(conn, server_side=True), addr

        srv = Server((ip, port), Handler)
        self._servers.append(srv)
        self._spawn(srv.serve_forever)


def _recv_exact(conn, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


def cymru(lab: Lab, ip: str, asn: int, prefix: str, cc: str, name: str) -> None:
    rev = ".".join(reversed(ip.split(".")))
    lab.set("google", f"{rev}.origin.asn.cymru.com", "TXT", values=[f'"{asn} | {prefix} | {cc} | ripencc | 2015-01-01"'])
    lab.set("google", f"AS{asn}.asn.cymru.com", "TXT", values=[f'"{asn} | {cc} | ripencc | 2001-01-01 | {name}"'])
