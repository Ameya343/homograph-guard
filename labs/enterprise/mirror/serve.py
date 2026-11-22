"""The organisation's internal feed mirror: HTTPS with a certificate from the company's own CA."""
import functools
import http.server
import ssl

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/srv/tls/server.pem", "/srv/tls/server.key")
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory="/srv/www")
server = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), handler)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print("mirror listening on 8443", flush=True)
server.serve_forever()
