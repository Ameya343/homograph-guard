"""mitmproxy addon: one JSON line per request that crosses the corporate proxy (method, URL, headers, body size)."""
import json

from mitmproxy import http


def request(flow: http.HTTPFlow) -> None:
    r = flow.request
    print("REQUEST " + json.dumps({"method": r.method, "url": r.pretty_url, "headers": dict(r.headers),
                                   "body_bytes": len(r.raw_content or b"")}), flush=True)
