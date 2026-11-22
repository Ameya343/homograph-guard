#!/bin/bash
# Enterprise network lab: a corporate network with no direct internet, a TLS-inspecting proxy
# (mitmproxy) as the only way out, and an internal feed mirror. The employee machine is the
# hardened homograph-guard image (read-only, no capabilities, no new privileges).
#   bash labs/enterprise/run.sh [python]   (a Python with the "cryptography" package, for the lab CA)
set -u
PY="${1:-python3}"
. "$(dirname "$0")/../_lib.sh"
mkdir -p "$(dirname "$0")/mirror/tls" "$(dirname "$0")/ca"   # generated: lab CA, mirror certificate, proxy root
LAB="$(hostpath "$(dirname "$0")")"
MITM=mitmproxy/mitmproxy:12.3.1
cleanup() { docker rm -f hg-proxy hg-mirror hg-client >/dev/null 2>&1; docker network rm hg-corp hg-internet >/dev/null 2>&1; }
cleanup

echo "=== building the hardened image and the lab certificates"
docker build -q -t homograph-guard:lab "$REPO" >/dev/null || exit 1
"$PY" - "$LAB" "$REPO" <<'PY'
import shutil, sys
from pathlib import Path
lab, repo = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(repo / "tests"))
from dnslab import make_pki
ca, _, _ = make_pki(lab / "mirror" / "tls", ["hg-mirror"])
shutil.copy(ca, lab / "policies" / "lab-ca.pem")
print("company CA for the internal mirror: policies/lab-ca.pem")
PY

docker network create hg-internet >/dev/null
docker network create --internal hg-corp >/dev/null
docker run -d --name hg-proxy --network hg-internet -v "$LAB/proxy:/addon:ro" $MITM \
  mitmdump --listen-host 0.0.0.0 --listen-port 8080 --set block_global=false --flow-detail 0 -s /addon/log_requests.py >/dev/null
docker network connect hg-corp hg-proxy
for i in $(seq 1 30); do docker exec hg-proxy test -f /home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem && break; sleep 1; done
docker cp hg-proxy:/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem "$LAB/ca/corp-root.pem" >/dev/null
echo "corporate TLS-inspection root (public certificate only): ca/corp-root.pem"
docker run -d --name hg-mirror --network hg-corp -v "$LAB/mirror:/srv:ro" python:3.15-slim python /srv/serve.py >/dev/null

docker run --rm --name hg-client --network hg-corp --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,mode=1777 --tmpfs /data:rw,uid=10001,gid=10001,mode=0700 -e HGUARD_HOME=/data \
  -v "$LAB/ca:/ca:ro" -v "$LAB/policies:/policies:ro" -v "$LAB/client.sh:/client.sh:ro" \
  --entrypoint bash homograph-guard:lab /client.sh

docker logs hg-proxy > "$LAB/proxy.log" 2>&1
docker logs hg-mirror > "$LAB/mirror.log" 2>&1
echo; echo "=== 9. everything that crossed the corporate proxy"
"$PY" - "$LAB/proxy.log" <<'PY'
import collections, json, re, sys
lines = open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines()
reqs = [json.loads(l.split("REQUEST ", 1)[1]) for l in lines if "REQUEST {" in l]
hosts = collections.Counter((r["method"], re.sub(r"^https?://([^/:]+).*", r"\1", r["url"])) for r in reqs)
for (m, h), n in sorted(hosts.items()):
    print(f"  {n:>2} x {m} {h}")
names = sorted({k.lower() for r in reqs for k in r["headers"]})
print("  request headers sent:", ", ".join(names))
print("  user agents:", sorted({r["headers"].get("User-Agent", "") for r in reqs}))
print("  query strings:", sorted({r["url"].split("?", 1)[1] for r in reqs if "?" in r["url"]}) or "none")
print("  request bodies:", sum(r["body_bytes"] for r in reqs), "bytes")
tls = [l for l in lines if "TLS handshake failed" in l or "does not trust" in l]
print(f"  TLS handshakes the app refused (untrusted proxy certificate): {len(tls)}")
for l in tls[:2]:
    print("   ", l.strip()[:160])
PY
echo; echo "=== mirror requests"; grep -c '"GET /feeds/' "$LAB/mirror.log"
cleanup
echo "=== lab removed"
