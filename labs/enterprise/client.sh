#!/bin/bash
# The employee machine: hardened image, read-only, no capabilities, only on the corporate network.
set -u
hg() { python -I -B /app/src/homograph_guard/_entry.py "$@"; }
step() { echo; echo "=== $*"; }

step "1. the corporate network has no direct internet"
python -I - <<'PY'
import socket, urllib.request
for target in ("https://github.com/", "https://raw.githubusercontent.com/"):
    try:
        urllib.request.urlopen(target, timeout=5)
        print("REACHED (should not happen):", target)
    except Exception as exc:
        print("blocked:", target, "-", type(exc).__name__)
for ip in ("8.8.8.8", "1.1.1.1"):
    s = socket.socket(); s.settimeout(3)
    try:
        s.connect((ip, 443)); print("REACHED (should not happen):", ip)
    except OSError as exc:
        print("blocked: DoH resolver", ip, "-", type(exc).__name__)
    finally:
        s.close()
PY

step "2. update through the TLS-inspecting proxy WITHOUT the company's root certificate"
HGUARD_POLICY=/policies/proxy-only.json hg update --feed openphish --feed phishing-filter; echo "exit (expect 1, refused): $?"
hg db status | head -3

step "3. same proxy, with the company's root certificate from the policy file"
HGUARD_POLICY=/policies/proxy-and-ca.json hg update; echo "exit (expect 0): $?"

step "4. the user cannot change what the organisation set"
HGUARD_POLICY=/policies/proxy-and-ca.json hg settings set dns_mode all; echo "exit (expect non-zero): $?"
HGUARD_POLICY=/policies/proxy-and-ca.json hg settings show

step "5. organisation block and allow lists"
for u in https://payroll.corp-blocked-example.com/login https://partner-portal-example.com/ https://paypa1.com/signin; do
  HGUARD_POLICY=/policies/proxy-and-ca.json hg --no-dns --json "$u" > /tmp/r.json; rc=$?
  echo "$u -> exit $rc, $(grep -o '"verdict": "[a-z_]*"' /tmp/r.json | head -1), $(grep -o '"code": "LIST_[A-Z_]*\|"code": "FEED_[A-Z_]*' /tmp/r.json | tr '\n' ' ')"
done

step "6. DNS comparison when the firewall blocks DNS-over-HTTPS"
start=$(date +%s)
hg --json https://paypa1.com/login > /tmp/d.json; rc=$?
echo "exit $rc after $(( $(date +%s) - start )) s: $(grep -o '"verdict": "[a-z_]*"' /tmp/d.json | head -1), $(grep -o '"code": "DNS_[A-Z_]*"' /tmp/d.json | sort -u | tr '\n' ' ')"

step "7. air-gapped: no proxy at all, feeds only from the company's internal mirror"
export HGUARD_HOME=/tmp/mirror-home
HGUARD_POLICY=/policies/mirror.json hg update; echo "exit (expect 0): $?"
HGUARD_POLICY=/policies/mirror.json hg --no-dns --json https://mirror-only-phish.com/signin | grep -o '"verdict": "[a-z_]*"\|"code": "FEED_[A-Z_]*"' | tr '\n' ' '; echo
step "8. what the app left on the machine"
ls -la /data /tmp/mirror-home | sed -n '1,20p'
