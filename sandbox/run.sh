#!/usr/bin/env bash
# Run homograph-guard inside a locked-down, throw-away container.
#
#   sandbox/run.sh https://xn--80ak6aa92e.com
#   sandbox/run.sh --stdin --json < urls.txt > report.json
#   sandbox/run.sh --no-dns "pаypal.com"                    (no network at all)
#
# What the container gets:
#   * read-only root filesystem, a small noexec tmpfs, nothing mounted from the host
#   * no Linux capabilities, no privilege escalation, non-root user 10001
#   * memory / CPU / process limits
#   * --network none when --no-dns is given; otherwise the firewalled "hguard-egress"
#     network if sandbox/egress-firewall.sh created it, else the default bridge
#   * a dead system resolver (--dns 127.0.0.1): the tool only talks to pinned resolver IPs
set -euo pipefail

IMAGE="${HGUARD_IMAGE:-homograph-guard:latest}"
NETWORK="${HGUARD_NETWORK:-}"

offline=0
for arg in "$@"; do
  if [[ "$arg" == "--no-dns" ]]; then offline=1; fi
done

if [[ $offline -eq 1 ]]; then
  net=(--network none)
else
  if [[ -z "$NETWORK" ]] && docker network inspect hguard-egress >/dev/null 2>&1; then
    NETWORK=hguard-egress
  fi
  net=(--network "${NETWORK:-bridge}" --dns 127.0.0.1)
fi

if [[ -t 0 && -t 1 ]]; then io=(-it); else io=(-i); fi

exec docker run --rm "${io[@]}" \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 64 --memory 256m --memory-swap 256m --cpus 1 \
  --user 10001:10001 \
  "${net[@]}" \
  "$IMAGE" "$@"
