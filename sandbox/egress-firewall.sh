#!/usr/bin/env bash
# Linux host firewall for the sandbox (needs root and Docker's iptables integration).
#
# Creates the Docker network "hguard-egress". Containers attached to it can reach ONLY the
# pinned public resolvers (UDP/TCP 53, TCP 443 for DoH, TCP 853 for DoT). Everything else -
# including the suspect sites, your LAN and the host itself - is rejected.
# sandbox/run.sh and the GUI use this network automatically when it exists.
#
#   sudo sandbox/egress-firewall.sh up
#   sudo sandbox/egress-firewall.sh status
#   sudo sandbox/egress-firewall.sh down
#
# Note: --tls-peek needs to reach the suspect server on port 443, which this network blocks
# by design. Run TLS peeks on a separate, disposable network (e.g. through a VPN).
set -euo pipefail

NET=hguard-egress
BRIDGE=br-hguard
SUBNET="${HGUARD_SUBNET:-172.31.250.0/24}"
CHAIN=HGUARD-EGRESS
RESOLVERS=(
  8.8.8.8 8.8.4.4                       # Google Public DNS
  1.1.1.1 1.0.0.1 1.1.1.2 1.0.0.2       # Cloudflare / Cloudflare security
  94.140.14.14 94.140.15.15             # AdGuard default
  94.140.14.140 94.140.14.141           # AdGuard non-filtering
  94.140.14.15 94.140.15.16             # AdGuard family
  9.9.9.9 149.112.112.112 9.9.9.10 149.112.112.10   # Quad9 (optional resolvers)
)

need_root() {
  if [[ $EUID -ne 0 ]]; then echo "run as root (sudo)" >&2; exit 1; fi
}

up() {
  need_root
  if ! iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    echo "DOCKER-USER chain not found - is Docker running with its iptables integration?" >&2
    exit 1
  fi
  docker network inspect "$NET" >/dev/null 2>&1 ||
    docker network create --driver bridge --subnet "$SUBNET" \
      -o "com.docker.network.bridge.name=$BRIDGE" "$NET" >/dev/null

  iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"
  iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  for ip in "${RESOLVERS[@]}"; do
    iptables -A "$CHAIN" -d "$ip" -p udp --dport 53 -j RETURN
    for port in 53 443 853; do
      iptables -A "$CHAIN" -d "$ip" -p tcp --dport "$port" -j RETURN
    done
  done
  iptables -A "$CHAIN" -j REJECT --reject-with icmp-admin-prohibited

  # Forwarded traffic leaving the sandbox bridge goes through the allowlist ...
  iptables -C DOCKER-USER -i "$BRIDGE" -j "$CHAIN" 2>/dev/null ||
    iptables -I DOCKER-USER -i "$BRIDGE" -j "$CHAIN"
  # ... and the containers may not talk to the host at all.
  iptables -C INPUT -i "$BRIDGE" -j REJECT 2>/dev/null ||
    iptables -I INPUT -i "$BRIDGE" -j REJECT

  echo "ready: containers on '$NET' can reach only ${#RESOLVERS[@]} pinned resolver addresses"
}

down() {
  need_root
  iptables -D DOCKER-USER -i "$BRIDGE" -j "$CHAIN" 2>/dev/null || true
  iptables -D INPUT -i "$BRIDGE" -j REJECT 2>/dev/null || true
  iptables -F "$CHAIN" 2>/dev/null || true
  iptables -X "$CHAIN" 2>/dev/null || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  echo "removed network '$NET' and its firewall rules"
}

status() {
  iptables -S "$CHAIN" 2>/dev/null || echo "no $CHAIN chain"
  docker network inspect "$NET" --format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null ||
    echo "no '$NET' network"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "usage: $0 up|down|status" >&2; exit 2 ;;
esac
