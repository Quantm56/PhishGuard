#!/bin/bash
# Container entrypoint: set up iptables egress rules BEFORE the worker runs.
#
# Security model
# ==============
# This script is the HARD network boundary. The Playwright route intercept in
# worker.py is a second layer that gives structured error messages, but the
# iptables rules here are the authoritative enforcement point.
#
# Blocked destinations
# --------------------
#   RFC 1918 private ranges:       10/8, 172.16/12, 192.168/16
#   Loopback:                      127/8
#   Link-local / IMDS:             169.254/16
#   CGNAT:                         100.64/10
#   Documentation / reserved:      192.0.2/24, 198.51.100/24, 203.0.113/24
#   Broadcast / multicast:         224/4, 240/4, 255.255.255.255/32
#
# IMPORTANT LIMITATION:
#   This iptables-based egress filter is effective only when the container
#   has NET_ADMIN capability and iptables is available in the image (both are
#   set up in docker-compose.yml and the Dockerfile).
#   Without NET_ADMIN, the script prints a clear warning but continues so
#   that the worker still functions in test environments. In production, the
#   container MUST be started with NET_ADMIN or the compose service definition
#   that grants it. See README § Security Limitations.
set -euo pipefail

BLOCKED_RANGES=(
    10.0.0.0/8
    172.16.0.0/12
    192.168.0.0/16
    127.0.0.0/8
    169.254.0.0/16
    100.64.0.0/10
    192.0.2.0/24
    198.51.100.0/24
    203.0.113.0/24
    224.0.0.0/4
    240.0.0.0/4
)

setup_iptables() {
    if [ "${PHISHGUARD_ALLOW_LOCAL_TEST:-0}" = "1" ]; then
        echo "[entrypoint] TEST MODE: PHISHGUARD_ALLOW_LOCAL_TEST=1 - skipping iptables egress filtering for local test fixture." >&2
        return
    fi
    if ! command -v iptables &>/dev/null; then
        echo "[entrypoint] WARNING: iptables not found – network egress not filtered at OS level." >&2
        return
    fi
    if ! iptables -L OUTPUT -n &>/dev/null 2>&1; then
        echo "[entrypoint] WARNING: iptables OUTPUT chain not writable (missing NET_ADMIN?) – egress not filtered." >&2
        return
    fi

    echo "[entrypoint] Installing egress iptables rules…" >&2
    for cidr in "${BLOCKED_RANGES[@]}"; do
        iptables -A OUTPUT -d "$cidr" -j REJECT --reject-with icmp-net-unreachable 2>/dev/null || true
    done

    # Allow DNS (port 53) to the configured nameservers so legitimate domain lookup succeeds
    if [ -f /etc/resolv.conf ]; then
        NAMESERVERS=$(grep -E '^nameserver' /etc/resolv.conf | awk '{print $2}')
        for ns in $NAMESERVERS; do
            iptables -I OUTPUT 1 -d "$ns" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
            iptables -I OUTPUT 1 -d "$ns" -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
        done
    fi

    echo "[entrypoint] Egress rules applied." >&2
}

setup_iptables

# Run the worker with the supplied arguments (or default: read from stdin)
exec "$@"

