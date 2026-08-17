#!/usr/bin/env bash
# Read-only diagnostics for a site-to-site IPSec tunnel that will not come up.
#
# Changes nothing. Every command here only reads state, so it is safe to run on
# a production gateway and safe to run repeatedly.
#
# The question it answers, in order:
#   1. is this host blocking the peer, or the IKE ports?
#   2. is the peer's traffic arriving at all, and from which address?
#   3. what does the IKE daemon say about why the tunnel is down?
#
# Usage:  sudo bash scripts/diagnose-ipsec.sh [peer-ip]

set -u

PEER="${1:-76.230.144.67}"
CAPTURE_SECONDS="${CAPTURE_SECONDS:-20}"

say() { printf '\n=== %s ===\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo — firewall rules, IPSec state and packet capture all need root."
    echo "  sudo bash $0 ${PEER}"
    exit 1
fi

echo "Diagnosing IPSec tunnel to peer ${PEER}"
date

say "Network Sentinel service"
if have systemctl; then
    systemctl is-active networksentinel-web 2>/dev/null || echo "(networksentinel-web not active)"
    # A unit that is failing to start is worth seeing here — a half-installed
    # upgrade looks exactly like "the app is fine" from the outside otherwise.
    systemctl status networksentinel-web --no-pager -n 5 2>/dev/null | sed -n '1,12p'
else
    echo "(no systemctl)"
fi

say "Firewall rules naming the peer or the IKE ports"
FOUND_RULE=0
if have nft; then
    if nft list ruleset 2>/dev/null | grep -nE "${PEER}|\b(500|4500)\b"; then
        FOUND_RULE=1
    else
        echo "(nft: nothing matching)"
    fi
fi
if have iptables; then
    if iptables -S 2>/dev/null | grep -nE "${PEER}|\b(500|4500)\b"; then
        FOUND_RULE=1
    else
        echo "(iptables: nothing matching)"
    fi
fi
if have ip6tables; then
    ip6tables -S 2>/dev/null | grep -nE "${PEER}" || true
fi
echo "--> blocking rules present: ${FOUND_RULE} (0 = none found, so a block is NOT the cause)"

say "Configured peer addresses"
# Only the address fields, never the secrets alongside them.
CONFIGURED=$(grep -rhoE '^[[:space:]]*(left|right|local_addrs|remote_addrs)[[:space:]]*=[[:space:]]*[^#;]*' \
    /etc/ipsec.conf /etc/ipsec.d/*.conf /etc/swanctl/swanctl.conf /etc/swanctl/conf.d/*.conf 2>/dev/null \
    | sed 's/^[[:space:]]*//' | sort -u)
if [ -n "${CONFIGURED}" ]; then
    echo "${CONFIGURED}"
    echo "--> compare the remote address here against the UniFi's CURRENT WAN IP."
else
    echo "(no IPSec config found in /etc/ipsec* or /etc/swanctl — if the tunnel is"
    echo " terminated by something else, say so and I will point the checks there)"
fi

say "Live IPSec state"
if have swanctl; then
    swanctl --list-sas 2>&1 | sed -n '1,30p'
elif have ipsec; then
    ipsec status 2>&1 | sed -n '1,30p'
else
    echo "(neither swanctl nor ipsec found — is strongSwan installed?)"
fi

say "Kernel SAs"
if have ip; then
    # Header lines only: the rest of `ip xfrm state` is key material.
    ip xfrm state 2>/dev/null | grep -E '^src ' || echo "(no SAs installed — the tunnel is fully down)"
else
    echo "(no ip command)"
fi

say "Are the peer's packets arriving? (${CAPTURE_SECONDS}s capture)"
if have tcpdump; then
    echo "Watching UDP 500/4500 and ESP. Source addresses below are who is actually dialling in."
    timeout "${CAPTURE_SECONDS}" tcpdump -ni any -c 20 \
        'udp port 500 or udp port 4500 or proto 50' 2>&1 | sed -n '1,40p'
    echo "--> if this is empty, nothing is reaching the box: check Linode's Cloud Firewall"
    echo "    in the dashboard (a separate layer from nft/iptables, invisible from here)."
    echo "--> if packets arrive from an address other than ${PEER}, the far end's WAN IP"
    echo "    changed and the config above is pinned to the old one."
else
    echo "(tcpdump not installed: apt-get install -y tcpdump)"
fi

say "Recent IKE log"
if have journalctl; then
    for unit in strongswan strongswan-starter ipsec libreswan; do
        if journalctl -u "$unit" -n 25 --no-pager >/dev/null 2>&1; then
            echo "--- unit: ${unit} ---"
            journalctl -u "$unit" -n 25 --no-pager 2>/dev/null
        fi
    done
    # Some builds log to syslog under the charon tag rather than a unit.
    journalctl -t charon -n 25 --no-pager 2>/dev/null | sed -n '1,25p'
else
    tail -n 25 /var/log/syslog 2>/dev/null | grep -iE 'charon|ipsec|pluto' || echo "(no journal)"
fi

say "Done"
echo "Paste this whole output back. Nothing above changed any state."
