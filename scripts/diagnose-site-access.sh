#!/usr/bin/env bash
# Read-only diagnostics for a site a tunnel client cannot reach — YouTube by default.
#
# The case it was written for: a WireGuard client reaches most of the web, but one
# family of sites hangs or errors, and the same client is fine with the tunnel off.
# That shape is almost never "the VPN is broken" — it is one of five specific things,
# and this prints the evidence for each in the order they turn out to be the answer.
#
# Changes nothing. Every command here only reads state, so it is safe on a production
# node and safe to run repeatedly.
#
# The questions it answers, in order:
#   1. is the filtering resolver refusing a name the site needs?
#   2. is a firewall rule on this node dropping the addresses that name resolves to?
#   3. does the tunnel offer IPv6 that this node cannot actually forward?
#      (the classic Google-only failure: every Google name has an AAAA, macOS prefers
#       it, and a half-configured v6 tunnel blackholes it while v4-only sites are fine)
#   4. is the tunnel's MTU too large for the path?
#   5. can this node reach the site at all — or is the site refusing the VPS?
#
# Usage:
#   sudo bash scripts/diagnose-site-access.sh                 # the YouTube name set
#   sudo bash scripts/diagnose-site-access.sh example.com …   # any other names
#
# Secrets: this never prints WireGuard private keys, the AdGuard password hash, or
# anything from settings.json beyond the named auto-block keys.

set -u

DEFAULT_DOMAINS=(
    www.youtube.com            # the page itself
    youtubei.googleapis.com    # the signed-in API — the page is inert without it
    accounts.google.com        # the session that makes "signed in" mean anything
    www.googleapis.com
    i.ytimg.com                # thumbnails
    yt3.ggpht.com              # avatars
    redirector.googlevideo.com # picks the media host
    manifest.googlevideo.com   # the media path itself
    jnn-pa.googleapis.com      # attestation; blocklists do carry it, and playback
                               # fails with "something went wrong" when it is refused
    oauthaccountmanager.googleapis.com  # token refresh on Apple platforms
)

# Blocked on purpose by any DNS ad blocker — and YouTube's player asks for them, so
# refusing them is visible to the page. These are NOT names to allow reflexively;
# they are here because a page that loads and then refuses to play is a different
# fault from a page that cannot connect, and this is what tells the two apart.
AD_DOMAINS=(
    googleads.g.doubleclick.net
    static.doubleclick.net
    pagead2.googlesyndication.com
    securepubads.g.doubleclick.net
    www.googleadservices.com
)

if [ "$#" -gt 0 ]; then
    DOMAINS=("$@")
else
    DOMAINS=("${DEFAULT_DOMAINS[@]}")
fi

CONTROL_DNS="${CONTROL_DNS:-9.9.9.9}"
CURL_TIMEOUT="${CURL_TIMEOUT:-8}"

say()  { printf '\n=== %s ===\n' "$1"; }
info() { printf '  %s\n' "$*"; }
verdict() { printf -- '--> %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo — firewall rules, the resolver's query log and sysctls all need root."
    echo "  sudo bash $0 $*"
    exit 1
fi

echo "Diagnosing client access to: ${DOMAINS[*]}"
date

# ---------------------------------------------------------------------------
# The tunnel
# ---------------------------------------------------------------------------
say "The tunnel"

TUN=""
for dev in /sys/class/net/*; do
    [ -e "${dev}/uevent" ] || continue
    if grep -q '^DEVTYPE=wireguard$' "${dev}/uevent" 2>/dev/null; then
        TUN="$(basename "$dev")"
        break
    fi
done
if [ -z "$TUN" ]; then
    for dev in /sys/class/net/*; do
        name="$(basename "$dev")"
        case "$name" in wg*|xfrm*|ipsec*|tun*) TUN="$name"; break ;; esac
    done
fi

if [ -n "$TUN" ]; then
    info "interface: ${TUN}"
    ip -brief addr show dev "$TUN" 2>/dev/null | sed 's/^/  /'
    TUN_MTU="$(cat "/sys/class/net/${TUN}/mtu" 2>/dev/null || echo '?')"
    info "MTU: ${TUN_MTU}"
    TUN_V4="$(ip -4 -o addr show dev "$TUN" 2>/dev/null | awk '{print $4}' | head -1)"
    TUN_V6="$(ip -6 -o addr show dev "$TUN" scope global 2>/dev/null | awk '{print $4}' | head -1)"
    if have wg && [ -d "/sys/class/net/${TUN}/wireguard" ]; then
        # $1 is the peer's public key on every line; replace it rather than print it.
        echo "  peers and what they are allowed to route into the tunnel:"
        wg show "$TUN" allowed-ips 2>/dev/null | awk '{$1="peer"; print "    " $0}'
    fi
else
    TUN_V4=""; TUN_V6=""; TUN_MTU=""
    info "(no wireguard/xfrm/tun interface found — is the tunnel up?)"
fi

DEF_IFACE="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
if [ -n "${DEF_IFACE:-}" ]; then
    info "egress interface: ${DEF_IFACE} (MTU $(cat "/sys/class/net/${DEF_IFACE}/mtu" 2>/dev/null || echo '?'))"
fi

# ---------------------------------------------------------------------------
# 1. The resolver
# ---------------------------------------------------------------------------
say "1. What the filtering resolver answers"

RESOLVED_IPS=""
if ! have dig; then
    info "(dig not installed, so the resolver comparison cannot run: apt-get install -y dnsutils)"
    info "falling back to the host's own resolution, which still feeds sections 2 and 4:"
    for d in "${DOMAINS[@]}"; do
        ips="$(getent ahostsv4 "$d" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')"
        shown="$(printf '%s' "$ips" | cut -d' ' -f1-3)"
        printf '  %-36s %s\n' "$d" "${shown:-did not resolve}"
        RESOLVED_IPS="${RESOLVED_IPS} ${ips}"
    done
else
    if have ss; then
        echo "  listening on 53:"
        ss -lnup 'sport = :53' 2>/dev/null | sed -n '2,6p' | sed 's/^/    /'
    fi

    # Ask whichever address actually answers. The setup script binds loopback and the
    # tunnel address; a client uses the tunnel one, so that is the more faithful test.
    TUN_ADDR_HINT="${TUN_V4%%/*}"
    TUN_ADDR_HINT="${TUN_ADDR_HINT:-the tunnel address}"
    LOCAL_DNS=""
    for cand in 127.0.0.1 "${TUN_V4%%/*}"; do
        [ -n "$cand" ] || continue
        if dig +time=2 +tries=1 "@${cand}" A example.com >/dev/null 2>&1 \
           && dig +time=2 +tries=1 "@${cand}" A example.com 2>/dev/null | grep -q 'status:'; then
            LOCAL_DNS="$cand"
            break
        fi
    done
    if [ -z "$LOCAL_DNS" ]; then
        LOCAL_DNS="127.0.0.1"
        verdict "nothing answered DNS on 127.0.0.1 or ${TUN_ADDR_HINT} — either the"
        verdict "filtering resolver is not installed here, or it is down. If your clients carry a"
        verdict "DNS = line pointing at this node, every name fails for them and no site works."
    else
        info "asking the resolver at ${LOCAL_DNS}"
    fi

    printf '\n  %-36s %-22s %s\n' "name" "this node's resolver" "control (${CONTROL_DNS})"
    DNS_BLOCKED=0
    for d in "${DOMAINS[@]}"; do
        local_out="$(dig +time=3 +tries=1 "@${LOCAL_DNS}" A "$d" 2>/dev/null)"
        local_status="$(printf '%s' "$local_out" | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)"
        local_ips="$(printf '%s' "$local_out" | awk '$4=="A" {print $5}' | tr '\n' ' ')"
        [ -z "$local_status" ] && local_status="NO-REPLY"

        ctl_out="$(dig +time=3 +tries=1 "@${CONTROL_DNS}" A "$d" 2>/dev/null)"
        ctl_status="$(printf '%s' "$ctl_out" | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)"
        ctl_ips="$(printf '%s' "$ctl_out" | awk '$4=="A" {print $5}' | tr '\n' ' ')"
        [ -z "$ctl_status" ] && ctl_status="NO-REPLY"

        note=""
        case "${local_ips}" in
            *0.0.0.0*|*127.0.0.1*) note="  <-- FILTERED (null answer)"; DNS_BLOCKED=1 ;;
        esac
        if [ -z "$note" ] && [ "$local_status" = "NXDOMAIN" ] && [ "$ctl_status" = "NOERROR" ]; then
            note="  <-- FILTERED (NXDOMAIN here, resolves upstream)"
            DNS_BLOCKED=1
        fi
        if [ -z "$note" ] && [ "$local_status" = "NO-REPLY" ]; then
            note="  <-- resolver did not answer"
        fi
        local_first="$(printf '%s' "$local_ips" | awk '{print $1}')"
        printf '  %-36s %-22s %s%s\n' "$d" \
            "${local_status} ${local_first:-—}" "${ctl_status}" "$note"
        RESOLVED_IPS="${RESOLVED_IPS} ${local_ips} ${ctl_ips}"
    done
    verdict "a FILTERED line above is the whole answer: the client never learns an address."
    verdict "blocked names: ${DNS_BLOCKED} (0 = the resolver is not what is stopping you)"

    # Refusing these is correct behaviour, so they get their own table: a blocked
    # count here is not a fault to fix, it is the fact that explains an adblock wall.
    echo ""
    echo "  ad endpoints (refusing these is the blocker working — but YouTube sees it):"
    AD_BLOCKED=0
    for d in "${AD_DOMAINS[@]}"; do
        a_out="$(dig +time=3 +tries=1 "@${LOCAL_DNS}" A "$d" 2>/dev/null)"
        a_status="$(printf '%s' "$a_out" | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)"
        a_ips="$(printf '%s' "$a_out" | awk '$4=="A" {print $5}' | head -1)"
        [ -z "$a_status" ] && a_status="NO-REPLY"
        mark=""
        if [ "$a_status" = "NXDOMAIN" ] || [ "${a_ips}" = "0.0.0.0" ]; then
            mark="  <-- refused"
            AD_BLOCKED=$(( AD_BLOCKED + 1 ))
        fi
        printf '  %-36s %s%s\n' "$d" "${a_status} ${a_ips}" "$mark"
    done
    if [ "$AD_BLOCKED" -gt 0 ]; then
        verdict "${AD_BLOCKED} ad endpoint(s) refused. On its own that is the blocker doing its"
        verdict "job. It becomes the answer when the page LOADS but will not PLAY, because"
        verdict "that is what YouTube does when it notices — and it is the one cause that"
        verdict "disappears with the tunnel off while every check in this script stays clean."
    fi
fi

echo ""
echo "  is the resolver itself healthy?"
if have systemctl; then
    printf '    AdGuardHome: %s\n' "$(systemctl is-active AdGuardHome 2>/dev/null || echo 'not installed')"
    journalctl -u AdGuardHome -n 200 --no-pager 2>/dev/null \
        | grep -iE 'error|refus|timeout|upstream|ratelimit' | tail -5 | sed 's/^/    /'
fi
if [ -f /opt/AdGuardHome/AdGuardHome.yaml ]; then
    verdict "setup-dns-filter.sh sets fallback_dns to none deliberately: if the encrypted"
    verdict "upstream stalls, names fail rather than leaking in the clear. Intermittent"
    verdict "failures on heavy pages and none on light ones look exactly like that."
fi

# What the resolver's own log says it refused — needs no credentials, unlike the API.
QLOG=""
for cand in /opt/AdGuardHome/data/querylog.json /opt/AdGuardHome/data/querylog.json.1; do
    [ -f "$cand" ] && QLOG="$cand" && break
done
if [ -n "$QLOG" ]; then
    echo ""
    echo "  names in these families that the resolver actually refused (last 20k queries):"
    tail -n 20000 "$QLOG" 2>/dev/null \
        | grep -F '"IsFiltered":true' \
        | grep -Ei 'youtube|googlevideo|ggpht|ytimg|googleapis|google\.com' \
        | sed -n 's/.*"QH":"\([^"]*\)".*/\1/p' | sort | uniq -c | sort -rn | head -20 \
        | sed 's/^/    /'
    echo "    (no lines above = nothing in these families was filtered)"

    # The ad endpoints, counted separately. Refusing these is the blocker doing its
    # job, not a fault — but YouTube's player asks for them, notices the refusal, and
    # answers with a wall instead of a video. That is the one cause where every
    # connectivity check in this script comes back clean and the site still fails.
    echo ""
    echo "  ad endpoints refused (this is the ad blocker working as intended):"
    AD_HITS="$(tail -n 20000 "$QLOG" 2>/dev/null \
        | grep -F '"IsFiltered":true' \
        | grep -Ei 'doubleclick|googlesyndication|googleadservices|googletagservices' \
        | sed -n 's/.*"QH":"\([^"]*\)".*/\1/p' | sort | uniq -c | sort -rn | head -10)"
    if [ -n "$AD_HITS" ]; then
        printf '%s\n' "$AD_HITS" | sed 's/^/    /'
        verdict "YouTube can see these being refused. If the page LOADS and then refuses to"
        verdict "play — an anti-adblock notice, or a video that never starts while the rest of"
        verdict "the site works — that is this, not a network fault, and it explains why the"
        verdict "same client is fine with the tunnel off: off the tunnel it is not filtered."
        verdict "Confirm by pausing protection for five minutes and reloading; if that fixes"
        verdict "it, decide whether you would rather see ads or allow these names."
    else
        echo "    (none — the ad endpoints are being answered, so this is not an adblock wall)"
    fi

    # Which clients are actually using this resolver, and for what record types. A
    # client absent from this list is not using it at all, which makes every
    # resolver-side setting — filters, aaaa_disabled, the rate limit — irrelevant to it.
    echo ""
    echo "  tunnel clients seen asking this resolver (last 20k queries):"
    tail -n 20000 "$QLOG" 2>/dev/null \
        | sed -n 's/.*"IP":"\([^"]*\)".*/\1/p' | sort | uniq -c | sort -rn | head -10 \
        | sed 's/^/    /'
    echo "  record types asked for the site families above:"
    tail -n 20000 "$QLOG" 2>/dev/null \
        | grep -Ei 'youtube|googlevideo|ytimg|ggpht' \
        | sed -n 's/.*"QT":"\([^"]*\)".*/\1/p' | sort | uniq -c | sort -rn | head -6 \
        | sed 's/^/    /'
    verdict "a client missing from that list is not using this resolver — check the DNS line"
    verdict "in its tunnel config before trusting any resolver-side test."
    verdict "HTTPS records in the type list matter: they carry ipv6hint values, so a client"
    verdict "can still be handed IPv6 while aaaa_disabled is on."
fi

if [ -f /opt/AdGuardHome/AdGuardHome.yaml ]; then
    echo ""
    echo "  resolver settings that change which family a client can reach:"
    grep -nE '^[[:space:]]*(protection_enabled|filtering_enabled|safebrowsing_enabled|parental_enabled|blocking_mode|aaaa_disabled|enable_dnssec|ratelimit):' \
        /opt/AdGuardHome/AdGuardHome.yaml 2>/dev/null | sed 's/^/    /'
    if grep -qE '^[[:space:]]*aaaa_disabled:[[:space:]]*true' /opt/AdGuardHome/AdGuardHome.yaml 2>/dev/null; then
        verdict "aaaa_disabled is ON. Two consequences worth knowing before you read section 3:"
        verdict "this node cannot look up an AAAA either, so any v6 test by NAME reports broken"
        verdict "whether or not it is (section 3 uses literal addresses and is unaffected); and"
        verdict "HTTPS/SVCB records still carry ipv6hint values, so a client can be handed IPv6"
        verdict "regardless. Removing v6 from the client tunnel config is the deterministic"
        verdict "version of this test — no cache, no record type, can lie to you."
    fi
    RATE="$(sed -n 's/^[[:space:]]*ratelimit:[[:space:]]*\([0-9]*\).*/\1/p' \
            /opt/AdGuardHome/AdGuardHome.yaml 2>/dev/null | head -1)"
    if [ -n "${RATE:-}" ] && [ "$RATE" != "0" ] && [ "$RATE" -lt 100 ] 2>/dev/null; then
        verdict "ratelimit is ${RATE} queries/second PER CLIENT, and queries over it are dropped"
        verdict "silently — no error, just no answer. One Mac opening a signed-in YouTube tab"
        verdict "bursts well past that: the page loads, then individual subresources fail. If"
        verdict "sections 2-5 come back clean, raise it (0 = unlimited) and retest. The limit"
        verdict "exists to stop amplification abuse, and allowed_clients already does that job"
        verdict "for a tunnel-only resolver."
    fi
    if grep -qE '^[[:space:]]*-[[:space:]]*\|\|.*(youtube|googlevideo|googleapis)' /opt/AdGuardHome/AdGuardHome.yaml 2>/dev/null; then
        echo "    user_rules mention these domains:"
        grep -nE '^[[:space:]]*-[[:space:]]*.*(youtube|googlevideo|googleapis)' \
            /opt/AdGuardHome/AdGuardHome.yaml | sed 's/^/      /'
    fi
fi

# ---------------------------------------------------------------------------
# 2. The firewall
# ---------------------------------------------------------------------------
say "2. Is anything on this node dropping those addresses"

# Unique /24s, so a rule written against a neighbouring Google address still shows up.
PREFIXES="$(printf '%s\n' ${RESOLVED_IPS:-} | grep -E '^[0-9]+(\.[0-9]+){3}$' \
            | sed -E 's/\.[0-9]+$//' | sort -u)"
if [ -z "$PREFIXES" ]; then
    info "(nothing resolved above, so there is no address to look for)"
else
    P_COUNT="$(printf '%s\n' $PREFIXES | wc -l)"
    info "looking for rules naming ${P_COUNT} networks, e.g. $(printf '%s.x ' $(printf '%s\n' $PREFIXES | head -5))"
    FOUND=0
    for p in $PREFIXES; do
        if have nft && nft list ruleset 2>/dev/null | grep -n "${p}\." ; then FOUND=1; fi
        if have iptables && iptables -S 2>/dev/null | grep -n "${p}\." ; then FOUND=1; fi
    done
    [ "$FOUND" = "0" ] && info "(no rule names any of them)"
    verdict "rules naming a resolved address: ${FOUND} (0 = not a block on this node)"
fi

echo ""
echo "  rules this app wrote (auto-block writes these):"
{ have nft && nft list ruleset 2>/dev/null | grep -i 'networksentinel'; } | head -20 | sed 's/^/    /'
{ have iptables && iptables -S 2>/dev/null | grep -i 'networksentinel'; } | head -20 | sed 's/^/    /'
echo "    (empty = this app has written no rules)"

# The layer this script structurally cannot see. Worth saying plainly, because every
# check above answers "not the firewall" while meaning only "not the firewall ON THIS
# HOST", and a provider firewall fails exactly like a silent drop.
echo ""
echo "  NOT visible from inside this machine: the provider's own firewall."
echo "    On Linode that is Cloud Firewall, attached per-interface and enforced upstream."
echo "    Check its inbound AND outbound policies, and whether its rules cover IPv6 at all"
echo "    — a v4-only ruleset with a DROP default silently blackholes every v6 client."

echo ""
echo "  rules that would drop QUIC (UDP 443) — YouTube prefers it, and a silent drop"
echo "  shows up as stalling video rather than as an error:"
{ have nft && nft list ruleset 2>/dev/null | grep -E 'udp .*(dport|sport) 443' ; } | sed 's/^/    /'
{ have iptables && iptables -S 2>/dev/null | grep -E '\-p udp .*443' ; } | sed 's/^/    /'
echo "    (empty = QUIC is not being dropped here)"

# Auto-block state. Named keys only — settings.json also holds a certificate password
# and the webhook URL, and neither belongs in a paste-back diagnostic.
echo ""
echo "  auto-block settings:"
SETTINGS_SEEN=0
for f in /root/.local/share/NetworkSentinel/settings.json \
         /home/*/.local/share/NetworkSentinel/settings.json; do
    [ -f "$f" ] || continue
    SETTINGS_SEEN=1
    echo "    ${f}:"
    grep -oE '"(AutoBlockEnabled|AutoBlockMinLevel|AutoBlockInbound|AutoBlockOutbound|PreventionDryRun|AutoBlockExpiryMinutes)"[[:space:]]*:[[:space:]]*("[^"]*"|[A-Za-z0-9]+)' \
        "$f" 2>/dev/null | sed 's/^/      /'
done
[ "$SETTINGS_SEEN" = "0" ] && echo "    (no settings.json found — auto-block is off by default)"

# ---------------------------------------------------------------------------
# 3. IPv6
# ---------------------------------------------------------------------------
say "3. IPv6 — the half-configured tunnel that only breaks Google"

NODE_V6="$(ip -6 -o addr show scope global 2>/dev/null \
           | awk -v tun="${TUN:-__none__}" '$2 != tun {print $4}' | head -1)"
FWD6="$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo '?')"
FWD4="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '?')"
info "node global IPv6:      ${NODE_V6:-none}"
info "tunnel IPv6 address:   ${TUN_V6:-none}"
info "ipv4 forwarding:       ${FWD4}"
info "ipv6 forwarding:       ${FWD6}"

NAT6=""
if have ip6tables; then
    NAT6="$(ip6tables -t nat -S 2>/dev/null | grep -i 'masquerade\|snat')"
fi
if [ -z "$NAT6" ] && have nft; then
    NAT6="$(nft list ruleset 2>/dev/null | grep -iE 'ip6 .*(masquerade|snat)|meta nfproto ipv6.*masquerade')"
fi
info "ipv6 NAT/masquerade:   ${NAT6:-none found}"

# Absence of NAT66 proves nothing on its own: a routed prefix needs none, and NAT66
# on an un-routed one is a workaround rather than the intended shape. What decides it
# is whether a packet SOURCED FROM THE TUNNEL PREFIX gets an answer, because that is
# the address a client's traffic will carry once it is forwarded.
#
# Every probe here uses a literal address. Testing v6 by name breaks the moment
# aaaa_disabled is set on the resolver — the node then cannot look up an AAAA either,
# and a working v6 path reports as broken. That is a measurement artefact, and one
# that shows up exactly when someone is mid-way through testing this hypothesis.
V6_PING="2001:4860:4860::8888"        # Google Public DNS, answers ICMPv6
V6_TCP="[2606:4700:4700::1111]"       # Cloudflare, answers TCP/443
V6_TCP_ALT="[2001:4860:4860::8888]"   # Google DoH, same

# ICMP and TCP are different questions and a firewall can answer them differently.
# Testing only ICMP was the flaw in the first version of this probe: ping proves a
# route exists in both directions, and says nothing about whether a stateful filter
# somewhere upstream will pass a TCP handshake from the same source. That pair —
# ping fine, TCP dead — is the signature of a provider firewall, and it is invisible
# to a script that only pings. Both are asked, and the combination is reported.
v6_pings() {
    local src="$1"
    if [ -n "$src" ]; then
        ping -6 -c1 -W3 -I "$src" "$V6_PING" >/dev/null 2>&1
    else
        ping -6 -c1 -W3 "$V6_PING" >/dev/null 2>&1
    fi
}

# -k because the cert cannot match a literal address; any HTTP status back proves the
# handshake completed, which is the whole question.
v6_connects() {
    local src="$1" target code
    have curl || return 2
    for target in "$V6_TCP" "$V6_TCP_ALT"; do
        if [ -n "$src" ]; then
            code="$(curl -6 -k -sS -o /dev/null -m 8 --interface "$src" \
                    -w '%{http_code}' "https://${target}/" 2>/dev/null)"
        else
            code="$(curl -6 -k -sS -o /dev/null -m 8 \
                    -w '%{http_code}' "https://${target}/" 2>/dev/null)"
        fi
        [ "${code:-000}" != "000" ] && return 0
    done
    return 1
}

describe_v6() {
    local src="$1" ping_ok tcp_ok
    v6_pings "$src" && ping_ok=1 || ping_ok=0
    v6_connects "$src"
    case "$?" in
        0) tcp_ok=1 ;;
        2) tcp_ok=2 ;;
        *) tcp_ok=0 ;;
    esac
    if [ "$tcp_ok" = "2" ]; then
        [ "$ping_ok" = "1" ] && echo "ping yes, TCP untested (no curl)" || echo "no"
    elif [ "$ping_ok" = "1" ] && [ "$tcp_ok" = "1" ]; then
        echo "yes (ping and TCP)"
    elif [ "$ping_ok" = "1" ]; then
        echo "PING ONLY — TCP blocked"
    elif [ "$tcp_ok" = "1" ]; then
        echo "TCP only (ICMP filtered, which is harmless)"
    else
        echo "no"
    fi
}

V6_EGRESS="no"
[ -n "$NODE_V6" ] && V6_EGRESS="$(describe_v6 "")"
info "this node over IPv6:   ${V6_EGRESS}  (its own address — says nothing about clients)"

TUN_V6_ADDR="${TUN_V6%%/*}"
V6_TUN_EGRESS="untested"
if [ -n "$TUN_V6_ADDR" ]; then
    V6_TUN_EGRESS="$(describe_v6 "$TUN_V6_ADDR")"
    info "FROM the tunnel prefix: ${V6_TUN_EGRESS}  <-- this is the one that matters"
fi

case "$V6_TUN_EGRESS" in
    "PING ONLY"*)
        verdict "PROBLEM: from the tunnel prefix, ICMPv6 gets through and TCP does not."
        verdict "A route exists in both directions, so this is not a routing fault and not"
        verdict "the tunnel: something upstream is passing pings and dropping handshakes."
        verdict "On a cloud instance that is the provider firewall — the layer no check in"
        verdict "this script can see. Look at its IPv6 rules, and at whether its stateful"
        verdict "handling covers the routed range as well as the instance's own address."
        verdict "Clients get IPv6 from this prefix, so every v6 connection they open dies"
        verdict "here while v4 stays perfect — which looks exactly like 'only Google broke'."
        ;;
esac

if [ -n "$TUN_V6" ] && [ "$V6_TUN_EGRESS" = "no" ]; then
    verdict "PROBLEM: the tunnel hands clients IPv6 that cannot reach the internet. Traffic"
    verdict "sourced from ${TUN_V6_ADDR} gets no answer, and that is the address a forwarded"
    verdict "client packet carries."
    verdict "macOS prefers IPv6 whenever a name has an AAAA record. Every Google name has one;"
    verdict "most of what you would test with does not — which is exactly why YouTube fails"
    verdict "alone. Three ways out, cheapest first:"
    verdict "  - prove it in 30s: set aaaa_disabled: true in AdGuardHome.yaml, restart it, and"
    verdict "    reload the page. Clients stop seeing AAAA records and fall back to v4."
    verdict "  - make v6 real: have the provider ROUTE this prefix to the node (on Linode that"
    verdict "    is a routed range, requested per instance) — no NAT needed once it is routed."
    verdict "  - or drop v6 from the tunnel: remove the v6 Address and ::/0 from the clients."
elif [ -n "$TUN_V6" ] && [ "$FWD6" != "1" ]; then
    verdict "PROBLEM: the tunnel carries IPv6 but net.ipv6.conf.all.forwarding is ${FWD6}, so"
    verdict "this node will not pass a client's v6 packet at all. Set it to 1 (and persist it"
    verdict "in /etc/sysctl.d/) before looking any further."
elif [ -n "$TUN_V6" ] && [ "$V6_TUN_EGRESS" = "untested" ]; then
    verdict "the tunnel carries IPv6 and this node could not test whether that prefix reaches"
    verdict "the internet (no curl). Install curl and re-run: everything else here is guesswork"
    verdict "without it, because a missing NAT rule is normal for a properly routed prefix."
elif [ -z "$TUN_V6" ] && [ -n "$NODE_V6" ]; then
    verdict "the tunnel is v4-only while this node has v6. That is consistent as long as the"
    verdict "client's AllowedIPs is 0.0.0.0/0 (v6 then stays on its local link, outside the"
    verdict "tunnel). If the client routes ::/0 in as well, its v6 has nowhere to go: check"
    verdict "AllowedIPs on the Mac, and see the client checklist at the end."
else
    verdict "no v6 mismatch visible from this side."
fi

# ---------------------------------------------------------------------------
# 4. MTU
# ---------------------------------------------------------------------------
say "4. MTU on the path out of this node"

PROBE_IP="$(printf '%s\n' ${RESOLVED_IPS:-} | grep -E '^[0-9]+(\.[0-9]+){3}$' | head -1)"
PROBE_IP="${PROBE_IP:-8.8.8.8}"
info "probing towards ${PROBE_IP} with DF set"
BEST=0
for size in 1500 1492 1472 1420 1400 1380 1300 1280; do
    payload=$(( size - 28 ))
    if ping -c1 -W2 -M do -s "$payload" "$PROBE_IP" >/dev/null 2>&1; then
        BEST="$size"
        break
    fi
done
if [ "$BEST" = "0" ]; then
    info "no size got a reply — this target may just not answer ICMP; not conclusive."
else
    info "largest packet that crossed: ${BEST} bytes"
    verdict "a WireGuard client's MTU must fit inside that minus 60 bytes of encapsulation"
    verdict "(80 if the tunnel's outer transport is IPv6): $(( BEST - 60 )) here."
fi
info "tunnel interface MTU is ${TUN_MTU:-unknown}"
verdict "this only measures THIS node's path. The Mac's path to this node is the half that"
verdict "usually breaks — run the client-side probe in the checklist below before changing MTU."

# ---------------------------------------------------------------------------
# 5. Can this node reach the site
# ---------------------------------------------------------------------------
say "5. Can this node itself reach the site"

if have curl; then
    printf '  %-34s %-14s %s\n' "name" "HTTP (v4)" "time"
    for d in "${DOMAINS[@]}"; do
        out="$(curl -4 -sS -o /dev/null -m "$CURL_TIMEOUT" \
               -w '%{http_code} %{time_total}' "https://${d}/" 2>/dev/null)"
        code="$(printf '%s' "$out" | awk '{print $1}')"
        secs="$(printf '%s' "$out" | awk '{print $2}')"
        flag=""
        case "${code:-000}" in
            000) flag="  <-- no connection at all" ;;
            429|403) flag="  <-- reachable, but refused: see the note below" ;;
        esac
        printf '  %-34s %-14s %ss%s\n' "$d" "${code:-000}" "${secs:-?}" "$flag"
    done
    verdict "200/301/404 all mean the path works — 404 from an API host is a healthy answer."
    verdict "403/429 from Google means the path works and Google is refusing THIS ADDRESS."
    verdict "Datacenter ranges (Linode included) collect that treatment; on the Mac it appears"
    verdict "as 'Sign in to confirm you're not a bot' or an endless spinner on a page that"
    verdict "otherwise loads. Nothing on this node can fix it — see the checklist."
else
    info "(curl not installed)"
fi

# ---------------------------------------------------------------------------
# The other half of the picture
# ---------------------------------------------------------------------------
say "Run these on the Mac, with the tunnel UP"

TUN_ADDR="${TUN_V4%%/*}"
cat <<EOF
  # 1. Is the Mac actually using this node's resolver?
  scutil --dns | grep 'nameserver\[' | sort -u

  # 2. Ask it directly for the names that matter (same comparison as section 1):
  dig +short www.youtube.com @${TUN_ADDR:-<tunnel-ip>}
  dig +short youtubei.googleapis.com @${TUN_ADDR:-<tunnel-ip>}

  # 3. Does the Mac prefer a v6 path that does not work? Compare the two:
  curl -4 -s -o /dev/null -w 'v4 %{http_code} %{time_total}s\n' https://www.youtube.com/
  curl -6 -s -o /dev/null -w 'v6 %{http_code} %{time_total}s\n' https://www.youtube.com/

  # 4. In the WireGuard app, check the tunnel's AllowedIPs, DNS and MTU fields.
  #    AllowedIPs with ::/0 while this node has no working v6 is section 3's failure.

  # 5. MTU: what the tunnel carries, and what the path to this node actually allows.
  ifconfig | grep '^utun'                        # the tunnel's own MTU
  ping -D -s 1372 -c 3 <this node's public IP>   # 1372+28 = 1400; halve on failure

  # 6. What the failure actually looks like matters — a DNS error, a blank page, a
  #    spinner, or a bot check are four different causes.
EOF

say "Reading the result"
cat <<'EOF'
  Section 1 shows FILTERED     -> the resolver refused a name YouTube needs. Allow it in
                                  AdGuard (user_rules: @@||name^) and it is fixed. The
                                  signed-in page dies without youtubei.googleapis.com in
                                  particular, while the logged-out page still renders.
  Section 1 flags ratelimit    -> 40 queries/second per client is under what one Mac asks
                                  for when a signed-in YouTube tab opens, and the excess
                                  is dropped in silence. Raise it and retest.
  Ad endpoints refused, and    -> not a network fault. The page loads, YouTube notices the
  the page loads but won't        refusal and answers with a wall instead of a video. This is
  play                            the only cause where every other check is clean and the
                                  tunnel being off "fixes" it. Pause protection to confirm.
  Section 2 names an address   -> a firewall rule here is dropping it. If it is an
                                  auto-block rule, allowlist the address rather than
                                  unblocking: an unblock only suppresses it for 24 h.
  Section 3 says PROBLEM       -> v6 the tunnel offers but cannot carry. The single most
                                  common cause of "only Google is broken". The line to read
                                  is "FROM the tunnel prefix", not the NAT one: a routed
                                  prefix needs no NAT, so its absence proves nothing.
  Section 3 says PING ONLY     -> the route is fine and TCP is being dropped upstream.
                                  Ping is not a connectivity test; that pair is what a
                                  provider firewall looks like from inside the box.
  Section 4 much below 1420    -> lower the client's MTU. Symptom is a page that starts
                                  and stalls, or video that never begins.
  Section 5 shows 403/429      -> Google is refusing the VPS address itself. Not fixable
                                  here; use a residential exit or split-tunnel YouTube.
  All five clean               -> the problem is between the Mac and this node, not on it.
                                  The Mac-side checklist above is where to look next.
EOF

say "Done"
echo "Nothing above changed any state. Paste the whole output back."
